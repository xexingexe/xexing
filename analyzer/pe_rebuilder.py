# -*- coding: utf-8 -*-
"""内存 PE dump 修复器 — 把"映像布局"内存 dump 重建为"磁盘布局"PE 文件

背景: 从进程内存 dump 下来的 PE (反射注入/镂空载荷/模块映像) 是 Windows 加载后的
"展开"形态: 节区数据按 VirtualAddress 布局, RAW 偏移处是空的。这种文件直接交给
pefile/IDA/CFF 解析会失败或得到错误结果 (文章《PE dump 通用技巧》的经典问题)。

修复原理:
  1. 解析内存中的 DOS/PE 头 + 节区表 (SizeOfHeaders 内是头部数据)
  2. 按节区表把每个节的"虚拟地址处内容"搬移到"文件 RAW 偏移处"
  3. 修正 SizeOfHeaders / SizeOfImage (按磁盘布局重算)
  4. 可选: 重写 ImageBase (若调用方知道真实加载基址)

输出可直接被 pefile / IDA / CFF Explorer 解析。
"""
import struct
import logging

logger = logging.getLogger('malware_sandbox.pe_rebuilder')

# PE 常量
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_FILE_RELOCS_STRIPPED = 0x0001

# 常规对齐 (与加载器默认一致)
DEFAULT_SECTION_ALIGNMENT = 0x1000
DEFAULT_FILE_ALIGNMENT = 0x200


def rebuild_memory_pe(data: bytes, image_base: int = 0, max_sections: int = 40) -> bytes:
    """将内存映像布局的 PE 重建为磁盘布局。

    Args:
        data: 从内存读出的字节 (应以 MZ 开头, 或含偏移; 这里取第一个 MZ)
        image_base: 实际加载基址 (若已知, 用于重写 ImageBase 字段; 0=保持原值)
        max_sections: 节区数量上限 (防畸形头)

    Returns:
        修复后的 PE 字节; 非 PE / 解析失败返回 b''
    """
    mz = data.find(b'MZ')
    if mz == -1 or mz + 0x40 > len(data):
        return b''
    try:
        pe_off = struct.unpack_from('<I', data, mz + 0x3C)[0]
        if pe_off + 0x18 > len(data):
            return b''
        if data[mz + pe_off:mz + pe_off + 4] != b'PE\x00\x00':
            return b''
        nsec = struct.unpack_from('<H', data, mz + pe_off + 6)[0]
        if not (0 < nsec <= max_sections):
            return b''
        opt_size = struct.unpack_from('<H', data, mz + pe_off + 20)[0]
        if opt_size == 0:
            return b''
        # 可选头 magic: 0x10B PE32 / 0x20B PE32+
        magic = struct.unpack_from('<H', data, mz + pe_off + 24)[0]
        if magic not in (0x10B, 0x20B):
            return b''

        # 节区表起始
        sec_table = mz + pe_off + 24 + opt_size
        if sec_table + nsec * 40 > len(data):
            return b''

        # 头部大小 (磁盘布局: 头 + 节区表, 对齐到文件对齐)
        # ⚠ SizeOfHeaders 在 OptionalHeader 内偏移 60 → 绝对偏移 = pe_off + 24 + 60
        size_of_headers = struct.unpack_from('<I', data, mz + pe_off + 24 + 60)[0]
        if not (0x200 <= size_of_headers <= 0x1000):
            size_of_headers = sec_table + nsec * 40
        file_alignment = struct.unpack_from('<I', data, mz + pe_off + 24 + 36)[0]
        if file_alignment not in (0x200, 0x1000, 0x100):
            file_alignment = DEFAULT_FILE_ALIGNMENT

        # 解析节区
        sections = []
        max_va_end = 0
        for i in range(nsec):
            off = sec_table + i * 40
            name = data[off:off + 8].rstrip(b'\x00')
            vsize = struct.unpack_from('<I', data, off + 8)[0]
            va = struct.unpack_from('<I', data, off + 12)[0]
            raw_size = struct.unpack_from('<I', data, off + 16)[0]
            raw_ptr = struct.unpack_from('<I', data, off + 20)[0]
            characteristics = struct.unpack_from('<I', data, off + 36)[0]
            sections.append({
                'name': name, 'vsize': vsize, 'va': va,
                'raw_size': raw_size, 'raw_ptr': raw_ptr, 'chars': characteristics,
            })
            max_va_end = max(max_va_end, va + max(vsize, raw_size))

        if not sections:
            return b''

        # ===== 重建文件 (磁盘布局) =====
        # 文件大小 = 头 + 各节 raw 结尾的最大值 (按文件对齐)
        file_size = size_of_headers
        for s in sections:
            end = s['raw_ptr'] + max(s['raw_size'], s['vsize'])
            if end > file_size:
                file_size = end
        file_size = (file_size + file_alignment - 1) // file_alignment * file_alignment
        file_size = max(file_size, size_of_headers)

        rebuilt = bytearray(file_size)
        # 1) 头部: 拷贝到 SizeOfHeaders
        head_len = min(size_of_headers, len(data) - mz)
        if head_len > 0:
            rebuilt[0:head_len] = data[mz:mz + head_len]
        # 2) 节区数据: 虚拟地址处内容 → RAW 偏移
        #    内存映像从 ImageBase 开始, dump 内偏移 == VirtualAddress (RVA)
        for s in sections:
            va = s['va']
            copy_size = max(s['raw_size'], s['vsize'])
            if copy_size <= 0:
                continue
            if mz + va + copy_size <= len(data):
                rebuilt[s['raw_ptr']:s['raw_ptr'] + copy_size] = \
                    data[mz + va:mz + va + copy_size]
        # 3) 修正 SizeOfImage (VA 布局下总映像大小) — OptionalHeader 偏移 56
        if max_va_end > 0:
            size_of_image = (max_va_end + DEFAULT_SECTION_ALIGNMENT - 1) \
                // DEFAULT_SECTION_ALIGNMENT * DEFAULT_SECTION_ALIGNMENT
            struct.pack_into('<I', rebuilt, mz + pe_off + 24 + 56, size_of_image)
        # 4) 重写 ImageBase (可选)
        if image_base:
            base_off = mz + pe_off + 24 + (8 if magic == 0x20B else 4)
            if base_off + 8 <= len(rebuilt):
                struct.pack_into('<Q', rebuilt, base_off, image_base & 0xFFFFFFFFFFFFFFFF)

        # ===== 校验: 重建结果必须可被 pefile 识别 =====
        try:
            import pefile
            pe = pefile.PE(data=bytes(rebuilt), fast_load=True)
            n = pe.FILE_HEADER.NumberOfSections
            pe.close()
            if n == 0:
                return b''
        except Exception:
            return b''
        return bytes(rebuilt)
    except Exception as e:
        logger.debug(f"[PeRebuild] 失败: {e}")
        return b''


def rebuild_pe_file(src_path: str, dst_path: str, image_base: int = 0) -> bool:
    """把 dump 文件修复为磁盘布局 PE 并写盘。

    Returns:
        True=修复成功并写入; False=不是 PE 或失败
    """
    try:
        with open(src_path, 'rb') as f:
            data = f.read()
    except Exception:
        return False
    rebuilt = rebuild_memory_pe(data, image_base=image_base)
    if not rebuilt:
        return False
    try:
        with open(dst_path, 'wb') as f:
            f.write(rebuilt)
        return True
    except Exception:
        return False
