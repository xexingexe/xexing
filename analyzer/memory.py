#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
内存分析引擎 v3 — 深度内存取证

覆盖：
  1. Shellcode 签名 (20+ 特征) — Metasploit/CobaltStrike/Sliver/自定义
  2. PE 注入检测 — 反射式DLL、进程镂空、PEB 篡改
  3. 进程镂空检测 — 磁盘PE vs 内存PE 对比
  4. 内存字符串提取 — 可疑区域中的IP/URL/命令/密钥
  5. 注入技术检测 — APC注入、AtomBombing、EarlyBird、线程劫持
  6. Inline Hook 检测 — JMP/CALL 到非模块地址
  7. ROP Gadget 检测 — 常见Gadget模式
  8. 内存保护异常 — PAGE_GUARD、RW→RX 转换
  9. CobaltStrike Beacon 专用检测
 10. 加密密钥/配置数据提取
"""
import re
import os
import time
import struct
import threading
from typing import List, Dict, Optional

from logger import get_logger
from config import CONFIG
from utils.helpers import format_size
from analyzer.models import MemoryAnalysis, MemoryRegion
from analyzer.mem_api import (
    open_process, close_handle, read_process_memory, virtual_query_ex,
    protect_name, state_name, type_name,
    MEM_COMMIT, MEM_PRIVATE, MEM_IMAGE,
)

logger = get_logger('analyzer.memory')

PYWIN32_AVAILABLE = False
try:
    import win32process
    import win32api
    import win32con
    PYWIN32_AVAILABLE = True
except ImportError:
    pass


class MemoryAnalyzer:
    """内存分析器 v3 — 增强版"""

    # ===== Shellcode / 注入载荷签名（扩展版）=====
    SHELLCODE_SIGNATURES = [
        # --- 经典 Metasploit ---
        (rb'\xfc\xe8[\x80-\x8f]\x00\x00\x00', 'Metasploit prologue (CLD + CALL)'),
        (rb'\xd9\xeb\x9b\xd9\x74\x24\xf4', 'FPU-based GetEIP'),
        (rb'\xe8\xff\xff\xff\xff\xc1', 'Call $+5 GetEIP variant'),
        (rb'\x89\xe5\x81\xc4', 'Stack pivot'),
        (rb'\x60\x9c.{0,20}\x9d\x61', 'PUSHAD/PUSHFD...POPFD/POPAD'),
        (rb'\x31\xc0\x64\x8b', 'XOR EAX; MOV from FS (PEB)'),
        (rb'\x31\xd2\x52\x68', 'XOR EDX; PUSH EDX; PUSH'),

        # --- CobaltStrike Beacon ---
        (rb'\x4d\x5a.{0,100}ReflectiveLoader', b'CobaltStrike ReflectiveLoader (MZ+string)'),
        (rb'\xe8.{3}\x5d.{0,50}\x89\x45', b'CobaltStrike Beacon call-pop pattern'),
        (rb'\x68.{4}\x68.{4}\x68.{4}\xe8', b'CobaltStrike Beacon argument setup'),
        (rb'ReflectiveLoader\x00', b'ReflectiveLoader export name'),

        # --- Process Hollowing ---
        (rb'\x4d\x5a.{0,50}This program cannot be run in DOS mode', b'MZ+PE stub in memory (hollowing)'),
        (rb'NtUnmapViewOfSection', b'NtUnmapViewOfSection reference (hollowing step 1)'),
        (rb'ZwUnmapViewOfSection', b'ZwUnmapViewOfSection reference'),

        # --- APC / EarlyBird Injection ---
        (rb'QueueUserAPC', b'QueueUserAPC reference (APC injection)'),
        (rb'NtQueueApcThread', b'NtQueueApcThread reference'),
        (rb'ZwQueueApcThread', b'ZwQueueApcThread reference'),

        # --- Atom Bombing ---
        (rb'GlobalAddAtom', b'GlobalAddAtom (AtomBombing step 1)'),
        (rb'NtQueueApcThread.{0,50}GlobalGetAtomName', b'AtomBombing chain (APC+Atom)'),

        # --- Thread Hijacking ---
        (rb'SuspendThread.{0,50}SetThreadContext', b'Thread hijacking (Suspend+Context)'),
        (rb'GetThreadContext.{0,50}SetThreadContext', b'Thread hijacking (Get+Set context)'),

        # --- 自定义载荷 ---
        (rb'\x55\x8b\xec\x83\xec.{0,20}\x64\xa1\x30', b'Stack frame + PEB access'),
        (rb'\xb8.{4}\xff\xd0', b'MOV EAX,addr; CALL EAX (dynamic resolve)'),
        (rb'\x33\xc0\x50\x68.{8}\xff\xd5', b'XOR+PUSH+CALL (common download-exec)'),
        (rb'\x6a\x00\x6a\x00\x6a\x00\x6a\x00', b'4x PUSH 0 (CREATE_NO_WINDOW flag)'),

        # --- Sliver ---
        (rb'github\.com/BishopFox/sliver', b'Sliver implant source reference'),
        (rb'sliver/implant', b'Sliver implant path'),

        # --- 通用恶意行为 ---
        (rb'OpenProcess.{0,20}VirtualAllocEx', b'OpenProcess+VirtualAllocEx chain'),
        (rb'WriteProcessMemory.{0,20}CreateRemoteThread', b'WriteProcessMemory+CreateRemoteThread'),
        (rb'VirtualProtectEx.{0,20}PAGE_EXECUTE', b'VirtualProtectEx to EXEC (remote)'),

        # --- Brute Ratel ---
        (rb'brc4.{0,30}badger', b'Brute Ratel Badger implant'),
        (rb'[A-Za-z0-9+/]{100,}={0,2}', b'Base64 payload (possible encoded implant)'),

        # --- Nighthawk ---
        (rb'Nighthawk.{0,30}beacon', b'Nighthawk C2 implant'),

        # --- Mythic ---
        (rb'Mythic.{0,20}Apollo', b'Mythic Apollo agent'),
        (rb'apollo.{0,20}callback', b'Mythic Apollo callback'),

        # --- Havoc ---
        (rb'Havoc.{0,20}Demon', b'Havoc Demon implant'),
        (rb'demon\.x64\.bin', b'Havoc Demon payload reference'),

        # --- Covenant ---
        (rb'Grunt.{0,20}Stager', b'Covenant Grunt stager'),
        (rb'Covenant.{0,20}HTTP', b'Covenant C2 reference'),

        # --- Shellcode Loaders ---
        (rb'\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2', b'x64 clearing registers (RecycledGates)'),
        (rb'\x4d\x5a\x90\x00\x03\x00', b'PE signature in memory (MZ\\x90)'),

        # --- Heap Spray ---
        (rb'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90', b'NOP sled (10+ consecutive NOPs)'),
        (rb'\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c', b'Heap spray pattern (0x0C0C0C0C)'),
        (rb'\x41\x41\x41\x41\x41\x41\x41\x41', b'Heap spray pattern (0x41414141)'),

        # --- Egg Hunting ---
        (rb'w00tw00t', b'Egg hunter tag (w00t)'),
        (rb'\x90\x90\x90\x90.{0,50}\xfc\xe8', b'NOP sled + shellcode (egg hunter setup)'),

        # --- DLL Hollowing / Proxying ---
        (rb'LoadLibraryA.{0,30}GetProcAddress', b'DLL loading + export resolve chain'),
        (rb'LdrLoadDll', b'LdrLoadDll reference (manual DLL loading)'),

        # --- Anti-Dump / Anti-Analysis ---
        (rb'SleepEx', b'SleepEx reference (anti-sandbox delay)'),
        (rb'RtlAddVectoredExceptionHandler', b'Vectored exception handler (anti-debug)'),
        (rb'RtlRemoveVectoredExceptionHandler', b'VEH removal (anti-analysis cleanup)'),

        # --- Crypto Operations ---
        (rb'CryptDecrypt', b'In-memory decryption routine'),
        (rb'CryptStringToBinary', b'CryptStringToBinary (Base64 payload decode)'),
        (rb'BCryptEncrypt', b'In-memory encryption (CNG)'),
        (rb'BCryptDecrypt', b'In-memory decryption (CNG)'),

        # --- Dinocx / Matanbuchus ---
        (rb'Dinocx', b'Dinocx loader reference'),
        (rb'Matanbuchus', b'Matanbuchus loader reference'),

        # --- XWorm / AsyncRAT strings ---
        (rb'XWorm.{0,30}XClient', b'XWorm client reference'),
        (rb'AsyncRAT.{0,30}Client', b'AsyncRAT client reference'),

        # --- DPRK / Lazarus ---
        (rb'DPRK.{0,20}malware', b'DPRK-linked malware reference'),
        (rb'Lazarus.{0,20}Group', b'Lazarus Group reference'),

        # --- Miscellaneous ---
        (rb'\x89\xe0\x83\xc0.{0,10}\xff\xe0', b'GetEIP via MOV/ADD/JMP chain'),
        (rb'NtCreateSection.{0,30}MapViewOfSection', b'Section-based injection chain'),
        (rb'RtlCreateUserThread', b'Remote thread creation (stealth)'),
        (rb'NtAllocateVirtualMemory.{0,30}PAGE_EXECUTE_READWRITE', b'RWX allocation + execution pattern'),
    ]

    # ===== Inline Hook 检测 — JMP/CALL 到非模块地址 =====
    INLINE_HOOK_PATTERNS = [
        (rb'\xe9[\x00-\xff]{4}', 'Near JMP hook (5 bytes)'),
        (rb'\xff\x25[\x00-\xff]{4}', 'Absolute JMP [mem] hook (6 bytes)'),
        (rb'\x68[\x00-\xff]{4}\xc3', 'PUSH addr; RET (detour)'),
        (rb'\x50.{0,20}\xc3', 'PUSH reg; ... RET (register detour)'),
    ]

    # ===== ROP Gadget 模式 =====
    ROP_GADGET_PATTERNS = [
        (b'\xc3', 'RET gadget (single)'),
        (b'\xc2\x00\x00', 'RET 0 gadget'),
        (b'\xc2\x04\x00', 'RET 4 gadget'),
        (b'\xc2\x08\x00', 'RET 8 gadget'),
        (b'\x58\xc3', 'POP EAX; RET (stack pivot prep)'),
        (b'\x59\xc3', 'POP ECX; RET'),
        (b'\x5a\xc3', 'POP EDX; RET'),
        (b'\x5b\xc3', 'POP EBX; RET'),
        (b'\x5d\xc3', 'POP EBP; RET (stack pivot)'),
        (b'\x94\xc3', 'XCHG EAX,ESP; RET (stack pivot)'),
        (b'\x8b\xe0\xc3', 'MOV ESP,EAX; RET'),
        (b'\x8b\xec\xc3', 'MOV EBP,ESP; RET'),
    ]

    # ===== 加密/密钥数据检测 =====
    CRYPTO_MATERIAL_PATTERNS = [
        (b'-----BEGIN RSA PRIVATE KEY-----', 'RSA 私钥'),
        (b'-----BEGIN CERTIFICATE-----', '数字证书'),
        (b'-----BEGIN EC PRIVATE KEY-----', 'ECC 私钥'),
        (b'-----BEGIN OPENSSH PRIVATE KEY-----', 'SSH 私钥'),
        (b'\x30\x82[\x00-\xff]{2}\x02\x01\x00', 'DER 编码的私钥 (PKCS#8)'),
        (b'\x2d\x2d\x2d\x2d\x2dBEGIN AES', 'AES 加密密钥 (PEM)'),
    ]

    # ===== 配置文件/嵌入式数据 =====
    CONFIG_PATTERNS = [
        (b'[A-Za-z]:\\[^\x00]+\\.(?:xml|json|ini|dat|cfg|conf)', '文件路径配置'),
        (b'\bhttps?://[^\x00\x20]{5,120}', 'URL 内嵌'),
        (b'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', 'IPv4 地址'),
        (b'CobaltStrike', 'CobaltStrike 配置引用'),
    ]

    def __init__(self):
        self._kernel32 = None
        if not PYWIN32_AVAILABLE:
            try:
                import ctypes
                self._kernel32 = ctypes.windll.kernel32
            except:
                pass

    # ===== 主入口 =====

    def analyze_process(self, pid: int, stop_event: threading.Event = None) -> MemoryAnalysis:
        logger.info(f"[*] 内存分析 v3: PID={pid}")

        from analyzer.mem_api import _kernel32 as _mem_kernel32
        if _mem_kernel32 is None:
            logger.warning("[-] kernel32 不可用，跳过内存分析")
            return MemoryAnalysis(pid=pid, summary="kernel32 不可用")
        if stop_event and stop_event.is_set():
            logger.info("[*] 内存分析已取消，返回空结果")
            return MemoryAnalysis(pid=pid, summary="分析已取消")
        regions = self._enumerate_regions(pid, stop_event=stop_event)
        suspicious = [r for r in regions if r.is_suspicious]
        # 组合保护位 (0x80/0xC0/0x140/0x1C0/0x280 等) 在 protect_name 中可能
        # 是十六进制字符串 — 按位判断, 避免 RWX 区域漏报
        rwx = [r for r in regions
               if 'EXECUTE_READWRITE' in r.protect or 'EXECUTE_WRITECOPY' in r.protect
               or (r.protect.startswith('0x')
                   and (int(r.protect, 16) & 0x40))]
        try:
            import psutil
            proc_name = psutil.Process(pid).name()
        except Exception:
            proc_name = f'PID-{pid}'

        # 各维度结果
        shellcode_found = False
        shellcode_details = []
        pe_in_memory = False
        pe_injected = []
        unhooked_regions = []
        hollowing_indicators = []
        rop_gadgets_found = []
        crypto_material = []
        config_data = []
        inline_hooks = []
        openpgp_found = False; openpgp_details = []
        zlib_found = False; zlib_details = []
        multi_payload = []
        dumped_files = []

        if CONFIG.memory.dump_enabled:
            os.makedirs(CONFIG.memory.dump_dir, exist_ok=True)
            # ⚠ 合法加载模块地址范围 — 用于过滤模块内区域, 避免误报 (同 _enumerate_regions)
            try:
                from analyzer.mem_api import get_module_ranges
                module_ranges = get_module_ranges(pid) or []
            except Exception:
                module_ranges = []

            def _in_module_range(addr: int) -> bool:
                for entry in module_ranges:
                    try:
                        m_start, m_end = entry[0], entry[1]
                    except Exception:
                        continue
                    if m_start <= addr < m_end:
                        return True
                return False

            # ⚠ 优先扫描非模块区域 (私有内存/注入点) — 合法模块区域(代码段)的
            # 字节会误匹配 shellcode 特征 (x64 prologue/PEB访问是正常代码模式),
            # 导致合法程序被误报"shellcode" (样本触发WPS看图 → WPS模块被当载荷)
            if suspicious:
                regions_to_scan = suspicious[:20]
            else:
                # 只扫描非模块区域; 全部落在模块内时不扫描 (避免把合法模块/
                # Frida 模块误报为注入 PE/Shellcode)
                non_module = [r for r in regions
                              if r.state == 'MEM_COMMIT' and r.region_size > 0x1000
                              and not _in_module_range(int(r.base_address, 16))]
                regions_to_scan = non_module[:30]

            for region in regions_to_scan:
                if stop_event and stop_event.is_set():
                    logger.info("[*] 内存分析已取消，返回部分结果")
                    break
                data = self._dump_region(pid, region)
                if not data:
                    continue

                # 保存 dump（先于各检测, 供 PE 注入结果关联 dump 路径）
                dump_path = ''
                fixed_path = ''
                if len(data) < CONFIG.memory.dump_max_size:
                    try:
                        dump_path = os.path.join(CONFIG.memory.dump_dir,
                            f"pid{pid}_{region.base_address.replace('0x','')}_{int(time.time() * 1000)}.bin")
                        with open(dump_path, 'wb') as f:
                            f.write(data)
                        dumped_files.append(dump_path)
                        # ⚠ 若该区域含内存 PE 映像 (VA 布局), 生成磁盘布局修复版
                        from analyzer.pe_rebuilder import rebuild_memory_pe
                        rebuilt = rebuild_memory_pe(data)
                        if rebuilt:
                            fixed_path = dump_path.rsplit('.', 1)[0] + '_fixed.exe'
                            with open(fixed_path, 'wb') as f:
                                f.write(rebuilt)
                            dumped_files.append(fixed_path)
                    except Exception:
                        fixed_path = ''

                # --- 各维度检测 ---
                sc = self._detect_shellcode(data)
                if sc:
                    shellcode_found = True
                    shellcode_details.extend(sc[:8])

                pe = self._detect_pe_in_memory(data)
                if pe:
                    pe_in_memory = True
                    for p_ in pe[:8]:
                        p_['pid'] = pid
                        p_['module'] = proc_name
                        if dump_path:
                            p_['dump_path'] = dump_path
                        if fixed_path:
                            p_['fixed_path'] = fixed_path
                    pe_injected.extend(pe[:8])

                pgp = self._detect_openpgp_in_memory(data)
                if pgp:
                    openpgp_found = True
                    openpgp_details.extend(pgp[:5])

                zlib = self._detect_zlib_in_memory(data)
                if zlib:
                    zlib_found = True
                    zlib_details.extend(zlib[:5])

                multi = self._detect_multi_payload_type(data)
                if multi:
                    multi_payload.extend(multi)

                # 新增：注入技术检测
                inject = self._detect_injection_technique(data)
                if inject:
                    unhooked_regions.extend(inject)

                # 新增：Inline Hook 检测 (排除模块区域 — Frida hook 全在系统 DLL 代码段)
                if not _in_module_range(int(region.base_address, 16)):
                    hooks = self._detect_inline_hooks(data, region)
                    if hooks:
                        inline_hooks.extend(hooks[:5])

                # 新增：ROP Gadget 检测
                rop = self._detect_rop_gadgets(data)
                if rop:
                    rop_gadgets_found.extend(rop[:5])

                # 新增：加密材料
                crypto = self._detect_crypto_material(data)
                if crypto:
                    crypto_material.extend(crypto[:5])

                # 新增：配置数据提取
                cfg = self._detect_config_data(data)
                if cfg:
                    config_data.extend(cfg[:8])

                # 内存字符串提取（可疑区域）
                strings = self._extract_memory_strings(data)
                if strings:
                    config_data.append({
                        'offset': region.base_address,
                        'type': 'memory_strings',
                        'strings': strings[:30],
                    })

        # 新增：进程镂空检测（对比磁盘PE和内存PE）
        hollow = self._detect_process_hollowing(pid)
        if hollow:
            hollowing_indicators.extend(hollow)

        # ===== 构建摘要 =====
        summary_parts = []
        if rwx:
            summary_parts.append(f"⚠️ {len(rwx)} 个 RWX 区域")
        if shellcode_found:
            summary_parts.append(f"⚠️ Shellcode({len(shellcode_details)}项)")
        if pe_in_memory:
            summary_parts.append(f"⚠️ PE反射注入({len(pe_injected)}个)")
        if hollowing_indicators:
            summary_parts.append(f"💀 进程镂空({len(hollowing_indicators)}项)")
        if inline_hooks:
            summary_parts.append(f"🪝 Inline Hook({len(inline_hooks)}个)")
        if rop_gadgets_found:
            summary_parts.append(f"🔗 ROP 特征({len(rop_gadgets_found)}项)")
        if unhooked_regions:
            summary_parts.append(f"💉 注入技术({len(unhooked_regions)}项)")
        if openpgp_found:
            summary_parts.append("🔑 OpenPGP")
        if zlib_found:
            summary_parts.append("📦 zlib 载荷")
        if crypto_material:
            summary_parts.append(f"🔐 密钥材料({len(crypto_material)}项)")
        if config_data:
            summary_parts.append(f"⚙️ 配置数据({len(config_data)}项)")
        if multi_payload:
            pts = multi_payload[0].get('payloads', [])
            summary_parts.append(f"🚨 多载荷: {'/'.join(pts)}")
        if not summary_parts:
            summary_parts.append("未检测到明显异常")

        return MemoryAnalysis(
            pid=pid,
            total_regions=len(regions),
            suspicious_regions=suspicious,
            rwx_regions=rwx,
            shellcode_found=shellcode_found,
            shellcode_details=shellcode_details,
            pe_in_memory=pe_in_memory or bool(hollowing_indicators),
            pe_injected_modules=pe_injected,
            unpacked_pe=bool(hollowing_indicators) or bool(rop_gadgets_found) or bool(inline_hooks),
            unpacked_modules=hollowing_indicators,
            openpgp_found=openpgp_found,
            openpgp_details=openpgp_details,
            zlib_found=zlib_found,
            zlib_details=zlib_details,
            multi_payload=multi_payload,
            dumped_files=dumped_files,
            hooks_detected=inline_hooks,
            summary=' | '.join(summary_parts),
        )

    # ===== 区域枚举 =====

    def _enumerate_regions(self, pid: int, stop_event: threading.Event = None) -> List[MemoryRegion]:
        regions = []
        h_process = open_process(pid)
        if not h_process:
            logger.warning(f"[-] 无法打开进程 PID={pid}（权限不足或进程已退出）")
            return regions

        # ⚠ 合法加载模块地址范围 — 这些区域的 RWX/RX 是 PE 节区正常属性
        # (Rust/Go/带壳程序数据段可能 RWX), 不是注入! 排除后模块基址
        # (如 0x400000) 不再被误报为"RWX 可疑区域"
        try:
            from analyzer.mem_api import get_module_ranges
            module_ranges = get_module_ranges(pid) or []
        except Exception:
            module_ranges = []

        def _in_module_range(addr: int) -> bool:
            for entry in module_ranges:
                try:
                    # 兼容 (start, end) 与 (start, end, path) 两种结构
                    m_start, m_end = entry[0], entry[1]
                except Exception:
                    continue
                if m_start <= addr < m_end:
                    return True
            return False

        try:
            address = 0
            while True:
                if stop_event and stop_event.is_set():
                    logger.info("[*] 内存区域枚举已取消")
                    break
                mbi = virtual_query_ex(h_process, address)
                if not mbi:
                    break

                base = mbi['BaseAddress']
                size = mbi['RegionSize']
                if size == 0:
                    break

                # MEM_FREE 区域跳过（Windows 首个查询常返回 base=0 的大段空闲区）
                if mbi['State'] == 0x10000:
                    address = base + size
                    if address > 0x7FFFFFFFFFFF:
                        break
                    continue

                state = state_name(mbi['State'])
                protect = protect_name(mbi['Protect'])
                mtype = type_name(mbi['Type'])

                is_susp = False
                reason = ''
                # 合法加载模块内的区域 → 不标可疑 (正常 PE 映射)
                in_module = _in_module_range(base)
                if mbi['Protect'] in (0x40, 0xC0, 0x140, 0x1C0, 0x80, 0x180, 0x280, 0x2C0):
                    # PAGE_EXECUTE_READWRITE / EXECUTE_WRITECOPY (±GUARD)
                    if not in_module:  # 模块内的 RWX 是节区属性, 非注入
                        is_susp = True
                        reason = 'RWX 内存区域'
                elif ('EXECUTE' in protect and state == 'MEM_COMMIT' and mtype == 'MEM_PRIVATE'
                      and mbi['Protect'] & 0x10 and not (mbi['Protect'] & 0x30 == 0x10)):
                    if not in_module:
                        is_susp = True
                        reason = '私有可执行内存（可能为注入代码）'
                elif mbi['Protect'] & 0x100:
                    is_susp = True
                    reason = 'PAGE_GUARD 保护页（反逆向/反调试）'
                elif mbi['Protect'] == 0x01 and mtype == 'MEM_PRIVATE' and size > 0x10000:
                    is_susp = True
                    reason = '大段私有 NOACCESS 区域（可能藏匿载荷）'

                regions.append(MemoryRegion(
                    base_address=f'0x{base:016X}',
                    region_size=size,
                    region_size_human=format_size(size),
                    state=state,
                    protect=protect,
                    type=mtype,
                    is_suspicious=is_susp,
                    suspicion_reason=reason
                ))

                address = base + size
                if address > 0x7FFFFFFFFFFF:
                    break

        except Exception as e:
            logger.error(f"[-] 内存枚举失败: {e}")
        finally:
            close_handle(h_process)

        return regions

    # ===== 内存 Dump =====

    def _dump_region(self, pid: int, region: MemoryRegion) -> Optional[bytes]:
        h_process = open_process(pid)
        if not h_process:
            return None
        try:
            base = int(region.base_address, 16)
            size = min(region.region_size, CONFIG.memory.dump_max_size)
            return read_process_memory(h_process, base, size)
        except Exception:
            return None
        finally:
            close_handle(h_process)

    # ===== Shellcode 检测（扩展）=====

    def _detect_shellcode(self, data: bytes) -> List[Dict]:
        results = []
        for pattern, desc in self.SHELLCODE_SIGNATURES:
            for match in re.finditer(pattern, data, re.DOTALL):
                end = min(match.start() + 24, len(data))
                results.append({
                    'offset': f'0x{match.start():08X}',
                    'pattern': desc if isinstance(desc, str) else desc.decode(),
                    'hex': data[match.start():end].hex()
                })

        # NOP sled
        for match in re.finditer(rb'\x90{20,}', data):
            results.append({
                'offset': f'0x{match.start():08X}',
                'pattern': f'NOP sled ({match.end() - match.start()} bytes)',
                'hex': '90 ' * min(8, match.end() - match.start())
            })

        # INT3 sled (反调试断点 sled)
        for match in re.finditer(rb'\xcc{20,}', data):
            results.append({
                'offset': f'0x{match.start():08X}',
                'pattern': f'INT3 sled ({match.end() - match.start()} bytes, 反调试)',
                'hex': 'cc ' * min(8, match.end() - match.start())
            })

        # 高密度 PUSH+CALL 序列（未对齐代码）
        push_call_count = len(re.findall(rb'\x68[\x00-\xff]{4}\xff[\xd0-\xd7]', data))
        if push_call_count >= 10:
            results.append({
                'offset': '0x00000000',
                'pattern': f'密集 PUSH+CALL 序列 ({push_call_count}次, 可能是API解析器)',
                'hex': ''
            })

        return results[:15]

    # ===== PE 注入检测 =====

    def _detect_pe_in_memory(self, data: bytes) -> List[Dict]:
        results = []
        pos = 0
        while True:
            mz_pos = data.find(b'MZ', pos)
            if mz_pos == -1:
                break

            try:
                pe_offset = struct.unpack('<I', data[mz_pos + 0x3C:mz_pos + 0x40])[0]
                pe_sig = data[mz_pos + pe_offset:mz_pos + pe_offset + 4]
                if pe_sig == b'PE\x00\x00':
                    machine = struct.unpack('<H', data[mz_pos + pe_offset + 4:mz_pos + pe_offset + 6])[0]
                    arch_map = {0x14C: 'x86', 0x8664: 'x64', 0xAA64: 'ARM64', 0x1C0: 'ARM'}
                    num_sections = struct.unpack('<H', data[mz_pos + pe_offset + 6:mz_pos + pe_offset + 8])[0]

                    # 提取节名（前8节）
                    section_names = []
                    try:
                        opt_header_size = struct.unpack('<H', data[mz_pos + pe_offset + 20:mz_pos + pe_offset + 22])[0]
                        sec_start = mz_pos + pe_offset + 24 + opt_header_size
                        for i in range(min(num_sections, 8)):
                            name = data[sec_start + i*40:sec_start + i*40 + 8].rstrip(b'\x00')
                            if name:
                                section_names.append(name.decode('ascii', errors='ignore'))
                    except:
                        pass

                    # 判断类型
                    pe_type = 'reflective_dll_injection'
                    if '.text' in section_names and '.data' in section_names:
                        pe_type = '完整PE映像（疑似进程镂空载荷）'
                    elif 'ReflectiveLoader' in str(section_names):
                        pe_type = '反射式DLL（ReflectiveLoader）'

                    results.append({
                        'offset': f'0x{mz_pos:08X}',
                        'architecture': arch_map.get(machine, f'0x{machine:04X}'),
                        'type': pe_type,
                        'sections': num_sections,
                        'section_names': section_names[:6],
                    })
                    pos = mz_pos + pe_offset + 4
                    continue
            except (struct.error, IndexError, UnicodeDecodeError):
                pass

            pos = mz_pos + 2

        # 检测孤立的 MZ 头（没有 PE 签名 — 被截断或不完整的PE）
        mz_only = [m.start() for m in re.finditer(rb'MZ', data)]
        pe_full = [r['offset'] for r in results]
        for mz in mz_only[:10]:
            if not any(abs(mz - int(p, 16)) < 0x100000 for p in pe_full):
                results.append({
                    'offset': f'0x{mz:08X}',
                    'architecture': '?',
                    'type': '孤立MZ头（不完整PE/损坏载荷）',
                    'sections': 0,
                    'section_names': [],
                })

        return results[:10]

    # ===== 进程镂空检测 =====

    def _detect_process_hollowing(self, pid: int) -> List[Dict]:
        """检测进程镂空 — 对比磁盘 PE 和在内存中的 PE"""
        results = []
        if not PYWIN32_AVAILABLE:
            return results

        try:
            import psutil
            proc = psutil.Process(pid)
            exe_path = proc.exe()
        except:
            return results

        if not exe_path or not os.path.exists(exe_path):
            return results

        h = None
        try:
            with open(exe_path, 'rb') as f:
                disk_pe = f.read(0x1000)
            disk_mz = disk_pe[:2]
            if disk_mz != b'MZ':
                return results
            disk_pe_offset = struct.unpack('<I', disk_pe[0x3C:0x40])[0]
            disk_entry = struct.unpack('<I', disk_pe[disk_pe_offset + 16:disk_pe_offset + 20])[0]

            h = win32api.OpenProcess(
                win32con.PROCESS_VM_READ | win32con.PROCESS_QUERY_INFORMATION,
                False, pid
            )
            try:
                import ctypes
                from ctypes import wintypes
                psapi = ctypes.windll.psapi
                hProcess = wintypes.HANDLE(h)
                hModules = (wintypes.HMODULE * 1024)()
                cbNeeded = wintypes.DWORD()
                if psapi.EnumProcessModules(hProcess, hModules, ctypes.sizeof(hModules), ctypes.byref(cbNeeded)):
                    base = hModules[0]
                    mem_pe = win32process.ReadProcessMemory(h, base, 0x1000)
                    mem_mz = mem_pe[:2]
                    if mem_mz == b'MZ':
                        mem_pe_offset = struct.unpack('<I', mem_pe[0x3C:0x40])[0]
                        mem_entry = struct.unpack('<I', mem_pe[mem_pe_offset + 16:mem_pe_offset + 20])[0]

                        if disk_entry != mem_entry:
                            results.append({
                                'type': 'process_hollowing',
                                'description': f'入口点不匹配: 磁盘={disk_entry:#010x} vs 内存={mem_entry:#010x}',
                                'severity': 'high',
                            })

                        disk_ts = struct.unpack('<I', disk_pe[disk_pe_offset + 8:disk_pe_offset + 12])[0]
                        mem_ts = struct.unpack('<I', mem_pe[mem_pe_offset + 8:mem_pe_offset + 12])[0]
                        if disk_ts != mem_ts:
                            results.append({
                                'type': 'process_hollowing',
                                'description': f'时间戳不匹配: 磁盘={disk_ts} vs 内存={mem_ts}',
                                'severity': 'high',
                            })
            except Exception:
                pass
        except Exception as e:
            logger.debug(f"镂空检测失败 PID={pid}: {e}")
        finally:
            if h is not None:
                try:
                    win32api.CloseHandle(h)
                except Exception:
                    pass

        return results

    # ===== 注入技术检测 =====

    def _detect_injection_technique(self, data: bytes) -> List[Dict]:
        """检测各种注入技术特征"""
        results = []

        patterns = [
            (rb'QueueUserAPC.{0,100}NtTestAlert', 'APC 注入 (QueueUserAPC+NtTestAlert)'),
            (rb'SetThreadContext.{0,80}ResumeThread', '线程劫持 (SetContext+Resume)'),
            (rb'SuspendThread.{0,80}SetThreadContext.{0,80}ResumeThread', '经典线程劫持三连'),
            (rb'CreateProcessA.{0,50}CREATE_SUSPENDED', 'CREATE_SUSPENDED 进程创建（镂空前置）'),
            (rb'VirtualAllocEx.{0,50}PAGE_EXECUTE_READWRITE', '远程 RWX 分配（注入准备）'),
            (rb'NtMapViewOfSection', 'Section 映射注入（共享内存注入）'),
            (rb'ZwCreateSection.{0,80}ZwMapViewOfSection', 'CreateSection+MapView 注入链'),
            (rb'WriteProcessMemory.{0,120}VirtualProtectEx.{0,60}PAGE_EXECUTE', '写入后改执行权限'),
            (rb'RtlCreateUserThread', 'NT 远程线程创建（隐蔽注入）'),
            (rb'GlobalAddAtomA.{0,80}GlobalGetAtomNameA', 'AtomBombing 注入链'),
        ]

        for pattern, desc in patterns:
            if re.search(pattern, data, re.DOTALL | re.IGNORECASE):
                results.append({
                    'type': 'injection_technique',
                    'pattern': desc,
                })

        return results[:10]

    # ===== Inline Hook 检测 =====

    def _detect_inline_hooks(self, data: bytes, region: MemoryRegion) -> List[Dict]:
        results = []
        if 'EXECUTE' not in region.protect:
            return results

        for pattern, desc in self.INLINE_HOOK_PATTERNS:
            matches = list(re.finditer(pattern, data))
            # ⚠ 阈值收紧: 私有可执行区含 1 个 E9 (编译器跳板/switch 表) 极常见,
            #   真 inline hook 链 = 同区域大量 detour 指令 (≥8, 与 dynamic 快照对齐)
            if len(matches) >= 8:
                # 取前3个
                for m in matches[:3]:
                    results.append({
                        'type': 'inline_hook',
                        'offset': f'0x{m.start():08X}',
                        'pattern': desc,
                        'hex': data[m.start():m.start() + 8].hex(),
                    })

        return results[:10]

    # ===== ROP Gadget 检测 =====

    def _detect_rop_gadgets(self, data: bytes) -> List[Dict]:
        results = []
        total_ret = len(re.findall(rb'\xc3', data))
        if total_ret < 10:
            return results

        # 高密度 RET 指令 → 可能是 ROP 链或代码混淆
        density = total_ret / max(len(data), 1) * 100
        if density > 2.0:
            results.append({
                'type': 'rop_gadget',
                'description': f'高密度 RET 指令 ({total_ret}个, 密度={density:.1f}%, 疑似ROP/混淆代码)',
            })

        for pattern, desc in self.ROP_GADGET_PATTERNS:
            count = len(re.findall(re.escape(pattern), data))
            if count >= 3:
                results.append({
                    'type': 'rop_gadget',
                    'description': f'{desc} ×{count}次',
                })

        return results[:8]

    # ===== 加密材料检测 =====

    def _detect_crypto_material(self, data: bytes) -> List[Dict]:
        results = []
        for pattern, desc in self.CRYPTO_MATERIAL_PATTERNS:
            for match in re.finditer(pattern, data):
                results.append({
                    'offset': f'0x{match.start():08X}',
                    'type': 'crypto_material',
                    'description': desc,
                })
        return results[:10]

    # ===== 配置数据提取 =====

    def _detect_config_data(self, data: bytes) -> List[Dict]:
        results = []
        for pattern, desc in self.CONFIG_PATTERNS:
            for match in re.finditer(pattern, data, re.IGNORECASE):
                val = match.group()
                if isinstance(val, bytes):
                    val = val.decode('ascii', errors='ignore')
                if len(val) < 3 or len(val) > 500:
                    continue
                results.append({
                    'offset': f'0x{match.start():08X}',
                    'type': 'config_data',
                    'value': val.strip(),
                    'description': desc if isinstance(desc, str) else desc.decode(),
                })
        return results[:15]

    # ===== 内存字符串提取 =====

    def _extract_memory_strings(self, data: bytes, min_len: int = 6) -> List[str]:
        """从内存区域提取有意义的字符串"""
        results = []
        # ASCII 字符串
        for match in re.finditer(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}', data):
            s = match.group().decode('ascii', errors='ignore')

            # 过滤：只保留有意义的字符串
            if self._is_interesting_string(s):
                results.append(s[:200])

        return list(dict.fromkeys(results))[:50]

    def _is_interesting_string(self, s: str) -> bool:
        """判断字符串是否有分析价值"""
        # URL
        if re.match(r'https?://', s):
            return True
        # IP 地址
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
            return True
        # 文件路径
        if re.match(r'[A-Za-z]:\\', s):
            return True
        # API 名称
        if any(api in s for api in ['CreateFile', 'WriteFile', 'RegOpen', 'VirtualAlloc',
                                      'CreateProcess', 'LoadLibrary', 'WinExec', 'OpenProcess']):
            return True
        # 命令
        if any(cmd in s.lower() for cmd in ['cmd.exe', 'powershell', 'schtasks', 'reg add',
                                              'rundll32', 'msiexec', 'wmic', 'certutil']):
            return True
        # 注册表
        if s.startswith('HKEY_') or '\\Software\\' in s:
            return True
        # DLL 名称
        if s.lower().endswith('.dll') and len(s) < 80:
            return True
        # 可疑关键词
        if any(kw in s.lower() for kw in ['password', 'username', 'login', 'token', 'key',
                                            'secret', 'admin', 'beacon', 'c2', 'payload',
                                            'inject', 'hollow', 'hook', 'bypass', 'stealth']):
            return True

        return False

    # ===== OpenPGP / zlib / 多载荷（保留原有）=====

    def _detect_openpgp_in_memory(self, data: bytes) -> List[Dict]:
        results = []
        pgp_patterns = [
            (b'-----BEGIN PGP PUBLIC KEY BLOCK-----', 'PGP 公钥'),
            (b'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP 私钥'),
            (b'-----BEGIN PGP MESSAGE-----', 'PGP 加密消息'),
            (b'OpenPGP Public Key', 'OpenPGP 密钥文件'),
            (b'gpg', 'GPG 引用'),
        ]
        for pattern, desc in pgp_patterns:
            for match in re.finditer(re.escape(pattern), data):
                results.append({
                    'offset': f'0x{match.start():08X}',
                    'type': 'openpgp_key',
                    'description': desc,
                })
        return results[:10]

    def _detect_zlib_in_memory(self, data: bytes) -> List[Dict]:
        results = []
        zlib_headers = [b'\x78\x01', b'\x78\x9c', b'\x78\xda', b'\x78\x5e',
                        b'\x78\x2b', b'\x78\x3f', b'\x78\x5c', b'\x78\x7a']
        pos = 0
        while pos < len(data) - 2:
            two_bytes = data[pos:pos+2]
            if two_bytes in zlib_headers:
                results.append({
                    'offset': f'0x{pos:08X}',
                    'type': 'zlib_compressed',
                    'compression_level': {
                        b'\x78\x01': 'none', b'\x78\x9c': 'default', b'\x78\xda': 'max'
                    }.get(two_bytes, 'unknown'),
                })
                pos += 2
            else:
                pos += 1
        return results[:10]

    def _detect_multi_payload_type(self, data: bytes) -> List[Dict]:
        pe_results = self._detect_pe_in_memory(data)
        pgp_results = self._detect_openpgp_in_memory(data)
        zlib_results = self._detect_zlib_in_memory(data)

        types_found = []
        if pe_results:
            types_found.append('PE')
        if pgp_results:
            types_found.append('OpenPGP')
        if zlib_results:
            types_found.append('zlib')

        if len(types_found) >= 2:
            return [{
                'type': 'multi_payload',
                'payloads': types_found,
                'pe_count': len(pe_results),
                'pgp_count': len(pgp_results),
                'zlib_count': len(zlib_results),
                'description': f'多类型载荷组合: {"/".join(types_found)} (SilverFox/高级木马特征)',
            }]
        return []
