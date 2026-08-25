#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用工具函数
"""
import hashlib
import math
import os
import re
import shutil
import struct
import sys
import tempfile
import time
from typing import Iterator, Optional, Tuple


def resource_path(rel_path: str) -> str:
    """返回资源文件的绝对路径，兼容 PyInstaller 打包后的运行环境"""
    if hasattr(sys, '_MEIPASS'):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel_path)


def format_size(size: int) -> str:
    """转换为人可读大小"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def format_duration(seconds: float) -> str:
    """格式化持续时间"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"


def calc_entropy(data: bytes) -> float:
    """计算香农熵（快速版本）"""
    if not data:
        return 0.0
    
    length = len(data)
    if length < 256:
        # 小数据：精确计算
        entropy = 0.0
        for x in range(256):
            count = data.count(bytes([x]))
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)
    
    # 大数据：使用直方图（O(n) 而非 O(256*n)）
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def calc_entropy_file(filepath: str, chunk_size: int = 4 * 1024 * 1024) -> float:
    """流式计算文件熵值（适用于大文件）"""
    total_length = 0
    counts = [0] * 256
    
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            total_length += len(chunk)
            for b in chunk:
                counts[b] += 1
    
    if total_length == 0:
        return 0.0
    
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / total_length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def entropy_level(entropy: float) -> str:
    """判断熵值等级"""
    if entropy < 4:
        return "low"
    elif entropy < 6:
        return "normal"
    elif entropy < 7:
        return "high"
    else:
        return "suspicious"


def _compute_ssdeep(data: bytes) -> str:
    """计算模糊哈希 — 先试 ssdeep，不行试 ppdeep"""
    try:
        import ssdeep
        return ssdeep.hash(data)
    except (ImportError, Exception):
        pass
    try:
        import ppdeep
        return ppdeep.hash_from_bytes(data)
    except (ImportError, Exception):
        pass
    return ''


def compute_hashes(data: bytes) -> dict:
    """计算多种哈希值（含模糊哈希）"""
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'sha512': hashlib.sha512(data).hexdigest(),
        'imphash': '',
        'ssdeep': _compute_ssdeep(data),
    }


def compute_hashes_file(filepath: str, chunk_size: int = 4 * 1024 * 1024) -> dict:
    """流式计算文件哈希（大文件安全）"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
    
    return {
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
        'sha512': sha512.hexdigest(),
    }


def detect_file_type(data: bytes) -> Tuple[str, str]:
    """基于魔数检测文件类型"""
    magic_signatures = {
        b'MZ': ('PE/EXE/DLL', 'application/x-msdos-program'),
        b'PK\x03\x04': ('ZIP', 'application/zip'),
        b'PK\x05\x06': ('ZIP (empty)', 'application/zip'),
        b'PK\x07\x08': ('ZIP (spanned)', 'application/zip'),
        b'7z\xbc\xaf\x27\x1c': ('7z', 'application/x-7z-compressed'),
        b'\x89PNG': ('PNG', 'image/png'),
        b'\xff\xd8\xff': ('JPEG', 'image/jpeg'),
        b'%PDF': ('PDF', 'application/pdf'),
        b'Rar!': ('RAR', 'application/x-rar-compressed'),
        b'xar!': ('XAR', 'application/x-xar'),
        b'\x1f\x8b\x08': ('GZIP', 'application/gzip'),
        b'BZh': ('BZIP2', 'application/x-bzip2'),
        b'\xfd7zXZ': ('XZ', 'application/x-xz'),
        b'MSCF': ('CAB', 'application/vnd.ms-cab-compressed'),
        b'ISc(': ('InstallShield', 'application/x-installshield'),
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': ('OLE2/MSI', 'application/x-ole-storage'),
        b'\xca\xfe\xba\xbe': ('Java Class', 'application/x-java-class'),
        b'\xef\xbb\xbf': ('UTF-8 BOM Text', 'text/plain'),
        b'\xfe\xff': ('UTF-16 BE BOM Text', 'text/plain'),
        b'\xff\xfe': ('UTF-16 LE BOM Text', 'text/plain'),
    }
    
    for sig, (ftype, mime) in magic_signatures.items():
        if data.startswith(sig):
            return ftype, mime
    
    # 检查 ELF
    if data[:4] == b'\x7fELF':
        return 'ELF', 'application/x-executable'
    
    # 检查 Mach-O
    if data[:4] in (b'\xfeedface', b'\xfeedfacf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
        return 'Mach-O', 'application/x-mach-binary'
    
    return 'Unknown', 'application/octet-stream'


def detect_file_type_file(filepath: str) -> Tuple[str, str]:
    """从文件路径检测类型"""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(64)
        return detect_file_type(header)
    except Exception:
        return 'Unknown', 'application/octet-stream'


def extract_strings(data: bytes, min_length: int = 4) -> Tuple[list, list]:
    """提取 ASCII 和 Unicode 字符串"""
    # ASCII
    ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    ascii_matches = re.findall(ascii_pattern, data)
    ascii_strings = [s.decode('ascii', errors='ignore') for s in ascii_matches]
    
    # Unicode (UTF-16LE + UTF-16BE)
    unicode_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
    unicode_matches = re.findall(unicode_pattern, data)
    unicode_strings = [s.decode('utf-16le', errors='ignore') for s in unicode_matches]
    unicode_be_pattern = rb'(?:\x00[\x20-\x7e]){' + str(min_length).encode() + rb',}'
    unicode_be_matches = re.findall(unicode_be_pattern, data)
    unicode_strings += [s.decode('utf-16be', errors='ignore') for s in unicode_be_matches]
    
    return ascii_strings, unicode_strings


def extract_strings_file(filepath: str, min_length: int = 4, chunk_size: int = 4 * 1024 * 1024) -> Iterator[str]:
    """流式提取文件字符串（生成器，内存友好）"""
    buffer = b''
    unicode_buf = b''
    
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            
            buffer += chunk
            unicode_buf += chunk
            
            ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
            ascii_matches = list(re.finditer(ascii_pattern, buffer))
            if ascii_matches:
                for match in ascii_matches[:-1]:
                    yield match.group().decode('ascii', errors='ignore')
                buffer = buffer[ascii_matches[-1].start():]
            else:
                buffer = buffer[-min_length * 2:]
            
            uni_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
            uni_matches = list(re.finditer(uni_pattern, unicode_buf))
            if uni_matches:
                for match in uni_matches[:-1]:
                    yield match.group().decode('utf-16le', errors='ignore')
                unicode_buf = unicode_buf[uni_matches[-1].start():]
            else:
                unicode_buf = unicode_buf[-min_length * 4:]
    
    if buffer:
        ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
        for match in re.finditer(ascii_pattern, buffer):
            yield match.group().decode('ascii', errors='ignore')
    
    if unicode_buf:
        uni_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
        for match in re.finditer(uni_pattern, unicode_buf):
            yield match.group().decode('utf-16le', errors='ignore')


def create_temp_dir(prefix: str = 'sandbox_') -> str:
    """创建临时目录"""
    return tempfile.mkdtemp(prefix=prefix)


def clean_directory(path: str, max_retries: int = 3) -> bool:
    """安全删除目录 — 仅允许删除系统临时目录内的路径, 防止误传根/家/项目目录"""
    import logging as _logging
    _log = _logging.getLogger('helpers')
    if not path or not isinstance(path, str):
        return False
    try:
        target = os.path.realpath(os.path.abspath(path))
        temp_root = os.path.realpath(tempfile.gettempdir())
        home = os.path.realpath(os.path.expanduser('~'))
        # 拒绝: 不在临时目录内 / 临时目录本身 / 用户主目录 / 驱动器根
        if os.path.commonpath([temp_root, target]) != temp_root:
            _log.warning(f"[helpers] 拒绝删除非临时目录: {path}")
            return False
        if target in (temp_root, home) or os.path.dirname(target) == target:
            _log.warning(f"[helpers] 拒绝删除受保护目录: {path}")
            return False
    except Exception as e:
        _log.warning(f"[helpers] 目录校验失败, 拒绝删除 {path}: {e}")
        return False

    for i in range(max_retries):
        try:
            if os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)
            return True
        except Exception:
            if i < max_retries - 1:
                time.sleep(0.5)
    return False


def is_pe_file(data: bytes) -> bool:
    """检查是否为 PE 文件"""
    return len(data) >= 2 and data[:2] == b'MZ'


def is_pe_file_path(filepath: str) -> bool:
    """从路径检查是否为 PE 文件"""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(2)
        return header == b'MZ'
    except Exception:
        return False


def get_pe_architecture(data: bytes) -> Optional[str]:
    """获取 PE 文件架构（需要至少 64 字节）"""
    if not is_pe_file(data) or len(data) < 64:
        return None
    
    try:
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        if pe_offset + 4 > len(data):
            return None
        
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return None
        
        machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
        arch_map = {
            0x14c: 'x86',
            0x8664: 'x64',
            0xaa64: 'ARM64',
            0x1c0: 'ARM',
            0x1c4: 'ARMv7',
            0x169: 'IA64',
            0x5032: 'RISC-V 32',
            0x5064: 'RISC-V 64',
            0x5128: 'RISC-V 128',
        }
        return arch_map.get(machine, f'Unknown(0x{machine:04x})')
    except Exception:
        return None


def safe_read_file(filepath: str, max_size: int = 500 * 1024 * 1024, 
                   chunk_size: int = 4 * 1024 * 1024) -> bytes:
    """安全读取文件，带大小限制"""
    size = os.path.getsize(filepath)
    if size > max_size:
        raise ValueError(f"文件过大: {format_size(size)} > {format_size(max_size)}")
    
    if size <= chunk_size:
        with open(filepath, 'rb') as f:
            return f.read()
    
    # 大文件分块读取
    chunks = []
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)
    return b''.join(chunks)
