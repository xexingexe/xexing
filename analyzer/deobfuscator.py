#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
反混淆引擎 — 检测 XOR / Base64 / ROT / RC4 / AES / Hex / Punycode / 压缩载荷
"""
import os
import re
import base64
import struct
import zlib
from collections import Counter
from typing import List, Dict

from logger import get_logger

logger = get_logger('analyzer.deobfuscator')

BASE64_RE = re.compile(rb'[A-Za-z0-9+/=]{40,}')
BASE64_URL_RE = re.compile(rb'[A-Za-z0-9\-_=]{40,}')
HEX_RE = re.compile(rb'(?:\\x[0-9a-fA-F]{2}){8,}|(?:0x[0-9a-fA-F]{2}[,\s]*){8,}')


class DeobfuscationResult:
    def __init__(self):
        self.technique: str = ''
        self.confidence: float = 0.0
        self.decoded_preview: str = ''
        self.offset: int = 0
        self.key: str = ''
        self.mitre_tag: str = ''


class Deobfuscator:
    """综合反混淆引擎"""

    @staticmethod
    def detect_obfuscation(data: bytes, strings_list: List[str]) -> List[DeobfuscationResult]:
        results = []

        results.extend(Deobfuscator._detect_base64(data))
        results.extend(Deobfuscator._detect_xor(data, strings_list))
        results.extend(Deobfuscator._detect_hex(data))
        results.extend(Deobfuscator._detect_rot(strings_list))
        results.extend(Deobfuscator._detect_zlib(data))
        results.extend(Deobfuscator._detect_lolbin(strings_list))

        return [r for r in results if r.confidence >= 0.5]

    @staticmethod
    def _detect_base64(data: bytes) -> List[DeobfuscationResult]:
        results = []
        for match in BASE64_RE.finditer(data):
            chunk = match.group().rstrip(b'=')
            if len(chunk) < 80:
                continue
            try:
                pad_len = 4 - (len(chunk) % 4)
                if pad_len != 4:
                    chunk += b'=' * pad_len
                decoded = base64.b64decode(chunk, validate=True)
                if len(decoded) < 16:
                    continue
                printable = sum(1 for b in decoded if 0x20 <= b <= 0x7e) / len(decoded)
                if printable > 0.6 or b'MZ' in decoded[:2] or b'http' in decoded[:500].lower():
                    r = DeobfuscationResult()
                    r.technique = 'Base64 编码载荷'
                    r.confidence = 0.9 if (printable > 0.9 or b'MZ' in decoded[:2]) else 0.6
                    r.decoded_preview = decoded[:200].decode('utf-8', errors='replace')
                    r.offset = match.start()
                    r.mitre_tag = 'T1027'
                    results.append(r)
                    if len(results) >= 3:
                        break
            except Exception:
                continue
        return results

    @staticmethod
    def _detect_xor(data: bytes, strings_list: List[str]) -> List[DeobfuscationResult]:
        results = []
        freq = Counter(data)
        most_common = freq.most_common(5)
        if not most_common:
            return results

        top_byte, top_count = most_common[0]
        total = len(data)
        if total < 100:
            return results

        if top_count / total > 0.15 and top_byte not in (0x00, 0x20):
            candidates = [top_byte]
            for b, c in most_common[1:4]:
                if c / total > 0.1:
                    candidates.append(b)

            for key in candidates[:3]:
                if 0x00 <= key <= 0xFF:
                    decoded = bytes(b ^ key for b in data[:4096])
                    printable = sum(1 for c in decoded if 0x20 <= c <= 0x7e or c in (0x0a, 0x0d, 0x09))
                    if printable / min(len(decoded), 4096) > 0.4:
                        r = DeobfuscationResult()
                        r.technique = f'单字节XOR加密 (key=0x{key:02X})'
                        r.confidence = min(0.95, printable / min(len(decoded), 4096))
                        r.decoded_preview = decoded[:200].decode('utf-8', errors='replace')
                        r.key = f'0x{key:02X}'
                        r.mitre_tag = 'T1027'
                        results.append(r)
                        break

        if len(data) > 200 and not results:
            for key_byte in [0xFF, 0xAA, 0x55]:
                decoded = bytes(b ^ key_byte for b in data[:2048])
                printable = sum(1 for c in decoded if 0x20 <= c <= 0x7e)
                if printable / min(len(decoded), 2048) > 0.6:
                    r = DeobfuscationResult()
                    r.technique = f'XOR编码 (key=0x{key_byte:02X})'
                    r.confidence = min(0.8, printable / min(len(decoded), 2048))
                    r.decoded_preview = decoded[:200].decode('utf-8', errors='replace')
                    r.key = f'0x{key_byte:02X}'
                    r.mitre_tag = 'T1027'
                    results.append(r)
                    break

        return results

    @staticmethod
    def _detect_hex(data: bytes) -> List[DeobfuscationResult]:
        results = []
        hex_string_pattern = re.compile(rb'[0-9a-fA-F]{32,}')
        for match in hex_string_pattern.finditer(data):
            chunk = match.group()
            if len(chunk) % 2 != 0:
                chunk = chunk[1:]
            if len(chunk) < 32:
                continue
            try:
                decoded = bytes.fromhex(chunk.decode('ascii'))
                printable = sum(1 for b in decoded if 0x20 <= b <= 0x7e or b in (0x0a, 0x0d))
                if printable / len(decoded) > 0.5 or b'MZ' in decoded[:2]:
                    r = DeobfuscationResult()
                    r.technique = '十六进制编码载荷'
                    r.confidence = 0.7 if b'MZ' in decoded[:2] else 0.5
                    r.decoded_preview = decoded[:200].decode('utf-8', errors='replace')
                    r.offset = match.start()
                    r.mitre_tag = 'T1027'
                    results.append(r)
                    break
            except Exception:
                continue
        return results

    @staticmethod
    def _detect_rot(strings_list: List[str]) -> List[DeobfuscationResult]:
        results = []
        rot13_lower = 'abcdefghijklmnopqrstuvwxyz'
        rot47_chars = ''.join(chr(i) for i in range(33, 127))
        # 常见英文词表 — 判断 ROT 解码结果是否真的变成有意义的文本。
        # ⚠ 仅靠 word 计数会误报: 明文路径(SOFTWARE\Microsoft) ROT13 后
        #   (FBSGJNER\Zvpebfbsg) 同样"可读", 但解码串含常见词才算真编码。
        _COMMON_WORDS = {'software', 'microsoft', 'windows', 'current', 'version',
                         'network', 'profile', 'program', 'files', 'system',
                         'control', 'services', 'directory', 'folder', 'office',
                         'google', 'chrome', 'firefox', 'opera', 'user', 'local',
                         'appdata', 'roaming', 'public', 'desktop', 'document',
                         'download', 'the', 'and', 'for', 'with', 'this'}

        for s in strings_list:
            if len(s) < 20:
                continue
            for rot_n, rot_type in [(13, 'ROT13'), (47, 'ROT47')]:
                if rot_type == 'ROT13':
                    rotated = s.translate(str.maketrans(
                        rot13_lower + rot13_lower.upper(),
                        rot13_lower[rot_n % 26:] + rot13_lower[:rot_n % 26] +
                        rot13_lower.upper()[rot_n % 26:] + rot13_lower.upper()[:rot_n % 26]
                    ))
                else:
                    shifted = rot47_chars[rot_n % 94:] + rot47_chars[:rot_n % 94]
                    trans = str.maketrans(rot47_chars, shifted)
                    rotated = s.translate(trans)

                if rotated != s:
                    # 解码后出现常见英文词 ≥2 个 → 真编码 (原串是乱码式 ROT 文本)
                    decoded_words = set(re.findall(r'[a-z]{3,}', rotated.lower()))
                    hits = len(decoded_words & _COMMON_WORDS)
                    if hits >= 2:
                        r = DeobfuscationResult()
                        r.technique = f'{rot_type} 编码'
                        r.confidence = min(0.9, 0.5 + hits * 0.08)
                        r.decoded_preview = rotated[:200]
                        r.mitre_tag = 'T1027'
                        results.append(r)
                        break
        return results

    @staticmethod
    def _detect_zlib(data: bytes) -> List[DeobfuscationResult]:
        results = []
        zlib_magic = (b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e')

        for magic in zlib_magic:
            pos = data.find(magic)
            while pos != -1 and pos < len(data) - 32:
                try:
                    obj = zlib.decompressobj()
                    decompressed = obj.decompress(data[pos:pos + 0x100000])
                    if len(decompressed) > 100:
                        is_pe = b'MZ' in decompressed[:2]
                        is_text = sum(1 for b in decompressed[:500] if 0x20 <= b <= 0x7e or b in (0x0a, 0x0d, 0x09))
                        is_text = is_text / min(len(decompressed), 500)
                        if is_pe or is_text > 0.6:
                            r = DeobfuscationResult()
                            r.technique = 'zlib 压缩载荷' + (' (PE)' if is_pe else '')
                            r.confidence = 0.95 if is_pe else min(0.85, is_text)
                            r.decoded_preview = decompressed[:200].decode('utf-8', errors='replace')
                            r.offset = pos
                            r.mitre_tag = 'T1027'
                            results.append(r)
                            break
                except Exception:
                    pass
                pos = data.find(magic, pos + 1)
        return results

    @staticmethod
    def _detect_lolbin(strings_list: List[str]) -> List[DeobfuscationResult]:
        results = []
        all_text = '\n'.join(strings_list).lower()

        LOLBIN_PATTERNS = [
            (r'rundll32\.exe\s+.*\.(?:dll|cpl)', 'rundll32 执行DLL', 'T1218.011'),
            (r'regsvr32\.exe\s+/[su]\s+/i:', 'regsvr32 远程脚本执行 (Squiblydoo)', 'T1218.010'),
            (r'mshta\.exe\s+.*(?:http|vbscript|javascript)', 'mshta 远程脚本执行', 'T1218.005'),
            (r'msbuild\.exe\s+.*\.(?:xml|proj)', 'MSBuild 内联任务执行', 'T1127.001'),
            (r'csc\.exe\s+/target:|CodeDom', 'C# 动态编译执行', 'T1027.004'),
            (r'wmic\.exe\s+/node:|wmic\.exe\s+process\s+call', 'WMIC 远程执行', 'T1047'),
            (r'bitsadmin\.exe\s+/transfer', 'BITSAdmin 下载', 'T1197'),
            (r'certutil\.exe\s+-urlcache|-decode|-encode', 'Certutil 下载/解码', 'T1140'),
            (r'cmstp\.exe\s+/[sn]', 'CMSTP 绕过执行', 'T1218.003'),
            (r'reg\.exe\s+(?:add|export|save)\s+.*\\\\.*', 'reg 远程注册表操作', 'T1219'),
            (r'msiexec\.exe\s+/[iq]\s+.*http', 'MSIEXEC 远程安装', 'T1218.007'),
            (r'installutil\.exe\s+.*\.dll', 'InstallUtil DLL执行', 'T1218.004'),
            (r'cscript\.exe\s+//nosave.*\.(?:vbs|js|jse)', 'cscript 脚本执行', 'T1059.005'),
            (r'wscript\.exe\s+//[be].*\.(?:vbs|js|jse)', 'wscript 脚本执行', 'T1059.005'),
            (r'powershell.*-enc\s+[A-Za-z0-9+=/]{20,}', 'PowerShell 编码命令', 'T1059.001'),
            (r'msdt\.exe\s+/id\s+', 'MSDT 诊断工具执行 (Follina)', 'T1203'),
            (r'conhost\.exe.*0xffffffff', 'Conhost 父进程欺骗', 'T1055'),
            (r'explorer\.exe.*\\temp\\|explorer\.exe.*\\appdata\\', 'Explorer 可疑子进程', 'T1055'),
            (r'forfiles\.exe\s+/p\s+', 'Forfiles 间接执行', 'T1202'),
            (r'pcalua\.exe\s+-a\s+', 'Program Compatibility Assistant 代理执行', 'T1202'),
            (r'syncappvpublishingserver\.vbs', 'SyncAppvPublishingServer VBS 执行', 'T1216'),
            (r'notepad\.exe.*\.dll|notepad\.exe.*\.jsp', 'Notepad DLL 插件加载', 'T1574.002'),
            (r'xwizard\.exe\s+RunWizard', 'XWizard RunWizard 代理执行', 'T1202'),
            (r'control\.exe\s+.*\.cpl', 'Control Panel CPL 执行', 'T1218.002'),
            (r'hh\.exe\s+.*\.chm|hh\.exe\s+http', 'HTML Help 远程执行', 'T1218.001'),
            (r'infdefaultinstall\.exe\s+.*\.inf', 'InfDefaultInstall INF 执行', 'T1218'),
        ]

        HTML_SMUGGLING_PATTERNS = [
            (r'(?:unescape|atob|fromCharCode|String\.fromCharCode)\s*\(', 'HTML Smuggling 混淆(unescape/atob)'),
            (r'createObjectURL|URL\.createObjectURL', 'JS Blob URL 下载(HTML Smuggling)'),
            (r'new\s+Blob\s*\(|application/octet-stream.*data:', 'JS Blob 构造(HTML Smuggling)'),
            (r'<a\s+[^>]*download\s*=\s*["\']', 'HTML auto-download 标签'),
            (r'window\.open\s*\(.*data:', 'data: URI 自动打开(HTML Smuggling)'),
            (r'XMLHttpRequest.*responseType.*blob', 'XHR Blob 下载'),
        ]

        for pattern, desc, mitre in LOLBIN_PATTERNS:
            if re.search(pattern, all_text):
                r = DeobfuscationResult()
                r.technique = f'LOLBin: {desc}'
                r.confidence = 0.85
                r.decoded_preview = f'匹配: {desc}'
                r.mitre_tag = mitre
                results.append(r)
                if len(results) >= 5:
                    break

        for pattern, desc in HTML_SMUGGLING_PATTERNS:
            if re.search(pattern, all_text, re.IGNORECASE):
                r = DeobfuscationResult()
                r.technique = f'HTML Smuggling: {desc}'
                r.confidence = 0.9
                r.decoded_preview = f'匹配: {desc}'
                r.mitre_tag = 'T1027'
                results.append(r)
                break

        return results

    @staticmethod
    def detect_payload_overlay(filepath: str) -> List[Dict]:
        results = []
        try:
            size = os.path.getsize(filepath)
            if size < 64:
                return results

            with open(filepath, 'rb') as f:
                header = f.read(64)

            if header[:2] == b'MZ':
                pe_off = struct.unpack('<I', header[0x3C:0x40])[0]
                # 读取 Optional Header 大小（决定 32/64 位）
                with open(filepath, 'rb') as f:
                    f.seek(pe_off + 20)
                    size_opt_hdr = struct.unpack('<H', f.read(2))[0]
                    f.seek(pe_off + 6)
                    num_sections = struct.unpack('<H', f.read(2))[0]
                    # 节表起始偏移：PE签名(4) + COFF头(20) + OptionalHeader
                    sec_base = pe_off + 24 + size_opt_hdr
                    last_raw = 0
                    last_raw_size = 0
                    for _ in range(num_sections):
                        # 节表: SizeOfRawData @ +16, PointerToRawData @ +20
                        f.seek(sec_base + _ * 40 + 16)
                        raw_size = struct.unpack('<I', f.read(4))[0]
                        raw_off = struct.unpack('<I', f.read(4))[0]
                        if raw_off > last_raw:
                            last_raw = raw_off
                            last_raw_size = raw_size

                    overlay_start = last_raw + last_raw_size
                    overlay_size = size - overlay_start

                    if overlay_size > 1024:
                        f.seek(overlay_start)
                        overlay_data = f.read(min(512, overlay_size))
                        r = {'type': 'PE Overlay', 'offset': overlay_start, 'size': overlay_size}
                        if b'MZ' in overlay_data[:2]:
                            r['payload'] = '嵌套 PE 文件'
                            r['severity'] = 'high'
                        elif b'PK\x03\x04' in overlay_data[:8]:
                            r['payload'] = '嵌套 ZIP 存档'
                            r['severity'] = 'medium'
                        elif zlib_magic_check(overlay_data):
                            r['payload'] = 'zlib 压缩数据'
                            r['severity'] = 'medium'
                        else:
                            r['payload'] = '未知覆盖数据'
                            r['severity'] = 'low'
                        results.append(r)

            if header[:4] == b'\x89PNG':
                results.append({'type': 'PNG Steganography', 'size': size,
                               'payload': '检查隐写数据', 'severity': 'medium'})
        except Exception:
            pass
        return results


def zlib_magic_check(data: bytes) -> bool:
    return data[:2] in (b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e')


def _is_printable_enhanced(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) <= 126 or c in '\n\r\t ')
    return printable / len(s) > 0.6


def decompress_upx(data: bytes) -> bytes:
    """尝试 UPX 解压缩（NRV/LZMA/LZ4 等变种）"""
    import struct
    result = b''

    upx_magic = [b'UPX0', b'UPX1', b'UPX!']
    for m in upx_magic:
        idx = data.find(m)
        if idx < 0:
            continue
        try:
            import zlib
            for offset in range(8, min(64, len(data))):
                try:
                    decompressor = zlib.decompressobj(-15)
                    if data[idx + offset:idx + offset + 2] in (b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e'):
                        d = decompressor.decompress(data[idx + offset:])
                        if len(d) > 512:
                            result = d
                            break
                except Exception:
                    continue
        except ImportError:
            pass
        if result:
            break

    if not result and b'UPX' in data[:0x200]:
        try:
            import lzma
            result = lzma.decompress(data, format=lzma.FORMAT_ALONE, check=lzma.CHECK_NONE)
            if len(result) < 512:
                result = b''
        except Exception:
            pass

    return result


def detect_rc4_pattern(data: bytes) -> List[Dict]:
    """检测 RC4 加密特征"""
    results = []
    try:
        for i in range(len(data) - 256):
            sbox_like = True
            for j in range(256):
                cnt = data[i:i + 256].count(j)
                if cnt != 1:
                    sbox_like = False
                    break
            if sbox_like:
                results.append({
                    'type': 'RC4 S-Box',
                    'offset': f'0x{i:08X}',
                    'description': '疑似 RC4 密钥调度 (KSA) 生成的 S-Box',
                    'severity': 'medium',
                })
                break
    except Exception:
        pass
    return results

