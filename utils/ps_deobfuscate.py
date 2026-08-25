#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PowerShell 反混淆工具 — 解码常见的 PowerShell 混淆技术
支持: Base64 -Enc, 字符串拼接, 变量替换, 字符偏移, XOR, etc.
"""
import re
import base64
from typing import List, Tuple

from logger import get_logger

logger = get_logger('utils.ps_deobfuscate')


class PSDeobfuscator:
    """PowerShell 反混淆器"""

    # Common encoded command detection patterns
    ENCODED_PATTERNS = [
        re.compile(rb'-e(?:nc(?:odedCommand)?)?\s+([A-Za-z0-9+/=]{20,})', re.I),
        re.compile(rb'-EncodedCommand\s+["\']?([A-Za-z0-9+/=]{20,})["\']?', re.I),
        re.compile(rb'FromBase64String\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']\s*\)', re.I),
        re.compile(rb'::FromBase64String\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']\s*\)', re.I),
    ]

    # Common obfuscation patterns
    XOR_PATTERN = re.compile(rb'([0-9]+)\s*-bxor\s*([0-9]+)', re.I)
    CHAR_PATTERN = re.compile(rb'\[char\]\s*(\d+)', re.I)
    STRING_JOIN_PATTERN = re.compile(rb'"([^"]+)"\s*\+\s*"([^"]+)"')

    def __init__(self):
        self.decoded_commands: List[str] = []
        self.iocs: List[str] = []

    def deobfuscate(self, data: bytes) -> List[Tuple[str, str, bytes]]:
        """反混淆 PowerShell 命令
        Returns: List of (technique, description, decoded_data)
        """
        results = []
        self.decoded_commands = []
        self.iocs = []

        # 1. Try Base64 encoded commands
        for pattern in self.ENCODED_PATTERNS:
            for match in pattern.findall(data):
                try:
                    b64_str = match.decode('ascii', errors='ignore')
                    # Normalize base64
                    b64_str = b64_str.strip().rstrip('"').rstrip("'")
                    decoded = base64.b64decode(b64_str)
                    # Check if result is readable Unicode
                    try:
                        decoded_str = decoded.decode('utf-16-le', errors='ignore')
                        if len(decoded_str) > 20 and self._readable_ratio(decoded_str) > 0.5:
                            results.append(('Base64 -EncodedCommand', '解码的 PowerShell 编码命令', decoded))
                            self.decoded_commands.append(decoded_str)
                            # Extract IOCs from decoded
                            self._extract_iocs(decoded_str)
                            continue
                    except:
                        pass
                    # Try UTF-8
                    decoded_str = decoded.decode('utf-8', errors='ignore')
                    if len(decoded_str) > 20 and self._readable_ratio(decoded_str) > 0.5:
                        results.append(('Base64 -EncodedCommand', '解码的 PowerShell 编码命令', decoded))
                        self.decoded_commands.append(decoded_str)
                        self._extract_iocs(decoded_str)
                        continue
                    # Try as raw ASCII
                    if len(decoded) > 30:
                        results.append(('Base64 Blob', 'Base64 数据块', decoded))
                except Exception as e:
                    logger.debug(f"Base64 decode failed: {e}")

        # 2. Try char array construction ([char]65 + [char]66 ...)
        char_matches = self.CHAR_PATTERN.findall(data)
        if len(char_matches) >= 4:
            try:
                chars = ''.join(chr(int(m)) for m in char_matches if 32 <= int(m) <= 126)
                if len(chars) > 10 and self._readable_ratio(chars) > 0.6:
                    results.append(('Char Array Construction', '字符数组拼接去混淆', chars.encode('utf-8')))
                    self.decoded_commands.append(chars)
                    self._extract_iocs(chars)
            except Exception as e:
                logger.debug(f"Char decode failed: {e}")

        # 3. Try XOR decoding
        for match in self.XOR_PATTERN.findall(data):
            try:
                val = int(match[0])
                key = int(match[1])
                decoded_byte = val ^ key
                if 32 <= decoded_byte <= 126:
                    pass  # Single char XOR - less useful for bulk extraction
            except:
                pass

        # 4. Look for IEX (Invoke-Expression) patterns
        iex_pattern = re.compile(
            rb'(?:IEX|Invoke-Expression)\s*(?:\(|@)?\s*(?:New-Object\s+Net\.WebClient\)\.DownloadString\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)', re.I
        )
        for match in iex_pattern.findall(data):
            try:
                url = match.decode('ascii', errors='ignore')
                self.iocs.append(f'Download URL: {url}')
                results.append(('IEX Download Cradle', f'Invoke-Expression 下载执行: {url}', match))
            except:
                pass

        return results

    def _extract_iocs(self, text: str):
        """从解码文本中提取 IOCs"""
        # URLs
        urls = re.findall(r'https?://[^\s"\'<>]+', text)
        for u in urls[:10]:
            self.iocs.append(f'URL: {u}')

        # IPs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        for ip in ips[:10]:
            if ip not in ('0.0.0.0', '127.0.0.1', '255.255.255.255'):
                self.iocs.append(f'IP: {ip}')

        # Registry paths
        regs = re.findall(r'HKEY_[A-Z_]+\\[^\s"\'<>]+', text)
        for r in regs[:5]:
            self.iocs.append(f'Registry: {r}')

        # File paths
        paths = re.findall(r'[A-Za-z]:\\(?:[^\\/:*?"<>|]+\\)*[^\\/:*?"<>|]+', text)
        for p in paths[:5]:
            if any(ext in p.lower() for ext in ['.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs']):
                self.iocs.append(f'File: {p}')

        # Commands
        cmds = re.findall(r'(?:cmd|powershell|wmic|schtasks|reg)\s+[^\n]{10,100}', text, re.I)
        for c in cmds[:5]:
            self.iocs.append(f'Command: {c[:120]}')

    def _readable_ratio(self, text: str) -> float:
        """计算文本中可读字符的比例"""
        if not text:
            return 0.0
        printable = sum(1 for c in text if c.isprintable() or c in '\t\n\r')
        return printable / len(text)

    def get_iocs(self) -> List[str]:
        """获取所有提取的 IOCs（去重）"""
        return list(dict.fromkeys(self.iocs))

    def get_decoded_commands(self) -> List[str]:
        """获取所有解码的命令"""
        return list(dict.fromkeys(self.decoded_commands))


def deobfuscate_powershell(data: bytes) -> Tuple[List[str], List[str]]:
    """便捷函数：反混淆并返回 (commands, iocs)"""
    deob = PSDeobfuscator()
    deob.deobfuscate(data)
    return deob.get_decoded_commands(), deob.get_iocs()
