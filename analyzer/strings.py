#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
字符串分析引擎 — 提取 URL、IP、邮箱、注册表、API 等
"""
import re

from logger import get_logger
from utils.helpers import extract_strings
from analyzer.models import StringAnalysis

logger = get_logger('analyzer.strings')

# 假阳性IP黑名单
_FALSE_IP = {
    '0.0.0.0', '127.0.0.1', '255.255.255.255',
    '0.0.0.1', '1.1.1.1',
    # 常见版本号伪装
    '1.0.0.0', '1.0.0.1', '2.0.0.0', '2.0.0.1', '3.0.0.0',
    '4.0.0.0', '4.0.5.0', '5.0.0.0',
}

# 版本号常见前缀 — 后面跟着更多 .数字 则是版本号
_VERSION_PREFIX = re.compile(r'(?:ver|version|v)[\s:=]*\d+\.\d+\.\d+\.\d+', re.I)


def _is_valid_ip(ip: str) -> bool:
    if ip in _FALSE_IP:
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        try:
            n = int(p)
        except ValueError:
            return False
        if n > 255:
            return False
        if p != '0' and p.startswith('0'):
            return False
    if ip.startswith('127.'):
        return False
    if ip.startswith('0.'):
        return False
    if ip.split('.')[0] == '255':
        return False
    return True


class StringAnalyzer:
    """字符串分析器"""
    
    SUSPICIOUS_KEYWORDS = [
        'cmd.exe', 'powershell', 'powershell.exe', 'regsvr32', 'rundll32',
        'schtasks', 'netsh', 'certutil', 'mshta', 'wscript', 'cscript',
        'base64', 'powershell -enc', 'bitsadmin', 'vssadmin', 'wbadmin',
        'wevtutil', 'mimikatz', 'mimilib', 'sekurlsa', 'procdump',
        'VMware', 'VirtualBox', 'Sandboxie', 'Cuckoo', 'Joe Sandbox',
        'wireshark', 'process hacker', 'process monitor', 'sysinternals',
        'x64dbg', 'ollydbg', 'idaq', 'ida64', 'ghidra', 'dnspy',
        'amsi', 'etw', 'patch', 'hook', 'unhook',
        'WScript.Shell', 'Shell.Application', 'Scripting.FileSystemObject',
        'Win32_Process', 'Win32_Service', 'Win32_ShadowCopy',
        'ReflectiveLoader', 'RunPE', 'Process Hollowing',
    ]
    
    SUSPICIOUS_APIS = [
        'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
        'ReadProcessMemory', 'OpenProcess', 'TerminateProcess',
        'SetWindowsHookEx', 'GetKeyState', 'GetAsyncKeyState',
        'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'NtUnmapViewOfSection', 'NtCreateThreadEx', 'RtlCreateUserThread',
        'VirtualProtect', 'NtAllocateVirtualMemory', 'NtWriteVirtualMemory',
        'QueueUserAPC', 'SetThreadContext', 'NtQueueApcThread',
        'AdjustTokenPrivileges', 'LookupPrivilegeValue',
    ]
    
    def __init__(self, data: bytes):
        self.data = data
        
    def analyze(self) -> StringAnalysis:
        """分析字符串"""
        logger.info("[Strings] 提取字符串...")
        
        ascii_strings, unicode_strings = extract_strings(self.data, min_length=4)
        all_strings = ascii_strings + unicode_strings
        
        logger.info(f"[Strings] 共 {len(all_strings)} 个字符串")
        
        # 提取各类特征
        urls = []
        ips = []
        emails = []
        domains = []
        file_paths = []
        registry_keys = []
        api_calls = []
        suspicious = []
        base64_strings = []
        crypto_wallets = []
        user_agents = []
        cmdline_patterns = []
        powershell_patterns = []
        
        url_pattern = re.compile(r'https?://[^\s<>"{}|\^`\[\]]+(?<![.,;:!?)\]}>])', re.IGNORECASE)
        ip_octet = r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
        ip_pattern = re.compile(r'(?<![.\d])' + ip_octet + r'\.' + ip_octet + r'\.' + ip_octet + r'\.' + ip_octet + r'(?![.\d])')
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        domain_pattern = re.compile(r'\b[a-zA-Z0-9-]+\.(?:com|net|org|cn|cc|xyz|top|win|club|site|space|icu|cyou|work|tk|ml|ga|cf|gq)\b', re.IGNORECASE)
        path_pattern = re.compile(r'[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*')
        reg_pattern = re.compile(r'HKEY_[A-Z_]+\\[^\s]+')
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')
        crypto_wallet_pattern = re.compile(
            r'\b(bc1q[a-zA-Z0-9]{25,59}|'
            r'bc1p[a-zA-Z0-9]{25,59}|'
            r'1[a-km-zA-HJ-NP-Z1-9]{25,34}|'
            r'3[a-km-zA-HJ-NP-Z1-9]{25,34}|'
            r'0x[a-fA-F0-9]{40})\b'
        )
        ua_pattern = re.compile(r'Mozilla/5\.0[^\r\n]*|User-Agent:[^\r\n]*', re.IGNORECASE)
        
        seen = set()
        for s in all_strings:
            if s in seen:
                continue
            seen.add(s)
            
            # URL
            urls.extend(url_pattern.findall(s))
            # IP — 过滤假阳性
            raw_ips = ip_pattern.findall(s)
            for ip in raw_ips:
                if _is_valid_ip(ip):
                    ips.append(ip)
            # Email
            emails.extend(email_pattern.findall(s))
            # Domain
            domains.extend(domain_pattern.findall(s))
            # 文件路径
            file_paths.extend(path_pattern.findall(s))
            # 注册表
            registry_keys.extend(reg_pattern.findall(s))
            # Base64
            base64_strings.extend(base64_pattern.findall(s))
            # 加密钱包
            crypto_wallets.extend(crypto_wallet_pattern.findall(s))
            # User-Agent
            user_agents.extend(ua_pattern.findall(s))
            
            # API 调用
            for api in self.SUSPICIOUS_APIS:
                if api.lower() in s.lower():
                    api_calls.append(s[:120])
            
            # 可疑关键词
            for kw in self.SUSPICIOUS_KEYWORDS:
                if kw.lower() in s.lower():
                    suspicious.append(s[:200])
                    break
            
            # PowerShell 模式
            if 'powershell' in s.lower() or '-enc' in s.lower() or 'invoke' in s.lower():
                powershell_patterns.append(s[:200])
            
            # 命令行模式
            if any(cmd in s.lower() for cmd in ['cmd.exe', 'cmd /c', 'cmd /k', 'rundll32', 'regsvr32']):
                cmdline_patterns.append(s[:200])
        
        # 去重并限制数量
        def dedup_limit(items, limit=30):
            return list(dict.fromkeys(items))[:limit]
        
        return StringAnalysis(
            urls=dedup_limit(urls),
            ips=dedup_limit(ips),
            emails=dedup_limit(emails, 20),
            domains=dedup_limit(domains),
            file_paths=dedup_limit(file_paths, 20),
            registry_keys=dedup_limit(registry_keys, 20),
            api_calls=dedup_limit(api_calls),
            suspicious_strings=dedup_limit(suspicious),
            base64_strings=dedup_limit(base64_strings, 20),
            crypto_wallets=dedup_limit(crypto_wallets, 20),
            user_agents=dedup_limit(user_agents, 20),
            cmdline_patterns=dedup_limit(cmdline_patterns, 20),
            powershell_patterns=dedup_limit(powershell_patterns, 20),
            total_strings=len(all_strings)
        )
