#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sigma 规则引擎 — 将动态行为映射为 Sigma 风格检测规则

内置20+条常见恶意行为Sigma规则，覆盖：
  - 持久化 (Autorun Keys / Scheduled Tasks / Services)
  - 凭证窃取 (LSASS Dump / SAM / DPAPI)
  - 进程注入 (Remote Thread / APC / Hollowing)
  - 反检测 (Sleep Obfuscation / Code Tampering)
  - C2通信 (Suspicious Network / DNS Tunnel)
  - 键盘记录 (SetWindowsHook)
  - 文件释放 (Temp / AppData / Public)
"""
import re
from typing import List, Dict, Any
from dataclasses import dataclass, field

from logger import get_logger

logger = get_logger('analyzer.sigma_rules')


@dataclass
class SigmaMatch:
    title: str
    description: str
    tags: List[str] = field(default_factory=list)
    level: str = 'medium'
    technique: str = ''
    matched_on: str = ''
    evidence: str = ''


class SigmaEngine:
    """Sigma规则引擎"""

    BUILTIN_RULES = [
        {
            'title': 'Autorun Keys Modification',
            'description': 'Detects modification of autostart extensibility point (ASEP) in registry.',
            'tags': ['persistence', 't1547.001', 't1060'],
            'level': 'medium',
            'technique': 'T1547.001',
            'category': 'registry',
            'patterns': [
                r'Run.{0,20}\\(?:SOFTWARE|Software)\\.*(?:Run|RunOnce)',
                r'HKCU.*CurrentVersion\\(?:Run|RunOnce)',
                r'HKLM.*CurrentVersion\\(?:Run|RunOnce)',
                r'RegSetValue.*\\(?:Run|RunOnce)',
            ],
        },
        {
            'title': 'New Application in AppCompat',
            'description': 'A General detection for a new application in AppCompat.',
            'tags': ['execution', 't1204.002'],
            'level': 'info',
            'technique': 'T1204.002',
            'category': 'file',
            'patterns': [
                r'AppCompat\\\\Custom.{0,20}\\.exe',
                r'Program Compatibility Assistant',
            ],
        },
        {
            'title': 'Suspicious Process Creation from Temp',
            'description': 'Process executable launched from Temp directory.',
            'tags': ['execution', 't1204.002'],
            'level': 'high',
            'technique': 'T1204.002',
            'category': 'process',
            'patterns': [
                r'(?:Temp|%TEMP%|%APPDATA%).*\.(?:exe|dll|scr)',
                r'(?:\\.\\)?Temp\\.*\\.(?:exe|dll|scr)',
            ],
        },
        {
            'title': 'File Dropped to AppData',
            'description': 'Executable file dropped to AppData or ProgramData.',
            'tags': ['dropped', 't1105', 't1543.003'],
            'level': 'medium',
            'technique': 'T1105',
            'category': 'file',
            'patterns': [
                r'\\AppData\\(?:Roaming|Local|LocalLow)\\.*\.(?:exe|dll|scr|bat|ps1)',
                r'\\ProgramData\\.*\.(?:exe|dll|scr|bat|ps1)',
            ],
        },
        {
            'title': 'Keyboard Input Hook Installed',
            'description': 'Windows hook to monitor keyboard input (keylogger).',
            'tags': ['keylogging', 't1056.001'],
            'level': 'high',
            'technique': 'T1056.001',
            'category': 'api',
            'patterns': [
                r'SetWindowsHookEx.*WH_KEYBOARD',
                r'SetWindowsHookEx.*13',
                r'keyboard.{0,20}hook',
            ],
        },
        {
            'title': 'LSASS Memory Dump',
            'description': 'Process accessed LSASS memory to dump credentials.',
            'tags': ['credential_dumping', 't1003.001'],
            'level': 'high',
            'technique': 'T1003.001',
            'category': 'api',
            'patterns': [
                r'OpenProcess.{0,30}lsass',
                r'MiniDumpWriteDump',
                r'ReadProcessMemory.{0,30}lsass',
                r'SamePass',
                r'sekurlsa',
                r'comsvcs\.dll.*MiniDump',
            ],
        },
        {
            'title': 'SAM Registry Hive Access',
            'description': 'Access to SAM/SECURITY registry hives for credential extraction.',
            'tags': ['credential_dumping', 't1003.002'],
            'level': 'high',
            'technique': 'T1003.002',
            'category': 'api',
            'patterns': [
                r'reg\.exe.*save.*SAM',
                r'reg\.exe.*save.*SECURITY',
                r'reg\.exe.*save.*SYSTEM',
            ],
        },
        {
            'title': 'Remote Thread Creation',
            'description': 'Thread created in remote process (process injection).',
            'tags': ['injection', 't1055.001', 't1055.002'],
            'level': 'high',
            'technique': 'T1055',
            'category': 'api',
            'patterns': [
                r'CreateRemoteThread',
                r'RtlCreateUserThread',
                r'NtCreateThreadEx',
                r'VirtualAllocEx.*WriteProcessMemory',
                r'WriteProcessMemory.*CreateRemoteThread',
            ],
        },
        {
            'title': 'Process Hollowing Detection',
            'description': 'Detects process hollowing via NtUnmapViewOfSection.',
            'tags': ['injection', 't1055.012'],
            'level': 'high',
            'technique': 'T1055.012',
            'category': 'api',
            'patterns': [
                r'NtUnmapViewOfSection',
                r'ZwUnmapViewOfSection',
                r'CREATE_SUSPENDED.*(?:VirtualAlloc|WriteProcessMemory)',
            ],
        },
        {
            'title': 'Reflective DLL Loader',
            'description': 'In-memory DLL loading via reflective loader pattern.',
            'tags': ['injection', 't1620'],
            'level': 'high',
            'technique': 'T1620',
            'category': 'memory',
            'patterns': [
                r'ReflectiveLoader',
                r'MZ.{0,200}ReflectiveLoader',
            ],
        },
        {
            'title': 'Suspicious Service Created',
            'description': 'New Windows service created from suspicious path.',
            'tags': ['persistence', 't1543.003'],
            'level': 'medium',
            'technique': 'T1543.003',
            'category': 'api',
            'patterns': [
                r'CreateServiceW.*(.temp.|.appdata.|.programdata.)',
                r'sc\.exe.*create',
            ],
        },
        {
            'title': 'Scheduled Task Created',
            'description': 'Scheduled task created for persistence.',
            'tags': ['persistence', 't1053.005'],
            'level': 'medium',
            'technique': 'T1053.005',
            'category': 'string',
            'patterns': [
                r'schtasks.*/create',
                r'Schedule\.Service',
                r'Register-ScheduledTask',
            ],
        },
        {
            'title': 'Defender Exclusion Added',
            'description': 'Windows Defender exclusion rule added.',
            'tags': ['defense_evasion', 't1562.001'],
            'level': 'high',
            'technique': 'T1562.001',
            'category': 'string',
            'patterns': [
                r'Add-MpPreference.*-ExclusionPath',
                r'Set-MpPreference.*-ExclusionPath',
                r'powershell.*Add-MpPreference',
            ],
        },
        {
            'title': 'WMI Event Subscription',
            'description': 'WMI event subscription created for persistence or C2.',
            'tags': ['persistence', 't1546.003'],
            'level': 'high',
            'technique': 'T1546.003',
            'category': 'string',
            'patterns': [
                r'__EventFilter',
                r'__FilterToConsumerBinding',
                r'ActiveScriptEventConsumer',
                r'CommandLineEventConsumer',
            ],
        },
        {
            'title': 'System Time Change for Anti-Forensics',
            'description': 'System time was modified to evade time-based detections.',
            'tags': ['defense_evasion', 't1070.006'],
            'level': 'low',
            'technique': 'T1070.006',
            'category': 'api',
            'patterns': [
                r'SetSystemTime',
                r'SetSystemTimeAdjustment',
            ],
        },
        {
            'title': 'Powershell Encoded Command',
            'description': 'Powershell executed with encoded Base64 command.',
            'tags': ['execution', 't1059.001', 't1027'],
            'level': 'medium',
            'technique': 'T1059.001',
            'category': 'string',
            'patterns': [
                r'powershell.*-e(?:nc)?\s+\w{20,}',
                r'powershell.*-EncodedCommand',
                r'powershell.*-enc\s+',
            ],
        },
        {
            'title': 'Powershell Download String',
            'description': 'Powershell download cradle detected.',
            'tags': ['command_and_control', 't1059.001', 't1105'],
            'level': 'high',
            'technique': 'T1105',
            'category': 'string',
            'patterns': [
                r'Net\.WebClient.*DownloadString',
                r'Net\.WebClient.*DownloadFile',
                r'Invoke-WebRequest',
                r'IWR\s+http',
                r'iex\s*\(.*Net\.WebClient',
                r'Invoke-Expression.*http',
            ],
        },
        {
            'title': 'VBScript / JScript Execution',
            'description': 'Scripting host executed with suspicious parameters.',
            'tags': ['execution', 't1059.005', 't1059.007'],
            'level': 'medium',
            'technique': 'T1059',
            'category': 'string',
            'patterns': [
                r'wscript\.exe.*\\Temp\\',
                r'cscript\.exe.*\\Temp\\',
                r'mshta\.exe.*http',
            ],
        },
        {
            'title': 'Suspicious CertificateUtil Abuse',
            'description': 'Certutil used to download or decode malicious content.',
            'tags': ['execution', 't1105', 't1140'],
            'level': 'medium',
            'technique': 'T1105',
            'category': 'string',
            'patterns': [
                r'certutil.*-urlcache.*http',
                r'certutil.*-decode',
                r'certutil.*-encode',
            ],
        },
        {
            'title': 'Cygwin / MinGW Suspicious Usage',
            'description': 'Cygwin or MinGW environment detected (common in malware sandboxes).',
            'tags': ['execution', 't1203'],
            'level': 'low',
            'technique': 'T1203',
            'category': 'string',
            'patterns': [
                r'cygwin',
                r'C:\\cygwin',
            ],
        },
        {
            'title': 'Network Connection to High Port',
            'description': 'Outbound connection to high/unusual port (potential C2).',
            'tags': ['command_and_control', 't1071'],
            'level': 'medium',
            'technique': 'T1071',
            'category': 'network',
            'patterns': [
                r':(?:444[0-9]|5555|666[0-9]|777[0-8]|888[0-9]|999[0-9]|31337|63016|63026)',
            ],
        },
        {
            'title': 'Self-Delete Mechanism',
            'description': 'Sample deleted itself after execution (anti-forensics).',
            'tags': ['defense_evasion', 't1070.004'],
            'level': 'high',
            'technique': 'T1070.004',
            'category': 'behavior',
            'patterns': [
                r'SELF.DELETE',
                r'self_delete',
            ],
        },
        {
            'title': 'DLL Side-Loading Pattern',
            'description': 'EXE and DLL files placed in same directory (side-loading).',
            'tags': ['persistence', 't1574.002'],
            'level': 'medium',
            'technique': 'T1574.002',
            'category': 'file',
            'patterns': [
                r'(.exe.{0,5}.dll|.dll.{0,5}.exe)',
            ],
        },
        {
            'title': 'UAC Bypass via Fodhelper',
            'description': 'UAC bypass using fodhelper.exe registry manipulation.',
            'tags': ['privilege_escalation', 't1548.002'],
            'level': 'high',
            'technique': 'T1548.002',
            'category': 'string',
            'patterns': [
                r'fodhelper',
                r'ms-settings',
                r'eventvwr.*UAC',
                r'compmgmtlauncher',
            ],
        },
        {
            'title': 'Suspicious Named Pipe',
            'description': 'Named pipe communication (potential C2 or priv escalation).',
            'tags': ['command_and_control', 't1090'],
            'level': 'medium',
            'technique': 'T1090',
            'category': 'string',
            'patterns': [
                r'\\\\\.\\pipe\\[^\x00]{3,}',
            ],
        },
        {
            'title': 'Internet Settings ZoneMap Modification',
            'description': 'Registry modification to Internet Settings ZoneMap (Raspberry Robin marker).',
            'tags': ['defense_evasion', 't1112'],
            'level': 'medium',
            'technique': 'T1112',
            'category': 'registry',
            'patterns': [
                r'ZoneMap',
                r'Internet\s+Settings.*ZoneMap',
            ],
        },
        {
            'title': 'Suspicious Image Loaded Into LSASS',
            'description': 'Module loaded into LSASS process (potential credential theft via loaded module).',
            'tags': ['credential_access', 't1003.001'],
            'level': 'high',
            'technique': 'T1003.001',
            'category': 'api',
            'patterns': [
                r'lsass.*(?:LoadLibrary|LdrLoadDll)',
                r'(?:LoadLibrary|LdrLoadDll).{0,30}lsass',
                r'lsass\.exe.*\.dll',
            ],
        },
        {
            'title': 'Executable File Creation',
            'description': 'New executable file created on disk (Sysmon EventID 11 equivalent).',
            'tags': ['execution', 't1105'],
            'level': 'low',
            'technique': 'T1105',
            'category': 'file',
            'patterns': [
                r'CreateFile.*\.(?:exe|dll|scr|bat|cmd|ps1)',
                r'NtCreateFile.*\.(?:exe|dll|scr)',
            ],
        },
        {
            'title': 'Suspicious Binaries in Public Folder',
            'description': 'Executable dropped to C:\\Users\\Public (commonly abused for staging/execution, e.g. SilverFox).',
            'tags': ['dropped', 't1105', 't1059'],
            'level': 'high',
            'technique': 'T1105',
            'category': 'file',
            'patterns': [
                r'\\Users\\Public\\.*\.(?:exe|dll|scr|bat|ps1|vbs|js|msi)',
                r'C:\\Users\\Public\\.*\.(?:exe|dll|scr)',
            ],
        },
        {
            'title': 'Browser Credential Theft',
            'description': 'Access to browser cookie/login databases (steal web session cookies, T1539).',
            'tags': ['credential_access', 't1539', 't1555.003'],
            'level': 'high',
            'technique': 'T1539',
            'category': 'file',
            'patterns': [
                r'\\User Data\\.*(?:Cookies|Login Data|Web Data)',
                r'cookies\.sqlite',
                r'\\Cookies\\',
                r'Login Data',
            ],
        },
        {
            'title': 'Data Staged for Exfiltration',
            'description': 'Archive created in temp/public directory (data staged before exfiltration, T1074).',
            'tags': ['collection', 't1074', 't1560'],
            'level': 'medium',
            'technique': 'T1074',
            'category': 'file',
            'patterns': [
                r'\\(?:Temp|Public)\\.*\.(?:zip|7z|rar|tar|gz|cab)',
                r'\\AppData\\Local\\Temp\\.*\.(?:zip|7z|rar)',
            ],
        },
    ]

    def __init__(self):
        self._rules = list(self.BUILTIN_RULES)

    def scan_strings(self, strings_data) -> List[SigmaMatch]:
        """对字符串分析结果运行 Sigma 规则"""
        matches = []
        all_text = ' '.join(
            (getattr(strings_data, 'suspicious_strings', []) or []) +
            (getattr(strings_data, 'api_calls', []) or []) +
            (getattr(strings_data, 'powershell_patterns', []) or []) +
            (getattr(strings_data, 'cmdline_patterns', []) or []) +
            (getattr(strings_data, 'file_paths', []) or []) +
            (getattr(strings_data, 'registry_keys', []) or []) +
            (getattr(strings_data, 'urls', []) or []) +
            (getattr(strings_data, 'domains', []) or []) +
            (getattr(strings_data, 'ips', []) or [])
        )
        if not all_text:
            return matches
        all_text_lower = all_text.lower()

        for rule in self._rules:
            if rule['category'] not in ('string', 'file', 'registry',):
                continue
            for pattern in rule['patterns']:
                if re.search(pattern, all_text_lower, re.IGNORECASE):
                    matches.append(SigmaMatch(
                        title=rule['title'],
                        description=rule['description'],
                        tags=rule['tags'],
                        level=rule['level'],
                        technique=rule['technique'],
                        matched_on='strings',
                        evidence=pattern[:80],
                    ))
                    break
        return matches

    def scan_api_calls(self, api_monitor_result) -> List[SigmaMatch]:
        """对API监控结果运行 Sigma 规则"""
        matches = []
        api_names = []
        api_args = []
        if api_monitor_result and hasattr(api_monitor_result, 'call_records'):
            for record in api_monitor_result.call_records:
                api_names.append(record.api_name)
                api_args.extend(str(a) for a in (record.arguments or []))

        all_text = ' '.join(api_names + api_args)
        if not all_text:
            return matches

        for rule in self._rules:
            if rule['category'] not in ('api',):
                continue
            for pattern in rule['patterns']:
                if re.search(pattern, all_text, re.IGNORECASE):
                    matches.append(SigmaMatch(
                        title=rule['title'],
                        description=rule['description'],
                        tags=rule['tags'],
                        level=rule['level'],
                        technique=rule['technique'],
                        matched_on='api_monitor',
                        evidence=pattern[:80],
                    ))
                    break
        return matches

    def scan_process_tree(self, dynamic_behavior) -> List[SigmaMatch]:
        """对进程树运行 Sigma 规则"""
        matches = []
        process_texts = []
        if dynamic_behavior and hasattr(dynamic_behavior, 'processes_created'):
            for p in dynamic_behavior.processes_created:
                process_texts.append(p.get('name', ''))
                process_texts.append(p.get('exe', ''))
                process_texts.append(p.get('cmdline', ''))
                if 'self_delete' in str(p.get('name', '')):
                    process_texts.append('SELF-DELETE')

        all_text = ' '.join(str(t) for t in process_texts)
        if not all_text:
            return matches

        for rule in self._rules:
            if rule['category'] not in ('process', 'behavior',):
                continue
            for pattern in rule['patterns']:
                if re.search(pattern, all_text, re.IGNORECASE):
                    matches.append(SigmaMatch(
                        title=rule['title'],
                        description=rule['description'],
                        tags=rule['tags'],
                        level=rule['level'],
                        technique=rule['technique'],
                        matched_on='process_tree',
                        evidence=pattern[:80],
                    ))
                    break
        return matches

    def scan_files(self, dropped_files_analysis) -> List[SigmaMatch]:
        """对释放文件运行 Sigma 规则"""
        matches = []
        file_paths = []
        if dropped_files_analysis and hasattr(dropped_files_analysis, 'dropped_files'):
            for df in dropped_files_analysis.dropped_files:
                file_paths.append(df.path)
                file_paths.append(df.abs_path)

        all_text = ' '.join(file_paths)
        if not all_text:
            return matches

        for rule in self._rules:
            if rule['category'] not in ('file',):
                continue
            for pattern in rule['patterns']:
                if re.search(pattern, all_text, re.IGNORECASE):
                    matches.append(SigmaMatch(
                        title=rule['title'],
                        description=rule['description'],
                        tags=rule['tags'],
                        level=rule['level'],
                        technique=rule['technique'],
                        matched_on='dropped_files',
                        evidence=pattern[:80],
                    ))
                    break
        return matches

    def scan_network(self, network_traffic) -> List[SigmaMatch]:
        """对网络流量运行 Sigma 规则"""
        matches = []
        network_texts = []
        if network_traffic:
            for conn in (getattr(network_traffic, 'tcp_connections', []) or []):
                network_texts.append(f"{conn.remote_addr}:{conn.remote_port}")
                network_texts.append(conn.remote_addr)
            for dns in (getattr(network_traffic, 'dns_queries', []) or []):
                network_texts.append(dns.domain)

        all_text = ' '.join(network_texts)
        if not all_text:
            return matches

        for rule in self._rules:
            if rule['category'] not in ('network',):
                continue
            for pattern in rule['patterns']:
                if re.search(pattern, all_text, re.IGNORECASE):
                    matches.append(SigmaMatch(
                        title=rule['title'],
                        description=rule['description'],
                        tags=rule['tags'],
                        level=rule['level'],
                        technique=rule['technique'],
                        matched_on='network',
                        evidence=pattern[:80],
                    ))
                    break
        return matches

    def scan_memory(self, memory_analysis) -> List[SigmaMatch]:
        """对内存分析结果运行 Sigma 规则"""
        matches = []
        memory_texts = []
        if memory_analysis:
            for r in (getattr(memory_analysis, 'suspicious_regions', []) or []):
                memory_texts.append(r.suspicion_reason if hasattr(r, 'suspicion_reason') else '')
            memory_texts.append(memory_analysis.summary or '')
            if memory_analysis.shellcode_found:
                memory_texts.append('shellcode detected')
            # ⚠ 修复误报: 不能因为 pe_in_memory=True 就硬编码 "ReflectiveLoader" —
            # 模块 dump(含 Frida 符号 DLL) 也会置 pe_in_memory, 导致 Reflective DLL
            # Loader 规则必然命中。改为只在可疑区域描述含反射特征时标注。
            if memory_analysis.pe_in_memory:
                try:
                    _region_text = ' '.join(
                        getattr(r, 'suspicion_reason', '') or ''
                        for r in (getattr(memory_analysis, 'suspicious_regions', []) or []))
                    _reflective_hint = any(k in _region_text.lower() for k in (
                        'reflectiveloader', '反射', 'rw->rx', 'rw to rx',
                        'remote thread', 'writeprocessmemory'))
                    if _reflective_hint:
                        memory_texts.append('PE in memory ReflectiveLoader')
                except Exception:
                    pass

        all_text = ' '.join(memory_texts)
        if not all_text:
            return matches

        for rule in self._rules:
            if rule['category'] not in ('memory',):
                continue
            for pattern in rule['patterns']:
                if re.search(pattern, all_text, re.IGNORECASE):
                    matches.append(SigmaMatch(
                        title=rule['title'],
                        description=rule['description'],
                        tags=rule['tags'],
                        level=rule['level'],
                        technique=rule['technique'],
                        matched_on='memory',
                        evidence=pattern[:80],
                    ))
                    break
        return matches

    def run_all(self, report) -> List[SigmaMatch]:
        """综合运行所有Sigma规则检测"""
        all_matches = []

        if hasattr(report, 'strings') and report.strings:
            all_matches.extend(self.scan_strings(report.strings))

        if hasattr(report, 'api_monitor') and report.api_monitor:
            all_matches.extend(self.scan_api_calls(report.api_monitor))

        if hasattr(report, 'dynamic') and report.dynamic:
            all_matches.extend(self.scan_process_tree(report.dynamic))

        if hasattr(report, 'dropped_files') and report.dropped_files:
            all_matches.extend(self.scan_files(report.dropped_files))

        if hasattr(report, 'network') and report.network:
            all_matches.extend(self.scan_network(report.network))

        if hasattr(report, 'memory') and report.memory:
            all_matches.extend(self.scan_memory(report.memory))

        # 去重
        seen = set()
        unique = []
        for m in all_matches:
            if m.title not in seen:
                seen.add(m.title)
                unique.append(m)

        logger.info(f"[Sigma] {len(unique)} rules matched across {len(all_matches)} total hits")
        return unique


def get_sigma_mitre_mapping(matches: List[SigmaMatch]) -> Dict[str, List[str]]:
    """提取 MITRE ATT&CK 技术映射"""
    mapping = {}
    for m in matches:
        if m.technique:
            if m.technique not in mapping:
                mapping[m.technique] = []
            mapping[m.technique].append(m.title)
    return mapping
