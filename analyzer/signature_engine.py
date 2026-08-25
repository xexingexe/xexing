#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
社区签名引擎 — 集成 CAPE-style 行为签名 + YARA 规则库
自动下载社区规则包，适配器将沙箱输出转为签名匹配格式
"""
import os
import re
import urllib.request
import shutil
from typing import List, Dict
from logger import get_logger

logger = get_logger('analyzer.signatures')

# ============================================================
#  简化版 CAPE 签名框架 — 兼容社区签名格式
# ============================================================

class Signature:
    """行为签名基类"""
    name = ""
    description = ""
    severity = 1  # 1-5
    categories = []  # 如: "persistence", "anti-vm", "infostealer"
    mitre = []
    references = []
    minimum = "1.0"

    def __init__(self):
        self.matched = False
        self.data = []

    def run(self, results: Dict) -> bool:
        """子类重写，返回 True 表示命中"""
        return False

    def get_data(self):
        return {"name": self.name, "description": self.description,
                "severity": self.severity, "categories": self.categories,
                "mitre": self.mitre, "data": self.data}


class SignatureRegistry:
    """签名注册表"""
    _signatures = []

    @classmethod
    def register(cls, sig_cls):
        cls._signatures.append(sig_cls)
        return sig_cls

    @classmethod
    def get_all(cls):
        return [s() for s in cls._signatures]


# ============================================================
#  适配器 — 沙箱输出 → 签名格式
# ============================================================

class SandboxAdapter:
    """将沙箱报告转为签名引擎需要的 results dict"""

    @staticmethod
    def adapt(report) -> Dict:
        """转换 AnalysisReport → CAPE-style results dict"""
        res = {
            'target': {},
            'static': {},
            'behavior': {'processes': [], 'summary': {}},
            'strings': [],
            'network': {},
            'dropped': [],
        }

        # 文件信息
        if report.file_info:
            res['target']['file'] = {
                'name': report.file_info.name,
                'size': report.file_info.size,
                'md5': report.file_info.md5,
                'sha256': report.file_info.sha256,
                'type': report.file_info.file_type,
            }

        # PE 信息
        if report.pe_info:
            pe = report.pe_info
            res['static']['pe'] = {
                'sections': [{'name': s.name, 'entropy': s.entropy,
                              'characteristics': s.characteristics} for s in pe.sections],
                'imports': [{'dll': i.dll, 'imports': [{'name': f} for f in i.functions]}
                           for i in pe.imports],
                'exports': [e.name for e in pe.exports],
                'resources': [r.name for r in pe.resources],
                'entrypoint': pe.entry_point,
                'imphash': pe.imphash,
                'timestamp': pe.compile_time,
            }
            if pe.suspicious_features:
                res['static']['pe_features'] = pe.suspicious_features
            if pe.tls_callbacks:
                res['static']['tls_callbacks'] = pe.tls_callbacks

        # 动态行为
        if report.dynamic:
            dyn = report.dynamic
            for p in dyn.processes_created:
                proc = {
                    'process_name': p.get('name', ''),
                    'pid': p.get('pid', 0),
                    'ppid': p.get('ppid', 0),
                    'command_line': p.get('cmdline', ''),
                    'calls': [],
                }
                # 模拟 API calls
                for ac in dyn.api_calls:
                    if ac.get('api'):
                        proc['calls'].append({
                            'api': ac['api'],
                            'category': ac.get('category', ''),
                        })
                res['behavior']['processes'].append(proc)

            res['behavior']['summary']['file_created'] = [f['path'] if isinstance(f, dict) else f for f in dyn.files_created]
            res['behavior']['summary']['file_written'] = dyn.files_modified
            res['behavior']['summary']['file_deleted'] = dyn.files_deleted
            _reg_created = list(dyn.registry_created or [])
            if dyn.sandbox_result and getattr(dyn.sandbox_result, 'registry_created', None):
                _reg_created = list(dict.fromkeys(_reg_created + list(dyn.sandbox_result.registry_created)))
            res['behavior']['summary']['regkey_written'] = _reg_created

        # 字符串
        if report.strings:
            res['strings'] = report.strings.suspicious_strings + report.strings.api_calls

        # 网络
        if report.network:
            res['network'] = {
                'tcp': [{'dst': f"{c.remote_addr}:{c.remote_port}",
                         'src': f"{c.local_addr}:{c.local_port}",
                         'dport': c.remote_port}
                        for c in report.network.tcp_connections],
                'dns': [d.domain for d in report.network.dns_queries],
                'http': [{'host': h.host, 'uri': h.path, 'method': h.method}
                        for h in report.network.http_requests],
            }

        return res


# ============================================================
#  CAPE 社区签名（Python 版，可直接移植）
# ============================================================

@SignatureRegistry.register
class AntiDebug_Signature(Signature):
    name = "antidebug_debugger_check"
    description = "检测到反调试行为（IsDebuggerPresent / CheckRemoteDebuggerPresent）"
    severity = 3
    categories = ["anti-debug", "anti-analysis"]
    mitre = ["T1622"]

    def run(self, results):
        indicators = []
        for proc in results.get('behavior', {}).get('processes', []):
            for call in proc.get('calls', []):
                if call.get('api') in ('IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                                        'NtQueryInformationProcess'):
                    indicators.append(call['api'])
        # 也检查字符串
        for s in results.get('strings', []):
            if any(k in s for k in ('IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                                      'NtQueryInformationProcess', 'DebugActiveProcess')):
                indicators.append(s)

        if indicators:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class AntiVM_Signature(Signature):
    name = "antivm_generic"
    description = "检测到反虚拟机行为"
    severity = 4
    categories = ["anti-vm", "anti-analysis"]
    mitre = ["T1497"]

    # ⚠ 移除 cpuid: 正常程序也调用 CPUID 指令检测 CPU 特性 (SSE/AVX 支持) —
    #   泛匹配导致误报; 其余 VM 供应商词是强反VM特征 (正常软件不会引用)
    VM_STRINGS = ['vmware', 'vbox', 'qemu', 'virtualbox', 'sandboxie',
                  'hyper-v', 'vmtoolsd', 'vboxservice', 'vboxguest', 'sbiedll',
                  'vmci', 'vmhgfs', 'qemu-ga', 'parallels tools']

    def run(self, results):
        hits = []
        for s in results.get('strings', []):
            for vm_s in self.VM_STRINGS:
                if vm_s in s.lower():
                    hits.append(s)
        # 检查导入
        pe_data = results.get('static', {}).get('pe', {})
        for imp in pe_data.get('imports', []):
            if imp['dll'].lower() in ('sbiedll.dll', 'vmcheck.dll'):
                hits.append(f"DLL: {imp['dll']}")
        if hits:
            self.data = hits[:15]
            return True
        return False


@SignatureRegistry.register
class Persistence_Schtasks(Signature):
    name = "persistence_schtasks"
    description = "创建计划任务实现持久化"
    severity = 4
    categories = ["persistence"]
    mitre = ["T1053.005"]

    def run(self, results):
        cmds = []
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '')
            if 'schtasks' in cmd.lower() and '/create' in cmd.lower():
                cmds.append(cmd[:200])
        if cmds:
            self.data = cmds
            return True
        return False


@SignatureRegistry.register
class Persistence_Registry(Signature):
    name = "persistence_registry_run"
    description = "注册表 Run 键持久化"
    severity = 3
    categories = ["persistence"]
    mitre = ["T1547.001"]

    def run(self, results):
        regs = results.get('behavior', {}).get('summary', {}).get('regkey_written', [])
        run_patterns = [r'\\Run\\', r'\\RunOnce\\', r'\\Windows\\CurrentVersion\\Run']
        hits = []
        for r in regs:
            for pat in run_patterns:
                if re.search(pat, r, re.IGNORECASE):
                    hits.append(r)
        if hits:
            self.data = hits
            return True
        return False


@SignatureRegistry.register
class DefenseEvasion_DefenderExclusion(Signature):
    name = "defense_evasion_defender_exclusion"
    description = "添加 Windows Defender 排除路径（防御规避）"
    severity = 4
    categories = ["defense-evasion"]
    mitre = ["T1562.001"]

    def run(self, results):
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '').lower()
            if 'defender' in cmd and 'exclusion' in cmd:
                self.data = [cmd[:200]]
                return True
        return False


@SignatureRegistry.register
class Inject_ProcessHollowing(Signature):
    name = "injection_process_hollowing"
    description = "可疑进程注入/镂空行为"
    severity = 4
    categories = ["injection"]
    mitre = ["T1055.012"]

    HOLLOWING_APIS = ['NtUnmapViewOfSection', 'VirtualAllocEx', 'WriteProcessMemory',
                      'CreateRemoteThread', 'NtCreateThreadEx', 'SetThreadContext',
                      'ResumeThread', 'QueueUserAPC', 'NtQueueApcThread']

    def run(self, results):
        apis_found = set()
        for proc in results.get('behavior', {}).get('processes', []):
            for call in proc.get('calls', []):
                if call.get('api') in self.HOLLOWING_APIS:
                    apis_found.add(call['api'])
        for s in results.get('strings', []):
            for api in self.HOLLOWING_APIS:
                if api in s:
                    apis_found.add(api)
        if len(apis_found) >= 2:
            self.data = list(apis_found)
            return True
        return False


@SignatureRegistry.register
class Infostealer_Keylogging(Signature):
    name = "infostealer_keylogging"
    description = "检测到键盘记录行为"
    severity = 3
    categories = ["infostealer", "collection"]
    mitre = ["T1056.001"]

    KEYLOG_APIS = ['SetWindowsHookEx', 'SetWindowsHookExA', 'SetWindowsHookExW',
                   'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState',
                   'UnhookWindowsHookEx', 'CallNextHookEx',
                   'GetRawInputData', 'GetForegroundWindow', 'GetWindowTextA',
                   'GetWindowTextW', 'AttachThreadInput']

    JOURNAL_APIS = ['SetWindowsHookEx.*JOURNALRECORD', 'SetWindowsHookEx.*JOURNALPLAYBACK',
                    'WH_JOURNALRECORD']

    def run(self, results):
        hits = set()
        is_journal = False
        _has_hook_api = False
        for proc in results.get('behavior', {}).get('processes', []):
            for call in proc.get('calls', []):
                if call.get('api') in self.KEYLOG_APIS:
                    hits.add(call['api'])
                if 'SetWindowsHookEx' in str(call.get('api', '')):
                    _has_hook_api = True
        for s in results.get('strings', []):
            for api in self.KEYLOG_APIS:
                if api in s:
                    hits.add(api)
            if 'SetWindowsHookEx' in s:
                _has_hook_api = True
            for japi in self.JOURNAL_APIS:
                if re.search(japi, s, re.IGNORECASE):
                    is_journal = True
                    hits.add('WH_JOURNALRECORD')

        # WH_JOURNALRECORD 必须与 SetWindowsHookEx 同现 (0xFFFFFFFF 是常见错误码/标志, 单独命中不算)
        if is_journal and _has_hook_api:
            self.data = list(hits)
            self.severity = 5
            self.description = "检测到 WH_JOURNALRECORD 系统级消息记录钩子（全量键盘/消息捕获）"
            self.categories.append("keylogger")
            return True
        if len(hits) >= 2:
            self.data = list(hits)
            return True
        return False


@SignatureRegistry.register
class Network_C2_HTTP(Signature):
    name = "network_c2_http"
    description = "检测到 HTTP C2 通信特征"
    severity = 3
    categories = ["network", "c2"]
    mitre = ["T1071.001"]

    def run(self, results):
        net = results.get('network', {})
        indicators = []
        # 检查异常端口
        for tcp in net.get('tcp', []):
            port = tcp.get('dport', 0)
            if port in (4444, 5555, 8080, 8443, 9090, 31337):
                indicators.append(f"suspicious_port:{port}")
        # 检查 HTTP
        for http in net.get('http', []):
            uri = http.get('uri', '')
            if any(k in uri.lower() for k in ('.php?', 'cmd=', 'exec=', 'upload', 'gate')):
                indicators.append(f"http_uri:{uri[:80]}")
        if indicators:
            self.data = indicators
            return True
        return False


@SignatureRegistry.register
class Dropper_ExecutableInTemp(Signature):
    name = "dropper_exe_in_temp"
    description = "在临时目录释放可执行文件"
    severity = 3
    categories = ["dropper"]
    mitre = ["T1105"]

    def run(self, results):
        files = results.get('behavior', {}).get('summary', {}).get('file_created', [])
        hits = []
        for f in files:
            fl = f.lower()
            if ('temp' in fl or 'tmp' in fl) and fl.endswith(('.exe', '.dll', '.scr', '.bat')):
                hits.append(f)
        if hits:
            self.data = hits[:10]
            return True
        return False


@SignatureRegistry.register
class Ransomware_ShadowCopyDelete(Signature):
    name = "ransomware_shadowcopy_delete"
    description = "尝试删除卷影副本（勒索软件特征）"
    severity = 5
    categories = ["ransomware"]
    mitre = ["T1490"]

    def run(self, results):
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '').lower()
            if 'vssadmin' in cmd and 'delete' in cmd and 'shadow' in cmd:
                self.data = [cmd[:200]]
                return True
            if 'wmic' in cmd and 'shadowcopy' in cmd and 'delete' in cmd:
                self.data = [cmd[:200]]
                return True
        return False


@SignatureRegistry.register
class SystemInfo_Discovery(Signature):
    name = "discovery_system_information"
    description = "搜集系统信息（计算机名/用户名/CPU/磁盘）"
    severity = 2
    categories = ["discovery"]
    mitre = ["T1082"]

    DISCOVERY_APIS = ['GetComputerName', 'GetUserName', 'GetSystemInfo',
                      'GetDiskFreeSpace', 'GetDiskFreeSpaceEx', 'GetLogicalDrives',
                      'GlobalMemoryStatusEx', 'GetSystemDirectory']

    def run(self, results):
        hits = set()
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '')
            for api in self.DISCOVERY_APIS:
                if api in cmd:
                    hits.add(api)
        for s in results.get('strings', []):
            for api in self.DISCOVERY_APIS:
                if api in s:
                    hits.add(api)
        if len(hits) >= 2:
            self.data = list(hits)
            return True
        return False


@SignatureRegistry.register
class CredentialAccess_DPAPI(Signature):
    name = "credential_dpapi_access"
    description = "访问 DPAPI 加密凭据（凭据窃取）"
    severity = 4
    categories = ["credential-access"]
    mitre = ["T1003"]

    def run(self, results):
        hits = set()
        for proc in results.get('behavior', {}).get('processes', []):
            for call in proc.get('calls', []):
                if call.get('api') in ('CryptUnprotectData', 'CryptProtectData'):
                    hits.add(call['api'])
        for s in results.get('strings', []):
            if 'CryptUnprotectData' in s or 'CryptProtectData' in s:
                hits.add(s)
        if hits:
            self.data = list(hits)
            return True
        return False


@SignatureRegistry.register
class Evasion_HiddenProcess(Signature):
    name = "evasion_hidden_window"
    description = "启动隐藏窗口进程（规避用户检测）"
    severity = 2
    categories = ["evasion"]
    mitre = ["T1564.003"]

    def run(self, results):
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '').lower()
            if ('/qn' in cmd or '/quiet' in cmd or '/silent' in cmd or
                'sw_hide' in cmd or 'create_no_window' in cmd):
                self.data = [cmd[:200]]
                return True
        return False


@SignatureRegistry.register
class Loader_DLLSideLoading(Signature):
    name = "loader_dll_sideloading"
    description = "DLL 侧加载（EXE/DLL 同级目录）"
    severity = 3
    categories = ["loader"]
    mitre = ["T1574.002"]

    def run(self, results):
        files = results.get('behavior', {}).get('summary', {}).get('file_created', [])
        exe_dirs = set()
        dll_dirs = set()
        for f in files:
            d = os.path.dirname(f) if os.path.dirname(f) else '.'
            if f.lower().endswith('.exe'):
                exe_dirs.add(d)
            if f.lower().endswith('.dll'):
                dll_dirs.add(d)
        common = exe_dirs & dll_dirs
        if common:
            self.data = list(common)
            return True
        return False


@SignatureRegistry.register
class SilverFox_OpenPGP_Payload(Signature):
    name = "silverfox_openpgp_payload"
    description = "检测到 SilverFox OpenPGP 加密载荷（C2 加密通信特征）"
    severity = 5
    categories = ["trojan", "c2", "silverfox"]
    mitre = ["T1573.001"]

    def run(self, results):
        indicators = []
        for s in results.get('strings', []):
            if 'BEGIN PGP' in s or 'OpenPGP' in s or 'PGP PUBLIC KEY' in s:
                indicators.append(s[:120])
        # 检查文件创建
        files = results.get('behavior', {}).get('summary', {}).get('file_created', [])
        for f in files:
            if 'nvml.bin' in f.lower() or 'pgp' in f.lower():
                indicators.append(f)
        if len(indicators) >= 1:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class SilverFox_Zlib_Compressed(Signature):
    name = "silverfox_zlib_compressed_payload"
    description = "检测到 SilverFox zlib 压缩数据载荷（内存注入载荷）"
    severity = 4
    categories = ["trojan", "loader", "silverfox"]
    mitre = ["T1027", "T1055"]

    ZLIB_PATTERNS = ['deflate', 'zlib', 'compress', 'inflate', 'uncompress']

    def run(self, results):
        indicators = []
        for s in results.get('strings', []):
            sl = s.lower()
            for pat in self.ZLIB_PATTERNS:
                if pat in sl:
                    indicators.append(s[:120])
                    break
        # PE sections 高熵
        pe_data = results.get('static', {}).get('pe', {})
        for sec in pe_data.get('sections', []):
            if sec.get('entropy', 0) > 7.2:
                indicators.append(f"High entropy section: {sec.get('name', '')} ({sec.get('entropy', 0):.2f})")
        if len(indicators) >= 2:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class SilverFox_MultiPayload(Signature):
    name = "silverfox_multi_payload"
    description = "检测到 SilverFox 多类型内存载荷（PE+zlib+OpenPGP 组合特征）"
    severity = 5
    categories = ["trojan", "silverfox"]
    mitre = ["T1055", "T1573.001", "T1027"]

    def run(self, results):
        pe_count = 0
        zlib_count = 0
        pgp_count = 0
        for s in results.get('strings', []):
            sl = s.lower()
            if 'this program cannot be run in dos mode' in sl or 'mz' in sl[:4]:
                pe_count += 1
            elif 'deflate' in sl or 'zlib' in sl or 'inflate' in sl:
                zlib_count += 1
            elif 'pgp' in sl or 'openpgp' in sl:
                pgp_count += 1
        # 检查 PE info
        pe_data = results.get('static', {}).get('pe', {})
        if pe_data.get('entrypoint'):
            pe_count += 1
        if len(pe_data.get('sections', [])) >= 4:
            pe_count += 1

        indicators = []
        if pe_count > 0:
            indicators.append(f"PE payload ({pe_count} indicators)")
        if zlib_count > 0:
            indicators.append(f"Zlib compressed ({zlib_count} indicators)")
        if pgp_count > 0:
            indicators.append(f"OpenPGP key ({pgp_count} indicators)")

        # 至少两个不同类型
        types_found = sum(1 for c in [pe_count, zlib_count, pgp_count] if c > 0)
        if types_found >= 2:
            self.data = indicators
            return True
        return False


@SignatureRegistry.register
class Injection_CrossProcessMemory(Signature):
    name = "injection_cross_process_memory"
    description = "跨进程非子进程内存写入（代码注入攻击）"
    severity = 5
    categories = ["injection", "process-injection"]
    mitre = ["T1055"]

    def run(self, results):
        indicators = []
        for proc in results.get('behavior', {}).get('processes', []):
            for call in proc.get('calls', []):
                api = call.get('api', '')
                if api in ('WriteProcessMemory', 'NtWriteVirtualMemory', 'ZwWriteVirtualMemory'):
                    indicators.append(f"{api} from {proc.get('process_name', '')}")
                elif api in ('VirtualProtectEx', 'NtProtectVirtualMemory'):
                    indicators.append(f"RemoteProtect: {api}")
        for s in results.get('strings', []):
            if 'WriteProcessMemory' in s or 'VirtualProtectEx' in s:
                indicators.append(s[:100])
        if len(indicators) >= 2:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class Injection_ReflectiveDLL(Signature):
    name = "injection_reflective_dll_loading"
    description = "疑似 DLL 反射加载（RW→RX 内存保护变更 + LoadLibrary 模式）"
    severity = 5
    categories = ["injection", "loader"]
    mitre = ["T1620", "T1055"]

    REFLECTIVE_APIS = ['VirtualProtect', 'NtProtectVirtualMemory', 'LoadLibraryA',
                       'LoadLibraryW', 'GetProcAddress', 'VirtualAlloc']

    def run(self, results):
        hits = set()
        for proc in results.get('behavior', {}).get('processes', []):
            for call in proc.get('calls', []):
                if call.get('api') in self.REFLECTIVE_APIS:
                    hits.add(call['api'])
        for s in results.get('strings', []):
            for api in self.REFLECTIVE_APIS:
                if api in s:
                    hits.add(api)
        # 至少需要 VirtualProtect + 加载类API
        has_protect = any(a in hits for a in ('VirtualProtect', 'NtProtectVirtualMemory'))
        has_load = any(a in hits for a in ('LoadLibraryA', 'LoadLibraryW', 'GetProcAddress'))
        if has_protect and has_load and len(hits) >= 3:
            self.data = list(hits)
            return True
        return False


@SignatureRegistry.register
class COM_SurrogateAbuse(Signature):
    name = "com_surrogate_abuse"
    description = "COM Surrogate (dllhost.exe) 滥用 — DCOM 横向渗透或 COM 劫持执行"
    severity = 4
    categories = ["execution", "lateral-movement"]
    mitre = ["T1559.001", "T1021.003"]

    def run(self, results):
        indicators = []
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '').lower()
            name = proc.get('process_name', '').lower()
            if 'dllhost.exe' in name and 'processid' in cmd:
                indicators.append(f"dllhost.exe /Processid:{cmd.split('{')[1][:8] if '{' in cmd else '???'}")
            elif 'clsid' in cmd or 'appid' in cmd:
                indicators.append(f"COM: {cmd[:100]}")
        # 多个 dllhost 实例是 DCOM 滥用的强烈信号
        dllhost_count = sum(1 for p in results.get('behavior', {}).get('processes', [])
                           if 'dllhost.exe' in p.get('process_name', '').lower())
        if dllhost_count >= 3:
            indicators.append(f"{dllhost_count} 个 dllhost.exe 实例（DCOM 批量执行）")
        if indicators:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class C2_WebSocket(Signature):
    name = "c2_websocket"
    description = "WebSocket 协议 C2 通信（持久化实时通道）"
    severity = 4
    categories = ["network", "c2"]
    mitre = ["T1071.001", "T1571"]

    def run(self, results):
        indicators = []
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '').lower()
            if 'websocket' in cmd or 'sec-websocket' in cmd:
                indicators.append(cmd[:200])
        for s in results.get('strings', []):
            sl = s.lower()
            if 'sec-websocket-key' in sl or 'sec-websocket-version' in sl:
                indicators.append(s[:100])
            elif 'ws://' in sl or 'wss://' in sl:
                indicators.append(s[:100])
        for http in results.get('network', {}).get('http', []):
            uri = http.get('uri', '').lower()
            host = http.get('host', '').lower()
            if 'websocket' in uri or 'upgrade' in uri:
                indicators.append(f"WebSocket: {host}{uri}")
        if indicators:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class Discovery_DiskSize(Signature):
    name = "discovery_disk_size_vm_check"
    description = "查询系统硬盘大小判定是否运行在 VM 中（GetDiskFreeSpaceEx）"
    severity = 3
    categories = ["discovery", "anti-vm"]
    mitre = ["T1082", "T1497.001"]

    DISK_APIS = ['GetDiskFreeSpaceEx', 'GetDiskFreeSpace', 'GetDriveType',
                'GetVolumeInformation', 'DeviceIoControl']

    def run(self, results):
        hits = set()
        for proc in results.get('behavior', {}).get('processes', []):
            for call in proc.get('calls', []):
                if call.get('api') in self.DISK_APIS:
                    hits.add(call['api'])
        for s in results.get('strings', []):
            for api in self.DISK_APIS:
                if api in s:
                    hits.add(api)
        if len(hits) >= 2:
            self.data = list(hits)
            return True
        return False


@SignatureRegistry.register
class UAC_Bypass_ConsentPrompt(Signature):
    name = "uac_bypass_consent_prompt_behavior"
    description = "修改 UAC ConsentPromptBehaviorAdmin 策略（UAC 绕过前置操作）"
    severity = 5
    categories = ["privilege-escalation", "defense-evasion"]
    mitre = ["T1548.002"]

    def run(self, results):
        indicators = []
        for s in results.get('strings', []):
            if 'ConsentPromptBehaviorAdmin' in s or 'EnableLUA' in s:
                indicators.append(s[:120])
        regs = results.get('behavior', {}).get('summary', {}).get('regkey_written', [])
        for r in regs:
            if 'ConsentPromptBehavior' in r or 'EnableLUA' in r:
                indicators.append(r)
        if indicators:
            self.data = indicators[:5]
            return True
        return False


@SignatureRegistry.register
class HostsFile_Tamper(Signature):
    name = "hosts_file_tamper"
    description = "篡改系统 Hosts 文件（DNS 劫持/重定向）"
    severity = 4
    categories = ["defense-evasion", "collection"]
    mitre = ["T1562.001", "T1557.001"]

    def run(self, results):
        indicators = []
        for s in results.get('strings', []):
            sl = s.lower()
            if 'hosts' in sl and ('etc' in sl or 'drivers' in sl or 'write' in sl or 'create' in sl):
                indicators.append(s[:120])
        files = results.get('behavior', {}).get('summary', {}).get('file_created', [])
        for f in files:
            if 'hosts' in f.lower():
                indicators.append(f)
        if indicators:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class PowerShell_RegistryPersistence(Signature):
    name = "powershell_registry_persistence"
    description = "PowerShell 添加注册表项实现持久化"
    severity = 4
    categories = ["persistence", "execution"]
    mitre = ["T1059.001", "T1547.001"]

    def run(self, results):
        indicators = []
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '').lower()
            if 'powershell' in cmd:
                if 'reg' in cmd and 'add' in cmd:
                    indicators.append(f"PS-RegAdd: {cmd[:150]}")
                elif 'set-itemproperty' in cmd or 'new-itemproperty' in cmd:
                    indicators.append(f"PS-RegProp: {cmd[:150]}")
                elif '-enc ' in cmd or 'encodedcommand' in cmd:
                    indicators.append(f"PS-Encoded: {cmd[:100]}")
                elif 'iex' in cmd or 'invoke-expression' in cmd:
                    indicators.append(f"PS-IEX: {cmd[:100]}")
        for s in results.get('strings', []):
            if 'powershell' in s.lower() and ('reg add' in s.lower() or 'set-itemproperty' in s.lower()):
                indicators.append(s[:120])
        if indicators:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class AntiForensics_DeleteOnReboot(Signature):
    name = "anti_forensics_delete_on_reboot"
    description = "标记文件关闭/重启时删除（反取证清理痕迹）"
    severity = 3
    categories = ["defense-evasion", "anti-forensics"]
    mitre = ["T1070.004"]

    def run(self, results):
        indicators = []
        for s in results.get('strings', []):
            if 'FILE_FLAG_DELETE_ON_CLOSE' in s or 'DeleteOnClose' in s:
                indicators.append(s[:120])
            elif 'MOVEFILE_DELAY_UNTIL_REBOOT' in s:
                indicators.append(s[:120])
            elif 'MoveFileEx' in s and 'DELAY' in s:
                indicators.append(s[:120])
        for proc in results.get('behavior', {}).get('processes', []):
            for call in proc.get('calls', []):
                api = call.get('api', '')
                if api in ('NtDeleteFile', 'DeleteFileW', 'MoveFileExW'):
                    indicators.append(f"{api} called by {proc.get('process_name', '')}")
        if indicators:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class WindowsUpdate_Sabotage(Signature):
    name = "windows_update_sabotage"
    description = "破坏 Windows Update 服务/DLL（物理隔离系统修复能力）"
    severity = 5
    categories = ["defense-evasion", "destruction"]
    mitre = ["T1562.001", "T1489"]

    UPDATE_SERVICES = ['wuauserv', 'UsoSvc', 'uhssvc', 'WaaSMedicSvc']
    UPDATE_DLLS = ['wuaueng']

    def run(self, results):
        indicators = []
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '').lower()
            name = proc.get('process_name', '').lower()
            if name in ('net.exe', 'net1.exe', 'sc.exe'):
                for svc in self.UPDATE_SERVICES:
                    if svc.lower() in cmd:
                        indicators.append(f"Stop: {svc}")
            if 'takeown' in cmd and any(d in cmd for d in self.UPDATE_DLLS):
                indicators.append("Takeown Windows Update DLL")
            if 'rename' in cmd and 'wuaueng' in cmd:
                indicators.append("Rename Windows Update DLL")
            if 'softwaredistribution' in cmd:
                indicators.append("Delete SoftwareDistribution")
            if 'noautoupdate' in cmd:
                indicators.append("Disable AutoUpdate registry")
        if len(indicators) >= 3:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class Schtasks_CreateRunDelete(Signature):
    name = "schtasks_one_shot_privilege_escalation"
    description = "计划任务一键三连（Create→Run→Delete）— SilverFox 标志性 SYSTEM 提权技术"
    severity = 5
    categories = ["privilege-escalation", "defense-evasion", "silverfox"]
    mitre = ["T1053.005", "T1548.002"]

    def run(self, results):
        creates = 0
        runs = 0
        deletes = 0
        defender_excl = False
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '')
            name = proc.get('process_name', '').lower()
            if 'schtasks' in name:
                if '/create' in cmd.lower():
                    creates += 1
                elif '/run' in cmd.lower():
                    runs += 1
                elif '/delete' in cmd.lower():
                    deletes += 1
            if 'defender' in cmd.lower() and 'exclusion' in cmd.lower():
                defender_excl = True

        # 至少 Create+Run+Delete 各 3 次以上 + Defender 排除 = SilverFox 确定性指纹
        if creates >= 3 and runs >= 3 and deletes >= 3 and defender_excl:
            self.data = [f"Schtasks 1-2-3 pattern: Create×{creates} Run×{runs} Delete×{deletes} + DefenderExclusion"]
            return True
        elif creates >= 1 and runs >= 1 and deletes >= 1 and defender_excl:
            self.data = ["Schtasks Create/Run/Delete pattern with Defender exclusion"]
            return True
        return False


@SignatureRegistry.register
class Permission_Manipulation(Signature):
    name = "permission_manipulation_icacls_takeown"
    description = "icacls/takeown 文件权限操纵（夺取所有权+修改ACL+移除继承）"
    severity = 4
    categories = ["defense-evasion", "privilege-escalation"]
    mitre = ["T1222.001", "T1564.004"]

    def run(self, results):
        indicators = []
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '').lower()
            name = proc.get('process_name', '').lower()
            if name in ('icacls.exe', 'icacls'):
                if '/inheritance:r' in cmd:
                    indicators.append("Remove inheritance")
                elif '/grant' in cmd and ('*s-1-1-0' in cmd or 'everyone' in cmd):
                    indicators.append("Grant Everyone full control")
                elif '/setowner' in cmd:
                    indicators.append(f"Change owner: {cmd[:100]}")
            if name in ('takeown.exe', 'takeown'):
                indicators.append(f"Take ownership: {cmd[:100]}")
        if len(indicators) >= 2:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class InnoSetup_Abuse(Signature):
    name = "innosetup_packaged_malware"
    description = "InnoSetup 安装框架被滥用（is-*.tmp 文件链 + msys64 伪路径）"
    severity = 4
    categories = ["loader", "packer"]
    mitre = ["T1105", "T1027"]

    def run(self, results):
        indicators = []
        files = results.get('behavior', {}).get('summary', {}).get('file_created', [])
        for f in files:
            fl = f.lower()
            if 'msys64' in fl:
                indicators.append(f"msys64 path: {f}")
            if 'is-' in fl and '.tmp' in fl:
                indicators.append(f"InnoSetup temp: {f}")
            if '_isetup' in fl:
                indicators.append(f"InnoSetup extract: {f}")

        for s in results.get('strings', []):
            if 'innosetup' in s.lower() or 'inno setup' in s.lower():
                indicators.append(s[:120])

        # msys64 + InnoSetup 临时文件是强特征
        has_msys = any('msys64' in i for i in indicators)
        has_inno = any('is-' in i for i in indicators)
        if has_msys and has_inno:
            self.data = indicators[:10]
            self.severity = 5
            return True
        if len(indicators) >= 3:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class Fake_SecuritySoftware(Signature):
    name = "fake_security_software_social_engineering"
    description = "伪装为安全软件的恶意程序（火绒/sys_HR/allapp 模式）"
    severity = 5
    categories = ["trojan", "social-engineering"]
    mitre = ["T1036.005", "T1204.002"]

    def run(self, results):
        indicators = []
        for s in results.get('strings', []):
            sl = s.lower()
            if 'sys_hr' in sl and 'allapp' in sl:
                indicators.append(f"Fake Huorong: {s[:120]}")
            elif 'allapp_x64' in sl:
                indicators.append(f"allapp packer: {s[:120]}")
            elif 'huorong' in sl or '火绒' in s:
                indicators.append(f"Huorong reference: {s[:120]}")

        files = results.get('behavior', {}).get('summary', {}).get('file_created', [])
        for f in files:
            fl = f.lower()
            if 'sys_hr' in fl or 'huorong' in fl:
                indicators.append(f"Fake security file: {f}")
            if '火绒' in f:
                indicators.append(f"Chinese security name: {f}")

        # allapp + HR 组合是强指纹
        has_hr = any('hr' in i.lower() or 'huorong' in i.lower() or '火绒' in i for i in indicators)
        has_allapp = any('allapp' in i.lower() for i in indicators)
        if has_hr and has_allapp:
            self.data = indicators[:10]
            return True
        if len(indicators) >= 2:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class Browser_Reconnaissance(Signature):
    name = "browser_reconnaissance"
    description = "探测已安装浏览器（信息窃取前置侦察）"
    severity = 3
    categories = ["discovery", "collection"]
    mitre = ["T1082", "T1555.003"]

    BROWSER_PATTERNS = ['chrome', 'firefox', 'mozilla', 'edge', 'brave',
                       'vivaldi', 'opera', 'safari', 'chromium']

    def run(self, results):
        indicators = []
        for s in results.get('strings', []):
            sl = s.lower()
            for browser in self.BROWSER_PATTERNS:
                if browser in sl:
                    # 排除正常系统路径中的无关匹配
                    if 'app paths' in sl or 'clients' in sl or 'startmenuinternet' in sl:
                        indicators.append(f"Browser registry: {browser}")
                    elif 'program files' in sl and browser in sl:
                        indicators.append(f"Browser path: {s[:100]}")
        if len(indicators) >= 3:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class NSIS_InstallerAbuse(Signature):
    name = "nsis_installer_abuse"
    description = "NSIS 自解压安装器被滥用（ns*.tmp + Nullsoft 框架）"
    severity = 4
    categories = ["loader", "packer"]
    mitre = ["T1105", "T1218"]

    def run(self, results):
        indicators = []
        files = results.get('behavior', {}).get('summary', {}).get('file_created', [])
        for f in files:
            if 'ns' in os.path.basename(f).lower()[:4] and f.lower().endswith('.tmp'):
                indicators.append(f"NSIS temp: {f}")
        for s in results.get('strings', []):
            if 'nullsoft' in s.lower() or 'nsis' in s.lower():
                indicators.append(f"NSIS string: {s[:120]}")
        if len(indicators) >= 2:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class AntiCompetitor_AVDetection(Signature):
    name = "anti_competitor_av_detection"
    description = "检测竞品安全软件进程（360/火绒/卡巴斯基等—恶意竞争排除）"
    severity = 4
    categories = ["defense-evasion", "discovery"]
    mitre = ["T1518.001"]

    COMPETITOR_APPS = ['360tray', '360tray.exe', 'hipstray', 'hipstray.exe',
                      'kavtray', 'avp.exe', 'msmpeng', 'nissrv']

    def run(self, results):
        indicators = []
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '').lower()
            for app in self.COMPETITOR_APPS:
                if app in cmd:
                    indicators.append(f"Competitor check: {app}")
        for s in results.get('strings', []):
            sl = s.lower()
            if '360tray' in sl or 'hipstray' in sl:
                indicators.append(f"AV name in strings: {s[:120]}")
        if indicators:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class FullDisk_DefenderExclusion(Signature):
    name = "full_disk_defender_exclusion"
    description = r"全盘添加 Defender 排除路径（C:\,D:\,E:\—极端防御规避）"
    severity = 5
    categories = ["defense-evasion"]
    mitre = ["T1562.001"]

    def run(self, results):
        indicators = []
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '').lower()
            if 'add-mppreference' in cmd and 'exclusionpath' in cmd:
                import re
                paths = re.findall(r'([A-Za-z]:\\)', cmd)
                if len(paths) >= 2:
                    indicators.append(f"Full disk exclusion: {paths}")
                elif len(paths) >= 1:
                    indicators.append(f"Root path exclusion: {paths}")
        if indicators:
            self.data = indicators[:10]
            self.severity = 5
            return True
        return False


@SignatureRegistry.register
class AntiDebug_PageGuard(Signature):
    name = "antidebug_page_guard"
    description = "创建 PAGE_GUARD 内存页（反逆向/反调试高级技术）"
    severity = 4
    categories = ["anti-debug", "anti-analysis"]
    mitre = ["T1622"]

    def run(self, results):
        indicators = []
        for s in results.get('strings', []):
            if 'PAGE_GUARD' in s or '0x100' in s or '0x101' in s:
                if 'VirtualAlloc' in s or 'VirtualProtect' in s or 'NtAllocate' in s:
                    indicators.append(s[:120])
        for proc in results.get('behavior', {}).get('processes', []):
            for call in proc.get('calls', []):
                api = call.get('api', '')
                if api in ('VirtualAlloc', 'VirtualProtect', 'NtAllocateVirtualMemory'):
                    if 'PAGE_GUARD' in str(call):
                        indicators.append(f"{api} + PAGE_GUARD")
        if indicators:
            self.data = indicators[:10]
            return True
        return False


@SignatureRegistry.register
class SilverFox_MSIDLLSideLoad(Signature):
    name = "silverfox_msi_dll_sideload"
    description = "检测到 SilverFox MSI 安装 + DLL 侧加载组合行为"
    severity = 5
    categories = ["trojan", "silverfox", "loader"]
    mitre = ["T1218.007", "T1574.002"]

    def run(self, results):
        has_msi = False
        has_dll_side = False
        has_defender_excl = False
        indicators = []

        # MSI 检测
        for proc in results.get('behavior', {}).get('processes', []):
            cmd = proc.get('command_line', '').lower()
            name = proc.get('process_name', '').lower()
            if 'msiexec' in cmd or 'msiexec' in name:
                has_msi = True
                indicators.append(f"MSI: {cmd[:120]}")
            if 'defender' in cmd and 'exclusion' in cmd:
                has_defender_excl = True
                indicators.append(f"DefenderExclusion: {cmd[:120]}")

        # DLL 侧加载
        files = results.get('behavior', {}).get('summary', {}).get('file_created', [])
        exe_dirs = set()
        dll_dirs = set()
        for f in files:
            fl = f.lower()
            if fl.endswith('.exe'):
                exe_dirs.add(os.path.dirname(f))
            if fl.endswith('.dll'):
                dll_dirs.add(os.path.dirname(f))
        if exe_dirs & dll_dirs:
            has_dll_side = True
            indicators.append(f"DLLSideLoad: {list(exe_dirs & dll_dirs)}")

        # 组合判定
        if (has_msi and has_dll_side) or (has_msi and has_defender_excl):
            self.data = indicators[:10]
            return True
        return False


# ============================================================
#  签名引擎
# ============================================================

class SignatureEngine:
    """社区签名引擎 — 运行所有注册签名"""

    def __init__(self):
        try:
            self.signatures = SignatureRegistry.get_all()
        except Exception:
            self.signatures = []
        logger.info(f"[+] 社区签名加载: {len(self.signatures)} 条")

    def run_all(self, report) -> List[Dict]:
        """对所有签名运行沙箱报告，返回命中列表"""
        try:
            results_data = SandboxAdapter.adapt(report)
        except Exception as e:
            logger.warning(f"签名适配失败: {e}")
            return []
        hits = []
        for sig in self.signatures:
            try:
                if sig.run(results_data):
                    hits.append(sig.get_data())
            except Exception:
                pass  # 单个签名失败不影响整体
        if hits:
            logger.info(f"[+] 签名命中: {len(hits)}/{len(self.signatures)}")
        return hits


# ============================================================
#  YARA 规则下载器
# ============================================================

YARA_RULE_SOURCES = [
    {
        'name': 'Yara-Rules/malware',
        'url': 'https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_SilverFox.yar',
        'optional': True,
    },
]


class YARARuleManager:
    """YARA 规则管理 — 下载、更新、加载"""

    def __init__(self, rules_dir: str = None):
        self.rules_dir = rules_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 'rules', 'yara'
        )
        os.makedirs(self.rules_dir, exist_ok=True)

    def download_community_rules(self) -> int:
        """下载社区规则包"""
        count = 0
        for src in YARA_RULE_SOURCES:
            try:
                dest = os.path.join(self.rules_dir, os.path.basename(src['url']))
                if os.path.exists(dest):
                    continue  # 已存在，跳过
                logger.info(f"  下载: {src['name']}")
                req = urllib.request.Request(src['url'])
                with urllib.request.urlopen(req, timeout=30) as response, open(dest, 'wb') as out:
                    shutil.copyfileobj(response, out)
                count += 1
            except Exception as e:
                if not src.get('optional'):
                    logger.warning(f"  下载失败 {src['name']}: {e}")
        return count

    def count_rules(self) -> int:
        """统计规则文件数"""
        if not os.path.isdir(self.rules_dir):
            return 0
        return len([f for f in os.listdir(self.rules_dir) if f.endswith(('.yar', '.yara'))])
