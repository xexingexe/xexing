#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
行为标签标准化引擎 — 将分散在各分析模块里的行为证据，统一提取为
VT 风格的原子化行为标签（checks-usb-bus / long-sleeps / calls-wmi …），
并映射到 MITRE ATT&CK。

设计目标（对照 VT 标签体系）：
  1. 标签原子化、标准化、可枚举 —— 一个行为一个标签名；
  2. 每条标签带 MITRE 编号 + 证据 + 置信度 + 证据来源（静态/动态/网络）；
  3. 复用程序已经采集到的证据（字符串 / 导入表 / API 监控 / 动态行为 /
     网络连接 / 高级行为结论），不重复造轮子，只做"标签化提取"这一层。
"""
import re
from typing import List, Dict, Optional

from logger import get_logger
from analyzer.models import AnalysisReport

logger = get_logger('analyzer.behavior_tags')


class BehaviorTagEngine:
    """行为标签引擎 — 从分析报告中提取标准化行为标签"""

    # =====================================================================
    # 标签定义：每条 = (标签名, MITRE, 类别, 匹配函数)
    # 匹配函数签名: fn(ctx) -> (命中bool, 证据字符串)
    # =====================================================================

    # 证据上下文：由 run_all() 统一构建，避免每个规则各自遍历
    class _Ctx:
        __slots__ = ('text', 'api_names', 'dyn_api_names', 'dyn_api_count',
                     'processes', 'cmdlines', 'created_paths', 'imports',
                     'network_remotes', 'dns_domains', 'advanced')

    # ---- 匹配器：预编译正则 + 上下文 ----

    @staticmethod
    def _has_api(api_names, *names) -> bool:
        return any(n in api_names for n in names)

    @staticmethod
    def _count_api(dyn_api_count, *names) -> int:
        return sum(dyn_api_count.get(n, 0) for n in names)

    # ---- 规则表 ----

    RULES = [
        # ===== 发现 / 环境探测 =====
        dict(tag='checks-usb-bus', mitre='T1120', category='discovery',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'setupdigetclassdevsw', 'setupdigetclassdevsa',
                 'setupdienumdeviceinfo', 'cm_get_device_interface_listw',
                 'getlogicaldrivesw', 'getlogicaldrivesa', 'getdrivetypew',
                 'getdrivetypea')
                 or ('usbstor' in c.text or 'setupapi' in c.text),
                 '外围设备/USB 总线枚举 (SetupDi*/GetDriveType/USBSTOR)')),
        dict(tag='checks-user-input', mitre='T1497.002', category='discovery',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'getcursorpos', 'getasynckeystate', 'getkeystate',
                 'getlastinputinfo', 'getforegroundwindow')
                 or ('getlastinputinfo' in c.text),
                 '用户输入/交互探测 (GetCursorPos/GetAsyncKeyState/GetLastInputInfo)')),
        dict(tag='checks-hostname', mitre='T1082', category='discovery',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'getcomputernamew', 'getcomputernamea', 'gethostname'),
                 '主机名查询 (GetComputerName/GetHostName)')),
        dict(tag='checks-username', mitre='T1033', category='discovery',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'getusernamew', 'getusernamea', 'getusernameexw')
                 or ('getusername' in c.text),
                 '当前用户名查询 (GetUserName)')),
        dict(tag='checks-host-uptime', mitre='T1497.003', category='discovery',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'gettickcount', 'gettickcount64')
                 or 'gettickcount' in c.text,
                 '系统运行时长查询 (GetTickCount/GetTickCount64)')),
        dict(tag='checks-process-count', mitre='T1082', category='discovery',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'createtoolhelp32snapshot', 'process32firstw',
                 'process32firsta', 'ntquerysysteminformation')
                 or 'createtoolhelp32snapshot' in c.text,
                 '进程枚举/数量统计 (CreateToolhelp32Snapshot/Process32First)')),
        dict(tag='checks-ram', mitre='T1082', category='discovery',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'globalmemorystatusex', 'globalmemorystatus',
                 'getphysicallyinstalledsystemmemory')
                 or 'globalmemorystatus' in c.text,
                 '物理内存/内存状态查询 (GlobalMemoryStatusEx)')),
        dict(tag='checks-resolution', mitre='T1497.001', category='discovery',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'getsystemmetrics', 'getdevicecaps', 'enumdisplaysettingsw')
                 or 'getsystemmetrics' in c.text,
                 '屏幕分辨率/显示参数查询 (GetSystemMetrics)')),
        dict(tag='checks-mac-address', mitre='T1082', category='discovery',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'getadaptersinfo', 'getadaptersaddresses',
                 'getiftable', 'iphlpapi')
                 or ('getadaptersinfo' in c.text or 'getadaptersaddresses' in c.text),
                 '网卡/MAC 地址枚举 (GetAdaptersInfo/GetAdaptersAddresses)')),
        dict(tag='reads-machine-guid', mitre='T1082', category='discovery',
             fn=lambda c: ('machineguid' in c.text
                           or 'cryptography\\guid' in c.text,
                           'MachineGuid 注册表指纹读取')),
        dict(tag='enumerates-processes', mitre='T1057', category='discovery',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'enumprocesses', 'enumprocessmodules',
                 'k32enumprocessmodules', 'process32firstw', 'process32firsta'),
                 '进程枚举 (EnumProcesses/Process32First)')),

        # ===== 反分析 / 防御规避 =====
        dict(tag='detect-debug-environment', mitre='T1622', category='defense-evasion',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'isdebuggerpresent', 'checkremotedebuggerpresent',
                 'ntqueryinformationprocess')
                 or ('isdebuggerpresent' in c.text or 'checkremotedebuggerpresent' in c.text),
                 '反调试检测 (IsDebuggerPresent/CheckRemoteDebuggerPresent)')),
        dict(tag='detect-sandbox', mitre='T1497.001', category='defense-evasion',
             fn=lambda c: ('sandboxie' in c.text or 'sbiedll' in c.text
                           or 'cuckoo' in c.text or 'wireshark' in c.text
                           or 'procmon' in c.text or 'sbiectrl' in c.text,
                           '沙箱/分析工具检测 (Sandboxie/Cuckoo/Procmon 等)')),
        dict(tag='detect-vm', mitre='T1497.001', category='defense-evasion',
             fn=lambda c: ('vmware' in c.text or 'virtualbox' in c.text
                           or 'vbox' in c.text or 'qemu' in c.text
                           or 'vmtools' in c.text or 'vboxservice' in c.text
                           or 'cpuid' in c.text,
                           '虚拟机检测 (VMware/VBox/QEMU/CPUID)')),
        dict(tag='long-sleeps', mitre='T1497.003', category='defense-evasion',
             fn=lambda c: (bool(re.search(
                 r'sleep\s*\(\s*\d{5,}\s*\)|ntdelayexecution.{0,20}\d{6,}'
                 r'|waitforsingleobject.{0,20}0x[0-9a-f]{5,}',
                 c.text, re.IGNORECASE)),
                 '长时间延迟 (Sleep/NtDelayExecution 大延迟拖慢分析)')),
        dict(tag='timing-evasion', mitre='T1497.003', category='defense-evasion',
             fn=lambda c: (('queryperformancecounter' in c.text
                            and 'sleep' in c.text)
                           or 'rdtsc' in c.text or '__rdtsc' in c.text,
                           '时间差/时间流速检测 (QPC+RDTSC 反沙箱)')),
        dict(tag='deletes-self', mitre='T1070.004', category='defense-evasion',
             fn=lambda c: (('file_flag_delete_on_close' in c.text)
                           or ('deleteself' in c.text)
                           or bool(re.search(r'cmd\.exe\s+/c\s+del\s+["\']?%~f0|/c\s+del\s+/f\s+/q', c.text, re.IGNORECASE)),
                           '自删除 (FILE_FLAG_DELETE_ON_CLOSE / del %~f0)')),
        dict(tag='disables-security', mitre='T1562.001', category='defense-evasion',
             fn=lambda c: (bool(re.search(
                 r'defender|windowsdefender|mpcmdrun|set-mppreference',
                 c.text, re.IGNORECASE)),
                 '禁用/规避安全产品 (Defender/MPCmdRun)')),

        # ===== 执行 / 载荷投递 =====
        dict(tag='executes-dropped-file', mitre='T1105', category='execution',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'createprocessw', 'createprocessa', 'winexec',
                 'shellexecutea', 'shellexecutew')
                 and any(p.endswith(('.exe', '.dll', '.scr', '.com', '.bat', '.ps1'))
                         for p in c.created_paths),
                 '释放并执行文件 (CreateProcess/WinExec + 新落盘可执行文件)')),
        dict(tag='calls-wmi', mitre='T1047', category='execution',
             fn=lambda c: ('iwbemservices' in c.text or 'execmethod' in c.text
                           or 'iwbemlocator' in c.text or 'wbem' in c.text
                           or 'wmic.exe' in c.text,
                           'WMI 调用 (IWbemServices::ExecMethod/IWbemLocator)')),
        dict(tag='runs-powershell', mitre='T1059.001', category='execution',
             fn=lambda c: ('powershell' in c.text or 'powershell.exe' in c.text
                           or '-enc ' in c.text.lower(),
                           'PowerShell 执行 (powershell/-enc 编码命令)')),
        dict(tag='runs-cmd', mitre='T1059.003', category='execution',
             fn=lambda c: ('cmd.exe' in c.text or 'cmd /c' in c.text.lower(),
                           'cmd.exe 命令执行')),
        dict(tag='uses-lolbin', mitre='T1218', category='execution',
             fn=lambda c: (bool(re.search(
                 r'rundll32\.exe|regsvr32\.exe|mshta\.exe|wmic\.exe|bitsadmin\.exe|'
                 r'certutil\.exe|msbuild\.exe|cscript\.exe|wscript\.exe|msiexec\.exe|'
                 r'forfiles\.exe|cmstp\.exe', c.text, re.IGNORECASE)),
                 'LOLBin 滥用 (rundll32/regsvr32/mshta/certutil 等)')),
        dict(tag='creates-mutex', mitre='T1480', category='execution',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'createmutexw', 'createmutexa', 'createmutexexw')
                 or 'createmutex' in c.text,
                 '互斥体创建 (CreateMutex 单实例/命名互斥)')),

        # ===== 注入 / 权限 =====
        dict(tag='injects-code', mitre='T1055', category='privilege-escalation',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'writeprocessmemory', 'createremotethread',
                 'virtualallocex', 'ntwritevirtualmemory', 'rtlcreateuserthread',
                 'queueuserapc', 'setthreadcontext', 'ntcreatethreadex'),
                 '跨进程代码注入 (WriteProcessMemory/CreateRemoteThread/APC)')),
        dict(tag='hollows-process', mitre='T1055.012', category='privilege-escalation',
             fn=lambda c: ('ntunmapviewofsection' in c.text
                           or 'zwunmapviewofsection' in c.text
                           or 'createprocessw' in c.api_names
                           and 'create_suspended' in c.text,
                           '进程镂空 (NtUnmapViewOfSection/CREATE_SUSPENDED)')),
        dict(tag='escalates-privileges', mitre='T1134', category='privilege-escalation',
             fn=lambda c: ('adjusttokenprivileges' in c.text
                           or 'lookupprivilegevalue' in c.text
                           or 'seDebugPrivilege' in c.text or 'sedebugprivilege' in c.text,
                           '特权提升 (AdjustTokenPrivileges/SeDebug)')),
        dict(tag='bypasses-uac', mitre='T1548.002', category='privilege-escalation',
             fn=lambda c: ('alwaysinstallelevated' in c.text
                           or 'fodhelper' in c.text or 'sdclt' in c.text
                           or 'computerdefaults' in c.text,
                           'UAC 绕过 (Fodhelper/SDCLT/AlwaysInstallElevated)')),

        # ===== 收集 / 窃取 =====
        dict(tag='captures-keystrokes', mitre='T1056.001', category='collection',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'setwindowshookexw', 'setwindowshookexa',
                 'getasynckeystate', 'getkeystate')
                 or 'wh_keyboard' in c.text.lower() or 'wh_journalrecord' in c.text.lower(),
                 '键盘记录 (SetWindowsHookEx WH_KEYBOARD/GetAsyncKeyState)')),
        dict(tag='captures-screen', mitre='T1113', category='collection',
             fn=lambda c: ('bitblt' in c.text or 'createdc' in c.text
                           and 'getdc' in c.text or 'capturescreen' in c.text.lower(),
                           '屏幕捕获 (BitBlt/GetDC/CreateDC)')),
        dict(tag='steals-cookies', mitre='T1539', category='collection',
             fn=lambda c: ('cookie' in c.text and ('sqlite' in c.text
                           or 'appdata' in c.text or 'chrome' in c.text
                           or 'firefox' in c.text),
                           '浏览器 Cookie 窃取 (SQLite/AppData/Chrome)')),
        dict(tag='steals-credentials', mitre='T1003', category='collection',
             fn=lambda c: ('lsass' in c.text or 'sam' in c.text
                           or 'dpapi' in c.text or 'credential' in c.text
                           or 'minidump' in c.text or 'mimikatz' in c.text,
                           '凭据窃取 (LSASS/SAM/DPAPI/Minidump)')),
        dict(tag='accesses-webcam', mitre='T1123', category='collection',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'capcreatecapturewindoww', 'vfw32')
                 or 'webcam' in c.text.lower(),
                 '摄像头访问 (capCreateCaptureWindow/VFW)')),
        dict(tag='accesses-microphone', mitre='T1123', category='collection',
             fn=lambda c: ('waveinopen' in c.api_names or 'waveinstart' in c.api_names
                           or 'mixeropen' in c.api_names,
                           '麦克风访问 (waveInOpen/mixerOpen)')),
        dict(tag='monitors-clipboard', mitre='T1115', category='collection',
             fn=lambda c: (BehaviorTagEngine._has_api(
                 c.api_names, 'openclipboard', 'getclipboarddata',
                 'addclipboardformatlistener'),
                 '剪贴板监控 (OpenClipboard/GetClipboardData)')),

        # ===== 持久化 =====
        dict(tag='persistence-run-key', mitre='T1547.001', category='persistence',
             fn=lambda c: ('currentversion\\run' in c.text
                           or 'runonce' in c.text,
                           '注册表 Run/RunOnce 键持久化')),
        dict(tag='persistence-scheduled-task', mitre='T1053.005', category='persistence',
             fn=lambda c: ('schtasks' in c.text or 'scheduledtask' in c.text.lower()
                           or 'itask' in c.text,
                           '计划任务持久化 (schtasks/ITaskScheduler)')),
        dict(tag='persistence-service', mitre='T1543.003', category='persistence',
             fn=lambda c: ('createservicew' in c.text or 'createservicea' in c.text
                           or 'sc.exe create' in c.text.lower(),
                           '服务持久化 (CreateService/sc.exe create)')),

        # ===== 破坏 =====
        dict(tag='encrypts-files', mitre='T1486', category='impact',
             fn=lambda c: ('cryptencrypt' in c.text or 'cryptencryptfile' in c.text
                           or 'bcryptencrypt' in c.text or 'ransom' in c.text.lower(),
                           '文件加密 (CryptEncrypt/BCryptEncrypt/勒索)')),
        dict(tag='deletes-shadow-copies', mitre='T1490', category='impact',
             fn=lambda c: ('vssadmin' in c.text or 'wmic shadowcopy' in c.text
                           or 'shadowcopy' in c.text,
                           '卷影副本删除 (vssadmin/wmic shadowcopy)')),
    ]

    @classmethod
    def run_all(cls, report: AnalysisReport) -> List[Dict]:
        """从报告提取标准化行为标签"""
        try:
            ctx = cls._build_context(report)
        except Exception as e:
            logger.debug(f"行为标签上下文构建失败: {e}")
            return []

        tags: List[Dict] = []
        for rule in cls.RULES:
            try:
                hit, evidence = rule['fn'](ctx)
            except Exception:
                hit, evidence = False, ''
            if hit:
                tags.append({
                    'tag': rule['tag'],
                    'mitre': rule['mitre'],
                    'category': rule['category'],
                    'confidence': 'high',
                    'evidence': evidence,
                })

        # ===== 网络 C2 标签（依赖连接/DNS 证据）=====
        cls._add_network_tags(ctx, tags)

        # 去重（同 tag 只保留一条，evidence 拼接）
        dedup: Dict[str, Dict] = {}
        for t in tags:
            if t['tag'] in dedup:
                continue
            dedup[t['tag']] = t
        result = list(dedup.values())

        # 按类别排序展示
        _cat_order = {'discovery': 0, 'defense-evasion': 1, 'execution': 2,
                      'privilege-escalation': 3, 'collection': 4, 'persistence': 5,
                      'impact': 6, 'c2': 7}
        result.sort(key=lambda x: _cat_order.get(x['category'], 9))
        logger.info(f"[BehaviorTags] 提取 {len(result)} 个标准化行为标签")
        return result

    @classmethod
    def _build_context(cls, report: AnalysisReport) -> '_Ctx':
        ctx = cls._Ctx()
        parts: List[str] = []
        api_names: set = set()
        dyn_api_names: set = set()
        dyn_api_count: Dict[str, int] = {}
        cmdlines: List[str] = []
        processes: List[str] = []
        created_paths: List[str] = []
        imports: List[str] = []
        network_remotes: List[str] = []
        dns_domains: List[str] = []
        advanced: List[str] = []

        # 字符串
        if report.strings:
            s = report.strings
            for attr in ('suspicious_strings', 'api_calls', 'file_paths',
                         'registry_keys', 'domains', 'urls', 'ips',
                         'cmdline_patterns', 'powershell_patterns'):
                for v in (getattr(s, attr, None) or []):
                    parts.append(str(v))
                    if attr in ('api_calls',):
                        api_names.add(str(v).lower())
            for v in (s.registry_keys or []):
                parts.append(str(v).lower())
            for v in (s.domains or []):
                dns_domains.append(str(v).lower())
            for v in (s.urls or []):
                parts.append(str(v).lower())

        # 导入表 API
        if report.pe_info and report.pe_info.imports:
            for imp in report.pe_info.imports:
                imports.append(imp.dll.lower())
                for fn in imp.functions:
                    api_names.add(fn.lower())
                    parts.append(fn.lower())

        # 动态 API 监控
        if report.api_monitor:
            for r in (report.api_monitor.call_records or []):
                name = getattr(r, 'api_name', '')
                if name:
                    nl = name.lower()
                    api_names.add(nl)
                    dyn_api_names.add(nl)
                    dyn_api_count[nl] = dyn_api_count.get(nl, 0) + 1

        # 动态行为
        if report.dynamic:
            d = report.dynamic
            for p in (d.processes_created or []):
                name = str(p.get('name', '')).lower()
                cmd = str(p.get('cmdline', '')).lower()
                processes.append(name)
                cmdlines.append(cmd)
                parts.append(name + ' ' + cmd)
            for f in (d.files_created or []):
                fp = f.get('path', f) if isinstance(f, dict) else f
                fp_l = str(fp).lower()
                created_paths.append(fp_l)
                parts.append(fp_l)
            for m in (d.mutexes or []):
                parts.append(str(m).lower())
            for w in (d.wmi_events or []):
                parts.append(str(w).lower())
            for svc in (d.services_created or []):
                parts.append(str(svc).lower())
            for st in (d.scheduled_tasks or []):
                parts.append(str(st).lower())

        # 高级行为结论（已归纳的反沙箱/反调试/C2等）
        if report.advanced_behavior:
            ab = report.advanced_behavior
            for attr in ('anti_sandbox', 'anti_vm', 'anti_debug', 'anti_analysis',
                         'timing_evasion', 'process_injection', 'process_hollowing',
                         'privilege_escalation', 'uac_bypass', 'credential_theft',
                         'keylogging', 'c2_communication', 'ransomware_indicators',
                         'lateral_movement'):
                for v in (getattr(ab, attr, None) or []):
                    advanced.append(str(v))
                    parts.append(str(v).lower())

        # 网络
        if report.network:
            n = report.network
            for c in (n.tcp_connections or []):
                network_remotes.append(f"{c.remote_addr}:{c.remote_port}")
            for c in (n.udp_connections or []):
                network_remotes.append(f"{c.remote_addr}:{c.remote_port}")
            for d in (n.dns_queries or []):
                dns_domains.append(str(d.domain).lower())

        ctx.text = '\n'.join(parts).lower()
        ctx.api_names = api_names
        ctx.dyn_api_names = dyn_api_names
        ctx.dyn_api_count = dyn_api_count
        ctx.processes = processes
        ctx.cmdlines = cmdlines
        ctx.created_paths = created_paths
        ctx.imports = imports
        ctx.network_remotes = network_remotes
        ctx.dns_domains = dns_domains
        ctx.advanced = advanced
        return ctx

    @classmethod
    def _add_network_tags(cls, ctx: '_Ctx', tags: List[Dict]):
        """网络 C2 相关标签 — 有外联即打标，具体评分由 network 模块负责"""
        if not ctx.network_remotes:
            return
        # 是否命中 C2 评分结果（report._c2_candidates 由 orchestrator 先算好）
        # 这里退化为：存在非本地外联即打 c2-communication 标签
        _public = [r for r in ctx.network_remotes
                   if not cls._is_local_addr(r.split(':')[0])]
        if _public:
            tags.append({
                'tag': 'c2-communication',
                'mitre': 'T1071',
                'category': 'c2',
                'confidence': 'medium',
                'evidence': f'外部网络通信 ({len(_public)} 个远端)',
            })
        if ctx.dns_domains:
            _susp = [d for d in ctx.dns_domains
                     if any(d.endswith(t) for t in ('.tk', '.ml', '.ga', '.cf', '.gq'))
                     or (len(d) > 30 and d.count('.') >= 2)]
            if _susp:
                tags.append({
                    'tag': 'suspicious-dns',
                    'mitre': 'T1568.002',
                    'category': 'c2',
                    'confidence': 'medium',
                    'evidence': f'可疑 DNS 查询 ({len(_susp)} 条)',
                })

    @staticmethod
    def _is_local_addr(addr: str) -> bool:
        try:
            import ipaddress
            ip = ipaddress.ip_address(addr.strip())
            return (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
        except Exception:
            return False
