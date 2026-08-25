#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
系统破坏行为检测引擎 — 勒索/擦除/破坏性恶意软件
"""
import re
from logger import get_logger
from analyzer.models import DestructionIndicators, StringAnalysis, PEInfo, DynamicBehavior

logger = get_logger('analyzer.destruction')


class DestructionDetector:
    """破坏行为检测器"""

    MBR_PATTERNS = [
        r'\\\\.\\PhysicalDrive\d*',
        r'vssadmin\s+delete\s+shadows',
        r'wmic\s+shadowcopy\s+delete',
        r'bcdedit\s+/delete\s*\{current\}',
        r'bcdedit\s+/set\s*\{default\}\s+bootstatuspolicy',
        r'wbadmin\s+delete\s+catalog',
        r'del\s+/f\s+/s\s+/q',
        r'rd\s+/s\s+/q',
        r'format\s+[a-zA-Z]:',
        r'diskpart\s+/s\s+.*clean',
        r'cipher\s+/w:',
        r'wevtutil\s+(cl|clear-log)',
    ]

    AV_PROCESS_NAMES = (
        r'360tray|360safe|360rp|zhudongfangyu|360sd|'
        r'HipsTray|hipsmain|hipsdaemon|hipslog|wsctrl|usysdiag|'
        r'avp|kavtray|kavstart|klnagent|avpui|'
        r'msmpeng|mssense|nisSrv|securityhealth|windefend|'
        r'mcshield|mctray|mcuicnt|masvc|mfefire|'
        r'sophos|savservice|sophosav|hitmanpro|'
        r'crowdstrike|csfalcon|csagent|'
        r'sentinelone|sentinelagent|sentinelhelper|'
        r'bdagent|vsserv|bdservicehost|bdredline|'
        r'egui|ekrn|eamonm|'
        r'mbam|mbamtray|mbamservice|mbae|'
        r'nvcoas|symcorp|rtvscan|smcgui|ccsvchst|'
        r'trendmicro|pccnt|ntrtscan|tmproxy|'
        r'fortiedr|forticlient|'
        r'cylance|cyoptics|'
        r'carbonblack|cb\.exe|repuxit|'
        r'elastic|endpoint|endgame|'
        r'fireeye|xagt|'
        r'tanium|taniumclient|'
        r'qualys|qagent|'
        r'deepinstinct|dia|'
        r'withsecure|fsgk32|fssm32|fsav32|'
        r'comodo|cmdagent|cis\.exe|'
        r'webroot|wrkrn|wrsa|'
        r'vipre|sbamsvc|sbrp|'
        r'secureage|trustport|'
        r'ahnlab|asdsvc|AhnSDSvc|v3svc|'
        r'klif|klwtblfs|klim6|klbg|'
        r'GUBootService|gucoresvc|'
        r'pavsrv|pavbckp|'
    )

    SYSTEM_KILL_PATTERNS = [
        # taskkill 终止杀软进程 — AV_PROCESS_NAMES 作为 alternation 在 re.compile 时已处理
        rf'taskkill\s+/f\s+/im\s+(?:{AV_PROCESS_NAMES})',
        rf'taskkill\s+/im\s+(?:{AV_PROCESS_NAMES})',
        # sc stop / config 禁用
        r'sc\s+stop\s+(winDefend|wuauserv|bits|windefend|msmpeng|sense|mpssvc|securityhealth|sophos|ekrn|bdredline|vsserv)',
        r'sc\s+config\s+(winDefend|wuauserv|windefend|msmpeng|sense|mpssvc)\s+start\s*=\s*disabled',
        r'sc\s+delete\s+(winDefend|wuauserv|windefend|msmpeng|sense)',
        # net stop
        r'net\s+stop\s+(winDefend|wuauserv|mpssvc|sense|securityhealth)',
    ]

    POWERSHELL_AV_KILL_PATTERNS = [
        r'Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$?(?:true|1)',
        r'Set-MpPreference\s+-DisableBehaviorMonitoring\s+\$?(?:true|1)',
        r'Set-MpPreference\s+-DisableBlockAtFirstSeen\s+\$?(?:true|1)',
        r'Set-MpPreference\s+-DisableIOAVProtection\s+\$?(?:true|1)',
        r'Set-MpPreference\s+-DisablePrivacyMode\s+\$?(?:true|1)',
        r'Set-MpPreference\s+-DisableScriptScanning\s+\$?(?:true|1)',
        r'Set-MpPreference\s+-SubmitSamplesConsent\s+\$?(?:NeverSend|2)',
        r'Set-MpPreference\s+-ExclusionPath',
        r'Set-MpPreference\s+-ExclusionExtension',
        r'Set-MpPreference\s+-ExclusionProcess',
        r'Stop-Process\s+-Name\s+',
        r'Stop-Process\s+-Force.*-Name\s+',
        r'Get-Process\s+.*\|\s*Stop-Process',
        r'Add-MpPreference\s+-Exclusion',
        r'Remove-MpPreference\s+-Exclusion',
        r'Set-Service\s+-Name\s+(winDefend|windefend|wuauserv|sense).*-Status\s+Stopped',
    ]

    WMI_AV_KILL_PATTERNS = [
        r'wmic\s+process\s+where\s+(?:name|description)=.*call\s+terminate',
        r'Get-WmiObject\s+Win32_Service.*StopService',
        r'Get-CimInstance\s+Win32_Service.*StopService',
        r'Invoke-WmiMethod\s+.*Terminate',
        r'Invoke-CimMethod\s+.*Terminate',
    ]

    REGISTRY_AV_DISABLE_PATTERNS = [
        # Defender 实时保护
        r'DisableRealtimeMonitoring\s*(?:=|\s)\s*(?:dword:)?0*1',
        r'DisableBehaviorMonitoring\s*(?:=|\s)\s*(?:dword:)?0*1',
        r'DisableBlockAtFirstSeen\s*(?:=|\s)\s*(?:dword:)?0*1',
        r'DisableIOAVProtection\s*(?:=|\s)\s*(?:dword:)?0*1',
        r'DisableScriptScanning\s*(?:=|\s)\s*(?:dword:)?0*1',
        r'DisableAntiSpyware\s*(?:=|\s)\s*(?:dword:)?0*1',
        r'DisableAntiVirus\s*(?:=|\s)\s*(?:dword:)?0*1',
        r'DisableRestrictedAdmin\s*(?:=|\s)\s*(?:dword:)?0*1',
        # 服务启动类型改为禁用 (兼容动态 diff 格式: "Services\\BITS | Start: DWORD:2 → DWORD:4")
        r'Start\s*:\s*(?:DWORD:)?\d+\s*(?:→|->)\s*(?:DWORD:)?0*4',
        r'Start\s*=\s*(?:dword:)?0*4',
        # 完整注册表路径格式 (静态/字符串扫描)
        r'\\\\SYSTEM\\\\.*Services\\\\.*\\\\Start\s*(?:=|\s)\s*(?:dword:)?0*4',
        # WDigest 凭据窃取
        r'UseLogonCredential\s*(?:=|\s)\s*(?:dword:)?0*1',
        r'WDigest.*UseLogonCredential',
    ]

    REGISTRY_DESTROY_PATTERNS = [
        r'SafeBoot\s+.*delete',
        r'DisableTaskMgr',
        r'DisableRegistryTools',
        r'EnableLUA\s+0',
        r'DisableCMD',
        r'HideSCAHealth',
        r'SecurityHealth',
    ]

    NETWORK_DESTROY_PATTERNS = [
        r'netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off',
        r'Set-NetFirewallProfile\s+-Enabled\s+False',
        r'netsh\s+firewall\s+set\s+opmode\s+disable',
        r'echo\s+.*>>.*\\drivers\\etc\\hosts',
    ]

    BYOVD_DRIVERS = [
        # 最常被滥用的漏洞驱动
        ('kprocesshacker.sys', 'Process Hacker 驱动 — 终止任意进程/加载未签名驱动'),
        ('gdrv.sys', 'GIGABYTE 驱动 (CVE-2018-19320) — 内核内存读写'),
        ('rtcore64.sys', 'MSI Afterburner 驱动 (CVE-2019-16098) — 内核内存读写'),
        ('aswArPot.sys', 'Avast Anti-Rootkit 驱动 — 内核内存操作'),
        ('aswSP.sys', 'Avast Self-Protection 驱动'),
        ('atillk64.sys', 'AMD GPU 驱动 — 任意物理内存读写'),
        ('bs_dhd.sys', 'BiosIt 驱动 — 任意 MSR 读写'),
        ('capcom.sys', 'Capcom 反作弊驱动 — 任意代码执行'),
        ('cpuz.sys', 'CPU-Z 驱动 (CVE-2017-15303) — 任意物理内存读写'),
        ('dbutil_2_3.sys', 'Dell DBUtil 驱动 (CVE-2021-21551) — 任意内核读写'),
        ('eio64.sys', 'ASUS EIO64 驱动 — 任意端口 I/O'),
        ('ene.sys', 'ENE 驱动 (CVE-2018-12038) — 任意物理内存读写'),
        ('gdrv.sys', 'GIGABYTE APP Center 驱动 — 内核内存访问'),
        ('hack_sys.sys', 'Heaven\'s Gate 漏洞利用驱动'),
        ('HwOs2Ec10.sys', '华为 HWOs2Ec10 驱动'),
        ('HwOs2Ec64.sys', '华为 HWOs2Ec64 驱动'),
        ('klif.sys', '卡巴斯基拦截驱动 — 可被绕过利用'),
        ('mimidrv.sys', 'Mimikatz 驱动 (mimidrv) — 内核级凭据窃取'),
        ('MsIo64.sys', 'MSI MsIo64 驱动 — 任意物理内存访问'),
        ('NalDrv.sys', 'Intel 网卡驱动漏洞 — 任意内核读写'),
        ('PassMark.sys', 'PassMark DirectIo 驱动 — 任意 I/O'),
        ('pcileech.sys', 'PCILeech DMA 攻击驱动'),
        ('phymem64.sys', 'Physical Memory 驱动 — 任意物理内存'),
        ('Povod.sys', 'Povod 驱动'),
        ('PROCEXP152.SYS', 'Process Explorer 旧版驱动 — 内核内存访问'),
        ('RTCore64.sys', 'MSI Afterburner 驱动变种 — 内核内存操作'),
        ('RtPort.sys', 'Realtek RtPort 驱动 — 任意 I/O 端口'),
        ('rwdrv.sys', 'RWEverything 驱动 — 任意硬件访问'),
        ('secbiz64.sys', 'Lenovo secbiz64 驱动'),
        ('secdrv.sys', 'Macrovision SafeDisc 驱动'),
        ('speedfan.sys', 'SpeedFan 驱动 (CVE-2007-5633) — 任意 MSR 读写'),
        ('TdkLib64.sys', 'Intel TDKLib64 驱动'),
        ('Tdlcmd.dll', 'TDL4 驱动加载 DLL'),
        ('tlfsdrv.sys', 'Tiny Firewall 驱动'),
        ('truesight.sys', 'Adlice TrueSight 驱动'),
        ('vboxdrv.sys', 'VirtualBox 驱动 — 被恶意利用加载'),
        ('ViGEm.sys', 'ViGEm 驱动'),
        ('vul_drv.sys', '通用漏洞驱动名'),
        ('WinFlash64.sys', 'ASUS WinFlash 驱动'),
        ('WinRing0.sys', 'WinRing0 驱动 — 任意端口 I/O'),
        ('WinRing0x64.sys', 'WinRing0 x64 驱动 — 任意端口 I/O'),
        ('WiseHD.sys', 'WiseHD 驱动'),
        ('zamguard64.sys', 'Zemana 反恶意软件驱动 (CVE-2018-6600) — 内核内存操作'),
        ('amp.sys', 'Cisco AMP 驱动'),
        ('bddci.sys', 'Bitdefender 驱动'),
    ]

    DRIVER_LOAD_PATTERNS = [
        r'SeLoadDriverPrivilege',
        r'ZwLoadDriver|NtLoadDriver|IOCreateDriver',
        r'CreateServiceW.*SERVICE_KERNEL_DRIVER',
        r'StartServiceW.*SERVICE_KERNEL_DRIVER',
        r'NtLoadDriver.*\\Registry\\Machine',
        r'sc\s+create\s+.*type\s*=\s*kernel',
        r'OpenSCManager.*SC_MANAGER_CREATE_SERVICE',
    ]

    def __init__(self):
        self._mbr = [re.compile(p, re.IGNORECASE) for p in self.MBR_PATTERNS]
        self._kill = [re.compile(p, re.IGNORECASE) for p in self.SYSTEM_KILL_PATTERNS]
        self._ps_kill = [re.compile(p, re.IGNORECASE) for p in self.POWERSHELL_AV_KILL_PATTERNS]
        self._wmi_kill = [re.compile(p, re.IGNORECASE) for p in self.WMI_AV_KILL_PATTERNS]
        self._reg_av = [re.compile(p, re.IGNORECASE) for p in self.REGISTRY_AV_DISABLE_PATTERNS]
        self._reg = [re.compile(p, re.IGNORECASE) for p in self.REGISTRY_DESTROY_PATTERNS]
        self._net = [re.compile(p, re.IGNORECASE) for p in self.NETWORK_DESTROY_PATTERNS]
        self._driver_load = [re.compile(p, re.IGNORECASE) for p in self.DRIVER_LOAD_PATTERNS]
        self._byovd_names = {name.lower(): desc for name, desc in self.BYOVD_DRIVERS}

    def analyze_combined(self, strings: StringAnalysis) -> DestructionIndicators:
        """综合分析 — 静态字符串 + 可选沙箱结果"""
        ind = DestructionIndicators()

        all_text = ' '.join(
            strings.suspicious_strings + strings.api_calls +
            strings.urls + strings.registry_keys + strings.file_paths
        )

        self._detect_from_text(all_text, ind)
        return self._calc_level(ind)

    def analyze_dynamic(self, dynamic: DynamicBehavior, existing: DestructionIndicators = None) -> DestructionIndicators:
        """从动态沙箱执行结果中检测破坏行为"""
        ind = existing or DestructionIndicators()

        # 0) 禁装杀软检测 — 银狐核心手法: 禁用杀软安装/更新必需服务
        #    (msiserver/BITS/wuauserv/UsoSvc/WaaSMedicSvc/TrustedInstaller 等)
        #    动态数据格式: registry_modified 条目 {'key': 'Services\\BITS',
        #    'values': 'Start: DWORD:2 → DWORD:3'} — 先于文本拼接单独解析!
        self._detect_av_install_block(dynamic, ind)

        # 0b) ETW 内核注册表写事件 → 并入 registry_modified 做统一检测
        #     (快照 diff 可能漏瞬时写删, ETW 全量捕获; 键格式 \\Registry\Machine\...)
        try:
            etw_evts = list(getattr(dynamic, '_etw_registry_events', None) or [])
            if etw_evts:
                merged = list(dynamic.registry_modified or [])
                seen = {str(r.get('key', '')) for r in merged if isinstance(r, dict)}
                for ev in etw_evts:
                    key = str(ev.get('key', ''))
                    if key in seen:
                        continue
                    merged.append(ev)
                    seen.add(key)
                dynamic.registry_modified = merged
        except Exception:
            pass

        dynamic_text_parts = []
        for p in dynamic.processes_created:
            name = p.get('name', '')
            cmd = p.get('cmdline', '')
            dynamic_text_parts.append(name)
            dynamic_text_parts.append(cmd)
        for f in dynamic.files_created:
            fpath = f['path'] if isinstance(f, dict) else f
            dynamic_text_parts.append(fpath)
        for r in (dynamic.registry_created or []):
            dynamic_text_parts.append(str(r))
        for r in (dynamic.registry_modified or []):
            if isinstance(r, dict):
                dynamic_text_parts.append(str(r.get('key', '')) + ' ' + str(r.get('values', '')))
            else:
                dynamic_text_parts.append(str(r))

        # 沙箱底层数据
        if dynamic.sandbox_result:
            sr = dynamic.sandbox_result
            for r in (sr.registry_created or []):
                dynamic_text_parts.append(str(r))
            for r in (sr.registry_modified or []):
                dynamic_text_parts.append(str(r))
            for p in (sr.child_processes or []):
                dynamic_text_parts.append(p.get('name', ''))
                dynamic_text_parts.append(p.get('cmdline', ''))

        all_text = ' '.join(dynamic_text_parts)
        self._detect_from_text(all_text, ind)

        self._detect_drivers_in_files(dynamic, ind, all_text)
        self._detect_av_in_processes(dynamic, ind)

        return self._calc_level(ind)

    def _detect_from_text(self, text: str, ind: DestructionIndicators):
        """从文本中检测所有模式"""
        # MBR/磁盘
        for pat in self._mbr:
            for m in pat.finditer(text):
                ind.mbr_write_commands.append(m.group(0)[:100])
        ind.mbr_access = bool(ind.mbr_write_commands)
        ind.shadow_copy_delete = any(
            'vssadmin' in s.lower() or 'shadowcopy' in s.lower()
            for s in ind.mbr_write_commands
        )

        # AV 终止 — 传统命令行
        for pat in self._kill:
            for m in pat.finditer(text):
                cmd = m.group(0)[:120]
                if any(name in cmd.lower() for name in ['windefend', 'msmpeng', 'sense', 'securityhealth']):
                    ind.edr_termination.append(cmd)
                else:
                    ind.av_termination.append(cmd)

        # PowerShell 杀软控制
        for pat in self._ps_kill:
            for m in pat.finditer(text):
                cmd = m.group(0)[:120]
                if 'stopprocess' in cmd.lower() or 'stop-process' in cmd.lower():
                    ind.av_termination.append(f'[PowerShell] {cmd}')
                else:
                    ind.defender_registry_disable.append(f'[PowerShell] {cmd}')

        # WMI 杀软终止
        for pat in self._wmi_kill:
            for m in pat.finditer(text):
                ind.av_termination.append(f'[WMI] {m.group(0)[:120]}')

        # 注册表禁用 Defender
        for pat in self._reg_av:
            for m in pat.finditer(text):
                ind.defender_registry_disable.append(m.group(0)[:100])

        # 注册表破坏
        for pat in self._reg:
            for m in pat.finditer(text):
                ind.security_registry_delete.append(m.group(0)[:100])

        # 防火墙 / hosts
        for pat in self._net:
            for m in pat.finditer(text):
                cmd = m.group(0)[:100]
                if 'firewall' in cmd.lower():
                    ind.firewall_disable = True
                if 'hosts' in cmd.lower():
                    ind.hosts_file_modify = True

        # 服务禁用 (sc config start=disabled)
        sc_config_pattern = re.compile(
            r'sc\s+config\s+(\S+)\s+start\s*=\s*disabled', re.IGNORECASE
        )
        for m in sc_config_pattern.finditer(text):
            ind.service_disable.append(m.group(0)[:120])

        # 驱动加载特权/API
        for pat in self._driver_load:
            for m in pat.finditer(text):
                ind.driver_privilege_escalation = True
                cmd = m.group(0)[:120]
                if cmd not in ind.dangerous_driver_load:
                    ind.dangerous_driver_load.append(cmd)

    def _detect_drivers_in_files(self, dynamic: DynamicBehavior, ind: DestructionIndicators, all_text: str):
        """在动态分析的文件操作中检测 BYOVD 漏洞驱动"""
        all_text_lower = all_text.lower()
        for drv_name, drv_desc in self._byovd_names.items():
            if drv_name in all_text_lower:
                entry = f'{drv_name} — {drv_desc}'
                if entry not in ind.dangerous_driver_load:
                    ind.dangerous_driver_load.append(entry)

    def _detect_av_in_processes(self, dynamic: DynamicBehavior, ind: DestructionIndicators):
        """检测是否在动态执行中尝试操作安全软件进程"""
        av_names = [
            '360tray', '360safe', 'zhudongfangyu', 'hipstray', 'hipsmain', 'hipsdaemon',
            'avp', 'kavtray', 'msmpeng', 'mssense', 'windefend', 'mcshield',
            'sophos', 'sentinel', 'bdagent', 'ekrn', 'egui', 'mbam', 'nvcoas',
            'rtvscan', 'ccsvchst', 'csfalcon', 'csagent',
        ]
        for p in dynamic.processes_created:
            cmd = (p.get('cmdline', '') + p.get('name', '')).lower()
            for av in av_names:
                if av in cmd and any(kw in cmd for kw in ['kill', 'stop', 'taskkill', 'terminat', 'delete', '/f']):
                    ind.av_termination.append(f'[Dynamic] 尝试终止安全软件进程: {p.get("cmdline", p.get("name", ""))[:120]}')
                    break

    # 杀软安装/更新必需服务 — 银狐禁装杀软的核心目标
    AV_INSTALL_BLOCK_SERVICES = {
        'msiserver': 'Windows Installer — MSI 安装包无法安装',
        'bits': 'BITS 后台传输 — 杀软安装包/更新无法下载',
        'wuauserv': 'Windows Update — 系统/杀软更新失败',
        'usosvc': 'Update Orchestrator — 更新编排器被禁用',
        'waasmedicsvc': 'WaaS 更新修复服务被禁用',
        'trustedinstaller': 'Windows Modules Installer — 组件安装被阻断',
        'dosvc': '传递优化 — 更新分发被禁用',
        'installservice': 'Microsoft Store 安装服务被禁用',
        'windefend': 'Windows Defender 引擎服务被禁用',
        'wscsvc': '安全中心服务被禁用',
        'securityhealthservice': '安全中心健康服务被禁用',
        'sense': 'Defender ATP 被禁用',
        'wdboot': 'Defender 启动驱动被禁用',
        'wdfilter': 'Defender 文件过滤驱动被禁用',
        'wdnisdrv': 'Defender NIS 驱动被禁用',
        'wdiservice': 'Defender NIS 服务被禁用',
    }

    def _detect_av_install_block(self, dynamic: DynamicBehavior, ind: DestructionIndicators):
        """检测禁装杀软: 动态注册表变更中 Services\\<名> 的 Start 被改为 3(手动)/4(禁用)

        数据来源: system_monitor 的注册表快照 diff (category='Service') 与
        ETW 内核注册表写事件 (Registry\\Machine\\...\\Services\\<名> 的 RegSetValue)。
        银狐典型操作: msiserver Start=2→4, BITS Start=2→3 — 导致杀软安装包无法下载/安装。
        """
        try:
            for r in (dynamic.registry_modified or []):
                key = str(r.get('key', '')) if isinstance(r, dict) else str(r)
                values = str(r.get('values', '')) if isinstance(r, dict) else ''
                svc_name = ''
                key_l = key.lower()
                # 格式1: 快照 diff "Services\\BITS"
                if key_l.startswith('services\\'):
                    svc_name = key.split('\\', 1)[-1].strip().lower()
                elif '\\services\\' in key_l:
                    svc_name = key_l.rsplit('\\services\\', 1)[-1].strip()
                # 格式2: ETW "\\Registry\Machine\SYSTEM\CurrentControlSet\Services\BITS"
                if not svc_name and '\\registry\\' in key_l:
                    m = re.search(r'\\services\\[^\\]+$', key_l)
                    if m:
                        svc_name = m.group(0).rsplit('\\', 1)[-1].strip()
                if not svc_name or svc_name not in self.AV_INSTALL_BLOCK_SERVICES:
                    continue
                # ETW 事件: values 形如 "RegSetValue | 进程: xxx (PID=1)" — 直接按 op 判定
                if r.get('type') == 'etw_write' or 'RegSetValue' in values:
                    ind.av_install_block.append(
                        f'{svc_name}: ETW内核写操作 — {self.AV_INSTALL_BLOCK_SERVICES[svc_name]}')
                    continue
                # 解析 "Start: DWORD:2 → DWORD:3" (旧值 → 新值)
                m = re.search(r'Start\s*:\s*(?:DWORD:)?(\w+)\s*(?:→|->)\s*(?:DWORD:)?(\w+)', values)
                if not m:
                    continue
                old_v, new_v = m.group(1), m.group(2)
                # 只标记"被改成手动/禁用" (3=手动 4=禁用), 2=自动 1=系统 0=引导 为正常
                if new_v in ('3', '4') and new_v != old_v:
                    entry = f'{svc_name}: Start {old_v}→{new_v} — {self.AV_INSTALL_BLOCK_SERVICES[svc_name]}'
                    ind.av_install_block.append(entry)
                    ind.service_disable.append(f'[Dynamic] {entry}')
            # 静态文本兜底: sc config / Set-Service 命令行禁用
            for p in dynamic.processes_created:
                cmd = str(p.get('cmdline', '') or '').lower()
                for svc, desc in self.AV_INSTALL_BLOCK_SERVICES.items():
                    if re.search(rf'(?:sc\s+config|set-service)\s+\S*{svc}\S*\s+.*(?:disabled|4)', cmd) \
                            or re.search(rf'sc\s+config\s+\S*{svc}\S*\s+start\s*=\s*4', cmd):
                        ind.av_install_block.append(f'{svc}: 命令行禁用 — {desc}')
                        break
        except Exception:
            pass

    def analyze_pe_imports(self, pe_info: PEInfo, existing: DestructionIndicators = None) -> DestructionIndicators:
        """从 PE 导入表检测"""
        ind = existing or DestructionIndicators()
        if not pe_info or not pe_info.is_pe:
            return ind

        DESTRUCTIVE = {
            # ⚠ 导入表只保留高信号/组合才有意义的条目:
            #   进程注入/内存写入/打开进程/CryptoAPI/通用注册表写/删除文件
            #   在正常软件里普遍存在, 单独出现不再计为破坏性行为。
            'TerminateProcess': ('av_termination', '进程终止'),
            'NtTerminateProcess': ('av_termination', 'NT 进程终止'),
            'ZwTerminateProcess': ('av_termination', 'ZW 进程终止'),
            'OpenSCManagerA': ('service_stop', '服务管理器'),
            'ControlService': ('service_stop', '服务控制'),
            'DeleteService': ('service_delete', '服务删除'),
            'ChangeServiceConfigA': ('service_disable', '修改服务配置'),
            'ChangeServiceConfigW': ('service_disable', '修改服务配置'),
            'NtLoadDriver': ('dangerous_driver_load', 'NT 加载驱动'),
            'ZwLoadDriver': ('dangerous_driver_load', 'ZW 加载驱动'),
            'NtSetSystemInformation': ('dangerous_driver_load', 'NT 加载驱动(系统信息)'),
        }

        for imp in pe_info.imports:
            for func in imp.functions:
                if func not in DESTRUCTIVE:
                    continue
                field, desc = DESTRUCTIVE[func]
                if field == 'raw_disk_access':
                    ind.raw_disk_access = True
                elif field == 'mbr_access':
                    ind.mbr_access = True
                elif field == 'service_stop':
                    ind.service_stop.append(f'{func}: {desc}')
                elif field == 'service_delete':
                    ind.service_delete.append(f'{func}: {desc}')
                elif field == 'service_disable':
                    ind.service_disable.append(f'{func}: {desc}')
                elif field == 'security_registry_delete':
                    ind.security_registry_delete.append(f'{func}: {desc}')
                elif field == 'system_file_delete':
                    ind.system_file_delete.append(f'{func}: {desc}')
                elif field == 'av_termination':
                    ind.av_termination.append(f'{func}: {desc}')
                elif field == 'dangerous_driver_load':
                    ind.dangerous_driver_load.append(f'{func}: {desc}')
                    ind.driver_privilege_escalation = True

        return self._calc_level(ind)

    def _calc_level(self, ind: DestructionIndicators) -> DestructionIndicators:
        # 去重（多个分析阶段可能重复添加）
        list_fields = [
            'mbr_write_commands', 'disk_wipe_commands', 'backup_delete_commands',
            'system_file_delete', 'system_file_rename', 'av_termination',
            'edr_termination', 'security_registry_delete', 'uac_bypass_attempts',
            'service_stop', 'service_delete', 'service_disable',
            'defender_registry_disable', 'av_install_block', 'dangerous_driver_load',
        ]
        for attr in list_fields:
            lst = getattr(ind, attr, None)
            if isinstance(lst, list) and lst:
                setattr(ind, attr, list(dict.fromkeys(lst)))

        score = 0
        if ind.mbr_access: score += 25
        if ind.raw_disk_access: score += 25
        if ind.shadow_copy_delete: score += 15
        score += len(ind.av_termination) * 15 + len(ind.edr_termination) * 15
        score += len(ind.defender_registry_disable) * 12
        score += len(ind.av_install_block) * 15  # 禁装杀软 — 银狐核心持久对抗手法
        score += len(ind.dangerous_driver_load) * 10
        score += len(ind.security_registry_delete) * 8
        score += len(ind.service_stop) * 8
        score += len(ind.service_disable) * 8
        score += len(ind.mbr_write_commands) * 3

        ind.total_indicators = score
        if score >= 75:
            ind.destruction_level = 'destructive'
            ind.summary = '🔴 破坏性恶意软件 — 全面系统攻击'
        elif score >= 40:
            ind.destruction_level = 'high'
            ind.summary = '🟠 高度破坏性 — 可能勒索/擦除'
        elif score >= 15:
            ind.destruction_level = 'medium'
            ind.summary = '🟡 中度破坏性 — 尝试禁用安全软件'
        elif score >= 1:
            ind.destruction_level = 'low'
            ind.summary = '🟢 低度破坏性'
        else:
            ind.destruction_level = 'none'
            ind.summary = '未检测到系统破坏行为'

        return ind
