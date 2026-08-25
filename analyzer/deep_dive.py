#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""深度追踪分析 (DeepDive)

对动态分析全程收集的数据做长时程深度关联分析：
  - 进程链还原（父子关系/存活时长/关键进程）
  - 释放文件逐个代码深析（PE/驱动/脚本：导出表/签名/字符串/YARA/IoC/家族）
  - 内存载荷代码深析（反射加载 PE 的导出表、解密字符串、窃密特征码扫描）
  - 网络外联画像（目标聚合 / C2 候选判定 / DNS / HTTP）
  - 运行环境校验检测（目标进程检测：wegame/rail/xclient/QQ 等）
  - 驱动加载链（白驱动黑驱动/数字签名）
  - 数据窃取线索（凭证/浏览器/钱包特征码）
  - 攻击链叙事式编排 + 综合结论

不重新执行样本，仅对现有报告数据做深度关联分析。
"""
import os
import re
import time
import struct
import logging
from typing import List, Optional

from analyzer.models import (
    AnalysisReport, DeepDiveReport, DeepDiveFile, DeepDiveMemoryCode,
    DeepDiveProcessNode, DeepDiveNetwork,
)

logger = logging.getLogger(__name__)

# ============ 窃密/对抗特征码库 ============
# 类别 → (正则模式, 描述) — 用于扫描内存 dump / 文件字符串
THEFT_SIGNATURES = [
    ('credential_qq',      r'"uin"\s*[:=]',          'QQ号字段 (JSON "uin")'),
    ('credential_qq',      r'stpass',                'QQ会话密码 (stpass)'),
    ('credential_qq',      r'p_skey',                'QQ网页密钥 (p_skey)'),
    ('credential_qq',      r'skey\b',                'QQ会话密钥 (skey)'),
    ('credential_generic', r'pass(?:word|wd|_hash)?\s*[:=]', '口令字段 (password/passwd)'),
    ('credential_generic', r'token\s*[:=]',          '会话令牌 (token)'),
    ('credential_generic', r'autologin',             '自动登录凭证'),
    ('credential_generic', r'credential',            '凭证库引用'),
    ('credential_generic', r'session(?:key|id)?\s*[:=]', '会话标识'),
    ('credential_generic', r'"salt"\s*[:=]',         '盐值字段'),
    ('credential_generic', r'uid\s*[:=]',            '用户ID字段'),
    ('browser',            r'Login Data',            '浏览器登录数据'),
    ('browser',            r'Web Data',              '浏览器表单数据'),
    ('browser',            r'Cookies',               '浏览器Cookie'),
    ('browser',            r'Local State',           '浏览器加密主密钥'),
    ('wallet',             r'wallet|seed phrase|keystore|private key', '加密钱包'),
    ('win11_recall',       r'CoreAIPlatform|AIBackend|WebExperienceHost', 'Win11 Recall/AI 数据'),
    ('win11_recall',       r'SnapDB|Recall',         'Win11 记忆搜索 (Recall) 数据库'),
    ('win11_recall',       r'Copilot|AIShell',       'Win11 Copilot/AI 组件'),
    ('win11_cred',         r'WiFiSvc|\.wifi|WlanProfileManager', 'WiFi 凭据 (Win11 WLAN)'),
    ('target_process',     r'wegame',                '目标进程: WeGame'),
    ('target_process',     r'rail\.exe',             '目标进程: WeGame Rail'),
    ('target_process',     r'xclient|xcomw|xcomu|ACE-Tray', '目标进程: 网吧安全程序'),
    ('target_process',     r'QQ\.exe|TIM\.exe|WeChat', '目标进程: 聊天软件'),
    ('target_process',     r'steam|battle\.net|epic', '目标进程: 游戏平台'),
    ('target_process',     r'wefault|mgodb',          '目标进程: 合法软件伪装'),
    ('keylog',             r'WH_KEYBOARD|GetAsyncKeyState', '键盘记录'),
    ('screen_capture',     r'BitBlt|GetDC\b|CreateCompatibleBitmap', '屏幕截取'),
    ('anti_debug',         r'IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess', '反调试'),
    ('anti_debug',         r'DebugActiveProcess|CreateProcessA.*DEBUG', '调试器检测'),
    ('injection',          r'VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|SetWindowsHookEx', '进程注入'),
    ('kernel_read',        r'KeStackAttachProcess|MmCopyVirtualMemory', '内核读进程内存'),
    ('driver',             r'DriverEntry|IoCreateDevice|PsCreateSystemThread', '驱动入口/设备创建'),
    ('driver',             r'DeviceIoControl',       '设备控制 (驱动通信)'),
    ('driver',             r'MmGetSystemRoutineAddress|ZwQuerySystemInformation', '内核API解析'),
    ('crypto',             r'RC4|Rijndael|AES-?128|AES-?256|3DES', '对称加密算法'),
    ('anti_analysis',      r'\\\\\.\\',          '设备对象路径 (\\\\.\\xxx)'),
]

# 进程名校验特征（环境检测：检查目标进程是否运行）
ENV_CHECK_PROCESSES = [
    r'wegame', r'rail\.exe', r'xclient', r'xcomw', r'xcomu', r'ACE-Tray',
    r'QQ\.exe', r'TIM\.exe', r'WeChat', r'steam', r'battle\.net',
]

# 环境检测相关 API（Frida 记录的调用名）
ENV_CHECK_APIS = [
    'CreateToolhelp32Snapshot', 'Process32FirstW', 'Process32NextW',
    'FindWindowW', 'FindWindowA', 'EnumWindows', 'GetForegroundWindow',
    'GetWindowTextW', 'OpenProcess',
]

# ============ 行为深析特征库（对照真实样本分析报告） ============
# (类别, 名称, [正则特征], 说明) — 特征匹配: 字符串 + 反混淆预览 + 文件内容
BEHAVIOR_SIGNATURES = [
    ('av_detection', '杀软进程检测',
     [r'360tray\.exe', r'360safe', r'360sd\.exe', r'HipsDaemon\.exe', r'Huorong',
      r'qqpctray\.exe', r'kwatch\.exe', r'avp\.exe', r'kavsvc', r'bdagent\.exe',
      r'msmpeng\.exe', r'egui\.exe', r'ekrn\.exe'],
     '检测安全软件进程（如 360tray.exe / HipsDaemon.exe），按结果调整行为'),
    ('defender_disable', '关闭 Windows Defender',
     [r'Add-MpPreference', r'ExclusionPath', r'DisableRealtimeMonitoring',
      r'Set-MpPreference', r'Get-MpComputerStatus', r'Defender\s*:\s*(?:Disable|Off|0)',
      r'MpPreference'],
     '通过 PowerShell 修改 Defender 策略（如将 C 盘整盘加入排除路径）'),
    ('uac_disable', '禁用 UAC 用户账户控制',
     [r'EnableLUA', r'ConsentPromptBehaviorAdmin', r'PromptOnSecureDesktop',
      r'UAC\b'],
     '修改 Policies\\System 注册表禁用 UAC（EnableLUA=0 等 3 个键值）'),
    ('privilege', 'SeDebugPrivilege 提权',
     [r'SeDebugPrivilege', r'AdjustTokenPrivileges', r'SeBackupPrivilege',
      r'OpenProcessToken', r'LookupPrivilegeValue'],
     '获取调试/备份特权，用于读取其他进程内存或防终止'),
    ('break_on_termination', '进程防终止保护',
     [r'ProcessBreakOnTermination', r'BreakOnTermination'],
     '设置关键进程保护，阻止杀软终止恶意进程'),
    ('scheduled_rpc', '计划任务 RPC 创建',
     [r'atsvc', r'\\pipe\\atsvc', r'TaskScheduler', r'ITaskScheduler'],
     '绕过 schtasks 直接调用任务计划 RPC 接口创建持久化任务'),
    ('shortcut', '快捷方式伪装',
     [r'\.lnk', r'IShellLink', r'KOOK\.lnk', r'QQ\.lnk'],
     '创建伪装快捷方式（如 KOOK.lnk 指向恶意程序）'),
    ('startup_redirect', '启动目录重定向',
     [r'Shell Folders', r'\\Startup\b'],
     '修改 Explorer Shell Folders\\Startup 指向攻击者目录'),
    ('keylogger', '键盘记录',
     [r'DirectInput8.*c_dfDIKeyboard', r'c_dfDIKeyboard', r'DISCL_BACKGROUND',
      r'SetWindowsHookEx.*WH_KEYBOARD', r'WH_KEYBOARD_LL',
      r'GetAsyncKeyState.*GetKeyState'],
     'DirectInput/钩子键盘记录（后台静默捕获按键）'),
    ('clipboard', '剪贴板监控',
     [r'AddClipboardFormatListener', r'OpenClipboard.*SetClipboardData',
      r'GetClipboardData.*CF_UNICODETEXT', r'OpenClipboard.*EmptyClipboard',
      r'CF_UNICODETEXT.*GetClipboardData'],
     '监控剪贴板内容（复制的口令/钱包地址等）'),
    ('injection_guard', '注入守护进程',
     [r'svchost\.exe', r'CREATE_SUSPENDED', r'CreateRemoteThread',
      r'VirtualAllocEx', r'WriteProcessMemory', r'ResumeThread'],
     '注入 svchost.exe 等系统进程实现进程守护（被杀后自动重启）'),
    ('screenshot', '屏幕截取',
     [r'BitBlt.*CreateCompatibleBitmap', r'GetWindowDC.*BitBlt',
      r'AcquireNextFrame', r'CreateDXGIFactory.*AcquireNextFrame',
      r'PrintWindow'],
     'DXGI/GDI 截取屏幕画面'),
    ('anti_eventlog', '清除事件日志',
     [r'ClearEventLog', r'ElfClearEventLogFile', r'wevtutil\s+cl\s', r'Clear-EventLog',
      r'wevtutil\s+clear-log'],
     '清除 Application/Security/System 事件日志（反取证）'),
    ('network_lateral', '横向移动/反向连接',
     [r'WNetAddConnection', r'NetUseAdd', r'psexec', r'wmic\s+process',
      r'net\s+user\s', r'net\s+share'],
     '网络共享/远程命令（横向移动或反向连接特征）'),
    ('polymorphic', '多态/免杀改造',
     [r'UPX0', r'UPX1', r'aspack', r'UPX!\s', r'\.UPX'],
     '壳/加密特征（UPX、ASPack 等）'),
    ('doh', 'DNS-over-HTTPS 解析 C2',
     [r'/resolve\?name=', r'type=A', r'DoH', r'dns\.google\.com/resolve',
      r'cloudflare-dns\.com', r'223\.5\.5\.5', r'8\.8\.8\.8/resolve'],
     '通过 DoH (如 223.5.5.5 阿里 DNS) 动态解析 C2 域名'),
    ('heartbeat', '心跳机制',
     [r'heartbeat', r'ping\s+interval', r'keepalive', r'send\s+beacon'],
     '定期心跳保活（命令 ID 0x09 发送 0x15 等模式）'),
    ('command_table', '远程命令处理表',
     [r'screenshot.*keylog', r'shell\b.*upload', r'keylog.*upload',
      r'plugin.*download', r'update\s+c2', r'exitprocess.*screenshot'],
     '内置远程命令分发表（截屏/文件管理/终端/插件等）'),
]

# 杀软进程清单（用于进程链标记）
AV_PROCESS_NAMES = ['360tray', '360safe', '360sd', 'hipsdaemon', 'huorong',
                    'qqpctray', 'kwatch', 'kav', 'avp', 'bdagent', 'msmpeng',
                    'egui', 'ekrn', 'avgnt', 'nis', 'mcshield', 'savservice']

# ============ HTA/脚本投递 & 白加黑 & 云服务 C2 特征库 ============
# (类别, 名称, [正则特征], 说明)
HTA_SIGNATURES = [
    ('hta_hidden', 'HTA 隐藏启动',
     [r'<HTA:APPLICATION', r'SHOWINTASKBAR\s*=\s*"no"', r'WindowState\s*=\s*"hidden"',
      r'INNERBORDER', r'APPLICATIONNAME'],
     'HTA(HTML Application) 隐藏窗口/任务栏启动 — 用户无感知执行'),
    ('hta_antidebug_js', 'HTA 反调试 JS',
     [r'moveTo\(\s*-3000', r'Function\(\s*["\']Function', r'console\.log\s*=\s*function',
      r'debugger\s*;\s*debugger'],
     '重写 console / 窗口移出屏幕 / Function 递归构造 debugger — 反调试对抗'),
    ('hta_activex_dotnet', 'ActiveX 注册 .NET 程序集',
     [r'ActiveXObject', r'\.NETFrameWork', r'System\.Reflection', r'mscorlib',
      r'Microsoft\.JScript', r'COM\.SafeArray'],
     '通过 ActiveXObject 加载嵌入的 .NET 程序集（可信解密器模式）'),
    ('embedded_base64', '嵌入 Base64 载荷',
     [r'[A-Za-z0-9+/]{4000,}==?\s*[\'")]', r'fromBase64', r'base64\s*decode'],
     '脚本内嵌大段 Base64（可解码为 PE/ZIP — 载荷隔离静态分析）'),
    ('zip_package', '魔改 ZIP 分块解密',
     [r'package[123]', r'UnZipFilesFix', r'SharpZipLib', r'ZipInputStream',
      r'ExtractToFile', r'ZipFile'],
     '魔改 ZIP 库按 package1/2/3 分块解密释放（硬编码密钥）'),
    ('hardcoded_key', '硬编码解密密钥',
     [r'password\s*=\s*["\'][^"\']{3,}', r'passwd\s*=\s*["\']', r'decrypt\s*\([^)]*key',
      r'secret\s*=\s*["\']', r'key\s*=\s*["\'][A-Za-z0-9]{6,}'],
     '脚本/C# 程序集中硬编码密钥 — 静态可提取'),
    ('sideloading', '白加黑 DLL 侧加载',
     [r'LIBEAY32\.dll', r'libeay32', r'libssl-?1[_-]1[_-]x64\.dll', r'ssleay32\.dll',
      r'version\.dll', r'dxgi\.dll', r'dbghelp\.dll', r'netutils\.dll',
      r'wlanapi\.dll', r'cryptbase\.dll', r'd3d11\.dll', r'winmm\.dll'],
     '释放仿冒 DLL（OpenSSL/系统库名）— 白加黑侧加载（无签名 DLL 被合法程序加载）'),
    ('vmp_packed', 'VMProtect 加壳',
     [r'vmp0', r'vmp1', r'VMProtect', r'\.vmp', r'vmp2'],
     'VMProtect 加壳特征 — 强代码虚拟化保护（常见于银狐/远控）'),
    ('cloud_c2', '云服务滥用投递/C2',
     [r'note\.youdao\.com', r'shareKey', r'yws/api', r'raw\.githubusercontent\.com',
      r'gitee\.com', r'pastebin\.com', r'pasted\.co', r'transfer\.sh',
      r'file\.io', r'0x0\.st', r'catbox\.moe', r'cdn\.discordapp\.com'],
     '滥用公开云服务（有道云笔记/GitHub/Pastebin 等）作配置下发或 C2 通道'),
    ('self_delete', '自删除与痕迹清理',
     [r'DeleteFile\s*\(', r'fso\.DeleteFile', r'FileSystemObject\s*.*delete',
      r'delete\s+self', r'del\s+/f\s+/q', r'self[-_]?delete'],
     '执行后删除自身/临时文件 — 降低驻留痕迹（反取证）'),
]

# DLL 侧加载目标（白加黑仿冒名）— 小写比较
SIDELOAD_TARGETS = ['libeay32.dll', 'ssleay32.dll', 'libssl-1_1-x64.dll',
                    'libssl-1_1.dll', 'version.dll', 'dxgi.dll', 'd3d11.dll',
                    'dbghelp.dll', 'netutils.dll', 'wlanapi.dll', 'cryptbase.dll',
                    'winmm.dll', 'dwmapi.dll', 'cryptsp.dll', 'wtsapi32.dll',
                    'dxgi.dll', 'xinput1_3.dll', 'xinput9_1_0.dll']

# 云服务域（作 C2/载荷投递滥用标记）
CLOUD_C2_DOMAINS = ['note.youdao.com', 'raw.githubusercontent.com', 'gitee.com',
                    'pastebin.com', 'pasted.co', 'transfer.sh', 'file.io',
                    '0x0.st', 'catbox.moe', 'cdn.discordapp.com', 'send.firefox.com',
                    'anonfiles.com', 'bayfiles.com']


class DeepDiveAnalyzer:
    """深度追踪分析器（后处理，不重跑样本）"""

    def __init__(self, max_file_analysis: int = 40, max_file_size: int = 50 * 1024 * 1024):
        self.max_file_analysis = max_file_analysis
        self.max_file_size = max_file_size

    # ==================== 主入口 ====================
    def analyze(self, report: AnalysisReport, file_path: str = '',
                stop_event=None) -> Optional[DeepDiveReport]:
        """对已有报告数据做深度关联分析，生成叙事式 DeepDive 报告"""
        if not report.dynamic:
            return None
        if stop_event and stop_event.is_set():
            return None
        t0 = time.time()
        result = DeepDiveReport()
        logger.info("[DeepDive] 深度追踪分析启动...")

        try:
            self._rebuild_process_chain(report, result, stop_event)
            self._analyze_files(report, result, stop_event)
            self._analyze_memory_codes(report, result, stop_event)
            self._analyze_network(report, result)
            self._detect_environment_checks(report, result)
            self._detect_theft(report, result)
            self._detect_defense_evasion(report, result)
            self._detect_persistence(report, result)
            self._detect_behavior_insights(report, result)
            self._build_delivery_layers(report, result)
            self._build_ioc_summary(report, result)
            self._compose_attack_chain(report, result)
            self._conclude(report, result)
        except Exception as e:
            logger.warning(f"[DeepDive] 分析异常: {e}")
            return result
        logger.info(f"[DeepDive] 完成 ({time.time()-t0:.1f}s) — {len(result.files)}文件 {len(result.process_chain)}进程 {len(result.attack_chain)}事件")
        return result

    # ==================== 阶段A0: 长时观察窗 (动态分析结束后继续监控) ====================
    def watch_after(self, report: AnalysisReport, result: DeepDiveReport,
                    timeout: int = 180, interval: int = 5,
                    max_files: int = 20, max_processes: int = 15,
                    stop_event=None, on_payload_kill=None) -> DeepDiveReport:
        """动态分析结束后长时观察: 慢速样本的后续进程/外联/释放文件

        观察期间持续捕获:
          - 与样本链关联的新进程 (祖先链含样本 PID)
          - 样本链进程的新网络外联 (聚合进 network_profile)
          - 常见释放目录中的新文件 (逐个深析)
        观察结束自动增量重算行为深析/投递链/IoC/攻击链/结论

        on_payload_kill: 可选回调 on_payload_kill(pid, name, exe) —
        观察窗发现"exe 命中样本释放文件"的载荷进程时调用 (沙箱模式下终止它,
        解决计划任务延迟拉起的载荷逃逸: 动态分析收工时进程还没出现)
        """
        if not result:
            return result
        import psutil
        logger.info(f"[DeepDive] 长时观察窗启动 ({timeout}s, 每{interval}s轮询)...")
        watch_start = time.time()
        # 样本种子 PID
        seed_pids = set()
        try:
            for p in report.dynamic.processes_created or []:
                if p.get('pid'):
                    seed_pids.add(p['pid'])
        except Exception:
            pass
        known_pids = {p.pid for p in result.process_chain} | seed_pids
        # 释放文件路径集合 (小写) — 计划任务/服务延迟拉起的载荷在观察窗内启动,
        # 祖先链/时间窗判据都可能失效, 但 exe 必命中样本释放的文件
        released_exes = set()
        try:
            for fc in (report.dynamic.files_created or []):
                p = fc.get('path', '') if isinstance(fc, dict) else fc
                if isinstance(p, str) and p.lower().endswith(
                        ('.exe', '.dll', '.scr', '.com', '.sys')):
                    released_exes.add(os.path.abspath(p).lower())
        except Exception:
            pass
        # 样本释放目录集合 (小写, 用于窄判据: 观察窗新进程/新文件只在这些目录内采信)
        allowed_dirs = set()
        try:
            for fc in (report.dynamic.files_created or []):
                p = fc.get('path', '') if isinstance(fc, dict) else fc
                if isinstance(p, str) and p:
                    parent = os.path.dirname(os.path.abspath(p)).lower()
                    if parent:
                        allowed_dirs.add(parent)
        except Exception:
            pass
        for exe in released_exes:
            parent = os.path.dirname(exe)
            if parent:
                allowed_dirs.add(parent)
        # 沙箱工作目录也作为观察范围 (样本可能在沙箱目录内释放)
        try:
            sr_dir = getattr(getattr(report.dynamic, 'sandbox_result', None), 'sandbox_dir', '')
            if sr_dir:
                allowed_dirs.add(os.path.abspath(sr_dir).lower())
        except Exception:
            pass
        watch_dirs = sorted(allowed_dirs)
        if not watch_dirs:
            logger.info("[DeepDive] 未发现样本释放目录, 观察窗仅做祖先链/释放文件路径匹配")
        else:
            logger.info(f"[DeepDive] 观察窗文件监控范围: {len(watch_dirs)} 个样本释放目录")
        # 已知文件 (避免重复分析)
        known_files = {f.path.lower() for f in result.files}
        new_procs = 0
        new_conns = 0
        new_files = 0
        baseline_ctime = watch_start - 10  # 观察窗基线: 观察开始前10秒
        try:
            while time.time() - watch_start < timeout:
                if stop_event and stop_event.is_set():
                    logger.info("[DeepDive] 观察窗被用户停止")
                    break
                time.sleep(interval)
                # 1) 关联新进程
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe', 'create_time', 'cmdline']):
                        try:
                            pid = proc.info['pid']
                            if pid in known_pids or new_procs >= max_processes:
                                continue
                            related = self._is_related_to_sample(
                                proc.info, seed_pids, watch_start, allowed_dirs)
                            # 释放文件路径关联通道: 不管创建时间/父进程链, exe 命中
                            # 样本释放的文件即载荷本体 (如 ITeWS计划任务→z2VIqs.exe)
                            if not related:
                                try:
                                    exe_l = (proc.info.get('exe') or '').lower()
                                    related = bool(exe_l and exe_l in released_exes)
                                except Exception:
                                    related = False
                            if not related:
                                continue
                            node = DeepDiveProcessNode(
                                pid=pid, name=proc.info.get('name', ''),
                                ppid=proc.info.get('ppid') or 0,
                                cmdline=str(proc.info.get('cmdline') or '')[:300],
                                exe=proc.info.get('exe', '') or '',
                                create_time=str(proc.info.get('create_time') or '')[:19],
                            )
                            node.flags.append('长时观察新增')
                            result.process_chain.append(node)
                            known_pids.add(pid)
                            new_procs += 1
                            logger.info(f"[DeepDive] 观察到新进程: {node.name} (PID={pid})")
                            # exe 命中样本释放文件 → 载荷本体: 回调终止 (沙箱模式)
                            try:
                                exe_l = (proc.info.get('exe') or '').lower()
                                if exe_l and exe_l in released_exes and on_payload_kill:
                                    try:
                                        on_payload_kill(pid, node.name, proc.info.get('exe') or '')
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                            # 同步回主报告 processes_created (主报告进程列表也要能看到)
                            try:
                                if report.dynamic:
                                    dup = any(x.get('pid') == pid
                                              for x in (report.dynamic.processes_created or []))
                                    if not dup:
                                        report.dynamic.processes_created.append({
                                            'pid': pid,
                                            'ppid': proc.info.get('ppid') or 0,
                                            'name': proc.info.get('name') or '',
                                            'cmdline': str(proc.info.get('cmdline') or '')[:300],
                                            'exe': proc.info.get('exe') or '',
                                            'create_time': str(proc.info.get('create_time') or '')[:19],
                                            'wmi_event': True,
                                            'note': 'DeepDive观察窗捕获 (计划任务/延迟拉起)',
                                        })
                            except Exception:
                                pass
                        except Exception:
                            pass
                except Exception:
                    pass
                # 2) 样本链进程的新外联
                try:
                    for conn in psutil.net_connections(kind='inet'):
                        try:
                            if conn.pid not in known_pids or not conn.raddr:
                                continue
                            host = conn.raddr.ip
                            port = conn.raddr.port
                            key = f'{host}:{port}'
                            t = next((x for x in result.network_profile.targets
                                      if f'{x.get("host","")}:{x.get("port","")}' == key), None)
                            if t:
                                t['count'] = t.get('count', 0) + 1
                            else:
                                result.network_profile.targets.append(
                                    {'host': host, 'port': port, 'count': 1,
                                     'bytes_sent': 0, 'bytes_recv': 0})
                                # 云服务域直接判 C2
                                if any(c in host.lower() for c in CLOUD_C2_DOMAINS):
                                    try:
                                        c2_proc = psutil.Process(conn.pid).name()
                                    except Exception:
                                        c2_proc = ''
                                    result.network_profile.c2_candidates.append(
                                        {'host': host, 'port': port, 'count': 1,
                                         'bytes_sent': 0, 'bytes_recv': 0,
                                         'process': c2_proc,
                                         'reasons': ['云服务滥用 (长时观察)']})
                                new_conns += 1
                        except Exception:
                            pass
                except Exception:
                    pass
                # 3) 释放目录新文件
                try:
                    for d in watch_dirs:
                        try:
                            for fn in os.listdir(d):
                                full = os.path.join(d, fn)
                                if full.lower() in known_files:
                                    continue
                                try:
                                    st = os.stat(full)
                                except OSError:
                                    continue
                                if st.st_ctime < baseline_ctime:
                                    continue
                                if not st.st_size or st.st_size > self.max_file_size:
                                    known_files.add(full.lower())
                                    continue
                                f = self._analyze_one_file(full, '释放文件', stop_event)
                                if f:
                                    result.files.append(f)
                                    if f.exports or f.yara_matches or f.is_driver:
                                        result.payload_delivery.append({
                                            'file': full, 'kind': f.kind, 'size': f.size,
                                            'yara': f.yara_matches[:10], 'family': f.family_hits[:5],
                                            'exports': f.exports[:20], 'iocs': f.iocs[:10]})
                                    new_files += 1
                                    logger.info(f"[DeepDive] 观察到新文件: {fn}")
                                known_files.add(full.lower())
                                if new_files >= max_files:
                                    break
                        except Exception:
                            pass
                        if new_files >= max_files:
                            break
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"[DeepDive] 观察窗异常: {e}")
        # 增量重算
        self._detect_behavior_insights(report, result)
        self._build_delivery_layers(report, result)
        self._build_ioc_summary(report, result)
        self._compose_attack_chain(report, result)
        self._conclude(report, result)
        result.attack_chain.append({
            'phase': '长时观察', 'event': f'观察窗 {int(time.time()-watch_start)}s 结束',
            'source': f'新增 {new_procs} 进程 / {new_conns} 外联 / {new_files} 文件',
        })
        logger.info(f"[DeepDive] 观察窗结束: +{new_procs}进程 +{new_conns}外联 +{new_files}文件")
        return result

    # 观察窗进程白名单 (系统基础进程, 观察期间大量出现, 排除噪音)
    WATCH_PROCESS_WHITELIST = {
        'svchost.exe', 'conhost.exe', 'csrss.exe', 'lsass.exe', 'services.exe',
        'dwm.exe', 'fontdrvhost.exe', 'dllhost.exe', 'wmiprvse.exe',
        'taskhostw.exe', 'searchindexer.exe', 'runtimebroker.exe',
        'securityhealthservice.exe', 'msmpeng.exe', 'audiodg.exe',
        'smss.exe', 'wininit.exe', 'winlogon.exe', 'explorer.exe',
        'sihost.exe', 'shellexperiencehost.exe', 'startmenuexperiencehost.exe',
        'textinputhost.exe', 'ctfmon.exe', 'splwow64.exe', 'spoolsv.exe',
        'backgroundtaskhost.exe', 'searchapp.exe', 'settingssynchorization.exe',
        # ⚠ 用户环境/VM 工具进程 — 观察窗内新增≠样本行为 (msedge/vmtoolsd 曾误报)
        'msedge.exe', 'chrome.exe', 'firefox.exe', 'iexplore.exe',
        'microsoftedgeupdate.exe', 'msedgewebview2.exe', 'msedgeupdater.exe',
        'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe', 'vm3dservice.exe',
        'vboxservice.exe', 'vboxtray.exe', 'dismhost.exe', 'wuauclt.exe',
        'moUsoCoreWorker.exe', 'usocoreworker.exe', 'searchfilterhost.exe',
        'searchprotocolhost.exe', 'compatTelrunner.exe', 'werfault.exe',
        'werfaultsecure.exe', 'wermgr.exe', 'python.exe', 'pythonw.exe',
        'cmd.exe', 'powershell.exe', 'pwsh.exe',
    }

    @staticmethod
    def _is_related_to_sample(proc_info: dict, seed_pids: set,
                              window_start: float = None,
                              allowed_dirs: set = None) -> bool:
        """判断进程是否与样本链相关:
        1) 祖先链含样本 PID (直接子进程/孙进程)
        2) 观察窗内新创建、且 exe 位于样本释放目录内 (计划任务/服务延迟拉起的载荷)

        ⚠ 不再使用"观察窗内任意新进程"的宽泛判据 — 那会把 WPS/QQ/浏览器
        更新器等正常应用误判为样本进程。
        """
        import psutil
        pid = proc_info.get('pid')
        if not pid:
            return False
        if pid in seed_pids:
            return False  # 样本本身, 跳过
        # 通道1: 祖先链
        try:
            p = psutil.Process(pid)
            seen = set()
            while p:
                ppid = p.ppid()
                if ppid in seed_pids:
                    return True
                if ppid in seen or ppid <= 0:
                    break
                seen.add(ppid)
                p = psutil.Process(ppid)
        except Exception:
            pass
        # 通道2: 仅限样本释放目录内的新进程 (窄判据)
        if window_start is not None and allowed_dirs:
            try:
                ct = proc_info.get('create_time') or 0
                if not ct or ct < window_start - 5:
                    return False
                name = (proc_info.get('name') or '').lower()
                if name in DeepDiveAnalyzer.WATCH_PROCESS_WHITELIST:
                    return False
                exe = (proc_info.get('exe') or '').lower()
                if '\\system32\\' in exe or '\\windows\\' in exe:
                    return False
                exe_parent = os.path.dirname(exe)
                if not exe_parent:
                    return False
                return any(exe_parent.startswith(ad) for ad in allowed_dirs)
            except Exception:
                return False
        return False

    # ==================== 阶段A: 进程链还原 ====================
    def _rebuild_process_chain(self, report, result: DeepDiveReport, stop_event=None):
        """从动态数据还原完整进程链"""
        dyn = report.dynamic
        nodes = {}   # pid -> node
        try:
            for p in dyn.processes_created:
                node = DeepDiveProcessNode(
                    pid=p.get('pid', 0), name=p.get('name', ''),
                    ppid=p.get('ppid', 0), cmdline=str(p.get('cmdline', ''))[:300],
                    exe=p.get('exe', ''),
                    create_time=str(p.get('create_time', ''))[:19],
                )
                nodes[node.pid] = node
        except Exception:
            pass
        # 补充沙箱记录的子进程
        sr = dyn.sandbox_result
        if sr:
            try:
                for cp in sr.child_processes or []:
                    pid = cp.get('pid', 0)
                    node = nodes.get(pid)
                    if node is None:
                        node = DeepDiveProcessNode(pid=pid, name=cp.get('name', ''))
                        nodes[pid] = node
                    if cp.get('cmdline'):
                        node.cmdline = str(cp['cmdline'])[:300]
                    if cp.get('exit_code') is not None:
                        node.exit_code = cp['exit_code']
            except Exception:
                pass
        # 系统监控进程 diff（含已退出进程）
        try:
            sysmon = getattr(report, '_system_monitor', None) or {}
            for entry in (sysmon.get('processes') or []):
                pid = entry.get('pid', 0)
                if pid and pid not in nodes:
                    nodes[pid] = DeepDiveProcessNode(
                        pid=pid, name=entry.get('name', ''),
                        ppid=entry.get('ppid', 0),
                        cmdline=str(entry.get('cmdline', ''))[:300],
                        exe=entry.get('exe', ''),
                        exit_code=entry.get('exit_code', -1),
                    )
        except Exception:
            pass
        # 标记异常进程
        flagged_names = {p.get('name', '') for p in dyn.processes_created
                         if p.get('suspicious') or p.get('flagged')}
        for node in nodes.values():
            if node.name.lower() in (n.lower() for n in flagged_names):
                node.flags.append('可疑进程')
            if node.exit_code not in (-1, 0) and node.exit_code is not None:
                node.flags.append(f'非零退出码 {node.exit_code}')
            if node.cmdline and re.search(r'(?i)(schtasks|powershell|mshta|rundll32|regsvr32)',
                                          node.cmdline):
                node.flags.append('可疑命令链')
        result.process_chain = sorted(nodes.values(), key=lambda n: n.pid)

    # ==================== 阶段B: 释放文件代码深析 ====================
    def _analyze_files(self, report, result: DeepDiveReport, stop_event=None):
        """对样本 + 所有释放文件逐个深度分析"""
        paths = []
        main_path = getattr(report, '_original_path', '') or ''
        if not main_path and report.file_info:
            main_path = report.file_info.path
        if main_path and os.path.exists(main_path):
            paths.append((main_path, '主程序'))
        # 释放文件
        try:
            for df in report.dropped_files.dropped_files if report.dropped_files else []:
                p = getattr(df, 'abs_path', '') or ''
                if p and os.path.exists(p) and os.path.isfile(p):
                    paths.append((p, '释放文件'))
        except Exception:
            pass
        if not paths:
            # 无 dropped_files 时兜底: 用动态 files_created 中存在的文件
            try:
                for fc in report.dynamic.files_created or []:
                    p = fc.get('path', '') if isinstance(fc, dict) else fc
                    if isinstance(p, str) and p and os.path.exists(p) and os.path.isfile(p):
                        # ⚠ 过滤沙箱/系统噪音 (VM工具日志/uv/Frida/WER/缓存)
                        #   vmware-vmtoolsd-SYSTEM.log 曾被误当"释放文件"
                        try:
                            from analyzer.dynamic import FileSystemMonitor
                            if FileSystemMonitor._is_noise_file(p):
                                continue
                        except Exception:
                            pass
                        paths.append((p, '释放文件'))
            except Exception:
                pass

        # 驱动文件识别: 系统目录(Windows\System32\drivers 等)之外的 .sys
        seen = set()
        for p, role in paths:
            if stop_event and stop_event.is_set():
                break
            if p in seen or len(result.files) >= self.max_file_analysis:
                break
            seen.add(p)
            try:
                f = self._analyze_one_file(p, role, stop_event)
            except Exception:
                continue
            if f:
                result.files.append(f)
                # 归类到攻击链章节
                if f.is_driver or any(k in f.role for k in ('驱动',)):
                    result.driver_chain.append({
                        'file': f.path, 'signer': f.signature_verifier,
                        'signature_valid': f.signature_valid,
                        'exports': f.exports[:20], 'notes': f.notes[:5],
                    })
                if f.role == '释放文件' and (f.yara_matches or f.family_hits or f.exports):
                    result.payload_delivery.append({
                        'file': f.path, 'kind': f.kind, 'size': f.size,
                        'yara': f.yara_matches[:10], 'family': f.family_hits[:5],
                        'exports': f.exports[:20], 'iocs': f.iocs[:10],
                    })

    def _analyze_one_file(self, path: str, role: str, stop_event=None) -> Optional[DeepDiveFile]:
        if not os.path.isfile(path):
            return None
        try:
            size = os.path.getsize(path)
        except OSError:
            return None
        if size > self.max_file_size:
            return None
        f = DeepDiveFile(path=path, role=role, size=size)
        try:
            with open(path, 'rb') as fh:
                head = fh.read(0x800)
        except OSError:
            return f
        if not head:
            return f
        # 文件类型判定
        if head[:2] == b'MZ' and b'PE\x00\x00' in head:
            self._analyze_pe_file(f, path, head)
        elif head[:4] == b'\x7fELF':
            f.kind = 'ELF (Linux)'
            f.notes.append('非 Windows 平台载荷 (ELF)')
        elif head[:2] in (b'#!', b'<s', b'<?', b'<h', b'<H') or head[:2].lower() in (b'sc',):
            f.kind = '脚本'
            self._analyze_script_file(f, path)
        elif head[:4] == b'PK\x03\x04':
            f.kind = 'ZIP/Office 文档'
        elif head[:2] == b'{\x0a' or head[:2] == b'\x0a{' or b'gzip' in head[:16]:
            f.kind = '压缩/归档数据'
        else:
            f.kind = '数据/配置文件'
        # 通用: 字符串 + IoC + 窃密特征
        try:
            with open(path, 'rb') as fh:
                data = fh.read(min(size, 30 * 1024 * 1024))
            self._extract_iocs(f, data)
            self._scan_theft_patterns(f, data)
        except Exception:
            pass
        return f

    def _analyze_pe_file(self, f: DeepDiveFile, path: str, head: bytes):
        """PE 深析: 架构/导出表/导入/签名/字符串/YARA/家族"""
        try:
            from analyzer.pe import PEAnalyzer
            info = PEAnalyzer(path).analyze()
            if info:
                f.kind = 'PE32' if info.architecture == 'x86' else 'PE32+'
                try:
                    from analyzer.static import StaticAnalyzer
                    fi = StaticAnalyzer(path).analyze()
                    f.entropy = fi.entropy
                    f.md5 = fi.md5
                    f.sha256 = fi.sha256
                except Exception:
                    pass
                try:
                    sig = info.digital_signature or {}
                    f.signature_verifier = str(sig.get('signer') or sig.get('subject') or '')
                    f.signature_valid = bool(sig.get('valid') or sig.get('verified'))
                except Exception:
                    pass
                if info.is_dll:
                    f.kind += ' / DLL'
                if info.is_driver if hasattr(info, 'is_driver') else False:
                    f.is_driver = True
                    f.kind += ' / 驱动'
                for sec in info.sections:
                    if sec.name.lower() in ('.text', 'CODE') and sec.is_executable:
                        f.notes.append('可执行节区正常')
                for imp in info.imports:
                    for fn in imp.functions[:8]:
                        f.imports.append(f"{imp.dll.split('.')[0]}!{fn}")
                f.imports = f.imports[:30]
        except Exception:
            pass
        # 导出表: 手写轻量解析（内存反射载荷无磁盘PE时也走此函数）
        try:
            with open(path, 'rb') as fh:
                data = fh.read(min(f.size, 50 * 1024 * 1024))
            f.exports = self._parse_pe_exports(data)[:100]
        except Exception:
            pass
        # 字符串 + YARA + 家族
        try:
            from analyzer.strings import StringAnalyzer
            sa = StringAnalyzer(data).analyze()
            f.strings_found = (sa.suspicious_strings or [])[:20]
            f.iocs = ((sa.urls or [])[:10] + (sa.domains or [])[:10] + (sa.ips or [])[:10])
            try:
                from analyzer.family import FamilyAnalyzer
                fam = FamilyAnalyzer().analyze(sa, None)
                if fam.primary_family and fam.primary_family != 'Unknown':
                    f.family_hits = [f"{fam.primary_family} ({fam.primary_confidence}%)"]
            except Exception:
                pass
        except Exception:
            pass
        try:
            from analyzer.yara_scanner import YARAScanner
            from utils.helpers import resource_path
            scanner = YARAScanner(rules_dir=resource_path('rules/yara'))
            hits = scanner.scan_file(path) or []
            for h in hits[:10]:
                rname = h.get('rule') or h.get('name') or str(h)[:40]
                f.yara_matches.append(rname)
        except Exception:
            pass
        # 白加黑侧加载: DLL 名命中侧加载目标 + 无有效签名 → 高置信侧加载
        base = os.path.basename(path).lower()
        if base in SIDELOAD_TARGETS or (base.endswith('.dll') and any(
                t.split('.')[0] in base for t in SIDELOAD_TARGETS[:6])):
            if not f.signature_valid:
                f.notes.append(f'⚠ 白加黑侧加载目标: {base} 无有效签名 (合法程序 sideloading)')
        # VMP 加壳
        try:
            with open(path, 'rb') as fh:
                vmp_data = fh.read(min(f.size, 6 * 1024 * 1024))
            if re.search(rb'(vmp0|vmp1|vmp2|VMProtect)', vmp_data, re.IGNORECASE):
                f.notes.append('⚠ VMProtect 加壳 — 强代码虚拟化保护')
                if 'VMP' not in f.yara_matches:
                    f.yara_matches.append('VMProtect (特征)')
        except Exception:
            pass
        # 驱动识别: .sys 或含驱动特征
        if path.lower().endswith('.sys') or any(k in (f.kind or '').lower() for k in ('驱动',)):
            f.is_driver = True
            if not f.signature_verifier:
                f.notes.append('⚠ 无有效数字签名 (未签名驱动)')
            elif f.signature_valid:
                f.notes.append(f'有效签名: {f.signature_verifier}')
            else:
                f.notes.append(f'签名校验失败: {f.signature_verifier}')
            # 驱动导出表即分发函数入口
            if 'DriverEntry' not in f.exports:
                for exp in f.exports:
                    f.notes.append(f'导出: {exp}')

    def _analyze_script_file(self, f: DeepDiveFile, path: str):
        """脚本深析: HTA/JS/VBS/PS 识别 + Base64 载荷 + ActiveX + URL 提取"""
        try:
            with open(path, 'rb') as fh:
                raw = fh.read(8 * 1024 * 1024)
            try:
                text = raw.decode('utf-8', errors='ignore')
            except Exception:
                text = raw.decode('gbk', errors='ignore')
            f.strings_found = text[:400].replace('\n', ' | ')[:400]
            lower = text.lower()
            # HTA 识别
            if '<hta:application' in lower or '<hta:' in lower or path.lower().endswith('.hta'):
                f.kind = 'HTA (HTML Application)'
                f.notes.append('HTA 脚本 — mshta.exe 执行, 高权限初始投递载体')
            elif lower.startswith('<html') or 'html' in lower[:200]:
                f.kind += ' / HTML'
            # 提取 URL
            for m in re.finditer(r'https?://[\x21-\x7e]{4,200}', text):
                f.iocs.append('URL: ' + m.group(0)[:140])
                if len(f.iocs) >= 8:
                    break
            # Base64 大块 (可解码为 PE/ZIP)
            for m in re.finditer(r'([A-Za-z0-9+/]{2000,}==?[\'")])', text):
                b64 = m.group(1).rstrip('\'")')
                if len(b64) >= 4000:
                    try:
                        import base64 as _b64
                        dec = _b64.b64decode(b64[:1000], validate=False)
                        kind = 'ZIP' if dec[:4] == b'PK\x03\x04' else ('PE' if dec[:2] == b'MZ' else 'data')
                        f.notes.append(f'⚠ 嵌入大段 Base64 (可解码为 {kind}) — 隔离载荷/静态分析绕过')
                    except Exception:
                        pass
                    break
            # ActiveX/.NET 程序集
            if 'activexobject' in lower:
                f.notes.append('ActiveXObject 调用 — 注册 .NET 程序集/COM 组件')
            if 'system.reflection' in lower or 'mscorlib' in lower:
                f.notes.append('.NET 反射/程序集加载')
            # 硬编码密钥
            for m in re.finditer(r'(?i)(password|passwd|secret|key)\s*=\s*[\'"]([^\'"]{4,40})', text):
                f.notes.append(f'硬编码密钥: {m.group(2)[:30]}')
                break
            # 反调试 JS
            if 'moveto(-3000' in text or 'function("function(' in lower:
                f.notes.append('⚠ 反调试 JS (窗口移出屏幕/Function递归debugger)')
            # 命令模式
            for pat in [r'(?i)(Invoke-Expression|IEX\s*\()', r'(?i)(downloadstring|downloadfile)',
                        r'(?i)(VirtualAlloc|kernel32)', r'(?i)(Add-Type|DllImport|CreateThread)',
                        r'(?i)(rundll32|mshta|regsvr32|schtasks|powershell\s+-enc)']:
                if re.search(pat, text):
                    f.notes.append(f'脚本危险模式: {pat.strip()[:40]}')
                    if len(f.notes) > 15:
                        break
        except Exception:
            pass

    @staticmethod
    def _parse_pe_exports(data: bytes) -> List[str]:
        """轻量 PE 导出表解析（不依赖第三方库）"""
        if len(data) < 0x40 or data[:2] != b'MZ':
            return []
        try:
            pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
            if pe_off + 24 > len(data) or data[pe_off:pe_off+4] != b'PE\x00\x00':
                return []
            magic = struct.unpack('<H', data[pe_off+24:pe_off+26])[0]
            opt_off = pe_off + 24
            if magic == 0x10B:      # PE32
                exp_rva, exp_size = struct.unpack('<II', data[opt_off+96:opt_off+104])
            elif magic == 0x20B:    # PE32+
                exp_rva, exp_size = struct.unpack('<II', data[opt_off+112:opt_off+120])
            else:
                return []
            if not exp_rva:
                return []
            # RVA → 文件偏移（节表映射）
            num_sec = struct.unpack('<H', data[pe_off+6:pe_off+8])[0]
            sec_table = opt_off + (0xF0 if magic == 0x20B else 0xE0)
            rva_to_off = {}
            for i in range(num_sec):
                off = sec_table + i * 40
                if off + 40 > len(data):
                    break
                vaddr, vsize, raw_off, raw_size = struct.unpack('<IIII', data[off+12:off+28])
                rva_to_off[vaddr] = raw_off
                rva_to_off[vaddr + raw_size] = raw_off + raw_size
            keys = sorted(rva_to_off.keys())
            def rva2off(rva):
                import bisect
                idx = bisect.bisect_right(keys, rva) - 1
                if idx < 0:
                    return None
                base = keys[idx]
                if base not in rva_to_off:
                    return None
                return rva_to_off[base] + (rva - base)
            exp_off = rva2off(exp_rva)
            if exp_off is None or exp_off + 40 > len(data):
                return []
            num_funcs, num_names = struct.unpack('<II', data[exp_off+20:exp_off+28])
            addr_names = struct.unpack('<I', data[exp_off+32:exp_off+36])[0]
            if not num_names or num_names > 1000:
                return []
            names_off = rva2off(addr_names)
            if names_off is None:
                return []
            names = []
            for i in range(min(num_names, 200)):
                rva = struct.unpack('<I', data[names_off+i*4:names_off+i*4+4])[0]
                str_off = rva2off(rva)
                if str_off is None or str_off >= len(data):
                    continue
                end = data.find(b'\x00', str_off, str_off + 128)
                if end == -1:
                    continue
                try:
                    names.append(data[str_off:end].decode('ascii', errors='ignore'))
                except Exception:
                    pass
            return names
        except Exception:
            return []

    @staticmethod
    def _extract_iocs(f: DeepDiveFile, data: bytes):
        """从字节流提取 IoC 并写入 f.iocs"""
        iocs = set()
        try:
            text = data[:4 * 1024 * 1024]
            for m in re.finditer(rb'(?i)(https?://[\x21-\x7e]{4,256})', text):
                iocs.add('URL: ' + m.group(1).decode('ascii', errors='ignore')[:120])
            for m in re.finditer(rb'(?:\d{1,3}\.){3}\d{1,3}', text):
                iocs.add('IP: ' + m.group(0).decode())
            for m in re.finditer(rb'[a-z0-9][a-z0-9\-\.]{2,60}\.(?:com|net|org|ru|cn|tk|ml|ga|cf|top|xyz|info|biz|shop|site|live)',
                                 text):
                dom = m.group(0).decode('ascii', errors='ignore').lower()
                if not re.match(r'^\d', dom) and '.' in dom:
                    iocs.add('域名: ' + dom)
        except Exception:
            pass
        f.iocs = sorted(iocs)[:20]

    @staticmethod
    def _scan_theft_patterns(f: DeepDiveFile, data: bytes):
        """扫描窃密/对抗特征码"""
        if not data:
            return
        try:
            text = data[:8 * 1024 * 1024]
            for cat, pat, desc in THEFT_SIGNATURES:
                if re.search(pat.encode('utf-8', 'ignore'), text, re.IGNORECASE):
                    f.notes.append(f'{desc}')
                    if len(f.notes) > 25:
                        break
        except Exception:
            pass

    # ==================== 阶段C: 内存代码深析 ====================
    def _analyze_memory_codes(self, report, result: DeepDiveReport, stop_event=None):
        """对内存快照/转储的载荷做代码深析"""
        dyn = report.dynamic
        snapshots = list(getattr(dyn, 'memory_snapshots', None) or [])
        try:
            mem = report.memory
            if mem:
                for mod in (mem.pe_injected_modules or []):
                    snapshots.append({
                        'pid': mod.get('pid', mem.pid),
                        'process': mod.get('module', f'PID-{mem.pid}'),
                        'address': mod.get('offset', mod.get('address', '')),
                        'size': 0,
                        'type': mod.get('type', '注入PE'),
                        'dump_path': mod.get('dump_path', ''),
                    })
        except Exception:
            pass
        # 从原始样本取前3个 shellcode/注入PE 快照
        for snap in snapshots:
            if stop_event and stop_event.is_set():
                break
            if len(result.memory_codes) >= 8:
                break
            try:
                mc = DeepDiveMemoryCode(
                    pid=snap.get('pid', 0), process=snap.get('process', ''),
                    address=snap.get('address', ''), size=snap.get('size', 0),
                    kind=snap.get('type', ''),
                    dump_path=snap.get('dump_path', ''),
                )
                payload = b''
                # ⚠ 优先用修复后的磁盘布局版本 (RAW=VA 对齐) — 内存映像 dump
                #   的导出表/节区无法直接解析, 修复版才能正确反编译
                fixed_path = snap.get('fixed_path', '')
                read_path = fixed_path if (fixed_path and os.path.exists(fixed_path)) else ''
                if not read_path and mc.dump_path and os.path.exists(mc.dump_path):
                    read_path = mc.dump_path
                if read_path:
                    try:
                        with open(read_path, 'rb') as fh:
                            payload = fh.read(min(mc.size or 10 * 1024 * 1024,
                                                  10 * 1024 * 1024))
                    except Exception:
                        pass
                if fixed_path and os.path.exists(fixed_path):
                    mc.dump_path = fixed_path  # 报告关联到可解析的修复版
                if payload:
                    # 导出表（若为内存 PE）
                    if payload[:2] == b'MZ':
                        mc.exports = self._parse_pe_exports(payload)[:80]
                    # 解密字符串（XOR/Base64 等）
                    try:
                        from analyzer.deobfuscator import Deobfuscator
                        deobs = Deobfuscator.detect_obfuscation(payload, [])
                        mc.decrypted_strings = [
                            {'technique': d.technique, 'preview': d.decoded_preview[:120],
                             'confidence': d.confidence}
                            for d in (deobs or [])[:5]
                        ]
                    except Exception:
                        pass
                    # 窃密特征码
                    for cat, pat, desc in THEFT_SIGNATURES:
                        if re.search(pat.encode('utf-8', 'ignore'), payload[:6*1024*1024],
                                     re.IGNORECASE):
                            mc.theft_signatures.append({'category': cat, 'desc': desc})
                            if len(mc.theft_signatures) >= 20:
                                break
                result.memory_codes.append(mc)
            except Exception:
                continue
        # 去重: 同一 (pid, address) 只保留一次 (快照与 pe_injected_modules 可能重复)
        seen = set()
        uniq = []
        for mc in result.memory_codes:
            key = (mc.pid, mc.address)
            if key in seen:
                # 合并: 保留有 dump 载荷的条目
                existing = next((x for x in uniq if (x.pid, x.address) == key), None)
                if existing and mc.dump_path and not existing.dump_path:
                    existing.dump_path = mc.dump_path
                    existing.size = mc.size or existing.size
                continue
            seen.add(key)
            uniq.append(mc)
        result.memory_codes = uniq[:8]

    # ==================== 阶段D: 网络外联画像 ====================
    def _analyze_network(self, report, result: DeepDiveReport):
        net = DeepDiveNetwork()
        target_map = {}   # remote -> {host, port, count, bytes_sent, bytes_recv, procs}
        try:
            for conn in report.dynamic.network_connections or []:
                remote = conn.get('remote', '')
                if not remote:
                    continue
                host, _, port = remote.rpartition(':')
                if not port.isdigit():
                    host, port = remote, ''
                key = f'{host}:{port}' if port else host
                t = target_map.setdefault(key, {'host': host, 'port': port, 'count': 0,
                                                'bytes_sent': 0, 'bytes_recv': 0,
                                                'process': conn.get('process_name', ''),
                                                'status': conn.get('status', '')})
                t['count'] += 1
                t['bytes_sent'] += conn.get('bytes_sent', 0) or 0
                t['bytes_recv'] += conn.get('bytes_recv', 0) or 0
        except Exception:
            pass
        # pcap 级连接
        try:
            if report.network:
                for conn in (report.network.tcp_connections or []) + (report.network.udp_connections or []):
                    remote = conn.remote_addr
                    if not remote:
                        continue
                    key = f'{remote}:{conn.remote_port}'
                    t = target_map.setdefault(key, {'host': remote, 'port': conn.remote_port,
                                                    'count': 0, 'bytes_sent': 0, 'bytes_recv': 0,
                                                    'process': conn.process_name, 'status': conn.status})
                    t['count'] += 1
                    t['bytes_sent'] += conn.bytes_sent or 0
                    t['bytes_recv'] += conn.bytes_recv or 0
        except Exception:
            pass
        # C2 判定
        suspicious_ports = {4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321, 1337, 8080}
        for key, t in target_map.items():
            reasons = []
            try:
                port = int(t['port'])
            except Exception:
                port = 0
            if port in suspicious_ports:
                reasons.append(f'非常规端口 {port}')
            if not t['port'] or t['port'] == '0':
                reasons.append('无端口(可能UDP广播)')
            if t['count'] >= 10:
                reasons.append(f'高频连接 ×{t["count"]}')
            host = str(t['host'] or '')
            # IP 直连外联需有实际数据交换 — SYN_SENT 0 字节握手(代理节点/端口探测)不算外联
            _status = str(t.get('status', '')).upper()
            _has_traffic = (t.get('bytes_sent', 0) or 0) > 0 or (t.get('bytes_recv', 0) or 0) > 0
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host) and host not in ('0.0.0.0', '127.0.0.1'):
                if not (_status == 'SYN_SENT' and not _has_traffic):
                    reasons.append('IP 直连外联')
            if re.search(r'(?i)\.(tk|ml|ga|cf|gq|top|xyz)$', host):
                reasons.append('恶意顶级域')
            if any(cloud in host.lower() for cloud in CLOUD_C2_DOMAINS):
                reasons.append('云服务滥用 (载荷投递/C2 通道)')
            if t['count'] >= 5 or len(reasons) >= 2 or any('云服务' in r for r in reasons):
                c2 = {'host': host, 'port': t['port'], 'count': t['count'],
                      'bytes_sent': t['bytes_sent'], 'bytes_recv': t['bytes_recv'],
                      'process': t['process'], 'reasons': reasons[:4]}
                net.c2_candidates.append(c2)
            net.targets.append({'host': host, 'port': t['port'], 'count': t['count'],
                                'bytes_sent': t['bytes_sent'], 'bytes_recv': t['bytes_recv']})
        net.c2_candidates.sort(key=lambda x: -x['count'])
        net.targets.sort(key=lambda x: -x['count'])
        # DNS
        try:
            for q in report.network.dns_queries or []:
                dom = q.domain
                if dom and (dom.endswith('.tk') or dom.endswith('.ml') or len(dom.split('.')) >= 4):
                    net.dns_interesting.append(dom)
        except Exception:
            pass
        try:
            for q in report.dynamic.dns_queries or []:
                dom = q.get('domain', '') if isinstance(q, dict) else getattr(q, 'domain', '')
                if dom and dom not in net.dns_interesting:
                    net.dns_interesting.append(dom)
        except Exception:
            pass
        # HTTP 概要
        try:
            for h in (report.network.http_requests or [])[:20]:
                net.http_summary.append({
                    'method': h.method, 'host': h.host, 'path': str(h.path)[:120],
                    'suspicious': bool(h.is_suspicious),
                })
        except Exception:
            pass
        # ⚠ C2 配置提取 — 大佬分析的 URL/密钥/路径/上线包格式 (静态字符串 + 威胁情报)
        try:
            cfg = {}
            s_text = ''
            if report.strings:
                s_text = ' '.join((report.strings.urls or []) + (report.strings.domains or []))
            # 已知 XML 命名空间/安装器文档 URL — 不是 C2, 不进画像
            _BENIGN_C2_HINTS = (
                'w3.org', 'ns.adobe.com', 'adobe.com', 'apache.org', 'github.com',
                'github.io', 'opengl.org', 'sil.org', 'iec.ch', 'creativecommons.org',
                'gnu.org', 'ietf.org', 'mozilla.org', 'wikipedia.org',
                'schemas.microsoft.com', 'jrsoftware.org', 'inno',
                '/rdf-syntax-ns', '/xap/', '/licenses/', '/sdk/', '/fonts/',
            )

            def _is_benign_c2_text(value):
                low = str(value or '').lower()
                return not low or any(h in low for h in _BENIGN_C2_HINTS)

            # URL
            urls = [u for u in (report.strings.urls or [])
                    if 'http' in str(u).lower() and not _is_benign_c2_text(u)]
            if urls:
                cfg['urls'] = urls[:8]
            # 域名/IP — 过滤单字符碎片 (s.gq/V.GA/U.Ml 这类变量名误提取)
            domains = []
            for d in (report.strings.domains or []):
                low = str(d or '').lower().rstrip('.')
                if not low or _is_benign_c2_text(d):
                    continue
                if re.match(r'^[a-z0-9]\.[a-z]{2,3}$', low):
                    continue
                domains.append(d)
            if domains:
                cfg['domains'] = domains[:6]
            if report.strings.ips:
                cfg['ips'] = report.strings.ips[:6]
            # 上线包格式 (fingerprint=/build_id=/UID 格式)
            full_text = s_text
            try:
                full_text += ' ' + ' '.join(report.strings.suspicious_strings or [])
            except Exception:
                pass
            if re.search(r'fingerprint\s*=', full_text, re.I):
                cfg['beacon_format'] = 'fingerprint={hash}&build_id={KEY}'
            if re.search(r'build_id\s*=', full_text, re.I):
                cfg['build_id_field'] = 'build_id (上线包标识)'
            if re.search(r'CPU:.*GUID:.*PC:', full_text, re.I) or \
                    ('CPU:' in full_text and 'GUID:' in full_text and 'PC:' in full_text):
                cfg['uid_format'] = 'CPU:<指纹>|GUID:<MachineGuid>|PC:<ComputerName>'
            # 密钥 (从威胁情报/字符串提取 32hex 密钥)
            for kw in re.findall(r'\b[0-9a-f]{24,32}\b', full_text):
                if kw not in ('aabbccdd' * 6,):
                    cfg['key'] = kw
                    break
            # 已知 C2 域名 (威胁情报命中)
            try:
                if report.threat_intel and report.threat_intel.iocs:
                    known = [i for i in report.threat_intel.iocs if 'c2' in str(i).lower() or 'c2' in str(i.get('type', '')).lower()]
                    if known:
                        cfg['threat_intel'] = [str(i)[:120] for i in known[:5]]
            except Exception:
                pass
            if cfg:
                net.c2_config = cfg
        except Exception:
            pass
        result.network_profile = net

    # ==================== 阶段E: 运行环境校验 ====================
    def _detect_environment_checks(self, report, result: DeepDiveReport):
        """检测样本是否校验运行环境（目标进程/登录状态/调试器）"""
        env_checks = []
        text = ''
        try:
            if report.strings:
                text += ' '.join(report.strings.suspicious_strings or [])
                text += ' '.join(report.strings.api_calls or [])
        except Exception:
            pass
        for pat in ENV_CHECK_PROCESSES:
            if re.search(pat, text, re.IGNORECASE):
                env_checks.append({'type': '目标进程校验', 'target': pat,
                                   'desc': f'样本内置进程名 "{pat}" — 通常用于轮询检测目标进程是否运行 (如 CreateToolhelp32Snapshot 快照扫描)'})
        # API 层证据
        try:
            apis = ' '.join(str(a.get('api', '')) for a in (report.dynamic.api_calls or []))
            for api in ENV_CHECK_APIS:
                if re.search(api, apis):
                    env_checks.append({'type': 'API', 'target': api,
                                       'desc': f'调用 {api} — 进程/窗口枚举'})
        except Exception:
            pass
        # ⚠ 合并 advanced_behavior 的具体环境检测技术 (反沙箱/反VM/反调试列表) —
        # 大佬分析的核心价值就是 30+ 项环境检测细节, 只报计数太粗
        try:
            ab = report.advanced_behavior
            if ab:
                for attr, tech_type in (('anti_sandbox', '反沙箱'), ('anti_vm', '反VM'),
                                        ('anti_debug', '反调试'), ('timing_evasion', '时序规避')):
                    for item in (getattr(ab, attr, None) or []):
                        env_checks.append({'type': tech_type, 'target': str(item)[:80],
                                           'desc': f'检测到{tech_type}技术: {item}'})
                # 去重 (同一条目可能多次出现)
                seen = set()
                uniq = []
                for e in env_checks:
                    k = (e['type'], e['target'])
                    if k in seen:
                        continue
                    seen.add(k)
                    uniq.append(e)
                env_checks = uniq
        except Exception:
            pass
        result.execution_environment = env_checks[:40]

    # ==================== 阶段F: 数据窃取线索 ====================
    def _detect_theft(self, report, result: DeepDiveReport):
        theft = []
        text = ''
        try:
            if report.strings:
                text += ' '.join(report.strings.suspicious_strings or []) + ' '
                text += ' '.join(report.strings.crypto_wallets or []) + ' '
        except Exception:
            pass
        try:
            for d in getattr(report, '_deobfuscation', None) or []:
                text += str(d.get('preview', '')) + ' '
        except Exception:
            pass
        for cat, pat, desc in THEFT_SIGNATURES:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                # ⚠ 证据显示实际命中内容 (不只是"静态字符串"标签)
                start = max(0, m.start() - 30)
                snippet = text[start:m.end() + 30].replace('\x00', ' ').strip()[:120]
                theft.append({'category': cat, 'desc': desc,
                              'evidence': f'静态字符串: {snippet}'})
        # 内存命中（来自阶段C已收集）+ 字符串命中
        for mc in result.memory_codes:
            for ts in mc.theft_signatures:
                theft.append({'category': ts['category'], 'desc': ts['desc'],
                              'evidence': f"内存@{mc.process}(0x{mc.address})"})
        # 释放文件中的浏览器数据（浏览历史/下载目录引用）
        try:
            if report.dropped_files:
                for df in report.dropped_files.dropped_files:
                    p = str(getattr(df, 'path', '') or '').lower()
                    if any(k in p for k in ('login data', 'cookies', 'web data', 'local state')):
                        theft.append({'category': 'browser', 'desc': '浏览器数据文件被释放/访问',
                                      'evidence': p})
        except Exception:
            pass
        # 去重
        seen = set()
        uniq = []
        for t in theft:
            k = t['category'] + t['desc']
            if k not in seen:
                seen.add(k)
                uniq.append(t)
        result.data_theft = uniq[:40]

    # ==================== 阶段G: 对抗规避 ====================
    def _detect_defense_evasion(self, report, result: DeepDiveReport):
        ev = []
        try:
            if report.advanced_behavior:
                ab = report.advanced_behavior
                for v in (ab.anti_vm or []):
                    ev.append({'type': '反虚拟机', 'desc': str(v)[:200], 'evidence': 'advanced_behavior: anti_vm'})
                for v in (ab.anti_sandbox or []):
                    ev.append({'type': '反沙箱', 'desc': str(v)[:200], 'evidence': 'advanced_behavior: anti_sandbox'})
                for v in (ab.process_injection or []):
                    ev.append({'type': '进程注入', 'desc': str(v)[:200], 'evidence': 'advanced_behavior: process_injection'})
                for v in (ab.anti_debug or []):
                    ev.append({'type': '反调试', 'desc': str(v)[:200], 'evidence': 'advanced_behavior: anti_debug'})
                for v in (ab.anti_analysis or []):
                    ev.append({'type': '反分析', 'desc': str(v)[:200], 'evidence': 'advanced_behavior: anti_analysis'})
                for v in (ab.timing_evasion or []):
                    ev.append({'type': '时序规避', 'desc': str(v)[:200], 'evidence': 'advanced_behavior: timing_evasion'})
                for v in (ab.c2_communication or []):
                    ev.append({'type': 'C2 通信', 'desc': str(v)[:200], 'evidence': 'advanced_behavior: c2_communication'})
                for v in (ab.credential_theft or []):
                    ev.append({'type': '凭证窃取', 'desc': str(v)[:200], 'evidence': 'advanced_behavior: credential_theft'})
                for v in (ab.keylogging or []):
                    ev.append({'type': '键盘记录', 'desc': str(v)[:200], 'evidence': 'advanced_behavior: keylogging'})
        except Exception:
            pass
        try:
            if report.memory and report.memory.shellcode_found:
                ev.append({'type': 'Shellcode', 'desc': f'{len(report.memory.shellcode_details or [])} 处可疑 Shellcode',
                           'evidence': str([s.get('details', '') for s in (report.memory.shellcode_details or [])[:3]])[:150]})
            if report.memory and report.memory.pe_in_memory:
                ev.append({'type': '反射加载', 'desc': '私有内存中发现注入 PE 映像（未出现在模块列表）',
                           'evidence': f"{len(report.memory.pe_injected_modules or [])} 个注入映像"})
            if report.memory and report.memory.hollowed_regions:
                ev.append({'type': '进程镂空', 'desc': f'{len(report.memory.hollowed_regions)} 个镂空区域',
                           'evidence': str([h.get('description', '') for h in (report.memory.hollowed_regions or [])[:3]])[:150]})
            if report.memory and report.memory.hooks_detected:
                ev.append({'type': 'Inline Hook', 'desc': f"{len(report.memory.hooks_detected)} 处内联钩子 (E9/FF25)",
                           'evidence': str([h.get('pattern', '') for h in (report.memory.hooks_detected or [])[:4]])[:150]})
        except Exception:
            pass
        try:
            if report.dynamic and report.dynamic.critical_process_events:
                ev.append({'type': '关键进程保护', 'desc': '设置 BreakOnTermination 阻止终止（对抗安全软件）',
                           'evidence': str([e.get('name', '') for e in report.dynamic.critical_process_events[:4]])[:150]})
        except Exception:
            pass
        # 去重
        seen = set()
        uniq = []
        for e in ev:
            k = e['type'] + e['desc']
            if k in seen:
                continue
            seen.add(k)
            uniq.append(e)
        result.defense_evasion = uniq[:30]

    # ==================== 阶段H: 持久化 ====================
    def _detect_persistence(self, report, result: DeepDiveReport):
        """收集持久化证据: 注册表启动项/服务/计划任务"""
        per = []
        try:
            for r in (report.dynamic.registry_modified or []):
                key = r.get('key', '') if isinstance(r, dict) else str(r)
                if re.search(r'(?i)(\\run\b|runonce|startup|autorun|shell\s*=\s|userinit|winlogon)', key):
                    per.append({'type': '注册表启动项', 'target': key})
        except Exception:
            pass
        try:
            for s in (report.dynamic.services_created or []):
                name = s.get('name', '') if isinstance(s, dict) else str(s)
                per.append({'type': '服务创建', 'target': name})
        except Exception:
            pass
        try:
            for t in (report.dynamic.scheduled_tasks or []):
                name = t.get('name', '') if isinstance(t, dict) else str(t)
                per.append({'type': '计划任务', 'target': name})
        except Exception:
            pass
        result.persistence = per[:10]

    # ==================== 阶段I: 行为深析 (对照真实样本分析报告) ====================
    def _detect_behavior_insights(self, report, result: DeepDiveReport):
        """检测对抗/提权/持久化/记录类行为细节"""
        # 收集全部可搜文本: 静态字符串 + 反混淆预览 + 内存快照 + API调用 + 文件内容
        search_blob = ''
        try:
            if report.strings:
                search_blob += ' '.join(report.strings.suspicious_strings or []) + ' '
                search_blob += ' '.join(report.strings.api_calls or []) + ' '
        except Exception:
            pass
        try:
            for d in getattr(report, '_deobfuscation', None) or []:
                search_blob += str(d.get('preview', '')) + ' '
        except Exception:
            pass
        try:
            for a in (report.dynamic.api_calls or []):
                search_blob += str(a.get('api', '')) + ' '
        except Exception:
            pass
        try:
            if report.advanced_behavior:
                for lst in ('anti_vm', 'anti_sandbox', 'anti_debug', 'anti_analysis'):
                    for v in (getattr(report.advanced_behavior, lst, None) or []):
                        search_blob += str(v) + ' '
        except Exception:
            pass
        try:
            for r in (report.dynamic.registry_modified or []):
                key = r.get('key', '') if isinstance(r, dict) else str(r)
                val = r.get('value_name', '') if isinstance(r, dict) else ''
                search_blob += f'{key} {val} '
        except Exception:
            pass
        # 文件内容样本 — 主程序与释放文件分开统计(证据来源要准确)
        main_blob = ''
        dropped_blob = ''
        try:
            for f in result.files[:12]:
                if f.size and f.size < 20 * 1024 * 1024 and os.path.exists(f.path):
                    try:
                        with open(f.path, 'rb') as fh:
                            blob = fh.read(2 * 1024 * 1024).decode('utf-8', errors='ignore')
                    except Exception:
                        continue
                    if f.role == '主程序':
                        main_blob += blob + ' '
                    else:
                        dropped_blob += blob + ' '
        except Exception:
            pass
        combined = search_blob + main_blob + dropped_blob
        insights = []
        for cat, name, pats, desc in BEHAVIOR_SIGNATURES + HTA_SIGNATURES:
            matched = []
            # ⚠ 提取实际命中证据: 把命中的字符串原文/API/文件写进报告,
            # 而不是只给模板化的 desc 说明 (用户反馈: 说明都是举例, 不是检测结果)
            evidence_hits = []
            for pat in pats:
                m = re.search(pat, combined, re.IGNORECASE)
                if m:
                    matched.append(pat)
                    # 截取命中点前后各 40 字符作为实际证据
                    start = max(0, m.start() - 40)
                    snippet = combined[start:m.end() + 40].replace('\x00', ' ')
                    evidence_hits.append(snippet.strip()[:120])
                    if len(matched) >= 3:
                        break
            if matched:
                if any(re.search(p, search_blob, re.IGNORECASE) for p in matched):
                    evidence = '动态行为/静态字符串'
                elif any(re.search(p, main_blob, re.IGNORECASE) for p in matched):
                    evidence = '主程序静态特征'
                else:
                    evidence = '释放文件内容'
                insights.append({
                    'category': cat, 'name': name, 'desc': desc,
                    'matched': matched[:3], 'evidence': evidence,
                    'evidence_hits': evidence_hits[:3],  # 实际命中证据
                })
        # mshta.exe 进程链 → HTA 投递
        try:
            if any((p.name or '').lower() == 'mshta.exe' for p in result.process_chain):
                insights.append({'category': 'hta_hidden', 'name': 'mshta.exe 执行',
                                 'desc': '进程链出现 mshta.exe — HTA 脚本初始投递（高权限无窗口执行）',
                                 'matched': [], 'evidence': '进程链'})
        except Exception:
            pass
        # 自删除证据: 动态删除自身/临时文件
        # ⚠ 必须过滤正常软件噪音 (uv/Python 安装、Frida、系统更新会大量删除临时文件) —
        # 否则合法安装器会被误报"自删除反取证" (用户反馈: 888 个文件删除是噪音)
        try:
            del_files = report.dynamic.files_deleted or []
            _noise_hints = ('\\uv\\', '\\frida-', '\\nsk', '\\wer\\',
                            'memory_dumps', '\\temp\\', '\\cache\\',
                            '\\inprogressinstallinfo', '\\installer\\')
            suspicious_del = []
            for f in del_files:
                fstr = str(f)
                fl = fstr.lower()
                # 过滤噪音路径 (uv/Frida/NSIS/WER/缓存/安装器)
                if any(h in fl for h in _noise_hints):
                    continue
                # 只保留特征: 样本删除自身释放物/持久化文件
                if re.search(r'(?i)(\.hta$|\.lnk$|\.dll$|\.exe$|runonce|startup)', fstr):
                    suspicious_del.append(f)
            if suspicious_del:
                insights.append({'category': 'self_delete', 'name': '自删除/痕迹清理',
                                 'desc': f'执行期间删除 {len(suspicious_del)} 个样本特征文件（含自身释放物/持久化文件）— 反取证',
                                 'matched': [], 'evidence': '; '.join(
                                     [os.path.basename(str(f)) for f in suspicious_del[:5]])})
        except Exception:
            pass
        # 进程链中的杀软进程（svchost 守护注入迹象）
        av_in_procs = []
        try:
            for p in result.process_chain:
                pl = (p.name or '').lower()
                for av in AV_PROCESS_NAMES:
                    if av in pl:
                        av_in_procs.append(p.name)
        except Exception:
            pass
        if av_in_procs:
            insights.append({'category': 'av_detection', 'name': '检测到杀软进程',
                             'desc': f'进程链中出现杀软进程: {", ".join(set(av_in_procs))[:100]}',
                             'matched': [], 'evidence': '进程链'})
        # svchost 子进程 + 注入特征 = 进程守护
        try:
            svc_children = [p.name for p in result.process_chain
                            if p.name and p.name.lower() == 'svchost.exe']
            has_inj = any('CreateRemoteThread' in str(a.get('api', ''))
                          for a in (report.dynamic.api_calls or []))
            if svc_children and has_inj:
                insights.append({'category': 'injection_guard', 'name': 'svchost 注入守护',
                                 'desc': '创建 svchost.exe 子进程并注入远程线程 — 进程守护/逃杀机制 (发起方被杀后自动重启)',
                                 'matched': [], 'evidence': '进程链+API'})
        except Exception:
            pass
        # 去重
        seen = set()
        uniq = []
        for i in insights:
            k = (i['category'], i['name'])
            if k not in seen:
                seen.add(k)
                uniq.append(i)
        result.behavior_insights = uniq[:20]

    # ==================== 阶段I2: 层级投递链 (L1→Ln) ====================
    def _build_delivery_layers(self, report, result: DeepDiveReport):
        """按 样本→释放→内存加载→子进程 的依赖关系构建层级链"""
        layers = []
        main_name = ''
        try:
            if report.file_info:
                main_name = report.file_info.name or ''
        except Exception:
            pass
        layers.append({
            'layer': 1, 'name': main_name or '样本', 'kind': '主程序',
            'detail': f'{result.files[0].kind}' if result.files else '',
            'role': '原始载荷',
        })
        # 释放文件 (PE/脚本/驱动)
        l = 2
        for f in result.files[1:]:
            if f.role != '释放文件':
                continue
            layers.append({
                'layer': l, 'name': os.path.basename(f.path),
                'kind': f.kind, 'detail': (f.signature_verifier or '无签名'),
                'role': '释放物' + ('/驱动' if f.is_driver else ''),
                'exports': f.exports[:10], 'yara': f.yara_matches[:5],
            })
            l += 1
            if l > 8:
                break
        # 内存注入载荷 (反射加载的 PE 是链的更深环节)
        seen_mem = set()
        for mc in result.memory_codes[:4]:
            key = (mc.pid, mc.address)
            if key in seen_mem:
                continue
            seen_mem.add(key)
            if mc.kind and 'PE' in mc.kind or mc.exports:
                layers.append({
                    'layer': l, 'name': f'{mc.process or f"PID-{mc.pid}"}@{mc.address}',
                    'kind': mc.kind or '内存PE', 'detail': '内存反射加载(未落盘)',
                    'role': '内存载荷',
                    'exports': mc.exports[:10],
                })
                l += 1
                if l > 9:
                    break
        # 子进程投递链
        try:
            interesting = [p for p in result.process_chain
                           if p.ppid and p.name and p.name.lower() not in
                           ('svchost.exe', 'conhost.exe', 'csrss.exe', 'dwm.exe')]
            for p in interesting[:3]:
                layers.append({
                    'layer': l, 'name': p.name,
                    'kind': '子进程', 'detail': str(p.cmdline)[:100],
                    'role': '进程执行', 'exports': [],
                })
                l += 1
                if l > 10:
                    break
        except Exception:
            pass
        result.delivery_layers = layers

    # ==================== 阶段I3: IOC 分类汇总 ====================
    def _build_ioc_summary(self, report, result: DeepDiveReport):
        """文件/网络/注册表/计划任务/互斥量 分类汇总"""
        ioc = {}
        # 文件
        files_ioc = []
        try:
            for f in result.files:
                # ⚠ 过滤 VM 工具日志/系统噪音 (vmware-vmtoolsd-SYSTEM.log 曾进 IoC)
                _fl = (f.path or '').lower()
                if 'vmware-vmtoolsd' in _fl or 'vmware-vmvss' in _fl \
                        or '\\vmware\\' in _fl or 'vmwaretools' in _fl:
                    continue
                files_ioc.append({
                    'type': '文件', 'name': os.path.basename(f.path),
                    'value': f.path, 'note': f.role + '/' + (f.kind or ''),
                })
        except Exception:
            pass
        # 网络
        net_ioc = []
        for c in result.network_profile.c2_candidates[:8]:
            net_ioc.append({'type': 'C2', 'name': '网络外联',
                            'value': f"{c.get('host','')}:{c.get('port','')}",
                            'note': '; '.join(c.get('reasons', []))[:80]})
        try:
            for d in result.network_profile.dns_interesting[:8]:
                net_ioc.append({'type': 'DNS', 'name': '域名', 'value': d, 'note': ''})
        except Exception:
            pass
        # 静态网络 IoC (字符串分析中的 URL/域名/IP — 动态未外联时也能给指标)
        try:
            if report.strings:
                for u in (report.strings.urls or [])[:6]:
                    net_ioc.append({'type': 'URL(静态)', 'name': '静态字符串',
                                    'value': u, 'note': '样本内置地址(未捕获外联)'})
                for d in (report.strings.domains or [])[:6]:
                    if not any(n.get('value') == d for n in net_ioc):
                        net_ioc.append({'type': '域名(静态)', 'name': '静态字符串',
                                        'value': d, 'note': '样本内置域名(未捕获外联)'})
                for ip in (report.strings.ips or [])[:6]:
                    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip):
                        net_ioc.append({'type': 'IP(静态)', 'name': '静态字符串',
                                        'value': ip, 'note': '样本内置IP(未捕获外联)'})
        except Exception:
            pass
        # 注册表 (持久化/禁用UAC/Defender相关)
        reg_ioc = []
        try:
            for r in (report.dynamic.registry_modified or []):
                key = r.get('key', '') if isinstance(r, dict) else str(r)
                val = r.get('value_name', '') if isinstance(r, dict) else ''
                if re.search(r'(?i)(run\b|startup|console|policies\\system|defender|exclusions|explorer)', key):
                    reg_ioc.append({'type': '注册表', 'name': '持久化/策略',
                                    'value': key + (f' :: {val}' if val else ''), 'note': ''})
        except Exception:
            pass
        # 计划任务
        task_ioc = []
        try:
            for t in (report.dynamic.scheduled_tasks or []) + (report.dynamic.services_created or []):
                name = t.get('name', '') if isinstance(t, dict) else str(t)
                task_ioc.append({'type': '计划任务/服务', 'name': '持久化', 'value': name, 'note': ''})
        except Exception:
            pass
        ioc['files'] = files_ioc[:15]
        ioc['network'] = net_ioc[:14]
        ioc['registry'] = reg_ioc[:12]
        ioc['tasks'] = task_ioc[:8]
        ioc['total'] = len(files_ioc) + len(net_ioc) + len(reg_ioc) + len(task_ioc)
        result.ioc_summary = ioc

    # ==================== 阶段J: 攻击链编排 ====================
    def _compose_attack_chain(self, report, result: DeepDiveReport):
        chain = []
        add = lambda phase, event, source='': chain.append({'phase': phase, 'event': event, 'source': source})
        try:
            if result.execution_environment:
                # ⚠ 全列环境检测技术 (大佬分析 30+ 项, 只取3条太粗)
                for e in result.execution_environment[:12]:
                    add('环境校验', f'{e.get("type", "")}: {e.get("target", "")}', e.get('desc', '')[:100])
            if result.defense_evasion:
                for e in result.defense_evasion[:6]:
                    add('对抗规避', e.get('type', ''), e.get('desc', '')[:100])
            # 行为深析 (对抗/提权/记录等)
            try:
                for i in result.behavior_insights[:4]:
                    add('对抗规避', i['name'], i.get('desc', '')[:90])
            except Exception:
                pass
            # 投递链
            if result.payload_delivery:
                for p in result.payload_delivery[:3]:
                    add('载荷投递', os.path.basename(p.get('file', '')), f"{p.get('kind','')} 导出{len(p.get('exports',[]))} 个函数")
            if result.driver_chain:
                for d in result.driver_chain[:2]:
                    sig = f"签名:{d.get('signer','')}" if d.get('signer') else '无签名'
                    add('驱动加载', os.path.basename(d.get('file', '')), f"{sig} {'有效' if d.get('signature_valid') else '无效/未签名'}")
            if result.data_theft:
                cats = set(t['category'] for t in result.data_theft[:8])
                add('数据窃取', f'窃密特征: {", ".join(sorted(cats))}', f'{len(result.data_theft)} 条证据')
            if result.network_profile.c2_candidates:
                c2 = result.network_profile.c2_candidates[0]
                add('网络外联', f'外联 {c2.get("host", "")}:{c2.get("port", "")}', f'{c2.get("count", 0)} 次连接')
            # 持久化
            try:
                if report.dynamic.services_created:
                    add('持久化', f'创建服务 {len(report.dynamic.services_created)} 个', '服务注册')
                if report.dynamic.scheduled_tasks:
                    add('持久化', f'计划任务 {len(report.dynamic.scheduled_tasks)} 个', '任务计划')
                reg_keys = [r.get('key', '') for r in (report.dynamic.registry_modified or [])]
                run_keys = [k for k in reg_keys if re.search(r'(?i)(\\run|startup|autorun)', k)]
                if run_keys:
                    add('持久化', '写入启动项注册表', '; '.join(run_keys[:3]))
            except Exception:
                pass
        except Exception:
            pass
        result.attack_chain = chain

    # ==================== 阶段J: 综合结论 ====================
    def _conclude(self, report, result: DeepDiveReport):
        score = 0.0
        verdict_parts = []
        if result.execution_environment:
            score += 0.15
            verdict_parts.append('定向环境校验(目标进程检测)')
        if result.defense_evasion:
            score += 0.15
            verdict_parts.append('反分析/对抗')
        if result.driver_chain:
            score += 0.2
            verdict_parts.append('驱动加载链(白驱动黑驱动风险)')
        if result.payload_delivery:
            score += 0.1
            verdict_parts.append('恶意载荷投递')
        if result.memory_codes:
            score += 0.1
            verdict_parts.append('内存代码(反射加载/注入)')
        theft_cats = {t['category'] for t in result.data_theft}
        if 'credential_qq' in theft_cats:
            score += 0.2
            verdict_parts.append('QQ/微信凭证窃取')
        if 'browser' in theft_cats or 'wallet' in theft_cats:
            score += 0.15
            verdict_parts.append('浏览器/钱包数据窃取')
        if 'win11_recall' in theft_cats or 'win11_cred' in theft_cats:
            score += 0.1
            verdict_parts.append('Win11数据窃取(Recall/AI/WiFi)')
        if result.network_profile.c2_candidates:
            score += 0.15
            verdict_parts.append(f"C2 外联({len(result.network_profile.c2_candidates)} 个候选)")
        if report.dynamic.services_created or report.dynamic.scheduled_tasks:
            score += 0.1
            verdict_parts.append('持久化')
        # 行为深析加分
        insight_cats = {i['category'] for i in result.behavior_insights}
        if 'av_detection' in insight_cats:
            score += 0.05
            verdict_parts.append('杀软对抗')
        if 'defender_disable' in insight_cats:
            score += 0.1
            verdict_parts.append('关闭Defender')
        if 'uac_disable' in insight_cats:
            score += 0.05
            verdict_parts.append('禁用UAC')
        if 'privilege' in insight_cats:
            score += 0.05
            verdict_parts.append('提权')
        if 'keylogger' in insight_cats or 'clipboard' in insight_cats:
            score += 0.1
            verdict_parts.append('键盘/剪贴板记录')
        if 'injection_guard' in insight_cats:
            score += 0.1
            verdict_parts.append('进程守护注入')
        if 'doh' in insight_cats:
            score += 0.05
            verdict_parts.append('DoH解析C2')
        if 'hta_hidden' in insight_cats or 'hta_activex_dotnet' in insight_cats:
            score += 0.05
            verdict_parts.append('HTA脚本投递')
        if 'embedded_base64' in insight_cats:
            score += 0.05
            verdict_parts.append('嵌入Base64载荷')
        if 'sideloading' in insight_cats:
            score += 0.05
            verdict_parts.append('白加黑侧加载')
        if 'vmp_packed' in insight_cats:
            score += 0.05
            verdict_parts.append('VMProtect加壳')
        if 'cloud_c2' in insight_cats:
            score += 0.05
            verdict_parts.append('云服务滥用')
        if 'self_delete' in insight_cats:
            score += 0.05
            verdict_parts.append('自删除/痕迹清理')
        score = min(score, 0.99)
        if score >= 0.55:
            verdict = '高度疑似恶意：窃密木马/加载器'
        elif score >= 0.3:
            verdict = '疑似恶意：存在对抗与投递行为'
        elif score >= 0.15:
            verdict = '可疑：存在异常行为特征'
        else:
            verdict = '未发现显著恶意行为'
        result.verdict = verdict
        result.confidence = round(score, 2)
        result.conclusion = (
            f'样本在动态执行期间共产生 {len(result.process_chain)} 个关联进程、'
            f'{len(result.files)} 个分析文件、{len(result.attack_chain)} 个攻击链事件。'
            + ('样本启动后先校验运行环境' if result.execution_environment
               else '未检测到明显的环境校验行为')
            + ('，随后' if result.execution_environment and (result.payload_delivery or result.data_theft) else '')
            + ('释放/加载恶意载荷' if result.payload_delivery else '')
            + ('，通过内存反射方式注入私有内存' if result.memory_codes else '')
            + ('，利用驱动链获取内核能力' if result.driver_chain else '')
            + ('，在目标进程内存中定位并提取凭证数据（含 QQ 号/口令/令牌等特征码）'
               if 'credential_qq' in theft_cats else '')
            + ('，并通过网络外联回传数据' if result.network_profile.c2_candidates else '')
            + ('，同时建立持久化' if result.persistence or report.dynamic.services_created else '')
            + '。' + f'综合判定：{verdict}（置信度 {score:.0%}）。'
        )
