#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高级行为检测引擎 — 反沙箱、反虚拟机、进程注入、数据窃取、勒索软件等
"""
import os
import re
from typing import Optional

from logger import get_logger
from analyzer.models import AdvancedBehavior, StringAnalysis, PEInfo, DynamicBehavior

logger = get_logger('analyzer.advanced_behavior')


class AdvancedBehaviorDetector:
    """高级行为检测器"""
    
    # MITRE ATT&CK 映射表
    MITRE_TAGS = {
        'Sandboxie 检测': 'T1497.001',
        'Cuckoo/CAPE 沙箱检测': 'T1497.001',
        '调试器检测': 'T1622',
        'Windows 调试器检测': 'T1622',
        '时间差反沙箱': 'T1497.003',
        '用户交互检测': 'T1497.002',
        '多显示器/远程会话检测': 'T1497.001',
        'CPUID 指令检测': 'T1497.001',
        'VMware 检测': 'T1497.001',
        'VirtualBox 检测': 'T1497.001',
        'QEMU/KVM 检测': 'T1497.001',
        'Wine 检测': 'T1497.001',
        'VM MAC 地址检测': 'T1497.001',
        'BIOS 注册表检测': 'T1497.001',
        'CPU 核心数检测': 'T1497.001',
        '键盘记录': 'T1056.001',
        '全局键盘钩子': 'T1056.001',
        '远程线程注入': 'T1055.001',
        'APC 注入': 'T1055.004',
        '进程镂空': 'T1055.012',
        '反射式加载': 'T1620',
        'Token 特权提升': 'T1134.001',
        'UAC 绕过': 'T1548.002',
        '凭据窃取': 'T1003.001',
        'LSASS 凭据提取': 'T1003.001',
        'DPAPI 解密': 'T1555.003',
        '浏览器数据窃取': 'T1555.003',
        '浏览器 Cookie 窃取': 'T1539',
        'Chrome Cookie': 'T1539',
        'Web 会话 Cookie 窃取': 'T1539',
        '剪贴板监控': 'T1115',
        '屏幕截图': 'T1113',
        '文件加密': 'T1486',
        '赎金通知': 'T1486',
        '卷影删除': 'T1490',
        '备份删除': 'T1490',
        'DGA 域名生成': 'T1568.002',
        'HTTP C2': 'T1071.001',
        'DNS 隧道': 'T1572',
        '驱动加载': 'T1543.003',
        'SSDT Hook': 'T1014',
        '引导扇区操作': 'T1542.003',
        '物理磁盘访问': 'T1561.001',
        'MSI 安装包执行': 'T1218.007',
        'AlwaysInstallElevated': 'T1548.002',
        '计划任务持久化': 'T1053.005',
        'Defender 排除项': 'T1562.001',
        'Disable Defender': 'T1562.001',
        'DLL 侧加载': 'T1574.002',
        'Shellcode 分配': 'T1055',
        '查询系统硬盘大小': 'T1082',
        '创建可执行文件': 'T1105',
        '注册表 Run 键': 'T1547.001',
        'WMI 持久化': 'T1546.003',
        '创建快捷方式': 'T1547.009',
        # ===== 新增行为 MITRE 映射 =====
        'GetTickCount64 反沙箱': 'T1497.003',
        'RW→RX 内存保护变更': 'T1620',
        '跨进程写入数据': 'T1055',
        'COM Surrogate 执行': 'T1559.001',
        '远程 COM 对象激活': 'T1021.003',
        'WebSocket 协议升级': 'T1071.001',
        'WebSocket 连接': 'T1071.001',
        'svchost 计划任务触发': 'T1053.005',
        'dllhost COM 代理进程链': 'T1559.001',
        '以 VM 写权限打开其他进程': 'T1055',
        '反射式 DLL 加载': 'T1620',
        'nvgpu 载荷': 'T1543.003',
        'Common Files 下 nvgpu': 'T1543.003',
        '查询系统硬盘大小': 'T1082',
        # ===== 线索追踪新增 MITRE 映射 =====
        '修改 UAC 提示行为': 'T1548.002',
        'UAC 策略注册表修改': 'T1548.002',
        '修改系统 Hosts 文件': 'T1562.001',
        '写入 Hosts 文件': 'T1562.001',
        '读取 Hosts 文件': 'T1082',
        'PowerShell 添加注册表项': 'T1059.001',
        'PowerShell 编码命令执行': 'T1059.001',
        'PowerShell 远程下载执行': 'T1059.001',
        '标记文件关闭时删除': 'T1070.004',
        '延迟删除文件': 'T1070.004',
        'XPSPLOG.dll 侧加载': 'T1574.002',
        'Domo 目录': 'T1543.003',
        'IE 缓存目录': 'T1564.001',
        'drops[N].jpg 伪装载荷': 'T1564.001',
        'MSI 安装痕迹': 'T1218.007',
        'PF x86 随机目录+随机EXE': 'T1543.003',
        # ===== 进程树分析新增 MITRE 映射 =====
        '停止/禁用 Windows Update 服务': 'T1562.001',
        '破坏 Windows Update 核心 DLL': 'T1489',
        '禁用 Windows Update 服务恢复机制': 'T1562.001',
        '删除 Windows Update 缓存目录': 'T1070.004',
        '注册表禁用自动更新': 'T1112',
        'PowerShell 禁用更新计划任务': 'T1059.001',
        '移除目录权限继承': 'T1222.001',
        '授予所有人完全控制权': 'T1222.001',
        '夺取文件/目录所有权': 'T1222.001',
        '修改文件所有者': 'T1222.001',
        '授予管理员完全控制+继承': 'T1222.001',
        '计划任务添加 Defender 排除路径': 'T1053.005',
        '计划任务一键三连': 'T1053.005',
        # ===== 键盘记录器/消息钩子 MITRE 映射 =====
        'WH_JOURNALRECORD（系统级全量消息记录）': 'T1056.001',
        'WH_KEYBOARD（全局键盘钩子）': 'T1056.001',
        'WH_KEYBOARD_LL（低级键盘钩子）': 'T1056.001',
        'WH_MOUSE（全局鼠标钩子）': 'T1056.001',
        'WH_MOUSE_LL（低级鼠标钩子）': 'T1056.001',
        'WH_CALLWNDPROC（窗口消息钩子）': 'T1056.001',
        'WH_GETMESSAGE（消息队列钩子）': 'T1056.001',
        '消息钩子无模块句柄': 'T1056.001',
        '安装 Windows 消息钩子': 'T1056.001',
        '系统消息记录钩子 WH_JOURNALRECORD': 'T1056.001',
        '消息回放钩子': 'T1056.001',
        '全局鼠标钩子': 'T1056.001',
        # ===== InnoSetup/伪造安全软件/浏览器探测 MITRE 映射 =====
        'InnoSetup 临时文件': 'T1105',
        'msys64 目录下随机子目录': 'T1105',
        'InnoSetup 64位安装器临时文件': 'T1105',
        'InnoSetup 打包器特征': 'T1027',
        '伪装火绒安全软件': 'T1036.005',
        'allapp 统一安装器': 'T1204.002',
        '零宽字符混淆文件名': 'T1036.005',
        '零宽字符伪装': 'T1036.005',
        '检测已安装浏览器': 'T1082',
        '浏览器安装路径探测': 'T1082',
        '注册表浏览器路径查询': 'T1082',
        '注册表默认浏览器查询': 'T1082',
        '跨用户目录释放文件': 'T1105',
        '多用户 Profile 遍历': 'T1082',
        '枚举本地用户账户': 'T1087.001',
    }

    ANTI_SANDBOX_PATTERNS = [
        # ⚠ 收紧: 移除裸词 Sandbox/Debug/analyzer/in|out — IGNORECASE 下匹配
        #   input/output/inside/调试构建 等海量正常内容 (历史误报源)
        (r'Sandboxie|SbieDll|SbieSvc', 'Sandboxie 检测'),
        (r'Cuckoo|cape', 'Cuckoo/CAPE 沙箱检测'),
        (r'Joe Sandbox|joebox|JoeBox', 'Joe Sandbox 检测'),
        (r'Wireshark|wireshark|ethereal|sniffer|winpcap|npcap', '网络嗅探器检测'),
        (r'Process Hacker|Process Monitor|Procmon|Tcpview|Autoruns|Dbgview', 'Sysinternals 检测'),
        (r'debugger|OllyDbg|x64dbg|IDA|Immunity|WinDbg', '调试器检测'),
        (r'CheckRemoteDebuggerPresent|IsDebuggerPresent|NtQueryInformationProcess.*Debug', 'Windows 调试器检测'),
        (r'NtQueryInformationProcess.*Debug|ProcessDebugPort|ProcessDebugFlags|ProcessBasicInformation', 'NT 调试查询'),
        (r'GetTickCount.*Sleep|Sleep.*GetTickCount|timeGetTime|QueryPerformanceCounter', '时间差反沙箱'),
        (r'GetTickCount64', 'GetTickCount64 反沙箱（规避短时间分析）'),
        (r'QueryPerformanceCounter|GetPerformanceCounter|RDTSC|rdtsc|__rdtsc', '性能计数器反沙箱'),
        (r'GetCursorPos|GetAsyncKeyState|GetKeyState|GetForegroundWindow|GetLastInputInfo', '用户交互检测'),
        (r'GetSystemMetrics|SM_CMONITORS|SM_CXVIRTUALSCREEN|SM_CYVIRTUALSCREEN|SM_REMOTESESSION', '多显示器/远程会话检测'),
        (r'GetComputerName|GetUserName|GetVolumeInformation|GetSystemFirmwareTable', '系统信息检测'),
        (r'WMI.*Win32_ComputerSystem.*Model|Win32_BIOS.*SerialNumber|Win32_BaseBoard.*SerialNumber', 'WMI 系统信息检测'),
        (r'cpuid|CPUID|__cpuid|__cpuidex', 'CPUID 指令检测'),
        (r'__inbyte|__outbyte|__inp|__outp|_inp\b|_outp\b|inb\s*\(|outb\s*\(', '端口 I/O 检测'),
        (r'LoadLibraryA.*SbieDll|LoadLibraryW.*SbieDll', 'Sandboxie DLL 加载检测'),
        (r'CreateFileW.*\\\\.\\pipe\\cuckoo|CreateFileW.*\\\\.\\pipe\\VBox', '沙箱管道检测'),
        (r'RegOpenKeyEx.*Software\\Vbox|RegOpenKeyEx.*Software\\VMware', '注册表沙箱检测'),
        (r'macro.*sandbox|Document_Open.*sandbox|AutoOpen.*sandbox', 'Office 宏沙箱检测'),
        (r'GetModuleHandleA.*SbieDll|GetModuleHandleW.*SbieDll', 'SbieDll 模块检测'),
        (r'GetProcAddress.*SbieDll|GetProcAddress.*hook', 'API Hook 检测'),
        (r'GetProcessHeap|HeapSetInformation|GetProcessMitigationPolicy', '内存策略检测'),
        (r'GetCommandLine|GetCommandLineW|lpCmdLine|argv\[0\]', '命令行参数检测'),
        (r'CreateMutex.*Global\\\|Global\\', '互斥体沙箱检测'),
        (r'EnumProcesses|EnumProcessModules|K32EnumProcessModules', '进程枚举沙箱检测'),
        (r'GetModuleFileName.*\\\\analyzer|\\\\sample|\\\\sandbox|\\\\malware', '沙箱路径检测'),
        (r'GetTempPath.*\\\\Temp|GetEnvironmentVariable.*TEMP', '临时目录检测'),
        # 云沙箱对照补强: 检测常用办公/IM软件判断是否沙箱环境
        (r'Software\\\\Tencent\\\\WeChat|Software\\\\Tencent\\\\QQ|WeChat|微信', '微信检测（判断真实用户环境—沙箱无微信）'),
        (r'Software\\\\Microsoft\\\\Office|Microsoft\\\\Office\\\\\d+|Outlook\.Application|Excel\.Application|Word\.Application', '办公软件检测（判断真实用户环境—沙箱无Office）'),
        (r'Software\\\\Google\\\\Chrome|Software\\\\Mozilla\\\\Firefox|Software\\\\Microsoft\\\\Edge|Software\\\\Chromium', '浏览器检测（判断真实用户环境）'),
        (r'Software\\\\WPS|Kingsoft|WPS Office', 'WPS办公软件检测（中文环境真实用户判定）'),
        (r'Tencent\\\\|Software\\\\WeChatFiles|WeChatFiles', '腾讯系软件检测（IM环境判定）'),
    ]

    ANTI_ANALYSIS_PATTERNS = [
        # 时区检测
        (r'GetTimeZoneInformation|TIME_ZONE|SetTimeZoneInformation|GetDynamicTimeZoneInformation', '时区检测（常用于规避分析系统）'),
        # ===== 音频硬件 COM 检测（虚拟机通常无真实音频设备）=====
        (r'IMMDeviceEnumerator|MMDeviceEnumerator|IAudioEndpointVolume|IAudioMeterInformation', '通过 COM 检测音频硬件（无音频设备→VM/沙箱）'),
        (r'CoCreateInstance.*MMDeviceEnumerator|CLSID.*BCDE0395|IMMDevice', 'COM 音频设备枚举（反 VM 音响检测）'),
        # ===== 办公软件沙箱检测 =====
        (r'Microsoft.*Office|Office.*\d{2,4}|WINWORD|EXCEL\.EXE|POWERPNT|Microsoft Word|Microsoft Excel', '检测已安装 Office（沙箱通常不装 Office）'),
        (r'Outlook|Microsoft Outlook|olMailItem|MAPI', '检测 Outlook 邮件客户端（反沙箱—真实用户特征）'),
        (r'Software\\Microsoft\\Office', '注册表检测 Office 安装（反沙箱判定）'),
        (r'GetSystemTime|GetLocalTime|GetSystemTimeAsFileTime|SystemTimeToTzSpecificLocalTime', '系统时间查询'),
        (r'TimeZoneKeyName|DaylightName', '时区名称检测'),
        # 磁盘大小检测（VM 判定）
        (r'GetDiskFreeSpace|GetDiskFreeSpaceEx|DeviceIoControl.*IOCTL_DISK', '查询系统硬盘大小（VM检测—小硬盘=虚拟机）'),
        (r'IOCTL_STORAGE_GET_DEVICE_NUMBER|IOCTL_DISK_GET_DRIVE_GEOMETRY|IOCTL_DISK_GET_LENGTH_INFO', '查询硬盘物理几何信息（VM检测）'),
        (r'SMART_RCV_DRIVE_DATA|SMART_GET_VERSION|PhysicalDrive', 'S.M.A.R.T 磁盘信息获取（VM检测）'),
        (r'GlobalMemoryStatusEx|GetPhysicallyInstalledSystemMemory', '查询物理内存大小（VM检测—小内存=虚拟机）'),
        # 网络适配器
        (r'GetAdaptersInfo|GetAdaptersAddresses|GetIfTable|GetIpAddrTable', '网络适配器信息获取'),
        (r'NetWkstaGetInfo|NetServerGetInfo|WNetGetConnection|WNetGetUniversalName', '网络工作区信息'),
        # 用户目录检测
        (r'SHGetFolderPath|SHGetSpecialFolderPath|SHGetKnownFolderPath|CSIDL_PROFILE', '用户目录路径获取'),
        (r'FOLDERID_LocalAppData|FOLDERID_RoamingAppData|FOLDERID_ProgramData', '应用数据目录获取'),
        (r'ExpandEnvironmentStrings.*%APPDATA%|%USERPROFILE%|%LOCALAPPDATA%', '环境变量路径展开'),
        # 终端服务 / RDP
        (r'RegOpenKeyEx.*Terminal Server|Terminal Services|TSClient|rdpwd', '终端服务注册表读取（RDP 相关）'),
        (r'WTSQuerySessionInformation|WTSEnumerateSessions|WTSGetActiveConsoleSessionId', '终端服务会话查询'),
        (r'CredEnumerate|CredRead|CredReadDomainCredentials|vaultcli', 'Windows 凭据管理器访问'),
        # 任务栏 / Explorer 注入
        (r'FindWindow.*Shell_TrayWnd|FindWindow.*Progman|FindWindow.*WorkerW', '任务栏窗口扫描（Explorer 注入）'),
        (r'SHAppBarMessage|ABM_GETTASKBARPOS|RegisterShellHookWindow|Shell_NotifyIcon', '任务栏 Hook/消息'),
        (r'GetWindowThreadProcessId.*explorer|FindWindow.*explorer\.exe', 'Explorer 进程交互'),
        # Wine 检测
        (r'wine_get_version|wine_get_unix_file_name|ntdll\.wine|winecfg', 'Wine 环境检测（wine 专属函数）'),
        (r'kernel32\.dll\.wine|user32\.dll\.wine|gdi32\.dll\.wine', 'Wine DLL 版本检测'),
        # 错误返回/异常处理
        (r'RtlSetLastWin32Error|SetLastError|NtRaiseHardError|RtlNtStatusToDosError', '错误码设置/返回'),
        (r'__except|EXCEPTION_EXECUTE_HANDLER|SetUnhandledExceptionFilter|UnhandledExceptionFilter', '异常处理（错误返回调用者）'),
        (r'RaiseException|RtlRaiseException|NtRaiseException|ZwRaiseException', '主动触发异常'),
    ]

    TIMING_EVASION_PATTERNS = [
        (r'Sleep.*\d{4,}|NtDelayExecution.*\d{4,}|WaitForSingleObject.*\d{4,}', '长时间延迟（拖慢分析）'),
        # ⚠ 时间流速反沙箱: 线程 Sleep(83s) + WaitForSingleObject(80s) —
        # 沙箱常加速 Sleep, 线程提前返回则判定为沙箱 (QQ浏览器patch样本手法)
        (r'CreateThread.*Sleep.*(?:WaitForSingleObject|WaitForSingleObjectEx)'
         r'|Sleep.*WaitForSingleObject.*0x|NtDelayExecution.*WaitForSingleObject', '时间流速反沙箱（Sleep线程+Wait超时—沙箱时间加速检测）'),
        (r'Sleep\(|NtDelayExecution|WaitForMultipleObjects|WaitForSingleObject', '延迟执行'),
        (r'SetTimer|CreateTimerQueue|CreateTimerQueueTimer|timeSetEvent', '定时器/回调延迟'),
        (r'GetTickCount.*while|while.*GetTickCount|do.*while|loop.*counter', '忙等待循环'),
        (r'SwitchToThread|Sleep\(0\)|Sleep\(1\)|YieldProcessor', 'CPU 时间片释放'),
    ]
    
    ANTI_VM_PATTERNS = [
        (r'vmware|VMware|vmci|vmtools|vmusrvc|vmsrvc|vmx|vmhgfs', 'VMware 检测'),
        (r'VirtualBox|vbox|VBoxGuest|VBoxMouse|VBoxSF|VBoxVideo|VBoxTray|innotek', 'VirtualBox 检测'),
        (r'qemu|QEMU|qemu-ga|virtio|virt-manager|KVM', 'QEMU/KVM 检测'),
        (r'xen|Xen|XenService|xenserver|citrix', 'Xen 检测'),
        (r'parallels|Parallels|prl_tools|prlstrg', 'Parallels 检测'),
        (r'Hyper-V|HyperV|Microsoft Hv|MsHyperV|hyperv', 'Hyper-V 检测'),
        (r'vmdebug|vmicheartbeat|vmicvss|vmicshutdown|vmicexchange', 'Hyper-V 集成服务检测'),
        (r'vpc|Virtual PC|VirtualPC|msvpc', 'Virtual PC 检测'),
        (r'wine|Wine|wine_get_version', 'Wine 检测'),
        (r'wine_get_version|wine_get_unix_file_name|ntdll\.wine|winecfg', 'Wine 环境检测（完整函数匹配）'),
        (r'wine.*version|GetVersion.*wine|kernel32.*wine', 'Wine 版本检测（注册表/API 查询）'),
        (r'anubis|Anubis|threat|ThreatExpert|Norman|JoeBox|CWSandbox', '在线沙箱检测'),
        (r'ACPI.*DSDT.*VBOX|ACPI.*DSDT.*VMWARE|ACPI.*FADT.*VBOX|ACPI.*FADT.*VMWARE', 'ACPI VM 检测'),
        (r'HAL.*ACPI.*PC|HAL.*VBOX|HAL.*VMWARE', 'HAL 检测'),
        (r'RegOpenKeyEx.*HARDWARE\\DESCRIPTION\\System\\BIOS', 'BIOS 注册表检测'),
        (r'RegQueryValueEx.*SystemProductName|SystemManufacturer|SystemSKU', 'BIOS 值检测'),
        (r'\\\\.\\pipe\\cuckoo|\\\\.\\pipe\\VBox', 'VM 管道检测'),
        (r'cpuid.*eax.*0x40000000|cpuid.*eax.*0x40000001', 'CPUID 超调用检测'),
        (r'__cpuid|__cpuidex|cpuid|CPUID|cpuid_level', 'CPUID 指令'),
        (r'rdmsr|wrmsr|__readmsr|__writemsr', 'MSR 寄存器检测'),
        (r'GetDiskFreeSpaceEx|GetDriveType|GlobalMemoryStatusEx', '资源限制检测'),
        (r'GetAdaptersInfo|GetAdaptersAddresses|NetWkstaGetInfo', '网络适配器检测'),
        (r'MAC.*00:50:56|MAC.*00:0c:29|MAC.*08:00:27|MAC.*52:54:00', 'VM MAC 地址检测'),
        (r'NumberOfProcessors|dwNumberOfProcessors|GetLogicalProcessorInformation', 'CPU 核心数检测'),
        (r'RegQueryValueEx.*VideoBiosVersion|VideoBiosDate', '显卡 BIOS 检测'),
        (r'dmidecode|DMI|SMBIOS|System Management BIOS', 'SMBIOS 检测'),
        (r'\\\\.\\Scsi|scsi.*virtual|scsi.*vmware|scsi.*vbox', 'SCSI 控制器检测'),
        (r'\\\\.\\IDE|IDE.*virtual|IDE.*vmware|IDE.*vbox', 'IDE 控制器检测'),
    ]
    
    # 5.2 七组条件反沙箱 (IsSandboxEnvironment@0x140002E20 行为模式)
    # 所有条件全部满足才继续执行, 任一不满足立即退出:
    # !IsDebuggerPresent && SM_CXSCREEN>=800 && CPU>=2 && GetTickCount>=300000
    # && 物理内存>=2GB && 进程数>=10 && 用户名不在黑名单
    SEVEN_CONDITION_SANDBOX_PATTERNS = [
        (r'(?=.*IsDebuggerPresent)(?=.*GetSystemMetrics)(?=.*(?:GetTickCount|GetTickCount64))'
         r'(?=.*(?:GlobalMemoryStatus|GlobalMemoryStatusEx|GetPhysicallyInstalledSystemMemory))'
         r'(?=.*(?:CreateToolhelp32Snapshot|Process32First|NtQuerySystemInformation))'
         r'(?=.*(?:GetUserName|GetEnvironmentVariable))',
         '七组条件反沙箱评分 (IsDebuggerPresent+分辨率+CPU+运行时长+内存+进程数+用户名黑名单)'),
        (r'IsDebuggerPresent.*GetSystemMetrics|GetSystemMetrics.*GetTickCount|GetTickCount.*GlobalMemoryStatus',
         '多条件串联环境检测 (反调试+分辨率+运行时长+内存 组合)'),
        (r'GetUserName.{0,200}(?:sandbox|malware|virus|sample|analysis|analyst)'
         r'|(?:sandbox|malware|virus|sample|analysis|analyst).{0,200}GetUserName'
         r'|GetEnvironmentVariable.{0,200}USERNAME.{0,200}(?:sandbox|malware|virus|sample|analysis|analyst)',
         '沙箱用户名黑名单检测 (GetUserName/环境变量 附近出现 sandbox/malware/virus/sample/analysis/analyst)'),
    ]
    
    ANTI_DEBUG_PATTERNS = [
        (r'IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess.*Debug', 'Windows 调试 API'),
        (r'NtQueryInformationProcess|ProcessDebugPort|ProcessDebugFlags|ProcessBasicInformation', 'NT 调试信息查询'),
        (r'NtSetInformationThread|ThreadHideFromDebugger', '线程隐藏调试器'),
        (r'OutputDebugString|OutputDebugStringA|OutputDebugStringW', '调试字符串检测'),
        (r'FindWindow.*OllyDbg|FindWindow.*x64dbg|FindWindow.*IDA|FindWindow.*Immunity', '调试器窗口检测'),
        (r'GetTickCount|timeGetTime|QueryPerformanceCounter|RDTSC|rdtsc', '时间检测调试器'),
        (r'CloseHandle.*INVALID_HANDLE|CloseHandle.*0xDEADBEEF', '异常句柄检测'),
        (r'SetUnhandledExceptionFilter|UnhandledExceptionFilter|AddVectoredExceptionHandler', '异常处理检测'),
        (r'NtContinue|NtSetContextThread|NtGetContextThread', '线程上下文检测'),
        (r'HeapSetInformation|HeapValidation|GetProcessHeap|RtlGetHeap', '堆检测调试器'),
        (r'GetModuleHandle.*dbghook|GetModuleHandle.*hook.*dll', 'Hook 模块检测'),
        (r'NtGlobalFlag|FLG_HEAP_ENABLE_TAIL_CHECK|FLG_HEAP_ENABLE_FREE_CHECK', 'NT 全局标志检测'),
        (r'BeingDebugged|ProcessHeap.*Flags|ProcessHeap.*ForceFlags', 'PEB 调试标志检测'),
        (r'INT3|CC|0xCC|int 3|int3|__debugbreak|DebugBreak', 'INT3 断点检测'),
        (r'0xEBFE|jmp.*\$-2|infinite loop|dead loop', '无限循环反调试'),
        # ⚠ 循环计数反调试: WaitForSingleObject(0) 循环 0x26000+ 次 —
        # 单步调试下计数不达标, 兼作系统性能判断 (QQ浏览器patch样本手法)
        (r'WaitForSingleObject.*0\s*[);,].*\+{2}|WaitForSingleObject.*\b0\b.*\+\+|loop.*WaitForSingleObject.*0',
         '超短超时循环计数反调试（WaitForSingleObject(0)+计数阈值）'),
        (r'NtCreateThreadEx|RtlCreateUserThread|CreateRemoteThread', '远程线程反调试'),
        # ===== PAGE_GUARD 反逆向 =====
        (r'PAGE_GUARD|PAGE_GUARD.*VirtualAlloc|VirtualAlloc.*PAGE_GUARD', '创建 PAGE_GUARD 内存页（反逆向/反调试）'),
        (r'VirtualProtect.*PAGE_GUARD|NtProtectVirtualMemory.*PAGE_GUARD', '修改为 PAGE_GUARD（反逆向触发）'),
        (r'PAGE_GUARD.*PAGE_EXECUTE|0x100|0x101', 'PAGE_GUARD + 可执行（Shellcode+反调试组合）'),
        # ===== 新增：PEB直接访问 / DLL枚举反调试 =====
        (r'NtCurrentPeb|__readfsdword.*0x18|__readgsqword.*0x60', '直接读取PEB结构（绕过API—反调试）'),
        (r'NtGlobalFlag.*0x70|NtGlobalFlag.*\b112\b|FLG_HEAP_ENABLE.*FLG_HEAP_VALIDATE', 'PEB NtGlobalFlag三标志组合检测（*70=堆检查全部启用）'),
        (r'DEBUGGER_PRESENT|DBG_PRESENT', '调试器存在标志字符串'),
        (r'K32EnumProcessModules.*tolower|K32GetModuleFileNameEx.*tolower|EnumProcessModules.*tolower', '枚举进程模块+DLL名小写比较（检测Hook DLL注入）'),
        (r'frida.*dll|frida-agent|sbie.*dll|dbghelp.*dll|dbgeng.*dll', '检测已知Hook/沙箱DLL加载（Frida/Sandboxie/调试器）'),
        (r'NTGLOBALFLAG_SET|NT.*GLOBAL.*FLAG.*SET', 'NtGlobalFlag设置标志字符串'),
    ]
    
    INJECTION_PATTERNS = [
        (r'VirtualAllocEx.*WriteProcessMemory.*CreateRemoteThread', '经典远程线程注入'),
        (r'NtCreateThreadEx|RtlCreateUserThread', 'NT 远程线程注入'),
        (r'QueueUserAPC|NtQueueApcThread', 'APC 注入'),
        (r'SetThreadContext.*ResumeThread', '线程上下文注入'),
        (r'NtMapViewOfSection.*NtCreateThreadEx', 'Section 映射注入'),
        (r'NtUnmapViewOfSection.*VirtualAllocEx', '进程镂空（Process Hollowing）'),
        (r'Process Hollowing|RunPE|RunPE2', 'RunPE 技术'),
        (r'ReflectiveLoader|reflective', '反射式加载'),
        (r'ManualMap|manual map', '手动映射'),
        (r'WOW64|heavens gate', 'Heavens Gate 技术'),
        # ===== 反射式 DLL 注入 / 内存载荷执行 =====
        (r'VirtualProtect.*PAGE_EXECUTE_READ|NtProtectVirtualMemory.*PAGE_EXECUTE_READ', 'RW→RX 内存保护变更（反射式 DLL 加载）'),
        (r'PAGE_EXECUTE_READ(?!WRITE)', '仅读-执行内存段（无写权限，代码注入/Shellcode）'),
        (r'WriteProcessMemory.*OpenProcess', '跨进程写入数据（代码注入）'),
        (r'OpenProcess.*PROCESS_VM_WRITE.*PROCESS_VM_OPERATION', '打开进程 VM 写权限（注入准备）'),
        (r'CreateRemoteThread.*LoadLibrary|RtlCreateUserThread.*LoadLibrary', '远程线程 LoadLibrary（经典 DLL 注入）'),
        # ===== Step Bear 内核注入 (Storm-0978): cbClsExtra 共享内存 + 窗口消息回调 + RPC 反序列化 =====
        (r'EM_SETWORDBREAKPROC|SetWordBreakProc', '编辑框回调设置（窗口消息执行代码—Step Bear手法）'),
        (r'cbClsExtra\s*=\s*(?:0x[0-9A-Fa-f]+|\d{4,})|cbClsExtra\s*>\s*0x28|cbClsExtra\s*=\s*1024\s*\*\s*64',
         '超大 cbClsExtra 窗口类（cls共享内存—跨进程payload传递）'),
        # ⚠ NdrServerCallAll/MIDL 是 RPC 运行时正常符号 (COM/DCOM 程序都有) —
        #   必须要求"劫持语义"上下文 (DispatchTable 覆盖/伪造接口指针), 否则误报
        (r'DispatchTable\w*\[\d+\]\s*=\s*\([^;]*?(?:0x[0-9A-Fa-f]+|REMOTE_|NdrServerCallAll)', 'RPC DispatchTable 覆盖（反序列化劫持—代码执行）'),
        (r'I_RpcFreePipeBuffer\s*\(|I_RpcGetBufferWithObject\s*\(', 'RPC 函数劫持（I_RpcFreePipeBuffer 回调—Step Bear 链）'),
        (r'RpcInterfaceInformation\s*=\s*(?:\([^;]*\))?(?:0x[0-9A-Fa-f]+|REMOTE_|\(RPC_SERVER_INTERFACE\*)',
         'RPC 接口结构伪造（构造假 MIDL_SERVER_INFO—反序列化利用）'),
        (r'PostMessage.*WM_LBUTTONDBLCLK|WM_LBUTTONDBLCLK.*PostMessage', '双击消息激活回调（notepad 编辑框触发链）'),
        (r'ZwQueryVirtualMemory.*PAGE_READONLY|MEM_PRIVATE.*PAGE_READONLY|PAGE_READONLY.*MEM_MAPPED',
         '全地址空间扫描只读页（定位 cls 共享内存标记）'),
    ]
    
    PRIVESC_PATTERNS = [
        # === UAC Bypass — 注册表 ===
        (r'UAC|ConsentPromptBehaviorAdmin|EnableLUA', 'UAC 绕过注册表操作'),
        (r'ConsentPromptBehaviorAdmin|EnableLUA.*0|PromptOnSecureDesktop', '修改 UAC 提示行为'),
        (r'Policies\\\\System\\\\.*ConsentPromptBehavior|Policies\\\\System\\\\.*EnableLUA', 'UAC 策略注册表修改'),
        # === UAC Bypass — 系统工具代理执行 ===
        (r'fodhelper\.exe', 'Fodhelper UAC 绕过 (T1548.002)'),
        (r'ComputerDefaults\.exe', 'ComputerDefaults UAC 绕过'),
        (r'sdclt\.exe', 'SDCLT UAC 绕过'),
        (r'eventvwr\.exe.*mmc', 'EventVwr UAC 绕过 (注册表劫持)'),
        (r'CompMgmtLauncher\.exe', 'CompMgmtLauncher UAC 绕过'),
        (r'DCCW\.exe|DCCWLauncher', 'DCCW UAC 绕过'),
        # === Token 特权操作 ===
        # ⚠ AdjustTokenPrivileges / LookupPrivilegeValue 这两个弱模式已移除:
        # Inno Setup/WPS 等正常安装器静态字符串里都有, 曾把 sysdiag 判成提权。
        # 现在由下方动态 API 调用记录精确判定。
        (r'SeDebugPrivilege', '启用 SeDebugPrivilege (调试进程→LSASS注入)'),
        (r'SeBackupPrivilege', '启用 SeBackupPrivilege (绕过ACL读文件)'),
        (r'SeRestorePrivilege', '启用 SeRestorePrivilege (绕过ACL写文件)'),
        (r'SeTakeOwnershipPrivilege', '启用 SeTakeOwnershipPrivilege (夺取所有权)'),
        (r'SeImpersonatePrivilege', '启用 SeImpersonatePrivilege (模拟令牌)'),
        (r'SeLoadDriverPrivilege', '启用 SeLoadDriverPrivilege (加载恶意驱动)'),
        (r'SeTcbPrivilege', '启用 SeTcbPrivilege (最高特权—ACT AS OS)'),
        (r'SeCreateTokenPrivilege', '启用 SeCreateTokenPrivilege (创建令牌)'),
        (r'OpenProcessToken.*TOKEN_ADJUST_PRIVILEGES', '打开进程令牌并修改特权'),
        # LookupPrivilegeValueW 弱模式已移除 — 正常程序也常查特权名,
        # 由动态 API 记录精确判定。
        # === 命名管道模拟 ===
        (r'NamedPipe|pipe.*impersonate|ImpersonateNamedPipeClient', '命名管道模拟 (T1134.001)'),
        (r'CreateNamedPipe.*ImpersonateNamedPipeClient', '创建命名管道+模拟客户端'),
        (r'ImpersonateLoggedOnUser', '模拟登录用户'),
        (r'RevertToSelf', '恢复自身令牌 (提权后切换)'),
        # === Kerberos 攻击 ===
        (r'Kerberoast|AS-REP|golden ticket|silver ticket', 'Kerberos 票据攻击'),
        (r'diamond ticket|sapphire ticket', 'Kerberos 高级票据伪造'),
        (r'LsaCallAuthenticationPackage.*Kerberos', 'LSA Kerberos 认证包调用'),
        # === 服务 / 驱动提权 ===
        (r'CreateServiceW.*SERVICE_KERNEL_DRIVER', '创建内核驱动服务 (加载恶意驱动)'),
        (r'StartServiceW.*SERVICE_KERNEL_DRIVER', '启动内核驱动 (驱动级提权)'),
        (r'OpenSCManager.*SC_MANAGER_ALL_ACCESS', '以完全权限打开SCM'),
        (r'ChangeServiceConfig.*SERVICE_USER.*LocalSystem', '修改服务账号为SYSTEM'),
        (r'sc\s+create.*binPath|sc\s+config.*binPath', 'sc 命令修改服务二进制路径'),
        (r'sc\s+start.*SERVICE_SYSTEM_START', '以SYSTEM权限启动服务'),
        # === DLL 劫持 / 搜索顺序劫持提权 ===
        (r'DLL.*SearchOrder|KnownDLLs|SafeDllSearchMode', 'DLL 搜索顺序劫持'),
        (r'SetDllDirectory|AddDllDirectory|RemoveDllDirectory', '修改 DLL 搜索路径'),
        (r'LoadLibrary.*\\Temp|LoadLibrary.*\\AppData|LoadLibrary.*\\Public', '从非系统路径加载 DLL (DLL侧加载)'),
        # === 计划任务 SYSTEM 提权 ===
        (r'schtasks.*(/Create|/create).*/ru SYSTEM', '创建SYSTEM权限计划任务'),
        (r'schtasks.*/rl HIGHEST', '创建最高权限计划任务'),
        (r'SCHTASKS /Create.*SCHTASKS /Run.*SCHTASKS /Delete', '计划任务一键三连 (提权后清理)'),
        # === 注册表提权键 ===
        (r'Image File Execution Options', 'IFEO 映像劫持 (T1546.012)'),
        (r'AppInit_DLLs', 'AppInit_DLLs 全局DLL注入'),
        (r'LoadAppInit_DLLs', '启用 AppInit_DLLs 全局注入'),
        (r'Shell\\.*Open\\.*Command', '修改文件关联命令 (T1546.001)'),
        (r'Active Setup\\Installed Components', 'Active Setup 持久化/提权'),
        (r'BootExecute|Session Manager', 'BootExecute/SessionManager (启动时SYSTEM执行)'),
        # === WMI 提权 ===
        (r'__EventFilter.*__FilterToConsumerBinding', 'WMI 事件过滤器绑定'),
        (r'ActiveScriptEventConsumer|CommandLineEventConsumer', 'WMI 事件消费者 (持久化/提权)'),
        (r'__Namespace.*root/subscription', 'WMI 订阅命名空间操作'),
        # === Bypass AMSI / ETW ===
        (r'amsi.*scan|amsi.*buffer|AmsiScanBuffer', 'AMSI 扫描缓冲区操作'),
        (r'amsi.*patch|amsi.*hook|amsi.*bypass|AmsiInitialize', 'AMSI 补丁/绕过'),
        (r'etw.*patch|etw.*hook|EtwEventWrite|NtTraceEvent', 'ETW 补丁/绕过'),
        (r'SetConsoleMode.*GetStdHandle|WriteConsole', '控制台绕过AMSI'),
        # === 进程/线程 令牌窃取 ===
        (r'OpenProcessToken.*DuplicateTokenEx', '打开令牌→复制令牌 (令牌窃取)'),
        (r'DuplicateTokenEx.*SecurityImpersonation', '复制模拟令牌'),
        (r'CreateProcessWithTokenW', '使用窃取的令牌创建进程'),
        (r'CreateProcessAsUserW', '以其他用户身份创建进程'),
        (r'CreateProcessWithLogonW', '以登录凭据创建进程 (RunAs)'),
        # === 提权利用漏洞特征 ===
        (r'CVE-\d{4}-\d+|exploit|privilege escalation|0day', '已知漏洞利用/提权引用'),
        (r'EoP|LPE|local.*privilege.*escalation', '本地提权 (LPE) 关键词'),
        (r'PrintSpoofer|Potato|Juicy.*Potato|RoguePotato|SweetPotato', 'Potato 系列提权工具'),
        (r'GodPotato|EfsPotato|RemotePotato0', 'Potato 变种提权'),
        (r'PrintNotify|pipe.*spoolss|RpcOpenPrinter', '打印后台处理程序利用 (PrintSpoofer)'),
    ]

    # ===== UAC 绕过专有检测 =====
    UAC_BYPASS_PATTERNS = [
        (r'ConsentPromptBehaviorAdmin|EnableLUA.*0|PromptOnSecureDesktop', 'UAC提示行为修改'),
        (r'Policies\\\\System\\\\.*ConsentPromptBehavior|Policies\\\\System\\\\.*EnableLUA', 'UAC策略注册表修改'),
        (r'fodhelper\.exe.*\\shell\\open\\command', 'Fodhelper UAC绕过 (注册表劫持)'),
        (r'ComputerDefaults\.exe.*\\shell\\open\\command', 'ComputerDefaults UAC绕过'),
        (r'sdclt\.exe|sdclt.*Elevation', 'SDCLT UAC绕过'),
        (r'eventvwr\.exe.*mmc\.exe', 'EventVwr UAC绕过 (MMC劫持)'),
        (r'CompMgmtLauncher\.exe', 'CompMgmtLauncher UAC绕过'),
        (r'DiskCleanup.*/d.*\\windows\\system32', 'DiskCleanup UAC绕过'),
        (r'wscript\.exe.*slmgr\.vbs', 'slmgr UAC绕过'),
        (r'WSReset\.exe', 'WSReset UAC绕过 (Windows Store)'),
        (r'cmstp\.exe.*/s', 'CMSTP UAC绕过'),
        (r'/quiet.*/norestart|/qn.*/norestart', '静默安装提权'),
        (r'AlwaysInstallElevated.*1', 'AlwaysInstallElevated MSI提权'),
        (r'DisableMSI.*0', '禁用 MSI 限制'),
        (r'EnableLUA.*0', '完全禁用 UAC'),
    ]

    # ===== API 调用链检测 =====
    API_CHAIN_PATTERNS = [
        (r'VirtualAlloc.*WriteProcessMemory.*CreateRemoteThread', '经典进程注入三连'),
        (r'OpenProcess.*VirtualAllocEx.*WriteProcessMemory', '远程进程操作链'),
        (r'LoadLibrary.*GetProcAddress.*CreateThread', '动态API解析+线程创建'),
        (r'InternetOpen.*InternetConnect.*HttpSendRequest.*InternetReadFile', 'HTTP下载链'),
        (r'FindFirstFile.*FindNextFile.*WriteFile', '文件枚举+写入'),
        (r'OpenSCManager.*CreateService.*StartService', '服务创建+启动链'),
        (r'CryptAcquireContext.*CryptCreateHash.*CryptEncrypt', '加密API调用链'),
        # ===== 新增：线程劫持 / 直接系统调用注入链 =====
        (r'CreateProcess.*CREATE_SUSPENDED.*VirtualAllocEx.*WriteProcessMemory.*SetThreadContext.*ResumeThread', '挂起进程→分配→写入→劫持上下文→恢复（线程劫持注入全链路）'),
        (r'ZwAllocateVirtualMemory.*ZwWriteVirtualMemory.*ZwProtectVirtualMemory.*ZwSetContextThread.*ZwResumeThread', 'Zw系统调用注入链（绕过用户态Hook—Halo\'s Gate风格）'),
        (r'VirtualAllocEx.*WriteProcessMemory.*VirtualProtectEx.*SetThreadContext', 'RW→RX权限切换+线程劫持（RWX规避）'),
    ]

    # ===== 凭据转储检测 =====
    CREDENTIAL_DUMP_PATTERNS = [
        (r'lsass\.exe|MiniDumpWriteDump.*lsass', 'LSASS 内存 Dump'),
        (r'CreateFile.*lsass\.dmp', '创建 LSASS dump 文件'),
        (r'reg\.exe.*save.*(?:SAM|SYSTEM|SECURITY)', 'reg save 导出凭据数据库'),
        (r'CopyFile.*\\Windows\\System32\\config\\(?:SAM|SYSTEM)', '复制 SAM/SYSTEM 文件'),
        (r'CreateFile.*\\Windows\\NTDS\\ntds\.dit', '读取 NTDS.dit (域控凭据)'),
        (r'mimikatz|MimiKatz|mimilib|sekurlsa', 'MimiKatz 凭据提取工具'),
        # ===== EDRSandBlast (红队 EDR 绕过工具 — 内核回调删除 + LSASS 转储) =====
        (r'EDRSandblast|NtoskrnlOffsets\.csv|WdigestOffsets\.csv|unhook_method|--kernelmode|--usermode',
         'EDRSandBlast 红队工具特征（EDR绕过/LSASS转储—内核回调删除+ETW禁用）'),
        (r'g_fParameter_useLogonCredential|g_IsCredGuardEnabled|WdigestOffsets',
         'Credential Guard 绕过特征（wdigest 明文凭据修补—LSASS转储前置）'),
        (r'ProviderEnableInfo|EtwThreatIntProvRegHandleOffset|OB_CALLBACK_ENTRY|PspCreateProcessNotifyRoutine',
         '内核回调/ETW 禁用特征（EDR 监控绕过—内核级）'),
        (r'UNHOOK_WITH_NTPROTECTVIRTUALMEMORY|UNHOOK_WITH_DIRECT_SYSCALL|UNHOOK_WITH_EDR',
         'API Unhooking 技术（EDR 用户态 Hook 绕过—解钩）'),
        (r'comsvcs\.dll.*MiniDump|rundll32.*comsvcs', 'comsvcs.dll 内存Dump (LotL)'),
        (r'CryptUnprotectData.*master.?key', 'DPAPI 主密钥解密'),
        (r'vaultcli\.dll|VaultEnumerateItems', 'Windows Vault 凭据枚举'),
    ]

    # ===== PII / 敏感数据泄露 =====
    PII_EXFIL_PATTERNS = [
        (r'\b\d{16,19}\b', '信用卡号格式 (16-19位纯数字)'),
        (r'password\s*=\s*["\']|passwd\s*=\s*["\']|pwd\s*=\s*["\']', '硬编码密码/凭据'),
        (r'connectionString|Server=.*Database=.*Password=', '数据库连接字符串'),
        (r'API[_-]?KEY|api[_-]?key|access[_-]?token', '硬编码API密钥/Token'),
        (r'BEGIN RSA PRIVATE KEY|BEGIN EC PRIVATE KEY', '内嵌私钥'),
    ]

    # ===== 宏/文档攻击检测 =====
    MACRO_ATTACK_PATTERNS = [
        (r'AutoOpen|Auto_Open|Document_Open|Workbook_Open', 'Office 自动宏触发器'),
        (r'CreateObject.*WScript\.Shell|CreateObject.*Scripting\.FileSystemObject', 'VBA 创建Shell/文件对象'),
        (r'Chr\(\d+\)\s*&\s*Chr\(\d+\)', 'VBA 字符串混淆 (Chr拼接)'),
        (r'Shell\s*\(|Call\s+Shell\s*\(', 'VBA Shell 执行命令'),
        # ===== 宏字符串混淆: 插入垃圾串再 Replace 移除 (Kimsuky/韩系 APT 手法) =====
        (r'vnslavnsla|vnslasla|wraevnsla|Nwraew', '宏字符串混淆（垃圾串插入+Replace去杂—Kimsuky手法）'),
        (r'Replace\([^,)]*,[^,)]*,\s*""\s*\).*Replace\(',
         '宏多重 Replace 去杂混淆（隐藏真实字符串）'),
        (r'DDEAUTO|DDE.*\\\.\.\\\.\.', 'DDE 自动执行攻击'),
    ]

    # ===== 自启动持久化增强 =====
    AUTORUN_PERSIST_PATTERNS = [
        (r'Winlogon\\\\Shell|Winlogon\\\\Userinit', 'Winlogon Shell 劫持'),
        (r'AppInit_DLLs|AppCertDlls', '全局 DLL 注入 (AppInit/AppCert)'),
        (r'BootExecute|Session Manager.*Execute', 'BootExecute 启动项'),
        (r'\\Explorer\\ShellServiceObjects', 'ShellServiceObject 劫持'),
        (r'reg\s+add.*\\Run.*/f', 'reg add 强制写入 Run 键'),
        (r'schtasks.*/create.*/sc\s+(?:onlogon|onstart|daily|hourly)', '计划任务持久化 (登入/启动)'),
    ]

    # ===== 浏览器凭据窃取 =====
    BROWSER_CRED_PATTERNS = [
        (r'Chrome.*\\User Data\\Default\\Login Data', 'Chrome 登录凭据'),
        (r'Chrome.*\\User Data\\Default\\Cookies', 'Chrome Cookie'),
        (r'Firefox\\Profiles\\.*\\logins\.json', 'Firefox 登录凭据'),
        (r'Firefox\\Profiles\\.*\\key4\.db|key3\.db', 'Firefox 加密密钥'),
        (r'wallet\.dat|wallet\.json|metamask|ethereum.*keystore', '加密钱包文件'),
        (r'FileZilla.*recentservers\.xml|FileZilla.*sitemanager\.xml', 'FileZilla FTP 凭据'),
        (r'PuTTY\\SshHostKeys|known_hosts', 'SSH 已知主机/密钥'),
        (r'LastPass|1Password|Dashlane|Bitwarden', '密码管理器引用'),
    ]

    # ===== 横向移动检测 =====
    LATERAL_MOVEMENT_PATTERNS = [
        # PsExec / 远程服务创建
        (r'PsExec|PsExec\.exe|psexec', 'PsExec 远程执行工具'),
        (r'\\admin\$|\\C\$|\\IPC\$', r'Windows 管理共享访问 (admin$/C$/IPC$)'),
        (r'\\[\w.-]+\[\w]+\$\.exe', '远程共享文件执行 (UNC路径EXE)'),
        (r'net\s+use\s+\\', 'net use 远程共享映射'),
        # 远程服务 (SC)
        (r'sc\s+\\\\.*create', 'SC 远程服务创建'),
        (r'sc\s+\\\\.*start', 'SC 远程服务启动'),
        (r'sc\s+\\\\.*config', 'SC 远程服务配置'),
        # 远程计划任务
        (r'schtasks.*/s\s+\\', '远程计划任务创建'),
        (r'schtasks.*/u\s+[\w.]+.*/p\s+', '计划任务带凭据 (远程执行)'),
        # 远程 WMI
        (r'winrm\s+|winrs\s+|Enter-PSSession|Invoke-Command', 'WinRM/PowerShell 远程会话'),
        (r'wmic\s+/node:', 'WMI 远程执行 (/node 参数)'),
        (r'wmic\s+/user:.*/password:', 'WMI 远程带凭据执行'),
        (r'/NAMESPACE:.*\\\\.*root', 'WMI 远程命名空间'),
        # 远程 DCOM
        (r'CoCreateInstanceEx|CLSCTX_REMOTE_SERVER|COAUTHINFO', 'DCOM 远程对象激活'),
        (r'MMC20\.Application|ShellWindows|ShellBrowserWindow', 'DCOM 横向移动对象'),
        (r'Excel\.Application.*DCOM|Outlook\.Application.*DCOM', 'Office DCOM 滥用'),
        # 远程注册表
        (r'RegConnectRegistry|\\\\.*\\[A-Z]:\\', '远程注册表连接'),
        (r'reg\s+query\s+\\\\.*\\HK', 'reg query 远程注册表'),
        # RDP
        (r'EnableRemoteDesktop|fDenyTSConnections.*0', '启用远程桌面'),
        (r'reg.*Terminal Server.*TSUserEnabled', '启用 RDP 用户'),
        (r'netsh.*portproxy.*v4tov4', 'netsh 端口转发 (RDP隧道)'),
        (r'RDPWRAP|rdpwrap|RDP Wrapper', 'RDP Wrapper 工具'),
        # Pass-the-Hash / Pass-the-Ticket
        (r'sekurlsa::pth|pth-winexe|wmiexec\.py', 'Pass-the-Hash 工具'),
        (r'sekurlsa::tickets|kerberos::ptt', 'Pass-the-Ticket (Kerberos票据传递)'),
        (r'sekurlsa::ekeys|lsadump::dcsync', 'DCSync / eKeys 导出'),
        (r'mimikatz.*sekurlsa::logonpasswords', 'Mimikatz 凭据导出 (横向移动前置)'),
        # 远程文件复制
        (r'copy.*\\\\.*\\admin\$|xcopy.*\\\\.*\\C\$', r'向远程ADMIN$复制文件'),
        (r'robocopy.*\\\\.*\\admin\$', 'robocopy 远程复制'),
        # SSH 横向
        (r'ssh\s+[\w.-]+@[\w.-]+.*-o.*StrictHostKeyChecking=no', 'SSH 忽略主机密钥 (自动化攻击)'),
        (r'ssh-keygen.*-t\s+rsa.*-N\s+["\']', 'SSH 密钥生成 (免密横向)'),
        (r'authorized_keys|id_rsa\.pub', 'SSH 公钥部署'),
        # BloodHound / SharpHound
        (r'SharpHound|BloodHound|bloodhound', 'BloodHound 域侦察工具'),
        (r'Invoke-BloodHound|Get-BloodHoundData|Get-NetSession', 'BloodHound PS脚本'),
        (r'Get-DomainController|Get-DomainUser|Get-DomainComputer', 'PowerView 域枚举'),
        # 其它横向工具
        (r'CrackMapExec|crackmapexec|cme\s+smb', 'CrackMapExec 横向工具'),
        (r'Impacket|impacket|impacket-secretsdump', 'Impacket 横向工具集'),
        (r'secretsdump\.py|samrdump\.py', 'Impacket 凭据导出'),
        (r'Invoke-TheHash|Invoke-SMBExec|Invoke-WMIExec', 'PowerShell 横向工具'),
    ]

    # ===== 侦察/网络发现 =====
    RECON_DISCOVERY_PATTERNS = [
        # 网络扫描
        (r'net\s+view\s+/domain', 'net view 域计算机枚举'),
        (r'net\s+view\s+\\', 'net view 远程计算机枚举'),
        (r'nltest\s+/dclist:', 'nltest 域控制器列表'),
        (r'nltest\s+/domain_trusts', 'nltest 域信任关系'),
        (r'ping\s+-n\s+\d+\s+[\d.]+', 'ping 扫描 (主机探测)'),
        (r'nmap|Nmap|nmap\s+-s[STUP]', 'Nmap 端口扫描'),
        (r'-sS\s+-sV\s+-O\s+-p\s+', 'Nmap 服务/OS探测参数'),
        # ARP / 网络嗅探
        (r'arp\s+-a', 'ARP 表查询 (主机发现)'),
        (r'Wireshark|wireshark|tcpdump|WinPcap|Npcap', '网络嗅探工具'),
        (r'promiscuous|混杂模式|raw\s+socket|SIO_RCVALL', '网卡混杂模式/原始套接字'),
        (r'WinPcap.*packet\.dll|pcap_loop|pcap_next_ex', 'WinPcap 抓包API'),
        # 域信息收集
        (r'net\s+group\s+/domain', 'AD 组枚举'),
        (r'net\s+user\s+/domain', 'AD 用户枚举'),
        (r'net\s+localgroup\s+administrators', '本地管理员组查询'),
        (r'dsquery\s+computer|dsquery\s+user', 'dsquery AD 查询'),
        (r'Get-ADUser|Get-ADComputer|Get-ADGroup', 'AD PowerShell 枚举'),
        (r'netsh\s+advfirewall\s+show', '防火墙规则查询 (侦察)'),
        (r'ipconfig\s+/all|route\s+print|tracert', '网络拓扑探测'),
        # 进程/服务侦察
        (r'tasklist\s+/v|tasklist\s+/svc', '进程列表+服务 (侦察)'),
        (r'net\s+start|sc\s+query', '服务状态枚举'),
        (r'wmic\s+process\s+list|wmic\s+service\s+list', 'WMI 进程/服务枚举'),
        # 文件/共享侦察
        (r'net\s+share|net\s+view\s+/all', '共享资源枚举'),
        (r'dir\s+/s\s+\\\\', '远程共享文件遍历'),
        # Kerberoasting
        (r'Kerberoast|kerberoast|Invoke-Kerberoast', 'Kerberoasting 攻击'),
        (r'AS-REP.*Roast|ASREPRoast|Get-ASREPHash', 'AS-REP Roasting'),
        (r'Get-SPN|Get-DomainSPNTicket', 'SPN 票据请求'),
    ]

    # ===== 攻击链组合检测 =====
    ATTACK_CHAIN_PATTERNS = [
        # 初始访问
        (r'Spear[_-]?phish|phishing|malicious.*attachment', '鱼叉式钓鱼/恶意附件'),
        (r'exploit.*CVE-\d{4}-\d{4,}', '已知漏洞利用 (CVE)'),
        (r'Remote.*Code.*Execution|RCE', '远程代码执行'),
        # 执行阶段
        (r'rundll32.*javascript:', 'rundll32 JavaScript 执行'),
        (r'mshta.*javascript:|mshta.*vbscript:', 'mshta 脚本执行'),
        (r'regsvr32.*/s.*/u.*/i:', 'regsvr32 远程脚本执行 (Squiblydoo)'),
        (r'msbuild.*\.xml|msbuild.*\.proj', 'MSBuild 内联任务执行'),
        (r'InstallUtil.*\.dll', 'InstallUtil DLL 执行'),
        (r'csc\.exe.*\.cs|CodeDom|Compiler\.Compile', 'C# 动态编译执行'),
        # 持久化
        (r'Get-ScheduledTask.*-TaskName.*New-ScheduledTaskAction', 'PowerShell 计划任务创建'),
        (r'New-ItemProperty.*-Path.*\\Run', 'PowerShell 注册表 Run 键'),
        (r'Set-ItemProperty.*-Path.*\\Run', 'PowerShell 修改 Run 键'),
        # 防御绕过
        (r'Set-MpPreference.*-DisableRealtimeMonitoring\s+\$true', 'PowerShell 禁用实时保护'),
        (r'Add-MpPreference.*-ExclusionPath.*[A-Z]:\\', 'PowerShell 添加排除路径'),
        (r'Unregister-ScheduledTask.*Windows\s*Defender', '取消 Defender 计划任务'),
        (r'Set-ExecutionPolicy\s+(?:Bypass|Unrestricted)', '修改执行策略绕过'),
        # 凭据访问
        (r'vaultcmd\s+/list|vaultcmd\s+/listcreds', 'vaultcmd 凭据列表'),
        (r'rundll32.*keymgr\.dll.*KRShowKeyMgr', '凭据管理器 GUI 调用'),
        # 发现
        (r'whoami\s+/all|whoami\s+/groups|whoami\s+/priv', 'whoami 权限枚举'),
        (r'quser|qwinsta|query\s+user', '登录会话查询'),
        (r'qwinsta\s+/server:', '远程登录会话查询'),
        # 横向移动
        (r'Enter-PSSession.*-ComputerName|Invoke-Command.*-ComputerName', 'PowerShell 远程会话'),
        (r'Copy-Item.*-ToSession|Copy-Item.*-FromSession', 'PowerShell 远程文件复制'),
        # 收集
        (r'Get-ChildItem.*-Recurse.*-Filter.*\.(?:doc|pdf|xls|txt)', 'PowerShell 文件搜索收集'),
        (r'Compress-Archive.*-Path.*\\.*\\.*', 'PowerShell 压缩收集'),
        (r'findstr\s+/s\s+/i\s+password', 'findstr 搜索密码文件'),
        # C2
        (r'Invoke-WebRequest.*-UseBasicParsing.*-Uri\s+http', 'PowerShell 下载执行'),
        (r'Net\.WebClient.*DownloadString|Net\.WebClient.*DownloadFile', '.NET WebClient 下载'),
        (r'Start-BitsTransfer.*-Source\s+http', 'BITS 文件传输'),
        # 数据渗出
        (r'Send-MailMessage.*-Attachments', 'PowerShell 邮件附件渗出'),
        (r'Invoke-RestMethod.*-Method\s+Post.*-Body', 'PowerShell HTTP POST 渗出'),
        (r'ftp\s+-s:|ftp\s+open\s+[\w.]+', 'FTP 脚本渗出'),
        (r'bitsadmin\s+/transfer', 'BITSAdmin 下载/上传'),
        # 影响
        (r'Remove-Item.*-Recurse.*-Force.*[A-Z]:\\', 'PowerShell 递归删除 (磁盘破坏)'),
        (r'Stop-Computer|Restart-Computer.*-Force', 'PowerShell 关机/重启'),
        (r'Clear-EventLog.*-LogName\s+(?:Security|System|Application)', '清除 Windows 事件日志'),
        (r'wevtutil\s+cl\s+(?:System|Security|Application)', 'wevtutil 清除日志'),
        (r'fsutil\s+usn\s+deletejournal', 'USN 日志删除 (反取证)'),
    ]

    HOSTS_TAMPER_PATTERNS = [
        (r'\\etc\\hosts|\\\\drivers\\\\etc\\\\hosts|hosts file', '修改系统 Hosts 文件（DNS 劫持）'),
        (r'WriteFile.*hosts|CreateFile.*hosts|fopen.*hosts', '写入 Hosts 文件'),
        (r'ReadFile.*hosts|CreateFileW.*hosts', '读取 Hosts 文件（侦察）'),
    ]

    # ===== PowerShell 注册表持久化 =====
    POWERSHELL_PERSIST_PATTERNS = [
        (r'powershell.*reg.*add|powershell.*Set-ItemProperty|powershell.*New-ItemProperty', 'PowerShell 添加注册表项（持久化）'),
        (r'powershell.*-enc\s|powershell.*-EncodedCommand|powershell.*FromBase64String', 'PowerShell 编码命令执行'),
        (r'powershell.*IEX\s*\(|powershell.*Invoke-Expression|powershell.*Invoke-WebRequest', 'PowerShell 远程下载执行'),
    ]

    # ===== 文件属性删除标记 =====
    FILE_DELETE_MARK_PATTERNS = [
        (r'FILE_FLAG_DELETE_ON_CLOSE|NtSetInformationFile.*DeleteFile|SetFileInformationByHandle.*Delete', '标记文件关闭时删除（反取证）'),
        (r'MoveFileEx.*MOVEFILE_DELAY_UNTIL_REBOOT|NtDeleteFile|DeleteFileW', '延迟删除文件（重启前反取证）'),
    ]
    
    DATA_THEFT_PATTERNS = [
        # ⚠ 收紧: 旧模式把正常 API/词当窃密特征 (GetKeyState 按键查询/password 对话框/
        #   crypto 匹配 cryptography/BitBlt·GetDC 是正常绘画 API/FTP·SSH 是协议词)。
        #   窃密判定应依赖高置信特征, 否则每个正常程序都被标"凭证窃取"
        (r'AddClipboardFormatListener|GetClipboardSequenceNumber.*GetClipboardData|OpenClipboard.*GetClipboardData.*Sleep', '剪贴板监控'),
        (r'GetAsyncKeyState.*GetKeyState|SetWindowsHookEx.*WH_KEYBOARD_LL', '键盘记录'),
        (r'PrintWindow|BitBlt.*CreateCompatible(?:DC|Bitmap)|GetWindowDC.*BitBlt|DwmRegisterThumbnail', '屏幕截图'),
        (r'Login Data|Cookies.*Web Data|History.*Bookmarks|Local Storage.*leveldb', '浏览器数据窃取'),
        (r'dpapi|masterkey|LSASS|lsa secrets|NTDS\.dit|SAM\.dll|vaultcmd', '凭证窃取'),
        (r'wallet\.dat|bitcoin|ethereum|monero|mnemonic|seed phrase|phantom|metamask', '加密钱包窃取'),
        (r'Outlook.*PST|PST.*OST|Thunderbird|Mail\.dat|Apple Mail', '邮件数据窃取'),
        (r'FileZilla|WinSCP|Putty|mRemoteNG|KeePass|MobaXterm|CyberDuck|1Password', '远程工具凭证窃取'),
    ]
    
    RANSOMWARE_PATTERNS = [
        # ⚠ 收紧: 旧规则 (encrypt.*file / README|DECRYPT|RECOVER|RESTORE 单词表) 命中面过大 —
        #   RECOVER 匹配 recovery、RESTORE 是系统恢复正常词、BCryptEncrypt 含 encrypt。
        #   真勒索特征 = 全大写勒索信标题/明确扩展名/加密全部数据声明。
        (r'encrypt.*all\s+(?:files?|data|drives?)|encrypt.*every\s+\w+|ransomware', '文件加密'),
        (r'\.(?:encrypted|locked|crypto|vault|wlu|leto)$', '加密扩展名'),
        (r'README[_. ]+TO[_. ]+DECRYPT|HOW_TO[_. ]+(?:DECRYPT|UNLOCK|RECOVER)|DECRYPT[_. ]+FILES|YOUR[_. ]+FILES[_. ]+ENCRYPTED|RANSOM[_. ]+NOTE', '赎金通知'),
        (r'bitcoin|btc|monero|xmr|ethereum|eth|payment|ransom', '赎金要求'),
        (r'vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete', '卷影删除'),
        (r'wbadmin.*delete.*catalog|bcdedit.*delete', '备份删除'),
    ]

    # ===== 感染型木马 (文件感染 — 与勒索不同: 不改名/不删原文件, 只加密文件头) =====
    INFECTION_PATTERNS = [
        (r'0xAABBCCDD|AABBCCDD', '感染标记 (resvr 病毒已感染标志)'),
        (r'SetFilePointer.*0x400|Seek.*0x400|ReadFile.*0x400|头部.*0x400.*xor|xor.*0x400',
         '文件头 0x400 字节 XOR 加密（感染型木马特征）'),
        (r'\.doc.*\.xls.*\.jpg.*\.rar|doc.*xls.*jpg.*rar|扩展名.*感染',
         '指定扩展名感染 (doc/xls/jpg/rar—感染型木马目标)'),
        (r'[A-Z]:\\\\\\.*(?:doc|xls|jpg|rar)|遍历.*盘符.*感染|ABCDEFGHIJKLMNOPQRSTUVWXYZ',
         '遍历所有盘符感染文件（感染型木马全盘传播）'),
        (r'127\.0\.0\.1.*40(?:118|000|00[0-9])|bind.*40118|socket.*listen.*40118',
         '本地监听 socket (resvr: 127.0.0.1:40118 等待远程控制)'),
        (r'ddCmdMsg|dwCmdMsg|CmdMsg\+|命令类型.*8字节|前8字节.*命令',
         '远程控制命令协议（ddCmdMsg 前8字节命令类型）'),
        (r'Index\.bat|X\.bat|\\Microsoft Shared\\', 'DOS 命令 bat 释放 (Index.bat/X.bat—远程控制辅助)'),
        (r'net\s+user\s+Guest|net\s+user\s+guest\s+/add|Guest\s+账户',
         '创建 Guest 系统账户（远程控制后门账户）'),
    ]
    
    C2_PATTERNS = [
        (r'base64.*decode|decode.*base64|FromBase64String', 'Base64 通信编码'),
        (r'AES.*encrypt|AES.*decrypt|ChaCha|Salsa|RC4|XOR', '加密通信'),
        (r'Domain Generation|DGA|domain.*generation|generate.*domain', 'DGA 域名生成'),
        (r'HTTP.*POST|POST.*data|GET.*command|cmd=', 'HTTP C2'),
        (r'DNS.*tunnel|DNS.*exfil|DNS.*c2', 'DNS 隧道'),
        (r'WebSocket|Socket\.IO|SignalR|gRPC', '高级通信协议'),
        (r'Pastebin|GitHub|Twitter|Telegram|Discord', '合法平台 C2'),
        # ⚠ Tor 加词边界: 无边界 Tor 匹配 monitor/editor/factor 等正常词 (IGNORECASE 下尤甚)
        (r'\bTor\b|\bonion\b|tor2web|TorBrowser', 'Tor 网络'),
        # ===== Kimsuky APT 家族特征 =====
        (r'----WebKitFormBoundarywhpFxMBe19cSjFnG|WebKitFormBoundarywhpFxMBe19cSjFnG',
         'Kimsuky 特征 multipart boundary（信息回传协议）'),
        (r'Alzipupdate', 'Kimsuky 持久化键名（伪装解压工具更新—Run键）'),
        (r'mybobo\.mygamesonline\.org|pingguo2\.atwebpages\.com|uekaf\.myartsonline\.com',
         'Kimsuky C2 域名'),
        (r'flower01|bobo\.txt|/ha/nn\.txt|download\.php\?filename=',
         'Kimsuky 载荷命名/下载路径特征'),
        # 多阶段 C2: 下载→del.php 删除服务器载荷 (Kimsuky 近期手法)
        (r'del\.php\?filename=|/down$|\.down[\s"\']', '多阶段 C2（下载+服务器清理）'),
    ]
    
    ROOTKIT_PATTERNS = [
        (r'ZwLoadDriver|NtLoadDriver|IOCreateDriver', '驱动加载'),
        (r'\\Device\\|\\Driver\\|\\\\.\\', '内核设备操作'),
        (r'MmMapIoSpace|IoAllocateMdl|ZwMapViewOfSection', '内核内存操作'),
        (r'PsSetCreateProcessNotifyRoutine|PsSetCreateThreadNotifyRoutine', '进程/线程监控回调'),
        (r'SSDT|KiServiceTable|SystemServiceDescriptorTable', 'SSDT Hook'),
        (r'IRP_MJ_|MajorFunction|FastIo', 'IRP Hook'),
        (r'MBR|boot sector|VBR|volume boot', '引导扇区操作'),
        (r'\\\\\\.\\PhysicalDrive|\\\0\\PhysicalDrive|NtReadFile.*PhysicalDrive', '物理磁盘访问'),
    ]

    SHELLCODE_PATTERNS = [
        (r'VirtualAlloc.*0x[0-9a-fA-F]+|VirtualAllocEx.*PAGE_EXECUTE', '可执行内存分配（疑似 Shellcode）'),
        (r'PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY', 'RWX 内存分配'),
        (r'VirtualProtect.*PAGE_EXECUTE|NtProtectVirtualMemory.*PAGE_EXECUTE', '修改内存保护为可执行'),
        (r'memcpy.*alloc|memmove.*alloc|RtlMoveMemory', '内存复制到动态分配区域'),
        (r'WriteProcessMemory.*VirtualAlloc|WriteProcessMemory.*NtAllocateVirtualMemory', '跨进程写入+执行'),
        (r'0x[0-9a-fA-F]{8,}', '硬编码大段十六进制数据'),
        (r'\\\\x[0-9a-fA-F]{2}', 'shellcode 字节模式'),
    ]

    FILE_CREATION_PATTERNS = [
        (r'CreateFile.*\.exe|CreateFile.*\.dll|CreateFile.*\.scr|CreateFile.*\.sys', '创建可执行文件'),
        (r'CreateFile.*AppData\\\\Roaming|CreateFile.*AppData\\\\Local|CreateFile.*\\\\Temp', '在用户/临时目录创建文件'),
        (r'CreateFile.*\\\\Start Menu|CreateFile.*\\\\Startup|CreateFile.*\\\\Programs', '创建启动项/快捷方式位置'),
        (r'IShellLink|CoCreateInstance.*ShellLink|IPersistFile', '创建快捷方式（ShellLink COM）'),
        (r'\.lnk|\.url|CreateShortcut|SHFileOperation', '快捷方式/URL 文件操作'),
        (r'WriteFile.*\.exe|WriteFile.*\.dll|WriteFile.*\.bat|WriteFile.*\.vbs', '写入可执行/脚本文件'),
    ]

    DEAD_CONNECTION_PATTERNS = [
        (r'connect.*0\.0\.0\.0|connect.*127\.0\.0\.\d+|connect.*\.local', '连接到无效/回环地址'),
        (r'socket.*connect.*timeout|connect.*WSAETIMEDOUT|connect.*refused', '连接超时/被拒'),
        (r'gethostbyname.*fail|getaddrinfo.*fail|WSAStartup.*fail', 'DNS 解析失败后的行为'),
        (r'connect.*retry|reconnect|try.*connect|attempt.*connect', '连接重试（可能测试网络）'),
    ]

    PERSISTENCE_PATTERNS = [
        (r'schtasks.*(/Create|/create)|Create.*schtasks', '创建计划任务（schtasks）'),
        (r'SCHTASKS /Create|SCHTASKS.*\/Create|SCHTASKS.*\/F', '强制创建计划任务'),
        (r'/TN.*Task|TaskName|SCHTASKS.*\/TN', '命名计划任务'),
        (r'reg.*add.*\\Run|reg.*add.*CurrentVersion\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\Run', '注册表 Run 键持久化'),
        (r'CopyFile.*Startup|SHFileOperation.*Startup|Start Menu\\\\Programs\\\\Startup', '启动文件夹持久化'),
        (r'CreateService|StartService|OpenSCManager|SERVICE_AUTO_START', '创建系统服务持久化'),
        (r'WMI.*__InstanceCreationEvent|WMI.*ActiveScriptEventConsumer|CommandLineEventConsumer', 'WMI 事件持久化'),
    ]

    DEFENDER_PATTERNS = [
        (r'Windows Defender\\\\Exclusions\\\\Paths', '添加 Defender 排除路径'),
        (r'Exclusions\\\\Extensions|Exclusions\\\\Processes|Exclusions\\\\IpAddresses', '添加 Defender 排除项'),
        (r'DisableAntiSpyware|DisableRealtimeMonitoring|DisableBehaviorMonitoring', '禁用 Defender 实时保护'),
        (r'DisableAntiVirus|DisableAntiSpyware|DisableIOAVProtection', '禁用 Defender 组件'),
        (r'MpPreference|Set-MpPreference|Disable.*Defender', 'PowerShell 操作 Defender'),
        (r'Add-MpPreference.*Exclusion|Set-MpPreference.*Exclusion', 'PowerShell 添加排除'),
        # ===== 计划任务一次性添加排除（SilverFox 标志性技术）=====
        (r'schtasks.*reg add.*Defender.*Exclusions.*Paths', '计划任务添加 Defender 排除路径（SilverFox 标志）'),
        (r'SCHTASKS /Create.*SCHTASKS /Run.*SCHTASKS /Delete', '计划任务一键三连（Create→Run→Delete—一次性提权）'),
    ]

    # ===== Windows Update 破坏检测 =====
    WINDOWS_UPDATE_SABOTAGE_PATTERNS = [
        (r'wuauserv|UsoSvc|uhssvc|WaaSMedicSvc', '停止/禁用 Windows Update 服务（阻止系统修复）'),
        (r'takeown.*System32.*wuaueng|rename.*wuaueng.*BAK', '破坏 Windows Update 核心 DLL（物理隔离修复能力）'),
        (r'sc config.*start= disabled.*wuau|sc failure.*reset= 0', '禁用 Windows Update 服务恢复机制'),
        (r'SoftwareDistribution|erase.*softwaredistribution|rmdir.*softwaredistribution', '删除 Windows Update 缓存目录'),
        (r'NoAutoUpdate.*1|DisableOSUpgrade|DisableWindowsUpdateAccess', '注册表禁用自动更新'),
        (r'Disable-ScheduledTask.*UpdateOrchestrator|Disable-ScheduledTask.*WaaSMedic|Disable-ScheduledTask.*WindowsUpdate', 'PowerShell 禁用更新计划任务'),
    ]

    # ===== icacls/takeown 权限操作 =====
    PERMISSION_MANIPULATION_PATTERNS = [
        (r'icacls.*/inheritance:r', '移除目录权限继承（隔离防护/隐藏文件）'),
        (r'icacls.*/grant.*\*S-1-1-0:F|icacls.*/grant.*Everyone', '授予所有人完全控制权（权限后门）'),
        (r'takeown /f', '夺取文件/目录所有权（权限提升前置）'),
        (r'icacls.*/setowner.*SYSTEM|icacls.*/setowner.*Administrators', '修改文件所有者'),
        (r'icacls.*/grant.*Administrators.*OI.*CI.*F', '授予管理员完全控制+继承'),
    ]

    MSI_ABUSE_PATTERNS = [
        (r'msiexec.*(/i|/I|/install).*\.msi', 'MSI 安装执行'),
        (r'MsiInstallProduct|MsiSetInternalUI|MsiDatabaseOpenView', 'MSI API 调用'),
        (r'MsiExec.*Embedding|Embedding.*MsiExec|MSI[0-9a-fA-F]+', 'MSI SYSTEM 权限执行 (AlwaysInstallElevated)'),
        (r'AlwaysInstallElevated|EnableLUA.*MSI|DisableMSI.*0', 'MSI 特权安装检测'),
        (r'\.msi.*CustomAction|CustomAction.*binary|InstallExecuteSequence', 'MSI 自定义动作执行'),
    ]

    DLL_SIDELOAD_PATTERNS = [
        (r'\.exe.*\.dll|\.dll.*同级|同级.*dll', 'EXE/DLL 同级目录（侧加载特征）'),
        (r'LoadLibrary.*\\\\Temp|LoadLibrary.*\\\\AppData|LoadLibrary.*\\\\Public', '从非系统路径加载 DLL'),
        (r'DLL.*SearchOrder|KnownDLLs|SafeDllSearchMode', 'DLL 搜索顺序劫持'),
    ]

    KEYLOGGING_PATTERNS = [
        (r'SetWindowsHookEx.*WH_KEYBOARD|SetWindowsHookEx.*WH_KEYBOARD_LL', '全局键盘钩子'),
        (r'SetWindowsHookEx.*WH_JOURNALRECORD|SetWindowsHookEx.*0xFFFFFFFF|hook_identifier.*4294967295', '系统消息记录钩子 WH_JOURNALRECORD（全量消息捕获）'),
        (r'SetWindowsHookEx.*WH_JOURNALPLAYBACK|hook_identifier.*1\b', '消息回放钩子（输入模拟/重放攻击）'),
        (r'SetWindowsHookEx.*WH_MOUSE|SetWindowsHookEx.*WH_MOUSE_LL', '全局鼠标钩子（输入监控）'),
        (r'SetWindowsHookEx.*WH_GETMESSAGE|SetWindowsHookEx.*WH_CALLWNDPROC', '消息队列钩子（窗口消息窃听）'),
        (r'GetAsyncKeyState.*GetKeyState|GetKeyboardState.*GetKeyState', '键盘状态轮询'),
        (r'GetRawInputData|GetRawInputBuffer|RegisterRawInputDevices', '原始输入监控'),
        (r'WM_KEYDOWN|WM_KEYUP|WM_CHAR|VK_', '键盘消息处理'),
        (r'GetForegroundWindow.*GetWindowText|GetActiveWindow.*GetWindowTextA', '窗口标题+按键组合记录'),
        (r'SetWindowsHookExA|SetWindowsHookExW|SetWindowsHookEx', '安装 Windows 消息钩子'),
    ]

    # ===== 消息钩子 API 常量检测（参数级精准匹配）=====
    HOOK_IDENTIFIER_PATTERNS = [
        (r'4294967295|0x[fF]{8}', 'WH_JOURNALRECORD（系统级全量消息记录，重度键盘记录特征）'),
        (r'hook_identifier.*\b5\b|WH_KEYBOARD\b', 'WH_KEYBOARD（全局键盘钩子—键盘记录器标志）'),
        (r'hook_identifier.*\b13\b|WH_KEYBOARD_LL', 'WH_KEYBOARD_LL（低级键盘钩子—现代键盘记录器）'),
        (r'hook_identifier.*\b7\b|WH_MOUSE\b', 'WH_MOUSE（全局鼠标钩子—输入监控）'),
        (r'hook_identifier.*\b14\b|WH_MOUSE_LL', 'WH_MOUSE_LL（低级鼠标钩子）'),
        (r'hook_identifier.*\b12\b|WH_CALLWNDPROC\b', 'WH_CALLWNDPROC（窗口消息钩子—凭证窃取）'),
        (r'hook_identifier.*\b3\b|WH_GETMESSAGE\b', 'WH_GETMESSAGE（消息队列钩子）'),
        (r'SetWindowsHookEx.*module_address.*0x00000000|module_address.*NULL', '消息钩子无模块句柄（进程内钩子—自包含键盘记录器）'),
    ]

    FILE_OPS_PATTERNS = [
        (r'SetFileAttributes.*FILE_ATTRIBUTE_HIDDEN|SetFileAttributes.*0x[0-9a-fA-F]+', '设置文件属性为隐藏'),
        (r'attrib.*\+h|attrib.*\+s|attrib.*\+r', 'attrib 修改文件属性（隐藏/系统/只读）'),
        (r'SetFileAttributesW|SetFileAttributesA', 'SetFileAttributes 修改文件属性'),
        (r'FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_READONLY', '文件属性标志（隐藏/系统/只读）'),
    ]

    SYSTEM_ENUM_PATTERNS = [
        (r'GetComputerName|GetComputerNameEx|GetComputerNameA|GetComputerNameW', '查询计算机名'),
        (r'GetUserName|GetUserNameEx|GetUserNameA|GetUserNameW', '查询系统用户名'),
        (r'GetSystemInfo|GetNativeSystemInfo|GetSystemWow64Directory', '获取系统信息'),
        (r'GetVersion|GetVersionEx|RtlGetVersion|VerifyVersionInfo', '获取操作系统版本'),
        (r'GetSystemDirectory|GetWindowsDirectory|GetSystemWindowsDirectory', '获取系统目录'),
        (r'GetTempPath|GetTempPath2|GetTempFileName', '获取临时目录路径'),
        (r'GetLogicalDriveStrings|GetDriveType|GetVolumeInformation', '枚举磁盘驱动器'),
        (r'GetProductInfo|IsProcessorFeaturePresent|GetLogicalProcessorInformation', '获取CPU/产品信息'),
        (r'GetCurrentDirectory|SetCurrentDirectory|GetFullPathName', '操作当前工作目录'),
        # ⚠ 函数名哈希动态解析 (getprocaddr_by_hash) — patch 免杀核心手法:
        # 恶意代码无导入表痕迹, 运行时按 FNV/Murmur 哈希遍历导出表解析 API
        # (QQ浏览器patch样本: 逐函数哈希对比 + 存入全局数组)
        (r'fnv|FNV|murmur|murmurhash|hash.*export.*name|export.*hash.*name|getprocaddr.*hash|hash.*getprocaddr',
         'API 函数名哈希解析（getprocaddr_by_hash—免杀核心手法）'),
        (r'GetProcAddress.*loop|loop.*GetProcAddress|GetProcAddress.*export|export.*GetProcAddress',
         '遍历导出表动态解析 API（运行时API解析）'),
    ]

    COM_PATTERNS = [
        (r'CoInitialize|CoInitializeEx|CoCreateInstance|CoGetClassObject', '调用 COM 相关 API'),
        (r'CLSIDFromProgID|CLSIDFromString|ProgIDFromCLSID', 'COM 类标识符操作'),
        (r'CoCreateGuid|UuidCreate|UuidFromString', 'COM GUID 操作'),
    ]

    CRYPTO_PATTERNS = [
        # ⚠ 拆分: 一般加密 API (CryptGenRandom/CryptHash 等) 是正常软件常用 —
        #   曾把正常程序误报"credential_theft: 使用 Windows 加密 API" (历史9次)。
        #   仅 DPAPI/凭据级操作才属于窃密特征。
        (r'CryptAcquireContext|CryptReleaseContext|CryptGenRandom', '使用 Windows 加密 API'),
        (r'CryptEncrypt|CryptDecrypt|CryptEncryptMessage|CryptDecryptMessage', '加密/解密操作'),
        (r'CryptHashData|CryptCreateHash|CryptDestroyHash|CryptGetHashParam', '加密哈希计算'),
        (r'CryptStringToBinary|CryptBinaryToString|CryptEncodeObject', '加密编码转换'),
        (r'CertOpenStore|CertFindCertificateInStore|CertGetNameString', '证书存储访问'),
    ]

    # ===== 音频/麦克风/摄像头设备访问 =====
    AUDIO_ACCESS_PATTERNS = [
        (r'waveInOpen|waveInStart|waveInAddBuffer|waveInPrepareHeader', '麦克风/音频输入设备访问'),
        (r'mixerOpen|m mixerGetLineInfo|mixerGetLineControls', '混音器枚举 (窃听控制检测)'),
        (r'midiInOpen|midiInAddBuffer|midiInPrepareHeader', 'MIDI 设备访问'),
        (r'capCreateCaptureWindow|capGetDriverDescription|ICaptureGraphBuilder', '摄像头/视频捕获设备访问'),
        (r'DirectSoundCaptureCreate|DirectSoundFullDuplexCreate', 'DirectSound 捕获设备访问'),
    ]

    # ===== 代理设置操控 =====
    PROXY_MANIPULATION_PATTERNS = [
        (r'InternetSetOption.*(SETTINGS_CHANGED|PROXY_CHANGED|PER_CONNECTION_OPTION|INTERNET_OPTION_PROXY)', 'InternetSetOption 代理设置操控'),
        (r'WinHttpSetDefaultProxyConfiguration', 'WinHTTP 默认代理配置修改'),
        (r'ProxyEnable.*=.*0|ProxyServer.*=.*', '注册表代理设置修改'),
    ]

    # 凭据级加密操作 — 单独挂 credential_theft (高置信窃密特征)
    DPAPI_CREDENTIAL_PATTERNS = [
        (r'CryptProtectData|CryptUnprotectData|DPAPI|DataProtection', 'DPAPI 数据保护（凭据窃取特征）'),
    ]

    CONFIG_FILE_PATTERNS = [
        (r'GetPrivateProfileString|GetPrivateProfileInt|GetPrivateProfileSection', '读取 INI 配置文件'),
        (r'WritePrivateProfileString|WritePrivateProfileSection', '写入 INI 配置文件'),
        (r'\.ini|\.cfg|\.conf|\.xml|\.json', '配置文件读写'),
    ]

    TRUST_PATTERNS = [
        (r'WinVerifyTrust|Wintrust|WinVerifyTrustEx', '读取系统信任设置（数字签名验证）'),
        (r'CertGetCertificateChain|CertVerifyCertificateChainPolicy', '证书链验证'),
        (r'RegOpenKeyEx.*\\\\System\\\\CurrentControlSet\\\\Services|HKLM\\\\System', '读取系统服务/驱动配置'),
    ]

    OSS_C2_PATTERNS = [
        (r'aliyun|aliyuncs|oss-cn-|oss-accelerate', '使用阿里云 OSS 对象存储通信'),
        (r'qcloud|myqcloud|cos\.|cos-', '使用腾讯云 COS 通信'),
        (r'amazonaws|s3\.|s3-', '使用 AWS S3 通信'),
        (r'storage\.googleapis|firebasestorage', '使用 Google Cloud Storage 通信'),
    ]

    NETWORK_BEHAVIOR_PATTERNS = [
        (r'InternetOpen|InternetOpenA|InternetOpenW|InternetConnect', '发起网络连接'),
        (r'HttpOpenRequest|HttpSendRequest|InternetReadFile', '发送 HTTP 请求'),
        (r'URLDownloadToFile|URLDownloadToCacheFile', '下载文件到本地'),
        (r'WinHttpOpen|WinHttpConnect|WinHttpOpenRequest|WinHttpSendRequest', 'WinHTTP 网络请求'),
        (r'getaddrinfo|gethostbyname|DNSQuery|DnsQuery', 'DNS 域名解析'),
        (r'WSAStartup|socket|connect|send|recv|WSASend|WSARecv', 'Socket 网络通信'),
    ]

    HIDDEN_PROC_PATTERNS = [
        (r'CREATE_NO_WINDOW|STARTF_USESHOWWINDOW|SW_HIDE|SW_MINIMIZE', '创建隐藏窗口进程'),
        (r'ShowWindow.*SW_HIDE|ShowWindowAsync.*SW_HIDE', '隐藏窗口'),
        (r'CREATE_NEW_CONSOLE.*FALSE|DETACHED_PROCESS', '无窗口/分离进程创建'),
        (r'wShowWindow.*0\b|dwFlags.*STARTF.*0', '窗口显示标志为隐藏'),
    ]

    # ===== SilverFox 专有检测模式 =====
    OPENPGP_PATTERNS = [
        (r'-----BEGIN PGP PUBLIC KEY BLOCK-----', '内嵌 OpenPGP 公钥（加密 C2 通信）'),
        (r'-----BEGIN PGP MESSAGE-----', 'PGP 加密消息（C2 通信载荷）'),
        (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', '内嵌 PGP 私钥（严重）'),
        (r'OpenPGP Public Key|OpenPGP Secret Key|OpenPGP\b', 'OpenPGP 密钥载荷数据'),
        (r'Version:.*PGP|Comment:.*PGP|gpg\s.*--encrypt|gpg\s.*--decrypt', 'PGP/GPG 加密操作'),
    ]

    ZLIB_PAYLOAD_PATTERNS = [
        (r'deflate|zlib\b|uncompress|inflateInit|inflateEnd', 'zlib 压缩/解压 API 调用'),
        (r'compress2\b|uncompress\b|compressBound', 'zlib 内存压缩操作（载荷解压特征）'),
        (r'\\x78\\x9[cC]|\\x78\\xd[aA]|\\x78\\x01', 'zlib 压缩数据魔数（0x789C/0x78DA/0x7801）'),
        (r'Z_SYNC_FLUSH|Z_FINISH|Z_NO_FLUSH|Z_FULL_FLUSH', 'zlib 压缩标志常量'),
    ]

    SILVERFOX_PAYLOAD_PATTERNS = [
        (r'nvml\.bin', '释放 nvml.bin（SilverFox OpenPGP 载荷）'),
        (r'ranchserv\.jpg', '释放 ranchserv.jpg（SilverFox 伪装载荷）'),
        (r'anti\.exe\b|zintall\.exe|MZiewp\.exe', 'SilverFox 可执行载荷名称'),
        (r'UxEnhance64\.dll', '释放 UxEnhance64.dll（SilverFox DLL 侧加载）'),
        (r'msadox\.tb\b|adoresd\.dat\b|destopbak\.ini\b', 'SilverFox 数据配置文件释放'),
        (r'\\public\\[a-z0-9]{4,8}\\', '释放到 Public 随机目录（SilverFox 典型路径）'),
        (r'Domo\b|UKzGKr\b|NPztVj\b|ztOOvp\b', 'SilverFox 加密常量/标识符'),
        (r'Ali Licensing Agent|AliLicense', 'SilverFox MSI 伪装信息'),
        (r'nvgpu_x64|nvgpu\.exe', 'nvgpu 载荷（SilverFox 新版伪装名）'),
        (r'\\Program Files\\Common Files\\nvgpu', 'Common Files 下 nvgpu 目录（SilverFox 驻留路径）'),
        # ===== 线索追踪新发现 =====
        (r'XPSPLOG\.dll', 'XPSPLOG.dll 侧加载（SilverFox MSI/SFX 载荷搭档）'),
        (r'3bqWiX\.exe|yrTzAI\.exe', 'SilverFox 随机名载荷（MSI释放的SFX）'),
        (r'\\AppData\\Roaming\\Domo\\', 'Domo 目录（SilverFox 持久化载荷路径）'),
        (r'\\AppData\\Roaming\\IE\\[A-Z0-9]{6,8}\\', 'IE 缓存目录（SilverFox 隐写载荷）'),
        (r'drops\[\d+\]\.jpg', 'drops[N].jpg 伪装载荷（SilverFox 隐写释放）'),
        (r'\\Config\.Msi\\|inprogressinstallinfo|SourceHash\{', 'MSI 安装痕迹（SilverFox 安装器残留）'),
        (r'c:\\\\xxxx\.ini', '根目录 xxxx.ini（SilverFox 配置/标记文件）'),
        (r'\\(?:Program Files \(x86\))\\[A-Za-z0-9]{4,8}\\\w+\.exe', 'PF x86 随机目录+随机EXE（SilverFox 多目录驻留）'),
    ]

    MEMORY_PAYLOAD_PATTERNS = [
        (r'This program cannot be run in DOS mode', '内存中检测到 PE 文件头'),
        (r'MZ\\x90\\x00|4d5a9000|\\x4d\\x5a', 'MZ 头在内存数据中（PE 注入特征）'),
        (r'PE\\x00\\x00|PE\\x00\\x00L\\x01|PE\\x00\\x00d\\x86', 'PE 签名在数据段中（内存 PE 载荷）'),
        (r'\.text\\x00\\x00\\x00|\.data\\x00\\x00\\x00|\.rdata\\x00\\x00', 'PE 节表在内存中（完整 PE 映像）'),
    ]

    # ===== COM 代理/Surrogate 滥用检测 =====
    COM_SURROGATE_PATTERNS = [
        (r'dllhost\.exe.*Processid|dllhost\.exe.*\{[0-9A-F]{8}', 'COM Surrogate 执行（dllhost.exe 滥用—DCOM 横向渗透）'),
        (r'CLSID.*AppID|AppID.*DllSurrogate', '自定义 COM Surrogate 注册（DLL 劫持执行）'),
        (r'CoCreateInstance.*CLSCTX_LOCAL_SERVER|CoGetClassObject.*CLSCTX_REMOTE_SERVER', '远程 COM 对象激活（DCOM 横向移动）'),
        (r'CLSID.*\{F8284233|CLSID.*\{[0-9A-F]{8}-[0-9A-F]{4}', '已知恶意 CLSID 模式（COM 劫持）'),
    ]

    # ===== WebSocket C2 通信检测 =====
    WEBSOCKET_C2_PATTERNS = [
        (r'Sec-WebSocket-Key|Sec-WebSocket-Version|Sec-WebSocket-Protocol', 'WebSocket 协议升级（C2 实时通道）'),
        (r'WebSocket|ws://|wss://', 'WebSocket 连接（持久化 C2 通道）'),
        (r'Upgrade: websocket|Connection: Upgrade', 'HTTP Upgrade 到 WebSocket（C2 握手）'),
    ]

    # ===== COM 劫持持久化检测 (云沙箱对照补强) =====
    COM_HIJACK_PATTERNS = [
        (r'CLSID.*InprocServer32.*\\(?!system32|syswow64)[^\s]+\.dll', 'COM 劫持: CLSID InprocServer32 指向非系统目录 DLL'),
        (r'InprocServer32.*LoadLibrary|InprocServer32.*SetValue', '写入 InprocServer32 注册表值（COM 劫持持久化）'),
        (r'CLSID.*TreatAs', 'COM TreatAs 重定向（COM 劫持—合法CLSID指向恶意实现）'),
        (r'CLSID.*LocalServer32.*\\(?!system32)[^\s]+\.exe', 'COM LocalServer32 劫持（非系统目录）'),
        (r'HKCU.*CLSID.*InprocServer32|HKCU.*Software\\Classes\\CLSID', 'HKCU 下注册 CLSID（当前用户 COM 劫持）'),
        (r'RegSetValue.*InprocServer32|RegCreateKey.*InprocServer32', '注册 InprocServer32 键值（COM 劫持）'),
    ]

    # ===== 反取证/痕迹清除检测 (云沙箱对照补强) =====
    ANTI_FORENSICS_PATTERNS = [
        (r'SetFileTime', 'SetFileTime 篡改文件时间戳（反取证清除痕迹）'),
        (r'FILE_FLAG_DELETE_ON_CLOSE|DeleteOnClose', '文件关闭即删除（反取证）'),
        (r'wevtutil.*cl |Clear-EventLog|Clear-EventLog|eventlog.*clear', '清除事件日志（反取证）'),
        (r'timestomp|Set-CreationTime|Set-LastWriteTime|Set-LastAccessTime', '时间戳篡改工具（timestomp）'),
        (r'fsutil.*usn|deletejournal', 'USN 日志操作（反取证）'),
        (r'\.shred|sdelete|DeleteFile.*secure', '安全删除工具（反取证）'),
    ]

    # ===== PDF 恶意特征检测 (云沙箱对照补强) =====
    PDF_MALWARE_PATTERNS = [
        (r'/OpenAction\s', 'PDF 打开动作（OpenAction—打开即执行）'),
        (r'/JavaScript|/JS\s|app\.launchURL', 'PDF 内嵌 JavaScript（恶意 PDF 常用）'),
        (r'/Launch\s', 'PDF Launch 动作（启动外部程序）'),
        (r'/AA\s*<<|/OpenAction\s*<<', 'PDF 自动动作字典（AA/OpenAction）'),
        (r'%PDF.*(?:/Encrypt|/EncryptMetadata)', 'PDF 加密（隐藏恶意内容）'),
        (r'/RichMedia|/Flash|/XFA', 'PDF 嵌入 Flash/XFA（恶意载荷载体）'),
        (r'/URI\s*\(.*\)|SubmitForm|GoToR', 'PDF 外部链接/表单提交动作'),
    ]

    # ===== 进程繁衍/批量创建检测 =====
    PROCESS_SPAWN_PATTERNS = [
        (r'svchost\.exe.*-k netsvcs -p -s Schedule', 'svchost 计划任务触发执行（SilverFox 持久化特征）'),
        (r'svchost\.exe.*Schedule', 'svchost 计划任务服务进程'),
        (r'dllhost\.exe.*/Processid', 'dllhost COM 代理进程链（DCOM/Surrogate 执行）'),
        (r'CreateProcess.*svchost|CreateProcess.*dllhost', '创建系统进程作为代理（进程注入代理）'),
    ]

    # ===== 跨进程非子进程内存操作检测 =====
    CROSS_PROCESS_MEMORY_PATTERNS = [
        (r'OpenProcess.*PROCESS_VM_WRITE|OpenProcess.*PROCESS_VM_OPERATION', '以 VM 写权限打开其他进程（注入前准备）'),
        (r'WriteProcessMemory.*NtWriteVirtualMemory|WriteProcessMemory.*ZwWriteVirtualMemory', '跨进程写入内存（代码注入执行）'),
        (r'VirtualProtectEx.*PAGE_EXECUTE|NtProtectVirtualMemory.*Remote', '远程修改内存为可执行（注入执行）'),
        (r'ReadProcessMemory.*WriteProcessMemory', '先读后写进程内存（内存替换/镂空）'),
    ]

    # ===== InnoSetup 打包器检测（伪装安装程序）=====
    INNOSETUP_PATTERNS = [
        (r'is-[A-Z0-9]{5,6}\.tmp', 'InnoSetup 临时文件（is-XXXXX.tmp—安装框架滥用）'),
        (r'\\msys64\\[a-zA-Z0-9]{4}\\', 'msys64 目录下随机子目录（伪造安装路径）'),
        (r'_isetup\\_setup64\.tmp|_isetup\\setup.*\.tmp', 'InnoSetup 64位安装器临时文件'),
        (r'InnoSetup|Inno Setup|innounp', 'InnoSetup 打包器特征'),
    ]

    # ===== 伪造安全软件社会工程检测 =====
    FAKE_SECURITY_SOFTWARE_PATTERNS = [
        (r'sys_HR_allapp|sys_HR_.*\.exe', '伪装火绒安全软件（sys_HR 前缀）'),
        (r'火绒|huorong|HRSetup|HRSword|wsctrlsvc', '火绒安全软件相关（可能被恶意伪装）'),
        (r'allapp_x64\.exe|allapp\.exe', 'allapp 统一安装器（常见于恶意捆绑）'),
        (r'火.绒.安.全.软.件|火\\u200[0-9a-f]绒|火.{0,3}绒.{0,3}安.{0,3}全', '零宽字符混淆文件名（反字符串匹配）'),
        (r'\\u200b|\\u200c|\\u200d|\\u200e|\\u200f|\\ufeff', '零宽字符伪装（文件名欺骗—社会工程）'),
    ]

    # ===== 浏览器检测模式 =====
    BROWSER_DETECTION_PATTERNS = [
        (r'chrome|firefox|edge|opera|brave|vivaldi|safari', '检测已安装浏览器（信息窃取前置侦察）'),
        (r'Mozilla.*Firefox|Chrome.*Application|Microsoft.*Edge', '浏览器安装路径探测'),
        (r'Software\\Microsoft\\Windows\\CurrentVersion\\App Paths.*chrome|firefox|edge', '注册表浏览器路径查询'),
        (r'SOFTWARE\\\\Clients\\\\StartMenuInternet|SOFTWARE\\\\Microsoft\\\\Internet Explorer', '注册表默认浏览器查询'),
    ]

    # ===== 多用户环境遍历 =====
    # ===== NSIS 安装器滥用检测 =====
    NSIS_PATTERNS = [
        (r'Nullsoft|nsis|NSIS|NullSoft', 'Nullsoft NSIS 安装器框架'),
        (r'ns[a-zA-Z0-9]{4,6}\.tmp', 'NSIS 临时文件（nsXXXXX.tmp—自解压滥用）'),
        (r'\\Temp\\ns[a-zA-Z0-9]{4,6}\.tmp', 'Temp 下 NSIS 自解压临时文件'),
        (r'nsExec|nsDialogs|NSISdl|inetc', 'NSIS 插件调用（网络下载/执行）'),
        (r'sysdiag-all-x64.*\.exe', 'sysdiag 安装包（火绒/安全软件伪装分发）'),
    ]

    # ===== 反竞争/反安全软件检测 =====
    ANTI_COMPETITOR_PATTERNS = [
        (r'360tray\.exe|360Tray|360safe|zhudongfangyu', '检测 360 安全软件（竞争排除）'),
        (r'HipsTray\.exe|HipsMain|HipsDaemon', '检测火绒 HipsTray（竞争排除）'),
        (r'tasklist.*findstr.*360|tasklist.*findstr.*Hips', 'tasklist+findstr 检测安全软件'),
        (r'kavstart|kavtray|avp\.exe|Kaspersky', '检测卡巴斯基进程'),
        (r'MsMpEng|NisSrv|SecurityHealth', '检测 Windows Defender 服务'),
        # ⚠ PlugX 反竞争: 杀 Adobe 更新程序进程并删启动项 (长期行为特征)
        (r'AdobeHelper\.exe|AdobeUpdates\.exe|AdobeUpdate\.exe|AdobeARM\.exe|AAM Update\.exe|AAM Updates\.exe',
         '终止 Adobe 更新程序（PlugX 反竞争特征）'),
    ]

    # ===== PlugX RAT 家族行为 (白加黑 + USB 蠕虫 + 文档窃取) =====
    PLUGX_PATTERNS = [
        (r'USB_NOTIFY_INF_|USB_NOTIFY_COP_', 'USB 驱动器互斥体（PlugX 蠕虫传播标志）'),
        (r'AvastSvcPYT|AvastAuth\.dat|CEFHelper\.exe', 'PlugX 持久化文件特征（白加黑三件套/回收站伪装）'),
        (r'ms-pu\\PROXY|SOFTWARE\\Classes\\ms-pu', 'PlugX 注册表特征（ms-pu PROXY CLSID）'),
        (r'GetLogicalDriveStrings.*CreateFile.*\\\\\.\\|CreateFile.*\\\\\.\\.*:\\\\',
         '遍历驱动器打开设备句柄（USB 蠕虫传播准备）'),
        (r'RECYCLER\.BIN|\\\\\$Recycle\.Bin.*\.lnk|recycle.*copy.*exe', '回收站藏匿载荷/快捷方式（蠕虫传播）'),
        (r'InternetCheckConnectionW|internetcheckconnection', '网络连通性检测（C2 前探测—PlugX 常用）'),
        (r'_run@4|wsc\.dll.*AvastSvc', '白加黑入口（AvastSvc 加载 wsc.dll 导出）'),
    ]

    # ===== 全盘 Defender 排除检测 =====
    # ===== 自解压子进程模式 =====
    SELF_EXTRACTING_CHILD_PATTERNS = [
        (r'\\Temp\\\d{8,}.*\.exe.*--child', 'Temp 下时间戳自解压子进程（SFX 释放模式）'),
        (r'\\Temp\\\d{8,}[A-Z0-9]*\.exe', 'Temp 下时间戳随机名 EXE（自解压典型模式）'),
        (r'--child\s|/child\s', '--child 参数自解压子进程（父进程指示器）'),
    ]

    # ===== 心跳式 C2 检测 =====
    # ===== CobaltStrike SMB Beacon 命名管道 =====
    CS_NAMED_PIPE_PATTERNS = [
        (r'MSSE-\d+-server|msagent_\w+|postex_\w+', 'CobaltStrike SMB Beacon 命名管道'),
        (r'\\\\.\\pipe\\MSSE-|\\\\.\\pipe\\msagent_|\\\\.\\pipe\\postex_', 'CobaltStrike 命名管道创建'),
        (r'NtCreateNamedPipeFile.*MSSE|CreateNamedPipe.*MSSE', '创建 CobaltStrike 通信管道'),
    ]

    # ===== CobaltStrike Beacon 配置特征 =====
    CS_CONFIG_PATTERNS = [
        (r'/g\.pixel|/submit\.php|/cmd\.html|/jquery|/ga\.js', 'CobaltStrike C2 URI 模式（Malleable C2）'),
        (r'ReflectiveLoader|reflective_loader', '反射式 DLL 加载器（CobaltStrike Beacon 特征）'),
        (r'beacon.*sleep|sleep.*beacon|beacon.*config', 'Beacon 休眠/配置特征'),
        (r'%windir%.*rundll32|spawnto.*rundll32', 'CobaltStrike SpawnTo 进程（rundll32 代理执行）'),
    ]

    HEARTBEAT_C2_PATTERNS = [
        (r'socket.*connect.*5252|connect.*:5252|port.*5252', '连接到高位端口 5252（非标 C2 通信）'),
        (r'send\(|WSASend.*52|sendto.*52\b', '52 字节小包重复发送（心跳探活模式）'),
        (r'connect.*sleep|connect.*loop|reconnect.*interval', '连接-休眠-重连循环（心跳 C2 模式）'),
    ]

    # ===== 自删除 + 伪造弹窗 + 崩溃规避 =====
    # ===== 系统 DLL 感染型木马 (永恒小马: SFC 绕过 + 原地插入感染系统DLL) =====
    SYSTEM_DLL_INFECTION_PATTERNS = [
        (r'sfc_os\.dll|SetSfcFileException|SfcIsFileProtected|SfcGetFiles',
         'SFC 系统文件保护绕过（禁用系统DLL保护—感染前置）'),
        (r'd3d9\.dll\+mshtml\.dll|d3d9\.dll.*mshtml\.dll|感染.*d3d9|d3d9.*\.rep|mshtml.*\.rep',
         '感染目标系统 DLL（d3d9/mshtml 等替换感染）'),
        (r'GetTempFileNameA|GetTempFileNameW|Vch~[0-9a-fA-F]{8}|Vch[A-Za-z0-9]',
         'Vch 前缀临时文件释放（永恒小马 DLL 载体）'),
        # ⚠ AION 单独出现是正常词(游戏名), 需与感染流程组合
        (r'AION.*(?:\.rep|\.bak|Vch|sfc_os|MoveFileEx|DllCache)|(?:\.rep|\.bak|Vch|sfc_os|MoveFileEx|DllCache).*AION',
         'AION 感染标记（永恒小马 PE 头部/.text 感染标志）'),
        (r'\.dll\.rep|\.dll\.bak', '系统 DLL 备份/副本操作（.rep/.bak—感染替换流程）'),
        (r'CopyFileA.*\.rep|MoveFileExA.*\.rep|MoveFileEx.*MOVEFILE_REPLACE_EXISTING',
         '系统 DLL 副本感染后替换原文件'),
        (r'MapViewOfFile.*memcpy.*entry|memcpy.*入口.*16|保存原始入口点.*16',
         '保存原始入口点+写入病毒代码（原地感染不增加文件大小）'),
        (r'SessionManager\\\\Environment|环境变量.*PATH|SetEnvironmentVariable.*Path',
         '修改系统环境变量 PATH（持久化—临时目录加入搜索路径）'),
    ]

    SELF_DELETE_PATTERNS = [
        (r'DeleteFile.*self|self.*delete|DeleteFileW.*\.exe|NtDeleteFile.*\.exe', '自删除可执行文件（反取证清理痕迹）'),
        (r'MoveFileEx.*MOVEFILE_DELAY_UNTIL_REBOOT.*\.exe', '重启后删除自身（延迟反取证）'),
        (r'delete.*original|remove.*installer|erase.*\.exe', '删除原始安装程序（单次执行证据销毁）'),
    ]

    FAKE_DIALOG_PATTERNS = [
        (r'该文件已损坏|文件已损坏|文件损坏|已损坏.*无法打开|cannot be opened|corrupted', '伪造系统错误弹窗（社会工程—掩盖恶意行为）'),
        (r'MessageBox.*损坏|MessageBox.*错误|MessageBox.*error|MessageBox.*corrupt', '弹出伪造错误提示（分散用户注意力）'),
        (r'错误.*确定|Error.*OK|错误信息.*关闭', '伪装系统错误对话框模式'),
    ]

    # ===== EDR/杀软枚举 (T1518.001 安全软件发现 — 定向企业攻击标志) =====
    EDR_ENUM_PATTERNS = [
        (r'crowdstrike|csfalcon|csagent|falcon', '枚举 CrowdStrike Falcon (EDR)'),
        (r'sentinelone|sentinelagent|sentinelhelper', '枚举 SentinelOne (EDR)'),
        (r'cylance|cylancesvc', '枚举 Cylance (EDR/AI杀软)'),
        (r'carbonblack|cb\.exe|cbserver', '枚举 CarbonBlack (EDR)'),
        (r'defender|msmpeng|windefend', '枚举 Windows Defender'),
        (r'avast|avgnt', '枚举 Avast/AVG'),
        (r'kaspersky|avp\.exe|kavtray', '枚举 Kaspersky'),
        (r'symantec|norton|ccsvchst', '枚举 Symantec/Norton'),
        (r'trend.?micro|tmccsf|pccntmon', '枚举 Trend Micro'),
        (r'360safe|360tray|huorong|hipsdaemon|qqpcmgr|kxe', '枚举国产安全软件 (360/火绒/管家/金山)'),
    ]

    CRASH_EVASION_PATTERNS = [
        (r'WerFault\.exe|werfault|WerReportCreate|WerReportSubmit', '触发 Windows 错误报告（崩溃式分析规避）'),
        (r'NtProtectVirtualMemory.*werfault|VirtualProtect.*werfault', 'WerFault 进程修改内存保护（崩溃注入技术）'),
        (r'Exception.*ContinueExecution|EXCEPTION_CONTINUE_EXECUTION', '异常后继续执行（反调试/反分析续命）'),
    ]

    FULL_DISK_EXCLUSION_PATTERNS = [
        (r'Add-MpPreference.*ExclusionPath.*C:\\\\,.*D:\\\\,.*E:\\\\|ExclusionPath.*[A-Z]:\\\\,', '全盘添加 Defender 排除路径（严重规避）'),
        (r'Add-MpPreference.*ExclusionPath.*[A-Z]:\\\\', '添加磁盘根目录 Defender 排除'),
        (r'Add-MpPreference.*ExclusionExtension|Add-MpPreference.*ExclusionProcess', '添加 Defender 排除扩展名/进程'),
    ]

    MULTI_USER_PATTERNS = [
        (r'C:\\\\Users\\\\.*\\\\AppData.*\\.tmp|C:\\\\Users\\\\.*\\\\Desktop.*\\.lnk', '跨用户目录释放文件（多账户感染）'),
        (r'\\\\Users\\\\Admin\\\\|\\\\Users\\\\Administrator\\\\', '多用户 Profile 遍历'),
        (r'NetUserEnum|NetQueryDisplayInformation|LsaEnumerateLogonSessions', '枚举本地用户账户（多账户传播准备）'),
    ]

    # ===== 新增：反沙箱环境指纹检测 =====
    SLEEP_PRECISION_PATTERNS = [
        (r'QueryPerformanceCounter.*Sleep|Sleep.*QueryPerformanceCounter', 'Sleep 精度检测（测量Sleep实际耗时—反Hook）'),
        (r'QueryPerformanceFrequency.*Sleep.*QueryPerformanceCounter', '高精度 Sleep 时间差检测（沙箱Hook判定）'),
        (r'Sleep\(0x64\)|Sleep\(100\)', 'Sleep(100ms) 精度探测（沙箱时间加速检测标志）'),
        (r'dwFileAttributes.*Sleep|dwLowDateTime.*Sleep|dwHighDateTime.*Sleep', '通过系统时间结构体检测Sleep精度'),
    ]

    CPUID_TIMING_PATTERNS = [
        (r'__rdtsc.*cpuid.*__rdtsc|rdtsc.*cpuid.*rdtsc', 'CPUID VM退出开销检测（RDTSC差>1000周期=VM）'),
        (r'VM_EXIT_OVERHEAD|VM_EXIT.*OVERHEAD', 'VM退出开销标志字符串'),
        (r'cpuid.*0x40000000[\x00-\xff]*rdtsc', 'CPUID超调用+时间差 反VM组合检测'),
    ]

    RDTSC_JITTER_PATTERNS = [
        (r'LOW_RDTSC_JITTER|RDTSC.*JITTER', 'RDTSC抖动检测（VM时钟过于精准—低方差=VM）'),
        (r'__rdtsc.*__rdtsc.*__rdtsc.*__rdtsc.*__rdtsc', '连续5次以上RDTSC采样（抖动分析）'),
        (r'rdtsc.*std.*dev|rdtsc.*variance|rdtsc.*stddev', 'RDTSC标准差/方差计算（VM检测算法）'),
    ]

    SYSTEM_UPTIME_PATTERNS = [
        (r'GetTickCount.*0xDBB9F|GetTickCount.*\b900000\b|GetTickCount.*15.*min', '系统运行时间不足15分钟检测（沙箱判定）'),
        (r'SHORT_UPTIME|SHORT.*UPTIME|LOW_UPTIME', '短运行时间标志字符串'),
        (r'GetTickCount64.*\b9[0-9]{5}\b', 'GetTickCount64 短时间阈值检测'),
    ]

    USER_INTERACTION_PATTERNS = [
        (r'GetLastInputInfo.*0x493E0|GetLastInputInfo.*300000|GetLastInputInfo.*5.*min', '5分钟内无用户输入检测（沙箱判定）'),
        (r'NO_RECENT_INPUT|NO.*INPUT|NO_INPUT.*DETECT', '无用户输入标志字符串'),
        (r'OpenClipboard.*CountClipboardFormats.*CloseClipboard', '剪贴板空检测（真实用户通常有内容）'),
        (r'EMPTY_CLIPBOARD|EMPTY.*CLIPBOARD|CLIPBOARD.*EMPTY', '空剪贴板标志字符串'),
    ]

    SYSTEM_TRACE_PATTERNS = [
        (r'USBSTOR[\\/]|Enum[\\/]USBSTOR', 'USB设备使用历史检测（真实系统应有记录）'),
        (r'NO_USB_HISTORY|NO.*USB.*HISTORY|USB.*HISTORY.*EMPTY', '无USB历史标志字符串'),
        (r'RecentDocs|Explorer[\\/]RecentDocs|RecentDocs[\\/]\\.*\.lnk', '最近文档列表检测（真实用户应有记录）'),
        (r'NO_JUMP_LISTS|NO.*JUMP.*LIST|JUMPLIST.*EMPTY', '无JumpList标志字符串'),
        (r'ShellNoRoam[\\/]MUICache|UserAssist|Prefetch', '用户活动痕迹查询（MUICache/UserAssist/Prefetch）'),
    ]

    DISK_ANTI_VM_PATTERNS = [
        (r'ROUND_DISK_SIZE|DISK.*SIZE.*ROUND|DISK.*ROUND.*SIZE', '磁盘大小规整检测（虚拟磁盘整G大小）'),
        (r'DeviceIoControl.*DISK_GEOMETRY|IOCTL_DISK_GET_DRIVE_GEOMETRY|DISK_GEOMETRY', '硬盘几何信息查询（VM判定）'),
        (r'VBOX.*HARDDISK|VMware.*Virtual.*disk|QEMU.*HARDDISK|Msft.*Virtual.*Disk', '磁盘厂商名包含VM标识（字符匹配）'),
        (r'VM_VENDOR_ID|VM.*VENDOR|VENDOR.*VM', 'VM厂商标志字符串'),
        (r'STORAGE_DEVICE_DESCRIPTOR|IOCTL_STORAGE_QUERY_PROPERTY', '存储设备描述符查询（序列号分析）'),
        (r'DiskSerialNumber.*entropy|serial.*entropy|disk.*entropy', '磁盘序列号熵值分析（低熵=VM）'),
    ]

    MEMORY_ANTI_VM_PATTERNS = [
        (r'VirtualAlloc.*VirtualFree.*QueryPerformanceCounter|VirtualAlloc.*VirtualFree.*rdtsc', '内存分配/释放计时分析（VM页面模式检测）'),
        (r'VirtualAlloc.*MEM_COMMIT.*PAGE_READWRITE.*32', '批量分配32次内存页面（时序分析）'),
        (r'MEM_ALLOC_PATTERN|ALLOC.*TIMING|MEM.*TIMING', '内存分配模式标志字符串'),
        (r'page.*entropy.*1024|page.*repeat.*pattern|PAGE_ENTROPY', '内存页面熵值/重复模式分析（VM内存特征）'),
        (r'm128i_i32.*1024|mm_load_si128.*1024|_mm_load_si128.*1023', 'SIMD 内存页面批量扫描（1024次重复检查）'),
    ]

    # ===== 新增：系统指纹深度检测 =====
    HASH_PROCESS_PATTERNS = [
        (r'0x[a-fA-F0-9]{8}.*process.*name|process.*hash.*0x[a-fA-F0-9]{8}', '进程名哈希匹配（规避字符串检测）'),
        (r'-1356851726|hash.*process.*blacklist|sub_14.*CF0', '进程哈希黑名单（反安全软件检测）'),
    ]

    INSTALLED_PROGRAMS_PATTERNS = [
        (r'dwSize.*0x13|InstalledPrograms.*\b20\b|FEW_INSTALLED_PROGRAMS', '已安装程序数量检测（<20=沙箱）'),
        (r'Uninstall.*count|Software\\\\Microsoft\\\\Windows.*Uninstall.*enum', '遍历已安装程序计数'),
    ]

    SYSTEM_CONFIG_PATTERNS = [
        (r'dwSize.*0x63|FEW_FONTS|EnumFonts.*count.*100', '系统字体数量检测（<100=沙箱）'),
        (r'dwSize.*0x31|SIMPLE_REGISTRY|registry.*key.*count.*50', '注册表复杂度检测（<50项=沙箱）'),
        (r'System32.*\b500\b|FEW_SYSTEM_FILES|system.*files.*count.*\b\d{3}\b', 'System32文件数量检测（<500=沙箱）'),
    ]

    PREFETCH_DETECTION_PATTERNS = [
        (r'Prefetch.*\b30\b|FEW_PREFETCH_FILES|prefetch.*count.*\b\d{1,2}\b', 'Prefetch文件数量检测（<30=沙箱）'),
        (r'CLUSTERED_PREFETCH_TIMESTAMPS|prefetch.*cluster|prefetch.*timestamp.*cluster', 'Prefetch时间戳聚类分析（沙箱判定）'),
        (r'prefetch.*std|prefetch.*variance|prefetch.*0\.8', 'Prefetch时间分布统计检测'),
    ]

    EVENT_LOG_PATTERNS = [
        (r'FEW_SYSTEM_EVENTS|0x7CF|system.*event.*\b1999\b|event.*log.*count.*system', '系统事件日志数量检测（<1999=沙箱）'),
        (r'FEW_APP_EVENTS|0x3E7|application.*event.*\b999\b|event.*log.*count.*app', '应用程序事件日志数量检测（<999=沙箱）'),
    ]

    UPDATE_HISTORY_PATTERNS = [
        (r'NO_UPDATE_HISTORY|update.*history.*\b5\b|Windows.*Update.*count.*\b[0-5]\b', 'Windows更新历史检测（<5条=沙箱）'),
        (r'wua_history|KB[0-9]{6,}.*count|InstalledUpdates', '更新历史枚举计数'),
    ]

    NETWORK_CONFIG_PATTERNS = [
        (r'GetIpNetTable.*\b4\b|ARP.*table.*count|FEW_ARP_ENTRIES', 'ARP表条目检测（<=4=沙箱）'),
        (r'WlanEnumInterfaces|WlanGetAvailableNetworkList|WiFi.*count|NO_WIFI_CONFIG', 'Wi-Fi配置检测（无WiFi=沙箱）'),
        (r'GetAdaptersInfo.*count|NO_VALID_ADAPTER|FEW_NETWORK_ADAPTERS', '网卡数量检测'),
    ]

    COM_WMI_PATTERNS = [
        (r'dwSize.*0x1F3|FEW_COM_CLASSES|COM.*class.*count.*500', 'COM类数量检测（<500=沙箱）'),
        (r'SMALL_WMI_REPO|WMI.*repo.*\b10\b.*MB|0\.00000095367431640625', 'WMI存储库大小检测（<10MB=沙箱）'),
        (r'CLSID.*enum|HKEY_CLASSES_ROOT.*CLSID.*count', 'COM/CLSID注册表项枚举计数'),
    ]

    RECYCLE_BIN_PATTERNS = [
        (r'CLUSTERED_RECYCLE_TIMES|recycle.*time.*cluster|recycle.*timestamp.*cluster', '回收站时间戳聚类检测（沙箱判定）'),
        (r'TINY_RECYCLE_FILES|recycle.*file.*\b1\b.*KB|recycle.*size.*avg', '回收站文件大小检测（平均<1KB=沙箱）'),
        (r'Recycle\.Bin|S-1-5-21.*recycle|\\\\$Recycle\.Bin|recycle.*count', '回收站文件枚举分析'),
    ]

    SMART_DETECTION_PATTERNS = [
        (r'SMART_CAPABLE|NO_SMART_SUPPORT|0x74080|SMART_RCV_DRIVE_DATA', 'SMART支持检测（无SMART=VM）'),
        (r'DeviceIoControl.*SMART|IOCTL_DISK.*SMART|SMART_GET_VERSION', 'SMART IOCTL查询（磁盘直通判定）'),
    ]

    # ===== 新增：ETW绕过 / 直接系统调用 / 线程劫持注入链 =====
    ETW_BYPASS_PATTERNS = [
        (r'EtwEventWrite.*0xE8F45F7B|EtwEventWriteEx.*0xE8F45F7B', 'ETW EventWrite API Hook（反EDR—禁用事件跟踪）'),
        (r'EtwEventWriteFull|EtwEventWriteTransfer|EtwEventWriteString', '批量ETW API Hook（7个ETW函数—系统性绕过事件跟踪）'),
        (r'EtwEventRegister.*0x326E5E8E|NtTraceEvent.*0x21419E94', 'ETW注册+NtTraceEvent双Hook（完全静默事件日志）'),
        (r'0xE8F45F7B|0x671697A7|0xE5F4BDDE|0x21419E94|0x326E5E8E|0xB68708D5|0x8DEF088F', 'FNV-1a Hash ETW API表（7个预计算Hash—EDR规避）'),
        (r'ETW.*patch|ETW.*hook|etw.*bypass|EtwEvent.*patch', 'ETW补丁/Hook绕过（通用）'),
    ]

    DIRECT_SYSCALL_PATTERNS = [
        (r"Zw[a-zA-Z]+.*syscall.*stub|syscall.*0x[0-9a-fA-F]+.*Zw", "直接系统调用（绕过用户态API Hook—Halo's Gate风格）"),
        (r'ZwAllocateVirtualMemory|ZwWriteVirtualMemory|ZwProtectVirtualMemory|ZwGetContextThread|ZwSetContextThread|ZwResumeThread', 'Zw* 系统调用链（远程线程注入—绕过用户态Hook）'),
        (r'syscall.*resolver|syscall.*stub|syscall.*number.*parse|Halo.*Gate', '系统调用解析器（Halo\'s Gate—跳过jmp Hook定位真实syscall）'),
        (r'ntdll.*export.*Zw.*enum|Zw.*export.*table.*scan', 'ntdll导出表枚举Zw*函数（系统调用解析）'),
        (r'syscall.*ret.*sequence|syscall.*byte.*pattern|0x0F\x05|syscall.*instruction', 'syscall+ret指令序列检测'),
    ]

    THREAD_HIJACK_PATTERNS = [
        (r'CreateProcess.*CREATE_SUSPENDED.*notepad|notepad.*CREATE_SUSPENDED', '创建挂起的notepad进程（线程劫持宿体）'),
        (r'ZwAllocateVirtualMemory.*ZwWriteVirtualMemory.*ZwProtectVirtualMemory.*ZwSetContextThread', 'Zw内存分配→写入→改权限→劫持上下文（完整注入链）'),
        (r'ZwGetContextThread.*ZwSetContextThread.*ZwResumeThread', '获取线程上下文→修改RIP→恢复执行（线程劫持）'),
        (r'RW.*RX.*ZwProtect|PAGE_READWRITE.*PAGE_EXECUTE_READ.*ZwProtect', 'RW→RX 内存权限变更（隐蔽注入—避免RWX特征）'),
        (r'Thread.*Context.*Hijack|context.*hijack|thread.*hijack.*RIP|RIP.*redirect', '线程上下文劫持标志'),
    ]

    # ===== 新增：MSC/XSLT脚本注入 / 白加黑路径伪装 / 参数反沙箱 =====
    MSC_XSLT_ATTACK_PATTERNS = [
        (r'\.msc.*XML|mmc\.exe.*\.msc|Management Console.*XSLT', 'MSC文件利用（MMC+XSLT脚本注入）'),
        (r'StringTable.*script|XSL.*transform|msxsl.*processing', 'MSC StringTable XSLT脚本注入（XML解析触发）'),
        (r'eval.*decodeURIComponent|decodeURIComponent.*eval', 'JavaScript嵌套解码（XSLT→JS→VBScript链）'),
        (r'WScript\.Shell|CreateObject.*WScript|ActiveXObject.*Shell', 'XSLT触发WScript.Shell（高权限脚本执行）'),
        (r'BinaryStorage.*\.msc|\.msc.*Base64|msc.*dropper', 'MSC BinaryStorage载荷释放（嵌入式二进制块）'),
        (r'Word\.Application.*Visible|CreateObject.*Word\.Application', '创建Word进程打开诱饵文档（掩护后台恶意行为）'),
    ]

    DLL_SIDELOAD_PATH_PATTERNS = [
        (r'Cloudflare[\\/]Warp\.exe|Program Files[\\/]Cloudflare[\\/]Warp', '伪装Cloudflare Warp路径（DLL侧荷载路径欺骗—APT41）'),
        (r'7z\.dll.*sideload|7zwrap.*7z\.dll|Warp\.exe.*7z\.dll', '7zwrap侧荷载—白文件Warp.exe+恶意7z.dll'),
        (r'CreateObject.*GetHandlerProperty|7-Zip.*DLL.*hijack', '7-Zip导出函数劫持（恶意DLL伪装7z接口）'),
    ]

    PARAM_GATE_PATTERNS = [
        (r'GetCommandLineW.*cmp.*0x74|cmp.*byte.*0x74.*t', "命令行参数门控（需要't'参数才执行—反沙箱）"),
        (r'GetCommandLineW.*argv.*param|param.*required.*execute', '参数依赖执行（无参数不触发恶意行为—反沙箱）'),
        (r'command.*line.*gate|param.*gate|argument.*check.*execute', '命令行参数门控标志'),
    ]

    # ===== 新增：legion 样本系列 — bat网络驱动器/ctypes ShellCode加载/PowerShell混淆/XWorm =====
    NET_DRIVE_DELIVERY_PATTERNS = [
        (r'net\s+use.*\\\\[\w.-]+[@]trycloudflare\.com|net\s+use.*\\\\.*cloudflare.*DavWWWRoot', 'net use挂载Cloudflare Tunnel网络驱动器（载荷分发）'),
        (r'net\s+use.*\\\\[\w.-]+@SSL|net\s+use.*\\\\[\w.-]+@\d+.*DavWWW', 'net use WebDAV网络驱动器挂载（远程载荷分发）'),
        (r'trycloudflare\.com|\.trycloudflare\.com|Cloudflare.*Tunnel', 'Cloudflare Tunnel内网穿透（C2/载荷分发通道）'),
        (r'net\s+use\s+\w:\s+\\\\|net\s+use.*\\\\[\w.-]+\\.*\.zip', '网络驱动器挂载+zip下载（bat分发模式）'),
    ]

    PYTHON_CTYPES_SHELLCODE_PATTERNS = [
        (r'ctypes\.windll\.kernel32\.VirtualProtect|ctypes\.windll\.kernel32\.VirtualAlloc', 'Python ctypes调用VirtualProtect（内存ShellCode加载）'),
        (r'ctypes\.CFUNCTYPE.*c_void_p|ctypes\.cast.*CFUNCTYPE', 'Python ctypes函数指针强转（ShellCode跳转执行）'),
        (r'ctypes\.create_string_buffer.*base64|base64.*RC4|RC4.*base64.*decode', 'Base64+RC4双编码ShellCode（序列化存储+反序列化执行）'),
        (r'KSA.*PRGA|S.*box.*256.*RC4|RC4.*KSA|RC4.*key.*schedule', 'RC4 KSA/PRGA算法实现（自定义加密ShellCode）'),
        (r'Donut|donut.*shellcode|donut.*loader|laZzzy.*inject', 'Donut生成ShellCode / laZzzy注入器（开源工具变异）'),
    ]

    PS_OBFUSCATION_PATTERNS = [
        (r'\[char\]\(\(-?\d+.*-Band.*-Bor|\[char\]\(\(-?\d+.*-band.*-bor', 'PowerShell [char] 数学混淆（加减+位运算解密字符串）'),
        (r'System\.Diagnostics\.ProcessStartInfo.*CreateNoWindow|ProcessStartInfo.*WindowStyle.*Hidden', 'PowerShell ProcessStartInfo静默无窗口执行'),
        (r'\[System\.Diagnostics\.Process\]::Start.*ProcessStartInfo|ProcessStartInfo.*FileName', 'PowerShell启动进程（ProcessStartInfo + .exe）'),
        (r'\[sYstEm\.iO\.PAtH\]::gEtTemPpath|getsTrinG.*0x[0-9a-fA-F]+,.*0x[0-9a-fA-F]+', 'PowerShell混淆大小写+Decimal/Hex ASCII拼接'),
        (r'WriteAllBytes.*CurrentDirectory|\[IO\.File\]::WriteAllBytes', 'PowerShell WriteAllBytes释放PE到磁盘'),
        (r'timeout.*\/t.*\/nobreak.*del.*\/f.*\/q.*exit|del.*\$[a-zA-Z]+.*\/f.*\/q.*exit', 'bat自删除模式（timeout→del→exit—反取证）'),
    ]

    XWORM_LAZZY_PATTERNS = [
        (r'XWorm|XWorm\s+V\d|Xwormmm|<Xwormmm>|XWorm.*Mutex', 'XWorm木马标志（版本号/SPL/Mutex）'),
        (r'laZzzy|LaZzzy.*inject|Early.*bird.*APC|APC.*early.*bird', 'laZzzy注入器 / 早鸟APC注入（开源ShellCode注入框架）'),
        (r'KernelCallbackTable|Section View Mapping|Fiber Local Storage.*Callback|FLS.*Callback', 'laZzzy高级注入技术（KernelCallback/FLS/LineDDA）'),
        (r'EnumSystemGeoID.*Callback|LineDDA.*Callback|SetTimer.*Callback', 'laZzzy回调注入（EnumSystemGeoID/LineDDA/SetTimer）'),
        (r'<123456789>|Aes key.*123456789|Install file.*USB\.exe', 'XWorm配置特征（AES密钥/USB.exe安装文件）'),
    ]

    VM_SELFKILL_PATTERNS = [
        (r"can't be executed on virtual machines|can.*not.*execute.*virtual.*machine", 'VM检测后自退出+提示信息（反虚拟机条件执行）'),
        (r'color\s+\w+.*echo.*virtual.*machine.*pause|cmd\.exe.*\/c.*echo.*virtual.*machine', 'cmd弹窗提示虚拟机检测（color+echo+pause）'),
        (r'OneDrive\s+Updater\.exe|Public[\\/]OneDrive.*Updater', '伪装OneDrive更新器（自复制到Public目录持久化）'),
        (r'SetWindowsHookExW.*\b13\b|SetWindowsHookExW.*0xd|idHook.*0xd', 'WH_KEYBOARD_LL 键盘记录钩子 (idHook=13/0xd)'),
        (r'.NET.*virtual.*machine|NET.*protected.*memory|this.*assembly.*protected', '.NET程序集反VM保护（混淆器+VM检测组合）'),
    ]

    # ===== 新增：uzusy 10层嵌套RAT — PyInstaller链/encodings劫持/FileMapping/DirectInput/svchost守护 =====
    PYINSTALLER_CHAIN_PATTERNS = [
        (r'PyInstaller|pyinstaller|pyinstxtractor|MEIPASS|_internal.*python', 'PyInstaller打包Python恶意软件（多层嵌套分发）'),
        (r'encodings[\\/]__init__\.pyc|encodings.*hijack|encodings.*inject', 'Python encodings标准库劫持（自动加载恶意代码—无显式import）'),
        (r'python310\.zip.*encodings|python3\d+\.zip.*encodings', 'Python标准库zip篡改（encodings模块恶意注入）'),
        (r'py7zr|SevenZipFile.*password|io\.BytesIO.*7z|decompress.*7z.*from.*memory', 'Python内存中解压7z（加载加密载荷—密码硬编码）'),
    ]

    FILEMAPPING_SHELLCODE_PATTERNS = [
        (r'CreateFileMappingW.*PAGE_EXECUTE_READWRITE|CreateFileMapping.*INVALID_HANDLE.*RWX', '文件映射创建可执行内存（CreateFileMapping+RWX—无文件ShellCode注入）'),
        (r'MapViewOfFile.*FILE_MAP_EXECUTE|MapViewOfFile.*FILE_MAP_WRITE.*FILE_MAP_EXECUTE', 'MapViewOfFile映射可执行视图（文件映射型ShellCode执行）'),
        (r'CreateFileMapping.*MapViewOfFile.*ctypes|ctypes.*CreateFileMapping.*MapViewOfFile', 'Python ctypes文件映射ShellCode加载链'),
        (r'PAGE_EXECUTE_READWRITE.*FILE_MAP_WRITE.*FILE_MAP_EXECUTE', 'RWX文件映射+可执行视图组合标志'),
    ]

    DOH_C2_PATTERNS = [
        (r'223\.5\.5\.5[\\/]resolve|223\.5\.5\.5.*resolve.*name|resolve.*name.*type=A', '阿里DNS DoH C2解析 (223.5.5.5/resolve?name=)'),
        (r'dns-over-https|DNS.*over.*HTTPS|DoH.*C2|resolve.*type=A.*https', 'DNS-over-HTTPS C2地址解析（隐藏真实C2流量）'),
        (r'DNS-Agent|DNS.*Agent.*User-Agent|User-Agent.*DNS-Agent', 'DNS-Agent User-Agent（DNS隧道/DoH通信特征）'),
        (r'https://[\d.]+\/resolve\?name=|https.*dns.*resolve.*name=', 'HTTPS DNS解析API（阿里/腾讯DoH—C2寻址）'),
    ]

    DIRECTINPUT_KEYLOGGER_PATTERNS = [
        (r'DirectInput8Create|DirectInput8|DirectInput.*8.*Create', 'DirectInput8初始化（DirectX输入系统—低层键盘记录）'),
        (r'c_dfDIKeyboard|DISCL_BACKGROUND.*DISCL_NONEXCLUSIVE|GetDeviceState.*keyboard', 'DirectInput键盘设备初始化（后台静默记录）'),
        (r'DisplaySessionContainers\.log|Display.*Session.*Container.*log', '键盘记录日志文件（DisplaySessionContainers.log—本地暂存）'),
        (r'GetClipboardData.*CF_UNICODETEXT.*OpenClipboard|OpenClipboard.*GetClipboardData.*1500', '剪贴板监控循环（1.5s间隔—配合键盘记录）'),
        (r'GetKeyState.*VK_CAPITAL|scan.*code.*102.*map|scancode.*shift.*capslock', '键盘扫描码映射表（102键+Shift/CapsLock状态处理）'),
    ]

    SVCHOST_DAEMON_PATTERNS = [
        (r'CreateProcessA.*svchost\.exe.*CREATE_SUSPENDED|svchost.*suspended.*inject', '创建挂起svchost进程（进程守护宿体—注入后监控主进程）'),
        (r'WaitForSingleObject.*INFINITE.*OpenProcess.*PID|WaitForSingleObject.*INFINITE.*parent', '等待主进程退出后自动重启（svchost守护—进程复活）'),
        (r'WinExec.*SW_HIDE.*restart|WinExec.*parent.*path.*restart|WinExec.*relaunch', 'WinExec静默重启主程序（进程死而复生—反杀软终止）'),
        (r'SeDebugPrivilege|AdjustTokenPrivileges.*SeDebug|OpenProcessToken.*SE_DEBUG', '启用SeDebugPrivilege（调试权限—进程注入前置）'),
        (r'ProcessBreakOnTermination|NtSetInformationProcess.*BreakOnTermination|BreakOnTermination.*1', '设置ProcessBreakOnTermination（防止任务管理器终止—反杀）'),
    ]

    RPC_SCHEDULED_TASK_PATTERNS = [
        (r'\\\\pipe\\\\atsvc|pipe.*atsvc|atsvc.*RPC|atsvc.*schedule', 'RPC atsvc管道创建计划任务（绕过schtasks命令行检测）'),
        (r'MicrosoftUpdate.*schedule|Microsoft\\\\MicrosoftUpdate|MicrosoftUpdate.*task', '伪装MicrosoftUpdate计划任务（持久化—绕过安全审计）'),
        (r'Add-MpPreference.*ExclusionPath.*C:\\\\|ExclusionPath.*C:\\\\', '添加整个C盘到Defender排除（全盘放行—反Defender通杀）'),
    ]

    # ===== 新增：捆绑下载/多阶段投放 =====
    BUNDLE_DROPPER_PATTERNS = [
        (r'URLDownloadToFile.*ShellExecute|URLDownloadToFile.*WinExec|URLDownloadToFile.*CreateProcess', '下载+执行链（URLDownloadToFile→执行—典型捆绑投放）'),
        (r'BITSAdmin.*transfer.*execute|bitsadmin.*\/transfer.*&&|bitsadmin.*下载.*执行', 'BITSAdmin下载+执行（系统工具捆绑下载）'),
        (r'certutil.*urlcache.*split|certutil.*-urlcache.*-f.*&&|certutil.*下载', 'certutil下载载荷（Living-off-the-Land—捆绑下载）'),
        (r'Invoke-WebRequest.*IEX|Invoke-WebRequest.*Invoke-Expression|IWR.*IEX|iwr.*iex', 'PowerShell下载+执行（IWR+IEX内存加载—无文件捆绑）'),
        (r'Invoke-RestMethod.*IEX|IRM.*Invoke-Expression|irm.*iex', 'PowerShell REST下载+执行（IRM+IEX）'),
        (r'Net\.WebClient.*DownloadString.*IEX|WebClient.*DownloadData.*Invoke', '.NET WebClient下载+执行（内存捆绑载荷）'),
        (r'NSIS.*bundle|InnoSetup.*bundle|Nullsoft.*bundle|setup.*embedded.*PE', 'NSIS/InnoSetup安装包捆绑（多个嵌入式PE）'),
        (r'\.data.*resource.*PE|RT_RCDATA.*MZ|resource.*embedded.*exe|embedded.*payload.*resource', '资源段嵌入PE（RCDATA/MZ头—捆绑加载）'),
        (r'multi.*stage.*download|second.*stage.*download|stage.*2.*download|dropper.*stage', '多阶段下载器（Dropper→Stage2→载荷）'),
        (r'self.*extract.*archive|SFX.*archive|7z.*SFX.*setup|self-extracting.*install', '自解压归档包捆绑（7z SFX—静默安装捆绑）'),
    ]

    # ===== 新增：DDoS/洪水攻击 =====
    DDOS_PATTERNS = [
        # SYN Flood
        (r'socket.*SOCK_RAW.*IPPROTO_RAW|SOCK_RAW.*socket.*create|raw.*socket.*syn', '原始套接字创建（SOCK_RAW—SYN Flood准备）'),
        (r'\.syn\s|syn.*flood|SYN.*attack|synflood', 'SYN Flood攻击（DDoS子命令/配置）'),
        (r'SYN.*packet.*loop|syn.*sendto.*while|syn.*flood.*thread', 'SYN Flood发包循环（大量SYN包发送）'),
        # UDP Flood
        (r'\.udp\s|udp.*flood|UDP.*attack|udpflood', 'UDP Flood攻击（DDoS子命令/配置）'),
        (r'sendto.*while.*true.*rand|UDP.*random.*payload.*loop', 'UDP随机载荷发包循环（UDP Flood—放大/随机化）'),
        (r'udp.*amplif|amplification.*attack|SSDP.*amplif|NTP.*amplif|DNS.*amplif', 'UDP放大攻击（SSDP/NTP/DNS反射—DDoS变体）'),
        # HTTP Flood
        (r'\.http\s|http.*flood|HTTP.*attack|httpflood', 'HTTP Flood攻击（DDoS子命令/配置）'),
        (r'HttpSendRequest.*while.*true|WinHttpSendRequest.*loop.*infinite|HTTP.*GET.*flood.*loop', 'HTTP Flood循环（无限GET/POST请求—应用层DDoS）'),
        (r'InternetOpen.*InternetConnect.*while.*true.*HttpSendRequest', 'WinInet HTTP Flood循环（持续HTTP请求）'),
        # Slowloris / Slow Attack
        (r'Slowloris|slow.*loris|slow.*http.*attack|RUDY.*attack', 'Slowloris/RUDY慢速攻击（保持连接耗尽资源）'),
        (r'socket.*send.*byte.*by.*byte|send.*slow|partial.*header.*send', '慢速发送（逐字节/分段发送—Slowloris特征）'),
        # 通用DDoS
        (r'ddos.*attack|ddos.*bot|ddos.*command|DDoS.*config', 'DDoS攻击配置/命令（僵尸网络远程指令）'),
        (r'attack.*target.*port.*duration|attack.*method.*target', 'DDoS攻击参数（目标+端口+持续时间+方法）'),
        (r'thread.*count.*attack|socket.*count.*attack|connection.*pool.*attack', '多线程/多连接池DDoS（并发攻击调度）'),
        (r'CC.*attack|CC.*flood|Challenge.*Collapsar|CC.*proxy.*list', 'CC攻击（Challenge Collapsar—HTTP代理DDoS）'),
        # ARP / 内网
        (r'arpspoof|arp.*spoof|ARP.*mitm|ARP.*flood', 'ARP欺骗/洪水（内网DDoS/MITM）'),
        (r'memcached.*amplif|Memcached.*flood|CLDAP.*reflection', 'Memcached/CLDAP反射放大（DDoS攻击向量）'),
    ]

    # ===== 新增：Chrome扩展恶意行为 / Facebook广告窃取 / 浏览器密码解密 =====
    CHROME_EXTENSION_PATTERNS = [
        (r'extensions\.settings.*\.crx|Secure\s*Preferences.*extensions', '篡改Chrome Secure Preferences（强制安装恶意扩展）'),
        (r'protection\.macs|protection.*super.*mac|super_mac', 'Chrome配置完整性绕过（protection_macs/super_mac字段）'),
        (r'aieoplapobidheellikiicjfpamacpfd|chrome.*extension.*id.*[a-z]{32}', '恶意Chrome扩展ID（伪装Google Translate）'),
        (r'cookies.*tabs.*history.*webRequest.*downloads.*privacy', 'Chrome扩展高危权限申请（Cookie+标签+历史+网络+下载）'),
        (r'webRequestBlocking.*contentSettings|declarativeNetRequest.*cookies', 'Chrome MV2/3扩展网络拦截权限（流量劫持）'),
        (r'manifest\.json.*permissions.*cookies|permissions.*tabs.*webRequest', 'Chrome扩展manifest权限声明（Cookie/标签/网络）'),
        (r'chrome\.runtime\.sendMessage|chrome\.tabs\.executeScript|chrome\.cookies\.getAll', 'Chrome扩展API调用（注入脚本/读取Cookie/标签操作）'),
    ]

    FACEBOOK_AD_THEFT_PATTERNS = [
        (r'graph\.facebook\.com.*me/accounts|graph\.facebook\.com.*act_\d+|graph\.facebook\.com.*adaccounts', 'Facebook Graph API广告账户查询（Business Manager资产窃取）'),
        (r'fb_dtsg|facebook.*access_token|EAAAAU.*token|EAAB.*token', 'Facebook Access Token提取（短/长令牌窃取）'),
        (r'facebook.*ads.*manager|business.*manager.*facebook|ads.*account.*status|ads.*spend.*limit', 'Facebook广告资产枚举（账户状态/花费/验证状态）'),
        (r'Home/Index/ehruow|Home/Index/dywdg|Home/Index/hduhe', '恶意扩展C2心跳/上传接口（ehruow/dywdg/hduhe）'),
        (r'AES.*encrypt.*facebook|facebook.*cookie.*aes.*upload|encrypt.*facebook.*data', 'Facebook数据AES加密后上传（Cookie/Token外泄）'),
    ]

    BROWSER_DECRYPT_PATTERNS = [
        (r'CryptUnprotectData.*Chrome|CryptUnprotectData.*Firefox|CryptUnprotectData.*Login\s*Data', 'DPAPI解密Chrome/Firefox存储的Cookie和密码'),
        (r'Chrome.*Cookies.*Login\s*Data.*Local\s*State|cookies\.sqlite|key4\.db.*logins\.json', '浏览器凭据文件路径（Chrome Cookies/Login Data + Firefox cookies.sqlite）'),
        (r'Local\\\\Google\\\\Chrome.*Cookies|Local\\\\Google\\\\Chrome.*Login|Profiles.*cookies\.sqlite', '完整浏览器凭据路径（Chrome/Firefox用户数据目录）'),
        (r'hexaeye\.com.*fw.*exe|hexaeye\.com.*fw.*php|fw\d+\.exe|fw\d+\.php', '后续载荷下载（hexaeye.com动态C2—fw_数字.exe/php）'),
        (r'VMProtect.*payload|VMProtect.*protected.*64|Resource.*exe.*VMProtect', 'VMProtect保护的64位载荷（Resource.exe—高隐蔽性）'),
        (r'runas.*COM.*elevat|runas.*COM.*CoCreateInstance|COM.*elevat.*Folder\.exe', 'COM提权执行（runas+COM对象—Folder.exe）'),
    ]

    def analyze(self, strings: StringAnalysis, pe_info: Optional[PEInfo] = None,
                dynamic: Optional[DynamicBehavior] = None,
                api_records: Optional[list] = None) -> AdvancedBehavior:
        """分析高级行为，包括反VM/反沙箱/反调试/Shellcode/键盘记录等

        api_records: 动态 API 调用记录 — 提权类行为只认真实调用,
        不再从静态字符串/导入表里的 AdjustTokenPrivileges 直接判定。
        """
        logger.info("[*] 高级行为检测...")

        ab = AdvancedBehavior()
        all_text = ' '.join(
            strings.suspicious_strings + strings.api_calls + strings.file_paths
        ).lower()

        _re_cache = {}
        def _match(patterns, target_list):
            for pattern, desc in patterns:
                if pattern not in _re_cache:
                    _re_cache[pattern] = re.compile(pattern, re.IGNORECASE)
                if _re_cache[pattern].search(all_text):
                    target_list.append(desc)

        # === 动态行为检测（进程、文件、网络） ===
        if dynamic:
            dynamic_text = ''
            dynamic_paths = set()

            # 收集进程名和命令行
            for p in dynamic.processes_created:
                name = (p.get('name', '')).lower()
                cmd = (p.get('cmdline', '')).lower()
                dynamic_text += ' ' + name + ' ' + cmd

            # 收集文件路径
            for f in dynamic.files_created:
                fpath = f['path'] if isinstance(f, dict) else f
                f_lower = fpath.lower()
                dynamic_text += ' ' + f_lower
                dynamic_paths.add(f_lower)

            # 进程行为
            if 'msiexec' in dynamic_text and '.msi' in dynamic_text:
                ab.anti_analysis.append('MSI 安装包执行（常见于恶意软件分发）')
            if any(n in dynamic_text for n in ['msiexec', 'msiexec.exe']):
                if any(d in dynamic_text for d in ['\\appdata\\', '\\public\\', '\\programdata\\']):
                    ab.anti_analysis.append('msiexec 释放文件到用户/系统目录')
            # 在非标准目录创建可执行文件 — 排除 Inno Setup 自身临时目录
            # (is-XXXX.tmp\_isetup), 否则所有 Inno 安装包都会误报。
            _inno_temp_hints = ('\\temp\\is-', '\\_isetup', '\\is-')
            _susp_exe_paths = [
                f for f in dynamic_paths
                if f.endswith(('.exe', '.dll'))
                and any(d in f for d in ('\\public\\', '\\appdata\\', '\\programdata\\'))
                and not any(t in f for t in _inno_temp_hints)
            ]
            if _susp_exe_paths:
                ab.anti_analysis.append('在非标准目录创建可执行文件')

            # DLL 侧加载检测 — Inno 临时目录的同级 EXE/DLL 是正常安装行为
            if any('.dll' in f for f in dynamic_paths) and any('.exe' in f for f in dynamic_paths):
                exe_dirs = {os.path.dirname(f) for f in dynamic_paths if f.endswith('.exe')}
                dll_dirs = {os.path.dirname(f) for f in dynamic_paths if f.endswith('.dll')}
                if any(d not in _inno_temp_hints and '\\temp\\is-' not in d and '\\_isetup' not in d
                       for d in (exe_dirs & dll_dirs)):
                    ab.anti_analysis.append('EXE/DLL 同级目录（侧加载特征）')

            # 嵌套安装器
            if sum(1 for f in dynamic_paths if f.endswith('.msi')) > 1:
                ab.anti_analysis.append('多阶段 MSI 安装（嵌套载荷）')

            # 文件伪装 — .dat 是 cookie/SQLite 常见扩展名, 曾把 cookie.dat/LGI.dat
            # 误报为“伪装可执行文件”; 只保留图片类扩展名。
            for f in dynamic_paths:
                basename = os.path.basename(f).lower()
                if basename.endswith(('.jpg', '.png')):
                    # 这些扩展名通常不是程序释放的可执行文件
                    ab.anti_analysis.append(f'文件类型伪装: {basename}')

            # 随机目录名（反取证）— 排除常见目录名 (desktop/pictures/runtime等)
            # 且目录名必须含数字, 否则 "desktop" 这种正常目录会被误报。
            _COMMON_PARENT_NAMES = {
                'desktop', 'downloads', 'documents', 'pictures', 'runtime', 'cookie',
                'temp', 'public', 'appdata', 'windows', 'system32', 'tasks',
                'startup', 'roaming', 'local', 'microsoft', 'windowsapps',
            }
            for f in dynamic_paths:
                parent = os.path.basename(os.path.dirname(f)).lower()
                if (re.match(r'^[a-z0-9]{5,12}$', parent)
                        and re.search(r'\d', parent)
                        and parent not in _COMMON_PARENT_NAMES):
                    ab.anti_analysis.append(f'随机名称目录（反取证）: {parent}')
                    break  # 只报一次

            # ===== 感染型木马动态检测: 批量修改现有文档文件 (不改名不删除) =====
            # resvr/感染型病毒特征: 遍历驱动器, 对 .doc/.xls/.jpg/.rar 文件头 XOR 加密
            try:
                _doc_exts = ('.doc', '.docx', '.xls', '.xlsx', '.jpg', '.jpeg',
                             '.rar', '.zip', '.pdf', '.ppt', '.pptx')
                _sys_noise_prefix = ('c:\\windows\\', 'c:\\program files\\', 'c:\\programdata\\')
                modified_docs = []
                for f in (dynamic.files_modified or []):
                    fstr = str(f).lower()
                    if not fstr.endswith(_doc_exts):
                        continue
                    if fstr.startswith(_sys_noise_prefix):
                        continue
                    if any(h in fstr for h in ('\\temp\\', '\\cache\\', '\\frida-',
                                               '\\uv\\', '\\gen_py\\', '\\wer\\')):
                        continue
                    modified_docs.append(str(f))
                if len(modified_docs) >= 3:
                    ab.anti_analysis.append(
                        f'批量修改 {len(modified_docs)} 个文档文件（感染型木马特征—文件头加密感染）: '
                        + '; '.join(modified_docs[:3]))
            except Exception:
                pass

            # ===== 系统 DLL 感染动态检测: system32 下系统 DLL 被修改/替换 =====
            # 永恒小马: d3d9.dll/mshtml.dll 感染替换 (SFC 绕过 + MoveFileEx 替换)
            try:
                _sys_dll_names = ('d3d9.dll', 'mshtml.dll', 'wininet.dll', 'ws2_32.dll',
                                  'winmm.dll', 'comctl32.dll', 'shell32.dll', 'user32.dll',
                                  'kernel32.dll', 'ntdll.dll')
                _modified_sys_dll = []
                for f in (dynamic.files_modified or []):
                    fstr = str(f).lower()
                    if fstr.endswith(_sys_dll_names) and ('\\system32\\' in fstr or '\\system\\' in fstr):
                        _modified_sys_dll.append(str(f))
                for f in (dynamic.files_deleted or []):
                    fstr = str(f).lower()
                    if fstr.endswith(_sys_dll_names) and ('\\system32\\' in fstr or '\\system\\' in fstr):
                        _modified_sys_dll.append(str(f) + ' (被删除/替换)')
                if _modified_sys_dll:
                    ab.anti_analysis.append(
                        f'系统 DLL 被修改/替换（感染型木马—SFC绕过替换）: ' + '; '.join(_modified_sys_dll[:3]))
            except Exception:
                pass

        # 环境检测
        _match(self.ANTI_SANDBOX_PATTERNS, ab.anti_sandbox)
        _match(self.SEVEN_CONDITION_SANDBOX_PATTERNS, ab.anti_sandbox)
        _match(self.ANTI_VM_PATTERNS, ab.anti_vm)
        _match(self.ANTI_DEBUG_PATTERNS, ab.anti_debug)
        _match(self.ANTI_ANALYSIS_PATTERNS, ab.anti_analysis)
        _match(self.TIMING_EVASION_PATTERNS, ab.timing_evasion)

        # 持久化 / 防御绕过
        _match(self.PERSISTENCE_PATTERNS, ab.anti_analysis)
        _match(self.DEFENDER_PATTERNS, ab.anti_analysis)
        _match(self.WINDOWS_UPDATE_SABOTAGE_PATTERNS, ab.anti_analysis)
        _match(self.PERMISSION_MANIPULATION_PATTERNS, ab.anti_analysis)

        # 注入/操纵
        _match(self.INJECTION_PATTERNS, ab.process_injection)
        _match(self.SHELLCODE_PATTERNS, ab.process_injection)
        _match(self.CROSS_PROCESS_MEMORY_PATTERNS, ab.process_injection)

        # 云沙箱对照补强: COM劫持 / 反取证 / PDF恶意
        _match(self.COM_HIJACK_PATTERNS, ab.privilege_escalation)
        _match(self.ANTI_FORENSICS_PATTERNS, ab.anti_analysis)
        _match(self.PDF_MALWARE_PATTERNS, ab.attack_chain)

        # 权限
        _match(self.PRIVESC_PATTERNS, ab.privilege_escalation)
        _match(self.MSI_ABUSE_PATTERNS, ab.privilege_escalation)
        # UAC 绕过单独归类
        _match(self.UAC_BYPASS_PATTERNS, ab.uac_bypass)

        # 提权类行为必须由真实动态 API 调用支撑 — 静态字符串里的
        # AdjustTokenPrivileges/LookupPrivilegeValueW 不再直接判定。
        if api_records is not None:
            _seen_apis = set()
            _api_count = {}
            for _r in (api_records or []):
                try:
                    _name = _r.api_name if hasattr(_r, 'api_name') else str(_r)
                    if _name:
                        _seen_apis.add(_name.lower())
                        _api_count[_name.lower()] = _api_count.get(_name.lower(), 0) + 1
                except Exception:
                    continue

            # ===== 七组条件反沙箱动态确认 (IsSandboxEnvironment 0x140002E20 模式) =====
            _seven_dyn = {
                '反调试': 'isdebuggerpresent' in _seen_apis or 'checkremotedebuggerpresent' in _seen_apis,
                '分辨率': 'getsystemmetrics' in _seen_apis,
                'CPU': any(k in _seen_apis for k in ('getsysteminfo', 'getnativesysteminfo',
                                                      'getlogicalprocessorinformation')),
                '运行时长': any(k in _seen_apis for k in ('gettickcount', 'gettickcount64')),
                '内存': any(k in _seen_apis for k in ('globalmemorystatusex', 'globalmemorystatus',
                                                      'getphysicallyinstalledsystemmemory')),
                '进程数': any(k in _seen_apis for k in ('createtoolhelp32snapshot',
                                                        'process32firstw', 'process32firsta',
                                                        'ntquerysysteminformation')),
                '用户名': any(k in _seen_apis for k in ('getusernamew', 'getusernamea',
                                                        'getusernameexw', 'getenvironmentvariablew')),
            }
            _seven_dyn_hit = sum(1 for v in _seven_dyn.values() if v)
            if _seven_dyn_hit >= 4:
                ab.anti_sandbox.append(
                    f'七组条件反沙箱环境评分 ×{_seven_dyn_hit}/7 (动态API确认): '
                    + ' + '.join(k for k, v in _seven_dyn.items() if v))
                ab.timing_evasion.append('反沙箱运行时长门槛 (GetTickCount>=300000ms 类检测)')

            # ===== 键盘记录动态确认 =====
            _keylog_apis = {'getasynckeystate', 'getkeystate', 'getkeyboardstate',
                            'setwindowshookexw', 'setwindowshookexa', 'getforegroundwindow'}
            _keylog_count = sum(_api_count.get(k, 0) for k in _keylog_apis)
            if _keylog_count > 0:
                if _keylog_count >= 50:
                    ab.keylogging.append(
                        f'键盘状态高频轮询 ×{_keylog_count} (动态API确认)')
                else:
                    ab.keylogging.append(
                        f'键盘/钩子 API 调用 ×{_keylog_count} (动态)')

            # ===== 音频设备访问动态确认 =====
            _audio_apis = {'waveinopen', 'waveinstart', 'mixeropen', 'midiinopen'}
            _audio_count = sum(_api_count.get(k, 0) for k in _audio_apis)
            if _audio_count > 0:
                ab.audio_surveillance.append(
                    f'音频/麦克风设备访问 ×{_audio_count} (动态API确认)')

            # ===== 代理设置操控动态确认 =====
            _proxy_apis = {'internetsetoptionw', 'internetsetoptiona',
                           'winhttpsetdefaultproxyconfiguration'}
            _proxy_count = sum(_api_count.get(k, 0) for k in _proxy_apis)
            if _proxy_count > 0:
                ab.proxy_manipulation.append(
                    f'代理设置操控 (InternetSetOption/WinHttp) ×{_proxy_count} (动态API确认)')

            # ===== PAGE_GUARD 反调试动态确认 =====
            _has_page_guard = False
            _has_guard_exec = False
            if hasattr(dynamic, 'api_monitor') and dynamic.api_monitor:
                _memprot = getattr(dynamic.api_monitor, '_memprot_events', [])
                for _mp in _memprot:
                    if _mp.get('page_guard'):
                        _has_page_guard = True
                        if _mp.get('guard_exec'):
                            _has_guard_exec = True
            if _has_guard_exec:
                ab.anti_debug.append(
                    'PAGE_GUARD + 可执行内存 (反调试陷阱, 动态memprot确认)')
            elif _has_page_guard:
                ab.anti_debug.append(
                    'PAGE_GUARD 内存页创建 (反逆向行为, 动态确认)')

            # ===== 系统枚举 VM 检测动态确认 =====
            _vm_enum_apis = {'getadaptersaddresses', 'getiftable',
                             'getvolumeinformationw', 'getvolumeinformationa',
                             'querydosdevicew', 'querydosdevicea',
                             'getlogicaldrives', 'getdrivetypew', 'getdrivetypea',
                             'gettimezoneinformation'}
            _vm_enum_count = sum(_api_count.get(k, 0) for k in _vm_enum_apis)
            if _vm_enum_count >= 2:
                ab.anti_vm.append(
                    f'系统枚举探测 (网卡/磁盘/设备/时区) ×{_vm_enum_count} (动态API确认)')

            # ===== DEP 绕过动态确认: RWX 分配 / RW->RX 转换 / 写后执行链 =====
            _dep_dyn_names = ('ntallocatevirtualmemory', 'ntprotectvirtualmemory',
                              'virtualalloc', 'virtualallocEx', 'virtualprotect',
                              'virtualprotectex')
            _dep_dyn_apis = [n for n in _dep_dyn_names if n in _api_count]
            if _dep_dyn_apis:
                _dep_dyn_text = ' '.join(str(r.arguments).lower() for r in api_records
                                         if hasattr(r, 'api_name')
                                         and (r.api_name or '').lower() in _dep_dyn_names
                                         and r.arguments)
                _dep_rwx = ('0x40' in _dep_dyn_text or '0x80' in _dep_dyn_text
                            or 'page_execute_readwrite' in _dep_dyn_text
                            or 'execute_readwrite' in _dep_dyn_text
                            or 'execute_writecopy' in _dep_dyn_text)
                _dep_rwrx = ('page_execute_read' in _dep_dyn_text
                             or 'execute_read' in _dep_dyn_text)
                if _dep_rwx:
                    ab.process_injection.append(
                        'RWX 内存分配/保护修改 (DEP 绕过特征, 动态参数确认)')
                if _dep_rwrx:
                    ab.process_injection.append(
                        'RW→RX 内存保护转换 (载荷解密后执行, 动态参数确认)')
                if ('writeprocessmemory' in _seen_apis or 'ntwritevirtualmemory' in _seen_apis) \
                        and ('createremotethread' in _seen_apis or 'ntcreatethreadex' in _seen_apis
                             or 'rtlcreateuserthread' in _seen_apis or 'queueuserapc' in _seen_apis):
                    ab.process_injection.append(
                        '跨进程写入+远程线程执行链 (DEP 绕过后的载荷注入执行)')

            # ===== 内存分配/释放失衡动态确认 (分配后不释放) =====
            _alloc_dyn = sum(_api_count.get(k, 0) for k in
                             ('virtualalloc', 'virtualallocex', 'ntallocatevirtualmemory',
                              'heapalloc', 'rtlallocateheap', 'globalalloc', 'localalloc'))
            _free_dyn = sum(_api_count.get(k, 0) for k in
                            ('virtualfree', 'virtualfreeex', 'ntfreevirtualmemory',
                             'heapfree', 'rtlfreeheap', 'globalfree', 'localfree'))
            if _alloc_dyn >= 3 and _alloc_dyn >= _free_dyn * 2:
                ab.anti_analysis.append(
                    f'内存分配未释放 (alloc×{_alloc_dyn} / free×{_free_dyn}, 驻留/泄漏特征)')

            _priv_api_gates = {
                'AdjustTokenPrivileges 提权操作': ('adjusttokenprivileges',),
                '查找特权值 (提权准备)': ('lookupprivilegevaluew', 'lookupprivilegevaluea'),
                '打开进程令牌并修改特权': ('openprocesstoken',),
            }
            # Se* 特权名称出现在静态字符串里很常见 (安装器/安全组件),
            # 必须有真实的 Lookup/AdjustToken 动态调用才计入提权行为。
            for _item in ab.privilege_escalation:
                if _item.startswith('启用 Se'):
                    _priv_api_gates.setdefault(
                        _item, ('lookupprivilegevaluew', 'lookupprivilegevaluea',
                                'adjusttokenprivileges'))
            _filtered_priv = []
            for _item in ab.privilege_escalation:
                _gates = _priv_api_gates.get(_item)
                if _gates and not any(_g in _seen_apis for _g in _gates):
                    continue
                _filtered_priv.append(_item)
            # 静态模式已移除的弱项, 由真实 API 调用动态补回
            if 'adjusttokenprivileges' in _seen_apis:
                _filtered_priv.append('AdjustTokenPrivileges 提权操作')
            if 'lookupprivilegevaluew' in _seen_apis or 'lookupprivilegevaluea' in _seen_apis:
                _filtered_priv.append('查找特权值 (提权准备)')
            ab.privilege_escalation = list(dict.fromkeys(_filtered_priv))

        # DLL 侧加载
        _match(self.DLL_SIDELOAD_PATTERNS, ab.anti_analysis)

        # 数据窃取
        _match(self.DATA_THEFT_PATTERNS, ab.credential_theft)
        _match(self.KEYLOGGING_PATTERNS, ab.keylogging)
        _match(self.HOOK_IDENTIFIER_PATTERNS, ab.keylogging)
        _match(self.AUDIO_ACCESS_PATTERNS, ab.audio_surveillance)
        _match(self.PROXY_MANIPULATION_PATTERNS, ab.proxy_manipulation)

        # 文件/进程操作
        _match(self.FILE_OPS_PATTERNS, ab.anti_analysis)
        _match(self.HIDDEN_PROC_PATTERNS, ab.anti_analysis)
        _match(self.FILE_DELETE_MARK_PATTERNS, ab.anti_analysis)

        # Hosts 篡改 / PowerShell 持久化
        _match(self.HOSTS_TAMPER_PATTERNS, ab.anti_analysis)
        _match(self.POWERSHELL_PERSIST_PATTERNS, ab.anti_analysis)

        # 系统探测/信息搜集 — 常规 API 不是“反分析”, 曾把 GetSystemDirectory
        # 这类正常调用算成 anti_analysis; 只保留高信号模式 (哈希解析/导出表遍历)。
        _BENIGN_SYSTEM_ENUM = {
            '查询计算机名', '查询系统用户名', '获取系统信息', '获取操作系统版本',
            '获取系统目录', '获取临时目录路径', '枚举磁盘驱动器', '获取CPU/产品信息',
            '操作当前工作目录',
        }
        _match([p for p in self.SYSTEM_ENUM_PATTERNS if p[1] not in _BENIGN_SYSTEM_ENUM],
               ab.anti_analysis)
        _match(self.COM_PATTERNS, ab.anti_analysis)
        _match(self.CRYPTO_PATTERNS, ab.anti_analysis)
        _match(self.DPAPI_CREDENTIAL_PATTERNS, ab.credential_theft)

        # 配置文件/信任设置
        _match(self.CONFIG_FILE_PATTERNS, ab.anti_analysis)
        _match(self.TRUST_PATTERNS, ab.anti_analysis)

        # 网络通信模式
        _match(self.OSS_C2_PATTERNS, ab.c2_communication)
        _match(self.NETWORK_BEHAVIOR_PATTERNS, ab.c2_communication)
        _match(self.WEBSOCKET_C2_PATTERNS, ab.c2_communication)

        # ===== SilverFox 专有载荷检测 =====
        _match(self.OPENPGP_PATTERNS, ab.c2_communication)
        _match(self.ZLIB_PAYLOAD_PATTERNS, ab.process_injection)
        _match(self.SILVERFOX_PAYLOAD_PATTERNS, ab.anti_analysis)
        _match(self.MEMORY_PAYLOAD_PATTERNS, ab.process_injection)

        # ===== COM 代理/进程繁衍/跨进程注入检测 =====
        _match(self.COM_SURROGATE_PATTERNS, ab.anti_analysis)
        _match(self.PROCESS_SPAWN_PATTERNS, ab.anti_analysis)

        # ===== InnoSetup 打包/伪造安全软件/浏览器探测/多用户 =====
        _match(self.INNOSETUP_PATTERNS, ab.anti_analysis)
        _match(self.FAKE_SECURITY_SOFTWARE_PATTERNS, ab.anti_analysis)
        _match(self.BROWSER_DETECTION_PATTERNS, ab.credential_theft)
        _match(self.MULTI_USER_PATTERNS, ab.anti_analysis)

        # ===== 新增：反沙箱环境指纹检测 =====
        _match(self.SLEEP_PRECISION_PATTERNS, ab.anti_sandbox)
        _match(self.CPUID_TIMING_PATTERNS, ab.anti_vm)
        _match(self.RDTSC_JITTER_PATTERNS, ab.anti_vm)
        _match(self.SYSTEM_UPTIME_PATTERNS, ab.anti_sandbox)
        _match(self.USER_INTERACTION_PATTERNS, ab.anti_sandbox)
        _match(self.SYSTEM_TRACE_PATTERNS, ab.anti_sandbox)
        _match(self.DISK_ANTI_VM_PATTERNS, ab.anti_vm)
        _match(self.MEMORY_ANTI_VM_PATTERNS, ab.anti_vm)

        # ===== 新增：系统指纹深度检测 =====
        _match(self.HASH_PROCESS_PATTERNS, ab.anti_analysis)
        _match(self.INSTALLED_PROGRAMS_PATTERNS, ab.anti_sandbox)
        _match(self.SYSTEM_CONFIG_PATTERNS, ab.anti_sandbox)
        _match(self.PREFETCH_DETECTION_PATTERNS, ab.anti_sandbox)
        _match(self.EVENT_LOG_PATTERNS, ab.anti_sandbox)
        _match(self.UPDATE_HISTORY_PATTERNS, ab.anti_sandbox)
        _match(self.NETWORK_CONFIG_PATTERNS, ab.anti_vm)
        _match(self.COM_WMI_PATTERNS, ab.anti_vm)
        _match(self.RECYCLE_BIN_PATTERNS, ab.anti_sandbox)
        _match(self.SMART_DETECTION_PATTERNS, ab.anti_vm)

        # ===== 新增：ETW绕过 / 直接系统调用 / 线程劫持 =====
        _match(self.ETW_BYPASS_PATTERNS, ab.anti_analysis)
        _match(self.DIRECT_SYSCALL_PATTERNS, ab.process_injection)
        _match(self.THREAD_HIJACK_PATTERNS, ab.process_injection)

        # ===== 新增：MSC/XSLT脚本注入 / 白加黑路径 / 参数反沙箱 =====
        _match(self.MSC_XSLT_ATTACK_PATTERNS, ab.anti_analysis)
        _match(self.DLL_SIDELOAD_PATH_PATTERNS, ab.anti_analysis)
        _match(self.PARAM_GATE_PATTERNS, ab.anti_sandbox)

        # ===== 新增：legion样本 — net use/ctypes/PowerShell混淆/XWorm/VM自杀死 =====
        _match(self.NET_DRIVE_DELIVERY_PATTERNS, ab.anti_sandbox)
        _match(self.PYTHON_CTYPES_SHELLCODE_PATTERNS, ab.process_injection)
        _match(self.PS_OBFUSCATION_PATTERNS, ab.anti_analysis)
        _match(self.XWORM_LAZZY_PATTERNS, ab.anti_analysis)
        _match(self.VM_SELFKILL_PATTERNS, ab.anti_vm)

        # ===== 新增：uzusy 10层嵌套RAT — PyInstaller/encodings/FileMapping/DirectInput/svchost守护 =====
        _match(self.PYINSTALLER_CHAIN_PATTERNS, ab.anti_analysis)
        _match(self.FILEMAPPING_SHELLCODE_PATTERNS, ab.process_injection)
        _match(self.DOH_C2_PATTERNS, ab.c2_communication)
        _match(self.DIRECTINPUT_KEYLOGGER_PATTERNS, ab.keylogging)
        _match(self.SVCHOST_DAEMON_PATTERNS, ab.anti_analysis)
        _match(self.RPC_SCHEDULED_TASK_PATTERNS, ab.anti_analysis)

        # ===== 新增：捆绑下载/多阶段投放 / DDoS =====
        _match(self.BUNDLE_DROPPER_PATTERNS, ab.anti_analysis)
        _match(self.DDOS_PATTERNS, ab.c2_communication)

        # ===== 新增：Chrome扩展恶意行为 / 浏览器数据窃取 =====
        _match(self.CHROME_EXTENSION_PATTERNS, ab.credential_theft)
        _match(self.FACEBOOK_AD_THEFT_PATTERNS, ab.credential_theft)
        _match(self.BROWSER_DECRYPT_PATTERNS, ab.credential_theft)

        # ===== NSIS/反竞争AV/全盘排除 =====
        _match(self.NSIS_PATTERNS, ab.anti_analysis)
        _match(self.ANTI_COMPETITOR_PATTERNS, ab.anti_analysis)
        _match(self.PLUGX_PATTERNS, ab.anti_analysis)
        _match(self.FULL_DISK_EXCLUSION_PATTERNS, ab.anti_analysis)
        _match(self.SELF_EXTRACTING_CHILD_PATTERNS, ab.anti_analysis)
        _match(self.SELF_DELETE_PATTERNS, ab.anti_analysis)
        _match(self.SYSTEM_DLL_INFECTION_PATTERNS, ab.anti_analysis)
        _match(self.FAKE_DIALOG_PATTERNS, ab.anti_analysis)
        _match(self.CRASH_EVASION_PATTERNS, ab.anti_analysis)
        _match(self.EDR_ENUM_PATTERNS, ab.anti_analysis)
        _match(self.HEARTBEAT_C2_PATTERNS, ab.c2_communication)
        _match(self.CS_NAMED_PIPE_PATTERNS, ab.c2_communication)
        _match(self.CS_CONFIG_PATTERNS, ab.c2_communication)

        # 恶意行为
        _match(self.RANSOMWARE_PATTERNS, ab.ransomware_indicators)
        _match(self.INFECTION_PATTERNS, ab.anti_analysis)
        _match(self.C2_PATTERNS, ab.c2_communication)
        _match(self.ROOTKIT_PATTERNS, ab.rootkit_indicators)

        # 文件/连接行为
        _match(self.FILE_CREATION_PATTERNS, ab.anti_analysis)
        _match(self.DEAD_CONNECTION_PATTERNS, ab.anti_analysis)

        # ===== 新增: API 调用链检测 =====
        _match(self.API_CHAIN_PATTERNS, ab.process_injection)
        # ===== 新增: 凭据转储检测 =====
        _match(self.CREDENTIAL_DUMP_PATTERNS, ab.credential_theft)
        # ===== 新增: PII敏感数据泄露 =====
        _match(self.PII_EXFIL_PATTERNS, ab.credential_theft)
        # ===== 新增: 宏/文档攻击 =====
        _match(self.MACRO_ATTACK_PATTERNS, ab.anti_analysis)
        # ===== 新增: 自启动持久化增强 =====
        _match(self.AUTORUN_PERSIST_PATTERNS, ab.anti_analysis)
        # ===== 新增: 浏览器凭据窃取 =====
        _match(self.BROWSER_CRED_PATTERNS, ab.credential_theft)
        # ===== 新增: 横向移动 =====
        _match(self.LATERAL_MOVEMENT_PATTERNS, ab.lateral_movement)
        # ===== 新增: 侦察/网络发现 =====
        _match(self.RECON_DISCOVERY_PATTERNS, ab.lateral_movement)
        # ===== 新增: 攻击链检测 =====
        _match(self.ATTACK_CHAIN_PATTERNS, ab.attack_chain)

        # PE 结构中的 TLS 回调
        if pe_info and pe_info.tls_callbacks:
            ab.anti_analysis.append(f"Tls 节回调 ({len(pe_info.tls_callbacks)} 个回调地址)")

        # 去重（所有字段）
        for field_name in [
            'anti_sandbox', 'anti_vm', 'anti_debug', 'anti_analysis', 'timing_evasion',
            'process_injection', 'process_hollowing', 'privilege_escalation', 'uac_bypass',
            'credential_theft', 'keylogging', 'clipboard_monitoring', 'screenshot_capture',
            'ransomware_indicators', 'c2_communication', 'rootkit_indicators', 'bootkit_indicators',
            'lateral_movement', 'attack_chain',
        ]:
            setattr(ab, field_name, list(set(getattr(ab, field_name))))

        # DGA 检测
        domains = [d for d in strings.domains if len(d) > 15]
        if len(domains) > 5:
            ab.dga_detected = True
            ab.domain_generation = domains[:10]

        # 风险评分
        risk = 0
        risk += len(ab.anti_sandbox) * 3
        risk += len(ab.anti_vm) * 3
        risk += len(ab.anti_debug) * 3
        risk += len(ab.anti_analysis) * 4
        risk += len(ab.timing_evasion) * 3
        risk += len(ab.process_injection) * 10
        risk += len(ab.process_hollowing) * 15
        risk += len(ab.privilege_escalation) * 8
        risk += len(ab.uac_bypass) * 10
        risk += len(ab.credential_theft) * 10
        risk += len(ab.keylogging) * 8
        risk += len(ab.audio_surveillance) * 8
        risk += len(ab.proxy_manipulation) * 5
        risk += len(ab.screenshot_capture) * 5
        risk += len(ab.clipboard_monitoring) * 5
        risk += len(ab.browser_data_theft) * 8
        risk += len(ab.ransomware_indicators) * 15
        risk += len(ab.c2_communication) * 5
        risk += len(ab.rootkit_indicators) * 20
        risk += len(ab.bootkit_indicators) * 25
        risk += len(ab.lateral_movement) * 12
        risk += len(ab.attack_chain) * 8

        ab.risk_score = min(risk, 100)

        # 摘要
        summary_parts = []
        if ab.anti_vm:
            summary_parts.append(f"反VM {len(ab.anti_vm)}项")
        if ab.anti_sandbox:
            summary_parts.append(f"反沙箱 {len(ab.anti_sandbox)}项")
        if ab.anti_debug:
            summary_parts.append(f"反调试 {len(ab.anti_debug)}项")
        if ab.anti_analysis:
            summary_parts.append(f"反分析 {len(ab.anti_analysis)}项")
        if ab.timing_evasion:
            summary_parts.append(f"时间逃逸 {len(ab.timing_evasion)}项")
        if ab.keylogging:
            summary_parts.append(f"键盘记录 {len(ab.keylogging)}项")
        if ab.audio_surveillance:
            summary_parts.append(f"设备监听 {len(ab.audio_surveillance)}项")
        if ab.proxy_manipulation:
            summary_parts.append(f"代理操控 {len(ab.proxy_manipulation)}项")
        if ab.process_injection:
            summary_parts.append(f"注入 {len(ab.process_injection)}项")
        if ab.privilege_escalation:
            summary_parts.append(f"提权 {len(ab.privilege_escalation)}项")
        if ab.credential_theft:
            summary_parts.append(f"凭据窃取 {len(ab.credential_theft)}项")
        if ab.uac_bypass:
            summary_parts.append(f"UAC绕过 {len(ab.uac_bypass)}项")
        if ab.ransomware_indicators:
            summary_parts.append(f"勒索 {len(ab.ransomware_indicators)}项")
        if ab.c2_communication:
            summary_parts.append(f"C2 {len(ab.c2_communication)}项")
        if ab.rootkit_indicators:
            summary_parts.append(f"Rootkit {len(ab.rootkit_indicators)}项")
        if ab.lateral_movement:
            summary_parts.append(f"横向移动 {len(ab.lateral_movement)}项")
        if ab.attack_chain:
            summary_parts.append(f"攻击链 {len(ab.attack_chain)}项")
        if not summary_parts:
            summary_parts.append("未检测到高级行为特征")

        ab.summary = ' | '.join(summary_parts)
        return ab
