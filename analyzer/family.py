#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
木马家族分析引擎 — 基于签名、行为、网络特征识别恶意软件家族
"""
import os
import re
from typing import Optional

from logger import get_logger
from analyzer.models import MalwareFamilyAnalysis, MalwareFamilyIndicator, StringAnalysis, PEInfo

logger = get_logger('analyzer.family')


class FamilyAnalyzer:
    """恶意软件家族分析器"""
    
    FAMILY_SIGNATURES = {
        'Emotet': {
            'strings': [
                'emotet', 'heuk', 'epoch',
                r'\.dll', r'\.exe', r'\-0000', r'\-0001', r'\-0002',
            ],
            'apis': ['CryptDecrypt', 'CryptEncrypt', 'InternetReadFile', 'InternetOpenA'],
            'network': ['185.', '81.', '91.', '194.'],
            'description': 'Emotet 银行木马，以邮件传播和模块化加载著称',
            'behaviors': ['邮件窃密', '银行凭证窃取', '模块化加载', 'C2 通信'],
        },
        'TrickBot': {
            'strings': [
                'trickbot', 'trick', 'inject', 'moduleconfig', 'yandin',
                'wininet.dll', 'syswow64', 'system32',
            ],
            'apis': ['RtlMoveMemory', 'NtWriteVirtualMemory', 'CreateRemoteThread'],
            'network': ['185.', '51.', '82.', '91.', '103.'],
            'description': 'TrickBot 银行木马，擅长凭证窃取和横向移动',
            'behaviors': ['凭证窃取', '横向移动', '浏览器数据窃取', '系统信息收集'],
        },
        'QakBot': {
            'strings': [
                'qakbot', 'qb', 'bri', 'tan', 'au', 'socks', 'proxy',
                'dllhost.exe', 'explorer.exe', 'svchost.exe',
            ],
            'apis': ['NtCreateSection', 'NtMapViewOfSection', 'RtlCreateUserThread'],
            'network': ['185.', '45.', '23.', '104.'],
            'description': 'QakBot 银行木马，长期活跃，使用进程注入和持久化',
            'behaviors': ['进程注入', '持久化', '凭证窃取', 'C2 通信'],
        },
        'CobaltStrike': {
            # ⚠ 只保留 CobaltStrike 特异性特征; smb/pipe/post/upload 等泛词
            # 曾导致大量网络样本被误判为 CobaltStrike (银狐误报根源之一)
            'strings': [
                'cobalt', 'beacon', 'ms-windows-update', 'msse-',
                'postex', 'msagent', 'smb_beacon', 'beacon_x64', 'beacon_x86',
                r'\\\\.\\pipe\\msagent', r'\\\\.\\pipe\\postex', r'\\\\.\\pipe\\msse',
            ],
            'apis': ['VirtualAlloc', 'CreateThread', 'InternetOpen', 'InternetConnect', 'HttpSendRequest'],
            'network': ['443', '80'],
            'description': 'Cobalt Strike 商业渗透测试框架，常被 APT 组织滥用',
            'behaviors': ['Beacon 通信', '管道通信', '反射注入', '横向移动', '权限提升'],
        },
        'EnvScoreLoader': {
            'strings': [
                'SLEEP_HOOKED', 'VM_EXIT_OVERHEAD', 'LOW_RDTSC_JITTER',
                'SHORT_UPTIME', 'NO_RECENT_INPUT', 'EMPTY_CLIPBOARD',
                'NO_USB_HISTORY', 'NO_JUMP_LISTS', 'ROUND_DISK_SIZE',
                'VM_VENDOR_ID', 'FEW_INSTALLED_PROGRAMS', 'FEW_FONTS',
                'SIMPLE_REGISTRY', 'FEW_SYSTEM_FILES', 'FEW_PREFETCH_FILES',
                'FEW_SYSTEM_EVENTS', 'NO_UPDATE_HISTORY', 'FEW_COM_CLASSES',
                'SMALL_WMI_REPO', 'CLUSTERED_PREFETCH_TIMESTAMPS',
                'TINY_RECYCLE_FILES', 'SMART_CAPABLE', 'NO_SMART_SUPPORT',
                'DEBUGGER_PRESENT', 'NTGLOBALFLAG_SET', 'EDR_DETECTED',
                'DEFINITE_SANDBOX', 'POSSIBLE_SANDBOX',
                # 截断混淆变种 (1.exe 家族)
                'FEW_ETW_', 'NO_NETWOH', 'HOOKING_L', 'VMWARE_MH',
                'HR_DETECTH', 'VM_VENDOH',
            ],
            'apis': ['ZwOpenProcess', 'ZwTerminateProcess', 'BCryptDecrypt',
                     'BCryptEncrypt', 'IsDebuggerPresent', 'VirtualProtect'],
            'network': [],
            'description': 'EnvScoreLoader 企业级定向加载器（评分制环境检测+ETW绕过+线程劫持注入）',
            'behaviors': ['环境评分检测', 'ETW Hook', 'Halo Gate系统调用', '线程劫持注入', 'C2载荷分发'],
        },
        'Meterpreter': {
            # ⚠ 旧签名含 x86/x64/reverse/443/80/VirtualAlloc 等泛词,
            # 任何安装器都能凑出 43% — sysdiag/WPS 被误判为 Meterpreter。
            # 只保留 Meterpreter 专属特征。
            'strings': [
                'meterpreter', 'metsrv', 'metasploit', 'stdapi', 'extapi',
                'incognito', 'msfvenom',
            ],
            'apis': ['CreateRemoteThread', 'WriteProcessMemory'],
            'network': ['4444'],
            'description': 'Metasploit Meterpreter 载荷，高级后渗透工具',
            'behaviors': ['反射注入', '内存执行', '键盘记录', '屏幕截图', '权限提升'],
        },
        'Mimikatz': {
            'strings': [
                'mimikatz', 'mimilib', 'sekurlsa', 'lsadump', 'kerberos',
                'token', 'privilege', 'process', 'crypto', 'vault',
                'dpapi', 'sid', 'sam', 'lsa', 'wdigest', 'tspkg', 'livessp', 'kerb',
            ],
            'apis': ['LsaEnumerateLogonSessions', 'LsaGetLogonSessionData', 'NtQuerySystemInformation'],
            'network': [],
            'description': 'Mimikatz 凭证提取工具，广泛用于凭据窃取和权限提升',
            'behaviors': ['LSA 凭据提取', 'Kerberos 票据操作', 'Token 操纵', 'DPAPI 解密'],
        },
        'Ransomware': {
            'strings': [
                'ransom', 'encrypt', 'decrypt', 'bitcoin', 'btc', 'monero',
                'readme', 'unlock', 'recover', 'restore', 'payment',
                'tor', '.onion', 'aes', 'rsa', 'chacha', 'salsa',
            ],
            'apis': ['CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptAcquireContext', 'FindFirstFile', 'FindNextFile'],
            'network': ['.onion', 'tor', 'bitcoin', 'blockchain'],
            'description': '勒索软件，加密受害者文件并索要赎金',
            'behaviors': ['文件加密', '赎金通知', '卷影删除', '备份删除', 'C2 通信'],
        },
        'APT29': {
            'strings': [
                'apt29', 'cozy', 'dukes', 'hammertoss', 'onionduke', 'miniduke',
                'cloud', 'onedrive', 'twitter', 'github', 'pastebin',
            ],
            'apis': ['InternetOpen', 'InternetConnect', 'HttpOpenRequest', 'HttpSendRequest'],
            'network': ['onedrive', 'twitter', 'github', 'pastebin', 'cloud'],
            'description': 'APT29 (Cozy Bear) 俄罗斯 APT 组织，使用云服务作为 C2',
            'behaviors': ['云 C2 通信', '隐蔽持久化', '凭证窃取', '横向移动'],
        },
        'APT28': {
            'strings': [
                'apt28', 'fancy', 'sofacy', 'x-agent', 'chopstick', 'xtunnel',
                'sednit', 'sr', 'game', 'drop', 'zade',
            ],
            'apis': ['CreateThread', 'VirtualAlloc', 'WriteProcessMemory', 'DeviceIoControl'],
            'network': ['80', '443', '8080', '25', '587'],
            'description': 'APT28 (Fancy Bear) 俄罗斯 APT 组织，以军事和政治目标为主',
            'behaviors': ['鱼叉式钓鱼', '漏洞利用', '凭证窃取', 'C2 通信'],
        },
        'Lazarus': {
            'strings': [
                'lazarus', 'hidden', 'cobra', 'apple', 'jesus', 'bat',
                'backdoor', 'dtrack', 'wannacry', 'ms17', 'eternal',
            ],
            'apis': ['CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile', 'MoveFile'],
            'network': ['443', '80', '8080', '21', '22'],
            'description': 'Lazarus Group 朝鲜 APT 组织，以金融攻击和破坏性攻击著称',
            'behaviors': ['破坏性攻击', '金融犯罪', '勒索软件', '供应链攻击'],
        },
        'Dridex': {
            'strings': [
                'dridex', 'crambus', 'bugat', 'dyre', 'dyd', 'vnc',
                'webinject', 'cookiesteal', 'formgrab', 'certgrab',
            ],
            'apis': ['InternetReadFile', 'InternetWriteFile', 'HttpSendRequest', 'FtpPutFile'],
            'network': ['443', '80', '25', '587'],
            'description': 'Dridex 银行木马，以 Web 注入和凭证窃取著称',
            'behaviors': ['Web 注入', '凭证窃取', '证书窃取', 'VNC 远程访问'],
        },
        'AgentTesla': {
            'strings': [
                'agenttesla', 'agent', 'tesla', 'smtp', 'ftp', 'telegram',
                'clipboard', 'keystroke', 'screenshot', 'credentials',
            ],
            'apis': ['GetClipboardData', 'SetClipboardData', 'GetAsyncKeyState', 'GetKeyboardState'],
            'network': ['smtp', 'ftp', 'telegram', 'discord', ' webhook'],
            'description': 'AgentTesla 信息窃取木马，通过 SMTP/Telegram 回传数据',
            'behaviors': ['键盘记录', '剪贴板监控', '屏幕截图', '凭证窃取', '数据回传'],
        },
        'RedLine': {
            'strings': [
                'redline', 'stealer', 'wallet', 'browser', 'cookie', 'password',
                'autofill', 'credit', 'card', 'telegram', 'discord', 'smtp',
            ],
            'apis': ['CryptUnprotectData', 'NtReadVirtualMemory', 'OpenProcess'],
            'network': ['telegram', 'discord', 'smtp', 'ftp'],
            'description': 'RedLine Stealer 信息窃取木马，专门窃取浏览器数据和加密钱包',
            'behaviors': ['浏览器数据窃取', '加密钱包窃取', '系统信息收集', '数据回传'],
        },
        'Sliver': {
            'strings': [
                'sliver', 'implant', 'c2', 'session', 'beacon', 'tunnel',
                'mTLS', 'wireguard', 'dns', 'mtls', 'http', 'https',
            ],
            'apis': ['CreateThread', 'VirtualAlloc', 'WriteProcessMemory', 'LoadLibraryA'],
            'network': ['443', '80', '53', '8080', '8888'],
            'description': 'Sliver C2 框架，开源跨平台植入体框架',
            'behaviors': ['C2 通信', '隧道通信', '进程注入', '横向移动'],
        },
        'SilverFox': {
            'strings': [
                'anti.exe', 'zintall', 'Domo', 'UKzGKr', 'MZiewp',
                'UxEnhance64', 'msadox', 'adoresd', 'destopbak',
                'NPztVj', 'ztOOvp', 'ranchserv', 'nvml',
                # OpenPGP C2 载荷特征（新版 SilverFox）
                'BEGIN PGP', 'PUBLIC KEY BLOCK', 'OpenPGP', 'gpg',
                'zlib', 'inflate', 'deflate',
                # 新版行为特征
                'nvgpu_x64', 'nvgpu.exe', 'nvgpu',
                'dllhost.exe', 'Processid', 'netsvcs -p -s Schedule',
                'GetTickCount64', 'GetDiskFreeSpaceEx',
                # 进程树分析
                'Ali Licensing Agent', 'Ali Inc.', 'Ali Ali Client Dll',
                'SCHTASKS /Create /F /TN', 'SCHTASKS /Run /TN', 'SCHTASKS /Delete /TN',
                'wuauserv', 'UsoSvc', 'WaaSMedicSvc', 'icacls',
                'vssadmin delete shadows', 'NoAutoUpdate',
                'appinstall.', 'cDYYQc', 'stpsu_epac',
                '4750390253',
                # 此变种特有：AliyunWrap 侧加载链
                'AliyunWrap', 'AliyunWrap_original', 'AliyunConfig',
                'sysupdate.exe', 'edgestore.dll', 'WebView2Loader',
                'res_bg.bmp', 'res_icon.bmp', 'edge_prefs.dat',
                'DisplaySessionContainers.log',
                'cygwin', 'Bio74', 'VLZr', 'XrwD2', 'log_5BFA',
            ],
            'apis': [
                'MsiSetInternalUI', 'MsiInstallProduct', 'MsiDatabaseOpenView',
                'ShellExecuteEx', 'CreateProcess', 'CreateService',
                'RegSetValueEx', 'RegCreateKeyEx',
                'WriteProcessMemory', 'VirtualProtectEx', 'NtWriteVirtualMemory',
                'OpenProcess', 'CreateRemoteThread', 'LoadLibraryA',
                'GetTickCount64', 'GetDiskFreeSpaceExW',
            ],
            'network': ['aliyuncs.com', 'oss-', '101.67.', '61.135.', '39.156.',
                        '18.163.217.102', '47.75.103.130', '27.124.18.166',
                        '43.128.240.63', '117.168.151.126',
                        '63016', '63026'],  # SilverFox 常用高位端口
            'dropped_files': [
                'UxEnhance64.dll', 'msadox.tb', 'adoresd.dat',
                'ranchserv.jpg', 'destopbak.ini',
                'nvml.bin', 'nvgpu_x64.exe',
                '3bqWiX.exe', 'XPSPLOG.dll', 'anti.exe',
                'drops[1].jpg', 'image.png', 'thumbs.db',
                'xxxx.ini', 'ea81582.msi', 'SiPolicy.p7b',
                # 此变种特有
                'sysupdate.exe', 'AliyunWrap.dll', 'AliyunWrap_original.dll',
                'edgestore.dll', 'WebView2Loader.dll', 'AliyunConfig.ini',
                'res_bg.bmp', 'res_icon.bmp', 'edge_prefs.dat',
                'DisplaySessionContainers.log',
            ],
            'dropped_patterns': [
                r'\\cygwin\\.*\\.*\\.*\\.*\\(?:sysupdate|AliyunWrap|AliyunWrap_original|edgestore|WebView2Loader)',
                r'\\appdata\\roaming\\microsoft\\edgeupdate\\edgestore\.dll',
                r'\\public\\[a-z0-9]{4,8}\\[^\\]+\.exe$',
                r'\\public\\[a-z0-9]{4,8}\\UxEnhance64\.dll$',
                r'\\public\\[a-z0-9]{4,8}\\msadox\.tb$',
                r'\\public\\[a-z0-9]{4,8}\\adoresd\.dat$',
                r'\\appdata\\roaming\\[a-z]{4,8}\\[^\\]+\.exe$',
                r'\\appdata\\roaming\\Domo\\anti\.exe$',
                r'\\windows\\installer\\[a-f0-9]{4,6}\.msi$',
                r'\\windows\\temp\\ranchserv\.jpg$',
                r'\\program files.*\\[A-Za-z0-9]{4,8}\\XPSPLOG\.dll$',
                r'\\program files.*\\common files\\nvgpu.*\.exe$',
                r'\\Config\.Msi\\[a-f0-9]{6,8}\.rbs$',
            ],
            'dropped_dirs': ['\\cygwin\\', '\\public\\', '\\appdata\\roaming\\',
                           '\\program files (x86)\\', '\\windows\\installer\\',
                           '\\common files\\nvgpu', '\\program files\\common files\\',
                           '\\appdata\\roaming\\domo\\', '\\appdata\\roaming\\ie\\',
                           '\\program files (x86)\\', '\\config.msi\\',
                           '\\users\\public\\music\\', '\\microsoft\\edgeupdate\\'],
            'description': 'SilverFox（银狐）木马，MSI白加黑→计划任务SYSTEM提权→Defender排除→WindowsUpdate破坏→DLL侧加载→DCOM代理',
            'behaviors': ['MSI 白加黑', '计划任务一键三连 SYSTEM 提权', 'Defender 多路径排除',
                          'DLL 侧加载', '文件隐藏', '进程注入', '阿里云 OSS C2',
                          'COM Surrogate 代理', 'OpenPGP 加密 C2', 'nvgpu 载荷驻留',
                          'dllhost DCOM 执行', 'WebSocket 实时通道',
                          'Windows Update 服务破坏', 'icacls 权限操纵',
                          '卷影副本删除', 'PowerShell 更新任务禁用',
                          'AliyunWrap 侧加载链', 'cygwin 环境伪装'],
        },
        'Gh0st': {
            'strings': ['Gh0st', 'gh0st', 'rat', 'yyy', 'CCTVSOCKET', '屏幕传输'],
            'apis': ['CreateToolhelp32Snapshot', 'Process32First', 'Process32Next',
                     'Thread32First', 'Module32First', 'InternetOpen', 'InternetConnect'],
            'network': ['3322.org', 'no-ip', 'ddns'],
            'description': 'Gh0st（幽灵）远控木马，中国市场最活跃RAT之一',
            'behaviors': ['远程桌面', '键盘记录', '文件管理', '进程管理', '屏幕监控'],
        },
        'Dyreza': {
            'strings': [
                # 核心标识
                'comain_ev2', 'ev2f79', 'ev2c34', 'mfcsubs',
                'DcryptDll', 'ntrin.er', 'cmrsk.ce', 'fhkan.oi',
                'bteuns.pt', 'yinma.vc', 'dxyvnb.ti', 'otrm.oi',
                # 安装器伪装
                'huorong_win_setup', 'huorong_win',
            ],
            'apis': [
                'SetFileAttributesW', 'WriteProcessMemory', 'VirtualAllocEx',
                'CreateRemoteThread', 'OpenProcess', 'Add-MpPreference',
            ],
            'network': [],
            'dropped_files': [
                'mfcsubs.dll', 'DcryptDll.dll', 'cache.dat',
            ],
            'dropped_patterns': [
                r'\\comain_ev2[a-z0-9]{2,4}\\ev2[a-z0-9]{2,4}\.exe$',
                r'\\AppData\\Roaming\\comain_ev2',
                r'\\Temp\\ns[a-zA-Z0-9]{4,6}\.tmp',
                r'\\Temp\\nsb[A-Z0-9]{4}\.tmp\\[a-f0-9]{8}\\',
                r'\\.(?:ce|oi|er|vc|pt|ti)$',  # 加密载荷扩展名
            ],
            'dropped_dirs': [
                '\\appdata\\roaming\\comain_ev2',
                '\\temp\\ns',
            ],
            'description': 'Dyreza/Dyre 银行木马，伪装火绒安装器，NSIS自解压，Defender全盘排除，进程注入+100+DLL侧加载',
            'behaviors': ['NSIS 自解压', '反竞争AV检测', '全盘Defender排除',
                          '进程注入 (VSSVC/sihost)', '大量DLL侧加载代理',
                          '加密Shellcode载荷', '伪装安全软件'],
        },
        'Farfli': {
            'strings': ['Farfli', 'Plugins', 'ServiceMain', 'PluginRun', '.dat'],
            'apis': ['InternetOpen', 'HttpOpenRequest', 'URLDownloadToFile',
                     'WinExec', 'CreateService', 'StartService'],
            'network': ['tcp://', 'http://', '.jpg', '.png', '.gif'],
            'description': 'Farfli 远控木马，以插件化架构和流量伪装著称',
            'behaviors': ['插件化加载', '流量伪装', 'C2 通信', '持久化服务'],
        },
        # ===== 新增家族 =====
        'LokiBot': {
            'strings': ['lokibot', 'loki', 'bot', 'lokibot'],
            'apis': ['GetClipboardData', 'GetAsyncKeyState', 'URLDownloadToFile',
                    'CryptUnprotectData', 'socket', 'connect'],
            'network': ['smtp', 'ftp', 'panel', 'gate'],
            'description': 'LokiBot 信息窃取木马，以窃取浏览器/FTP/邮件凭据著称',
            'behaviors': ['键盘记录', '剪贴板监控', '凭据窃取', 'SMTP/FTP 回传'],
        },
        'Remcos': {
            'strings': ['Remcos', 'remcos', 'RAT', 'remcos_rat'],
            'apis': ['InternetOpen', 'InternetConnect', 'CreateProcess',
                    'RegSetValueEx', 'OpenProcess', 'WriteProcessMemory'],
            'network': ['443', '80', '8080', 'no-ip', 'ddns'],
            'description': 'Remcos RAT 远控木马，功能完整（键盘记录/摄像头/屏幕截图/文件管理）',
            'behaviors': ['键盘记录', '屏幕截图', '摄像头控制', '文件管理', '持久化'],
        },
        'NanoCore': {
            'strings': ['nanocore', 'NanoCore', 'nanocore_client', 'PluginHost',
                       'ClientPlugin', 'nanocore rat'],
            'apis': ['Socket', 'TcpClient', 'NetworkStream', 'ThreadStart',
                    'RegistryKey', 'ProcessStart'],
            'network': ['443', '80', 'no-ip', 'ddns'],
            'description': 'NanoCore RAT，.NET远控，插件化架构，广泛用于APT攻击',
            'behaviors': ['远程桌面', '键盘记录', '文件管理', '进程管理', '插件加载'],
        },
        'AsyncRAT': {
            'strings': ['AsyncRAT', 'asyncrat', 'asyncclient', 'async_client',
                       'Pastebin', 'Stub', 'asyncrat_stub'],
            'apis': ['Socket', 'TcpClient', 'NetworkStream', 'SendAsync',
                    'ReceiveAsync', 'Threading'],
            'network': ['pastebin', '443', '8888', 'no-ip'],
            'description': 'AsyncRAT 开源.NET远控，常被修改后用于恶意攻击',
            'behaviors': ['远程桌面', '键盘记录', '文件窃取', 'Pastebin C2'],
        },
        'XWorm': {
            'strings': ['xworm', 'XWorm', 'xworm_rat', 'xworm_client', 'xworm_stub',
                       'xworm', 'xworm_'],
            'apis': ['Socket', 'TcpClient', 'Send', 'Receive', 'RegistryKey',
                    'ProcessStart', 'FileStream'],
            'network': ['7000', '8888', 'no-ip', 'ddns'],
            'description': 'XWorm RAT，多功能.NET远控，窃密+挖矿+勒索组合',
            'behaviors': ['键盘记录', 'USB传播', '挖矿', '勒索模块', '剪贴板替换'],
        },
        'FormBook': {
            'strings': ['formbook', 'FormBook', 'formgrabber', 'form_grabber',
                       'keylogger_class', 'formbook_stub'],
            'apis': ['GetAsyncKeyState', 'SetWindowsHookEx', 'InternetReadFile',
                    'HttpSendRequest', 'GetClipboardData', 'URLDownloadToFile'],
            'network': ['443', '80', '.php', 'gate'],
            'description': 'FormBook 信息窃取+键盘记录木马，以表单抓取著称',
            'behaviors': ['键盘记录', '表单抓取', '剪贴板窃取', '进程注入'],
        },
        'PlugX': {
            'strings': ['plugx', 'PlugX', 'AvastSvcPYT', 'AvastAuth.dat', 'CEFHelper',
                       'USB_NOTIFY_INF', 'USB_NOTIFY_COP', 'ms-pu'],
            'apis': ['GetLogicalDriveStrings', 'CreateMutexW', 'CopyFileW',
                    'InternetCheckConnectionW', 'LoadLibraryW'],
            'network': ['45.142.166', 'www.microsoft.com'],
            'description': 'PlugX RAT，白加黑加载/USB蠕虫传播/文档窃取',
            'behaviors': ['白加黑', 'USB传播', '文档窃取', '反竞争杀Adobe', '回收站藏匿'],
        },
        'Vidar': {
            'strings': ['vidar', 'Vidar', 'vidar_stealer', 'vidar_stub',
                       'BrowserCredential', 'FileZilla', 'WinSCP', 'Pidgin'],
            'apis': ['CryptUnprotectData', 'InternetReadFile', 'HttpSendRequest',
                    'GetAsyncKeyState'],
            'network': ['api.telegram', 'steam', 'discord'],
            'description': 'Vidar 信息窃取木马，专注浏览器/钱包/2FA软件数据窃取',
            'behaviors': ['浏览器凭据', '加密钱包', '2FA数据', 'Telegram 回传'],
        },
        'Amadey': {
            'strings': ['amadey', 'Amadey', 'amadey_bot', 'amadey_loader',
                       'amadey_panel', 'amadey_stub'],
            'apis': ['InternetOpen', 'URLDownloadToFile', 'WinExec',
                    'CreateProcess', 'RegSetValueEx'],
            'network': ['/joomla/', '/wp-admin/', '/cpanel/', 'gate'],
            'description': 'Amadey 恶意软件分发机器人，常作为其他木马的加载器',
            'behaviors': ['载荷下载', '信息收集', '截屏', '后续木马投递'],
        },
        'SnakeKeylogger': {
            'strings': ['SnakeKeylogger', 'snake', 'keylogger', 'snake_keylogger',
                       'KeyloggerClass', 'KeyboardHook'],
            'apis': ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetForegroundWindow',
                    'GetWindowText', 'send', 'connect'],
            'network': ['smtp', 'ftp', 'telegram', 'email'],
            'description': 'Snake Keylogger .NET键盘记录器，SMTP/FTP/Telegram回传',
            'behaviors': ['键盘记录', '剪贴板监控', '截屏', '凭据窃取'],
        },
        'GuLoader': {
            'strings': ['guloader', 'GuLoader', 'CloudEyE', 'cloudeye',
                       'guloader_stub', 'CloudEyE_Protector'],
            'apis': ['VirtualAlloc', 'VirtualProtect', 'CreateProcess',
                    'ResumeThread', 'NtUnmapViewOfSection'],
            'network': ['cloud', 'download', 'update', 'check'],
            'description': 'GuLoader 高级恶意软件加载器，使用反VM/反沙箱技术分发载荷',
            'behaviors': ['反VM', '反沙箱', '进程镂空', '载荷解密', '内存执行'],
        },
    }
    
    def analyze(self, strings: StringAnalysis, pe_info: Optional[PEInfo] = None) -> MalwareFamilyAnalysis:
        """分析恶意软件家族"""
        logger.info("[*] 木马家族分析...")
        
        all_text = ' '.join(
            strings.suspicious_strings + strings.api_calls + 
            strings.urls + strings.domains + strings.file_paths
        ).lower()
        
        all_apis = []
        if pe_info and pe_info.imports:
            for imp in pe_info.imports:
                all_apis.extend(imp.functions)
        all_apis = [a.lower() for a in all_apis]
        
        # 高误报通用词（禁止单独触发家族匹配）
        ALLOWLIST_WORDS = {
            'token', 'privilege', 'process', 'crypto', 'vault', 'dpapi',
            'sid', 'sam', 'lsa', 'password', 'cookie', 'wallet', 'browser',
            'autofill', 'credit', 'card', 'telegram', 'discord', 'smtp',
            'ftp', 'clipboard', 'keystroke', 'screenshot', 'credentials',
            'encrypt', 'decrypt', 'readme', 'unlock', 'recover', 'restore',
            'payment', 'tor', 'aes', 'rsa', 'chacha', 'salsa', 'cloud',
            'onedrive', 'twitter', 'github', 'pastebin', 'http', 'https',
            'game', 'drop', 'backdoor', 'bat', 'c2', 'session', 'tunnel',
            'mtls', 'wireguard', 'dns', 'implant',
            # 赎金/付费软件误报修复
            'restore', 'unlock', 'recover',
            # CobaltStrike 泛词修复: 这些词在网络样本中极其常见
            'smb', 'pipe', 'post', 'upload', 'beacon',
        }

        results = []
        for family_name, sig in self.FAMILY_SIGNATURES.items():
            confidence = 0
            generic_bonus = 0
            indicators = []
            matched_rules = []

            for s in sig['strings']:
                try:
                    matched = bool(re.search(s, all_text, re.IGNORECASE))
                except re.error:
                    matched = s.lower() in all_text
                if matched:
                    if s.lower() in ALLOWLIST_WORDS:
                        generic_bonus += 3  # 通用词降权
                    else:
                        confidence += 10   # 特异性词全权重
                    indicators.append(f"字符串: {s}")
                    matched_rules.append(f"string:{s}")

            # 通用词加分：必须 ≥1 个特异性字符串命中才有效
            if confidence > 0:
                confidence += generic_bonus

            for api in sig['apis']:
                if api.lower() in all_apis:
                    confidence += 8
                    indicators.append(f"API: {api}")
                    matched_rules.append(f"api:{api}")

            for net in sig['network']:
                # 端口号需匹配网络上下文避免误报: 只有 URL/字符串中确实出现 ":<port>"、
                # "/<port>" 或 "=<port>" 才计入, 避免 '443' 这类数字撞上时间戳/版本号。
                if net.isdigit():
                    port_match = False
                    port_pat = re.compile(
                        rf'(?<![\d])(?:[:/=]|\bport\s*[:=]?){re.escape(net)}\b')
                    for url in strings.urls:
                        if port_pat.search(url):
                            port_match = True
                            break
                    if not port_match and port_pat.search(all_text):
                        port_match = True
                else:
                    port_match = net in all_text or any(net in url for url in strings.urls)
                if port_match:
                    confidence += 5
                    indicators.append(f"网络: {net}")
                    matched_rules.append(f"network:{net}")

            if confidence > 0:
                results.append(MalwareFamilyIndicator(
                    family_name=family_name,
                    confidence=min(confidence, 100),
                    indicators=indicators[:10],
                    matched_rules=matched_rules[:10],
                    description=sig['description'],
                    typical_behaviors=sig['behaviors'],
                    iocs=list(set(strings.urls + strings.ips))[:10]
                ))
        
        results.sort(key=lambda x: (x.confidence, self._strong_rule_count(x),
                                    len(x.indicators or [])), reverse=True)

        result = MalwareFamilyAnalysis(
            primary_family='Unknown',
            primary_confidence=0.0,
            all_families=results[:5],
            matched_signatures=len(results),
            total_rules=len(self.FAMILY_SIGNATURES),
            summary=''
        )
        return self._reselect_primary(result)

    @staticmethod
    def _strong_rule_count(ind: MalwareFamilyIndicator) -> int:
        """统计强证据数量 — 用于排序与低置信度拦截。

        强证据: YARA/RAT配置/释放文件/动态行为/强字符串模式。
        弱证据: 仅 API 名称、端口/网络、通用字符串。
        """
        if not ind or not getattr(ind, 'matched_rules', None):
            return 0
        strong = 0
        weak_words = ('.dll', '.exe', 'token', 'privilege', 'process', 'crypto',
                      'vault', 'dpapi', 'sid', 'sam', 'lsa', 'password', 'cookie',
                      'wallet', 'browser', 'telegram', 'discord', 'smtp', 'ftp',
                      'http', 'https', 'beacon', 'session', 'tunnel', 'implant',
                      'dns', 'mtls', 'wireguard', 'c2', 'game', 'drop', 'backdoor',
                      'bat', 'cloud', 'onedrive', 'twitter', 'github', 'pastebin',
                      'encrypt', 'decrypt', 'readme', 'unlock', 'recover', 'restore',
                      'payment', 'tor', 'aes', 'rsa', 'chacha', 'salsa', 'autofill',
                      'credit', 'card', 'credentials', 'keystroke', 'clipboard',
                      'screenshot', 'stealer', 'rat', 'bot', 'ssl')
        for rule in ind.matched_rules:
            rl = str(rule).lower()
            if rl.startswith(('yara:', 'rat配置:', '释放文件:', '模式匹配:', '行为匹配:',
                              '威胁情报:')):
                strong += 1
                continue
            if rl.startswith('string:') and not any(w in rl for w in weak_words):
                strong += 1
        return strong

    @staticmethod
    def _reselect_primary(existing: MalwareFamilyAnalysis) -> MalwareFamilyAnalysis:
        """所有精炼阶段统一重选主家族并同步 summary, 修复
        primary_family 与 summary 不一致的历史问题。

        平局时优先证据数量多的家族 (更具体的匹配更可信)。
        仅弱证据凑出的低置信度匹配不再直接作为主家族结论 (避免误报具体家族)。
        """
        if not existing or not existing.all_families:
            return existing
        existing.all_families.sort(
            key=lambda x: (x.confidence, FamilyAnalyzer._strong_rule_count(x),
                           len(x.indicators or [])),
            reverse=True
        )
        top = existing.all_families[0]
        strong = FamilyAnalyzer._strong_rule_count(top)
        # 置信度 <30 一律不报具体家族: 单条短字符串 (如 QakBot 的 "au"、
        # Lazarus 的 "apple") 也可能计为强证据, 但 10% 的结论不可信。
        if top.confidence < 30:
            existing.primary_family = 'Unknown'
            existing.primary_confidence = top.confidence
            existing.summary = (
                f"检测到 {len(existing.all_families)} 个低置信度家族线索"
                f"(最高 {top.family_name} {top.confidence:.0f}%), 不足以判定具体家族"
            )
            return existing
        existing.primary_family = top.family_name
        existing.primary_confidence = top.confidence
        existing.matched_signatures = len(existing.all_families)
        existing.summary = (
            f"检测到 {existing.matched_signatures} 个家族匹配，"
            f"最可能: {existing.primary_family} "
            f"(置信度 {existing.primary_confidence:.0f}%)"
        )
        return existing

    def refine_with_dropped(self, existing: MalwareFamilyAnalysis,
                            dropped) -> MalwareFamilyAnalysis:
        """用释放文件信息二次精炼家族识别"""
        if not dropped or not dropped.dropped_files:
            return existing

        dropped_names = [d.path.lower() for d in dropped.dropped_files]
        dropped_full = ' '.join(dropped_names)

        for family_name, sig in self.FAMILY_SIGNATURES.items():
            exact_files = sig.get('dropped_files', [])
            regex_patterns = sig.get('dropped_patterns', [])
            dir_patterns = sig.get('dropped_dirs', [])
            if not exact_files and not regex_patterns and not dir_patterns:
                continue
            bonus = 0
            reasons = []
            for pat in exact_files:
                if pat.lower() in dropped_full:
                    bonus += 30
                    reasons.append(f"释放文件: {pat}")
            for pat in regex_patterns:
                for d in dropped_names:
                    if re.search(pat, d, re.IGNORECASE):
                        bonus += 25
                        reasons.append(f"模式匹配: {os.path.basename(d)}")
                        break
            for pat in dir_patterns:
                if any(pat.lower() in d for d in dropped_names):
                    bonus += 20
                    reasons.append(f"释放目录: {pat}")
            if bonus > 0:
                found = False
                for ind in existing.all_families:
                    if ind.family_name == family_name:
                        ind.confidence = min(ind.confidence + bonus, 100)
                        ind.indicators.extend(reasons[:5])
                        found = True
                        break
                if not found:
                    existing.all_families.append(MalwareFamilyIndicator(
                        family_name=family_name, confidence=min(bonus, 100),
                        indicators=reasons[:10], matched_rules=reasons[:10],
                        description=sig.get('description', ''),
                        typical_behaviors=sig.get('behaviors', []),
                    ))

        return self._reselect_primary(existing)

    def refine_with_behavior(self, existing: MalwareFamilyAnalysis,
                             dynamic_behavior=None, api_monitor=None) -> MalwareFamilyAnalysis:
        """用动态行为检测结果精炼家族识别"""
        behavior_text = ''

        if api_monitor and api_monitor.call_records:
            apis = []
            for rec in api_monitor.call_records[:2000]:
                apis.append(rec.api_name if hasattr(rec, 'api_name') else '')
                for arg in (rec.arguments or [])[:3]:
                    apis.append(str(arg)[:200])
            behavior_text = ' '.join(apis).lower()

        if dynamic_behavior:
            for p in (dynamic_behavior.processes_created or [])[:20]:
                cmd = (p.get('cmdline', '') or '') if isinstance(p, dict) else str(p)
                behavior_text += ' ' + cmd.lower()[:300]
            for f in (dynamic_behavior.files_created or [])[:50]:
                fpath = f.get('path', '') if isinstance(f, dict) else str(f)
                behavior_text += ' ' + fpath.lower()[:200]

        if not behavior_text:
            return existing

        BEHAVIOR_FAMILY_MAP = {
            'SilverFox': [
                (r'schtasks.*create.*schtasks.*run|schtasks.*delete', 30),
                (r'Add-MpPreference|DisableAntiSpyware|DisableRealtimeMonitoring|defender.*exclusion', 25),
                (r'vssadmin\s+delete|shadow.*delete', 20),
                (r'BEGIN PGP|OpenPGP|gpg', 30),
                (r'zlib|inflate|deflate|nvgpu', 20),
                (r'MsiInstallProduct|msiexec|DllRegisterServer', 15),
                (r'dllhost.*surrogate|DCOM', 15),
                (r'GetTickCount64|GetDiskFreeSpaceEx', 10),
                (r'AliyunWrap|AliyunConfig|sysupdate\.exe|edgestore\.dll', 25),
                # 释放物强特征: 出现这些文件名/路径基本可确认银狐
                (r'UxEnhance64\.dll|msadox\.tb|ranchserv|nvgpu_x64|adoresd\.dat', 30),
                (r'\\public\\[a-z0-9]{4,8}\\|\\appdata\\roaming\\[a-z]{4,8}\\', 20),
            ],
            'RedLine': [
                (r'chrome.*password|firefox.*password|browser.*cookie', 25),
                (r'wallet\.dat|bitcoin|ethereum|metamask|exodus', 25),
                (r'CryptUnprotectData.*DPAPI', 20),
                (r'telegram.*bot.*\d{8,10}:|discord.*webhook.*\d{17,20}', 20),
                (r'stealer', 10),
            ],
            'Meterpreter': [
                (r'ReflectiveLoader|metsrv|meterpreter|stdapi', 30),
                (r'NtUnmapViewOfSection.*NtMapViewOfSection|process.*hollow', 25),
                (r'migrate', 15),
                (r'reverse_tcp|bind_tcp|reverse_http', 20),
            ],
            'CobaltStrike': [
                (r'beacon_x64|beacon_x86|smb_beacon|postex_|msagent_', 25),
                (r'\\\\\\.\\\\pipe\\\\MSSE|\\\\\\.\\\\pipe\\\\postex_|\\\\\\.\\\\pipe\\\\msagent', 25),
            ],
            'EnvScoreLoader': [
                # ⚠ 评分制环境检测标记 (完整 + 截断混淆变种) — 家族专属命名约定
                (r'SLEEP_HOOKED|VM_EXIT_OVERHEAD|LOW_RDTSC_JITTER|SHORT_UPTIME', 35),
                (r'NO_RECENT_INPUT|EMPTY_CLIPBOARD|NO_USB_HISTORY|NO_JUMP_LISTS', 35),
                (r'ROUND_DISK_SIZE|VM_VENDOR_ID|FEW_INSTALLED_PROGRAMS|FEW_FONTS', 30),
                (r'SIMPLE_REGISTRY|FEW_SYSTEM_FILES|FEW_PREFETCH_FILES|FEW_SYSTEM_EVENTS', 30),
                (r'NO_UPDATE_HISTORY|FEW_COM_CLASSES|SMALL_WMI_REPO|CLUSTERED_PREFETCH_TIMESTAMPS', 30),
                (r'TINY_RECYCLE_FILES|SMART_CAPABLE|NO_SMART_SUPPORT|DEBUGGER_PRESENT', 25),
                (r'NTGLOBALFLAG_SET|EDR_DETECTED|DEFINITE_SANDBOX|POSSIBLE_SANDBOX', 25),
                # 截断混淆变种 (1.exe 家族 — 标记截断到 8-10 字符)
                (r'FEW_ETW_|NO_NETWOH|HOOKING_L|VMWARE_MH|HR_DETECTH|VM_VENDOH', 35),
                (r'HOOKED\s|VM_VENDOR', 20),
            ],
            'Dyreza': [
                (r'comain_ev2|mfcsubs|DcryptDll', 25),
                (r'Add-MpPreference.*-ExclusionPath|全盘排除', 25),
                (r'huorong.*uninstall|360.*uninstall|杀软.*卸载', 15),
            ],
            'AgentTesla': [
                (r'GetClipboardData|clipboard', 20),
                (r'smtp\.send|ftp.*upload|telegram.*token', 20),
                (r'screenshot|screen.*capture', 15),
            ],
            'Ransomware': [
                (r'vssadmin\s+delete\s+shadows|卷影副本', 25),
                (r'加密.*文件|encrypt.*all|ransom', 20),
                (r'bitcoin.*payment|\.onion.*payment|赎金', 20),
            ],
        }

        for family_name, rules in BEHAVIOR_FAMILY_MAP.items():
            bonus = 0
            reasons = []
            for pattern, score in rules:
                try:
                    if re.search(pattern, behavior_text, re.IGNORECASE | re.DOTALL):
                        bonus += score
                        reasons.append(f"行为匹配: {pattern[:50]}")
                except re.error:
                    pass

            if bonus > 0:
                found = False
                for ind in existing.all_families:
                    if ind.family_name == family_name:
                        ind.confidence = min(ind.confidence + bonus, 100)
                        ind.indicators.extend(reasons[:5])
                        found = True
                        break
                if not found:
                    existing.all_families.append(MalwareFamilyIndicator(
                        family_name=family_name,
                        confidence=min(bonus, 100),
                        indicators=reasons[:10],
                        matched_rules=reasons[:10],
                        description='动态行为匹配',
                        typical_behaviors=reasons[:5],
                    ))

        return self._reselect_primary(existing)

    def refine_with_rat(self, existing: MalwareFamilyAnalysis,
                        rat_configs: list = None) -> MalwareFamilyAnalysis:
        """用 RAT/Stealer 配置提取结果精炼家族识别（云沙箱对照补强）

        样本提取到 RedLine C2 配置但家族判为 CobaltStrike 的根因:
        家族判定只用了字符串/YARA, 未融合配置提取结果。
        """
        if not rat_configs:
            return existing

        RAT_FAMILY_MAP = {
            'redline': 'RedLine',
            'agenttesla': 'AgentTesla',
            'formbook': 'FormBook',
            'remcos': 'Remcos',
            'asyncrat': 'AsyncRAT',
            'xworm': 'XWorm',
            'nanocore': 'NanoCore',
            'lokibot': 'LokiBot',
            'vidar': 'Vidar',
            'stealer': 'RedLine',   # 通用 Stealer → RedLine 家族
            'quasarrat': 'AsyncRAT',
            'njrat': 'Gh0st',
            'gh0st': 'Gh0st',
        }

        for cfg in rat_configs:
            fam_hint = ''
            if isinstance(cfg, dict):
                fam_hint = str(cfg.get('family', ''))
                desc = str(cfg.get('description', ''))
                fam_hint = fam_hint or desc
            else:
                fam_hint = str(cfg)
            hl = fam_hint.lower()

            target = None
            for key, fam in RAT_FAMILY_MAP.items():
                if key in hl:
                    target = fam
                    break
            if not target:
                continue

            found = False
            for ind in existing.all_families:
                if ind.family_name == target:
                    ind.confidence = min(ind.confidence + 30, 100)
                    ind.matched_rules.append(f"RAT配置: {fam_hint[:60]}")
                    found = True
                    break
            if not found:
                existing.all_families.append(MalwareFamilyIndicator(
                    family_name=target,
                    confidence=min(30, 100),
                    matched_rules=[f"RAT配置: {fam_hint[:60]}"],
                    indicators=[f"配置提取: {fam_hint[:60]}"],
                ))
            logger.info(f"[Family] RAT配置精炼: {fam_hint} → {target}")

        return self._reselect_primary(existing)

    def refine_with_threat_intel(self, existing: MalwareFamilyAnalysis,
                                 threat_intel=None) -> MalwareFamilyAnalysis:
        """用多引擎威胁情报家族结论精炼本地识别 (外部证据优先级高)。

        仅当情报引擎给出明确家族名 (非 Unknown/Clean) 时提升对应家族置信度;
        若本地完全未知, 则直接以情报家族建立候选。
        """
        if not threat_intel:
            return existing
        fam_hint = str(getattr(threat_intel, 'family', '') or '').strip()
        if not fam_hint or fam_hint.lower() in ('unknown', 'none', 'clean', 'n/a', ''):
            return existing

        # 常见引擎命名别名 → 本地家族
        alias_map = {
            'silverfox': 'SilverFox', 'silver_fox': 'SilverFox', 'silver fox': 'SilverFox',
            'envscoreloader': 'EnvScoreLoader', 'env_score_loader': 'EnvScoreLoader',
            'agenttesla': 'AgentTesla', 'agent_tesla': 'AgentTesla', 'agent tesla': 'AgentTesla',
            'redline': 'RedLine', 'redline stealer': 'RedLine',
            'stealer': 'RedLine',
            'formbook': 'FormBook', 'form_book': 'FormBook',
            'remcos': 'Remcos', 'asyncrat': 'AsyncRAT', 'async rat': 'AsyncRAT',
            'xworm': 'XWorm', 'nanocore': 'NanoCore', 'lokibot': 'LokiBot',
            'vidar': 'Vidar', 'cobaltstrike': 'CobaltStrike', 'cobalt strike': 'CobaltStrike',
            'cobalt': 'CobaltStrike', 'meterpreter': 'Meterpreter',
            'metasploit': 'Meterpreter', 'emotet': 'Emotet', 'trickbot': 'TrickBot',
            'qakbot': 'QakBot', 'mimikatz': 'Mimikatz', 'gh0st': 'Gh0st',
            'ghost rat': 'Gh0st', 'plugx': 'PlugX', 'dridex': 'Dridex',
            'lazarus': 'Lazarus', 'dyreza': 'Dyreza', 'dyre': 'Dyreza',
            'ransomware': 'Ransomware', 'lockbit': 'Ransomware',
        }
        hl = fam_hint.lower()
        target = None
        for key, fam in alias_map.items():
            if key in hl:
                target = fam
                break
        if not target:
            # 本地有同名家族则直接命中
            for ind in existing.all_families:
                if ind.family_name.lower() in hl or hl in ind.family_name.lower():
                    target = ind.family_name
                    break
        if not target:
            return existing

        found = False
        for ind in existing.all_families:
            if ind.family_name == target:
                ind.confidence = min(ind.confidence + 35, 100)
                ind.matched_rules.append(f"威胁情报: {fam_hint[:80]}")
                ind.indicators.append(f"威胁情报家族: {fam_hint[:80]}")
                found = True
                break
        if not found:
            sig = self.FAMILY_SIGNATURES.get(target, {})
            existing.all_families.append(MalwareFamilyIndicator(
                family_name=target,
                confidence=min(35, 100),
                matched_rules=[f"威胁情报: {fam_hint[:80]}"],
                indicators=[f"威胁情报家族: {fam_hint[:80]}"],
                description=sig.get('description', '外部威胁情报命中'),
                typical_behaviors=sig.get('behaviors', []),
            ))
        logger.info(f"[Family] 威胁情报精炼: {fam_hint} → {target}")
        return self._reselect_primary(existing)

    def refine_with_yara(self, existing: MalwareFamilyAnalysis,
                         yara_matches: list = None) -> MalwareFamilyAnalysis:
        """用YARA匹配结果精炼家族识别"""
        if not yara_matches:
            return existing

        YARA_FAMILY_MAP = {
            'SilverFox': 30, 'silverfox': 30, 'silver_fox': 30, 'APT_SilverFox': 30,
            'AgentTesla': 25, 'agenttesla': 25, 'MALW_AgentTesla': 25,
            'RedLine': 25, 'redline': 25, 'MALW_RedLine': 25,
            # Stealer 类 (Trojan_Stealer_Xor13 等通用窃密规则 → RedLine 家族承载)
            'trojan_stealer': 22, 'stealer': 15,
            'FormBook': 25, 'formbook': 25, 'MALW_FormBook': 25,
            'LokiBot': 25, 'lokibot': 25, 'MALW_LokiBot': 25,
            'Remcos': 25, 'remcos': 25, 'MALW_Remcos': 25,
            'AsyncRAT': 25, 'asyncrat': 25, 'MALW_AsyncRAT': 25,
            'Vidar': 25, 'vidar': 25, 'MALW_Vidar': 25,
            'XWorm': 25, 'xworm': 25, 'MALW_XWorm': 25,
            'NanoCore': 25, 'nanocore': 25, 'MALW_NanoCore': 25,
            'CobaltStrike': 25, 'cobaltstrike': 25, 'MALW_CobaltStrike': 25,
            'Lazarus': 25, 'lazarus': 25, 'APT_Lazarus': 25,
            'LockBit': 25, 'lockbit': 25, 'RANSOM_LockBit': 25,
            'Conti': 25, 'conti': 25, 'RANSOM_Conti': 25,
            'Meterpreter': 20, 'meterpreter': 20, 'metasploit': 20,
            'SpyEye': 20, 'spyeye': 20, 'spyeye_plugins': 20,
            'Ransomware': 15, 'ransomware': 15, 'ransom': 15,
        }

        for match in yara_matches:
            rule_name = ''
            if isinstance(match, str):
                rule_name = match.lower()
            elif isinstance(match, dict):
                rule_name = (match.get('rule', '') or match.get('name', '')).lower()

            # Stealer 类规则别名 → 具体家族(RedLine 为 Stealer 代表)
            YARA_ALIAS = {
                'trojan_stealer': 'RedLine',
                'stealer': 'RedLine',
            }
            resolved_key = None
            for key, score in YARA_FAMILY_MAP.items():
                if key.lower() in rule_name:
                    resolved_key = key
                    break
            if resolved_key is None:
                continue
            target_fam = YARA_ALIAS.get(resolved_key, resolved_key)
            for fam_name in self.FAMILY_SIGNATURES:
                if fam_name.lower() == target_fam.lower() or \
                   target_fam.lower() in fam_name.lower() or \
                   fam_name.lower() in target_fam.lower():
                    found = False
                    for ind in existing.all_families:
                        if ind.family_name == fam_name:
                            ind.confidence = min(ind.confidence + YARA_FAMILY_MAP[resolved_key], 100)
                            ind.matched_rules.append(f"YARA: {rule_name}")
                            found = True
                            break
                    if not found:
                        existing.all_families.append(MalwareFamilyIndicator(
                            family_name=fam_name,
                            confidence=min(YARA_FAMILY_MAP[resolved_key], 100),
                            matched_rules=[f"YARA: {rule_name}"],
                            indicators=[f"YARA匹配: {rule_name}"],
                        ))
                    break

        return self._reselect_primary(existing)
