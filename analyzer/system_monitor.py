#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
系统状态监控 — 注册表前后对比 + 系统配置变更检测
不依赖Frida，纯系统级快照对比。
覆盖：Defender禁用、防火墙、服务、计划任务、WMI、用户账号、安全策略、日志清除、卷影删除、凭证窃取（LSASS访问检测）
"""
import os
import subprocess
import re
import winreg
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from logger import get_logger

logger = get_logger('analyzer.system_monitor')

# ===== 监控的注册表键 =====
MONITOR_REGISTRY_KEYS = {
    # Windows Defender 禁用
    'Defender_Policy': [
        r'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender',
    ],
    'Defender_RealTime': [
        r'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection',
    ],
    'Defender_Signatures': [
        r'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates',
    ],
    'Defender_Spynet': [
        r'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet',
    ],
    # 防火墙
    'Firewall_Policy': [
        r'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy',
        r'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile',
        r'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile',
        r'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile',
    ],
    'Firewall_Rules': [
        r'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall',
    ],
    # 持久化 — Run 键
    'Persistence_Run': [
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    ],
    # 持久化 — Winlogon
    'Persistence_Winlogon': [
        r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    ],
    # 持久化 — Shell Folders / Startup
    'Persistence_Startup': [
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
    ],
    # 持久化 — AppCertDlls / AppInit
    'Persistence_DLL': [
        r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs',
        r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls',
    ],
    # 持久化 — WinSock LSP
    'Persistence_LSP': [
        r'HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9',
    ],
    # 持久化 — 计划任务缓存
    'ScheduledTasks': [
        r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree',
    ],
    # WMI 持久化
    'WMI_Persistence': [
        r'HKLM\SOFTWARE\Microsoft\WBEM\CIMOM',
    ],
    # 安全策略 / UAC / 系统配置
    'Security_Policy': [
        r'HKLM\SOFTWARE\Policies\Microsoft',
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies',
    ],
    # 安全软件 — 禁用其他杀软
    'Security_Software': [
        r'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Disabled',
    ],
    # 服务
    'Services': [
        r'HKLM\SYSTEM\CurrentControlSet\Services',
    ],
    # 网络配置 — DNS / 代理
    'Network_Config': [
        r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings',
    ],
    # 浏览器劫持
    'Browser_Hijack': [
        r'HKCU\Software\Microsoft\Internet Explorer\Main',
        r'HKLM\SOFTWARE\Microsoft\Internet Explorer\Main',
    ],
    # 映像劫持 (IFEO)
    'ImageHijack': [
        r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    ],
    # SafeBoot 覆盖（勒索常用）
    'SafeBoot': [
        r'HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot',
    ],
    # 远程桌面 / 后门
    'RDP_Backdoor': [
        r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server',
        r'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    ],
    # 凭据管理器
    'CredentialManager': [
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore',
    ],
    # 启动项 — BootExecute (勒索常用)
    'BootExecute': [
        r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager',
    ],
    # 浏览器助手对象 (BHO) — 浏览器劫持/持久化
    'Browser_BHO': [
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects',
    ],
    # HKLM Policies Run (组策略级启动项)
    'Policies_Run': [
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    ],
    # 计划任务动作 (TaskCache\Tasks 含任务命令)
    'ScheduledTasks_Actions': [
        r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks',
    ],
    # ETW/内核事件日志禁用 (对抗检测)
    'ETW_Disable': [
        r'HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger',
        r'HKLM\SYSTEM\CurrentControlSet\Services\EventLog',
    ],
    # 系统代理 (WinHTTP — 独立于 IE 代理)
    'WinHTTP_Proxy': [
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp',
    ],
    # Code Integrity 策略 (CiPolicies — 驱动签名/CI 绕过)
    'CodeIntegrity': [
        r'HKLM\SOFTWARE\Policies\Microsoft\Windows\CodeIntegrity',
        r'HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy',
    ],
    # 卷影复制服务配置 (VSS — 勒索/备份破坏)
    'VSS_Service': [
        r'HKLM\SYSTEM\CurrentControlSet\Services\VSS',
        r'HKLM\SYSTEM\CurrentControlSet\Services\swprv',
    ],
    # COM 劫持 — CLSID 注册 (恶意 COM 组件持久化)
    'COM_Hijack': [
        r'HKCR\CLSID',
    ],
    # Shell 图标覆盖 (资源管理器加载任意 DLL — 持久化点)
    'ShellIconOverlay': [
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers',
    ],
    # Defender 实际排除项 (银狐必加! — 与 Policies 不同, 这是引擎实际生效的排除)
    'Defender_Exclusions': [
        r'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths',
        r'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions',
        r'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes',
    ],
    # Defender Tamper Protection / 功能开关
    'Defender_Features': [
        r'HKLM\SOFTWARE\Microsoft\Windows Defender\Features',
    ],
    # LSA 安全包/通知包 (SSP 注入持久化 — 远控常用) + WDigest 凭据
    'LSA_Security': [
        r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
    ],
    # KnownDLLs 系统 DLL 劫持 (白加黑/全局钩子)
    'KnownDLLs': [
        r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs',
    ],
    # 文件关联劫持 (exe/txt/lnk 打开方式被改 — 持久化经典)
    'FileAssociation': [
        r'HKCR\exefile\shell\open\command',
        r'HKCR\txtfile\shell\open\command',
        r'HKCR\lnkfile\shell\open\command',
        r'HKCU\Software\Classes\exefile\shell\open\command',
        r'HKCU\Software\Classes\txtfile\shell\open\command',
    ],
    # 用户环境变量 (UserInitMprLogonScript — 登录脚本持久化)
    'UserEnvironment': [
        r'HKCU\Environment',
    ],
    # 时间提供器 (Time Providers — 隐蔽持久化)
    'TimeProviders': [
        r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Providers',
    ],
    # 打印监控器 (Print Monitors — 隐蔽持久化)
    'PrintMonitors': [
        r'HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors',
    ],
    # 网络提供者顺序 (NetworkProvider — 隐蔽持久化)
    'NetworkProvider': [
        r'HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order',
    ],
    # ShellExecuteHooks / SharedTaskScheduler (资源管理器加载 — 持久化)
    'ShellHooks': [
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks',
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler',
    ],
    # 系统还原开关 (勒索禁用还原)
    'SystemRestore': [
        r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore',
    ],
    # 屏幕保护程序劫持 (SCRNSAVE.EXE 指向恶意程序)
    'ScreenSaver': [
        r'HKCU\Control Panel\Desktop',
    ],
}


def _query_registry_key(hive: int, subkey: str) -> Dict[str, str]:
    """递归查询注册表键，返回 {value_name: value_data}"""
    result = {}
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, value, vtype = winreg.EnumValue(key, i)
                    if vtype == winreg.REG_SZ:
                        result[name] = str(value)
                    elif vtype == winreg.REG_DWORD:
                        result[name] = f"DWORD:{value}"
                    elif vtype == winreg.REG_QWORD:
                        result[name] = f"QWORD:{value}"
                    elif vtype == winreg.REG_BINARY:
                        result[name] = f"BINARY:{len(value)}b"
                    elif vtype == winreg.REG_EXPAND_SZ:
                        result[name] = str(value)
                    elif vtype == winreg.REG_MULTI_SZ:
                        result[name] = "MULTI_SZ:" + "|".join(value)
                    else:
                        result[name] = f"TYPE({vtype})"
                    i += 1
                except OSError:
                    break
    except (FileNotFoundError, OSError, PermissionError):
        pass
    return result


def _enumerate_service_subkeys() -> Dict[str, Dict[str, str]]:
    """列举 Services 子键名及 ImagePath/Start/Type"""
    services = {}
    try:
        hive = winreg.HKEY_LOCAL_MACHINE
        with winreg.OpenKey(hive, r'SYSTEM\CurrentControlSet\Services', 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    # 只读每个服务的关键值
                    svc_data = _query_registry_key(
                        hive, rf'SYSTEM\CurrentControlSet\Services\{subkey_name}')
                    if svc_data:
                        # 只保留关键字段，减少数据量
                        filtered = {}
                        for k in ('ImagePath', 'Start', 'Type', 'DisplayName',
                                   'Description', 'ErrorControl'):
                            if k in svc_data:
                                filtered[k] = svc_data[k]
                        # 服务 DLL 注入 (svchost 宿主): Parameters\ServiceDll
                        try:
                            params = _query_registry_key(
                                hive, rf'SYSTEM\CurrentControlSet\Services\{subkey_name}\Parameters')
                            if params.get('ServiceDll'):
                                filtered[r'Parameters\ServiceDll'] = params['ServiceDll']
                        except Exception:
                            pass
                        if filtered:
                            services[subkey_name] = filtered
                    i += 1
                except OSError:
                    break
    except (FileNotFoundError, OSError, PermissionError):
        pass
    return services


def _query_subkey_defaults(hive: int, subkey: str, max_entries: int = 500) -> Dict[str, str]:
    """枚举一层子键, 读取每个子键的 default 值 — 用于 CLSID/COM 劫持检测

    返回 {子键名: default值(截断)}; 只读名字+default, 轻量可承受大键树
    """
    result = {}
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while i < max_entries:
                try:
                    sub_name = winreg.EnumKey(key, i)
                    try:
                        with winreg.OpenKey(hive, f'{subkey}\\{sub_name}', 0, winreg.KEY_READ) as sk:
                            try:
                                val, _ = winreg.QueryValueEx(sk, '')
                                result[sub_name] = str(val)[:120]
                            except OSError:
                                result[sub_name] = ''
                    except OSError:
                        result[sub_name] = ''
                    i += 1
                except OSError:
                    break
    except (FileNotFoundError, OSError, PermissionError):
        pass
    return result


def take_registry_snapshot(full_scan: bool = False) -> Dict[str, Dict[str, str]]:
    """对所有监控键做快照; full_scan=True 时改用排除式全量快照 (覆盖所有位置)"""
    if full_scan:
        return take_full_registry_snapshot()
    hive_map = {
        'HKLM': winreg.HKEY_LOCAL_MACHINE,
        'HKCU': winreg.HKEY_CURRENT_USER,
        'HKCR': winreg.HKEY_CLASSES_ROOT,
        'HKU': winreg.HKEY_USERS,
    }
    snapshot = {}
    for category, keys in MONITOR_REGISTRY_KEYS.items():
        for full_key in keys:
            parts = full_key.split('\\', 1)
            hive_str = parts[0]
            subkey = parts[1] if len(parts) > 1 else ''
            if hive_str not in hive_map:
                continue
            hive = hive_map[hive_str]
            # 大键树 (CLSID/ShellIconOverlay): 枚举子键 default 而非全量值
            if category in ('COM_Hijack', 'ShellIconOverlay'):
                data = _query_subkey_defaults(hive, subkey)
            else:
                data = _query_registry_key(hive, subkey)
            if data:
                snapshot[full_key] = data

    # 特殊处理：Services 枚举所有子键
    services = _enumerate_service_subkeys()
    if services:
        snapshot['__SERVICES_SUBKEYS__'] = services

    return snapshot


# ===== 全量注册表快照 (排除式) — 不依赖白名单键, 任何位置的变化都能捕获 =====
# 规则: 按"前缀/知名噪音区"结构化排除, 其余全部纳入快照。
# 优势: 不再需要预知恶意键名 — 未知变种在任何位置的写入都会被 diff 捕获。
_FULL_SNAPSHOT_EXCLUDE_PREFIX = (
    # COM/类型库 — 系统规模巨大的动态区 (数十万键, 无恶意价值, CLSID 已由白名单单独监控)
    r'software\classes\clsid',
    r'software\classes\interface',
    r'software\classes\typelib',
    r'software\classes\wow6432node\clsid',
    r'software\classes\wow6432node\interface',
    r'software\classes\wow6432node\typelib',
    r'software\classes\installer',
    # 系统组件/服务自主动态区 (Windows 正常运行就频繁写, 无恶意价值)
    r'software\microsoft\windows\currentversion\installer',
    r'software\microsoft\windows\currentversion\component based servicing',
    r'software\microsoft\windows\currentversion\sidebyside',
    r'software\microsoft\windows\currentversion\activesetup',
    r'software\microsoft\windows\currentversion\appmodel',
    r'software\microsoft\windows\currentversion\appx',
    r'software\microsoft\windows\currentversion\appxpackagemanager',
    r'software\microsoft\windows\currentversion\compatibility',
    r'software\microsoft\windows\currentversion\componentstore',
    r'software\microsoft\windows\currentversion\deliveryoptimization',
    r'software\microsoft\windows\currentversion\devicemetadata',
    r'software\microsoft\windows\currentversion\devicepnp',
    r'software\microsoft\windows\currentversion\driverdatabase',
    r'software\microsoft\windows\currentversion\driversearch',
    r'software\microsoft\windows\currentversion\graphics',
    r'software\microsoft\windows\currentversion\graphics drivers',
    r'software\microsoft\windows\currentversion\memorydiagnostic',
    r'software\microsoft\windows\currentversion\nettrace',
    r'software\microsoft\windows\currentversion\prefetcher',
    r'software\microsoft\windows\currentversion\privacy',
    r'software\microsoft\windows\currentversion\reliability',
    r'software\microsoft\windows\currentversion\search',
    r'software\microsoft\windows\currentversion\shareddlls',
    r'software\microsoft\windows\currentversion\telephony',
    r'software\microsoft\windows\currentversion\wmi',
    r'software\microsoft\windows\currentversion\winstore',
    r'software\microsoft\windows\currentversion\wusa',
    r'software\microsoft\windows\currentversion\edgeupdate',
    r'software\microsoft\windows\currentversion\authentication',
    r'software\microsoft\windows\currentversion\internet settings',
    r'software\microsoft\windows\currentversion\app paths',
    r'software\microsoft\windows\currentversion\cryptography',
    r'software\microsoft\windows\currentversion\media player',
    r'software\microsoft\windows\currentversion\mediaplayer',
    # 已由白名单监控的键 — 全量模式下跳过避免重复
    r'software\microsoft\windows\currentversion\policies',
    r'software\microsoft\windows\currentversion\run',
    r'software\microsoft\windows\currentversion\runonce',
    r'software\microsoft\windows\currentversion\runservices',
    r'software\microsoft\windows\currentversion\uninstall',
    r'software\microsoft\windows\currentversion\explorer',
    r'software\microsoft\windows\currentversion\internetsettings',
    r'software\microsoft\windows\currentversion\setup',
    r'software\microsoft\windows\currentversion\windows search',
    r'software\microsoft\windows\currentversion\winevt',
    r'software\microsoft\windows\currentversion\winsearch',
    r'software\microsoft\windows\currentversion\wsman',
    # Explorer 用户态动态区 (使用痕迹, 无恶意价值)
    r'software\microsoft\windows\currentversion\explorer\recentdocs',
    r'software\microsoft\windows\currentversion\explorer\userassist',
    r'software\microsoft\windows\currentversion\explorer\mountpoints',
    r'software\microsoft\windows\currentversion\explorer\recentapps',
    r'software\microsoft\windows\currentversion\explorer\streams',
    r'software\microsoft\windows\currentversion\explorer\typedpaths',
    r'software\microsoft\windows\currentversion\explorer\comdlg32',
    r'software\microsoft\windows\currentversion\explorer\wordwheelquery',
    r'software\microsoft\windows\currentversion\explorer\runchistory',
    r'software\microsoft\windows\currentversion\explorer\openwithlist',
    r'software\microsoft\windows\currentversion\explorer\openwithprogids',
    r'software\microsoft\windows\currentversion\explorer\fileexts',
    r'software\microsoft\windows\currentversion\explorer\sessioninfo',
    r'software\microsoft\windows\currentversion\explorer\sessions',
    r'software\microsoft\windows\currentversion\explorer\advise',
    r'software\microsoft\windows\currentversion\explorer\bargap',
    r'software\microsoft\windows\currentversion\explorer\thumbcache',
    r'software\microsoft\windows\currentversion\explorer\recent',
    r'software\microsoft\windows\currentversion\explorer\publish',
    r'software\microsoft\windows\currentversion\explorer\menuorder',
    r'software\microsoft\windows\currentversion\explorer\networkstreamhistory',
    r'software\microsoft\windows\currentversion\explorer\tips',
    r'software\microsoft\windows\currentversion\explorer\urlhistory',
    r'software\microsoft\windows\currentversion\explorer\windowmetrics',
    r'software\microsoft\windows\currentversion\explorer\startupapproved',
    # 系统 Control 区自主动态 (网络/时间/用户/字体/设备等)
    r'control\wmi',
    r'control\session manager\memory management',
    r'control\session manager\executive',
    r'control\session manager\power',
    r'control\session manager\quota',
    r'control\session manager\resources',
    r'control\session manager\environ',
    r'control\session manager\iolog',
    r'control\session manager\kernel',
    r'control\graphicsdrivers',
    r'control\video',
    r'control\windows',
    r'control\print\environments',
    r'control\timezone',
    r'control\networks',
    r'control\network',
    r'control\nls',
    r'control\fonts',
    r'control\fontdrivers',
    r'control\keyboard layouts',
    r'control\keyboardlayout',
    r'control\keyboard layout',
    r'control\installed updates',
    r'control\hivelist',
    r'control\wow',
    r'control\usbflags',
    r'control\usbstor',
    r'control\usbclass',
    r'control\usb',
    r'control\updates',
    r'control\trustedinstaller',
    r'control\transactions',
    r'control\time',
    r'control\systemboot',
    r'control\svc',
    r'control\storage',
    r'control\spool',
    r'control\secureboot',
    r'control\scesrv',
    r'control\profilelist',
    r'control\power',
    r'control\pnp',
    r'control\package',
    r'control\osdata',
    r'control\nsi',
    r'control\mup',
    r'control\media',
    r'control\lsa',
    r'control\internet',
    r'control\interrupt',
    r'control\keyboard',
    r'control\bcd',
    r'control\cit',
    r'control\terminal server',
    # 用户/系统自主动态
    r'software\microsoft\windows\currentversion\cloudstore',
    r'software\microsoft\windows\currentversion\dwm',
    r'software\microsoft\windows\currentversion\personalization',
    r'software\microsoft\windows\currentversion\notificationarea',
    r'software\microsoft\windows\currentversion\action center',
    r'software\microsoft\windows\currentversion\applets',
    r'software\microsoft\windows\currentversion\controls',
    r'software\microsoft\windows\currentversion\cursors',
    r'software\microsoft\windows\currentversion\fonts',
    r'software\microsoft\windows\currentversion\ime',
    r'software\microsoft\windows\currentversion\keyboardlayout',
    r'software\microsoft\windows\currentversion\logon',
    r'software\microsoft\windows\currentversion\media',
    r'software\microsoft\windows\currentversion\minidump',
    r'software\microsoft\windows\currentversion\netcache',
    r'software\microsoft\windows\currentversion\netfw',
    r'software\microsoft\windows\currentversion\network',
    r'software\microsoft\windows\currentversion\networklist',
    r'software\microsoft\windows\currentversion\mmc',
    r'software\microsoft\windows\currentversion\perflib',
    r'software\microsoft\windows\currentversion\perfmon',
    r'software\microsoft\windows\currentversion\taskbar',
    r'software\microsoft\windows\currentversion\themes',
    r'software\microsoft\windows\currentversion\theme',
    r'software\microsoft\windows\currentversion\userprofile',
    r'software\microsoft\windows\currentversion\userrights',
    r'software\microsoft\windows\currentversion\startmenu',
    r'software\microsoft\windows\currentversion\shell',
    r'software\microsoft\windows\currentversion\sendto',
    r'software\microsoft\windows\currentversion\startup',
)
# 值名级噪音 (写频繁但无恶意价值)
_FULL_SNAPSHOT_NOISE_VALUES = {
    'lastwritetime', 'lwt', 'mru', 'mrulistex', 'recent', 'recentdocs',
    'userassist', 'bagmru', 'bagnum', 'visited', 'typedpaths',
    'lastvisitedmru', 'lastactivatedapp', 'streammru',
    'user settime', 'last timespan', 'last active time',
}


def _full_snapshot_walk(hive: int, root_key: str, snapshot: Dict,
                        max_keys: int = 60000, excluded: set = None) -> int:
    """递归遍历整个注册表子树 (排除式), 返回遍历的键数"""
    if excluded is None:
        excluded = _FULL_SNAPSHOT_EXCLUDE_DIRS
    count = 0

    def _walk(subkey_path: str):
        nonlocal count
        if count >= max_keys:
            return
        sub_l = subkey_path.lower()
        for ex in excluded:
            if sub_l == ex or sub_l.startswith(ex + '\\'):
                return
        try:
            with winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ) as key:
                vals = {}
                i = 0
                while True:
                    try:
                        name, value, vtype = winreg.EnumValue(key, i)
                        if vtype == winreg.REG_SZ:
                            vals[name] = str(value)
                        elif vtype == winreg.REG_DWORD:
                            vals[name] = f'DWORD:{value}'
                        elif vtype == winreg.REG_QWORD:
                            vals[name] = f'QWORD:{value}'
                        elif vtype == winreg.REG_BINARY:
                            vals[name] = f'BINARY:{len(value or b"")}b'
                        elif vtype == winreg.REG_EXPAND_SZ:
                            vals[name] = str(value)
                        elif vtype == winreg.REG_MULTI_SZ:
                            vals[name] = 'MULTI_SZ:' + '|'.join(value)
                        i += 1
                    except OSError:
                        break
                if vals:
                    clean = {k: v for k, v in vals.items()
                             if k.lower() not in _FULL_SNAPSHOT_NOISE_VALUES}
                    if clean:
                        full_path = subkey_path if subkey_path else root_key
                        snapshot[full_path] = clean
                j = 0
                while True:
                    try:
                        sub_name = winreg.EnumKey(key, j)
                        sub_path = sub_name if not subkey_path else subkey_path + '\\' + sub_name
                        _walk(sub_path)
                        j += 1
                    except OSError:
                        break
        except (FileNotFoundError, OSError, PermissionError):
            return

    _walk(root_key)
    return count


def take_full_registry_snapshot(max_keys: int = 60000) -> Dict[str, Dict[str, str]]:
    """全量注册表快照 (键名集合级) — 不依赖白名单, 任何位置的"新键创建/删除"都会被捕获

    实现: 白名单快照 + 全量键名集合 (reg.exe export + 只取 [HKEY...] 键名行,
    不解析值)。键名集合 diff 能捕获未知位置的持久化键创建 (如计划任务/服务/
    随机目录注册表), 值级变化由白名单快照精确监控 — 两者互补, 速度可接受。

    返回 {完整键路径: {'@': 'KEY_EXISTS'}} (兼容 diff_registry), 附 Services 快照。
    """
    import subprocess as _sp
    import tempfile as _tf
    import threading as _th

    snapshot = {}
    # 先取白名单快照 (精确值级) — 保持原有能力
    snapshot.update(take_registry_snapshot(full_scan=False))

    def _export_key_names(hive: str, prefix: str):
        fd, tmp = _tf.mkstemp(suffix='.reg')
        os.close(fd)
        try:
            r = _sp.run(['reg', 'export', hive, tmp, '/y'],
                        capture_output=True, timeout=45)
            if r.returncode != 0:
                return
            with open(tmp, 'r', encoding='utf-16-le', errors='ignore') as f:
                for line in f:
                    line = line.rstrip('\r\n')
                    if line.startswith('[') and line.endswith(']'):
                        path = prefix + line[1:-1].strip('"')
                        pl = path.lower()
                        skip = False
                        for ex in _FULL_SNAPSHOT_EXCLUDE_DIRS:
                            if pl == ex or pl.startswith(ex + '\\'):
                                skip = True
                                break
                        if not skip:
                            snapshot.setdefault(path, {'@': 'KEY_EXISTS'})
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    threads = [
        _th.Thread(target=_export_key_names, args=('HKLM', 'HKLM\\'), daemon=True),
        _th.Thread(target=_export_key_names, args=('HKCU', 'HKCU\\'), daemon=True),
        _th.Thread(target=_export_key_names, args=('HKCR', 'HKCR\\'), daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=55)

    services = _enumerate_service_subkeys()
    if services:
        snapshot['__SERVICES_SUBKEYS__'] = services
    return snapshot


_FULL_SNAPSHOT_EXCLUDE_DIRS = set(_FULL_SNAPSHOT_EXCLUDE_PREFIX)





def diff_registry(before: Dict[str, Dict[str, str]], after: Dict[str, Dict[str, str]]) -> Dict:
    """对比前后快照，返回变更报告"""
    changes = {
        'created_keys': [],
        'deleted_keys': [],
        'modified_keys': [],
        'details': [],
    }

    # 处理普通注册表键
    all_keys = set(before.keys()) | set(after.keys())
    all_keys.discard('__SERVICES_SUBKEYS__')

    for key_path in sorted(all_keys):
        before_vals = before.get(key_path, {})
        after_vals = after.get(key_path, {})

        if not before_vals and after_vals:
            category = _classify_key(key_path)
            changes['created_keys'].append(key_path)
            new_vals_str = ', '.join(f'{k}={v}' for k, v in list(after_vals.items())[:10])
            changes['details'].append({
                'type': 'created', 'key': key_path, 'category': category,
                'values': new_vals_str[:300],
            })
            logger.warning(f"[Registry] NEW {category}: {key_path} → {new_vals_str[:200]}")
        elif before_vals and not after_vals:
            category = _classify_key(key_path)
            changes['deleted_keys'].append(key_path)
            changes['details'].append({
                'type': 'deleted', 'key': key_path, 'category': category, 'values': '',
            })
            logger.warning(f"[Registry] DELETED {category}: {key_path}")
        elif before_vals != after_vals:
            category = _classify_key(key_path)
            mods = []
            for vname in set(before_vals.keys()) | set(after_vals.keys()):
                bv = before_vals.get(vname, '')
                av = after_vals.get(vname, '')
                if bv != av:
                    mods.append(f'{vname}: {bv} → {av}')
            if mods:
                changes['modified_keys'].append(key_path)
                changes['details'].append({
                    'type': 'modified', 'key': key_path, 'category': category,
                    'values': '; '.join(mods)[:400],
                })
                logger.warning(f"[Registry] MODIFIED {category}: {key_path} | {'; '.join(mods[:3])[:250]}")

    # 处理服务子键变更
    services_before = before.get('__SERVICES_SUBKEYS__', {})
    services_after = after.get('__SERVICES_SUBKEYS__', {})
    all_svc = set(services_before.keys()) | set(services_after.keys())

    for svc_name in sorted(all_svc):
        svc_before = services_before.get(svc_name, {})
        svc_after = services_after.get(svc_name, {})

        if not svc_before and svc_after:
            changes['created_keys'].append(f'Services\\{svc_name}')
            changes['details'].append({
                'type': 'created', 'key': f'Services\\{svc_name}', 'category': 'Service',
                'values': ', '.join(f'{k}={v}' for k, v in svc_after.items())[:300],
            })
            logger.warning(f"[Registry] NEW Service: {svc_name} → {svc_after.get('ImagePath', '?')}")
        elif svc_before and not svc_after:
            changes['deleted_keys'].append(f'Services\\{svc_name}')
            changes['details'].append({
                'type': 'deleted', 'key': f'Services\\{svc_name}', 'category': 'Service', 'values': '',
            })
            logger.warning(f"[Registry] DELETED Service: {svc_name}")
        elif svc_before != svc_after:
            mods = []
            for k in set(svc_before.keys()) | set(svc_after.keys()):
                if svc_before.get(k) != svc_after.get(k):
                    mods.append(f'{k}: {svc_before.get(k)} → {svc_after.get(k)}')
            if mods:
                changes['modified_keys'].append(f'Services\\{svc_name}')
                changes['details'].append({
                    'type': 'modified', 'key': f'Services\\{svc_name}', 'category': 'Service',
                    'values': '; '.join(mods)[:400],
                })
                logger.warning(f"[Registry] MODIFIED Service: {svc_name} | {'; '.join(mods)}")

    return changes


def _classify_key(key_path: str) -> str:
    """将注册表键归类"""
    key_upper = key_path.upper()
    if 'DEFENDER' in key_upper or 'ANTISPYWARE' in key_upper or 'ANTIMALWARE' in key_upper:
        if 'EXCLUSIONS' in key_upper:
            return 'Defender_Exclusions'
        if 'FEATURES' in key_upper:
            return 'Defender_Features'
        return 'Defender'
    if 'FIREWALL' in key_upper or 'SHAREDACCESS' in key_upper:
        return 'Firewall'
    if '\\SERVICES\\' in key_upper and 'CurrentControlSet' in key_upper and 'Parameters' not in key_upper:
        return 'Service'
    if '\\SCHEDULE\\' in key_upper or 'TASKCACHE' in key_upper:
        return 'ScheduledTask'
    if 'WBEM' in key_upper or 'WMI' in key_upper:
        return 'WMI'
    if 'WINLOGON' in key_upper:
        return 'Winlogon'
    if '\\RUN' in key_upper or 'RUNONCE' in key_upper:
        return 'Persistence_Run'
    if 'APPLICATION_IDENTITY' in key_upper or 'APPCERTDLLS' in key_upper or 'APPINIT' in key_upper:
        return 'Persistence_DLL'
    if 'SHELL FOLDERS' in key_upper or 'STARTUP' in key_upper:
        return 'Startup'
    if 'POLICIES' in key_upper:
        return 'SecurityPolicy'
    if 'IMAGE FILE EXECUTION' in key_upper:
        return 'ImageHijack'
    if 'INTERNET SETTINGS' in key_upper or 'INTERNET EXPLORER' in key_upper:
        return 'Browser'
    if 'SAFEBOOT' in key_upper:
        return 'SafeBoot'
    if 'TERMINAL SERVER' in key_upper:
        return 'RDP'
    if 'TCPIP' in key_upper:
        return 'Network'
    if 'CONTROL\\LSA' in key_upper or key_upper.endswith('\\LSA'):
        return 'LSA_Security'
    if 'CREDENTIALS' in key_upper or 'CREDENTIAL' in key_upper or 'LSA' in key_upper:
        return 'Credential'
    if 'SESSION MANAGER' in key_upper:
        if 'KNOWNDLLS' in key_upper:
            return 'KnownDLLs'
        return 'BootConfig'
    # 新增类别
    if 'EXEFILE' in key_upper or 'TXTFILE' in key_upper or 'LNKFILE' in key_upper \
            or 'SOFTWARE\\CLASSES' in key_upper:
        return 'FileAssociation'
    if '\\ENVIRONMENT' in key_upper:
        return 'UserEnvironment'
    if 'TIME PROVIDERS' in key_upper:
        return 'TimeProviders'
    if 'PRINT\\MONITORS' in key_upper:
        return 'PrintMonitors'
    if 'NETWORKPROVIDER' in key_upper:
        return 'NetworkProvider'
    if 'SHELLEXECUTEHOOKS' in key_upper or 'SHAREDTASKSCHEDULER' in key_upper:
        return 'ShellHooks'
    if 'SYSTEMRESTORE' in key_upper:
        return 'SystemRestore'
    if 'CONTROL PANEL\\DESKTOP' in key_upper:
        return 'ScreenSaver'
    return 'Other'


# ===== 系统状态检测（非注册表） =====

# 已知安全产品进程名 → 产品名
KNOWN_SEC_PRODUCTS = {
    'MsMpEng.exe': 'Windows Defender Antimalware',
    'NisSrv.exe': 'Windows Defender NIS',
    'SenseCncProxy.exe': 'Defender ATP',
    'SecurityHealthService.exe': 'Windows Security Health',
    'MpDefenderCoreService.exe': 'Defender Core Service',
    'MpCopyAccelerator.exe': 'Defender Copy Accelerator',
    '360sd.exe': '360杀毒', '360tray.exe': '360安全卫士', '360safe.exe': '360安全卫士',
    'ZhuDongFangYu.exe': '360主动防御',
    'HipsTray.exe': '火绒安全', 'HipsMain.exe': '火绒安全', 'HipsDaemon.exe': '火绒后台',
    'wsctrl.exe': '火绒网络防护',
    'QQPCRTP.exe': '腾讯电脑管家', 'QQPCTray.exe': '腾讯电脑管家', 'QQPCMgr.exe': '腾讯电脑管家',
    'kxetray.exe': '金山毒霸', 'kxescore.exe': '金山毒霸',
    'RavMonD.exe': '瑞星杀毒', 'rsagent.exe': '瑞星杀毒',
    'avp.exe': 'Kaspersky', 'avpui.exe': 'Kaspersky UI',
    'ekrn.exe': 'ESET NOD32', 'egui.exe': 'ESET NOD32 UI',
    'ccSvcHst.exe': 'Norton/Symantec', 'SymCorpUI.exe': 'Symantec UI',
    'mcshield.exe': 'McAfee', 'mfefire.exe': 'McAfee Firewall',
    'bdagent.exe': 'Bitdefender', 'vsserv.exe': 'Bitdefender',
    'coreServiceShell.exe': 'Trend Micro', 'PccNTMon.exe': 'Trend Micro',
    'mbamservice.exe': 'Malwarebytes', 'mbamtray.exe': 'Malwarebytes',
    'avastsvc.exe': 'Avast', 'avastui.exe': 'Avast UI',
    'avgnt.exe': 'Avira', 'avguard.exe': 'Avira',
    'LenovoPcManager.exe': '联想电脑管家', 'HwRlService.exe': '华为电脑管家',
    # ⚠ Defender 更新组件 — 分析期间正常退出(更新完成), 不是被样本终止!
    # 加入名单后 diff_processes 不会把它们的正常退出报为"被样本终止"
    'MpSigStub.exe': 'Defender 签名更新 (系统正常退出)',
    'AM_Delta.exe': 'Defender 增量更新 (系统正常退出)',
    'MpCmdRun.exe': 'Defender 命令行扫描 (系统正常退出)',
}


def take_process_snapshot() -> Dict[str, int]:
    """记录当前运行的进程名→PID映射"""
    snap = {}
    try:
        import psutil
        for proc in psutil.process_iter(['name', 'pid']):
            name = proc.info['name']
            if name:
                snap[name] = proc.info['pid']
    except Exception:
        pass
    return snap


def diff_processes(before: Dict[str, int], after: Dict[str, int]) -> Dict:
    """比较进程快照，检测被杀/新增的进程"""
    killed = {}
    started = {}
    for name, pid in before.items():
        if name not in after:
            killed[name] = pid
    for name, pid in after.items():
        if name not in before:
            started[name] = pid

    # 检测被杀的安全产品
    killed_security = {}
    # ⚠ Defender 更新组件 (MpSigStub/AM_Delta/MpCmdRun) 分析期间正常退出 —
    # 是"更新完成退出"不是"被样本终止", 不能报为 killed_security
    _UPDATE_ONLY = ('MpSigStub.exe', 'AM_Delta.exe', 'MpCmdRun.exe')
    for name, pid in killed.items():
        if name not in KNOWN_SEC_PRODUCTS:
            continue
        if name in _UPDATE_ONLY:
            # 只记录为普通退出, 不归入"被样本终止"
            continue
        killed_security[name] = {
            'product': KNOWN_SEC_PRODUCTS[name],
            'pid': pid,
        }

    return {
        'killed_processes': killed,
        'started_processes': started,
        'killed_security_products': killed_security,
    }


_DEFENDER_SERVICES = ('WinDefend', 'wscsvc', 'MsMpEng')


def take_defender_baseline() -> set:
    """执行前 Defender 服务基线 — 记录哪些服务当前在运行。
    执行后只报 "运行→停止" 的变化, 避免 VM/精简系统里
    本来就停用的 Defender 被误报为"被样本终止" """
    try:
        import subprocess as _sp
        r = _sp.run(['powershell', '-NoProfile', '-Command',
                     'Get-Service -Name ' + ','.join(_DEFENDER_SERVICES) +
                     ' -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq "Running"} '
                     '| Select-Object -ExpandProperty Name'],
                    capture_output=True, text=True, errors='ignore', timeout=15)
        return {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}
    except Exception:
        return set()


def _vss_present_now() -> Optional[bool]:
    """当前是否存在卷影副本; 查询失败返回 None (无法判断)"""
    try:
        import subprocess as _sp
        r = _sp.run(['vssadmin', 'list', 'shadows'],
                    capture_output=True, text=True, timeout=15, errors='ignore')
        out = r.stdout + r.stderr
        return not ('No items found' in out or '没有符合' in out)
    except Exception:
        return None


def _log_nonempty_map() -> Dict[str, Optional[bool]]:
    """当前常见事件日志是否非空; 查询失败返回 None"""
    result = {}
    for log_name in ['System', 'Security', 'Application', 'Windows PowerShell']:
        try:
            import subprocess as _sp
            r = _sp.run(['wevtutil', 'gli', log_name],
                        capture_output=True, text=True, timeout=5, errors='ignore')
            result[log_name] = 'numberOfLogRecords: 0' not in r.stdout
        except Exception:
            result[log_name] = None
    return result


def take_system_state_baseline() -> Dict:
    """执行前 VSS/事件日志基线 — 执行后只报"有→无"的变化,
    避免机器本来就没有卷影副本/日志为空时被误报为勒索/清日志"""
    return {
        'vss_present': _vss_present_now(),
        'logs_nonempty': _log_nonempty_map(),
    }


def check_system_state_post_exec(defender_baseline: set = None, pre_baseline: Dict = None) -> Dict:
    """执行后系统状态检查 — VSS、日志清除、用户账号等"""
    pre_baseline = pre_baseline or {}
    pre_vss = pre_baseline.get('vss_present')
    pre_logs = pre_baseline.get('logs_nonempty') or {}
    # 引擎活跃推断: 基线里有 WinDefend 服务在运行 → 执行前引擎是启用的
    _defender_engine_was_active = bool(defender_baseline) and 'windefend' in {
        s.lower() for s in defender_baseline}
    results = {
        'vss_deleted': False,
        'vss_shadows': [],
        'event_logs_cleared': False,
        'new_users': [],
        'user_groups_modified': [],
        'firewall_rules_added': [],
        'hosts_modified': False,
        'security_products_stopped': [],
        'proxy_hijack': '',
        'defender_status': '',
        'detections': [],
    }

    # 1. 卷影副本检查 (仅当执行前存在、执行后消失才判定被删除)
    try:
        vss_now = _vss_present_now()
        if vss_now is False:
            if pre_vss is True:
                results['vss_deleted'] = True
                results['detections'].append('VSS_Deleted')
                logger.warning("[SystemState] 卷影副本已被删除（勒索行为可能）")
            else:
                logger.info("[SystemState] 执行前即无卷影副本, 跳过 VSS 删除误报")
        elif vss_now is True:
            r = subprocess.run(['vssadmin', 'list', 'shadows'],
                               capture_output=True, text=True, timeout=15, errors='ignore')
            vss_output = r.stdout + r.stderr
            results['vss_shadows'] = [l.strip() for l in vss_output.split('\n') if 'Shadow Copy' in l][:10]
    except Exception:
        pass

    # 2. 事件日志状态 (仅当执行前非空、执行后为空才判定被清除)
    try:
        now_logs = _log_nonempty_map()
        for log_name, nonempty in now_logs.items():
            if nonempty is False and pre_logs.get(log_name) is True:
                results['event_logs_cleared'] = True
                results['detections'].append(f'LogCleared_{log_name}')
                logger.warning(f"[SystemState] 事件日志 {log_name} 已被清除")
    except Exception:
        pass

    # 3. hosts 文件修改
    hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
    try:
        if os.path.exists(hosts_path):
            mtime = os.path.getmtime(hosts_path)
            # 粗略判断：过去几分钟内修改过（与沙箱执行窗口匹配）
            if time_since(mtime) < 600:  # 10分钟内
                with open(hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                non_comment_lines = [l for l in content.split('\n')
                                     if l.strip() and not l.strip().startswith('#')]
                if len(non_comment_lines) > len([l for l in content.split('\n') if l.strip().startswith('127.0.0.1')]):
                    results['hosts_modified'] = True
                    results['detections'].append('HostsFileModified')
    except Exception:
        pass

    # 4. 安全产品进程检测
    #    ⚠ process_iter 只列现存进程 — 被杀的 MsMpEng 已不在列表, 此检测天然失效!
    #    (被杀安全产品的可靠检测来自 diff_processes 前后快照对比 → killed_security_products)
    #    此处保留对"安全产品服务已停止"的状态检查 (服务层)
    #    ⚠ 必须与执行前基线对比: VM/精简系统里 Defender 可能一开始就没运行,
    #      直接报"被终止"是当前状态断言而非样本行为 (曾误报 SecurityStopped_Defender)
    try:
        import subprocess as _sp
        r = _sp.run(['powershell', '-NoProfile', '-Command',
                     'Get-Service -Name WinDefend,wscsvc,MsMpEng -ErrorAction SilentlyContinue '
                     '| Where-Object {$_.Status -ne "Running"} | Select-Object -ExpandProperty Name'],
                    capture_output=True, text=True, errors='ignore', timeout=15)
        stopped = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        for svc in stopped:
            # ⚠ 基线过滤: 执行前就没运行的服务不报 (VM/精简系统 Defender 默认停用)
            if defender_baseline is not None and svc.lower() not in defender_baseline:
                logger.info(f"[SystemState] Defender 服务 {svc} 执行前已停止, 跳过 (基线)")
                continue
            results['security_products_stopped'].append(f'Defender服务: {svc}')
            results['detections'].append(f'SecurityStopped_Defender_{svc}')
            logger.warning(f"[SystemState] Defender 服务已停止: {svc}")
    except Exception:
        pass

    # 5. 系统代理被劫持 (winhttp/WinINet — 银狐常劫持代理做中间人/阻断杀软更新)
    try:
        import subprocess as _sp
        r = _sp.run(['powershell', '-NoProfile', '-Command',
                     '(Get-ItemProperty "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"'
                     ' -ErrorAction SilentlyContinue).ProxyServer'],
                    capture_output=True, text=True, errors='ignore', timeout=10)
        proxy = r.stdout.strip() if r.stdout else ''
        if proxy and not any(skip in proxy.lower() for skip in ('127.0.0.1', 'localhost', 'none')):
            results['proxy_hijack'] = proxy
            results['detections'].append(f'ProxyHijack_{proxy[:60]}')
            logger.warning(f"[SystemState] 系统代理被设置: {proxy}")
    except Exception:
        pass

    # 6. Windows Defender 引擎状态 (Get-MpComputerStatus — 实时保护/签名状态)
    try:
        import subprocess as _sp
        r = _sp.run(['powershell', '-NoProfile', '-Command',
                     'try { $s = Get-MpComputerStatus -ErrorAction Stop; '
                     '"Realtime=$($s.RealTimeProtectionEnabled);Antivirus=$($s.AntivirusEnabled);'
                     'Tamper=$($s.IsTamperProtected);Updated=$($s.AntivirusSignatureLastUpdated)" } '
                     'catch { "ERR" }'],
                    capture_output=True, text=True, errors='ignore', timeout=20)
        mp_status = r.stdout.strip() if r.stdout else ''
        if mp_status and mp_status != 'ERR':
            results['defender_status'] = mp_status
            if 'Realtime=False' in mp_status or 'Antivirus=False' in mp_status:
                # ⚠ 基线过滤: 执行前引擎已禁用则不报 (VM 无 Defender 是常态)
                if defender_baseline is not None and not _defender_engine_was_active:
                    logger.info(f"[SystemState] Defender 引擎执行前已禁用, 跳过 (基线)")
                else:
                    results['detections'].append('DefenderDisabledStatus')
                    logger.warning(f"[SystemState] Defender 引擎已禁用: {mp_status}")
        elif mp_status == 'ERR':
            results['defender_status'] = 'Get-MpComputerStatus 失败 (引擎可能被移除)'
            results['detections'].append('DefenderStatusUnavailable')
    except Exception:
        pass

    return results


def time_since(timestamp: float) -> float:
    return datetime.now().timestamp() - timestamp


def take_user_snapshot() -> Dict:
    """本地用户 / 管理员组 / 监听端口 / 防火墙规则 / WMI订阅 / 关键进程 / 系统文件 / PPL 快照"""
    snap = {'users': set(), 'admins': set(), 'listeners': set(), 'fw_rules': set(),
            'wmi_filters': set(), 'wmi_consumers': set(), 'wmi_bindings': set(),
            'critical_procs': {}, 'ppl_procs': {}, 'sys_files': {},
            'dns_cache': set()}
    import subprocess
    # 0d. DNS 缓存 (无 scapy 时的 DNS 域名捕获 — C2 情报第一来源)
    try:
        r = subprocess.run(['powershell', '-NoProfile', '-Command',
                            'Get-DnsClientCache -ErrorAction SilentlyContinue '
                            '| Select-Object -ExpandProperty Entry'],
                           capture_output=True, text=True, errors='ignore', timeout=15)
        snap['dns_cache'] = {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}
    except Exception:
        pass
    # 0a. 关键进程 (BreakOnTermination) — 全表扫描
    try:
        import psutil as _ps
        import ctypes as _ct
        for p in _ps.process_iter(['pid', 'name']):
            try:
                h = _ct.windll.kernel32.OpenProcess(0x0400, False, p.info['pid'])
                if not h:
                    continue
                val = _ct.c_ulong()
                st = _ct.windll.ntdll.NtQueryInformationProcess(
                    _ct.c_void_p(h), _ct.c_ulong(29), _ct.byref(val),
                    _ct.c_ulong(_ct.sizeof(val)), None)
                _ct.windll.kernel32.CloseHandle(h)
                if st == 0 and val.value != 0:
                    snap['critical_procs'][p.info['pid']] = p.info['name']
            except Exception:
                continue
    except Exception:
        pass
    # 0b. PPL 保护进程 (ProcessProtectionInformation) — 全表扫描
    try:
        import psutil as _ps
        import ctypes as _ct
        for p in _ps.process_iter(['pid', 'name']):
            try:
                h = _ct.windll.kernel32.OpenProcess(0x1000, False, p.info['pid'])  # QUERY_LIMITED
                if not h:
                    continue
                buf = _ct.create_string_buffer(8)
                ret = _ct.c_ulong(0)
                st = _ct.windll.ntdll.NtQueryInformationProcess(
                    _ct.c_void_p(h), _ct.c_ulong(0x3F), buf, 8, _ct.byref(ret))
                _ct.windll.kernel32.CloseHandle(h)
                if st == 0 and ret.value >= 2:
                    level = buf[0] & 0x0F
                    if level > 0:
                        snap['ppl_procs'][p.info['pid']] = f"{p.info['name']} (PPL level={level})"
            except Exception:
                continue
    except Exception:
        pass
    # 0c. 关键系统文件哈希 (检测系统文件劫持/感染)
    try:
        import hashlib as _hl
        _sys_files = [
            r'C:\Windows\System32\ntdll.dll',
            r'C:\Windows\System32\kernel32.dll',
            r'C:\Windows\System32\kernelbase.dll',
            r'C:\Windows\System32\user32.dll',
            r'C:\Windows\System32\win32u.dll',
            r'C:\Windows\System32\advapi32.dll',
            r'C:\Windows\System32\sechost.dll',
            r'C:\Windows\System32\winsrv.dll',
            r'C:\Windows\System32\winlogon.exe',
            r'C:\Windows\System32\lsass.exe',
            r'C:\Windows\System32\services.exe',
            r'C:\Windows\System32\svchost.exe',
            r'C:\Windows\System32\csrss.exe',
            r'C:\Windows\System32\smss.exe',
            r'C:\Windows\System32\drivers\etc\hosts',
        ]
        for _f in _sys_files:
            try:
                with open(_f, 'rb') as _fh:
                    snap['sys_files'][_f] = _hl.sha256(_fh.read()).hexdigest()[:16]
            except Exception:
                pass
    except Exception:
        pass
    # 0. WMI 持久化订阅 (root\subscription — 远控常用持久化, 注册表快照看不到!)
    try:
        r = subprocess.run(['powershell', '-NoProfile', '-Command',
                            'Get-WmiObject -Namespace root\\subscription -Class __EventFilter '
                            '-ErrorAction SilentlyContinue | ForEach-Object { $_.Name + "|" + $_.Query }'],
                           capture_output=True, text=True, errors='ignore', timeout=20)
        snap['wmi_filters'] = {l.strip() for l in r.stdout.splitlines() if l.strip()}
        r = subprocess.run(['powershell', '-NoProfile', '-Command',
                            'Get-WmiObject -Namespace root\\subscription -Class __EventConsumer '
                            '-ErrorAction SilentlyContinue | ForEach-Object { $_.Name + "|" + $_.__CLASS }'],
                           capture_output=True, text=True, errors='ignore', timeout=20)
        snap['wmi_consumers'] = {l.strip() for l in r.stdout.splitlines() if l.strip()}
        # WMI consumer 脚本内容 (ActiveScript/CommandLine 恶意代码 — 作为内容特征)
        try:
            r = subprocess.run(['powershell', '-NoProfile', '-Command',
                                'Get-WmiObject -Namespace root\\subscription -Class ActiveScriptEventConsumer '
                                '-ErrorAction SilentlyContinue | ForEach-Object { $_.Name + "|" + ($_.ScriptText -replace "`r`n"," ") }'],
                               capture_output=True, text=True, errors='ignore', timeout=20)
            snap['wmi_scripts'] = {l.strip()[:300] for l in r.stdout.splitlines() if l.strip()}
            r = subprocess.run(['powershell', '-NoProfile', '-Command',
                                'Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer '
                                '-ErrorAction SilentlyContinue | ForEach-Object { $_.Name + "|" + $_.CommandLineTemplate }'],
                               capture_output=True, text=True, errors='ignore', timeout=20)
            snap['wmi_scripts'] |= {l.strip()[:300] for l in r.stdout.splitlines() if l.strip()}
        except Exception:
            snap['wmi_scripts'] = set()
        r = subprocess.run(['powershell', '-NoProfile', '-Command',
                            'Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding '
                            '-ErrorAction SilentlyContinue | ForEach-Object { $_.Filter + "|" + $_.Consumer }'],
                           capture_output=True, text=True, errors='ignore', timeout=20)
        snap['wmi_bindings'] = {l.strip() for l in r.stdout.splitlines() if l.strip()}
    except Exception:
        pass
    # 1. 本地用户
    try:
        r = subprocess.run(['powershell', '-NoProfile', '-Command',
                            'Get-LocalUser -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name'],
                           capture_output=True, text=True, errors='ignore', timeout=15)
        snap['users'] = {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}
    except Exception:
        pass
    # 2. 管理员组成员
    try:
        r = subprocess.run(['powershell', '-NoProfile', '-Command',
                            'Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue '
                            '| Select-Object -ExpandProperty Name'],
                           capture_output=True, text=True, errors='ignore', timeout=15)
        snap['admins'] = {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}
    except Exception:
        pass
    # 3. 监听端口 (addr|pid)
    try:
        r = subprocess.run(['netstat', '-ano'], capture_output=True, text=True,
                           errors='ignore', timeout=15)
        for line in r.stdout.splitlines():
            if 'LISTENING' not in line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                snap['listeners'].add(f'{parts[1]}|{parts[4]}')
    except Exception:
        pass
    # 4. 防火墙规则名
    try:
        r = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                           capture_output=True, text=True, errors='ignore', timeout=30)
        in_rule = False
        for line in r.stdout.splitlines():
            ls = line.strip()
            if ls.startswith('规则名称'):
                in_rule = True
                name = ls.split(':', 1)[-1].strip()
                if name:
                    snap['fw_rules'].add(name)
            elif in_rule and ls and ':' not in ls:
                in_rule = False
    except Exception:
        pass
    return snap


def diff_user_snapshot(before: Dict, after: Dict) -> Dict:
    """对比用户/组/端口/防火墙/WMI订阅/关键进程/系统文件/PPL 快照"""
    # 关键进程增加/减少
    b_crit = before.get('critical_procs', {})
    a_crit = after.get('critical_procs', {})
    crit_added = {f"{v}(PID={k})" for k, v in a_crit.items() if k not in b_crit}
    crit_removed = {f"{v}(PID={k})" for k, v in b_crit.items() if k not in a_crit}
    # PPL 新增
    b_ppl = before.get('ppl_procs', {})
    a_ppl = after.get('ppl_procs', {})
    ppl_added = {f"{v}(PID={k})" for k, v in a_ppl.items() if k not in b_ppl}
    # 系统文件变化
    b_sf = before.get('sys_files', {})
    a_sf = after.get('sys_files', {})
    sysfile_changed = {f"{k} ({b_sf.get(k, '?')[:8]}→{v[:8]})"
                       for k, v in a_sf.items() if b_sf.get(k) and b_sf[k] != v}
    return {
        'new_users': sorted(after.get('users', set()) - before.get('users', set())),
        'removed_users': sorted(before.get('users', set()) - after.get('users', set())),
        'new_admins': sorted(after.get('admins', set()) - before.get('admins', set())),
        'new_listeners': sorted(after.get('listeners', set()) - before.get('listeners', set())),
        'new_fw_rules': sorted(after.get('fw_rules', set()) - before.get('fw_rules', set())),
        'new_wmi_filters': sorted(after.get('wmi_filters', set()) - before.get('wmi_filters', set())),
        'new_wmi_consumers': sorted(after.get('wmi_consumers', set()) - before.get('wmi_consumers', set())),
        'new_wmi_bindings': sorted(after.get('wmi_bindings', set()) - before.get('wmi_bindings', set())),
        'new_wmi_scripts': sorted(after.get('wmi_scripts', set()) - before.get('wmi_scripts', set())),
        'critical_added': sorted(crit_added),
        'critical_removed': sorted(crit_removed),
        'ppl_added': sorted(ppl_added),
        'sysfile_changed': sorted(sysfile_changed),
        'new_dns': sorted(after.get('dns_cache', set()) - before.get('dns_cache', set())),
    }


def _registry_section_value_exists(section: str, value_name: str) -> bool:
    """检查注册表section下某值是否存在且不为0"""
    try:
        hive_path, subkey = section.split('\\', 1)
        hive_map = {'HKLM': winreg.HKEY_LOCAL_MACHINE, 'HKCU': winreg.HKEY_CURRENT_USER}
        hive = hive_map.get(hive_path)
        if not hive:
            return False
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, value_name)
            if isinstance(val, int):
                return val != 0
            return bool(val)
    except Exception:
        return False


def generate_system_report(reg_changes: Dict, system_state: Dict) -> Dict:
    """综合注册表变更 + 系统状态，生成结构化报告"""
    detections = system_state.get('detections', [])
    details = reg_changes.get('details', [])

    # 分类汇总
    categories = {}
    for d in details:
        cat = d.get('category', 'Other')
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(d)

    # 高危检测项
    high_severity = []
    medium_severity = []
    info_severity = []

    high_categories = ['Defender', 'Defender_Exclusions', 'Defender_Features', 'Firewall',
                       'SafeBoot', 'ImageHijack', 'Credential', 'SecurityPolicy',
                       'LSA_Security', 'KnownDLLs', 'FileAssociation']
    med_categories = ['Persistence_Run', 'Persistence_DLL', 'Winlogon', 'Service',
                      'ScheduledTask', 'WMI', 'RDP', 'BootConfig',
                      'UserEnvironment', 'TimeProviders', 'PrintMonitors',
                      'NetworkProvider', 'ShellHooks', 'SystemRestore', 'ScreenSaver']

    for cat, items in categories.items():
        if cat in high_categories:
            high_severity.append({'category': cat, 'count': len(items), 'items': items})
        elif cat in med_categories:
            medium_severity.append({'category': cat, 'count': len(items), 'items': items})
        else:
            info_severity.append({'category': cat, 'count': len(items), 'items': items})

    # 系统状态高危
    for det in detections:
        if 'VSS' in det or 'LogCleared' in det or 'SecurityStopped' in det \
                or 'ProxyHijack' in det or 'DefenderDisabled' in det or 'DefenderStatusUnavailable' in det:
            high_severity.append({'category': 'SystemState', 'count': 1, 'items': [{'type': 'system', 'key': det}]})
        elif 'Hosts' in det:
            medium_severity.append({'category': 'SystemState', 'count': 1, 'items': [{'type': 'system', 'key': det}]})

    total_changes = len(details) + len(detections)

    return {
        'total_changes': total_changes,
        'registry_created': len(reg_changes.get('created_keys', [])),
        'registry_deleted': len(reg_changes.get('deleted_keys', [])),
        'registry_modified': len(reg_changes.get('modified_keys', [])),
        'system_detections': len(detections),
        'high_severity': high_severity,
        'medium_severity': medium_severity,
        'info_severity': info_severity,
        'raw_changes': details,
        'raw_detections': detections,
    }
