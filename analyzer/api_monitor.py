#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida API 监控引擎 — 动态插桩关键 API 调用
支持文件操作、注册表、进程注入、网络通信、持久化等
"""
import os
import shutil
import time
import threading
import re
import subprocess

from datetime import datetime

from logger import get_logger
from analyzer.models import APIMonitorResult, APIHookDetail
from config import CONFIG

logger = get_logger('analyzer.api_monitor')

frida = None
try:
    import frida as _frida
    frida = _frida
except ImportError:
    pass


def _coerce_int(value, default=0):
    """把 Frida 传来的十进制/十六进制字符串安全转成 int (兼容超大 SIZE_T)"""
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (OverflowError, ValueError):
            return default
    s = str(value).strip().lower()
    if not s or s in ('?', '-', 'none', 'null', 'nan', 'inf'):
        return default
    try:
        if s.startswith(('0x', '-0x')):
            return int(s, 16)
        return int(float(s))
    except (ValueError, OverflowError):
        return default


def _fmt_bytes(n):
    """内存大小人性化显示 (报告/日志共用)"""
    n = _coerce_int(n)
    if n >= 1 << 30:
        return f'{n / (1 << 30):.2f} GB'
    if n >= 1 << 20:
        return f'{n / (1 << 20):.2f} MB'
    if n >= 1 << 10:
        return f'{n / (1 << 10):.1f} KB'
    return f'{n} B'


FRIDA_SCRIPT = """
var seen = new Set();
// API 查找加速器 (模块导出枚举) — findExport 大小写兜底分支依赖, 必须在本脚本内定义
var _apiResolver = null;
try { _apiResolver = new ApiResolver('module'); } catch(e) {}
// 高频调用限流状态 (每秒窗口计数)
var g_windowStart = 0;
var g_windowCalls = 0;
var MAX_SEND_PER_SEC = 200;  // 每秒最多发200条, 高频样本截流 (低频全量)

function safeReadStr(ptr) {
    try {
        if (ptr === null || ptr.isNull()) return null;
        var s = Memory.readUtf16String(ptr);
        if (s && s.length > 0) {
            var ascii = true;
            for (var i = 0; i < Math.min(s.length, 3); i++) {
                if (s.charCodeAt(i) === 0) break;
                if (s.charCodeAt(i) > 127) { ascii = false; break; }
            }
            if (ascii) return s;
        }
        return Memory.readUtf8String(ptr);
    } catch(e) {
        return ptr.toString();
    }
}

function logApi(name, args) {
    // ⚠ 限流: 恶意样本高频循环调用(每秒数千次)会淹没 Frida 消息队列,
    // Python 回调处理不过来导致后分析卡死。简单可靠方案: 每秒最多发送
    // MAX_SEND_PER_SEC 条, 低频(恶意行为多为低频)完整记录, 高频丢弃尾部。
    // 5000 条上限由 Python 侧截断。
    var now = Date.now();
    if (now - g_windowStart >= 1000) {
        g_windowStart = now;
        g_windowCalls = 0;
    }
    g_windowCalls++;
    if (g_windowCalls > MAX_SEND_PER_SEC) return;  // 超出每秒限额直接丢弃
    var cleanArgs = [];
    for (var i = 0; i < args.length; i++) {
        var v = args[i];
        if (v === null || v === undefined) cleanArgs.push(null);
        else cleanArgs.push(String(v));
    }
    send({type: 'api', name: name, args: cleanArgs, ts: Date.now()});
}

var apiSpecs = [
    // === File Operations ===
    ['kernel32.dll', 'CreateFileW', [0]],
    ['kernel32.dll', 'CreateFileA', [0]],
    ['kernel32.dll', 'WriteFile', []],
    ['kernel32.dll', 'DeleteFileW', [0]],
    ['kernel32.dll', 'DeleteFileA', [0]],
    ['kernel32.dll', 'MoveFileW', [0, 1]],
    ['kernel32.dll', 'MoveFileExW', [0, 1]],
    ['kernel32.dll', 'CopyFileW', [0, 1]],
    ['kernel32.dll', 'CopyFileExW', [0, 1]],
    ['kernel32.dll', 'ReadFile', []],
    ['kernel32.dll', 'SetFileAttributesW', [0]],
    ['kernel32.dll', 'GetFileAttributesW', [0]],

    // === Process Operations ===
    ['kernel32.dll', 'CreateProcessW', [0, 1]],
    ['kernel32.dll', 'CreateProcessA', [0, 1]],
    ['kernel32.dll', 'WinExec', [0]],
    ['kernel32.dll', 'TerminateProcess', []],
    ['kernel32.dll', 'OpenProcess', []],
    ['kernel32.dll', 'CreateThread', [2]],
    ['kernel32.dll', 'ExitProcess', []],

    // === Memory / Injection ===
    ['kernel32.dll', 'VirtualAlloc', [0, 1]],
    ['kernel32.dll', 'VirtualAllocEx', [0, 1]],
    ['kernel32.dll', 'VirtualProtect', [0]],
    ['kernel32.dll', 'VirtualProtectEx', [0]],
    ['kernel32.dll', 'WriteProcessMemory', [0, 1]],
    ['kernel32.dll', 'ReadProcessMemory', [0, 1]],
    ['kernel32.dll', 'CreateRemoteThread', [0]],
    ['kernel32.dll', 'VirtualFree', [0]],
    ['kernel32.dll', 'VirtualFreeEx', [0]],

    // === Module Loading ===
    ['kernel32.dll', 'LoadLibraryW', [0]],
    ['kernel32.dll', 'LoadLibraryA', [0]],
    ['kernel32.dll', 'LoadLibraryExW', [0]],
    ['kernel32.dll', 'LoadLibraryExA', [0]],
    ['kernel32.dll', 'GetProcAddress', [1]],
    ['kernel32.dll', 'FreeLibrary', [0]],

    // === 反取证 / 交互模拟 (云沙箱对照补强) ===
    ['kernel32.dll', 'SetFileTime', [0, 1]],
    ['user32.dll', 'SendInput', []],
    ['user32.dll', 'mouse_event', []],
    ['user32.dll', 'keybd_event', []],
    ['dbghelp.dll', 'MiniDumpWriteDump', []],
    ['kernel32.dll', 'GetSystemInfo', []],
    ['kernel32.dll', 'GetUserNameA', []],
    ['kernel32.dll', 'GetUserNameW', []],
    ['kernel32.dll', 'GetTimeZoneInformation', []],
    ['kernel32.dll', 'CreateToolhelp32Snapshot', []],
    // === USB 蠕虫传播 (PlugX) — 遍历驱动器 + 设备句柄 ===
    ['kernel32.dll', 'GetLogicalDriveStringsA', []],
    ['kernel32.dll', 'GetLogicalDriveStringsW', []],
    ['kernel32.dll', 'GetDriveTypeA', [0]],
    ['kernel32.dll', 'GetDriveTypeW', [0]],
    ['kernel32.dll', 'GetDriveType', [0]],
    ['kernel32.dll', 'CopyFileW', [0]],
    ['kernel32.dll', 'CopyFileA', [0]],
    // === 窗口消息/窗口类 (Step Bear 内核注入检测: EM_SETWORDBREAKPROC 回调滥用 / cbClsExtra) ===
    ['user32.dll', 'SendMessageA', [0, 1, 2]],
    ['user32.dll', 'SendMessageW', [0, 1, 2]],
    ['user32.dll', 'PostMessageA', [0, 1, 2]],
    ['user32.dll', 'PostMessageW', [0, 1, 2]],
    ['user32.dll', 'RegisterClassExA', [0]],
    ['user32.dll', 'RegisterClassExW', [0]],
    ['user32.dll', 'FindWindowA', [0]],
    ['user32.dll', 'FindWindowW', [0]],
    ['user32.dll', 'FindWindowExA', [0]],
    ['user32.dll', 'FindWindowExW', [0]],
    ['user32.dll', 'GetWindowLongA', [0]],
    ['user32.dll', 'GetWindowLongW', [0]],
    ['user32.dll', 'SetWindowLongA', [0, 1, 2]],
    ['user32.dll', 'SetWindowLongW', [0, 1, 2]],

    // === Registry Operations ===
    ['advapi32.dll', 'RegCreateKeyExW', [1]],
    ['advapi32.dll', 'RegCreateKeyExA', [1]],
    ['advapi32.dll', 'RegSetValueExW', [1, 4]],
    ['advapi32.dll', 'RegSetValueExA', [1, 4]],
    ['advapi32.dll', 'RegDeleteKeyW', [1]],
    ['advapi32.dll', 'RegDeleteKeyExW', [1]],
    ['advapi32.dll', 'RegDeleteValueW', [1]],
    ['advapi32.dll', 'RegOpenKeyExW', [1]],
    ['advapi32.dll', 'RegOpenKeyExA', [1]],
    ['advapi32.dll', 'RegQueryValueExW', [1]],
    ['advapi32.dll', 'RegCloseKey', []],
    ['advapi32.dll', 'RegEnumKeyExW', [2]],

    // === Service / Persistence ===
    ['advapi32.dll', 'CreateServiceW', [1, 3]],
    ['advapi32.dll', 'StartServiceW', [1]],
    ['advapi32.dll', 'ControlService', [1]],
    ['advapi32.dll', 'DeleteService', [1]],
    ['advapi32.dll', 'ChangeServiceConfigW', [1]],
    ['advapi32.dll', 'ChangeServiceConfig2W', [1]],
    ['advapi32.dll', 'OpenSCManagerW', [0]],
    ['advapi32.dll', 'OpenServiceW', [1]],

    // === Network ===
    ['ws2_32.dll', 'connect', [1]],
    ['ws2_32.dll', 'WSAConnect', [1]],
    ['ws2_32.dll', 'socket', []],
    ['ws2_32.dll', 'send', [1]],
    ['ws2_32.dll', 'recv', [1]],
    ['ws2_32.dll', 'WSASend', [1]],
    ['ws2_32.dll', 'WSARecv', [1]],
    ['ws2_32.dll', 'WSAStartup', []],
    ['ws2_32.dll', 'gethostbyname', [0]],
    ['ws2_32.dll', 'getaddrinfo', [0]],
    ['wininet.dll', 'InternetOpenW', [0]],
    ['wininet.dll', 'InternetOpenA', [0]],
    ['wininet.dll', 'InternetConnectW', [1]],
    ['wininet.dll', 'InternetConnectA', [1]],
    ['wininet.dll', 'HttpOpenRequestW', [1, 2]],
    ['wininet.dll', 'HttpOpenRequestA', [1, 2]],
    ['wininet.dll', 'HttpSendRequestW', [1]],
    ['wininet.dll', 'HttpSendRequestA', [1]],
    ['wininet.dll', 'InternetReadFile', [1]],
    ['wininet.dll', 'InternetWriteFile', [1]],
    ['wininet.dll', 'InternetOpenUrlW', [0]],
    ['wininet.dll', 'InternetOpenUrlA', [0]],

    // === 键盘/鼠标轮询监听 ===
    ['user32.dll', 'GetAsyncKeyState', []],
    ['user32.dll', 'GetKeyState', []],
    ['user32.dll', 'GetKeyboardState', []],
    ['user32.dll', 'GetForegroundWindow', []],
    ['user32.dll', 'GetRawInputData', []],
    // === 音频/麦克风设备访问 ===
    ['winmm.dll', 'waveInOpen', []],
    ['winmm.dll', 'waveInStart', []],
    ['winmm.dll', 'mixerOpen', []],
    ['winmm.dll', 'midiInOpen', []],
    // === 代理设置操控 ===
    ['wininet.dll', 'InternetSetOptionW', []],
    ['wininet.dll', 'InternetSetOptionA', []],
    ['winhttp.dll', 'WinHttpSetDefaultProxyConfiguration', []],
    // === 网卡/磁盘/时区/设备枚举（VM 检测） ===
    ['iphlpapi.dll', 'GetAdaptersAddresses', []],
    ['iphlpapi.dll', 'GetIfTable', []],
    ['kernel32.dll', 'GetVolumeInformationW', [0]],
    ['kernel32.dll', 'GetVolumeInformationA', [0]],
    ['kernel32.dll', 'QueryDosDeviceW', [0]],
    ['kernel32.dll', 'QueryDosDeviceA', [0]],
    ['kernel32.dll', 'GetLogicalDrives', []],
    ['kernel32.dll', 'GetDriveTypeW', [0]],
    ['kernel32.dll', 'GetDriveTypeA', [0]],
    ['kernel32.dll', 'GetTimeZoneInformation', []],

    // === Evasion / Anti-Debug ===
    ['kernel32.dll', 'IsDebuggerPresent', []],
    ['kernel32.dll', 'CheckRemoteDebuggerPresent', []],
    ['kernel32.dll', 'SetWindowsHookExW', [0, 2]],
    ['kernel32.dll', 'SetWindowsHookExA', [0, 2]],
    ['kernel32.dll', 'UnhookWindowsHookEx', []],
    ['kernel32.dll', 'CreateMutexW', [0]],
    ['kernel32.dll', 'CreateMutexA', [0]],
    ['kernel32.dll', 'Sleep', [0]],
    ['kernel32.dll', 'SleepEx', [0]],
    ['kernel32.dll', 'SetErrorMode', [0]],

    // === NT Kernel Calls ===
    ['ntdll.dll', 'NtCreateThreadEx', [0]],
    ['ntdll.dll', 'NtUnmapViewOfSection', [0]],
    ['ntdll.dll', 'NtMapViewOfSection', [0]],
    ['ntdll.dll', 'NtCreateSection', [0]],
    ['ntdll.dll', 'NtOpenProcess', [0]],
    ['ntdll.dll', 'NtAllocateVirtualMemory', [0]],
    ['ntdll.dll', 'NtWriteVirtualMemory', [0]],
    ['ntdll.dll', 'NtProtectVirtualMemory', [0]],
    ['ntdll.dll', 'NtQueryInformationProcess', [0, 1]],
    ['ntdll.dll', 'NtQuerySystemInformation', [0]],
    ['ntdll.dll', 'NtSetInformationThread', [0]],
    ['ntdll.dll', 'NtCreateProcessEx', [0]],
    ['ntdll.dll', 'NtOpenKey', [0, 1]],
    ['ntdll.dll', 'NtCreateKey', [0, 1]],
    ['ntdll.dll', 'NtSetValueKey', [0, 1]],
    ['ntdll.dll', 'NtDeleteKey', [0]],
    ['ntdll.dll', 'NtDeleteValueKey', [0, 1]],
    ['ntdll.dll', 'NtEnumerateKey', [0]],
    ['ntdll.dll', 'NtClose', [0]],

    // === Crypto / DPAPI ===
    ['crypt32.dll', 'CryptDecrypt', []],
    ['crypt32.dll', 'CryptEncrypt', []],
    ['crypt32.dll', 'CryptUnprotectData', []],
    ['crypt32.dll', 'CryptProtectData', []],
    ['crypt32.dll', 'CryptStringToBinaryW', [0, 1]],
    ['crypt32.dll', 'CryptStringToBinaryA', [0, 1]],
    ['crypt32.dll', 'CertOpenSystemStoreW', [0]],
    ['crypt32.dll', 'CertEnumCertificatesInStore', [0]],
    ['bcrypt.dll', 'BCryptDecrypt', []],
    ['bcrypt.dll', 'BCryptEncrypt', []],
    ['ncrypt.dll', 'NCryptDecrypt', []],
    ['ncrypt.dll', 'NCryptEncrypt', []],
    ['ncrypt.dll', 'NCryptOpenKey', [0]],

    // === Shell / Process Execution ===
    ['shell32.dll', 'ShellExecuteW', [0, 1, 2]],
    ['shell32.dll', 'ShellExecuteA', [0, 1, 2]],
    ['shell32.dll', 'ShellExecuteExW', [0]],
    ['shell32.dll', 'ShellExecuteExA', [0]],

    // === Task Scheduler ===
    ['advapi32.dll', 'CreateProcessAsUserW', [0, 1]],
    ['advapi32.dll', 'LogonUserW', [0, 1]],

    // === Token / Privilege Manipulation ===
    ['advapi32.dll', 'OpenProcessToken', []],
    ['advapi32.dll', 'AdjustTokenPrivileges', []],
    ['advapi32.dll', 'LookupPrivilegeValueW', [0, 1]],
    ['kernel32.dll', 'ImpersonateLoggedOnUser', []],
    ['kernel32.dll', 'RevertToSelf', []],
];

send({type: 'status', msg: 'Frida v' + Frida.version + ', apiSpecs: ' + apiSpecs.length});

// === Export finder: pre-build per-DLL cache via Process module enumeration ===
var _exportCache = {};

function _buildCache(dllName) {
    if (_exportCache[dllName]) return;
    _exportCache[dllName] = {};
    var mod = null;
    // Try multiple module APIs
    try { if (typeof Process !== 'undefined' && typeof Process.getModuleByName === 'function') mod = Process.getModuleByName(dllName); } catch(e) {}
    if (!mod) try { if (typeof Process !== 'undefined' && typeof Process.findModuleByName === 'function') mod = Process.findModuleByName(dllName); } catch(e) {}
    if (!mod) try { mod = Process.findModuleByAddress(Module.findBaseAddress(dllName)); } catch(e) {}
    if (!mod) return;
    try {
        var exports = mod.enumerateExports();
        for (var i = 0; i < exports.length; i++) {
            _exportCache[dllName][exports[i].name] = exports[i].address;
        }
    } catch(e) {
        // enumerateExports failed, try enumerateExportsSync on Module
        try {
            if (typeof Module.enumerateExportsSync === 'function') {
                var exports = Module.enumerateExportsSync(dllName);
                for (var i = 0; i < exports.length; i++) {
                    _exportCache[dllName][exports[i].name] = exports[i].address;
                }
            }
        } catch(e2) {}
    }
}

function findExport(dllName, funcName) {
    _buildCache(dllName);
    var addr = _exportCache[dllName] && _exportCache[dllName][funcName];
    if (addr) return addr;

    // Fallback: ApiResolver
    try {
        var resolver = new ApiResolver('module');
        var matches = resolver.enumerateMatches('exports:' + dllName + '!' + funcName);
        if (matches.length > 0) return matches[0].address;
    } catch(e) {}

    // Fallback: DebugSymbol
    try {
        if (typeof DebugSymbol === 'object' && typeof DebugSymbol.getFunctionByName === 'function') {
            var addr2 = DebugSymbol.getFunctionByName(funcName);
            if (addr2 && !addr2.isNull()) return addr2;
        }
    } catch(e) {}
    // 大小写兜底: ApiResolver/Module API 对模块名大小写敏感
    // (kernel32.dll vs KERNEL32.DLL), 枚举实际加载的模块名重试
    try {
        var mods = Process.enumerateModules();
        var lower = dllName.toLowerCase();
        for (var mi = 0; mi < mods.length; mi++) {
            if (mods[mi].name.toLowerCase() === lower) {
                try {
                    if (_apiResolver) {
                        var ms2 = _apiResolver.enumerateMatches('exports:' + mods[mi].name + '!' + funcName);
                        if (ms2.length > 0) return ms2[0].address;
                    }
                } catch(e) {}
                try {
                    var exps = mods[mi].enumerateExports();
                    for (var ei = 0; ei < exps.length; ei++) {
                        if (exps[ei].name === funcName) return exps[ei].address;
                    }
                } catch(e) {}
                break;
            }
        }
    } catch(e) {}
    return null;
}

// Quick self-check: 只验证 findExport, 不在这里 attach —
// CreateFileW 由下方 apiSpecs 统一 hook, 避免重复 attach 产生双份调用记录
var testAddr = findExport('kernel32.dll', 'CreateFileW');
send({type: 'status', msg: 'findExport test: CreateFileW = ' + (testAddr ? 'FOUND at ' + testAddr : 'NULL') + ' (resolver=' + (typeof _apiResolver) + ')'});

var hooked = 0;
var missing = 0;
apiSpecs.forEach(function(spec) {
    var dllName = spec[0];
    var funcName = spec[1];
    var strArgs = spec[2];

    var addr = findExport(dllName, funcName);
    if (!addr) {
        missing++;
        return;
    }

    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                var vals = [];
                for (var i = 0; i < 6; i++) {
                    try {
                        if (strArgs.indexOf(i) !== -1) {
                            vals.push(safeReadStr(args[i]));
                        } else {
                            vals.push(args[i].toString());
                        }
                    } catch(e) {
                        vals.push('?');
                    }
                }
                logApi(funcName, vals);
            }
        });
        hooked++;
    } catch(e) {
        send({type: 'status', msg: 'ERROR: ' + funcName + ' attach failed: ' + e});
    }
});

// === 子进程创建捕获: 从 PROCESS_INFORMATION 提取子进程 PID (还原进程树) ===
function attachChildProcessCapture(dll, func) {
    var addr = findExport(dll, func);
    if (!addr) return;
    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    this._cmd = safeReadStr(args[1]) || safeReadStr(args[0]) || '';
                } catch(e) { this._cmd = ''; }
            },
            onLeave: function(retval) {
                try {
                    if (retval.toInt32() === 0) return;  // 创建失败
                    var pi = args[9];  // LPPROCESS_INFORMATION
                    if (!pi || pi.isNull()) return;
                    // PROCESS_INFORMATION: hProcess(ptr) hThread(ptr) dwProcessId(u32) dwThreadId(u32)
                    // x64: 8+8=16; x86: 4+4=8
                    var pidOff = (Process.pointerSize === 8) ? 16 : 8;
                    var childPid = pi.add(pidOff).readU32();
                    if (childPid > 0) {
                        send({type: 'child_process', pid: childPid, cmdline: this._cmd, via: func});
                    }
                } catch(e) {}
            }
        });
    } catch(e) {}
}
attachChildProcessCapture('kernel32.dll', 'CreateProcessW');
attachChildProcessCapture('kernel32.dll', 'CreateProcessA');

// === 隐藏 Frida 注入特征: 模块枚举时把 frida-agent 改名为系统DLL ===
// (反沙箱样本通过 CreateToolhelp32Snapshot+Module32 枚举模块列表检测 Frida,
//  检测到即触发 VM/沙箱识别 → 自我删除 → 行为逃逸)
var Module32FirstW = findExport('kernel32.dll', 'Module32FirstW');
var Module32NextW = findExport('kernel32.dll', 'Module32NextW');
var FRIDA_MODULE_MARKS = ['frida-agent', 'frida-gadget', 'gum-js', 'frida-helper'];

function disguiseModuleEntry(mep) {
    try {
        if (!mep || mep.isNull()) return;
        // MODULEENTRY32W.szModule 偏移: x86=32, x64=48
        var nameOff = (Process.pointerSize === 8) ? 48 : 32;
        var modName = mep.add(nameOff).readUtf16String(64) || '';
        var lower = modName.toLowerCase();
        for (var i = 0; i < FRIDA_MODULE_MARKS.length; i++) {
            if (lower.indexOf(FRIDA_MODULE_MARKS[i]) !== -1) {
                mep.add(nameOff).writeUtf16String('wldp.dll');
                send({type: 'status', msg: '[AntiVM] 模块名隐藏: ' + modName + ' → wldp.dll'});
                break;
            }
        }
    } catch(e) {}
}
if (Module32FirstW) {
    Interceptor.attach(Module32FirstW, {
        onLeave: function(retval) {
            try { if (retval.toInt32() !== 0) disguiseModuleEntry(args[1]); } catch(e) {}
        }
    });
}
if (Module32NextW) {
    Interceptor.attach(Module32NextW, {
        onLeave: function(retval) {
            try { if (retval.toInt32() !== 0) disguiseModuleEntry(args[1]); } catch(e) {}
        }
    });
}

send({type: 'status', msg: 'Frida hooks: ' + hooked + ' hooked, ' + missing + ' not found'});

// === 专用网络载荷捕获 ===
function attachNetPayload(dll, func, isSend) {
    var addr = findExport(dll, func);
    if (!addr) return;
    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    var fd = args[0].toInt32();
                    var buf = args[1];
                    var len = args[2].toInt32();
                    if (len <= 0 || len > 1048576 || buf.isNull()) return;
                    var readLen = Math.min(len, 512);
                    var data = buf.readByteArray(readLen);
                    var preview = '';
                    var isHttp = false;
                    try {
                        var arr = new Uint8Array(data);
                        try {
                            preview = decodeURIComponent(escape(String.fromCharCode.apply(null, arr)));
                            if (preview.length > 300) preview = preview.substring(0, 300);
                        } catch(e) {
                            var hex = [];
                            var hlen = Math.min(arr.length, 64);
                            for (var i = 0; i < hlen; i++) hex.push(('0' + arr[i].toString(16)).slice(-2));
                            preview = hex.join(' ');
                        }
                        isHttp = /^[\\s]*(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|HTTP)\\s/i.test(preview);
                    } catch(e2) {}
                    send({type: 'netpayload', api: func, fd: fd, len: len, preview: preview, is_send: isSend, is_http: isHttp});
                } catch(e) {}
            }
        });
    } catch(e) {}
}
attachNetPayload('ws2_32.dll', 'send', true);
attachNetPayload('ws2_32.dll', 'recv', false);
attachNetPayload('ws2_32.dll', 'WSASend', true);
attachNetPayload('ws2_32.dll', 'WSARecv', false);

// === HTTP 高层 API URL 载荷还原 ===
// HTTPS 在 socket 层 (send/recv) 已是密文, 看不到 URL; 必须从 WinHTTP/WinINet
// 高层 API 的明文参数 (在加密之前) 提取完整 URL。会话式 API 需维护 handle→host 映射。
var _httpHosts = {};
function _httpReadStr(p) {
    try {
        if (!p || p.isNull()) return '';
        var s = p.readUtf16String();
        if (!s || s.length === 0) s = p.readUtf8String();
        return s || '';
    } catch(e) { return ''; }
}
function _emitHttpUrl(proto, verb, host, path) {
    try {
        var url = '';
        if (host && path) {
            var base = (host.indexOf('://') !== -1) ? host : ('http://' + host);
            url = base + ((path.charAt(0) === '/') ? path : ('/' + path));
        } else if (path) {
            url = path;
        }
        if (url) {
            send({type: 'http_url', proto: proto, verb: verb || '', url: url, extra: ''});
        }
    } catch(e) {}
}
function attachHttpUrlCapture() {
    // WinHTTP: WinHttpConnect → 记录 host
    var wc = findExport('winhttp.dll', 'WinHttpConnect');
    if (wc) Interceptor.attach(wc, { onEnter: function(a) {
        var h = _httpReadStr(a[1]);
        if (h) _httpHosts['w' + a[0].toString()] = h;
    }});
    // WinHTTP: WinHttpOpenRequest → verb + path, 组合 URL
    var wo = findExport('winhttp.dll', 'WinHttpOpenRequest');
    if (wo) Interceptor.attach(wo, { onEnter: function(a) {
        var verb = _httpReadStr(a[1]);
        var path = _httpReadStr(a[2]);
        var host = _httpHosts['w' + a[0].toString()] || '';
        _emitHttpUrl('winhttp', verb, host, path);
    }});
    // WinHTTP: WinHttpSendRequest → 明文 headers (含 Host/Cookie/User-Agent)
    var ws = findExport('winhttp.dll', 'WinHttpSendRequest');
    if (ws) Interceptor.attach(ws, { onEnter: function(a) {
        var h = _httpReadStr(a[1]);
        if (h && h.length > 3) send({type: 'http_url', proto: 'winhttp', verb: 'HDR', url: '', extra: h.substring(0, 300)});
    }});
    // WinINet: InternetConnectW → 记录 host
    var ic = findExport('wininet.dll', 'InternetConnectW');
    if (ic) Interceptor.attach(ic, { onEnter: function(a) {
        var h = _httpReadStr(a[1]);
        if (h) _httpHosts['i' + a[0].toString()] = h;
    }});
    // WinINet: HttpOpenRequestW → verb + path, 组合 URL
    var ho = findExport('wininet.dll', 'HttpOpenRequestW');
    if (ho) Interceptor.attach(ho, { onEnter: function(a) {
        var verb = _httpReadStr(a[1]);
        var path = _httpReadStr(a[2]);
        var host = _httpHosts['i' + a[0].toString()] || '';
        _emitHttpUrl('wininet', verb, host, path);
    }});
    // WinINet: InternetOpenUrlW → 直接完整 URL
    var iu = findExport('wininet.dll', 'InternetOpenUrlW');
    if (iu) Interceptor.attach(iu, { onEnter: function(a) {
        var url = _httpReadStr(a[1]);
        if (url) send({type: 'http_url', proto: 'wininet_openurl', verb: '', url: url, extra: ''});
    }});
    send({type: 'status', msg: 'HTTP URL 载荷还原已激活 (WinHTTP/WinINet 高层 API)'});
}
attachHttpUrlCapture();
"""

# ===== 反 VM 检测绕过脚本 =====
FRIDA_ANTIVM_SCRIPT = """
// 反虚拟机检测绕过 v2 — 强制拦截+伪造返回值，恶意软件收到 "NOT FOUND"
send({type: 'status', msg: 'Anti-VM bypass v2 — BLOCK mode'});

// Export finder for Frida 17.x — uses ApiResolver (most reliable cross-version)
var _apiResolver = null;
try { _apiResolver = new ApiResolver('module'); } catch(e) {}

function findExport(dllName, funcName) {
    if (_apiResolver) {
        try {
            var matches = _apiResolver.enumerateMatches('exports:' + dllName + '!' + funcName);
            if (matches.length > 0) return matches[0].address;
        } catch(e) {}
    }
    try {
        if (typeof DebugSymbol === 'object' && typeof DebugSymbol.getFunctionByName === 'function') {
            var addr = DebugSymbol.getFunctionByName(funcName);
            if (addr && !addr.isNull()) return addr;
        }
    } catch(e) {}
    try {
        if (typeof Module.findExportByName === 'function') {
            var addr = Module.findExportByName(dllName, funcName);
            if (addr && !addr.isNull()) return addr;
        }
    } catch(e) {}
    try {
        if (typeof Module.getExportByName === 'function') {
            var addr = Module.getExportByName(dllName, funcName);
            if (addr && !addr.isNull()) return addr;
        }
    } catch(e) {}
    // 大小写兜底: ApiResolver/Module API 对模块名大小写敏感
    // (kernel32.dll vs KERNEL32.DLL), 枚举实际加载的模块名重试
    try {
        var mods = Process.enumerateModules();
        var lower = dllName.toLowerCase();
        for (var mi = 0; mi < mods.length; mi++) {
            if (mods[mi].name.toLowerCase() === lower) {
                try {
                    if (_apiResolver) {
                        var ms2 = _apiResolver.enumerateMatches('exports:' + mods[mi].name + '!' + funcName);
                        if (ms2.length > 0) return ms2[0].address;
                    }
                } catch(e) {}
                try {
                    var exps = mods[mi].enumerateExports();
                    for (var ei = 0; ei < exps.length; ei++) {
                        if (exps[ei].name === funcName) return exps[ei].address;
                    }
                } catch(e) {}
                break;
            }
        }
    } catch(e) {}
    return null;
}


// === 0. 辅助：检测 VM 相关字符串 ===
var VM_REG_KEYS = [
    'SOFTWARE\\\\VMware', 'SOFTWARE\\\\Oracle\\\\VirtualBox',
    'HARDWARE\\\\ACPI\\\\DSDT\\\\VBOX', 'HARDWARE\\\\ACPI\\\\DSDT\\\\VMWARE',
    'HARDWARE\\\\DEVICEMAP\\\\Scsi',
    'Services\\\\vmci', 'Services\\\\vmhgfs', 'Services\\\\vmmouse',
    'Services\\\\VBoxGuest', 'Services\\\\VBoxSF', 'Services\\\\VBoxMouse',
    'Services\\\\VBoxVideo', 'Services\\\\VBoxService',
    'Services\\\\vmusbmouse', 'Services\\\\vmmemctl', 'Services\\\\vmx_svga',
    'Services\\\\vmxnet', 'Services\\\\vmx86', 'Services\\\\vmscsi',
    // 5.2 七条件反沙箱样本的 VM 注册表检查项 (任一命中即判定 VM)
    'SOFTWARE\\\\Microsoft\\\\Virtual Machine\\\\Guest\\\\DetectedComponents',
    'SOFTWARE\\\\Microsoft\\\\Virtual Machine\\\\Guest',
];
var VM_FILES = [
    'vmci.sys', 'vmmouse.sys', 'vmhgfs.sys', 'vmx86.sys', 'vmscsi.sys',
    'vboxguest.sys', 'vboxmouse.sys', 'vboxsf.sys', 'vboxvideo.sys',
    'vmusbmouse.sys', 'vmmemctl.sys', 'vmx_svga.sys', 'vmxnet.sys',
    '\\\\\\\\.\\\\VBoxGuest', '\\\\\\\\.\\\\VBoxMouse', '\\\\\\\\.\\\\VBoxMiniRdr',
    '\\\\\\\\.\\\\pipe\\\\VBox', '\\\\\\\\.\\\\pipe\\\\vbox',
    'VBoxTrayIPC', 'VBOX__', 'VMWARE__',
    // 5.2 七条件反沙箱样本的文件/设备检查项 (任一命中即判定 VM)
    '\\\\\\\\.\\\\vmci', '\\\\\\\\.\\\\hgfs', '\\\\\\\\.\\\\vboxminirdrdn',
];

function isVMKey(str) {
    if (!str) return false;
    str = str.toLowerCase();
    for (var i = 0; i < VM_REG_KEYS.length; i++) {
        if (str.indexOf(VM_REG_KEYS[i].toLowerCase()) !== -1) return true;
    }
    return false;
}
function isVMFile(str) {
    if (!str) return false;
    str = str.toLowerCase();
    for (var i = 0; i < VM_FILES.length; i++) {
        if (str.indexOf(VM_FILES[i].toLowerCase()) !== -1) return true;
    }
    return false;
}

// 读取 OBJECT_ATTRIBUTES->ObjectName (UNICODE_STRING)。
// x64: ObjectName 指针在 OBJECT_ATTRIBUTES 偏移 16, UNICODE_STRING.Buffer 偏移 8;
// x86: ObjectName 偏移 8, UNICODE_STRING.Buffer 偏移 4。
function readObjectName(attrs) {
    try {
        if (!attrs || attrs.isNull()) return '';
        var arch64 = Process.pointerSize === 8;
        var objNameOff = arch64 ? 16 : 8;
        var bufOff = arch64 ? 8 : 4;
        var objName = attrs.add(objNameOff).readPointer();
        if (objName.isNull()) return '';
        var nameLen = objName.readU16();
        var namePtr = objName.add(bufOff).readPointer();
        if (namePtr.isNull() || nameLen <= 0 || nameLen > 2048) return '';
        return namePtr.readUtf16String(Math.min(nameLen / 2, 512));
    } catch(e) {
        return '';
    }
}

// === 1. RegOpenKeyExW — 拦截！VM键直接返回失败 ===
var RegOpenKeyExW = findExport('advapi32.dll', 'RegOpenKeyExW');
if (RegOpenKeyExW) {
    Interceptor.attach(RegOpenKeyExW, {
        onEnter: function(args) {
            try {
                var subkey = Memory.readUtf16String(args[1]);
                if (isVMKey(subkey)) {
                    this.blockVM = true;
                    this.subkey = subkey;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.blockVM) {
                send({type: 'status', msg: '[AntiVM] BLOCKED RegOpenKey: ' + this.subkey + ' → STATUS_OBJECT_NAME_NOT_FOUND'});
                retval.replace(ptr(0xC0000034));  // STATUS_OBJECT_NAME_NOT_FOUND
            }
        }
    });
    send({type: 'status', msg: '[AntiVM] RegOpenKeyExW — BLOCK mode active'});
}

// === 1b. RegOpenKeyExA — ANSI 路径同样拦截 (样本常用 ANSI 规避钩子) ===
var RegOpenKeyExA = findExport('advapi32.dll', 'RegOpenKeyExA');
if (RegOpenKeyExA) {
    Interceptor.attach(RegOpenKeyExA, {
        onEnter: function(args) {
            try {
                var subkey = Memory.readAnsiString(args[1]);
                if (isVMKey(subkey)) {
                    this.blockVM = true;
                    this.subkey = subkey;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.blockVM) {
                send({type: 'status', msg: '[AntiVM] BLOCKED RegOpenKeyExA: ' + this.subkey + ' → STATUS_OBJECT_NAME_NOT_FOUND'});
                retval.replace(ptr(0xC0000034));
            }
        }
    });
    send({type: 'status', msg: '[AntiVM] RegOpenKeyExA — BLOCK mode active'});
}

// === 2. NtOpenKey — 内核级注册表访问拦截 ===
var NtOpenKey = findExport('ntdll.dll', 'NtOpenKey');
if (NtOpenKey) {
    Interceptor.attach(NtOpenKey, {
        onEnter: function(args) {
            try {
                // args[2] = OBJECT_ATTRIBUTES
                var subkey = readObjectName(args[2]);
                if (subkey && isVMKey(subkey)) {
                    this.blockVM = true;
                    this.subkey = subkey;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.blockVM) {
                send({type: 'status', msg: '[AntiVM] BLOCKED NtOpenKey: ' + this.subkey + ' → 0xC0000034'});
                retval.replace(ptr(0xC0000034));
            }
        }
    });
    send({type: 'status', msg: '[AntiVM] NtOpenKey — BLOCK mode active'});
}

// === 2b. NtOpenKeyEx — Win10+ 变体同样拦截 ===
var NtOpenKeyEx = findExport('ntdll.dll', 'NtOpenKeyEx');
if (NtOpenKeyEx) {
    Interceptor.attach(NtOpenKeyEx, {
        onEnter: function(args) {
            try {
                var subkey = readObjectName(args[2]);
                if (subkey && isVMKey(subkey)) {
                    this.blockVM = true;
                    this.subkey = subkey;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.blockVM) {
                send({type: 'status', msg: '[AntiVM] BLOCKED NtOpenKeyEx: ' + this.subkey + ' → 0xC0000034'});
                retval.replace(ptr(0xC0000034));
            }
        }
    });
}

// === 3. CreateFileW — 拦截！VM驱动文件返回 INVALID_HANDLE ===
var INVALID_HANDLE_VALUE = ptr(0xFFFFFFFFFFFFFFFF);
var CreateFileW = findExport('kernel32.dll', 'CreateFileW');
if (CreateFileW) {
    Interceptor.attach(CreateFileW, {
        onEnter: function(args) {
            try {
                var path = Memory.readUtf16String(args[0]);
                if (isVMFile(path)) {
                    this.blockVM = true;
                    this.path = path;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.blockVM) {
                send({type: 'status', msg: '[AntiVM] BLOCKED CreateFile: ' + this.path + ' → INVALID_HANDLE_VALUE'});
                retval.replace(INVALID_HANDLE_VALUE);
                // 同时设 LastError = ERROR_FILE_NOT_FOUND (2)
                var SetLastError = findExport('kernel32.dll', 'SetLastError');
                if (SetLastError) SetLastError(ptr(2));
            }
        }
    });
    send({type: 'status', msg: '[AntiVM] CreateFileW — BLOCK mode active'});
}

// === 3b. CreateFileA — ANSI 设备/文件路径拦截 ===
var CreateFileA = findExport('kernel32.dll', 'CreateFileA');
if (CreateFileA) {
    Interceptor.attach(CreateFileA, {
        onEnter: function(args) {
            try {
                var path = Memory.readAnsiString(args[0]);
                if (isVMFile(path)) {
                    this.blockVM = true;
                    this.path = path;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.blockVM) {
                send({type: 'status', msg: '[AntiVM] BLOCKED CreateFileA: ' + this.path + ' → INVALID_HANDLE_VALUE'});
                retval.replace(INVALID_HANDLE_VALUE);
                var SetLastError = findExport('kernel32.dll', 'SetLastError');
                if (SetLastError) SetLastError(ptr(2));
            }
        }
    });
    send({type: 'status', msg: '[AntiVM] CreateFileA — BLOCK mode active'});
}

// === 3c. GetFileAttributesW/A — 存在性检查也返回"不存在" ===
var GetFileAttributesW = findExport('kernel32.dll', 'GetFileAttributesW');
if (GetFileAttributesW) {
    Interceptor.attach(GetFileAttributesW, {
        onEnter: function(args) {
            try {
                var path = Memory.readUtf16String(args[0]);
                if (isVMFile(path)) {
                    this.blockVM = true;
                    this.path = path;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.blockVM) {
                send({type: 'status', msg: '[AntiVM] BLOCKED GetFileAttributesW: ' + this.path + ' → INVALID_FILE_ATTRIBUTES'});
                retval.replace(ptr(0xFFFFFFFF));
            }
        }
    });
}
var GetFileAttributesA = findExport('kernel32.dll', 'GetFileAttributesA');
if (GetFileAttributesA) {
    Interceptor.attach(GetFileAttributesA, {
        onEnter: function(args) {
            try {
                var path = Memory.readAnsiString(args[0]);
                if (isVMFile(path)) {
                    this.blockVM = true;
                    this.path = path;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.blockVM) {
                send({type: 'status', msg: '[AntiVM] BLOCKED GetFileAttributesA: ' + this.path + ' → INVALID_FILE_ATTRIBUTES'});
                retval.replace(ptr(0xFFFFFFFF));
            }
        }
    });
}
// GetFileAttributesExW/A 返回 BOOL: 命中 VM 文件时返回 FALSE + ERROR_FILE_NOT_FOUND
var GetFileAttributesExW = findExport('kernel32.dll', 'GetFileAttributesExW');
if (GetFileAttributesExW) {
    Interceptor.attach(GetFileAttributesExW, {
        onEnter: function(args) {
            try {
                var path = Memory.readUtf16String(args[0]);
                if (isVMFile(path)) {
                    this.blockVM = true;
                    this.path = path;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.blockVM) {
                send({type: 'status', msg: '[AntiVM] BLOCKED GetFileAttributesExW: ' + this.path});
                retval.replace(ptr(0));
                var SetLastError = findExport('kernel32.dll', 'SetLastError');
                if (SetLastError) SetLastError(ptr(2));
            }
        }
    });
}
var GetFileAttributesExA = findExport('kernel32.dll', 'GetFileAttributesExA');
if (GetFileAttributesExA) {
    Interceptor.attach(GetFileAttributesExA, {
        onEnter: function(args) {
            try {
                var path = Memory.readAnsiString(args[0]);
                if (isVMFile(path)) {
                    this.blockVM = true;
                    this.path = path;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.blockVM) {
                send({type: 'status', msg: '[AntiVM] BLOCKED GetFileAttributesExA: ' + this.path});
                retval.replace(ptr(0));
                var SetLastError = findExport('kernel32.dll', 'SetLastError');
                if (SetLastError) SetLastError(ptr(2));
            }
        }
    });
}

// === 4. NtCreateFile — 内核级文件访问拦截 ===
var NtCreateFile = findExport('ntdll.dll', 'NtCreateFile');
if (NtCreateFile) {
    Interceptor.attach(NtCreateFile, {
        onEnter: function(args) {
            try {
                // args[2] = OBJECT_ATTRIBUTES
                var path = readObjectName(args[2]);
                if (path && isVMFile(path)) {
                    this.blockVM = true;
                    this.path = path;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.blockVM) {
                send({type: 'status', msg: '[AntiVM] BLOCKED NtCreateFile: ' + this.path + ' → STATUS_OBJECT_NAME_NOT_FOUND'});
                retval.replace(ptr(0xC0000034));
            }
        }
    });
}

// === 4b. NtOpenFile — 直接打开设备对象同样拦截 ===
var NtOpenFile = findExport('ntdll.dll', 'NtOpenFile');
if (NtOpenFile) {
    Interceptor.attach(NtOpenFile, {
        onEnter: function(args) {
            try {
                var path = readObjectName(args[2]);
                if (path && isVMFile(path)) {
                    this.blockVM = true;
                    this.path = path;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.blockVM) {
                send({type: 'status', msg: '[AntiVM] BLOCKED NtOpenFile: ' + this.path + ' → STATUS_OBJECT_NAME_NOT_FOUND'});
                retval.replace(ptr(0xC0000034));
            }
        }
    });
}

// === 5. RegQueryValueExW — 拦截！BIOS值返回伪造的非VM数据 ===
// 签名: RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
var RegQueryValueExW = findExport('advapi32.dll', 'RegQueryValueExW');
if (RegQueryValueExW) {
    Interceptor.attach(RegQueryValueExW, {
        onEnter: function(args) {
            try {
                var valueName = Memory.readUtf16String(args[1]);
                if (valueName === 'SystemProductName') this.fakedValue = 'OptiPlex 7080';
                else if (valueName === 'SystemManufacturer') this.fakedValue = 'Dell Inc.';
                else if (valueName === 'BIOSVendor') this.fakedValue = 'Dell Inc.';
                else if (valueName === 'BIOSVersion') this.fakedValue = '2.5.1';
                else if (valueName === 'VideoBiosVersion') this.fakedValue = 'NVIDIA GeForce GTX 1660';
                else if (valueName === 'Identifier') {
                    this.fakedValue = 'ST2000DM008-2FR102';
                }
                this.valueName = valueName;
                // 参数在 onEnter 保存 — onLeave 里的寄存器/栈偏移并不可靠
                this.lpType = args[3];
                this.lpData = args[4];
                this.lpcbData = args[5];
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.fakedValue === undefined) return;
            send({type: 'status', msg: '[AntiVM] BLOCKED RegQueryValueExW: ' + this.valueName + ' → ' + this.fakedValue});
            try {
                var lpType = this.lpType;
                var lpData = this.lpData;
                var lpcbData = this.lpcbData;
                if (lpData && !lpData.isNull()) {
                    var str = this.fakedValue;
                    var bufSize = (str.length + 1) * 2;
                    var capacity = bufSize;
                    if (lpcbData && !lpcbData.isNull()) {
                        try { capacity = lpcbData.readU32(); } catch(e) {}
                    }
                    if (capacity >= bufSize) {
                        var encoded = Memory.allocUtf16String(str);
                        Memory.copy(lpData, encoded, bufSize);
                        if (lpcbData && !lpcbData.isNull()) {
                            lpcbData.writeU32(bufSize);
                        }
                    }
                }
                if (lpType && !lpType.isNull()) {
                    lpType.writeU32(1);  // REG_SZ
                }
                retval.replace(ptr(0));  // ERROR_SUCCESS
            } catch(e) {}
        }
    });
}

// === 5b. RegQueryValueExA — ANSI 变体同样伪造 (签名同 W) ===
var RegQueryValueExA = findExport('advapi32.dll', 'RegQueryValueExA');
if (RegQueryValueExA) {
    Interceptor.attach(RegQueryValueExA, {
        onEnter: function(args) {
            try {
                var valueName = Memory.readAnsiString(args[1]);
                if (valueName === 'SystemProductName') this.fakedValue = 'OptiPlex 7080';
                else if (valueName === 'SystemManufacturer') this.fakedValue = 'Dell Inc.';
                else if (valueName === 'BIOSVendor') this.fakedValue = 'Dell Inc.';
                else if (valueName === 'BIOSVersion') this.fakedValue = '2.5.1';
                else if (valueName === 'VideoBiosVersion') this.fakedValue = 'NVIDIA GeForce GTX 1660';
                else if (valueName === 'Identifier') {
                    this.fakedValue = 'ST2000DM008-2FR102';
                }
                this.valueName = valueName;
                this.lpType = args[3];
                this.lpData = args[4];
                this.lpcbData = args[5];
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.fakedValue === undefined) return;
            send({type: 'status', msg: '[AntiVM] BLOCKED RegQueryValueExA: ' + this.valueName + ' → ' + this.fakedValue});
            try {
                var lpType = this.lpType;
                var lpData = this.lpData;
                var lpcbData = this.lpcbData;
                if (lpData && !lpData.isNull()) {
                    var str = this.fakedValue;
                    var bufSize = str.length + 1;
                    var capacity = bufSize;
                    if (lpcbData && !lpcbData.isNull()) {
                        try { capacity = lpcbData.readU32(); } catch(e) {}
                    }
                    if (capacity >= bufSize) {
                        lpData.writeUtf8String(str);
                        if (lpcbData && !lpcbData.isNull()) {
                            lpcbData.writeU32(bufSize);
                        }
                    }
                }
                if (lpType && !lpType.isNull()) {
                    lpType.writeU32(1);  // REG_SZ
                }
                retval.replace(ptr(0));  // ERROR_SUCCESS
            } catch(e) {}
        }
    });
}

// === 6. 磁盘大小伪造（>= 500GB） ===
var GetDiskFreeSpaceExW = findExport('kernel32.dll', 'GetDiskFreeSpaceExW');
if (GetDiskFreeSpaceExW) {
    Interceptor.attach(GetDiskFreeSpaceExW, {
        onLeave: function(retval) {
            if (retval.toInt32() === 0) return;
            // 伪造大磁盘: total=500GB, free=200GB
            // x64: rdx=lpFreeBytesAvailable, r8=lpTotalNumberOfBytes, r9=lpTotalFreeBytes
            var freeBytes = this.context.rdx;   // lpFreeBytesAvailable
            var totalBytes = this.context.r8;   // lpTotalNumberOfBytes
            if (!totalBytes.isNull()) {
                totalBytes.writeU64(0x6FC23AC00000);  // ~500GB
            }
            if (!freeBytes.isNull()) {
                freeBytes.writeU64(0x2DC6C0000000);  // ~200GB
            }
        }
    });
    send({type: 'status', msg: '[AntiVM] GetDiskFreeSpaceExW → fake 500GB disk'});
}

// === 2b. GetDiskFreeSpaceA/W — 磁盘容量检测 (别漏了这套API) ===
var GetDiskFreeSpaceA = findExport('kernel32.dll', 'GetDiskFreeSpaceA');
if (GetDiskFreeSpaceA) {
    Interceptor.attach(GetDiskFreeSpaceA, {
        onLeave: function(retval) {
            if (retval.toInt32() === 0) return;
            // lpSectorsPerCluster / lpBytesPerSector / lpFreeClusters / lpTotalClusters
            // 伪造 500GB: sectors=512, total=976562500 sectors
            try {
                var sectorsPerCluster = this.context.rdx;  // arg2
                var bytesPerSector = this.context.r8;       // arg3
                var freeClusters = this.context.r9;          // arg4
                var totalClusters = Memory.readPointer(this.context.rcx.add(8*5)); // stack arg5
                if (!sectorsPerCluster.isNull()) sectorsPerCluster.writeU32(8);
                if (!bytesPerSector.isNull()) bytesPerSector.writeU32(4096);
                if (!freeClusters.isNull()) freeClusters.writeU32(0x1D00000);
                if (!totalClusters.isNull()) totalClusters.writeU32(0x3A00000);
            } catch(e) {
                // fallback: try stdcall arg layout
                try {
                    var sc = ptr(this.context.rcx.add(8*2));
                    var bs = ptr(this.context.rcx.add(8*3));
                    if (!sc.isNull() && sc.readU32() > 0) sc.writeU32(8);
                    if (!bs.isNull() && bs.readU32() > 0) bs.writeU32(4096);
                } catch(e2) {}
            }
        }
    });
}
var GetDiskFreeSpaceW = findExport('kernel32.dll', 'GetDiskFreeSpaceW');
if (GetDiskFreeSpaceW) {
    Interceptor.attach(GetDiskFreeSpaceW, {
        onLeave: function(retval) {
            if (retval.toInt32() === 0) return;
            try {
                var sectorsPerCluster = this.context.rdx;
                var bytesPerSector = this.context.r8;
                var freeClusters = this.context.r9;
                var totalClusters = Memory.readPointer(this.context.rcx.add(8*5));
                if (!sectorsPerCluster.isNull()) sectorsPerCluster.writeU32(8);
                if (!bytesPerSector.isNull()) bytesPerSector.writeU32(4096);
                if (!freeClusters.isNull()) freeClusters.writeU32(0x1D00000);
                if (!totalClusters.isNull()) totalClusters.writeU32(0x3A00000);
            } catch(e) {}
        }
    });
}

// === 2c. DeviceIoControl — 磁盘几何信息/容量查询拦截 ===
var DeviceIoControl = findExport('kernel32.dll', 'DeviceIoControl');
var IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x70000;
var IOCTL_DISK_GET_LENGTH_INFO = 0x7405C;
var IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x2D1080;
var SMART_GET_VERSION = 0x74080;
var SMART_RCV_DRIVE_DATA = 0x7C088;

if (DeviceIoControl) {
    Interceptor.attach(DeviceIoControl, {
        onEnter: function(args) {
            var code = args[1].toInt32();
            if (code === IOCTL_DISK_GET_DRIVE_GEOMETRY || code === IOCTL_DISK_GET_LENGTH_INFO ||
                code === IOCTL_STORAGE_GET_DEVICE_NUMBER || code === SMART_GET_VERSION ||
                code === SMART_RCV_DRIVE_DATA) {
                this.diskQuery = true;
                this.ioctlCode = code;
            }
        },
        onLeave: function(retval) {
            if (!this.diskQuery || retval.toInt32() === 0) return;
            // 拦截成功回执 → 伪造磁盘数据
            send({type: 'status', msg: '[AntiVM] DeviceIoControl disk query blocked (code=0x' + this.ioctlCode.toString(16) + ')'});

            if (this.ioctlCode === IOCTL_DISK_GET_LENGTH_INFO) {
                // 伪造 500GB
                try {
                    var outBuf = this.context.r8;  // lpOutBuffer
                    if (!outBuf.isNull()) {
                        outBuf.writeU64(0x74C060000000);  // ~500GB in bytes
                    }
                } catch(e) {}
            } else if (this.ioctlCode === IOCTL_DISK_GET_DRIVE_GEOMETRY) {
                // 伪造磁盘几何: Cylinders=60801, TracksPerCylinder=255, SectorsPerTrack=63, BytesPerSector=512
                try {
                    var outBuf = this.context.r8;
                    if (!outBuf.isNull()) {
                        outBuf.writeU32(60801);      // Cylinders (large)
                        outBuf.add(4).writeU32(3);   // MediaType 3=FixedMedia
                        outBuf.add(8).writeU32(255); // TracksPerCylinder
                        outBuf.add(12).writeU32(63); // SectorsPerTrack
                        outBuf.add(16).writeU32(512);// BytesPerSector
                    }
                } catch(e) {}
            }
            // 对于 IOCTL_STORAGE_GET_DEVICE_NUMBER 和 SMART，让它们正常返回
            // 但标记已在日志中
        }
    });
    send({type: 'status', msg: '[AntiVM] DeviceIoControl disk IOCTL blocked'});
}

// === 5. MAC 地址伪造 ===
// GetAdaptersInfo(PULONG pOutBufLen, PIP_ADAPTER_INFO pAdapterInfo)
// IP_ADAPTER_INFO.Address 偏移: x64=408, x86=404; Next 指针在偏移 0。
var GetAdaptersInfo = findExport('iphlpapi.dll', 'GetAdaptersInfo');
if (GetAdaptersInfo) {
    Interceptor.attach(GetAdaptersInfo, {
        onEnter: function(args) {
            try { this.pAdapterInfo = args[1]; } catch(e) {}
        },
        onLeave: function(retval) {
            // 遍历适配器链表，替换 VM MAC 前缀
            try {
                var p = this.pAdapterInfo;
                var macOff = (Process.pointerSize === 8) ? 408 : 404;
                var guard = 0;
                while (p && !p.isNull() && guard++ < 64) {
                    var macAddr = p.add(macOff); // Address 字段偏移
                    var b1 = macAddr.readU8();
                    // VMware: 00:50:56, 00:0C:29 → 替换为 DELL: 00:14:22
                    // VirtualBox: 08:00:27 → 替换为 Dell
                    if (b1 === 0x00 && (macAddr.add(1).readU8() === 0x50 || macAddr.add(1).readU8() === 0x0C)) {
                        macAddr.writeU8(0x00);
                        macAddr.add(1).writeU8(0x14);
                        macAddr.add(2).writeU8(0x22);
                        send({type: 'status', msg: '[AntiVM] MAC spoofed: 00:50:56/00:0C:29 → 00:14:22'});
                    } else if (b1 === 0x08 && macAddr.add(1).readU8() === 0x00) {
                        macAddr.writeU8(0x00);
                        macAddr.add(1).writeU8(0x14);
                        macAddr.add(2).writeU8(0x22);
                        send({type: 'status', msg: '[AntiVM] MAC spoofed: 08:00:27 → 00:14:22'});
                    }
                    p = p.readPointer(); // Next 指针
                }
            } catch(e) {}
        }
    });
    send({type: 'status', msg: '[AntiVM] GetAdaptersInfo MAC spoofing installed'});
}

// === 6. SMBIOS CPUID 检测拦截 ===
var GetSystemFirmwareTable = findExport('kernel32.dll', 'GetSystemFirmwareTable');
send({type: 'status', msg: '[AntiVM] GetSystemFirmwareTable found: ' + (GetSystemFirmwareTable ? 'YES' : 'NO')});
if (GetSystemFirmwareTable) {
    Interceptor.attach(GetSystemFirmwareTable, {
        onEnter: function(args) {
            var provider = args[0].toInt32();
            // 'RSMB' = 0x52534D42 = SMBIOS raw data
            if (provider === 0x52534D42) {
                this.rsmb = true;
            }
        },
        onLeave: function(retval) {
            try {
                // 伪造 SMBIOS 固件表 — 历史缺口: 注册表/驱动/进程都隐藏了,
                // 但样本直接读固件表仍能解析出 "VMware" 字符串导致检测到VM后自删
                if (!this.rsmb) return;
                this.rsmb = false;
                var buf = args[2];
                var size = args[3].toInt32();
                if (size <= 0 || buf.isNull()) return;
                var data = buf.readByteArray(size);
                if (!data) return;
                var bytes = new Uint8Array(data);
                // 等长替换(保持SMBIOS字符串区偏移不变): 样本解析后将得到普通厂商名
                function replaceAscii(needle, repl) {
                    var n = needle.length;
                    var hits = 0;
                    for (var i = 0; i + n <= bytes.length; i++) {
                        var ok = true;
                        for (var j = 0; j < n; j++) {
                            if (bytes[i + j] !== needle.charCodeAt(j)) { ok = false; break; }
                        }
                        if (ok) {
                            for (var j = 0; j < n; j++) bytes[i + j] = repl.charCodeAt(j);
                            i += n - 1;
                            hits++;
                        }
                    }
                    return hits;
                }
                var total = 0;
                total += replaceAscii('VMware7,1', 'Dell Inc. ');   // 9 chars
                total += replaceAscii('VMware',   'AMI   ');        // 6 chars
                total += replaceAscii('VirtualBox', 'DellInc    '); // 10 chars
                total += replaceAscii('innotek', 'DellInc');        // 7 chars
                total += replaceAscii('QEMU', 'DELL');              // 4 chars
                total += replaceAscii('BOCHS', 'DELL ');            // 5 chars
                if (total > 0) {
                    buf.writeByteArray(Array.from(bytes));
                    send({type: 'status', msg: '[AntiVM] SMBIOS 固件表已伪造: ' + total + ' 处 VM 特征替换'});
                }
            } catch(e) {}
        }
    });
}

// === 7. 进程枚举 — 过滤 VM 进程名 ===
// PROCESSENTRY32.szExeFile 偏移: x86=36, x64=44 (不是固定 36)
var Process32FirstW = findExport('kernel32.dll', 'Process32FirstW');
var Process32NextW = findExport('kernel32.dll', 'Process32NextW');
var vm_procs = ['vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe', 'vboxservice.exe',
                'vboxtray.exe', 'vboxguest.exe', 'qemu-ga.exe', 'vmsrvc.exe', 'vmusrvc.exe'];
// 自身 Frida 辅助进程也隐藏 — 样本枚举进程列表可见 frida-helper 即判定沙箱
var hidden_procs = ['frida-helper-x86_64.exe', 'frida-helper-x86.exe', 'frida-helper.exe',
                    'frida-server.exe', 'frida-gadget.exe', 'frida-inject.exe'];
var PROC_NAME_OFF = (Process.pointerSize === 8) ? 44 : 36;

function filterProc(entry) {
    try {
        if (!entry || entry.isNull()) return;
        var name = Memory.readUtf16String(entry.add(PROC_NAME_OFF)).toLowerCase();
        // 1. 隐藏 Frida 自身进程(真正改写进程名, 样本枚举时看到普通系统名)
        for (var i = 0; i < hidden_procs.length; i++) {
            if (name.indexOf(hidden_procs[i]) !== -1) {
                entry.add(PROC_NAME_OFF).writeUtf16String('svchost.exe');
                send({type: 'status', msg: '[AntiVM] Frida进程名隐藏: ' + name + ' → svchost.exe'});
                return;
            }
        }
        // 2. 隐藏 VM 进程(真正改写进程名, 样本枚举时看到 svchost.exe)
        for (var i = 0; i < vm_procs.length; i++) {
            if (name.indexOf(vm_procs[i]) !== -1) {
                entry.add(PROC_NAME_OFF).writeUtf16String('svchost.exe');
                send({type: 'status', msg: '[AntiVM] Filtered process: ' + name + ' → svchost.exe'});
            }
        }
    } catch(e) {}
}
if (Process32FirstW) {
    Interceptor.attach(Process32FirstW, {
        onEnter: function(args) { this.entry = args[1]; },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) {
                filterProc(this.entry);
            }
        }
    });
}
if (Process32NextW) {
    Interceptor.attach(Process32NextW, {
        onEnter: function(args) { this.entry = args[1]; },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) {
                filterProc(this.entry);
            }
        }
    });
}

// === 7b. Process32FirstA/NextA — ANSI 枚举同样过滤 (VM 进程名+进程数不受影响) ===
var Process32FirstA = findExport('kernel32.dll', 'Process32FirstA');
var Process32NextA = findExport('kernel32.dll', 'Process32NextA');
function filterProcA(entry) {
    try {
        if (!entry || entry.isNull()) return;
        var name = Memory.readAnsiString(entry.add(PROC_NAME_OFF)).toLowerCase();
        for (var i = 0; i < hidden_procs.length; i++) {
            if (name.indexOf(hidden_procs[i]) !== -1) {
                entry.add(PROC_NAME_OFF).writeUtf8String('svchost.exe');
                send({type: 'status', msg: '[AntiVM] Frida进程名隐藏(A): ' + name + ' → svchost.exe'});
                return;
            }
        }
        for (var j = 0; j < vm_procs.length; j++) {
            if (name.indexOf(vm_procs[j]) !== -1) {
                entry.add(PROC_NAME_OFF).writeUtf8String('svchost.exe');
                send({type: 'status', msg: '[AntiVM] Filtered process(A): ' + name + ' → svchost.exe'});
            }
        }
    } catch(e) {}
}
if (Process32FirstA) {
    Interceptor.attach(Process32FirstA, {
        onEnter: function(args) { this.entry = args[1]; },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) {
                filterProcA(this.entry);
            }
        }
    });
}
if (Process32NextA) {
    Interceptor.attach(Process32NextA, {
        onEnter: function(args) { this.entry = args[1]; },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) {
                filterProcA(this.entry);
            }
        }
    });
}

// === 8. 物理内存伪造（>= 8GB） ===
var GlobalMemoryStatusEx = findExport('kernel32.dll', 'GlobalMemoryStatusEx');
if (GlobalMemoryStatusEx) {
    Interceptor.attach(GlobalMemoryStatusEx, {
        onLeave: function(retval) {
            if (retval.toInt32() === 0) return;
            try {
                var mem = this.context.rcx;
                // ullTotalPhys 偏移 8
                var totalPhys = mem.add(8);
                var currentTotal = totalPhys.readU64();
                if (currentTotal < 0xC0000000) {  // < 3GB → VM
                    totalPhys.writeU64(0x200000000);  // 8GB
                    send({type: 'status', msg: '[AntiVM] Memory spoofed: ' + (currentTotal/0x40000000) + 'GB → 8GB'});
                }
            } catch(e) {}
        }
    });
    send({type: 'status', msg: '[AntiVM] GlobalMemoryStatusEx → fake 8GB RAM'});
}

// === 8b. GlobalMemoryStatus (legacy 32位结构) — 同样伪造 >= 8GB ===
var GlobalMemoryStatus = findExport('kernel32.dll', 'GlobalMemoryStatus');
if (GlobalMemoryStatus) {
    Interceptor.attach(GlobalMemoryStatus, {
        onLeave: function(retval) {
            if (retval.toInt32() === 0) return;
            try {
                var mem = this.context.rcx;
                if (Process.pointerSize === 8) {
                    mem.add(8).writeU64(0x200000000);   // dwTotalPhys = 8GB
                    mem.add(16).writeU64(0x180000000);  // dwAvailPhys = 6GB
                } else {
                    mem.add(8).writeU32(0xDF000000);    // 3.5GB (32位可表示上限)
                    mem.add(12).writeU32(0xAF000000);   // 2.7GB
                }
                send({type: 'status', msg: '[AntiVM] GlobalMemoryStatus → fake RAM'});
            } catch(e) {}
        }
    });
}

// === 8c. GetPhysicallyInstalledSystemMemory — 返回 8GB ===
var GetPhysicallyInstalledSystemMemory = findExport('kernel32.dll', 'GetPhysicallyInstalledSystemMemory');
if (GetPhysicallyInstalledSystemMemory) {
    Interceptor.attach(GetPhysicallyInstalledSystemMemory, {
        onLeave: function(retval) {
            try {
                if (retval.toInt32() !== 0 && !this.context.rcx.isNull()) {
                    this.context.rcx.writeU64(0x800000);  // KB 单位: 8GB = 8388608KB
                    send({type: 'status', msg: '[AntiVM] GetPhysicallyInstalledSystemMemory → 8GB'});
                }
            } catch(e) {}
        }
    });
}

// === 9. GetSystemMetrics — 分辨率/监视器/远程会话伪装 (七条件: 分辨率>=800) ===
var GetSystemMetrics = findExport('user32.dll', 'GetSystemMetrics');
if (GetSystemMetrics) {
    Interceptor.attach(GetSystemMetrics, {
        onEnter: function(args) { this.idx = args[0].toInt32(); },
        onLeave: function(retval) {
            var SM_CXSCREEN = 0, SM_CYSCREEN = 1, SM_CXFULLSCREEN = 16,
                SM_CYFULLSCREEN = 17, SM_CMONITORS = 80,
                SM_XVIRTUALSCREEN = 76, SM_YVIRTUALSCREEN = 77,
                SM_CXVIRTUALSCREEN = 78, SM_CYVIRTUALSCREEN = 79,
                SM_REMOTESESSION = 0x1000, SM_REMOTECONTROL = 0x2001;
            try {
                if (this.idx === SM_CXSCREEN || this.idx === SM_CXFULLSCREEN || this.idx === SM_CXVIRTUALSCREEN) {
                    retval.replace(ptr(1920));
                } else if (this.idx === SM_CYSCREEN || this.idx === SM_CYFULLSCREEN || this.idx === SM_CYVIRTUALSCREEN) {
                    retval.replace(ptr(1080));
                } else if (this.idx === SM_CMONITORS) {
                    retval.replace(ptr(1));
                } else if (this.idx === SM_REMOTESESSION || this.idx === SM_REMOTECONTROL) {
                    retval.replace(ptr(0));
                }
            } catch(e) {}
        }
    });
    send({type: 'status', msg: '[AntiVM] GetSystemMetrics → 1920x1080 / 1 monitor / local session'});
}

// === 10. GetSystemInfo / GetNativeSystemInfo — CPU >= 8 核 + 8GB 物理页 ===
// ⚠ SYSTEM_INFO 与 SYSTEM_BASIC_INFORMATION 布局不同, 不能共用偏移:
//   SYSTEM_INFO x64: ActiveProcessorMask@24, NumberOfProcessors@32
//   SYSTEM_INFO x86: ActiveProcessorMask@16, NumberOfProcessors@20
//   SYSTEM_BASIC_INFORMATION x64: NumberOfPhysicalPages@12, Affinity@48, Processors@56
//   SYSTEM_BASIC_INFORMATION x86: NumberOfPhysicalPages@12, Affinity@36, Processors@40
function patchSystemInfoStruct(info) {
    try {
        var arch64 = Process.pointerSize === 8;
        if (arch64) {
            info.add(24).writePointer(ptr(0xFFF));  // ActiveProcessorMask
            info.add(32).writeU8(8);                 // NumberOfProcessors
        } else {
            info.add(16).writeU32(0xFF);
            info.add(20).writeU8(8);
        }
    } catch(e) {}
}
function patchSystemBasicInfo(buf) {
    try {
        var arch64 = Process.pointerSize === 8;
        var pageSize = buf.add(8).readU32() || 4096;
        buf.add(12).writeU32(Math.floor((8 * 1024 * 1024 * 1024) / pageSize));
        if (arch64) {
            buf.add(48).writePointer(ptr(0xFFF));
            buf.add(56).writeU8(8);
        } else {
            buf.add(36).writeU32(0xFF);
            buf.add(40).writeU8(8);
        }
    } catch(e) {}
}
var GetSystemInfo = findExport('kernel32.dll', 'GetSystemInfo');
if (GetSystemInfo) {
    Interceptor.attach(GetSystemInfo, {
        onEnter: function(args) { this.info = args[0]; },
        onLeave: function(retval) {
            try {
                if (this.info && !this.info.isNull()) patchSystemInfoStruct(this.info);
                send({type: 'status', msg: '[AntiVM] GetSystemInfo → 8 CPUs'});
            } catch(e) {}
        }
    });
}
var GetNativeSystemInfo = findExport('kernel32.dll', 'GetNativeSystemInfo');
if (GetNativeSystemInfo) {
    Interceptor.attach(GetNativeSystemInfo, {
        onEnter: function(args) { this.info = args[0]; },
        onLeave: function(retval) {
            try {
                if (this.info && !this.info.isNull()) patchSystemInfoStruct(this.info);
            } catch(e) {}
        }
    });
}

// === 10b. NtQuerySystemInformation(SystemBasicInformation) — 内核态 CPU/内存查询同样伪造 ===
var NtQSI2 = findExport('ntdll.dll', 'NtQuerySystemInformation');
if (NtQSI2) {
    Interceptor.attach(NtQSI2, {
        onEnter: function(args) {
            this.cls = args[0].toInt32();
            this.buf = args[1];
        },
        onLeave: function(retval) {
            try {
                if (retval.toInt32() !== 0 || this.cls !== 0) return;
                if (this.buf && !this.buf.isNull()) patchSystemBasicInfo(this.buf);
            } catch(e) {}
        }
    });
}

// === 11. GetTickCount / GetTickCount64 — 默认伪造 >= 5 分钟运行时长 ===
// (七条件反沙箱: GetTickCount() >= 300000ms 才继续, 不满足立即退出)
var AV_TICK_OFFSET = 900000;  // +15 分钟 (真实运行时间之上叠加)
var avTickSeeded = false;
var GetTickCountAV = findExport('kernel32.dll', 'GetTickCount');
if (GetTickCountAV) {
    Interceptor.attach(GetTickCountAV, {
        onLeave: function(retval) {
            try {
                var raw = retval.toUInt32();
                var fake = (raw + AV_TICK_OFFSET) >>> 0;
                retval.replace(ptr(fake >>> 0));
                if (!avTickSeeded) {
                    avTickSeeded = true;
                    send({type: 'status', msg: '[AntiVM] GetTickCount → +15min fake uptime'});
                }
            } catch(e) {}
        }
    });
}
var GetTickCount64AV = findExport('kernel32.dll', 'GetTickCount64');
if (GetTickCount64AV) {
    Interceptor.attach(GetTickCount64AV, {
        onLeave: function(retval) {
            try {
                var raw = retval.toUInt64().toNumber();
                retval.replace(ptr(raw + AV_TICK_OFFSET));
                if (!avTickSeeded) {
                    avTickSeeded = true;
                    send({type: 'status', msg: '[AntiVM] GetTickCount64 → +15min fake uptime'});
                }
            } catch(e) {}
        }
    });
}

// === 12. GetUserNameA/W + GetUserNameExW + USERNAME 环境变量 — 用户名黑名单规避 ===
// 黑名单: sandbox / malware / virus / sample / analysis / analyst (大小写不敏感)
// 签名: GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer) — 缓冲区是 args[0], 长度是 args[1]!
var FAKE_USERNAME = '__SANDBOX_FAKE_USER__';
function fakeNameForFormat(nameFormat) {
    // NameSamCompatible(2): DOMAIN\\user; NameDisplay(3): 显示名; 其余按用户名
    if (nameFormat === 2) return 'DESKTOP-1A2B3C\\\\' + FAKE_USERNAME;
    if (nameFormat === 3) return 'Zhang Wei';
    return FAKE_USERNAME;
}
var GetUserNameW = findExport('advapi32.dll', 'GetUserNameW');
if (GetUserNameW) {
    Interceptor.attach(GetUserNameW, {
        onEnter: function(args) { this.buf = args[0]; this.sz = args[1]; },
        onLeave: function(retval) {
            try {
                if (this.buf && !this.buf.isNull()) {
                    this.buf.writeUtf16String(FAKE_USERNAME);
                    if (this.sz && !this.sz.isNull()) this.sz.writeU32(FAKE_USERNAME.length + 1);
                    retval.replace(ptr(1));
                    send({type: 'status', msg: '[AntiVM] GetUserNameW → ' + FAKE_USERNAME});
                }
            } catch(e) {}
        }
    });
}
var GetUserNameA = findExport('advapi32.dll', 'GetUserNameA');
if (GetUserNameA) {
    Interceptor.attach(GetUserNameA, {
        onEnter: function(args) { this.buf = args[0]; this.sz = args[1]; },
        onLeave: function(retval) {
            try {
                if (this.buf && !this.buf.isNull()) {
                    this.buf.writeUtf8String(FAKE_USERNAME);
                    if (this.sz && !this.sz.isNull()) this.sz.writeU32(FAKE_USERNAME.length + 1);
                    retval.replace(ptr(1));
                    send({type: 'status', msg: '[AntiVM] GetUserNameA → ' + FAKE_USERNAME});
                }
            } catch(e) {}
        }
    });
}
var GetUserNameExW = findExport('secur32.dll', 'GetUserNameExW')
                     || findExport('advapi32.dll', 'GetUserNameExW')
                     || findExport('sspicli.dll', 'GetUserNameExW');
if (GetUserNameExW) {
    Interceptor.attach(GetUserNameExW, {
        onEnter: function(args) {
            this.nameFormat = args[0].toInt32();
            this.buf = args[1];
            this.sz = args[2];
        },
        onLeave: function(retval) {
            try {
                if (this.buf && !this.buf.isNull()) {
                    var fake = fakeNameForFormat(this.nameFormat);
                    this.buf.writeUtf16String(fake);
                    if (this.sz && !this.sz.isNull()) this.sz.writeU32(fake.length + 1);
                    retval.replace(ptr(1));
                    send({type: 'status', msg: '[AntiVM] GetUserNameExW(' + this.nameFormat + ') → ' + fake});
                }
            } catch(e) {}
        }
    });
}
function fakeEnvUserNameW() {
    var GetEnvironmentVariableW = findExport('kernel32.dll', 'GetEnvironmentVariableW');
    if (GetEnvironmentVariableW) {
        Interceptor.attach(GetEnvironmentVariableW, {
            onEnter: function(args) {
                try { this.name = Memory.readUtf16String(args[0]); this.buf = args[1]; this.size = args[2].toInt32(); } catch(e) {}
            },
            onLeave: function(retval) {
                try {
                    if (this.name && this.name.toUpperCase() === 'USERNAME' && this.buf && !this.buf.isNull()) {
                        if (this.size >= FAKE_USERNAME.length + 1) {
                            this.buf.writeUtf16String(FAKE_USERNAME);
                            retval.replace(ptr(FAKE_USERNAME.length));
                            send({type: 'status', msg: '[AntiVM] env USERNAME → ' + FAKE_USERNAME});
                        }
                    }
                } catch(e) {}
            }
        });
    }
    var GetEnvironmentVariableA = findExport('kernel32.dll', 'GetEnvironmentVariableA');
    if (GetEnvironmentVariableA) {
        Interceptor.attach(GetEnvironmentVariableA, {
            onEnter: function(args) {
                try { this.name = Memory.readAnsiString(args[0]); this.buf = args[1]; this.size = args[2].toInt32(); } catch(e) {}
            },
            onLeave: function(retval) {
                try {
                    if (this.name && this.name.toUpperCase() === 'USERNAME' && this.buf && !this.buf.isNull()) {
                        if (this.size >= FAKE_USERNAME.length + 1) {
                            this.buf.writeUtf8String(FAKE_USERNAME);
                            retval.replace(ptr(FAKE_USERNAME.length));
                            send({type: 'status', msg: '[AntiVM] env USERNAME(A) → ' + FAKE_USERNAME});
                        }
                    }
                } catch(e) {}
            }
        });
    }
}
fakeEnvUserNameW();

send({type: 'status', msg: '[AntiVM] All bypass hooks active (VM 13项 + 七条件反沙箱环境模拟)'});
"""

# ===== 时间加速脚本 — 绕过 Sleep 精度/CPUID/RDTSC 反沙箱检测 =====
FRIDA_TIMEACCEL_SCRIPT = """
// 隐形时间加速 v3 — 绕过常见的反沙箱时间检测
var ACCEL_FACTOR = 0.001;  // 1000倍加速（仅用于长延迟）
var MIN_ACCEL_MS = 5000;   // 仅加速 >=5秒的 Sleep（短 Sleep 保持原样，绕过精度检测）
var FAKE_UPTIME_MS = 1800000; // 伪造30分钟运行时间（绕过 SHORT_UPTIME 检测）

var g_tickOffset = 0;
var g_tickInitialized = false;
var g_qpcBase = null;
var g_qpcTicks = null;

send({type: 'status', msg: '[TimeAccel] Stealth mode — min=' + MIN_ACCEL_MS + 'ms, uptime=' + (FAKE_UPTIME_MS/60000).toFixed(0) + 'min'});

// Export finder: Process module enumeration with cache
var _exportCache = {};
function _buildCache(dllName) { if (_exportCache[dllName]) return; _exportCache[dllName] = {}; var mod = null; try { if (typeof Process !== 'undefined' && typeof Process.getModuleByName === 'function') mod = Process.getModuleByName(dllName); } catch(e) {} if (!mod) try { if (typeof Process !== 'undefined' && typeof Process.findModuleByName === 'function') mod = Process.findModuleByName(dllName); } catch(e) {} if (!mod) return; try { var exps = mod.enumerateExports(); for (var i = 0; i < exps.length; i++) { _exportCache[dllName][exps[i].name] = exps[i].address; } } catch(e) {} }
function findExport(dllName, funcName) { _buildCache(dllName); var addr = _exportCache[dllName] && _exportCache[dllName][funcName]; if (addr) return addr; try { var r = new ApiResolver('module'); var m = r.enumerateMatches('exports:' + dllName + '!' + funcName); if (m.length > 0) return m[0].address; } catch(e) {} try { if (typeof DebugSymbol === 'object' && typeof DebugSymbol.getFunctionByName === 'function') { var a = DebugSymbol.getFunctionByName(funcName); if (a && !a.isNull()) return a; } } catch(e) {} return null; }

// ===== 辅助: 添加随机微抖动（模拟真实硬件时钟不精确） =====
function addJitter(val, pct) {
    var j = (Math.random() - 0.5) * 2 * pct * val;
    return Math.floor(val + j);
}

// === 1. kernel32!Sleep — 只加速长延迟 ===
var Sleep = findExport('kernel32.dll', 'Sleep');
if (Sleep) {
    Interceptor.attach(Sleep, {
        onEnter: function(args) {
            var ms = args[0].toInt32();
            if (ms > 0 && ms >= MIN_ACCEL_MS) {
                var newMs = Math.max(1, Math.floor(ms * ACCEL_FACTOR));
                send({type: 'status', msg: '[TimeAccel] Sleep ' + ms + 'ms → ' + newMs + 'ms'});
                args[0] = ptr(newMs);
            }
            // 短 Sleep(<5s) 原样通过，不触发精度检测
            if (ms > 0 && ms < MIN_ACCEL_MS) {
                send({type: 'status', msg: '[TimeAccel] Sleep ' + ms + 'ms — pass through (anti-precision-detect)'});
            }
        }
    });
}

// === 2. kernel32!SleepEx ===
var SleepEx = findExport('kernel32.dll', 'SleepEx');
if (SleepEx) {
    Interceptor.attach(SleepEx, {
        onEnter: function(args) {
            var ms = args[0].toInt32();
            if (ms > 0 && ms >= MIN_ACCEL_MS) {
                var newMs = Math.max(1, Math.floor(ms * ACCEL_FACTOR));
                send({type: 'status', msg: '[TimeAccel] SleepEx ' + ms + 'ms → ' + newMs + 'ms'});
                args[0] = ptr(newMs);
            }
        }
    });
}

// === 3. ntdll!NtDelayExecution — 只加速长延迟 ===
var NtDelayExecution = findExport('ntdll.dll', 'NtDelayExecution');
if (NtDelayExecution) {
    Interceptor.attach(NtDelayExecution, {
        onEnter: function(args) {
            try {
                var interval = args[1];
                if (!interval.isNull()) {
                    var delay = interval.readS64();
                    var delayMs = -delay / 10000;  // -100ns → ms
                    if (delay < 0 && delayMs >= MIN_ACCEL_MS) {
                        var newDelay = Math.floor(delay * ACCEL_FACTOR);
                        if (newDelay > -1) newDelay = -1;
                        interval.writeS64(newDelay);
                        send({type: 'status', msg: '[TimeAccel] NtDelayExecution ' + delayMs.toFixed(0) + 'ms → ' + (-newDelay/10000).toFixed(0) + 'ms'});
                    }
                }
            } catch(e) {}
        },
        onLeave: function(retval) {}
    });
}

// === 4. kernel32!WaitForSingleObject ===
var WaitForSingleObject = findExport('kernel32.dll', 'WaitForSingleObject');
if (WaitForSingleObject) {
    Interceptor.attach(WaitForSingleObject, {
        onEnter: function(args) {
            var ms = args[1].toInt32();
            if (ms >= MIN_ACCEL_MS && ms !== 0xFFFFFFFF) {
                var newMs = Math.max(1, Math.floor(ms * ACCEL_FACTOR));
                send({type: 'status', msg: '[TimeAccel] WaitForSingleObject ' + ms + 'ms → ' + newMs + 'ms'});
                args[1] = ptr(newMs);
            }
        }
    });
}

// === 5. kernel32!WaitForMultipleObjects ===
var WaitForMultipleObjects = findExport('kernel32.dll', 'WaitForMultipleObjects');
if (WaitForMultipleObjects) {
    Interceptor.attach(WaitForMultipleObjects, {
        onEnter: function(args) {
            var ms = args[2].toInt32();
            if (ms >= MIN_ACCEL_MS && ms !== 0xFFFFFFFF) {
                var newMs = Math.max(1, Math.floor(ms * ACCEL_FACTOR));
                send({type: 'status', msg: '[TimeAccel] WaitForMultipleObjects ' + ms + 'ms → ' + newMs + 'ms'});
                args[2] = ptr(newMs);
            }
        }
    });
}

// === 6. kernel32!GetTickCount — 伪造运行时间，不加速流速 ===
var GetTickCount = findExport('kernel32.dll', 'GetTickCount');
if (GetTickCount) {
    Interceptor.attach(GetTickCount, {
        onEnter: function(args) {
            if (!g_tickInitialized) {
                g_tickOffset = FAKE_UPTIME_MS;
                g_tickInitialized = true;
                send({type: 'status', msg: '[TimeAccel] GetTickCount offset=' + g_tickOffset + 'ms (fake uptime)'});
            }
        },
        onLeave: function(retval) {
            var raw = retval.toUInt32();
            var fake = (raw + g_tickOffset) >>> 0;  // 32位无符号回绕, 防溢出成负数
            // 添加微小抖动（±0.1%），模拟真实硬件 RTC 不精确
            fake = addJitter(fake, 0.001);
            retval.replace(ptr(fake >>> 0));
        }
    });
}

// === 7. kernel32!GetTickCount64 — 64位处理（toInt32 会截断溢出, 已修复） ===
var GetTickCount64 = findExport('kernel32.dll', 'GetTickCount64');
if (GetTickCount64) {
    Interceptor.attach(GetTickCount64, {
        onEnter: function(args) {
            if (!g_tickInitialized) {
                g_tickOffset = FAKE_UPTIME_MS;
                g_tickInitialized = true;
            }
        },
        onLeave: function(retval) {
            var raw = retval.toUInt64().toNumber();  // 完整 64 位运行时间
            var fake = raw + g_tickOffset;
            fake = addJitter(fake, 0.001);
            retval.replace(ptr(fake));
        }
    });
}

// === 8. kernel32!QueryPerformanceCounter — 保持真实流速（不触发Sleep精度检测） ===
var QueryPerformanceCounter = findExport('kernel32.dll', 'QueryPerformanceCounter');
if (QueryPerformanceCounter) {
    Interceptor.attach(QueryPerformanceCounter, {
        onEnter: function(args) {
            // 不修改返回值 — 让 Sleep 精度检测通过（短 Sleep + 真实 QPC = 匹配）
        },
        onLeave: function(retval) {
            // 微抖动（±0.05%），避免过于精确的时钟暴露 VM
            try {
                var outPtr = this.context.rdx || this.context.edx; // 第二个参数
                if (outPtr && !outPtr.isNull()) {
                    var raw = outPtr.readU64();
                    var jittered = addJitter(raw, 0.0005);
                    if (jittered !== raw) {
                        outPtr.writeU64(jittered);
                    }
                }
            } catch(e) {}
        }
    });
    send({type: 'status', msg: '[TimeAccel] QPC: pass-through + micro-jitter (anti-RDTSC-jitter detection)'});
}

// === 9. kernel32!QueryPerformanceFrequency — 不变 ===
var QueryPerformanceFrequency = findExport('kernel32.dll', 'QueryPerformanceFrequency');
if (QueryPerformanceFrequency) {
    Interceptor.attach(QueryPerformanceFrequency, {
        onLeave: function(retval) {
            // 不修改 — 让频率保持真实 (10MHz on most systems)
        }
    });
}

send({type: 'status', msg: '[TimeAccel] Stealth mode active — 9 APIs hooked, Sleep precision/CPUID overhead/RDTSC jitter bypassed'});
"""

# ===== 强制拦截关机/重启/休眠 — 防止恶意样本通过关机逃避动态分析 =====
FRIDA_SHUTDOWN_BLOCK_SCRIPT = """
var _exportCache = {};
function _buildCache(dllName) { if (_exportCache[dllName]) return; _exportCache[dllName] = {}; var mod = null; try { if (typeof Process !== 'undefined' && typeof Process.getModuleByName === 'function') mod = Process.getModuleByName(dllName); } catch(e) {} if (!mod) try { if (typeof Process !== 'undefined' && typeof Process.findModuleByName === 'function') mod = Process.findModuleByName(dllName); } catch(e) {} if (!mod) return; try { var exps = mod.enumerateExports(); for (var i = 0; i < exps.length; i++) { _exportCache[dllName][exps[i].name] = exps[i].address; } } catch(e) {} }
function findExport(dllName, funcName) { _buildCache(dllName); var addr = _exportCache[dllName] && _exportCache[dllName][funcName]; if (addr) return addr; try { var r = new ApiResolver('module'); var m = r.enumerateMatches('exports:' + dllName + '!' + funcName); if (m.length > 0) return m[0].address; } catch(e) {} try { if (typeof DebugSymbol === 'object' && typeof DebugSymbol.getFunctionByName === 'function') { var a = DebugSymbol.getFunctionByName(funcName); if (a && !a.isNull()) return a; } } catch(e) {} return null; }

var blocked = [];

function logAndBlock(api, detail) {
    var evt = {api: api, detail: detail};
    blocked.push(evt);
    send({type: 'status', msg: '[ShutdownBlock] ' + api + ' blocked (' + detail + ')'});
    // 每拦截一次立即上报增量事件 — 旧实现只在脚本加载瞬间发送空数组, 导致报告侧永远拿不到拦截记录
    send({type: 'shutdown_blocked', blocked: [evt]});
}

// ====================================================================
// 1. user32!ExitWindowsEx — 改 flags 为无效值阻止所有操作
// ====================================================================
var ExitWindowsEx = findExport('user32.dll', 'ExitWindowsEx');
if (ExitWindowsEx) {
    Interceptor.attach(ExitWindowsEx, {
        onEnter: function(args) {
            var flags = args[0].toInt32();
            logAndBlock('ExitWindowsEx', 'flags=0x' + flags.toString(16));
            args[0] = ptr(0xFFFFFFFF);
        },
        onLeave: function(retval) {
            retval.replace(ptr(1));
        }
    });
}

// ====================================================================
// 2. advapi32!InitiateSystemShutdownExW — 设空机器名阻止
// ====================================================================
var InitiateSystemShutdownExW = findExport('advapi32.dll', 'InitiateSystemShutdownExW');
if (InitiateSystemShutdownExW) {
    Interceptor.attach(InitiateSystemShutdownExW, {
        onEnter: function(args) {
            var machine = args[0].isNull() ? '(local)' : args[0].readUtf16String();
            logAndBlock('InitiateSystemShutdownExW', 'machine=' + machine);
            args[0] = ptr(0);
        },
        onLeave: function(retval) {
            retval.replace(ptr(1));
        }
    });
}

// ====================================================================
// 3. advapi32!InitiateSystemShutdownW — 设空机器名阻止
// ====================================================================
var InitiateSystemShutdownW = findExport('advapi32.dll', 'InitiateSystemShutdownW');
if (InitiateSystemShutdownW) {
    Interceptor.attach(InitiateSystemShutdownW, {
        onEnter: function(args) {
            logAndBlock('InitiateSystemShutdownW', 'blocked');
            args[0] = ptr(0);
        },
        onLeave: function(retval) {
            retval.replace(ptr(1));
        }
    });
}

// ====================================================================
// 4. ntdll!NtShutdownSystem — 改 action 为无效值
// ====================================================================
var NtShutdownSystem = findExport('ntdll.dll', 'NtShutdownSystem');
if (NtShutdownSystem) {
    Interceptor.attach(NtShutdownSystem, {
        onEnter: function(args) {
            var action = args[0].toInt32();
            logAndBlock('NtShutdownSystem', 'action=' + action);
            args[0] = ptr(0xFFFFFFFF);
        }
    });
}

// ====================================================================
// 5. kernel32!SetSystemPowerState — 设 fSuspend=FALSE, fForce=FALSE
// ====================================================================
var SetSystemPowerState = findExport('kernel32.dll', 'SetSystemPowerState');
if (SetSystemPowerState) {
    Interceptor.attach(SetSystemPowerState, {
        onEnter: function(args) {
            logAndBlock('SetSystemPowerState', 'blocked');
            args[0] = ptr(0);
            args[1] = ptr(0);
        },
        onLeave: function(retval) {
            retval.replace(ptr(1));
        }
    });
}

// ====================================================================
// 6. ntdll!NtRaiseHardError — 改 ResponseOption=OptionOk 阻止 BSOD
//    签名: NtRaiseHardError(ErrorStatus, NumParams, ParamMask, Params*, ResponseOption, Response*)
//    args[4]=ResponseOption (改为OptionOk=1), args[5]=Response* (预填ResponseOk=1)
// ====================================================================
var NtRaiseHardError = findExport('ntdll.dll', 'NtRaiseHardError');
if (NtRaiseHardError) {
    Interceptor.attach(NtRaiseHardError, {
        onEnter: function(args) {
            var status = args[0].toInt32();
            var option = args[4].toInt32();
            var opts = {0:'OptionAbortRetryIgnore',1:'OptionOk',2:'OptionOkCancel',3:'OptionRetryCancel',
                        4:'OptionYesNo',5:'OptionYesNoCancel',6:'OptionShutdownSystem'};
            logAndBlock('NtRaiseHardError', 'NTSTATUS=0x' + status.toString(16) + ' option=' + (opts[option]||option));
            args[4] = ptr(1);
        },
        onLeave: function(retval) {
            retval.replace(ptr(0));
        }
    });
}

// ====================================================================
// 7. ntdll!RtlAdjustPrivilege — 强制设 Enable=FALSE 阻止提权
//    签名: RtlAdjustPrivilege(Privilege, Enable, CurrentThread, *Enabled)
// ====================================================================
var RtlAdjustPrivilege = findExport('ntdll.dll', 'RtlAdjustPrivilege');
if (RtlAdjustPrivilege) {
    Interceptor.attach(RtlAdjustPrivilege, {
        onEnter: function(args) {
            var priv = args[0].toInt32();
            var priv_names = {19:'SeShutdownPrivilege',20:'SeDebugPrivilege',24:'SeLoadDriverPrivilege'};
            var name = priv_names[priv] || ('Privilege(' + priv + ')');
            var enable = args[1].toInt32() ? 'ENABLE' : 'DISABLE';
            if (args[1].toInt32()) {
                logAndBlock('RtlAdjustPrivilege', name + ' ' + enable + ' -> forced DISABLE');
                args[1] = ptr(0);
            }
        }
    });
}

// ====================================================================
// 8. ntdll!NtLoadDriver — UNICODE_STRING Buffer 在偏移 8 处，修改为空串
//    UNICODE_STRING { USHORT Length(2) + USHORT MaxLength(2) + pad(4) + PWSTR Buffer(8) }
// ====================================================================
var NtLoadDriver = findExport('ntdll.dll', 'NtLoadDriver');
if (NtLoadDriver) {
    Interceptor.attach(NtLoadDriver, {
        onEnter: function(args) {
            var bufOff = (Process.pointerSize === 8) ? 8 : 4;  // UNICODE_STRING.Buffer 偏移按架构
            var bufPtr = args[0].add(bufOff).readPointer();
            var name = '(null)';
            try { if (bufPtr && !bufPtr.isNull()) name = bufPtr.readUtf16String(); } catch(e) {}
            logAndBlock('NtLoadDriver', name);
            var empty = Memory.allocUtf16String('');
            args[0].writeU16(0);
            args[0].add(2).writeU16(0);
            args[0].add(bufOff).writePointer(empty);
        },
        onLeave: function(retval) {
            retval.replace(ptr(0xC0000034));
        }
    });
}

// ====================================================================
// 9. ntdll!NtSetSystemInformation — block SystemShutdownInformation(class=57)
// ====================================================================
var NtSetSystemInformation = findExport('ntdll.dll', 'NtSetSystemInformation');
if (NtSetSystemInformation) {
    Interceptor.attach(NtSetSystemInformation, {
        onEnter: function(args) {
            this._infoClass = args[0].toInt32();
            if (this._infoClass === 57) {
                logAndBlock('NtSetSystemInformation', 'SystemShutdownInformation');
            }
        },
        onLeave: function(retval) {
            if (this._infoClass === 57) {
                retval.replace(ptr(0));
            }
        }
    });
}

// ====================================================================
// 10. advapi32!CreateServiceW — 检测到 .sys 驱动路径时返回无效句柄
//     签名: CreateServiceW(hSCManager, lpSvcName, lpDisplayName, dwAccess, dwType,
//                          dwStart, dwErrCtrl, lpBinPath, lpOrderGroup, lpdwTagId,
//                          lpDeps, lpSvcStartName, lpPassword)
// ====================================================================
var CreateServiceW = findExport('advapi32.dll', 'CreateServiceW');
if (CreateServiceW) {
    Interceptor.attach(CreateServiceW, {
        onEnter: function(args) {
            var svcName = '(null)';
            try { if (!args[1].isNull()) svcName = args[1].readUtf16String(); } catch(e) {}
            var binPath = '(null)';
            try { if (!args[7].isNull()) binPath = args[7].readUtf16String(); } catch(e) {}
            if (binPath.toLowerCase().indexOf('.sys') !== -1 || svcName.toLowerCase().indexOf('driver') !== -1) {
                logAndBlock('CreateServiceW', svcName + ' -> ' + binPath);
                this._block = true;
            }
        },
        onLeave: function(retval) {
            if (this._block) {
                retval.replace(ptr(0));
            }
        }
    });
}

// ====================================================================
// 11. advapi32!StartServiceW — 阻止所有服务启动
//      签名: StartServiceW(hService, dwNumArgs, *lpArgVectors)
// ====================================================================
var StartServiceW = findExport('advapi32.dll', 'StartServiceW');
if (StartServiceW) {
    Interceptor.attach(StartServiceW, {
        onEnter: function(args) {
            logAndBlock('StartServiceW', 'all service starts blocked');
        },
        onLeave: function(retval) {
            retval.replace(ptr(0));
        }
    });
}

// ====================================================================
// 12. ntdll!NtSetInformationProcess — 阻止设 ProcessBreakOnTermination(29)
//     签名: NtSetInformationProcess(hProcess, infoClass, infoBuffer, infoLength)
// ====================================================================
var NtSetInformationProcess = findExport('ntdll.dll', 'NtSetInformationProcess');
if (NtSetInformationProcess) {
    Interceptor.attach(NtSetInformationProcess, {
        onEnter: function(args) {
            this._infoClass = args[1].toInt32();
            if (this._infoClass === 29) {
                this._blocked = true;
                logAndBlock('NtSetInformationProcess', 'ProcessBreakOnTermination blocked');
            }
        },
        onLeave: function(retval) {
            if (this._blocked) {
                retval.replace(ptr(0));
            }
        }
    });
}

send({type: 'status', msg: '[ShutdownBlock] 12 APIs hooked — all shutdown/reboot/BSOD/driver/privilege/critical-process vectors blocked'});
"""

# ===== 内存保护监控脚本 — 云沙箱对照补强 =====
# 检测: RW→RX 内存保护转换(载荷解密执行) / 远程RWX分配 / 远程注入链 /
#       进程枚举频率(反沙箱) / Sleep总量(时间规避)
FRIDA_MEMPROT_SCRIPT = """
send({type: 'status', msg: 'Memory-protect monitor loaded'});

var _apiResolver = null;
try { _apiResolver = new ApiResolver('module'); } catch(e) {}
function findExport(dllName, funcName) {
    if (_apiResolver) {
        try {
            var matches = _apiResolver.enumerateMatches('exports:' + dllName + '!' + funcName);
            if (matches.length > 0) return matches[0].address;
        } catch(e) {}
    }
    try {
        if (typeof Module.findExportByName === 'function') {
            var addr = Module.findExportByName(dllName, funcName);
            if (addr && !addr.isNull()) return addr;
        }
    } catch(e) {}
    // 大小写兜底: ApiResolver/Module API 对模块名大小写敏感
    // (kernel32.dll vs KERNEL32.DLL), 枚举实际加载的模块名重试
    try {
        var mods = Process.enumerateModules();
        var lower = dllName.toLowerCase();
        for (var mi = 0; mi < mods.length; mi++) {
            if (mods[mi].name.toLowerCase() === lower) {
                try {
                    if (_apiResolver) {
                        var ms2 = _apiResolver.enumerateMatches('exports:' + mods[mi].name + '!' + funcName);
                        if (ms2.length > 0) return ms2[0].address;
                    }
                } catch(e) {}
                try {
                    var exps = mods[mi].enumerateExports();
                    for (var ei = 0; ei < exps.length; ei++) {
                        if (exps[ei].name === funcName) return exps[ei].address;
                    }
                } catch(e) {}
                break;
            }
        }
    } catch(e) {}
    return null;
}

function protName(p) {
    var names = {1:'NOACCESS',2:'READONLY',4:'READWRITE',8:'WRITECOPY',16:'EXECUTE',32:'EXECUTE_READ',64:'EXECUTE_READWRITE',128:'EXECUTE_WRITECOPY'};
    if (names[p] !== undefined) return names[p];
    // 组合保护位 (如 0xE8 = EXECUTE_WRITECOPY|EXECUTE_READWRITE|EXECUTE_READ|WRITECOPY)
    var parts = [];
    if (p & 0x80) parts.push('EXECUTE_WRITECOPY'); else if (p & 0x40) parts.push('EXECUTE_READWRITE'); else if (p & 0x20) parts.push('EXECUTE_READ'); else if (p & 0x10) parts.push('EXECUTE');
    if (p & 0x08) parts.push('WRITECOPY'); else if (p & 0x04) parts.push('READWRITE'); else if (p & 0x02) parts.push('READONLY'); else if (p & 0x01) parts.push('NOACCESS');
    return parts.length ? parts.join('|') : ('0x' + p.toString(16));
}
function protFullName(p) {
    var s = protName(p & 0xFF);
    if (p & 0x100) s += '+GUARD';
    if (p & 0x200) s += '+NOCACHE';
    if (p & 0x400) s += '+WRITECOMBINE';
    return s;
}
function isExec(p) { return (p & 0xF0) !== 0; }
// 可写判定: READWRITE(0x04)/WRITECOPY(0x08), 以及本身即“可写可执行”的
// EXECUTE_READWRITE(0x40)/EXECUTE_WRITECOPY(0x80) — 后两者没有单独的 WRITE 位,
// 但正是 DEP 绕过/RWX 分配的核心标志 (云沙箱样本 protection=0x400080E8)。
function isWrite(p) { return (p & 0x0C) !== 0 || (p & 0x40) !== 0 || (p & 0x80) !== 0; }

// 读取原生 SIZE_T (32/64位进程自适应), 返回十进制字符串避免 JS 32位截断
function readNativeSize(ptr) {
    try {
        if (ptr === null || ptr.isNull()) return '0';
        if (Process.pointerSize === 8) return ptr.readU64().toString(10);
        return ptr.readU32().toString();
    } catch(e) { return '0'; }
}

// DEP绕过阈值: RWX 分配本身即绕过数据执行保护 (JIT除外, 单独计分);
// >=64MB 的 RWX 分配视为 ROP/Shellcode 喷射; >=256MB 分配视为内存喷射。
var DEP_HUGE_RWX = 0x4000000;   // 64MB
var MEMSPRAY_SIZE = 0x10000000; // 256MB

var sleepTotalMs = 0;
var enumSnapshotCount = 0;
var MEM_EVENTS = [];

function sendMem(api, base, size, oldProt, newProt) {
    var oldE = isExec(oldProt), newE = isExec(newProt);
    var oldW = isWrite(oldProt), newW = isWrite(newProt);
    var rw_to_rx = (!oldE && oldW) && (newE && !newW);
    var rwx_new = newE && newW;
    var page_guard = (newProt & 0x100) !== 0;
    var guard_exec = page_guard && newE;
    if (!rw_to_rx && !rwx_new && !page_guard && oldE === newE) return;  // 无意义转换跳过
    var evt = {type: 'memprot', api: api, base: base, size: size,
               old_prot: protName(oldProt), new_prot: protName(newProt),
               rw_to_rx: rw_to_rx, rwx_alloc: rwx_new,
               page_guard: page_guard, guard_exec: guard_exec};
    MEM_EVENTS.push(evt);
    send(evt);
}

// === 1. NtProtectVirtualMemory — RW→RX 核心 ===
var NtProtectVM = findExport('ntdll.dll', 'NtProtectVirtualMemory');
if (NtProtectVM) {
    Interceptor.attach(NtProtectVM, {
        onEnter: function(args) {
            try {
                this.base = args[1].readPointer().toString();
                this.size = args[2].readPointer().toString(10);
                this.newProt = args[3].toInt32();
            } catch(e) {}
        },
        onLeave: function(retval) {
            try {
                if (retval.toInt32() !== 0) return;
                var oldProt = args[4].readU32();
                sendMem('NtProtectVirtualMemory', this.base, this.size, oldProt, this.newProt);
            } catch(e) {}
        }
    });
}

// === 2. kernel32!VirtualProtect ===
var VirtualProtect = findExport('kernel32.dll', 'VirtualProtect');
if (VirtualProtect) {
    Interceptor.attach(VirtualProtect, {
        onEnter: function(args) {
            try {
                this.base = args[0].toString();
                this.size = args[1].toInt32();
                this.newProt = args[2].toInt32() & 0xFF;
            } catch(e) {}
        },
        onLeave: function(retval) {
            try {
                if (retval.toInt32() === 0) return;
                var oldProt = args[3].readU32();
                sendMem('VirtualProtect', this.base, this.size, oldProt, this.newProt);
            } catch(e) {}
        }
    });
}

// === 3. VirtualProtectEx — 远程进程保护修改(注入特征) ===
var VirtualProtectEx = findExport('kernel32.dll', 'VirtualProtectEx');
if (VirtualProtectEx) {
    Interceptor.attach(VirtualProtectEx, {
        onEnter: function(args) {
            try {
                this.hproc = args[0].toString();
                this.base = args[1].toString();
                this.size = args[2].toInt32();
                this.newProt = args[3].toInt32() & 0xFF;
            } catch(e) {}
        },
        onLeave: function(retval) {
            try {
                if (retval.toInt32() === 0) return;
                var oldProt = args[4].readU32();
                sendMem('VirtualProtectEx(remote)', this.base, this.size, oldProt, this.newProt);
            } catch(e) {}
        }
    });
}

// === 4. NtAllocateVirtualMemory — RWX 分配 / DEP绕过 / ROP喷射 ===
// ⚠ 参数顺序: (ProcessHandle, BaseAddress*, ZeroBits, RegionSize*,
//               AllocationType, Protect) — Protect 是 args[5], 不是 args[4]!
// 旧版误读 AllocationType 低字节为保护属性, 导致 RWX 分配全部漏检。
var NtAllocVM = findExport('ntdll.dll', 'NtAllocateVirtualMemory');
if (NtAllocVM) {
    Interceptor.attach(NtAllocVM, {
        onEnter: function(args) {
            try {
                this.basePtr = args[1];
                this.sizeStr = readNativeSize(args[3]);
                this.allocType = args[4].toInt32() >>> 0;
                this.protectFull = args[5].toInt32() >>> 0;
            } catch(e) {}
        },
        onLeave: function(retval) {
            try {
                var protectFull = this.protectFull || 0;
                var lowProt = protectFull & 0xFF;
                var sizeNum = parseInt(this.sizeStr || '0', 10) || 0;
                var rwx = isExec(lowProt) && isWrite(lowProt);
                var huge = sizeNum >= MEMSPRAY_SIZE;
                if (!rwx && !huge) return;  // 普通分配忽略, 避免洪泛

                var base = '?';
                try { base = this.basePtr.readPointer().toString(); } catch(e) {}

                var evt = {
                    type: 'memprot', api: 'NtAllocateVirtualMemory',
                    base: base, size: this.sizeStr,
                    old_prot: '-', new_prot: protFullName(protectFull),
                    protection: '0x' + protectFull.toString(16),
                    allocation_type: '0x' + (this.allocType || 0).toString(16),
                    status: retval.toInt32(),
                    rw_to_rx: false, rwx_alloc: rwx,
                    dep_bypass: rwx,
                    rop_like: rwx && sizeNum >= DEP_HUGE_RWX,
                    huge_alloc: huge, injection: false
                };
                MEM_EVENTS.push(evt);
                send(evt);
            } catch(e) {}
        }
    });
}

// === 5. VirtualAllocEx — 远程 RWX 分配(注入前置) ===
// ⚠ 参数顺序: (hProcess, lpAddress, dwSize, flAllocationType, flProtect)
// Protect 是 args[4], 不是 args[3]!
var VirtualAllocEx = findExport('kernel32.dll', 'VirtualAllocEx');
if (VirtualAllocEx) {
    Interceptor.attach(VirtualAllocEx, {
        onEnter: function(args) {
            try {
                var protectFull = args[4].toInt32() >>> 0;
                var protect = protectFull & 0xFF;
                var sizeNum = parseInt(args[2].toString(10), 10) || 0;
                var rwx = isExec(protect) && isWrite(protect);
                var huge = sizeNum >= MEMSPRAY_SIZE;
                if (!rwx && !huge) return;
                var evt = {
                    type: 'memprot', api: 'VirtualAllocEx(remote)', base: args[1].toString(),
                    size: args[2].toString(10), old_prot: '-', new_prot: protFullName(protectFull),
                    protection: '0x' + protectFull.toString(16),
                    allocation_type: '0x' + (args[3].toInt32() >>> 0).toString(16),
                    rw_to_rx: false, rwx_alloc: rwx,
                    dep_bypass: rwx,
                    rop_like: rwx && sizeNum >= DEP_HUGE_RWX,
                    huge_alloc: huge, injection: true
                };
                MEM_EVENTS.push(evt);
                send(evt);
            } catch(e) {}
        }
    });
}

// === 6. 远程注入链: WriteProcessMemory + CreateRemoteThread ===
var WPM = findExport('kernel32.dll', 'WriteProcessMemory');
if (WPM) {
    Interceptor.attach(WPM, {
        onEnter: function(args) {
            try {
                send({type: 'memprot', api: 'WriteProcessMemory(remote)', base: args[1].toString(),
                      size: args[2].toInt32(), old_prot: '-', new_prot: '-',
                      rw_to_rx: false, rwx_alloc: false, injection: true});
            } catch(e) {}
        }
    });
}
var CRT = findExport('kernel32.dll', 'CreateRemoteThread');
if (CRT) {
    Interceptor.attach(CRT, {
        onEnter: function(args) {
            try {
                send({type: 'memprot', api: 'CreateRemoteThread(remote)', base: args[2].toString(),
                      size: 0, old_prot: '-', new_prot: '-',
                      rw_to_rx: false, rwx_alloc: false, injection: true});
            } catch(e) {}
        }
    });
}

// === 7. CreateToolhelp32Snapshot — 进程枚举频率(反沙箱) ===
var CT32 = findExport('kernel32.dll', 'CreateToolhelp32Snapshot');
if (CT32) {
    Interceptor.attach(CT32, {
        onEnter: function(args) {
            try {
                if ((args[0].toInt32() & 2) !== 0) {  // TH32CS_SNAPPROCESS
                    enumSnapshotCount++;
                    if (enumSnapshotCount <= 5 || enumSnapshotCount % 10 === 0) {
                        send({type: 'status', msg: '[EnumProc] CreateToolhelp32Snapshot x' + enumSnapshotCount});
                    }
                }
            } catch(e) {}
        }
    });
}

// === 8. Sleep 总量统计(时间规避) ===
function hookSleepAccumulate(name, getMs) {
    var addr = findExport('kernel32.dll', name);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            try {
                var ms = getMs(args);
                if (ms > 0) sleepTotalMs += ms;
            } catch(e) {}
        }
    });
}
hookSleepAccumulate('Sleep', function(a) { return a[0].toInt32(); });
hookSleepAccumulate('SleepEx', function(a) { return a[0].toInt32(); });
var NtDelay = findExport('ntdll.dll', 'NtDelayExecution');
if (NtDelay) {
    Interceptor.attach(NtDelay, {
        onEnter: function(args) {
            try {
                var iv = args[1];
                if (!iv.isNull()) {
                    var d = iv.readS64();
                    if (d < 0) sleepTotalMs += (-d / 10000);
                }
            } catch(e) {}
        }
    });
}

// 定期上报统计
setInterval(function() {
    if (sleepTotalMs > 0 || enumSnapshotCount > 0) {
        send({type: 'memstat', sleep_total_ms: Math.round(sleepTotalMs), enum_snapshot_count: enumSnapshotCount});
    }
}, 5000);

send({type: 'status', msg: '[MemProt] 内存保护/注入/枚举/睡眠监控已加载'});



// ===== Anti-Frida Hardening =====
// Hide frida-agent from module enumeration (PEB Ldr)
try {
    var _origEnumerateModules = Process.enumerateModules;
    Process.enumerateModules = function() {
        var mods = _origEnumerateModules();
        return mods.filter(function(m) {
            return (m.name || "").toLowerCase().indexOf("frida") === -1;
        });
    };
} catch(e) {}

// Hide frida-agent from EnumProcessModules (psapi)
try {
    var _epmAddr = Module.getExportByName("psapi.dll", "EnumProcessModules");
    if (_epmAddr) {
        Interceptor.attach(_epmAddr, {
            onLeave: function(retval) {
                try {
                    var hProcess = args[0];
                    var lphModule = args[1];
                    var cb = args[2].toInt32();
                    var lpcbNeeded = args[3];
                    var bytesNeeded = lpcbNeeded.readU32();
                    var nModules = Math.min(Math.floor(cb / Process.pointerSize), Math.floor(bytesNeeded / Process.pointerSize));
                    var writePos = 0;
                    for (var i = 0; i < nModules; i++) {
                        var hMod = lphModule.add(i * Process.pointerSize).readPointer();
                        try {
                            var mName = Module.findModuleByAddress(hMod);
                            if (mName && (mName.name || "").toLowerCase().indexOf("frida") !== -1) {
                                var remaining = nModules - i - 1;
                                for (var j = 0; j < remaining; j++) {
                                    lphModule.add((i + j) * Process.pointerSize).writePointer(lphModule.add((i + j + 1) * Process.pointerSize).readPointer());
                                }
                                nModules--;
                                bytesNeeded -= Process.pointerSize;
                                lpcbNeeded.writeU32(bytesNeeded);
                                i--;
                            }
                        } catch(e2) {}
                    }
                } catch(e) {}
            }
        });
    }
} catch(e) {}

// Hide frida-server from NtQuerySystemInformation(SystemProcessInformation=5)
try {
    var _ntqsi = Module.getExportByName("ntdll.dll", "NtQuerySystemInformation");
    if (_ntqsi) {
        Interceptor.attach(_ntqsi, {
            onEnter: function(args) { this._sysClass = args[0].toUInt32(); this._buf = args[1]; },
            onLeave: function(retval) {
                try {
                    if (this._sysClass !== 5) return;
                    var buffer = this._buf;
                    var ptrSize = Process.pointerSize;
                    var nameOff = (ptrSize === 8) ? 0x38 : 0x28;
                    var offset = 0;
                    var prevEntry = null;
                    while (true) {
                        var entry = buffer.add(offset);
                        var nextOff = entry.readU32();
                        var nameStruct = entry.add(nameOff);
                        var nameLen = nameStruct.add(4).readU16();
                        if (nameLen > 0) {
                            var nameBuf = nameStruct.add(8).readUtf16String(nameLen / 2);
                            if (nameBuf && nameBuf.toLowerCase().indexOf("frida") !== -1) {
                                if (nextOff === 0) {
                                    if (prevEntry) prevEntry.writeU32(0);
                                    break;
                                } else {
                                    // compact: overwrite current with next
                                    var src2 = entry.add(nextOff);
                                    for (var bi = 0; bi < nextOff; bi++) {
                                        entry.add(bi).writeU8(src2.add(bi).readU8());
                                    }
                                    continue; // re-check same offset
                                }
                            }
                        }
                        if (nextOff === 0) break;
                        prevEntry = entry;
                        offset += nextOff;
                        if (offset > 1024 * 1024) break;
                    }
                } catch(e) {}
            }
        });
    }
} catch(e) {}
"""

# ===== DLL 调用监控 + API 欺骗脚本 =====
# 1) 动态 hook 样本加载的非系统 DLL 导出函数 — 监控"目标调用 DLL 干什么"
# 2) 假反馈: 对反调试/反分析 API 返回伪造的正常值, 让样本不触发环境检测,
#    暴露完整恶意行为 (云沙箱同款"欺骗"策略)
FRIDA_SPOOF_SCRIPT = """
send({type: 'status', msg: 'DLL-call monitor + API spoof loaded'});

var _apiResolver = null;
try { _apiResolver = new ApiResolver('module'); } catch(e) {}
function findExport(dllName, funcName) {
    if (_apiResolver) {
        try {
            var matches = _apiResolver.enumerateMatches('exports:' + dllName + '!' + funcName);
            if (matches.length > 0) return matches[0].address;
        } catch(e) {}
    }
    try {
        if (typeof Module.findExportByName === 'function') {
            var addr = Module.findExportByName(dllName, funcName);
            if (addr && !addr.isNull()) return addr;
        }
    } catch(e) {}
    // 大小写兜底: ApiResolver/Module API 对模块名大小写敏感
    // (kernel32.dll vs KERNEL32.DLL), 枚举实际加载的模块名重试
    try {
        var mods = Process.enumerateModules();
        var lower = dllName.toLowerCase();
        for (var mi = 0; mi < mods.length; mi++) {
            if (mods[mi].name.toLowerCase() === lower) {
                try {
                    if (_apiResolver) {
                        var ms2 = _apiResolver.enumerateMatches('exports:' + mods[mi].name + '!' + funcName);
                        if (ms2.length > 0) return ms2[0].address;
                    }
                } catch(e) {}
                try {
                    var exps = mods[mi].enumerateExports();
                    for (var ei = 0; ei < exps.length; ei++) {
                        if (exps[ei].name === funcName) return exps[ei].address;
                    }
                } catch(e) {}
                break;
            }
        }
    } catch(e) {}
    return null;
}

var dllCallTotal = 0;
var hookedModules = {};
var hookedFuncs = 0;

// 已由其他脚本 hook 的函数, 避免重复/冲突
var SKIP_FUNCS = {
    'VirtualAlloc':1,'VirtualAllocEx':1,'VirtualProtect':1,'VirtualProtectEx':1,
    'WriteProcessMemory':1,'ReadProcessMemory':1,'CreateRemoteThread':1,'VirtualFree':1,'VirtualFreeEx':1,
    'Sleep':1,'SleepEx':1,'NtDelayExecution':1,'WaitForSingleObject':1,'WaitForMultipleObjects':1,
    'GetTickCount':1,'GetTickCount64':1,'QueryPerformanceCounter':1,'QueryPerformanceFrequency':1,
    'CreateFileW':1,'CreateFileA':1,'WriteFile':1,'DeleteFileW':1,'DeleteFileA':1,
    'MoveFileW':1,'MoveFileExW':1,'CopyFileW':1,'CopyFileExW':1,'ReadFile':1,
    'SetFileAttributesW':1,'GetFileAttributesW':1,'SetFileTime':1,
    'CreateProcessW':1,'CreateProcessA':1,'WinExec':1,'TerminateProcess':1,'OpenProcess':1,
    'CreateThread':1,'ExitProcess':1,
    'LoadLibraryW':1,'LoadLibraryA':1,'LoadLibraryExW':1,'LoadLibraryExA':1,
    'GetProcAddress':1,'FreeLibrary':1,
    'SendInput':1,'mouse_event':1,'keybd_event':1,'MiniDumpWriteDump':1,
    'GetSystemInfo':1,'GetUserNameA':1,'GetUserNameW':1,'GetTimeZoneInformation':1,
    'CreateToolhelp32Snapshot':1,
    'RegOpenKeyExW':1,'NtOpenKey':1,'NtCreateFile':1,'RegQueryValueExW':1,
    'GetDiskFreeSpaceExW':1,'GetDiskFreeSpaceA':1,'GetDiskFreeSpaceW':1,
    'DeviceIoControl':1,'GetAdaptersInfo':1,'GetSystemFirmwareTable':1,
    'Process32FirstW':1,'Process32NextW':1,'GlobalMemoryStatusEx':1,
    'ExitWindowsEx':1,'InitiateSystemShutdownExW':1,'InitiateSystemShutdownW':1,
    'NtShutdownSystem':1,'SetSystemPowerState':1,'NtRaiseHardError':1,
    'RtlAdjustPrivilege':1,'NtLoadDriver':1,'NtSetSystemInformation':1,
    'CreateServiceW':1,'StartServiceW':1,'NtSetInformationProcess':1,
    'NtProtectVirtualMemory':1,'NtAllocateVirtualMemory':1
};

function isSystemModule(path) {
    if (!path) return true;
    var p = path.toLowerCase();
    if (p.indexOf('\\\\windows\\\\') !== -1) return true;
    if (p.indexOf('\\\\program files') !== -1) return true;
    return false;
}

function hookModuleExports(mod) {
    if (hookedModules[mod.name]) return;
    hookedModules[mod.name] = true;
    try {
        var exports = mod.enumerateExports();
        var count = 0;
        for (var i = 0; i < exports.length && count < 300; i++) {
            var exp = exports[i];
            if (exp.type !== 'function') continue;
            if (SKIP_FUNCS[exp.name]) continue;
            count++;
            hookedFuncs++;
            (function(dllName, funcName, addr) {
                try {
                    Interceptor.attach(addr, {
                        onEnter: function() {
                            dllCallTotal++;
                            send({type: 'dllcall', dll: dllName, func: funcName});
                        }
                    });
                } catch(e) {}
            })(mod.name, exp.name, exp.address);
        }
        if (count > 0) {
            send({type: 'status', msg: '[DLLWatch] hook ' + mod.name + ': ' + count + ' exports (累计 ' + hookedFuncs + ')'});
        }
    } catch(e) {}
}

// 初始枚举: hook 非系统 DLL (样本自身 + 释放的 DLL)
Process.enumerateModules().forEach(function(mod) {
    if (isSystemModule(mod.path)) return;
    hookModuleExports(mod);
});

// 动态加载的新 DLL: LoadLibrary 成功后延迟重新枚举
function rehookAfterLoad() {
    setTimeout(function() {
        try {
            ensureAmsiHooks();  // amsi.dll 可能此时才加载 (PowerShell/脚本引擎)
            Process.enumerateModules().forEach(function(mod) {
                if (isSystemModule(mod.path)) return;
                hookModuleExports(mod);
            });
        } catch(e) {}
    }, 150);
}
var LoadLibW = findExport('kernel32.dll', 'LoadLibraryW');
if (LoadLibW) {
    Interceptor.attach(LoadLibW, { onLeave: function(r) { if (!r.isNull()) rehookAfterLoad(); } });
}
var LoadLibA = findExport('kernel32.dll', 'LoadLibraryA');
if (LoadLibA) {
    Interceptor.attach(LoadLibA, { onLeave: function(r) { if (!r.isNull()) rehookAfterLoad(); } });
}
var LoadLibExW = findExport('kernel32.dll', 'LoadLibraryExW');
if (LoadLibExW) {
    Interceptor.attach(LoadLibExW, { onLeave: function(r) { if (!r.isNull()) rehookAfterLoad(); } });
}
var LoadLibExA = findExport('kernel32.dll', 'LoadLibraryExA');
if (LoadLibExA) {
    Interceptor.attach(LoadLibExA, { onLeave: function(r) { if (!r.isNull()) rehookAfterLoad(); } });
}

// ================= 假反馈 API (欺骗反分析) =================
var spoofCount = 0;
function logSpoof(name, detail) {
    spoofCount++;
    send({type: 'spoof', api: name, detail: detail || ''});
}

// 1. IsDebuggerPresent -> 0 (未调试)
var IsDbg = findExport('kernel32.dll', 'IsDebuggerPresent');
if (IsDbg) {
    Interceptor.replace(IsDbg, new NativeCallback(function() {
        logSpoof('IsDebuggerPresent', '返回 FALSE');
        return 0;
    }, 'int', []));
}

// 2. CheckRemoteDebuggerPresent -> FALSE
var ChkRemote = findExport('kernel32.dll', 'CheckRemoteDebuggerPresent');
if (ChkRemote) {
    Interceptor.attach(ChkRemote, {
        onEnter: function(args) {
            try { this.flagPtr = args[1]; } catch(e) {}
        },
        onLeave: function(retval) {
            try {
                if (retval.toInt32() !== 0 && this.flagPtr) {
                    this.flagPtr.writeU32(0);  // pbDebuggerPresent = FALSE
                    logSpoof('CheckRemoteDebuggerPresent', 'pbDebuggerPresent=FALSE');
                }
            } catch(e) {}
        }
    });
}

// 3. NtQueryInformationProcess — 反调试查询全部伪装
var NtQIP = findExport('ntdll.dll', 'NtQueryInformationProcess');
if (NtQIP) {
    Interceptor.attach(NtQIP, {
        onEnter: function(args) {
            try {
                this.class_ = args[1].toInt32();
                this.buf = args[2];
            } catch(e) {}
        },
        onLeave: function(retval) {
            try {
                if (retval.toInt32() !== 0) return;
                var cls = this.class_;
                // ProcessDebugPort(7) -> 0 | ProcessDebugObjectHandle(30) -> NULL | ProcessDebugFlags(31) -> 1
                if (cls === 7) {
                    this.buf.writeU32(0);
                    logSpoof('NtQueryInformationProcess', 'ProcessDebugPort=0');
                } else if (cls === 30) {
                    this.buf.writePointer(ptr(0));
                    logSpoof('NtQueryInformationProcess', 'DebugObjectHandle=NULL');
                } else if (cls === 31) {
                    this.buf.writeU32(1);
                    logSpoof('NtQueryInformationProcess', 'ProcessDebugFlags=1(未调试)');
                }
            } catch(e) {}
        }
    });
}

// 4. NtQuerySystemInformation — 内核调试器查询伪装
var NtQSI = findExport('ntdll.dll', 'NtQuerySystemInformation');
if (NtQSI) {
    Interceptor.attach(NtQSI, {
        onEnter: function(args) {
            try {
                this.cls = args[0].toInt32();
                this.buf = args[1];
            } catch(e) {}
        },
        onLeave: function(retval) {
            try {
                if (retval.toInt32() !== 0) return;
                // SystemKernelDebuggerInformation(35): [DebuggerEnabled, DebuggerNotPresent]
                if (this.cls === 35) {
                    this.buf.writeU8(0);       // DebuggerEnabled = FALSE
                    this.buf.add(1).writeU8(1); // DebuggerNotPresent = TRUE
                    logSpoof('NtQuerySystemInformation', 'KernelDebugger=FALSE');
                }
            } catch(e) {}
        }
    });
}

// 5. NtSetInformationThread ThreadHideFromDebugger(17) — 假装成功
var NtSIT = findExport('ntdll.dll', 'NtSetInformationThread');
if (NtSIT) {
    Interceptor.attach(NtSIT, {
        onEnter: function(args) {
            try {
                if (args[1].toInt32() === 17) {
                    this.hide = true;
                    logSpoof('NtSetInformationThread', 'ThreadHideFromDebugger 假装成功');
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            try {
                if (this.hide) retval.replace(0);  // STATUS_SUCCESS
            } catch(e) {}
        }
    });
}

// 6. 模拟真实用户活动 (GetCursorPos 周期性移动, 对抗无交互检测)
var lastMouseX = 400, lastMouseY = 300;
var GetCursorPos = findExport('user32.dll', 'GetCursorPos');
if (GetCursorPos) {
    Interceptor.attach(GetCursorPos, {
        onLeave: function(retval) {
            try {
                if (retval.toInt32() === 0) return;
                // 周期内轻微移动鼠标位置, 模拟真实用户
                var pt = args[0];
                lastMouseX = (lastMouseX + 3) % 1200 + 100;
                lastMouseY = (lastMouseY + 1) % 700 + 100;
                pt.writeS32(lastMouseX);
                pt.add(4).writeS32(lastMouseY);
                if (spoofCount % 50 === 1) {
                    logSpoof('GetCursorPos', '模拟鼠标位置 (' + lastMouseX + ',' + lastMouseY + ')');
                }
            } catch(e) {}
        }
    });
}

// 7. GetAsyncKeyState / GetKeyState — 返回 0 (无按键), 但允许正常调用
var GetAsyncKeyState = findExport('user32.dll', 'GetAsyncKeyState');
if (GetAsyncKeyState) {
    Interceptor.attach(GetAsyncKeyState, {
        onLeave: function(retval) { try { retval.replace(0); } catch(e) {} }
    });
}
var GetKeyState = findExport('user32.dll', 'GetKeyState');
if (GetKeyState) {
    Interceptor.attach(GetKeyState, {
        onLeave: function(retval) { try { retval.replace(0); } catch(e) {} }
    });
}

// 7b. GetTimeZoneInformation — 伪装为中国标准时间 (GMT+8)
var GetTimeZoneInfo = findExport('kernel32.dll', 'GetTimeZoneInformation');
if (GetTimeZoneInfo) {
    Interceptor.attach(GetTimeZoneInfo, {
        onLeave: function(retval) {
            try {
                if (retval.toInt32() === 0) return;
                var buf = this.buf;
                buf.writeS32(-480);
                buf.add(4).writeUtf16String('China Standard Time');
                buf.add(132).writeS32(0); buf.add(148).writeS32(0);
                buf.add(152).writeUtf16String('China Daylight Time');
                buf.add(280).writeS32(0); buf.add(296).writeS32(-60);
                retval.replace(0);
                logSpoof('GetTimeZoneInformation', '伪装 GMT+8 CST');
            } catch(e) {}
        },
        onEnter: function(args) { this.buf = args[0]; }
    });
}

// 7c. GetVolumeInformationW/A — 伪装卷序列号 (VM 默认序列号特征)
function spoofVolumeSerial(buf) {
    try {
        if (!buf || buf.isNull()) return;
        var serial = 0x5A3B2C1D;
        buf.writeU32(serial);
        logSpoof('GetVolumeInformation', '序列号伪装 0x' + serial.toString(16).toUpperCase());
    } catch(e) {}
}
var GetVolInfoW = findExport('kernel32.dll', 'GetVolumeInformationW');
if (GetVolInfoW) {
    Interceptor.attach(GetVolInfoW, {
        onEnter: function(args) { this.serialBuf = args[3]; },
        onLeave: function(retval) { try { if (retval.toInt32() !== 0) spoofVolumeSerial(this.serialBuf); } catch(e) {} }
    });
}
var GetVolInfoA = findExport('kernel32.dll', 'GetVolumeInformationA');
if (GetVolInfoA) {
    Interceptor.attach(GetVolInfoA, {
        onEnter: function(args) { this.serialBuf = args[3]; },
        onLeave: function(retval) { try { if (retval.toInt32() !== 0) spoofVolumeSerial(this.serialBuf); } catch(e) {} }
    });
}

// 7d. GetDriveTypeW/A — 将非 DRIVE_FIXED 伪装为固定磁盘 (隐藏 VM 共享文件夹/光驱)
var GetDriveTypeW = findExport('kernel32.dll', 'GetDriveTypeW');
if (GetDriveTypeW) {
    Interceptor.attach(GetDriveTypeW, {
        onLeave: function(retval) {
            try {
                var t = retval.toInt32();
                if (t !== 3) { retval.replace(3); logSpoof('GetDriveTypeW', t + '->DRIVE_FIXED'); }
            } catch(e) {}
        }
    });
}
var GetDriveTypeA = findExport('kernel32.dll', 'GetDriveTypeA');
if (GetDriveTypeA) {
    Interceptor.attach(GetDriveTypeA, {
        onLeave: function(retval) {
            try {
                var t = retval.toInt32();
                if (t !== 3) { retval.replace(3); logSpoof('GetDriveTypeA', t + '->DRIVE_FIXED'); }
            } catch(e) {}
        }
    });
}

// 8a. GetAdaptersAddresses — MAC 地址伪装 (现代 API)
var GetAdaptersAddresses = findExport('iphlpapi.dll', 'GetAdaptersAddresses');
if (GetAdaptersAddresses) {
    Interceptor.attach(GetAdaptersAddresses, {
        onEnter: function(args) { this.buf = args[1]; this.family = args[2].toInt32(); },
        onLeave: function(retval) {
            try {
                if (retval.toInt32() !== 0 || !this.buf || this.buf.isNull()) return;
                var structLen = this.buf.readU32();
                if (structLen < 400) return;
                var physOff = 16 + 8 * Process.pointerSize;
                var entry = this.buf;
                var count = 0;
                while (entry && !entry.isNull() && count < 20) {
                    var len = entry.readU32();
                    if (len < physOff + 36) break;
                    var addrLen = entry.add(physOff + 32).readU32();
                    if (addrLen === 6) {
                        entry.add(physOff).writeU8(0x00);
                        entry.add(physOff+1).writeU8(0x1A);
                        entry.add(physOff+2).writeU8(0x2B);
                        entry.add(physOff+3).writeU8(0x44);
                        entry.add(physOff+4).writeU8(0x55);
                        entry.add(physOff+5).writeU8(0x66);
                        count++;
                    }
                    var next = entry.add(8).readUSizeT();
                    if (next === 0) break;
                    entry = entry.add(next);
                }
                if (count > 0) logSpoof('GetAdaptersAddresses', 'MAC 伪装 ' + count + ' 个适配器');
            } catch(e) {}
        }
    });
}

// 8b. GetIfTable — MIB_IFTABLE MAC 伪装
var GetIfTable = findExport('iphlpapi.dll', 'GetIfTable');
if (GetIfTable) {
    Interceptor.attach(GetIfTable, {
        onEnter: function(args) { this.buf = args[0]; },
        onLeave: function(retval) {
            try {
                if (retval.toInt32() !== 0 || !this.buf || this.buf.isNull()) return;
                var numEntries = this.buf.readU32();
                if (numEntries === 0 || numEntries > 100) return;
                // MIB_IFROW: bPhysAddr at offset 532 (wszName 512 + 5 DWORDs=20)
                for (var i = 0; i < numEntries; i++) {
                    var row = this.buf.add(4 + i * 696);
                    try {
                        var addrLen = row.add(536).readU32();
                        if (addrLen === 6) {
                            row.add(532).writeU8(0x00);
                            row.add(533).writeU8(0x1A);
                            row.add(534).writeU8(0x2B);
                            row.add(535).writeU8(0x44);
                            row.add(536).writeU8(0x55);
                            row.add(537).writeU8(0x66);
                        }
                    } catch(e2) { break; }
                }
                logSpoof('GetIfTable', 'MAC 伪装 ' + numEntries + ' 行');
            } catch(e) {}
        }
    });
}

// 9. Sleep 不做假反馈 — 时间加速脚本已处理

// 定期上报 DLL 调用统计
setInterval(function() {
    send({type: 'dllstat', total: dllCallTotal, hooked_funcs: hookedFuncs});
}, 5000);

// === AMSI 监控 — 脚本型恶意载荷的扫描接口 (Win11 重点: PowerShell/JS/宏 载荷) ===
// AmsiScanBuffer(amsiContext, buffer, length, contentName, result) — 记录被扫描的数据
var AMSI_LOGGED = 0;
var amsiHooked = {buffer: false, string: false};

// Uint8Array -> Base64 (Frida JS 没有 btoa, 必须自带编码器)
function _arrayToB64(bytes) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var out = '';
    var len = bytes.length;
    for (var i = 0; i < len; i += 3) {
        var a = bytes[i];
        var b = (i + 1 < len) ? bytes[i + 1] : 0;
        var c = (i + 2 < len) ? bytes[i + 2] : 0;
        var n = (a << 16) | (b << 8) | c;
        out += chars[(n >> 18) & 63] + chars[(n >> 12) & 63];
        out += (i + 1 < len) ? chars[(n >> 6) & 63] : '=';
        out += (i + 2 < len) ? chars[n & 63] : '=';
    }
    return out;
}

function hookAmsi(exportName) {
    if (amsiHooked[exportName]) return false;
    var fn = findExport('amsi.dll', exportName);
    if (!fn) return false;
    try {
        Interceptor.attach(fn, {
            onEnter: function(args) {
                try {
                    if (AMSI_LOGGED >= 8) return;
                    // 读取扫描缓冲区前 512 字节 (base64)
                    var buf = args[1];
                    var len = args[2].toInt32();
                    if (buf.isNull() || len <= 0) return;
                    var n = Math.min(len, 512);
                    var bytes = buf.readByteArray(n);
                    var b64 = '';
                    if (bytes) b64 = _arrayToB64(new Uint8Array(bytes));
                    var cname = '';
                    try {
                        cname = args[3].readUtf16String() || args[3].readUtf8String() || '';
                    } catch(e) {}
                    send({type: 'amsi', api: exportName, len: len, preview: b64, content: cname});
                    AMSI_LOGGED++;
                } catch(e) {}
            }
        });
        amsiHooked[exportName] = true;
        return true;
    } catch(e) {
        return false;
    }
}
function ensureAmsiHooks() {
    try { hookAmsi('AmsiScanBuffer'); } catch(e) {}
    try { hookAmsi('AmsiScanString'); } catch(e) {}
}
ensureAmsiHooks();
// AmsiInitialize — 样本主动初始化 AMSI (PowerShell/脚本引擎在跑)
var AmsiInitialize = findExport('amsi.dll', 'AmsiInitialize');
if (AmsiInitialize) {
    Interceptor.attach(AmsiInitialize, {
        onEnter: function(args) {
            send({type: 'amsi_init', app: args[1].isNull() ? '' : args[1].readUtf16String()});
        }
    });
}
// AmsiUninitialize — 多次调用可疑 (绕过/卸载 AMSI)
var AmsiUninitialize = findExport('amsi.dll', 'AmsiUninitialize');
if (AmsiUninitialize) {
    Interceptor.attach(AmsiUninitialize, {
        onEnter: function(args) {
            send({type: 'amsi_uninit'});
        }
    });
}

// === AdjustTokenPrivileges — 检测 SeDebugPrivilege 启用 (提权/进程注入前置) ===
var AdjustTokenPrivilegesHook = findExport('advapi32.dll', 'AdjustTokenPrivileges');
if (AdjustTokenPrivilegesHook) {
    Interceptor.attach(AdjustTokenPrivilegesHook, {
        onEnter: function(args) {
            try {
                var newState = args[2];
                if (newState.isNull()) return;
                var count = newState.readU32();
                if (count > 32) return;
                for (var i = 0; i < count; i++) {
                    // TOKEN_PRIVILEGES: PrivilegeCount(4) 之后紧接 LUID_AND_ATTRIBUTES[12]
                    // 每条: LUID(8) + Attributes(4) — 首条 LUID 从偏移 4 开始 (不是 8!)
                    var ent = newState.add(4 + i * 12);
                    var low = ent.readU32();
                    var attrs = ent.add(8).readU32();
                    if (low === 20) {  // SeDebugPrivilege LUID=20
                        var act = (attrs & 2) ? 'ENABLED' : ((attrs & 1) ? 'attempt' : 'disabled');
                        send({type: 'priv', api: 'AdjustTokenPrivileges',
                              privilege: 'SeDebugPrivilege', action: act});
                    } else if (low === 17) {  // SeBackupPrivilege
                        var act2 = (attrs & 2) ? 'ENABLED' : 'attempt';
                        if (attrs & 2) send({type: 'priv', api: 'AdjustTokenPrivileges',
                                             privilege: 'SeBackupPrivilege', action: act2});
                    }
                }
            } catch(e) {}
        }
    });
}

// === RegSaveKey — 离线凭据窃取 (SAM/SYSTEM/SECURITY hive 复制) ===
var RegSaveKeyH = findExport('advapi32.dll', 'RegSaveKeyW');
if (!RegSaveKeyH) RegSaveKeyH = findExport('advapi32.dll', 'RegSaveKeyA');
if (!RegSaveKeyH) RegSaveKeyH = findExport('ntdll.dll', 'NtSaveKey');
if (RegSaveKeyH) {
    Interceptor.attach(RegSaveKeyH, {
        onEnter: function(args) {
            try {
                // RegSaveKey(hKey, lpFile, sa) — 文件路径在 args[1]
                var fname = '';
                try { fname = args[1].readUtf16String() || args[1].readUtf8String() || ''; } catch(e) {}
                send({type: 'regsave', file: fname || '(未知路径)', api: 'RegSaveKey/NtSaveKey'});
            } catch(e) {}
        }
    });
}
// reg.exe save 命令监控 (cmdline 检测)
var CreateProcessWRegSave = findExport('kernel32.dll', 'CreateProcessW');
if (CreateProcessWRegSave) {
    Interceptor.attach(CreateProcessWRegSave, {
        onEnter: function(args) {
            try {
                var cmd = args[0].readUtf16String() || '';
                if (/reg[ \t]+save|reg[.]exe[ \t]+save/i.test(cmd)) {                send({type: 'regsave', file: cmd.substring(0, 200), api: 'reg save'});
                }
            } catch(e) {}
        }
    });
}

send({type: 'status', msg: '[Spoof] 假反馈就绪: 反调试伪装/鼠标模拟/DLL调用监控/AMSI监控/特权监控/凭据保护'});
"""


class _SpawnedProcess:
    """Frida spawn 创建的挂起进程的轻量包装 — 兼容 subprocess.Popen 常用接口。

    dynamic.py 的 Sandbox.wait_process / kill_process 只使用 pid / wait / returncode，
    本包装提供这些属性/方法，使 spawn 路径与 Popen 路径共用同一套等待/清理逻辑。
    """

    def __init__(self, pid: int, cmd: list = None, device=None):
        self.pid = pid
        self.returncode = None
        self._cmd = list(cmd or [str(pid)])
        self._device = device
        # spawn 失败/中止时由 monitor_spawn 置位; wait() 立即返回, 避免空等满超时
        self._abort_event = threading.Event()

    def wait(self, timeout=None):
        """等待进程结束并设置 returncode；超时抛 subprocess.TimeoutExpired。

        若 spawn 侧已宣告失败(_abort_event), 立即返回 -1, 不再等待挂起进程。
        """
        import time as _time
        import psutil
        deadline = None if timeout is None else _time.time() + timeout
        while True:
            if self._abort_event.is_set():
                self.returncode = -1
                return self.returncode
            _remaining = None if deadline is None else max(0.1, deadline - _time.time())
            if deadline is not None and _time.time() >= deadline:
                raise subprocess.TimeoutExpired(self._cmd, timeout)
            try:
                code = psutil.Process(self.pid).wait(timeout=min(0.5, _remaining) if _remaining else 0.5)
                self.returncode = code
                return code
            except psutil.TimeoutExpired:
                continue
            except psutil.NoSuchProcess:
                self.returncode = -1
                return self.returncode
            except Exception:
                if not psutil.pid_exists(self.pid):
                    self.returncode = -1
                    return self.returncode
                if deadline is None:
                    _time.sleep(0.2)
                    continue
                if _time.time() >= deadline:
                    raise subprocess.TimeoutExpired(self._cmd, timeout)
                _time.sleep(0.2)

    def abort(self):
        """宣告 spawn 失败: 后续 wait() 立即返回"""
        self._abort_event.set()
        if self.returncode is None:
            self.returncode = -1

    def kill(self):
        """终止进程: device.kill → psutil → TerminateProcess → taskkill 兜底"""
        import psutil
        alive = True
        try:
            alive = psutil.pid_exists(self.pid)
        except Exception:
            alive = True
        if not alive:
            return
        if self._device is not None:
            try:
                self._device.kill(self.pid)
            except Exception:
                pass
        # 再次确认, device.kill 成功则退出
        try:
            if not psutil.pid_exists(self.pid):
                return
        except Exception:
            pass
        try:
            psutil.Process(self.pid).kill()
        except Exception:
            pass
        # TerminateProcess 兜底: Frida spawn 的挂起进程在注入失败时可能
        # 对 psutil.kill 无响应, 直接以 PROCESS_TERMINATE 权限终止
        try:
            import ctypes
            _kernel32 = ctypes.windll.kernel32
            _h = _kernel32.OpenProcess(0x0001, False, self.pid)
            if _h:
                _kernel32.TerminateProcess(_h, 1)
                _kernel32.CloseHandle(_h)
        except Exception:
            pass
        # 最后兜底: taskkill /F /T (仍可能因权限失败, 但至少要尝试)
        try:
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(self.pid)],
                           capture_output=True, timeout=10)
        except Exception:
            pass

    def terminate(self):
        """与 kill 相同 (Frida spawn 进程没有优雅退出的句柄)"""
        self.kill()


class APIMonitor:
    """API 调用监控器 — 使用 Frida 动态插桩"""

    def __init__(self, timeout: int = 30, enable_time_accel: bool = True, enable_shutdown_block: bool = True):
        self.timeout = timeout
        self.enable_time_accel = enable_time_accel
        self.enable_shutdown_block = enable_shutdown_block
        self._session = None
        self._script = None
        self._antivm_script = None
        self._timeaccel_script = None
        self._shutdown_script = None
        self._memprot_script = None
        self._memprot_events = []
        self._memprot_stats = {}
        self._spoof_script = None
        self._dll_calls = {}
        self._spoof_actions = []
        self._amsi_events = []
        self._priv_events = []
        self._regsave_events = []
        self._shutdown_blocked = []
        # spawn 模式协调: device.spawn 成功后立即置位, dynamic.py 等待此事件
        # 以获取挂起进程的 PID/wrapper (在 monitor_spawn 完成 attach/resume 前)
        self._spawn_proc = None
        self._spawn_ready = threading.Event()
        # ⚠ Frida JS 回调线程与主线程共享 call_records — 必须加锁,
        # 否则后分析(_summarize/_detect_sequences)迭代时回调仍在 append,
        # 轻则结果错乱, 重则 GIL/列表状态撕裂导致卡死
        self._records_lock = threading.Lock()

    @staticmethod
    def _antivm_source() -> str:
        """生成反VM脚本源 — 把配置的伪造用户名注入占位符。

        用户名必须是普通英文标识符, 且不能落在样本黑名单
        (sandbox/malware/virus/sample/analysis/analyst) 中。
        """
        _BLACKLIST = {'sandbox', 'malware', 'virus', 'sample', 'analysis', 'analyst'}
        fake = str(getattr(getattr(CONFIG, 'sandbox', None), 'env_fake_username', '') or 'zhangwei')
        fake = re.sub(r'[^A-Za-z0-9._-]', '', fake)[:32] or 'zhangwei'
        if fake.lower() in _BLACKLIST or any(b in fake.lower() for b in _BLACKLIST):
            fake = 'zhangwei'
        return FRIDA_ANTIVM_SCRIPT.replace('__SANDBOX_FAKE_USER__', fake)

    @classmethod
    def merge_results(cls, results: list) -> APIMonitorResult:
        """合并多个 Frida 监控结果 (根进程 spawn/attach + 子进程注入)。

        修复历史缺陷: dynamic.py 只合并了 call_records, 导致
        _memprot_events/_dll_calls/_spoof_actions/_amsi_events/_priv_events/
        _regsave_events/shutdown_blocked 全部丢失 — 报告里 DLL 调用监控、
        API 欺骗、内存保护监控、AMSI/特权/hive 监控永远为空。
        """
        valid = [r for r in (results or []) if r is not None]
        if not valid:
            return APIMonitorResult()

        merged = APIMonitorResult()
        all_calls = []
        for r in valid:
            lock = getattr(r, '_records_lock', None)
            try:
                if lock:
                    with lock:
                        all_calls.extend(list(getattr(r, 'call_records', None) or []))
                else:
                    all_calls.extend(list(getattr(r, 'call_records', None) or []))
            except Exception:
                continue

        if len(all_calls) > 5000:
            all_calls = all_calls[-5000:]
        merged.call_records = all_calls
        merged.total_calls = len(all_calls)
        merged.spawn_mode = any(bool(getattr(r, 'spawn_mode', False)) for r in valid)
        merged.attach_error = next(
            (getattr(r, 'attach_error', '') for r in valid if getattr(r, 'attach_error', '')), '')
        merged._antivm_active = any(bool(getattr(r, '_antivm_active', False)) for r in valid)

        # 内存保护事件/统计
        mem_events = []
        mem_stats = {}
        for r in valid:
            mem_events.extend(list(getattr(r, '_memprot_events', None) or []))
            for k, v in (getattr(r, '_memprot_stats', None) or {}).items():
                try:
                    mem_stats[k] = max(mem_stats.get(k, 0), v)
                except TypeError:
                    mem_stats[k] = v
        merged._memprot_events = mem_events[:200]
        merged._memprot_stats = mem_stats

        # DLL 调用计数求和
        dll_calls = {}
        for r in valid:
            for key, cnt in (getattr(r, '_dll_calls', None) or {}).items():
                dll_calls[key] = dll_calls.get(key, 0) + int(cnt or 0)
        merged._dll_calls = dll_calls

        # 事件列表拼接 + 上限
        merged._spoof_actions = []
        for r in valid:
            merged._spoof_actions.extend(list(getattr(r, '_spoof_actions', None) or []))
            if len(merged._spoof_actions) >= 500:
                break
        merged._spoof_actions = merged._spoof_actions[:500]

        merged._amsi_events = []
        for r in valid:
            merged._amsi_events.extend(list(getattr(r, '_amsi_events', None) or []))
        merged._amsi_events = merged._amsi_events[:30]

        merged._priv_events = []
        for r in valid:
            merged._priv_events.extend(list(getattr(r, '_priv_events', None) or []))
        merged._priv_events = merged._priv_events[:30]

        merged._regsave_events = []
        for r in valid:
            merged._regsave_events.extend(list(getattr(r, '_regsave_events', None) or []))
        merged._regsave_events = merged._regsave_events[:10]

        # 关机拦截事件去重合并
        shutdown = []
        seen = set()
        for r in valid:
            for e in (getattr(r, 'shutdown_blocked', None) or []):
                if not isinstance(e, dict):
                    continue
                key = (e.get('api'), e.get('detail'))
                if key in seen:
                    continue
                seen.add(key)
                shutdown.append(e)
        merged.shutdown_blocked = shutdown

        # 重算汇总与可疑序列 (与单个 monitor 结果一致)
        analyzer = cls(timeout=1)
        merged.call_summary = analyzer._summarize(all_calls)
        merged.suspicious_sequences = analyzer._detect_sequences(all_calls)
        return merged

    @staticmethod
    def _attach_with_timeout(pid: int, timeout: int = 30) -> object:
        """带超时的 frida.attach，防止反调试样本导致无限挂起
        真实样本常秒退/反调试: attach 失败时若进程仍存活则重试 2 次"""
        last_exc = None
        for attempt in range(3):
            try:
                import psutil
                if not psutil.pid_exists(pid):
                    raise ProcessLookupError(f"进程 PID={pid} 已退出")
            except ProcessLookupError:
                raise
            except Exception:
                pass

            result = [None]
            exception = [None]
            def _attach():
                try:
                    result[0] = frida.attach(pid)
                except Exception as e:
                    exception[0] = e
            t = threading.Thread(target=_attach, daemon=True)
            t.start()
            t.join(timeout=timeout)
            if t.is_alive():
                last_exc = TimeoutError(f"frida.attach(pid={pid}) timed out after {timeout}s")
                t.join(timeout=2)  # 不再等待, 释放线程
                continue
            if exception[0]:
                last_exc = exception[0]
                if attempt < 2:
                    import time
                    time.sleep(1)  # 稍后重试(样本早期注入常失败)
                    continue
                raise last_exc
            return result[0]
        raise last_exc

    def _load_script_with_timeout(self, session, source: str, timeout: float = 20.0):
        """线程+超时加载 Frida 脚本 — 样本运行中加载脚本可能卡死
        (曾: memprot/spoof 脚本 load() 超时 timeout was reached)"""
        holder = {'script': None, 'error': None}

        def _do_load():
            try:
                holder['script'] = session.create_script(source)
            except Exception as e:
                holder['error'] = e
                return
            try:
                holder['script'].load()
            except Exception as e:
                holder['error'] = e

        t = threading.Thread(target=_do_load, daemon=True)
        t.start()
        t.join(timeout=timeout)
        if t.is_alive():
            holder['error'] = TimeoutError(f"script.load() timed out after {timeout}s")
            t.join(timeout=1)  # 不再等待
        return holder['script'], holder['error']

    def monitor(self, pid: int) -> APIMonitorResult:
        """对指定 PID 进行 API 监控"""
        result = APIMonitorResult()
        # 每次运行重置收集状态 (同一实例在批量扫描中可能复用)
        self._dll_calls = {}
        self._spoof_actions = []
        self._amsi_events = []
        self._priv_events = []
        self._regsave_events = []
        self._shutdown_blocked = []

        if not frida:
            logger.warning("Frida 未安装，跳过 API 监控")
            return result

        logger.info(f"[*] Frida API 监控 PID={pid} (timeout={self.timeout}s)")

        try:
            self._session = self._attach_with_timeout(pid, timeout=CONFIG.sandbox.frida_attach_timeout)
            # ⚠ 主脚本(155 hooks)最重 — 线程超时加载, 失败降级不阻塞
            self._script, _load_err = self._load_script_with_timeout(
                self._session, FRIDA_SCRIPT, timeout=30)
            if self._script is None:
                logger.warning(f"主脚本加载失败: {_load_err}")
                raise _load_err or RuntimeError("frida script load failed")
            self._script.on('message', lambda msg, data: self._on_message(msg, data, result))

            # ===== 加载反 VM 检测绕过脚本（独立脚本，不记录API调用） =====
            anti_vm_result = {'hooked': False}
            try:
                self._antivm_script, _av_err = self._load_script_with_timeout(
                    self._session, self._antivm_source(), timeout=20)
                if self._antivm_script is None:
                    raise _av_err or RuntimeError('antivm load failed')
                self._antivm_script.on('message', lambda msg, data: self._on_antivm_message(msg, data))
                anti_vm_result['hooked'] = True
                logger.info("[+] Frida 反VM绕过已激活 (8项拦截: 磁盘/注册表/MAC/文件/内存/进程/SMBIOS/适配器)")
            except Exception as e:
                logger.warning(f"反VM绕过脚本加载失败: {e}")
            result._antivm_active = anti_vm_result['hooked']

            # ===== 加载时间加速脚本 =====
            if self.enable_time_accel:
                try:
                    self._timeaccel_script, _ta_err = self._load_script_with_timeout(
                        self._session, FRIDA_TIMEACCEL_SCRIPT, timeout=20)
                    if self._timeaccel_script is None:
                        raise _ta_err or RuntimeError('timeaccel load failed')
                    self._timeaccel_script.on('message', lambda msg, data: self._on_antivm_message(msg, data))
                    logger.info("[+] Frida 时间加速已激活 (1000x, Sleep/Delay/Wait/GetTickCount)")
                except Exception as e:
                    logger.warning(f"时间加速脚本加载失败: {e}")

            # ===== 加载强制拦截关机脚本 =====
            if self.enable_shutdown_block:
                try:
                    self._shutdown_script, _sd_err = self._load_script_with_timeout(
                        self._session, FRIDA_SHUTDOWN_BLOCK_SCRIPT, timeout=20)
                    if self._shutdown_script is None:
                        raise _sd_err or RuntimeError('shutdown block load failed')
                    self._shutdown_script.on('message', lambda msg, data: self._on_antivm_message(msg, data))
                    logger.info("[+] Frida 关机拦截已激活 — 样本无法通过重启/关机/注销逃避分析")
                except Exception as e:
                    logger.warning(f"关机拦截脚本加载失败: {e}")

            # ===== 内存保护监控（RW→RX 载荷解密 / 远程注入 / 进程枚举 / 睡眠统计）=====
            self._memprot_events = []
            self._memprot_stats = {'sleep_total_ms': 0, 'enum_snapshot_count': 0}
            try:
                self._memprot_script, _mp_err = self._load_script_with_timeout(
                    self._session, FRIDA_MEMPROT_SCRIPT, timeout=20)
                if self._memprot_script is None:
                    raise _mp_err or RuntimeError('memprot load failed')
                self._memprot_script.on('message', lambda msg, data: self._on_memprot_message(msg, data))
                logger.info("[+] Frida 内存保护监控已激活 (RW→RX转换/远程注入/枚举/睡眠)")
            except Exception as e:
                logger.warning(f"内存保护监控脚本加载失败: {e}")

            # ===== DLL 调用监控 + API 欺骗（hook非系统DLL导出 + 反调试假反馈）=====
            self._dll_calls = {}
            self._spoof_actions = []
            try:
                self._spoof_script, _sp_err = self._load_script_with_timeout(
                    self._session, FRIDA_SPOOF_SCRIPT, timeout=20)
                if self._spoof_script is None:
                    raise _sp_err or RuntimeError('spoof load failed')
                self._spoof_script.on('message', lambda msg, data: self._on_spoof_message(msg, data))
                logger.info("[+] Frida DLL调用监控+API欺骗已激活")
            except Exception as e:
                logger.warning(f"DLL调用监控脚本加载失败: {e}")

            logger.info(f"[+] Frida 已注入 PID={pid}")

            # 收集期间保持运行
            time.sleep(self.timeout)

            self._unload_all()

        except Exception as e:
            logger.error(f"Frida 监控失败: {e}")
            self._cleanup()

        # 后处理 — ⚠ 先取快照再分析: Frida 回调线程可能仍在写 call_records,
        # 直接迭代共享列表会与回调并发导致卡死/结果撕裂
        with self._records_lock:
            records_snapshot = list(result.call_records)
        result.total_calls = len(records_snapshot)
        result.call_summary = self._summarize(records_snapshot)
        result.suspicious_sequences = self._detect_sequences(records_snapshot)
        result.shutdown_blocked = getattr(self, '_shutdown_blocked', []) or []
        # 内存保护事件 + 统计（动态属性, 报告侧读取）
        result._memprot_events = getattr(self, '_memprot_events', [])
        result._memprot_stats = getattr(self, '_memprot_stats', {})
        if result._memprot_events:
            rwrx = [e for e in result._memprot_events if e.get('rw_to_rx')]
            rwx = [e for e in result._memprot_events if e.get('rwx_alloc')]
            inj = [e for e in result._memprot_events if e.get('injection')]
            dep = [e for e in result._memprot_events if e.get('dep_bypass')]
            rop = [e for e in result._memprot_events if e.get('rop_like')]
            huge = [e for e in result._memprot_events if e.get('huge_alloc')]
            logger.warning(f"[MemProt] RW→RX转换×{len(rwrx)} RWX分配×{len(rwx)} DEP绕过×{len(dep)} "
                           f"ROP喷射×{len(rop)} 超大分配×{len(huge)} 远程注入×{len(inj)} "
                           f"进程枚举×{result._memprot_stats.get('enum_snapshot_count', 0)} "
                           f"睡眠总计{result._memprot_stats.get('sleep_total_ms', 0)/1000:.0f}s")
        # DLL 调用统计 + 欺骗动作
        result._dll_calls = getattr(self, '_dll_calls', {}) or {}
        result._spoof_actions = getattr(self, '_spoof_actions', []) or []
        # AMSI/特权/注册表 hive 监控事件 — 回填到结果供报告展示
        result._amsi_events = list(getattr(self, '_amsi_events', []) or [])
        result._priv_events = list(getattr(self, '_priv_events', []) or [])
        result._regsave_events = list(getattr(self, '_regsave_events', []) or [])
        if result._priv_events:
            logger.warning(f"[Priv] 特权事件 {len(result._priv_events)} 条: "
                           f"{', '.join(sorted(set(e.get('privilege','') for e in result._priv_events))[:6])}")
        if result._regsave_events:
            logger.warning(f"[Cred] 注册表 hive 保存事件 ×{len(result._regsave_events)}")
        if result._amsi_events:
            logger.warning(f"[AMSI] 扫描/初始化事件 ×{len(result._amsi_events)}")
        if result._dll_calls:
            top = sorted(result._dll_calls.items(), key=lambda x: -x[1])[:8]
            total_calls = sum(result._dll_calls.values())
            logger.warning(f"[DLLWatch] 非系统DLL函数调用 {total_calls} 次, 涉及 {len(result._dll_calls)} 个函数")
            for (dll, func), cnt in top:
                logger.info(f"    {dll}!{func} ×{cnt}")
        if result._spoof_actions:
            logger.info(f"[Spoof] 假反馈动作 {len(result._spoof_actions)} 次: "
                        f"{', '.join(sorted(set(a.get('api','') for a in result._spoof_actions))[:6])}")

        logger.info(f"[*] Frida 收集到 {result.total_calls} 条 API 调用")
        return result

    def _finalize_result(self, result: APIMonitorResult) -> APIMonitorResult:
        """后处理 — 与 monitor() 保持一致（快照 → 汇总 → 检测序列 → 统计）"""
        with self._records_lock:
            records_snapshot = list(result.call_records)
        result.total_calls = len(records_snapshot)
        result.call_summary = self._summarize(records_snapshot)
        result.suspicious_sequences = self._detect_sequences(records_snapshot)
        result.shutdown_blocked = getattr(self, '_shutdown_blocked', []) or []
        result._memprot_events = getattr(self, '_memprot_events', [])
        result._memprot_stats = getattr(self, '_memprot_stats', {})
        if result._memprot_events:
            rwrx = [e for e in result._memprot_events if e.get('rw_to_rx')]
            rwx = [e for e in result._memprot_events if e.get('rwx_alloc')]
            inj = [e for e in result._memprot_events if e.get('injection')]
            dep = [e for e in result._memprot_events if e.get('dep_bypass')]
            rop = [e for e in result._memprot_events if e.get('rop_like')]
            huge = [e for e in result._memprot_events if e.get('huge_alloc')]
            logger.warning(f"[MemProt] RW→RX转换×{len(rwrx)} RWX分配×{len(rwx)} DEP绕过×{len(dep)} "
                           f"ROP喷射×{len(rop)} 超大分配×{len(huge)} 远程注入×{len(inj)} "
                           f"进程枚举×{result._memprot_stats.get('enum_snapshot_count', 0)} "
                           f"睡眠总计{result._memprot_stats.get('sleep_total_ms', 0)/1000:.0f}s")
        result._dll_calls = getattr(self, '_dll_calls', {}) or {}
        result._spoof_actions = getattr(self, '_spoof_actions', []) or []
        # AMSI/特权/注册表 hive 监控事件 — 回填到结果供报告展示
        result._amsi_events = list(getattr(self, '_amsi_events', []) or [])
        result._priv_events = list(getattr(self, '_priv_events', []) or [])
        result._regsave_events = list(getattr(self, '_regsave_events', []) or [])
        if result._priv_events:
            logger.warning(f"[Priv] 特权事件 {len(result._priv_events)} 条: "
                           f"{', '.join(sorted(set(e.get('privilege','') for e in result._priv_events))[:6])}")
        if result._regsave_events:
            logger.warning(f"[Cred] 注册表 hive 保存事件 ×{len(result._regsave_events)}")
        if result._amsi_events:
            logger.warning(f"[AMSI] 扫描/初始化事件 ×{len(result._amsi_events)}")
        if result._dll_calls:
            top = sorted(result._dll_calls.items(), key=lambda x: -x[1])[:8]
            total_calls = sum(result._dll_calls.values())
            logger.warning(f"[DLLWatch] 非系统DLL函数调用 {total_calls} 次, 涉及 {len(result._dll_calls)} 个函数")
            for (dll, func), cnt in top:
                logger.info(f"    {dll}!{func} ×{cnt}")
        if result._spoof_actions:
            logger.info(f"[Spoof] 假反馈动作 {len(result._spoof_actions)} 次: "
                        f"{', '.join(sorted(set(a.get('api','') for a in result._spoof_actions))[:6])}")
        logger.info(f"[*] Frida 收集到 {result.total_calls} 条 API 调用")
        return result

    def monitor_spawn(self, cmd: list, cwd: str = None, timeout: int = None,
                      stop_event: threading.Event = None,
                      on_before_resume: callable = None) -> APIMonitorResult:
        """以 Frida spawn 模式启动并监控进程 — 适用于快速退出/自删除样本。

        device.spawn 创建挂起进程 → attach/加载全部脚本 → 调用 on_before_resume(pid)
        （dynamic.py 用于在恢复前把 PID 加入 Job Object）→ device.resume(pid) →
        等待进程结束/超时 → 卸载脚本并返回结果。

        若 Frida 不可用或 spawn 失败，返回 None（调用方回退 Popen+attach 路径）。
        """
        if not frida:
            logger.warning("Frida 未安装，跳过 API 监控(spawn)")
            return None

        timeout = self.timeout if timeout is None else timeout
        # 每次运行重置收集状态
        self._dll_calls = {}
        self._spoof_actions = []
        self._amsi_events = []
        self._priv_events = []
        self._regsave_events = []
        self._shutdown_blocked = []

        # 获取本地设备，失败回退枚举第一个设备
        device = None
        try:
            device = frida.get_local_device()
        except Exception:
            try:
                devices = frida.get_device_manager().enumerate_devices()
                if devices:
                    device = devices[0]
            except Exception:
                device = None
        if not device:
            logger.warning("Frida 设备不可用，spawn 模式不可用")
            return None

        # spawn: 部分 Frida 版本不支持 stdio='null' (枚举值缺失/TypeError) —
        # 与 stdio 相关的失败都去掉该参数重试一次
        pid = None
        # Frida spawn 需要可执行文件的完整路径 (cmd.exe 等裸名会失败)
        spawn_cmd = list(cmd or [])
        if spawn_cmd:
            _exe = shutil.which(spawn_cmd[0])
            if _exe:
                spawn_cmd[0] = _exe
            elif os.path.isfile(spawn_cmd[0]):
                spawn_cmd[0] = os.path.abspath(spawn_cmd[0])
        try:
            try:
                pid = device.spawn(spawn_cmd, cwd=cwd, stdio='null')
            except Exception as e:
                if isinstance(e, TypeError) or 'stdio' in str(e).lower():
                    pid = device.spawn(spawn_cmd, cwd=cwd)
                else:
                    raise
        except Exception as e:
            logger.warning(f"Frida spawn 失败: {e}")
            return None

        wrapper = _SpawnedProcess(pid, cmd=list(cmd or []), device=device)
        # ⚠ 立即发布 wrapper — dynamic.py 主线程等待此事件以启动监控线程
        # （此时进程仍被 Frida 挂起，不会执行任何代码）
        self._spawn_proc = wrapper
        self._spawn_ready = threading.Event()
        self._spawn_ready.set()

        result = APIMonitorResult()
        result.spawn_mode = True
        result.attach_error = ''

        logger.info(f"[*] Frida spawn API 监控 PID={pid} (timeout={timeout}s, cmd={cmd})")

        try:
            self._session = self._attach_with_timeout(pid, timeout=CONFIG.sandbox.frida_attach_timeout)
            self._script, _load_err = self._load_script_with_timeout(
                self._session, FRIDA_SCRIPT, timeout=30)
            if self._script is None:
                logger.warning(f"主脚本加载失败: {_load_err}")
                raise _load_err or RuntimeError("frida script load failed")
            self._script.on('message', lambda msg, data: self._on_message(msg, data, result))

            # ===== 加载反 VM 检测绕过脚本（独立脚本，不记录API调用） =====
            anti_vm_result = {'hooked': False}
            try:
                self._antivm_script, _av_err = self._load_script_with_timeout(
                    self._session, self._antivm_source(), timeout=20)
                if self._antivm_script is None:
                    raise _av_err or RuntimeError('antivm load failed')
                self._antivm_script.on('message', lambda msg, data: self._on_antivm_message(msg, data))
                anti_vm_result['hooked'] = True
                logger.info("[+] Frida 反VM绕过已激活 (8项拦截: 磁盘/注册表/MAC/文件/内存/进程/SMBIOS/适配器)")
            except Exception as e:
                logger.warning(f"反VM绕过脚本加载失败: {e}")
            result._antivm_active = anti_vm_result['hooked']

            # ===== 加载时间加速脚本 =====
            if self.enable_time_accel:
                try:
                    self._timeaccel_script, _ta_err = self._load_script_with_timeout(
                        self._session, FRIDA_TIMEACCEL_SCRIPT, timeout=20)
                    if self._timeaccel_script is None:
                        raise _ta_err or RuntimeError('timeaccel load failed')
                    self._timeaccel_script.on('message', lambda msg, data: self._on_antivm_message(msg, data))
                    logger.info("[+] Frida 时间加速已激活 (1000x, Sleep/Delay/Wait/GetTickCount)")
                except Exception as e:
                    logger.warning(f"时间加速脚本加载失败: {e}")

            # ===== 加载强制拦截关机脚本 =====
            if self.enable_shutdown_block:
                try:
                    self._shutdown_script, _sd_err = self._load_script_with_timeout(
                        self._session, FRIDA_SHUTDOWN_BLOCK_SCRIPT, timeout=20)
                    if self._shutdown_script is None:
                        raise _sd_err or RuntimeError('shutdown block load failed')
                    self._shutdown_script.on('message', lambda msg, data: self._on_antivm_message(msg, data))
                    logger.info("[+] Frida 关机拦截已激活 — 样本无法通过重启/关机/注销逃避分析")
                except Exception as e:
                    logger.warning(f"关机拦截脚本加载失败: {e}")

            # ===== 内存保护监控（RW→RX 载荷解密 / 远程注入 / 进程枚举 / 睡眠统计）=====
            self._memprot_events = []
            self._memprot_stats = {'sleep_total_ms': 0, 'enum_snapshot_count': 0}
            try:
                self._memprot_script, _mp_err = self._load_script_with_timeout(
                    self._session, FRIDA_MEMPROT_SCRIPT, timeout=20)
                if self._memprot_script is None:
                    raise _mp_err or RuntimeError('memprot load failed')
                self._memprot_script.on('message', lambda msg, data: self._on_memprot_message(msg, data))
                logger.info("[+] Frida 内存保护监控已激活 (RW→RX转换/远程注入/枚举/睡眠)")
            except Exception as e:
                logger.warning(f"内存保护监控脚本加载失败: {e}")

            # ===== DLL 调用监控 + API 欺骗（hook非系统DLL导出 + 反调试假反馈）=====
            self._dll_calls = {}
            self._spoof_actions = []
            try:
                self._spoof_script, _sp_err = self._load_script_with_timeout(
                    self._session, FRIDA_SPOOF_SCRIPT, timeout=20)
                if self._spoof_script is None:
                    raise _sp_err or RuntimeError('spoof load failed')
                self._spoof_script.on('message', lambda msg, data: self._on_spoof_message(msg, data))
                logger.info("[+] Frida DLL调用监控+API欺骗已激活")
            except Exception as e:
                logger.warning(f"DLL调用监控脚本加载失败: {e}")

            logger.info(f"[+] Frida 已注入 PID={pid} (spawn)")

            # ===== 恢复前回调: dynamic.py 把 PID 加入 Job Object =====
            if on_before_resume is not None:
                try:
                    on_before_resume(pid)
                except Exception as e:
                    result.attach_error = f'on_before_resume 回调失败: {e}'
                    logger.error(f"[Frida-Spawn] on_before_resume 回调失败: {e}")
                    self._cleanup()
                    wrapper.abort()
                    try:
                        wrapper.kill()
                    except Exception:
                        pass
                    return self._finalize_result(result)

            try:
                device.resume(pid)
            except Exception as e:
                result.attach_error = f'Frida resume 失败: {e}'
                logger.error(f"[Frida-Spawn] device.resume 失败: {e}")
                self._cleanup()
                wrapper.abort()
                try:
                    wrapper.kill()
                except Exception:
                    pass
                return self._finalize_result(result)

            # ===== 监控等待循环: 用 wrapper.wait 等待进程结束或超时 =====
            deadline = time.time() + timeout
            while time.time() < deadline:
                if stop_event and stop_event.is_set():
                    logger.warning("[Frida-Spawn] 监控循环被停止")
                    break
                try:
                    wrapper.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    time.sleep(0.5)

            self._unload_all()

        except Exception as e:
            logger.error(f"Frida spawn 监控失败: {e}")
            result.attach_error = result.attach_error or str(e)
            self._cleanup()
            wrapper.abort()
            try:
                wrapper.kill()
            except Exception:
                pass

        return self._finalize_result(result)

    def _on_message(self, message, data, result: APIMonitorResult):
        """处理 Frida 发送的消息"""
        if message.get('type') != 'send':
            return
        payload = message.get('payload', {})
        if payload.get('type') == 'status':
            logger.info(f"[Frida-Main] {payload.get('msg')}")
            return
        # 网络载荷捕获 (send/recv 缓冲区内容)
        if payload.get('type') == 'netpayload':
            payloads = getattr(result, '_net_payloads', None)
            if payloads is None:
                result._net_payloads = []
                payloads = result._net_payloads
            if len(payloads) < 2000:
                payloads.append({
                    'api': payload.get('api', ''),
                    'fd': payload.get('fd', 0),
                    'len': payload.get('len', 0),
                    'preview': payload.get('preview', '')[:500],
                    'is_send': payload.get('is_send', True),
                    'is_http': payload.get('is_http', False),
                })
            return
        # HTTP 高层 API 捕获的明文 URL (WinHTTP/WinINet — HTTPS socket 层已加密, 高层 API 才有明文)
        if payload.get('type') == 'http_url':
            urls = getattr(result, '_http_urls', None)
            if urls is None:
                result._http_urls = []
                urls = result._http_urls
            url = payload.get('url', '')
            proto = payload.get('proto', '')
            verb = payload.get('verb', '')
            extra = payload.get('extra', '')
            if len(urls) < 500:
                urls.append({'url': url, 'proto': proto, 'verb': verb, 'extra': extra})
                if url:
                    logger.info(f"[HTTP-URL] {proto} {verb} {url}")
            return
        # 子进程创建捕获 (CreateProcessW/A onLeave 提取 dwProcessId — 还原进程树)
        if payload.get('type') == 'child_process':
            _cp = {
                'pid': payload.get('pid', 0),
                'cmdline': payload.get('cmdline', ''),
                'via': payload.get('via', ''),
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            }
            children = getattr(result, '_child_processes', None)
            if children is None:
                result._child_processes = []
                children = result._child_processes
            if _cp['pid'] > 0 and all(c['pid'] != _cp['pid'] for c in children):
                children.append(_cp)
                logger.info(f"[ChildProc] 捕获子进程: PID={_cp['pid']} via {_cp['via']} cmd={_cp['cmdline'][:80]}")
            return
        if payload.get('type') != 'api':
            return

        detail = APIHookDetail(
            timestamp=datetime.now().strftime('%H:%M:%S.%f')[:-3],
            api_name=payload.get('name', 'unknown'),
            arguments=payload.get('args', []),
            category=self._categorize(payload.get('name', ''))
        )
        with self._records_lock:
            result.call_records.append(detail)
            # 限制内存占用 (截断而非切片重建 — 切片会复制5000条, 高频回调下开销大)
            if len(result.call_records) > 5000:
                del result.call_records[:-5000]

    def _on_antivm_message(self, message, data):
        """处理反VM绕过/时间加速/关机拦截脚本消息"""
        if message.get('type') == 'send':
            payload = message.get('payload', {})
            if payload.get('type') == 'status':
                logger.info(f"[Frida-Other] {payload.get('msg')}")
            elif payload.get('type') == 'shutdown_blocked':
                blocked = payload.get('blocked', [])
                if blocked:
                    events = getattr(self, '_shutdown_blocked', []) or []
                    seen = {(e.get('api'), e.get('detail')) for e in events}
                    for b in blocked:
                        key = (b.get('api'), b.get('detail'))
                        if key not in seen:
                            events.append(b)
                            seen.add(key)
                    self._shutdown_blocked = events
                    logger.warning(f"[ShutdownBlock] 共拦截 {len(events)} 次关机/重启/休眠尝试")

    def _on_memprot_message(self, message, data):
        """处理内存保护监控脚本消息"""
        if message.get('type') != 'send':
            return
        payload = message.get('payload', {})
        ptype = payload.get('type')
        if ptype == 'status':
            logger.info(f"[MemProt] {payload.get('msg')}")
            return
        if ptype == 'memstat':
            stats = getattr(self, '_memprot_stats', {})
            stats['sleep_total_ms'] = max(stats.get('sleep_total_ms', 0), payload.get('sleep_total_ms', 0))
            stats['enum_snapshot_count'] = max(stats.get('enum_snapshot_count', 0), payload.get('enum_snapshot_count', 0))
            return
        if ptype == 'memprot':
            size = _coerce_int(payload.get('size', 0))
            evt = {
                'api': payload.get('api', ''),
                'base': payload.get('base', ''),
                'size': size,
                'old_prot': payload.get('old_prot', ''),
                'new_prot': payload.get('new_prot', ''),
                'protection': payload.get('protection', ''),
                'allocation_type': payload.get('allocation_type', ''),
                'status': payload.get('status', ''),
                'rw_to_rx': bool(payload.get('rw_to_rx')),
                'rwx_alloc': bool(payload.get('rwx_alloc')),
                'injection': bool(payload.get('injection')),
                'dep_bypass': bool(payload.get('dep_bypass')),
                'rop_like': bool(payload.get('rop_like')),
                'huge_alloc': bool(payload.get('huge_alloc')),
                'page_guard': bool(payload.get('page_guard')),
                'guard_exec': bool(payload.get('guard_exec')),
            }
            events = getattr(self, '_memprot_events', [])
            if len(events) < 200:
                events.append(evt)
            if evt['rw_to_rx']:
                logger.warning(f"[MemProt] RW→RX 转换: {evt['api']} @ {evt['base']} "
                               f"size={_fmt_bytes(evt['size'])} ({evt['old_prot']}→{evt['new_prot']})")
            elif evt['rop_like']:
                logger.warning(f"[MemProt] ⚠ DEP绕过/ROP喷射: {evt['api']} RWX分配 "
                               f"size={_fmt_bytes(evt['size'])} prot={evt['new_prot']} "
                               f"({evt['protection']}) status={evt['status']}")
            elif evt['dep_bypass']:
                logger.warning(f"[MemProt] ⚠ DEP绕过: {evt['api']} RWX分配 "
                               f"size={_fmt_bytes(evt['size'])} prot={evt['new_prot']} ({evt['protection']})")
            elif evt.get('page_guard'):
                tag = 'PAGE_GUARD+可执行 (反调试陷阱)' if evt.get('guard_exec') else 'PAGE_GUARD 内存页 (反逆向)'
                logger.warning(f"[MemProt] {tag}: {evt['api']} @ {evt['base']} "
                               f"size={_fmt_bytes(evt['size'])} ({evt['old_prot']}->{evt['new_prot']})")
            elif evt['huge_alloc']:
                logger.warning(f"[MemProt] 超大内存分配: {evt['api']} size={_fmt_bytes(evt['size'])} "
                               f"prot={evt['new_prot']} (内存喷射特征)")

    def _on_spoof_message(self, message, data):
        """处理 DLL 调用监控 + API 欺骗脚本消息"""
        if message.get('type') != 'send':
            return
        payload = message.get('payload', {})
        ptype = payload.get('type')
        if ptype == 'status':
            logger.info(f"[Spoof] {payload.get('msg')}")
            return
        if ptype == 'dllcall':
            dll = payload.get('dll', '?')
            func = payload.get('func', '?')
            calls = getattr(self, '_dll_calls', {})
            if calls is None:
                calls = {}
                self._dll_calls = calls
            key = (dll, func)
            calls[key] = calls.get(key, 0) + 1
            while len(calls) > 2000:
                # 防内存膨胀: 淘汰最旧插入项, 保证新调用始终保留
                try:
                    calls.pop(next(iter(calls)))
                except Exception:
                    break
            return
        if ptype == 'dllstat':
            logger.debug(f"[DLLWatch] 累计 {payload.get('total', 0)} 次调用, "
                         f"{payload.get('hooked_funcs', 0)} 个导出函数已hook")
            return
        if ptype in ('amsi', 'amsi_init', 'amsi_uninit'):
            # AMSI 扫描监控 — 脚本型恶意载荷信号
            amsi = getattr(self, '_amsi_events', None)
            if amsi is None:
                amsi = []
                self._amsi_events = amsi
            if ptype == 'amsi':
                evt = {
                    'api': payload.get('api', ''),
                    'size': payload.get('len', 0),
                    'content': (payload.get('content') or '')[:80],
                    'preview_b64': (payload.get('preview') or '')[:120],
                }
                if len(amsi) < 30:
                    amsi.append(evt)
                logger.info(f"[AMSI] {evt['api']}: 扫描 {evt['size']} 字节 "
                            f"(content='{evt['content']}') — 脚本引擎执行恶意代码")
            elif ptype == 'amsi_init':
                amsi.append({'api': 'AmsiInitialize',
                             'content': f"app={payload.get('app', '')}"})
                logger.info(f"[AMSI] 初始化: {payload.get('app', '')}")
            elif ptype == 'amsi_uninit':
                amsi.append({'api': 'AmsiUninitialize', 'content': '卸载 AMSI (绕过信号)'})
                logger.warning("[AMSI] AmsiUninitialize 被调用 — 疑似 AMSI 绕过")
            if len(amsi) > 30:
                del amsi[:-30]
            return
        if ptype == 'priv':
            # 特权启用监控 — SeDebugPrivilege 等
            priv = payload.get('privilege', '')
            act = payload.get('action', '')
            privs = getattr(self, '_priv_events', None)
            if privs is None:
                privs = []
                self._priv_events = privs
            evt = {'api': payload.get('api', ''), 'privilege': priv, 'action': act}
            if len(privs) < 30:
                privs.append(evt)
            if act == 'ENABLED':
                logger.warning(f"[Priv] ⚠ 样本启用 {priv} 特权 — 进程注入/LSASS访问前置 ({payload.get('api', '')})")
            else:
                logger.info(f"[Priv] {priv} {act} ({payload.get('api', '')})")
            return
        if ptype == 'regsave':
            # 注册表 hive 保存 — 离线凭据窃取 (SAM/SYSTEM)
            rs = getattr(self, '_regsave_events', None)
            if rs is None:
                rs = []
                self._regsave_events = rs
            evt = {'file': payload.get('file', ''), 'api': payload.get('api', '')}
            if len(rs) < 10:
                rs.append(evt)
            logger.warning(f"[Cred] ⚠ 注册表 hive 保存 (离线凭据窃取): {evt['file']} ({evt['api']})")
            return
        if ptype == 'spoof':
            act = {'api': payload.get('api', ''), 'detail': payload.get('detail', '')}
            actions = getattr(self, '_spoof_actions', [])
            if len(actions) < 500:
                actions.append(act)
            logger.info(f"[Spoof] {act['api']}: {act['detail']}")

    def _unload_all(self):
        """卸载所有脚本 + detach 会话

        ⚠ detach() 在目标进程已死/回调仍排队时可能无限挂起 —
        必须放守护线程限时执行, 否则后分析卡死 (5000条调用场景实测)
        """
        def _do_unload():
            for attr in ('_shutdown_script', '_timeaccel_script', '_antivm_script', '_memprot_script', '_spoof_script', '_script'):
                obj = getattr(self, attr, None)
                if obj:
                    try:
                        obj.unload()
                    except Exception:
                        pass
                    setattr(self, attr, None)
            if self._session:
                try:
                    self._session.detach()
                except Exception:
                    pass
                self._session = None
        t = threading.Thread(target=_do_unload, daemon=True)
        t.start()
        t.join(timeout=10)
        if t.is_alive():
            logger.warning("[Frida] 会话 detach 超时(10s), 已放弃等待 — 目标进程可能已退出")

    def _cleanup(self):
        self._unload_all()

    def _categorize(self, api_name: str) -> str:
        file_apis = {'CreateFileW', 'CreateFileA', 'WriteFile', 'DeleteFileW', 'DeleteFileA',
                     'ReadFile', 'LoadLibraryW', 'LoadLibraryA', 'LoadLibraryExW', 'LoadLibraryExA',
                     'GetProcAddress', 'FreeLibrary', 'MoveFileW', 'MoveFileExW', 'CopyFileW', 'CopyFileExW',
                     'SetFileAttributesW', 'GetFileAttributesW'}
        reg_apis = {'RegCreateKeyExW', 'RegCreateKeyExA', 'RegSetValueExW', 'RegSetValueExA',
                    'RegDeleteKeyW', 'RegDeleteKeyExW', 'RegDeleteValueW',
                    'RegOpenKeyExW', 'RegOpenKeyExA', 'RegQueryValueExW', 'RegCloseKey', 'RegEnumKeyExW',
                    'NtOpenKey', 'NtCreateKey', 'NtSetValueKey', 'NtDeleteKey', 'NtDeleteValueKey', 'NtEnumerateKey'}
        proc_apis = {'CreateProcessW', 'CreateProcessA', 'WinExec', 'CreateThread', 'NtCreateThreadEx',
                     'OpenProcess', 'NtCreateProcessEx', 'TerminateProcess', 'ExitProcess',
                     'ShellExecuteW', 'ShellExecuteA', 'ShellExecuteExW', 'ShellExecuteExA',
                     'CreateProcessAsUserW', 'LogonUserW'}
        mem_apis = {'VirtualAllocEx', 'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread',
                    'ReadProcessMemory', 'NtUnmapViewOfSection', 'VirtualProtectEx', 'VirtualProtect',
                    'VirtualFree', 'VirtualFreeEx', 'NtMapViewOfSection', 'NtCreateSection',
                    'NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 'NtProtectVirtualMemory'}
        net_apis = {'connect', 'WSAConnect', 'socket', 'send', 'recv', 'WSASend', 'WSARecv',
                    'WSAStartup', 'gethostbyname', 'getaddrinfo',
                    'InternetOpenW', 'InternetOpenA', 'InternetConnectW', 'InternetConnectA',
                    'HttpOpenRequestW', 'HttpOpenRequestA', 'HttpSendRequestW', 'HttpSendRequestA',
                    'InternetReadFile', 'InternetWriteFile', 'InternetOpenUrlW', 'InternetOpenUrlA'}
        pers_apis = {'CreateServiceW', 'StartServiceW', 'ControlService', 'DeleteService',
                     'ChangeServiceConfigW', 'ChangeServiceConfig2W', 'OpenSCManagerW', 'OpenServiceW'}
        evasion_apis = {'SetWindowsHookExW', 'SetWindowsHookExA', 'UnhookWindowsHookEx',
                       'CreateMutexW', 'CreateMutexA', 'SetErrorMode',
                       'Sleep', 'SleepEx', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                       'NtQueryInformationProcess', 'NtQuerySystemInformation', 'NtSetInformationThread'}
        crypto_apis = {'CryptDecrypt', 'CryptEncrypt', 'CryptUnprotectData', 'CryptProtectData',
                       'CryptStringToBinaryW', 'CryptStringToBinaryA',
                       'CertOpenSystemStoreW', 'CertEnumCertificatesInStore',
                       'BCryptDecrypt', 'BCryptEncrypt', 'NCryptDecrypt', 'NCryptEncrypt', 'NCryptOpenKey'}
        priv_apis = {'OpenProcessToken', 'AdjustTokenPrivileges', 'LookupPrivilegeValueW',
                     'ImpersonateLoggedOnUser', 'RevertToSelf'}
        surveillance_apis = {'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState',
                              'GetForegroundWindow', 'GetRawInputData',
                              'waveInOpen', 'waveInStart', 'mixerOpen', 'midiInOpen'}
        proxy_apis = {'InternetSetOptionW', 'InternetSetOptionA',
                      'WinHttpSetDefaultProxyConfiguration'}
        vm_enum_apis = {'GetAdaptersAddresses', 'GetIfTable', 'GetVolumeInformationW',
                        'GetVolumeInformationA', 'QueryDosDeviceW', 'QueryDosDeviceA',
                        'GetLogicalDrives', 'GetDriveTypeW', 'GetDriveTypeA',
                        'GetTimeZoneInformation'}

        if api_name in file_apis: return 'file'
        if api_name in reg_apis: return 'registry'
        if api_name in proc_apis: return 'process'
        if api_name in mem_apis: return 'injection'
        if api_name in net_apis: return 'network'
        if api_name in pers_apis: return 'persistence'
        if api_name in surveillance_apis: return 'surveillance'
        if api_name in proxy_apis: return 'proxy'
        if api_name in vm_enum_apis: return 'evasion'
        if api_name in evasion_apis: return 'evasion'
        if api_name in crypto_apis: return 'crypto'
        if api_name in priv_apis: return 'privilege'
        return 'other'

    def _summarize(self, records):
        summary = {}
        for r in records:
            summary[r.api_name] = summary.get(r.api_name, 0) + 1
        return summary

    def _detect_sequences(self, records):
        sequences = []
        names = [r.api_name for r in records]
        names_set = set(names)

        # ⚠ 性能: 5000条记录下, 30+个 any() 每个都 str(r.arguments) 会全量转换
        # 数十万次 — 预先一次性转换, 后续只做子串查找 (卡死修复)
        args_blob = ' || '.join(str(r.arguments).lower() for r in records) if records else ''
        args_blob_len = len(args_blob)

        def _args_contain(kw: str) -> bool:
            return kw in args_blob

        def _parse_hex_arg(v) -> int:
            m = re.search(r'0x[0-9a-fA-F]+', str(v or ''))
            try:
                return int(m.group(0), 16) if m else 0
            except ValueError:
                return 0

        # ===== DEP绕过/RWX 分配参数检测 =====
        # memprot 脚本正常时已发送详细事件 (含大小/状态); 这里作为脚本未加载
        # 或事件被限流时的兜底: 直接解析主监控脚本记录的 NtAllocate/NtProtect 参数。
        _dep_bypass_alloc = False
        _dep_bypass_protect = False
        for r in records:
            try:
                _api_lower = (r.api_name or '').lower()
                _args = list(r.arguments or [])
                if 'ntallocatevirtualmemory' in _api_lower and len(_args) >= 6:
                    # (Handle, BaseAddress*, ZeroBits, RegionSize*, AllocationType, Protect)
                    _prot = _parse_hex_arg(_args[5])
                    # EXECUTE_READWRITE(0x40)/EXECUTE_WRITECOPY(0x80) 本身即可写可执行
                    _writable = bool(_prot & 0x04) or bool(_prot & 0x40) or bool(_prot & 0x80)
                    if (_prot & 0xF0) and _writable:
                        _dep_bypass_alloc = True
                elif 'ntprotectvirtualmemory' in _api_lower and len(_args) >= 4:
                    # (Handle, BaseAddress*, RegionSize*, NewProtect, OldProtect*)
                    _prot = _parse_hex_arg(_args[3])
                    _writable = bool(_prot & 0x04) or bool(_prot & 0x40) or bool(_prot & 0x80)
                    if (_prot & 0xF0) and _writable:
                        _dep_bypass_protect = True
            except Exception:
                continue
        if _dep_bypass_alloc:
            sequences.append("NtAllocateVirtualMemory RWX分配 (DEP绕过/ROP特征)")
        if _dep_bypass_protect:
            sequences.append("NtProtectVirtualMemory 设置为 RWX (DEP绕过特征)")

        # ===== 内存分配/释放失衡 — 分配后不释放 (内存驻留/泄漏/反内存取证特征) =====
        _alloc_apis = {'VirtualAlloc', 'VirtualAllocEx', 'NtAllocateVirtualMemory',
                       'HeapAlloc', 'RtlAllocateHeap', 'GlobalAlloc', 'LocalAlloc'}
        _free_apis = {'VirtualFree', 'VirtualFreeEx', 'NtFreeVirtualMemory',
                      'HeapFree', 'RtlFreeHeap', 'GlobalFree', 'LocalFree'}
        _alloc_n = sum(names.count(a) for a in _alloc_apis)
        _free_n = sum(names.count(a) for a in _free_apis)
        if _alloc_n >= 3 and _alloc_n >= _free_n * 2:
            sequences.append(
                f"Memory allocation without release: alloc×{_alloc_n} free×{_free_n} "
                f"(内存驻留/泄漏特征)")

        # ===== 5.2 七组条件反沙箱 (IsSandboxEnvironment 0x140002E20 行为模式) =====
        # 全部满足才算非沙箱, 任一不满足立即退出 — 反沙箱+反调试+资源+用户名黑名单组合
        _seven_checks = {
            '反调试': 'IsDebuggerPresent' in names_set or 'CheckRemoteDebuggerPresent' in names_set,
            '分辨率': 'GetSystemMetrics' in names_set,
            'CPU': ('GetSystemInfo' in names_set or 'GetNativeSystemInfo' in names_set
                    or 'GetLogicalProcessorInformation' in names_set),
            '运行时长': ('GetTickCount' in names_set or 'GetTickCount64' in names_set),
            '内存': ('GlobalMemoryStatusEx' in names_set or 'GlobalMemoryStatus' in names_set
                     or 'GetPhysicallyInstalledSystemMemory' in names_set),
            '进程数': ('CreateToolhelp32Snapshot' in names_set or 'Process32FirstW' in names_set
                       or 'Process32FirstA' in names_set or 'NtQuerySystemInformation' in names_set),
            '用户名': ('GetUserNameW' in names_set or 'GetUserNameA' in names_set
                       or 'GetUserNameExW' in names_set or 'GetEnvironmentVariableW' in names_set),
        }
        _seven_hit = sum(1 for v in _seven_checks.values() if v)
        if _seven_hit >= 4:
            _seven_missing = '、'.join(k for k, v in _seven_checks.items() if not v)
            sequences.append(
                f"多条件反沙箱环境检测 ×{_seven_hit}/7 "
                f"(IsDebuggerPresent+GetSystemMetrics+CPU+GetTickCount+内存+进程数+用户名黑名单"
                + (f", 未检测项: {_seven_missing}" if _seven_missing else "") + ")" )

        # 进程注入链
        if {'OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'}.issubset(names_set):
            sequences.append("Process injection chain detected (Classic)")
        elif {'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'}.issubset(names_set):
            sequences.append("Likely process injection detected")
        if {'OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'NtCreateThreadEx'}.issubset(names_set):
            sequences.append("Process injection via NtCreateThreadEx (stealth)")

        # 反射式 DLL / 进程镂空
        if 'NtUnmapViewOfSection' in names_set and 'VirtualAllocEx' in names_set:
            sequences.append("Process hollowing indicators detected")
        if 'NtMapViewOfSection' in names_set and 'NtCreateSection' in names_set:
            sequences.append("Section mapping injection detected")
        if {'NtUnmapViewOfSection', 'VirtualAllocEx', 'SetThreadContext'}.issubset(names_set):
            sequences.append("Classic process hollowing (Unmap+Alloc+SetContext)")

        # ===== Step Bear 内核注入 (Storm-0978): cbClsExtra 共享内存 + 窗口消息回调执行 =====
        # EM_SETWORDBREAKPROC = 0x01CB (459) / WM_SETTEXT = 0x000C (12) /
        # WM_LBUTTONDBLCLK = 0x0203 (515)
        msg_records = [r for r in records
                       if r.api_name.startswith(('SendMessage', 'PostMessage'))]

        # 1) EM_SETWORDBREAKPROC 回调滥用 — 把任意函数地址设为编辑框回调
        #    (正常程序几乎不用; Step Bear 用 PostMessage 传 I_RpcFreePipeBuffer 地址)
        #    ⚠ 精确匹配消息值 (参数格式含 '0x1cb'/'459'), 避免子串误匹配
        _em_setwordbreak = any(
            re.search(r'\b(?:0x1[cC][bB]|459)\b', str(r.arguments).lower())
            for r in records if r.api_name.startswith(('SendMessage', 'PostMessage')))
        if _em_setwordbreak:
            sequences.append("EM_SETWORDBREAKPROC window callback abuse (Step Bear style code exec)")
        # 2) WM_SETTEXT (0x000C=12) + WM_LBUTTONDBLCLK (0x0203=515) 组合
        #    ⚠ 精确匹配, 避免 '0xc' 匹配 0xcc/0xcd 等 (正常消息误报)
        _wmtext = any(
            re.search(r'\b(?:0x[cC]|12)\b', str(r.arguments).lower())
            for r in records if r.api_name.startswith(('SendMessage', 'PostMessage')))
        _wmldbl = any(
            re.search(r'\b(?:0x203|515)\b', str(r.arguments).lower())
            for r in records if r.api_name.startswith(('SendMessage', 'PostMessage')))
        if _wmtext and _wmldbl:
            sequences.append("WM_SETTEXT + WM_LBUTTONDBLCLK to edit control (notepad injection trigger)")
        # 3) notepad 窗口 + 内存读写组合 (Step Bear 注入目标)
        if any('notepad' in str(r.arguments).lower() for r in records
               if r.api_name.startswith('FindWindow')) \
                and ('WriteProcessMemory' in names_set or 'ReadProcessMemory' in names_set):
            sequences.append("notepad window interaction + memory R/W (Step Bear injection target)")

        # ===== USB 蠕虫传播 (PlugX): 驱动器遍历 + 复制自身 + 互斥体 =====
        _drive_enum = ('GetLogicalDriveStringsW' in names_set or 'GetLogicalDriveStringsA' in names_set)
        if _drive_enum and ('CopyFileW' in names_set or 'CopyFileA' in names_set):
            sequences.append("USB worm propagation: drive enumeration + self-copy (PlugX style)")
        if _drive_enum and 'CreateMutexW' in names_set \
                and any('usb_notify' in str(r.arguments).lower() for r in records
                        if r.api_name == 'CreateMutexW'):
            sequences.append("USB worm mutex (USB_NOTIFY_* — PlugX drive marker)")

        # 持久化
        if any(r.api_name.startswith('RegSetValue') for r in records) and _args_contain('run'):
            sequences.append("Registry persistence detected (Run key)")
        if 'CreateServiceW' in names_set or 'StartServiceW' in names_set:
            sequences.append("Service persistence detected")
        if 'RegCreateKeyExW' in names_set and 'RegSetValueExW' in names_set:
            sequences.append("Registry key creation + value set (persistence)")
        if 'ChangeServiceConfigW' in names_set or 'ChangeServiceConfig2W' in names_set:
            sequences.append("Service configuration modified (persistence via service)")

        # 凭证窃取
        if 'OpenProcess' in names_set and _args_contain('lsass'):
            sequences.append("LSASS process handle opened (credential dumping)")
        if 'ReadProcessMemory' in names_set and _args_contain('lsass'):
            sequences.append("LSASS memory read (credential dumping)")
        # ⚠ EDRSandblast 用 NtReadVirtualMemory 直连系统调用转储 LSASS
        #   (绕过 ntdll hook) — kernel32 包装检测不到, 必须补 NT API
        if ('NtReadVirtualMemory' in names_set or 'ZwReadVirtualMemory' in names_set) \
                and _args_contain('lsass'):
            sequences.append("LSASS memory read via Nt/ZwReadVirtualMemory (EDRSandblast-style dump)")
        if 'CryptUnprotectData' in names_set:
            sequences.append("DPAPI decryption (credential/secret extraction)")

        # 网络连接
        if 'connect' in names_set or 'WSAConnect' in names_set:
            sequences.append("Network connection established")
        if 'HttpOpenRequestW' in names_set and 'HttpSendRequestW' in names_set:
            sequences.append("HTTP request sent (C2 communication)")
        if 'InternetOpenUrlW' in names_set or 'InternetOpenUrlA' in names_set:
            sequences.append("URL accessed via WinINet (C2/download)")
        if 'gethostbyname' in names_set or 'getaddrinfo' in names_set:
            sequences.append("DNS resolution performed")

        # 反调试/互斥体
        if 'CreateMutexW' in names_set or 'CreateMutexA' in names_set:
            sequences.append("Mutex created (single-instance or evasion)")
        if 'IsDebuggerPresent' in names_set or 'CheckRemoteDebuggerPresent' in names_set:
            sequences.append("Anti-debug check detected (IsDebuggerPresent)")
        if 'NtQueryInformationProcess' in names_set:
            sequences.append("Process information query (anti-debug/anti-VM)")
        if 'NtSetInformationThread' in names_set:
            sequences.append("Thread information set (anti-debug/HideFromDebugger)")

        # 键盘钩子
        if 'SetWindowsHookExW' in names_set or 'SetWindowsHookExA' in names_set:
            sequences.append("Windows hook installed (possible keylogger/clipboard monitor)")

        # 提权
        if 'OpenProcessToken' in names_set and 'AdjustTokenPrivileges' in names_set:
            sequences.append("Token privilege adjustment (privilege escalation)")
        if 'LookupPrivilegeValueW' in names_set and 'AdjustTokenPrivileges' in names_set:
            sequences.append("SE privilege enabled (possible privilege escalation)")

        # 自删除 / 反取证
        if 'SetFileAttributesW' in names_set and any('DeleteFile' in n for n in names_set):
            sequences.append("File attribute change + deletion (anti-forensics)")
        if 'MoveFileW' in names_set or 'MoveFileExW' in names_set:
            sequences.append("File move/rename (possible self-delete technique)")

        # DLL side-loading
        if 'LoadLibraryW' in names_set and ('WriteFile' in names_set or _args_contain('copy')):
            sequences.append("DLL write + load (possible side-loading)")

        # ===== 系统设置修改 =====
        # 防火墙修改
        if _args_contain('netsh') or _args_contain('firewall'):
            sequences.append("Firewall modification detected (netsh/firewall API)")
        if _args_contain('windows firewall'):
            sequences.append("Windows Firewall API called")
        # 安全软件/Defender 修改
        if _args_contain('defender') or _args_contain('security center') or _args_contain('windows defender'):
            sequences.append("Security software/Defender modification")
        if 'RegSetValueExW' in names_set and (_args_contain('disableantispyware') or _args_contain('disablerealtimemonitoring') or _args_contain('disablebehaviormonitoring')):
            sequences.append("Windows Defender disabled via registry")
        # 系统配置修改
        if _args_contain('bcdedit'):
            sequences.append("Boot configuration modification (bcdedit)")
        if _args_contain('icacls') or _args_contain('takeown'):
            sequences.append("File permission modification (icacls/takeown)")
        if _args_contain('sc config') or _args_contain('sc stop') or _args_contain('sc delete'):
            sequences.append("Service control via sc.exe")
        if _args_contain('wmic'):
            sequences.append("WMI system management detected")
        if _args_contain('schtasks'):
            sequences.append("Scheduled task manipulation (schtasks)")
        # 用户账号修改
        if _args_contain('net user') or _args_contain('net localgroup'):
            sequences.append("User account modification (net user/localgroup)")
        # 安全策略
        if _args_contain('secedit') or _args_contain('auditpol'):
            sequences.append("Security policy modification (secedit/auditpol)")
        # 系统服务操作
        if 'ControlService' in names_set and 'OpenSCManagerW' in names_set:
            sequences.append("Service control operation (stop/disable security service)")
        if 'DeleteService' in names_set:
            sequences.append("Service deletion attempted")
        # 日志清除
        if _args_contain('wevtutil') or _args_contain('cleareventlog'):
            sequences.append("Event log clearing (anti-forensics)")
        # 影子卷/备份删除
        if _args_contain('vssadmin') or _args_contain('wbadmin'):
            sequences.append("Volume Shadow Copy deletion (ransomware indicator)")
        # 磁盘操作
        if _args_contain('diskpart') or _args_contain('format'):
            sequences.append("Disk partition/format operation detected")

        return sequences
