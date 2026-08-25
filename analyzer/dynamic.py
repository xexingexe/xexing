#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
动态行为分析引擎 — 真正的多线程进程/文件/网络/API 监控
支持沙箱隔离 + Frida API 插桩 + 进程树追踪 + 文件系统监控
"""
import os
import re
import struct
import hashlib
import time
import threading
import tempfile
import shutil
import subprocess
from typing import Tuple
from datetime import datetime

from logger import get_logger
from config import CONFIG
from analyzer.models import DynamicBehavior, SandboxResult, APIMonitorResult
from analyzer.sandbox import Sandbox, _SYSTEM_NOISE_PROCESSES
from analyzer.api_monitor import APIMonitor, frida as _frida
from utils.helpers import calc_entropy, detect_file_type_file
from analyzer.system_monitor import take_registry_snapshot, diff_registry, check_system_state_post_exec, generate_system_report
from analyzer.system_monitor import take_user_snapshot, diff_user_snapshot
from analyzer.system_monitor import take_process_snapshot, diff_processes

logger = get_logger('analyzer.dynamic')

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import win32process
    import win32api
    import win32con
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False

# ===== ctypes 降级层 — 不依赖 pywin32 的内存读取 =====
import ctypes
from ctypes import wintypes, byref, sizeof, Structure, c_void_p, c_ulong, c_ulonglong, c_size_t
_ctypes_kernel32 = ctypes.windll.kernel32
_ctypes_psapi = None
try:
    _ctypes_psapi = ctypes.windll.psapi
except:
    pass


class _MEMORY_BASIC_INFORMATION64(Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.c_ulong),
        ("__alignment1", ctypes.c_ulong),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
        ("__alignment2", ctypes.c_ulong),
    ]


def _ctypes_open_process(pid):
    """ctypes 版本 OpenProcess"""
    if not _ctypes_kernel32:
        return None
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    handle = _ctypes_kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    return handle if handle else None


def _ctypes_handle(h):
    """PyHANDLE / 整数 / 句柄统一转为 c_void_p"""
    try:
        return ctypes.c_void_p(int(h))
    except Exception:
        return ctypes.c_void_p(h)


def _ctypes_virtual_query(h_process, addr):
    """ctypes 版本 VirtualQueryEx（注意: pywin32 没有 win32process.VirtualQueryEx）"""
    if not _ctypes_kernel32:
        return None
    mbi = _MEMORY_BASIC_INFORMATION64()
    result = _ctypes_kernel32.VirtualQueryEx(
        _ctypes_handle(h_process), ctypes.c_void_p(addr),
        byref(mbi), sizeof(mbi)
    )
    if result == 0:
        return None
    return {
        'BaseAddress': mbi.BaseAddress,
        'RegionSize': mbi.RegionSize,
        'State': mbi.State,
        'Protect': mbi.Protect,
        'Type': mbi.Type,
    }


def _ctypes_read_memory(h_process, addr, size):
    """ctypes 版本 ReadProcessMemory"""
    if not _ctypes_kernel32:
        return None
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    ok = _ctypes_kernel32.ReadProcessMemory(
        _ctypes_handle(h_process), ctypes.c_void_p(addr),
        buf, size, byref(bytes_read)
    )
    if not ok or bytes_read.value == 0:
        return None
    return buf.raw[:bytes_read.value]


def _ctypes_close_handle(h):
    if h and _ctypes_kernel32:
        try:
            _ctypes_kernel32.CloseHandle(_ctypes_handle(h))
        except Exception:
            pass


_DEFENDER_MODULES = {
    # Windows Defender / Microsoft Defender for Endpoint 模块 (挂在 svchost 上, 非样本注入)
    'mpoav.dll', 'mpclient.dll', 'mpengine.dll', 'mpasdesc.dll', 'mpsvc.dll',
    'mpcmdrun.exe', 'mpfilter.sys', 'msmpeng.exe', 'nissrv.exe', 'mpsigstub.exe',
    'wdboot.sys', 'wdnisdrv.sys', 'wdfilter.sys', 'mssense.dll', 'sense.dll',
}


def _scan_system_process_injection() -> list:
    """扫描关键系统进程 (lsass/services/winlogon/spoolsv/svchost) 加载的非系统目录模块,
    检测样本向系统进程注入的 DLL (如 SilverFox 向 svchost/lsass 注入 UxEnhance64.dll)。
    执行后分析阶段调用 — Public/Temp/AppData 目录的 DLL 挂在系统进程上即为注入证据。"""
    injections = []
    _TARGET_PROCS = {'lsass.exe', 'services.exe', 'winlogon.exe', 'spoolsv.exe', 'svchost.exe'}
    _SYS_DIRS = ('\\windows\\system32', '\\windows\\syswow64', '\\windows\\winsxs',
                 '\\windows\\microsoft.net', '\\windows\\system')
    try:
        import psutil
        # 声明 argtypes (与 _dump_loaded_modules 一致, 避免 64 位句柄截断)
        _ctypes_kernel32.K32EnumProcessModules.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
        _ctypes_kernel32.K32EnumProcessModules.restype = ctypes.c_int
        _ctypes_kernel32.K32EnumProcessModulesEx.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
            ctypes.POINTER(ctypes.c_uint), ctypes.c_uint]
        _ctypes_kernel32.K32EnumProcessModulesEx.restype = ctypes.c_int
        _ctypes_kernel32.K32GetModuleFileNameExW.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]
        _ctypes_kernel32.K32GetModuleFileNameExW.restype = ctypes.c_uint

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = (proc.info['name'] or '').lower()
                pid = proc.info['pid']
            except Exception:
                continue
            if name not in _TARGET_PROCS:
                continue
            h = _ctypes_open_process(pid)
            if not h:
                continue
            try:
                mods = (ctypes.c_void_p * 2048)()
                cb = ctypes.c_uint(0)
                ok = _ctypes_kernel32.K32EnumProcessModules(
                    _ctypes_handle(h), ctypes.byref(mods), ctypes.sizeof(mods), ctypes.byref(cb))
                if not ok:
                    ok = _ctypes_kernel32.K32EnumProcessModulesEx(
                        _ctypes_handle(h), ctypes.byref(mods), ctypes.sizeof(mods),
                        ctypes.byref(cb), 0x03)  # LIST_MODULES_ALL
                if not ok:
                    continue
                cnt = min(cb.value // ctypes.sizeof(ctypes.c_void_p), 500)
                for i in range(cnt):
                    buf = ctypes.create_unicode_buffer(520)
                    ln = _ctypes_kernel32.K32GetModuleFileNameExW(
                        _ctypes_handle(h), mods[i], buf, 520)
                    if not ln:
                        continue
                    mp = buf.value
                    lp = mp.lower()
                    if not lp.endswith(('.dll', '.exe')):
                        continue
                    if any(sd in lp for sd in _SYS_DIRS):
                        continue
                    if 'frida' in lp or lp.endswith(('symsrv.dll', 'dbghelp.dll')):
                        continue
                    # 过滤 Windows Defender / 系统安全软件模块 (挂在 svchost 上, 非样本注入)
                    if 'windows defender' in lp or '\\microsoft\\windows defender\\' in lp:
                        continue
                    if os.path.basename(lp) in _DEFENDER_MODULES:
                        continue
                    injections.append({'pid': pid, 'process': name, 'module': mp})
            finally:
                _ctypes_close_handle(h)
    except Exception:
        pass
    return injections

# ===== MEM 常量 =====
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000
PAGE_GUARD = 0x100


class BaseMonitorThread(threading.Thread):
    """监控线程基类"""
    def __init__(self, timeout: int):
        super().__init__(daemon=True)
        self.timeout = timeout
        self._stop_event = threading.Event()
        self._start_time = time.time()
        
    def stop(self):
        self._stop_event.set()
        
    def should_stop(self):
        if self._stop_event.is_set():
            return True
        if time.time() - self._start_time > self.timeout:
            self._stop_event.set()
            return True
        return False
    
    def safe_sleep(self, seconds):
        self._stop_event.wait(timeout=seconds)


# 快速 Shellcode 签名
_SC_SIGS = [
    (rb'\xfc\xe8[\x80-\x8f]\x00\x00\x00', 'Metasploit prologue'),
    (rb'\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00', 'CobaltStrike x64 loader'),
    (rb'\x64\x48\x8b\x04\x25\x60', 'x64 PEB access'),
    (rb'ReflectiveLoader\x00', 'ReflectiveLoader export'),
    (rb'\xe9[\x00-\xff]{4}', 'Near JMP hook (E9)'),
    (rb'\xff\x25[\x00-\xff]{4}', 'Absolute JMP hook (FF 25)'),
    (rb'\x68[\x00-\xff]{4}\xc3', 'PUSH addr; RET (detour)'),
    (rb'\xcc{15,}', 'INT3 sled (反调试)'),
]


class ProcessTreeMonitor(BaseMonitorThread):
    """进程树监控 — 追踪目标进程树 + 即时内存快照 + Temp/AppData 子进程链"""
    def __init__(self, root_pid: int, timeout: int, output_list: list, target_file: str = '',
                 memory_snapshots: list = None, dropped_files_list: list = None):
        super().__init__(timeout)
        self.root_pid = root_pid
        self.output_list = output_list
        self._known_pids = set()
        self._scanned_modules = set()  # 已 dump 过的 PID，避免重复
        self._svc_scanned = set()  # 已快照过的 svchost 实例 (防重复扫描)
        self._terminated = []
        self.target_file = target_file
        # 注意: 不能用 `or []` — 空列表是 falsy, 会创建新列表断开与调用方的引用!
        self.memory_snapshots = memory_snapshots if memory_snapshots is not None else []
        # 样本释放文件列表 (FileSystemMonitor 实时写入同一列表) — 用于"释放文件路径
        # 关联"通道: 计划任务/服务/WMI 启动的载荷父进程链断裂, 祖先链判据全部失效,
        # 但它的 exe 必然命中样本释放的文件 (如 MSI→计划任务→z2VIqs.exe)
        self.dropped_files_list = dropped_files_list if dropped_files_list is not None else []
        target_lower = target_file.lower()
        self._track_by_name = target_lower.endswith(('.msi', '.ps1', '.vbs', '.js', '.hta', '.bat', '.cmd'))

    def _released_exe_paths(self) -> set:
        """当前样本已释放的可执行文件绝对路径(小写)

        ⚠ 必须过滤沙箱自身文件 (Frida/NSIS/uv/Python/内存dump) —
        否则 frida-helper.exe 等会被误判为"样本释放的载荷"并被当样本进程收录。
        """
        paths = set()
        try:
            for e in self.dropped_files_list:
                p = e.get('path', '') if isinstance(e, dict) else e
                if not (isinstance(p, str) and p.lower().endswith(
                        ('.exe', '.dll', '.scr', '.com', '.sys'))):
                    continue
                # 过滤沙箱自身产物/正常软件噪音 (与 _is_noise_file 同规则)
                # ⚠ _is_noise_file 是 FileSystemMonitor 的 staticmethod, 须用类名调用
                if FileSystemMonitor._is_noise_file(p):
                    continue
                paths.add(os.path.abspath(p).lower())
        except Exception:
            pass
        return paths

    def _is_released_exe_process(self, pid: int) -> bool:
        """进程 exe 是否命中样本释放的文件 (跨链关联: 计划任务/服务启动的载荷)"""
        try:
            exe = (psutil.Process(pid).exe() or '').lower()
            if not exe:
                return False
            # ⚠ 沙箱/系统进程绝不能判定为样本载荷
            if self._is_sandbox_or_system_process(exe, pid):
                return False
            return exe in self._released_exe_paths()
        except Exception:
            return False

    @staticmethod
    def _is_sandbox_or_system_process(exe: str, pid: int = None) -> bool:
        """判断进程是否为沙箱自身/系统进程 (不应收录为样本进程)"""
        _e = (exe or '').lower()
        _n = ''
        if pid:
            try:
                _n = (psutil.Process(pid).name() or '').lower()
            except Exception:
                pass
        # 沙箱自身: Frida helper / sandbox / python 运行沙箱
        if _n in ('frida-helper.exe', 'frida-helper-x86.exe', 'frida-helper-x86_64.exe',
                  'sandboxanalyzer.exe'):
            return True
        if '\\frida-' in _e:
            return True
        # 系统进程白名单 (conhost/vm3dservice/SecurityHealth 等)
        if _n in _SYSTEM_NOISE_PROCESSES:
            return True
        # 系统目录运行的进程
        if _e and ('\\windows\\' in _e or '\\program files\\' in _e):
            return True
        # ⚠ 用户环境应用 (WPS/Kingsoft) — 用户自己开的合法应用, 非样本
        # (样本若真启动 WPS 会通过进程树父链显示, 不依赖此过滤)
        if '\\kingsoft\\' in _e or '\\wps office\\' in _e:
            return True
        return False

    def _add_process(self, proc):
        """记录新发现的进程 (⚠ 过滤沙箱自身/系统进程, 防误报)"""
        if proc.pid in self._known_pids:
            return
        # 沙箱自身进程 (frida-helper/sandboxanalyzer) 绝不能当样本进程
        try:
            if self._is_sandbox_or_system_process(proc.exe(), proc.pid):
                return
        except Exception:
            pass
        self._known_pids.add(proc.pid)
        try:
            entry = {
                'pid': proc.pid,
                'ppid': proc.ppid(),
                'name': proc.name(),
                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                'exe': proc.exe() or '',
                'create_time': datetime.fromtimestamp(proc.create_time()).strftime('%H:%M:%S')
            }
            self.output_list.append(entry)
            logger.info(f"[Dynamic] New process: {entry['name']} (PID={entry['pid']}, PPID={entry['ppid']})")
            # 即时内存快照 — 趁进程还活着快速扫描
            self._quick_memory_snapshot(proc.pid, entry['name'])
            # 枚举并 dump 加载的 DLL 模块（云沙箱同款能力）
            self._dump_loaded_modules(proc.pid, entry['name'])
        except:
            pass

    def _start_wmi_watcher(self) -> bool:
        """WMI 进程创建事件订阅 (Win32_ProcessStartTrace) — 实时捕获进程创建

        轮询(0.5s)会漏掉毫秒级快速进程和父进程已死的重父(reparent)进程;
        WMI 事件在进程创建瞬间触发, 补全子进程检测盲区。
        """
        try:
            self._wmi_processes = []   # WMI 捕获的进程 (含快速进程)
            self._wmi_known = set()
            self._wmi_watcher = None

            def _wmi_loop():
                import pythoncom
                pythoncom.CoInitialize()
                try:
                    from win32com.client import GetObject
                    # ⚠ COM 对象必须在本线程(CoInitialize之后)创建并调用,
                    #   否则跨线程调用 EventSink.NextEvent 会抛 RPC_E_WRONG_THREAD
                    watcher = GetObject(
                        'winmgmts:\\\\.\\root\\cimv2').ExecNotificationQuery(
                        'SELECT * FROM Win32_ProcessStartTrace')
                    self._wmi_watcher = watcher
                except Exception:
                    self._wmi_watcher = None
                    try:
                        pythoncom.CoUninitialize()
                    except Exception:
                        pass
                    return
                while not self.should_stop():
                    try:
                        evt = watcher.NextEvent(1000)
                        if evt is None:
                            continue
                        try:
                            pid = evt.ProcessID
                            ppid = evt.ParentProcessID
                            name = str(evt.ProcessName or '')
                            cmdline = str(evt.CommandLine or '')[:300]
                        except Exception:
                            continue
                        if pid in self._wmi_known:
                            continue
                        self._wmi_known.add(pid)
                        # 关联判定: 祖先链含 root 或 ppid 链可达已知集合
                        related = False
                        try:
                            cur = ppid
                            seen = set()
                            while cur and cur not in seen:
                                seen.add(cur)
                                if cur == self.root_pid or cur in self._known_pids:
                                    related = True
                                    break
                                try:
                                    cur = psutil.Process(cur).ppid()
                                except Exception:
                                    cur = 0
                        except Exception:
                            pass
                        if not related:
                            # PPID 链断裂 (计划任务 svchost/WMI WmiPrvSE/服务拉起/重父):
                            # Win32_ProcessStartTrace 无 exe 字段, 用命令行中的释放路径兜底判定
                            try:
                                nm = (name or '').lower()
                                if nm in ('frida-helper.exe', 'frida-helper-x86.exe',
                                          'frida-helper-x86_64.exe', 'sandboxanalyzer.exe'):
                                    related = False
                                else:
                                    cl = (cmdline or '').lower()
                                    if cl:
                                        for path in re.findall(r'[a-z]:[\\/][^"\s;|&()]+', cl):
                                            pl = path.lower()
                                            if '\\windows\\' in pl or '\\program files' in pl:
                                                continue
                                            if any(s in pl for s in ('\\appdata\\', '\\public\\',
                                                                     '\\temp\\', '\\programdata\\',
                                                                     '\\windows\\temp\\')):
                                                related = True
                                                break
                            except Exception:
                                pass
                        if not related:
                            # 兜底2: 释放文件路径关联 — 计划任务(ITeWS等)经 svchost
                            # 启动的载荷父进程链断裂, 但 exe 命中样本释放的文件
                            try:
                                if self._is_released_exe_process(pid):
                                    related = True
                            except Exception:
                                pass
                        if not related:
                            continue
                        entry = {
                            'pid': pid, 'ppid': ppid, 'name': name,
                            'cmdline': cmdline, 'exe': '',
                            'create_time': datetime.now().strftime('%H:%M:%S'),
                            'wmi_event': True,  # 标记: WMI 事件捕获 (轮询未见)
                        }
                        self._wmi_processes.append(entry)
                        if pid not in self._known_pids:
                            self.output_list.append(entry)
                            self._known_pids.add(pid)  # ⚠ 同步标记, 防止轮询重复记录
                            logger.info(f"[WMI-Proc] 捕获新进程: {name} (PID={pid}, PPID={ppid})"
                                        + (' [快速/重父]' if pid not in {x['pid'] for x in self.output_list} else ''))
                        # 快速进程可能已死, 尽力快照
                        try:
                            p = psutil.Process(pid)
                            self._quick_memory_snapshot(pid, name)
                        except Exception:
                            pass
                    except Exception:
                        continue
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

            self._wmi_thread = threading.Thread(target=_wmi_loop, daemon=True)
            self._wmi_thread.start()
            logger.info("[+] WMI 进程创建事件订阅已启动 (快速/重父进程实时捕获)")
            return True
        except Exception as e:
            logger.debug(f"WMI 进程事件订阅不可用: {e}")
            self._wmi_processes = []
            return False

    def _dump_loaded_modules(self, pid, proc_name):
        """枚举进程加载的所有 DLL 模块，dump 非系统模块到磁盘"""
        if pid in self._scanned_modules:
            return
        h = None
        try:
            if PYWIN32_AVAILABLE:
                h = win32api.OpenProcess(
                    win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid
                )
            else:
                h = _ctypes_open_process(pid)
            if not h:
                logger.warning(f"[ModuleDump] OpenProcess failed for PID={pid}")
                return

            # 枚举模块 — ⚠ 必须声明 argtypes: K32GetModuleFileNameExW 的
            # 模块句柄参数是 64 位指针, 不声明会溢出转换静默失败 (模块dump全空)
            k32 = _ctypes_kernel32
            k32.K32EnumProcessModules.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p,
                ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
            k32.K32EnumProcessModules.restype = ctypes.c_int
            k32.K32EnumProcessModulesEx.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p,
                ctypes.c_uint, ctypes.POINTER(ctypes.c_uint), ctypes.c_uint]
            k32.K32EnumProcessModulesEx.restype = ctypes.c_int
            k32.K32GetModuleFileNameExW.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]
            k32.K32GetModuleFileNameExW.restype = ctypes.c_uint

            # 枚举模块
            module_handles = (ctypes.c_void_p * 2048)()
            cb_needed = ctypes.c_uint(0)
            ok = False
            err_info = ""

            try:
                ok = _ctypes_kernel32.K32EnumProcessModules(
                    int(h), ctypes.byref(module_handles),
                    ctypes.sizeof(module_handles), ctypes.byref(cb_needed))
                err_info = "K32EnumProcessModules"
            except Exception as e:
                err_info = f"K32EnumProcessModules error: {e}"

            if not ok:
                LIST_MODULES_ALL = 0x03
                try:
                    ok = _ctypes_kernel32.K32EnumProcessModulesEx(
                        int(h), ctypes.byref(module_handles),
                        ctypes.sizeof(module_handles), ctypes.byref(cb_needed),
                        LIST_MODULES_ALL)
                    err_info = "K32EnumProcessModulesEx"
                except Exception as e:
                    err_info = f"K32EnumProcessModulesEx error: {e}"

            if not ok:
                logger.warning(f"[ModuleDump] All enum methods failed for PID={pid}: {err_info}, ret={ok}")
                return

            module_count = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
            module_count = min(module_count, 500)
            logger.info(f"[ModuleDump] PID={pid}: {module_count} total modules")
            if module_count <= 0:
                self._scanned_modules.add(pid)
                return

            # 系统目录，跳过其中的模块
            system_dirs = [
                'C:\\Windows\\System32\\', 'C:\\Windows\\SysWOW64\\',
                'C:\\Windows\\WinSxS\\', 'C:\\Windows\\Microsoft.NET\\',
            ]
            # 系统 DLL 名列表
            system_dll_names = {
                'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll',
                'gdi32.dll', 'advapi32.dll', 'ole32.dll', 'oleaut32.dll',
                'shell32.dll', 'comctl32.dll', 'comdlg32.dll',
                'msvcrt.dll', 'ucrtbase.dll', 'vcruntime140.dll',
                'rpcrt4.dll', 'ws2_32.dll', 'crypt32.dll', 'bcrypt.dll',
                'ncrypt.dll', 'sechost.dll', 'shlwapi.dll', 'imm32.dll',
                'winmm.dll', 'version.dll', 'msi.dll', 'dwmapi.dll',
                'propsys.dll', 'setupapi.dll', 'wintrust.dll', 'msasn1.dll',
                'cfgmgr32.dll', 'powrprof.dll', 'umpdc.dll', 'sspicli.dll',
                'profapi.dll', 'win32u.dll', 'gdi32full.dll', 'bcryptprimitives.dll',
                'wldp.dll', 'windows.storage.dll', 'cryptbase.dll',
            }

            dumped_modules = 0
            fixed_paths = []  # PE dump 修复后的磁盘布局文件 (_fixed.exe)
            for i in range(module_count):
                if dumped_modules >= 15:
                    break
                mod_base = module_handles[i]
                if not mod_base:
                    continue

                # 获取模块路径 — 用 kernel32 K32 版本
                path_buf = ctypes.create_unicode_buffer(520)
                length = 0
                try:
                    length = _ctypes_kernel32.K32GetModuleFileNameExW(
                        int(h), mod_base, path_buf, 520)
                except Exception:
                    pass
                if length == 0:
                    continue
                module_path = path_buf.value

                if not module_path or len(module_path) < 3:
                    continue

                # ⚠ 跳过主程序自身模块 — 它必然在非系统目录(Desktop/下载),
                #   被 dump 后报告会把主模块基址误报为"注入 PE/RWX 区域"
                #   (0x7FF6E1D70000=样本.exe 自身基址的误报根因)
                try:
                    if module_path.lower() == (psutil.Process(pid).exe() or '').lower():
                        continue
                except Exception:
                    pass

                # 跳过系统模块
                name_lower = os.path.basename(module_path).lower()
                if name_lower in system_dll_names:
                    continue
                if any(module_path.lower().startswith(d.lower()) for d in system_dirs):
                    continue
                # ⚠ 跳过沙箱自身 Frida 运行时模块 (Temp\frida-*\frida-agent.dll /
                # symsrv.dll / dbghelp.dll / frida-helper*) — 是注入工具不是样本行为!
                # 否则会把 Frida 注入的符号 DLL 误报为"样本 PE 注入"
                _mp = module_path.lower()
                if '\\frida-' in _mp or 'frida-agent.dll' in _mp or 'frida-helper' in _mp:
                    continue
                if _mp.endswith('symsrv.dll') or _mp.endswith('dbghelp.dll'):
                    # 系统目录的 symsrv/dbghelp 是调试器正常符号加载;
                    # 非系统目录(如 Temp\frida)的已是 Frida 痕迹, 均跳过
                    continue

                # Dump 模块
                try:
                    pe_data = None
                    if PYWIN32_AVAILABLE:
                        pe_data = win32process.ReadProcessMemory(h, mod_base, 0x1000)
                    else:
                        pe_data = _ctypes_read_memory(h, mod_base, 0x1000)

                    if pe_data and len(pe_data) >= 0x200 and pe_data[:2] == b'MZ':
                        pe_off = struct.unpack('<I', pe_data[0x3C:0x40])[0]
                        if pe_off + 0x54 < len(pe_data):
                            img_size = struct.unpack('<I', pe_data[pe_off+0x50:pe_off+0x54])[0]
                            read_size = min(img_size, 10 * 1024 * 1024)
                            full_data = None
                            if PYWIN32_AVAILABLE:
                                full_data = win32process.ReadProcessMemory(h, mod_base, read_size)
                            else:
                                full_data = _ctypes_read_memory(h, mod_base, read_size)
                            if full_data and len(full_data) > 0x200:
                                import config as _cfg
                                ddir = getattr(getattr(_cfg, 'CONFIG', None), 'memory', None)
                                dump_dir = getattr(ddir, 'dump_dir', 'memory_dumps') if ddir else 'memory_dumps'
                                os.makedirs(dump_dir, exist_ok=True)
                                safe_name = os.path.basename(module_path).replace('.', '_')
                                dump_path = os.path.join(dump_dir,
                                    f'pid{pid}_{safe_name}_{int(time.time() * 1000)}.bin')
                                with open(dump_path, 'wb') as df:
                                    df.write(full_data)

                                # ⚠ PE dump 修复: 同时保存"磁盘布局"版本 (RAW=VA 对齐),
                                # 供 pefile/IDA/后续分析直接解析 (内存映像 dump 无法反编译)
                                try:
                                    from analyzer.pe_rebuilder import rebuild_memory_pe
                                    rebuilt = rebuild_memory_pe(full_data, image_base=mod_base)
                                    if rebuilt:
                                        fixed_path = dump_path.rsplit('.', 1)[0] + '_fixed.exe'
                                        with open(fixed_path, 'wb') as ff:
                                            ff.write(rebuilt)
                                        fixed_paths.append(fixed_path)
                                except Exception:
                                    pass

                                sha = hashlib.sha256(full_data).hexdigest()[:16]
                                snap_entry = {
                                    'pid': pid, 'process': proc_name,
                                    'address': f'0x{mod_base:016X}',
                                    'size': read_size,
                                    'architecture': 'x64',
                                    'type': f'内存PE（加载模块）: {os.path.basename(module_path)}',
                                    'module_path': module_path,
                                    'dump_path': dump_path,
                                    'sha256_short': sha,
                                }
                                if fixed_paths:
                                    snap_entry['fixed_path'] = fixed_paths[-1]
                                self.memory_snapshots.append(snap_entry)
                                logger.info(f"[ModuleDump] PID={pid} {os.path.basename(module_path)} ({read_size//1024}KB) -> {sha}")
                                dumped_modules += 1
                except Exception as e:
                    logger.debug(f"[ModuleDump] dump failed for {module_path}: {e}")

            # ⚠ 无论是否 dump 到模块都标记已扫描 — 之前只在 dumped>0 时标记,
            #   主程序被排除(非系统模块但为主进程)的样本每 5 秒无限重扫 (日志刷屏)
            self._scanned_modules.add(pid)
            if dumped_modules > 0:
                logger.info(f"[ModuleDump] PID={pid}: dumped {dumped_modules} non-system modules")

        except Exception as e:
            logger.debug(f"[ModuleDump] PID={pid} error: {e}")
        finally:
            if h:
                if PYWIN32_AVAILABLE:
                    try: win32api.CloseHandle(h)
                    except: pass
                else:
                    _ctypes_close_handle(h)

    def _quick_memory_snapshot(self, pid, proc_name):
        """用 ctypes 或 pywin32 扫描进程内存中的 PE/Shellcode/Hook"""
        h = None
        try:
            # 优先用 pywin32
            if PYWIN32_AVAILABLE:
                h = win32api.OpenProcess(
                    win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid
                )
            else:
                h = _ctypes_open_process(pid)
            if not h:
                logger.debug(f"无法打开进程 PID={pid}")
                return
        except Exception as e:
            logger.debug(f"OpenProcess PID={pid} 失败: {e}")
            return

        try:
            addr = 0
            found_pe = 0
            found_shellcode = 0
            found_hooks = 0
            scanned = 0
            max_scans = 2000  # 覆盖足够多区域
            scannable_prots = {0x04, 0x10, 0x20, 0x40, 0x80, 0x08, 0x02}
            addr_limit = 0x7FFEFFFF if struct.calcsize('P') == 4 else 0x7FFFFFFFFFFF

            # 已知加载模块地址范围 — 排除合法模块内的MZ/钩子误报
            while addr < addr_limit and scanned < max_scans:
                try:
                    # 注意: pywin32 的 win32process 没有 VirtualQueryEx!
                    # 统一走 ctypes 实现（对 PyHANDLE 同样可用）
                    mbi_info = _ctypes_virtual_query(h, addr)
                    if not mbi_info:
                        break
                    base_addr = mbi_info['BaseAddress']
                    size = mbi_info['RegionSize']
                    prot = mbi_info['Protect'] & ~PAGE_GUARD
                    state = mbi_info['State']
                except Exception:
                    break

                scanned += 1
                # 只扫描 MEM_PRIVATE 私有区域 — 注入载荷只出现在私有内存,
                # 跳过 MEM_IMAGE/MEM_MAPPED 可彻底消除合法模块/数据映射中的MZ/E9巧合误报
                if (state == MEM_COMMIT and size > 0x2000 and prot in scannable_prots
                        and mbi_info['Type'] == 0x20000):
                    try:
                        read_size = min(size, 0x300000)
                        if PYWIN32_AVAILABLE:
                            try:
                                data = win32process.ReadProcessMemory(h, base_addr, read_size)
                            except Exception:
                                data = _ctypes_read_memory(h, base_addr, read_size)
                        else:
                            data = _ctypes_read_memory(h, base_addr, read_size)
                        if not data:
                            addr = base_addr + size
                            continue

                        # PE 扫描 — 私有区域内的 MZ+PE（已过滤模块/映射区域）
                        pos = data.find(b'MZ')
                        if pos != -1 and pos + 0x40 < len(data):
                            pe_off = struct.unpack('<I', data[pos+0x3C:pos+0x40])[0]
                            if pe_off + 6 < len(data) and data[pos+pe_off:pos+pe_off+4] == b'PE\x00\x00':
                                pe_addr = base_addr + pos
                                sections = struct.unpack('<H', data[pos+pe_off+6:pos+pe_off+8])[0]
                                machine = struct.unpack('<H', data[pos+pe_off+4:pos+pe_off+6])[0]
                                arch = 'x64' if machine == 0x8664 else 'ARM64' if machine == 0xAA64 else 'x86'
                                # sanity: 节区数量合理 + 机器类型已知, 过滤字符串巧合误报
                                if not (0 < sections <= 40 and machine in (0x14C, 0x8664, 0xAA64, 0x1C0)):
                                    addr = base_addr + size
                                    continue
                                # 节区名校验(软过滤): 尝试解析, 解析失败不阻止 —
                                # 混淆/加密样本的内存PE节区表常被破坏(XOR/加密), 硬过滤会导致漏报
                                # (回归: cba3ac2e.exe 等混淆样本注入PE被节区名检查漏掉, 内存取证为空)
                                sec_names = []
                                try:
                                    opt_hdr_size = struct.unpack('<H', data[pos+pe_off+20:pos+pe_off+22])[0]
                                    sec_start = pos + pe_off + 24 + opt_hdr_size
                                    for i in range(min(sections, 8)):
                                        nm = data[sec_start + i*40:sec_start + i*40 + 8]
                                        if all(b == 0 or 0x20 <= b < 0x7f for b in nm):
                                            sec_names.append(nm.rstrip(b'\x00').decode('ascii', errors='ignore'))
                                except Exception:
                                    pass  # 解析失败 → 视为可能被破坏的PE, 继续检测
                                # 节区名全部可解析且全部非法(非ASCII)时才视为字符串巧合
                                if sec_names and not any(sec_names):
                                    addr = base_addr + size
                                    continue
                                prot_names = {0x04:'RW', 0x20:'RX', 0x40:'RWX', 0x08:'WC'}
                                try:
                                    entry_rva = struct.unpack('<I', data[pos+pe_off+40:pos+pe_off+44])[0]
                                    timestamp = struct.unpack('<I', data[pos+pe_off+8:pos+pe_off+12])[0]
                                    from datetime import datetime
                                    # 验证时间戳有效性 (Unix时间戳范围: 1970-01-01 到 2038-01-19)
                                    if 0 < timestamp < 2147483647:
                                        ts_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')
                                    else:
                                        ts_str = 'invalid'
                                except:
                                    entry_rva = 0; ts_str = '?'


                                dump_path = ''
                                try:
                                    import config
                                    ddir = getattr(getattr(config, 'CONFIG', None), 'memory', None)
                                    if ddir:
                                        dump_dir = getattr(ddir, 'dump_dir', 'memory_dumps')
                                    else:
                                        dump_dir = 'memory_dumps'
                                    os.makedirs(dump_dir, exist_ok=True)
                                    safe_addr = f'{base_addr + pos:08X}'
                                    dump_path = os.path.join(dump_dir,
                                        f'pid{pid}_{safe_addr}_{int(time.time() * 1000)}.bin')
                                    with open(dump_path, 'wb') as df:
                                        df.write(data[:min(len(data), 5 * 1024 * 1024)])
                                except Exception:
                                    pass

                                self.memory_snapshots.append({
                                    'pid': pid, 'process': proc_name,
                                    'address': f'0x{pe_addr:08X}',
                                    'size': size,
                                    'architecture': arch, 'sections': sections,
                                    'type': '内存PE映像（疑似注入/镂空）',
                                    'region_protect': prot_names.get(prot, f'0x{prot:02X}'),
                                    'entry_rva': f'0x{entry_rva:08X}',
                                    'timestamp': ts_str,
                                    'dump_path': dump_path,
                                })
                                logger.warning(f"[!] 内存PE: PID={pid} {proc_name} @ 0x{pe_addr:08X} ({arch} {sections}节)")
                                found_pe += 1

                        # Shellcode — 排除索引4-6(E9/FF25/PUSH-RET钩子特征, 由Hook检测单独处理)
                        if found_shellcode < 3:
                            for sig, desc in (_SC_SIGS[:4] + _SC_SIGS[7:]):
                                if re.search(sig, data):
                                    self.memory_snapshots.append({
                                        'pid': pid, 'process': proc_name,
                                        'address': f'0x{base_addr:08X}',
                                        'type': f'Shellcode: {desc}',
                                        'size': size,
                                    })
                                    found_shellcode += 1
                                    break

                        # Hook — 只在私有(非模块)可执行区域检测, 避免正常模块内E9误报。
                        # ⚠ 阈值收紧: 私有区含少量 E9 (样本自身代码/跳转表/switch 表) 极常见,
                        #   真 inline hook 链 = 同一区域大量连续 detour 指令 (≥8), 否则误报
                        #   (曾把样本自身私有代码报成 "Inline Hook: E9 ×2")
                        if found_hooks < 3 and prot in (0x20, 0x40, 0x10) and mbi_info['Type'] == 0x20000:
                            for sig, desc in _SC_SIGS[4:7]:
                                matches = re.findall(sig, data[:0x1000])
                                if len(matches) >= 8:
                                    self.memory_snapshots.append({
                                        'pid': pid, 'process': proc_name,
                                        'address': f'0x{base_addr:08X}',
                                        'type': f'Inline Hook: {desc} ×{len(matches)}',
                                        'size': size,
                                    })
                                    found_hooks += 1
                                    break

                    except Exception:
                        pass

                addr = base_addr + size
                if addr > 0x7FFFFFFFFFFF or (found_pe >= 5 and found_shellcode >= 3):
                    break

            if found_pe == 0 and found_shellcode == 0:
                logger.debug(f"[Memory] PID={pid} {proc_name}: 扫描{scanned}区域, 无异常")
            else:
                logger.info(f"[Memory] PID={pid} {proc_name}: PE×{found_pe} SC×{found_shellcode} Hook×{found_hooks}")

        except Exception as e:
            logger.debug(f"[Memory] PID={pid} 扫描异常: {e}")
        finally:
            if PYWIN32_AVAILABLE:
                try: win32api.CloseHandle(h)
                except: pass
            else:
                _ctypes_close_handle(h)

    def run(self):
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil 未安装，跳过进程树监控")
            return

        try:
            root = psutil.Process(self.root_pid)
            self._add_process(root)
            for child in root.children(recursive=True):
                self._add_process(child)
        except psutil.NoSuchProcess:
            logger.warning(f"Root PID {self.root_pid} not found at start")
            return
        except Exception as e:
            logger.error(f"ProcessTreeMonitor init error: {e}")
            return

        # WMI 进程创建事件订阅 — 实时捕获轮询漏掉的快速/重父(reparent)进程
        wmi_ok = self._start_wmi_watcher()
        self._start_ts = time.time()  # 用于 svchost 新实例识别
        loop_count = 0
        root_exit_reported = False

        def _is_related(proc_pid):
            """沿 ppid 链上溯, 判断进程是否与样本进程树相关（防止误监控系统进程）"""
            seen = set()
            p = proc_pid
            while p and p not in seen:
                seen.add(p)
                if p == self.root_pid or p in self._known_pids:
                    return True
                try:
                    p = psutil.Process(p).ppid()
                except Exception:
                    return False
            return False

        def _is_suspicious_new(proc_info, window_start):
            """执行窗口内启动 + 非系统目录 + 非系统进程 → 判定为样本释放进程

            覆盖 PPID 链断裂场景: 计划任务(svchost父)/WMI(WmiPrvSE父)/服务拉起/孤儿重父进程。
            """
            try:
                ct = proc_info.get('create_time') or 0
                if not ct or ct < window_start:
                    return False
                name = (proc_info.get('name') or '').lower()
                if name in _SYSTEM_NOISE_PROCESSES:
                    return False
                if name in ('frida-helper.exe', 'frida-helper-x86.exe',
                            'frida-helper-x86_64.exe', 'sandboxanalyzer.exe'):
                    return False
                exe = (proc_info.get('exe') or '').lower()
                if not exe:
                    return False
                if '\\windows\\' in exe or '\\program files' in exe:
                    return False
                # ⚠ 用户环境应用 (WPS/Office/看图/媒体播放器) — 用户自己开的,
                # 不是样本释放 (样本可能触发但那是进程树关系, 父链断裂的
                # 孤立 WPS 实例是用户操作噪音)
                if '\\kingsoft\\' in exe or '\\wps office\\' in exe:
                    return False
                suspicious_paths = ['\\appdata\\', '\\public\\', '\\temp\\',
                                  '\\programdata\\', '\\windows\\temp\\']
                return any(p in exe for p in suspicious_paths)
            except Exception:
                return False

        while not self.should_stop():
            loop_count += 1
            root_alive = True
            try:
                root = psutil.Process(self.root_pid)
                if not root.is_running():
                    root_alive = False
            except psutil.NoSuchProcess:
                root_alive = False
            except Exception:
                root_alive = False

            try:
                if root_alive:
                    for child in root.children(recursive=True):
                        self._add_process(child)
                elif self._track_by_name:
                    # ⚠ 修复: 根进程(如 msiexec)死后, 原逻辑在 psutil.Process(root_pid)
                    # 处每次抛 NoSuchProcess, 下方载荷追踪代码永不执行 — 计划任务/WMI
                    # 拉起的释放进程全部漏检。必须继续执行下方全表扫描。
                    if not root_exit_reported:
                        root_exit_reported = True
                        logger.info("[Dynamic] Root exited, continuing to track payload...")
                else:
                    logger.info("[Dynamic] Root process exited")
                    break

                window_start = self._start_ts - 5

                # 搜索范围：MSI/脚本模式追踪系统工具 + Temp目录进程
                if self._track_by_name:
                    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline', 'exe', 'create_time']):
                        name = (proc.info['name'] or '').lower()
                        if name in ('msiexec.exe', 'cmd.exe', 'schtasks.exe', 'reg.exe',
                                    'powershell.exe', 'wscript.exe', 'cscript.exe',
                                    'rundll32.exe', 'mshta.exe', 'msbuild.exe',
                                    'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe'):
                            # 只追踪与样本进程树相关的系统工具, 不碰系统上无关实例
                            if not (_is_related(proc.info['pid'])
                                    or (proc.info['ppid'] or 0) in self._known_pids
                                    or _is_suspicious_new(proc.info, window_start)):
                                continue
                            try:
                                p = psutil.Process(proc.info['pid'])
                                self._add_process(p)
                                for child in p.children(recursive=True):
                                    self._add_process(child)
                            except:
                                pass
                        exe_path = (proc.info['exe'] or '').lower()
                        suspicious_paths = ['\\appdata\\', '\\public\\', '\\temp\\',
                                          '\\programdata\\', '\\windows\\temp\\']
                        if any(p in exe_path for p in suspicious_paths):
                            if not (_is_related(proc.info['pid'])
                                    or (proc.info['ppid'] or 0) in self._known_pids
                                    or _is_suspicious_new(proc.info, window_start)):
                                continue
                            try:
                                p = psutil.Process(proc.info['pid'])
                                self._add_process(p)
                                for child in p.children(recursive=True):
                                    self._add_process(child)
                            except:
                                pass

                # 对所有样本：追踪从临时目录启动的子进程
                for proc in psutil.process_iter(['pid', 'ppid', 'exe', 'name', 'create_time']):
                    exe_path = (proc.info['exe'] or '').lower()
                    suspicious_paths = ['\\appdata\\', '\\public\\', '\\temp\\',
                                      '\\programdata\\', '\\windows\\temp\\']
                    if any(p in exe_path for p in suspicious_paths):
                        ppid = proc.info['ppid'] or 0
                        if ppid in self._known_pids or ppid == self.root_pid \
                                or _is_suspicious_new(proc.info, window_start):
                            try:
                                p = psutil.Process(proc.info['pid'])
                                self._add_process(p)
                                for child in p.children(recursive=True):
                                    self._add_process(child)
                            except:
                                pass

                # 释放文件路径关联通道 — 计划任务/服务/WMI 启动的载荷父进程链断裂
                # (如 MSI→ITeWS计划任务→svchost→z2VIqs.exe), 祖先链判据全部失效;
                # 只要进程 exe 命中样本已释放的可执行文件, 无条件纳入追踪
                # (路径是样本自己释放的, 不可能误伤系统进程)
                try:
                    released_exes = self._released_exe_paths()
                    if released_exes:
                        for proc in psutil.process_iter(['pid', 'ppid', 'exe', 'name']):
                            try:
                                exe_l = (proc.info['exe'] or '').lower()
                                if not exe_l or exe_l not in released_exes:
                                    continue
                                if proc.info['pid'] in self._known_pids:
                                    continue
                                p = psutil.Process(proc.info['pid'])
                                self._add_process(p)
                                for child in p.children(recursive=True):
                                    self._add_process(child)
                            except:
                                pass
                except Exception:
                    pass

                # 每 5 秒（10 个循环）重扫已知进程的模块（DLL 可能后加载）
                if loop_count % 10 == 0:
                    for pid in list(self._known_pids):
                        try:
                            p = psutil.Process(pid)
                            if p.is_running():
                                self._dump_loaded_modules(pid, p.name())
                        except Exception:
                            pass

                # 每 30 秒（60 个循环）全内存 PE 快照 — 长存活样本(msiexec/pythonw等)
                # 在载荷注入/解密后的内存窗口不能错过 (修复: 无子进程时快照从不执行)
                if loop_count % 60 == 0:
                    for pid in list(self._known_pids):
                        try:
                            p = psutil.Process(pid)
                            if p.is_running():
                                self._quick_memory_snapshot(pid, p.name())
                        except Exception:
                            pass
                    # 关键系统进程注入检测 — vssvc.exe (卷影服务, 勒索/备份破坏常注入)
                    # ⚠ 不加入 _known_pids, 用 _svc_scanned 防重复快照
                    try:
                        for p in psutil.process_iter(['pid', 'name']):
                            if p.info['name'] and p.info['name'].lower() in (
                                    'vssvc.exe', 'swprv.exe', 'sqlwriter.exe'):
                                if p.info['pid'] not in self._svc_scanned:
                                    self._svc_scanned.add(p.info['pid'])
                                    self._quick_memory_snapshot(p.info['pid'], p.info['name'])
                    except Exception:
                        pass
                    # svchost 注入检测 — 只扫分析期间新启动的实例 (全量太吵)
                    # ⚠ 不加入 _known_pids: 避免全部 svchost 进入周期快照/回调扫描 (性能灾难)
                    try:
                        for p in psutil.process_iter(['pid', 'name', 'create_time']):
                            if p.info['name'] and p.info['name'].lower() == 'svchost.exe':
                                try:
                                    ct = p.info['create_time'] or 0
                                except Exception:
                                    ct = 0
                                if ct and ct >= self._start_ts - 2:
                                    if p.info['pid'] not in self._svc_scanned:
                                        self._svc_scanned.add(p.info['pid'])
                                        self._quick_memory_snapshot(p.info['pid'], 'svchost.exe')
                    except Exception:
                        pass

            except Exception as e:
                logger.debug(f"ProcessTreeMonitor error: {e}")

            self.safe_sleep(0.5)


class FileSystemMonitor(BaseMonitorThread):
    """文件系统监控 — ReadDirectoryChangesW 事件驱动 (零轮询, 只在文件变化时回调)

    ⚠ 旧版每 2 秒 os.walk 全量目录树: 目录大时 CPU 占满 + GIL 竞争,
    导致 GUI 未响应/后分析卡死。本版用 Windows 原生 ReadDirectoryChangesW:
      - 阻塞等待目录变化事件, 无轮询开销, 变化即回调
      - 每监控目录一个监听线程 (多线程, 各目录独立)
      - 只关注文件创建/写入 (FILE_ACTION_ADDED/MODIFIED), 忽略目录变更噪音
      - 智能过滤: 扩展名白名单(样本释放特征) + 噪音目录 + 浏览器缓存
    """
    # 样本释放文件特征扩展名 (只监控这些, 过滤正常文件)
    SUSPICIOUS_EXTS = (
        '.exe', '.dll', '.scr', '.sys', '.com', '.pif', '.bat', '.cmd',
        '.ps1', '.vbs', '.vbe', '.js', '.jse', '.hta', '.wsf', '.wsh',
        '.msi', '.dat', '.tmp', '.jpg', '.jpeg', '.png', '.gif', '.ico',
        '.bin', '.db', '.ini', '.cfg', '.config', '.reg', '.lnk',
        '.lock', '.lck', '.sock',
        '.docm', '.xlsm', '.pptm', '.zip', '.rar', '.7z',
    )
    # 文件大小上限 (超过不分析内容, 只记录路径)
    MAX_META_SIZE = 50 * 1024 * 1024

    def __init__(self, watch_dir, timeout: int, created: list, modified: list, deleted: list, exec_start: float = None):
        super().__init__(timeout)
        self.watch_dirs = [watch_dir] if isinstance(watch_dir, str) else watch_dir
        self.created = created
        self.modified = modified
        self.deleted = deleted
        self._snapshot = {}  # 兼容旧字段 (保留, 事件驱动不使用)
        self.exec_start = exec_start or time.time()  # 样本执行开始时间
        # 额外监控的目录（样本可能释放文件到这些位置）
        # ⚠ 覆盖所有高频释放点: ProgramData/Public/用户文档目录/启动文件夹/
        #    计划任务目录/驱动目录 — 缺失任一都可能导致释放文件漏检
        self._extra_dirs = []
        _extra_candidates = [
            os.environ.get('APPDATA', ''),                     # Roaming (整树)
            os.environ.get('PUBLIC', ''),                      # Public (整树)
            os.environ.get('ProgramData', 'C:\\ProgramData'),  # ProgramData (整树!)
            os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Temp'),
            os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Installer'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Temp'),
            # 用户文档目录 (样本释放伪装文档/钓鱼文件)
            os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
            # 启动文件夹 (持久化)
            os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'),
                         'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows',
                         'Start Menu', 'Programs', 'Startup'),
            # 计划任务/驱动目录 (ITeWS 任务 XML / 恶意驱动释放)
            os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32', 'Tasks'),
            os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32', 'drivers'),
        ]
        for d in _extra_candidates:
            if d and os.path.exists(d):
                self._extra_dirs.append(d)
        # 恶意软件特定释放目录必须加
        for d in ['C:\\cygwin', 'C:\\cygwin64',
                  os.path.join(os.environ.get('APPDATA', ''), 'Roaming', 'Microsoft', 'EdgeUpdate'),
                  os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'EdgeUpdate')]:
            if d and os.path.exists(d):
                self._extra_dirs.append(d)
        # 用户本地应用数据根 + 用户配置根
        _extra_candidates_v2 = [
            os.environ.get('LOCALAPPDATA', ''),
            os.environ.get('USERPROFILE', ''),
        ]
        for d in _extra_candidates_v2:
            if d and os.path.exists(d) and d not in self._extra_dirs:
                self._extra_dirs.append(d)
        # 所有监控目录 (去重)
        self._monitor_dirs = []
        seen = set()
        for d in self.watch_dirs + self._extra_dirs:
            dl = os.path.abspath(d).lower()
            if dl not in seen and os.path.isdir(d):
                seen.add(dl)
                self._monitor_dirs.append(os.path.abspath(d))
        # 事件监听线程
        self._watch_threads = []
        self._rwd_handles = []
        # ReadDirectoryChangesW 缓冲 (每目录 64KB)
        self._rwd_bufs = []
        # 事件去重 (ADDED/MODIFIED 双事件 + 多线程回调)
        self._seen_paths = set()
        self._seen_deleted = set()
        self._created_final = set()  # 已完成元数据捕获的路径 (防后台重复)
        self._seen_lock = threading.Lock()
        # 元数据捕获线程池 (事件驱动不阻塞监听循环)
        import concurrent.futures as _cf
        self._meta_pool = _cf.ThreadPoolExecutor(max_workers=4)

    # ===== ReadDirectoryChangesW 底层 =====
    @staticmethod
    def _init_rwd():
        """初始化 ctypes 绑定 (惰性, 只初始化一次)"""
        if hasattr(FileSystemMonitor, '_rwd_ready'):
            return True
        try:
            import ctypes
            from ctypes import wintypes
            k32 = ctypes.windll.kernel32
            # CreateFileW 打开目录
            k32.CreateFileW.restype = wintypes.HANDLE
            # ReadDirectoryChangesW
            k32.ReadDirectoryChangesW.argtypes = [
                wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                wintypes.BOOL, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                ctypes.c_void_p, ctypes.c_void_p]
            k32.ReadDirectoryChangesW.restype = wintypes.BOOL
            FileSystemMonitor._k32 = k32
            FileSystemMonitor._rwd_ready = True
            return True
        except Exception:
            FileSystemMonitor._rwd_ready = False
            return False

    # ReadDirectoryChangesW 常量
    FILE_LIST_DIRECTORY = 0x0001
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OVERLAPPED = 0x40000000
    # 通知过滤: 文件创建 + 文件写入 (不监控目录本身/属性/安全, 减噪音)
    FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
    FILE_NOTIFY_CHANGE_SIZE = 0x00000008
    FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
    # 动作
    FILE_ACTION_ADDED = 1
    FILE_ACTION_MODIFIED = 2
    FILE_ACTION_REMOVED = 3
    FILE_ACTION_RENAMED_OLD = 4
    FILE_ACTION_RENAMED_NEW = 5

    def _open_dir(self, path: str):
        """CreateFileW 打开目录句柄"""
        try:
            k32 = self._k32
            h = k32.CreateFileW(
                path, self.FILE_LIST_DIRECTORY,
                self.FILE_SHARE_READ | self.FILE_SHARE_WRITE | self.FILE_SHARE_DELETE,
                None, self.OPEN_EXISTING,
                self.FILE_FLAG_BACKUP_SEMANTICS | self.FILE_FLAG_OVERLAPPED, None)
            return h if h and h != -1 else None
        except Exception:
            return None

    def _watch_dir_loop(self, dir_path: str, buf_size: int = 262144, recursive: bool = False):
        """单个目录的 ReadDirectoryChangesW 监听循环 — 阻塞等待变化

        recursive=True 时监控整个子树 (新目录自动纳入) —
        释放母目录 (Public/AppData/Temp/ProgramData) 用递归, 噪音靠 _is_noise_file 过滤。

        ⚠ 缓冲 256KB (默认64KB): 样本批量释放(解压数百文件)时小缓冲溢出
        会静默丢事件; 溢出时 ReadDirectoryChangesW 返回 ERROR_NOTIFY_ENUM_DIR,
        此时对该目录做一次快速重扫兜底, 把漏掉的文件补回来。
        """
        h = self._open_dir(dir_path)
        if not h:
            logger.debug(f"[FSWatch] 无法打开目录: {dir_path}")
            return
        self._rwd_handles.append(h)
        buf = ctypes.create_string_buffer(buf_size)
        bytes_returned = ctypes.c_ulong(0)
        ERROR_NOTIFY_ENUM_DIR = 1022  # 缓冲溢出
        while not self.should_stop():
            try:
                ok = self._k32.ReadDirectoryChangesW(
                    h, buf, buf_size, recursive,
                    self.FILE_NOTIFY_CHANGE_FILE_NAME | self.FILE_NOTIFY_CHANGE_SIZE | self.FILE_NOTIFY_CHANGE_LAST_WRITE,
                    ctypes.byref(bytes_returned), None, None)
                if not ok:
                    err = ctypes.windll.kernel32.GetLastError()
                    if err == ERROR_NOTIFY_ENUM_DIR:
                        logger.warning(f"[FSWatch] 目录事件缓冲溢出 ({dir_path}) — 重扫兜底")
                        self._rescan_dir(dir_path, recursive)
                    time.sleep(0.5)
                    continue
                if bytes_returned.value == 0:
                    continue
                self._process_events(buf.raw[:bytes_returned.value], dir_path, recursive)
            except Exception:
                time.sleep(0.5)
                continue
        try:
            ctypes.windll.kernel32.CloseHandle(h)
        except Exception:
            pass

    def _rescan_dir(self, dir_path: str, recursive: bool):
        """缓冲溢出兜底: 快速重扫目录, 把溢出期间漏掉的新文件补回来"""
        try:
            for root, dirs, files in os.walk(dir_path):
                if not recursive and root != dir_path:
                    dirs[:] = []
                if '_artifacts_' in root:
                    dirs[:] = []
                    continue
                for f in files:
                    full = os.path.join(root, f)
                    if self._path_in_created(full):
                        continue
                    if self._seen_paths and os.path.abspath(full).lower() in self._seen_paths:
                        continue
                    try:
                        st = os.stat(full)
                        if st.st_ctime < self.exec_start - 5:
                            continue
                    except OSError:
                        continue
                    self._on_file_event(full)
        except Exception:
            pass

    def _process_events(self, data: bytes, base_dir: str, recursive: bool = False):
        """解析 FILE_NOTIFY_INFORMATION 结构, 处理文件事件

        结构: NextEntryOffset(DWORD) Action(DWORD) FileNameLength(DWORD) FileName[]
        ⚠ Action 是 DWORD(4字节) — 用 H 会错位导致乱码路径
        recursive 时事件路径是相对监控根的相对路径, 需拼接完整路径。
        """
        import struct
        pos = 0
        while pos + 12 <= len(data):
            try:
                next_off, action, name_len = struct.unpack_from('<LLL', data, pos)
                name_bytes = data[pos + 12:pos + 12 + name_len]
                # 文件名是 UTF-16LE, name_len 是字节数 — 必须为偶数
                if name_len % 2 != 0:
                    break
                rel = name_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
                if not rel:
                    break
                # 相对路径可能含子目录 (递归模式): rel = 'UjIl9a\\z2VIqs.exe'
                full_path = os.path.join(base_dir, rel)
                if action in (self.FILE_ACTION_ADDED, self.FILE_ACTION_MODIFIED):
                    self._on_file_event(full_path)
                elif action == self.FILE_ACTION_REMOVED:
                    self._on_file_removed(full_path)
                elif action == self.FILE_ACTION_RENAMED_NEW:
                    # renamed file - treat as new creation
                    try:
                        new_name = name_bytes.decode('utf-16-le', errors='replace').rstrip('')
                        new_path = os.path.join(base_dir, new_name)
                        self._on_file_event(new_path)
                    except Exception:
                        pass

                if next_off == 0:
                    break
                pos += next_off
            except Exception:
                break

    def _should_watch(self, path: str) -> bool:
        """是否记录此文件事件

        策略: 默认记录 + 噪音排除 (不是扩展名白名单!)
          - 排除: 沙箱产物目录/目录本身/浏览器缓存/杀软系统软件目录
          - 默认放行所有文件 — 勒索信(.txt) 窃密导出(.csv/.json) 伪装载荷
            等任何扩展名都可能是有价值的样本行为, 白名单会漏
          - 仅对"纯系统噪音扩展名"(如 .log/.etl 事件日志)做节流, 不删除
        """
        try:
            if '_artifacts_' in path:
                return False
            if os.path.isdir(path):
                return False
            # 噪音目录
            if self._is_noise_file(path):
                return False
            # 系统软件正常活动目录 (360/火绒/杀软/浏览器/更新器 — 非样本释放)
            pl = path.lower()
            _sys_noise_dirs = (
                '\\360safe\\', '\\360\\', '\\huorong\\', '\\hips',
                '\\windows defender\\', '\\microsoft\\windows defender\\',
                '\\usoshared\\', '\\softwaredistribution\\', '\\servicing\\',
                '\\google\\chrome\\', '\\microsoft\\edge\\', '\\mozilla\\',
                '\\weixin\\', '\\wechat\\', '\\tencent\\', '\\qq\\',
                '\\programdata\\microsoft\\windows\\wlan\\', '\\prefetch\\',
            )
            if any(s in pl for s in _sys_noise_dirs):
                return False
            # 系统自身高频写扩展名 (事件日志/数据库/临时) — 全记录会刷屏,
            # 这些几乎不可能是样本行为, 节流掉
            _sys_noise_exts = ('.etl', '.log', '.evtx', '.ldb', '.blf',
                               '.regtrans-ms', '.jrs')
            ext = os.path.splitext(path)[1].lower()
            if ext in _sys_noise_exts:
                return False
            return True  # 其余默认记录
        except Exception:
            return False

    def _on_file_event(self, path: str):
        """文件创建/修改事件 → 过滤 → 记录

        ⚠ 快速返回: 事件监听线程不能阻塞 (批量释放时 sleep 会让事件
        处理排队, 缓冲被覆盖丢事件)。元数据读取放后台线程池。
        """
        try:
            if not self._should_watch(path):
                return
            # 创建时间过滤: 必须晚于样本执行开始
            try:
                st = os.stat(path)
                if st.st_ctime < self.exec_start - 5:
                    return
            except OSError:
                return
            # 去重 (独立集合 + 锁 — ADDED/MODIFIED 双事件可能几乎同时到达)
            pl = os.path.abspath(path).lower()
            with self._seen_lock:
                if pl in self._seen_paths:
                    return
                self._seen_paths.add(pl)
            if self._path_in_created(path):
                return
            # 异步: 后台线程延迟读元数据 (文件写入稳定后), 不阻塞事件循环
            try:
                self._meta_pool.submit(self._capture_later, path, pl)
            except Exception:
                self._capture_later(path, pl)
        except Exception:
            pass

    def _capture_later(self, path: str, pl: str):
        """后台: 延迟 0.3s 等文件写完, 再捕获元数据"""
        try:
            time.sleep(0.3)
            entry = self._capture_file_meta(path)
            if not entry or not entry.get('size'):
                # file already deleted (transient) - still record path
                with self._seen_lock:
                    if pl in self._created_final:
                        return
                    self._created_final.add(pl)
                self.created.append({
                    'path': path, 'size': 0, 'md5': '', 'sha256': '',
                    'file_type': 'deleted_transient', 'entropy': 0.0,
                })
                logger.info(f"[Dynamic] File created then deleted: {path}")
                return
            with self._seen_lock:
                if pl in self._created_final:
                    return
                self._created_final.add(pl)
            self.created.append(entry)
            logger.info(f"[Dynamic] File created: {path}")
        except Exception:
            pass

    def _on_file_removed(self, path: str):
        """文件删除事件 → 记录 (默认记录, 仅排除噪音)

        删除事件价值: 样本删除自己释放的载荷/痕迹/勒索信/配置。
        """
        try:
            if '_artifacts_' in path:
                return
            if self._is_noise_file(path):
                return
            # 目录删除事件忽略 (目录本身非载荷)
            if os.path.isdir(path) or not os.path.splitext(path)[1]:
                return
            # 复用创建事件的噪音过滤 (360/杀软/浏览器/系统日志等)
            if not self._should_watch(path):
                return
            pl = os.path.abspath(path).lower()
            with self._seen_lock:
                if pl in self._seen_deleted:
                    return
                self._seen_deleted.add(pl)
            if path not in self.deleted:
                self.deleted.append(path)
                logger.info(f"[Dynamic] File deleted: {path}")
        except Exception:
            pass

    def _capture_file_meta(self, path: str) -> dict:
        """检测到新文件时立即捕获元数据"""
        meta = {'path': path, 'size': 0, 'md5': '', 'sha256': '', 'entropy': 0.0,
                'file_type': 'Unknown', 'is_suspicious': False}
        try:
            if os.path.isfile(path):
                size = os.path.getsize(path)
                meta['size'] = size
                # 特征扩展名 → 可疑标记 (仅标记, 不影响记录)
                ext = os.path.splitext(path)[1].lower()
                meta['is_suspicious'] = ext in self.SUSPICIOUS_EXTS
                if 0 < size < self.MAX_META_SIZE:
                    with open(path, 'rb') as fp:
                        data = fp.read()
                    meta['md5'] = hashlib.md5(data).hexdigest()
                    meta['sha256'] = hashlib.sha256(data).hexdigest()
                    if size < 10 * 1024 * 1024:
                        meta['entropy'] = calc_entropy(data)
                    meta['file_type'], _ = detect_file_type_file(path)
        except Exception:
            pass
        return meta

    def _path_in_created(self, path: str) -> bool:
        """检查路径是否已在 created 列表中（支持 dict 和 str 混合）"""
        for e in self.created:
            ep = e['path'] if isinstance(e, dict) else e
            if ep == path:
                return True
        return False

    @staticmethod
    def _is_noise_file(path: str) -> bool:
        """浏览器/系统正常活动的噪音文件过滤 — 防止分析期间用户操作污染报告"""
        pl = path.lower()
        # 浏览器用户数据目录(Edge/Chrome/Firefox 缓存、存储、组件更新)
        browser_dirs = (
            '\\edge\\user data\\', '\\chrome\\user data\\', '\\chromium\\user data\\',
            '\\firefox\\profiles\\', '\\opera\\', '\\brave\\user data\\',
        )
        if any(d in pl for d in browser_dirs):
            return True
        # 浏览器内部子目录(通用 cache 不列入, 避免误伤非浏览器路径的载荷)
        browser_subdirs = (
            '\\code cache\\', '\\indexeddb\\', '\\local storage\\',
            '\\session storage\\', '\\service worker\\', '\\gpucache\\',
            '\\component_crx_cache\\', '\\firstpartysetspreloaded\\',
            '\\trusttokenkeycommitments\\', '\\safe browsing\\',
            '\\web notifications\\', '\\autofill\\', '\\pkimetadata\\',
            '\\typosquatting\\', '\\safetytips\\', '\\edge3pserp\\',
            '\\eadpdata component\\', '\\well known domains\\',
            '\\edge signal triggers\\', '\\dashtracker', '\\platform notifications\\',
            '\\domain actions\\', '\\crashpad\\', '\\jumplisticonsrecentclosed\\',
            '\\blob_storage\\', '\\sharedstorage', '\\edge notifications\\',
            '\\sessions\\', '\\certificaterevocation\\', '\\downloads\\',
            '\\extensions\\', '\\file type policies\\', '\\media engagement\\',
            '\\origin trials\\', '\\permissions\\', '\\preferences\\', '\\privacy sandbox\\',
            '\\supervised user\\', '\\translations\\', '\\webrtc\\', '\\widevine\\',
            '\\client hints\\', '\\compression dictionary\\', '\\deprecation\\',
            '\\interest group\\', '\\managed components\\', '\\optimization guide\\',
            '\\prerender\\', '\\segmentation platform\\', '\\speculation rules\\',
            '\\storage quota\\', '\\sync\\', '\\visited links\\',
            # 非浏览器但属系统正常活动
            '\\usoshared\\', '\\apprepository\\', '\\windows defender\\',
            '\\diagnosis\\', '\\d3dscache\\', '\\inetcache\\', '\\cryptneturlcache\\',
            '\\windows\\prefetch\\', '\\softwaredistribution\\',
        )
        if any(d in pl for d in browser_subdirs):
            return True
        # 文件特征: Edge 缓存 f_000xxx / leveldb 组件 / 事件日志
        import os as _os
        base = _os.path.basename(path)
        if base.lower().startswith('f_000') and base.endswith(('.tmp', '')):
            return True
        if path.endswith(('.ldb', '.log', '.etl', '.rslc', '.pb')) and (
                '\\cache' in pl or '\\storage' in pl or '\\data' in pl
                or '\\metadata\\' in pl or '\\usoshared\\' in pl or '\\apprepository\\' in pl):
            return True
        if path.endswith(('CURRENT', 'LOCK', 'MANIFEST-000001')) and '.leveldb' in pl:
            return True
        # Temp 下随机 GUID 临时文件(浏览器/系统组件产生)
        if '\\temp\\' in pl and path.endswith('.tmp'):
            return True
        # ⚠ 沙箱自身 Frida 运行时文件 (Temp\frida-<hash>\...) — 是注入工具不是样本行为!
        if '\\frida-' in pl and ('\\frida-agent.dll' in pl or '\\frida-helper' in pl
                                 or '\\symsrv.dll' in pl or '\\dbghelp.dll' in pl):
            return True
        if '\\frida-' in pl and path.endswith(('.dll', '.exe')):
            return True
        # ⚠ NSIS 安装器官方组件 (Temp\nsk*.tmp\...) — 合法安装器自带, 非样本释放
        # System.dll/nsDialogs.dll/nsis_tauri_utils.dll/modern-*.bmp 是 NSIS 标准组件
        if '\\nsk' in pl and '\\temp\\' in pl and any(
                n in base.lower() for n in ('nsdialogs.dll', 'nsis_tauri_utils.dll',
                                            'system.dll', 'modern-', 'nsis')):
            return True
        # ⚠ 系统更新/Defender 更新进程的临时目录 (MpSigStub/AM_Delta 工作目录)
        if any(seg in pl for seg in ('\\mpcmdrstaging', '\\mpsigstub', '\\am_delta')):
            return True
        # ⚠ uv/Python 环境安装产物 (装 Python 的正常文件, 非样本释放):
        #   AppData\Roaming\uv\python\...  (.pyd/.pyc/python.exe 标准库)
        #   AppData\Roaming\uv\tools\...   (uv 工具隔离环境)
        #   Temp\alphagpt-uv-python-* / cli-install-* (uv 下载缓存解压目录)
        if '\\uv\\python\\' in pl or '\\uv\\tools\\' in pl:
            return True
        if '\\uv\\' in pl and path.endswith(('.pyd', '.pyc', '.py', '.whl')):
            return True
        if 'alphagpt-uv-python' in pl or 'cli-install-' in pl:
            return True
        if '\\uv\\' in pl and any(n in base.lower() for n in (
                'python.exe', 'pythonw.exe', 'uv.exe', 'uvw.exe', 'uvx.exe',
                'activate.ps1', 'activate.bat', 'deactivate.bat', 'pydoc.bat')):
            return True
        # ⚠ Windows 错误报告 (WER) — 系统崩溃/程序错误报告, 非样本行为
        # WER\Temp 下任意随机文件名 (wer*.tmp / GUID) 都是 WER 服务自身产物
        if '\\wer\\temp\\' in pl:
            return True
        # ⚠ pywin32 COM 缓存 (Temp\gen_py\<ver>\) — 沙箱自身 WMI 事件订阅
        # (win32com.GetObject) 首次初始化时生成/重建 __init__.py + dicts.dat,
        # 时间点恰在样本启动后, 极易被误判为样本释放
        if '\\gen_py\\' in pl and any(b in base.lower() for b in (
                '__init__.py', 'dicts.dat', 'makepy.py')):
            return True
        # ⚠ 系统缓存/分析缓存 (PowerShell ModuleAnalysisCache / Windows Cache / INetCache)
        if 'moduleanalysiscache' in base.lower():
            return True
        if '\\windows\\cache\\' in pl or '\\inetcache\\' in pl:
            return True
        if '{' in base and '.3.ver' in base.lower() and '.db' in base.lower():
            return True  # 系统缓存 GUID 数据库文件
        # ⚠ macOS 元数据 (zip 解压带出的 .DS_Store / ._* 文件)
        if base == '.ds_store' or base.startswith('._'):
            return True
        # ⚠ DISM/系统更新临时目录 (Temp\<GUID>\ 下的系统组件 DLL —
        # AppxProvider/DismCore/SmiProvider 等, 系统 DISM 操作产生,
        # 曾把 59 个系统 DLL 当"样本释放"撑爆分析磁盘!)
        if '\\temp\\' in pl and re.match(r'^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$',
                                         base) and pl.count('\\') <= 5:
            return True
        # ⚠ VM 工具日志 (vmware-vmtoolsd-SYSTEM.log 等 — vm_hider 重命名 vmtoolsd 后
        # VMware 服务自身生成的日志, 非样本行为)
        if base.lower().startswith('vmware-') and base.lower().endswith('.log'):
            return True
        if '\\temp\\' in pl and any(n in base.lower() for n in (
                'appxprovider.dll', 'assocprovider.dll', 'cbsprovider.dll', 'dismcore.dll',
                'dismcoreps.dll', 'dismhost.exe', 'dismprov.dll', 'dmiprovider.dll',
                'ffuprovider.dll', 'folderprovider.dll', 'genericprovider.dll',
                'ibsprovider.dll', 'imagingprovider.dll', 'intlprovider.dll',
                'logprovider.dll', 'msiprovider.dll', 'offlinesetupprovider.dll',
                'osprovider.dll', 'provprovider.dll', 'setupplatformprovider.dll',
                'smiprovider.dll', 'sysprepprovider.dll', 'transmogprovider.dll',
                'unattendprovider.dll', 'vhdprovider.dll', 'wimprovider.dll')):
            return True
        # ⚠ 沙箱自身内存 dump (memory_dumps/ — 沙箱的内存转储产物)
        # 覆盖 pid*.bin 原始 dump + *_fixed.exe 修复版 (PE dump 重建器输出)
        if '\\memory_dumps\\' in pl and (
                base.lower().startswith('pid') or base.endswith('_fixed.exe')):
            return True
        # ⚠ 样本触发合法软件(WPS/Office/看图/播放器)后的运行噪音 —
        # 合法软件自身的日志/缓存/插件/配置更新, 不是样本释放物!
        # 场景: 样本是图片/文档, 双击后启动 photolaunch.exe/wps.exe 看图,
        #       其运行日志(kingsoft\office6\log)、照片缓存(photo_cache)、
        #       插件更新(wps\addons)全被误当"样本释放"
        if '\\kingsoft\\' in pl or '\\wpsphoto' in pl or '\\photo_cache\\' in pl:
            return True
        if '\\wps\\' in pl and any(n in pl for n in (
                '\\addons\\', '\\office6\\', '\\cache\\', '\\log\\', '\\dcsdk\\')):
            return True
        return False

    def stop(self):
        """停止监控 + 关闭元数据线程池 (等后台捕获完成)"""
        super().stop()
        try:
            self._meta_pool.shutdown(wait=True, cancel_futures=False)
        except Exception:
            pass

    def run(self):
        """启动 ReadDirectoryChangesW 事件监听 (每监控目录一个线程)

        零轮询: 线程阻塞在 ReadDirectoryChangesW 上, 目录有变化才返回。
        与旧版 2s 全盘 walk 相比 CPU 占用趋近于零, 不再抢 GIL 饿死 GUI。

        递归策略:
          - 释放母目录 (Public/AppData/Temp/ProgramData) 用递归监控,
            样本新建随机子目录(如 Public + UjIl9a)再释放也能捕获
          - 沙箱工作目录非递归 (事件都在根下, 减噪音)
        """
        if not self._init_rwd():
            logger.warning("[FSWatch] ReadDirectoryChangesW 初始化失败, 文件监控降级")
            self._fallback_poll()
            return
        # 释放母目录: 递归监控 (新子目录自动纳入)
        # 必须覆盖所有"样本可能新建子目录再释放"的根 — 漏一个就漏一类样本
        _release_parents = (
            os.environ.get('PUBLIC', '').lower(),
            os.environ.get('APPDATA', '').lower(),
            os.environ.get('ProgramData', 'C:\\ProgramData').lower(),
            os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Temp').lower(),
            os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Installer').lower(),
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Temp').lower(),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop').lower(),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Documents').lower(),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads').lower(),
        )
        logger.info(f"[FSWatch] 事件驱动文件监控启动: {len(self._monitor_dirs)} 个目录")
        for d in self._monitor_dirs:
            recursive = d.lower() in _release_parents
            t = threading.Thread(target=self._watch_dir_loop,
                                 args=(d,), kwargs={'recursive': recursive}, daemon=True)
            t.start()
            self._watch_threads.append(t)
        # 主线程保持存活直到超时 (监听线程为 daemon)
        while not self.should_stop():
            self.safe_sleep(1)

    def _fallback_poll(self):
        """降级: 简单轮询 (仅在 ReadDirectoryChangesW 不可用时)"""
        self._snapshot = {}
        while not self.should_stop():
            self.safe_sleep(5)
            for d in self._monitor_dirs:
                try:
                    for root, dirs, files in os.walk(d):
                        if '_artifacts_' in root:
                            dirs[:] = []
                            continue
                        for f in files:
                            full = os.path.join(root, f)
                            if self._path_in_created(full):
                                continue
                            if not self._should_watch(full):
                                continue
                            try:
                                st = os.stat(full)
                                if st.st_ctime < self.exec_start - 5:
                                    continue
                            except OSError:
                                continue
                            self._on_file_event(full)
                except Exception:
                    pass


class NetworkConnectionMonitor(BaseMonitorThread):
    """网络连接监控 — 轮询目标进程的网络连接 + 字节追踪"""
    def __init__(self, timeout: int, output_list: list, target_pid: int, extra_pids_provider=None):
        super().__init__(timeout)
        self.target_pid = target_pid
        self.output_list = output_list
        self._known_conns = set()
        self._io_start = {}
        # ⚠ 残留载荷 PID 提供器 (可调用对象, 返回 set) — 释放文件匹配的孤儿进程
        #   祖先链不达样本, 连接会被漏掉 (MSI→释放AhXQ9j.exe→C2 场景)
        self._extra_pids_provider = extra_pids_provider

    def run(self):
        if not PSUTIL_AVAILABLE:
            return

        # 记录起始 IO 计数
        try:
            root = psutil.Process(self.target_pid)
            self._io_start[self.target_pid] = root.io_counters()
            for child in root.children(recursive=True):
                self._io_start[child.pid] = child.io_counters()
        except Exception:
            pass

        # 主进程死后用全表扫描 + 祖先链补集 (与 wait_process 同款逻辑)
        known_pids = {self.target_pid}

        def _is_sample_pid(pid):
            if pid in known_pids:
                return True
            seen = set()
            p = pid
            while p and p not in seen:
                seen.add(p)
                if p in known_pids or p == self.target_pid:
                    return True
                try:
                    p = psutil.Process(p).ppid()
                except Exception:
                    return False
            return False

        while not self.should_stop():
            try:
                try:
                    target = psutil.Process(self.target_pid)
                    children = target.children(recursive=True)
                    all_pids = {target.pid} | {c.pid for c in children}
                except Exception:
                    # 主进程已死: 全表扫描祖先链
                    all_pids = set()
                    for proc in psutil.process_iter(['pid', 'ppid']):
                        pid = proc.info['pid']
                        ppid = proc.info['ppid'] or 0
                        if ppid in known_pids or ppid == self.target_pid or _is_sample_pid(pid):
                            all_pids.add(pid)
                # ⚠ 并入残留载荷 PID (释放文件匹配的孤儿进程 — 计划任务/服务拉起的载荷)
                # 从提供器动态获取 (沙箱 _tracked_processes 会随兜底扫描更新)
                try:
                    if self._extra_pids_provider is not None:
                        _extra = self._extra_pids_provider() or set()
                        if _extra:
                            all_pids |= set(_extra)
                except Exception:
                    pass
                known_pids |= all_pids

                # 记录所有连接状态(ESTABLISHED/SYN_SENT/TIME_WAIT等) — 短连接常只有 SYN_SENT
                for conn in psutil.net_connections():
                    if conn.pid in all_pids and conn.raddr:
                        key = (conn.pid, conn.laddr, conn.raddr)
                        if key not in self._known_conns:
                            self._known_conns.add(key)
                            entry = {
                                'pid': conn.pid,
                                'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                                'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                                'status': conn.status,
                                # SOCK_STREAM/SOCK_DGRAM → 合并网络报告时区分 TCP/UDP
                                'kind': str(getattr(conn, 'type', '') or ''),
                            }
                            self.output_list.append(entry)
                            logger.info(f"[Dynamic] Network connection: {entry['remote']} ({conn.status})")
            except Exception:
                pass

            self.safe_sleep(0.2)  # 高频轮询 — 秒退样本的毫秒级短连接需要快速捕捉

    def get_bytes_per_remote(self):
        """计算每个 remote 的收发字节数（执行结束后的总增量）"""
        bytes_map = {}
        try:
            root = psutil.Process(self.target_pid)
            all_pids = {self.target_pid} | {c.pid for c in root.children(recursive=True)}
        except Exception:
            # 主进程已死: 用连接记录过的 pid 兜底 (NetworkConnectionMonitor 记录)
            all_pids = set()
            for entry in getattr(self, 'output_list', []):
                if entry.get('pid'):
                    all_pids.add(entry['pid'])
            if not all_pids:
                all_pids.add(self.target_pid)

        for pid in all_pids:
            try:
                proc = psutil.Process(pid)
                io_now = proc.io_counters()
                io_start = self._io_start.get(pid)
                if io_start:
                    sent = max(0, (io_now.write_bytes or 0) - (io_start.write_bytes or 0))
                    recv = max(0, (io_now.read_bytes or 0) - (io_start.read_bytes or 0))
                else:
                    sent = io_now.write_bytes or 0
                    recv = io_now.read_bytes or 0
                # 存到 map 中
                for entry in self.output_list:
                    if entry.get('pid') == pid:
                        remote = entry.get('remote', '')
                        if remote:
                            if remote not in bytes_map:
                                bytes_map[remote] = [0, 0]
                            bytes_map[remote][0] += sent
                            bytes_map[remote][1] += recv
            except Exception:
                pass
        return bytes_map


class DynamicAnalyzer:
    """动态行为分析器 — 真正的多线程监控 + Frida API 插桩"""
    
    def __init__(self, timeout: int = 60, use_sandbox: bool = True, enable_time_accel: bool = True):
        self.timeout = timeout
        self.use_sandbox = use_sandbox and CONFIG.sandbox.enabled
        self.enable_time_accel = enable_time_accel
        self.sandbox = None
        self._monitors = []
        
    def analyze(self, file_path: str, stop_event=None) -> Tuple[DynamicBehavior, APIMonitorResult]:
        """执行动态分析，返回 (DynamicBehavior, APIMonitorResult)"""
        logger.info(f"[*] 启动动态行为监控 (timeout={self.timeout}s, sandbox={self.use_sandbox})")
        
        if stop_event and stop_event.is_set():
            _stopped_result = APIMonitorResult()
            _stopped_result.spawn_mode = False
            _stopped_result.attach_error = ''
            return DynamicBehavior(), _stopped_result
        
        if self.use_sandbox:
            return self._analyze_with_sandbox(file_path, stop_event=stop_event)
        else:
            return self._analyze_without_sandbox(file_path, stop_event=stop_event)

    def _analyze_with_sandbox(self, file_path: str, stop_event=None) -> Tuple[DynamicBehavior, APIMonitorResult]:
        """沙箱模式执行 + 多线程监控"""
        self.sandbox = Sandbox(
            timeout=self.timeout,
            memory_limit_mb=CONFIG.sandbox.memory_limit_mb,
            process_limit=CONFIG.sandbox.process_limit,
            cpu_limit_sec=CONFIG.sandbox.cpu_limit_sec
        )
        
        behavior = DynamicBehavior()
        api_result = APIMonitorResult()
        api_result.spawn_mode = False
        api_result.attach_error = ''
        memory_snapshots = []
        exec_start = time.time()  # 记录执行开始时间

        with self.sandbox:
            # 0. 执行前注册表快照（监控 Defender/防火墙/服务/持久化等）
            #    full_scan: 全量键名快照 — 覆盖白名单外位置 (默认关闭, 40-60s 太慢)
            #    ⚠ 限时执行: 放后台线程, 超时降级白名单快照, 绝不拖慢分析主流程
            logger.info("[*] 系统状态监控: 执行前注册表快照...")
            reg_snapshot_before = [None]

            def _snap_before():
                try:
                    reg_snapshot_before[0] = take_registry_snapshot(
                        full_scan=CONFIG.sandbox.full_registry_snapshot)
                except Exception:
                    reg_snapshot_before[0] = None

            _st = threading.Thread(target=_snap_before, daemon=True)
            _st.start()
            _st.join(timeout=25)
            if reg_snapshot_before[0] is None:
                logger.warning("[!] 全量注册表快照超时(25s), 降级白名单快照")
                reg_snapshot_before[0] = take_registry_snapshot(full_scan=False)
            proc_snapshot_before = take_process_snapshot()
            user_snapshot_before = take_user_snapshot()
            # 持久化快照 (Run键 + 计划任务) — 分析结束后回滚样本新增的延迟重启机制
            try:
                from analyzer.persistence_rollback import take_persistence_snapshot
                persistence_snapshot = take_persistence_snapshot()
            except Exception:
                persistence_snapshot = None
            # ⚠ Defender 服务基线 (执行前) — 用于区分"样本终止"与"本来就停用"
            try:
                from analyzer.system_monitor import take_defender_baseline, take_system_state_baseline
                defender_baseline = take_defender_baseline()
                system_state_baseline = take_system_state_baseline()
            except Exception:
                defender_baseline = None
                system_state_baseline = None
            logger.info(f"[+] 注册表快照: {len(reg_snapshot_before[0])} 个键")

            # 1. 构建目标命令（扩展名分发），并优先尝试 Frida spawn 模式。
            #    spawn 模式下样本由 Frida 挂起创建；monitor_spawn 完成 attach 后
            #    会通过 on_before_resume 回调把 PID 加入 Job Object，再 resume。
            cmd = self.sandbox.build_command(file_path)

            proc = None
            pid = None
            spawn_mode_used = False
            frida_thread = None
            api_result_local = [None]
            frida_child_threads = []
            frida_injected_pids = set()
            frida_results = [api_result_local]

            spawn_holder = {'spawn_failed': threading.Event(), 'result': None}

            def _on_before_resume(spawn_pid):
                # 安全优先: 与 start_process 的挂起创建→入 Job→恢复 同策略。
                # 加入 Job 失败时抛错, monitor_spawn 会终止挂起进程并记录 attach_error。
                if spawn_holder['spawn_failed'].is_set():
                    raise RuntimeError('spawn 已被主线程取消, 拒绝恢复')
                try:
                    ok = self.sandbox.assign_to_job(spawn_pid)
                    if ok:
                        logger.info(f"[+] 沙箱: Frida spawn PID={spawn_pid} 已在恢复前加入 Job Object")
                    else:
                        logger.warning(f"[-] 沙箱: Frida spawn PID={spawn_pid} 加入 Job Object 失败 — 拒绝无隔离恢复")
                        raise RuntimeError(f'AssignProcessToJobObject failed for PID={spawn_pid}')
                except RuntimeError:
                    raise
                except Exception as e:
                    logger.warning(f"[-] 沙箱: Frida spawn PID={spawn_pid} 加入 Job Object 异常: {e}")
                    raise

            if _frida:
                spawn_mon = APIMonitor(timeout=self.timeout, enable_time_accel=self.enable_time_accel)

                def _do_spawn():
                    try:
                        res = spawn_mon.monitor_spawn(
                            cmd,
                            cwd=os.path.dirname(os.path.abspath(file_path)),
                            timeout=self.timeout,
                            stop_event=stop_event,
                            on_before_resume=_on_before_resume)
                        if spawn_holder['spawn_failed'].is_set():
                            # 主线程已回退 Popen+attach, 不再采纳该结果
                            return
                        if res is None or not getattr(res, 'spawn_mode', False):
                            logger.warning("[Frida-Spawn] spawn 模式不可用，回退 Popen+attach")
                            spawn_holder['spawn_failed'].set()
                        else:
                            spawn_holder['result'] = res
                            api_result_local[0] = res
                    except Exception as e:
                        logger.error(f"Frida spawn thread error: {e}")
                        spawn_holder['spawn_failed'].set()

                frida_thread = threading.Thread(target=_do_spawn, daemon=True)
                frida_thread.start()

                # monitor_spawn 在 device.spawn 成功后立即置位 _spawn_ready,
                # 因此这里只会等待 spawn 创建挂起进程 (而非 attach/脚本加载)。
                _spawn_deadline = time.time() + getattr(CONFIG.sandbox, 'frida_attach_timeout', 15) + 10
                while True:
                    if getattr(spawn_mon, '_spawn_ready', None) and spawn_mon._spawn_ready.is_set():
                        break
                    if spawn_holder['spawn_failed'].is_set():
                        break
                    if time.time() > _spawn_deadline:
                        logger.warning("[Frida-Spawn] 等待 spawn 挂起进程创建超时，回退 Popen+attach")
                        spawn_holder['spawn_failed'].set()
                        break
                    time.sleep(0.1)

                if (getattr(spawn_mon, '_spawn_ready', None) and spawn_mon._spawn_ready.is_set()
                        and not spawn_holder['spawn_failed'].is_set()):
                    proc = spawn_mon._spawn_proc
                    if proc is not None:
                        pid = proc.pid
                        spawn_mode_used = True
                        self.sandbox.target_pid = pid
                        self.sandbox._start_time = time.time()
                        logger.info(f"[+] 沙箱: 使用 Frida spawn 模式 PID={pid}")

            # 2. spawn 不可用/失败/超时时，回退原有 Popen+attach 路径
            if proc is None:
                proc = self.sandbox.start_process(file_path)
                if not proc:
                    sandbox_error = getattr(self.sandbox, '_sandbox_error', None)
                    if sandbox_error and getattr(sandbox_error, 'winerror', 0) == 225:
                        logger.error("[!] Windows Defender 拦截了样本执行")
                        logger.error("[!] 解决方法：将以下目录添加到 Windows Defender 排除项：")
                        logger.error(f"    {self.sandbox.work_dir}")
                        logger.error(f"    {os.path.dirname(os.path.abspath(file_path))}")
                        logger.error("[!] 或临时关闭「病毒和威胁防护」→「实时保护」")
                        behavior.sandbox_result = sandbox_error
                    else:
                        logger.error("[-] 沙箱: 进程启动失败")
                    return behavior, api_result

                pid = proc.pid
                self.sandbox.target_pid = pid

            # 2b. start_process 会在挂起态完成 Job 加入与恢复；spawn 路径由
            #     on_before_resume 在 Frida resume 前完成 Job 加入。

            # 3. 启动监控线程 — 监视沙箱目录 + 原始文件目录
            watch_dirs = [self.sandbox.work_dir]
            orig_dir = os.path.dirname(os.path.abspath(file_path))
            if orig_dir and not orig_dir.startswith(self.sandbox.work_dir):
                watch_dirs.append(orig_dir)
            self._monitors = [
                ProcessTreeMonitor(pid, self.timeout, behavior.processes_created, file_path, memory_snapshots,
                                   behavior.files_created),
                FileSystemMonitor(watch_dirs, self.timeout, behavior.files_created, behavior.files_modified, behavior.files_deleted, exec_start),
                NetworkConnectionMonitor(self.timeout, behavior.network_connections, pid,
                                         extra_pids_provider=lambda: set(getattr(self.sandbox, '_tracked_processes', {}).keys())),
            ]

            for m in self._monitors:
                m.start()

            # 3b. 执行期桌面截图线程 (CAPE/微步同款 — 样本执行画面留证)
            screenshot_thread = None
            try:
                if CONFIG.screenshots.enabled:
                    os.makedirs(CONFIG.screenshots.dir, exist_ok=True)
                    screenshot_thread = threading.Thread(
                        target=self._screenshot_loop,
                        args=(behavior.screenshots,
                              CONFIG.screenshots.interval,
                              CONFIG.screenshots.max_count,
                              exec_start), daemon=True)
                    screenshot_thread.start()
                    logger.info(f"[+] 执行期截图已启动 (每{CONFIG.screenshots.interval}s, 上限{CONFIG.screenshots.max_count}张)")
            except Exception as e:
                logger.debug(f"截图线程启动失败: {e}")

            # 3c. ETW 内核监控 — 一劳永逸捕获所有注册表写操作 (不依赖白名单键)
            #     ⚠ 用 start_async (守护线程+15s超时): 360 Kernel Logger 竞争等
            #     环境因素可能让 ETW 启动阻塞/失败, 绝不能拖慢主分析流程
            etw_mon = None
            try:
                from analyzer.etw_monitor import ETWFullMonitor
                etw_mon = ETWFullMonitor(include_noise_processes=False)
                etw_mon.start_async()
                if etw_mon.is_running:
                    logger.info("[+] ETW 内核注册表监控已启动 (写操作全覆盖)")
                else:
                    logger.debug("[ETW] 监控未就绪 (可能被 360 Kernel Logger 占用, 已降级)")
            except Exception as e:
                logger.debug(f"ETW 监控启动失败(不影响分析): {e}")

            # 4. Frida API 监控
            #    spawn 路径: frida_thread 已是 monitor_spawn 后台线程；
            #    attach 路径: 与旧逻辑一致，对已运行进程直接 attach。
            def _inject_frida(target_pid):
                """注入 Frida 到指定 PID，返回线程"""
                result = [None]
                def _do():
                    try:
                        result[0] = APIMonitor(timeout=self.timeout, enable_time_accel=self.enable_time_accel).monitor(target_pid)
                    except Exception as e:
                        logger.error(f"Frida thread error PID={target_pid}: {e}")
                t = threading.Thread(target=_do, daemon=True)
                t.start()
                frida_results.append(result)
                return t

            if _frida and not spawn_mode_used:
                frida_thread = _inject_frida(pid)

            # 5. 等待进程结束或超时（每秒回调 dump 子进程模块）
            def _dump_child_modules(child_pids):
                """木马自退前趁进程活着：全内存PE扫描 + 模块dump + 清除BreakOnTermination防蓝屏"""
                # 持续清除 BreakOnTermination — 防止木马设关键进程后自杀导致蓝屏
                all_known_pids = set(child_pids)
                if proc and proc.pid:
                    all_known_pids.add(proc.pid)
                for check_pid in all_known_pids:
                    try:
                        if self.sandbox._check_break_on_termination(check_pid):
                            self.sandbox._clear_break_on_termination(check_pid)
                    except Exception:
                        pass
                # 注入 Frida 到新发现的子进程
                if _frida:
                    for cpid in child_pids:
                        if cpid not in frida_injected_pids:
                            frida_injected_pids.add(cpid)
                            try:
                                frida_child_threads.append(_inject_frida(cpid))
                                logger.info(f"[Frida] Injected into child PID={cpid}")
                            except Exception:
                                pass
                    # 释放文件路径关联进程也注入 Frida (计划任务/服务拉起的载荷)
                    try:
                        if ptm := next((m for m in self._monitors
                                        if isinstance(m, ProcessTreeMonitor)), None):
                            for pid2 in ptm._known_pids:
                                if pid2 not in frida_injected_pids:
                                    frida_injected_pids.add(pid2)
                                    try:
                                        frida_child_threads.append(_inject_frida(pid2))
                                        logger.info(f"[Frida] Injected into released-payload PID={pid2}")
                                    except Exception:
                                        pass
                    except Exception:
                        pass
                ptm = None
                for m in self._monitors:
                    if isinstance(m, ProcessTreeMonitor):
                        ptm = m; break
                if ptm:
                    try:
                        # ⚠ 限频: sandbox 回调每秒触发, 全内存扫描/模块dump 不能每秒全量执行 (性能)
                        scan_tick = getattr(ptm, '_scan_ticks', 0) + 1
                        ptm._scan_ticks = scan_tick
                        if scan_tick % 5 == 1:
                            ptm._scanned_modules.clear()
                            # 1. 全内存区域 PE 扫描（云沙箱做法：扫所有 MEM_COMMIT）
                            #    ⚠ 必须遍历 all_known_pids(含根进程) — 修复: 长存活样本
                            #    (如 msiexec 600s) 无子进程时 child_pids 为空, 根进程内存
                            #    在载荷注入后从不被重扫, 导致内存取证空白
                            for cpid in all_known_pids:
                                try:
                                    import psutil
                                    p = psutil.Process(cpid)
                                    ptm._quick_memory_snapshot(cpid, p.name() or 'unknown')
                                except Exception:
                                    pass
                            # 2. 枚举加载模块 dump（模块列表法）
                            for cpid in all_known_pids:
                                try:
                                    import psutil
                                    p = psutil.Process(cpid)
                                    ptm._dump_loaded_modules(cpid, p.name() or 'unknown')
                                except Exception:
                                    pass
                            # 3. 按名搜索 sysupdate.exe
                            import psutil
                            for proc in psutil.process_iter(['pid', 'name']):
                                if proc.info['name'] == 'sysupdate.exe':
                                    try:
                                        ptm._quick_memory_snapshot(proc.info['pid'], 'sysupdate.exe')
                                        ptm._dump_loaded_modules(proc.info['pid'], 'sysupdate.exe')
                                    except Exception:
                                        pass
                    except Exception:
                        pass

            try:
                self.sandbox.wait_process(proc, on_child_pids=_dump_child_modules, stop_event=stop_event)
            except Exception as e:
                logger.error(f"[!] wait_process 异常(继续清理): {e}")

            # 5b. 持续清除 BreakOnTermination — 防止木马自杀导致蓝屏
            # 在等待期间也周期性检查和清除，不等kill时才清
            pass  # _dump_child_modules callback already handles this

            # 6b. 自删除检测 — 原始样本文件是否还在？
            if not os.path.exists(file_path):
                logger.warning(f"[!] 原始样本已自删除: {file_path}")
                behavior.files_deleted.append(file_path)
                behavior.processes_created.append({
                    'name': 'self_delete',
                    'pid': pid, 'ppid': 0,
                    'cmdline': f'SELF-DELETE: original sample {os.path.basename(file_path)} removed by child process',
                })

            # 7. 停止所有监控线程
            self._stop_monitors()

            # 7b. 取回 ETW 内核事件 → 写入 behavior (注册表写操作全覆盖 + 瞬时进程)
            if etw_mon:
                try:
                    etw_data = etw_mon.stop_and_get()
                    reg_evts = etw_data.get('registry', []) or []
                    proc_evts = etw_data.get('processes', []) or []
                    # 注册表写事件 → registry_modified (与快照 diff 格式兼容)
                    etw_reg_entries = []
                    for ev in reg_evts:
                        key = ev.get('key', '')
                        if not key:
                            continue
                        # \\Registry\Machine\... → HKLM\... 可读格式
                        display_key = key.replace('\\Registry\\Machine\\', 'HKLM\\') \
                                       .replace('\\Registry\\User\\', 'HKCU\\')
                        entry = {
                            'key': display_key,
                            'type': 'etw_write',
                            'category': 'ETW_RegistryWrite',
                            'values': f"{ev.get('op', '')} | 进程: {ev.get('process', '')} (PID={ev.get('pid', '')})"
                                      + (f" | 值: {ev.get('value', '')}" if ev.get('value') else ''),
                            'pid': ev.get('pid', 0),
                            'process': ev.get('process', ''),
                            'op': ev.get('op', ''),
                        }
                        etw_reg_entries.append(entry)
                    if etw_reg_entries:
                        behavior._etw_registry_events = etw_reg_entries
                        logger.info(f"[ETW] 捕获 {len(etw_reg_entries)} 条注册表写事件"
                                    f" (进程: {len({e.get('pid') for e in etw_reg_entries})} 个)")
                    # 进程创建事件 → processes_created (瞬时快速进程兜底)
                    if proc_evts:
                        etw_new = 0
                        existing_pids = {e.get('pid') for e in behavior.processes_created}
                        for ev in proc_evts:
                            pid = ev.get('pid', 0)
                            if pid in existing_pids or not pid:
                                continue
                            existing_pids.add(pid)
                            behavior.processes_created.append({
                                'pid': pid,
                                'ppid': 0,
                                'name': ev.get('name', '') or f'PID-{pid}',
                                'cmdline': '',
                                'exe': '',
                                'create_time': '',
                                'etw_event': True,
                                'note': 'ETW内核进程创建 (瞬时进程/断裂链)',
                            })
                            etw_new += 1
                        if etw_new:
                            logger.info(f"[ETW] 捕获 {etw_new} 个内核级进程创建事件")
                except Exception as e:
                    logger.debug(f"ETW 事件取回失败: {e}")

            # 7c. 系统进程注入检测 — 扫描 lsass/services/svchost 等关键系统进程的非系统模块
            # (补进程树盲区: 样本向系统进程注入 DLL 不产生新进程, 进程创建监控抓不到)
            try:
                _sys_inj = _scan_system_process_injection()
                if _sys_inj:
                    behavior._system_injections = _sys_inj
                    _inj_desc = ', '.join(
                        f"{x['process']}(PID={x['pid']})←{os.path.basename(x['module'])}"
                        for x in _sys_inj[:6])
                    logger.warning(f"[Injection] 检测到 {len(_sys_inj)} 个系统进程非系统模块 (疑似 DLL 注入): {_inj_desc}")
            except Exception as e:
                logger.debug(f"系统进程注入扫描失败: {e}")

            # 8. 确保进程已终止 (异常保护: 即使前面出错也要清理样本进程)
            released_exes = set()
            try:
                # 收集样本释放的可执行文件路径 → 补杀计划任务/服务拉起的断裂链载荷
                for e in behavior.files_created:
                    p = e.get('path', '') if isinstance(e, dict) else e
                    if isinstance(p, str) and p.lower().endswith(
                            ('.exe', '.dll', '.scr', '.com', '.sys')):
                        released_exes.add(os.path.abspath(p).lower())
                self.sandbox.kill_process(proc, extra_exe_paths=released_exes)
            except Exception as e:
                logger.error(f"[!] kill_process 异常: {e}")
            # 8a. 重启观察窗: 拦截"先退出再重启"逃逸 (样本退出后延迟拉起的进程)
            try:
                self.sandbox.watch_for_restart(
                    extra_exe_paths=released_exes,
                    watch_timeout=getattr(CONFIG.sandbox, 'restart_watch_timeout', 15),
                    stop_event=stop_event)
            except Exception as e:
                logger.debug(f"重启观察窗异常: {e}")
            # 8b. 持久化回滚: 清理样本新增的 Run 键/计划任务 (堵"退出后经持久化延迟重启")
            try:
                if persistence_snapshot:
                    from analyzer.persistence_rollback import rollback_persistence
                    behavior._persistence_rollback = rollback_persistence(
                        persistence_snapshot, released_exes)
            except Exception as e:
                logger.debug(f"持久化回滚异常: {e}")
            # 记录系统关键进程（BreakOnTermination）检测
            bot_log = getattr(self.sandbox, '_break_on_termination_log', [])
            if bot_log:
                behavior.critical_process_events = bot_log
                for evt in bot_log:
                    logger.warning(f"[CriticalProcess] {evt['name']} PID={evt['pid']} BreakOnTermination "
                                   f"({'已清除' if evt['cleared'] else '清除失败'}) — {evt['detail'][:100]}")

            # 8c. 补录沙箱兜底追踪发现但监控线程未记录的释放进程
            # (计划任务 ITeWS/svchost、WMI WmiPrvSE、服务拉起等 PPID 链断裂场景 —
            #  进程树监控的祖先链判定看不到它们, 但沙箱 wait_process 的兜底扫描捕获到了)
            try:
                tracked = getattr(self.sandbox, '_tracked_processes', None) or {}
                recorded_pids = set()
                for e in behavior.processes_created:
                    if e.get('pid'):
                        recorded_pids.add(e['pid'])
                for tpid, tinfo in tracked.items():
                    if tpid in recorded_pids or tpid == pid:
                        continue
                    # ⚠ 补录也要过滤噪音: WPS/Kingsoft/VM工具/系统进程 不能算样本释放
                    _tname = (tinfo.get('name', '') or '').lower()
                    _texe = (tinfo.get('exe', '') or '').lower()
                    if _tname in _SYSTEM_NOISE_PROCESSES:
                        continue
                    if '\\kingsoft\\' in _texe or '\\wps office\\' in _texe \
                            or '\\vmware\\' in _texe or '\\virtualbox\\' in _texe:
                        continue
                    recorded_pids.add(tpid)
                    entry = {
                        'pid': tpid,
                        'ppid': tinfo.get('ppid', 0),
                        'name': tinfo.get('name', '') or 'unknown',
                        'cmdline': tinfo.get('cmdline', '') or '',
                        'exe': tinfo.get('exe', '') or '',
                        'create_time': '',
                        'wmi_event': False,
                    }
                    try:
                        if tinfo.get('create_time'):
                            entry['create_time'] = datetime.fromtimestamp(
                                tinfo['create_time']).strftime('%H:%M:%S')
                    except Exception:
                        pass
                    behavior.processes_created.append(entry)
                    logger.warning(f"[Dynamic] 补录沙箱发现的释放进程: {entry['name']} "
                                   f"(PID={tpid}, {entry['exe'] or 'n/a'})")
            except Exception as e:
                logger.debug(f"补录释放进程失败: {e}")

            # 8b. 执行后系统状态分析 — 注册表diff + VSS/日志/安全产品检测
            try:
                logger.info("[*] 系统状态监控: 执行后分析...")
                # ⚠ 执行后快照同样限时 (全量 20s+ 会拖慢后分析)
                reg_snapshot_after = [None]

                def _snap_after():
                    try:
                        reg_snapshot_after[0] = take_registry_snapshot(
                            full_scan=CONFIG.sandbox.full_registry_snapshot)
                    except Exception:
                        reg_snapshot_after[0] = None

                _st2 = threading.Thread(target=_snap_after, daemon=True)
                _st2.start()
                _st2.join(timeout=25)
                if reg_snapshot_after[0] is None:
                    logger.warning("[!] 执行后全量快照超时(25s), 降级白名单快照")
                    reg_snapshot_after[0] = take_registry_snapshot(full_scan=False)
                reg_changes = diff_registry(reg_snapshot_before[0] or {}, reg_snapshot_after[0])
                # ⚠ check_system_state_post_exec 内部多个串行 subprocess
                # (wevtutil/powershell 各 5-20s), 慢机器上可能 1 分钟+ —
                # 放后台线程限时, 超时降级空结果 (后分析卡死修复)
                system_state = [None]

                def _check_state():
                    try:
                        system_state[0] = check_system_state_post_exec(
                            defender_baseline, system_state_baseline)
                    except Exception:
                        system_state[0] = None

                _st3 = threading.Thread(target=_check_state, daemon=True)
                _st3.start()
                _st3.join(timeout=30)
                if system_state[0] is None:
                    logger.warning("[!] 系统状态检查超时(30s), 降级跳过")
                    system_state = {
                        'vss_deleted': False, 'vss_shadows': [], 'event_logs_cleared': False,
                        'new_users': [], 'user_groups_modified': [],
                        'firewall_rules_added': [], 'hosts_modified': False,
                        'security_products_stopped': [], 'proxy_hijack': '',
                        'defender_status': '', 'detections': [],
                    }
                else:
                    system_state = system_state[0]
                proc_diff = diff_processes(proc_snapshot_before, take_process_snapshot())
                sys_report = generate_system_report(reg_changes, system_state)
                # 用户/管理员组/监听端口/防火墙规则 前后对比 (新建用户/开放端口/规则添加检测)
                try:
                    user_diff = diff_user_snapshot(user_snapshot_before, take_user_snapshot())
                    if user_diff.get('new_users'):
                        logger.warning(f"[SystemState] 新增用户: {user_diff['new_users']}")
                    if user_diff.get('new_admins'):
                        logger.warning(f"[SystemState] 新增管理员组成员: {user_diff['new_admins']}")
                    if user_diff.get('new_listeners'):
                        logger.warning(f"[SystemState] 新增监听端口: {user_diff['new_listeners']}")
                    if user_diff.get('new_fw_rules'):
                        logger.warning(f"[SystemState] 新增防火墙规则: {user_diff['new_fw_rules']}")
                    if user_diff.get('new_wmi_filters') or user_diff.get('new_wmi_consumers') \
                            or user_diff.get('new_wmi_bindings'):
                        logger.warning(f"[SystemState] 新增 WMI 持久化订阅! filters={user_diff['new_wmi_filters']} "
                                       f"consumers={user_diff['new_wmi_consumers']} "
                                       f"bindings={user_diff['new_wmi_bindings']}")
                    if user_diff.get('critical_added'):
                        logger.warning(f"[SystemState] 新增系统关键进程: {user_diff['critical_added']}")
                    if user_diff.get('critical_removed'):
                        logger.warning(f"[SystemState] 系统关键进程减少: {user_diff['critical_removed']}")
                    if user_diff.get('ppl_added'):
                        logger.warning(f"[SystemState] 新增 PPL 保护进程: {user_diff['ppl_added']}")
                    if user_diff.get('sysfile_changed'):
                        logger.warning(f"[SystemState] ⚠ 系统文件被篡改: {user_diff['sysfile_changed']}")
                    if user_diff.get('new_dns'):
                        logger.warning(f"[SystemState] 新增 DNS 解析 (C2 情报): {user_diff['new_dns'][:10]}")
                    if user_diff.get('new_wmi_scripts'):
                        logger.warning(f"[SystemState] 新增 WMI 脚本订阅内容: {user_diff['new_wmi_scripts'][:5]}")
                    sys_report['user_diff'] = user_diff
                except Exception:
                    pass
                # 加入进程diff结果
                sys_report['process_diff'] = proc_diff
                if proc_diff.get('killed_security_products'):
                    sys_report['system_detections'] += len(proc_diff['killed_security_products'])
                    for name, info in proc_diff['killed_security_products'].items():
                        sys_report['raw_detections'].append(f'SecurityKilled_{info["product"]}_{name}_PID{info["pid"]}')
                behavior._system_monitor = sys_report
                if sys_report['total_changes'] > 0:
                    logger.warning(f"[SystemState] 注册表变更: {sys_report['registry_created']}新增 "
                                   f"{sys_report['registry_deleted']}删除 {sys_report['registry_modified']}修改, "
                                   f"系统检测: {sys_report['system_detections']}项")
                    # 将注册表变更写入 behavior
                    for d in reg_changes.get('details', []):
                        behavior.registry_modified.append({
                            'key': d['key'],
                            'type': d['type'],
                            'category': d['category'],
                            'values': d['values'],
                        })
            except Exception as e:
                logger.warning(f"系统状态分析异常: {e}")
            
            # 9. 等待所有 Frida 线程结束，合并结果
            for t in frida_child_threads:
                if t.is_alive():
                    t.join(timeout=5)
            if frida_thread and frida_thread.is_alive():
                frida_thread.join(timeout=5)

            # 合并所有 Frida 结果 — 必须用 APIMonitor.merge_results 全量合并:
            # 旧实现只拼接 call_records, memprot/DLL调用/API欺骗/AMSI/特权/
            # 注册表hive/关机拦截事件全部丢失, 报告相关章节永远为空。
            api_result = APIMonitor.merge_results([r[0] for r in frida_results])

            # 9b. API 监控错误标记（报告侧读取 spawn_mode / attach_error）
            if spawn_mode_used:
                _root_res = api_result_local[0] or spawn_holder.get('result')
                api_result.spawn_mode = True
                api_result.attach_error = getattr(_root_res, 'attach_error', '') if _root_res else ''
            else:
                api_result.spawn_mode = False
                api_result.attach_error = ''
            _api_err = getattr(api_result, 'attach_error', '')
            if getattr(api_result, 'spawn_mode', False):
                if _api_err:
                    behavior.api_monitor_error = f'Frida spawn 模式启动失败: {_api_err}'
                elif api_result.total_calls == 0:
                    behavior.api_monitor_error = '进程退出过早, API监控未捕获'
            elif _frida and api_result.total_calls == 0:
                api_result.attach_error = '进程退出过早, API监控未捕获'
                behavior.api_monitor_error = api_result.attach_error
            if getattr(behavior, 'api_monitor_error', ''):
                logger.warning(f"[!] API监控异常: {behavior.api_monitor_error}")

            # 10. 收集沙箱产物
            self.sandbox.sandbox_result = self.sandbox.collect_artifacts()
            # 传递关键进程标记到报告
            if hasattr(self.sandbox, '_critical_pids') and self.sandbox.sandbox_result:
                self.sandbox.sandbox_result._critical_pids = self.sandbox._critical_pids
            behavior.sandbox_result = self.sandbox.sandbox_result
            if behavior.sandbox_result:
                behavior.sandbox_result.execution_start = exec_start

            # 10b. 深度扫描常见释放目录 (SilverFox: cygwin, AppData\EdgeUpdate, ProgramData)
            self._deep_scan_dropped_files(behavior, file_path)
            
            # 同步沙箱产物到 behavior
            if self.sandbox.sandbox_result:
                sr = self.sandbox.sandbox_result
                existing_paths = set()
                for e in behavior.files_created:
                    existing_paths.add(e['path'] if isinstance(e, dict) else e)
                for f in sr.files_created:
                    if f not in existing_paths:
                        behavior.files_created.append(f)
                        existing_paths.add(f)
                for f in sr.files_modified:
                    if f not in behavior.files_modified:
                        behavior.files_modified.append(f)
                for f in sr.files_deleted:
                    if f not in behavior.files_deleted:
                        behavior.files_deleted.append(f)
                behavior.execution_time = sr.execution_time
                
                # 同步子进程信息到 sandbox_result
                sr.child_processes = list(behavior.processes_created)
                sr.child_process_count = len(behavior.processes_created)
        
        # 转换 API 结果到 behavior
        if api_result.call_records:
            behavior.api_calls = [
                {
                    'api': r.api_name,
                    'args': r.arguments,
                    'category': r.category,
                    'ts': r.timestamp
                }
                for r in api_result.call_records
            ]
        
        behavior.execution_time = behavior.sandbox_result.execution_time if behavior.sandbox_result else 0.0
        
        # 将内存快照附加到 behavior
        behavior.memory_snapshots = memory_snapshots
        if memory_snapshots:
                        # 按类型统计快照 (勿笼统称"注入PE映像" — 多为 hook/shellcode 快照)
            _pe_n = sum(1 for s in memory_snapshots if 'PE' in s.get('type', '') and 'Shellcode' not in s.get('type', ''))
            _sc_n = sum(1 for s in memory_snapshots if 'Shellcode' in s.get('type', '') or 'shellcode' in s.get('type', '').lower())
            _hk_n = sum(1 for s in memory_snapshots if 'Hook' in s.get('type', '') or 'hook' in s.get('type', '').lower())
            logger.warning(f"[!] 内存快照: {len(memory_snapshots)} 条 (PE注入 {_pe_n} / Shellcode {_sc_n} / Hook {_hk_n})")

        logger.info(f"[+] 动态分析完成: {len(behavior.processes_created)} 进程, {len(behavior.files_created)} 文件, {api_result.total_calls} API")
        return behavior, api_result
    
    def _analyze_without_sandbox(self, file_path: str, stop_event=None) -> Tuple[DynamicBehavior, APIMonitorResult]:
        """无沙箱模式（危险！仅用于已知安全样本）"""
        logger.warning("[!] 警告: 无沙箱模式 — 文件将在宿主机直接执行!")
        
        behavior = DynamicBehavior()
        api_result = APIMonitorResult()
        api_result.spawn_mode = False
        api_result.attach_error = ''
        memory_snapshots = []
        work_dir = tempfile.mkdtemp(prefix="sandbox_")
        proc = None
        frida_thread = None
        api_result_local = [None]
        spawn_mode_used = False
        
        try:
            exec_start = time.time()
            # 与沙箱模式共用同一条扩展名命令分发逻辑（不创建 Job）
            cmd = Sandbox().build_command(file_path)

            # 优先 Frida spawn 模式（快速退出/自删除样本）
            if _frida:
                spawn_mon = APIMonitor(timeout=self.timeout, enable_time_accel=self.enable_time_accel)
                spawn_holder = {'spawn_failed': threading.Event(), 'result': None}

                def _do_spawn():
                    try:
                        res = spawn_mon.monitor_spawn(
                            cmd,
                            cwd=work_dir,
                            timeout=self.timeout,
                            stop_event=stop_event)
                        if spawn_holder['spawn_failed'].is_set():
                            return
                        if res is None or not getattr(res, 'spawn_mode', False):
                            logger.warning("[Frida-Spawn] spawn 模式不可用，回退 Popen+attach")
                            spawn_holder['spawn_failed'].set()
                        else:
                            spawn_holder['result'] = res
                            api_result_local[0] = res
                    except Exception as e:
                        logger.error(f"Frida spawn thread error: {e}")
                        spawn_holder['spawn_failed'].set()

                frida_thread = threading.Thread(target=_do_spawn, daemon=True)
                frida_thread.start()

                _spawn_deadline = time.time() + getattr(CONFIG.sandbox, 'frida_attach_timeout', 15) + 10
                while True:
                    if getattr(spawn_mon, '_spawn_ready', None) and spawn_mon._spawn_ready.is_set():
                        break
                    if spawn_holder['spawn_failed'].is_set():
                        break
                    if time.time() > _spawn_deadline:
                        logger.warning("[Frida-Spawn] 等待 spawn 挂起进程创建超时，回退 Popen+attach")
                        spawn_holder['spawn_failed'].set()
                        break
                    time.sleep(0.1)

                if (getattr(spawn_mon, '_spawn_ready', None) and spawn_mon._spawn_ready.is_set()
                        and not spawn_holder['spawn_failed'].is_set()):
                    proc = spawn_mon._spawn_proc
                    if proc is not None:
                        pid = proc.pid
                        spawn_mode_used = True
                        logger.info(f"[+] 无沙箱模式: 使用 Frida spawn PID={pid}")

            if proc is None:
                proc = subprocess.Popen(
                    cmd,
                    cwd=work_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                pid = proc.pid

                # Frida attach（后台线程，与进程执行并行）
                def run_frida():
                    try:
                        api_result_local[0] = APIMonitor(timeout=self.timeout, enable_time_accel=self.enable_time_accel).monitor(pid)
                    except Exception as e:
                        logger.error(f"Frida thread error: {e}")

                if _frida:
                    frida_thread = threading.Thread(target=run_frida, daemon=True)
                    frida_thread.start()

            # 启动监控（spawn 与 Popen 路径均在此；spawn 时进程可能仍被 Frida 挂起，
            # 但 ProcessTreeMonitor 首轮会等到进程可见后继续，不影响后续追踪）
            self._monitors = [
                ProcessTreeMonitor(pid, self.timeout, behavior.processes_created, file_path, memory_snapshots,
                                   behavior.files_created),
                FileSystemMonitor(work_dir, self.timeout, behavior.files_created, behavior.files_modified, behavior.files_deleted, exec_start),
                NetworkConnectionMonitor(self.timeout, behavior.network_connections, pid,
                                         extra_pids_provider=lambda: set()),
            ]
            for m in self._monitors:
                m.start()

            try:
                proc.wait(timeout=self.timeout)
                elapsed = time.time() - exec_start
                behavior.sandbox_result = SandboxResult(
                    execution_time=elapsed,
                    was_terminated=False,
                    sandbox_dir=work_dir,
                    child_processes=list(behavior.processes_created),
                    child_process_count=len(behavior.processes_created)
                )
            except subprocess.TimeoutExpired:
                proc.kill()
                elapsed = time.time() - exec_start
                behavior.sandbox_result = SandboxResult(
                    execution_time=elapsed,
                    was_terminated=True,
                    sandbox_dir=work_dir,
                    child_processes=list(behavior.processes_created),
                    child_process_count=len(behavior.processes_created)
                )
                
        finally:
            self._stop_monitors()
            shutil.rmtree(work_dir, ignore_errors=True)

        # 等待 Frida 线程结束
        if frida_thread and frida_thread.is_alive():
            frida_thread.join(timeout=5)

        if api_result_local[0]:
            api_result = api_result_local[0]

        # API 监控错误标记（报告侧读取 spawn_mode / attach_error）
        if not hasattr(api_result, 'spawn_mode'):
            api_result.spawn_mode = False
        if not hasattr(api_result, 'attach_error'):
            api_result.attach_error = ''
        if getattr(api_result, 'spawn_mode', False):
            if api_result.attach_error:
                behavior.api_monitor_error = f'Frida spawn 模式启动失败: {api_result.attach_error}'
            elif api_result.total_calls == 0:
                behavior.api_monitor_error = '进程退出过早, API监控未捕获'
        elif _frida and api_result.total_calls == 0:
            api_result.attach_error = '进程退出过早, API监控未捕获'
            behavior.api_monitor_error = api_result.attach_error
        if getattr(behavior, 'api_monitor_error', ''):
            logger.warning(f"[!] API监控异常: {behavior.api_monitor_error}")

        # 将内存快照附加到 behavior
        behavior.memory_snapshots = memory_snapshots
        if memory_snapshots:
                        # 按类型统计快照 (勿笼统称"注入PE映像" — 多为 hook/shellcode 快照)
            _pe_n = sum(1 for s in memory_snapshots if 'PE' in s.get('type', '') and 'Shellcode' not in s.get('type', ''))
            _sc_n = sum(1 for s in memory_snapshots if 'Shellcode' in s.get('type', '') or 'shellcode' in s.get('type', '').lower())
            _hk_n = sum(1 for s in memory_snapshots if 'Hook' in s.get('type', '') or 'hook' in s.get('type', '').lower())
            logger.warning(f"[!] 内存快照: {len(memory_snapshots)} 条 (PE注入 {_pe_n} / Shellcode {_sc_n} / Hook {_hk_n})")

        return behavior, api_result
    
    def _stop_monitors(self):
        """停止所有监控线程"""
        for m in self._monitors:
            m.stop()
        for m in self._monitors:
            m.join(timeout=5)
        self._monitors = []

    @staticmethod
    def _screenshot_loop(screenshots: list, interval: int, max_count: int, exec_start: float):
        """执行期周期桌面截图 (保存到 screenshots/ 供报告展示)"""
        import config as _cfg
        out_dir = _cfg.CONFIG.screenshots.dir
        count = 0
        while count < max_count:
            try:
                elapsed = time.time() - exec_start
                if elapsed < interval:
                    time.sleep(min(interval - elapsed, 5))
                    continue
                os.makedirs(out_dir, exist_ok=True)
                from PIL import ImageGrab
                img = ImageGrab.grab()
                path = os.path.join(out_dir, f'exec_{int(time.time())}_{count+1}.png')
                img.save(path, 'PNG')
                screenshots.append(path)
                count += 1
                logger.info(f"[Screenshot] 已保存执行期画面: {path}")
                exec_start = time.time()  # 重置基准
            except Exception:
                # 截图失败(无桌面会话/权限): 计数+1 防死循环, 静默降级
                count += 1
                try:
                    time.sleep(min(interval, 5))
                except Exception:
                    pass

    def _deep_scan_dropped_files(self, behavior, sample_path):
        """深度扫描常见释放目录，仅报告执行期间新创建的文件（基于ctime）

        ⚠ 性能: 本函数遍历 ProgramData/Public/AppData 等大目录, 对每个文件
        os.stat — 系统文件多时可能数十秒; 若残留文件多还逐个读文件哈希,
        曾导致后分析卡死数分钟。必须加时间预算+文件数上限+读取大小上限。
        """
        exec_start = getattr(behavior.sandbox_result, 'execution_start', 0) if behavior.sandbox_result else time.time()
        if exec_start <= 0:
            exec_start = time.time()

        # ⚠ 时间预算: 整个深扫最多 20 秒, 超时立即停止 (防后分析卡死)
        _budget_start = time.time()
        _BUDGET = 20.0
        # 单文件哈希读取上限: 超过 3MB 不再读内容算哈希 (防大文件拖死)
        _MAX_HASH_SIZE = 3 * 1024 * 1024
        # 最多处理的新文件数
        _MAX_NEW_FILES = 60

        # 高频释放目录（不只依赖沙箱目录，因为样本可能直接写入绝对路径）
        scan_roots = [
            os.path.join(os.environ.get('APPDATA', ''), 'Roaming', 'Microsoft', 'EdgeUpdate'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'EdgeUpdate'),
            os.path.join(os.environ.get('APPDATA', ''), 'Roaming', 'Microsoft', 'Windows'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Windows'),
            'C:\\cygwin', 'C:\\cygwin64',
            os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Temp'),
            os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32', 'Tasks'),
            'C:\\ProgramData',
            'C:\\Users\\Public',                                # 银狐释放主目录!
            os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'),
                         'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows',
                         'Start Menu', 'Programs', 'Startup'),
        ]
        # 去重 + 过滤不存在的
        scan_roots = list(set(r for r in scan_roots if r and os.path.isdir(r)))

        existing_paths = set()
        for e in behavior.files_created:
            existing_paths.add(e['path'] if isinstance(e, dict) else e)

        new_file_count = 0
        for root_dir in scan_roots:
            if time.time() - _budget_start > _BUDGET:
                logger.warning(f"[DeepScan] 深度扫描超时预算({_BUDGET}s), 提前结束 (已处理 {new_file_count} 个新文件)")
                break
            try:
                for dirpath, dirs, files in os.walk(root_dir):
                    depth = dirpath.replace(root_dir, '').count(os.sep)
                    if depth > 4:
                        dirs.clear()
                        continue
                    for f in files:
                        if time.time() - _budget_start > _BUDGET:
                            break
                        full = os.path.join(dirpath, f)
                        if full in existing_paths:
                            continue
                        # 噪音过滤: 沙箱自身产物(WMI gen_py缓存)/WER/AppRepository 等
                        # ⚠ _is_noise_file 是 FileSystemMonitor 的 staticmethod, 必须用类名调用
                        #   (曾用 self._is_noise_file 导致 DynamicAnalyzer AttributeError 崩溃)
                        if FileSystemMonitor._is_noise_file(full):
                            existing_paths.add(full)
                            continue
                        # 核心过滤：仅保留 ctime 在执行开始之后的文件
                        try:
                            st = os.stat(full)
                            if st.st_ctime < exec_start - 5:  # 5秒容差
                                continue
                        except OSError:
                            continue

                        size = st.st_size
                        if size < 5 * 1024 * 1024 and new_file_count < _MAX_NEW_FILES:
                            try:
                                if size <= _MAX_HASH_SIZE:
                                    with open(full, 'rb') as fp:
                                        data = fp.read()
                                    md5 = hashlib.md5(data).hexdigest()
                                    sha256 = hashlib.sha256(data).hexdigest()
                                    entropy = calc_entropy(data) if size < 10 * 1024 * 1024 else 0.0
                                    ftype, _ = detect_file_type_file(full)
                                else:
                                    md5 = sha256 = 'skipped_large'; entropy = 0.0; ftype = 'Large'
                            except:
                                md5 = sha256 = ''; entropy = 0.0; ftype = 'Unknown'
                            entry = {
                                'path': full, 'size': size, 'md5': md5,
                                'sha256': sha256, 'entropy': entropy, 'file_type': ftype
                            }
                            behavior.files_created.append(entry)
                            existing_paths.add(full)
                            new_file_count += 1
                            logger.info(f"[DeepScan] File created during exec: {full}")
                            # PE/DLL 文件同步到 memory_dumps/ 供内存分析使用
                            ext = os.path.splitext(f)[1].lower()
                            if ext in ('.exe', '.dll', '.scr', '.sys'):
                                try:
                                    ddir = 'memory_dumps'
                                    os.makedirs(ddir, exist_ok=True)
                                    dst = os.path.join(ddir, f)
                                    if not os.path.exists(dst):
                                        shutil.copy2(full, dst)
                                except Exception:
                                    pass
            except PermissionError:
                pass

        # 最后一搏：查找 sysupdate.exe 进程并重新 dump 其加载的模块
        try:
            import psutil as _ps
            pt_monitor = None
            for m in (getattr(self, '_monitors', []) or []):
                if isinstance(m, ProcessTreeMonitor):
                    pt_monitor = m
                    break
            if pt_monitor:
                # 清掉去重标记，强制重扫
                if hasattr(pt_monitor, '_scanned_modules'):
                    pt_monitor._scanned_modules.clear()
                for proc in _ps.process_iter(['pid', 'name']):
                    if proc.info['name'] == 'sysupdate.exe':
                        try:
                            alive_pid = proc.info['pid']
                            pt_monitor._dump_loaded_modules(alive_pid, 'sysupdate.exe')
                        except Exception:
                            pass
                        break
        except Exception:
            pass

        # 计划任务持久化识别 — 执行期间创建的 Tasks\*.xml 中 Command 指向
        # 样本释放的可执行文件 (如 ITeWS → C:\Users\Public\UjIl9a\z2VIqs.exe):
        # 这才是载荷进程"死而复生"的根源, 必须写进报告供清理脚本处理
        try:
            import xml.etree.ElementTree as _ET
            tasks_dir = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'),
                                     'System32', 'Tasks')
            if os.path.isdir(tasks_dir):
                for tf in os.listdir(tasks_dir):
                    tpath = os.path.join(tasks_dir, tf)
                    if not tf.endswith('.xml'):
                        continue
                    try:
                        st = os.stat(tpath)
                        if st.st_ctime < exec_start - 5:
                            continue
                    except OSError:
                        continue
                    command = ''
                    arguments = ''
                    try:
                        tree = _ET.parse(tpath)
                        cmd_el = tree.find('.//{*}Command')
                        if cmd_el is not None:
                            command = (cmd_el.text or '').strip()
                        args_el = tree.find('.//{*}Arguments')
                        if args_el is not None:
                            arguments = (args_el.text or '').strip()
                    except Exception:
                        continue
                    if not command:
                        continue
                    cmd_lower = command.lower()
                    # 仅识别: 命令指向释放目录/释放文件名 (避免误报系统任务)
                    cmd_match = (
                        any(seg in cmd_lower for seg in (r'\users\public', r'\programdata',
                                                         r'\appdata', r'\windows\temp'))
                        or os.path.basename(cmd_lower) in {
                            os.path.basename(e.get('path', '')).lower()
                            for e in behavior.files_created if isinstance(e, dict)
                        }
                    )
                    if not cmd_match:
                        continue
                    entry = {
                        'name': tf[:-4],
                        'path': tpath,
                        'command': (command + ' ' + arguments).strip()[:300],
                        'note': '计划任务指向样本释放文件 (持久化载荷)',
                    }
                    if not any(x.get('name') == entry['name'] for x in behavior.scheduled_tasks):
                        behavior.scheduled_tasks.append(entry)
                        logger.warning(f"[DeepScan] 计划任务持久化: {entry['name']} "
                                       f"→ {entry['command'][:150]}")
        except Exception:
            pass
