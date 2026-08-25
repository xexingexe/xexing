#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ETW 内核注册表监控 — 一劳永逸的"所有注册表操作"捕获

原理:
  通过 Windows ETW 订阅内核提供者 (NT Kernel Logger + EVENT_TRACE_FLAG_REGISTRY),
  内核层面实时推送所有注册表写操作事件, 不需要预知任何键名 —
  未知变种的任意写入都会被捕获。

  实现: 基于 pywintrace。⚠ 回调必须用模块级函数 (绑定方法在 C 回调线程
  中会卡死 — 实测), 通过全局事件缓冲 + 锁访问。

  限制:
    - 需要管理员权限
    - 与 360 等占用 Kernel Logger 的软件冲突时自动降级 (不影响主分析)
"""
import os
import time
import threading

from logger import get_logger

logger = get_logger('analyzer.etw')

NT_KERNEL_LOGGER_GUID = '{9e814aad-3204-11d2-9a82-006008a86939}'
NT_KERNEL_LOGGER_NAME = 'NT Kernel Logger'
EVENT_TRACE_FLAG_REGISTRY = 0x00020000

REG_EVENT_OPS = {
    0: 'RegOpenKey', 1: 'RegCloseKey', 2: 'RegDeleteKey', 3: 'RegQueryValue',
    4: 'RegSetValue', 5: 'RegDeleteValue', 6: 'RegQueryKey', 7: 'RegEnumerateKey',
    8: 'RegEnumerateValue', 9: 'RegQueryMultipleValue', 10: 'RegSetInformation',
    11: 'RegFlush', 12: 'RegKCB', 13: 'RegVirtual', 14: 'RegLoadKey',
    15: 'RegUnLoadKey', 16: 'RegQuerySecurity', 17: 'RegSetSecurity',
    18: 'RegGetKeySecurity', 19: 'RegRenameKey', 20: 'RegCreateKey',
}
REG_WRITE_OPS = {2, 4, 5, 10, 14, 17, 19, 20}

_REG_NOISE_PREFIX = (
    r'\registry\machine\system\currentcontrolset\services\eventlog',
    r'\registry\machine\software\microsoft\windows\currentversion\installer',
    r'\registry\machine\software\microsoft\windows\currentversion\component based servicing',
    r'\registry\machine\software\microsoft\windows\currentversion\sidebyside',
    r'\registry\machine\software\microsoft\windows\currentversion\activesetup',
    r'\registry\machine\software\microsoft\windows\currentversion\appmodel',
    r'\registry\machine\software\microsoft\windows\currentversion\appx',
    r'\registry\machine\software\microsoft\windows\currentversion\appxpackagemanager',
    r'\registry\machine\software\microsoft\windows\currentversion\componentstore',
    r'\registry\machine\software\microsoft\windows\currentversion\deliveryoptimization',
    r'\registry\machine\software\microsoft\windows\currentversion\devicepnp',
    r'\registry\machine\software\microsoft\windows\currentversion\driverdatabase',
    r'\registry\machine\software\microsoft\windows\currentversion\graphics',
    r'\registry\machine\software\microsoft\windows\currentversion\reliability',
    r'\registry\machine\software\microsoft\windows\currentversion\search',
    r'\registry\machine\software\microsoft\windows\currentversion\shareddlls',
    r'\registry\machine\software\microsoft\windows\currentversion\telephony',
    r'\registry\machine\software\microsoft\windows\currentversion\wmi',
    r'\registry\machine\software\microsoft\windows\currentversion\winstore',
    r'\registry\machine\software\microsoft\windows\currentversion\wusa',
    r'\registry\machine\software\microsoft\windows\currentversion\edgeupdate',
    r'\registry\machine\software\microsoft\windows\currentversion\cryptography',
    r'\registry\machine\system\currentcontrolset\control\wmi',
    r'\registry\machine\system\currentcontrolset\control\graphicsdrivers',
    r'\registry\machine\system\currentcontrolset\control\video',
    r'\registry\machine\system\currentcontrolset\control\timezone',
    r'\registry\machine\system\currentcontrolset\control\fonts',
    r'\registry\machine\system\currentcontrolset\control\nls',
    r'\registry\machine\system\currentcontrolset\control\usb',
    r'\registry\machine\system\currentcontrolset\control\usbstor',
    r'\registry\machine\system\currentcontrolset\control\power',
    r'\registry\machine\system\currentcontrolset\control\pnp',
    r'\registry\machine\system\currentcontrolset\control\profilelist',
    r'\registry\machine\system\currentcontrolset\control\time',
    r'\registry\machine\system\currentcontrolset\control\session manager\memory management',
    r'\registry\machine\system\currentcontrolset\control\keyboard',
    r'\registry\machine\system\currentcontrolset\control\bcd',
    r'\registry\machine\system\currentcontrolset\services\bth',
    r'\registry\machine\system\currentcontrolset\services\cryptsvc',
    r'\registry\machine\system\currentcontrolset\services\dhcp',
    r'\registry\machine\system\currentcontrolset\services\dns',
    r'\registry\machine\system\currentcontrolset\services\dnscache',
    r'\registry\machine\system\currentcontrolset\services\lmhosts',
    r'\registry\machine\system\currentcontrolset\services\ndis',
    r'\registry\machine\system\currentcontrolset\services\netbt',
    r'\registry\machine\system\currentcontrolset\services\nla',
    r'\registry\machine\system\currentcontrolset\services\ntoskrnl',
    r'\registry\machine\system\currentcontrolset\services\rdp',
    r'\registry\machine\system\currentcontrolset\services\tcpip',
    r'\registry\machine\system\currentcontrolset\services\termservice',
    r'\registry\machine\system\currentcontrolset\services\w32time',
    r'\registry\machine\system\currentcontrolset\services\winsock',
    r'\registry\machine\system\currentcontrolset\services\winhttp',
    r'\registry\machine\system\currentcontrolset\services\wudfsvc',
    r'\registry\machine\system\currentcontrolset\services\wuauserv',
    r'\registry\machine\software\microsoft\windows\currentversion\explorer',
    r'\registry\machine\software\microsoft\windows\currentversion\uninstall',
    r'\registry\machine\software\microsoft\windows\currentversion\internet settings',
    r'\registry\machine\software\microsoft\windows\currentversion\policies',
    r'\registry\machine\software\microsoft\windows\currentversion\setup',
    r'\registry\machine\software\microsoft\windows\currentversion\windows search',
    r'\registry\machine\software\microsoft\windows\currentversion\winevt',
    r'\registry\user\.default',
    r'\registry\machine\software\classes\clsid',
    r'\registry\machine\software\classes\interface',
    r'\registry\machine\software\classes\typelib',
    r'\registry\machine\software\classes\wow6432node\clsid',
    r'\registry\machine\software\classes\wow6432node\interface',
    r'\registry\machine\software\classes\wow6432node\typelib',
    r'\registry\machine\software\classes\installer',
)
_REG_NOISE_PREFIX = tuple(x.lower() for x in _REG_NOISE_PREFIX)

_REG_NOISE_PROCESSES = {
    'svchost.exe', 'lsass.exe', 'services.exe', 'winlogon.exe', 'csrss.exe',
    'explorer.exe', 'dwm.exe', 'msmpeng.exe', 'nissrv.exe', 'dllhost.exe',
    'conhost.exe', 'ctfmon.exe', 'sihost.exe', 'taskhostw.exe',
    'searchindexer.exe', 'audiodg.exe', 'fontdrvhost.exe', 'wmiprvse.exe',
    'runtimebroker.exe', 'startmenuexperiencehost.exe', 'shellexperiencehost.exe',
    'textinputhost.exe', 'backgroundtaskhost.exe', 'applicationframehost.exe',
    'wudfhost.exe', 'spoolsv.exe', 'vmtoolsd.exe', 'vm3dservice.exe',
    'vmwaretray.exe', 'vmwareuser.exe', 'vmnat.exe', 'vmnetdhcp.exe',
    'chrome.exe', 'msedge.exe', 'wechat.exe', 'weixin.exe', 'qq.exe',
    'python.exe', 'pythonw.exe', 'powershell.exe', 'cmd.exe',
    'frida-helper-x86_64.exe', 'frida-helper-x86.exe', 'frida-helper.exe',
    'sandboxanalyzer.exe', '360tray.exe', 'hipstray.exe', '360safe.exe',
    'searchapp.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe',
}

_pid_name_cache = {}


def _pid_name(pid: int) -> str:
    if pid in _pid_name_cache:
        return _pid_name_cache[pid]
    name = ''
    try:
        import psutil
        name = psutil.Process(pid).name()
    except Exception:
        name = f'PID-{pid}'
    _pid_name_cache[pid] = name
    return name


def _is_noise_key(key_path: str) -> bool:
    if not key_path:
        return True
    kl = key_path.lower()
    for p in _REG_NOISE_PREFIX:
        if kl.startswith(p):
            return True
    return False


# ===== 全局事件缓冲 (回调线程写入, 主线程读取) =====
_g_events = []
_g_lock = threading.Lock()
_g_include_noise = False
_g_etw_owned = False  # 当前 NT Kernel Logger 会话是否由本沙箱启动 (区分自己 vs 其他工具占用)


def _etw_callback(event):
    """模块级回调 — pywintrace 传入 (opcode, data_dict); 绑定方法会卡死, 必须模块级"""
    try:
        if not (isinstance(event, tuple) and len(event) == 2):
            return
        _event_id, data = event
        if not isinstance(data, dict):
            return
        # ⚠ pywintrace 回调第一个参数是 EventId (不是 opcode!), 真正的 Registry
        # 操作类型 opcode 在 data['EventDescriptor']['Opcode'] (RegSetValue=4 等)
        try:
            opcode = int((data.get('EventDescriptor') or {}).get('Opcode', -1))
        except Exception:
            opcode = -1
        if opcode not in REG_WRITE_OPS:
            return
        pid = data.get('ProcessId') or 0
        name = _pid_name(pid) if pid else '?'
        if not _g_include_noise and name.lower() in _REG_NOISE_PROCESSES:
            return
        key_path = str(data.get('KeyName') or '')
        value_name = str(data.get('ValueName') or '')
        if not key_path:
            raw = data.get('UserData') or data.get('raw_data') or data.get('RawData')
            if raw:
                import re as _re
                strings = []
                try:
                    buf = bytes(raw[:4096])
                    pos = 0
                    while pos + 2 <= len(buf) and len(strings) < 8:
                        c = buf[pos:pos + 2]
                        if c == b'\x00\x00':
                            pos += 2
                            continue
                        try:
                            ch = c.decode('utf-16-le')
                        except Exception:
                            pos += 2
                            continue
                        if ch.isprintable() and ch != '\x00':
                            end = pos
                            acc = b''
                            while end + 2 <= len(buf) and len(acc) < 1024:
                                cc = buf[end:end + 2]
                                if cc == b'\x00\x00':
                                    break
                                try:
                                    s = cc.decode('utf-16-le')
                                except Exception:
                                    break
                                if not s.isprintable() and s not in ('\\', '/', ':', '.'):
                                    break
                                acc += cc
                                end += 2
                            if len(acc) >= 6:
                                s = acc.decode('utf-16-le', errors='ignore')
                                if s.isprintable() and len(s) >= 3 and not _is_noise_key(s):
                                    strings.append(s)
                            pos = end + 2
                        else:
                            pos += 2
                except Exception:
                    pass
                if strings:
                    key_path = strings[0]
                    value_name = strings[1] if len(strings) > 1 else ''
        if not key_path:
            return
        with _g_lock:
            _g_events.append({
                'opcode': opcode,
                'op': REG_EVENT_OPS.get(opcode, str(opcode)),
                'pid': pid,
                'process': name,
                'key': key_path,
                'value': value_name,
                'ts': time.time(),
            })
    except Exception:
        pass


def _kernel_logger_active() -> bool:
    """检查 NT Kernel Logger 会话当前是否存在 (可能被 ProcMon 等其他工具占用)"""
    try:
        import subprocess as _sp
        r = _sp.run(['logman', 'query', '-ets'],
                    capture_output=True, text=True, timeout=5, errors='ignore')
        return NT_KERNEL_LOGGER_NAME in (r.stdout or '')
    except Exception:
        return False


def _cleanup_kernel_logger(owned_by_us: bool = False) -> bool:
    """清理 NT Kernel Logger 会话。

    若会话已存在, 说明有其他工具 (ProcMon 等) 正在使用 — 不强制停止,
    返回 False 让调用方降级跳过, 避免打断其他工具的 ETW 会话。
    owned_by_us=True 表示会话是自己启动的, 直接强制停止 (不会误判)。
    """
    if owned_by_us:
        # 自己启动的会话: 直接 logman stop, 不做占用检查
        try:
            import subprocess as _sp
            _sp.run(['logman', 'stop', NT_KERNEL_LOGGER_NAME, '-ets'],
                    capture_output=True, timeout=5)
        except Exception:
            pass
        return True
    if _kernel_logger_active():
        logger.warning("[ETW] NT Kernel Logger 已被其他工具使用, 跳过启动 (不强制停止)")
        return False
    try:
        import subprocess as _sp
        _sp.run(['logman', 'stop', NT_KERNEL_LOGGER_NAME, '-ets'],
                capture_output=True, timeout=5)
    except Exception:
        pass
    return True


class ETWFullMonitor:
    """ETW 内核注册表写监控 — 全覆盖捕获 (模块级回调, 避免绑定方法卡死)"""

    def __init__(self, include_noise_processes: bool = False):
        global _g_include_noise
        _g_include_noise = include_noise_processes
        with _g_lock:
            _g_events.clear()
        self._running = False
        self._provider = None
        self._consumer = None

    def start(self):
        if self._running:
            return
        self._running = True
        if not _cleanup_kernel_logger():
            self._running = False
            return
        time.sleep(0.3)
        try:
            from etw import etw as etwmod
            from etw import GUID as etwGUID
            props = etwmod.TraceProperties()
            props.BufferSize = 64
            props.MinimumBuffers = 2
            props.MaximumBuffers = 32
            props.LogFileMode = 0x00000100
            props.FlushTimer = 1
            self._provider = etwmod.EventProvider(
                session_name=NT_KERNEL_LOGGER_NAME,
                session_properties=props,
                providers=[etwmod.ProviderInfo(
                    name='NT Kernel Logger',
                    guid=etwGUID(NT_KERNEL_LOGGER_GUID),
                    level=4,
                    any_keywords=EVENT_TRACE_FLAG_REGISTRY,
                )],
            )
            self._consumer = etwmod.EventConsumer(
                logger_name=NT_KERNEL_LOGGER_NAME,
                event_callback=_etw_callback,  # 模块级函数!
                # TDH 解析 Registry 事件常失败 (WinError 1168 找不到 manifest),
                # 开启此标志让解析失败时仍返回原始 UserData 字节 (供 KeyName 提取)
                callback_data_flag=getattr(etwmod, 'RETURN_RAW_DATA_ON_ERROR', 0),
            )
            # ⚠ 必须在调用线程直接执行 (守护线程内 ProcessTrace 上下文异常, 实测回调不触发)
            self._provider.start()
            self._consumer.start()
            global _g_etw_owned
            _g_etw_owned = True
            logger.info('[ETW] 内核注册表监控已启用 (NT Kernel Logger)')
        except Exception as e:
            logger.warning(f'[ETW] 内核监控启动失败(不影响分析): {e}')
            self._running = False

    def start_async(self):
        """后台线程启动 (带超时守护) — 供沙箱调用, 失败/卡死不影响主流程"""
        def _go():
            try:
                self.start()
            except Exception:
                pass
        t = threading.Thread(target=_go, daemon=True)
        t.start()
        t.join(timeout=15)

    def stop(self):
        self._running = False

        def _do_stop():
            try:
                if self._consumer:
                    self._consumer.stop()
            except Exception:
                pass
            try:
                if self._provider:
                    self._provider.stop()
            except Exception:
                pass
            self._provider = None
            self._consumer = None
        t = threading.Thread(target=_do_stop, daemon=True)
        t.start()
        t.join(timeout=8)
        global _g_etw_owned
        _cleanup_kernel_logger(owned_by_us=_g_etw_owned)
        _g_etw_owned = False

    def get_events(self) -> list:
        with _g_lock:
            return list(_g_events)

    def stop_and_get(self) -> dict:
        self.stop()
        with _g_lock:
            events = list(_g_events)
            _g_events.clear()
        return {'registry': events, 'processes': []}

    @property
    def is_running(self) -> bool:
        return self._running


def monitor_registry_events(duration_sec: float = 5.0) -> list:
    """同步监控注册表写操作 duration 秒, 返回事件列表 (管理员权限)"""
    mon = ETWFullMonitor()
    mon.start()
    time.sleep(duration_sec)
    data = mon.stop_and_get()
    return data.get('registry', [])
