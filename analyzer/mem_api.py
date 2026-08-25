#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一内存读取 API — ctypes 直调 kernel32
pywin32 的 win32process 模块没有 VirtualQueryEx（只有 ReadProcessMemory），
历史版本全部内存枚举因此静默失败（AttributeError 被 except 吞掉）。
本模块提供跨版本可靠的 OpenProcess / VirtualQueryEx / ReadProcessMemory。
"""
import ctypes
from ctypes import wintypes, byref, sizeof, Structure

try:
    _kernel32 = ctypes.windll.kernel32
except Exception:
    _kernel32 = None

# 权限常量
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# MEM 常量
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000
PAGE_GUARD = 0x100

# 保护常量
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80


class MEMORY_BASIC_INFORMATION(Structure):
    """x64 版 MEMORY_BASIC_INFORMATION (64位进程间通用)"""
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


def open_process(pid: int):
    """打开进程句柄（QUERY_INFORMATION + VM_READ），失败返回 None"""
    if not _kernel32:
        return None
    try:
        return _kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    except Exception:
        return None


def close_handle(handle):
    if handle and _kernel32:
        try:
            _kernel32.CloseHandle(ctypes.c_void_p(handle))
        except Exception:
            pass


def _as_handle(handle):
    """将 pywin32 PyHANDLE 或 ctypes 句柄统一转为 c_void_p"""
    try:
        return ctypes.c_void_p(int(handle))
    except Exception:
        return ctypes.c_void_p(handle)


def virtual_query_ex(handle, addr: int):
    """VirtualQueryEx — 返回 dict 或 None"""
    if not _kernel32:
        return None
    mbi = MEMORY_BASIC_INFORMATION()
    result = _kernel32.VirtualQueryEx(
        _as_handle(handle), ctypes.c_void_p(addr),
        byref(mbi), sizeof(mbi)
    )
    if result == 0:
        return None
    return {
        'BaseAddress': mbi.BaseAddress,
        'AllocationBase': mbi.AllocationBase,
        'AllocationProtect': mbi.AllocationProtect,
        'RegionSize': mbi.RegionSize,
        'State': mbi.State,
        'Protect': mbi.Protect,
        'Type': mbi.Type,
    }


def read_process_memory(handle, addr: int, size: int):
    """ReadProcessMemory — 返回 bytes 或 None（部分读取时返回已读部分）"""
    if not _kernel32:
        return None
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    ok = _kernel32.ReadProcessMemory(
        _as_handle(handle), ctypes.c_void_p(addr),
        buf, size, byref(bytes_read)
    )
    if not ok or bytes_read.value == 0:
        return None
    return buf.raw[:bytes_read.value]


def enumerate_regions(pid: int, max_regions: int = 20000):
    """枚举进程全部已提交内存区域，返回区域 dict 列表"""
    h = open_process(pid)
    if not h:
        return []
    regions = []
    try:
        addr = 0
        limit = 0x7FFFFFFFFFFF
        while addr < limit and len(regions) < max_regions:
            mbi = virtual_query_ex(h, addr)
            if not mbi:
                break
            base = mbi['BaseAddress']
            size = mbi['RegionSize']
            if base == 0:
                break
            mbi['_address'] = addr
            regions.append(mbi)
            addr = base + size
            if size == 0:
                break
    finally:
        close_handle(h)
    return regions


def protect_name(protect: int) -> str:
    """保护属性转名称"""
    p = protect & ~PAGE_GUARD
    guard = '|GUARD' if protect & PAGE_GUARD else ''
    names = {
        PAGE_NOACCESS: 'PAGE_NOACCESS',
        PAGE_READONLY: 'PAGE_READONLY',
        PAGE_READWRITE: 'PAGE_READWRITE',
        PAGE_WRITECOPY: 'PAGE_WRITECOPY',
        PAGE_EXECUTE: 'PAGE_EXECUTE',
        PAGE_EXECUTE_READ: 'PAGE_EXECUTE_READ',
        PAGE_EXECUTE_READWRITE: 'PAGE_EXECUTE_READWRITE',
        PAGE_EXECUTE_WRITECOPY: 'PAGE_EXECUTE_WRITECOPY',
    }
    return names.get(p, f'0x{protect:08X}') + guard


def state_name(state: int) -> str:
    return {MEM_COMMIT: 'MEM_COMMIT', MEM_RESERVE: 'MEM_RESERVE', MEM_FREE: 'MEM_FREE'}.get(state, f'0x{state:08X}')


def type_name(mtype: int) -> str:
    return {MEM_PRIVATE: 'MEM_PRIVATE', MEM_MAPPED: 'MEM_MAPPED', MEM_IMAGE: 'MEM_IMAGE'}.get(mtype, f'0x{mtype:08X}')


class MODULEINFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", ctypes.c_ulong),
        ("EntryPoint", ctypes.c_void_p),
    ]


def get_module_ranges(pid: int):
    """枚举进程已加载模块的地址范围 [(start, end, path)] — EnumProcessModulesEx + GetModuleInformation
    注意: pywin32 没有 psapi 模块, 必须 ctypes 直调 psapi.dll"""
    ranges = []
    if not _kernel32:
        return ranges
    h = open_process(pid)
    if not h:
        return ranges
    try:
        try:
            _psapi = ctypes.windll.psapi
        except Exception:
            _psapi = None
        if _psapi is not None:
            try:
                hmods = (ctypes.c_void_p * 2048)()
                cb = ctypes.c_ulong()
                if _psapi.EnumProcessModulesEx(_as_handle(h), hmods, ctypes.sizeof(hmods), ctypes.byref(cb), 0x03):
                    count = cb.value // ctypes.sizeof(ctypes.c_void_p)
                    _psapi.GetModuleInformation.restype = ctypes.c_int
                    _psapi.GetModuleInformation.argtypes = [
                        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(MODULEINFO), ctypes.c_ulong]
                    _psapi.GetModuleFileNameExW.restype = ctypes.c_ulong
                    _psapi.GetModuleFileNameExW.argtypes = [
                        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
                    for i in range(count):
                        mi = MODULEINFO()
                        if _psapi.GetModuleInformation(_as_handle(h), hmods[i], ctypes.byref(mi), ctypes.sizeof(mi)):
                            base = mi.lpBaseOfDll or 0
                            size = mi.SizeOfImage
                            path = ''
                            try:
                                buf = ctypes.create_unicode_buffer(1024)
                                n = _psapi.GetModuleFileNameExW(_as_handle(h), hmods[i], buf, 1024)
                                if n:
                                    path = buf.value
                            except Exception:
                                pass
                            if base:
                                ranges.append((base, base + size, path))
                return ranges
            except Exception:
                pass

        # 回退: psutil memory_maps (addr 为字符串)
        try:
            import psutil
            for mm in psutil.Process(pid).memory_maps(grouped=False):
                try:
                    start = int(mm.addr, 16)
                except Exception:
                    continue
                if not mm.path:
                    continue
                size = 0x1000000  # 默认 16MB 范围上限(粗粒度, 仅兜底)
                ranges.append((start, start + size, mm.path or ''))
        except Exception:
            pass
    finally:
        close_handle(h)
    return ranges
