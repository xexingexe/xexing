#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
内存取证增强引擎 — IAT/EAT Hook / Heaven's Gate / PEB篡改 / SEH覆写 / 反Dump检测

在现有 MemoryAnalyzer 基础上增加：
  1. IAT/EAT Hook 检测 — 导入/导出地址表篡改（EDR/AV bypass）
  2. Heaven's Gate 检测 — 32位⇄64位模式切换（WoW64逃逸）
  3. PEB/TEB 篡改检测 — BeingDebugged/HeapFlags/NtGlobalFlag
  4. SEH 覆写检测 — 结构化异常处理链篡改
  5. 内存保护阶段分析 — RW→RX 多阶段载荷注入检测
  6. 反Dump/反分析检测 — 抹除PE头/PEB伪装
  7. 现代C2框架载荷模式 (BruteRatel/Nighthawk/Mythic)
  8. API Unhooking 检测 — ntdll 重载绕过EDR
  9. VAD 隐藏区域检测 — 无VAD节点的RWX内存
"""
import re
import struct
from typing import List, Dict

from logger import get_logger
from analyzer.mem_api import (
    open_process, close_handle, virtual_query_ex,
    MEM_COMMIT, MEM_PRIVATE,
)

logger = get_logger('analyzer.memory_forensics')

PYWIN32_AVAILABLE = False
try:
    import win32process
    import win32api
    import win32con
    PYWIN32_AVAILABLE = True
except ImportError:
    pass


class MemoryForensicsEnhancer:
    """内存取证增强器"""

    # ===== Modern C2 框架 Shellcode 签名 =====
    ADVANCED_SHELLCODE_PATTERNS = [
        # --- Brute Ratel C4 ---
        (rb'Badger\x00', 'Brute Ratel Badger shellcode'),
        (rb'\x4d\x5a.{4}\xff\xff', 'Brute Ratel PE loader stub'),
        (rb'\xe8.{3}\x00\x00\x00.{0,50}\x48\x8b', 'Brute Ratel x64 trampoline'),

        # --- Nighthawk (MDSec) ---
        (rb'Nighthawk', 'Nighthawk C2 reference'),
        (rb'nighthawk\x00', 'Nighthawk config string'),

        # --- Mythic (Apfell) ---
        (rb'Mythic', 'Mythic C2 framework reference'),
        (rb'Apfell', 'Apfell/Mythic agent reference'),
        (rb'\xfc\x48\x83\xe4\xf0\xe8\x00\x00\x00\x00', 'Mythic Apollo x64 loader'),

        # --- BRC4 / Sliver variants ---
        (rb'\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6', 'XOR-zero trick (common in BRC4/Sliver)'),
        (rb'sliver\x00', 'Sliver implant string'),
        (rb'github\.com/BishopFox/sliver', 'Sliver source path'),

        # --- Havoc C2 ---
        (rb'Havoc', 'Havoc C2 framework'),
        (rb'Demon\.x(?:86|64)', 'Havoc Demon agent'),
        (rb'\x55\x48\x89\xe5\x48\x81\xec\x00\x04\x00\x00', 'Havoc Demon stack allocation'),

        # --- Covenant / Grunt ---
        (rb'GruntStager', 'Covenant Grunt stager'),

        # --- NPS (Not PowerShell) ---
        (rb'nps\x00|nps\\.exe', 'NPS implant reference'),
    ]

    # ===== IAT/EAT Hook 检测模式 =====
    # ⚠ 字节级 JMP/PUSH-RET 模式 (旧: \xe9... \xff\x25... \x68...\xc3) 误报率极高 —
    # 编译器生成的跳板/尾调用/延迟加载在几乎所有正常 PE 里都大量存在。
    # 只保留高置信特征: 明确的 Hook 字符串标记。真正的 IAT Hook 检测
    # 需要对比导入表/模块上下文, 纯字节扫描无法可靠判定。
    IAT_HOOK_PATTERNS = [
        (rb'nativeOverwrite', 'nativeOverwrite 标记 (Hook 重写)'),
        (rb'AppInit_DLLs', 'AppInit_DLLs 引用 (全局 DLL 注入)'),
        (rb'DetourFunction|DetourAttach', 'Detours 库引用 (API Hook 框架)'),
        (rb'MinHook|mh_hook', 'MinHook 库引用 (API Hook 框架)'),
        (rb'\x68[\x00-\xff]{4}\xff\x25[\x00-\xff]{4}\xc3', 'PUSH addr; JMP [addr]; RET (经典 detour 链)'),
    ]

    # ===== Heaven's Gate 检测 (32⇔64模式切换) =====
    # ⚠ PUSH 0x33; CALL (\x6a\x33\xe8) 在 Frida agent/部分正常代码里也存在 —
    # 无上下文时误报高。只保留高置信的 FAR JMP 0x33 与 CS 选择器改写特征。
    HEAVENS_GATE_PATTERNS = [
        (rb'\xea[\x00-\xff]{4}\x33\x00', 'Heavens Gate via FAR JMP 0x33'),
        (rb'\x8e\xd8\x33\x00', 'MOV DS, 0x33 (x64 data segment)'),
        (rb'\x8e\xc0\x33\x00', 'MOV ES, 0x33'),
        (rb'\x8e\xd8\x33', 'MOV DS, 0x33 selector'),
    ]

    # ===== PEB/TEB 篡改检测 =====
    PEB_TAMPER_PATTERNS = [
        (rb'\x64\xa1\x30\x00\x00\x00.{0,20}\xc6\x40\x02\x00', 'PEB.BeingDebugged = 0 (反反调试)'),
        (rb'\x64\xa1\x30.{0,30}NtGlobalFlag.{0,20}\x00\x00\x00\x00', 'PEB.NtGlobalFlag 清零'),
        (rb'\x64\xa1\x30.{0,50}\xc7\x40\x10\x00\x00\x00\x00', 'PEB.HeapFlags 清零 (反堆检测)'),
        (rb'\x6a\x60\x5a', 'PUSH 0x60; POP EDX — PEB access trick'),
    ]

    # ===== SEH 覆写检测 =====
    # ⚠ 只检测真正的"SEH 链头覆写" (往 FS:[0] 写入攻击者控制的 handler)。
    # 旧的 MOV EAX, FS:[EAX] / PUSH FS:[EAX] 是编译器生成的正常 SEH 枚举/
    # 异常处理代码, 几乎所有 C/C++/Rust 程序都有 — 误报率极高, 已移除。
    SEH_OVERWRITE_PATTERNS = [
        (rb'\x64\xa3\x00\x00\x00\x00', 'MOV FS:[0], EAX — SEH 链头覆写 (恶意设 handler)'),
        (rb'\x64\x89\x25\x00\x00\x00\x00', 'MOV FS:[0], ESP — 覆写 SEH 链头'),
        (rb'\x64\xc7\x05\x00\x00\x00\x00', 'MOV DWORD PTR FS:[0], imm32 — SEH 链头直接覆写'),
    ]

    # ===== 内存保护阶段分析 (多阶段注入) =====
    STAGED_PROTECTION_PATTERNS = [
        (rb'VirtualProtect.{0,300}PAGE_READWRITE.{0,300}VirtualProtect.{0,300}PAGE_EXECUTE_READ',
         'RW→RX 双阶段保护变更（载荷解密→执行）'),
        (rb'VirtualAlloc.{0,300}PAGE_READWRITE.{0,200}VirtualProtect.{0,300}PAGE_EXECUTE_READ',
         'RW分配→RX 转换（载荷加载→就绪）'),
        (rb'PAGE_READWRITE.{0,100}PAGE_EXECUTE_READWRITE',
         'RW→RWX 保护升级（内存直接可写可执行）'),
    ]

    # ===== 反Dump/反分析检测 =====
    ANTI_DUMP_PATTERNS = [
        (rb'\x64\xa1\x30\x00\x00\x00\x31\xc0\x64\x8b\x40\x0c',
         'PEB.Ldr 清零（阻止模块枚举）'),
        (rb'MZ.{0,20}This program cannot be run.{0,20}MZ',
         '双重MZ头（内存PE镜像拼接/反Dump）'),
        (rb'\x00{128,}\x4d\x5a', '大段零填充 + MZ（抹除PE头后重新注入）'),
        (rb'ZwProtectVirtualMemory.*PAGE_NOACCESS',
         '设置 NOACCESS 保护（隐藏载荷区域）'),
    ]

    # ===== API Unhooking 检测 =====
    UNHOOKING_PATTERNS = [
        (rb'LdrLoadDll.{0,300}ntdll|LdrGetProcedureAddress.{0,300}ntdll',
         '从已知位置重新加载 ntdll（绕过EDR Hook）'),
        (rb'ZwMapViewOfSection.{0,300}ntdll|MapViewOfFile.{0,300}ntdll',
         '内存映射 ntdll 新副本（Unhooking）'),
        (rb'NtProtectVirtualMemory.{0,300}ntdll.{0,300}PAGE_EXECUTE_READ',
         '还原 ntdll .text 节保护（Unhooking）'),
        (rb'\.text\x00\x00\x00.{0,50}ntdll',
         'ntdll .text 节引用（Unhooking 定位）'),
    ]

    # ===== 内核/驱动后门检测 =====
    KERNEL_BACKDOOR_PATTERNS = [
        (rb'NtLoadDriver|ZwLoadDriver|SeLoadDriverPrivilege',
         '加载内核驱动（持久化/提权）'),
        (rb'\\Device\\[^\x00]{2,30}\\', '内核设备路径引用'),
        (rb'\\Driver\\[^\x00]{2,30}\\', '内核驱动路径引用'),
        (rb'IoCreateDevice|IoCreateSymbolicLink', '内核设备创建（驱动后门）'),
        (rb'PsSetCreateProcessNotifyRoutine|PsSetLoadImageNotifyRoutine',
         '进程/镜像加载回调注册（监控所有进程）'),
    ]

    def __init__(self):
        self._kernel32 = None
        self._ntdll = None
        try:
            import ctypes
            self._kernel32 = ctypes.windll.kernel32
            self._ntdll = ctypes.windll.ntdll
        except:
            pass

    def comprehensive_scan(self, data: bytes, pid: int = 0) -> Dict:
        """综合内存取证扫描"""
        # 限制扫描大小: 取证特征(PE头/shellcode/hook)集中在代码段, 前 4MB 足够
        # 避免对几十 MB 的 dump 做灾难性回溯正则扫描 (曾导致收尾分析卡 15 分钟)
        _MAX_SCAN = 4 * 1024 * 1024
        if len(data) > _MAX_SCAN:
            data = data[:_MAX_SCAN]
        result = {
            'advanced_shellcode': [],
            'iat_eat_hooks': [],
            'heavens_gate': [],
            'peb_tamper': [],
            'seh_overwrite': [],
            'staged_protection': [],
            'anti_dump': [],
            'unhooking': [],
            'kernel_backdoor': [],
            'summary': '',
        }

        result['advanced_shellcode'] = self._scan_patterns(
            data, self.ADVANCED_SHELLCODE_PATTERNS, 'advanced_shellcode')
        result['iat_eat_hooks'] = self._scan_patterns(
            data, self.IAT_HOOK_PATTERNS, 'iat_hook')
        result['heavens_gate'] = self._scan_patterns(
            data, self.HEAVENS_GATE_PATTERNS, 'heavens_gate')
        result['peb_tamper'] = self._scan_patterns(
            data, self.PEB_TAMPER_PATTERNS, 'peb_tamper')
        result['seh_overwrite'] = self._scan_patterns(
            data, self.SEH_OVERWRITE_PATTERNS, 'seh_overwrite')
        result['staged_protection'] = self._scan_patterns(
            data, self.STAGED_PROTECTION_PATTERNS, 'staged_protection')
        result['anti_dump'] = self._scan_patterns(
            data, self.ANTI_DUMP_PATTERNS, 'anti_dump')
        result['unhooking'] = self._scan_patterns(
            data, self.UNHOOKING_PATTERNS, 'unhooking')
        result['kernel_backdoor'] = self._scan_patterns(
            data, self.KERNEL_BACKDOOR_PATTERNS, 'kernel_backdoor')

        parts = []
        if result['advanced_shellcode']:
            parts.append(f"现代C2框架({len(result['advanced_shellcode'])}项)")
        if result['heavens_gate']:
            parts.append(f"Heaven's Gate({len(result['heavens_gate'])}项)")
        if result['peb_tamper']:
            parts.append(f"PEB篡改({len(result['peb_tamper'])}项)")
        if result['seh_overwrite']:
            parts.append(f"SEH覆写({len(result['seh_overwrite'])}项)")
        if result['iat_eat_hooks']:
            parts.append(f"IAT Hook({len(result['iat_eat_hooks'])}项)")
        if result['anti_dump']:
            parts.append(f"反Dump({len(result['anti_dump'])}项)")
        if result['unhooking']:
            parts.append(f"API Unhooking({len(result['unhooking'])}项)")
        if result['kernel_backdoor']:
            parts.append(f"内核后门({len(result['kernel_backdoor'])}项)")
        result['summary'] = ' | '.join(parts) if parts else '未检测到高级内存取证特征'

        return result

    def _scan_patterns(self, data: bytes, patterns, category: str) -> List[Dict]:
        results = []
        for item in patterns:
            if isinstance(item, tuple) and len(item) == 2:
                pattern, desc = item
                for match in re.finditer(pattern, data, re.DOTALL | re.IGNORECASE):
                    end = min(match.start() + 32, len(data))
                    results.append({
                        'category': category,
                        'offset': f'0x{match.start():08X}',
                        'pattern': desc if isinstance(desc, str) else desc.decode(),
                        'hex': data[match.start():end].hex(),
                    })
                    if len(results) >= 12:
                        break
            if len(results) >= 12:
                break
        return results

    def detect_peb_anomalies(self, pid: int) -> List[Dict]:
        """检测 PEB 异常（BeingDebugged/HeapFlags/NtGlobalFlag）"""
        results = []

        try:
            import ctypes
            from ctypes import wintypes, byref, sizeof

            kernel32 = ctypes.windll.kernel32
            h_process = kernel32.OpenProcess(
                0x0410, False, pid  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
            )
            if not h_process:
                return results

            class PROCESS_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("ExitStatus", ctypes.c_ulong),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("AffinityMask", ctypes.c_ulong),
                    ("BasePriority", ctypes.c_ulong),
                    ("UniqueProcessId", ctypes.c_ulong),
                    ("InheritedFromUniqueProcessId", ctypes.c_ulong),
                ]

            pbi = PROCESS_BASIC_INFORMATION()
            ntdll = ctypes.windll.ntdll
            ret = ntdll.NtQueryInformationProcess(
                h_process, 0, byref(pbi), sizeof(pbi), None  # ProcessBasicInformation
            )

            if ret == 0 and pbi.PebBaseAddress:
                peb_addr = pbi.PebBaseAddress
                try:
                    peb = ctypes.create_string_buffer(1024)
                    read = wintypes.SIZE_T(0)
                    if kernel32.ReadProcessMemory(h_process, peb_addr, peb, 1024, byref(read)):
                        peb_bytes = bytes(peb[:read.value])

                        # BeingDebugged @ offset 2
                        if len(peb_bytes) > 3:
                            being_debugged = peb_bytes[2]
                            if being_debugged != 0:
                                results.append({
                                    'field': 'BeingDebugged',
                                    'value': str(being_debugged),
                                    'expected': '0',
                                    'description': 'BeingDebugged 非零（进程自认为被调试）',
                                })

                        # NtGlobalFlag 偏移: 32位 PEB @0x68, 64位 PEB @0xBC
                        _wow64 = False
                        try:
                            import ctypes as _ct
                            _out = _ct.c_ulong(0)
                            if _ct.windll.kernel32.IsWow64Process(
                                    h_process, _ct.byref(_out)):
                                _wow64 = bool(_out.value)
                        except Exception:
                            pass
                        _flag_off = 0x68 if _wow64 else 0xBC
                        if len(peb_bytes) > _flag_off + 4:
                            global_flag = struct.unpack(
                                '<I', peb_bytes[_flag_off:_flag_off + 4])[0]
                            suspicious_flags = global_flag & 0x7F
                            if suspicious_flags and suspicious_flags != 0x70:
                                results.append({
                                    'field': 'NtGlobalFlag',
                                    'value': f'0x{global_flag:08X}',
                                    'expected': '0x70 (normal)',
                                    'description': f'NtGlobalFlag 异常值（调试器标记={suspicious_flags:#x}）',
                                })
                except Exception:
                    pass

            kernel32.CloseHandle(h_process)

        except Exception as e:
            logger.debug(f"PEB检测失败 PID={pid}: {e}")

        return results

    def detect_hidden_regions(self, pid: int, known_regions: List) -> List[Dict]:
        """检测隐藏内存区域（VAD树异常/无VAD节点的内存）"""
        results = []

        h_process = open_process(pid)
        if not h_process:
            return results

        try:
            known_bases = set()
            for r in known_regions:
                try:
                    if hasattr(r, 'base_address') and r.base_address:
                        known_bases.add(int(r.base_address, 16))
                except:
                    pass

            address = 0
            scan_count = 0
            threshold = 0x7FFFFFFFFFFF

            while address < threshold and scan_count < 5000:
                mbi = virtual_query_ex(h_process, address)
                if not mbi:
                    break

                base = mbi['BaseAddress']
                size = mbi['RegionSize']
                protect = mbi['Protect']
                region_type = mbi['Type']

                if (protect in (0x40, 0x20) and  # EXECUTE_READWRITE or EXECUTE_READ
                        region_type == MEM_PRIVATE and
                        size > 0x10000 and
                        base not in known_bases):
                    results.append({
                        'type': 'hidden_region',
                        'address': f'0x{base:016X}',
                        'size': size,
                        'protect': f'0x{protect:08X}',
                        'description': '可疑私有可执行内存（不在已知区域列表中）',
                    })

                scan_count += 1
                if size == 0:
                    break
                address = base + size

        except Exception as e:
            logger.debug(f"隐藏区域检测失败 PID={pid}: {e}")
        finally:
            close_handle(h_process)

        return results[:20]


def enhance_memory_analysis(pid: int, raw_data_map: Dict[str, bytes],
                           known_regions: List) -> Dict:
    """
    便捷接口：对所有dump区域运行增强检测

    Args:
        pid: 进程PID
        raw_data_map: {region_address: dump_data} 映射
        known_regions: 已知区域列表（MemoryRegion对象列表）

    Returns:
        综合检测结果
    """
    enhancer = MemoryForensicsEnhancer()
    combined = {}

    for addr, data in raw_data_map.items():
        scan = enhancer.comprehensive_scan(data, pid)
        for key, val in scan.items():
            if key == 'summary':
                continue
            if key not in combined:
                combined[key] = []
            combined[key].extend(val)

    peb_anomalies = enhancer.detect_peb_anomalies(pid)
    if peb_anomalies:
        combined['peb_anomalies'] = peb_anomalies

    hidden = enhancer.detect_hidden_regions(pid, known_regions)
    if hidden:
        combined['hidden_regions'] = hidden

    parts = []
    if combined.get('advanced_shellcode'):
        parts.append(f"现代C2框架({len(combined['advanced_shellcode'])}项)")
    if combined.get('heavens_gate'):
        parts.append("Heaven's Gate")
    if combined.get('peb_tamper'):
        parts.append("PEB篡改")
    if combined.get('peb_anomalies'):
        parts.append(f"PEB异常({len(combined['peb_anomalies'])}项)")
    if combined.get('seh_overwrite'):
        parts.append("SEH覆写")
    if combined.get('iat_eat_hooks'):
        parts.append("IAT Hook")
    if combined.get('anti_dump'):
        parts.append("反Dump")
    if combined.get('unhooking'):
        parts.append("API Unhooking")
    if combined.get('kernel_backdoor'):
        parts.append("内核后门")
    if combined.get('hidden_regions'):
        parts.append(f"隐藏内存区域({len(combined['hidden_regions'])})")
    combined['summary'] = ' | '.join(parts) if parts else '未检测到高级内存取证特征'

    logger.info(f"[MemoryForensics] PID={pid}: {combined['summary']}")

    return combined
