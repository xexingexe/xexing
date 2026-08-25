#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v3.4 改进回归测试 — 不执行任何样本。

覆盖:
  1. DEP 绕过行为时间线 (memprot 事件进入时间线) 与阶段化流程图
  2. 目标进程退出时的内存诊断 (分配/释放失衡 + 退出前 DEP 事件), 不再只提示"内存退出"
  3. 木马家族: 端口上下文匹配 / 仅弱证据不报具体家族 / 威胁情报精炼
  4. 高级行为: 七组条件反沙箱动态确认 + DEP 绕过动态确认
  5. 沙箱环境伪装: 反VM脚本覆盖 13 项 VM 检测 + 七条件 (GetSystemMetrics/CPU/GetTickCount/用户名)
"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.api_monitor import APIMonitor, FRIDA_ANTIVM_SCRIPT
from analyzer.models import APIMonitorResult, APIHookDetail, MemoryAnalysis
from report.html_generator import HTMLReportGenerator


class FakeReport:
    def __init__(self):
        self.dynamic = SimpleNamespace(
            processes_created=[], critical_process_events=[], files_created=[],
            files_deleted=[], files_modified=[], files_renamed=[],
            services_created=[], services_deleted=[], scheduled_tasks=[],
            sandbox_result=None, registry_modified=[], network_connections=[],
            mutexes=[], processes_terminated=[], memory_snapshots=[],
            execution_time=1.0,
        )
        self.network = None
        self.api_monitor = None
        self.archive = None
        self.pe_info = None
        self.memory = None
        self.threat_intel = None
        self.dropped_files = None
        self.malware_family = None
        self.advanced_behavior = None
        self._yara_matches = []
        self._sigma_matches = []
        self._community_signatures = []
        self._shutdown_blocked = []
        self._system_monitor = {}
        self._loaded_archive_children = []
        self._archive_shellcode_loads = []
        self._memprot_summary = None

    def __getattr__(self, item):
        return None


class TestDepBypassTimelineAndFlow(unittest.TestCase):
    def test_memprot_events_enter_behavior_timeline(self):
        from orchestrator import MalwareAnalysisPlatform
        report = FakeReport()
        am = APIMonitorResult()
        am._memprot_events = [{
            'api': 'NtAllocateVirtualMemory', 'base': '0x1a2b3c4d0000',
            'size': 5368742120, 'old_prot': '-',
            'new_prot': 'EXECUTE_READWRITE|WRITECOPY',
            'rw_to_rx': False, 'rwx_alloc': True, 'injection': False,
            'dep_bypass': True, 'rop_like': True, 'huge_alloc': True,
        }]
        am._memprot_stats = {'sleep_total_ms': 0, 'enum_snapshot_count': 0}
        report.api_monitor = am
        platform = object.__new__(MalwareAnalysisPlatform)
        events = platform._build_behavior_timeline(report)
        dep_events = [e for e in events if e.get('category') == 'dep']
        self.assertTrue(dep_events)
        self.assertTrue(any('DEP绕过' in e.get('title', '') for e in dep_events))

    def test_dep_flow_section_renders_stages(self):
        report = FakeReport()
        am = APIMonitorResult()
        am._memprot_events = [{
            'api': 'VirtualProtect', 'base': '0x1000', 'size': 4096,
            'old_prot': 'READWRITE', 'new_prot': 'EXECUTE_READ',
            'rw_to_rx': True, 'rwx_alloc': False, 'injection': False,
            'dep_bypass': False, 'rop_like': False, 'huge_alloc': False,
        }, {
            'api': 'NtAllocateVirtualMemory', 'base': '0x2', 'size': 5368742120,
            'old_prot': '-', 'new_prot': 'EXECUTE_READWRITE|WRITECOPY',
            'rw_to_rx': False, 'rwx_alloc': True, 'injection': False,
            'dep_bypass': True, 'rop_like': True, 'huge_alloc': True,
        }]
        am.suspicious_sequences = ['NtAllocateVirtualMemory RWX分配 (DEP绕过/ROP特征)']
        am.call_records = [
            APIHookDetail(api_name='WriteProcessMemory', arguments=['0x1', '0x2']),
            APIHookDetail(api_name='CreateRemoteThread', arguments=['0x1', '0x2']),
        ]
        report.api_monitor = am
        html = HTMLReportGenerator()._build_dep_bypass_flow_section(report)
        self.assertIn('DEP 绕过行为时间线流程图', html)
        self.assertIn('② RWX 内存分配 (DEP绕过)', html)
        self.assertIn('T1620', html)
        self.assertIn('✅', html)

    def test_no_dep_evidence_returns_empty_flow(self):
        report = FakeReport()
        am = APIMonitorResult()
        am._memprot_events = []
        am.suspicious_sequences = []
        am.call_records = []
        report.api_monitor = am
        self.assertEqual(HTMLReportGenerator()._build_dep_bypass_flow_section(report), '')


class TestMemoryExitDiagnosis(unittest.TestCase):
    def test_exit_diagnosis_reports_leak_and_dep(self):
        from orchestrator import MalwareAnalysisPlatform
        report = FakeReport()
        am = APIMonitorResult()
        am.call_records = [
            APIHookDetail(api_name='VirtualAlloc', arguments=['0x1', '0x1000'])
            for _ in range(10)
        ] + [
            APIHookDetail(api_name='VirtualFree', arguments=['0x1'])
            for _ in range(2)
        ]
        am._memprot_events = [{
            'api': 'NtAllocateVirtualMemory', 'base': '0x1', 'size': 5368742120,
            'old_prot': '-', 'new_prot': 'EXECUTE_READWRITE|WRITECOPY',
            'rw_to_rx': False, 'rwx_alloc': True, 'injection': False,
            'dep_bypass': True, 'rop_like': True, 'huge_alloc': True,
        }]
        am._memprot_stats = {'sleep_total_ms': 0, 'enum_snapshot_count': 0}
        report.api_monitor = am
        platform = object.__new__(MalwareAnalysisPlatform)
        diag = platform._build_memory_exit_diagnosis(report, {1234})
        self.assertTrue(diag.process_exited)
        self.assertFalse(diag.live_analyzed)
        self.assertEqual(diag.exit_diagnosis['alloc_calls'], 10)
        self.assertEqual(diag.exit_diagnosis['free_calls'], 2)
        self.assertEqual(diag.exit_diagnosis['leaked_allocations'], 8)
        self.assertIn('内存未释放', diag.summary)
        self.assertIn('DEP绕过', diag.summary)

    def test_html_memory_section_shows_diagnosis(self):
        report = FakeReport()
        report.memory = MemoryAnalysis(
            process_exited=True, live_analyzed=False,
            exit_diagnosis={
                'alloc_calls': 10, 'free_calls': 2, 'leaked_allocations': 8,
                'rwx_alloc': 1, 'rw_to_rx': 0, 'dep_bypass': 1, 'rop_like': 1,
                'huge_alloc': 1, 'injection': 0, 'dump_files': [],
                'execution_snapshots': 0,
            },
            summary='目标进程已退出 — 诊断',
        )
        html = HTMLReportGenerator()._build_memory_section(report)
        self.assertIn('内存检测结论', html)
        self.assertIn('内存未释放', html)
        self.assertIn('DEP绕过/ROP喷射', html)


class TestFamilyAccuracy(unittest.TestCase):
    def test_benign_port_in_url_does_not_boost_family(self):
        from analyzer.family import FamilyAnalyzer
        strings = SimpleNamespace(
            suspicious_strings=['x86', 'x64', 'reverse', 'priv'],
            api_calls=['VirtualAlloc', 'LoadLibraryA'],
            urls=['https://example.com:443/index.html'],
            domains=['example.com'], file_paths=[], ips=[])
        result = FamilyAnalyzer().analyze(strings, None)
        self.assertEqual(result.primary_family, 'Unknown')

    def test_threat_intel_refines_family(self):
        from analyzer.family import FamilyAnalyzer
        from analyzer.models import MalwareFamilyAnalysis, MalwareFamilyIndicator
        existing = MalwareFamilyAnalysis(
            primary_family='Unknown', primary_confidence=0,
            all_families=[], summary='')
        refined = FamilyAnalyzer().refine_with_threat_intel(
            existing, SimpleNamespace(family='SilverFox', threat_labels=['malicious']))
        self.assertEqual(refined.primary_family, 'SilverFox')
        self.assertGreaterEqual(refined.primary_confidence, 35)


class TestAdvancedBehaviorSevenConditions(unittest.TestCase):
    def _strings(self):
        return SimpleNamespace(
            suspicious_strings=[
                'IsDebuggerPresent', 'GetSystemMetrics', 'GetTickCount64',
                'GlobalMemoryStatusEx', 'CreateToolhelp32Snapshot',
                'GetUserNameW', 'GetSystemInfo', 'VirtualAlloc',
            ],
            api_calls=['IsDebuggerPresent', 'GetSystemMetrics', 'GetTickCount64',
                       'GlobalMemoryStatusEx', 'CreateToolhelp32Snapshot',
                       'GetUserNameW', 'GetSystemInfo'],
            file_paths=[], urls=[], domains=[], ips=[])

    def test_static_seven_condition_pattern(self):
        from analyzer.advanced_behavior import AdvancedBehaviorDetector
        ab = AdvancedBehaviorDetector().analyze(self._strings(), None)
        self.assertTrue(any('七组条件' in s or '多条件串联' in s for s in ab.anti_sandbox))

    def test_dynamic_seven_condition_and_dep_confirmation(self):
        from analyzer.advanced_behavior import AdvancedBehaviorDetector
        records = [
            APIHookDetail(api_name='IsDebuggerPresent'),
            APIHookDetail(api_name='GetSystemMetrics', arguments=['0']),
            APIHookDetail(api_name='GetSystemInfo'),
            APIHookDetail(api_name='GetTickCount64'),
            APIHookDetail(api_name='GlobalMemoryStatusEx'),
            APIHookDetail(api_name='Process32FirstW'),
            APIHookDetail(api_name='GetUserNameW'),
            APIHookDetail(api_name='NtAllocateVirtualMemory',
                          arguments=['0x1c0', '0x2a1f0e00000', '0x0',
                                     '0x2a1f0dffc0', '0xfac000', '0x40']),
            APIHookDetail(api_name='WriteProcessMemory', arguments=['0x1', '0x2']),
            APIHookDetail(api_name='CreateRemoteThread', arguments=['0x1', '0x2']),
        ]
        ab = AdvancedBehaviorDetector().analyze(self._strings(), None, None, api_records=records)
        self.assertTrue(any('七组条件' in s for s in ab.anti_sandbox))
        self.assertTrue(any('DEP 绕过' in s for s in ab.process_injection))
        self.assertTrue(any('远程线程执行链' in s for s in ab.process_injection))


class TestSandboxDisguiseCoverage(unittest.TestCase):
    def test_antivm_script_covers_reported_checks(self):
        low = FRIDA_ANTIVM_SCRIPT.lower()
        # 5.1 VM 检测 13 项
        # 反斜杠在 JS 字符串字面量中成对出现, 统一去掉反斜杠/空格后做覆盖断言
        compact = low.replace('\\', '').replace(' ', '')
        for needle in ('softwarevmware', 'softwareoraclevirtualbox',
                       'detectedcomponents', '.vmci', '.hgfs',
                       'vboxminirdrdn', 'vmmouse.sys', 'vmhgfs.sys',
                       'vboxguest.sys', 'vmtoolsd.exe', 'vmwaretray.exe',
                       'vboxservice.exe', 'vboxtray.exe'):
            self.assertIn(needle, compact, needle)
        # 5.2 七组条件
        for needle in ('getsystemmetrics', 'getsysteminfo', 'getnativesysteminfo',
                       'gettickcount', 'globalmemorystatus',
                       'getusernamew', 'getusernameexw',
                       'getenvironmentvariablew'):
            self.assertIn(needle, low, needle)
        # 伪造用户名: 源脚本含占位符, 生成脚本注入配置值 (规避黑名单)
        self.assertIn('__SANDBOX_FAKE_USER__', FRIDA_ANTIVM_SCRIPT)
        generated = APIMonitor._antivm_source()
        self.assertIn("FAKE_USERNAME = 'zhangwei'", generated)
        self.assertNotIn('__SANDBOX_FAKE_USER__', generated)

    def test_vm_hider_removes_hyperv_guest_key(self):
        from analyzer.vm_process_hider import VM_REGISTRY_KEYS
        joined = '|'.join(VM_REGISTRY_KEYS).lower()
        self.assertIn('virtual machine\\guest\\detectedcomponents', joined)

    def test_deep_dive_auto_enabled_by_default(self):
        from config import CONFIG
        self.assertTrue(getattr(CONFIG.deep_dive, 'auto_enabled', False))


if __name__ == '__main__':
    unittest.main(verbosity=2)
