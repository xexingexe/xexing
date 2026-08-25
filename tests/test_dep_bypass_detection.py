#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DEP绕过 / ROP喷射 行为检测 — 内存测试 (不执行任何样本)
覆盖: Frida memprot 事件归一化、NtAllocate/NtProtect RWX 参数兜底、
      orchestrator 风险计分、HTML MITRE 矩阵聚合。
"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.api_monitor import APIMonitor, _coerce_int, _fmt_bytes
from analyzer.models import APIMonitorResult, APIHookDetail
from report.html_generator import HTMLReportGenerator


class FakeReport:
    """任意未定义属性返回 None, 模拟未执行的分析阶段"""
    def __init__(self):
        self.api_monitor = None
        self.advanced_behavior = None
        self.dynamic = None
        self.network = None
        self.memory = None
        self.destruction = None
        self.file_info = None
        self.pe_info = None
        self.strings = None
        self.threat_intel = None
        self.malware_family = None
        self._memprot_summary = None
        self._sigma_matches = []
        self._yara_matches = []
        self._community_signatures = []

    def __getattr__(self, item):
        return None


class TestMemprotEventNormalization(unittest.TestCase):
    def test_cloud_sandbox_equivalent_event(self):
        """云沙箱对照样本: region_size=5368742120 protection=0x400080E8"""
        mon = APIMonitor(timeout=1)
        payload = {
            'type': 'memprot',
            'api': 'NtAllocateVirtualMemory',
            'base': '0x1a2b3c4d0000',
            'size': '5368742120',
            'old_prot': '-',
            'new_prot': 'EXECUTE_WRITECOPY|EXECUTE_READWRITE|EXECUTE_READ|WRITECOPY',
            'protection': '0x400080e8',
            'allocation_type': '0xfac000',
            'status': -1073741811,
            'rw_to_rx': False,
            'rwx_alloc': True,
            'dep_bypass': True,
            'rop_like': True,
            'huge_alloc': True,
            'injection': False,
        }
        mon._on_memprot_message({'type': 'send', 'payload': payload}, None)
        self.assertEqual(len(mon._memprot_events), 1)
        evt = mon._memprot_events[0]
        self.assertEqual(evt['size'], 5368742120)
        self.assertTrue(evt['rwx_alloc'])
        self.assertTrue(evt['dep_bypass'])
        self.assertTrue(evt['rop_like'])
        self.assertTrue(evt['huge_alloc'])
        self.assertEqual(evt['status'], -1073741811)
        self.assertEqual(evt['protection'], '0x400080e8')

    def test_old_format_event_backward_compatible(self):
        mon = APIMonitor(timeout=1)
        mon._on_memprot_message({'type': 'send', 'payload': {
            'type': 'memprot', 'api': 'VirtualProtect', 'base': '0x1000',
            'size': 4096, 'old_prot': 'READWRITE', 'new_prot': 'EXECUTE_READ',
            'rw_to_rx': True, 'rwx_alloc': False, 'injection': False,
        }}, None)
        evt = mon._memprot_events[0]
        self.assertTrue(evt['rw_to_rx'])
        self.assertFalse(evt['dep_bypass'])

    def test_size_coercion(self):
        self.assertEqual(_coerce_int('5368742120'), 5368742120)
        self.assertEqual(_coerce_int('0x400080e8'), 0x400080e8)
        self.assertEqual(_coerce_int(None), 0)
        self.assertIn('5.00 GB', _fmt_bytes(5368742120))


class TestRecordFallback(unittest.TestCase):
    def test_rwx_protection_arguments_detected(self):
        """memprot 脚本未加载时, 从主脚本 API 记录解析 RWX 参数"""
        mon = APIMonitor(timeout=1)
        records = [
            # NtAllocateVirtualMemory(Handle, BaseAddress*, ZeroBits, RegionSize*,
            #                        AllocationType, Protect) — 保护属性是第6个参数
            APIHookDetail(api_name='NtAllocateVirtualMemory', arguments=[
                '0x1c0', '0x2a1f0e00000', '0x0', '0x2a1f0dffc0',
                '0xfac000', '0x400080e8']),
            # NtProtectVirtualMemory(Handle, BaseAddress*, RegionSize*,
            #                        NewProtect, OldProtect*)
            APIHookDetail(api_name='NtProtectVirtualMemory', arguments=[
                '0x1c0', '0x2a1f0e00000', '0x2a1f0dffd0', '0x40', '0x2a1f0dffe8']),
        ]
        sequences = mon._detect_sequences(records)
        self.assertIn('NtAllocateVirtualMemory RWX分配 (DEP绕过/ROP特征)', sequences)
        self.assertIn('NtProtectVirtualMemory 设置为 RWX (DEP绕过特征)', sequences)

    def test_normal_allocation_not_flagged(self):
        mon = APIMonitor(timeout=1)
        records = [APIHookDetail(api_name='NtAllocateVirtualMemory', arguments=[
            '0x1c0', '0x2a1f0e00000', '0x0', '0x2a1f0dffc0',
            '0x3000', '0x4'])]  # MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
        sequences = mon._detect_sequences(records)
        self.assertFalse(any('DEP绕过' in s for s in sequences))


class TestMitreAggregation(unittest.TestCase):
    def test_memprot_and_sigma_and_sequences_aggregated(self):
        report = FakeReport()
        am = APIMonitorResult(
            suspicious_sequences=[
                'NtAllocateVirtualMemory RWX分配 (DEP绕过/ROP特征)',
                'Process injection chain detected (Classic)',
                'Windows Defender disabled via registry',
            ],
            call_summary={'NtCreateThreadEx': 1, 'CreateRemoteThread': 2},
        )
        report.api_monitor = am
        report._memprot_summary = {
            'rw_to_rx': 1, 'rwx_alloc': 1, 'dep_bypass': 1, 'rop_like': 1,
            'huge_alloc': 1, 'injection': 1, 'enum_snapshot_count': 20,
            'sleep_total_ms': 60000,
        }
        report._sigma_matches = [type('Sigma', (), {'technique': 'T1547.001'})()]
        html = HTMLReportGenerator()._build_mitre_matrix_section(report)
        self.assertIn('T1620', html)
        self.assertIn('T1055', html)
        self.assertIn('T1055.001', html)
        self.assertIn('T1057', html)
        self.assertIn('T1497.003', html)
        self.assertIn('T1547.001', html)
        self.assertIn('T1562.001', html)

    def test_empty_report_returns_empty(self):
        report = FakeReport()
        self.assertEqual(HTMLReportGenerator()._build_mitre_matrix_section(report), '')


class TestRiskScoring(unittest.TestCase):
    def test_rop_event_scores_and_sets_summary(self):
        from orchestrator import MalwareAnalysisPlatform
        report = FakeReport()
        am = APIMonitorResult()
        am._memprot_events = [{
            'api': 'NtAllocateVirtualMemory', 'base': '0x1', 'size': 5368742120,
            'old_prot': '-', 'new_prot': 'EXECUTE_WRITECOPY|WRITECOPY',
            'rw_to_rx': False, 'rwx_alloc': True, 'injection': False,
            'dep_bypass': True, 'rop_like': True, 'huge_alloc': True,
        }]
        am._memprot_stats = {'sleep_total_ms': 0, 'enum_snapshot_count': 0}
        am._dll_calls = {}
        am._spoof_actions = []
        report.api_monitor = am
        report.dynamic = SimpleNamespace(
            processes_created=[], files_created=[], memory_snapshots=[],
            sandbox_result=None,
        )
        score, level = MalwareAnalysisPlatform._calc_risk(None, report)
        self.assertGreater(score, 0)
        summary = report._memprot_summary
        self.assertEqual(summary['dep_bypass'], 1)
        self.assertEqual(summary['rop_like'], 1)
        self.assertEqual(summary['huge_alloc'], 1)
        details = [item['detail'] for item in report._risk_breakdown['items']]
        self.assertTrue(any('DEP绕过/ROP喷射' in d for d in details))


if __name__ == '__main__':
    unittest.main(verbosity=2)
