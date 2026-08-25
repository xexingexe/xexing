#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告问题回归测试 — 不执行任何样本
覆盖: 行为时间线 None 参数不再崩溃、RAT 单弱字段不再误报具体家族。
"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.models import APIMonitorResult, APIHookDetail
from analyzer.rat_config import RATConfigExtractor


class FakeReport:
    def __init__(self):
        self.dynamic = SimpleNamespace(
            processes_created=[], critical_process_events=[], files_created=[],
            files_deleted=[], files_modified=[], files_renamed=[],
            services_created=[], services_deleted=[], scheduled_tasks=[],
            sandbox_result=None, registry_modified=[], network_connections=[],
            mutexes=[], processes_terminated=[], memory_snapshots=[],
        )
        self.network = None
        self.api_monitor = APIMonitorResult()
        self.archive = None
        self.pe_info = None
        self.memory = None
        self.threat_intel = None
        self.dropped_files = None
        self._yara_matches = []
        self._sigma_matches = []
        self._shutdown_blocked = []
        self._system_monitor = {}
        self._loaded_archive_children = []
        self._archive_shellcode_loads = []

    def __getattr__(self, item):
        return None


class TestBehaviorTimelineNoneSafety(unittest.TestCase):
    def test_none_argument_does_not_crash(self):
        from orchestrator import MalwareAnalysisPlatform
        report = FakeReport()
        report.api_monitor.call_records = [
            APIHookDetail(api_name='CreateFileW', arguments=[None, '0x123']),
            APIHookDetail(api_name='RegQueryValueExW', arguments=[None, None]),
        ]
        platform = object.__new__(MalwareAnalysisPlatform)
        events = platform._build_behavior_timeline(report)
        self.assertIsInstance(events, list)
        self.assertTrue(any(e.get('title') == 'CreateFileW' for e in events))
        # None 被过滤, 不出现 "None(...)"
        self.assertFalse(any('None' in str(e.get('detail', '')) for e in events))

    def test_high_frequency_api_events_capped(self):
        """OpenProcessToken ×50 不能再把时间线灌到 200+ 条"""
        from orchestrator import MalwareAnalysisPlatform
        report = FakeReport()
        report.api_monitor.call_records = [
            APIHookDetail(api_name='OpenProcessToken',
                          arguments=['0xffffffffffffffff', '0x8'])
            for _ in range(50)
        ] + [APIHookDetail(api_name='NtAllocateVirtualMemory',
                           arguments=['0x0', '0x1', '0x0', '0x2', '0x3000', '0x4'])
             for _ in range(50)]
        platform = object.__new__(MalwareAnalysisPlatform)
        events = platform._build_behavior_timeline(report)
        priv_titles = [e for e in events if e['title'].startswith('OpenProcessToken')]
        alloc_titles = [e for e in events if e['title'].startswith('NtAllocateVirtualMemory')]
        self.assertLessEqual(len(priv_titles), 10)
        self.assertEqual(len(alloc_titles), 0)  # 高频噪音不进时间线


class TestRATConfigFalsePositiveTightening(unittest.TestCase):
    def test_single_weak_field_not_family(self):
        ext = RATConfigExtractor()
        # 只有 smtp_pass=xxx 一个弱字段: 不应断言 AgentTesla
        results = ext.extract(b'config data smtp_pass=values123')
        families = [r['family'] for r in results]
        self.assertNotIn('AgentTesla', families)
        # 只有 campaign=2000 一个弱字段: 不应断言 FormBook
        results = ext.extract(b'campaign=2000 some other text')
        self.assertNotIn('FormBook', [r['family'] for r in results])

    def test_two_fields_still_detected(self):
        ext = RATConfigExtractor()
        results = ext.extract(b'smtp.gmail.com smtp_port=587 user=a@b.com smtp_pass=abcdef')
        self.assertIn('AgentTesla', [r['family'] for r in results])
        results = ext.extract(b'campaign=2000 http://evil.com/gate.php?id=abc123')
        self.assertIn('FormBook', [r['family'] for r in results])

    def test_two_weak_fields_not_redline(self):
        """mutex+build_id 两个弱字段巧合同现不得认定 RedLine (SilverFox 误报回归)"""
        ext = RATConfigExtractor()
        results = ext.extract(
            b'mutex=APDXAPRXASPXATOXATPXATRXBPOXBP build_id=able')
        self.assertNotIn('RedLine', [r['family'] for r in results])
        # 有真实 C2 证据时仍可识别
        results = ext.extract(
            b'mutex=APDXAPRXASPXATOXATPXATRXBPOXBP server=1.2.3.4 port=5555')
        self.assertIn('RedLine', [r['family'] for r in results])


class TestRiskCaps(unittest.TestCase):
    def test_memory_snapshot_and_url_score_capped(self):
        from orchestrator import MalwareAnalysisPlatform
        report = FakeReport()
        report.dynamic = SimpleNamespace(
            processes_created=[], files_created=[],
            memory_snapshots=[{'n': i} for i in range(37)],
            sandbox_result=None,
        )
        report.api_monitor = APIMonitorResult()
        report._url_scans = [
            SimpleNamespace(risk_level='critical', url=f'http://x{i}.com', ioc_hits=[])
            for i in range(3)
        ]
        score, level = MalwareAnalysisPlatform._calc_risk(None, report)
        items = report._risk_breakdown['items']
        snap = next(i for i in items if '内存快照' in i['detail'])
        url = next(i for i in items if i['detail'].startswith('URL扫描命中'))
        self.assertLessEqual(snap['score'], 20)
        self.assertLessEqual(url['score'], 30)
        self.assertLessEqual(score, 100)


class TestFamilySummarySync(unittest.TestCase):
    def test_yara_refine_updates_summary(self):
        from analyzer.family import FamilyAnalyzer
        from analyzer.models import MalwareFamilyAnalysis, MalwareFamilyIndicator
        existing = MalwareFamilyAnalysis(
            primary_family='SilverFox', primary_confidence=60,
            all_families=[MalwareFamilyIndicator(family_name='SilverFox',
                                                 confidence=60, indicators=['UxEnhance64.dll'])],
            summary='检测到 1 个家族匹配，最可能: SilverFox (置信度 60%)')
        refined = FamilyAnalyzer().refine_with_yara(
            existing, [{'rule': 'SilverFox_Payload_DLL'}])
        self.assertEqual(refined.primary_family, 'SilverFox')
        self.assertIn('SilverFox', refined.summary)
        self.assertIn(str(int(refined.primary_confidence)), refined.summary)
        self.assertNotIn('60%', refined.summary)  # 精炼后 summary 必须同步到 90%


class TestDynamicNetworkMerge(unittest.TestCase):
    def test_pcap_off_still_reports_connections(self):
        """银狐外联场景: 没开抓包时, 进程级连接也要进入网络分析"""
        from orchestrator import MalwareAnalysisPlatform
        from analyzer.models import NetworkTraffic
        traffic = NetworkTraffic()
        dyn = SimpleNamespace(network_connections=[
            {'pid': 100, 'local': '10.0.0.5:50000',
             'remote': '39.156.231.62:443', 'status': 'ESTABLISHED'},
            {'pid': 100, 'local': '10.0.0.5:50001',
             'remote': '39.156.231.62:443', 'status': 'SYN_SENT'},
        ])
        MalwareAnalysisPlatform._merge_dynamic_connections(None, traffic, dyn)
        self.assertEqual(len(traffic.tcp_connections), 1)  # 同远端去重
        conn = traffic.tcp_connections[0]
        self.assertEqual(conn.remote_addr, '39.156.231.62')
        self.assertEqual(conn.remote_port, 443)
        self.assertEqual(conn.pid, 100)

    def test_pid_backfilled_onto_existing_pcap_connection(self):
        """pcap 已有同名远端(pid=0)时, 动态连接 PID 必须回填, 否则会被过滤成 0 条"""
        from orchestrator import MalwareAnalysisPlatform
        from analyzer.models import NetworkTraffic, NetworkConnection
        traffic = NetworkTraffic()
        traffic.tcp_connections = [
            NetworkConnection('TCP', '10.0.0.5', 50000, '110.43.89.73', 80),
            NetworkConnection('TCP', '10.0.0.5', 50001, '1.0.0.1', 443),  # 系统噪音
        ]
        dyn = SimpleNamespace(
            processes_created=[],
            sandbox_result=None,
            network_connections=[
                {'pid': 8408, 'local': '10.0.0.5:50000',
                 'remote': '110.43.89.73:80', 'status': 'ESTABLISHED',
                 'kind': 'SocketKind.SOCK_STREAM'},
            ])
        platform = object.__new__(MalwareAnalysisPlatform)
        MalwareAnalysisPlatform._merge_dynamic_connections(None, traffic, dyn)
        platform._filter_traffic_by_target(traffic, dyn)
        self.assertEqual(len(traffic.tcp_connections), 1)
        self.assertEqual(traffic.tcp_connections[0].remote_addr, '110.43.89.73')
        self.assertEqual(traffic.tcp_connections[0].pid, 8408)


class TestUnattributedPcapNoise(unittest.TestCase):
    def test_system_pcap_cleared_when_sample_has_no_connections(self):
        """sysdiag 场景: pcap 抓到系统 DNS 流量, 进程级监控证明样本没有外联"""
        from orchestrator import MalwareAnalysisPlatform
        from analyzer.models import NetworkTraffic, NetworkConnection
        traffic = NetworkTraffic()
        traffic.tcp_connections = [
            NetworkConnection('TCP', '10.0.0.5', 50000, '1.0.0.1', 443),
            NetworkConnection('TCP', '10.0.0.5', 50001, '1.1.1.1', 443),
        ]
        traffic.total_packets = 2
        dyn = SimpleNamespace(
            processes_created=[{'pid': 100, 'name': 'sysdiag.exe'}],
            sandbox_result=None, network_connections=[])
        platform = object.__new__(MalwareAnalysisPlatform)
        platform._filter_traffic_by_target(traffic, dyn)
        self.assertEqual(traffic.tcp_connections, [])
        self.assertEqual(traffic.total_packets, 0)
        self.assertEqual(getattr(traffic, '_network_attribution', ''),
                         'no_sample_connections')

    def test_sample_connections_kept(self):
        from orchestrator import MalwareAnalysisPlatform
        from analyzer.models import NetworkTraffic, NetworkConnection
        traffic = NetworkTraffic()
        traffic.tcp_connections = [
            NetworkConnection('TCP', '10.0.0.5', 50000, '39.156.231.62', 443, pid=100),
        ]
        dyn = SimpleNamespace(
            processes_created=[{'pid': 100, 'name': 'sample.exe'}],
            sandbox_result=None,
            network_connections=[{'pid': 100, 'remote': '39.156.231.62:443'}])
        platform = object.__new__(MalwareAnalysisPlatform)
        platform._filter_traffic_by_target(traffic, dyn)
        self.assertEqual(len(traffic.tcp_connections), 1)
        self.assertEqual(traffic.tcp_connections[0].remote_addr, '39.156.231.62')


class TestGenericRATNoise(unittest.TestCase):
    def test_schema_url_not_reported_as_c2(self):
        ext = RATConfigExtractor()
        results = ext.extract(b'xmlns http://schemas.microsoft.com/SMI/2005/WindowsSettings')
        self.assertEqual(results, [])


class TestInstallerFalsePositives(unittest.TestCase):
    def test_generic_terms_no_longer_meterpreter(self):
        from analyzer.family import FamilyAnalyzer
        strings = SimpleNamespace(
            suspicious_strings=['x86', 'x64', 'reverse', 'priv'],
            api_calls=['VirtualAlloc', 'LoadLibraryA'],
            urls=['https://example.com:443'], domains=['example.com'],
            file_paths=[], ips=[])
        result = FamilyAnalyzer().analyze(strings, None)
        self.assertNotEqual(result.primary_family, 'Meterpreter')

    def test_inno_temp_and_benign_paths_not_anti_analysis(self):
        from analyzer.advanced_behavior import AdvancedBehaviorDetector
        strings = SimpleNamespace(
            suspicious_strings=['GetSystemDirectory', 'AdjustTokenPrivileges',
                                'LookupPrivilegeValueW'],
            api_calls=['GetSystemDirectory', 'AdjustTokenPrivileges',
                       'LookupPrivilegeValueW'],
            file_paths=[], urls=[], domains=[], ips=[])
        dynamic = SimpleNamespace(
            processes_created=[],
            files_created=[
                {'path': r'C:\Users\ADMINI~1\AppData\Local\Temp\is-HV186.tmp\_isetup\_shfoldr.dll'},
                {'path': r'C:\Users\Public\Pictures\Runtime\Cookie\cookie.dat'},
                {'path': r'C:\Users\Administrator\Desktop\sysdiag_x64_6.0.1.lnk'},
            ],
            files_modified=[], files_deleted=[])
        ab = AdvancedBehaviorDetector().analyze(strings, None, dynamic, api_records=[])
        joined = ' '.join(ab.anti_analysis)
        self.assertNotIn('获取系统目录', joined)
        self.assertNotIn('cookie.dat', joined)
        self.assertNotIn('随机名称目录', joined)
        self.assertNotIn('AdjustTokenPrivileges 提权操作',
                         ' '.join(ab.privilege_escalation))

    def test_real_privilege_api_still_detected(self):
        from analyzer.advanced_behavior import AdvancedBehaviorDetector
        strings = SimpleNamespace(
            suspicious_strings=[], api_calls=[], file_paths=[],
            urls=[], domains=[], ips=[])
        dynamic = SimpleNamespace(
            processes_created=[], files_created=[], files_modified=[],
            files_deleted=[])
        records = [APIHookDetail(api_name='AdjustTokenPrivileges', arguments=[])]
        ab = AdvancedBehaviorDetector().analyze(strings, None, dynamic, api_records=records)
        # 动态调用证据存在时, 通过动态判定补回提权行为
        self.assertTrue(any('提权' in p or '特权' in p
                            for p in ab.privilege_escalation))

    def test_static_sedebug_without_api_not_privilege(self):
        from analyzer.advanced_behavior import AdvancedBehaviorDetector
        strings = SimpleNamespace(
            suspicious_strings=['SeDebugPrivilege'], api_calls=[],
            file_paths=[], urls=[], domains=[], ips=[])
        dynamic = SimpleNamespace(
            processes_created=[], files_created=[], files_modified=[],
            files_deleted=[])
        ab = AdvancedBehaviorDetector().analyze(strings, None, dynamic, api_records=[])
        self.assertFalse(any('SeDebugPrivilege' in p
                             for p in ab.privilege_escalation))


class TestDeepDiveBenignC2Filter(unittest.TestCase):
    def test_namespace_urls_not_in_c2_profile(self):
        from analyzer.deep_dive import DeepDiveAnalyzer
        report = SimpleNamespace()
        report.strings = SimpleNamespace(
            urls=['http://schemas.microsoft.com/SMI/2005/WindowsSettings',
                  'http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline'],
            domains=['s.gq', 'V.GA', 'microsoft.com', 'evil-c2.xyz'],
            ips=[], suspicious_strings=[])
        report.dynamic = SimpleNamespace(network_connections=[])
        report.network = None
        result = SimpleNamespace(network_profile=None)
        DeepDiveAnalyzer()._analyze_network(report, result)
        cfg = getattr(result.network_profile, 'c2_config', None) or {}
        urls = cfg.get('urls', [])
        domains = cfg.get('domains', [])
        self.assertNotIn('http://schemas.microsoft.com/SMI/2005/WindowsSettings', urls)
        self.assertNotIn('http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline', urls)
        self.assertNotIn('s.gq', domains)
        self.assertNotIn('V.GA', domains)
        self.assertIn('evil-c2.xyz', domains)


if __name__ == '__main__':
    unittest.main(verbosity=2)
