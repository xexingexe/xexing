#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
交互式图表 / 网络流聚合 — 内存测试 (不执行任何样本)
覆盖: 双向 TCP 流聚合(回程包不再产生本机伪节点)、网络图去重、
      进程树叶子节点格式、离线静态回退。
"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.network import NetworkAnalyzer
from analyzer.models import NetworkTraffic, NetworkConnection, DNSQuery
from report.html_generator import HTMLReportGenerator


class FakeLayer:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class FakePkt:
    def __init__(self, size, ip, tcp=None):
        self._size = size
        self._ip = ip
        self._tcp = tcp

    def __len__(self):
        return self._size

    def haslayer(self, layer):
        return (self._tcp is not None and layer is TCP) or (self._ip is not None and layer is IP)

    def __getitem__(self, layer):
        if layer is IP:
            return self._ip
        if layer is TCP:
            return self._tcp
        raise KeyError(layer)


class _IP:
    pass


class _TCP:
    pass


IP = _IP
TCP = _TCP


def _pkt(src, sport, dst, dport, flags, size=100):
    return FakePkt(size, FakeLayer(src=src, dst=dst),
                   FakeLayer(sport=sport, dport=dport, flags=flags))


class TestBidirectionalFlowAggregation(unittest.TestCase):
    def test_return_packets_do_not_create_local_fake_remote(self):
        """出站 SYN + 回程 ACK 应合并为 1 条远端连接, 而不是把本机临时端口当远端"""
        analyzer = NetworkAnalyzer()
        packets = [
            _pkt('192.168.179.128', 50641, '57.155.142.104', 443, 0x02, size=120),  # SYN 出站
            _pkt('57.155.142.104', 443, '192.168.179.128', 50641, 0x10, size=80),   # ACK 回程
            _pkt('192.168.179.128', 50641, '57.155.142.104', 443, 0x18, size=500),  # 数据出站
        ]
        traffic = analyzer._analyze_packets(packets, {'IP': IP, 'TCP': TCP, 'UDP': object(), 'DNS': object(), 'DNSQR': object(), 'Raw': object()})
        self.assertEqual(len(traffic.tcp_connections), 1)
        conn = traffic.tcp_connections[0]
        self.assertEqual(conn.remote_addr, '57.155.142.104')
        self.assertEqual(conn.remote_port, 443)
        self.assertEqual(conn.local_addr, '192.168.179.128')
        self.assertEqual(conn.local_port, 50641)
        self.assertEqual(conn.bytes_sent, 620)  # 120 + 500
        self.assertEqual(conn.bytes_recv, 80)

    def test_inbound_before_outbound_still_canonical(self):
        analyzer = NetworkAnalyzer()
        packets = [
            _pkt('57.155.142.104', 443, '192.168.179.128', 50641, 0x10, size=80),
            _pkt('192.168.179.128', 50641, '57.155.142.104', 443, 0x02, size=120),
        ]
        traffic = analyzer._analyze_packets(packets, {'IP': IP, 'TCP': TCP, 'UDP': object(), 'DNS': object(), 'DNSQR': object(), 'Raw': object()})
        self.assertEqual(len(traffic.tcp_connections), 1)
        conn = traffic.tcp_connections[0]
        self.assertEqual(conn.remote_addr, '57.155.142.104')
        self.assertEqual(conn.local_addr, '192.168.179.128')


class TestNetworkChartData(unittest.TestCase):
    def _report(self):
        report = SimpleNamespace(network=NetworkTraffic())
        report.network.tcp_connections = [
            NetworkConnection('TCP', '10.0.0.5', 50000, '1.2.3.4', 443),
            NetworkConnection('TCP', '10.0.0.5', 50001, '1.2.3.4', 443),   # 同远端重复
            NetworkConnection('TCP', '10.0.0.5', 50002, '127.0.0.1', 9999), # 回环剔除
            NetworkConnection('TCP', '10.0.0.5', 50003, '5.6.7.8', 4444, is_suspicious=True),
        ]
        report.network.dns_queries = [DNSQuery('a.com'), DNSQuery('a.com')]
        return report

    def test_dedup_and_noise_filter(self):
        data = HTMLReportGenerator()._network_chart_data(self._report())
        ids = [n['id'] for n in data['nodes']]
        links = [(l['source'], l['target']) for l in data['links']]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(links), len(set(links)))
        self.assertNotIn('tcp_127.0.0.1:9999', ids)
        self.assertEqual(ids.count('tcp_1.2.3.4:443'), 1)
        self.assertEqual(links.count(('sample', 'tcp_1.2.3.4:443')), 1)
        self.assertEqual(links.count(('sample', 'dns_a.com')), 1)
        # 可疑连接排最前
        self.assertTrue(ids.index('tcp_5.6.7.8:4444') < ids.index('tcp_1.2.3.4:443'))

    def test_dynamic_connections_fallback_when_pcap_empty(self):
        """未抓包时用 dynamic.network_connections 回退, 网络图谱不消失"""
        report = SimpleNamespace()
        report.network = NetworkTraffic()  # pcap 为空
        report.dynamic = SimpleNamespace(network_connections=[
            {'pid': 100, 'local': '10.0.0.5:50000', 'remote': '5.6.7.8:443', 'status': 'ESTABLISHED'},
            {'pid': 100, 'local': '10.0.0.5:50001', 'remote': '5.6.7.8:443', 'status': 'ESTABLISHED'},
        ])
        data = HTMLReportGenerator()._network_chart_data(report)
        self.assertIsNotNone(data)
        ids = [n['id'] for n in data['nodes']]
        self.assertIn('tcp_5.6.7.8:443', ids)
        self.assertEqual(len(ids), len(set(ids)))
        links = [(l['source'], l['target']) for l in data['links']]
        self.assertEqual(links.count(('sample', 'tcp_5.6.7.8:443')), 1)

    def test_association_graph_keeps_network_layer(self):
        report = SimpleNamespace()
        report.file_info = SimpleNamespace(name='a.exe')
        report.scan_id = 'S1'
        report.dynamic = SimpleNamespace(
            processes_created=[{'pid': 100, 'ppid': 0, 'name': 'a.exe', 'exe': r'C:\tmp\a.exe'}],
            files_created=[{'path': r'C:\Users\Public\X\p.dll'}],
            registry_modified=[],
            sandbox_result=None,
            network_connections=[{'pid': 100, 'remote': '5.6.7.8:443'}],
        )
        report.network = NetworkTraffic()
        html = HTMLReportGenerator()._build_association_graph(report)
        self.assertIn('5.6.7.8:443', html)
        self.assertGreaterEqual(html.count('<line '), 2)  # 样本→进程 + 样本→网络 等连线


class TestChartsSectionFallback(unittest.TestCase):
    def test_fallback_and_init_helper_present(self):
        report = SimpleNamespace()
        report.dynamic = SimpleNamespace(
            processes_created=[{'pid': 100, 'ppid': 0, 'name': 'a.exe'},
                               {'pid': 200, 'ppid': 100, 'name': 'b.exe'}],
        )
        report.network = NetworkTraffic()
        report.network.tcp_connections = [
            NetworkConnection('TCP', '10.0.0.5', 50000, '1.2.3.4', 443),
        ]
        html = HTMLReportGenerator()._build_charts_section(report)
        self.assertIn('chart-fallback', html)
        self.assertIn('离线静态预览', html)
        self.assertIn("initChart('chart-proctree'", html)
        self.assertIn("initChart('chart-network'", html)
        # 叶子节点 children 应为 [], 不再输出 null
        self.assertNotIn('"children": null', html)


if __name__ == '__main__':
    unittest.main(verbosity=2)
