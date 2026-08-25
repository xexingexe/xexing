#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suricata 规则引擎 — 网络流量层面的 IDS 签名匹配

对标 VT 的 Suricata 维度：基于已捕获的连接元数据（IP:端口/字节流方向）、
HTTP 请求、DNS 查询，做 Suricata/ET 风格签名匹配，输出命中规则清单。

⚠ 说明：本模块匹配的是"连接/请求元数据"，非原始载荷字节（载荷在抓包时
已按需落盘 PCAP，可后续扩展深度报文匹配）。
"""
import re
from typing import List, Dict
from dataclasses import dataclass, field

from logger import get_logger
from analyzer.models import AnalysisReport

logger = get_logger('analyzer.suricata_rules')


@dataclass
class SuricataMatch:
    sid: int
    msg: str
    category: str
    severity: str = 'medium'
    reference: str = ''
    matched_on: str = ''
    evidence: str = ''


class SuricataEngine:
    """Suricata 风格网络签名引擎"""

    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq']
    # 已知恶意端口集合（与 network.SUSPICIOUS_PORTS 对齐 + 常见 RAT 端口）
    MALICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321,
                       5252, 8443, 9001, 4443, 9020, 1337, 6667, 44333, 444, 1177, 2087}

    def run_all(self, report: AnalysisReport) -> List[SuricataMatch]:
        """对报告网络流量执行全部 Suricata 签名"""
        matches: List[SuricataMatch] = []
        net = getattr(report, 'network', None)
        if not net:
            return matches

        tcp = net.tcp_connections or []
        udp = net.udp_connections or []
        dns = net.dns_queries or []
        http = net.http_requests or []
        suspicious = net.suspicious_traffic or []

        # ===== 1. 可疑端口外联 =====
        for conn in (tcp + udp):
            port = getattr(conn, 'remote_port', 0)
            remote = getattr(conn, 'remote_addr', '')
            if not remote or not port:
                continue
            if self._is_public_ip(remote):
                if port in self.MALICIOUS_PORTS:
                    matches.append(SuricataMatch(
                        sid=2100001, category='malware-cnc',
                        msg=f'ET MALWARE Known Malicious Port {port} Traffic',
                        severity='high',
                        reference=f'url,vet/known-malicious-port/{port}',
                        matched_on=f'{remote}:{port}',
                        evidence=f'公网 {remote} 非标准恶意端口 {port}',
                    ))
                elif port not in (80, 443, 53, 8080, 8443) and self._has_direct_ip(remote, dns):
                    matches.append(SuricataMatch(
                        sid=2100002, category='malware-cnc',
                        msg='ET POLICY Direct IP Connection (No DNS)',
                        severity='medium',
                        reference='url,vet/direct-ip',
                        matched_on=f'{remote}:{port}',
                        evidence=f'直连 IP {remote}:{port}（无 DNS 解析，规避域名信誉）',
                    ))

        # ===== 2. 可疑 TLD DNS 查询 =====
        for d in dns:
            domain = str(getattr(d, 'domain', ''))
            if any(domain.endswith(t) for t in self.SUSPICIOUS_TLDS):
                matches.append(SuricataMatch(
                    sid=2100003, category='policy-violation',
                    msg=f'ET POLICY DNS Query to Suspicious TLD ({domain.rsplit(".",1)[-1]})',
                    severity='medium',
                    reference='url,vet/suspicious-tld',
                    matched_on=domain,
                    evidence=f'DNS 查询可疑 TLD 域名 {domain}',
                ))

        # ===== 3. 高熵/DGA 域名 =====
        for d in dns:
            domain = str(getattr(d, 'domain', ''))
            if self._is_dga(domain):
                matches.append(SuricataMatch(
                    sid=2100004, category='malware-cnc',
                    msg='ET MALWARE DGA Domain Lookup',
                    severity='high',
                    reference='url,vet/dga',
                    matched_on=domain,
                    evidence=f'DGA 特征域名 {domain}（高熵/随机标签）',
                ))

        # ===== 4. DNS 隧道特征（超长标签/多级子域）=====
        for d in dns:
            domain = str(getattr(d, 'domain', ''))
            labels = [l for l in domain.split('.') if l]
            if labels and (max(len(l) for l in labels) >= 40 or len(domain) >= 60):
                matches.append(SuricataMatch(
                    sid=2100005, category='malware-cnc',
                    msg='ET MALWARE DNS Tunneling Query (Long Label)',
                    severity='high',
                    reference='url,vet/dns-tunnel',
                    matched_on=domain,
                    evidence=f'DNS 隧道疑似：{domain}（超长标签 {max(len(l) for l in labels)}）',
                ))

        # ===== 5. HTTP 可疑请求特征 =====
        for req in http:
            path = str(getattr(req, 'path', ''))
            ua = str(getattr(req, 'user_agent', ''))
            # C2 常见回调路径
            if re.search(r'/(?:beacon|heartbeat|ping|checkin|command|task|result|submit|upload|gate)',
                         path, re.IGNORECASE):
                matches.append(SuricataMatch(
                    sid=2100006, category='malware-cnc',
                    msg='ET MALWARE Possible C2 Callback URI Pattern',
                    severity='high',
                    reference='url,vet/c2-callback-uri',
                    matched_on=f'{req.host}{path}',
                    evidence=f'HTTP 回调路径疑似 C2：{path}',
                ))
            # 已知恶意 UA（curl/wget/python-requests 等脚本下载器）
            if re.search(r'curl/|wget/|python-requests/|Go-http-client/|PowerShell',
                         ua, re.IGNORECASE):
                matches.append(SuricataMatch(
                    sid=2100007, category='malware-cnc',
                    msg='ET MALWARE Suspicious User-Agent (Script Downloader)',
                    severity='medium',
                    reference='url,vet/suspicious-ua',
                    matched_on=ua[:80],
                    evidence=f'脚本下载器 UA：{ua[:100]}',
                ))

        # ===== 6. 已知可疑流量告警透传 =====
        for s in suspicious:
            stype = s.get('type', '')
            remote = s.get('remote', '')
            reason = s.get('reason', '')
            if stype == 'suspicious_port':
                matches.append(SuricataMatch(
                    sid=2100008, category='malware-cnc',
                    msg='ET MALWARE Suspicious Port Connection',
                    severity='medium',
                    reference='url,vet/suspicious-port',
                    matched_on=remote,
                    evidence=reason,
                ))

        # 去重（同 sid + matched_on 只留一条）
        dedup: Dict[str, SuricataMatch] = {}
        for m in matches:
            key = f'{m.sid}:{m.matched_on}'
            if key not in dedup:
                dedup[key] = m
        result = list(dedup.values())
        if result:
            logger.info(f"[Suricata] 命中 {len(result)} 条网络签名")
        return result

    # ---- 辅助 ----

    @staticmethod
    def _is_public_ip(addr: str) -> bool:
        try:
            import ipaddress
            ip = ipaddress.ip_address(addr.strip())
            return not (ip.is_private or ip.is_loopback or ip.is_link_local
                        or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
        except Exception:
            return False

    @staticmethod
    def _has_direct_ip(addr: str, dns) -> bool:
        """该 IP 是否从未出现在 DNS 解析结果中（直连）"""
        for d in dns:
            if addr in (d.resolved_ips or []):
                return False
        return True

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        import math
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in freq.values())

    @classmethod
    def _is_dga(cls, domain: str) -> bool:
        try:
            label = domain.split('.')[0]
            if not label or len(label) < 8:
                return False
            vowels = sum(1 for c in label.lower() if c in 'aeiou')
            consonants = sum(1 for c in label.lower() if c.isalpha()) - vowels
            digits = sum(1 for c in label if c.isdigit())
            if consonants == 0:
                return False
            v_ratio = vowels / len(label)
            d_ratio = digits / len(label)
            entropy = cls._shannon_entropy(label)
            return entropy > 3.2 and (v_ratio < 0.25 or d_ratio > 0.35)
        except Exception:
            return False
