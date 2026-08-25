#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络行为分析引擎 — 增强版，支持 DNS、HTTP、TCP/UDP、可疑流量检测
"""
import os
import socket
import threading
import time
from typing import Dict

from logger import get_logger
from analyzer.models import NetworkTraffic, NetworkConnection, DNSQuery, HTTPRequest

logger = get_logger('analyzer.network')

# psutil 可选
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

SCAPY_AVAILABLE = False
_scapy_module = None


def _ensure_scapy():
    """延迟导入 scapy，避免启动时触发平台探测"""
    global SCAPY_AVAILABLE, _scapy_module
    if SCAPY_AVAILABLE and _scapy_module is not None:
        return _scapy_module
    try:
        from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
        _scapy_module = {'sniff': sniff, 'IP': IP, 'TCP': TCP, 'UDP': UDP, 'DNS': DNS, 'DNSQR': DNSQR, 'Raw': Raw}
        SCAPY_AVAILABLE = True
        return _scapy_module
    except Exception:
        SCAPY_AVAILABLE = False
        return None


class NetworkAnalyzer:
    """网络行为分析器"""
    
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321,
                    5252, 8443, 9001, 4443, 9020, 1337, 6667, 44333}
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq']
    
    def __init__(self, timeout: int = 60, target_pid: int = None):
        self.timeout = timeout
        self.target_pid = target_pid
        self.packets = []
        
    def capture(self, stop_event: threading.Event = None, pcap_path: str = None) -> NetworkTraffic:
        """捕获网络流量"""
        logger.info(f"[*] 网络流量捕获 (timeout={self.timeout}s)")
        
        # 注意: 必须调用 _ensure_scapy() 实际检测 — 模块级 SCAPY_AVAILABLE
        # 从未被初始化(历史bug: scapy已安装却永远走psutil降级, DNS/HTTP解析从未生效)
        if _ensure_scapy() is None:
            logger.warning("[-] Scapy 不可用，使用 psutil 进行网络监控")
            return self._capture_with_psutil(stop_event=stop_event)
        
        return self._capture_with_scapy(stop_event=stop_event, pcap_path=pcap_path)
    
    def _capture_with_scapy(self, stop_event: threading.Event = None, pcap_path: str = None) -> NetworkTraffic:
        """使用 Scapy 抓包 — 多网卡并发 (修复虚拟机选错虚拟适配器导致 0 包)"""
        scapy = _ensure_scapy()
        if scapy is None:
            logger.warning("[-] Scapy 初始化失败，回退到 psutil")
            return self._capture_with_psutil(stop_event=stop_event)

        packets = []
        pcap_writer = None
        pcap_created = False

        # PCAP 落盘: 仅在配置启用且调用方提供路径时创建
        if pcap_path:
            try:
                from config import CONFIG
                if getattr(CONFIG.network, 'pcap_enabled', False):
                    pcap_dir = os.path.dirname(os.path.abspath(pcap_path))
                    if pcap_dir:
                        os.makedirs(pcap_dir, exist_ok=True)
                    from scapy.utils import PcapWriter
                    pcap_writer = PcapWriter(pcap_path, append=False, sync=True)
                    pcap_created = True
                    logger.info(f"[+] PCAP 抓包: {pcap_path}")
            except Exception as e:
                logger.warning(f"[-] PCAP 写入初始化失败，继续内存抓包: {e}")
                pcap_writer = None
                pcap_created = False

        _pkts_lock = threading.Lock()
        _write_lock = threading.Lock()

        def handler(pkt):
            with _pkts_lock:
                packets.append(pkt)
            if pcap_writer is not None:
                with _write_lock:
                    try:
                        pcap_writer.write(pkt)
                    except Exception:
                        pass

        # 枚举有 IPv4 的候选抓包网卡 (默认路由网卡优先)
        ifaces = self._enumerate_ifaces()
        if not ifaces:
            logger.warning("[-] 未枚举到可用抓包网卡，回退 psutil 模式")
            if pcap_writer is not None:
                try:
                    pcap_writer.close()
                except Exception:
                    pass
            return self._capture_with_psutil(stop_event=stop_event)

        if len(ifaces) == 1:
            sniff_kwargs = {'timeout': self.timeout, 'prn': handler, 'store': False, 'iface': ifaces[0]}
            if stop_event is not None:
                sniff_kwargs['stop_filter'] = (lambda p: bool(stop_event and stop_event.is_set()))
            logger.info(f"[*] 抓包网卡: {ifaces[0]}")
            try:
                scapy['sniff'](**sniff_kwargs)
            except Exception as e:
                logger.warning(f"[-] Scapy 抓包不可用 ({str(e)[:80]}), 自动降级 psutil 模式")
                try:
                    if pcap_writer is not None:
                        pcap_writer.close()
                except Exception:
                    pass
                return self._capture_with_psutil(stop_event=stop_event)
        else:
            # 多网卡并发抓包: 虚拟机里常有 VMnet1/VMnet8 等未接线虚拟适配器,
            # 只抓默认路由网卡可能选错 → 同时抓所有有 IPv4 的网卡, 合并结果。
            logger.info(f"[*] 并发抓包网卡 ({len(ifaces)}): {', '.join(ifaces)}")
            _threads = []
            for _iface in ifaces:
                def _run(_iface=_iface):
                    try:
                        kw = {'timeout': self.timeout, 'prn': handler, 'store': False, 'iface': _iface}
                        if stop_event is not None:
                            kw['stop_filter'] = (lambda p: bool(stop_event and stop_event.is_set()))
                        scapy['sniff'](**kw)
                    except Exception as e:
                        logger.warning(f"[-] 网卡 {_iface} 抓包异常: {str(e)[:60]}")
                t = threading.Thread(target=_run, daemon=True)
                _threads.append(t)
                t.start()
            if stop_event is not None:
                stop_event.wait(timeout=self.timeout)
            for t in _threads:
                t.join(timeout=5)

        if pcap_writer is not None:
            try:
                pcap_writer.close()
            except Exception:
                pass

        if not packets:
            logger.warning(
                f"[!] 抓包 0 包 (尝试 {len(ifaces)} 个网卡) — "
                f"Npcap 未安装/驱动异常/权限不足时 scapy 会静默返回 0 包, 已按进程级连接监控兜底"
            )

        traffic = self._analyze_packets(packets, scapy)
        setattr(traffic, 'pcap_path', pcap_path if pcap_created else '')
        return traffic
    def _enumerate_ifaces(self) -> list:
        """枚举有 IPv4 的 Npcap 抓包网卡 (默认路由网卡优先)"""
        try:
            from scapy.all import conf, get_windows_if_list
            default = None
            try:
                _route = conf.route.route('8.8.8.8')
                if _route and _route[0]:
                    default = _route[0]
            except Exception:
                pass
            result = []
            try:
                iflist = get_windows_if_list()
                for if_ in iflist:
                    name = if_.get('name', '')
                    ips = [str(x) for x in (if_.get('ips', []) or [])]
                    if not ips:
                        continue
                    if name.lower().startswith('lo'):
                        continue
                    result.append(name)
            except Exception:
                pass
            # 默认路由网卡优先
            if default:
                if default in result:
                    result.remove(default)
                result.insert(0, default)
            return result
        except Exception:
            return []

    def _capture_with_psutil(self, stop_event: threading.Event = None) -> NetworkTraffic:
        """使用 psutil 监控网络连接（可按 PID 过滤）"""
        connections = []
        start_time = time.time()

        # 收集要监控的 PID（目标进程 + 所有子进程）
        target_pids = set()
        # 主进程死后窗口兜底的系统进程白名单 (与 sandbox._collect_sample_children 同款)
        _NOISE_PROCESSES = {
            'svchost.exe', 'conhost.exe', 'csrss.exe', 'lsass.exe', 'services.exe',
            'dwm.exe', 'fontdrvhost.exe', 'dllhost.exe', 'wmiprvse.exe',
            'taskhostw.exe', 'searchindexer.exe', 'runtimebroker.exe',
            'securityhealthservice.exe', 'msmpeng.exe', 'audiodg.exe',
            'smss.exe', 'wininit.exe', 'winlogon.exe', 'explorer.exe',
            'sihost.exe', 'shellexperiencehost.exe', 'spoolsv.exe', 'ctfmon.exe',
        }
        if self.target_pid and PSUTIL_AVAILABLE:
            try:
                proc = psutil.Process(self.target_pid)
                target_pids.add(self.target_pid)
                for child in proc.children(recursive=True):
                    target_pids.add(child.pid)
            except psutil.NoSuchProcess:
                pass

        if PSUTIL_AVAILABLE:
            while time.time() - start_time < self.timeout:
                if stop_event and stop_event.is_set():
                    break
                try:
                    # 定期刷新子进程 PID 列表
                    if self.target_pid:
                        try:
                            proc = psutil.Process(self.target_pid)
                            for child in proc.children(recursive=True):
                                target_pids.add(child.pid)
                        except psutil.NoSuchProcess:
                            # 主进程已死: 窗口兜底收集执行期间创建的非系统进程
                            # (孤儿/守护进程 — 否则其外联连接会被 PID 过滤全部漏掉)
                            try:
                                for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
                                    try:
                                        ct = proc.info['create_time']
                                        if not ct or ct < start_time - 5:
                                            continue
                                        name = (proc.info['name'] or '').lower()
                                        if name in _NOISE_PROCESSES:
                                            continue
                                        exe = (proc.info['exe'] or '').lower()
                                        if exe and ('\\windows\\' in exe or '\\program files' in exe):
                                            continue
                                        target_pids.add(proc.info['pid'])
                                    except Exception:
                                        continue
                            except Exception:
                                pass

                    for conn in psutil.net_connections():
                        # PID 过滤：只保留目标进程及其子进程的连接
                        if self.target_pid and conn.pid not in target_pids:
                            continue
                        # TCP 各状态 + UDP (DNS 等) — UDP 的 status 常为 NONE
                        is_udp = getattr(conn, 'type', 0) == socket.SOCK_DGRAM
                        if conn.raddr and (is_udp or conn.status in (
                                'ESTABLISHED', 'SYN_SENT', 'SYN_RECEIVED',
                                'TIME_WAIT', 'CLOSE_WAIT', 'NONE')):
                            connections.append({
                                'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                                'status': conn.status,
                                'pid': conn.pid
                            })
                except:
                    pass
                # 0.25s 轮询 — 秒退/自删样本的毫秒级短连接只有高频轮询才能捕捉
                time.sleep(0.25)

        traffic = self._analyze_connections(connections)
        setattr(traffic, 'pcap_path', '')
        return traffic
    
    def _analyze_packets(self, packets: list, scapy: dict) -> NetworkTraffic:
        """分析数据包"""
        IP = scapy['IP']; TCP = scapy['TCP']; UDP = scapy['UDP']
        DNS = scapy['DNS']; DNSQR = scapy['DNSQR']; Raw = scapy['Raw']
        
        dns_queries = []
        http_requests = []
        tcp_packets = []
        udp_connections = []
        suspicious = []
        tls_fingerprints = []
        dga_domains = []
        dns_tunnel_indicators = []
        protocol_stats = {'TCP': 0, 'UDP': 0, 'DNS': 0, 'HTTP': 0, 'Other': 0}
        
        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
            
            # DNS
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                protocol_stats['DNS'] += 1
                qname = pkt[DNSQR].qname
                if isinstance(qname, (bytes, bytearray)):
                    qname = qname.decode('utf-8', errors='ignore')
                qname = str(qname).rstrip('.')
                qname = '.'.join(
                    part for part in qname.split('.') if part and not (len(part) == 1 and ord(part[0]) < 32)
                )
            
                is_susp = self._is_suspicious_domain(qname)
                qtype_val = pkt[DNSQR].qtype
                _QTYPE_MAP = {1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',255:'ANY'}
                qtype_str = _QTYPE_MAP.get(qtype_val, f'TYPE{qtype_val}')
                dns_queries.append(DNSQuery(
                    domain=qname,
                    query_type=qtype_str,
                    is_suspicious=is_susp,
                    suspicion_reason='Suspicious TLD' if is_susp else ''
                ))
                # DGA / DNS 隧道检测
                if self._is_dga_domain(qname) and qname not in dga_domains:
                    dga_domains.append(qname)
                _tunnel = self._dns_tunnel_indicator(qname)
                if _tunnel:
                    dns_tunnel_indicators.append(_tunnel)
            
            # TCP
            if pkt.haslayer(TCP):
                protocol_stats['TCP'] += 1
                pkt_len = len(pkt)
                # 方向判定: SYN(无ACK)为连接发起方(客户端→本机发出), 其余视为对端返回
                _flags = pkt[TCP].flags
                if isinstance(_flags, int):
                    _outbound = bool(_flags & 0x02) and not bool(_flags & 0x10)
                else:
                    _fs = str(_flags)
                    _outbound = 'S' in _fs and 'A' not in _fs
                tcp_packets.append((NetworkConnection(
                    protocol='TCP',
                    local_addr=pkt[IP].src,
                    local_port=pkt[TCP].sport,
                    remote_addr=pkt[IP].dst,
                    remote_port=pkt[TCP].dport,
                    is_suspicious=pkt[TCP].dport in self.SUSPICIOUS_PORTS,
                    bytes_sent=pkt_len if _outbound else 0,
                    bytes_recv=0 if _outbound else pkt_len,
                ), _outbound))
                
                # HTTP requests only (skip responses like "HTTP/1.1 200 OK")
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    http_methods = [b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS ', b'PATCH ']
                    if any(payload.startswith(m) for m in http_methods):
                        protocol_stats['HTTP'] += 1
                        try:
                            lines = payload.split(b'\r\n')
                            if not lines:
                                continue
                            first = lines[0].decode('utf-8', errors='ignore')
                            parts = first.split()
                            ua = ''
                            for line in lines[1:]:
                                try:
                                    line_str = line.decode('utf-8', errors='ignore')
                                    if line_str.lower().startswith('user-agent:'):
                                        ua = line_str.split(':', 1)[1].strip()[:200]
                                        break
                                except:
                                    pass
                            # parts = [METHOD, PATH, VERSION]
                            if len(parts) >= 2:
                                host = ''
                                for line in lines[1:]:
                                    try:
                                        line_str = line.decode('utf-8', errors='ignore')
                                        if line_str.lower().startswith('host:'):
                                            host = line_str.split(':', 1)[1].strip()[:200]
                                            break
                                    except:
                                        pass
                                http_requests.append(HTTPRequest(
                                    method=parts[0],
                                    host=host or pkt[IP].dst,
                                    path=parts[1],
                                    user_agent=ua
                                ))
                        except:
                            pass
                    # TLS 握手指纹 (JA3/JA3S/SNI)
                    elif payload[:1] == b'\x16':
                        try:
                            from analyzer.tls_fingerprint import extract_tls_fingerprints
                            fp = extract_tls_fingerprints(payload)
                            if fp and fp not in tls_fingerprints:
                                fp = dict(fp)
                                fp['src'] = f'{pkt[IP].src}:{pkt[TCP].sport}'
                                fp['dst'] = f'{pkt[IP].dst}:{pkt[TCP].dport}'
                                tls_fingerprints.append(fp)
                        except Exception:
                            pass
            
            # UDP
            if pkt.haslayer(UDP):
                protocol_stats['UDP'] += 1
                udp_connections.append(NetworkConnection(
                    protocol='UDP',
                    local_addr=pkt[IP].src,
                    local_port=pkt[UDP].sport,
                    remote_addr=pkt[IP].dst,
                    remote_port=pkt[UDP].dport
                ))
        
        # 聚合 TCP 连接：按双向流 (src:sport ↔ dst:dport) 去重 + 累计字节
        # ⚠ 旧逻辑只按 (remote_addr, remote_port) 去重: 回程包方向相反,
        # 会把“本机地址+临时端口”当成新的远端节点 — 交互式网络图因此被
        # 192.168.x.x:50xxx 这类本机端点刷屏, 且同一连接被画成两个节点。
        flow_map = {}
        for conn, is_outbound in tcp_packets:
            a = (conn.local_addr, conn.local_port)
            b = (conn.remote_addr, conn.remote_port)
            key = tuple(sorted([a, b]))
            entry = flow_map.get(key)
            if entry is None:
                entry = {
                    'local': a if is_outbound else b,
                    'remote': b if is_outbound else a,
                    'bytes_sent': 0,
                    'bytes_recv': 0,
                    'outbound_seen': bool(is_outbound),
                }
                flow_map[key] = entry
            elif is_outbound and not entry['outbound_seen']:
                # 先看到回程包、后看到出站 SYN 时, 校正本机/远端方向
                entry['local'] = a
                entry['remote'] = b
                entry['outbound_seen'] = True
            # conn.bytes_sent / bytes_recv 只是“按 SYN 方向”记在其中一个字段,
            # 二者之和即本包长度; 这里改用“源 == 本机”重算方向, 数据包(PSH+ACK)
            # 从本机发出时也应计入 bytes_sent。
            packet_total = conn.bytes_sent + conn.bytes_recv
            if a == entry['local']:
                entry['bytes_sent'] += packet_total
            else:
                entry['bytes_recv'] += packet_total

        tcp_aggregated = [
            NetworkConnection(
                protocol='TCP',
                local_addr=e['local'][0],
                local_port=e['local'][1],
                remote_addr=e['remote'][0],
                remote_port=e['remote'][1],
                bytes_sent=e['bytes_sent'],
                bytes_recv=e['bytes_recv'],
                is_suspicious=e['remote'][1] in self.SUSPICIOUS_PORTS,
            )
            for e in flow_map.values()
        ]
        tcp_aggregated.sort(key=lambda c: (c.remote_addr, c.remote_port))

        # 检测可疑流量
        for conn in tcp_aggregated:
            if conn.remote_port in self.SUSPICIOUS_PORTS:
                suspicious.append({
                    'type': 'suspicious_port',
                    'remote': f"{conn.remote_addr}:{conn.remote_port}",
                    'reason': f'连接到可疑端口 {conn.remote_port}'
                })

        total_bytes = sum(c.bytes_sent + c.bytes_recv for c in tcp_aggregated)

        return NetworkTraffic(
            total_packets=len(packets),
            total_bytes=total_bytes,
            dns_queries=dns_queries[:50],
            http_requests=http_requests[:50],
            tcp_connections=tcp_aggregated[:50],
            udp_connections=udp_connections[:50],
            suspicious_traffic=suspicious[:20],
            protocol_stats=protocol_stats,
            tor_nodes=self._detect_tor_nodes([c.remote_addr for c in tcp_aggregated]),
            tls_fingerprints=tls_fingerprints[:20],
            dga_domains=dga_domains[:20],
            dns_tunnel_indicators=dns_tunnel_indicators[:20]
        )
    
    @staticmethod
    def _parse_addr_port(raw: str):
        """从 'ip:port' 或 '[ipv6]:port' 或 'ipv6' 中安全提取 (addr, port)"""
        raw = raw.strip()
        if not raw:
            return '', 0
        if raw.startswith('['):
            try:
                addr, rest = raw[1:].split(']', 1)
                port = int(rest.lstrip(':')) if rest.lstrip(':') else 0
                return addr, port
            except (ValueError, IndexError):
                return raw, 0
        # IPv4 或 IPv6 无方括号: 最后一个冒号之后若是纯数字则视为端口
        if ':' in raw:
            # 统计冒号数量: >1 个冒号 = IPv6
            if raw.count(':') > 1:
                addr, tail = raw.rsplit(':', 1)
                if tail.isdigit():
                    return addr, int(tail)
                # 无端口 IPv6: 尝试去掉最后的 %scope-id
                if '%' in tail:
                    addr, _ = raw.rsplit('%', 1)
                    return addr, 0
                return raw, 0
            else:
                # 只有一个冒号: IPv4:port
                addr, tail = raw.rsplit(':', 1)
                if tail.isdigit():
                    return addr, int(tail)
                return raw, 0
        return raw, 0

    def _analyze_connections(self, connections: list) -> NetworkTraffic:
        """分析连接列表（去重 + 合并）"""
        tcp_conns = []
        suspicious = []
        seen = set()

        for conn in connections:
            try:
                local_addr, local_port = self._parse_addr_port(conn.get('local', ''))
                remote_addr, remote_port = self._parse_addr_port(conn.get('remote', ''))
            except Exception:
                continue

            # 去重（同一连接多次轮询只保留一条）
            key = (local_addr, local_port, remote_addr, remote_port)
            if key in seen:
                continue
            seen.add(key)

            tcp_conns.append(NetworkConnection(
                protocol='TCP',
                local_addr=local_addr,
                local_port=local_port,
                remote_addr=remote_addr,
                remote_port=remote_port,
                pid=conn.get('pid', 0),
                status=conn.get('status', '')
            ))

            if remote_port in self.SUSPICIOUS_PORTS:
                suspicious.append({
                    'type': 'suspicious_port',
                    'remote': conn['remote'],
                    'reason': f'连接到可疑端口 {remote_port}'
                })

        # 去重后重新计数
        return NetworkTraffic(
            total_packets=len(seen),
            tcp_connections=tcp_conns,
            suspicious_traffic=suspicious
        )
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """检测可疑域名"""
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return True
        # DGA 特征：长随机域名
        if len(domain) > 20 and domain.count('.') == 1:
            if sum(1 for c in domain if c.isdigit()) > 3:
                return True
        return False
    
    def _detect_dga(self, domains: list) -> bool:
        """检测 DGA 域名"""
        if len(domains) < 5:
            return False
        # 简单检测：大量二级域名具有相似长度和结构
        second_levels = [d.split('.')[0] for d in domains if '.' in d]
        if len(second_levels) < 5:
            return False
        avg_len = sum(len(s) for s in second_levels) / len(second_levels)
        if 10 < avg_len < 20:
            return True
        return False
    
    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """香农熵"""
        import math
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in freq.values())
    
    def _is_dga_domain(self, domain: str) -> bool:
        """单域名 DGA 检测: 高熵 + 元音/辅音比例异常 + 数字占比"""
        try:
            label = domain.split('.')[0]
            if not label or len(label) < 8:
                return False
            # 纯字典词/短域名排除
            vowels = sum(1 for c in label.lower() if c in 'aeiou')
            consonants = sum(1 for c in label.lower() if c.isalpha()) - vowels
            digits = sum(1 for c in label if c.isdigit())
            if consonants == 0:
                return False
            # 元音占比异常低 (随机串通常元音稀疏) 或数字占比高
            v_ratio = vowels / len(label)
            d_ratio = digits / len(label)
            entropy = self._shannon_entropy(label)
            if entropy > 3.2 and (v_ratio < 0.25 or d_ratio > 0.35):
                return True
        except Exception:
            pass
        return False
    
    def _dns_tunnel_indicator(self, domain: str) -> dict:
        """DNS 隧道特征: 超长域名 / 超长单标签 / 高频子域"""
        try:
            labels = [l for l in domain.split('.') if l]
            if not labels:
                return None
            total_len = len(domain)
            max_label = max(len(l) for l in labels)
            # 隧道特征: 域名总长 > 40 且某标签接近 63 上限, 或子域层级异常多
            if total_len >= 40 and max_label >= 30:
                return {'domain': domain, 'reason': f'DNS隧道疑似: 总长{total_len}, 最大标签{max_label}'}
            if len(labels) >= 5 and max_label >= 20:
                return {'domain': domain, 'reason': f'DNS隧道疑似: {len(labels)}层子域, 最大标签{max_label}'}
        except Exception:
            pass
        return None
    
    TOR_EXIT_NODES_CACHE = None
    _CACHE_TIME = 0

    def _detect_tor_nodes(self, ips: list) -> list:
        """检测 Tor 出口节点 — 本地前缀 + 远程下载（1小时缓存）"""
        tor_ips = set()
        if not ips:
            return []

        # 1. 本地已知 Tor 地址段
        tor_prefixes = [
            '185.220.101.', '185.220.100.', '199.249.230.',
            '23.129.64.', '171.25.193.', '185.129.61.',
            '83.97.117.', '192.42.116.', '185.56.82.',
            '104.244.72.', '82.221.131.', '128.31.',
            '193.189.100.', '51.15.', '95.216.',
            '51.75.', '193.70.', '185.220.102.',
            '45.154.98.', '199.58.86.',
        ]

        for ip in ips:
            ip_str = str(ip) if not isinstance(ip, str) else ip
            if any(ip_str.startswith(prefix) for prefix in tor_prefixes):
                tor_ips.add(ip_str)
                continue

        # 2. 远程下载 Tor 出口节点列表（缓存1小时）
        if self.TOR_EXIT_NODES_CACHE is None or time.time() - self._CACHE_TIME > 3600:
            try:
                import urllib.request
                import ssl
                ctx = ssl.create_default_context()
                url = 'https://check.torproject.org/torbulkexitlist'
                req = urllib.request.Request(url, headers={'User-Agent': 'Sandbox/3.2'})
                resp = urllib.request.urlopen(req, context=ctx, timeout=10)
                data = resp.read().decode()
                self.TOR_EXIT_NODES_CACHE = set()
                for line in data.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.TOR_EXIT_NODES_CACHE.add(line)
                self._CACHE_TIME = time.time()
                logger.debug(f"[Tor] 下载了 {len(self.TOR_EXIT_NODES_CACHE)} 个出口节点")
            except Exception:
                if self.TOR_EXIT_NODES_CACHE is None:
                    self.TOR_EXIT_NODES_CACHE = set()

        if self.TOR_EXIT_NODES_CACHE:
            for ip in ips:
                ip_str = str(ip) if not isinstance(ip, str) else ip
                if ip_str in self.TOR_EXIT_NODES_CACHE:
                    tor_ips.add(ip_str)

        return list(tor_ips)

    # ===== User-Agent 分析 =====

    MALICIOUS_UA_PATTERNS = [
        ('Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)', 'CobaltStrike', 'MSIE9 伪装 (常见Beacon)'),
        ('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)', 'CobaltStrike', 'MSIE8 伪装'),
        ('curl/', 'Script', 'curl 命令行下载'),
        ('wget/', 'Script', 'wget 命令行下载'),
        ('python-requests/', 'Script', 'Python requests库'),
        ('Go-http-client/', 'Go', 'Go HTTP 客户端'),
        ('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US)', 'Generic', 'WinXP伪装 (过时)'),
        ('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)', 'Generic', 'MSIE6 伪装 (过时)'),
        ('DiscordBot', 'Discord', 'Discord Bot C2'),
        ('TelegramBot', 'Telegram', 'Telegram Bot C2'),
        ('Mozilla/5.0 (iPhone; CPU iPhone OS', 'Stealer', 'iPhone UA伪装'),
    ]

    @staticmethod
    def analyze_user_agents(http_requests: list) -> Dict:
        """分析 HTTP 请求中的 User-Agent — 多UA检测 + 已知恶意UA匹配"""
        result = {
            'unique_agents': [], 'ua_count': 0, 'unique_count': 0,
            'diverse': False, 'diversity_warning': '',
            'malicious_hits': [], 'suspicious_anomalies': [],
        }
        uas = []
        for req in http_requests:
            ua = getattr(req, 'user_agent', '') or ''
            if ua:
                uas.append(ua)
        if not uas:
            return result

        unique = list(dict.fromkeys(uas))
        result['ua_count'] = len(uas)
        result['unique_count'] = len(unique)
        result['unique_agents'] = unique[:30]

        # 检测1: 多个不同 User-Agent
        if len(unique) >= 3:
            result['diverse'] = True
            result['diversity_warning'] = f"检测到 {len(unique)} 个不同的 User-Agent (共{len(uas)}次请求)"
            result['suspicious_anomalies'].append({
                'type': 'ua_diversity',
                'count': len(unique),
                'reason': f'{len(unique)}种不同UA — 正常应用通常固定UA，多UA是恶意软件特征',
            })

        # 检测2: 已知恶意UA匹配
        for pattern, family, desc in NetworkAnalyzer.MALICIOUS_UA_PATTERNS:
            for ua in unique:
                if pattern.lower() in ua.lower():
                    result['malicious_hits'].append({
                        'user_agent': ua[:150], 'family': family, 'description': desc,
                    })
                    break

        # 检测3: UA缺失
        empty_count = sum(1 for req in http_requests if not getattr(req, 'user_agent', ''))
        if empty_count > 0:
            result['suspicious_anomalies'].append({
                'type': 'ua_missing',
                'count': empty_count,
                'reason': f'{empty_count}次HTTP请求无UA头（正常浏览器必带UA）',
            })

        # 检测4: UA过短
        short_uas = [ua for ua in unique if 0 < len(ua) < 30]
        if short_uas:
            result['suspicious_anomalies'].append({
                'type': 'ua_short',
                'count': len(short_uas),
                'reason': f'{len(short_uas)}个UA过短(<30字符): {"/".join(short_uas[:5])[:120]}',
            })

        # 检测5: 格式异常（无括号）
        malformed = [ua for ua in unique if '(' not in ua and '/' in ua and len(ua) > 10]
        if malformed:
            result['suspicious_anomalies'].append({
                'type': 'ua_malformed',
                'count': len(malformed),
                'reason': f'{len(malformed)}个UA格式异常（缺少标准括号语法）',
            })

        return result

    # ===== C2 通信深度分析 — 可疑连接评分 =====

    # 常见合法端口：命中这些端口的连接不因端口本身扣分
    COMMON_PORTS = {80, 443, 53, 8080, 8443, 21, 22, 25, 110, 143, 465, 587, 993, 995, 3306}

    # 已知 CDN/云/合法服务 IP 前缀（降低误报）— 仅做前缀粗匹配
    KNOWN_BENIGN_PREFIXES = [
        # Microsoft / Azure
        '13.107.', '13.64.', '20.36.', '20.40.', '20.42.', '20.43.', '20.44.',
        '20.48.', '20.49.', '20.50.', '20.52.', '20.53.', '20.54.', '20.60.',
        '23.96.', '40.76.', '40.77.', '40.78.', '40.79.', '40.80.', '40.81.',
        '40.82.', '40.83.', '40.84.', '40.85.', '40.86.', '40.87.', '40.88.',
        '40.89.', '40.90.', '40.91.', '40.92.', '40.93.', '40.94.', '40.95.',
        '40.96.', '40.97.', '40.98.', '40.99.', '40.100.', '40.101.', '40.102.',
        '40.103.', '40.104.', '40.105.', '40.106.', '40.107.', '40.108.', '40.109.',
        '40.110.', '40.111.', '40.112.', '40.113.', '40.114.', '40.115.', '40.116.',
        '40.117.', '40.118.', '40.119.', '40.120.', '40.121.', '40.122.', '40.123.',
        '40.124.', '40.125.', '40.126.', '40.127.', '52.96.', '52.97.', '52.98.',
        '52.99.', '52.100.', '52.101.', '52.102.', '52.103.', '52.104.', '52.105.',
        '52.106.', '52.107.', '52.108.', '52.109.', '52.110.', '52.111.', '52.112.',
        '52.113.', '52.114.', '52.115.', '52.116.', '52.117.', '52.118.', '52.119.',
        '52.120.', '52.121.', '52.122.', '52.123.', '52.124.', '52.125.', '52.126.',
        '52.127.', '52.128.', '52.129.', '52.130.', '52.131.', '52.132.', '52.133.',
        '52.134.', '52.135.', '52.136.', '52.137.', '52.138.', '52.139.', '52.140.',
        '52.141.', '52.142.', '52.143.', '52.144.', '52.145.', '52.146.', '52.147.',
        '52.148.', '52.149.', '52.150.', '52.151.', '52.152.', '52.153.', '52.154.',
        '52.155.', '52.156.', '52.157.', '52.158.', '52.159.', '52.160.', '52.161.',
        '52.162.', '52.163.', '52.164.', '52.165.', '52.166.', '52.167.', '52.168.',
        '52.169.', '52.170.', '52.171.', '52.172.', '52.173.', '52.174.', '52.175.',
        '52.176.', '52.177.', '52.178.', '52.179.', '52.180.', '52.181.', '52.182.',
        '52.183.', '52.184.', '52.185.', '52.186.', '52.187.', '52.188.', '52.189.',
        '52.190.', '52.191.', '52.192.', '52.193.', '52.194.', '52.195.', '52.196.',
        '52.197.', '52.198.', '52.199.', '52.200.', '52.201.', '52.202.', '52.203.',
        '52.204.', '52.205.', '52.206.', '52.207.', '52.208.', '52.209.', '52.210.',
        '52.211.', '52.212.', '52.213.', '52.214.', '52.215.', '52.216.', '52.217.',
        '52.218.', '52.219.', '52.220.', '52.221.', '52.222.', '52.223.', '52.224.',
        '52.225.', '52.226.', '52.227.', '52.228.', '52.229.', '52.230.', '52.231.',
        '52.232.', '52.233.', '52.234.', '52.235.', '52.236.', '52.237.', '52.238.',
        '52.239.', '52.240.', '52.241.', '52.242.', '52.243.', '52.244.', '52.245.',
        '52.246.', '52.247.', '52.248.', '52.249.', '52.250.', '52.251.', '52.252.',
        '52.253.', '52.254.', '52.255.',
        # Google
        '142.250.', '142.251.', '172.217.', '173.194.', '216.58.', '74.125.',
        '34.102.', '35.190.', '35.191.', '35.201.', '35.227.', '35.241.',
        # Cloudflare
        '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.',
        '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.',
        '104.28.', '104.29.', '104.30.', '104.31.', '172.64.', '172.65.',
        '172.66.', '172.67.', '172.68.', '172.69.', '172.70.', '172.71.',
        # AWS
        '3.5.', '3.6.', '3.7.', '3.8.', '3.9.', '3.10.', '3.11.', '3.12.',
        '13.32.', '13.33.', '13.34.', '13.35.', '18.64.', '18.65.', '18.66.',
        '18.67.', '18.130.', '18.131.', '18.132.', '18.133.', '18.134.',
        '18.135.', '18.136.', '18.137.', '18.138.', '18.139.', '18.140.',
        '18.141.', '18.142.', '18.143.', '18.144.', '18.145.', '18.146.',
        '18.147.', '18.148.', '18.149.', '18.150.', '18.151.', '18.152.',
        '18.153.', '18.154.', '18.155.', '18.156.', '18.157.', '18.158.',
        '18.159.', '18.160.', '18.161.', '18.162.', '18.163.', '18.164.',
        '18.165.', '18.166.', '18.167.', '18.168.', '18.169.', '18.170.',
        '18.171.', '18.172.', '18.173.', '18.174.', '18.175.', '18.176.',
        '18.177.', '18.178.', '18.179.', '18.180.', '18.181.', '18.182.',
        '18.183.', '18.184.', '18.185.', '18.186.', '18.187.', '18.188.',
        '18.189.', '18.190.', '18.191.', '18.192.', '18.193.', '18.194.',
        '18.195.', '18.196.', '18.197.', '18.198.', '18.199.', '18.200.',
        '18.201.', '18.202.', '18.203.', '18.204.', '18.205.', '18.206.',
        '18.207.', '18.208.', '18.209.', '18.210.', '18.211.', '18.212.',
        '18.213.', '18.214.', '18.215.', '18.216.', '18.217.', '18.218.',
        '18.219.', '18.220.', '18.221.', '18.222.', '18.223.', '18.224.',
        '18.225.', '18.226.', '18.227.', '18.228.', '18.229.', '18.230.',
        '18.231.', '18.232.', '18.233.', '18.234.', '18.235.', '18.236.',
        '18.237.', '18.238.', '18.239.', '18.240.', '18.241.', '18.242.',
        '18.243.', '18.244.', '18.245.', '18.246.', '18.247.', '18.248.',
        '18.249.', '18.250.', '18.251.', '18.252.', '18.253.', '18.254.',
        # Akamai / Fastly / GitHub
        '23.32.', '23.33.', '23.34.', '23.35.', '23.36.', '23.37.', '23.38.',
        '23.39.', '23.40.', '23.41.', '23.42.', '23.43.', '23.44.', '23.45.',
        '23.46.', '23.47.', '23.48.', '23.49.', '23.50.', '23.51.', '23.52.',
        '23.53.', '23.54.', '23.55.', '23.56.', '23.57.', '23.58.', '23.59.',
        '23.60.', '23.61.', '23.62.', '23.63.', '151.101.', '185.199.',
        '140.82.',
    ]

    @staticmethod
    def _is_public_ip(addr: str) -> bool:
        try:
            import ipaddress
            ip = ipaddress.ip_address(addr.strip())
            return not (ip.is_private or ip.is_loopback or ip.is_link_local
                        or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
        except Exception:
            return False

    @classmethod
    def _is_known_benign(cls, addr: str) -> bool:
        addr = addr.strip()
        return any(addr.startswith(p) for p in cls.KNOWN_BENIGN_PREFIXES)

    @classmethod
    def analyze_c2_candidates(cls, traffic) -> list:
        """可疑连接评分 — 非标准端口 + 非白名单公网 IP = 高危 C2 候选

        返回: [{remote, port, score, level, reasons, is_c2}]
        """
        candidates = []
        if traffic is None:
            return candidates

        dns_domains = [d.domain for d in (traffic.dns_queries or [])]

        def _domain_for(addr):
            for d in (traffic.dns_queries or []):
                if addr in (d.resolved_ips or []):
                    return d.domain
            return ''

        seen = set()
        for conn in (traffic.tcp_connections or []) + (traffic.udp_connections or []):
            remote = getattr(conn, 'remote_addr', '')
            port = getattr(conn, 'remote_port', 0)
            if not remote or not port:
                continue
            key = (remote, port)
            if key in seen:
                continue
            seen.add(key)

            # 只评分公网 IP（内网地址不可能是 C2）
            if not cls._is_public_ip(remote):
                continue

            score = 0
            reasons = []

            # 1. 非标准端口
            if port not in cls.COMMON_PORTS:
                score += 2
                reasons.append(f'非标准端口 {port}')

            # 2. 命中已知可疑端口
            if port in cls.SUSPICIOUS_PORTS:
                score += 3
                reasons.append(f'已知恶意端口 {port}')

            # 3. 非白名单公网 IP
            if not cls._is_known_benign(remote):
                score += 2
                reasons.append(f'非白名单公网 IP {remote}')

            # 4. 无对应 DNS 查询（直连 IP，规避域名信誉）
            domain = _domain_for(remote)
            if not domain:
                score += 2
                reasons.append('直连 IP（无 DNS 解析记录）')
            else:
                for tld in cls.SUSPICIOUS_TLDS:
                    if domain.endswith(tld):
                        score += 2
                        reasons.append(f'可疑 TLD 域名 {domain}')
                        break

            # 5. 出站字节量异常（上行大 = 数据外泄特征）
            if getattr(conn, 'bytes_sent', 0) > 0 and getattr(conn, 'bytes_recv', 0) == 0:
                score += 1
                reasons.append('仅出站单向流量（外泄特征）')

            if score <= 0:
                continue

            if score >= 7:
                level = 'high'
                is_c2 = True
            elif score >= 4:
                level = 'medium'
                is_c2 = score >= 6
            else:
                level = 'low'
                is_c2 = False

            candidates.append({
                'remote': remote,
                'port': port,
                'domain': domain,
                'score': score,
                'level': level,
                'is_c2': is_c2,
                'reasons': reasons,
            })

        candidates.sort(key=lambda c: c['score'], reverse=True)
        return candidates[:20]
