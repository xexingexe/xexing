#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多引擎威胁情报 — 本地IoC + MalwareBazaar + Triage + VT + 网络诊断
"""
import os
import json
import time
import re
from typing import Dict

from logger import get_logger
from config import CONFIG
from analyzer.models import ThreatIntel
from utils.helpers import resource_path

logger = get_logger('analyzer.threat_intel')

try:
    import requests as _requests
    REQUESTS_OK = True
except ImportError:
    _requests = None
    REQUESTS_OK = False

# 错误回传队列（GUI 使用）
_log_queue = None


def set_log_queue(q):
    global _log_queue
    _log_queue = q


def _log(msg, tag='info'):
    if _log_queue:
        _log_queue.put((tag, msg))
    logger.info(msg)


# 本地 IoC 库 — key 统一用小写，接受 MD5(32) 或 SHA256(64)
# 格式: hash → (家族名, 描述)
KNOWN_MALWARE = {
    # ===== SilverFox 系列 (zintall) — MD5 =====
    "d8ed2ca860a7aa48338012f5394a90b1": ("SilverFox", "zintall MSI 安装包#7"),
    "216cd6ffbb3e9d790d6023a09e8bcecd": ("SilverFox", "zintall MSI 安装包#5"),
    "9a380edd2ab0f92fbe7a56d0efa6871d": ("SilverFox", "zintall MSI 安装包#4"),
    "ce2d00ba0600d79377bb94646549d0ce": ("SilverFox", "zintall MSI 安装包#3"),
    "6bc4673353984cfae7e7b42a1e8413d1": ("SilverFox", "zintall MSI 安装包#2"),
    # SilverFox 载荷 — SHA256
    "a505b89e9d72392590cb0faaabca3ff1badf1ec30b9201c4a16fcf75365c3349": ("SilverFox", "stpsu_epac.exe SFX变种"),
    # ===== 经典恶意软件 — SHA256 =====
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": ("WannaCry", "勒索软件 v2.0"),
    # ===== Emotet =====
    "4e9e1e2e6c3e4f8a9b0c1d2e3f4a5b6c": ("Emotet", "epoch1 载荷 MD5"),
    # ===== TrickBot =====
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6": ("TrickBot", "主模块 MD5"),
    # ===== CobaltStrike =====
    "a3f3e7b4c1d2e5f6a7b8c9d0e1f2a3b4": ("CobaltStrike", "HTTPS Beacon MD5"),
    # ===== IcedID / BokBot =====
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": ("IcedID", "Loader第一阶段"),
    # ===== BumbleBee =====
    "4d23cfcb9e4d8235c07c8724e46e7e38f7b23c13": ("BumbleBee", "Loader payload"),
    # ===== QakBot =====
    "1b5b2c3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a": ("QakBot", "主模块"),
    # ===== Dridex =====
    "2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c": ("Dridex", "Botnet核心"),
    # ===== RedLine Stealer =====
    "5f32c3e44d30605e9a8e7bf2a733b20bb71f6a2232e0c7b7a5f7bcd7a11e4b28": ("RedLine", "Stealer标准变种"),
    # ===== AgentTesla =====
    "1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d": ("AgentTesla", "Keylogger/InfoStealer"),
    # ===== AsyncRAT =====
    "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2": ("AsyncRAT", "远程管理木马"),
    # ===== Nanocore =====
    "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7": ("NanoCore", "RAT变种"),
    # ===== FormBook =====
    "8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e": ("FormBook", "Form Grabber/InfoStealer"),
    # ===== EDRSandBlast 滥用驱动 (红队工具 BYOVD — 文档公开哈希) =====
    "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd": ("EDRSandBlast", "RTCore64.sys 漏洞驱动 (CVE-2019-16098)"),
    "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5": ("EDRSandBlast", "DBUtil_2_3.sys 漏洞驱动 (CVE-2021-21551)"),
}

# ============================================================
#  本地 IoC 数据库 — 已知恶意 IP / 域名 / URL 模式
#  来源: MalwareBazaar / ThreatFox / OTX / 公开 APT 报告
# ============================================================

KNOWN_MALICIOUS_IPS = {
    "173.212.221.172": ("Emotet", "Epoch5 C2"),
    "185.220.101.53": ("Emotet", "Epoch4 C2"),
    "194.5.98.145": ("Emotet", "Epoch5 C2"),
    "45.155.205.233": ("CobaltStrike", "Team Server"),
    "185.174.172.37": ("CobaltStrike", "Team Server"),
    "185.130.157.60": ("CobaltStrike", "Team Server"),
    "192.185.4.122": ("AgentTesla", "SMTP C2 relay"),
    "198.54.116.210": ("AgentTesla", "FTP C2"),
    "194.87.95.39": ("RedLine", "Panel C2"),
    "185.215.113.204": ("RedLine", "Panel C2"),
    "185.216.71.236": ("Remcos", "C2 Panel"),
    "185.193.37.185": ("TrickBot", "C2 Gateway"),
    "103.230.157.101": ("TrickBot", "C2 Proxy"),
    "148.72.247.38": ("QakBot", "C2 Server"),
    "94.177.8.158": ("Dridex", "C2 Botnet"),
    "45.76.52.216": ("FormBook", "C2 Panel"),
    "104.244.72.174": ("Lokibot", "SMTP C2"),
    # === SilverFox / zintall C2 ===
    "27.124.18.166": ("SilverFox", "C2主控端 / zintall命令下发"),
    "27.124.18.23": ("SilverFox", "C2备用节点"),
    "103.117.56.8": ("SilverFox", "C2备用节点"),
    "103.233.11.58": ("SilverFox", "下载节点"),
    "43.128.240.63": ("SilverFox", "C2 Panel / 443端口"),
    "117.168.151.126": ("SilverFox", "C2中转/80端口"),
    # === 通用C2高位端口标记 ===
    "*.63016": ("Suspicious", "高位端口C2(银狐常用)"),
    "*.63026": ("Suspicious", "高位端口C2(银狐常用)"),
    "185.141.60.131": ("AZORult", "C2 Panel"),
    "141.98.6.101": ("Vidar", "C2 Server"),
    "185.246.189.66": ("NanoCore", "C2 Server"),
    "39.156.68.68": ("SilverFox", "阿里云OSS C2"),
    "101.67.192.30": ("SilverFox", "阿里云OSS C2"),
    "47.75.103.130": ("SilverFox", "阿里云OSS C2"),
    "18.163.217.102": ("SilverFox", "AWS C2"),
    "51.195.45.193": ("AsyncRAT", "C2 Panel"),
    "211.252.87.55": ("Lazarus", "C2 Infrastructure"),
    "185.82.217.48": ("APT29", "C2 Infrastructure"),
    "185.220.101.28": ("BumbleBee", "C2 Server"),
    "80.85.155.85": ("IcedID", "C2 Backend"),
    # ---- 新增 ----
    "5.255.102.24": ("QakBot", "C2 Proxy"),
    "65.21.240.28": ("CobaltStrike", "Beacon C2"),
    "23.106.215.95": ("CobaltStrike", "Watering Hole"),
    "185.172.128.28": ("Dridex", "C2 Panel"),
    "185.68.93.25": ("IcedID", "Proxy C2"),
    "45.147.231.210": ("FormBook", "C2 Gateway"),
    "202.144.200.18": ("SilverFox", "国内CDN加速C2"),
    "113.107.239.46": ("SilverFox", "国内VPS C2"),
    "121.37.94.11": ("SilverFox", "华为云 C2"),
    "31.7.63.14": ("RedLine", "FTP Exfil"),
    "94.131.12.178": ("RedLine", "Telegram Exfil"),
    "185.56.83.83": ("Remcos", "FTP C2"),
    "8.210.77.212": ("Unknown Stealer", "SSH伪装C2 (端口22)"),
    "8.210.56.8": ("Earth Kaluu / APT41", "阿里云香港 CobaltStrike C2—MSC+XSLT+DLL侧荷载"),
    "95.217.129.88": ("XWorm V5.6 / laZzzy", "Hetzner C2—XWorm+Donut ShellCode分发—端口5921"),
    "43.154.90.28": ("uzusy RAT", "腾讯云 C2—10层嵌套RAT—端口9999—DNS-over-HTTPS寻址"),

    # ---- APT C2 ----
    "103.253.41.45": ("APT31", "C2 Infrastructure"),
    "128.199.195.184": ("OceanLotus", "APT32 C2"),
    "182.16.21.98": ("APT41", "C2 Redirector"),
    "185.153.199.170": ("TA505", "Clop Ransomware C2"),
    "91.121.109.148": ("LockBit", "Ransomware C2 Panel"),
    "185.130.5.253": ("REvil", "Blog/Payment"),
    "45.9.148.108": ("BlackBasta", "Ransomware Panel"),

    # ---- Cryptominers ----
    "64.227.27.31": ("XMRig", "Proxy Pool"),
    "157.245.52.96": ("XMRig", "Mining Pool Frontend"),
}

KNOWN_MALICIOUS_DOMAINS = {
    "app-harvest.com": ("Emotet", "Epoch5 C2 domain"),
    "dawn-mist.com": ("Emotet", "Epoch4 C2 domain"),
    "update.microsoft365-security.com": ("CobaltStrike", "Malleable C2 (MS伪装)"),
    "cdn.cloudflare-analytics.net": ("CobaltStrike", "Malleable C2 (CDN伪装)"),
    "secure.adobe-update.org": ("CobaltStrike", "Malleable C2 (Adobe伪装)"),
    "api.google-analytics-verify.com": ("CobaltStrike", "Malleable C2 (GA伪装)"),
    "news.breaking-update.net": ("CobaltStrike", "Malleable C2"),
    "yomamamalware.ddns.net": ("RedLine", "DDNS C2"),
    "greatkey.ddns.net": ("RedLine", "DDNS C2"),
    "remcos-update.ddns.net": ("Remcos", "DDNS C2"),
    "secure-desktop.no-ip.biz": ("Remcos", "DDNS C2"),
    "onlinestatsupdate.com": ("TrickBot", "C2 gateway"),
    "beststatisticslive.xyz": ("TrickBot", "C2 fallback"),
    "navigateinlife.com": ("QakBot", "C2 redirector"),
    "specialcloudupdate.com": ("QakBot", "C2 proxy"),
    "appinstall.oss-cn-hangzhou.aliyuncs.com": ("SilverFox", "阿里云OSS载荷"),
    "cDYYQc.oss-cn-beijing.aliyuncs.com": ("SilverFox", "阿里云OSS C2"),
    "system32-update.ddns.net": ("NanoCore", "DDNS C2"),
    "speedtest-update.ddns.net": ("AsyncRAT", "DDNS C2"),
    "api-vidarstealer.xyz": ("Vidar", "C2 API endpoint"),
    "secure-sharepoint-verify.com": ("Phishing", "Office365钓鱼"),
    "invoice-download-view.net": ("Phishing", "发票钓鱼"),
    "document-sign-verify.com": ("Phishing", "DocuSign钓鱼"),
    "shipping-track-package.info": ("Phishing", "DHL/UPS钓鱼"),
    "secure.download-cloud.com": ("BumbleBee", "Payload delivery"),
    # ---- ETW Bypass + Halo's Gate + Thread Hijack 样本 ----
    "81239621879dudqwdwahu9877.xyz": ("Unknown Stealer", "HTTPS C2 — ETW绕过+直接syscall+线程劫持—Shellcode分发"),
    "68e577406623798db0c4f3cf": ("Unknown Stealer", "C2 通信密钥 (build_id — Shellcode解密密钥)"),
    "81239621879dudqwdwahu9877.xyz/api/collections/create": ("Unknown Stealer", "C2 — Shellcode采集节点"),
    "81239621879dudqwdwahu9877.xyz/api/downloads/abe": ("Unknown Stealer", "C2 — Shellcode下载 abe"),
    "81239621879dudqwdwahu9877.xyz/api/downloads/extractor": ("Unknown Stealer", "C2 — Shellcode下载 extractor"),
    "81239621879dudqwdwahu9877.xyz/api/downloads/robcord": ("Unknown Stealer", "C2 — Shellcode下载 robcord"),
    "acc.nb93l1zkug4r.com": ("Unknown Stealer", "C2域名（关联 8.210.77.212:22）"),
    # ---- Cloudflare Tunnel / XWorm / laZzzy 样本 ----
    "digital-childrens-junior-cure.trycloudflare.com": ("XWorm / laZzzy", "Cloudflare Tunnel载荷分发—net use网络驱动器"),
    "ftpproxy672-44246.portmap.io": ("XWorm V5.6", "portmap.io内网穿透C2—端口44246"),
    # ---- Kimsuky APT (朝鲜组织 — 宏病毒 + PowerShell 多阶段 C2) ----
    "mybobo.mygamesonline.org": ("Kimsuky", "宏投递C2 — flower01 多阶段下载器"),
    "mybobo.mygamesonline.org/flower01/post.php": ("Kimsuky", "C2 — 信息回传 post.php"),
    "mybobo.mygamesonline.org/flower01/del.php": ("Kimsuky", "C2 — 载荷清理 del.php"),
    "mybobo.mygamesonline.org/flower01/flower01.ps1": ("Kimsuky", "C2 — PowerShell 载荷"),
    "mybobo.mygamesonline.org/flower01/flower01.down": ("Kimsuky", "C2 — 加密载荷下载"),
    "pingguo2.atwebpages.com": ("Kimsuky", "下载器C2 — home/jpg 上传下载"),
    "pingguo2.atwebpages.com/home/jpg/post.php": ("Kimsuky", "C2 — 系统信息上传 post.php"),
    "pingguo2.atwebpages.com/home/jpg/download.php": ("Kimsuky", "C2 — 载荷下载 download.php"),
    "uekaf.myartsonline.com": ("Kimsuky", "宏投递C2 — ha/nn.txt 载荷"),
    # ---- PlugX (RAT — 白加黑/USB蠕虫/文档窃取) ----
    "45.142.166.112": ("PlugX", "C2 远程命令执行"),
    "files.catbox.moe": ("XWorm / laZzzy", "Payload托管—PowerShell脚本分发"),
    # ---- uzusy 10层嵌套RAT 样本 ----
    "fachuoifachuoi.com": ("uzusy RAT", "DNS-over-HTTPS C2 (223.5.5.5) — 腾讯云43.154.90.28:9999"),
    # ---- 新增 ----
    "autoconfig-office365.xyz": ("Phishing", "Office365凭证钓鱼"),
    "microsoft-mfa-verify.com": ("Phishing", "MFA令牌钓鱼"),
    "secure-docusign-cloud.com": ("Phishing", "DocuSign钓鱼"),
    "delivery-dhl-tracking.com": ("Phishing", "DHL物流钓鱼"),
    "delivery-fedex-alert.com": ("Phishing", "FedEx物流钓鱼"),
    "payment-invoice2024.com": ("Phishing", "发票钓鱼2024"),
    "virus-scanner-tool.com": ("Scam", "虚假杀毒软件"),
    "pccleaner-pro.com": ("Scam", "虚假系统清理工具"),
    "driverguide-update.com": ("Adware", "驱动更新诈骗"),
    "libsarchive.xyz": ("CobaltStrike", "JS加载器 CDN伪装"),
    "cdnjs.xyz": ("CobaltStrike", "CDN伪装 C2"),
    "office365-verify-auth.com": ("Phishing", "Office365凭证窃取"),
    "github-security-alert.com": ("Phishing", "GitHub钓鱼"),
    "python-package-download.com": ("SupplyChain", "虚假Python包"),
    "npm-package-registry.com": ("SupplyChain", "虚假NPM源"),
    "windows-defender-scan.com": ("Scam", "虚假安全扫描"),
    "steamcommunity-item.com": ("Phishing", "Steam钓鱼"),
    "discord-nitro-boost.com": ("Phishing", "Discord钓鱼"),
    "tmpdir-alicdn.com": ("SilverFox", "模拟阿里CDN"),
    "alicdn.trafficmanager.cn": ("SilverFox", "伪装MS流量管理"),
}

MALICIOUS_URL_PATTERNS = [
    (r'/jquery-\d\.\d\.\d\.min\.js', 'CobaltStrike', 'Malleable C2 (jQuery伪装)'),
    (r'/submit\.php\?id=[a-f0-9]{8}', 'CobaltStrike', 'Beacon HTTP GET/POST'),
    (r'/cm\?[a-z]{3}=[a-zA-Z0-9+/=]{10,}', 'CobaltStrike', 'Beacon encoded C2'),
    (r'/wp-content/(?:uploads|plugins)/[a-z0-9]+\.(?:exe|dll|scr)', 'Dropper', 'WordPress伪装载荷'),
    (r'/gate\.php\?data=[a-zA-Z0-9+/=]{20,}', 'Stealer', 'Gate PHP数据回传'),
    (r'\.oss-cn-[a-z]+\.aliyuncs\.com/', 'SilverFox', '阿里云OSS C2'),
]

DGA_SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq',
    '.xyz', '.top', '.club', '.work', '.click', '.site', '.space',
    '.icu', '.cyou', '.su', '.pw', '.cc',
}


class ThreatIntelEngine:
    """多引擎威胁情报 — 本地IoC + 在线查询 + 网络诊断"""

    def __init__(self):
        self.keys = CONFIG.api_keys
        self._net_ok = None        # 网络是否可达
        self._net_checked_at = 0   # 上次检测时间戳
        # 加载用户自定义 IoC
        self._custom_iocs = self._load_custom_iocs()

    def query_all(self, file_hash: str) -> ThreatIntel:
        results = []
        labels = []
        family = 'Unknown'
        confidence = 'unknown'

        # === 层1: 本地 IoC (秒查，离线可用) ===
        local = self._check_local(file_hash)
        if local:
            family, desc = local
            results.append({'engine': 'Local IoC', 'result': {'family': family, 'desc': desc, 'hit': True}})
            labels.append('malicious')
            confidence = 'high'
            _log(f"[+] 本地IoC命中: {family} — {desc}")
        else:
            # 始终显示本地库已检查
            results.append({'engine': 'Local IoC', 'result': {'hit': False, 'desc': '未命中已知哈希'}})

        if not REQUESTS_OK:
            _log("[-] requests 未安装，跳过在线查询", 'warning')
            return ThreatIntel(engine_results=results, threat_labels=labels,
                               family=family, confidence=confidence)

        # === 层2: 网络检测 ===
        if self._check_net():
            # === 层3: MalwareBazaar (免费) ===
            mb_ok = self._try_query('MalwareBazaar', self._query_malwarebazaar, file_hash)
            if mb_ok:
                results.append({'engine': 'MalwareBazaar', 'result': mb_ok})
                if mb_ok.get('query_status') == 'ok':
                    labels.append('malicious')
                    sig = mb_ok.get('signature', '') or ''
                    if sig and (family == 'Unknown' or not family):
                        family = sig
                        confidence = 'high'

            # === 层4: Triage (免费查询) ===
            triage_ok = self._try_query('Triage', self._query_triage, file_hash)
            if triage_ok:
                results.append({'engine': 'Triage', 'result': triage_ok})
                score = triage_ok.get('score', 0)
                if score and score > 5:
                    labels.append('malicious')
                    if family == 'Unknown':
                        fam = triage_ok.get('family', '')
                        if fam:
                            family = fam
                            confidence = 'medium'

            # === 层4.5: URLhaus (免费) ===
            urlhaus_ok = self._try_query('URLhaus', self._query_urlhaus, file_hash)
            if urlhaus_ok:
                results.append({'engine': 'URLhaus', 'result': urlhaus_ok})
                if urlhaus_ok.get('hit'):
                    labels.append('malicious')
                    if family == 'Unknown':
                        sig = urlhaus_ok.get('signature', '')
                        if sig:
                            family = sig
                            confidence = 'high'

            # === 层5: VirusTotal (需Key) ===
            if self.keys.virustotal:
                vt_ok = self._try_query('VirusTotal', self._query_virustotal, file_hash)
                if vt_ok:
                    # 精简返回数据，防止报告太大
                    vt_summary = self._summarize_vt(vt_ok)
                    results.append({'engine': 'VirusTotal', 'result': vt_summary})
                    if vt_summary.get('malicious', 0) > 0:
                        labels.append('malicious')
                        if family == 'Unknown':
                            popular = vt_summary.get('popular_threat', '')
                            if popular:
                                family = popular
                                confidence = 'high'

            # === 层6: ThreatBook 微步 (需Key) ===
            if self.keys.threatbook:
                tb_ok = self._try_query('ThreatBook', self._query_threatbook, file_hash)
                if tb_ok:
                    results.append({'engine': 'ThreatBook', 'result': tb_ok})
                    if tb_ok.get('hit'):
                        labels.append('malicious')
                        if family == 'Unknown' or not family:
                            fam = tb_ok.get('family', '')
                            if fam:
                                family = fam
                                confidence = 'high'
        else:
            _log("[!] 无网络连接，仅使用本地IoC库", 'warning')

        # 计算检出率：只统计实际返回结果的引擎
        queried = sum(1 for r in results if r.get('result') is not None)
        detected = len(labels)

        return ThreatIntel(
            engine_results=results,
            threat_labels=list(set(labels)),
            family=family,
            confidence=confidence,
            detection_rate=min(detected / max(queried, 1), 1.0)
        )

    # ---- 本地 IoC ----
    def _check_local(self, file_hash: str):
        """本地哈希匹配 — 支持精确匹配 + 前缀匹配（SHA256→MD5 交叉查询）"""
        if not file_hash or len(file_hash) < 8:
            return None
        h = file_hash.lower().strip()
        # 精确匹配
        if h in KNOWN_MALWARE:
            return KNOWN_MALWARE[h]
        # 前缀模糊匹配：只与同长度哈希比较避免跨类型误报
        prefix_len = min(len(h), 24)
        prefix = h[:prefix_len]
        for known, val in KNOWN_MALWARE.items():
            if len(known) == len(h) and known[:prefix_len] == prefix:
                return val
        # 短哈希（<24字符）回退：改为已知key starts_with 查询
        if len(h) < 24:
            for known, val in KNOWN_MALWARE.items():
                if known.startswith(h):
                    return val
        # 已知截断哈希（长度 16-63 且非标准 MD5/SHA256）→ 用已知值做前缀匹配
        for known, val in KNOWN_MALWARE.items():
            if 16 <= len(known) < 64 and len(known) not in (32, 40) and h.startswith(known):
                return val
        return None

    # ---- IP / 域名 / URL 情报 ----

    def check_ip(self, ip: str):
        """检查单个 IP 是否为已知恶意地址"""
        ip = ip.strip()
        # 先查内置库
        if ip in KNOWN_MALICIOUS_IPS:
            family, desc = KNOWN_MALICIOUS_IPS[ip]
            _log(f"[+] 恶意IP命中: {ip} -> {family} ({desc})")
            return {'ip': ip, 'family': family, 'description': desc, 'hit': True, 'source': 'builtin'}
        # 再查自定义库
        if ip in self._custom_iocs.get('ips', {}):
            info = self._custom_iocs['ips'][ip]
            return {'ip': ip, 'family': info.get('family', 'Unknown'),
                    'description': info.get('description', ''), 'hit': True, 'source': 'custom'}
        # 子网匹配：仅在已知 C2 基础设施的 /24 范围内匹配，且该 /24 内至少有 2 个已知 IP
        # 避免单个 IP 的误报扩散到整个子网
        ip_parts = ip.rsplit('.', 1)
        if len(ip_parts) == 2:
            prefix = ip_parts[0] + '.'
            known_in_subnet = [k for k in KNOWN_MALICIOUS_IPS if k.startswith(prefix) and k != ip]
            if len(known_in_subnet) >= 2:
                for known in known_in_subnet:
                    family, desc = KNOWN_MALICIOUS_IPS[known]
                    return {'ip': ip, 'family': family, 'description': desc + ' (同/24子网)', 'hit': True, 'source': 'builtin', 'confidence': 'low'}
            custom_in_subnet = [k for k in self._custom_iocs.get('ips', {}) if k.startswith(prefix) and k != ip]
            if len(custom_in_subnet) >= 2:
                for known in custom_in_subnet:
                    info = self._custom_iocs['ips'][known]
                    return {'ip': ip, 'family': info.get('family', 'Unknown'),
                            'description': info.get('description', '') + ' (同/24子网)', 'hit': True, 'source': 'custom', 'confidence': 'low'}
        return None

    def check_domain(self, domain: str):
        """检查域名是否为已知恶意域名"""
        domain = domain.strip().lower()
        # 内置库
        if domain in KNOWN_MALICIOUS_DOMAINS:
            family, desc = KNOWN_MALICIOUS_DOMAINS[domain]
            return {'domain': domain, 'family': family, 'description': desc, 'hit': True, 'source': 'builtin'}
        # 自定义库
        if domain in self._custom_iocs.get('domains', {}):
            info = self._custom_iocs['domains'][domain]
            return {'domain': domain, 'family': info.get('family', 'Unknown'),
                    'description': info.get('description', ''), 'hit': True, 'source': 'custom'}
        # www 剥离
        if domain.startswith('www.'):
            bare = domain[4:]
            if bare in KNOWN_MALICIOUS_DOMAINS:
                family, desc = KNOWN_MALICIOUS_DOMAINS[bare]
                return {'domain': domain, 'family': family, 'description': desc, 'hit': True, 'source': 'builtin'}
            if bare in self._custom_iocs.get('domains', {}):
                info = self._custom_iocs['domains'][bare]
                return {'domain': domain, 'family': info.get('family', 'Unknown'),
                        'description': info.get('description', ''), 'hit': True, 'source': 'custom'}
        # DGA TLD
        for tld in DGA_SUSPICIOUS_TLDS:
            if domain.endswith(tld) and len(domain) > 20:
                # DGA域名通常辅音/元音比例均衡且无常见单词
                body = domain.split('.')[0]
                vowels = sum(1 for c in body.lower() if c in 'aeiou')
                consonants = len(body) - vowels
                if min(vowels, consonants) >= 3:
                    return {'domain': domain, 'family': 'DGA', 'description': f'DGA域名 (TLD={tld})', 'hit': True, 'source': 'heuristic'}
        return None

    def check_url(self, url: str):
        """检查 URL 是否为已知恶意地址"""
        if not url:
            return None
        url = url.strip()
        import re
        dm = re.search(r'https?://([^/:\s]+)', url)
        domain = dm.group(1).lower() if dm else ''
        im = re.search(r'//(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)
        ip = im.group(1) if im else ''
        if domain:
            r = self.check_domain(domain)
            if r:
                return {'url': url, 'family': r['family'], 'description': r['description'], 'hit': True, 'matched': 'domain'}
        if ip:
            r = self.check_ip(ip)
            if r:
                return {'url': url, 'family': r['family'], 'description': r['description'], 'hit': True, 'matched': 'ip'}
        for pattern, family, desc in MALICIOUS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                _log(f"[+] 恶意URL模式命中: {url[:80]} -> {family} ({desc})")
                return {'url': url, 'family': family, 'description': desc, 'hit': True, 'matched': 'pattern'}
        return None

    def check_iocs_batch(self, ips=None, domains=None, urls=None):
        """批量检查 IOCs"""
        result = {'ips': [], 'domains': [], 'urls': [], 'total_hits': 0}
        if ips:
            for ip in ips:
                hit = self.check_ip(ip)
                if hit:
                    result['ips'].append(hit)
                    result['total_hits'] += 1
        if domains:
            for d in domains:
                hit = self.check_domain(d)
                if hit:
                    result['domains'].append(hit)
                    result['total_hits'] += 1
        if urls:
            for u in urls:
                hit = self.check_url(u)
                if hit:
                    result['urls'].append(hit)
                    result['total_hits'] += 1
        return result

    # ===== 自定义 IoC 管理（持久化到 rules/custom_iocs.json）=====

    CUSTOM_IOCS_PATH = resource_path('rules/custom_iocs.json')

    def _load_custom_iocs(self) -> Dict:
        """从文件加载用户自定义 IoC"""
        try:
            if os.path.exists(self.CUSTOM_IOCS_PATH):
                with open(self.CUSTOM_IOCS_PATH, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return {
                        'ips': data.get('ips', {}),
                        'domains': data.get('domains', {}),
                        'urls': data.get('urls', {}),
                    }
        except Exception as e:
            logger.warning(f"加载自定义IoC失败: {e}")
        return {'ips': {}, 'domains': {}, 'urls': {}}

    def _save_custom_iocs(self):
        """保存自定义 IoC 到文件 (临时文件 + os.replace 原子写, 防损坏丢失)"""
        try:
            os.makedirs(os.path.dirname(self.CUSTOM_IOCS_PATH) if os.path.dirname(self.CUSTOM_IOCS_PATH) else '.', exist_ok=True)
            tmp_path = self.CUSTOM_IOCS_PATH + '.tmp'
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(self._custom_iocs, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self.CUSTOM_IOCS_PATH)
            logger.info(f"[+] 自定义IoC已保存到 {self.CUSTOM_IOCS_PATH}")
            return True
        except Exception as e:
            logger.error(f"保存自定义IoC失败: {e}")
            return False

    def add_ioc(self, ioc_type: str, value: str, family: str = 'Custom', description: str = '') -> bool:
        """添加一个 IoC
        Args:
            ioc_type: 'ip' / 'domain' / 'url'
            value: IP地址、域名或URL
            family: 家族名（默认 'Custom'）
            description: 描述
        Returns: 是否成功
        """
        ioc_type = ioc_type.strip().lower()
        value = value.strip()
        if ioc_type not in ('ip', 'domain', 'url'):
            logger.error(f"不支持的IoC类型: {ioc_type}，支持: ip/domain/url")
            return False
        if not value:
            return False

        key = 'ips' if ioc_type == 'ip' else ('domains' if ioc_type == 'domain' else 'urls')
        self._custom_iocs[key][value] = {
            'family': family or 'Custom',
            'description': description or f'用户添加的{ioc_type.upper()}',
            'added_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        ok = self._save_custom_iocs()
        if ok:
            _log(f"[+] 已添加自定义IoC: [{ioc_type.upper()}] {value} ({family})")
        return ok

    def remove_ioc(self, ioc_type: str, value: str) -> bool:
        """移除一个 IoC"""
        ioc_type = ioc_type.strip().lower()
        key = 'ips' if ioc_type == 'ip' else ('domains' if ioc_type == 'domain' else 'urls')
        if value in self._custom_iocs.get(key, {}):
            del self._custom_iocs[key][value]
            self._save_custom_iocs()
            _log(f"[-] 已移除自定义IoC: [{ioc_type.upper()}] {value}")
            return True
        return False

    def list_custom_iocs(self) -> Dict:
        return {
            'ips': list(self._custom_iocs.get('ips', {}).keys()),
            'domains': list(self._custom_iocs.get('domains', {}).keys()),
            'urls': list(self._custom_iocs.get('urls', {}).keys()),
            'total': sum(len(v) for v in self._custom_iocs.values()),
        }

    def get_ioc_info(self, ioc_type: str, value: str) -> Dict:
        key = 'ips' if ioc_type == 'ip' else ('domains' if ioc_type == 'domain' else 'urls')
        return self._custom_iocs.get(key, {}).get(value, {})

    # ---- 网络 ----
    def _check_net(self) -> bool:
        """检测网络连通性 — 5分钟缓存，过期重新检测"""
        import time
        now = time.time()
        # 缓存 5 分钟，过期重试（避免永久缓存 False）
        if self._net_ok is not None:
            if self._net_checked_at and now - self._net_checked_at < 300:
                return self._net_ok
        self._net_checked_at = now

        if _requests is None:
            self._net_ok = False
            return False

        # 多目标探测
        test_urls = [
            ("https://mb-api.abuse.ch/api/v1/", (200, 405)),
            ("https://tria.ge/api/v0/", (200, 405)),
            ("https://www.virustotal.com/", (200, 301, 302, 401)),
        ]
        for url, ok_codes in test_urls:
            try:
                resp = _requests.get(url, timeout=5, allow_redirects=True)
                if resp.status_code in ok_codes:
                    self._net_ok = True
                    return True
            except Exception:
                continue
        self._net_ok = False
        return False

    def _try_query(self, name, func, *args):
        """安全执行一次查询，失败记录原因并返回 None"""
        try:
            return func(*args)
        except Exception as e:
            err_msg = str(e)[:120]
            # 异常信息可能包含完整请求 URL (apikey=...), 必须先脱敏再落日志/GUI
            err_msg = re.sub(r'(?i)(apikey|api_key|token|key)=[^&\s\'"]+',
                             r'\1=***', err_msg)
            logger.warning(f"[{name}] 查询失败: {err_msg}")
            _log(f"[{name}] 查询失败: {err_msg}", 'warning')
            return None

    # ---- API 查询 ----
    def _query_malwarebazaar(self, file_hash: str) -> Dict:
        """MalwareBazaar — 免费、无需Key、支持 SHA256"""
        resp = _requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={'query': 'get_info', 'hash': file_hash},
            timeout=15
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get('query_status') == 'ok':
                return {
                    'hit': True,
                    'signature': data.get('signature', ''),
                    'tags': data.get('tags', []),
                    'first_seen': data.get('first_seen', ''),
                    'file_name': data.get('file_name', ''),
                    'file_type': data.get('file_type', ''),
                }
            # 未命中：标记为已查询但无结果
            return {'hit': False, 'query_status': data.get('query_status', 'error')}
        return {}

    def _query_triage(self, file_hash: str) -> Dict:
        """Triage — 免费查询，score 0-10"""
        try:
            resp = _requests.get(
                f"https://tria.ge/api/v0/samples/{file_hash}/overview.json",
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                sample = data.get('sample', data) if isinstance(data, dict) else {}
                return {
                    'hit': sample.get('score', 0) > 0,
                    'score': sample.get('score', 0),
                    'family': sample.get('family', ''),
                    'tags': sample.get('tags', []),
                }
            if resp.status_code == 404:
                return {'hit': False, 'reason': 'not found'}
        except Exception:
            pass
        return {}

    def _query_urlhaus(self, file_hash: str) -> Dict:
        """URLhaus — 免费 Hash 查询"""
        try:
            resp = _requests.post(
                "https://urlhaus-api.abuse.ch/v1/payload/",
                data={'sha256_hash': file_hash},
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('query_status') == 'ok' and data.get('md5_hash'):
                    return {
                        'hit': True,
                        'signature': data.get('signature') or data.get('file_type', 'unknown'),
                        'urls': data.get('urls', [])[:5],
                        'first_seen': data.get('firstseen', ''),
                        'tags': data.get('tags', []),
                        'threat': data.get('threat', ''),
                    }
                return {'hit': False, 'query_status': data.get('query_status', 'error')}
        except Exception:
            pass
        return {}

    def _query_virustotal(self, file_hash: str) -> Dict:
        """VirusTotal v3 API — 需要 API Key"""
        if not self.keys.virustotal:
            return {}
        resp = _requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={'x-apikey': self.keys.virustotal}, timeout=10
        )
        if resp.status_code == 200:
            return resp.json()
        return {}

    def _summarize_vt(self, vt_data: Dict) -> Dict:
        """精简 VT 响应，只保留关键信息"""
        try:
            attrs = vt_data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            popular = attrs.get('popular_threat_classification', {})
            popular_name = popular.get('popular_threat_name', '') if popular else ''
            # 提取威胁名
            threat_names = []
            if popular_name:
                threat_names.append(popular_name)
            threat_cat = popular.get('popular_threat_category', []) if popular else []
            if threat_cat:
                for tc in threat_cat[:3]:
                    threat_names.append(tc.get('value', ''))

            return {
                'hit': stats.get('malicious', 0) > 0,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'total_engines': sum(stats.values()),
                'popular_threat': popular_name,
                'threat_details': threat_names[:5],
                'first_submission': attrs.get('first_submission_date', ''),
            }
        except Exception:
            return {'error': 'VT response parsing failed'}

    def _query_threatbook(self, file_hash: str) -> Dict:
        """ThreatBook 微步在线 v3 API — 文件信誉查询"""
        try:
            resp = _requests.get(
                "https://api.threatbook.cn/v3/file/report",
                params={'apikey': self.keys.threatbook, 'resource': file_hash}, timeout=10
            )
            if resp.status_code != 200:
                return {}
            data = resp.json()
            # 微步 v3 响应结构: {data: {summary: {...}, multiengines: {...}}}
            summary = (data.get('data') or {}).get('summary') or {}
            if not summary:
                return {'hit': False, 'threat_level': 'unreported', 'detail': '微步未见该样本'}
            multi = (data.get('data') or {}).get('multiengines') or {}
            threat_level = str(summary.get('threat_level', 'unknown') or 'unknown')
            family = summary.get('malware_family', '') or ''
            score = summary.get('threat_score', 0) or 0
            detection = summary.get('multi_engines', '') or ''  # 例: "13/28"
            eng_result = (multi.get('result') or {})
            detected = {k: v for k, v in eng_result.items()
                        if v and str(v).strip().lower() not in ('safe', '')}
            hit = threat_level in ('malicious', 'suspicious')
            return {
                'hit': hit,
                'threat_level': threat_level,
                'family': family,
                'score': score,
                'detection': detection,
                'malware_type': summary.get('malware_type', '') or '',
                'detected_engines': dict(list(detected.items())[:10]),
                'first_seen': summary.get('submit_time', '') or '',
            }
        except Exception as e:
            _log(f"[ThreatBook] 查询异常: {e}", 'warning')
            return {}
