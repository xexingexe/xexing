#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAT / Stealer 配置提取器 — 自动从恶意样本中提取 C2 地址、加密密钥、互斥体、版本等配置
支持: AgentTesla, RedLine, FormBook, Remcos, AsyncRAT, XWorm, QuasarRAT, 等
"""
import os
import re
import base64
from typing import Dict, List
from logger import get_logger

logger = get_logger('analyzer.rat_config')


class RATConfigExtractor:
    """RAT/Stealer 配置提取器 — 纯字符串/正则匹配，无需执行"""

    # ===== AgentTesla 特征 =====
    AGENTTESLA_PATTERNS = {
        'smtp_host': re.compile(rb'(?:smtp|mail)\.\w+\.\w+|smtp\.(?:gmail|yahoo|outlook|live)\.\w+', re.I),
        'smtp_port': re.compile(rb'(?:port|smtp_port)[\s:=]*(465|587|25|2525)\b'),
        'smtp_user': re.compile(rb'(?:user|email|from)[\s:=]+([\w._%+-]+@[\w.-]+\.\w+)', re.I),
        'smtp_pass': re.compile(rb'(?:pass|pwd|password)[\s:=]+([^\s]{6,40})', re.I),
        'telegram_token': re.compile(rb'(?:bot|telegram)[\s:=]*(\d{8,10}:[a-zA-Z0-9_-]{35,})'),
        'telegram_chatid': re.compile(rb'(?:chat.?id|chatid)[\s:=]*(\d{7,15})', re.I),
        'ftp_host': re.compile(rb'(?:ftp\.|ftps?://)([\w.-]+\.\w+:\d+)', re.I),
    }

    # ===== RedLine Stealer 特征 =====
    REDLINE_PATTERNS = {
        'c2_ip': re.compile(rb'\b(?:sip|host|server)[\s:=]*(?:"?)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:"?)', re.I),
        'c2_port': re.compile(rb'\b(?:port)[\s:=]*(4444|5555|6666|8888|9999|7000|5000)\b', re.I),
        'mutex': re.compile(rb'(?:mutex|mtx)[\s:=]*["\']?([a-zA-Z0-9_]{8,30})["\']?', re.I),
        'build_id': re.compile(rb'(?:build|version|ver)[\s:=]*["\']?([a-zA-Z0-9_.]{4,20})["\']?', re.I),
        'telegram_bot': re.compile(rb'(?:token|bot)\s*[:=]\s*["\']?(\d{8,10}:[a-zA-Z0-9_-]{35,})'),
        'discord_webhook': re.compile(rb'https?://(?:discord\.com|discordapp\.com)/api/webhooks/\d{17,20}/[a-zA-Z0-9_-]{60,80}'),
    }

    # ===== FormBook 特征 =====
    FORMBOOK_PATTERNS = {
        'c2_url': re.compile(rb'https?://[\w.-]+\.\w{2,}/[a-z]{2,6}\.php\?\w+=[a-f0-9]+', re.I),
        'user_agent': re.compile(rb'(?:Mozilla|user-agent)[\s:=]*["\']?(Mozilla/5\.0[^"\']{10,100})', re.I),
        'campaign_id': re.compile(rb'(?:campaign|cmp)[\s:=]*["\']?([a-zA-Z0-9_]{4,16})["\']?', re.I),
    }

    # ===== Remcos RAT 特征 =====
    REMCOS_PATTERNS = {
        'c2_host': re.compile(rb'(?:host|domain|dns)[\s:=]+["\']?([\w.-]+\.(?:ddns\.net|no-ip\.\w+|hopto\.org|zapto\.org|\w{2,}))["\']?', re.I),
        'c2_port': re.compile(rb'(?:port)[\s:=]*(443|80|8080|8888|9999|5555|5400)\b', re.I),
        'mutex': re.compile(rb'(?:mutex|mtx)[\s:=]+["\']?(Remcos[_\w]{4,20})["\']?', re.I),
        'keylog_file': re.compile(rb'(?:keylog|logs|logfile)[\s:=]+["\']?(\w+\.(?:dat|txt|log))["\']?', re.I),
    }

    # ===== AsyncRAT / QuasarRAT 特征 =====
    ASYNC_PATTERNS = {
        'c2_host': re.compile(rb'(?:host|ip|server)[\s:=]+["\']?([\w.-]+\.\w{2,}|(?:\d{1,3}\.){3}\d{1,3})["\']?', re.I),
        'c2_port': re.compile(rb'(?:port)[\s:=]*(443|80|8080|8888|6606|7707|8808)\b', re.I),
        'pastebin_url': re.compile(rb'https?://pastebin\.com/raw/[a-zA-Z0-9]{8}'),
    }

    # ===== XWorm RAT 特征 =====
    XWORM_PATTERNS = {
        'c2_host': re.compile(rb'(?:host|dns|domain)[\s:=]*["\']?([\w.-]+\.\w{2,})["\']?', re.I),
        'c2_port': re.compile(rb'(?:port|prt)[\s:=]*(7000|8888|5555|4444|3333)\b', re.I),
        'mutex': re.compile(rb'(?:mutex|mtx)[\s:=]*["\']?([a-zA-Z0-9_]{6,25})["\']?'),
        'encryption_key': re.compile(rb'(?:key|aes_key|rc4_key|xor_key)[\s:=]*["\']?([a-zA-Z0-9+/]{16,32}=?)["\']?', re.I),
    }

    # ===== 通用 C2 模式 =====
    GENERIC_C2_PATTERNS = {
        'url': re.compile(rb'https?://[\w.-]+\.\w{2,}(?::\d+)?(?:/[^\s"\'<>]*)?'),
        'ip_port': re.compile(rb'(?:connect|remote|server)[\s:=]*(?:"?)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):?(\d{2,5})?(?:"?)', re.I),
        'base64_config': re.compile(rb'(?:config|cfg|settings)[\s:=]*(?:["\'])?([A-Za-z0-9+/]{20,}={0,2})(?:["\'])?'),
        # ⚠ 任意 32 位 hex (SHA256/GUID) 都会命中 → 已移除, 改用上下文 ip_port
    }

    def __init__(self):
        self.results: List[Dict] = []

    def extract(self, data: bytes, pe_info=None) -> List[Dict]:
        """从样本数据中提取所有可识别的 RAT 配置"""
        self.results = []

        # 尝试解码可能的 base64 配置块
        # 先找大的 base64 块，尝试解码后再匹配
        base64_blocks = re.findall(rb'[A-Za-z0-9+/]{80,}={0,2}', data)
        decoded_blocks = []
        for block in base64_blocks[:20]:  # 只处理前20个避免太多误报
            try:
                decoded = base64.b64decode(block)
                if len(decoded) > 30 and self._has_readable_strings(decoded):
                    decoded_blocks.append(decoded)
            except Exception:
                pass

        # 合并原始数据和解码数据一起分析
        all_data = data
        for db in decoded_blocks:
            all_data += b'\n---DECODED---\n' + db

        # 逐一检测各个 RAT 家族
        # ⚠ 单一弱字段(如 smtp_pass=xxx / campaign=xxx / mutex=xxx)在普通软件里也
        # 大量存在, 曾把 SilverFox 样本误标为 AgentTesla/FormBook/RedLine 配置。
        # 策略: ≥2 字段之外, 还必须命中至少一个“强特征”(网络端点类), 避免两个
        # 弱字段巧合同现 (mutex+build_id 组合) 误报。
        self._detect_family(all_data, 'AgentTesla', self.AGENTTESLA_PATTERNS,
                            min_matches=2,
                            required_any=('smtp_host', 'smtp_user', 'telegram_token',
                                          'telegram_chatid', 'ftp_host'))
        # RedLine 弱字段多 (build_id 匹配任意 ver= 字符串) — 必须有网络端点证据
        self._detect_family(all_data, 'RedLine', self.REDLINE_PATTERNS,
                            min_matches=2,
                            required_any=('c2_ip', 'c2_port', 'telegram_bot', 'discord_webhook'))
        self._detect_family(all_data, 'FormBook', self.FORMBOOK_PATTERNS,
                            min_matches=2, required_fields=('c2_url',))
        self._detect_family(all_data, 'Remcos', self.REMCOS_PATTERNS,
                            min_matches=2, required_fields=('c2_host',))
        self._detect_family(all_data, 'AsyncRAT', self.ASYNC_PATTERNS,
                            min_matches=2, required_any=('pastebin_url',))
        self._detect_family(all_data, 'XWorm', self.XWORM_PATTERNS, min_matches=3)

        # 通用 C2 模式（如果没有家族匹配）
        if not self.results:
            # 已知 XML 命名空间/文档 URL 会被通用 url 规则误当成 C2
            # (如 schemas.microsoft.com/.../WindowsSettings) — 先剔除再匹配。
            generic_data = all_data
            for _noise in (b'schemas.microsoft.com', b'w3.org', b'ns.adobe.com',
                           b'purl.org', b'www.iec.ch'):
                generic_data = generic_data.replace(_noise, b'')
            self._detect_family(generic_data, 'Unknown', self.GENERIC_C2_PATTERNS,
                                min_matches=2)

        # 检测 Telegram Bot Token（通用）
        tg_tokens = re.findall(rb'\d{8,10}:[a-zA-Z0-9_-]{35,45}', all_data)
        if tg_tokens:
            for token in set(tg_tokens):
                self.results.append({
                    'family': 'Generic',
                    'type': 'telegram_bot_token',
                    'value': token.decode('ascii', errors='ignore'),
                    'description': 'Telegram Bot Token (C2 回传通道)'
                })

        # 检测 Discord Webhook（通用）
        discord_hooks = re.findall(
            rb'https?://(?:discord\.com|discordapp\.com)/api/webhooks/\d{17,20}/[a-zA-Z0-9_-]{60,80}',
            all_data
        )
        if discord_hooks:
            for hook in set(discord_hooks):
                self.results.append({
                    'family': 'Generic',
                    'type': 'discord_webhook',
                    'value': hook.decode('ascii', errors='ignore'),
                    'description': 'Discord Webhook URL (数据回传)'
                })

        # SMTP 凭据（通用窃取器特征）— 只有已命中家族/其它强 C2 证据时才提取,
        # 否则任何邮件客户端/配置文件都会被误报 Generic Stealer。
        if self.results:
            smtp_creds = self._extract_smtp_credentials(all_data)
            self.results.extend(smtp_creds)

        logger.info(f"[RAT Config] 提取到 {len(self.results)} 个配置项")
        return self.results

    def _detect_family(self, data: bytes, family: str, patterns: Dict[str, re.Pattern],
                       min_matches: int = 1, required_any: tuple = (),
                       required_fields: tuple = ()):
        """对给定家族检测配置模式
        ⚠ min_matches: 弱字段(如 build_id 匹配任意 ver= 字符串) 单独出现不可信,
        曾把样本字符串碎片误提取为 RedLine 配置 (build_id=Y_SHO 仅1匹配)
        ⚠ required_any/required_fields: 强特征约束 — 两个弱字段巧合同现也不能认定家族
        """
        config = {}
        for key, pattern in patterns.items():
            matches = pattern.findall(data)
            if matches:
                # 取第一次匹配
                val = matches[0]
                if isinstance(val, tuple):
                    val = next((v for v in val if v), val[0])
                if isinstance(val, bytes):
                    val = val.decode('ascii', errors='ignore')
                config[key] = val.strip()

        if len(config) < min_matches or not config:
            return
        if required_fields and not all(k in config for k in required_fields):
            return
        if required_any and not any(k in config for k in required_any):
            return

        self.results.append({
            'family': family,
            'type': 'c2_config',
            'config': config,
            'description': f'{family} C2/配置信息',
            'matches': len(config),
        })

    def _extract_smtp_credentials(self, data: bytes) -> List[Dict]:
        """提取 SMTP 凭据"""
        results = []
        # SMTP 主机 + 端口 + 用户名 + 密码组合
        smtp_match = re.search(
            rb'(?:smtp|mail)[\s:=]+["\']?([\w.-]+\.\w{2,})["\']?.*?'
            rb'(?:port)[\s:=]*(\d{2,5}).*?'
            rb'(?:user|email|from|login)[\s:=]+["\']?([\w._%+-]+@[\w.-]+\.\w+)["\']?.*?'
            rb'(?:pass|pwd|password)[\s:=]+["\']?([^\s"\'<>]{4,40})["\']?',
            data, re.I | re.S
        )
        if smtp_match:
            results.append({
                'family': 'Generic Stealer',
                'type': 'smtp_credentials',
                'config': {
                    'host': smtp_match.group(1).decode('ascii', errors='ignore'),
                    'port': smtp_match.group(2).decode('ascii', errors='ignore'),
                    'user': smtp_match.group(3).decode('ascii', errors='ignore'),
                    'password': smtp_match.group(4).decode('ascii', errors='ignore'),
                },
                'description': 'SMTP 凭据 (窃取器回传)',
            })
        return results

    def _has_readable_strings(self, data: bytes, min_ratio: float = 0.3) -> bool:
        """检查数据块是否包含足够多的可读 ASCII 字符串"""
        if len(data) < 10:
            return False
        printable = sum(1 for b in data if 0x20 <= b <= 0x7e)
        return printable / len(data) > min_ratio

    def get_c2_addresses(self) -> List[str]:
        """提取所有 C2 地址（去重）"""
        addresses = set()
        for r in self.results:
            cfg = r.get('config', {})
            for key, val in cfg.items():
                if any(k in key.lower() for k in ['ip', 'host', 'url', 'dns', 'domain', 'server', 'c2']):
                    addresses.add(str(val))
        return sorted(addresses)


# ===== 全局便捷函数 =====
def extract_rat_config(file_path: str) -> List[Dict]:
    """从文件路径提取 RAT 配置"""
    try:
        with open(file_path, 'rb') as f:
            fsize = os.path.getsize(file_path)
            # 只读前 10MB
            cap = 10 * 1024 * 1024
            if fsize > cap:
                f.seek(0)
                data = f.read(cap)
            else:
                data = f.read()
    except Exception as e:
        logger.error(f"读取文件失败: {e}")
        return []

    extractor = RATConfigExtractor()
    return extractor.extract(data)
