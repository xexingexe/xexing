#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""社区 YARA 规则自动下载器 — 多源规则库聚合"""
import os
import urllib.request
import urllib.error
import shutil
import json
from typing import List, Dict

from logger import get_logger
from utils.helpers import resource_path

logger = get_logger('analyzer.yara_downloader')

# ===== 社区YARA规则源 =====
# 使用 GitHub API (Accept: raw) 而非 raw.githubusercontent.com (被墙)
BASE = 'https://api.github.com/repos/Yara-Rules/rules/contents'
YARA_SOURCES = [
    f'{BASE}/malware/APT_Cobalt.yar',
    f'{BASE}/malware/MALW_AgentTesla.yar',
    f'{BASE}/malware/MALW_AgentTesla_SMTP.yar',
    f'{BASE}/malware/RAT_Asyncrat.yar',
    f'{BASE}/malware/RAT_Nanocore.yar',
    f'{BASE}/malware/RAT_Meterpreter_Reverse_Tcp.yar',
    f'{BASE}/malware/RAT_Gh0st.yar',
    f'{BASE}/malware/RAT_PlugX.yar',
    f'{BASE}/malware/RAT_PoisonIvy.yar',
    f'{BASE}/malware/RAT_Njrat.yar',
    f'{BASE}/malware/RAT_DarkComet.yar',
    f'{BASE}/malware/RAT_BlackShades.yar',
    f'{BASE}/malware/RAT_Adwind.yar',
    f'{BASE}/malware/RAT_Orcus.yar',
    f'{BASE}/malware/RAT_NetwiredRC.yar',
    f'{BASE}/malware/RAT_CyberGate.yar',
    f'{BASE}/malware/RAT_Sakula.yar',
    f'{BASE}/malware/RAT_Xtreme.yar',
    f'{BASE}/malware/RAT_Havex.yar',
    f'{BASE}/malware/RAT_Shim.yar',
    f'{BASE}/malware/RANSOM_MS17-010_Wannacrypt.yar',
    f'{BASE}/malware/RANSOM_Cerber.yar',
    f'{BASE}/malware/RANSOM_Locky.yar',
    f'{BASE}/malware/RANSOM_Petya.yar',
    f'{BASE}/malware/RANSOM_Cryptolocker.yar',
    f'{BASE}/malware/RANSOM_SamSam.yar',
    f'{BASE}/malware/RANSOM_BadRabbit.yar',
    f'{BASE}/malware/RANSOM_Maze.yar',
    f'{BASE}/malware/RANSOM_Snake.yar',
    f'{BASE}/malware/RANSOM_TeslaCrypt.yar',
]


def download_yara_rules(rules_dir: str = None) -> Dict[str, int]:
    if rules_dir is None:
        rules_dir = resource_path('rules/yara')
    """下载所有社区YARA规则到指定目录"""
    os.makedirs(rules_dir, exist_ok=True)
    stats = {'downloaded': 0, 'failed': 0, 'cached': 0}
    api_headers = {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/vnd.github.v3.raw'}

    for url in YARA_SOURCES:
        filename = url.split('/')[-1]
        local_path = os.path.join(rules_dir, filename)

        if os.path.exists(local_path):
            stats['cached'] += 1
            continue

        try:
            req = urllib.request.Request(url, headers=api_headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()

            if data and len(data) > 50:
                with open(local_path, 'wb') as f:
                    f.write(data)
                stats['downloaded'] += 1
                logger.info(f"[YARA-DL] {filename} ({len(data)} bytes)")
            else:
                stats['failed'] += 1
        except urllib.error.HTTPError as e:
            stats['failed'] += 1
            logger.debug(f"[YARA-DL] {filename} HTTP {e.code}")
        except Exception as e:
            stats['failed'] += 1
            logger.debug(f"[YARA-DL] {filename}: {e}")

    logger.info(f"[YARA-DL] 完成: {stats['downloaded']}下载 {stats['cached']}缓存 {stats['failed']}失败")
    return stats


def count_yara_rules(rules_dir: str = None) -> int:
    """统计YARA规则文件数"""
    if rules_dir is None:
        rules_dir = resource_path('rules/yara')
    if not os.path.isdir(rules_dir):
        return 0
    count = 0
    for f in os.listdir(rules_dir):
        if f.endswith('.yar') or f.endswith('.yara'):
            try:
                with open(os.path.join(rules_dir, f), 'r', encoding='utf-8', errors='ignore') as fh:
                    content = fh.read()
                    count += content.count('rule ') + content.count('rule\n')
            except Exception:
                pass
    return count
