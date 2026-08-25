#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""URL 扫描独立报告生成器 — HTML / JSON"""
import os
import json
import time
from datetime import datetime

from logger import get_logger
from config import CONFIG
from analyzer.models import URLScanResult

logger = get_logger('report.url')

_esc = lambda s: (str(s).replace('&', '&amp;').replace('<', '&lt;')
                  .replace('>', '&gt;').replace('"', '&quot;'))


def _safe_name(url: str, maxlen: int = 40) -> str:
    """从 URL 生成安全文件名 (去掉 Windows 非法字符)"""
    import re
    name = re.sub(r'https?://', '', url, flags=re.I)
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
    name = name.strip('._')
    return name[:maxlen] or 'url'


def _sev_color(sev: str) -> str:
    return {'critical': '#dc2626', 'high': '#ef4444', 'medium': '#f59e0b',
            'low': '#22c55e'}.get(sev, '#64748b')


def _risk_badge(level: str) -> str:
    colors = {'critical': '#dc2626', 'high': '#ea580c', 'medium': '#f59e0b',
              'low': '#059669', 'unknown': '#64748b'}
    c = colors.get(level, '#64748b')
    return f'<span style="background:{c};color:#fff;padding:6px 20px;border-radius:20px;font-weight:700">{_esc(level.upper())}</span>'


def _finding_rows(findings, max_items=100) -> str:
    if not findings:
        return '<tr><td colspan="3" style="color:#64748b">未发现</td></tr>'
    rows = ''
    for f in findings[:max_items]:
        sev = f.get('severity', 'low')
        c = _sev_color(sev)
        line = f.get('line', 0) or ''
        line_str = f'<span style="color:#64748b">L{line}</span>' if line else '<span style="color:#64748b">-</span>'
        rows += (f'<tr><td><span style="color:{c};font-weight:700">{sev}</span></td>'
                 f'<td style="font-family:Consolas,monospace;font-size:12px">{_esc(f.get("type", ""))}</td>'
                 f'<td style="font-family:Consolas,monospace;font-size:12px;word-break:break-all">{_esc(f.get("evidence", ""))}</td>'
                 f'<td>{line_str}</td></tr>')
    return rows


def _info_grid(items) -> str:
    rows = ''
    for lbl, val in items:
        rows += (f'<div style="padding:7px 0;border-bottom:1px solid #1e293b">'
                 f'<div style="font-size:11px;color:#64748b;font-weight:600">{_esc(lbl)}</div>'
                 f'<div style="font-size:13px;color:#e2e8f0;word-break:break-all">{val}</div></div>')
    return f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px 20px">{rows}</div>'


def generate_html(result: URLScanResult, filepath: str = None) -> str:
    """生成独立 URL 扫描 HTML 报告, 返回内容"""
    if filepath is None:
        out_dir = CONFIG.report.output_dir
        os.makedirs(out_dir, exist_ok=True)
        filepath = os.path.join(out_dir, f'urlscan_{_safe_name(result.url)}_{int(time.time())}.html')

    sections = []

    # 概览
    grid = _info_grid([
        ('目标 URL', _esc(result.url)),
        ('最终 URL', _esc(result.final_url or result.url)),
        ('HTTP 状态', f'{result.status_code} {_esc(result.reason)}'),
        ('风险评分', f'{result.risk_score}/100'),
        ('风险等级', _risk_badge(result.risk_level)),
        ('IP 地址', _esc(', '.join(result.resolved_ips) or '解析失败')),
        ('内容类型', _esc(result.content_type or 'N/A')),
        ('页面大小', f'{result.page_size // 1024} KB'),
        ('页面标题', _esc(result.page_title or 'N/A')),
        ('页面语言', 'PHP' if result.is_php else 'N/A'),
        ('phpinfo 暴露', '是' if result.phpinfo_exposed else '否'),
        ('扫描耗时', f'{result.scan_duration:.1f}s'),
        ('扫描时间', _esc(result.scanned_at)),
    ])
    sections.append(f'''<div class="section" style="border-left-color:#6366f1"><h2>📡 目标概览</h2>{grid}</div>''')

    # 跳转链
    if len(result.redirect_chain) > 1:
        chain = ''.join(f'<div style="padding:4px 0;font-family:Consolas,monospace;font-size:12px;color:#94a3b8">'
                        f'{i}. {_esc(u)}</div>' for i, u in enumerate(result.redirect_chain))
        sections.append(f'<div class="section" style="border-left-color:#6366f1"><h2>🔀 跳转链 ({len(result.redirect_chain)})</h2>{chain}</div>')

    # IoC
    if result.ioc_hits:
        rows = ''
        for h in result.ioc_hits:
            rows += (f'<tr class="suspicious"><td>{_esc(h.get("matched", h.get("source", "")))}</td>'
                     f'<td style="font-family:Consolas,monospace;font-size:12px">{_esc(h.get("url", h.get("ip", h.get("domain", ""))))}</td>'
                     f'<td>{_esc(h.get("family", ""))}</td>'
                     f'<td style="font-size:12px">{_esc(h.get("description", ""))}</td></tr>')
        sections.append(f'''<div class="section" style="border-left-color:#dc2626"><h2>☠️ 威胁情报命中 ({len(result.ioc_hits)})</h2>
<table class="data-table"><thead><tr><th>匹配</th><th>值</th><th>家族</th><th>描述</th></tr></thead><tbody>{rows}</tbody></table></div>''')

    # 命令执行 / WebShell
    if result.webshell_indicators:
        sections.append(f'''<div class="section" style="border-left-color:#dc2626"><h2>⚡ 命令执行 / WebShell ({len(result.webshell_indicators)})</h2>
<table class="data-table"><thead><tr><th>严重度</th><th>类型</th><th>证据</th><th>行</th></tr></thead><tbody>
{_finding_rows(result.webshell_indicators)}</tbody></table></div>''')

    # 挂马
    if result.malicious_iframes:
        sections.append(f'''<div class="section" style="border-left-color:#ef4444"><h2>🕳️ 挂马 / 页面篡改 ({len(result.malicious_iframes)})</h2>
<table class="data-table"><thead><tr><th>严重度</th><th>类型</th><th>证据</th><th>行</th></tr></thead><tbody>
{_finding_rows(result.malicious_iframes)}</tbody></table></div>''')

    # 混淆脚本
    if result.obfuscated_scripts:
        sections.append(f'''<div class="section" style="border-left-color:#f59e0b"><h2>🌀 恶意/混淆脚本 ({len(result.obfuscated_scripts)})</h2>
<table class="data-table"><thead><tr><th>严重度</th><th>类型</th><th>证据</th><th>行</th></tr></thead><tbody>
{_finding_rows(result.obfuscated_scripts)}</tbody></table></div>''')

    # 免杀下载
    if result.drive_by_downloads:
        sections.append(f'''<div class="section" style="border-left-color:#ef4444"><h2>💣 免杀下载 / 载荷释放 ({len(result.drive_by_downloads)})</h2>
<table class="data-table"><thead><tr><th>严重度</th><th>类型</th><th>证据</th><th>行</th></tr></thead><tbody>
{_finding_rows(result.drive_by_downloads)}</tbody></table></div>''')

    # 社会工程 (ClickFix / 假更新)
    if result.social_engineering:
        sections.append(f'''<div class="section" style="border-left-color:#ef4444"><h2>🪤 社会工程投放 (ClickFix/假更新) ({len(result.social_engineering)})</h2>
<table class="data-table"><thead><tr><th>严重度</th><th>类型</th><th>证据</th><th>行</th></tr></thead><tbody>
{_finding_rows(result.social_engineering)}</tbody></table></div>''')

    # 数据窃取 (Magecart/键盘记录)
    if result.data_theft:
        sections.append(f'''<div class="section" style="border-left-color:#ef4444"><h2>🕵️ 数据窃取 (Magecart/键盘记录) ({len(result.data_theft)})</h2>
<table class="data-table"><thead><tr><th>严重度</th><th>类型</th><th>证据</th><th>行</th></tr></thead><tbody>
{_finding_rows(result.data_theft)}</tbody></table></div>''')

    # PHP8 后门
    if result.php8_webshell:
        sections.append(f'''<div class="section" style="border-left-color:#dc2626"><h2>🧬 PHP8 新特性后门 ({len(result.php8_webshell)})</h2>
<table class="data-table"><thead><tr><th>严重度</th><th>类型</th><th>证据</th><th>行</th></tr></thead><tbody>
{_finding_rows(result.php8_webshell)}</tbody></table></div>''')

    # 挖矿
    if result.crypto_mining:
        sections.append(f'''<div class="section" style="border-left-color:#f59e0b"><h2>⛏️ 挖矿脚本 ({len(result.crypto_mining)})</h2>
<table class="data-table"><thead><tr><th>严重度</th><th>类型</th><th>证据</th><th>行</th></tr></thead><tbody>
{_finding_rows(result.crypto_mining)}</tbody></table></div>''')

    # 命令输出泄漏
    if result.command_output_leak:
        sections.append(f'''<div class="section" style="border-left-color:#ef4444"><h2>⌨️ 命令输出泄漏 ({len(result.command_output_leak)})</h2>
<table class="data-table"><thead><tr><th>严重度</th><th>类型</th><th>证据</th><th>行</th></tr></thead><tbody>
{_finding_rows(result.command_output_leak)}</tbody></table></div>''')

    # 钓鱼
    if result.phishing_indicators:
        sections.append(f'''<div class="section" style="border-left-color:#f59e0b"><h2>🎣 钓鱼指示器 ({len(result.phishing_indicators)})</h2>
<table class="data-table"><thead><tr><th>严重度</th><th>类型</th><th>证据</th><th>行</th></tr></thead><tbody>
{_finding_rows(result.phishing_indicators)}</tbody></table></div>''')

    # 可疑外链
    if result.suspicious_links:
        links = ''.join(f'<li>{_esc(l)}</li>' for l in result.suspicious_links)
        sections.append(f'<div class="section" style="border-left-color:#f59e0b"><h2>🔗 可疑外链 ({len(result.suspicious_links)})</h2><ul class="item-list" style="font-family:Consolas,monospace;font-size:12px;word-break:break-all">{links}</ul></div>')

    # 外部脚本
    if result.external_scripts:
        blocks = ''
        for s in result.external_scripts:
            sf = s.get('findings', [])
            head = (f'<summary><span style="color:{"#f87171" if sf else "#22c55e"};font-weight:700">'
                    f'{"⚠ " if sf else "✓ "}{_esc(s["url"])} (HTTP {s.get("status", 0)}, {s.get("size", 0) // 1024}KB)</span></summary>')
            body = ('<div class="content-inner"><table class="data-table"><tbody>' +
                    _finding_rows(sf) + '</tbody></table></div>') if sf else \
                ('<div class="content-inner" style="padding:6px 0;color:#64748b;font-size:12px">未发现恶意特征'
                 + (f' · 抓取失败: {_esc(s.get("error", ""))}' if s.get('error') else '') + '</div>')
            blocks += f'<details class="collapsible">{head}{body}</details>'
        sections.append(f'<div class="section" style="border-left-color:#6366f1"><h2>📜 外部脚本分析 ({len(result.external_scripts)})</h2>{blocks}</div>')

    # ===== 动态行为监控 =====
    if getattr(result, 'dynamic_used', False):
        dyn_badge = f'<span style="color:#22c55e;font-weight:700">✓ 已执行 ({_esc(result.dynamic_engine)})</span>'
    else:
        dyn_badge = f'<span style="color:#f59e0b;font-weight:700">未执行{(" · " + _esc(result.dynamic_error)) if getattr(result, "dynamic_error", "") else ""}</span>'
    dyn_title = f'🤖 动态行为监控 (浏览器沙箱) — {dyn_badge}'
    dyn_parts = []

    # 行为时间线
    if result.dynamic_events:
        rows = ''
        for e in result.dynamic_events[:200]:
            sev = ''
            if 'suspicious' in e.get('type', '') or e.get('type') in ('download', 'popup', 'dialog', 'page_error'):
                sev = ' class="suspicious"'
            rows += f'<tr{sev}><td style="font-family:Consolas,monospace;color:#94a3b8">+{e.get("t", 0):.1f}s</td><td style="font-family:Consolas,monospace;font-size:12px">{_esc(e.get("type", ""))}</td><td style="font-size:12px;word-break:break-all">{_esc(e.get("detail", ""))}</td></tr>'
        dyn_parts.append(f'''<div class="section" style="border-left-color:#6366f1"><h2>⏱ 行为时间线 ({len(result.dynamic_events)})</h2>
<table class="data-table"><thead><tr><th>时间</th><th>事件</th><th>详情</th></tr></thead><tbody>{rows}</tbody></table></div>''')

    # 网络请求
    if result.dynamic_requests:
        rows = ''
        for r in result.dynamic_requests[:150]:
            url_s = r.get('url', '')
            host = url_s.split('/')[2] if '://' in url_s else url_s
            status = r.get('status', 0)
            sc = '#f87171' if status >= 400 else '#94a3b8'
            rows += f'<tr><td style="color:{sc}">{status}</td><td style="font-size:11px">{_esc(r.get("method", "GET"))}</td><td style="font-size:11px">{_esc(r.get("type", ""))}</td><td style="font-size:11px;word-break:break-all">{_esc(url_s[:200])}</td><td style="font-size:11px">{r.get("size", 0) // 1024}KB</td></tr>'
        dyn_parts.append(f'''<div class="section" style="border-left-color:#6366f1"><h2>🌐 网络请求 ({len(result.dynamic_requests)}) — 含 JS 动态发起的请求</h2>
<table class="data-table"><thead><tr><th>状态</th><th>方法</th><th>类型</th><th>URL</th><th>大小</th></tr></thead><tbody>{rows}</tbody></table></div>''')

    # DOM 注入
    if result.dom_injected:
        rows = ''
        for f in result.dom_injected[:40]:
            c = _sev_color(f.get('severity', 'low'))
            rows += f'<tr class="suspicious"><td><span style="color:{c};font-weight:700">{f.get("severity", "")}</span></td><td style="font-family:Consolas,monospace;font-size:12px">{_esc(f.get("type", ""))}</td><td style="font-size:12px;word-break:break-all">{_esc(f.get("evidence", ""))}</td></tr>'
        dyn_parts.append(f'''<div class="section" style="border-left-color:#dc2626"><h2>🧬 JS 执行后 DOM 注入检测 ({len(result.dom_injected)}) — 静态看不到的挂马</h2>
<table class="data-table"><thead><tr><th>严重度</th><th>类型</th><th>证据</th></tr></thead><tbody>{rows}</tbody></table></div>''')

    # 资源分析
    if result.dynamic_resources:
        blocks = ''
        for res in result.dynamic_resources[:20]:
            sf = res.get('findings', [])
            head = f'<summary><span style="color:{"#f87171" if sf else "#22c55e"};font-weight:700">{"⚠ " if sf else "✓ "}{_esc(res.get("url", ""))} ({res.get("type", "")}, {res.get("size", 0) // 1024}KB)</span></summary>'
            body = ('<div class="content-inner"><table class="data-table"><tbody>' +
                    _finding_rows(sf) + '</tbody></table></div>') if sf else '<div class="content-inner" style="color:#64748b;font-size:12px">未发现恶意特征</div>'
            blocks += f'<details class="collapsible">{head}{body}</details>'
        dyn_parts.append(f'<div class="section" style="border-left-color:#6366f1"><h2>📦 动态抓取资源分析 ({len(result.dynamic_resources)})</h2>{blocks}</div>')

    # 控制台
    if result.dynamic_console:
        rows = ''
        for m in result.dynamic_console[:100]:
            lvl = m.get('level', '')
            lc = {'error': '#f87171', 'warning': '#fcd34d', 'info': '#94a3b8'}.get(lvl, '#94a3b8')
            rows += f'<tr><td style="color:{lc};font-weight:700">{_esc(lvl)}</td><td style="font-family:Consolas,monospace;font-size:12px;word-break:break-all">{_esc(m.get("text", ""))}</td></tr>'
        dyn_parts.append(f'''<div class="section" style="border-left-color:#6366f1"><h2>🖥 控制台消息 ({len(result.dynamic_console)})</h2>
<table class="data-table"><thead><tr><th>级别</th><th>内容</th></tr></thead><tbody>{rows}</tbody></table></div>''')

    # 下载
    if result.dynamic_downloads:
        rows = ''
        for d in result.dynamic_downloads:
            sus = ' class="suspicious"' if d.get('suspicious') else ''
            rows += (f'<tr{sus}><td style="font-family:Consolas,monospace;font-size:12px">{_esc(d.get("filename", ""))}</td>'
                     f'<td style="font-size:12px;word-break:break-all">{_esc(d.get("url", ""))}</td>'
                     f'<td style="font-size:11px">{d.get("size", 0) // 1024}KB</td>'
                     f'<td style="font-family:Consolas,monospace;font-size:11px">{_esc(d.get("sha256", "")[:16])}…</td>'
                     f'<td>{"<span style=\"color:#f87171;font-weight:700\">危险</span> " + _esc(", ".join(d.get("reasons", []))) if d.get("suspicious") else "<span style=\"color:#22c55e\">正常</span>"}</td></tr>')
        dyn_parts.append(f'''<div class="section" style="border-left-color:#ef4444"><h2>⬇ 浏览器触发下载 ({len(result.dynamic_downloads)})</h2>
<table class="data-table"><thead><tr><th>文件名</th><th>URL</th><th>大小</th><th>SHA256</th><th>判定</th></tr></thead><tbody>{rows}</tbody></table></div>''')

    # 截图
    if result.dynamic_screenshots:
        imgs = ''
        for s in result.dynamic_screenshots:
            if os.path.isfile(s):
                imgs += f'<img src="{_esc(os.path.basename(s))}" style="max-width:100%;border-radius:8px;border:1px solid #334155;margin-bottom:8px" alt="screenshot">'
        if imgs:
            dyn_parts.append(f'<div class="section" style="border-left-color:#6366f1"><h2>📷 执行期截图</h2>{imgs}</div>')

    if dyn_parts:
        sections.append(f'<div class="section" style="border-left-color:#059669"><h2>{dyn_title}</h2></div>' + ''.join(dyn_parts))

    # 结论
    if result.fetch_error:
        verdict = f'<div style="padding:14px;background:rgba(245,158,11,0.08);border:1px solid #f59e0b;border-radius:8px;color:#fcd34d">❌ 连接失败: {_esc(result.fetch_error)}</div>'
    else:
        level = result.risk_level
        icon = {'critical': '💀', 'high': '⛔', 'medium': '⚠️', 'low': '✅'}.get(level, '❔')
        vcolor = {'critical': '#f87171', 'high': '#fb923c', 'medium': '#fcd34d', 'low': '#4ade80'}.get(level, '#94a3b8')
        verdict = (f'<div style="padding:16px;background:rgba(99,102,241,0.06);border:1px solid #334155;border-radius:8px">'
                   f'<div style="font-size:15px;font-weight:700;color:{vcolor}">{icon} 扫描结论: {_esc(result.summary)}</div></div>')
    sections.append(f'<div class="section" style="border-left-color:#6366f1"><h2>🧾 结论</h2>{verdict}</div>')

    # 全量发现
    if result.all_findings:
        sections.append(f'''<div class="section" style="border-left-color:#6366f1"><h2>📋 全部发现 ({len(result.all_findings)})</h2>
<table class="data-table"><thead><tr><th>严重度</th><th>类型</th><th>证据</th><th>行</th></tr></thead><tbody>
{_finding_rows(result.all_findings)}</tbody></table></div>''')

    content = f'''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>URL 挂马扫描报告 - {_esc(result.url)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Microsoft YaHei','Segoe UI',Arial,sans-serif;background:#0f172a;padding:20px;color:#e2e8f0;line-height:1.6}}
.container{{max-width:1200px;margin:0 auto;background:#1e293b;border-radius:16px;overflow:hidden;border:1px solid #334155}}
.header{{background:linear-gradient(135deg,#1e3a5f 0,#312e81 50%,#581c87 100%);color:#f1f5f9;padding:36px 44px}}
.header h1{{font-size:24px;margin-bottom:8px}}
.content{{padding:30px 44px}}
h2{{font-size:16px;font-weight:700;margin-bottom:14px;color:#f1f5f9;border-bottom:2px solid #334155;padding-bottom:8px}}
.section{{margin-bottom:24px;padding:18px 20px;border-left:4px solid #6366f1;background:#1a2332;border-radius:0 10px 10px 0}}
.data-table{{width:100%;border-collapse:collapse;font-size:13px}}
.data-table th{{background:#0f172a;padding:9px 12px;text-align:left;font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px}}
.data-table td{{padding:8px 12px;border-bottom:1px solid #1e293b;color:#cbd5e1}}
.suspicious{{background:rgba(239,68,68,0.08)}}
.collapsible{{margin-bottom:10px;border:1px solid #334155;border-radius:10px;overflow:hidden;background:#0f172a}}
.collapsible summary{{padding:10px 16px;cursor:pointer;font-size:13px;background:#1e293b;color:#e2e8f0}}
.item-list li{{padding:6px 0;border-bottom:1px solid #1e293b}}
.footer{{text-align:center;padding:20px;color:#475569;font-size:12px}}
</style></head><body>
<div class="container">
<div class="header">
<h1>🌐 URL 挂马扫描报告</h1>
<div style="opacity:0.85;font-size:13px">{_esc(result.scanned_at)} · 目标: <span style="font-family:Consolas,monospace">{_esc(result.url)}</span></div>
<div style="margin-top:12px">{_risk_badge(result.risk_level)} <span style="font-size:13px;color:#cbd5e1">评分 {result.risk_score}/100</span></div>
</div>
<div class="content">{''.join(sections)}</div>
<div class="footer">Malware Analysis Platform · URL 挂马扫描器</div>
</div></body></html>'''

    try:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"[URLReport] HTML 报告已保存: {filepath}")
    except Exception as e:
        logger.error(f"[URLReport] HTML 保存失败: {e}")
    return content


def generate_json(result: URLScanResult, filepath: str = None) -> str:
    """生成 JSON 报告, 返回路径"""
    if filepath is None:
        out_dir = CONFIG.report.output_dir
        os.makedirs(out_dir, exist_ok=True)
        filepath = os.path.join(out_dir, f'urlscan_{_safe_name(result.url)}_{int(time.time())}.json')
    data = {
        'url': result.url,
        'final_url': result.final_url,
        'status_code': result.status_code,
        'reason': result.reason,
        'server_headers': result.server_headers,
        'redirect_chain': result.redirect_chain,
        'redirect_to_external': result.redirect_to_external,
        'resolved_ips': result.resolved_ips,
        'page_title': result.page_title,
        'content_type': result.content_type,
        'page_size': result.page_size,
        'fetch_error': result.fetch_error,
        'is_php': result.is_php,
        'phpinfo_exposed': result.phpinfo_exposed,
        'webshell_indicators': result.webshell_indicators,
        'malicious_iframes': result.malicious_iframes,
        'obfuscated_scripts': result.obfuscated_scripts,
        'drive_by_downloads': result.drive_by_downloads,
        'phishing_indicators': result.phishing_indicators,
        'social_engineering': result.social_engineering,
        'data_theft': result.data_theft,
        'crypto_mining': result.crypto_mining,
        'php8_webshell': result.php8_webshell,
        'command_output_leak': result.command_output_leak,
        'suspicious_links': result.suspicious_links,
        'external_scripts': result.external_scripts,
        'ioc_hits': result.ioc_hits,
        'all_findings': result.all_findings,
        'dynamic_used': result.dynamic_used,
        'dynamic_error': result.dynamic_error,
        'dynamic_engine': result.dynamic_engine,
        'dynamic_events': result.dynamic_events,
        'dynamic_requests': result.dynamic_requests,
        'dynamic_console': result.dynamic_console,
        'dynamic_downloads': result.dynamic_downloads,
        'dynamic_screenshots': result.dynamic_screenshots,
        'dynamic_resources': result.dynamic_resources,
        'dom_injected': result.dom_injected,
        'risk_score': result.risk_score,
        'risk_level': result.risk_level,
        'summary': result.summary,
        'scan_duration': result.scan_duration,
        'scanned_at': result.scanned_at,
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return filepath
