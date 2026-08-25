#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量/URL 扫描索引生成器 — 轻量 HTML 索引页

只依赖标准库 os / time / html，不导入任何项目模块。
所有动态字符串均经过 html.escape 处理。
"""
import html
import os
import time


def _esc(s):
    """HTML 转义所有动态字符串"""
    if s is None:
        return ''
    return html.escape(str(s), quote=True)


def _risk_color(risk):
    return {
        'critical': '#dc2626',
        'high': '#ef4444',
        'medium': '#f59e0b',
        'low': '#22c55e',
        'unknown': '#6b7280',
    }.get(str(risk or 'unknown').lower(), '#6b7280')


def _page(title, heading, rows_html, table_headers):
    return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Microsoft YaHei','Segoe UI',Arial,sans-serif;background:#0f172a;padding:24px;color:#e2e8f0;line-height:1.6}}
.container{{max-width:1100px;margin:0 auto;background:#1e293b;border-radius:14px;box-shadow:0 8px 40px rgba(0,0,0,0.5);overflow:hidden;border:1px solid #334155}}
.header{{background:linear-gradient(135deg,#1e3a5f 0,#312e81 100%);padding:26px 32px}}
.header h1{{font-size:20px;font-weight:800;margin-bottom:6px}}
.header .meta{{font-size:12px;color:#94a3b8}}
.content{{padding:24px 28px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#0f172a;padding:10px 14px;text-align:left;font-weight:700;color:#94a3b8;border-bottom:2px solid #334155;font-size:11px;text-transform:uppercase;letter-spacing:0.5px}}
td{{padding:9px 14px;border-bottom:1px solid #1e293b;color:#cbd5e1}}
tr:hover td{{background:rgba(99,102,241,0.08)}}
.badge{{display:inline-block;padding:3px 12px;border-radius:12px;font-size:11px;font-weight:700;color:#fff;text-transform:uppercase}}
a{{color:#60a5fa;text-decoration:none}}
a:hover{{text-decoration:underline}}
.muted{{color:#64748b;font-size:12px}}
</style>
</head>
<body>
<div class="container">
<div class="header"><h1>{_esc(heading)}</h1><div class="meta">{_esc(title)} · {_esc(time.strftime('%Y-%m-%d %H:%M:%S'))}</div></div>
<div class="content">
<table><thead><tr>{table_headers}</tr></thead><tbody>
{rows_html}
</tbody></table>
</div>
</div>
</body>
</html>'''


def _find_report_html(output_dir, scan_id):
    """查找 scan_id 对应的 HTML 报告相对链接。

    优先匹配 report_<scan_id>_*.html，其次匹配 <scan_id>_*.html，
    最后回退旧命名 <scan_id>.html。
    """
    if not scan_id:
        return ''
    try:
        names = set(os.listdir(output_dir))
    except OSError:
        return ''
    candidates = [n for n in names if n.endswith('.html') and n.startswith(f'report_{scan_id}_')]
    if not candidates:
        candidates = [n for n in names if n.endswith('.html') and n.startswith(f'{scan_id}_')]
    if not candidates and f'{scan_id}.html' in names:
        return f'{scan_id}.html'
    if not candidates:
        return ''
    newest = max(candidates, key=lambda n: os.path.getmtime(os.path.join(output_dir, n)))
    return newest


def _safe_url_stem(url):
    """从 URL 生成 url_report_generator 同风格的安全文件名字干（不导入项目模块）"""
    name = str(url or '')
    if '://' in name:
        name = name.split('://', 1)[1]
    illegal = set('<>:"/\\|?*')
    cleaned = ''.join('_' if (c in illegal or ord(c) < 32) else c for c in name)
    cleaned = cleaned.strip('._')
    return cleaned[:40] or 'url'


def _find_urlscan_html(output_dir, url):
    """按 URL 安全名查找已有的 urlscan_*.html 报告"""
    if not url:
        return ''
    stem = _safe_url_stem(url)
    try:
        names = [n for n in os.listdir(output_dir)
                 if n.endswith('.html') and n.startswith(f'urlscan_{stem}_')]
    except OSError:
        return ''
    if not names:
        return ''
    newest = max(names, key=lambda n: os.path.getmtime(os.path.join(output_dir, n)))
    return newest


def _batch_rows(output_dir, results):
    rows = []
    for file_path, report in (results or []):
        fname = os.path.basename(str(file_path or ''))
        if report is None:
            rows.append({
                'name': fname,
                'risk': '失败',
                'color': '#6b7280',
                'scan_id': '-',
                'summary': '分析失败或无报告',
                'link': '',
            })
            continue
        scan_id = str(getattr(report, 'scan_id', '') or '')
        risk = str(getattr(report, 'risk_level', 'low') or 'low').lower()
        score = int(getattr(report, 'risk_score', 0) or 0)
        link = _find_report_html(output_dir, scan_id) if scan_id else ''
        summary = str(getattr(report, 'summary', '') or '')
        rows.append({
            'name': fname,
            'risk': f'{risk.upper()} {score}',
            'color': _risk_color(risk),
            'scan_id': scan_id,
            'summary': summary[:240],
            'link': link,
        })
    return rows


def generate_batch_index(output_dir, results) -> str:
    """生成批量扫描索引 batch_index_<timestamp>.html 并返回文件路径。

    results: [(file_path, report_or_None), ...]
    """
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f'batch_index_{int(time.time())}.html')
    rows = _batch_rows(output_dir, results)
    trs = []
    for r in rows:
        name_html = f'<a href="{_esc(r["link"])}">{_esc(r["name"])}</a>' if r['link'] else _esc(r['name'])
        trs.append(
            f'<tr><td>{name_html}</td>'
            f'<td><span class="badge" style="background:{r["color"]}">{_esc(r["risk"])}</span></td>'
            f'<td>{_esc(r["scan_id"])}</td>'
            f'<td>{_esc(r["summary"])}</td></tr>'
        )
    table_headers = '<th>样本文件</th><th>风险</th><th>扫描ID</th><th>摘要</th>'
    doc = _page(
        '批量扫描索引',
        '批量扫描索引',
        '\n'.join(trs) or '<tr><td colspan="4" class="muted">无结果</td></tr>',
        table_headers,
    )
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(doc)
    return out_path


def _url_rows(output_dir, url_results):
    rows = []
    for r in (url_results or []):
        if isinstance(r, dict):
            url = str(r.get('url', '') or '')
            risk = str(r.get('risk_level', 'low') or 'low').lower()
            score = int(r.get('risk_score', 0) or 0)
            summary = str(r.get('summary', '') or '')
        else:
            url = str(getattr(r, 'url', '') or '')
            risk = str(getattr(r, 'risk_level', 'low') or 'low').lower()
            score = int(getattr(r, 'risk_score', 0) or 0)
            summary = str(getattr(r, 'summary', '') or '')
        link = _find_urlscan_html(output_dir, url)
        rows.append({
            'url': url,
            'risk': f'{risk.upper()} {score}',
            'color': _risk_color(risk),
            'summary': summary[:240],
            'link': link,
        })
    return rows


def generate_url_index(output_dir, url_results) -> str:
    """生成 URL 扫描索引 url_index_<timestamp>.html 并返回文件路径。

    url_results: URLScanResult 对象或 dict 列表。
    链接到同目录下已有的 urlscan_*.html 文件。
    """
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f'url_index_{int(time.time())}.html')
    rows = _url_rows(output_dir, url_results)
    trs = []
    for r in rows:
        url_html = f'<a href="{_esc(r["link"])}">{_esc(r["url"][:160])}</a>' if r['link'] else _esc(r['url'][:160])
        trs.append(
            f'<tr><td>{url_html}</td>'
            f'<td><span class="badge" style="background:{r["color"]}">{_esc(r["risk"])}</span></td>'
            f'<td>{_esc(r["summary"])}</td></tr>'
        )
    table_headers = '<th>URL</th><th>风险</th><th>摘要</th>'
    doc = _page(
        'URL 扫描索引',
        'URL 挂马扫描索引',
        '\n'.join(trs) or '<tr><td colspan="3" class="muted">无结果</td></tr>',
        table_headers,
    )
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(doc)
    return out_path
