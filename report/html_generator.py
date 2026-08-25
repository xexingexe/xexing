#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTML 报告生成器 — 富交互版，含思维导图、MITRE矩阵、反混淆徽章等"""

import os
import json
from datetime import datetime

from logger import get_logger
from analyzer.models import AnalysisReport
from version import APP_VERSION, APP_AUTHOR

logger = get_logger('report.html')

try:
    from config import CONFIG
except ImportError:
    CONFIG = None


def _esc(s):
    if s is None:
        return ''
    return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')

def _safe_join(items, sep=', '):
    """Safe join that filters None and converts all items to str"""
    if not items:
        return ''
    return sep.join(str(x) for x in items if x is not None)


class HTMLReportGenerator:
    """生成结构化的富交互 HTML 恶意软件分析报告"""

    def __init__(self, output_dir="reports"):
        if CONFIG and hasattr(CONFIG, 'report') and CONFIG.report.output_dir:
            self.output_dir = CONFIG.report.output_dir
        else:
            self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, report: AnalysisReport, filepath: str = None, web_state=None) -> str:
        # 执行期截图复制到报告同目录 (HTML 相对路径引用)
        try:
            if report.dynamic and report.dynamic.screenshots:
                report_dir = os.path.dirname(filepath) if filepath else self.output_dir
                os.makedirs(report_dir, exist_ok=True)
                for sp in list(report.dynamic.screenshots):
                    if os.path.exists(sp) and os.path.basename(sp) not in os.listdir(report_dir):
                        import shutil
                        shutil.copy2(sp, os.path.join(report_dir, os.path.basename(sp)))
        except Exception:
            pass
        html = self._build_html(report)
        if filepath is None:
            filepath = os.path.join(self.output_dir, f"report_{report.scan_id}.html")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        logger.info(f"报告已保存至 {filepath}")
        if web_state is not None:
            try:
                web_state.set_done(
                    html, scan_id=report.scan_id,
                    file_name=report.file_info.name if report.file_info else ''
                )
            except Exception:
                pass
        return filepath

    def _build_html(self, report):
        fi = report.file_info
        risk_levels = {'critical': '严重', 'high': '高危', 'medium': '中', 'low': '低', 'unknown': '未知'}
        risk_label = risk_levels.get(report.risk_level, '未知')
        risk_color_map = {'critical': '#dc2626', 'high': '#ef4444', 'medium': '#f59e0b', 'low': '#22c55e', 'unknown': '#6b7280'}
        risk_color = risk_color_map.get(report.risk_level, '#6b7280')

        sections = []

        # ===== 0. 分析错误/降级说明 =====
        errors = getattr(report, 'errors', None) or []
        report_errors = getattr(report, '_report_errors', '') or ''
        if errors or report_errors:
            err_items = []
            for e in errors:
                err_items.append(f'<li class="text-danger">{_esc(str(e))}</li>')
            if report_errors:
                err_items.append(f'<li class="text-danger">{_esc(str(report_errors))}</li>')
            sections.append(
                '<div class="section" style="border-left-color:#dc2626;background:rgba(220,38,38,0.06)">'
                '<h2 style="color:#fca5a5">⚠ 分析错误/降级说明</h2>'
                '<ul class="item-list">' + ''.join(err_items) + '</ul></div>'
            )

        # ===== 0.5. 压缩包子文件分析 =====
        if report.archive and report.archive.executable_files and len(report.archive.executable_files) > 1:
            child_section = self._build_archive_children_section(report)
            if child_section:
                sections.append(child_section)

        # ===== 1. 概览 =====
        overview = self._build_overview(report, risk_label, risk_color)
        if overview:
            sections.append(overview)

        # ===== 1.1. 威胁情报（多引擎）=====
        threat_section = self._build_threat_intel_section(report)
        if threat_section:
            sections.append(threat_section)

        # ===== 1.5. 行为时间线流程图 =====
        timeline_section = self._build_behavior_timeline(report)
        if timeline_section:
            sections.append(timeline_section)

        # ===== 1.55. DEP 绕过行为时间线流程图 (阶段化) =====
        dep_flow_section = self._build_dep_bypass_flow_section(report)
        if dep_flow_section:
            sections.append(dep_flow_section)

        # ===== 1.6. 深度关联图 (样本→进程→文件→网络→注册表) =====
        graph_section = self._build_association_graph(report)
        if graph_section:
            sections.append(graph_section)

        # ===== PE 结构分析 =====
        pe_section = self._build_pe_section(report)
        if pe_section:
            sections.append(pe_section)

        # ===== 2. 字符串分析 =====
        str_section = self._build_strings_section(report)
        if str_section:
            sections.append(str_section)

        # ===== 3. 反混淆检测 =====
        deob_section = self._build_deobfuscation_section(report)
        if deob_section:
            sections.append(deob_section)

        # ===== 3.5. Overlay 载荷检测 =====
        overlay_section = self._build_overlay_section(report)
        if overlay_section:
            sections.append(overlay_section)

        # ===== 3.6. Office 宏分析 (docx/xlsm/.doc — APT 投递) =====
        macro_section = self._build_macro_section(report)
        if macro_section:
            sections.append(macro_section)

        # ===== 4. 木马家族识别 =====
        family_section = self._build_family_section(report)
        if family_section:
            sections.append(family_section)

        # ===== 5. 行为检测 (MITRE ATT&CK) =====
        behavior_section = self._build_behavior_section(report)
        if behavior_section:
            sections.append(behavior_section)

        # ===== 6. 风险评分拆解 =====
        risk_detail = self._build_risk_score_detail(report)
        if risk_detail:
            sections.append(risk_detail)

        # ===== 6.5. 破坏性行为 =====
        destruction_section = self._build_destruction_section(report)
        if destruction_section:
            sections.append(destruction_section)

        # ===== 7. 释放文件 =====
        dropped_section = self._build_dropped_files_section(report)
        if dropped_section:
            sections.append(dropped_section)

        # ===== 8. 动态分析 =====
        dynamic_section = self._build_dynamic_section(report)
        if dynamic_section:
            sections.append(dynamic_section)

        # ===== 8.3. API 监控 (Frida) =====
        api_section = self._build_api_monitor_section(report)
        if api_section:
            sections.append(api_section)

        # ===== 8.5. DLL 调用监控 / API 欺骗 / 内存保护事件 =====
        dll_section = self._build_dll_watch_section(report)
        if dll_section:
            sections.append(dll_section)
        spoof_section = self._build_spoof_section(report)
        if spoof_section:
            sections.append(spoof_section)
        memprot_section = self._build_memprot_section(report)
        if memprot_section:
            sections.append(memprot_section)

        # ===== 9. 内存取证分析 =====
        memory_section = self._build_memory_section(report)
        if memory_section:
            sections.append(memory_section)

        # ===== 10. 网络分析 =====
        network_section = self._build_network_section(report)
        if network_section:
            sections.append(network_section)

        # ===== 10.5. 交互式图表 (ECharts 进程树/网络图) =====
        charts_section = self._build_charts_section(report)
        if charts_section:
            sections.append(charts_section)

        # ===== 11. 社区签名命中 =====
        community_section = self._build_community_section(report)
        if community_section:
            sections.append(community_section)

        # ===== 11.5. YARA 规则命中 =====
        yara_matches = getattr(report, '_yara_matches', None) or []
        if yara_matches:
            sections.append(self._build_yara_section(yara_matches))

        # ===== 11.6. Sigma 规则命中 =====
        sigma_matches = getattr(report, '_sigma_matches', None) or []
        if sigma_matches:
            sections.append(self._build_sigma_section(sigma_matches))

        # ===== 13. RAT/Stealer 配置提取 =====
        rat_section = self._build_rat_config_section(report)
        if rat_section:
            sections.append(rat_section)

        # ===== 13.5. 深度追踪分析 (DeepDive) =====
        deep_section = self._build_deep_dive_section(report)
        if deep_section:
            sections.append(deep_section)

        # ===== 14. 执行流程思维导图 =====
        tree_section = self._build_execution_tree_section(report)
        if tree_section:
            sections.append(tree_section)

        # ===== 15. MITRE ATT&CK 技术矩阵 =====
        mitre_section = self._build_mitre_matrix_section(report)
        if mitre_section:
            sections.append(mitre_section)

        # ===== 16. IoC 汇总 =====
        ioc_section = self._build_ioc_summary_section(report)
        if ioc_section:
            sections.append(ioc_section)

        # ===== 16.5. 关机拦截记录 =====
        shutdown_section = self._build_shutdown_section(report)
        if shutdown_section:
            sections.append(shutdown_section)

        # ===== 16.6. URL 挂马扫描 =====
        urlscan_section = self._build_urlscan_section(report)
        if urlscan_section:
            sections.append(urlscan_section)

        # ===== 17. 分析日志 =====
        log_section = self._build_log_section(report)
        if log_section:
            sections.append(log_section)

        sections_html = '\n'.join(sections)
        scan_id = _esc(report.scan_id)
        # JS 上下文中必须用 JSON 字符串转义 (HTML 转义防不了 ');alert()
        js_scan_id = json.dumps(str(report.scan_id))
        fname = _esc(fi.name if fi else 'Unknown')
        duration_str = f' | Scan: {report.analysis_duration:.1f}s' if getattr(report, 'analysis_duration', 0) else ''

        return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>恶意软件分析报告 - {scan_id}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Microsoft YaHei','Segoe UI',Arial,sans-serif;background:#0f172a;padding:20px;color:#e2e8f0;line-height:1.6;min-height:100vh}}
.container{{max-width:1320px;margin:0 auto;background:#1e293b;border-radius:16px;box-shadow:0 8px 40px rgba(0,0,0,0.5);overflow:hidden;border:1px solid #334155}}
.header{{background:linear-gradient(135deg,#1e3a5f 0,#312e81 50%,#581c87 100%);color:#f1f5f9;padding:44px 52px;position:relative;overflow:hidden}}
.header::before{{content:'';position:absolute;top:-50%;right:-20%;width:400px;height:400px;background:radial-gradient(circle,rgba(139,92,246,0.25),transparent 70%);border-radius:50%}}
.header h1{{font-size:30px;font-weight:800;margin-bottom:10px;position:relative;z-index:1}}
.header .meta{{opacity:0.85;font-size:14px;position:relative;z-index:1}}
.risk-badge{{display:inline-block;padding:5px 18px;border-radius:20px;font-size:13px;font-weight:700;margin-top:14px;position:relative;z-index:1;text-transform:uppercase;letter-spacing:0.5px}}
.content{{padding:36px 52px}}
h2{{font-size:17px;font-weight:700;margin-bottom:16px;padding-bottom:10px;border-bottom:2px solid #334155;color:#f1f5f9}}
.section{{margin-bottom:28px;padding:18px 22px;border-left:4px solid #6366f1;background:#1a2332;border-radius:0 10px 10px 0}}
.section h2{{border-bottom:none;padding-bottom:0;margin-bottom:14px;font-size:16px}}
.data-table{{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:10px}}
.data-table th{{background:#0f172a;padding:10px 14px;text-align:left;font-weight:700;color:#94a3b8;border-bottom:2px solid #334155;font-size:11px;text-transform:uppercase;letter-spacing:0.5px}}
.data-table td{{padding:9px 14px;border-bottom:1px solid #1e293b;color:#cbd5e1}}
.data-table tr:hover td{{background:rgba(99,102,241,0.08)}}
.hash{{font-family:'Cascadia Code','Fira Code',Consolas,monospace;font-size:12px;word-break:break-all;color:#94a3b8}}
.hash.small{{font-size:11px}}
.path-cell{{font-family:'Cascadia Code','Fira Code',Consolas,monospace;font-size:12px;max-width:400px;word-break:break-all}}
.ent-high{{color:#fca5a5;font-weight:700}}
.ent-med{{color:#fcd34d;font-weight:600}}
.small{{font-size:11px;color:#64748b}}
.suspicious{{background:rgba(239,68,68,0.08)!important}}
.suspicious td{{color:#fca5a5}}
.suspicious-text{{color:#fca5a5;font-weight:500}}
.collapsible{{margin-bottom:10px;border:1px solid #334155;border-radius:10px;overflow:hidden;background:#0f172a}}
.collapsible summary{{padding:11px 18px;cursor:pointer;font-weight:600;font-size:14px;background:#1e293b;color:#e2e8f0;user-select:none;list-style:none;display:flex;align-items:center;gap:8px;border-bottom:1px solid transparent}}
.collapsible summary::-webkit-details-marker{{display:none}}
.collapsible summary::before{{content:'▶';display:inline-block;font-size:10px;transition:transform 0.2s;color:#6366f1}}
.collapsible[open] summary::before{{transform:rotate(90deg)}}
.collapsible[open] summary{{border-bottom-color:#334155}}
.collapsible .content{{padding:10px 18px 14px}}
.collapsible .content-inner{{padding:0}}
.info-grid{{display:grid;grid-template-columns:1fr 1fr;gap:6px 20px}}
.info-item{{display:flex;flex-direction:column;padding:7px 0;border-bottom:1px solid #1e293b}}
.info-item .label{{font-size:11px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:2px}}
.info-item .value{{font-size:14px;color:#e2e8f0}}
.item-list{{list-style:none;padding:0;margin:0}}
.item-list li{{padding:7px 10px;border-bottom:1px solid #1e293b;font-size:13px;color:#cbd5e1;border-radius:4px}}
.item-list li:hover{{background:rgba(99,102,241,0.06)}}
.badge{{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;margin:2px;color:#fff;font-weight:600}}
.badge-list{{display:flex;flex-wrap:wrap;gap:3px;align-items:center}}
.tag{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;margin:1px;background:#334155;color:#94a3b8;font-family:'Cascadia Code','Fira Code',Consolas,monospace}}
.risk-tag{{display:inline-block;padding:5px 14px;border-radius:8px;font-size:12px;font-weight:600;margin:3px}}
.score-grid{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}}
.score-card{{background:#0f172a;border:1px solid #334155;border-radius:10px;padding:16px;text-align:center}}
.score-card .sval{{font-size:32px;font-weight:800;line-height:1.1}}
.score-card .slbl{{font-size:11px;color:#64748b;text-transform:uppercase;margin-top:4px;letter-spacing:0.5px}}
/* IoC cards */
.ioc-summary{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}}
.ioc-card{{background:#0f172a;border:1px solid #334155;border-radius:10px;padding:14px 16px;display:flex;align-items:flex-start;gap:12px;transition:border-color 0.2s}}
.ioc-card:hover{{border-color:#6366f1}}
.ioc-card .ioc-icon{{font-size:22px;flex-shrink:0;width:40px;height:40px;display:flex;align-items:center;justify-content:center;background:#1e293b;border-radius:8px}}
.ioc-card .ioc-body{{min-width:0}}
.ioc-card .ioc-type{{font-size:10px;color:#64748b;text-transform:uppercase;font-weight:700;letter-spacing:1px}}
.ioc-card .ioc-val{{font-size:13px;color:#e2e8f0;font-family:'Cascadia Code','Fira Code',Consolas,monospace;word-break:break-all;margin-top:2px}}
/* Deobfuscation badges */
.deobf-badge{{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:20px;font-size:12px;font-weight:700;color:#fff;margin:3px}}
.deobf-badge.xor{{background:linear-gradient(135deg,#dc2626,#b91c1c)}}
.deobf-badge.b64{{background:linear-gradient(135deg,#2563eb,#1d4ed8)}}
.deobf-badge.zlib{{background:linear-gradient(135deg,#059669,#047857)}}
.deobf-badge.lolbin{{background:linear-gradient(135deg,#d97706,#b45309)}}
.deobf-badge.hex{{background:linear-gradient(135deg,#7c3aed,#6d28d9)}}
.deobf-badge.rot{{background:linear-gradient(135deg,#db2777,#be185d)}}
.deobf-preview{{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 14px;font-family:'Cascadia Code','Fira Code',Consolas,monospace;font-size:12px;color:#a5b4fc;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto;margin-top:6px}}
.deobf-key{{display:inline-block;background:#312e81;color:#c7d2fe;padding:2px 8px;border-radius:4px;font-size:11px;font-family:'Cascadia Code','Fira Code',Consolas,monospace;margin-right:4px}}
/* MITRE ATT&CK grid */
.mitre-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}}
.mitre-item{{background:#0f172a;border:1px solid;border-radius:8px;padding:10px 14px;font-size:12px;text-align:center;transition:transform 0.15s,border-color 0.15s}}
.mitre-item:hover{{transform:translateY(-2px);border-color:#6366f1}}
.mitre-item.sev-critical{{border-color:#dc2626;color:#fca5a5;background:rgba(220,38,38,0.08)}}
.mitre-item.sev-high{{border-color:#ef4444;color:#fca5a5;background:rgba(239,68,68,0.06)}}
.mitre-item.sev-medium{{border-color:#f59e0b;color:#fcd34d;background:rgba(245,158,11,0.06)}}
.mitre-item.sev-low{{border-color:#22c55e;color:#86efac;background:rgba(34,197,94,0.06)}}
/* Tree visualization */
.tree-section{{margin:0;padding:0}}
.tree-container{{font-family:'Microsoft YaHei','Segoe UI',sans-serif;font-size:13px;line-height:1.6}}
.tree-node{{margin-left:0;position:relative}}
.tree-node-content{{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;margin:3px 0;border-radius:8px;cursor:default;background:#1e293b;border:1px solid #334155;transition:all .15s;white-space:nowrap}}
.tree-node-content:hover{{background:#2d3a50;border-color:#6366f1;box-shadow:0 2px 6px rgba(99,102,241,0.2)}}
.tree-node-content.sample{{background:rgba(239,68,68,0.1);border-color:#ef4444;font-weight:700}}
.tree-node-content.process{{background:rgba(250,204,21,0.08);border-color:#facc15}}
.tree-node-content.file{{background:rgba(34,197,94,0.08);border-color:#4ade80}}
.tree-node-content.archive{{background:rgba(96,165,250,0.08);border-color:#93c5fd}}
.tree-node-content.msi{{background:rgba(168,85,247,0.08);border-color:#c4b5fd}}
.tree-node-content.suspicious{{background:rgba(239,68,68,0.1)!important;border-color:#ef4444!important;box-shadow:0 0 0 1px #ef4444}}
.tree-node-content.high-risk{{border-color:#ef4444!important}}
.tree-node-content.script{{background:rgba(236,72,153,0.08);border-color:#f472b6}}
.tree-node-content.registry{{background:rgba(239,68,68,0.07);border-color:#fb7185}}
.tree-node-icon{{font-size:16px;flex-shrink:0}}
.tree-node-label{{font-weight:600;color:#cbd5e1;font-size:12px}}
.tree-node-name{{color:#e2e8f0;font-size:12px;font-family:'Cascadia Code','Fira Code',Consolas,monospace}}
.tree-node-badge{{font-size:10px;padding:2px 8px;border-radius:999px;color:#fff;margin-left:4px}}
.tree-node-toggle{{width:16px;height:16px;display:inline-flex;align-items:center;justify-content:center;border-radius:4px;background:#334155;color:#6366f1;font-size:8px;flex-shrink:0;transition:transform .2s;cursor:pointer;user-select:none}}
.tree-node-toggle:hover{{background:#6366f1;color:#fff}}
.tree-node-toggle.leaf{{visibility:hidden}}
.tree-node-toggle.open{{transform:rotate(90deg)}}
.tree-children{{margin-left:24px;border-left:2px dashed #334155;padding-left:8px}}
.tree-children.collapsed{{display:none}}
.tree-node-content .tree-tooltip{{display:none;position:absolute;z-index:100;background:#1e293b;color:#e2e8f0;padding:8px 12px;border-radius:6px;font-size:11px;max-width:420px;white-space:normal;word-break:break-all;pointer-events:none;margin-top:32px;box-shadow:0 4px 12px rgba(0,0,0,0.5);border:1px solid #334155}}
.tree-node-content:hover .tree-tooltip{{display:block}}
/* Misc */
.footer{{text-align:center;padding:28px;color:#475569;font-size:12px;border-top:1px solid #1e293b}}
.text-danger{{color:#fca5a5}}
.text-warning{{color:#fcd34d}}
.text-success{{color:#86efac}}
.text-muted{{color:#64748b}}
code{{font-family:'Cascadia Code','Fira Code',Consolas,monospace;font-size:12px;background:rgba(99,102,241,0.1);padding:1px 5px;border-radius:3px}}
pre{{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:12px 16px;overflow-x:auto;font-family:'Cascadia Code','Fira Code',Consolas,monospace;font-size:12px;color:#cbd5e1;line-height:1.5}}
.mb-8{{margin-bottom:8px}}
.mb-12{{margin-bottom:12px}}
.mb-16{{margin-bottom:16px}}
.flex-wrap{{display:flex;flex-wrap:wrap;gap:4px;align-items:center}}
/* Sidebar */
.sidebar{{position:fixed;left:0;top:0;width:240px;height:100vh;background:#0f172a;border-right:2px solid #334155;overflow-y:auto;z-index:1000;padding:16px 0;transition:transform .3s}}
.sidebar h3{{padding:8px 20px;font-size:13px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}}
.sidebar a{{display:block;padding:8px 20px;font-size:12px;color:#94a3b8;text-decoration:none;border-left:3px solid transparent;transition:all .15s}}
.sidebar a:hover,.sidebar a.active{{color:#e2e8f0;background:rgba(99,102,241,0.1);border-left-color:#6366f1}}
.sidebar-badge{{float:right;font-size:10px;background:#334155;color:#94a3b8;padding:1px 6px;border-radius:8px}}
.sidebar-toggle{{position:fixed;left:10px;top:10px;z-index:1001;background:#1e293b;border:1px solid #334155;color:#e2e8f0;font-size:20px;padding:6px 12px;border-radius:8px;cursor:pointer;display:none}}
.main-content{{margin-left:260px;padding:20px;transition:margin-left .3s}}
/* IoC export */
.ioc-toolbar{{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}}
.ioc-btn{{padding:6px 16px;border:1px solid #334155;border-radius:8px;background:#1e293b;color:#e2e8f0;cursor:pointer;font-size:12px;font-weight:600;transition:all .15s}}
.ioc-btn:hover{{border-color:#6366f1;background:rgba(99,102,241,0.1)}}
.ioc-btn.download{{border-color:#10b981;color:#34d399}}
.ioc-btn.download:hover{{background:rgba(16,185,129,0.1)}}
/* Progress bar */
.risk-bar{{height:8px;border-radius:4px;background:#1e293b;margin:8px 0;overflow:hidden}}
.risk-bar-fill{{height:100%;border-radius:4px;transition:width .5s}}
.scroll-top{{position:fixed;right:24px;bottom:24px;width:40px;height:40px;border-radius:50%;background:#6366f1;color:#fff;border:none;cursor:pointer;font-size:18px;display:none;align-items:center;justify-content:center;z-index:999;box-shadow:0 4px 12px rgba(99,102,241,0.4)}}
@media(max-width:768px){{.content{{padding:16px}}.info-grid{{grid-template-columns:1fr}}.header{{padding:24px}}.score-grid{{grid-template-columns:1fr}}.ioc-summary{{grid-template-columns:1fr}}.sidebar{{transform:translateX(-100%)}}.sidebar.open{{transform:translateX(0)}}.sidebar-toggle{{display:block}}.main-content{{margin-left:0}}}}
</style>
</head>
<body>
<button class="sidebar-toggle" onclick="document.querySelector('.sidebar').classList.toggle('open')">☰</button>
<nav class="sidebar">
<h3>导航</h3>
<a href="#overview">概览</a>
<a href="#threat">威胁情报</a>
<a href="#timeline">行为时间线</a>
<a href="#graph">深度关联图</a>
<a href="#archive_children">压缩包内容</a>
<a href="#pe">PE 结构</a>
<a href="#strings">字符串</a>
<a href="#deobf">反混淆</a>
<a href="#overlay">附加数据</a>
<a href="#macro">宏分析</a>
<a href="#family">家族识别</a>
<a href="#behavior">行为 (MITRE)</a>
<a href="#risk">风险评分</a>
<a href="#destruction">破坏行为</a>
<a href="#dropped">释放文件</a>
<a href="#dynamic">动态分析</a>
<a href="#api">API 监控</a>
<a href="#memory">内存取证</a>
<a href="#network">网络分析</a>
<a href="#community">社区签名</a>
<a href="#yara">YARA 规则</a>
<a href="#sigma">Sigma 规则</a>
<a href="#rat">RAT 配置</a>
<a href="#deepdive">深度追踪</a><a href="#tree">执行树</a>
<a href="#mitre">MITRE 矩阵</a>
<a href="#ioc">IoC 汇总</a>
<a href="#shutdown">关机拦截</a>
<a href="#logs">分析日志</a>
</nav>
<div class="main-content">
<div class="container">
<div class="header">
<h1>恶意软件分析报告</h1>
<div class="meta">扫描ID: {scan_id} | 文件: {fname} | 风险: <span class="risk-badge" style="background:{risk_color};color:#fff">{risk_label}</span></div>
</div>
<div class="ioc-toolbar">
<button class="ioc-btn download" onclick="downloadIOCs()">下载 IoC (JSON)</button>
<button class="ioc-btn" onclick="copyIOCs()">复制 IoC 到剪贴板</button>
</div>
<div class="content">
{sections_html}
</div>
<div class="footer">生成时间: {self._now()}{duration_str} | 样本动态分析工具 v{APP_VERSION} | 程序作者: {APP_AUTHOR}</div>
</div>
</div>
<button class="scroll-top" title="回到顶部" onclick="window.scrollTo({{top:0,behavior:'smooth'}})">↑</button>
<script>
(function(){{
var toggles=document.querySelectorAll('.tree-node-toggle:not(.leaf)');
toggles.forEach(function(t){{t.addEventListener('click',function(e){{e.stopPropagation();var content=this.closest('.tree-node-content');var node=content.parentElement;var children=node.querySelector(':scope > .tree-children');if(children){{children.classList.toggle('collapsed');this.classList.toggle('open')}}}})}});

var st=document.querySelector('.scroll-top');
window.addEventListener('scroll',function(){{if(window.scrollY>400){{st.style.display='flex'}}else{{st.style.display='none'}}}});

document.querySelectorAll('.sidebar a').forEach(function(a){{a.addEventListener('click',function(e){{e.preventDefault();var target=document.querySelector(this.getAttribute('href'));if(target)target.scrollIntoView({{behavior:'smooth'}});document.querySelector('.sidebar').classList.remove('open')}})}});

function downloadIOCs(){{var iocs=[];document.querySelectorAll('.ioc-card .ioc-val').forEach(function(el){{var t=el.closest('.ioc-card').querySelector('.ioc-type').textContent;var v=el.textContent.trim();if(v)iocs.push({{type:t,value:v}})}});var blob=new Blob([JSON.stringify(iocs,null,2)],{{type:'application/json'}});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='iocs_{js_scan_id}.json';a.click()}}
function copyIOCs(){{var iocs=[];document.querySelectorAll('.ioc-card .ioc-val').forEach(function(el){{var v=el.textContent.trim();if(v)iocs.push(v)}});navigator.clipboard.writeText(iocs.join('\\n')).then(function(){{alert('IoC copied! ('+iocs.length+' items)')}}).catch(function(){{alert('Copy failed')}})}}
}})();
</script>
</body>
</html>'''

    # ========================================================================
    # Section builders
    # ========================================================================

    def _build_overview(self, report, risk_label, risk_color):
        fi = report.file_info
        if not fi:
            return ''
        items = [
            ('文件名', _esc(fi.name)),
            ('文件类型', _esc(fi.file_type)),
            ('大小', _esc(fi.size_human)),
            ('熵值', f'{fi.entropy:.2f}' if fi.entropy is not None else 'N/A'),
            ('MD5', f'<span class="hash">{_esc(fi.md5)}</span>' if fi.md5 else 'N/A'),
            ('SHA1', f'<span class="hash">{_esc(fi.sha1)}</span>' if fi.sha1 else 'N/A'),
            ('SHA256', f'<span class="hash">{_esc(fi.sha256)}</span>' if fi.sha256 else 'N/A'),
        ]
        pe = report.pe_info
        if pe:
            items += [
                ('架构', _esc(pe.architecture) if pe.architecture else 'N/A'),
                ('编译时间', _esc(pe.compile_time) if pe.compile_time else 'N/A'),
                ('入口点', _esc(pe.entry_point) if pe.entry_point else 'N/A'),
                ('映像基址', _esc(pe.image_base) if pe.image_base else 'N/A'),
                ('子系统', _esc(pe.subsystem) if pe.subsystem else 'N/A'),
                ('Imphash', f'<span class="hash">{_esc(pe.imphash)}</span>' if pe.imphash else 'N/A'),
                ('可疑特征', str(len(pe.suspicious_features)) if pe.suspicious_features else '0'),
            ]
            if pe.packer_info:
                items.append(('加壳检测', _esc('; '.join(pe.packer_info[:5]))))
            if getattr(pe, 'rich_header', None):
                rh = pe.rich_header
                rh_txt = rh.get('summary') or rh.get('tool_id') or str(rh.get('compiler', '')) or ''
                items.append(('Rich 头', _esc(str(rh_txt)[:100]) if rh_txt else '是'))
            if pe.digital_signature:
                ds = pe.digital_signature
                signer = ds.get('signer') or ds.get('subject') or ''
                valid = ds.get('valid', None)
                sign_txt = f'{signer}' if signer else '存在'
                if valid is not None:
                    sign_txt += ' (验证' + ('通过' if valid else '失败/无效') + ')'
                items.append(('数字签名', _esc(sign_txt)[:120]))
        evidence_rel = getattr(report, '_evidence_pack_rel', '') or ''
        if evidence_rel:
            items.append((
                '🧾 证据包',
                f'<a href="{_esc(evidence_rel)}" download '
                f'style="color:#34d399;font-weight:700;text-decoration:none">下载</a>'
            ))
        rows = ''.join(
            f'<div class="info-item"><div class="label">{_esc(lbl)}</div><div class="value">{val}</div></div>'
            for lbl, val in items
        )
        return f'''<div class="section" style="border-left-color:{risk_color}">
<h2 id="overview">概览</h2>
<div class="info-grid">{rows}</div>
</div>'''

    def _build_pe_section(self, report):
        pe = report.pe_info
        if not pe:
            return ''
        parts = []

        # Section table
        if pe.sections:
            sect_rows = ''
            for s in pe.sections:
                cls = 'suspicious' if getattr(s, 'is_suspicious', False) else ''
                exec_flag = 'Y' if getattr(s, 'is_executable', False) else ''
                writable = 'Y' if getattr(s, 'is_writable', False) else ''
                sect_rows += f'<tr class="{cls}"><td>{_esc(s.name)}</td><td>{s.virtual_size}</td><td>{s.raw_size}</td><td>{s.entropy:.2f}</td><td>{exec_flag}</td><td>{writable}</td></tr>'
            parts.append(self._collapsible(
                f'节区信息 ({len(pe.sections)})', 'pe_sections',
                '<table class="data-table"><thead><tr><th>节名</th><th>VirtualSize</th><th>RawSize</th><th>熵值</th><th>可执行</th><th>可写</th></tr></thead><tbody>' + sect_rows + '</tbody></table>'
            ))

        # Imports table
        if pe.imports:
            imp_rows = ''
            for imp in pe.imports[:30]:
                sus_funcs = _safe_join(imp.suspicious_functions[:5], ',') if imp.suspicious_functions else ''
                imp_rows += f'<tr><td>{_esc(imp.dll)}</td><td>{len(imp.functions)}</td><td class="suspicious-text">{_esc(sus_funcs)}</td></tr>'
            parts.append(self._collapsible(
                f'导入表 ({len(pe.imports)} DLL)', 'pe_imports',
                '<table class="data-table"><thead><tr><th>DLL</th><th>函数数</th><th>可疑函数</th></tr></thead><tbody>' + imp_rows + '</tbody></table>'
            ))

        # Exports table
        if pe.exports:
            exp_rows = ''
            for exp in pe.exports[:30]:
                exp_rows += f'<tr><td class="hash">{_esc(str(exp.address))}</td><td>{_esc(exp.name)}</td><td>{exp.ordinal}</td></tr>'
            parts.append(self._collapsible(
                f'导出表 ({len(pe.exports)})', 'pe_exports',
                '<table class="data-table"><thead><tr><th>地址</th><th>名称</th><th>序号</th></tr></thead><tbody>' + exp_rows + '</tbody></table>'
            ))

        # Resources table
        if pe.resources:
            res_rows = ''
            for r in pe.resources[:20]:
                res_rows += f'<tr><td>{_esc(r.name)}</td><td>{_esc(r.type)}</td><td>{r.size}</td></tr>'
            parts.append(self._collapsible(
                f'资源表 ({len(pe.resources)})', 'pe_resources',
                '<table class="data-table"><thead><tr><th>名称</th><th>类型</th><th>大小</th></tr></thead><tbody>' + res_rows + '</tbody></table>'
            ))

        # TLS callbacks
        if pe.tls_callbacks:
            tls_html = '<div class="info-grid">' + ''.join(
                f'<div class="info-item"><div class="label">TLS 回调</div><div class="value"><code>{_esc(cb)}</code></div></div>'
                for cb in pe.tls_callbacks
            ) + '</div>'
            parts.append(self._collapsible(
                f'TLS 回调 ({len(pe.tls_callbacks)})', 'pe_tls', tls_html
            ))

        # Suspicious features
        if pe.suspicious_features:
            sf_list = ''.join(f'<li>{_esc(f)}</li>' for f in pe.suspicious_features[:20])
            parts.append(self._collapsible(
                f'可疑特征 ({len(pe.suspicious_features)})', 'pe_suspicious',
                f'<ul class="item-list">{sf_list}</ul>'
            ))

        if not parts:
            return ''
        return '<div class="section" style="border-left-color:#6366f1"><h2 id="pe">PE 结构分析</h2>' + '\n'.join(parts) + '</div>'

    def _build_strings_section(self, report):
        st = report.strings
        if not st:
            return ''
        str_parts = []
        # 统计条数概览
        total = getattr(st, 'total_strings', 0) or 0
        counts = []
        for label, val in [('URL', st.urls), ('IP', st.ips), ('域名', st.domains),
                           ('API', st.api_calls), ('可疑', st.suspicious_strings),
                           ('PowerShell', st.powershell_patterns)]:
            if val:
                counts.append(f'{label}×{len(val)}')
        if counts:
            str_parts.append(f'<div class="info-grid"><div class="info-item"><div class="label">字符串总数</div>'
                             f'<div class="value">{total if total else "N/A"}</div></div>'
                             f'<div class="info-item"><div class="label">分类统计</div>'
                             f'<div class="value">{" / ".join(counts)}</div></div></div>')
        if st.urls:
            str_parts.append(self._collapsible(
                f'URL 列表 ({len(st.urls)})', 'str_urls',
                '<ul class="item-list">' + ''.join(f'<li class="hash">{_esc(u)}</li>' for u in st.urls[:30]) + '</ul>'
            ))
        if st.domains:
            str_parts.append(self._collapsible(
                f'域名列表 ({len(st.domains)})', 'str_domains',
                '<ul class="item-list">' + ''.join(f'<li class="hash">{_esc(d)}</li>' for d in st.domains[:30]) + '</ul>'
            ))
        if st.ips:
            str_parts.append(self._collapsible(
                f'IP 列表 ({len(st.ips)})', 'str_ips',
                '<ul class="item-list">' + ''.join(f'<li class="hash">{_esc(ip)}</li>' for ip in st.ips[:30]) + '</ul>'
            ))
        if st.api_calls:
            str_parts.append(self._collapsible(
                f'API 调用 ({len(st.api_calls)})', 'str_apis',
                '<div class="flex-wrap">' + ''.join(f'<span class="badge" style="background:#6366f1">{_esc(a)}</span>' for a in st.api_calls[:40]) + '</div>'
            ))
        if st.suspicious_strings:
            str_parts.append(self._collapsible(
                f'可疑字符串 ({len(st.suspicious_strings)})', 'str_sus',
                '<ul class="item-list">' + ''.join(f'<li class="text-danger">{_esc(s)}</li>' for s in st.suspicious_strings[:30]) + '</ul>'
            ))
        if st.powershell_patterns:
            str_parts.append(self._collapsible(
                f'PowerShell 模式 ({len(st.powershell_patterns)})', 'str_ps',
                '<ul class="item-list">' + ''.join(f'<li><code>{_esc(p)}</code></li>' for p in st.powershell_patterns[:20]) + '</ul>'
            ))
        if not str_parts:
            return ''
        return '<div class="section" style="border-left-color:#10b981"><h2 id="strings">字符串分析</h2>' + '\n'.join(str_parts) + '</div>'

    def _build_deobfuscation_section(self, report):
        deobs = getattr(report, '_deobfuscation', None)
        ps_deobs = getattr(report, '_ps_deobfuscated', None)
        if not deobs and not ps_deobs:
            return ''
        deobs = (deobs or []) + (ps_deobs or [])
        deob_parts = []
        for d in deobs:
            conf = d.get('confidence', 0)
            tech = d.get('technique', 'unknown').lower()
            key = d.get('key', '')
            preview = d.get('preview', '') or d.get('decoded', '') or ''
            # Determine badge class
            tech_class = 'hex'
            if 'xor' in tech:
                tech_class = 'xor'
            elif 'base64' in tech or 'b64' in tech:
                tech_class = 'b64'
            elif 'zlib' in tech or 'inflate' in tech:
                tech_class = 'zlib'
            elif 'lolbin' in tech or 'living' in tech:
                tech_class = 'lolbin'
            elif 'rot' in tech or 'caesar' in tech:
                tech_class = 'rot'
            elif 'hex' in tech:
                tech_class = 'hex'

            sev_color = '#dc2626' if conf >= 0.7 else '#f59e0b' if conf >= 0.4 else '#64748b'
            icon = '◆' if conf >= 0.7 else '◇' if conf >= 0.4 else '○'
            key_html = f' <span class="deobf-key">{_esc(str(key))}</span>' if key else ''
            preview_html = f'<div class="deobf-preview">{_esc(preview[:300])}</div>' if preview else ''

            deob_parts.append(f'''<div style="margin-bottom:14px">
<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
<span class="deobf-badge {tech_class}">{icon} {_esc(tech.upper())}</span>{key_html}
<span style="margin-left:auto;font-size:12px;color:{sev_color};font-weight:600">置信度 {conf:.0%}</span>
</div>
{preview_html}
</div>''')

        return '<div class="section" style="border-left-color:#7c3aed"><h2 id="deobf">反混淆检测 (' + str(len(deobs)) + ' 项)</h2>' + '\n'.join(deob_parts) + '</div>'

    def _build_family_section(self, report):
        mf = report.malware_family
        if not mf:
            return ''
        items = [
            ('主要家族', _esc(mf.primary_family)),
            ('置信度', f'{mf.primary_confidence:.0f}%' if mf.primary_confidence else 'N/A'),
            ('匹配数', f'{mf.matched_signatures}/{mf.total_rules}'),
        ]
        if mf.summary:
            items.append(('说明', _esc(mf.summary)))
        rows = ''.join(
            f'<div class="info-item"><div class="label">{_esc(lbl)}</div><div class="value">{val}</div></div>'
            for lbl, val in items
        )
        candidates = ''
        for ind in (mf.all_families or [])[:5]:
            conf = max(0, min(100, int(getattr(ind, 'confidence', 0) or 0)))
            indicators = '; '.join(_esc(str(x)[:90]) for x in (getattr(ind, 'indicators', []) or [])[:5])
            rules = '; '.join(_esc(str(x)[:90]) for x in (getattr(ind, 'matched_rules', []) or [])[:5])
            desc = _esc(getattr(ind, 'description', '') or '')
            candidates += f'''<div style="padding:10px 12px;border:1px solid #334155;border-radius:8px;margin-bottom:8px">
<div style="display:flex;align-items:center;gap:10px">
<div style="flex:1"><span style="font-size:13px;font-weight:600;color:#f1f5f9">{_esc(ind.family_name)}</span>
<span class="small hash" style="margin-left:8px">{rules or '—'}</span></div>
<div style="font-size:12px;color:#fbbf24;font-weight:600">{conf}%</div>
</div>
<div style="height:4px;background:#334155;border-radius:2px;margin:6px 0 4px">
<div style="height:4px;width:{conf}%;background:linear-gradient(90deg,#f59e0b,#ef4444);border-radius:2px"></div>
</div>
<div style="font-size:11px;color:#94a3b8">{indicators or '—'}</div>
<div style="font-size:11px;color:#64748b;margin-top:2px">{desc}</div>
</div>'''
        if candidates:
            candidates = ('<div style="font-size:12px;font-weight:600;color:#cbd5e1;margin:12px 0 6px">'
                          '候选家族证据 (按置信度排序)</div>') + candidates
        return (f'<div class="section" style="border-left-color:#ef4444"><h2 id="family">木马家族识别</h2>'
                f'<div class="info-grid">{rows}</div>{candidates}</div>')

    def _build_behavior_section(self, report):
        all_behaviors = {'高危': [], '可疑': [], '一般': []}

        def _collect(cat, items):
            if items:
                for it in items:
                    if isinstance(it, str) and it.strip():
                        all_behaviors[cat].append(it)

        ab = report.advanced_behavior
        if ab and hasattr(ab, 'ransomware_indicators'):
            _collect('高危', ab.ransomware_indicators)
            _collect('高危', ab.rootkit_indicators)
            _collect('高危', ab.bootkit_indicators)
            _collect('高危', ab.process_hollowing)
            _collect('高危', ab.wiper_indicators)
            _collect('高危', ab.file_encryption)
            vm_evasion = [s for s in ab.anti_analysis if any(k in s for k in ['VM检测', '虚拟化', 'VM detect', 'virtual', 'sandbox'])]
            _collect('高危', vm_evasion)

            _collect('可疑', ab.anti_vm)
            _collect('可疑', ab.anti_sandbox)
            _collect('可疑', ab.anti_debug)
            _collect('可疑', ab.anti_analysis)
            _collect('可疑', ab.process_injection)
            _collect('可疑', ab.privilege_escalation)
            _collect('可疑', ab.uac_bypass)
            _collect('可疑', ab.credential_theft)
            _collect('可疑', ab.keylogging)
            _collect('可疑', ab.c2_communication)
            _collect('可疑', ab.lateral_movement)
            _collect('可疑', ab.token_manipulation)
            _collect('可疑', ab.apc_injection)
            _collect('可疑', ab.thread_hijacking)
            _collect('可疑', ab.browser_data_theft)
            _collect('可疑', ab.clipboard_monitoring)
            _collect('可疑', ab.screenshot_capture)
            _collect('可疑', ab.steganography)
            _collect('可疑', ab.domain_generation)
            _collect('高危', ab.audio_surveillance)
            _collect('可疑', ab.proxy_manipulation)

            _collect('一般', ab.timing_evasion)

        # Dynamic process behaviors
        if report.dynamic:
            for p in report.dynamic.processes_created:
                if not isinstance(p, dict):
                    continue
                cmd = (p.get('cmdline', '') or '').lower()
                exe = (p.get('exe', '') or '').lower()
                name = (p.get('name', '') or '').lower()
                if not cmd or 'python.exe' in name:
                    continue
                suspicious_dirs = ['\\choco\\', '\\appdata\\', '\\public\\', '\\temp\\', '\\programdata\\', '\\windows\\temp\\']
                if any(d in exe for d in suspicious_dirs) and exe.endswith('.exe'):
                    depth = exe.count('\\')
                    if depth > 4:
                        _collect('高危', [f'从深层随机目录启动进程 {os.path.basename(exe)}'])
                if 'reg add' in cmd and ('defender' in cmd or 'exclusions' in cmd):
                    _collect('高危', ['添加 Windows Defender 排除路径'])
                if 'schtasks' in cmd:
                    _collect('高危', ['创建计划任务持久化'])
                if 'powershell' in cmd and any(x in cmd for x in ['hidden', 'bypass', '-enc', '-e ']):
                    _collect('高危', ['隐藏式 PowerShell 执行 (Bypass/编码)'])
                if any(cmd.startswith(x) for x in ['rundll32', 'regsvr32', 'mshta']):
                    _collect('高危', ['使用 LOLBins 绕过应用白名单'])
                if 'bitsadmin' in cmd or 'certutil' in cmd:
                    _collect('高危', ['使用系统工具下载载荷'])
                if 'attrib' in cmd and ('+h' in cmd or '+s' in cmd):
                    _collect('高危', ['修改文件属性为隐藏/系统'])
                if 'cmd.exe /c' in cmd:
                    _collect('可疑', ['命令行执行链 (cmd.exe /c)'])
                if ('/qn' in cmd or '/quiet' in cmd) and 'msiexec' in cmd:
                    _collect('高危', ['静默 MSI 安装'])
                if 'cscript' in cmd or 'wscript' in cmd:
                    _collect('可疑', ['脚本宿主进程 (VBS/JS)'])
                if any(x in cmd for x in ['/passive', '/quiet']):
                    _collect('可疑', ['静默安装 (无用户界面)'])

        # ===== 威胁情报/IoC 行为 =====
        if report.threat_intel:
            ti = report.threat_intel
            if ti.threat_labels and 'malicious' in ti.threat_labels:
                _collect('高危', [f'多引擎威胁情报标记为恶意 (检出率 {ti.detection_rate:.0%})' if ti.detection_rate else '多引擎威胁情报标记为恶意'])
            if ti.family and ti.family != 'Unknown':
                _collect('高危', [f'威胁情报识别家族: {ti.family} (置信度: {ti.confidence})'])
            if ti.threat_labels:
                for label in ti.threat_labels[:5]:
                    if label.lower() not in ('unknown', 'malicious', 'clean', 'undetected'):
                        _collect('可疑', [f'威胁标签: {label}'])

        # ===== 本地IoC命中行为 =====
        ioc = getattr(report, '_ioc_hits', {}) or {}
        if ioc.get('total_hits', 0) > 0:
            _collect('高危', [f'本地IoC命中: {ioc["total_hits"]} 项 (IP={len(ioc.get("ips",[]))} 域名={len(ioc.get("domains",[]))} URL={len(ioc.get("urls",[]))})'])

        # ===== YARA/Sigma/社区签名行为 =====
        yara = getattr(report, '_yara_matches', []) or []
        for y in yara[:10]:
            rule = y.get('rule', '') or y.get('name', '') or ''
            if rule:
                _collect('高危', [f'YARA规则命中: {rule}'])

        sigma = getattr(report, '_sigma_matches', []) or []
        for s in sigma[:10]:
            title = s.title if hasattr(s, 'title') else s.get('title', '') or ''
            level = s.level if hasattr(s, 'level') else s.get('level', '') or ''
            if title:
                _collect('高危' if level in ('high','critical') else '可疑', [f'Sigma规则命中[{level}]: {title}'])

        comm = getattr(report, '_community_signatures', []) or []
        for c in comm[:10]:
            sig = c.get('signature', '') or c.get('name', '') or ''
            if sig:
                _collect('可疑', [f'社区签名命中: {sig}'])

        # ===== Frida 内存保护监控 (RW→RX载荷解密/DEP绕过/ROP喷射/远程注入/反沙箱) =====
        memprot = getattr(report, '_memprot_summary', None)
        if memprot:
            if memprot.get('rw_to_rx'):
                _collect('高危', [f'RW→RX内存保护转换 ×{memprot["rw_to_rx"]} (载荷解密/执行特征)'])
            if memprot.get('rwx_alloc'):
                _collect('高危', [f'RWX内存分配 ×{memprot["rwx_alloc"]} (可写可执行, DEP绕过特征)'])
            if memprot.get('dep_bypass'):
                _collect('高危', [f'DEP绕过 (RWX分配) ×{memprot["dep_bypass"]}'])
            if memprot.get('rop_like'):
                _collect('高危', [f'DEP绕过/ROP喷射 ×{memprot["rop_like"]} (超大RWX内存分配, Shellcode喷射特征)'])
            if memprot.get('huge_alloc'):
                _collect('可疑', [f'超大内存分配 ×{memprot["huge_alloc"]} (≥256MB, 内存喷射特征)'])
            if memprot.get('injection'):
                _collect('高危', [f'远程注入API调用 ×{memprot["injection"]} (WriteProcessMemory/CreateRemoteThread)'])
            if memprot.get('enum_snapshot_count', 0) >= 20:
                _collect('可疑', [f'高频进程枚举 ×{memprot["enum_snapshot_count"]} (反沙箱行为)'])
            if memprot.get('sleep_total_ms', 0) >= 60000:
                _collect('可疑', [f'长时间睡眠 {memprot["sleep_total_ms"]/1000:.0f}s (时间规避)'])

        # ===== Frida 行为序列 (DEP绕过/七条件反沙箱/内存泄漏) =====
        if report.api_monitor:
            for _seq in (report.api_monitor.suspicious_sequences or []):
                _sl = str(_seq).lower()
                if 'dep绕过' in _sl or 'rop' in _sl:
                    _collect('高危', [_seq])
                elif 'memory allocation without release' in _sl:
                    _collect('可疑', [_seq])
                elif '七组条件' in str(_seq) or '反沙箱环境检测 ×' in str(_seq):
                    _collect('高危', [_seq])

        # ===== DLL 调用监控 (非系统DLL函数调用) =====
        dll_sum = getattr(report, '_dll_call_summary', None)
        if dll_sum:
            _collect('可疑', [f'非系统DLL函数调用 {dll_sum["total_calls"]} 次, 涉及 {len(dll_sum["functions"])} 个函数'])
            for (dll, func), _cnt in dll_sum['functions'][:5]:
                _collect('可疑', [f'DLL调用: {dll}!{func}'])
            if dll_sum.get('suspicious_dlls'):
                _collect('高危', [f'可疑DLL名: {", ".join(dll_sum["suspicious_dlls"])}'])

        # ===== 内存取证行为 =====
        if report.memory:
            mem = report.memory
            if mem.shellcode_found:
                _collect('高危', [f'内存中发现Shellcode ({len(mem.shellcode_details) if mem.shellcode_details else 0} 处)'])
            if mem.pe_in_memory:
                _collect('高危', [f'内存中发现注入PE映像 ({len(mem.pe_injected_modules) if mem.pe_injected_modules else 0} 个)'])
            if mem.rwx_regions:
                _collect('高危', [f'发现RWX可执行内存区域 ({len(mem.rwx_regions)} 个)'])
            if mem.openpgp_found:
                _collect('可疑', ['内存中检测到OpenPGP加密载荷'])
            if mem.zlib_found:
                _collect('可疑', ['内存中检测到zlib压缩载荷'])
            if mem.multi_payload:
                _collect('高危', [f'检测到复合载荷 (多类型嵌套—{len(mem.multi_payload)}层)'])
            if mem.heavens_gate:
                _collect('高危', [f"Heaven's Gate检测 ({len(mem.heavens_gate)} 处—32/64位切换)"])
            if mem.iat_hooks:
                _collect('高危', [f'IAT/EAT Hook检测 ({len(mem.iat_hooks)} 处—API劫持)'])
            if mem.peb_anomalies:
                _collect('可疑', [f'PEB异常检测 ({len(mem.peb_anomalies)} 处—调试标志/篡改)'])
            if mem.seh_overwrite:
                _collect('高危', [f'SEH覆写检测 ({len(mem.seh_overwrite)} 处—异常处理劫持)'])
            if mem.anti_dump_measures:
                _collect('可疑', [f'反Dump措施检测 ({len(mem.anti_dump_measures)} 处—内存保护对抗)'])
            if mem.api_unhooking:
                _collect('可疑', [f'API Unhooking检测 ({len(mem.api_unhooking)} 处—反Hook恢复)'])
            if mem.kernel_backdoor:
                _collect('高危', [f'内核后门检测 ({len(mem.kernel_backdoor)} 处—驱动/Rootkit)'])
            if mem.hidden_regions:
                _collect('可疑', [f'隐藏内存区域检测 ({len(mem.hidden_regions)} 处—反取证)'])
            # 进程退出诊断: 分配未释放 / 退出前 DEP 事件
            exit_diag = getattr(mem, 'exit_diagnosis', {}) or {}
            if exit_diag:
                if exit_diag.get('leaked_allocations', 0) >= 3:
                    _collect('可疑', [f'内存分配未释放: 分配×{exit_diag.get("alloc_calls", 0)} / '
                                      f'释放×{exit_diag.get("free_calls", 0)} (驻留/泄漏特征)'])
                if exit_diag.get('dep_bypass') or exit_diag.get('rop_like'):
                    _collect('高危', [f'进程退出前捕获DEP绕过/ROP喷射 ×'
                                      f'{(exit_diag.get("dep_bypass") or 0) + (exit_diag.get("rop_like") or 0)}'])
                if exit_diag.get('rw_to_rx'):
                    _collect('高危', [f'进程退出前捕获RW→RX载荷解密 ×{exit_diag.get("rw_to_rx")}'])
                if exit_diag.get('dump_files'):
                    _collect('一般', [f'已对 {len(exit_diag.get("dump_files"))} 个残留内存dump做离线取证'])
        elif report.dynamic:
            _collect('一般', ['内存取证: 目标进程已退出，无实时内存证据（详见报告内存章节的退出诊断）'])
        else:
            _collect('一般', ['内存取证: 需要开启动态分析 (--dynamic) 才能执行'])

        # ===== 网络行为 =====
        if report.network:
            net = report.network
            if net.suspicious_traffic:
                _collect('高危', [f'检测到可疑网络流量 ({len(net.suspicious_traffic)} 条)'])
            if net.tcp_connections:
                for c in net.tcp_connections[:10]:
                    if getattr(c, 'is_suspicious', False):
                        _collect('高危', [f'可疑TCP连接: {c.remote_addr}:{c.remote_port} ({getattr(c, "suspicion_reason", "可疑")})'])
            if net.dns_queries:
                for d in net.dns_queries[:10]:
                    if getattr(d, 'is_suspicious', False):
                        _collect('可疑', [f'可疑DNS查询: {d.domain} → {", ".join(d.resolved_ips) if d.resolved_ips else "未解析"}'])
            if net.tor_nodes:
                _collect('高危', [f'检测到Tor节点连接 ({len(net.tor_nodes)} 个)'])
            if net.proxy_connections:
                _collect('可疑', [f'检测到代理连接 ({len(net.proxy_connections)} 个)'])

        # ===== 破坏性行为 =====
        if report.destruction:
            d = report.destruction
            if d.destruction_level in ('destructive', 'high'):
                _collect('高危', [f'破坏性行为等级: {d.destruction_level} ({d.total_indicators} 指标)'])
            if d.mbr_access:
                _collect('高危', ['检测到MBR/引导扇区访问'])
            if d.shadow_copy_delete:
                _collect('高危', ['检测到卷影副本删除命令 (反恢复/勒索)'])
            if d.raw_disk_access:
                _collect('高危', ['检测到磁盘直接访问 (绕过文件系统)'])
            if d.firewall_disable:
                _collect('高危', ['尝试禁用Windows防火墙'])
            if d.safe_mode_override:
                _collect('可疑', ['尝试覆写安全模式启动配置'])
            if d.hosts_file_modify:
                _collect('可疑', ['尝试修改Hosts文件 (DNS劫持)'])

        # ===== 释放文件行为 =====
        if report.dropped_files and report.dropped_files.dropped_files:
            df = report.dropped_files
            _collect('高危', [f'样本释放了 {df.total_dropped} 个文件 (可执行: {df.executable_dropped}, DLL: {df.dll_dropped or 0}, 可疑: {len(df.suspicious_dropped) if df.suspicious_dropped else 0})'])
            for f in df.suspicious_dropped[:5] if df.suspicious_dropped else []:
                fname = os.path.basename(getattr(f, 'path', '') or '')
                _collect('高危', [f'可疑释放文件: {fname}'])

        # ===== RAT配置行为 =====
        rats = getattr(report, '_rat_config', []) or []
        if rats:
            _collect('高危', [f'提取到RAT/Stealer配置 ({len(rats)} 项)'])
            for r in rats[:3]:
                for k, v in r.items():
                    if any(kw in k.lower() for kw in ['c2', 'host', 'port', 'key', 'url', 'server']):
                        _collect('高危', [f'RAT配置 — {k}: {v}'])

        # ===== 反混淆/Overlay行为 =====
        deobs = getattr(report, '_deobfuscation', []) or []
        if deobs:
            _collect('可疑', [f'检测到代码混淆/编码技术 ({len(deobs)} 项)'])
        overlay = getattr(report, '_overlay_payloads', []) or []
        if overlay:
            _collect('可疑', [f'检测到PE Overlay附加载荷 ({len(overlay)} 个)'])

        # ===== 关机拦截行为 =====
        sb = getattr(report, '_shutdown_blocked', []) or []
        if sb:
            _collect('高危', [f'强制拦截关机/重启/休眠尝试 ({len(sb)} 次)'])

        # ===== 加密压缩包破解行为 =====
        if report.archive:
            arc = report.archive
            if arc.encrypted_files:
                _collect('可疑', [f'发现加密压缩包 ({len(arc.encrypted_files)} 个加密文件)'])
            if 'password:' in (arc.summary or '').lower() or '破解' in (arc.summary or ''):
                _collect('高危', [f'加密压缩包已破解 — {arc.summary}'])
            if len(arc.executable_files) > 1:
                _collect('高危', [f'压缩包含 {len(arc.executable_files)} 个可执行文件（多文件组合攻击）'])
            children = getattr(report, '_archive_child_reports', []) or []
            for c in children:
                if c.get('risk_estimate') in ('critical', 'high'):
                    _collect('高危', [f'压缩包子文件高风险: {c.get("filename","")} (评分 {c.get("risk_score",0)})'])
                if c.get('is_shellcode'):
                    _collect('高危', [f'压缩包内含疑似Shellcode载荷: {c.get("filename","")} (熵值 {c.get("entropy",0):.2f})'])
                if c.get('is_script'):
                    _collect('可疑', [f'压缩包内含恶意脚本: {c.get("filename","")}'])
            # 交叉引用检测
            cross = getattr(report, '_loaded_archive_children', []) or []
            for cf in cross:
                _collect('高危', [f'主进程动态加载了压缩包内子文件: {cf}'])
            sc_loads = getattr(report, '_archive_shellcode_loads', []) or []
            for scf in sc_loads:
                _collect('高危', [f'主进程读取/加载了压缩包内Shellcode/脚本: {scf}'])

        for cat in all_behaviors:
            all_behaviors[cat] = list(set(all_behaviors[cat]))

        if not any(all_behaviors.values()):
            return ''

        cat_config = {
            '高危': ('#dc2626', '◆', '需立即关注'),
            '可疑': ('#f59e0b', '◇', '需进一步分析'),
            '一般': ('#64748b', '○', '仅供参考'),
        }

        cat_htmls = []
        for cat in ['高危', '可疑', '一般']:
            items = all_behaviors[cat]
            if not items:
                continue
            color, icon, desc = cat_config[cat]
            items_html = ''.join(
                self._render_behavior_item(it, color, report) for it in items
            )
            cat_htmls.append(f'''<div style="margin-bottom:14px;border:1px solid {color};border-radius:8px;overflow:hidden">
<div style="padding:8px 14px;background:{color}15;font-weight:700;font-size:13px;color:{color};border-bottom:1px solid #334155">{icon} {cat}行为 ({len(items)} 项) — {desc}</div>
<div>{items_html}</div>
</div>''')

        return '<div class="section" style="border-left-color:#7c3aed"><h2 id="behavior">行为检测 (MITRE ATT&CK)</h2>' + '\n'.join(cat_htmls) + '</div>'

    def _render_behavior_item(self, text: str, color: str, report) -> str:
        """渲染单个行为项（可折叠，含上下文证据详情）"""
        text_lower = text.lower()
        evidence = []

        # ===== 文件操作证据 =====
        if any(kw in text_lower for kw in ['文件', 'file', '释放', '创建', '写入', '删除', '下载', 'dropped', 'drop']):
            if report.dropped_files and report.dropped_files.dropped_files:
                for df in report.dropped_files.dropped_files[:8]:
                    path = getattr(df, 'path', '') or ''
                    exe = getattr(df, 'is_executable', False)
                    mark = ' ⚠️可执行' if exe else ''
                    if path:
                        evidence.append(('file', _esc(path) + mark))
            if not evidence and report.dynamic and report.dynamic.files_created:
                for f in report.dynamic.files_created[:8]:
                    fpath = f['path'] if isinstance(f, dict) else f
                    evidence.append(('file', _esc(str(fpath))))

        # ===== 进程操作证据 =====
        if any(kw in text_lower for kw in ['进程', 'process', '注入', 'inject', '启动', '执行', '创建', 'explorer', '傀儡', 'hollow']):
            if report.dynamic and report.dynamic.processes_created:
                for p in report.dynamic.processes_created[:8]:
                    if isinstance(p, dict):
                        name = p.get('name', '')
                        pid = p.get('pid', '')
                        cmd = (p.get('cmdline', '') or '')[:150]
                        if name:
                            evidence.append(('process', f'{_esc(name)} (PID={pid})'))
                            if cmd and len(cmd) > 3:
                                evidence.append(('cmdline', _esc(cmd)))
            if 'notepad' in text_lower or 'svchost' in text_lower:
                for p in (report.dynamic.processes_created if report.dynamic else []):
                    name = (p.get('name', '') if isinstance(p, dict) else '').lower()
                    if 'notepad' in name or 'svchost' in name:
                        evidence.append(('injection_target', f'{_esc(name)} (PID={p.get("pid","") if isinstance(p,dict) else ""})'))

        # ===== 内存/PE/Shellcode注入证据 =====
        if any(kw in text_lower for kw in ['pe', '注入', 'inject', '内存', 'memory', 'shellcode', '反射', 'reflect', 'rwx', 'hollow']):
            if report.memory and report.memory.pe_injected_modules:
                for mod in report.memory.pe_injected_modules[:6]:
                    addr = mod.get('address', '') if isinstance(mod, dict) else getattr(mod, 'address', '')
                    mtype = mod.get('type', '') if isinstance(mod, dict) else getattr(mod, 'type', '')
                    if addr:
                        evidence.append(('virtual_address', _esc(str(addr))))
                        sz = mod.get('size', '') if isinstance(mod, dict) else ''
                        evidence.append(('  memory_type', f'PE  size: {_esc(str(sz))}  pid: {_esc(str(mod.get("pid","") if isinstance(mod,dict) else ""))}'))
            if report.memory and report.memory.rwx_regions:
                for r in report.memory.rwx_regions[:5]:
                    addr = getattr(r, 'base_address', '') or (r.get('base_address','') if isinstance(r, dict) else '')
                    sz = getattr(r, 'region_size_human', '') or getattr(r, 'region_size', '') or ''
                    if addr:
                        evidence.append(('rwx_region', f'{_esc(str(addr))}  ({_esc(str(sz))})'))
            if report.memory and report.memory.shellcode_found and report.memory.shellcode_details:
                for sc in report.memory.shellcode_details[:5]:
                    addr = sc.get('address', '') if isinstance(sc, dict) else ''
                    detail = sc.get('details', '') if isinstance(sc, dict) else ''
                    if addr:
                        evidence.append(('shellcode', f'{_esc(str(addr))} — {_esc(str(detail))}'))

        # ===== API调用证据 =====
        if any(kw in text_lower for kw in ['hook', '钩子', 'api', 'keylog', '键盘', '监控', 'setwindowshook', 'setwindow', 'clipboard', '剪贴板', '截图', 'screenshot', '加密', 'encrypt', 'crypt', '凭证', 'credential', 'token', '令牌', 'lsass', 'dump', '提权', '特权']):
            # 按行为类型选证据 API, 不再一刀切包含 reg/ntcreate —
            # 曾导致“AdjustTokenPrivileges 提权”的详情里展示 RegOpenKeyExW/NtCreateSection
            _api_filters = []
            _tl = text_lower
            if any(k in _tl for k in ('adjusttoken', '提权', '特权', 'token')):
                _api_filters += ['adjusttoken', 'openprocesstoken', 'lookupprivilege',
                                 'impersonate', 'duplicatetoken', 'settoken']
            if any(k in _tl for k in ('hook', '钩子', 'keylog', '键盘', 'setwindow')):
                _api_filters += ['setwindowshook', 'getkeystate', 'getasynckeystate',
                                 'openclipboard', 'getclipboarddata']
            if any(k in _tl for k in ('截图', 'screenshot', 'bitblt', 'createdc')):
                _api_filters += ['bitblt', 'createdc']
            if any(k in _tl for k in ('加密', 'encrypt', 'crypt')):
                _api_filters += ['crypt']
            if any(k in _tl for k in ('凭证', 'credential', 'lsass', 'dump')):
                _api_filters += ['lsass', 'credential', 'crypt', 'openprocess']
            if any(k in _tl for k in ('注入', 'inject', 'section', 'hollow', 'remote thread')):
                _api_filters += ['openprocess', 'createremotethread', 'virtualallocex',
                                 'writeprocessmemory', 'setthreadcontext', 'queueuserapc',
                                 'ntmap', 'ntunmap', 'ntcreate']
            if not _api_filters:
                _api_filters = ['setwindowshook', 'getkeystate', 'getasynckeystate',
                                'openclipboard', 'getclipboarddata', 'bitblt', 'createdc',
                                'crypt', 'lsass', 'openprocess', 'createremotethread',
                                'virtualallocex', 'writeprocessmemory', 'setthreadcontext',
                                'queueuserapc', 'adjusttoken', 'openprocesstoken',
                                'lookupprivilege']
            shown = 0
            if report.api_monitor and report.api_monitor.call_records:
                for r in report.api_monitor.call_records:
                    if shown >= 8:
                        break
                    api = r.api_name if hasattr(r, 'api_name') else ''
                    args = _safe_join(r.arguments[:4]) if hasattr(r, 'arguments') and r.arguments else ''
                    ts = r.timestamp if hasattr(r, 'timestamp') else ''
                    cat = r.category if hasattr(r, 'category') else ''
                    # 只展示与该行为直接相关的 API
                    if api and any(k in api.lower() for k in _api_filters):
                        evidence.append(('API', _esc(api)))
                        if args:
                            evidence.append(('  arguments', _esc(args[:200])))
                        shown += 1

        # ===== 网络/C2证据（扩展） =====
        if any(kw in text_lower for kw in ['网络', 'c2', '通信', '连接', 'connect', 'network', 'http', 'socket', 'dns', 'url', 'tor', 'proxy', '代理']):
            if report.network and report.network.tcp_connections:
                for c in report.network.tcp_connections[:5]:
                    remote = f'{_esc(c.remote_addr)}:{c.remote_port}'
                    sent = c.bytes_sent or 0
                    recv = c.bytes_recv or 0
                    traffic = f'{sent//1024}KB↑/{recv//1024}KB↓' if (sent+recv)>0 else ''
                    evidence.append(('remote', f'{remote} ({c.protocol}) {traffic}'))
            if report.network and report.network.dns_queries:
                for d in report.network.dns_queries[:5]:
                    ips = _safe_join(d.resolved_ips) if d.resolved_ips else ''
                    evidence.append(('dns', f'{_esc(d.domain)} → {_esc(ips)}'))
            if report.network and report.network.http_requests:
                for h in report.network.http_requests[:3]:
                    evidence.append(('http', f'{h.method} {_esc(h.host)}{_esc(h.path[:60])}'))
            if report.network and report.network.tor_nodes:
                evidence.append(('tor', _safe_join(report.network.tor_nodes[:5])))
            if report.network and report.network.suspicious_traffic:
                for st in report.network.suspicious_traffic[:5]:
                    typ = st.get('type', '') if isinstance(st, dict) else ''
                    detail = st.get('detail', '') if isinstance(st, dict) else ''
                    evidence.append(('suspicious_traffic', f'{_esc(str(typ))}: {_esc(str(detail))}'))

        # ===== YARA/Sigma证据 =====
        if any(kw in text_lower for kw in ['yara', 'sigma', '签名', 'signature', '规则命中']):
            yara = getattr(report, '_yara_matches', []) or []
            for y in yara[:5]:
                rule = y.get('rule', '') or y.get('name', '') or ''
                desc = y.get('description', '') or ''
                if rule:
                    evidence.append(('yara', f'{_esc(rule)} — {_esc(desc)}'))
            sigma = getattr(report, '_sigma_matches', []) or []
            for s in sigma[:5]:
                title = s.title if hasattr(s, 'title') else s.get('title', '') or ''
                if title:
                    evidence.append(('sigma', _esc(title)))

        # ===== 威胁情报证据 =====
        if any(kw in text_lower for kw in ['威胁情报', 'threat intel', '标记为恶意', '检出率', '家族:']):
            if report.threat_intel:
                ti = report.threat_intel
                evidence.append(('threat_labels', _safe_join(ti.threat_labels[:5])))
                if ti.family and ti.family != 'Unknown':
                    evidence.append(('family', f'{ti.family} (置信度: {ti.confidence})'))
                if ti.engine_results:
                    for eng in ti.engine_results[:5]:
                        if isinstance(eng, dict):
                            result = eng.get('result', {}) or {}
                            if result.get('hit'):
                                evidence.append(('engine', f'{eng.get("engine","")} → 命中'))

        # ===== IoC命中证据 =====
        if any(kw in text_lower for kw in ['ioc', '命中']):
            ioc = getattr(report, '_ioc_hits', {}) or {}
            for item in ioc.get('ips', [])[:5]:
                evidence.append(('ioc_ip', f'{_esc(str(item.get("ip","") or item))} — {_esc(str(item.get("family","") or ""))}'))
            for item in ioc.get('domains', [])[:5]:
                evidence.append(('ioc_domain', f'{_esc(str(item.get("domain","") or item))} — {_esc(str(item.get("family","") or ""))}'))

        # ===== RAT配置证据 =====
        if any(kw in text_lower for kw in ['rat', '配置', 'config', 'stealer']):
            rats = getattr(report, '_rat_config', []) or []
            for r in rats[:5]:
                for k, v in r.items():
                    evidence.append(('config', f'{_esc(str(k))}: {_esc(str(v)[:100])}'))

        # ===== 反混淆/Overlay证据 =====
        if any(kw in text_lower for kw in ['混淆', '编码', 'overlay', '附加载荷', 'deobfuscat']):
            deobs = getattr(report, '_deobfuscation', []) or []
            for d in deobs[:5]:
                tech = d.get('technique', '') or ''
                conf = d.get('confidence', 0) or 0
                evidence.append(('deobf', f'{_esc(str(tech))} (置信度 {conf:.0%})'))
            overlay = getattr(report, '_overlay_payloads', []) or []
            for ov in overlay[:3]:
                evidence.append(('overlay', f'offset={_esc(str(ov.get("offset","?")))} size={_esc(str(ov.get("size","?")))}'))

        # ===== 注册表证据 =====
        if any(kw in text_lower for kw in ['注册表', 'registry', 'reg', 'run键', '持久化', 'persist', 'uac', '服务', 'service', 'defender', '排除', '防火墙', 'firewall']):
            sr = report.dynamic.sandbox_result if report.dynamic else None
            if sr:
                for r_key in (sr.registry_created or [])[:8]:
                    evidence.append(('registry', _esc(r_key)))
                for r_key in (sr.registry_modified or [])[:8]:
                    evidence.append(('registry(mod)', _esc(r_key)))
            if report.dynamic and report.dynamic.registry_modified:
                for r in report.dynamic.registry_modified[:5]:
                    key = r.get('key', '') if isinstance(r, dict) else getattr(r, 'key', '')
                    if key:
                        evidence.append(('registry', _esc(str(key))))

        # ===== 破坏性行为证据 =====
        if any(kw in text_lower for kw in ['破坏', 'destruction', 'mbr', '勒索', 'ransomware', '删除备份', '删备份', '卷影', 'shadow', '杀软', 'av', 'edr', 'terminat', '终止']):
            d = report.destruction
            if d:
                if d.mbr_access: evidence.append(('mbr_access', '检测到MBR访问'))
                if d.shadow_copy_delete: evidence.append(('shadow_copy', '检测到卷影副本删除命令'))
                if d.mbr_write_commands: evidence.append(('mbr_write', _safe_join(d.mbr_write_commands[:3])))
                if d.backup_delete_commands: evidence.append(('backup_delete', _safe_join(d.backup_delete_commands[:3])))
                if d.av_termination: evidence.append(('av_termination', _safe_join(d.av_termination[:5])))
                if d.edr_termination: evidence.append(('edr_termination', _safe_join(d.edr_termination[:5])))
                if d.firewall_disable: evidence.append(('firewall', '防火墙已被禁用'))
                if d.raw_disk_access: evidence.append(('raw_disk', '检测到磁盘直接访问'))

        # ===== VSS/磁盘取证证据 =====
        disk_f = getattr(report, '_disk_forensics', {}) or {}
        if disk_f:
            for k, v in disk_f.items():
                if v:
                    evidence.append(('disk_forensic', f'{k}: {_safe_join(v[:3], ", ") if isinstance(v,list) else str(v)}'))
        if getattr(report, '_vss_deleted', False):
            evidence.append(('vss', '卷影副本已被删除（勒索行为特征）'))

        # ===== 反VM/沙箱环境检测证据 =====
        if any(kw in text_lower for kw in ['vm', '沙箱', 'sandbox', '虚拟机', '反vm', 'anti-vm', 'anti-sandbox', '反沙箱', '调试', 'debug', '反调试']):
            # 从动态分析中提取环境检测证据
            if report.dynamic and report.dynamic.processes_created:
                for p in report.dynamic.processes_created[:3]:
                    if isinstance(p, dict):
                        cmd = (p.get('cmdline', '') or '').lower()
                        if any(k in cmd for k in ['vm', 'sandbox', 'debug', 'virtual']):
                            evidence.append(('cmdline', _esc(cmd[:150])))

        # ===== 通用：如果没有具体证据，尝试从动态日志中提取 =====
        if not evidence and report.dynamic:
            dyn = report.dynamic
            if dyn.processes_created:
                for p in dyn.processes_created[:3]:
                    if isinstance(p, dict):
                        evidence.append(('process', _esc(p.get('name', '') or '')))
                        cmd = (p.get('cmdline', '') or '')[:150]
                        if cmd:
                            evidence.append(('  cmdline', _esc(cmd)))
            if dyn.files_created and not evidence:
                for f in dyn.files_created[:3]:
                    fpath = f['path'] if isinstance(f, dict) else f
                    evidence.append(('file', _esc(str(fpath))))

        uid = abs(hash(text)) % 1000000

        if not evidence:
            return f'<div style="padding:5px 10px;border-bottom:1px solid #1e293b;font-size:13px;color:#cbd5e1">{_esc(text)}</div>'

        ev_html = '\n'.join(
            f'<div style="font-size:12px;padding:2px 0"><b style="color:#64748b">{_esc(kind)}:</b> <span class="hash small" style="color:#94a3b8">{_esc(str(val))}</span></div>'
            for kind, val in evidence
        )

        return f'''<details class="collapsible bh-item" style="margin:0;border:none;border-bottom:1px solid #1e293b;border-radius:0;background:transparent" id="bh{uid}">
<summary style="padding:7px 10px;font-size:13px;color:#cbd5e1;background:transparent;border:none">{_esc(text)}</summary>
<div class="content" style="padding:0 14px 10px 28px">
{ev_html}
</div>
</details>'''

    def _build_risk_score_detail(self, report):
        risk_items = []
        fi = report.file_info
        if fi and fi.entropy and fi.entropy > 7.5:
            risk_items.append(('高熵值', f'{fi.entropy:.2f}', '#dc2626'))
        elif fi and fi.entropy and fi.entropy > 6.5:
            risk_items.append(('中熵值', f'{fi.entropy:.2f}', '#f59e0b'))
        pe = report.pe_info
        if pe and pe.suspicious_features:
            for sf in pe.suspicious_features[:5]:
                risk_items.append(('PE 可疑', _esc(sf[:60]), '#f59e0b'))
        if report.strings and report.strings.suspicious_strings:
            risk_items.append(('可疑字符串', f'{len(report.strings.suspicious_strings)} 个', '#f59e0b'))
        if report.malware_family and report.malware_family.matched_signatures > 0:
            risk_items.append(('特征匹配', str(report.malware_family.matched_signatures), '#dc2626'))
        destruction = report.destruction
        if destruction:
            if getattr(destruction, 'edr_termination', None):
                risk_items.append(('终止EDR', '是', '#dc2626'))
            if getattr(destruction, 'defender_registry_disable', None):
                risk_items.append(('禁用Defender', '是', '#dc2626'))
            if getattr(destruction, 'av_install_block', None):
                risk_items.append(('禁装杀软', str(len(destruction.av_install_block)), '#dc2626'))
            if getattr(destruction, 'firewall_disable', False):
                risk_items.append(('禁用防火墙', '是', '#dc2626'))
            if getattr(destruction, 'raw_disk_access', False):
                risk_items.append(('磁盘直接访问', '是', '#dc2626'))
            if getattr(destruction, 'dangerous_driver_load', None):
                risk_items.append(('加载危险驱动', '是', '#dc2626'))
        mem = report.memory
        if mem and mem.rwx_regions:
            risk_items.append(('RWX 内存', str(len(mem.rwx_regions)), '#dc2626'))
        if mem and mem.shellcode_found:
            risk_items.append(('shellcode', '是', '#dc2626'))

        breakdown = getattr(report, '_risk_breakdown', None) or {}
        breakdown_items = []
        has_breakdown = isinstance(breakdown, dict)
        if has_breakdown:
            breakdown_items = (breakdown.get('items') or [])[:30]
        if not risk_items and not breakdown_items and not has_breakdown:
            return ''
        tags = ''.join(
            f'<div class="info-item" style="border-left:3px solid {c}"><div class="label">{_esc(l)}</div><div class="value" style="color:{c}">{v}</div></div>'
            for l, v, c in risk_items
        )
        breakdown_html = ''
        if has_breakdown:
            rows = ''
            for it in breakdown_items:
                if not isinstance(it, dict):
                    continue
                cat = _esc(str(it.get('category', '')))
                try:
                    pts = int(it.get('score', 0))
                except (TypeError, ValueError):
                    pts = 0
                det = _esc(str(it.get('detail', '')))
                rows += f'<tr><td>{cat}</td><td>{pts}</td><td>{det}</td></tr>'
            if not rows:
                rows = '<tr><td colspan="3" style="color:#64748b">本次未产生可计分风险因子</td></tr>'
            total = breakdown.get('total', report.risk_score or 0) if has_breakdown else (report.risk_score or 0)
            try:
                total = int(total)
            except (TypeError, ValueError):
                total = 0
            rows += f'<tr style="font-weight:700"><td>总分</td><td>{total}</td><td>加权合计</td></tr>'
            breakdown_html = ('<table class="data-table"><thead><tr><th>维度</th><th>得分</th><th>说明</th></tr></thead><tbody>'
                              + rows + '</tbody></table>')
        score = report.risk_score or 0
        level_colors = {'critical': '#dc2626', 'high': '#ef4444', 'medium': '#f59e0b', 'low': '#22c55e', 'unknown': '#6b7280'}
        lc = level_colors.get(report.risk_level, '#6b7280')
        return f'''<div class="section" style="border-left-color:{lc}">
<h2 id="risk">风险评分拆解 ({len(risk_items)} 项)</h2>
<div class="score-grid">
<div class="score-card" style="border-color:{lc}"><div class="sval" style="color:{lc}">{score}</div><div class="slbl">风险评分</div></div>
<div class="score-card"><div class="sval" style="color:{lc}">{report.risk_level.upper()}</div><div class="slbl">风险等级</div></div>
<div class="score-card"><div class="sval" style="color:#94a3b8">{len(risk_items)}</div><div class="slbl">风险因子</div></div>
</div>
<div class="flex-wrap" style="margin-top:14px">{tags}</div>
{breakdown_html}
</div>'''

    def _build_destruction_section(self, report):
        destruction = report.destruction
        if not destruction:
            return ''
        items = [
            ('破坏等级', _esc(destruction.destruction_level) if getattr(destruction, 'destruction_level', None) else '无'),
            ('MBR 访问', '是' if destruction.mbr_access else '否'),
            ('卷影副本删除', '是' if destruction.shadow_copy_delete else '否'),
            ('备份删除', str(len(destruction.backup_delete_commands) if destruction.backup_delete_commands else 0)),
            ('终止杀软', str(len(destruction.av_termination) if destruction.av_termination else 0)),
            ('终止 EDR', str(len(destruction.edr_termination) if destruction.edr_termination else 0)),
            ('禁用 Defender 注册表', str(len(destruction.defender_registry_disable) if destruction.defender_registry_disable else 0)),
            ('禁装杀软(禁用安装/更新服务)', str(len(getattr(destruction, 'av_install_block', None) or []))),
            ('禁用服务', str(len(destruction.service_disable) if destruction.service_disable else 0)),
            ('危险驱动加载', str(len(destruction.dangerous_driver_load) if destruction.dangerous_driver_load else 0)),
            ('驱动提权', '是' if getattr(destruction, 'driver_privilege_escalation', False) else '否'),
            ('防火墙禁用', '是' if getattr(destruction, 'firewall_disable', False) else '否'),
            ('损坏硬盘', '是' if getattr(destruction, 'raw_disk_access', False) else '否'),
        ]
        rows = ''.join(
            f'<div class="info-item"><div class="label">{_esc(lbl)}</div><div class="value">{val}</div></div>'
            for lbl, val in items
        )
        # 明细列表（与PDF一致: 杀软终止/EDR/Defender/危险驱动/备份删除）
        detail_parts = []
        detail_groups = [
            ('终止安全软件 (AV)', getattr(destruction, 'av_termination', None) or []),
            ('终止 EDR', getattr(destruction, 'edr_termination', None) or []),
            ('Defender 注册表禁用', getattr(destruction, 'defender_registry_disable', None) or []),
            ('禁装杀软(禁用安装/更新服务)', getattr(destruction, 'av_install_block', None) or []),
            ('危险驱动加载', getattr(destruction, 'dangerous_driver_load', None) or []),
            ('备份删除命令', getattr(destruction, 'backup_delete_commands', None) or []),
        ]
        for label, lst in detail_groups:
            if lst:
                detail_parts.append(self._collapsible(
                    f'{label} ({len(lst)})', 'dest_' + str(len(detail_parts)),
                    '<ul class="item-list">' + ''.join(f'<li class="text-danger">{_esc(str(x))[:200]}</li>' for x in lst[:15]) + '</ul>'
                ))
        return f'<div class="section" style="border-left-color:#dc2626"><h2 id="destruction">破坏性行为</h2><div class="info-grid">{rows}</div>' + '\n'.join(detail_parts) + '</div>'

    def _build_overlay_section(self, report):
        deobs = getattr(report, '_deobfuscation', None)
        if not deobs:
            return ''
        overlay_items = [d for d in deobs if isinstance(d, dict) and 'PE Overlay' in str(d.get('technique', ''))]
        if not overlay_items:
            overlay_items = [d for d in deobs if isinstance(d, dict) and d.get('type') == 'PE Overlay']
        if not overlay_items:
            return ''
        rows = ''
        for ov in overlay_items:
            offset = ov.get('offset', '?')
            size = ov.get('size', '?')
            payload = ov.get('payload', '未知')
            severity = ov.get('severity', 'low')
            sev_color = {'high': '#dc2626', 'medium': '#f59e0b', 'low': '#64748b'}.get(severity, '#64748b')
            rows += f'<div class="info-item" style="border-left:3px solid {sev_color}">'
            rows += f'<div class="label">PE Overlay (offset={offset})</div>'
            rows += f'<div class="value" style="color:{sev_color}">{_esc(str(payload))} ({size} bytes)</div></div>'
        return f'<div class="section" style="border-left-color:#f59e0b"><h2 id="overlay">Overlay 载荷检测</h2><div class="info-grid">{rows}</div></div>'

    def _build_macro_section(self, report):
        """Office 宏分析区块 (Kimsuky/银狐 APT 投递检测)"""
        macro = getattr(report, '_macro_analysis', None)
        if not macro or not macro.get('has_vba'):
            return ''
        parts = []
        container = macro.get('container', '')
        mods = macro.get('modules', [])
        autoexec = macro.get('autoexec', [])
        suspicious = macro.get('suspicious', [])
        urls = macro.get('urls', [])
        dpb = macro.get('dpb_protected', False)

        rows = f'<div class="info-item"><div class="label">VBA 宏</div><div class="value">存在 ({len(mods)} 模块)</div></div>'
        rows += f'<div class="info-item"><div class="label">容器</div><div class="value">{_esc(str(container))}</div></div>'
        _dpb_color = '#dc2626' if dpb else '#86efac'
        _dpb_text = '是 — 宏密码保护(恶意文档常见)' if dpb else '否'
        rows += f'<div class="info-item"><div class="label">DPB 伪加密</div><div class="value" style="color:{_dpb_color}">{_dpb_text}</div></div>'
        if autoexec:
            rows += f'<div class="info-item"><div class="label">自动触发</div><div class="value" style="color:#dc2626">{_esc(", ".join(autoexec))}</div></div>'
        if mods:
            rows += f'<div class="info-item"><div class="label">模块</div><div class="value">{_esc(', '.join(mods[:6]))}</div></div>'
        parts.append(f'<div class="info-grid">{rows}</div>')

        if suspicious:
            items = ''.join(f'<li class="text-danger">{_esc(s)}</li>' for s in suspicious)
            parts.append(f'<h4 style="color:#f87171;margin:10px 0 6px">恶意行为特征 ({len(suspicious)} 项)</h4>'
                         f'<ul class="item-list">{items}</ul>')
        if urls:
            items = ''.join(f'<li><span class="hash small">{_esc(u)}</span></li>' for u in urls)
            parts.append(f'<h4 style="color:#f472b6;margin:10px 0 6px">C2 / 下载 URL</h4>'
                         f'<ul class="item-list">{items}</ul>')

        risk = '高危' if (autoexec and suspicious) else '可疑'
        color = '#dc2626' if risk == '高危' else '#f59e0b'
        return (f'<div class="section" style="border-left-color:{color}"><h2 id="macro">Office 宏分析 '
                f'<span class="risk-badge" style="background:{color};color:#fff;font-size:11px">{risk}</span></h2>'
                + '\n'.join(parts) + '</div>')

    def _build_dropped_files_section(self, report):
        df = report.dropped_files
        if not df:
            return ''
        if not df.dropped_files:
            no_files = f'<div style="padding:10px;background:rgba(100,116,139,0.08);border:1px solid #334155;border-radius:8px;font-size:13px;color:#64748b">未检测到释放文件</div>'
            return '<div class="section" style="border-left-color:#8b5cf6"><h2 id="dropped">释放文件</h2>' + no_files + '</div>'
        stats_items = [
            ('总数', str(df.total_dropped)),
            ('可执行文件', str(df.executable_dropped)),
            ('DLL 文件', str(df.dll_dropped) if df.dll_dropped else '0'),
            ('脚本文件', str(df.script_dropped) if df.script_dropped else '0'),
            ('文档文件', str(df.documents_dropped) if df.documents_dropped else '0'),
            ('可疑文件', str(len(df.suspicious_dropped) if df.suspicious_dropped else 0)),
        ]
        stats_rows = ''.join(
            f'<div class="info-item"><div class="label">{_esc(lbl)}</div><div class="value">{val}</div></div>'
            for lbl, val in stats_items
        )
        stats_html = f'<div class="info-grid mb-12">{stats_rows}</div>'

        if df.summary:
            stats_html += f'<div style="padding:10px;background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.3);border-radius:8px;margin-bottom:10px;font-size:13px;color:#fcd34d">{_esc(df.summary)}</div>'

        # Main file table
        file_rows = ''
        for f in df.dropped_files[:100]:
            cls = 'suspicious' if getattr(f, 'detection', '') else ''
            exe_mark = '✓' if getattr(f, 'is_executable', False) else ''
            ent_cls = 'ent-high' if getattr(f, 'entropy', 0) > 7 else ('ent-med' if getattr(f, 'entropy', 0) > 5 else '')
            path = _esc((getattr(f, 'path', '') or '')[:80])
            abs_path = getattr(f, 'abs_path', '') or getattr(f, 'path', '') or ''
            folder = os.path.dirname(abs_path)
            if folder == '[外部]' or folder == '.':
                folder = _esc(abs_path[:80])
            else:
                folder = _esc(folder[:80])
            fname = os.path.basename(getattr(f, 'path', '') or '')
            md5_short = (f.md5 or '-')[:12]
            file_rows += f'<tr class="{cls}"><td class="path-cell">{fname}</td><td class="hash small">{_esc(folder[:60])}</td><td>{f.size}</td><td>{_esc(f.file_type)}</td><td class="{ent_cls}">{f.entropy:.2f}</td><td>{exe_mark}</td><td class="hash small">{_esc(md5_short)}</td><td class="small">{_esc(getattr(f, 'analysis_note', '') or '')}</td></tr>'

        parts = [self._collapsible(
            f'文件清单 ({len(df.dropped_files)})', 'dropped_table',
            '<table class="data-table"><thead><tr><th>文件名</th><th>所在文件夹</th><th>大小</th><th>类型</th><th>熵值</th><th>可执行</th><th>MD5</th><th>内容备注</th></tr></thead><tbody>' + file_rows + '</tbody></table>', True
        )]

        # Suspicious files detail
        if df.suspicious_dropped:
            sus_rows = ''
            for f in df.suspicious_dropped[:80]:
                fname = os.path.basename(getattr(f, 'path', '') or '')
                abs_path = getattr(f, 'abs_path', '') or getattr(f, 'path', '') or ''
                folder = os.path.dirname(abs_path)
                if folder == '[外部]' or folder == '.':
                    folder = _esc(abs_path[:80])
                else:
                    folder = _esc(folder[:60])
                md5_short = (f.md5 or '-')[:12]
                sus_rows += f'<tr><td class="path-cell">{_esc(fname)}</td><td class="hash small">{_esc(folder[:60])}</td><td>{f.size}</td><td>{_esc(f.file_type)}</td><td class="ent-high">{f.entropy:.2f}</td><td class="hash small">{_esc(md5_short)}</td></tr>'
            parts.append(self._collapsible(
                f'可疑文件详情 ({len(df.suspicious_dropped)})', 'suspicious_dropped',
                '<table class="data-table"><thead><tr><th>文件名</th><th>所在文件夹</th><th>大小</th><th>类型</th><th>熵值</th><th>MD5</th></tr></thead><tbody>' + sus_rows + '</tbody></table>', True
            ))

        
                # Archive children (内层释放文件)
        archive_children = getattr(df, 'archive_children', None) or []
        if archive_children:
            ac_rows = ''
            for ac in archive_children[:50]:
                if isinstance(ac, dict):
                    ac_name = _esc((ac.get('name', '') or '')[:80])
                    ac_size = ac.get('size', 0)
                    ac_parent = _esc((ac.get('parent', '') or '')[:60])
                    ac_rows += f'<tr><td>{ac_name}</td><td class="hash small">{ac_parent}</td><td>{ac_size}</td></tr>'
            parts.append(self._collapsible(
                f'归档内层文件 ({len(archive_children)})', 'archive_children',
                '<table class="data-table"><thead><tr><th>文件名</th><th>所属归档</th><th>大小</th></tr></thead><tbody>' + ac_rows + '</tbody></table>'
            ))

        return '<div class="section" style="border-left-color:#8b5cf6"><h2 id="dropped">释放文件</h2>' + stats_html + '\n'.join(parts) + '</div>'

    def _build_dynamic_section(self, report):
        dyn = report.dynamic
        if not dyn:
            return ''
        parts = []

        # API 监控错误警告 (attach/spawn 失败等)
        _dyn_api_err = getattr(dyn, 'api_monitor_error', '') or ''
        if _dyn_api_err:
            parts.append(
                f'<div style="padding:10px 14px;background:rgba(239,68,68,0.08);'
                f'border:1px solid rgba(239,68,68,0.3);border-radius:8px;'
                f'font-size:13px;color:#fca5a5;margin-bottom:10px">'
                f'⚠ API 监控错误: {_esc(_dyn_api_err)}</div>'
            )

        # Stats grid
        stats_items = [
            ('执行时间', f'{dyn.execution_time:.2f}s' if dyn.execution_time else 'N/A'),
            ('创建的进程', str(len(dyn.processes_created) if dyn.processes_created else 0)),
            ('创建的文件', str(len(dyn.files_created) if dyn.files_created else 0)),
            ('修改的文件', str(len(dyn.files_modified) if dyn.files_modified else 0)),
            ('DNS 查询', str(len(dyn.dns_queries) if dyn.dns_queries else 0)),
            ('网络连接', str(len(dyn.network_connections) if dyn.network_connections else 0)),
            ('互斥体', str(len(dyn.mutexes) if dyn.mutexes else 0)),
            ('注册表修改', str(len(dyn.registry_modified) if dyn.registry_modified else 0)),
            ('系统进程注入', str(len(getattr(dyn, '_system_injections', []) or []))),
        ]
        # 系统关键进程警告
        critical_pids = getattr(dyn.sandbox_result, '_critical_pids', None) if dyn.sandbox_result else None
        if critical_pids:
            stats_items.append(('<span style="color:#ef4444">⚠ 系统关键进程</span>',
                              f'<span style="color:#ef4444;font-weight:bold">{len(critical_pids)} 个 (PIDs: {",".join(str(p) for p in critical_pids)})</span>'))
        stats_rows = ''.join(
            f'<div class="info-item"><div class="label">{_esc(lbl)}</div><div class="value">{val}</div></div>'
            for lbl, val in stats_items
        )
        parts.append(f'<div class="info-grid mb-12">{stats_rows}</div>')

        # Processes table
        if dyn.processes_created:
            proc_rows = ''
            for p in dyn.processes_created[:30]:
                if isinstance(p, dict):
                    cmd = _esc((p.get('cmdline', '') or '')[:120])
                    name = _esc(p.get('name', '') or '')
                    pid = p.get('pid', '')
                    exe = _esc((p.get('exe', '') or '')[:80])
                else:
                    cmd = _esc(str(getattr(p, 'cmdline', '') or '')[:120])
                    name = _esc(str(getattr(p, 'name', '') or ''))
                    pid = getattr(p, 'pid', '')
                    exe = _esc(str(getattr(p, 'exe', '') or '')[:80])
                proc_rows += f'<tr><td>{pid}</td><td>{name}</td><td class="hash small">{exe}</td><td class="hash">{cmd}</td></tr>'
            parts.append(self._collapsible(
                f'进程列表 ({len(dyn.processes_created)})', 'dyn_procs',
                '<table class="data-table"><thead><tr><th>PID</th><th>进程名</th><th>路径</th><th>命令行</th></tr></thead><tbody>' + proc_rows + '</tbody></table>'
            ))

        # Mutexes
        if dyn.mutexes:
            parts.append(self._collapsible(
                f'互斥体 ({len(dyn.mutexes)})', 'dyn_mutex',
                '<ul class="item-list">' + ''.join(f'<li><code>{_esc(m)}</code></li>' for m in dyn.mutexes[:20]) + '</ul>'
            ))

        # Registry modified
        if dyn.registry_modified:
            reg_rows = ''
            for r in dyn.registry_modified[:20]:
                if isinstance(r, dict):
                    key = _esc(r.get('key', '') or '')
                    val = _esc(r.get('value', '') or '')
                    op = _esc(r.get('operation', '') or '')
                else:
                    key = _esc(str(getattr(r, 'key', '') or ''))
                    val = _esc(str(getattr(r, 'value', '') or ''))
                    op = _esc(str(getattr(r, 'operation', '') or ''))
                reg_rows += f'<tr><td class="hash">{key}</td><td>{val}</td><td>{op}</td></tr>'
            parts.append(self._collapsible(
                f'注册表修改 ({len(dyn.registry_modified)})', 'dyn_reg',
                '<table class="data-table"><thead><tr><th>键</th><th>值</th><th>操作</th></tr></thead><tbody>' + reg_rows + '</tbody></table>'
            ))

        # System process injection (跨进程 DLL 注入检测)
        _sys_inj = getattr(dyn, '_system_injections', []) or []
        if _sys_inj:
            inj_rows = ''
            for x in _sys_inj[:30]:
                inj_rows += (f'<tr><td>{_esc(str(x.get("pid", "")))}</td>'
                             f'<td>{_esc(x.get("process", ""))}</td>'
                             f'<td class="hash">{_esc(x.get("module", ""))}</td></tr>')
            parts.append(self._collapsible(
                f'系统进程注入 ({len(_sys_inj)})', 'dyn_inject',
                '<div style="padding:8px 0;color:#fca5a5;font-size:13px">'
                '检测到非系统目录 DLL 挂载在关键系统进程上（疑似跨进程 DLL 注入）</div>'
                '<table class="data-table"><thead><tr><th>PID</th><th>进程</th><th>注入模块</th></tr></thead><tbody>'
                + inj_rows + '</tbody></table>'
            ))

        # Files created
        if dyn.files_created:
            file_rows = ''
            for f in dyn.files_created[:100]:
                if isinstance(f, dict):
                    fpath = f.get('path', '') or ''
                    fname = _esc(os.path.basename(fpath)[:100])
                    folder = _esc(os.path.dirname(fpath)[:100])
                else:
                    fname = _esc(os.path.basename(str(f))[:100])
                    folder = _esc(os.path.dirname(str(f))[:100])
                file_rows += f'<tr><td class="path-cell">{fname}</td><td class="hash small">{folder}</td></tr>'
            parts.append(self._collapsible(
                f'创建的文件 ({len(dyn.files_created)})个', 'dyn_files',
                '<table class="data-table"><thead><tr><th>文件名</th><th>所在文件夹</th></tr></thead><tbody>' + file_rows + '</tbody></table>'
            ))

        if not parts:
            return ''
        # 执行期截图 (CAPE 同款能力)
        if dyn.screenshots:
            imgs = ''
            for i, sp in enumerate(dyn.screenshots[:8]):
                if os.path.exists(sp):
                    imgs += (f'<div style="flex:1;min-width:280px;max-width:420px">'
                             f'<img src="{_esc(os.path.basename(sp))}" loading="lazy" '
                             f'style="width:100%;border-radius:8px;border:1px solid #334155" '
                             f'title="{_esc(sp)}">'
                             f'<div class="small" style="text-align:center;margin-top:4px">截图 {i+1}</div></div>')
            if imgs:
                parts.append('<h4 style="margin:14px 0 8px">📸 执行期截图</h4>'
                             f'<div style="display:flex;flex-wrap:wrap;gap:14px">{imgs}</div>')

        # AMSI 监控 (Win11 脚本载荷)
        try:
            amsi_evts = getattr(report.api_monitor, '_amsi_events', None) or []
            if amsi_evts:
                rows = ''
                for ev in amsi_evts[:20]:
                    rows += (f'<tr><td class="hash">{_esc(ev.get("api", ""))}</td>'
                             f'<td>{ev.get("size", "")}</td>'
                             f'<td style="font-size:11px;color:#94a3b8">{_esc(ev.get("content", "")[:60])}</td>'
                             f'<td class="hash small">{_esc(ev.get("preview_b64", "")[:60])}</td></tr>')
                parts.append(self._collapsible(
                    f'AMSI 扫描监控 ({len(amsi_evts)} 事件) — 脚本引擎恶意载荷', 'dyn_amsi',
                    '<table class="data-table"><thead><tr><th>API</th><th>扫描大小</th><th>内容名</th>'
                    '<th>数据预览 (Base64)</th></tr></thead><tbody>' + rows + '</tbody></table>'))
        except Exception:
            pass

        return '<div class="section" style="border-left-color:#06b6d4"><h2 id="dynamic">动态分析</h2>' + '\n'.join(parts) + '</div>'

    def _build_api_monitor_section(self, report):
        """API 监控 (Frida) — spawn/attach 状态与 API 调用记录"""
        am = report.api_monitor
        if not am:
            return ''
        spawn_mode = bool(getattr(am, 'spawn_mode', False))
        attach_error = getattr(am, 'attach_error', '') or ''
        call_records = getattr(am, 'call_records', None) or []
        suspicious_sequences = getattr(am, 'suspicious_sequences', None) or []
        if not (spawn_mode or attach_error or call_records or suspicious_sequences):
            return ''

        parts = []
        if attach_error:
            parts.append(
                f'<div style="padding:10px 14px;background:rgba(239,68,68,0.08);'
                f'border:1px solid rgba(239,68,68,0.3);border-radius:8px;'
                f'font-size:13px;color:#fca5a5;margin-bottom:10px">'
                f'⚠ {_esc(attach_error)}</div>'
            )

        if suspicious_sequences:
            badges = ''.join(
                f'<span class="badge" style="background:#dc2626;margin:3px">{_esc(s)}</span>'
                for s in suspicious_sequences[:30]
            )
            parts.append(
                f'<div style="padding:10px 14px;background:rgba(239,68,68,0.07);'
                f'border:1px solid rgba(239,68,68,0.28);border-radius:8px;margin-bottom:10px">'
                f'<div style="font-size:13px;font-weight:600;color:#f87171;margin-bottom:6px">'
                f'⚠ 可疑行为序列 ({len(suspicious_sequences)} 项)</div>'
                f'<div class="flex-wrap">{badges}</div></div>'
            )

        if call_records:
            # 原始记录常被 NtAllocateVirtualMemory 这类高频调用占满前50条,
            # 按 API 去重取样 (每种最多3条) 展示更有代表性的调用。
            per_api = {}
            sample_records = []
            for r in call_records:
                api = (r.get('api_name', '') or r.get('api', '') or '') if isinstance(r, dict) \
                    else (getattr(r, 'api_name', '') or getattr(r, 'api', '') or '')
                if not api:
                    continue
                per_api[api] = per_api.get(api, 0) + 1
                if per_api[api] <= 3:
                    sample_records.append(r)
                if len(sample_records) >= 50:
                    break
            rows = ''
            for r in sample_records[:50]:
                if isinstance(r, dict):
                    api = r.get('api_name', '') or r.get('api', '') or ''
                    ts = r.get('timestamp', '') or ''
                    cat = r.get('category', '') or ''
                    args = r.get('arguments', []) or []
                else:
                    api = getattr(r, 'api_name', '') or getattr(r, 'api', '') or ''
                    ts = getattr(r, 'timestamp', '') or ''
                    cat = getattr(r, 'category', '') or ''
                    args = getattr(r, 'arguments', []) or []
                if not api:
                    continue
                rows += (f'<tr><td class="small">{_esc(str(ts))}</td>'
                         f'<td><code>{_esc(api)}</code></td>'
                         f'<td class="small">{_esc(cat)}</td>'
                         f'<td class="hash small">{_esc(_safe_join(args, ", ")[:160])}</td></tr>')
            if rows:
                parts.append(self._collapsible(
                    f'API 调用记录 (展示 {len(sample_records[:50])} 条代表性调用 / 共 {len(call_records)} 条)', 'api_records',
                    '<table class="data-table"><thead><tr><th>时间</th><th>API</th><th>分类</th><th>参数</th></tr></thead><tbody>' + rows + '</tbody></table>'
                ))

        # Network payloads captured by Frida hooks
        net_payloads = getattr(am, '_net_payloads', None) or []
        if net_payloads:
            np_rows = ''
            for np_item in net_payloads[:80]:
                if not isinstance(np_item, dict):
                    continue
                np_ts = _esc(str(np_item.get('timestamp', ''))[:19])
                np_api = _esc(np_item.get('api', ''))
                np_is_http = np_item.get('is_http', False)
                np_data = np_item.get('data', '') or ''
                np_data_esc = _esc(np_data[:200])
                if np_is_http:
                    np_data_esc = f'<code style="font-size:11px;color:#38bdf8">{np_data_esc}</code>'
                np_rows += f'<tr><td class="small">{np_ts}</td><td><code>{np_api}</code></td><td>{np_data_esc}</td></tr>'
            if np_rows:
                parts.append(self._collapsible(
                    f'网络载荷数据 (send/recv 前 512 字节, 共 {len(net_payloads)} 条)', 'net_payloads',
                    '<table class="data-table"><thead><tr><th>时间</th><th>API</th><th>数据预览</th></tr></thead><tbody>' + np_rows + '</tbody></table>'
                ))

        if not parts and not spawn_mode:
            return ''

        header_extra = ''
        if spawn_mode:
            header_extra = ' <span style="font-size:12px;color:#34d399;font-weight:600">Frida spawn 模式</span>'

        return '<div class="section" style="border-left-color:#9333ea"><h2 id="api">API 监控' + header_extra + '</h2>' + '\n'.join(parts) + '</div>'

    def _build_memory_section(self, report):
        mem = report.memory
        if not mem:
            # ⚠ 区分两种情况: 未开动态 vs 动态执行过但进程退出(无法实时内存分析)
            _dynamic_ran = False
            try:
                dyn = report.dynamic
                if dyn is not None and (dyn.execution_time or (dyn.processes_created or [])):
                    _dynamic_ran = True
            except Exception:
                pass
            if _dynamic_ran:
                _hint = ('动态分析已执行，但目标进程在分析期间退出'
                         '（MSI安装器/自删除样本常见），无法在进程存活时完成内存取证。'
                         '已记录的释放文件/进程行为见其他章节。')
            else:
                _hint = '内存取证分析需要<b>开启动态分析</b>（--dynamic）才能执行。请重新运行并启用动态行为分析。'
            return '''<div class="section" style="border-left-color:#f97316">
<h2 id="memory">内存取证分析</h2>
<div style="padding:16px;background:rgba(100,116,139,0.08);border:1px solid #334155;border-radius:8px;font-size:13px;color:#64748b">
''' + _hint + '''
</div>
</div>'''
        parts = []

        exit_diag = getattr(mem, 'exit_diagnosis', {}) or {}
        stats_items = [
            ('分析方式', '实时内存取证' if getattr(mem, 'live_analyzed', False) else
             ('退出后离线诊断' if getattr(mem, 'process_exited', False) else '离线/快照分析')),
            ('内存区域总数', str(mem.total_regions)),
            ('可疑区域', str(len(mem.suspicious_regions) if mem.suspicious_regions else 0)),
            ('RWX 区域', str(len(mem.rwx_regions) if mem.rwx_regions else 0)),
            ('内存中发现 shellcode', '是' if mem.shellcode_found else '否'),
            ('内存中发现 PE', '是' if mem.pe_in_memory else '否'),
            ('释放的 PE/DLL (非注入)', str(len(getattr(mem, 'released_pe_files', []) or []))),
            ('转储文件数', str(len(mem.dumped_files) if mem.dumped_files else 0)),
            ('空洞区域', str(len(mem.hollowed_regions) if mem.hollowed_regions else 0)),
            ('解包 PE', '是' if getattr(mem, 'unpacked_pe', False) else '否'),
            ("Heaven's Gate", str(len(getattr(mem, 'heavens_gate', []) or []))),
            ('IAT Hook 数', str(len(getattr(mem, 'iat_hooks', []) or []))),
            ('PEB 异常', str(len(getattr(mem, 'peb_anomalies', []) or []))),
            ('SEH 覆写', '是' if getattr(mem, 'seh_overwrite', None) else '否'),
            ('反 Dump 措施', str(len(getattr(mem, 'anti_dump_measures', []) or []))),
            ('API Unhooking', str(len(getattr(mem, 'api_unhooking', []) or []))),
            ('内核后门', str(len(getattr(mem, 'kernel_backdoor', []) or []))),
            ('隐藏区域', str(len(getattr(mem, 'hidden_regions', []) or []))),
        ]
        if exit_diag:
            stats_items.extend([
                ('内存分配调用', str(exit_diag.get('alloc_calls', 0))),
                ('内存释放调用', str(exit_diag.get('free_calls', 0))),
                ('未释放(失衡)', str(exit_diag.get('leaked_allocations', 0))),
                ('退出前 DEP绕过/ROP', str((exit_diag.get('dep_bypass') or 0) + (exit_diag.get('rop_like') or 0))),
                ('退出前 RW→RX', str(exit_diag.get('rw_to_rx', 0))),
                ('退出前 RWX 分配', str(exit_diag.get('rwx_alloc', 0))),
            ])
        stats_rows = ''.join(
            f'<div class="info-item"><div class="label">{_esc(lbl)}</div><div class="value">{val}</div></div>'
            for lbl, val in stats_items
        )
        parts.append(f'<div class="info-grid mb-12">{stats_rows}</div>')

        # 进程退出诊断块: 明确说明退出前捕获到什么, 而非只写"进程已退出"
        if getattr(mem, 'process_exited', False) and exit_diag:
            _diag_lines = []
            if exit_diag.get('leaked_allocations', 0) >= 3:
                _diag_lines.append(
                    f'<li>💾 <b>内存未释放</b>: 分配×{exit_diag.get("alloc_calls", 0)} / '
                    f'释放×{exit_diag.get("free_calls", 0)}, 失衡 {exit_diag.get("leaked_allocations", 0)} 次 — '
                    f'驻留/泄漏/反内存取证特征</li>')
            if exit_diag.get('dep_bypass') or exit_diag.get('rop_like'):
                _diag_lines.append(
                    f'<li>💥 <b>DEP绕过/ROP喷射</b>: 退出前捕获 '
                    f'{(exit_diag.get("dep_bypass") or 0) + (exit_diag.get("rop_like") or 0)} 次 RWX 事件</li>')
            if exit_diag.get('rw_to_rx'):
                _diag_lines.append(f'<li>🧠 <b>RW→RX 载荷解密</b>: {exit_diag.get("rw_to_rx")} 次</li>')
            if exit_diag.get('injection'):
                _diag_lines.append(f'<li>💉 <b>远程注入</b>: {exit_diag.get("injection")} 次</li>')
            if exit_diag.get('execution_snapshots'):
                _diag_lines.append(f'<li>📸 执行期内存快照 ×{exit_diag.get("execution_snapshots")}</li>')
            if exit_diag.get('dump_files'):
                _diag_lines.append(f'<li>📦 残留 dump ×{len(exit_diag.get("dump_files"))}: '
                                   + ', '.join(_esc(os.path.basename(p)) for p in exit_diag.get('dump_files')[:6])
                                   + '</li>')
            if not _diag_lines:
                _diag_lines.append('<li>目标进程退出前未捕获到可分析的内存行为证据</li>')
            parts.append(
                '<div style="padding:12px 14px;background:rgba(245,158,11,0.08);'
                'border:1px solid rgba(245,158,11,0.3);border-radius:8px;margin-bottom:10px">'
                '<div style="font-size:13px;font-weight:600;color:#fbbf24;margin-bottom:6px">'
                '🪦 目标进程已退出 — 内存检测结论（基于退出前的 API/内存保护监控与残留 dump）</div>'
                '<ul style="margin:0;padding-left:18px;font-size:12px;color:#cbd5e1;line-height:1.7">'
                + ''.join(_diag_lines) + '</ul></div>'
            )

        # Released PE files (明确标注不是内存注入证据)
        released_pe = getattr(mem, 'released_pe_files', []) or []
        if released_pe:
            rel_rows = ''.join(
                f'<tr><td class="hash">{_esc(r.get("path", "") if isinstance(r, dict) else str(r))}</td>'
                f'<td class="hash">{_esc(r.get("dump_path", "") if isinstance(r, dict) else "")}</td></tr>'
                for r in released_pe[:20])
            parts.append(self._collapsible(
                f'释放的 PE/DLL 文件 ({len(released_pe)} 个 — 文件释放证据, 不等同内存注入)',
                'mem_released_pe',
                '<table class="data-table"><thead><tr><th>原路径</th><th>取证副本</th></tr></thead><tbody>'
                + rel_rows + '</tbody></table>'))

        # Shellcode details
        if mem.shellcode_details:
            sc_rows = ''
            for sc in mem.shellcode_details[:20]:
                if isinstance(sc, dict):
                    # 兼容两种字段命名: memory._detect_shellcode 用 offset/pattern,
                    # orchestrator 快照/残留dump 用 address/size/details
                    addr = _esc(sc.get('address') or sc.get('offset') or '')
                    size = sc.get('size', '')
                    detail = _esc(sc.get('details') or sc.get('pattern') or '')
                    sc_rows += f'<tr class="suspicious"><td class="hash">{addr}</td><td>{size}</td><td>{detail}</td></tr>'
            if sc_rows:
                parts.append(self._collapsible(
                    f'Shellcode 详情 ({len(mem.shellcode_details)})', 'mem_sc',
                    '<table class="data-table"><thead><tr><th>地址</th><th>大小</th><th>详情</th></tr></thead><tbody>' + sc_rows + '</tbody></table>'
                ))

        # PE injected modules
        if mem.pe_injected_modules:
            peinj_rows = ''
            for mod in mem.pe_injected_modules[:20]:
                if isinstance(mod, dict):
                    peinj_rows += f'<tr class="suspicious"><td class="hash">{_esc(mod.get("address","") or "")}</td><td class="hash">{_esc(mod.get("module","") or "")}</td><td>{_esc(mod.get("details","") or "")}</td></tr>'
            if peinj_rows:
                parts.append(self._collapsible(
                    f'注入的 PE 模块 ({len(mem.pe_injected_modules)})', 'mem_peinj',
                    '<table class="data-table"><thead><tr><th>地址</th><th>模块</th><th>详情</th></tr></thead><tbody>' + peinj_rows + '</tbody></table>'
                ))

        # RWX regions
        if mem.rwx_regions:
            rwx_rows = ''
            for r in mem.rwx_regions[:20]:
                if isinstance(r, dict):
                    rwx_rows += f'<tr class="suspicious"><td class="hash">{_esc(r.get("base_address","") or "")}</td><td>{r.get("region_size_human","") or r.get("region_size","")}</td><td>{_esc(r.get("protect","") or "")}</td></tr>'
                else:
                    rwx_rows += f'<tr class="suspicious"><td class="hash">{_esc(r.base_address)}</td><td>{getattr(r, "region_size_human", "") or getattr(r, "region_size", "")}</td><td>{_esc(getattr(r, "protect", ""))}</td></tr>'
            if rwx_rows:
                parts.append(self._collapsible(
                    f'RWX 内存区域 ({len(mem.rwx_regions)})', 'mem_rwx',
                    '<table class="data-table"><thead><tr><th>基址</th><th>大小</th><th>保护属性</th></tr></thead><tbody>' + rwx_rows + '</tbody></table>'
                ))

        # Advanced shellcode
        if getattr(mem, 'advanced_shellcode', None):
            adv_rows = ''
            for a in mem.advanced_shellcode[:20]:
                if isinstance(a, dict):
                    adv_rows += f'<tr class="suspicious"><td class="hash">{_esc(a.get("address","") or "")}</td><td class="hash">{_esc(a.get("type","") or "")}</td><td>{_esc(a.get("details","") or "")}</td></tr>'
            if adv_rows:
                parts.append(self._collapsible(
                    f'高级 shellcode ({len(mem.advanced_shellcode)})', 'mem_adv_sc',
                    '<table class="data-table"><thead><tr><th>地址</th><th>类型</th><th>详情</th></tr></thead><tbody>' + adv_rows + '</tbody></table>'
                ))

        # Heaven's Gate
        hg = getattr(mem, 'heavens_gate', None)
        if hg:
            hg_rows = ''
            for h in hg[:10]:
                offset = _esc(h.get('offset', '') or '')
                pattern = _esc(h.get('pattern', '') or '')
                hg_rows += f'<tr class="suspicious"><td class="hash">{offset}</td><td>{pattern}</td></tr>'
            if hg_rows:
                parts.append(self._collapsible(
                    f"Heaven's Gate 检测 ({len(hg)})", 'mem_hg',
                    '<table class="data-table"><thead><tr><th>偏移</th><th>模式</th></tr></thead><tbody>' + hg_rows + '</tbody></table>'
                ))

        # IAT Hooks
        iath = getattr(mem, 'iat_hooks', None)
        if iath:
            ih_rows = ''
            for ih in iath[:10]:
                offset = _esc(ih.get('offset', '') or '')
                pattern = _esc(ih.get('pattern', '') or '')
                ih_rows += f'<tr class="suspicious"><td class="hash">{offset}</td><td>{pattern}</td></tr>'
            if ih_rows:
                parts.append(self._collapsible(
                    f'IAT/EAT Hook ({len(iath)})', 'mem_iath',
                    '<table class="data-table"><thead><tr><th>偏移</th><th>模式</th></tr></thead><tbody>' + ih_rows + '</tbody></table>'
                ))

        # PEB Anomalies
        peba = getattr(mem, 'peb_anomalies', None)
        if peba:
            pb_rows = ''
            for pb in peba[:10]:
                field = _esc(pb.get('field', '') or '')
                val = _esc(pb.get('value', '') or '')
                desc = _esc(pb.get('description', '') or '')
                pb_rows += f'<tr class="suspicious"><td>{field}</td><td>{val}</td><td>{desc}</td></tr>'
            if pb_rows:
                parts.append(self._collapsible(
                    f'PEB 异常 ({len(peba)})', 'mem_peb',
                    '<table class="data-table"><thead><tr><th>字段</th><th>值</th><th>说明</th></tr></thead><tbody>' + pb_rows + '</tbody></table>'
                ))

        # SEH Overwrite
        seh = getattr(mem, 'seh_overwrite', None)
        if seh:
            seh_rows = ''
            for s in seh[:10]:
                offset = _esc(s.get('offset', '') or '')
                pattern = _esc(s.get('pattern', '') or '')
                seh_rows += f'<tr class="suspicious"><td class="hash">{offset}</td><td>{pattern}</td></tr>'
            if seh_rows:
                parts.append(self._collapsible(
                    f'SEH 覆写检测 ({len(seh)})', 'mem_seh',
                    '<table class="data-table"><thead><tr><th>偏移</th><th>模式</th></tr></thead><tbody>' + seh_rows + '</tbody></table>'
                ))

        # Anti-Dump
        ad = getattr(mem, 'anti_dump_measures', None)
        if ad:
            ad_rows = ''
            for a in ad[:10]:
                offset = _esc(a.get('offset', '') or '')
                pattern = _esc(a.get('pattern', '') or '')
                ad_rows += f'<tr class="suspicious"><td class="hash">{offset}</td><td>{pattern}</td></tr>'
            if ad_rows:
                parts.append(self._collapsible(
                    f'反 Dump 检测 ({len(ad)})', 'mem_ad',
                    '<table class="data-table"><thead><tr><th>偏移</th><th>模式</th></tr></thead><tbody>' + ad_rows + '</tbody></table>'
                ))

        # API Unhooking
        au = getattr(mem, 'api_unhooking', None)
        if au:
            au_rows = ''
            for a in au[:10]:
                offset = _esc(a.get('offset', '') or '')
                pattern = _esc(a.get('pattern', '') or '')
                au_rows += f'<tr class="suspicious"><td class="hash">{offset}</td><td>{pattern}</td></tr>'
            if au_rows:
                parts.append(self._collapsible(
                    f'API Unhooking ({len(au)})', 'mem_au',
                    '<table class="data-table"><thead><tr><th>偏移</th><th>模式</th></tr></thead><tbody>' + au_rows + '</tbody></table>'
                ))

        # Kernel Backdoor
        kb = getattr(mem, 'kernel_backdoor', None)
        if kb:
            kb_rows = ''
            for k in kb[:10]:
                offset = _esc(k.get('offset', '') or '')
                pattern = _esc(k.get('pattern', '') or '')
                kb_rows += f'<tr class="suspicious"><td class="hash">{offset}</td><td>{pattern}</td></tr>'
            if kb_rows:
                parts.append(self._collapsible(
                    f'内核后门检测 ({len(kb)})', 'mem_kb',
                    '<table class="data-table"><thead><tr><th>偏移</th><th>模式</th></tr></thead><tbody>' + kb_rows + '</tbody></table>'
                ))

        # Hidden Regions
        hr = getattr(mem, 'hidden_regions', None)
        if hr:
            hr_rows = ''
            for h in hr[:10]:
                addr = _esc(h.get('address', '') or '')
                size = h.get('size', '')
                desc = _esc(h.get('description', '') or '')
                hr_rows += f'<tr class="suspicious"><td class="hash">{addr}</td><td>{size}</td><td>{desc}</td></tr>'
            if hr_rows:
                parts.append(self._collapsible(
                    f'隐藏内存区域 ({len(hr)})', 'mem_hr',
                    '<table class="data-table"><thead><tr><th>地址</th><th>大小</th><th>描述</th></tr></thead><tbody>' + hr_rows + '</tbody></table>'
                ))

        if mem.summary:
            parts.append(f'<div style="padding:10px 14px;background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.25);border-radius:8px;font-size:13px;color:#fca5a5">{_esc(mem.summary)}</div>')

        if not parts:
            return ''
        return '<div class="section" style="border-left-color:#f97316"><h2 id="memory">内存取证分析</h2>' + '\n'.join(parts) + '</div>'

    def _build_dll_watch_section(self, report):
        """DLL 调用监控 — 样本加载/调用的非系统 DLL 函数"""
        dll_sum = getattr(report, '_dll_call_summary', None)
        if not dll_sum:
            return ''
        parts = []
        funcs = dll_sum.get('functions', []) or []
        if funcs:
            rows = ''
            for (dll, func), cnt in funcs[:40]:
                rows += f'<tr><td class="hash">{_esc(dll)}</td><td><code>{_esc(func)}</code></td><td style="text-align:right">{cnt}</td></tr>'
            parts.append(self._collapsible(
                f'函数调用明细 ({dll_sum.get("total_calls", 0)} 次 / {len(funcs)} 个函数)', 'dllwatch_table',
                '<table class="data-table"><thead><tr><th>DLL</th><th>函数</th><th>调用次数</th></tr></thead><tbody>' + rows + '</tbody></table>', True
            ))
        susp = dll_sum.get('suspicious_dlls', []) or []
        if susp:
            parts.append('<ul class="item-list">' + ''.join(
                f'<li class="text-danger">可疑 DLL 被调用: {_esc(d)}</li>' for d in susp) + '</ul>')
        if not parts:
            return ''
        return '<div class="section" style="border-left-color:#8b5cf6"><h2 id="dllwatch">DLL 调用监控</h2>' + '\n'.join(parts) + '</div>'

    def _build_spoof_section(self, report):
        """API 欺骗 — 假反馈动作记录 + 特权/注册表 hive 专项监控"""
        spoof = getattr(report, '_spoof_summary', None)
        am = report.api_monitor
        privs = getattr(am, '_priv_events', None) or [] if am else []
        regsaves = getattr(am, '_regsave_events', None) or [] if am else []
        if not spoof and not privs and not regsaves:
            return ''
        parts = []
        if spoof:
            apis = spoof.get('apis', []) or []
            if apis:
                parts.append('<div class="flex-wrap">' + ''.join(
                    f'<span class="badge" style="background:#7c3aed">{_esc(a)}</span>' for a in apis) + '</div>')
            parts.append(f'<div class="info-grid"><div class="info-item"><div class="label">假反馈次数</div>'
                         f'<div class="value">{spoof.get("count", 0)}</div></div>'
                         f'<div class="info-item"><div class="label">欺骗的API</div>'
                         f'<div class="value">{len(apis)} 个</div></div></div>')
            if am:
                actions = getattr(am, '_spoof_actions', None) or []
                if actions:
                    rows = ''.join(
                        f'<tr><td><code>{_esc(a.get("api", ""))}</code></td>'
                        f'<td>{_esc(a.get("detail", ""))}</td></tr>'
                        for a in actions[:20])
                    parts.append(self._collapsible(
                        f'假反馈动作明细 (最近 {min(len(actions), 20)} 条)', 'spoof_actions',
                        '<table class="data-table"><thead><tr><th>API</th><th>伪造结果</th></tr></thead>'
                        '<tbody>' + rows + '</tbody></table>'))
        if privs:
            rows = ''.join(
                f'<tr class="{"suspicious" if e.get("action") == "ENABLED" else ""}">'
                f'<td><code>{_esc(e.get("api", ""))}</code></td>'
                f'<td>{_esc(e.get("privilege", ""))}</td>'
                f'<td>{_esc(e.get("action", ""))}</td></tr>'
                for e in privs[:20])
            parts.append(self._collapsible(
                f'特权启用监控 ({len(privs)} 事件 — SeDebug/SeBackup 等)', 'priv_events',
                '<table class="data-table"><thead><tr><th>API</th><th>特权</th><th>动作</th></tr></thead>'
                '<tbody>' + rows + '</tbody></table>', True))
        if regsaves:
            rows = ''.join(
                f'<tr class="suspicious"><td><code>{_esc(e.get("api", ""))}</code></td>'
                f'<td class="hash">{_esc(e.get("file", ""))}</td></tr>'
                for e in regsaves[:10])
            parts.append(self._collapsible(
                f'注册表 hive 保存监控 ({len(regsaves)} 事件 — SAM/SYSTEM 离线窃取)', 'regsave_events',
                '<table class="data-table"><thead><tr><th>API</th><th>目标文件</th></tr></thead>'
                '<tbody>' + rows + '</tbody></table>'))
        return '<div class="section" style="border-left-color:#8b5cf6"><h2 id="spoof">API 欺骗与专项监控</h2>' + '\n'.join(parts) + '</div>'

    def _build_memprot_section(self, report):
        """内存保护监控 — RW→RX 转换/远程注入事件明细"""
        memprot = getattr(report, '_memprot_summary', None)
        if not memprot:
            return ''
        parts = []
        events = memprot.get('events', []) or []
        if events:
            def _fmt_bytes(n):
                try:
                    n = int(n)
                except (TypeError, ValueError):
                    return str(n)
                if n >= 1 << 30:
                    return f'{n / (1 << 30):.2f} GB'
                if n >= 1 << 20:
                    return f'{n / (1 << 20):.2f} MB'
                if n >= 1 << 10:
                    return f'{n / (1 << 10):.1f} KB'
                return f'{n} B'

            rows = ''
            for e in events[:30]:
                is_rop = bool(e.get('rop_like'))
                is_dep = bool(e.get('dep_bypass'))
                is_huge = bool(e.get('huge_alloc'))
                cls = 'suspicious' if (e.get('rw_to_rx') or is_dep or is_huge) else ''
                if is_rop:
                    mark = 'ROP/DEP绕过'
                elif e.get('rw_to_rx'):
                    mark = 'RW→RX'
                elif is_dep:
                    mark = 'RWX分配'
                elif is_huge:
                    mark = '超大分配'
                elif e.get('injection'):
                    mark = '注入'
                else:
                    mark = ''
                prot = _esc(e.get('new_prot', '') or '')
                if e.get('protection'):
                    prot += f' <span class="small hash">({_esc(e.get("protection", ""))})</span>'
                status = _esc(str(e.get('status', ''))) if e.get('status', '') not in (None, '', 0) else ''
                rows += f'<tr class="{cls}"><td><code>{_esc(e.get("api", ""))}</code></td><td class="hash">{_esc(e.get("base", ""))}</td>' \
                        f'<td>{_fmt_bytes(e.get("size", 0))}</td><td>{_esc(e.get("old_prot", ""))} → {prot}</td>' \
                        f'<td>{status}</td><td class="suspicious-text">{mark}</td></tr>'
            parts.append(self._collapsible(
                f'内存保护事件明细 ({len(events)})', 'memprot_table',
                '<table class="data-table"><thead><tr><th>API</th><th>地址</th><th>大小</th><th>保护变化</th><th>返回值</th><th>类型</th></tr></thead><tbody>' + rows + '</tbody></table>', True
            ))
        return '<div class="section" style="border-left-color:#8b5cf6"><h2 id="memprot">内存保护监控</h2>' + '\n'.join(parts) + '</div>'

    def _build_network_section(self, report):
        net = report.network
        if not net:
            return ''
        parts = []

        # Traffic stats
        stats_items = [
            ('总数据包', str(net.total_packets)),
            ('总流量', f'{net.total_bytes:,} bytes' if net.total_bytes else 'N/A'),
            ('DNS 查询', str(len(net.dns_queries) if net.dns_queries else 0)),
            ('HTTP 请求', str(len(net.http_requests) if net.http_requests else 0)),
            ('TCP 连接', str(len(net.tcp_connections) if net.tcp_connections else 0)),
            ('UDP 连接', str(len(net.udp_connections) if net.udp_connections else 0)),
            ('可疑流量', str(len(net.suspicious_traffic) if net.suspicious_traffic else 0)),
        ]
        stats_rows = ''.join(
            f'<div class="info-item"><div class="label">{_esc(lbl)}</div><div class="value">{val}</div></div>'
            for lbl, val in stats_items
        )
        parts.append(f'<div class="info-grid mb-12">{stats_rows}</div>')

        # PCAP 抓包文件
        pcap_path = getattr(net, 'pcap_path', '') or getattr(net, 'pcap_file', '') or ''
        if pcap_path:
            parts.append(
                f'<div style="padding:8px 14px;background:rgba(16,185,129,0.08);'
                f'border:1px solid rgba(16,185,129,0.25);border-radius:8px;'
                f'font-size:13px;color:#cbd5e1;margin-bottom:10px">'
                f'📦 PCAP 抓包文件: <span class="hash">{_esc(pcap_path)}</span></div>'
            )

        # HTTP 高层 API 捕获的明文 URL 载荷 (WinHTTP/WinINet — 还原 HTTPS 加密前的明文)
        http_urls = getattr(getattr(report, 'api_monitor', None), '_http_urls', None) or []
        if http_urls:
            url_rows = ''
            for u in http_urls[:100]:
                u_url = u.get('url', '') or ''
                u_proto = u.get('proto', '') or ''
                u_verb = u.get('verb', '') or ''
                u_extra = u.get('extra', '') or ''
                if u_url:
                    url_rows += (f'<tr><td class="hash">{_esc(u_url)}</td>'
                                 f'<td>{_esc(u_proto)}</td><td>{_esc(u_verb)}</td></tr>')
                elif u_extra:
                    url_rows += (f'<tr><td class="hash" style="color:#94a3b8">[headers]</td>'
                                 f'<td>{_esc(u_proto)}</td><td class="small">{_esc(u_extra[:200])}</td></tr>')
            if url_rows:
                parts.append(self._collapsible(
                    f'明文 URL 载荷 ({len(http_urls)})', 'net_http_url',
                    '<table class="data-table"><thead><tr><th>URL</th><th>来源</th><th>方法/详情</th></tr></thead><tbody>'
                    + url_rows + '</tbody></table>'
                ))

        # DNS queries
        if net.dns_queries:
            dns_rows = ''
            for d in net.dns_queries:
                cls = 'suspicious' if getattr(d, 'is_suspicious', False) else ''
                ips = _safe_join(d.resolved_ips) if d.resolved_ips else '-'
                reason = _esc(d.suspicion_reason[:60]) if getattr(d, 'suspicion_reason', '') else ''
                dns_rows += f'<tr class="{cls}"><td class="hash">{_esc(d.domain)}</td><td>{d.query_type}</td><td class="hash">{_esc(ips)}</td><td>{reason}</td></tr>'
            parts.append(self._collapsible(
                f'DNS 查询 ({len(net.dns_queries)})', 'net_dns',
                '<table class="data-table"><thead><tr><th>域名</th><th>类型</th><th>解析 IP</th><th>可疑原因</th></tr></thead><tbody>' + dns_rows + '</tbody></table>'
            ))

        # TCP connections
        if net.tcp_connections:
            # 内置已知恶意 IP 标签（SilverFox / CobaltStrike 等）
            known_malicious = {
                '27.124.18.166': ('SilverFox C2', '#dc2626'),
                '43.128.240.63': ('SilverFox Panel', '#dc2626'),
                '117.168.151.126': ('SilverFox Relay', '#ef4444'),
                '185.220.101.53': ('Tor Exit / Emotet', '#dc2626'),
                '45.155.205.233': ('CobaltStrike', '#dc2626'),
                '185.174.172.37': ('CobaltStrike', '#dc2626'),
            }
            tcp_rows = ''
            for c in net.tcp_connections:
                remote_ip = c.remote_addr
                cls = 'suspicious' if getattr(c, 'is_suspicious', False) else ''
                proc = _esc(c.process_name[:30]) if c.process_name else ''
                # 上下行流量
                sent = c.bytes_sent if c.bytes_sent else 0
                recv = c.bytes_recv if c.bytes_recv else 0
                def _fmt_bytes(b):
                    if b >= 1048576: return f'{b/1048576:.1f} MB'
                    if b >= 1024: return f'{b/1024:.1f} KB'
                    return f'{b} B'
                traffic_str = f'↑ {_fmt_bytes(sent)}&nbsp;&nbsp;↓ {_fmt_bytes(recv)}' if (sent + recv) > 0 else '-'
                # 威胁情报标签
                ti_tag = ''
                known_malicious = {
                    '27.124.18.166': ('SilverFox C2', '#dc2626'),
                    '43.128.240.63': ('SilverFox Panel', '#dc2626'),
                    '117.168.151.126': ('SilverFox Relay', '#ef4444'),
                    '185.220.101.53': ('Tor / Emotet', '#dc2626'),
                    '45.155.205.233': ('CobaltStrike', '#dc2626'),
                }
                if remote_ip in known_malicious:
                    name, color = known_malicious[remote_ip]
                    ti_tag = f' <span style="background:{color};color:#fff;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600">{name}</span>'
                    cls = 'suspicious'
                tcp_rows += f'<tr class="{cls}"><td>{c.protocol}</td><td class="hash">{_esc(c.local_addr)}:{c.local_port}</td><td class="hash">{_esc(remote_ip)}:{c.remote_port}{ti_tag}</td><td style="white-space:nowrap">{traffic_str}</td><td>{_esc(c.status)}</td><td class="small" style="max-width:120px">{proc}</td></tr>'
            parts.append(self._collapsible(
                f'TCP 连接 ({len(net.tcp_connections)})', 'net_tcp',
                '<table class="data-table"><thead><tr><th>协议</th><th>本地</th><th>远程</th><th>流量</th><th>状态</th><th>进程</th></tr></thead><tbody>' + tcp_rows + '</tbody></table>'
            ))

        # UDP connections
        if net.udp_connections:
            udp_rows = ''
            for c in net.udp_connections:
                cls = 'suspicious' if getattr(c, 'is_suspicious', False) else ''
                udp_rows += f'<tr class="{cls}"><td>{c.protocol}</td><td class="hash">{_esc(c.local_addr)}:{c.local_port}</td><td class="hash">{_esc(c.remote_addr)}:{c.remote_port}</td></tr>'
            parts.append(self._collapsible(
                f'UDP 连接 ({len(net.udp_connections)})', 'net_udp',
                '<table class="data-table"><thead><tr><th>协议</th><th>本地</th><th>远程</th></tr></thead><tbody>' + udp_rows + '</tbody></table>'
            ))

        # HTTP requests
        if net.http_requests:
            http_rows = ''
            for h in net.http_requests:
                cls = 'suspicious' if getattr(h, 'is_suspicious', False) else ''
                ua = _esc(h.user_agent[:80]) if h.user_agent else '-'
                http_rows += f'<tr class="{cls}"><td>{h.method}</td><td class="hash">{_esc(h.host)}</td><td class="hash">{_esc(h.path[:80])}</td><td>{ua}</td></tr>'
            parts.append(self._collapsible(
                f'HTTP 请求 ({len(net.http_requests)})', 'net_http',
                '<table class="data-table"><thead><tr><th>方法</th><th>主机</th><th>路径</th><th>User-Agent</th></tr></thead><tbody>' + http_rows + '</tbody></table>'
            ))

        # UA analysis
        ua = getattr(report, '_ua_analysis', None)
        if ua and (ua.get('diverse') or ua.get('malicious_hits') or ua.get('suspicious_anomalies')):
            ua_parts = []
            ua_count = ua.get('ua_count', 0)
            unique_count = ua.get('unique_count', 0)
            ua_parts.append(f'<div style="font-size:13px;color:#cbd5e1;margin-bottom:8px">{unique_count} 种 UA / {ua_count} 次请求</div>')
            if ua.get('diversity_warning'):
                ua_parts.append(f'<div style="color:#fcd34d;font-weight:600;margin-bottom:6px">{_esc(ua["diversity_warning"])}</div>')
            for mh in ua.get('malicious_hits', [])[:10]:
                ua_short = ((mh.get("user_agent","") or "")[:120])
                ua_parts.append(f'<div style="border-left:3px solid #ef4444;padding:6px 12px;margin:4px 0;background:rgba(239,68,68,0.05);border-radius:0 6px 6px 0"><div class="label">家族: {_esc(mh.get("family",""))}</div><div class="hash small">{_esc(ua_short)}</div><div class="small">{_esc(mh.get("description","") or "")}</div></div>')
            for a in ua.get('suspicious_anomalies', [])[:10]:
                ua_short = ((a.get("user_agent","") or "")[:120])
                ua_parts.append(f'<div style="border-left:3px solid #f59e0b;padding:6px 12px;margin:4px 0;background:rgba(245,158,11,0.05);border-radius:0 6px 6px 0"><div class="hash small">{_esc(ua_short)}</div><div class="small text-warning">{_esc(a.get("reason","") or "")}</div></div>')
            parts.append(self._collapsible(
                f'User-Agent 分析 ({unique_count} 种)', 'net_ua',
                '<div style="padding:10px 14px;background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.25);border-radius:8px">' + '\n'.join(ua_parts) + '</div>'
            ))

        # Suspicious traffic
        if net.suspicious_traffic:
            sus_rows = ''
            for st in net.suspicious_traffic[:20]:
                if isinstance(st, dict):
                    sus_rows += f'<tr class="suspicious"><td>{_esc(st.get("type","") or "")}</td><td>{_esc(st.get("detail","") or "")}</td><td>{_esc(st.get("protocol","") or "")}</td></tr>'
            parts.append(self._collapsible(
                f'可疑流量 ({len(net.suspicious_traffic)})', 'net_sus',
                '<table class="data-table"><thead><tr><th>类型</th><th>详情</th><th>协议</th></tr></thead><tbody>' + sus_rows + '</tbody></table>'
            ))

        if not parts:
            return ''
        return '<div class="section" style="border-left-color:#10b981"><h2 id="network">网络分析</h2>' + '\n'.join(parts) + '</div>'

    def _build_community_section(self, report):
        sigs = getattr(report, '_community_signatures', None)
        if not sigs:
            return ''
        rows = ''
        for s in sigs[:50]:
            name = _esc((s.get('signature', '') or s.get('name', '') or '')[:80])
            desc = _esc((s.get('description', '') or '')[:120])
            categories = _esc(_safe_join(s.get('categories', []))[:80])
            mitre = _esc(_safe_join(s.get('mitre', []))[:80])
            evidence = _esc((s.get('evidence', '') or '')[:100])
            rows += f'<tr class="suspicious"><td style="font-weight:600">{name}</td><td>{desc}</td><td class="small">{categories}</td><td class="small">{mitre}</td><td class="small">{evidence}</td></tr>'
        table = '<table class="data-table"><thead><tr><th>签名</th><th>描述</th><th>分类</th><th>MITRE</th><th>证据</th></tr></thead><tbody>' + rows + '</tbody></table>'
        return '<div class="section" style="border-left-color:#ec4899"><h2 id="community">社区签名命中 (' + str(len(sigs)) + ' 项)</h2>' + table + '</div>'

    def _build_yara_section(self, yara_matches):
        """构建 YARA 规则命中区域"""
        if not yara_matches:
            return ''
        rows = ''
        for ym in yara_matches[:50]:
            rule = _esc((ym.get('rule', '') or ym.get('name', '') or '')[:100])
            desc = _esc((ym.get('description', '') or '')[:120])
            mitre = _esc((ym.get('mitre', '') or '')[:80])
            matched = _esc((ym.get('matched_string', '') or '')[:120])
            severity = ym.get('severity', '')
            sev_cls = 'suspicious' if severity in ('critical', 'high') else ''
            rows += f'<tr class="{sev_cls}"><td style="font-weight:600">{rule}</td><td>{desc}</td><td class="small">{mitre}</td><td class="small">{matched}</td></tr>'
        table = '<table class="data-table"><thead><tr><th>规则</th><th>描述</th><th>MITRE</th><th>匹配项</th></tr></thead><tbody>' + rows + '</tbody></table>'
        return '<div class="section" style="border-left-color:#f59e0b"><h2 id="yara">YARA 规则命中 (' + str(len(yara_matches)) + ' 项)</h2>' + table + '</div>'

    def _build_sigma_section(self, sigma_matches):
        """构建 Sigma 规则命中区域"""
        if not sigma_matches:
            return ''
        rows = ''
        levels = {'high': '高危', 'medium': '中', 'low': '低', 'info': '信息'}
        for sm in sigma_matches[:50]:
            title = _esc((sm.title if hasattr(sm, 'title') else sm.get('title', '') or '')[:100])
            desc = _esc((sm.description if hasattr(sm, 'description') else sm.get('description', '') or '')[:120])
            tags = _esc(_safe_join(sm.tags if hasattr(sm, 'tags') else sm.get('tags', []))[:80])
            level = sm.level if hasattr(sm, 'level') else sm.get('level', '')
            technique = _esc(sm.technique if hasattr(sm, 'technique') else sm.get('technique', '') or '')
            matched_on = _esc(sm.matched_on if hasattr(sm, 'matched_on') else sm.get('matched_on', '') or '')
            level_label = levels.get(level, level)
            sev_cls = 'suspicious' if level in ('high', 'medium') else ''
            rows += f'<tr class="{sev_cls}"><td style="font-weight:600">{title}</td><td>{desc}</td><td class="small">{tags}</td><td class="small">{technique}</td><td><span style="color:#f59e0b;font-weight:600">{level_label}</span></td><td class="small">{matched_on}</td></tr>'
        table = '<table class="data-table"><thead><tr><th>标题</th><th>描述</th><th>标签</th><th>MITRE</th><th>级别</th><th>来源</th></tr></thead><tbody>' + rows + '</tbody></table>'
        return '<div class="section" style="border-left-color:#a855f7"><h2 id="sigma">Sigma 规则命中 (' + str(len(sigma_matches)) + ' 项)</h2>' + table + '</div>'

    def _build_threat_intel_section(self, report):
        ti = report.threat_intel
        if not ti:
            return ''
        parts = []

        items = [
            ('家族', _esc(ti.family)),
            ('置信度', _esc(str(ti.confidence)) if ti.confidence else 'N/A'),
            ('标签', _safe_join(ti.threat_labels) if ti.threat_labels else '无'),
            ('检出率', f'{ti.detection_rate:.0%}' if ti.detection_rate else 'N/A'),
            ('首次发现', _esc(ti.first_seen) if ti.first_seen else '未知'),
            ('最近发现', _esc(ti.last_seen) if ti.last_seen else '未知'),
            ('提交次数', str(ti.submission_count) if ti.submission_count else 'N/A'),
        ]
        rows = ''.join(
            f'<div class="info-item"><div class="label">{_esc(lbl)}</div><div class="value">{val}</div></div>'
            for lbl, val in items
        )
        parts.append(f'<div class="info-grid mb-12">{rows}</div>')

        # IoC hits
        ioc = getattr(report, '_ioc_hits', None)
        if ioc and ioc.get('total_hits', 0) > 0:
            ioc_rows = ''
            for item in ioc.get('ips', [])[:20]:
                desc_short = ((item.get("description","") or "")[:80])
                ioc_rows += f'<tr class="suspicious"><td>IP</td><td class="hash">{_esc(item.get("ip","") or "")}</td><td>{_esc(item.get("family","") or "")}</td><td class="small">{_esc(desc_short)}</td></tr>'
            for item in ioc.get('domains', [])[:20]:
                dom_short = ((item.get("domain","") or "")[:80])
                desc_short = ((item.get("description","") or "")[:80])
                ioc_rows += f'<tr class="suspicious"><td>域名</td><td class="hash">{_esc(dom_short)}</td><td>{_esc(item.get("family","") or "")}</td><td class="small">{_esc(desc_short)}</td></tr>'
            for item in ioc.get('urls', [])[:20]:
                url_short = ((item.get("url","") or "")[:120])
                desc_short = ((item.get("description","") or "")[:80])
                ioc_rows += f'<tr class="suspicious"><td>URL</td><td class="hash small">{_esc(url_short)}</td><td>{_esc(item.get("family","") or "")}</td><td class="small">{_esc(desc_short)}</td></tr>'
            if ioc_rows:
                parts.append(self._collapsible(
                    f'IoC 命中 ({ioc["total_hits"]} 项)', 'ti_ioc',
                    '<table class="data-table"><thead><tr><th>类型</th><th>值</th><th>家族</th><th>描述</th></tr></thead><tbody>' + ioc_rows + '</tbody></table>',
                    default_open=True
                ))

        # Engine results
        if ti.engine_results:
            engine_rows = ''
            for r in ti.engine_results:
                if not isinstance(r, dict):
                    continue
                eng = r.get('engine', '?')
                res = r.get('result', {})
                if not isinstance(res, dict):
                    res = {}
                hit = res.get('hit', None)
                if hit is True:
                    hit_str = '命中'
                elif hit is False:
                    hit_str = '未命中'
                else:
                    hit_str = '-'
                detail = ''
                if eng == 'MalwareBazaar':
                    detail = res.get('signature', '') or _safe_join(res.get('tags', [])[:3])
                    if res.get('first_seen'):
                        detail += f' (首次: {res["first_seen"]})'
                elif eng == 'VirusTotal':
                    m = res.get('malicious', 0)
                    s = res.get('suspicious', 0)
                    detail = f'{m}恶意/{s}可疑/{res.get("total_engines", "?")}引擎'
                    popular = res.get('popular_threat', '')
                    if popular:
                        detail += f' — {popular}'
                elif eng == 'Triage':
                    detail = f'评分: {res.get("score", "?")}/10'
                    if res.get('family'):
                        detail += f' ({res["family"]})'
                elif eng == 'ThreatBook':
                    lvl = res.get('threat_level', '') or ''
                    fam = res.get('family', '') or ''
                    det = res.get('detection', '') or ''
                    _tb = [x for x in (lvl, fam) if x]
                    detail = ' — '.join(_tb)
                    if det:
                        detail += f' ({det})'
                    if not detail:
                        detail = res.get('detail', '') or '未报告'
                elif eng == 'Local IoC':
                    detail = res.get('desc', '') or ''
                elif eng == 'ClamAV':
                    detail = res.get('malware_name', '') or ('未检出' if hit is False else '')
                elif eng == '360':
                    detail = res.get('desc', '') or res.get('threat_level', '') or ''
                engine_rows += f'<tr><td style="font-weight:600">{_esc(eng)}</td><td>{hit_str}</td><td class="small">{_esc(detail[:150])}</td></tr>'
            parts.append(self._collapsible(
                f'引擎详情 ({len(ti.engine_results)})', 'ti_engines',
                '<table class="data-table"><thead><tr><th>引擎</th><th>结果</th><th>详情</th></tr></thead><tbody>' + engine_rows + '</tbody></table>'
            ))

        if not parts:
            return ''
        return '<div class="section" style="border-left-color:#a855f7"><h2 id="threat">威胁情报（多引擎）</h2>' + '\n'.join(parts) + '</div>'

    def _build_rat_config_section(self, report):
        rats = getattr(report, '_rat_config', None)
        if not rats:
            return ''
        rows = ''
        for r in rats[:30]:
            for k, v in r.items():
                v_str = _esc(str(v)[:200])
                rows += f'<tr><td style="font-weight:600;color:#c084fc">{_esc(k)}</td><td class="hash">{v_str}</td></tr>'
        table = '<table class="data-table"><thead><tr><th>配置项</th><th>值</th></tr></thead><tbody>' + rows + '</tbody></table>'
        return '<div class="section" style="border-left-color:#d946ef"><h2 id="rat">RAT/Stealer 配置提取 (' + str(len(rats)) + ' 项)</h2>' + table + '</div>'

    # ==================== DeepDive 深度追踪分析 ====================
    def _build_deep_dive_section(self, report):
        dd = getattr(report, '_deep_dive', None)
        if not dd:
            return ''
        parts = []
        # ---- 总览结论卡 ----
        verdict = _esc(getattr(dd, 'verdict', '') or '')
        conf = getattr(dd, 'confidence', 0.0) or 0.0
        conf_pct = int(conf * 100)
        conf_color = '#dc2626' if conf >= 0.55 else '#f59e0b' if conf >= 0.3 else '#22c55e'
        conclusion = _esc(getattr(dd, 'conclusion', '') or '')
        parts.append(
            f'<div class="risk-badge" style="background:{conf_color};color:#fff;display:inline-block;padding:4px 14px;margin:6px 0">'
            f'综合判定: {verdict} (置信度 {conf_pct}%)</div>'
            f'<div style="height:10px;background:#334155;border-radius:5px;margin:8px 0 14px;overflow:hidden">'
            f'<div style="height:100%;width:{conf_pct}%;background:{conf_color};border-radius:5px"></div></div>'
            f'<p style="background:#0f172a;padding:14px 16px;border-radius:10px;border-left:4px solid {conf_color}">{conclusion}</p>'
        )

        # ---- 环境检测技术清单 (30+ 项 — 反沙箱/反VM/反调试/时序 具体技术) ----
        env_checks = getattr(dd, 'execution_environment', None) or []
        if env_checks:
            rows = ''
            for e in env_checks[:30]:
                t = _esc(str(e.get('type', '')))
                target = _esc(str(e.get('target', '')))
                desc = _esc(str(e.get('desc', '')))[:90]
                color = {'反沙箱': '#f59e0b', '反VM': '#dc2626', '反调试': '#8b5cf6',
                         '时序规避': '#06b6d4', '目标进程校验': '#3b82f6', 'API': '#64748b'}.get(t, '#64748b')
                rows += (f'<tr><td><span class="risk-badge" style="background:{color};color:#fff;'
                         f'font-size:10px">{t}</span></td>'
                         f'<td style="font-size:12px">{target}</td>'
                         f'<td style="font-size:11px;color:#94a3b8">{desc}</td></tr>')
            env_table = (f'<table class="data-table"><thead><tr><th>类型</th><th>检测项</th><th>说明</th></tr></thead>'
                         f'<tbody>{rows}</tbody></table>')
            parts.append(self._collapsible(
                f'环境检测技术清单 ({len(env_checks)} 项 — 反沙箱/反VM/反调试)', 'dd_envlist',
                env_table, default_open=True))

        # ---- C2 配置详情 (URL/密钥/上线包格式) ----
        try:
            c2cfg = getattr(dd.network_profile, 'c2_config', None) or {}
        except Exception:
            c2cfg = {}
        if c2cfg:
            cfg_rows = ''
            for k, v in c2cfg.items():
                if isinstance(v, list):
                    v = '<br>'.join(_esc(str(x)) for x in v[:6])
                else:
                    v = _esc(str(v))
                cfg_rows += (f'<tr><td style="font-weight:600;color:#c084fc;width:140px">{_esc(k)}</td>'
                             f'<td class="hash">{v}</td></tr>')
            cfg_table = f'<table class="data-table"><tbody>{cfg_rows}</tbody></table>'
            parts.append(self._collapsible('C2 配置提取 (URL/密钥/上线包)', 'dd_c2cfg',
                                           cfg_table, default_open=True))

        # ---- 攻击链时间线 ----
        chain = getattr(dd, 'attack_chain', None) or []
        if chain:
            phase_colors = {'环境校验': '#3b82f6', '对抗规避': '#ef4444', '载荷投递': '#f59e0b',
                            '驱动加载': '#8b5cf6', '数据窃取': '#ec4899', '网络外联': '#06b6d4',
                            '持久化': '#84cc16', '执行': '#f97316'}
            tl = '<div style="position:relative;padding-left:26px">'
            for ev in chain[:15]:
                phase = _esc(ev.get('phase', '执行'))
                color = phase_colors.get(phase, '#64748b')
                tl += (f'<div style="position:relative;padding:0 0 14px;border-left:2px solid #334155;'
                       f'margin-left:-26px;padding-left:26px">'
                       f'<span style="position:absolute;left:-8px;top:2px;width:14px;height:14px;'
                       f'border-radius:50%;background:{color};border:2px solid #0f172a"></span>'
                       f'<span class="risk-badge" style="background:{color};color:#fff;font-size:11px;padding:1px 8px">{phase}</span> '
                       f'<b>{_esc(ev.get("event", ""))}</b>'
                       f'<div style="color:#94a3b8;font-size:12px">{_esc(ev.get("source", ""))}</div>'
                       f'</div>')
            tl += '</div>'
            parts.append(self._collapsible('攻击链时间线 (Attack Chain)', 'dd_chain', tl, default_open=True))

        # ---- 层级投递链 (L1→Ln) ----
        dl = getattr(dd, 'delivery_layers', None) or []
        if dl:
            tree = '<div style="font-family:Consolas,monospace;font-size:13px">'
            for i, node in enumerate(dl):
                indent = '&nbsp;&nbsp;&nbsp;&nbsp;' if i > 0 else ''
                connector = '├── ' if i > 0 else ''
                exp = _esc(', '.join(node.get('exports', [])[:6])) if node.get('exports') else ''
                yara = _esc(', '.join(node.get('yara', [])[:3])) if node.get('yara') else ''
                tree += (f'<div>{"&nbsp;"*0}{indent}{connector}'
                         f'<span class="risk-badge" style="background:#0ea5e9;color:#fff;font-size:10px">L{node.get("layer", i+1)}</span> '
                         f'<b>{_esc(node.get("name", ""))}</b> '
                         f'<span style="color:#94a3b8">({_esc(node.get("kind", ""))}) {_esc(node.get("detail", ""))[:80]}</span>'
                         + (f'<div style="color:#f472b6;padding-left:24px">导出: {exp}</div>' if exp else '')
                         + (f'<div style="color:#fbbf24;padding-left:24px">YARA: {yara}</div>' if yara else '')
                         + '</div>')
            tree += '</div>'
            parts.append(self._collapsible('层级投递链 (L1→Ln)', 'dd_layers', tree, default_open=True))

        # ---- 行为深析 ----
        bi = getattr(dd, 'behavior_insights', None) or []
        if bi:
            cat_color = {'av_detection': '#ef4444', 'defender_disable': '#f59e0b',
                         'uac_disable': '#f97316', 'privilege': '#a855f7',
                         'break_on_termination': '#dc2626', 'scheduled_rpc': '#84cc16',
                         'shortcut': '#eab308', 'startup_redirect': '#f59e0b',
                         'keylogger': '#ec4899', 'clipboard': '#db2777',
                         'injection_guard': '#7c3aed', 'screenshot': '#06b6d4',
                         'anti_eventlog': '#6366f1', 'network_lateral': '#0d9488',
                         'polymorphic': '#475569', 'doh': '#0891b2',
                         'heartbeat': '#0284c7', 'command_table': '#0369a1',
                         'hta_hidden': '#f97316', 'hta_antidebug_js': '#dc2626',
                         'hta_activex_dotnet': '#a855f7', 'embedded_base64': '#eab308',
                         'zip_package': '#84cc16', 'hardcoded_key': '#f59e0b',
                         'sideloading': '#ef4444', 'vmp_packed': '#7c3aed',
                         'cloud_c2': '#06b6d4', 'self_delete': '#64748b'}
            rows = ''
            for i in bi[:30]:
                c = cat_color.get(i.get('category', ''), '#64748b')
                # 证据列优先显示实际命中内容 (evidence_hits) — 修复: 之前只显示
                # 模板 desc 和来源标签, 用户反馈"说明都是举例, 不是检测结果"
                hits = i.get('evidence_hits') or []
                if hits:
                    ev_disp = ' | '.join(str(h)[:200] for h in hits[:4])
                else:
                    ev_disp = str(i.get('evidence', ''))
                rows += (f'<tr><td><span class="risk-badge" style="background:{c};color:#fff;font-size:10px">{_esc(i.get("category", ""))}</span></td>'
                         f'<td style="font-weight:600">{_esc(i.get("name", ""))}</td>'
                         f'<td style="color:#94a3b8;font-size:12px">{_esc(str(i.get("desc", ""))[:200])}</td>'
                         f'<td style="font-size:11px;color:#64748b;word-break:break-all">{_esc(ev_disp)}</td></tr>')
            parts.append(self._collapsible(
                f'行为深析 ({len(bi)} 项) — 杀软对抗/Defender/UAC/提权/键盘记录/守护注入', 'dd_insights',
                '<table class="data-table"><thead><tr><th>类别</th><th>行为</th><th>说明</th><th>命中证据</th></tr></thead><tbody>'
                + rows + '</tbody></table>', default_open=True))

        # ---- 运行环境校验 ----
        env = getattr(dd, 'execution_environment', None) or []
        if env:
            rows = ''.join(
                f'<tr><td style="font-weight:600">{_esc(e.get("type", ""))}</td>'
                f'<td class="hash">{_esc(str(e.get("target", ""))[:120])}</td>'
                f'<td style="color:#94a3b8;font-size:12px">{_esc(str(e.get("desc", ""))[:200])}</td></tr>'
                for e in env[:30])
            parts.append(self._collapsible(
                f'运行环境校验 ({len(env)} 项) — 目标进程/调试器检测', 'dd_env',
                '<table class="data-table"><thead><tr><th>类型</th><th>目标</th><th>说明</th></tr></thead><tbody>'
                + rows + '</tbody></table>'))

        # ---- 对抗规避 ----
        ev = getattr(dd, 'defense_evasion', None) or []
        if ev:
            rows = ''.join(
                f'<tr><td style="font-weight:600;color:#f87171">{_esc(e.get("type", ""))}</td>'
                f'<td>{_esc(str(e.get("desc", ""))[:250])}</td>'
                f'<td style="font-size:11px;color:#64748b;word-break:break-all">'
                f'{_esc(str(e.get("evidence", ""))[:150])}</td></tr>' for e in ev[:30])
            parts.append(self._collapsible(
                f'对抗规避行为 ({len(ev)} 项)', 'dd_evasion',
                '<table class="data-table"><thead><tr><th>类型</th><th>详情</th><th>证据</th></tr></thead><tbody>'
                + rows + '</tbody></table>'))

        # ---- 载荷投递链 ----
        pd = getattr(dd, 'payload_delivery', None) or []
        if pd:
            rows = ''.join(
                f'<tr><td class="hash">{_esc(os.path.basename(p.get("file", "")))}</td>'
                f'<td>{_esc(str(p.get("kind", "")))}</td><td>{p.get("size", 0)}</td>'
                f'<td>{_esc(", ".join(p.get("yara", [])[:5]))}</td>'
                f'<td>{_esc(", ".join(p.get("exports", [])[:6]))}</td>'
                f'<td>{_esc(", ".join(p.get("iocs", [])[:4]))}</td></tr>' for p in pd[:15])
            parts.append(self._collapsible(
                f'载荷投递链 ({len(pd)} 个载荷文件)', 'dd_delivery',
                '<table class="data-table"><thead><tr><th>文件</th><th>类型</th><th>大小</th>'
                '<th>YARA</th><th>导出函数</th><th>IoC</th></tr></thead><tbody>' + rows + '</tbody></table>',
                default_open=True))

        # ---- 驱动链 ----
        dc = getattr(dd, 'driver_chain', None) or []
        if dc:
            rows = ''.join(
                f'<tr><td class="hash">{_esc(os.path.basename(d.get("file", "")))}</td>'
                f'<td>{_esc(str(d.get("signer", "") or "无签名"))}</td>'
                f'<td>{"✅ 签名有效" if d.get("signature_valid") else "❌ 无效/未签名"}</td>'
                f'<td>{_esc(", ".join(d.get("exports", [])[:8]))}</td></tr>' for d in dc[:10])
            parts.append(self._collapsible(
                f'驱动加载链 ({len(dc)} 个驱动文件) — 白驱动黑驱动检测', 'dd_driver',
                '<table class="data-table"><thead><tr><th>驱动文件</th><th>签名者</th><th>签名状态</th>'
                '<th>导出函数</th></tr></thead><tbody>' + rows + '</tbody></table>',
                default_open=True))

        # ---- 内存代码深析 ----
        mc = getattr(dd, 'memory_codes', None) or []
        if mc:
            blocks = ''
            for m in mc[:8]:
                exp_str = _esc(', '.join(m.exports[:10])) if m.exports else '—'
                dec_str = ''
                for d in m.decrypted_strings[:3]:
                    dec_str += f'<div><b>{_esc(d.get("technique", ""))}</b> (conf {d.get("confidence", 0)}) '
                    f'<code>{_esc(d.get("preview", ""))[:200]}</code></div>'
                theft = _esc('; '.join(t['desc'] for t in m.theft_signatures[:8])) if m.theft_signatures else '—'
                blocks += (f'<div style="background:#0f172a;border-radius:10px;padding:12px 16px;margin:10px 0">'
                           f'<b>{_esc(m.process or str(m.pid))}</b> '
                           f'<span class="risk-badge" style="background:#8b5cf6;color:#fff;font-size:11px">{_esc(m.kind)}</span> '
                           f'<code style="color:#f472b6">@{_esc(m.address)}</code> (size {m.size})'
                           f'<div style="margin-top:8px"><b>导出表:</b> {exp_str}</div>'
                           f'<div style="margin-top:6px"><b>解密字符串:</b>{dec_str or "—"}</div>'
                           f'<div style="margin-top:6px"><b>窃密特征命中:</b> {theft}</div></div>')
            parts.append(self._collapsible(
                f'内存代码深析 ({len(mc)} 处) — 反射加载/注入载荷导出表·解密字符串·特征码', 'dd_memcode',
                blocks, default_open=True))

        # ---- 网络外联画像 ----
        np_ = getattr(dd, 'network_profile', None)
        if np_ and (np_.c2_candidates or np_.targets):
            net_html = ''
            if np_.c2_candidates:
                rows = ''.join(
                    f'<tr class="suspicious"><td class="hash">{_esc(c.get("host", ""))}</td>'
                    f'<td>{c.get("port", "")}</td><td>{c.get("count", 0)}</td>'
                    f'<td>{c.get("bytes_sent", 0)} / {c.get("bytes_recv", 0)}</td>'
                    f'<td>{_esc(str(c.get("process", "")))}</td>'
                    f'<td style="color:#f87171">{_esc(", ".join(c.get("reasons", [])))}</td></tr>'
                    for c in np_.c2_candidates[:10])
                net_html += ('<h4 style="color:#ef4444;margin:10px 0 6px">C2 外联候选</h4>'
                             '<table class="data-table"><thead><tr><th>主机</th><th>端口</th><th>次数</th>'
                             '<th>上行/下行</th><th>进程</th><th>判定依据</th></tr></thead><tbody>'
                             + rows + '</tbody></table>')
            if np_.targets:
                rows = ''.join(
                    f'<tr><td class="hash">{_esc(t.get("host", ""))}</td><td>{t.get("port", "")}</td>'
                    f'<td>{t.get("count", 0)}</td><td>{t.get("bytes_sent", 0)} / {t.get("bytes_recv", 0)}</td></tr>'
                    for t in np_.targets[:12])
                net_html += ('<h4 style="margin:12px 0 6px">外联目标汇总</h4>'
                             '<table class="data-table"><thead><tr><th>主机</th><th>端口</th><th>次数</th>'
                             '<th>上行/下行(B)</th></tr></thead><tbody>' + rows + '</tbody></table>')
            if np_.dns_interesting:
                net_html += '<h4 style="margin:12px 0 6px">可疑 DNS 域名</h4><p>' + _esc(' | '.join(np_.dns_interesting[:20])) + '</p>'
            if np_.http_summary:
                rows = ''.join(
                    f'<tr><td>{_esc(h.get("method", ""))}</td><td class="hash">{_esc(h.get("host", ""))}</td>'
                    f'<td>{_esc(h.get("path", ""))[:100]}</td></tr>' for h in np_.http_summary[:10])
                net_html += '<h4 style="margin:12px 0 6px">HTTP 请求概要</h4>' + \
                    '<table class="data-table"><thead><tr><th>方法</th><th>主机</th><th>路径</th></tr></thead><tbody>' + rows + '</tbody></table>'
            parts.append(self._collapsible('网络外联画像', 'dd_network', net_html, default_open=True))

        # ---- 数据窃取线索 ----
        dt = getattr(dd, 'data_theft', None) or []
        if dt:
            cat_color = {'credential_qq': '#ec4899', 'credential_generic': '#f43f5e',
                         'browser': '#f59e0b', 'wallet': '#eab308', 'keylog': '#ef4444',
                         'screen_capture': '#f97316', 'win11_recall': '#0ea5e9',
                         'win11_cred': '#0284c7'}
            # ⚠ 展开: 之前只显示标签, 现在显示每条线索的 描述+证据来源 (内存/静态)
            rows = ''
            seen_cat = set()
            for t in dt[:30]:
                c = cat_color.get(t.get('category', ''), '#64748b')
                ev = str(t.get('evidence', ''))[:120]
                rows += (f'<tr><td><span class="risk-badge" style="background:{c};color:#fff;font-size:10px">'
                         f'{_esc(t.get("category", ""))}</span></td>'
                         f'<td>{_esc(t.get("desc", ""))}</td>'
                         f'<td style="font-size:11px;color:#94a3b8">{_esc(ev)}</td></tr>')
            parts.append(self._collapsible(
                f'数据窃取线索 ({len(dt)} 条特征命中)', 'dd_theft',
                '<table class="data-table"><thead><tr><th>类别</th><th>窃取特征</th><th>证据来源</th></tr></thead><tbody>'
                + rows + '</tbody></table>', default_open=True))

        # ---- 持久化 ----
        per = getattr(dd, 'persistence', None) or []
        if per:
            rows = ''.join(
                f'<tr><td style="font-weight:600">{_esc(p.get("type", ""))}</td>'
                f'<td class="hash">{_esc(str(p.get("target", ""))[:120])}</td></tr>' for p in per[:10])
            parts.append(self._collapsible(
                f'持久化机制 ({len(per)} 项)', 'dd_persist',
                '<table class="data-table"><thead><tr><th>类型</th><th>目标</th></tr></thead><tbody>'
                + rows + '</tbody></table>'))

        # ---- 进程链 ----
        pc = getattr(dd, 'process_chain', None) or []
        if pc:
            rows = ''.join(
                f'<tr><td>{p.pid}</td><td>{p.ppid}</td><td class="hash">{_esc(p.name)}</td>'
                f'<td style="font-size:12px">{_esc(str(p.cmdline)[:100])}</td>'
                f'<td>{_esc(", ".join(p.flags[:3]))}</td></tr>' for p in pc[:25])
            parts.append(self._collapsible(
                f'进程链 ({len(pc)} 个关联进程)', 'dd_procs',
                '<table class="data-table"><thead><tr><th>PID</th><th>PPID</th><th>进程</th>'
                '<th>命令行</th><th>标记</th></tr></thead><tbody>' + rows + '</tbody></table>'))

        # ---- IOC 分类汇总 ----
        ioc = getattr(dd, 'ioc_summary', None) or {}
        if ioc.get('total'):
            def _ioc_table(items):
                if not items:
                    return ''
                rows = ''.join(
                    f'<tr><td>{_esc(i.get("name", ""))}</td>'
                    f'<td class="hash">{_esc(str(i.get("value", ""))[:120])}</td>'
                    f'<td style="color:#94a3b8;font-size:12px">{_esc(str(i.get("note", ""))[:80])}</td></tr>'
                    for i in items[:12])
                return '<table class="data-table"><thead><tr><th>名称</th><th>值</th><th>说明</th></tr></thead><tbody>' + rows + '</tbody></table>'
            ioc_html = ''
            if ioc.get('files'):
                ioc_html += '<h4 style="color:#f472b6;margin:10px 0 6px">📁 文件 (' + str(len(ioc['files'])) + ')</h4>' + _ioc_table(ioc['files'])
            if ioc.get('network'):
                ioc_html += '<h4 style="color:#06b6d4;margin:10px 0 6px">🌐 网络 (C2/DNS) (' + str(len(ioc['network'])) + ')</h4>' + _ioc_table(ioc['network'])
            if ioc.get('registry'):
                ioc_html += '<h4 style="color:#f59e0b;margin:10px 0 6px">🔑 注册表 (' + str(len(ioc['registry'])) + ')</h4>' + _ioc_table(ioc['registry'])
            if ioc.get('tasks'):
                ioc_html += '<h4 style="color:#84cc16;margin:10px 0 6px">⏱ 计划任务/服务 (' + str(len(ioc['tasks'])) + ')</h4>' + _ioc_table(ioc['tasks'])
            parts.append(self._collapsible(
                f'IoC 分类汇总 ({ioc.get("total", 0)} 条)', 'dd_ioc', ioc_html, default_open=True))

        return ('<div class="section" style="border-left-color:#06b6d4"><h2 id="deepdive">深度追踪分析 (DeepDive)</h2>'
                + '\n'.join(parts) + '</div>')

    def _build_execution_tree_section(self, report):
        tree = getattr(report, '_execution_tree', None)
        if not tree or not isinstance(tree, dict):
            return ''

        def _details_tooltip(details):
            if not details or not isinstance(details, dict):
                return ''
            lines = ''.join(f'<b>{_esc(k)}</b>: {_esc(str(v)[:120])}<br>' for k, v in details.items() if v)
            return lines

        def _render_node(node, depth=0):
            if not isinstance(node, dict):
                return ''
            name = _esc(node.get('name', '') or '')
            node_type = node.get('type', '')
            icon = node.get('icon', '')
            label = _esc(node.get('label', '') or name)
            children = node.get('children', [])
            details = node.get('details', {})
            risk = node.get('risk', '')
            suspicious = node.get('suspicious', False)

            # Determine CSS class for node content
            cls = node_type
            if suspicious:
                cls += ' suspicious'
            if risk in ('critical', 'high'):
                cls += ' high-risk'

            # Build badge
            badge_html = ''
            if risk:
                risk_colors = {'critical': '#dc2626', 'high': '#ef4444', 'medium': '#f59e0b', 'low': '#22c55e'}
                rc = risk_colors.get(risk, '#64748b')
                badge_html = f'<span class="tree-node-badge" style="background:{rc}">{_esc(risk)}</span>'

            # Build tooltip
            tooltip_html = ''
            if details:
                tt = _details_tooltip(details)
                if tt:
                    tooltip_html = f'<div class="tree-tooltip">{tt}</div>'

            # Toggle arrow
            has_children = bool(children and isinstance(children, list) and len(children) > 0)
            toggle_class = 'tree-node-toggle leaf' if not has_children else 'tree-node-toggle'
            toggle_content = '' if not has_children else '▶'

            # Icon
            icon_html = f'<span class="tree-node-icon">{icon}</span>' if icon else ''

            # Build child HTML
            child_html = ''
            if has_children:
                child_items = ''.join(_render_node(c, depth + 1) for c in children)
                if child_items.strip():
                    child_html = f'<div class="tree-children">{child_items}</div>'

            return f'''<div class="tree-node">
<div class="tree-node-content {cls}">
<span class="{toggle_class}">{toggle_content}</span>
{icon_html}
<span class="tree-node-label">{label}</span>
<span class="tree-node-name">{name}</span>
{badge_html}
{tooltip_html}
</div>
{child_html}
</div>'''

        tree_html = _render_node(tree)
        if not tree_html.strip():
            return ''

        return f'''<div class="section" style="border-left-color:#14b8a6">
<h2 id="tree">执行流程思维导图</h2>
<div class="tree-section">
<div class="tree-container" id="execution-tree">
<div class="tree-children" style="border-left:none;margin-left:0;padding-left:0">{tree_html}</div>
</div>
</div>
</div>'''

    def _build_mitre_matrix_section(self, report):
        items = set()
        try:
            from analyzer.advanced_behavior import AdvancedBehaviorDetector
            mitre_map = getattr(AdvancedBehaviorDetector, 'MITRE_TAGS', {})
        except Exception:
            mitre_map = {}

        # ===== 1) 高级行为检测字段 =====
        ab = report.advanced_behavior
        if ab and hasattr(ab, 'ransomware_indicators'):
            fields = [
                'ransomware_indicators', 'rootkit_indicators', 'bootkit_indicators',
                'process_hollowing', 'process_injection', 'privilege_escalation',
                'uac_bypass', 'credential_theft', 'keylogging', 'c2_communication',
                'anti_vm', 'anti_sandbox', 'anti_debug', 'anti_analysis',
                'token_manipulation', 'apc_injection', 'thread_hijacking',
                'browser_data_theft', 'clipboard_monitoring', 'screenshot_capture',
                'lateral_movement', 'steganography', 'wiper_indicators',
                'file_encryption', 'domain_generation',
            ]
            for fname in fields:
                val = getattr(ab, fname, None)
                if isinstance(val, list):
                    for b in val:
                        if isinstance(b, str):
                            tag = mitre_map.get(b)
                            if tag:
                                items.add(tag)

        # ===== 2) Sigma 规则命中 (动态行为证据) =====
        sigma_matches = getattr(report, '_sigma_matches', []) or []
        for sm in sigma_matches:
            try:
                tech = sm.technique if hasattr(sm, 'technique') else sm.get('technique', '')
            except Exception:
                tech = ''
            if tech and str(tech).strip():
                items.add(str(tech).strip())
        if sigma_matches:
            try:
                from analyzer.sigma_rules import get_sigma_mitre_mapping
                for tech in (get_sigma_mitre_mapping(sigma_matches) or {}):
                    if tech and str(tech).strip():
                        items.add(str(tech).strip())
            except Exception:
                pass

        # ===== 3) Frida 内存保护监控 (RW→RX/DEP绕过/ROP喷射/注入/规避) =====
        memprot = getattr(report, '_memprot_summary', None) or {}
        if memprot.get('rw_to_rx'):
            items.add('T1620')                      # 反射式代码加载
        if memprot.get('rwx_alloc') or memprot.get('dep_bypass') or memprot.get('rop_like'):
            items.add('T1055')                      # 进程注入 (RWX/ROP 载荷暂存)
        if memprot.get('injection'):
            items.add('T1055.001')                  # 远程线程注入
        if memprot.get('huge_alloc'):
            items.add('T1055')                      # 内存喷射
        if (memprot.get('enum_snapshot_count') or 0) >= 20:
            items.add('T1057')                      # 进程发现
        if (memprot.get('sleep_total_ms') or 0) >= 60000:
            items.add('T1497.003')                  # 基于时间的逃避

        # ===== 4) API 监控行为序列 → MITRE 关键词映射 =====
        seq_mitre = {
            'inject': 'T1055', 'hollow': 'T1055.012', 'remote thread': 'T1055.001',
            'ntcreatethread': 'T1055.001', 'ntunmap': 'T1055.012',
            'ntmapviewofsection': 'T1055', 'ntcreatesection': 'T1055',
            'reflective': 'T1620', 'rwx': 'T1055', 'dep': 'T1055', 'rop': 'T1055',
            'shellcode': 'T1055',
            'keylog': 'T1056.001', 'hook': 'T1056.001',
            'privilege': 'T1134', 'token': 'T1134',
            'uac': 'T1548.002',
            'credential': 'T1003', 'lsass': 'T1003.001', 'dpapi': 'T1555.003',
            'defender': 'T1562.001', 'security software': 'T1562.001',
            'firewall': 'T1562.004',
            'scheduled task': 'T1053.005', 'schtasks': 'T1053.005',
            'persist': 'T1547', 'run key': 'T1547.001',
            'bcdedit': 'T1542.001',
            'vss': 'T1490', 'shadow': 'T1490', 'wbadmin': 'T1490',
            'event log': 'T1070.001', 'wevtutil': 'T1070.001',
            'anti-forensic': 'T1070', 'self-delete': 'T1070.004', 'deletion': 'T1070.004',
            'debugger': 'T1622', 'anti-debug': 'T1622',
            'process enumeration': 'T1057', 'toolhelp': 'T1057',
            'wmi': 'T1047',
            'disk': 'T1561.001', 'format': 'T1561.001',
            'dga': 'T1568.002',
            'dll side': 'T1574.002', 'side-loading': 'T1574.002',
            'amsi': 'T1562.001',
        }
        am = report.api_monitor
        if am is not None:
            for seq in (getattr(am, 'suspicious_sequences', None) or []):
                _seq_lower = str(seq).lower()
                for kw, tag in seq_mitre.items():
                    if kw in _seq_lower:
                        items.add(tag)

            # ===== 5) 高频危险 API 名称兜底 (memprot 脚本未捕获时的记录证据) =====
            calls = getattr(am, 'call_summary', None) or {}
            api_mitre = {
                'createremotethread': 'T1055.001', 'ntcreatethreadex': 'T1055.001',
                'writeprocessmemory': 'T1055', 'virtualallocex': 'T1055',
                'ntunmapviewofsection': 'T1055.012', 'setthreadcontext': 'T1055.012',
                'ntmapviewofsection': 'T1055', 'ntcreatesection': 'T1055',
                'setwindowshookex': 'T1056.001', 'adjusttokenprivileges': 'T1134',
                'cryptunprotectdata': 'T1555.003', 'ntquerysysteminformation': 'T1082',
                'ntsetinformationthread': 'T1622', 'isdebuggerpresent': 'T1622',
            }
            for api, tag in api_mitre.items():
                if any(api in str(k).lower() for k in calls):
                    items.add(tag)

        if not items:
            return ''

        tactics = {}
        for item in sorted(items):
            tactic = item.split('.')[0] if '.' in item else 'Other'
            tactics.setdefault(tactic, []).append(item)

        rows = ''
        for tactic, techniques in sorted(tactics.items()):
            cls = 'sev-medium'
            if any('execution' in t.lower() for t in techniques):
                cls = 'sev-high'
            elif any('credential' in t.lower() or 'defense' in t.lower() for t in techniques):
                cls = 'sev-critical'
            tech_str = ', '.join(f'<span class="tag">{_esc(t)}</span>' for t in techniques[:8])
            rows += f'<tr class="{cls}"><td style="font-weight:700;color:#e2e8f0;width:120px">{_esc(tactic)}</td><td>{tech_str}</td></tr>'

        return '<div class="section" style="border-left-color:#7c3aed"><h2 id="mitre">MITRE ATT&CK 技术矩阵 (' + str(len(items)) + ' 项)</h2><table class="data-table"><thead><tr><th>战术</th><th>技术</th></tr></thead><tbody>' + rows + '</tbody></table></div>'

    def _build_ioc_summary_section(self, report):
        ips = []
        domains = []
        urls = []

        if report.network:
            for c in report.network.tcp_connections:
                if c.remote_addr:
                    ips.append(c.remote_addr)
            for c in report.network.udp_connections:
                if c.remote_addr:
                    ips.append(c.remote_addr)
            for d in report.network.dns_queries:
                if d.domain:
                    domains.append(d.domain)
            for h in report.network.http_requests:
                if h.host:
                    domains.append(h.host)
                if h.path:
                    urls.append(f'{h.host}{h.path}')
        if report.strings:
            if report.strings.urls:
                urls.extend(report.strings.urls)
            if report.strings.ips:
                ips.extend(report.strings.ips)
            if report.strings.domains:
                domains.extend(report.strings.domains)

        ips = list(set(ips))[:30]
        domains = list(set(domains))[:30]
        urls = list(set(urls))[:30]

        if not (ips or domains or urls):
            return ''

        cards = ''
        for ip in ips:
            cards += f'''<div class="ioc-card">
<div class="ioc-icon">🌐</div>
<div class="ioc-body">
<div class="ioc-type">IP 地址</div>
<div class="ioc-val">{_esc(ip)}</div>
</div>
</div>'''
        for d in domains:
            cards += f'''<div class="ioc-card">
<div class="ioc-icon">🔗</div>
<div class="ioc-body">
<div class="ioc-type">域名</div>
<div class="ioc-val">{_esc(d)}</div>
</div>
</div>'''
        for u in urls:
            cards += f'''<div class="ioc-card">
<div class="ioc-icon">📎</div>
<div class="ioc-body">
<div class="ioc-type">URL</div>
<div class="ioc-val">{_esc(u[:120])}</div>
</div>
</div>'''

        total = len(ips) + len(domains) + len(urls)
        return f'''<div class="section" style="border-left-color:#ef4444">
<h2 id="ioc">IoC 汇总 (共 {total} 项)</h2>
<div class="ioc-summary">{cards}</div>
</div>'''

    # ========================================================================
    # Helper methods
    # ========================================================================

    def _build_behavior_timeline(self, report):
        """行为时间线流程图"""
        events = getattr(report, '_behavior_timeline', None) or []
        if not events:
            return ''

        cat_colors = {
            'archive': ('#6366f1', '#eef2ff'), 'static': ('#0891b2', '#ecfeff'),
            'process': ('#2563eb', '#eff6ff'), 'file': ('#059669', '#ecfdf5'),
            'registry': ('#d97706', '#fffbeb'), 'network': ('#7c3aed', '#f5f3ff'),
            'api': ('#9333ea', '#faf5ff'), 'memory': ('#dc2626', '#fef2f2'),
            'threat': ('#ea580c', '#fff7ed'), 'defense': ('#db2777', '#fdf2f8'),
            'inject': ('#e11d48', '#fff1f2'), 'priv': ('#ca8a04', '#fefce8'),
            'sysmod': ('#0d9488', '#f0fdfa'),
            'dep': ('#b91c1c', '#fee2e2'),
        }

        nodes = ''
        for i, ev in enumerate(events):
            cat = ev.get('category', '')
            color, bg = cat_colors.get(cat, ('#64748b', '#f8fafc'))
            icon = ev.get('icon', '')
            title = _esc(ev.get('title', '') or '')
            detail = _esc(ev.get('detail', '') or '')
            # 连接线
            connector = '' if i == 0 else f'<div style="width:2px;height:16px;background:{color};margin-left:20px;opacity:0.5"></div>'
            # 详情折叠
            detail_block = ''
            if detail:
                detail_block = f'<div style="font-size:11px;color:#94a3b8;margin-top:4px;max-width:900px;word-break:break-all;padding:4px 8px;background:rgba(30,41,59,0.5);border-radius:4px;border-left:2px solid {color}">{detail}</div>'
            nodes += f'''{connector}
<div style="display:flex;align-items:flex-start;gap:10px;padding:4px 0">
<div style="min-width:32px;height:32px;background:{bg};border:2px solid {color};border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px">{icon}</div>
<div style="flex:1;padding-top:4px">
<div style="font-size:13px;font-weight:600;color:#e2e8f0">{title}</div>
{detail_block}
</div>
<div style="font-size:10px;color:#475569;padding-top:4px;white-space:nowrap">#{ev.get("seq","")}</div>
</div>'''

        return f'''<div class="section" style="border-left-color:#6366f1">
<h2 id="timeline">行为时间线流程图 — 共 {len(events)} 个事件</h2>
<div style="padding-left:8px">{nodes}</div>
</div>'''

    def _build_dep_bypass_flow_section(self, report):
        """DEP 绕过行为时间线流程图 — 按攻击阶段展示证据链。

        阶段: 载荷准备/解密 → RWX 分配(DEP绕过) → 载荷写入 → 执行劫持 → 载荷执行/回连
        任一阶段有 Frida 内存保护事件 / API 调用记录证据即点亮该节点。
        """
        am = report.api_monitor
        mem_events = getattr(am, '_memprot_events', []) or [] if am else []
        sequences = getattr(am, 'suspicious_sequences', []) or [] if am else []
        records = getattr(am, 'call_records', []) or [] if am else []

        api_names = set()
        for r in records:
            api_names.add((getattr(r, 'api_name', '') or '').lower())

        rw_to_rx = sum(1 for e in mem_events if e.get('rw_to_rx'))
        rwx_alloc = sum(1 for e in mem_events if e.get('rwx_alloc'))
        dep = sum(1 for e in mem_events if e.get('dep_bypass'))
        rop = sum(1 for e in mem_events if e.get('rop_like'))
        huge = sum(1 for e in mem_events if e.get('huge_alloc'))
        injection = sum(1 for e in mem_events if e.get('injection'))

        seq_blob = ' '.join(sequences).lower()
        protect_rx = any(k in api_names for k in ('virtualprotect', 'ntprotectvirtualmemory',
                                                  'virtualprotectex'))
        write_payload = any(k in api_names for k in ('writeprocessmemory', 'ntwritevirtualmemory'))
        hijack_exec = any(k in api_names for k in ('createremotethread', 'ntcreatethreadex',
                                                   'rtlcreateuserthread', 'queueuserapc',
                                                   'setthreadcontext', 'resumethread',
                                                   'ntsetcontextthread'))
        mem = report.memory
        payload_runs = bool(
            (mem and (getattr(mem, 'shellcode_found', False) or getattr(mem, 'pe_in_memory', False)
                      or getattr(mem, 'rwx_regions', None)))
            or hijack_exec or injection
            or (report.network and getattr(report.network, 'tcp_connections', None)))

        stages = [
            ('① 载荷准备/解密', rw_to_rx > 0 or protect_rx or 'rw→rx' in seq_blob,
             f'RW→RX 转换×{rw_to_rx}' if rw_to_rx else
             ('VirtualProtect/解密API调用' if protect_rx else '未捕获到 RW→RX 保护切换')),
            ('② RWX 内存分配 (DEP绕过)', rwx_alloc > 0 or dep > 0 or 'ntallocatevirtualmemory rwx' in seq_blob,
             f'RWX×{rwx_alloc} DEP绕过×{dep} ROP喷射×{rop} 超大分配×{huge}'),
            ('③ 载荷写入目标内存', write_payload or 'writeprocessmemory' in seq_blob,
             'WriteProcessMemory/NtWriteVirtualMemory 调用链命中'
             if write_payload else '未捕获到跨进程写入'),
            ('④ 执行劫持', hijack_exec or injection > 0 or 'injection chain' in seq_blob,
             '远程线程/APC/SetThreadContext 调用链命中'
             if hijack_exec else (f'远程注入事件×{injection}' if injection else '未捕获到执行劫持')),
            ('⑤ 载荷执行/回连', payload_runs,
             '内存 shellcode/PE 注入/RWX 区域/网络回连命中'
             if payload_runs else '未见执行后行为'),
        ]

        active = [s for s in stages if s[1]]
        # 至少有一个核心阶段命中才展示流程图 (避免空流程图噪音)
        if not any(s[1] for s in stages[:4]):
            return ''

        def _fmt_size(n):
            try:
                n = int(n)
            except (TypeError, ValueError):
                return str(n)
            if n >= 1 << 30:
                return f'{n / (1 << 30):.2f} GB'
            if n >= 1 << 20:
                return f'{n / (1 << 20):.2f} MB'
            if n >= 1 << 10:
                return f'{n / (1 << 10):.1f} KB'
            return f'{n} B'

        nodes = ''
        for i, (name, hit, detail) in enumerate(stages):
            color = '#ef4444' if hit else '#475569'
            bg = 'rgba(239,68,68,0.12)' if hit else 'rgba(51,65,85,0.35)'
            border = '#ef4444' if hit else '#334155'
            marker = '✅' if hit else '⬜'
            nodes += f'''<div style="min-width:150px;flex:1;background:{bg};border:1px solid {border};
border-radius:10px;padding:10px 12px;text-align:center">
<div style="font-size:20px">{marker}</div>
<div style="font-size:12px;font-weight:600;color:{color};margin:4px 0">{_esc(name)}</div>
<div style="font-size:10px;color:#94a3b8;line-height:1.5">{_esc(detail)}</div>
</div>'''
            if i < len(stages) - 1:
                nodes += '<div style="align-self:center;color:#64748b;font-size:16px">→</div>'

        events_html = ''
        if mem_events:
            rows = ''
            for e in mem_events[:12]:
                mark = []
                if e.get('dep_bypass'):
                    mark.append('DEP绕过')
                if e.get('rop_like'):
                    mark.append('ROP喷射')
                if e.get('rw_to_rx'):
                    mark.append('RW→RX')
                if e.get('rwx_alloc'):
                    mark.append('RWX')
                if e.get('huge_alloc'):
                    mark.append('超大')
                if e.get('injection'):
                    mark.append('注入')
                prot = _esc(e.get('new_prot', '') or '')
                if e.get('protection'):
                    prot += f' <span class="hash">({_esc(e.get("protection", ""))})</span>'
                rows += (f'<tr class="suspicious"><td><code>{_esc(e.get("api", ""))}</code></td>'
                         f'<td class="hash">{_esc(e.get("base", ""))}</td>'
                         f'<td>{_fmt_size(e.get("size", 0))}</td>'
                         f'<td>{_esc(e.get("old_prot", ""))} → {prot}</td>'
                         f'<td>{"/".join(mark)}</td></tr>')
            events_html = ('<div style="margin-top:12px"><div style="font-size:12px;font-weight:600;'
                           'color:#cbd5e1;margin-bottom:6px">🔎 关键内存保护事件</div>'
                           '<table class="data-table"><thead><tr><th>API</th><th>地址</th><th>大小</th>'
                           '<th>保护变化</th><th>判定</th></tr></thead><tbody>'
                           + rows + '</tbody></table></div>')

        return f'''<div class="section" style="border-left-color:#dc2626">
<h2 id="dep-flow">DEP 绕过行为时间线流程图 — 共 {len(active)}/{len(stages)} 个阶段命中</h2>
<div style="display:flex;gap:8px;align-items:stretch;overflow-x:auto;padding:8px 0">{nodes}</div>
<div style="font-size:12px;color:#94a3b8;margin-top:4px">
MITRE: T1620 反射式代码加载 · T1055 进程注入 · T1218.011 系统二进制代理执行
</div>
{events_html}
</div>'''

    def _build_association_graph(self, report):
        """深度关联图 — 纯内联 SVG 分层布局: 样本→进程→文件→网络→注册表"""
        dyn = report.dynamic
        if not dyn:
            return ''

        procs = list(getattr(dyn, 'processes_created', []) or [])[:20]
        files = list(getattr(dyn, 'files_created', []) or [])[:30]
        regs_dyn = list(getattr(dyn, 'registry_modified', []) or [])
        sr = getattr(dyn, 'sandbox_result', None)

        net = report.network
        tcp = list(getattr(net, 'tcp_connections', []) or []) if net else []
        dns = list(getattr(net, 'dns_queries', []) or []) if net else []

        # 注册表节点来源: 动态 registry_modified + sandbox_result registry_created/modified
        reg_entries = []
        for r in regs_dyn:
            if isinstance(r, dict):
                key = r.get('key', '') or r.get('path', '') or ''
                pid = r.get('pid', '') or r.get('process_pid', '') or 0
            else:
                key = getattr(r, 'key', '') or getattr(r, 'path', '') or ''
                pid = getattr(r, 'pid', '') or getattr(r, 'process_pid', '') or 0
            if key:
                reg_entries.append((str(key), pid))
        if sr:
            for key in (getattr(sr, 'registry_created', []) or []):
                if key:
                    reg_entries.append((str(key), 0))
            for key in (getattr(sr, 'registry_modified', []) or []):
                if key:
                    reg_entries.append((str(key), 0))
        reg_entries = reg_entries[:15]

        if not (procs or files or tcp or dns or reg_entries):
            return ''

        def _gv(obj, key, default=''):
            """dict / object 兼容取值"""
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        def _entry_path(entry):
            if isinstance(entry, dict):
                return entry.get('path', '') or ''
            return getattr(entry, 'path', '') or str(entry)

        def _short(text, n=28):
            text = str(text)
            return text if len(text) <= n else text[:n - 1] + '…'

        def _safe_int(v):
            try:
                return int(v)
            except Exception:
                return 0

        # 进程索引 (用于根进程判断和 pid 匹配)
        pid_map = {}
        for p in procs:
            pid = _safe_int(_gv(p, 'pid', 0))
            if pid:
                pid_map[pid] = p

        root_pids = []
        for p in procs:
            pid = _safe_int(_gv(p, 'pid', 0))
            ppid = _safe_int(_gv(p, 'ppid', 0))
            if pid and (ppid not in pid_map or ppid == 0):
                root_pids.append(pid)
        if not root_pids and pid_map:
            root_pids = [min(pid_map)]

        layers = {0: [], 1: [], 2: [], 3: [], 4: []}
        positions = {}
        edges = []

        def add_node(nid, layer, label, color):
            label = _esc(_short(label))
            x = layer * 260
            y = len(layers[layer]) * 46
            positions[nid] = (x, y)
            layers[layer].append({'id': nid, 'label': label, 'color': color, 'x': x, 'y': y})

        # Layer0: 样本根节点
        sample_name = ''
        if report.file_info:
            sample_name = getattr(report.file_info, 'name', '') or ''
        if not sample_name:
            sample_name = report.scan_id or '样本'
        add_node('sample', 0, sample_name, '#ef4444')

        # Layer1: 进程节点
        for p in procs:
            pid = _safe_int(_gv(p, 'pid', 0))
            if not pid:
                continue
            name = _gv(p, 'name', '?') or '?'
            add_node(f'p{pid}', 1, f'{name} [PID {pid}]', '#facc15')
            if pid in root_pids:
                edges.append(('sample', f'p{pid}'))

        # Layer2: 文件节点 + 进程→文件边 (文件路径位于进程 exe 同目录树下)
        file_nodes = []
        for entry in files:
            fpath = _entry_path(entry)
            if not fpath:
                continue
            nid = f'f{len(file_nodes)}'
            file_nodes.append((nid, fpath))
            add_node(nid, 2, os.path.basename(fpath) or fpath, '#4ade80')

        for nid, fpath in file_nodes:
            fdir = os.path.dirname(fpath).lower()
            matched_pid = 0
            for p in procs:
                exe = _gv(p, 'exe', '') or ''
                pdir = os.path.dirname(exe).lower()
                if pdir and fdir.startswith(pdir[:30]):
                    matched_pid = _safe_int(_gv(p, 'pid', 0))
                    break
            if matched_pid and f'p{matched_pid}' in positions:
                edges.append((f'p{matched_pid}', nid))

        # Layer3: 网络节点 (TCP/DNS, 合计上限 15) + 进程→网络边 (pid 匹配)
        net_nodes = []
        net_entries = list(tcp) + list(dns)
        # 未抓包时 pcap 为空, 回退到进程级连接监控 (dynamic.network_connections),
        # 否则图谱的网络层会整层消失 (只剩样本→进程一条线)。
        if not net_entries:
            dyn_conns = list(getattr(dyn, 'network_connections', []) or [])
            net_entries = dyn_conns
        for c in net_entries[:15]:
            if isinstance(c, dict):
                remote = c.get('remote_addr', '') or ''
                port = c.get('remote_port', '')
                domain = c.get('domain', '') or ''
                pid = c.get('pid', 0)
                # 进程级监控的字段名是 remote (字符串 "ip:port")
                if not remote and not domain and c.get('remote'):
                    label = str(c.get('remote', ''))
                    nid = f'net{len(net_nodes)}'
                    net_nodes.append((nid, pid))
                    add_node(nid, 3, label, '#60a5fa')
                    continue
            else:
                remote = getattr(c, 'remote_addr', '') or ''
                port = getattr(c, 'remote_port', '')
                domain = getattr(c, 'domain', '') or ''
                pid = getattr(c, 'pid', 0)
                if not remote and not domain and getattr(c, 'remote', ''):
                    label = str(getattr(c, 'remote', ''))
                    nid = f'net{len(net_nodes)}'
                    net_nodes.append((nid, pid))
                    add_node(nid, 3, label, '#60a5fa')
                    continue
            label = domain if domain else (f'{remote}:{port}' if remote else (str(remote or domain or '?')))
            nid = f'net{len(net_nodes)}'
            net_nodes.append((nid, pid))
            add_node(nid, 3, label, '#60a5fa')

        for nid, pid in net_nodes:
            pid = _safe_int(pid)
            if pid and f'p{pid}' in positions:
                edges.append((f'p{pid}', nid))
            else:
                # 无 pid 匹配时至少把网络节点挂到样本根, 保持图谱连通性
                edges.append(('sample', nid))

        # Layer4: 注册表节点 + 进程→注册表边 (pid 匹配)
        for i, (key, pid) in enumerate(reg_entries):
            nid = f'r{i}'
            add_node(nid, 4, key, '#fb7185')
            pid = _safe_int(pid)
            if pid and f'p{pid}' in positions:
                edges.append((f'p{pid}', nid))

        # 渲染 SVG
        edge_lines = []
        for a, b in edges:
            if a not in positions or b not in positions:
                continue
            x1 = positions[a][0] + 240
            y1 = positions[a][1] + 17
            x2 = positions[b][0]
            y2 = positions[b][1] + 17
            edge_lines.append(
                f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                f'stroke="#64748b" stroke-width="1.5" opacity="0.55"/>'
            )

        node_html = []
        for layer in layers.values():
            for node in layer:
                node_html.append(
                    f'<rect x="{node["x"]}" y="{node["y"]}" width="240" height="34" rx="7" '
                    f'fill="{node["color"]}" fill-opacity="0.14" stroke="{node["color"]}" stroke-width="1.2"/>'
                )
                node_html.append(
                    f'<text x="{node["x"] + 12}" y="{node["y"] + 21}" fill="#e2e8f0" '
                    f'font-size="12" font-family="\'Microsoft YaHei\',\'Segoe UI\',Arial,sans-serif">{node["label"]}</text>'
                )

        max_layer = max((i for i, l in layers.items() if l), default=0)
        max_count = max((len(l) for l in layers.values()), default=1)
        svg_width = max(560, (max_layer + 1) * 260)
        svg_height = max(120, max_count * 46 + 40)

        svg = (f'<svg viewBox="0 0 {svg_width} {svg_height}" xmlns="http://www.w3.org/2000/svg" '
               f'style="width:100%;height:auto;min-width:560px;background:transparent">'
               + ''.join(edge_lines) + ''.join(node_html) + '</svg>')

        return ('<div class="section" style="border-left-color:#14b8a6">'
                '<h2 id="graph">深度关联图 (样本→进程→文件→网络→注册表)</h2>'
                f'<div style="overflow-x:auto;padding:10px 0">{svg}</div>'
                '</div>')

    def _proc_tree_chart_data(self, report):
        dyn = report.dynamic
        if not dyn:
            return None
        procs = list(dyn.processes_created or [])
        if not procs:
            return None
        nodes = {}
        for p in procs:
            pid = p.get('pid')
            if pid is None:
                continue
            nodes[pid] = {'name': f"{p.get('name') or '?'} [{pid}]",
                          'pid': pid, 'ppid': p.get('ppid') or 0}
        pids = set(nodes.keys())
        roots = [n for pid, n in nodes.items() if n['ppid'] not in pids or n['ppid'] == 0]
        if not roots and nodes:
            roots = [next(iter(nodes.values()))]
        seen = set()

        def build(n):
            if n['pid'] in seen:
                return None
            seen.add(n['pid'])
            kids = [build(c) for c in nodes.values() if c['ppid'] == n['pid']]
            kids = [k for k in kids if k]
            return {'name': n['name'], 'children': kids if kids else []}

        data = [d for d in (build(r) for r in roots) if d]
        return data if data else None

    def _network_chart_data(self, report):
        net = getattr(report, 'network', None)
        nodes = []
        links = []
        seen_ids = set()
        seen_links = set()

        def add_node(nid, name, category, size, color=None):
            if nid in seen_ids:
                return
            seen_ids.add(nid)
            n = {'id': nid, 'name': name, 'category': category, 'symbolSize': size}
            if color:
                n['itemStyle'] = {'color': color}
            nodes.append(n)

        def add_link(source, target):
            key = (source, target)
            if key in seen_links:
                return
            seen_links.add(key)
            links.append({'source': source, 'target': target})

        def _is_noise_remote(addr):
            addr = str(addr or '').strip().lower()
            return (not addr or addr in ('0.0.0.0', '::', '::1', '127.0.0.1')
                    or addr.startswith('127.'))

        add_node('sample', '样本进程', 0, 45, '#ef4444')

        tcp_conns = list(getattr(net, 'tcp_connections', []) or []) if net else []
        dns_queries = list(getattr(net, 'dns_queries', []) or []) if net else []

        # TCP: 可疑连接优先展示, 回环/空地址剔除, 同名远端只保留一个节点和一条边
        conns = [c for c in tcp_conns if not _is_noise_remote(getattr(c, 'remote_addr', ''))]
        conns.sort(key=lambda c: (not bool(getattr(c, 'is_suspicious', False)),
                                  getattr(c, 'remote_addr', ''),
                                  getattr(c, 'remote_port', 0)))
        for conn in conns[:40]:
            remote = f"{conn.remote_addr}:{conn.remote_port}"
            add_node('tcp_' + remote, remote, 1, 16,
                     '#f59e0b' if getattr(conn, 'is_suspicious', False) else None)
            add_link('sample', 'tcp_' + remote)

        # 未开启抓包(--enable-network)时 pcap 为空, 但进程级网络监控
        # (dynamic.network_connections) 仍在采集 — 用其作为图谱回退数据源,
        # 否则“网络连接”交互图谱会整块消失。
        if not conns and not dns_queries:
            dyn = getattr(report, 'dynamic', None)
            dyn_conns = list(getattr(dyn, 'network_connections', []) or []) if dyn else []
            for c in dyn_conns[:30]:
                if isinstance(c, dict):
                    remote = str(c.get('remote', '') or '')
                else:
                    remote = str(getattr(c, 'remote', '') or '')
                if not remote or _is_noise_remote(remote.rsplit(':', 1)[0]):
                    continue
                nid = 'tcp_' + remote
                add_node(nid, remote, 1, 16)
                add_link('sample', nid)

        for dq in dns_queries[:30]:
            if not getattr(dq, 'domain', ''):
                continue
            nid = 'dns_' + dq.domain
            add_node(nid, dq.domain, 2, 14,
                     '#fbbf24' if getattr(dq, 'is_suspicious', False) else None)
            add_link('sample', nid)
        if net:
            for fp in (getattr(net, 'tls_fingerprints', []) or [])[:15]:
                if fp.get('ja3'):
                    nid = 'ja3_' + fp['ja3'][:12]
                    label = f"JA3 {fp['ja3'][:12]}" + (f" / {fp['sni']}" if fp.get('sni') else '')
                    add_node(nid, label, 3, 20, '#a855f7')
                    add_link('sample', nid)
        if len(nodes) <= 1:
            return None
        return {'nodes': nodes, 'links': links}

    def _build_charts_section(self, report):
        import json
        proctree = self._proc_tree_chart_data(report)
        netgraph = self._network_chart_data(report)
        if not proctree and not netgraph:
            return ''
        blocks = []
        scripts = []

        def _tree_fallback_html(nodes):
            def _li(node):
                kids = node.get('children') or []
                inner = ''.join(_li(k) for k in kids)
                return (f'<li>{_esc(node.get("name", ""))}'
                        + (f'<ul style="margin:2px 0 2px 16px;list-style:none">{inner}</ul>' if inner else '')
                        + '</li>')
            return ('<ul style="margin:4px 0 0 14px;list-style:none;font-size:12px;color:#cbd5e1">'
                    + ''.join(_li(n) for n in nodes) + '</ul>')

        def _net_fallback_html(graph):
            colors = {1: '#60a5fa', 2: '#4ade80', 3: '#c084fc'}
            cats = {1: 'IP/端口', 2: '域名', 3: 'TLS指纹'}
            rows = []
            for n in graph['nodes']:
                if n.get('id') == 'sample':
                    continue
                cat = int(n.get('category', 1))
                color = colors.get(cat, '#64748b')
                rows.append(f'<div style="display:flex;align-items:center;gap:6px;padding:2px 0;font-size:12px">'
                            f'<span class="badge" style="background:{color};font-size:10px">{_esc(cats.get(cat, ""))}</span>'
                            f'<span class="hash">{_esc(n.get("name", ""))}</span></div>')
            return ('<div style="max-height:378px;overflow:auto">' + ''.join(rows) + '</div>')

        if proctree:
            fallback = ('<div class="chart-fallback" style="max-height:420px;overflow:auto;padding:6px 10px">'
                        '<div style="font-size:11px;color:#64748b;margin-bottom:6px">离线静态预览（联网后自动切换为交互图表）</div>'
                        + _tree_fallback_html(proctree) + '</div>')
            blocks.append('<div style="background:#111c2e;border-radius:8px;padding:12px">'
                          '<h3 style="margin:0 0 8px;font-size:14px;color:#7dd3fc">进程树</h3>'
                          '<div id="chart-proctree" style="width:100%;height:420px">' + fallback + '</div></div>')
            opt = {
                'tooltip': {'trigger': 'item'},
                'series': [{'type': 'tree', 'data': proctree, 'top': '5%', 'left': '8%',
                            'bottom': '5%', 'right': '15%', 'symbolSize': 12, 'orient': 'LR',
                            'expandAndCollapse': True,
                            'label': {'position': 'left', 'verticalAlign': 'middle',
                                      'align': 'right', 'fontSize': 11},
                            'leaves': {'label': {'position': 'right', 'align': 'left'}},
                            'lineStyle': {'color': '#64748b', 'width': 1.5}}],
            }
            scripts.append("initChart('chart-proctree', "
                           + json.dumps(opt, ensure_ascii=False) + ");")
        if netgraph:
            fallback = ('<div class="chart-fallback" style="max-height:420px;overflow:auto;padding:6px 10px">'
                        '<div style="font-size:11px;color:#64748b;margin-bottom:6px">离线静态预览（联网后自动切换为交互图表）</div>'
                        + _net_fallback_html(netgraph) + '</div>')
            blocks.append('<div style="background:#111c2e;border-radius:8px;padding:12px">'
                          '<h3 style="margin:0 0 8px;font-size:14px;color:#7dd3fc">网络连接</h3>'
                          '<div id="chart-network" style="width:100%;height:420px">' + fallback + '</div></div>')
            opt = {
                'tooltip': {'trigger': 'item'},
                'legend': {'data': ['样本', 'IP/端口', '域名', 'TLS指纹'],
                           'textStyle': {'color': '#e2e8f0'}},
                'series': [{
                    'type': 'graph', 'layout': 'force', 'data': netgraph['nodes'],
                    'links': netgraph['links'],
                    'categories': [{'name': '样本'}, {'name': 'IP/端口'},
                                   {'name': '域名'}, {'name': 'TLS指纹'}],
                    'roam': True, 'label': {'show': True, 'fontSize': 10, 'color': '#cbd5e1'},
                    'force': {'repulsion': 200, 'edgeLength': 120},
                    'lineStyle': {'color': '#334155', 'curveness': 0.1},
                }],
            }
            scripts.append("initChart('chart-network', "
                           + json.dumps(opt, ensure_ascii=False) + ");")
        init = '\n'.join(scripts).replace('</', '<\\/')
        return f'''<div class="section" style="border-left-color:#0ea5e9">
<h2 id="charts">交互式图表</h2>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:16px;margin-top:8px">{"".join(blocks)}</div>
<div style="font-size:11px;color:#64748b;margin-top:8px">图表需联网加载 ECharts；离线时显示静态预览，不影响其余报告内容。</div>
</div>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js"></script>
<script>
(function(){{
function initChart(id, option){{
    var el = document.getElementById(id);
    if (!el) {{ return; }}
    if (typeof echarts === 'undefined') {{ return; }}  // 离线: 保留静态预览
    var fb = el.querySelector('.chart-fallback');
    if (fb) {{ el.removeChild(fb); }}
    try {{
        var chart = echarts.getInstanceByDom(el) || echarts.init(el);
        chart.setOption(option);
    }} catch(e) {{}}
}}
{init}
}})();
</script>'''

    def _build_archive_children_section(self, report):
        """压缩包内多文件分析汇总"""
        children = getattr(report, '_archive_child_reports', None) or []
        if not children:
            return ''
        risk_colors = {'critical': '#dc2626', 'high': '#ef4444', 'medium': '#f59e0b', 'low': '#22c55e'}
        rows = ''
        for c in children:
            fname = _esc(c.get('filename', '') or '')
            sha = (c.get('sha256', '') or '')[:16] + '...'
            ent = c.get('entropy', 0)
            ent_cls = 'ent-high' if ent > 7 else ('ent-med' if ent > 5 else '')
            risk = c.get('risk_estimate', 'low')
            rc = risk_colors.get(risk, '#64748b')
            is_pe = '✓' if c.get('is_pe') else ''
            is_sc = '⚠️SC' if c.get('is_shellcode') else ''
            is_scr = '📜' if c.get('is_script') else ''
            pe_arch = c.get('pe_info', {}).get('architecture', '') if c.get('pe_info') else ''
            threat = c.get('threat_family', '') or ''
            if c.get('threat_malicious'):
                threat = f'⚠️ {threat}' if threat else '⚠️ Malicious'
            file_type = f'{is_pe} {is_sc} {is_scr}'.strip()
            dyn_summary = c.get('dynamic_summary', '') or ''
            dyn_txt = _esc(dyn_summary) if dyn_summary else '-'
            rows += f'''<tr>
<td class="path-cell">{fname}</td>
<td>{c.get("size_human","") or c.get("size","")}</td>
<td class="{ent_cls}">{ent:.2f}</td>
<td>{file_type} {_esc(pe_arch)}</td>
<td><span class="hash small">{sha}</span></td>
<td style="color:{rc};font-weight:600">{risk.upper()}</td>
<td class="small">{threat}</td>
<td class="small">{dyn_txt}</td>
</tr>'''

        total = len(report.archive.executable_files) if report.archive else len(children) + 1
        return f'''<div class="section" style="border-left-color:#f59e0b">
<h2 id="archive_children">压缩包内容分析 — 共 {total} 个可执行文件</h2>
<table class="data-table"><thead><tr><th>文件名</th><th>大小</th><th>熵值</th><th>PE</th><th>SHA256</th><th>风险</th><th>威胁情报</th><th>动态摘要</th></tr></thead><tbody>{rows}</tbody></table>
</div>'''

    def _build_shutdown_section(self, report):
        sb = getattr(report, '_shutdown_blocked', None)
        if not sb:
            return ''
        api_labels = {
            'ExitWindowsEx': 'ExitWindowsEx (用户态关机/重启/注销)',
            'InitiateSystemShutdownExW': 'InitiateSystemShutdownExW (远程关机—含超时+消息)',
            'InitiateSystemShutdownW': 'InitiateSystemShutdownW (本地关机)',
            'NtShutdownSystem': 'NtShutdownSystem (内核级关机—最底层)',
            'SetSystemPowerState': 'SetSystemPowerState (休眠/待机)',
        }
        rows = ''
        for item in sb:
            api = item.get('api', '?')
            desc = api_labels.get(api, api)
            detail = ''
            if api == 'ExitWindowsEx':
                detail = f"Flags: {item.get('desc', '')} (reason=0x{item.get('reason', 0):x})"
            elif api == 'InitiateSystemShutdownExW':
                detail = f"机器: {item.get('machine', '')} | 超时: {item.get('timeout', '')}s | {item.get('reboot', '')} {item.get('force', '')}"
            elif api == 'NtShutdownSystem':
                detail = f"动作: {item.get('desc', '')}"
            elif api == 'SetSystemPowerState':
                detail = f"模式: {item.get('suspend', '')} {item.get('force', '')}"
            rows += f'<tr class="suspicious"><td style="font-weight:600">{_esc(desc)}</td><td>{_esc(detail)}</td></tr>'
        table = '<table class="data-table"><thead><tr><th>被拦截的API</th><th>详情</th></tr></thead><tbody>' + rows + '</tbody></table>'
        return '<div class="section" style="border-left-color:#dc2626"><h2 id="shutdown">关机拦截 — 成功阻止 ' + str(len(sb)) + ' 次关机/重启/休眠尝试</h2>' + table + '</div>'

    def _collapsible(self, title, key, inner_html, default_open=False):
        attrs = ' open' if default_open else ''
        return f'<details class="collapsible" id="{key}"{attrs}><summary>{title}</summary><div class="content">{inner_html}</div></details>'

    def _build_urlscan_section(self, report):
        """构建 URL 挂马扫描区域 (report._url_scans)"""
        scans = getattr(report, '_url_scans', None) or []
        if not scans:
            return ''
        parts = []
        for i, r in enumerate(scans):
            if hasattr(r, 'to_dict'):
                try:
                    r = r.to_dict()
                except Exception:
                    pass
            if isinstance(r, dict):
                url = r.get('url', '')
                status = r.get('status_code', 0)
                level = r.get('risk_level', 'low')
                score = r.get('risk_score', 0)
                summary = r.get('summary', '')
                final_url = r.get('final_url', '')
                ips = r.get('resolved_ips', []) or []
                ioc = r.get('ioc_hits', []) or []
                findings = r.get('all_findings', []) or []
                ext = r.get('external_scripts', []) or []
                fetch_error = r.get('fetch_error', '')
                bad = level in ('high', 'critical')
            else:
                url = r.url
                status = r.status_code
                level = r.risk_level
                score = r.risk_score
                summary = r.summary
                final_url = r.final_url
                ips = r.resolved_ips or []
                ioc = r.ioc_hits or []
                findings = r.all_findings or []
                ext = r.external_scripts or []
                fetch_error = r.fetch_error
                bad = level in ('high', 'critical')
            sev_color = {'critical': '#f87171', 'high': '#fb923c', 'medium': '#fcd34d',
                         'low': '#4ade80', 'unknown': '#94a3b8'}.get(level, '#94a3b8')
            head = (f'<summary><span style="color:{sev_color};font-weight:700">'
                    f'{"⛔ " if bad else "⚠️ " if level == "medium" else "✅ "}{_esc(url)}</span> '
                    f'<span class="small">HTTP {status} · 评分 {score}/100 · {_esc(level.upper())} · '
                    f'{_esc(", ".join(ips[:2]) or "无IP")}</span></summary>')
            inner = ''
            if fetch_error:
                inner += f'<div class="small" style="color:#fca5a5;padding:4px 0">连接失败: {_esc(fetch_error)}</div>'
            if final_url and final_url != url:
                inner += f'<div class="small" style="padding:4px 0;word-break:break-all">最终地址: {_esc(final_url)}</div>'
            if summary:
                inner += f'<div class="small" style="padding:4px 0;color:#fcd34d">结论: {_esc(summary)}</div>'
            if ioc:
                ioc_badges = ''.join(f'<span class="tag" style="background:#dc2626;color:#fff">{_esc(h.get("family", "IoC"))}</span>'
                                     for h in ioc[:6])
                inner += f'<div class="badge-list" style="padding:4px 0">威胁情报命中: {ioc_badges}</div>'
            if findings:
                rows = ''
                for f in findings[:30]:
                    fsev = f.get('severity', 'low')
                    fc = {'critical': '#f87171', 'high': '#fb923c', 'medium': '#fcd34d',
                          'low': '#4ade80'}.get(fsev, '#94a3b8')
                    rows += (f'<tr class="{"suspicious" if fsev in ("critical", "high") else ""}">'
                             f'<td><span style="color:{fc};font-weight:600">{fsev}</span></td>'
                             f'<td class="small">{_esc(f.get("type", ""))}</td>'
                             f'<td class="small" style="font-family:Consolas,monospace;word-break:break-all">{_esc(f.get("evidence", ""))}</td>'
                             f'<td class="small">{f.get("line", "-")}</td></tr>')
                inner += ('<table class="data-table"><thead><tr><th>严重度</th><th>类型</th>'
                          '<th>证据</th><th>行</th></tr></thead><tbody>' + rows + '</tbody></table>')
            if ext:
                ext_count = sum(len(s.get('findings', []) or []) for s in ext)
                inner += f'<div class="small" style="padding:4px 0">外部脚本分析: {len(ext)} 个, 发现 {ext_count} 项</div>'
            parts.append(f'<details class="collapsible">{head}<div class="content-inner">{inner or "<div class=\"small\" style=\"padding:4px 0\">未发现明显恶意特征</div>"}</div></details>')
        n_bad = 0
        for r in scans:
            lvl = r.get('risk_level', 'low') if isinstance(r, dict) else getattr(r, 'risk_level', 'low')
            if lvl in ('high', 'critical'):
                n_bad += 1
        color = '#dc2626' if n_bad else '#6366f1'
        title = f'URL 挂马扫描 ({len(scans)} 个目标' + (f', 危险 {n_bad} 个' if n_bad else '') + ')'
        return f'<div class="section" style="border-left-color:{color}"><h2 id="urlscan">🌐 {title}</h2>{chr(10).join(parts)}</div>'

    def _build_log_section(self, report):
        logs = getattr(report, '_analysis_logs', '') or ''
        if not logs.strip():
            return ''
        # 截断过长日志
        if len(logs) > 200000:
            logs = logs[:200000] + '\n\n... (truncated)'
        lines = logs.count('\n') + 1
        escaped = _esc(logs)
        inner = f'<pre style="max-height:500px;overflow-y:auto;font-size:11px;line-height:1.4">{escaped}</pre>'
        return ('<div class="section" style="border-left-color:#64748b">'
                f'<h2 id="logs">分析日志 ({lines} 行)</h2>'
                + inner + '</div>')

    def _now(self):
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
