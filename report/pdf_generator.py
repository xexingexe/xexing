#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PDF 报告生成器 — 基于 fpdf2 纯 Python 实现"""

import time
import os
from datetime import datetime
from typing import Optional

from logger import get_logger
from analyzer.models import AnalysisReport
from version import APP_VERSION

logger = get_logger('report.pdf')

FPDF_AVAILABLE = False
try:
    from fpdf import FPDF
    _FPDF = FPDF
    FPDF_AVAILABLE = True
except ImportError:
    _FPDF = object


class PDFReportGenerator:
    """生成 PDF 格式恶意软件分析报告"""

    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, report: AnalysisReport, filepath: str = None) -> Optional[str]:
        if not FPDF_AVAILABLE:
            logger.warning("fpdf2 未安装，跳过 PDF 报告生成。请运行: pip install fpdf2")
            return None

        if filepath is None:
            filepath = os.path.join(self.output_dir, f"report_{report.scan_id}.pdf")

        pdf = _PDFReport(report)
        pdf.output(filepath)
        logger.info(f"PDF报告已保存至 {filepath}")
        return filepath


class _PDFReport(_FPDF):
    CN_FONT_AVAILABLE = False

    def __init__(self, report: AnalysisReport):
        super().__init__()
        self.report = report
        self._setup_fonts()
        self._build()

    def _setup_fonts(self):
        import os as _os
        font_paths = [
            r'C:\Windows\Fonts\msyh.ttc',
            r'C:\Windows\Fonts\simsun.ttc',
            r'C:\Windows\Fonts\msyh.ttf',
            r'C:\Windows\Fonts\simhei.ttf',
        ]
        for fp in font_paths:
            if _os.path.exists(fp):
                try:
                    self.add_font('CN', '', fp, uni=True)
                    self.add_font('CN', 'B', fp, uni=True)
                    self.CN_FONT_AVAILABLE = True
                    return
                except Exception:
                    continue
        logger.debug("未找到中文字体，PDF 将使用 ASCII")

    def _font(self, size=10, bold=False):
        if self.CN_FONT_AVAILABLE:
            self.set_font('CN', 'B' if bold else '', size)
        else:
            self.set_font('Helvetica', 'B' if bold else '', size)

    def _safe_text(self, text):
        if text is None:
            return ''
        text = str(text)
        if self.CN_FONT_AVAILABLE:
            return text
        return text.encode('ascii', errors='replace').decode('ascii', errors='replace')

    # ---- headers / footers ----
    def header(self):
        self._font(8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 6, self._safe_text(f'沙箱分析器 v{APP_VERSION}  |  {datetime.now().strftime("%Y-%m-%d %H:%M")}'), align='R')
        self.ln(3)
        self.set_draw_color(200, 50, 50)
        self.set_line_width(0.5)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self._font(7)
        self.set_text_color(128, 128, 128)
        self.set_draw_color(200, 50, 50)
        self.set_line_width(0.5)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)
        self.cell(0, 8, f'第 {self.page_no()}/{{nb}} 页', align='C')

    # ---- builders ----
    def _build(self):
        self.alias_nb_pages()
        self.set_auto_page_break(True, 20)
        self.add_page()
        _sections = [
            self._build_overview, self._build_hashes, self._build_risk, self._build_pe,
            self._build_strings, self._build_deobfuscation, self._build_overlay,
            self._build_behavior, self._build_family, self._build_destruction,
            self._build_shutdown, self._build_dropped_files, self._build_dynamic,
            self._build_memory, self._build_network, self._build_archive_children,
            self._build_behavior_timeline, self._build_community_signatures,
            self._build_yara, self._build_sigma, self._build_rat_config,
            self._build_threat_intel, self._build_mitre_matrix,
            self._build_ioc_summary, self._build_log,
        ]
        for _fn in _sections:
            _fn()
            # 每个 section 之间让出 GIL, 报告生成(收尾分析)不阻塞 UI 响应
            time.sleep(0)

    def _section_title(self, title, color=(200, 50, 50)):
        self.ln(4)
        self._font(14, bold=True)
        self.set_text_color(*color)
        self.cell(0, 8, self._safe_text(title))
        self.ln(8)
        self.set_draw_color(*color)
        self.set_line_width(0.8)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def _kv_row(self, key, value, w_key=50):
        self._font(9)
        self.set_text_color(60, 60, 60)
        self.cell(w_key, 6, self._safe_text(key) + ':')
        self.set_text_color(30, 30, 30)
        self.cell(0, 6, self._safe_text(value))
        self.ln(5.5)

    def _badge(self, text, color=(220, 50, 50)):
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self._font(8, bold=True)
        w = self.get_string_width(self._safe_text(text)) + 4
        self.cell(w, 5, self._safe_text(text), fill=True)
        self.set_text_color(30, 30, 30)
        self.cell(2, 5, '')

    def _table_header(self, cols, widths):
        self.set_fill_color(50, 50, 50)
        self.set_text_color(255, 255, 255)
        self._font(8, bold=True)
        for col, w in zip(cols, widths):
            self.cell(w, 6, self._safe_text(col), border=1, fill=True)
        self.ln()

    def _table_row(self, values, widths, fills=None):
        self._font(8)
        self.set_text_color(30, 30, 30)
        row_h = 6
        for i, (val, w) in enumerate(zip(values, widths)):
            fill = fills[i] if fills and i < len(fills) else False
            if fill:
                self.set_fill_color(245, 245, 245)
            else:
                self.set_fill_color(255, 255, 255)
            self.cell(w, row_h, self._safe_text(val or ''), border=1, fill=True)
        self.ln()

    # ---- sections ----
    def _build_overview(self):
        r = self.report
        fi = r.file_info
        if not fi:
            return
        risk_map = {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危'}
        risk = risk_map.get(r.risk_level, '低危')
        risk_colors = {'严重': (220, 38, 38), '高危': (239, 68, 68), '中危': (245, 158, 11), '低危': (34, 197, 94)}

        self._section_title('分析报告', (200, 50, 50))
        self._kv_row('扫描ID', r.scan_id)
        self._kv_row('文件名', fi.name)
        self._kv_row('大小', fi.size_human or f'{fi.size} bytes')
        self._kv_row('类型', fi.file_type)
        self._kv_row('MIME类型', fi.mime_type)
        self._kv_row('熵值', f'{fi.entropy:.3f} ({fi.entropy_level})')
        self._kv_row('扫描时间', r.scan_time or '')
        self._kv_row('耗时', f'{r.analysis_duration:.1f}s' if r.analysis_duration else '无')

        self.ln(2)
        self._font(10, bold=True)
        self.set_text_color(30, 30, 30)
        self.cell(40, 7, '风险等级:')
        self._badge(risk, risk_colors.get(risk, (34, 197, 94)))
        self.ln(10)

    def _build_hashes(self):
        fi = self.report.file_info
        if not fi:
            return
        self._section_title('文件哈希', (80, 80, 200))
        self._kv_row('MD5', fi.md5)
        self._kv_row('SHA1', fi.sha1)
        self._kv_row('SHA256', fi.sha256)
        self._kv_row('SHA512', (fi.sha512 or '')[:64] + '...' if fi.sha512 and len(fi.sha512) > 64 else (fi.sha512 or ''))
        if fi.imphash:
            self._kv_row('ImpHash', fi.imphash)
        if fi.ssdeep:
            self._kv_row('SSDEEP', fi.ssdeep)

    def _build_pe(self):
        pe = self.report.pe_info
        if not pe or not pe.sections:
            return
        self._section_title('PE 结构', (80, 80, 200))

        if pe.packer_info:
            self._font(9, bold=True)
            self.set_text_color(220, 38, 38)
            self.cell(0, 6, f'[!] 检测到加壳: {", ".join(pe.packer_info[:3])}')
            self.ln(8)

        self._kv_row('架构', pe.architecture or '无')
        self._kv_row('入口点', str(pe.entry_point) if pe.entry_point else '无')
        self._kv_row('镜像基址', str(pe.image_base) if pe.image_base else '无')
        self._kv_row('节区数', str(len(pe.sections)))
        self.ln(2)

        cols = ['节区', '虚拟地址', '虚拟大小', '原始大小', '熵值', '标志']
        widths = [22, 22, 22, 22, 22, 60]
        self._table_header(cols, widths)
        for i, s in enumerate(pe.sections[:20]):
            flags = []
            if s.is_executable:
                flags.append('X')
            if s.is_writable:
                flags.append('W')
            if s.is_suspicious:
                flags.append('SUS')
            values = [s.name, s.virtual_address, str(s.virtual_size), str(s.raw_size),
                      f'{s.entropy:.2f}', ','.join(flags) or 'R']
            self._table_row(values, widths, fills=[i % 2 == 0] * len(values))

    def _build_strings(self):
        st = self.report.strings
        if not st:
            return
        self._section_title('字符串分析', (80, 80, 200))
        self._kv_row('字符串总数', str(st.total_strings) if st.total_strings else '无')

        items = []
        items.append(('URL', st.urls or []))
        items.append(('IP地址', st.ips or []))
        items.append(('域名', st.domains or []))
        items.append(('可疑字符串', st.suspicious_strings or []))
        items.append(('PowerShell', st.powershell_patterns or []))

        for label, lst in items:
            if lst:
                shown = lst[:8]
                self._font(8, bold=True)
                self.set_text_color(60, 60, 60)
                self.cell(0, 6, f'{label} ({len(lst)}):')
                self.ln(5)
                self._font(7)
                self.set_text_color(80, 80, 80)
                for item in shown:
                    self.cell(0, 4, '  ' + self._safe_text(item))
                    self.ln(4)
                if len(lst) > 8:
                    self.cell(0, 4, f'  ... 还有 {len(lst) - 8} 项')
                    self.ln(4)
                self.ln(2)

    def _build_behavior(self):
        ab = self.report.advanced_behavior
        if not ab or not hasattr(ab, 'anti_sandbox'):
            return
        self._section_title('行为检测', (200, 120, 20))

        categories = [
            ('反沙箱', ab.anti_sandbox or []),
            ('反虚拟机', ab.anti_vm or []),
            ('反调试', ab.anti_debug or []),
            ('权限提升', ab.privilege_escalation or []),
            ('UAC绕过', ab.uac_bypass or []),
            ('进程注入', ab.process_injection or []),
            ('凭证窃取', ab.credential_theft or []),
            ('横向移动', ab.lateral_movement or []),
            ('键盘记录', ab.keylogging or []),
            ('设备监听', ab.audio_surveillance or []),
            ('代理操控', ab.proxy_manipulation or []),
            ('C2通信', ab.c2_communication or []),
            ('勒索软件', ab.ransomware_indicators or []),
            ('Rootkit/Bootkit', (ab.rootkit_indicators or []) + (ab.bootkit_indicators or [])),
        ]

        for cat, items in categories:
            if items:
                self.ln(1)
                self._font(9, bold=True)
                self.set_text_color(180, 80, 20)
                self.cell(0, 6, f'{cat} ({len(items)})')
                self.ln(6)
                self._font(8)
                self.set_text_color(50, 50, 50)
                for item in items[:10]:
                    text = str(item) if isinstance(item, str) else item.get('description', str(item))
                    self.cell(0, 4, '  - ' + self._safe_text(text))
                    self.ln(4)
                if len(items) > 10:
                    self.cell(0, 4, f'  ... 还有 {len(items) - 10} 项')
                    self.ln(4)

    def _build_family(self):
        mf = self.report.malware_family
        if not mf or not mf.all_families:
            return
        self._section_title('木马家族', (150, 30, 150))
        for fam in mf.all_families:
            self._font(10, bold=True)
            self.set_text_color(120, 30, 120)
            self.cell(0, 7, f'{fam.family_name} (置信度: {fam.confidence:.0f}%)')
            self.ln(7)
            if fam.description:
                self._font(8)
                self.set_text_color(60, 60, 60)
                self.multi_cell(0, 4, self._safe_text(fam.description))
                self.ln(2)
            if fam.indicators:
                self._font(8)
                self.set_text_color(80, 80, 80)
                for ind in fam.indicators[:5]:
                    text = str(ind) if isinstance(ind, str) else ind.get('description', str(ind))
                    self.cell(0, 4, '  - ' + self._safe_text(text))
                    self.ln(4)
            self.ln(3)

    def _build_threat_intel(self):
        ti = self.report.threat_intel
        if not ti or not ti.engine_results:
            return
        self._section_title('威胁情报', (20, 120, 200))

        cols = ['引擎', '命中', '详情']
        widths = [40, 20, 110]
        self._table_header(cols, widths)
        for i, eng in enumerate(ti.engine_results[:15]):
            result = eng.get('result', {}) or {}
            hit = '是' if result.get('hit') else '否'
            detail = ''
            if result.get('signature'):
                detail = str(result['signature'])[:60]
            elif result.get('family'):
                detail = str(result['family'])[:60]
            elif result.get('desc'):
                detail = str(result['desc'])[:60]
            values = [eng.get('engine', ''), hit, detail]
            self._table_row(values, widths, fills=[i % 2 == 0] * 3)

        if ti.confidence:
            self.ln(2)
            self._kv_row('置信度', ti.confidence)

    def _build_risk(self):
        r = self.report
        self._section_title('风险评分', (200, 50, 50))

        self._font(10, bold=True)
        self.set_text_color(30, 30, 30)
        self.cell(40, 7, '风险总分:')
        self.set_text_color(220, 38, 38)
        score = r.risk_score if r.risk_score else '无'
        self.cell(0, 7, f'{score}/100')
        self.ln(10)

        risk_items = []
        fi = r.file_info
        if fi and fi.entropy and fi.entropy > 7.5:
            risk_items.append(('高熵值', f'{fi.entropy:.2f}'))
        elif fi and fi.entropy and fi.entropy > 6.5:
            risk_items.append(('中熵值', f'{fi.entropy:.2f}'))
        pe = r.pe_info
        if pe and pe.suspicious_features:
            risk_items.append(('PE可疑特征', str(len(pe.suspicious_features))))
        if r.strings and r.strings.suspicious_strings:
            risk_items.append(('可疑字符串', f'{len(r.strings.suspicious_strings)} 个'))
        if r.malware_family and r.malware_family.matched_signatures > 0:
            risk_items.append(('特征匹配', str(r.malware_family.matched_signatures)))
        destruction = r.destruction
        if destruction:
            if getattr(destruction, 'edr_termination', None):
                risk_items.append(('终止EDR', '是'))
            if getattr(destruction, 'defender_registry_disable', None):
                risk_items.append(('禁用Defender', '是'))
            if getattr(destruction, 'firewall_disable', False):
                risk_items.append(('禁用防火墙', '是'))
            if getattr(destruction, 'raw_disk_access', False):
                risk_items.append(('磁盘直接访问', '是'))
        mem = r.memory
        if mem and mem.rwx_regions:
            risk_items.append(('RWX内存', str(len(mem.rwx_regions))))
        if mem and mem.shellcode_found:
            risk_items.append(('Shellcode', '是'))

        if risk_items:
            self.ln(2)
            self._font(9, bold=True)
            self.set_text_color(80, 80, 80)
            self.cell(0, 6, '风险因子:')
            self.ln(6)
            self._font(8)
            self.set_text_color(60, 60, 60)
            for lbl, val in risk_items:
                self.cell(0, 5, f'  - {lbl}: {val}')
                self.ln(5)
        self.ln(4)

    def _build_deobfuscation(self):
        deobs = getattr(self.report, '_deobfuscation', None)
        ps_deobs = getattr(self.report, '_ps_deobfuscated', None)
        if not deobs and not ps_deobs:
            return
        all_deobs = (deobs or []) + (ps_deobs or [])
        self._section_title('反混淆检测', (124, 58, 237))
        self._kv_row('发现技术数', str(len(all_deobs)))
        self.ln(2)
        self._font(8, bold=True)
        self.set_text_color(80, 80, 80)
        shown = 0
        for d in all_deobs:
            if shown >= 8:
                break
            tech = d.get('technique', 'unknown')
            conf = d.get('confidence', 0)
            key = d.get('key', '')
            key_str = f' [key={key}]' if key else ''
            self.cell(0, 4, f'  [{conf:.0%}] {tech}{key_str}')
            self.ln(4)
            preview = d.get('preview', '') or d.get('decoded', '')
            if preview:
                self.cell(0, 4, '    ' + self._safe_text(str(preview)[:120]))
                self.ln(4)
            shown += 1
        if len(all_deobs) > 8:
            self.cell(0, 4, f'  ... 还有 {len(all_deobs) - 8} 项')
            self.ln(4)
        self.ln(4)

    def _build_overlay(self):
        deobs = getattr(self.report, '_deobfuscation', None)
        if not deobs:
            return
        overlay_items = [d for d in deobs if isinstance(d, dict) and ('PE Overlay' in str(d.get('technique', '')) or d.get('type') == 'PE Overlay')]
        if not overlay_items:
            return
        self._section_title('Overlay 载荷', (245, 158, 11))
        for ov in overlay_items[:5]:
            offset = ov.get('offset', '?')
            size = ov.get('size', '?')
            payload = ov.get('payload', '未知')
            self._kv_row(f'Offset={offset}', f'{payload} ({size} bytes)')
        self.ln(2)

    def _build_destruction(self):
        destruction = self.report.destruction
        if not destruction or not getattr(destruction, 'destruction_level', None) or destruction.destruction_level == 'none':
            return
        self._section_title('破坏性行为', (220, 38, 38))
        self._kv_row('破坏等级', str(getattr(destruction, 'destruction_level', '无')))
        self._kv_row('MBR访问', '是' if destruction.mbr_access else '否')
        self._kv_row('卷影删除', '是' if destruction.shadow_copy_delete else '否')
        bdc = getattr(destruction, 'backup_delete_commands', None)
        self._kv_row('备份删除命令', str(len(bdc)) if bdc else '0')
        avt = getattr(destruction, 'av_termination', None)
        self._kv_row('终止杀软', str(len(avt)) if avt else '0')
        edr = getattr(destruction, 'edr_termination', None)
        self._kv_row('终止EDR', str(len(edr)) if edr else '0')
        drd = getattr(destruction, 'defender_registry_disable', None)
        self._kv_row('禁用Defender', str(len(drd)) if drd else '0')
        aib = getattr(destruction, 'av_install_block', None)
        self._kv_row('禁装杀软', str(len(aib)) if aib else '0')
        ddl = getattr(destruction, 'dangerous_driver_load', None)
        self._kv_row('危险驱动', str(len(ddl)) if ddl else '0')
        self._kv_row('防火墙禁用', '是' if getattr(destruction, 'firewall_disable', False) else '否')
        self._kv_row('磁盘直接访问', '是' if getattr(destruction, 'raw_disk_access', False) else '否')
        self.ln(4)

    def _build_shutdown(self):
        sb = getattr(self.report, '_shutdown_blocked', None)
        if not sb:
            return
        self._section_title('关机拦截', (220, 38, 38))
        self._kv_row('拦截次数', str(len(sb)))
        api_labels = {
            'ExitWindowsEx': 'ExitWindowsEx (用户态关机/重启/注销)',
            'InitiateSystemShutdownExW': 'InitiateSystemShutdownExW (远程关机)',
            'InitiateSystemShutdownW': 'InitiateSystemShutdownW (本地关机)',
            'NtShutdownSystem': 'NtShutdownSystem (内核级关机)',
            'SetSystemPowerState': 'SetSystemPowerState (休眠/待机)',
        }
        for item in sb:
            api = item.get('api', '?')
            label = api_labels.get(api, api)
            detail = ''
            if api == 'ExitWindowsEx':
                detail = item.get('desc', '')
            elif api == 'InitiateSystemShutdownExW':
                detail = f"{item.get('reboot','')} timeout={item.get('timeout','')}s"
            elif api == 'NtShutdownSystem':
                detail = item.get('desc', '')
            elif api == 'SetSystemPowerState':
                detail = f"{item.get('suspend','')}"
            self._kv_row(label, detail)
        self.ln(4)

    def _build_dropped_files(self):
        df = self.report.dropped_files
        if not df or not df.dropped_files:
            return
        self._section_title('释放文件', (139, 92, 246))
        self._kv_row('总数', str(df.total_dropped))
        self._kv_row('可执行', str(df.executable_dropped))
        self._kv_row('DLL', str(df.dll_dropped) if df.dll_dropped else '0')
        self._kv_row('脚本', str(df.script_dropped) if df.script_dropped else '0')
        self._kv_row('可疑', str(len(df.suspicious_dropped) if df.suspicious_dropped else 0))
        self.ln(2)

        cols = ['文件', '大小', '类型', '熵值', '备注']
        widths = [65, 20, 35, 18, 45]
        self._table_header(cols, widths)
        for i, f in enumerate(df.dropped_files[:20]):
            fname = os.path.basename(getattr(f, 'path', '') or '')[:40]
            note = (getattr(f, 'analysis_note', '') or '')[:28]
            vals = [fname, str(f.size), str(f.file_type)[:25], f'{f.entropy:.2f}', note]
            self._table_row(vals, widths, fills=[i % 2 == 0] * len(vals))
        if len(df.dropped_files) > 20:
            self._font(8)
            self.cell(0, 5, f'... 还有 {len(df.dropped_files) - 20} 个文件')
            self.ln(5)
        # 归档内层文件
        ac = getattr(df, 'archive_children', None) or []
        if ac:
            self.ln(2)
            self._font(9, bold=True)
            self.set_text_color(139, 92, 246)
            self.cell(0, 6, f'归档内层文件 ({len(ac)}):')
            self.ln(6)
            self._font(7)
            self.set_text_color(80, 80, 80)
            for c in ac[:15]:
                if isinstance(c, dict):
                    cn = (c.get('name', '') or '')[:45]
                    cp = (c.get('parent', '') or '')[:30]
                    cs = c.get('size', 0)
                    self.cell(0, 4, f'  {self._safe_text(cn)}  ({self._safe_text(cp)}, {cs} B)')
                    self.ln(4)
            if len(ac) > 15:
                self.cell(0, 4, f'  ... 还有 {len(ac) - 15} 个内层文件')
                self.ln(4)
        self.ln(2)

    def _build_dynamic(self):
        dyn = self.report.dynamic
        if not dyn:
            return
        self._section_title('动态分析', (6, 182, 212))
        self._kv_row('执行时间', f'{dyn.execution_time:.2f}s' if dyn.execution_time else 'N/A')
        self._kv_row('创建的进程', str(len(dyn.processes_created) if dyn.processes_created else 0))
        self._kv_row('创建的文件', str(len(dyn.files_created) if dyn.files_created else 0))
        self._kv_row('修改的文件', str(len(dyn.files_modified) if dyn.files_modified else 0))
        self._kv_row('DNS查询', str(len(dyn.dns_queries) if dyn.dns_queries else 0))
        self._kv_row('网络连接', str(len(dyn.network_connections) if dyn.network_connections else 0))
        self._kv_row('互斥体', str(len(dyn.mutexes) if dyn.mutexes else 0))
        self._kv_row('注册表修改', str(len(dyn.registry_modified) if dyn.registry_modified else 0))
        self.ln(2)

        if dyn.processes_created:
            self._font(9, bold=True)
            self.set_text_color(60, 60, 60)
            self.cell(0, 6, f'进程列表 ({len(dyn.processes_created)}):')
            self.ln(6)
            for p in dyn.processes_created[:15]:
                if isinstance(p, dict):
                    name = p.get('name', '?')
                    pid = p.get('pid', '')
                    cmd = (p.get('cmdline', '') or '')[:80]
                else:
                    name = str(getattr(p, 'name', '?'))
                    pid = getattr(p, 'pid', '')
                    cmd = str(getattr(p, 'cmdline', '') or '')[:80]
                self._font(7)
                self.set_text_color(80, 80, 80)
                self.cell(0, 4, f'  PID={pid}  {name}')
                self.ln(3.5)
                if cmd:
                    self.cell(0, 4, f'    {self._safe_text(cmd)}')
                    self.ln(3.5)
            if len(dyn.processes_created) > 15:
                self.cell(0, 4, f'  ... 还有 {len(dyn.processes_created) - 15} 个进程')
                self.ln(4)
        self.ln(2)

    def _build_memory(self):
        mem = self.report.memory
        if not mem:
            self._section_title('内存取证', (249, 115, 22))
            self._font(9)
            self.set_text_color(100, 100, 100)
            self.cell(0, 6, '内存取证分析需要开启动态分析 (--dynamic) 才能执行。')
            self.ln(8)
            return
        self._section_title('内存取证', (249, 115, 22))
        self._kv_row('内存区域总数', str(mem.total_regions))
        self._kv_row('可疑区域', str(len(mem.suspicious_regions) if mem.suspicious_regions else 0))
        self._kv_row('RWX区域', str(len(mem.rwx_regions) if mem.rwx_regions else 0))
        self._kv_row('Shellcode', '是' if mem.shellcode_found else '否')
        self._kv_row('PE注入', '是' if mem.pe_in_memory else '否')
        self._kv_row('转储文件', str(len(mem.dumped_files) if mem.dumped_files else 0))
        hg = getattr(mem, 'heavens_gate', None)
        self._kv_row("Heaven's Gate", str(len(hg)) if hg else '0')
        iath = getattr(mem, 'iat_hooks', None)
        self._kv_row('IAT Hook', str(len(iath)) if iath else '0')
        peba = getattr(mem, 'peb_anomalies', None)
        self._kv_row('PEB异常', '是' if peba else '否')
        self._kv_row('反Dump', str(len(getattr(mem, 'anti_dump_measures', []) or [])))
        self._kv_row('API Unhooking', str(len(getattr(mem, 'api_unhooking', []) or [])))
        self._kv_row('内核后门', str(len(getattr(mem, 'kernel_backdoor', []) or [])))
        self.ln(2)

        if mem.shellcode_found and mem.shellcode_details:
            self._font(9, bold=True)
            self.set_text_color(220, 38, 38)
            self.cell(0, 6, f'Shellcode 详情 ({len(mem.shellcode_details)}):')
            self.ln(5)
            for sc in mem.shellcode_details[:5]:
                if isinstance(sc, dict):
                    self._font(7)
                    self.set_text_color(60, 60, 60)
                    self.cell(0, 4, f'  {sc.get("address","")}  {sc.get("details","")}')
                    self.ln(4)

        if mem.pe_in_memory and mem.pe_injected_modules:
            self._font(9, bold=True)
            self.set_text_color(220, 38, 38)
            self.cell(0, 6, f'注入PE模块 ({len(mem.pe_injected_modules)}):')
            self.ln(5)
            for mod in mem.pe_injected_modules[:5]:
                if isinstance(mod, dict):
                    self._font(7)
                    self.set_text_color(60, 60, 60)
                    self.cell(0, 4, f'  {mod.get("address","")}  {mod.get("module","")}')
                    self.ln(4)
        self.ln(2)

    def _build_network(self):
        net = self.report.network
        if not net:
            return
        self._section_title('网络分析', (16, 185, 129))
        self._kv_row('总数据包', str(net.total_packets))
        self._kv_row('总流量', f'{net.total_bytes:,} bytes' if net.total_bytes else 'N/A')
        self._kv_row('DNS查询', str(len(net.dns_queries) if net.dns_queries else 0))
        self._kv_row('HTTP请求', str(len(net.http_requests) if net.http_requests else 0))
        self._kv_row('TCP连接', str(len(net.tcp_connections) if net.tcp_connections else 0))
        self._kv_row('UDP连接', str(len(net.udp_connections) if net.udp_connections else 0))
        self.ln(2)

        if net.tcp_connections:
            self._font(9, bold=True)
            self.set_text_color(60, 60, 60)
            self.cell(0, 6, f'TCP 连接 ({len(net.tcp_connections)}):')
            self.ln(6)
            cols = ['远程', '端口', '流量']
            widths = [90, 30, 60]
            self._table_header(cols, widths)
            for i, c in enumerate(net.tcp_connections[:15]):
                sent = c.bytes_sent or 0
                recv = c.bytes_recv or 0
                def _fmt_bytes(b):
                    if b >= 1048576: return f'{b/1048576:.1f}MB'
                    if b >= 1024: return f'{b/1024:.1f}KB'
                    return f'{b}B'
                traffic = f'up {_fmt_bytes(sent)} / dn {_fmt_bytes(recv)}' if (sent + recv) > 0 else '-'
                vals = [str(c.remote_addr)[:45], str(c.remote_port), traffic]
                self._table_row(vals, widths, fills=[i % 2 == 0] * 3)
            if len(net.tcp_connections) > 15:
                self._font(8)
                self.cell(0, 5, f'... 还有 {len(net.tcp_connections) - 15} 个连接')
                self.ln(5)

        if net.dns_queries:
            self.ln(2)
            self._font(9, bold=True)
            self.set_text_color(60, 60, 60)
            self.cell(0, 6, f'DNS 查询 ({len(net.dns_queries)}):')
            self.ln(5)
            self._font(7)
            self.set_text_color(80, 80, 80)
            for d in net.dns_queries[:10]:
                ips = ', '.join(d.resolved_ips) if d.resolved_ips else '-'
                self.cell(0, 4, f'  {self._safe_text(d.domain)} -> {ips}')
                self.ln(4)

        # 网络载荷 (Frida send/recv 捕获)
        am = getattr(self.report, 'api_monitor', None)
        net_payloads = getattr(am, '_net_payloads', None) or [] if am else []
        if net_payloads:
            self.ln(2)
            self._font(9, bold=True)
            self.set_text_color(16, 185, 129)
            self.cell(0, 6, f'网络载荷数据 (send/recv 前 512 字节, 共 {len(net_payloads)} 条):')
            self.ln(5)
            self._font(7)
            self.set_text_color(80, 80, 80)
            for np_item in net_payloads[:20]:
                if not isinstance(np_item, dict):
                    continue
                api = np_item.get('api', '')
                is_http = np_item.get('is_http', False)
                preview = (np_item.get('preview', '') or '')[:80]
                tag = '[HTTP]' if is_http else ''
                self.cell(0, 4, f'  {self._safe_text(api)} {tag} {self._safe_text(preview)}')
                self.ln(4)
            if len(net_payloads) > 20:
                self.cell(0, 4, f'  ... 还有 {len(net_payloads) - 20} 条载荷')
                self.ln(4)

        self.ln(2)

    def _build_community_signatures(self):
        sigs = getattr(self.report, '_community_signatures', None)
        if not sigs:
            return
        self._section_title('社区签名', (236, 72, 153))
        for s in sigs[:20]:
            name = (s.get('signature', '') or s.get('name', '') or '')[:60]
            desc = (s.get('description', '') or '')[:80]
            if name:
                self._kv_row(name, desc)
        if len(sigs) > 20:
            self._font(8)
            self.cell(0, 5, f'... 还有 {len(sigs) - 20} 项')
            self.ln(5)
        self.ln(2)

    def _build_yara(self):
        ym = getattr(self.report, '_yara_matches', None)
        if not ym:
            return
        self._section_title('YARA 规则', (245, 158, 11))
        cols = ['规则', '描述']
        widths = [80, 100]
        self._table_header(cols, widths)
        for i, y in enumerate(ym[:20]):
            rule = (y.get('rule', '') or y.get('name', '') or '')[:40]
            desc = (y.get('description', '') or '')[:50]
            self._table_row([rule, desc], widths, fills=[i % 2 == 0] * 2)
        if len(ym) > 20:
            self._font(8)
            self.cell(0, 5, f'... 还有 {len(ym) - 20} 条')
            self.ln(5)
        self.ln(2)

    def _build_sigma(self):
        sm = getattr(self.report, '_sigma_matches', None)
        if not sm:
            return
        self._section_title('Sigma 规则', (168, 85, 247))
        cols = ['标题', '级别', 'MITRE']
        widths = [90, 25, 65]
        self._table_header(cols, widths)
        for i, s in enumerate(sm[:20]):
            title = (s.title if hasattr(s, 'title') else s.get('title', ''))[:45]
            level = s.level if hasattr(s, 'level') else s.get('level', '')
            tech = s.technique if hasattr(s, 'technique') else s.get('technique', '')
            self._table_row([str(title or ''), str(level or ''), str(tech or '')], widths, fills=[i % 2 == 0] * 3)
        if len(sm) > 20:
            self._font(8)
            self.cell(0, 5, f'... 还有 {len(sm) - 20} 条')
            self.ln(5)
        self.ln(2)

    def _build_rat_config(self):
        rats = getattr(self.report, '_rat_config', None)
        if not rats:
            return
        self._section_title('RAT/Stealer 配置', (217, 70, 239))
        for r in rats[:15]:
            for k, v in r.items():
                self._kv_row(str(k)[:30], str(v)[:80])
        self.ln(2)

    def _build_mitre_matrix(self):
        ab = self.report.advanced_behavior
        if not ab or not hasattr(ab, 'anti_sandbox'):
            return
        try:
            from analyzer.advanced_behavior import AdvancedBehaviorDetector
            mitre_map = getattr(AdvancedBehaviorDetector, 'MITRE_TAGS', {})
        except Exception:
            mitre_map = {}

        items = set()
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

        if not items:
            return
        self._section_title('MITRE ATT&CK', (124, 58, 237))
        tactics = {}
        for item in sorted(items):
            tactic = item.split('.')[0] if '.' in item else 'Other'
            tactics.setdefault(tactic, []).append(item)
        for tactic, techniques in sorted(tactics.items()):
            self._font(9, bold=True)
            self.set_text_color(100, 60, 200)
            self.cell(0, 6, tactic)
            self.ln(5)
            self._font(7)
            self.set_text_color(60, 60, 60)
            tech_str = ', '.join(techniques[:8])
            self.cell(0, 4, '  ' + tech_str)
            self.ln(4)
            if len(techniques) > 8:
                self.cell(0, 4, f'  ... 还有 {len(techniques) - 8} 项')
                self.ln(4)
        self.ln(2)

    def _build_ioc_summary(self):
        ips = set()
        domains = set()
        urls = set()
        net = self.report.network
        if net:
            for c in net.tcp_connections:
                if c.remote_addr:
                    ips.add(c.remote_addr)
            for d in net.dns_queries:
                if d.domain:
                    domains.add(d.domain)
            for h in net.http_requests:
                if h.host:
                    domains.add(h.host)
        st = self.report.strings
        if st:
            if st.urls:
                urls.update(st.urls)
            if st.ips:
                ips.update(st.ips)
            if st.domains:
                domains.update(st.domains)

        if not (ips or domains or urls):
            return
        self._section_title('IoC 汇总', (239, 68, 68))
        total = len(ips) + len(domains) + len(urls)
        self._kv_row('总计', str(total))
        if ips:
            self.ln(1)
            self._font(9, bold=True)
            self.set_text_color(60, 60, 60)
            self.cell(0, 6, f'IP 地址 ({len(ips)}):')
            self.ln(5)
            self._font(7)
            self.set_text_color(80, 80, 80)
            for ip in sorted(ips)[:10]:
                self.cell(0, 4, f'  {ip}')
                self.ln(4)
        if domains:
            self._font(9, bold=True)
            self.set_text_color(60, 60, 60)
            self.cell(0, 6, f'域名 ({len(domains)}):')
            self.ln(5)
            self._font(7)
            self.set_text_color(80, 80, 80)
            for d in sorted(domains)[:10]:
                self.cell(0, 4, f'  {d}')
                self.ln(4)
        if urls:
            self._font(9, bold=True)
            self.set_text_color(60, 60, 60)
            self.cell(0, 6, f'URL ({len(urls)}):')
            self.ln(5)
            self._font(7)
            self.set_text_color(80, 80, 80)
            for u in sorted(urls)[:10]:
                self.cell(0, 4, f'  {self._safe_text(u[:100])}')
                self.ln(4)
        self.ln(2)

    def _build_archive_children(self):
        children = getattr(self.report, '_archive_child_reports', None) or []
        if not children:
            return
        self._section_title('压缩包多文件分析', (245, 158, 11))
        cols = ['文件', '大小', '熵值', '风险']
        widths = [80, 25, 25, 50]
        self._table_header(cols, widths)
        risk_map = {'critical': '严重', 'high': '高危', 'medium': '中', 'low': '低'}
        for i, c in enumerate(children):
            fname = os.path.basename(c.get('filename', '') or '')[:35]
            sz = c.get('size_human', '') or str(c.get('size', ''))
            ent = f'{c.get("entropy", 0):.2f}'
            risk = risk_map.get(c.get('risk_estimate', 'low'), '低')
            vals = [fname, sz, ent, risk]
            self._table_row(vals, widths, fills=[i % 2 == 0] * 4)

    def _build_behavior_timeline(self):
        events = getattr(self.report, '_behavior_timeline', None) or []
        if not events:
            return
        self._section_title('行为时间线', (99, 102, 241))
        self._font(8)
        for i, ev in enumerate(events[:40]):
            title = ev.get('title', '') or ''
            detail = ev.get('detail', '') or ''
            icon = ev.get('icon', '')
            self.set_text_color(60, 60, 60)
            self.cell(0, 4, f'  {icon} {self._safe_text(str(title)[:100])}')
            self.ln(4)
            if detail:
                self.set_text_color(120, 120, 120)
                self._font(7)
                self.cell(0, 3.5, f'       {self._safe_text(str(detail)[:120])}')
                self.ln(3.5)
                self._font(8)
        if len(events) > 40:
            self.cell(0, 4, f'  ... 还有 {len(events) - 40} 个事件')
            self.ln(4)
        self.ln(2)

    def _build_log(self):
        logs = getattr(self.report, '_analysis_logs', '') or ''
        if not logs.strip():
            return
        self._section_title('分析日志', (100, 116, 139))
        if len(logs) > 20000:
            logs = logs[:20000] + '\n\n... (truncated)'
        self._font(6)
        self.set_text_color(80, 80, 80)
        for line in logs.split('\n')[:60]:
            self.cell(0, 3, self._safe_text(line[:150]))
            self.ln(3)
        if logs.count('\n') > 60:
            self.cell(0, 3, f'... 还有 {logs.count(chr(10)) - 59} 行')
            self.ln(3)
        self.ln(2)
