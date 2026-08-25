#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web 监控模式 — 内嵌 HTTP 服务器，通过浏览器实时查看分析结果。
自动探测可用端口（5000, 1979, 1949, 2007, 2008, 8000, 8888），
展示局域网连接地址，报告 HTML 直接内嵌在响应中防止勒索修改本地文件。
"""
import os
import json
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

from logger import get_logger

logger = get_logger('web_monitor')

PORT_CANDIDATES = [5000, 1979, 1949, 2007, 2008, 8000, 8888]


class ReportSharedState:
    """分析报告共享状态（线程安全）— 支持板块级流式更新 + 磁盘半成品持久化"""

    # 板块顺序（页面骨架渲染顺序）
    SECTION_ORDER = ['overview', 'strings', 'family', 'behavior', 'yara',
                     'sigma', 'risk', 'dynamic', 'memory', 'network',
                     'dropped', 'urlscan', 'deepdive']

    def __init__(self):
        self._lock = threading.Lock()
        self.status = 'idle'          # idle / analyzing / done / error
        self.progress = 0             # 0-100
        self.current_step = ''
        self.html_content = ''        # 完整 HTML 报告
        self.errors = []
        self.log_lines = []           # 最近 200 条日志
        self.scan_id = ''
        self.file_name = ''
        self.sections = {}            # 板块名 → HTML 片段 (流式更新)
        self.progress_file = ''       # 半成品报告落盘路径 (崩溃/重启后可打开)

    def set_status(self, status: str, progress: int = 0, step: str = ''):
        with self._lock:
            self.status = status
            self.progress = progress
            if step:
                self.current_step = step

    def set_progress_file(self, path: str):
        """设置半成品报告落盘路径 (崩溃安全)"""
        with self._lock:
            self.progress_file = path
            self._persist_locked()

    def set_section(self, name: str, html: str):
        """发布/更新一个报告板块 — 同时落盘半成品 (系统崩溃/重启后仍可查看)"""
        with self._lock:
            self.sections[name] = html
            self._persist_locked()

    def _persist_locked(self):
        """将已生成的板块拼装成半成品报告写盘 (原子写)"""
        if not self.progress_file:
            return
        try:
            html = ('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">'
                    '<title>半成品分析报告 (实时) - ' + str(self.scan_id) + '</title>'
                    '<style>'
                    '*{margin:0;padding:0;box-sizing:border-box}'
                    'body{font-family:Microsoft YaHei,sans-serif;background:#0f172a;padding:20px;color:#e2e8f0}'
                    '.banner{background:#312e81;color:#f1f5f9;padding:14px 20px;border-radius:10px;margin-bottom:16px;'
                    'font-weight:700}'
                    '.progress{color:#fcd34d;font-size:12px;margin-top:4px}'
                    '.section{background:#1e293b;border:1px solid #334155;border-radius:10px;'
                    'padding:16px;margin-bottom:14px}'
                    '.waiting{color:#64748b;font-size:12px}'
                    '</style></head><body>')
            html += (f'<div class="banner">半成品分析报告 (系统崩溃安全备份)<br>'
                     f'<span class="progress">扫描: {self.scan_id} | 状态: {self.status} '
                     f'| 进度: {self.progress}% | 已生成板块: {len(self.sections)}/{len(self.SECTION_ORDER)}</span></div>')
            for sec in self.SECTION_ORDER:
                if sec in self.sections:
                    html += f'<div class="section">{self.sections[sec]}</div>'
            html += '</body></html>'
            tmp = self.progress_file + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(html)
            os.replace(tmp, self.progress_file)
        except Exception:
            pass

    def set_done(self, html: str, scan_id: str = '', file_name: str = ''):
        with self._lock:
            self.status = 'done'
            self.progress = 100
            self.current_step = '分析完成'
            self.html_content = html
            self.scan_id = scan_id
            self.file_name = file_name

    def set_error(self, error: str):
        with self._lock:
            self.status = 'error'
            self.errors.append(error)
            if len(self.errors) > 50:
                self.errors = self.errors[-50:]

    def add_log(self, line: str):
        with self._lock:
            self.log_lines.append(line)
            if len(self.log_lines) > 200:
                self.log_lines = self.log_lines[-200:]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                'status': self.status,
                'progress': self.progress,
                'current_step': self.current_step,
                'errors': list(self.errors),
                'log_lines': list(self.log_lines),
                'scan_id': self.scan_id,
                'file_name': self.file_name,
                'sections': dict(self.sections),
                'section_order': list(self.SECTION_ORDER),
                'progress_file': self.progress_file,
            }


class MonitorHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器 — 内嵌分析报告，不从文件读取"""

    shared_state: ReportSharedState = None

    def log_message(self, format, *args):
        pass  # 不打印到 stderr

    def do_GET(self):
        path = self.path.rstrip('/') or '/'

        if path == '/':
            self._serve_dashboard()
        elif path == '/api/status':
            self._serve_api_status()
        elif path == '/api/report':
            self._serve_api_report()
        elif path == '/api/logs':
            self._serve_api_logs()
        else:
            self.send_error(404)

    def _serve_dashboard(self):
        state = self.shared_state.snapshot() if self.shared_state else {}
        status = state.get('status', 'idle')
        progress = state.get('progress', 0)
        step = state.get('current_step', '')
        scan_id = state.get('scan_id', '')
        fname = state.get('file_name', '')
        sections = state.get('sections', {})
        order = state.get('section_order', [])
        progress_file = state.get('progress_file', '')

        # 分析完成 → 直接返回完整 HTML 报告（内嵌，不经过文件）
        if status == 'done' and self.shared_state and self.shared_state.html_content:
            html = self.shared_state.html_content
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(html.encode('utf-8'))))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
            return

        # 分析中 / 等待 → 流式报告页: 骨架先行 + JS 轮询实时填充各板块
        # 板块中文名
        sec_names = {'overview': '概览', 'strings': '字符串', 'family': '家族识别',
                     'behavior': '行为检测', 'yara': 'YARA 规则', 'sigma': 'Sigma 规则',
                     'risk': '风险评分', 'dynamic': '动态分析', 'memory': '内存取证',
                     'network': '网络分析', 'dropped': '释放文件', 'deepdive': '深度追踪'}
        skeleton = ''
        for sec in order:
            filled = sec in sections
            skeleton += (f'<div class="section" id="sec-{sec}" data-sec="{sec}">'
                         f'<div class="sec-title">📄 {sec_names.get(sec, sec)}'
                         f'<span class="sec-status {"ready" if filled else "waiting"}">'
                         f'{"已更新" if filled else "等待数据…"}</span></div>'
                         f'<div class="sec-body">{"<div class=waiting>等待分析完成…</div>" if not filled else sections[sec]}</div>'
                         f'</div>')

        body = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>沙箱分析器 — 实时报告</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Microsoft YaHei','Segoe UI',sans-serif;background:#0f172a;padding:20px;color:#e2e8f0;min-height:100vh}}
.topbar{{max-width:1200px;margin:0 auto 16px;background:#1e293b;border:1px solid #334155;border-radius:14px;padding:18px 24px}}
h1{{font-size:20px;margin-bottom:6px}}
.status-line{{font-size:13px;color:#94a3b8}}
.progress-bar{{height:10px;background:#0f172a;border-radius:5px;overflow:hidden;margin:10px 0}}
.progress-fill{{height:100%;width:{progress}%;background:#6366f1;border-radius:5px;transition:width 0.5s}}
.step{{font-size:12px;color:#64748b;margin-top:6px}}
.crash-note{{font-size:11px;color:#f59e0b;margin-top:8px}}
.container{{max-width:1200px;margin:0 auto}}
.section{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px 20px;margin-bottom:12px}}
.sec-title{{font-weight:700;font-size:15px;color:#f1f5f9;display:flex;justify-content:space-between;align-items:center}}
.sec-status{{font-size:11px;font-weight:400;border-radius:10px;padding:2px 10px}}
.sec-status.ready{{background:rgba(34,197,94,0.15);color:#86efac}}
.sec-status.waiting{{background:rgba(100,116,139,0.2);color:#94a3b8}}
.sec-body{{margin-top:10px;font-size:13px}}
.sec-body .waiting{{color:#64748b;font-style:italic}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
td,th{{padding:8px 12px;border-bottom:1px solid #334155;text-align:left;color:#cbd5e1}}
th{{color:#94a3b8;font-weight:600;background:#0f172a}}
code{{font-family:Consolas,monospace;font-size:12px;background:rgba(99,102,241,0.1);padding:1px 5px;border-radius:3px}}
.hash{{font-family:Consolas,monospace;font-size:11px;color:#94a3b8;word-break:break-all}}
.suspicious{{color:#fca5a5}}
</style>
</head>
<body>
<div class="topbar">
<h1>🛡 沙箱分析器 — 实时报告</h1>
<div class="status-line">状态: <b id="st-status">{status}</b> · 进度: <b id="st-progress">{progress}%</b> · <span id="st-step">{step}</span></div>
<div class="progress-bar"><div class="progress-fill" id="st-bar"></div></div>
<div class="scan-id" style="font-family:monospace;font-size:11px;color:#475569">{fname}{'  |  ' + scan_id if scan_id else ''}</div>
<div class="crash-note" id="crash-note" style="display:none">⚠ 半成品备份: {progress_file}</div>
</div>
<div class="container" id="report-container">{skeleton}</div>
<div class="footer" style="text-align:center;color:#475569;font-size:11px;margin-top:20px">实时流式更新 · 分析完成后自动展示完整报告 · 系统崩溃后可从半成品文件恢复</div>
<script>
var secOrder = {json.dumps(order, ensure_ascii=False)};
var secNames = {json.dumps(sec_names, ensure_ascii=False)};
function poll() {{
    fetch('/api/report').then(r => r.json()).then(d => {{
        document.getElementById('st-status').textContent = d.status;
        document.getElementById('st-progress').textContent = d.progress + '%';
        document.getElementById('st-bar').style.width = d.progress + '%';
        document.getElementById('st-step').textContent = d.current_step || '';
        if (d.progress_file) {{
            document.getElementById('crash-note').style.display = 'block';
        }}
        // 更新各板块
        secOrder.forEach(sec => {{
            var el = document.getElementById('sec-' + sec);
            if (!el) return;
            var body = el.querySelector('.sec-body');
            var st = el.querySelector('.sec-status');
            if (d.sections && d.sections[sec]) {{
                body.innerHTML = d.sections[sec];
                st.textContent = '已更新';
                st.className = 'sec-status ready';
            }}
        }});
        if (d.status === 'done') {{ location.reload(); }}
    }}).catch(() => {{}});
}}
setInterval(poll, 2000);
poll();
</script>
</body>
</html>'''
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body.encode('utf-8'))

    def _serve_api_report(self):
        state = self.shared_state.snapshot() if self.shared_state else {}
        body = json.dumps(state, ensure_ascii=False)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body.encode('utf-8'))

    def _serve_api_status(self):
        state = self.shared_state.snapshot() if self.shared_state else {}
        body = json.dumps(state, ensure_ascii=False)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(body.encode('utf-8'))

    def _serve_api_logs(self):
        state = self.shared_state.snapshot() if self.shared_state else {}
        body = '\n'.join(state.get('log_lines', []))
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(body.encode('utf-8'))


class WebMonitor:
    """Web 监控器 — 管理 HTTP 服务器生命周期"""

    def __init__(self):
        self._server: HTTPServer = None
        self._thread: threading.Thread = None
        self._port = 0
        self._running = False
        self.state = ReportSharedState()

    @staticmethod
    def _get_lan_ips() -> list:
        """获取局域网 IP 地址"""
        ips = []
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = info[4][0]
                if not ip.startswith('127.'):
                    ips.append(ip)
        except Exception:
            pass
        if not ips:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(('8.8.8.8', 80))
                ips.append(s.getsockname()[0])
                s.close()
            except Exception:
                ips.append('127.0.0.1')
        return list(set(ips))

    def _find_port(self) -> int:
        """按优先级探测可用端口"""
        for port in PORT_CANDIDATES:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                s.bind(('0.0.0.0', port))
                s.close()
                return port
            except OSError:
                s.close()
                continue
        # 全部失败 → 让 OS 分配
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def start(self) -> bool:
        """启动 Web 服务器，返回是否成功"""
        if self._running:
            return True

        self._port = self._find_port()
        MonitorHandler.shared_state = self.state

        try:
            self._server = HTTPServer(('127.0.0.1', self._port), MonitorHandler)
            self._server.socket.settimeout(1.0)
        except OSError as e:
            logger.error(f"Web 监控启动失败 (port {self._port}): {e}")
            return False

        self._running = True
        self._thread = threading.Thread(target=self._server_loop, daemon=True)
        self._thread.start()
        self.state.set_status('idle')

        # 打印局域网地址
        ips = self._get_lan_ips()
        logger.info(f"[+] Web 监控已启动 — 端口 {self._port}")
        for ip in ips:
            url = f'http://{ip}:{self._port}'
            logger.info(f"    {url}")
        logger.info(f"    http://localhost:{self._port}")
        return True

    def _server_loop(self):
        try:
            while self._running:
                self._server.handle_request()
        except Exception:
            pass

    def stop(self):
        """停止 Web 服务器 — ⚠ 不能调 shutdown() (仅 serve_forever 有效, 会死锁)"""
        self._running = False
        if self._server:
            try:
                # server_close 关闭监听 socket → handle_request 循环自然退出
                self._server.server_close()
            except Exception:
                pass
            self._server = None
        self.state.set_status('idle')

    @property
    def port(self) -> int:
        return self._port

    @property
    def urls(self) -> list:
        urls = [f'http://localhost:{self._port}']
        for ip in self._get_lan_ips():
            urls.append(f'http://{ip}:{self._port}')
        return urls
