import os
import sys
import re
import glob
import queue
import time
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from logger import get_logger, LoggerManager
from config import CONFIG
from version import APP_NAME, APP_VERSION, APP_AUTHOR, APP_NAME_CN, APP_BILIBILI

logger = get_logger('gui')


class AnalysisGUI:
    def __init__(self):
        if sys.platform == 'win32':
            try:
                import ctypes
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
            except:
                pass

        self.root = tk.Tk()
        self.root.title(f"{APP_NAME_CN} v{APP_VERSION}")
        self.root.geometry("1200x850")
        self.root.minsize(1000, 700)
        self.root.configure(bg='#f0f2f5')

        self.analyzing = False
        self.log_queue = queue.Queue()
        self.current_report = None
        self._allow_dangerous = False
        self._analysis_thread = None
        self._analysis_stop_event = threading.Event()
        self._analysis_start_time = 0.0
        self._pending_env_file = ''
        self._pending_batch_dir = ''
        self._urlscan_index_path = ''
        self._batch_index_path = ''
        self.web_url_var = tk.StringVar(value='')

        # 依赖检查器 — 延迟初始化，GUI 先起来再后台检测
        self.dep_checker = None

        # Web 监控模式
        self.web_monitor = None

        self._build_ui()
        self._center_window()

        # Windows 原生文件拖拽 (WM_DROPFILES)
        self._enable_file_drop(self.root)

        # 日志轮询始终运行
        self._poll_running = True
        self._poll_log()

        # GUI 显示后再后台检测依赖和环境（不阻塞启动）
        self.root.after(200, self._init_deps_and_env)

        # 关闭时清理 Web 监控
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ===== UI构建 =====
    def _on_close(self):
        # 先请求停止正在进行的分析: 动态分析收到 stop_event 后会终止样本进程树,
        # 等一小段时间让清理完成, 避免关闭窗口导致样本孤儿进程残留。
        if self.analyzing:
            try:
                self._analysis_stop_event.set()
            except Exception:
                pass
            if self._analysis_thread and self._analysis_thread.is_alive():
                self._analysis_thread.join(timeout=5)
        if self.web_monitor:
            self.web_monitor.stop()
        self.web_url_var.set('')
        self._poll_running = False
        self.root.destroy()

    def _enable_file_drop(self, widget):
        """启用 Windows 原生文件拖拽 (WM_DROPFILES)"""
        try:
            import ctypes
            GWLP_WNDPROC = -4
            WM_DROPFILES = 0x0233

            user32 = ctypes.windll.user32
            shell32 = ctypes.windll.shell32

            WNDPROC = ctypes.WINFUNCTYPE(
                ctypes.c_ssize_t,
                ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p,
            )
            CallWindowProcW = user32.CallWindowProcW
            CallWindowProcW.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
                ctypes.c_void_p, ctypes.c_void_p,
            ]
            CallWindowProcW.restype = ctypes.c_ssize_t

            DragQueryFileW = shell32.DragQueryFileW
            DragQueryFileW.argtypes = [
                ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint,
            ]
            DragQueryFileW.restype = ctypes.c_uint
            DragFinish = shell32.DragFinish
            DragFinish.argtypes = [ctypes.c_void_p]
            DragFinish.restype = None
            DragAcceptFiles = shell32.DragAcceptFiles
            DragAcceptFiles.argtypes = [ctypes.c_void_p, ctypes.c_bool]
            DragAcceptFiles.restype = None

            hwnd = widget.winfo_id()

            def _wnd_proc(hwnd, msg, wparam, lparam):
                if msg == WM_DROPFILES:
                    try:
                        buf = ctypes.create_unicode_buffer(4096)
                        count = DragQueryFileW(wparam, 0xFFFFFFFF, None, 0)
                        if count >= 1:
                            DragQueryFileW(wparam, 0, ctypes.cast(buf, ctypes.c_void_p), len(buf))
                            path = buf.value
                            if path:
                                self.root.after(0, lambda p=path: self._on_file_dropped(p))
                        DragFinish(wparam)
                        return 0
                    except Exception:
                        pass
                if self._old_wndproc:
                    return CallWindowProcW(self._old_wndproc, hwnd, msg, wparam, lparam)
                return 0

            self._wndproc_ref = WNDPROC(_wnd_proc)
            self._old_wndproc = None
            if hasattr(user32, 'SetWindowLongPtrW'):
                SetWindowLongPtrW = user32.SetWindowLongPtrW
                SetWindowLongPtrW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
                SetWindowLongPtrW.restype = ctypes.c_ssize_t
                self._old_wndproc = SetWindowLongPtrW(
                    hwnd, GWLP_WNDPROC, ctypes.cast(self._wndproc_ref, ctypes.c_void_p)
                )
            if not self._old_wndproc:
                SetWindowLongW = user32.SetWindowLongW
                SetWindowLongW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
                SetWindowLongW.restype = ctypes.c_ssize_t
                self._old_wndproc = SetWindowLongW(
                    hwnd, GWLP_WNDPROC, ctypes.cast(self._wndproc_ref, ctypes.c_void_p)
                )
            DragAcceptFiles(hwnd, True)
            self._append_log("[DragDrop] 已启用文件拖拽", 'info')
        except Exception as e:
            try:
                self._append_log(f"[DragDrop] 文件拖拽不可用: {e}", 'warning')
            except Exception:
                pass

    def _on_file_dropped(self, path):
        """处理拖拽进入窗口的文件/目录"""
        try:
            if os.path.isdir(path):
                self._pending_batch_dir = path
                if messagebox.askyesno('批量扫描', f'检测到文件夹:\n{path}\n\n是否对该文件夹启动批量扫描？'):
                    self._start_batch_analysis(path)
            elif os.path.isfile(path):
                self.file_path_var.set(path)
                self.drop_label.config(text=f"已选择: {os.path.basename(path)}")
                self._append_log(f"[DragDrop] 已选择文件: {path}", 'info')
        except Exception as e:
            self._append_log(f"[DragDrop] 处理拖拽文件失败: {e}", 'warning')

    def _open_web_url(self, event=None):
        url = self.web_url_var.get()
        if url and url.startswith('http'):
            import webbrowser
            webbrowser.open(url)

    def _set_web_url(self, urls):
        if urls:
            for u in urls:
                if 'localhost' not in u and '127.0.0.1' not in u:
                    self.web_url_var.set(u)
                    return
            self.web_url_var.set(urls[0])
        else:
            self.web_url_var.set('')

    def _open_settings(self):
        """打开参数设置对话框"""
        settings_win = tk.Toplevel(self.root)
        settings_win.title("参数设置")
        settings_win.geometry("520x620")
        settings_win.minsize(420, 400)
        settings_win.configure(bg='#f0f2f5')
        settings_win.transient(self.root)
        settings_win.grab_set()

        from config import CONFIG as _cfg

        header = tk.Frame(settings_win, bg='#f0f2f5')
        header.pack(fill='x', padx=20, pady=(15, 10))
        ttk.Label(header, text="⚙ 沙箱参数设置", font=('Segoe UI', 14, 'bold'),
                  foreground='#4f46e5', background='#f0f2f5').pack(side='left')
        ttk.Label(header, text="修改即时生效，保存写入 config.json", font=('Segoe UI', 9),
                  foreground='#9ca3af', background='#f0f2f5').pack(side='right')

        canvas = tk.Canvas(settings_win, bg='#f0f2f5', highlightthickness=0)
        scrollbar = ttk.Scrollbar(settings_win, orient='vertical', command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg='#f0f2f5')
        scroll_frame.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        _frame_item = canvas.create_window((0, 0), window=scroll_frame, anchor='nw', width=440)
        canvas.bind('<Configure>', lambda e: canvas.itemconfigure(_frame_item, width=e.width))
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side='left', fill='both', expand=True, padx=(20, 0), pady=(0, 10))
        scrollbar.pack(side='right', fill='y', padx=(0, 5), pady=(0, 10))
        # 滚轮支持
        if hasattr(self, '_wheel_registry'):
            self._wheel_registry.append((canvas, scroll_frame))

        entries = {}

        def _add_group(parent, title):
            group = tk.LabelFrame(parent, text=title, bg='#f0f2f5', fg='#374151',
                                  font=('Segoe UI', 11, 'bold'), relief='groove', bd=1, padx=12, pady=8)
            group.pack(fill='x', pady=(0, 10))
            return group

        def _add_row(parent, label, key, current_val, min_v, max_v, unit='', step=5):
            row = tk.Frame(parent, bg='#f0f2f5')
            row.pack(fill='x', pady=2)
            tk.Label(row, text=label, font=('Segoe UI', 10), bg='#f0f2f5',
                     fg='#374151', width=26, anchor='w').pack(side='left')
            var = tk.IntVar(value=current_val)
            sb = ttk.Spinbox(row, from_=min_v, to=max_v, textvariable=var,
                             width=8, increment=step)
            sb.pack(side='left')
            if unit:
                tk.Label(row, text=unit, font=('Segoe UI', 9), bg='#f0f2f5',
                         fg='#9ca3af').pack(side='left', padx=(4, 0))
            entries[key] = var
            return var

        # === 沙箱 ===
        g1 = _add_group(scroll_frame, '制沙箱执行')
        _add_row(g1, '执行超时', 'sandbox_timeout', _cfg.sandbox.timeout, 30, 3600, '秒', 30)
        _add_row(g1, '子进程等待', 'child_wait', _cfg.sandbox.child_wait_timeout, 5, 300, '秒', 5)
        _add_row(g1, '内存限制', 'memory_limit', _cfg.sandbox.memory_limit_mb, 64, 4096, 'MB', 64)
        _add_row(g1, '进程数限制', 'process_limit', _cfg.sandbox.process_limit, 5, 100, '个', 5)
        _add_row(g1, 'CPU 时间限制', 'cpu_limit', _cfg.sandbox.cpu_limit_sec, 0, 3600, '秒', 60)

        # === Frida ===
        g2 = _add_group(scroll_frame, 'Frida API 监控')
        _add_row(g2, 'Attach 超时', 'frida_attach', _cfg.sandbox.frida_attach_timeout, 5, 120, '秒', 5)

        # === 网络 ===
        g3 = _add_group(scroll_frame, '网络捕获')
        _add_row(g3, '抓包超时', 'network_timeout', _cfg.network.capture_timeout, 30, 3600, '秒', 30)
        row3b = tk.Frame(g3, bg='#f0f2f5')
        row3b.pack(fill='x', pady=2)
        tk.Label(row3b, text='启用网络流量捕获', font=('Segoe UI', 10),
                 bg='#f0f2f5', fg='#374151', width=26, anchor='w').pack(side='left')
        capture_enabled_var = tk.BooleanVar(value=_cfg.network.capture_enabled)
        ttk.Checkbutton(row3b, variable=capture_enabled_var).pack(side='left')
        entries['capture_enabled'] = capture_enabled_var

        row3c = tk.Frame(g3, bg='#f0f2f5')
        row3c.pack(fill='x', pady=2)
        tk.Label(row3c, text='保存 PCAP 抓包文件', font=('Segoe UI', 10),
                 bg='#f0f2f5', fg='#374151', width=26, anchor='w').pack(side='left')
        pcap_enabled_var = tk.BooleanVar(value=_cfg.network.pcap_enabled)
        ttk.Checkbutton(row3c, variable=pcap_enabled_var).pack(side='left')
        entries['pcap_enabled'] = pcap_enabled_var

        # === 程序行为 ===
        g4 = _add_group(scroll_frame, '分析结束后行为')
        row1 = tk.Frame(g4, bg='#f0f2f5')
        row1.pack(fill='x', pady=2)
        tk.Label(row1, text='分析结束后自动清理临时文件', font=('Segoe UI', 10),
                 bg='#f0f2f5', fg='#374151', width=26, anchor='w').pack(side='left')
        auto_cleanup_var = tk.BooleanVar(value=getattr(self, '_auto_cleanup', False))
        ttk.Checkbutton(row1, variable=auto_cleanup_var).pack(side='left')
        entries['auto_cleanup'] = auto_cleanup_var

        row2 = tk.Frame(g4, bg='#f0f2f5')
        row2.pack(fill='x', pady=2)
        tk.Label(row2, text='分析结束后自动关闭程序', font=('Segoe UI', 10),
                 bg='#f0f2f5', fg='#374151', width=26, anchor='w').pack(side='left')
        auto_close_var = tk.BooleanVar(value=getattr(self, '_auto_close', False))
        ttk.Checkbutton(row2, variable=auto_close_var).pack(side='left')
        entries['auto_close'] = auto_close_var

        # === URL 扫描 ===
        g5 = _add_group(scroll_frame, 'URL 挂马扫描')
        _add_row(g5, '请求超时', 'url_timeout', _cfg.url_scan.timeout, 3, 120, '秒', 1)
        _add_row(g5, '动态监控超时', 'url_dyn_timeout', _cfg.url_scan.dynamic_timeout, 5, 180, '秒', 5)
        _add_row(g5, '加载后观察', 'url_dyn_wait', _cfg.url_scan.dynamic_wait, 0, 60, '秒', 1)
        _add_row(g5, '资源分析上限', 'url_max_res', _cfg.url_scan.max_resources, 5, 200, '个', 5)
        _add_row(g5, '外部脚本抓取', 'url_max_ext', _cfg.url_scan.max_external_scripts, 1, 30, '个', 1)
        _add_row(g5, '并行扫描URL数', 'url_parallel', _cfg.url_scan.max_parallel, 1, 8, '个', 1)
        row5e = tk.Frame(g5, bg='#f0f2f5')
        row5e.pack(fill='x', pady=2)
        tk.Label(row5e, text='浏览器引擎', font=('Segoe UI', 10),
                 bg='#f0f2f5', fg='#374151', width=26, anchor='w').pack(side='left')
        eng_var = tk.StringVar(value=_cfg.url_scan.browser_engines)
        ttk.Entry(row5e, textvariable=eng_var, width=26).pack(side='left')
        tk.Label(row5e, text='chrome,msedge,chromium,firefox,webkit 或 all',
                 font=('Segoe UI', 8), bg='#f0f2f5', fg='#9ca3af').pack(side='left', padx=(4, 0))
        entries['url_engines'] = eng_var
        row5a = tk.Frame(g5, bg='#f0f2f5')
        row5a.pack(fill='x', pady=2)
        tk.Label(row5a, text='开启动态行为监控(需浏览器)', font=('Segoe UI', 10),
                 bg='#f0f2f5', fg='#374151', width=26, anchor='w').pack(side='left')
        url_dyn_var = tk.BooleanVar(value=_cfg.url_scan.dynamic_analysis)
        ttk.Checkbutton(row5a, variable=url_dyn_var).pack(side='left')
        entries['url_dynamic'] = url_dyn_var

        # === 报告 / 证据包 / 用户环境痕迹 ===
        g6 = _add_group(scroll_frame, '报告 / 证据包 / 用户环境痕迹')
        _add_row(g6, '报告保留数', 'report_keep', _cfg.report.max_keep_reports, 0, 5000, '份', 100)

        row6a = tk.Frame(g6, bg='#f0f2f5')
        row6a.pack(fill='x', pady=2)
        tk.Label(row6a, text='报告附带证据包 (PCAP/截图/日志)', font=('Segoe UI', 10),
                 bg='#f0f2f5', fg='#374151', width=26, anchor='w').pack(side='left')
        evidence_pack_var = tk.BooleanVar(value=_cfg.report.evidence_pack)
        ttk.Checkbutton(row6a, variable=evidence_pack_var).pack(side='left')
        entries['evidence_pack'] = evidence_pack_var

        row6b = tk.Frame(g6, bg='#f0f2f5')
        row6b.pack(fill='x', pady=2)
        tk.Label(row6b, text='创建虚假用户环境痕迹', font=('Segoe UI', 10),
                 bg='#f0f2f5', fg='#374151', width=26, anchor='w').pack(side='left')
        fake_user_env_var = tk.BooleanVar(value=_cfg.sandbox.fake_user_env)
        ttk.Checkbutton(row6b, variable=fake_user_env_var).pack(side='left')
        entries['fake_user_env'] = fake_user_env_var

        # === 威胁情报 API ===
        g7 = _add_group(scroll_frame, '威胁情报 API')
        row7a = tk.Frame(g7, bg='#f0f2f5')
        row7a.pack(fill='x', pady=2)
        tk.Label(row7a, text='微步在线 API Key', font=('Segoe UI', 10),
                 bg='#f0f2f5', fg='#374151', width=26, anchor='w').pack(side='left')
        threatbook_var = tk.StringVar(value=_cfg.api_keys.threatbook or '')
        ttk.Entry(row7a, textvariable=threatbook_var, width=30, show='*').pack(side='left')
        entries['threatbook_key'] = threatbook_var
        tk.Label(row7a, text='留空则不查询微步', font=('Segoe UI', 8),
                 bg='#f0f2f5', fg='#9ca3af').pack(side='left', padx=(4, 0))
        row7b = tk.Frame(g7, bg='#f0f2f5')
        row7b.pack(fill='x', pady=2)
        tk.Label(row7b, text='VirusTotal API Key', font=('Segoe UI', 10),
                 bg='#f0f2f5', fg='#374151', width=26, anchor='w').pack(side='left')
        vt_var = tk.StringVar(value=_cfg.api_keys.virustotal or '')
        ttk.Entry(row7b, textvariable=vt_var, width=30, show='*').pack(side='left')
        entries['virustotal_key'] = vt_var
        tk.Label(row7b, text='留空则不查询 VT', font=('Segoe UI', 8),
                 bg='#f0f2f5', fg='#9ca3af').pack(side='left', padx=(4, 0))

        # === 按钮 ===
        btn_row = tk.Frame(scroll_frame, bg='#f0f2f5')
        btn_row.pack(fill='x', pady=(8, 0))

        def _save():
            _cfg.sandbox.timeout = entries['sandbox_timeout'].get()
            _cfg.sandbox.child_wait_timeout = entries['child_wait'].get()
            _cfg.sandbox.memory_limit_mb = entries['memory_limit'].get()
            _cfg.sandbox.process_limit = entries['process_limit'].get()
            _cfg.sandbox.cpu_limit_sec = entries['cpu_limit'].get()
            _cfg.sandbox.fake_user_env = entries['fake_user_env'].get()
            _cfg.sandbox.frida_attach_timeout = entries['frida_attach'].get()
            _cfg.network.capture_timeout = entries['network_timeout'].get()
            _cfg.network.capture_enabled = entries['capture_enabled'].get()
            _cfg.network.pcap_enabled = entries['pcap_enabled'].get()
            _cfg.report.max_keep_reports = entries['report_keep'].get()
            _cfg.report.evidence_pack = entries['evidence_pack'].get()
            _cfg.url_scan.timeout = entries['url_timeout'].get()
            _cfg.url_scan.dynamic_timeout = entries['url_dyn_timeout'].get()
            _cfg.url_scan.dynamic_wait = entries['url_dyn_wait'].get()
            _cfg.url_scan.max_resources = entries['url_max_res'].get()
            _cfg.url_scan.max_external_scripts = entries['url_max_ext'].get()
            _cfg.url_scan.max_parallel = entries['url_parallel'].get()
            _cfg.url_scan.browser_engines = entries['url_engines'].get().strip() or 'chrome'
            _cfg.url_scan.dynamic_analysis = entries['url_dynamic'].get()
            self._auto_cleanup = entries['auto_cleanup'].get()
            self._auto_close = entries['auto_close'].get()
            _cfg.api_keys.threatbook = entries['threatbook_key'].get().strip()
            _cfg.api_keys.virustotal = entries['virustotal_key'].get().strip()
            try:
                from config import save_default_config
                if getattr(sys, 'frozen', False):
                    _cfg_base = os.path.dirname(os.path.abspath(sys.executable))
                else:
                    _cfg_base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                _cfg_path = os.path.join(_cfg_base, 'config.json')
                save_default_config(_cfg_path)
                self._append_log(f"[SETTINGS] 参数已保存到 {_cfg_path}", 'info')
            except Exception as e:
                self._append_log(f"[SETTINGS] 保存失败: {e}", 'error')
            self._append_log(
                f"[SETTINGS] 沙箱超时={_cfg.sandbox.timeout}s  子进程={_cfg.sandbox.child_wait_timeout}s  "
                f"内存={_cfg.sandbox.memory_limit_mb}MB  进程上限={_cfg.sandbox.process_limit}  "
                f"CPU={_cfg.sandbox.cpu_limit_sec}s  虚假用户环境={'开' if _cfg.sandbox.fake_user_env else '关'}  "
                f"Frida={_cfg.sandbox.frida_attach_timeout}s  网络={_cfg.network.capture_timeout}s  "
                f"抓包={'开' if _cfg.network.capture_enabled else '关'}/PCAP={'开' if _cfg.network.pcap_enabled else '关'}  "
                f"报告保留={_cfg.report.max_keep_reports}份  证据包={'开' if _cfg.report.evidence_pack else '关'}  "
                f"URL超时={_cfg.url_scan.timeout}s 动态={_cfg.url_scan.dynamic_timeout}s",
                'info'
            )
            settings_win.destroy()

        def _apply():
            _cfg.sandbox.timeout = entries['sandbox_timeout'].get()
            _cfg.sandbox.child_wait_timeout = entries['child_wait'].get()
            _cfg.sandbox.memory_limit_mb = entries['memory_limit'].get()
            _cfg.sandbox.process_limit = entries['process_limit'].get()
            _cfg.sandbox.cpu_limit_sec = entries['cpu_limit'].get()
            _cfg.sandbox.fake_user_env = entries['fake_user_env'].get()
            _cfg.sandbox.frida_attach_timeout = entries['frida_attach'].get()
            _cfg.network.capture_timeout = entries['network_timeout'].get()
            _cfg.network.capture_enabled = entries['capture_enabled'].get()
            _cfg.network.pcap_enabled = entries['pcap_enabled'].get()
            _cfg.report.max_keep_reports = entries['report_keep'].get()
            _cfg.report.evidence_pack = entries['evidence_pack'].get()
            _cfg.url_scan.timeout = entries['url_timeout'].get()
            _cfg.url_scan.dynamic_timeout = entries['url_dyn_timeout'].get()
            _cfg.url_scan.dynamic_wait = entries['url_dyn_wait'].get()
            _cfg.url_scan.max_resources = entries['url_max_res'].get()
            _cfg.url_scan.max_external_scripts = entries['url_max_ext'].get()
            _cfg.url_scan.max_parallel = entries['url_parallel'].get()
            _cfg.url_scan.browser_engines = entries['url_engines'].get().strip() or 'chrome'
            _cfg.url_scan.dynamic_analysis = entries['url_dynamic'].get()
            self._auto_cleanup = entries['auto_cleanup'].get()
            self._auto_close = entries['auto_close'].get()
            _cfg.api_keys.threatbook = entries['threatbook_key'].get().strip()
            _cfg.api_keys.virustotal = entries['virustotal_key'].get().strip()
            self._append_log(
                f"[SETTINGS] 参数已更新: 沙箱超时={_cfg.sandbox.timeout}s  子进程={_cfg.sandbox.child_wait_timeout}s  "
                f"内存={_cfg.sandbox.memory_limit_mb}MB  进程上限={_cfg.sandbox.process_limit}  "
                f"CPU={_cfg.sandbox.cpu_limit_sec}s  虚假用户环境={'开' if _cfg.sandbox.fake_user_env else '关'}  "
                f"Frida={_cfg.sandbox.frida_attach_timeout}s  网络={_cfg.network.capture_timeout}s  "
                f"抓包={'开' if _cfg.network.capture_enabled else '关'}/PCAP={'开' if _cfg.network.pcap_enabled else '关'}  "
                f"报告保留={_cfg.report.max_keep_reports}份  证据包={'开' if _cfg.report.evidence_pack else '关'}  "
                f"URL超时={_cfg.url_scan.timeout}s 动态={_cfg.url_scan.dynamic_timeout}s  "
                f"引擎={_cfg.url_scan.browser_engines} 并发={_cfg.url_scan.max_parallel}",
                'info'
            )
            settings_win.destroy()

        def _reset():
            defaults = {
                'sandbox_timeout': 300, 'child_wait': 60, 'memory_limit': 512,
                'process_limit': 20, 'cpu_limit': 0, 'frida_attach': 30, 'network_timeout': 300,
                'report_keep': 100,
                'url_timeout': 15, 'url_dyn_timeout': 25, 'url_dyn_wait': 4,
                'url_max_res': 40, 'url_max_ext': 5, 'url_parallel': 3,
            }
            for k, v in defaults.items():
                entries[k].set(v)
            bool_defaults = {
                'capture_enabled': True, 'pcap_enabled': True,
                'fake_user_env': True, 'evidence_pack': True,
                'url_dynamic': True,
            }
            for k, v in bool_defaults.items():
                if k in entries:
                    entries[k].set(v)
            if 'url_engines' in entries:
                entries['url_engines'].set('chrome')
            if 'threatbook_key' in entries:
                entries['threatbook_key'].set('')
            if 'virustotal_key' in entries:
                entries['virustotal_key'].set('')
            self._append_log("[SETTINGS] 参数已重置为默认值（未保存）", 'info')

        tk.Button(btn_row, text="保存并关闭", command=_save,
                  bg='#4f46e5', fg='white', font=('Segoe UI', 10, 'bold'),
                  relief='flat', padx=16, pady=6, cursor='hand2').pack(side='left', padx=(0, 8))
        tk.Button(btn_row, text="仅应用", command=_apply,
                  bg='#10b981', fg='white', font=('Segoe UI', 10),
                  relief='flat', padx=12, pady=6, cursor='hand2').pack(side='left', padx=(0, 8))
        tk.Button(btn_row, text="恢复默认", command=_reset,
                  bg='#f59e0b', fg='white', font=('Segoe UI', 10),
                  relief='flat', padx=12, pady=6, cursor='hand2').pack(side='left')

        settings_win.wait_window()

    def _build_ui(self):
        main_frame = tk.Frame(self.root, bg='#f0f2f5')
        main_frame.pack(fill='both', expand=True, padx=15, pady=10)
        
        # === 顶部标题栏 ===
        header = tk.Frame(main_frame, bg='#f0f2f5')
        header.pack(fill='x', pady=(0, 8))
        
        title_left = tk.Frame(header, bg='#f0f2f5')
        title_left.pack(side='left')
        ttk.Label(title_left, text=f"🔍 {APP_NAME_CN}", font=('Segoe UI', 18, 'bold'), 
                 foreground='#4f46e5', background='#f0f2f5').pack(side='left')
        ttk.Label(title_left, text=f"v{APP_VERSION}", font=('Segoe UI', 10, 'bold'), 
                 foreground='#818cf8', background='#f0f2f5').pack(side='left', padx=(8, 0))
        ttk.Label(title_left, text=f"github: {APP_AUTHOR} · bilibili: {APP_BILIBILI}", 
                 font=('Segoe UI', 9), foreground='#94a3b8', background='#f0f2f5').pack(side='left', padx=(12, 0))
        
        # 环境安全状态
        self.env_status_var = tk.StringVar(value="环境检测中...")
        self.env_status_label = tk.Label(header, textvariable=self.env_status_var, 
                                         font=('Segoe UI', 10), bg='#f0f2f5', fg='#6b7280')
        self.env_status_label.pack(side='right')

        self.web_url_label = tk.Label(header, textvariable=self.web_url_var,
                                       font=('Segoe UI', 10, 'bold'), bg='#f0f2f5',
                                       fg='#059669', cursor='hand2')
        self.web_url_label.pack(side='right', padx=(0, 16))
        self.web_url_label.bind('<Button-1>', self._open_web_url)

        settings_btn = tk.Button(header, text="⚙ 参数设置", command=self._open_settings,
                                 bg='#e5e7eb', fg='#374151', font=('Segoe UI', 9),
                                 relief='flat', padx=10, pady=2, cursor='hand2')
        settings_btn.pack(side='right', padx=(0, 12))
        
        # === 主内容区（左侧面板 + 右侧日志） ===
        content = tk.PanedWindow(main_frame, orient='horizontal', bg='#e5e7eb', sashwidth=4)
        content.pack(fill='both', expand=True)
        
        # --- 左侧：Notebook标签页 ---
        left_frame = tk.Frame(content, bg='#f0f2f5', width=460)
        content.add(left_frame, minsize=400)
        
        notebook = ttk.Notebook(left_frame)
        notebook.pack(fill='both', expand=True)
        
        # 标签页1：分析
        self._build_analysis_tab(notebook)
        
        # 标签页1.5：URL 扫描
        self._build_urlscan_tab(notebook)

        # 标签页1.8：IoC 管理
        self._build_ioc_tab(notebook)
        
        # 标签页2：历史记录
        self._build_history_tab(notebook)
        
        # 标签页3：依赖库
        self._build_deps_tab(notebook)
        
        # 标签页4：环境信息
        self._build_env_tab(notebook)
        
        # --- 右侧：日志与进度 ---
        right_frame = tk.Frame(content, bg='#f0f2f5')
        content.add(right_frame, minsize=400)
        
        # 进度条
        prog_card = tk.Frame(right_frame, bg='white', highlightbackground='#e5e7eb', highlightthickness=1, bd=0)
        prog_card.pack(fill='x', pady=(0, 8))
        prog_inner = tk.Frame(prog_card, bg='white')
        prog_inner.pack(fill='x', padx=15, pady=10)
        ttk.Label(prog_inner, text="📊 Progress", font=('Segoe UI', 12, 'bold'), background='white').pack(anchor='w')
        self.progress = ttk.Progressbar(prog_inner, mode='indeterminate')
        self.progress.pack(fill='x', pady=(6, 2))
        self.progress_label = ttk.Label(prog_inner, text="Waiting...", font=('Segoe UI', 9), 
                                       foreground='#6b7280', background='white')
        self.progress_label.pack(anchor='w')
        
        # 日志
        log_card = tk.Frame(right_frame, bg='white', highlightbackground='#e5e7eb', highlightthickness=1, bd=0)
        log_card.pack(fill='both', expand=True)
        
        log_header = tk.Frame(log_card, bg='white')
        log_header.pack(fill='x', padx=15, pady=(10, 4))
        ttk.Label(log_header, text="📋 Analysis Log", font=('Segoe UI', 12, 'bold'), background='white').pack(side='left')
        ttk.Button(log_header, text="Clear", command=self._clear_log, width=8).pack(side='right')
        ttk.Button(log_header, text="Copy", command=self._copy_log, width=8).pack(side='right', padx=(0, 4))
        
        log_frame = tk.Frame(log_card, bg='#1e1e2e')
        log_frame.pack(fill='both', expand=True, padx=15, pady=(0, 10))
        self.log_text = tk.Text(log_frame, wrap='word', state='disabled', bg='#1e1e2e', fg='#cdd6f4', 
                               font=('Consolas', 10), relief='flat', insertbackground='white', padx=10, pady=8)
        self.log_text.pack(side='left', fill='both', expand=True)
        scroll = ttk.Scrollbar(log_frame, orient='vertical', command=self.log_text.yview)
        scroll.pack(side='right', fill='y')
        self.log_text.configure(yscrollcommand=scroll.set)
        
        # 日志标签
        self.log_text.tag_config('info', foreground='#89b4fa')
        self.log_text.tag_config('success', foreground='#a6e3a1')
        self.log_text.tag_config('warning', foreground='#f9e2af')
        self.log_text.tag_config('error', foreground='#f38ba8')
        self.log_text.tag_config('header', foreground='#cba6f7', font=('Consolas', 10, 'bold'))
        self.log_text.tag_config('highlight', foreground='#f9e2af', font=('Consolas', 10, 'bold'))
        
        # 结果面板（日志下方，默认隐藏）
        self.result_card = tk.Frame(right_frame, bg='#fef3c7', highlightbackground='#f59e0b', 
                                   highlightthickness=2, bd=0)
        # 不pack，分析完成后显示
        self.result_card_visible = False
        
        result_inner = tk.Frame(self.result_card, bg='#fef3c7')
        result_inner.pack(fill='x', padx=12, pady=10)
        self.result_title = tk.Label(result_inner, text="📊 Analysis Result", font=('Segoe UI', 12, 'bold'), 
                                     bg='#fef3c7', fg='#92400e')
        self.result_title.pack(anchor='w')
        self.result_content = tk.Label(result_inner, text="", font=('Segoe UI', 10), 
                                      bg='#fef3c7', fg='#78350f', justify='left', wraplength=500)
        self.result_content.pack(anchor='w', pady=(4, 0))
        
        btn_row = tk.Frame(result_inner, bg='#fef3c7')
        btn_row.pack(anchor='w', pady=(8, 0))
        self.btn_open_html = tk.Button(btn_row, text="📄 Open HTML Report", command=self._open_html_report,
                                      bg='#f59e0b', fg='white', font=('Segoe UI', 9), relief='flat', 
                                      padx=12, pady=4, cursor='hand2')
        self.btn_open_html.pack(side='left')
        self.btn_open_json = tk.Button(btn_row, text="📋 Open JSON Report", command=self._open_json_report,
                                      bg='#d97706', fg='white', font=('Segoe UI', 9), relief='flat', 
                                      padx=12, pady=4, cursor='hand2')
        self.btn_open_json.pack(side='left', padx=(6, 0))
        self.btn_open_batch_index = tk.Button(btn_row, text="📇 打开批量索引",
                                             command=lambda: os.startfile(self._batch_index_path),
                                             bg='#b45309', fg='white', font=('Segoe UI', 9), relief='flat',
                                             padx=12, pady=4, cursor='hand2')
        # 默认不显示, 批量扫描完成后按需 pack
    
    def _bind_mousewheel(self, canvas, frame):
        """注册滚动容器到全局滚轮分发器 (鼠标在哪个滚动区上就滚哪个)"""
        if not hasattr(self, '_wheel_registry'):
            self._wheel_registry = []
            self.root.bind_all('<MouseWheel>', self._on_global_wheel)
        self._wheel_registry.append((canvas, frame))

    def _on_global_wheel(self, event):
        """全局滚轮: 找到鼠标所在滚动区并滚动"""
        try:
            w = self.root.winfo_containing(event.x_root, event.y_root)
        except Exception:
            return None
        while w is not None:
            for canvas, frame in getattr(self, '_wheel_registry', []):
                try:
                    if not canvas.winfo_exists():
                        continue
                    if w == frame:
                        canvas.yview_scroll(int(-event.delta / 120), 'units')
                        return 'break'
                except Exception:
                    pass
            w = getattr(w, 'master', None)
        return None

    def _append_log(self, text, tag=None):
        """向日志窗口追加文本（线程安全，可在任意线程调用）"""
        # 使用 after(0, ...) 确保在主线程中执行 UI 更新
        def _do_append():
            self.log_text.configure(state='normal')
            # 行数上限 3000: 防止日志无限增长导致 insert/渲染越来越慢 (分析时 UI 未响应的元凶)
            try:
                _lines = int(self.log_text.index('end-1c').split('.')[0])
                if _lines > 3000:
                    self.log_text.delete('1.0', '%d.0' % (_lines - 3000 + 1))
            except Exception:
                pass
            if tag:
                self.log_text.insert('end', text + '\n', tag)
            else:
                self.log_text.insert('end', text + '\n')
            self.log_text.see('end')
            self.log_text.configure(state='disabled')
        # 如果当前已在主线程，直接执行；否则通过 after 调度到主线程
        if threading.current_thread() is threading.main_thread():
            _do_append()
        else:
            self.root.after(0, _do_append)
    
    def _build_analysis_tab(self, notebook):
        tab = tk.Frame(notebook, bg='#f0f2f5')
        notebook.add(tab, text="🛡️  分析")

        # ===== 滚动容器 (选项多, 防止遮挡) =====
        # ⚠ canvas 布局完成前 winfo_width() 为 1, 不能用 frame 的 Configure 同步宽度
        #   (会把内容宽度永久固定成 1px → 全空白); 用 canvas 的 Configure 事件
        scroll_canvas = tk.Canvas(tab, bg='#f0f2f5', highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient='vertical', command=scroll_canvas.yview)
        scroll_frame = tk.Frame(scroll_canvas, bg='#f0f2f5')
        scroll_frame.bind('<Configure>',
                          lambda e: scroll_canvas.configure(scrollregion=scroll_canvas.bbox('all')))
        _frame_item = scroll_canvas.create_window((0, 0), window=scroll_frame, anchor='nw', width=400)
        scroll_canvas.bind('<Configure>',
                           lambda e: scroll_canvas.itemconfigure(_frame_item, width=e.width))
        scroll_canvas.configure(yscrollcommand=scrollbar.set)
        scroll_canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        self._bind_mousewheel(scroll_canvas, scroll_frame)

        tab = scroll_frame  # 后续控件都挂到可滚动 frame 上

        # 文件选择卡片
        file_card = tk.Frame(tab, bg='white', highlightbackground='#e5e7eb', highlightthickness=1, bd=0)
        file_card.pack(fill='x', pady=(0, 10), padx=2)
        ttk.Label(file_card, text="📁 选择样本", font=('Segoe UI', 12, 'bold'), background='white').pack(anchor='w', padx=15, pady=(12, 8))
        
        drop_zone = tk.Frame(file_card, bg='#f8fafc', highlightbackground='#d1d5db', highlightthickness=2, bd=0, height=80)
        drop_zone.pack(fill='x', padx=15, pady=(0, 8))
        drop_zone.pack_propagate(False)
        self.drop_label = tk.Label(drop_zone, text="📂 点击或拖拽选择文件", font=('Segoe UI', 11), 
                                   fg='#6b7280', bg='#f8fafc')
        self.drop_label.pack(expand=True)
        drop_zone.bind('<Button-1>', lambda e: self._browse_file())
        
        path_frame = tk.Frame(file_card, bg='white')
        path_frame.pack(fill='x', padx=15, pady=(0, 12))
        self.file_path_var = tk.StringVar()
        ttk.Entry(path_frame, textvariable=self.file_path_var, font=('Consolas', 10), 
                 state='readonly').pack(side='left', fill='x', expand=True)
        ttk.Button(path_frame, text="浏览...", command=self._browse_file).pack(side='left', padx=(8, 0))
        self.batch_btn = tk.Button(path_frame, text="📁 批量扫描目录", command=self._start_batch_analysis,
                                   bg='#10b981', fg='white', font=('Segoe UI', 9),
                                   relief='flat', padx=10, pady=2, cursor='hand2')
        self.batch_btn.pack(side='left', padx=(8, 0))
        
        # 选项卡片
        opt_card = tk.Frame(tab, bg='white', highlightbackground='#e5e7eb', highlightthickness=1, bd=0)
        opt_card.pack(fill='x', pady=(0, 10), padx=2)
        ttk.Label(opt_card, text="⚙️ 分析选项", font=('Segoe UI', 12, 'bold'), background='white').pack(anchor='w', padx=15, pady=(12, 8))
        
        self.opt_vars = {}
        self.opt_widgets = {}  # 存储选项对应的widget，用于标记依赖状态
        
        opts = [
            ('enable_static', '静态分析 (Hash / Entropy / PE / Strings)', True, None, 'static'),
            ('enable_yara', 'YARA 规则扫描', True, 'yara', 'static'),
            ('enable_threat', '威胁情报查询 (需要 API Key)', True, None, 'intel'),
            ('scan_discovered_urls', '自动扫描样本中发现的 URL (需联网)', True, 'requests', 'intel'),
            ('sep1', None, None, None, None),
            ('enable_dynamic', '动态行为分析 (执行样本并监控)', False, 'psutil', 'dynamic'),
            ('enable_sandbox', '  ├ 启用沙箱隔离 (Job Object)', True, None, 'dynamic'),
            ('enable_vm_hide', '  ├ 自动隐藏VM进程 (对抗反VM)', True, None, 'dynamic'),
            ('enable_memory', '  ├ 内存分析 (需要 pywin32)', True, 'pywin32', 'dynamic'),
            ('enable_frida', '  ├ Frida API钩子 (需要 frida)', False, 'frida', 'dynamic'),
            ('enable_time_accel', '  └ 时间加速 1000x (Sleep/Delay压缩)', False, 'frida', 'dynamic'),
            ('sep2', None, None, None, None),
            ('enable_network', '网络流量捕获 (需要 scapy)', False, 'scapy', 'network'),
            ('sep3', None, None, None, None),
            ('enable_family', '木马家族分析', True, None, 'static'),
            ('enable_advanced', '高级行为检测 (反VM/反沙箱/反调试)', True, None, 'static'),
            ('enable_destruction', '破坏性行为检测', True, None, 'static'),
            ('sep4', None, None, None, None),
            ('enable_deep_dive', '🕵 深度追踪分析 (DeepDive) — 进程链/文件代码深析/驱动链/窃密特征/攻击链叙事报告',
             bool(getattr(getattr(CONFIG, 'deep_dive', None), 'auto_enabled', True)), None, 'dynamic'),
            ('enable_deep_dive_watch', '  └ 长时观察窗 (动态后继续监控新进程/外联/文件, 默认180s)', True, None, 'dynamic'),
            ('sep5', None, None, None, None),
            ('enable_cleanup', '🧹 生成杀毒清理脚本 (只生成不执行 — SYSTEM提权/注册表复原/随机名特征/重启验证)', False, None, 'cleanup'),
            ('enable_web_monitor', '🌐 Web 监控模式 (浏览器实时查看报告)', False, None, 'web'),
        ]
        
        for key, label, default, dep_pkg, category in opts:
            if key.startswith('sep'):
                ttk.Separator(opt_card, orient='horizontal').pack(fill='x', padx=15, pady=6)
                continue
            
            row = tk.Frame(opt_card, bg='white')
            row.pack(fill='x', padx=15, pady=2)
            
            var = tk.BooleanVar(value=default)
            self.opt_vars[key] = var
            
            cb = ttk.Checkbutton(row, text=label, variable=var)
            cb.pack(side='left')
            
            # 依赖标记 — 先创建占位标签，异步检测完成后刷新
            if dep_pkg:
                dep_label = tk.Label(row, text="⏳", font=('Segoe UI', 8),
                                    fg='#9ca3af', bg='white')
                dep_label.pack(side='right', padx=(0, 4))
                self.opt_widgets[key] = (cb, dep_label, dep_pkg)
            else:
                self.opt_widgets[key] = (cb, None, dep_pkg)

        # 动态分析子选项级联：勾选子项自动勾选 enable_dynamic
        dynamic_sub_keys = {'enable_sandbox', 'enable_vm_hide', 'enable_memory', 'enable_frida', 'enable_time_accel', 'enable_deep_dive', 'enable_deep_dive_watch'}
        def _make_sub_callback(subkey):
            def _callback(*args):
                if self.opt_vars[subkey].get():
                    self.opt_vars['enable_dynamic'].set(True)
            return _callback
        def _make_parent_callback():
            def _callback(*args):
                if not self.opt_vars['enable_dynamic'].get():
                    for dk in dynamic_sub_keys:
                        if dk in self.opt_vars:
                            self.opt_vars[dk].set(False)
            return _callback
        for sk in dynamic_sub_keys:
            if sk in self.opt_vars:
                self.opt_vars[sk].trace_add('write', _make_sub_callback(sk))
        if 'enable_dynamic' in self.opt_vars:
            self.opt_vars['enable_dynamic'].trace_add('write', _make_parent_callback())

        # ===== 加密压缩包密码输入 =====
        pw_row = tk.Frame(opt_card, bg='white')
        pw_row.pack(fill='x', padx=15, pady=(6, 2))
        tk.Label(pw_row, text='🗝 加密压缩包密码:', font=('Segoe UI', 10),
                bg='white', fg='#374151').pack(side='left')
        self.archive_password_var = tk.StringVar()
        self.archive_password_entry = tk.Entry(pw_row, textvariable=self.archive_password_var,
                                                font=('Segoe UI', 10), width=30,
                                                relief='solid', borderwidth=1)
        self.archive_password_entry.pack(side='left', padx=(6, 0))
        tk.Label(pw_row, text=' (多个密码用逗号分隔, 留空则自动字典破解)',
                font=('Segoe UI', 8), bg='white', fg='#9ca3af').pack(side='left', padx=(6, 0))

        # 按钮
        btn_frame = tk.Frame(tab, bg='#f0f2f5')
        btn_frame.pack(fill='x', pady=(6, 0))
        self.start_btn = tk.Button(btn_frame, text="🚀 开始分析", command=self._start_analysis,
                                   bg='#4f46e5', fg='white', font=('Segoe UI', 11, 'bold'), 
                                   relief='flat', padx=20, pady=10, cursor='hand2')
        self.start_btn.pack(fill='x')
        self.stop_btn = tk.Button(btn_frame, text="⏹ 停止", command=self._stop_analysis,
                                 bg='#ef4444', fg='white', font=('Segoe UI', 10), 
                                 relief='flat', padx=20, pady=6, state='disabled', cursor='hand2')
        self.stop_btn.pack(fill='x', pady=(6, 0))

    def _build_urlscan_tab(self, notebook):
        """URL 挂马扫描标签页: 网页源码/命令执行/挂马/动态行为监控"""
        tab = tk.Frame(notebook, bg='#f0f2f5')
        notebook.add(tab, text="🌐 URL扫描")

        # ===== 滚动容器 =====
        scroll_canvas = tk.Canvas(tab, bg='#f0f2f5', highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient='vertical', command=scroll_canvas.yview)
        scroll_frame = tk.Frame(scroll_canvas, bg='#f0f2f5')
        scroll_frame.bind('<Configure>',
                          lambda e: scroll_canvas.configure(scrollregion=scroll_canvas.bbox('all')))
        _frame_item = scroll_canvas.create_window((0, 0), window=scroll_frame, anchor='nw', width=400)
        scroll_canvas.bind('<Configure>',
                           lambda e: scroll_canvas.itemconfigure(_frame_item, width=e.width))
        scroll_canvas.configure(yscrollcommand=scrollbar.set)
        scroll_canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        self._bind_mousewheel(scroll_canvas, scroll_frame)
        tab = scroll_frame

        card = tk.Frame(tab, bg='white', highlightbackground='#e5e7eb', highlightthickness=1, bd=0)
        card.pack(fill='x', pady=(0, 10), padx=2)
        ttk.Label(card, text="🔗 目标 URL (每行一个, 支持多个)", font=('Segoe UI', 12, 'bold'),
                  background='white').pack(anchor='w', padx=15, pady=(12, 8))

        self.urlscan_text = tk.Text(card, height=6, font=('Consolas', 10),
                                    bg='#f8fafc', fg='#374151', relief='solid', borderwidth=1,
                                    insertbackground='#374151')
        self.urlscan_text.pack(fill='x', padx=15, pady=(0, 8))

        opt_row = tk.Frame(card, bg='white')
        opt_row.pack(fill='x', padx=15, pady=(0, 4))
        self.urlscan_fetch_js = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row, text="抓取外部 JS 脚本并分析",
                        variable=self.urlscan_fetch_js).pack(side='left')

        # 动态行为监控 (浏览器沙箱)
        opt_row2 = tk.Frame(card, bg='white')
        opt_row2.pack(fill='x', padx=15, pady=(0, 4))
        self.urlscan_dynamic = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row2, text="🤖 动态行为监控 (真实浏览器执行页面 JS, 捕获网络/控制台/下载/DOM注入)",
                        variable=self.urlscan_dynamic).pack(side='left')

        # 浏览器引擎选择
        opt_row4 = tk.Frame(card, bg='white')
        opt_row4.pack(fill='x', padx=15, pady=(0, 4))
        tk.Label(opt_row4, text='浏览器引擎:', font=('Segoe UI', 9), bg='white',
                 fg='#374151').pack(side='left')
        self.urlscan_engine_var = tk.StringVar(value='chrome')
        engine_choices = [
            ('chrome', 'Chrome (系统)'),
            ('msedge', 'Edge (系统)'),
            ('chrome,msedge', 'Chrome + Edge (双引擎)'),
            ('chromium', 'Chromium (内核)'),
            ('firefox', 'Firefox (内核)'),
            ('webkit', 'WebKit (内核)'),
            ('all', '全部引擎'),
        ]
        ttk.Combobox(opt_row4, textvariable=self.urlscan_engine_var, width=24, state='readonly',
                     values=[f'{v} — {k}' for k, v in engine_choices]).pack(side='left')
        tk.Label(opt_row4, text='  (恶意代码常针对特定浏览器)', font=('Segoe UI', 8), bg='white',
                 fg='#9ca3af').pack(side='left', padx=(6, 0))
        self._urlscan_engines = engine_choices

        # 并行数
        opt_row5 = tk.Frame(card, bg='white')
        opt_row5.pack(fill='x', padx=15, pady=(0, 4))
        tk.Label(opt_row5, text='并行扫描URL数:', font=('Segoe UI', 9), bg='white',
                 fg='#374151').pack(side='left')
        self.urlscan_parallel_var = tk.IntVar(value=3)
        ttk.Spinbox(opt_row5, from_=1, to=8, textvariable=self.urlscan_parallel_var,
                    width=5).pack(side='left', padx=(4, 0))

        # 超时设置
        opt_row3 = tk.Frame(card, bg='white')
        opt_row3.pack(fill='x', padx=15, pady=(0, 4))
        tk.Label(opt_row3, text='请求超时(秒):', font=('Segoe UI', 9), bg='white',
                 fg='#374151').pack(side='left')
        self.urlscan_timeout_var = tk.IntVar(value=15)
        ttk.Spinbox(opt_row3, from_=3, to=120, textvariable=self.urlscan_timeout_var,
                    width=5).pack(side='left', padx=(4, 0))
        tk.Label(opt_row3, text='  动态观察(秒):', font=('Segoe UI', 9), bg='white',
                 fg='#374151').pack(side='left', padx=(12, 0))
        self.urlscan_wait_var = tk.IntVar(value=4)
        ttk.Spinbox(opt_row3, from_=0, to=60, textvariable=self.urlscan_wait_var,
                    width=5).pack(side='left', padx=(4, 0))
        tk.Label(opt_row3, text='  动态超时(秒):', font=('Segoe UI', 9), bg='white',
                 fg='#374151').pack(side='left', padx=(12, 0))
        self.urlscan_dyn_timeout_var = tk.IntVar(value=25)
        ttk.Spinbox(opt_row3, from_=5, to=180, textvariable=self.urlscan_dyn_timeout_var,
                    width=5).pack(side='left', padx=(4, 0))

        btn_row = tk.Frame(card, bg='white')
        btn_row.pack(fill='x', padx=15, pady=(4, 12))
        self.urlscan_btn = tk.Button(btn_row, text="🚀 开始 URL 扫描", command=self._start_urlscan,
                                     bg='#059669', fg='white', font=('Segoe UI', 10, 'bold'),
                                     relief='flat', padx=14, pady=8, cursor='hand2')
        self.urlscan_btn.pack(side='left')
        self.urlscan_stop_btn = tk.Button(btn_row, text="⏹ 停止", command=self._stop_urlscan,
                                          bg='#ef4444', fg='white', font=('Segoe UI', 9),
                                          relief='flat', padx=12, pady=8, state='disabled',
                                          cursor='hand2')
        self.urlscan_stop_btn.pack(side='left', padx=(8, 0))
        self.urlscan_open_btn = tk.Button(btn_row, text="📄 打开报告", command=self._open_urlscan_report,
                                          bg='#d97706', fg='white', font=('Segoe UI', 9),
                                          relief='flat', padx=12, pady=8, state='disabled',
                                          cursor='hand2')
        self.urlscan_open_btn.pack(side='left', padx=(8, 0))

        hint = tk.Label(card, text="⚠️ 扫描会向目标站点发起 HTTP 请求获取网页源码。\n"
                                   "检测: WebShell/命令执行 · 挂马注入 · JS 混淆 · ClickFix/假更新 · Magecart · 免杀载荷 · 钓鱼 · IoC\n"
                                   "动态监控需 playwright (pip install playwright) + 系统 Chrome",
                        font=('Segoe UI', 8), bg='white', fg='#9ca3af', justify='left')
        hint.pack(anchor='w', padx=15, pady=(0, 10))

        self._urlscan_results = []
        self._urlscan_reports = []
        self._urlscan_running = False
        self._urlscan_stop_event = threading.Event()

    def _build_ioc_tab(self, notebook):
        """自定义 IoC 管理标签页: 添加/删除/刷新本地威胁情报"""
        tab = tk.Frame(notebook, bg='#f0f2f5')
        notebook.add(tab, text="🔖 IoC 管理")

        self.ioc_engine = None
        self.ioc_type_var = tk.StringVar(value='ip')
        self.ioc_value_var = tk.StringVar()
        self.ioc_tag_var = tk.StringVar(value='Custom')
        self.ioc_desc_var = tk.StringVar()

        form = tk.LabelFrame(tab, text='添加 / 删除自定义 IoC', bg='white',
                             fg='#374151', font=('Segoe UI', 11, 'bold'),
                             relief='groove', bd=1, padx=12, pady=8)
        form.pack(fill='x', padx=10, pady=(10, 6))

        row1 = tk.Frame(form, bg='white')
        row1.pack(fill='x', pady=2)
        tk.Label(row1, text='类型:', font=('Segoe UI', 9), bg='white',
                 fg='#374151', width=8, anchor='w').pack(side='left')
        ttk.Combobox(row1, textvariable=self.ioc_type_var, values=['ip', 'domain', 'url'],
                     state='readonly', width=10).pack(side='left')

        row2 = tk.Frame(form, bg='white')
        row2.pack(fill='x', pady=2)
        tk.Label(row2, text='值:', font=('Segoe UI', 9), bg='white',
                 fg='#374151', width=8, anchor='w').pack(side='left')
        ttk.Entry(row2, textvariable=self.ioc_value_var, width=38).pack(side='left')

        row3 = tk.Frame(form, bg='white')
        row3.pack(fill='x', pady=2)
        tk.Label(row3, text='标签:', font=('Segoe UI', 9), bg='white',
                 fg='#374151', width=8, anchor='w').pack(side='left')
        ttk.Entry(row3, textvariable=self.ioc_tag_var, width=20).pack(side='left')

        row4 = tk.Frame(form, bg='white')
        row4.pack(fill='x', pady=2)
        tk.Label(row4, text='描述:', font=('Segoe UI', 9), bg='white',
                 fg='#374151', width=8, anchor='w').pack(side='left')
        ttk.Entry(row4, textvariable=self.ioc_desc_var, width=38).pack(side='left')

        btn_row = tk.Frame(form, bg='white')
        btn_row.pack(fill='x', pady=(8, 0))
        tk.Button(btn_row, text='➕ 添加', command=self._ioc_add,
                  bg='#4f46e5', fg='white', font=('Segoe UI', 9),
                  relief='flat', padx=12, pady=3, cursor='hand2').pack(side='left')
        tk.Button(btn_row, text='🗑 删除', command=self._ioc_remove,
                  bg='#ef4444', fg='white', font=('Segoe UI', 9),
                  relief='flat', padx=12, pady=3, cursor='hand2').pack(side='left', padx=(8, 0))
        tk.Button(btn_row, text='🔄 刷新', command=self._ioc_refresh,
                  bg='#10b981', fg='white', font=('Segoe UI', 9),
                  relief='flat', padx=12, pady=3, cursor='hand2').pack(side='left', padx=(8, 0))

        list_frame = tk.Frame(tab, bg='#f0f2f5')
        list_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        scroll = tk.Scrollbar(list_frame)
        scroll.pack(side='right', fill='y')
        self.ioc_list = tk.Listbox(list_frame, yscrollcommand=scroll.set, font=('Consolas', 9),
                                   bg='white', fg='#374151', selectbackground='#4f46e5',
                                   selectforeground='white', relief='solid', borderwidth=1)
        self.ioc_list.pack(side='left', fill='both', expand=True)
        scroll.config(command=self.ioc_list.yview)

        self.root.after(0, self._ioc_refresh)

    def _ensure_ioc_engine(self):
        if self.ioc_engine is None:
            from analyzer.threat_intel import ThreatIntelEngine
            self.ioc_engine = ThreatIntelEngine()
        return self.ioc_engine

    def _ioc_refresh(self):
        """刷新 IoC 列表 (本地文件读取, 直接在主线程执行)"""
        try:
            engine = self._ensure_ioc_engine()
            iocs = engine.list_custom_iocs()
            self.ioc_list.delete(0, 'end')
            type_key_map = [('IP', 'ips', 'ip'), ('域名', 'domains', 'domain'), ('URL', 'urls', 'url')]
            for label, key, ioc_type in type_key_map:
                for value in iocs.get(key, []):
                    info = engine.get_ioc_info(ioc_type, value)
                    self.ioc_list.insert('end', f"[{label}] {value} | {info.get('family', '?')} | {info.get('description', '')}")
            self._append_log(f"[IoC] 已刷新: {iocs.get('total', 0)} 条自定义 IoC", 'info')
        except Exception as e:
            messagebox.showerror('IoC 管理', f'刷新失败: {e}')

    def _ioc_add(self):
        ioc_type = self.ioc_type_var.get().strip().lower()
        value = self.ioc_value_var.get().strip()
        family = self.ioc_tag_var.get().strip() or 'Custom'
        description = self.ioc_desc_var.get().strip()
        if not value:
            messagebox.showwarning('提示', '请输入 IoC 值')
            return
        try:
            engine = self._ensure_ioc_engine()
            ok = engine.add_ioc(ioc_type, value, family, description)
            if ok:
                self.ioc_value_var.set('')
                self.ioc_desc_var.set('')
                self._append_log(f"[IoC] 已添加: [{ioc_type}] {value} ({family})", 'success')
                self._ioc_refresh()
            else:
                messagebox.showwarning('提示', f'添加失败: 不支持的 IoC 类型 ({ioc_type})，支持 ip/domain/url')
        except Exception as e:
            messagebox.showerror('IoC 管理', f'添加失败: {e}')

    def _ioc_remove(self):
        ioc_type = self.ioc_type_var.get().strip().lower()
        value = self.ioc_value_var.get().strip()
        if not value:
            messagebox.showwarning('提示', '请输入要删除的 IoC 值')
            return
        if not messagebox.askyesno('确认删除', f'确定要删除 [{ioc_type}] {value} 吗？'):
            return
        try:
            engine = self._ensure_ioc_engine()
            ok = engine.remove_ioc(ioc_type, value)
            if ok:
                self.ioc_value_var.set('')
                self._append_log(f"[IoC] 已删除: [{ioc_type}] {value}", 'info')
                self._ioc_refresh()
            else:
                messagebox.showinfo('提示', f'未找到 [{ioc_type}] {value}')
        except Exception as e:
            messagebox.showerror('IoC 管理', f'删除失败: {e}')

    def _start_urlscan(self):
        if self._urlscan_running:
            return
        raw = self.urlscan_text.get('1.0', 'end').strip()
        urls = [u.strip() for u in re.split(r'[\n,;]+', raw) if u.strip()]
        if not urls:
            messagebox.showwarning("提示", "请输入要扫描的 URL (例如 http://example.com/info.php)")
            return
        # 简单校验: 至少看起来像 URL
        bad = [u for u in urls if not re.match(r'^https?://', u, re.I)]
        if bad:
            messagebox.showwarning("提示", f"URL 必须以 http:// 或 https:// 开头:\n" + "\n".join(bad[:5]))
            return

        self._urlscan_running = True
        self._urlscan_stop_event.clear()
        self._urlscan_index_path = ''
        self._urlscan_reports = []
        self.urlscan_btn.config(state='disabled')
        self.urlscan_stop_btn.config(state='normal')
        self.urlscan_open_btn.config(state='disabled')
        self.progress.start()
        self.progress_label.config(text=f"URL 扫描中 ({len(urls)} 个目标)...")

        self._append_log(f"[URLScan] 开始扫描 {len(urls)} 个 URL: {urls[:5]}{' ...' if len(urls) > 5 else ''}", 'header')

        # ⚠ 所有 Tk 变量必须在主线程读取, 子线程读取会触发线程安全问题
        fetch_js = self.urlscan_fetch_js.get()
        dyn = self.urlscan_dynamic.get()
        eng_text = self.urlscan_engine_var.get()
        urlscan_timeout = self.urlscan_timeout_var.get()
        urlscan_wait = self.urlscan_wait_var.get()
        urlscan_dyn_timeout = self.urlscan_dyn_timeout_var.get()
        urlscan_parallel = self.urlscan_parallel_var.get()
        # 引擎: Combobox 值 "label — key", 取 key
        engines = None
        for k, v in self._urlscan_engines:
            if eng_text.startswith(v):
                engines = [e.strip() for e in k.split(',') if e.strip()]
                break

        def _run():
            try:
                from analyzer.url_scanner import scan_urls
                # 应用本次的超时/观察设置
                try:
                    from config import CONFIG as _C
                    _C.url_scan.timeout = urlscan_timeout
                    _C.url_scan.dynamic_wait = urlscan_wait
                    _C.url_scan.dynamic_timeout = urlscan_dyn_timeout
                    _C.url_scan.max_parallel = urlscan_parallel
                except Exception:
                    pass
                results = scan_urls(urls, fetch_external_scripts=fetch_js,
                                    enable_dynamic=dyn,
                                    browser_engines=engines,
                                    max_workers=urlscan_parallel,
                                    stop_event=self._urlscan_stop_event)
                self._urlscan_results = results
                self.log_queue.put(('urlscan_done', results))
            except Exception as e:
                self.log_queue.put(('error', f"[URLScan] 扫描异常: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    def _stop_urlscan(self):
        if self._urlscan_running:
            self._urlscan_stop_event.set()
            self._append_log("[URLScan] 停止请求已发送...", 'warning')

    def _open_urlscan_report(self):
        if self._urlscan_index_path and os.path.isfile(self._urlscan_index_path):
            try:
                os.startfile(self._urlscan_index_path)
                return
            except Exception as e:
                messagebox.showerror('打开失败', str(e))
                return
        if not self._urlscan_reports:
            return
        try:
            os.startfile(self._urlscan_reports[0])
        except Exception as e:
            messagebox.showerror('打开失败', str(e))

    def _on_urlscan_done(self, results):
        self._urlscan_running = False
        self.progress.stop()
        self.urlscan_btn.config(state='normal')
        self.urlscan_stop_btn.config(state='disabled')
        self.progress_label.config(text="URL 扫描完成!")
        reports = []
        bad = 0
        try:
            from report.url_report_generator import generate_html, generate_json
            from config import CONFIG as _CONF
            out_dir = _CONF.report.output_dir
            for r in results:
                if r.risk_level in ('high', 'critical'):
                    bad += 1
                host = r.url.replace('http://', '').replace('https://', '').replace('/', '_')[:40]
                host = re.sub(r'[<>:"/\\|?*]', '_', host)
                p = os.path.join(out_dir, f'urlscan_{host}_{int(time.time())}.html')
                try:
                    generate_html(r, p)
                    reports.append(p)
                except Exception as e:
                    self._append_log(f"[URLScan] 报告生成失败: {e}", 'error')
                try:
                    generate_json(r)
                except Exception:
                    pass
                self._append_log(
                    f"[URLScan] {'⛔' if r.risk_level in ('high', 'critical') else '⚠️' if r.risk_level == 'medium' else '✅'} "
                    f"{r.url} → [{r.risk_level.upper()}] {r.risk_score}/100 | {r.summary}",
                    'error' if r.risk_level in ('high', 'critical') else 'warning' if r.risk_level == 'medium' else 'success')
        except Exception as e:
            self._append_log(f"[URLScan] 报告保存失败: {e}", 'error')
        self._urlscan_reports = reports
        self._urlscan_index_path = ''
        try:
            from report.index_generator import generate_url_index
            idx = generate_url_index(CONFIG.report.output_dir, results)
            self._urlscan_index_path = idx or ''
            if self._urlscan_index_path:
                self._append_log(f"[URLScan] URL 扫描索引已生成: {self._urlscan_index_path}", 'success')
        except Exception as e:
            self._append_log(f"[URLScan] URL 索引生成失败: {e}", 'warning')
        if reports or self._urlscan_index_path:
            self.urlscan_open_btn.config(state='normal')
        if not results:
            self._append_log("[URLScan] 无结果", 'warning')
        elif bad == 0:
            self._append_log(f"[URLScan] 扫描完成: {len(results)} 个目标, 未发现高危 (详见 HTML 报告)", 'success')
        else:
            self._append_log(f"[URLScan] 扫描完成: {len(results)} 个目标, {bad} 个危险!", 'error')

    def _build_history_tab(self, notebook):
        """历史分析记录: 列出 reports/ 下所有报告, 点击打开"""
        tab = tk.Frame(notebook, bg='#f0f2f5')
        notebook.add(tab, text="🕘 历史记录")

        top = tk.Frame(tab, bg='#f0f2f5')
        top.pack(fill='x', padx=10, pady=(10, 4))
        tk.Label(top, text="历史分析报告 (reports/)", font=('Segoe UI', 11, 'bold'),
                 bg='#f0f2f5', fg='#374151').pack(side='left')
        self.btn_refresh_history = tk.Button(top, text="🔄 刷新", command=self._refresh_history,
                                             bg='#4f46e5', fg='white', font=('Segoe UI', 9),
                                             relief='flat', padx=10, pady=3, cursor='hand2')
        self.btn_refresh_history.pack(side='right')

        # 列表容器 (滚动)
        wrap = tk.Frame(tab, bg='#f0f2f5')
        wrap.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        scroll = tk.Scrollbar(wrap)
        scroll.pack(side='right', fill='y')
        self.history_list = tk.Listbox(wrap, yscrollcommand=scroll.set, font=('Consolas', 9),
                                       bg='white', fg='#374151', selectbackground='#4f46e5',
                                       selectforeground='white', relief='solid', borderwidth=1)
        self.history_list.pack(side='left', fill='both', expand=True)
        scroll.config(command=self.history_list.yview)
        self.history_list.bind('<Double-Button-1>', lambda e: self._open_history_report())

        hint = tk.Label(tab, text="双击条目打开报告 · 每次分析完成后自动刷新",
                        font=('Segoe UI', 8), bg='#f0f2f5', fg='#9ca3af')
        hint.pack(anchor='w', padx=12, pady=(0, 8))
        self._history_entries = []
        self._refresh_history()

    def _refresh_history(self):
        """扫描 reports/ 目录列出 HTML 报告"""
        try:
            import config
            out_dir = config.CONFIG.report.output_dir
            entries = []
            if os.path.isdir(out_dir):
                for fn in sorted(os.listdir(out_dir)):
                    if fn.endswith('.html'):
                        full = os.path.join(out_dir, fn)
                        try:
                            mtime = time.strftime('%Y-%m-%d %H:%M', time.localtime(os.path.getmtime(full)))
                            size_kb = os.path.getsize(full) // 1024
                            entries.append((full, f'{mtime}  {size_kb}KB  {fn}'))
                        except OSError:
                            continue
            entries.sort(key=lambda x: x[0], reverse=True)
            self.history_list.delete(0, 'end')
            self._history_entries = entries
            for full, label in entries[:60]:
                self.history_list.insert('end', label)
        except Exception:
            pass

    def _open_history_report(self):
        sel = self.history_list.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx >= len(self._history_entries):
            return
        full = self._history_entries[idx][0]
        try:
            os.startfile(full)
        except Exception as e:
            messagebox.showerror('打开失败', str(e))

    def _build_deps_tab(self, notebook):
        tab = tk.Frame(notebook, bg='#f0f2f5')
        notebook.add(tab, text="📦 依赖库")
        # 延迟检测，初始显示占位
        if self.dep_checker:
            self._build_deps_tab_content(tab)
        else:
            self._deps_tab = tab
            tk.Label(tab, text="正在检测依赖库…", font=('Segoe UI', 11),
                    bg='#f0f2f5', fg='#6b7280').pack(expand=True)
    
    def _build_env_tab(self, notebook):
        tab = tk.Frame(notebook, bg='#f0f2f5')
        notebook.add(tab, text="🖥️  环境")

        # === 环境检测 ===
        env_frame = tk.Frame(tab, bg='white', highlightbackground='#e5e7eb', highlightthickness=1, bd=0)
        env_frame.pack(fill='x', pady=(0, 10), padx=2)
        tk.Label(env_frame, text="🛡️ 环境安全检测", font=('Segoe UI', 12, 'bold'),
                bg='white', fg='#374151').pack(anchor='w', padx=15, pady=(12, 8))

        self.env_detail_text = tk.Text(env_frame, wrap='word', height=12, font=('Consolas', 10),
                                      bg='#f8fafc', fg='#374151', relief='flat', padx=10, pady=8)
        self.env_detail_text.pack(fill='x', padx=15, pady=(0, 12))
        self.env_detail_text.config(state='disabled')

        btn_row = tk.Frame(env_frame, bg='white')
        btn_row.pack(fill='x', padx=15, pady=(0, 12))
        tk.Button(btn_row, text="🔄 重新检测", command=self._refresh_env,
                 bg='#4f46e5', fg='white', font=('Segoe UI', 9), relief='flat',
                 padx=12, pady=4, cursor='hand2').pack(side='left')

        # === VM 环境隐藏 ===
        vm_frame = tk.Frame(tab, bg='white', highlightbackground='#e5e7eb', highlightthickness=1, bd=0)
        vm_frame.pack(fill='x', pady=(0, 10), padx=2)
        tk.Label(vm_frame, text="🕶️ VM 痕迹隐藏", font=('Segoe UI', 12, 'bold'),
                bg='white', fg='#374151').pack(anchor='w', padx=15, pady=(12, 8))

        desc = tk.Label(vm_frame,
            text="在动态分析前隐藏 VM 进程/服务/驱动/注册表，对抗恶意软件的反 VM 检测。\n"
                 "需要管理员权限。分析完成后请记得恢复。",
            font=('Segoe UI', 9), bg='white', fg='#6b7280', justify='left')
        desc.pack(anchor='w', padx=15, pady=(0, 8))

        # 按钮行
        vm_btn_row = tk.Frame(vm_frame, bg='white')
        vm_btn_row.pack(fill='x', padx=15, pady=(0, 4))
        self.btn_hide_vm = tk.Button(vm_btn_row, text="🕶️ 隐藏 VM 痕迹", command=self._hide_vm,
                                     bg='#f59e0b', fg='white', font=('Segoe UI', 9), relief='flat',
                                     padx=12, pady=5, cursor='hand2')
        self.btn_hide_vm.pack(side='left')
        self.btn_restore_vm = tk.Button(vm_btn_row, text="🔄 恢复 VM 环境", command=self._restore_vm,
                                        bg='#10b981', fg='white', font=('Segoe UI', 9), relief='flat',
                                        padx=12, pady=5, cursor='hand2', state='disabled')
        self.btn_restore_vm.pack(side='left', padx=(6, 0))
        self.btn_verify_vm = tk.Button(vm_btn_row, text="🔍 验证隐藏效果", command=self._verify_vm,
                                       bg='#6366f1', fg='white', font=('Segoe UI', 9), relief='flat',
                                       padx=12, pady=5, cursor='hand2')
        self.btn_verify_vm.pack(side='left', padx=(6, 0))

        # 状态文本
        self.vm_status_text = tk.Text(vm_frame, wrap='word', height=8, font=('Consolas', 9),
                                      bg='#f8fafc', fg='#374151', relief='flat', padx=10, pady=8,
                                      state='disabled')
        self.vm_status_text.pack(fill='x', padx=15, pady=(6, 12))

        # 初始化 VM 隐藏器
        self.vm_hider = None

        # === 关于 ===
        about_frame = tk.Frame(tab, bg='white', highlightbackground='#e5e7eb', highlightthickness=1, bd=0)
        about_frame.pack(fill='x', pady=(0, 10), padx=2)
        tk.Label(about_frame, text="ℹ️ 关于", font=('Segoe UI', 12, 'bold'),
                 bg='white', fg='#374151').pack(anchor='w', padx=15, pady=(12, 8))

        yara_count = 'N/A'
        try:
            from utils.helpers import resource_path
            yara_dir = resource_path('rules/yara')
            if os.path.isdir(yara_dir):
                yara_count = len([n for n in os.listdir(yara_dir) if n.lower().endswith(('.yar', '.yara'))])
        except Exception:
            pass

        py_ver = 'N/A'
        try:
            import platform as _pf
            py_ver = _pf.python_version()
        except Exception:
            pass

        cfg_path = 'N/A'
        try:
            import config as _cfg_mod
            _cfg_file = getattr(getattr(_cfg_mod, '_config_manager', None), '_config_path', None)
            cfg_path = str(_cfg_file) if _cfg_file else '默认配置'
        except Exception:
            pass

        about_lines = [
            f"应用: {APP_NAME} v{APP_VERSION}",
            f"程序名称: {APP_NAME_CN}",
            f"Python 版本: {py_ver}",
            f"YARA 规则数: {yara_count}",
            f"配置文件: {cfg_path}",
        ]
        tk.Label(about_frame, text='\n'.join(about_lines), font=('Segoe UI', 10),
                 bg='white', fg='#374151', justify='left').pack(anchor='w', padx=15, pady=(0, 12))
    
    # ===== 事件处理 =====
    def _init_deps_and_env(self):
        """GUI 显示后后台初始化依赖检测和环境检测（不阻塞启动）"""
        def _do_init():
            # 依赖检测
            from utils.dep_checker import DependencyChecker
            self.dep_checker = DependencyChecker()
            # 到主线程刷新 UI
            self.root.after(0, self._on_deps_ready)
            # 环境检测
            self.root.after(100, self._show_dep_check)

        threading.Thread(target=_do_init, daemon=True).start()

    def _on_deps_ready(self):
        """依赖检测完成后刷新 UI"""
        # 重建依赖库标签页
        if hasattr(self, '_deps_tab') and self._deps_tab:
            for w in self._deps_tab.winfo_children():
                w.destroy()
            self._build_deps_tab_content(self._deps_tab)

        # 刷新分析选项的依赖标记
        for key, (cb, dep_label, dep_pkg) in list(self.opt_widgets.items()):
            if dep_pkg and dep_label:
                installed = self.dep_checker.results.get(dep_pkg, {}).get('installed', False)
                if installed:
                    dep_label.config(text="✅ 已安装", fg='#10b981')
                else:
                    dep_label.config(text="⚠️ 未安装", fg='#ef4444')

    def _show_dep_check(self):
        """启动时显示依赖检查结果"""
        if not self.dep_checker:
            return
        import sys as _sys
        frozen = getattr(_sys, 'frozen', False)
        missing = self.dep_checker.get_missing() or []
        if missing:
            self._append_log(f"[!] 检测到 {len(missing)} 个可选库未安装，部分功能受限", 'warning')
            if frozen:
                self._append_log("    打包版本不支持pip安装，请用源码运行并安装后重新打包", 'info')
            else:
                self._append_log("    切换到 '依赖库' 标签页查看详情并安装", 'info')
            for info in missing:
                if info['install_cmd']:
                    self._append_log(f"    ❌ {info['name']:12s} → {info['install_cmd']}", 'info')
                else:
                    self._append_log(f"    ❌ {info['name']:12s} — {info['description']}", 'info')
        else:
            self._append_log("[+] 所有依赖库均已安装", 'success')

        # 同时检测环境
        self._refresh_env()
    
    def _refresh_env(self):
        """刷新环境检测 — 后台执行, 避免主线程跑 PowerShell 子进程导致界面冻结"""
        def _worker():
            try:
                from analyzer.vm_detector import VMDetector
                result = VMDetector().detect()
            except Exception as e:
                result = {
                    'risk_level': 'unknown', 'is_vm': False,
                    'is_windows_sandbox': False, 'is_docker': False,
                    'is_hyperv': False, 'evidence': [f'检测异常: {e}'],
                }
            try:
                self.log_queue.put(('ui_call', lambda: self._apply_env_result(result)))
            except Exception:
                pass

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_env_result(self, result):
        """主线程: 更新环境检测结果界面"""
        try:
            # 更新顶部状态
            risk = result['risk_level']
            if risk == 'safe':
                self.env_status_var.set("🟢 环境安全 (Sandbox/VM)")
                self.env_status_label.config(fg='#10b981')
            elif risk == 'vm':
                self.env_status_var.set("🟡 虚拟机环境 (建议快照)")
                self.env_status_label.config(fg='#f59e0b')
            else:
                self.env_status_var.set("🔴 未检测到隔离环境！")
                self.env_status_label.config(fg='#ef4444')
            
            # 更新详情文本
            self.env_detail_text.config(state='normal')
            self.env_detail_text.delete('1.0', 'end')

            # 系统信息 (Win10/11 版本识别)
            sys_lines = []
            try:
                import platform as _pf
                ver = _pf.version()
                build = ver.split('.')[-1] if '.' in ver else ver
                try:
                    build_num = int(build)
                    if build_num >= 22000:
                        os_name = 'Windows 11'
                    elif build_num >= 10240:
                        os_name = 'Windows 10'
                    else:
                        os_name = f'Windows (build {build_num})'
                except Exception:
                    os_name = 'Windows'
                sys_lines = [
                    f"操作系统: {os_name} (build {build})",
                    f"平台: {_pf.platform()}",
                ]
            except Exception:
                pass

            lines = [
                f"环境安全等级: {risk.upper()}",
                "",
            ] + sys_lines + [
                "",
                "检测结果:",
                f"  虚拟机 (VM):     {'是' if result['is_vm'] else '否'}",
                f"  Windows Sandbox: {'是' if result['is_windows_sandbox'] else '否'}",
                f"  Docker:          {'是' if result['is_docker'] else '否'}",
                f"  Hyper-V:         {'是' if result['is_hyperv'] else '否'}",
                "",
                f"证据 ({len(result['evidence'])} 项):",
            ]
            for ev in result['evidence']:
                lines.append(f"  • {ev}")
            
            if risk == 'dangerous':
                lines.append("")
                lines.append("⚠️ 警告: 未检测到任何隔离环境!")
                lines.append("动态分析将直接执行恶意样本，可能导致系统感染!")
                lines.append("强烈建议在 VMware/VirtualBox 快照虚拟机中运行。")
            
            self.env_detail_text.insert('end', '\n'.join(lines))
            self.env_detail_text.config(state='disabled')
            
        except Exception:
            self.env_status_var.set("⚠️ 环境检测失败")
            self.env_status_label.config(fg='#f59e0b')

    # ===== VM 隐藏/恢复/验证 =====

    def _hide_vm(self):
        """隐藏 VM 痕迹"""
        if not messagebox.askyesno("确认", "将隐藏 VM 进程/服务/驱动/注册表痕迹。\n\n需要管理员权限。\n动态分析后请点击「恢复 VM 环境」。\n\n是否继续？"):
            return

        self._append_log("[*] 开始隐藏 VM 痕迹...", 'info')
        self._set_vm_status("正在隐藏…")

        def _do_hide():
            try:
                from analyzer.vm_process_hider import VMProcessHider
                self.vm_hider = VMProcessHider()
                result = self.vm_hider.hide()

                if result['status'].startswith('error'):
                    self.log_queue.put(("error", f"[!] VM 隐藏失败: {result['status']}"))
                    self.log_queue.put(('ui_call', lambda: self._set_vm_status("失败 — 需要管理员权限")))
                    self.log_queue.put(('ui_call', lambda: self.btn_restore_vm.config(state='disabled')))
                    return

                lines = [
                    f"状态: {result['status']}",
                    f"终止进程: {len(result['hidden'])} 个",
                    f"停止服务: {len(result['stopped'])} 个",
                    f"禁用驱动: {len(result['driver_stopped'])} 个",
                    f"重命名文件: {len(result['renamed'])} 个",
                    f"删除注册表: {len(result['registry_deleted'])} 个",
                    f"修改注册表值: {len(result['registry_modified'])} 个",
                ]
                if result['renamed']:
                    lines.append("\n重命名的文件:")
                    for r in result['renamed'][:10]:
                        lines.append(f"  • {r}")
                if result['driver_stopped']:
                    lines.append("\n禁用的驱动:")
                    for d in result['driver_stopped'][:15]:
                        lines.append(f"  • {d}")

                # 验证
                v = result.get('verification', {})
                lines.append("\n--- 验证 ---")
                lines.append(f"残留 VM 进程: {len(v.get('running_vm_processes', []))}")
                lines.append(f"残留 VM 服务: {len(v.get('running_vm_services', []))}")
                lines.append(f"残留 VM 驱动: {len(v.get('loaded_vm_drivers', []))}")
                lines.append(f"残留注册表:   {len(v.get('existing_vm_regkeys', []))}")
                if v.get('loaded_vm_drivers'):
                    lines.append(f"  ({', '.join(v['loaded_vm_drivers'][:8])})")

                all_clear = all(len(v.get(k, [])) == 0 for k in
                    ['running_vm_processes', 'running_vm_services', 'loaded_vm_drivers', 'existing_vm_regkeys'])

                self.log_queue.put(('ui_call', lambda: self._set_vm_status('\n'.join(lines))))
                self.log_queue.put(('ui_call', lambda: self.btn_hide_vm.config(state='disabled')))
                self.log_queue.put(('ui_call', lambda: self.btn_restore_vm.config(state='normal')))
                self.log_queue.put(f"[+] VM 隐藏完成: {result['status']}")
                if not all_clear:
                    self.log_queue.put(("warning", "[!] 仍有 VM 痕迹残留，请检查验证结果"))

            except Exception as e:
                self.log_queue.put(("error", f"[!] VM 隐藏异常: {e}"))
                self.log_queue.put(('ui_call', lambda e=e: self._set_vm_status(f"异常: {e}")))

        threading.Thread(target=_do_hide, daemon=True).start()

    def _restore_vm(self):
        """恢复 VM 环境"""
        if not self.vm_hider:
            messagebox.showinfo("提示", "没有需要恢复的内容")
            return

        if not messagebox.askyesno("确认", "将恢复 VM 进程/服务/驱动/注册表。\n\n是否继续？"):
            return

        self._append_log("[*] 恢复 VM 环境...", 'info')
        self._set_vm_status("正在恢复…")

        def _do_restore():
            try:
                result = self.vm_hider.restore()
                lines = [
                    f"状态: {result['status']}",
                    f"恢复文件:   {len(result['renamed_back'])} 个",
                    f"启动驱动:   {len(result['started_drivers'])} 个",
                    f"启动服务:   {len(result['started_services'])} 个",
                    f"恢复注册表: {len(result['registry_restored'])} 个",
                ]
                self.log_queue.put(('ui_call', lambda: self._set_vm_status('\n'.join(lines))))
                self.log_queue.put(('ui_call', lambda: self.btn_hide_vm.config(state='normal')))
                self.log_queue.put(('ui_call', lambda: self.btn_restore_vm.config(state='disabled')))
                self.log_queue.put(f"[+] VM 环境已恢复: {result['status']}")
            except Exception as e:
                self.log_queue.put(("error", f"[!] VM 恢复异常: {e}"))
                self.log_queue.put(('ui_call', lambda e=e: self._set_vm_status(f"异常: {e}")))

        threading.Thread(target=_do_restore, daemon=True).start()

    def _verify_vm(self):
        """验证 VM 隐藏效果"""
        self._append_log("[*] 验证 VM 隐藏效果...", 'info')
        self._set_vm_status("正在验证…")

        def _do_verify():
            try:
                from analyzer.vm_process_hider import VMProcessHider
                hider = self.vm_hider if self.vm_hider else VMProcessHider()
                v = hider._verify_hiding()
                running = sum(len(v.get(k, [])) for k in
                    ['running_vm_processes', 'running_vm_services', 'loaded_vm_drivers', 'existing_vm_regkeys'])

                lines = [
                    f"VM 进程:   {len(v.get('running_vm_processes', []))} 个",
                    f"VM 服务:   {len(v.get('running_vm_services', []))} 个",
                    f"VM 驱动:   {len(v.get('loaded_vm_drivers', []))} 个",
                    f"注册表键:  {len(v.get('existing_vm_regkeys', []))} 个",
                ]
                if running == 0:
                    lines.append("\n✅ 全部通过 — 无可检测的 VM 痕迹")
                else:
                    lines.append(f"\n⚠️ 仍有 {running} 项残留")
                    if v.get('loaded_vm_drivers'):
                        lines.append(f"驱动: {', '.join(v['loaded_vm_drivers'][:10])}")
                    if v.get('running_vm_services'):
                        lines.append(f"服务: {', '.join(v['running_vm_services'])}")
                    if v.get('running_vm_processes'):
                        lines.append(f"进程: {', '.join(v['running_vm_processes'])}")

                self.log_queue.put(('ui_call', lambda: self._set_vm_status('\n'.join(lines))))
                self.log_queue.put(f"[+] 验证完成: {'全部通过' if running == 0 else f'{running} 项残留'}")

                if running > 0:
                    self.log_queue.put(('ui_call', lambda: self.btn_restore_vm.config(state='normal')))
            except Exception as e:
                self.log_queue.put(("error", f"[!] 验证异常: {e}"))
                self.log_queue.put(('ui_call', lambda e=e: self._set_vm_status(f"异常: {e}")))

        threading.Thread(target=_do_verify, daemon=True).start()

    def _set_vm_status(self, text):
        """更新 VM 状态文本"""
        self.vm_status_text.config(state='normal')
        self.vm_status_text.delete('1.0', 'end')
        self.vm_status_text.insert('1.0', text)
        self.vm_status_text.config(state='disabled')

    def _browse_file(self):
        path = filedialog.askopenfilename(title='选择要分析的样本文件')
        if path:
            self.file_path_var.set(path)
            self.drop_label.config(text=f"已选择: {os.path.basename(path)}")
    
    def _start_analysis(self):
        file_path = self.file_path_var.get().strip()
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("提示", "请先选择一个有效的样本文件")
            return
        if self.analyzing:
            return
        
        # 安全检测：物理机上二次确认才允许动态分析
        enable_dynamic = self.opt_vars['enable_dynamic'].get()

        # 级联兜底：子选项开了但主开关没开 → 自动开启
        dynamic_sub_keys = ['enable_sandbox', 'enable_vm_hide', 'enable_memory', 'enable_frida', 'enable_time_accel']
        if not enable_dynamic and any(self.opt_vars[k].get() for k in dynamic_sub_keys if k in self.opt_vars):
            self.opt_vars['enable_dynamic'].set(True)
            enable_dynamic = True

        if enable_dynamic:
            # VM/环境检测在后台线程执行, 避免主线程跑多个 PowerShell 子进程导致界面冻结
            self._start_dynamic_env_check(file_path)
            return

        self._launch_analysis(file_path)

    def _start_dynamic_env_check(self, file_path):
        """后台检测运行环境; 完成后通过 log_queue 回主线程弹确认框"""
        self._pending_env_file = file_path
        self._append_log("[*] 正在检测运行环境 (VM/沙箱)...", 'info')
        try:
            self.start_btn.config(state='disabled')
        except Exception:
            pass

        def _worker():
            try:
                from analyzer.vm_detector import VMDetector
                result = VMDetector().detect()
            except Exception as e:
                result = {'risk_level': 'unknown', 'evidence': [f'检测异常: {e}']}
            self.log_queue.put(('env_check', result))

        threading.Thread(target=_worker, daemon=True).start()

    def _handle_env_check(self, result):
        """主线程: 根据环境检测结果确认动态分析是否继续"""
        try:
            self.start_btn.config(state='normal')
        except Exception:
            pass
        file_path = getattr(self, '_pending_env_file', '')
        if not file_path or not os.path.exists(file_path):
            return
        if result.get('risk_level') == 'dangerous':
            # 第一道：警告
            if not messagebox.askyesno(
                "⛔ 严重警告 — 未检测到隔离环境",
                "您当前运行在物理机（宿主机）上！\n\n"
                "开启动态分析将直接执行恶意样本，可能导致：\n"
                "  • 系统文件被加密/删除（勒索软件）\n"
                "  • 系统崩溃/重启\n"
                "  • 数据被窃取\n"
                "  • 注册表被修改实现持久化\n\n"
                "强烈建议在 VMware/VirtualBox 快照虚拟机中运行。\n\n"
                "是否仍要继续？",
                icon='error'
            ):
                self._append_log("[!] 动态分析已取消：用户拒绝在非隔离环境执行，仅运行静态分析", 'warning')
                self.opt_vars['enable_dynamic'].set(False)
            else:
                # 第二道：输入确认文字
                from tkinter import simpledialog
                confirm = simpledialog.askstring(
                    "最终确认",
                    "请输入「我了解风险」以确认开启动态分析：",
                    parent=self.root
                )
                if confirm != "我了解风险":
                    self._append_log("[!] 动态分析已取消：未输入确认文字，仅运行静态分析", 'warning')
                    self.opt_vars['enable_dynamic'].set(False)
                else:
                    self._append_log("[!] ⚠️ 用户已双重确认在宿主机上执行动态分析", 'warning')
                    self._allow_dangerous = True
        elif result.get('risk_level') == 'unknown':
            self._append_log("[!] 环境检测失败, 无法确认隔离状态 — 动态分析将被保守禁用 (仅运行静态分析)", 'warning')
            self.opt_vars['enable_dynamic'].set(False)
        else:
            self._append_log(f"[+] 环境安全: {result.get('risk_level')} — 继续分析", 'success')

        self._launch_analysis(file_path)

    def _launch_analysis(self, file_path):
        # 检查依赖（如果还没初始化完则跳过）
        if self.dep_checker:
            for key, (cb, dep_label, dep_pkg) in self.opt_widgets.items():
                if dep_pkg and self.opt_vars[key].get():
                    if not self.dep_checker.results.get(dep_pkg, {}).get('installed', False):
                        if not messagebox.askyesno(
                            "依赖缺失",
                            f"选项 '{cb.cget('text')}' 需要 '{dep_pkg}' 库，但当前未安装。\n"
                            f"该功能可能无法正常工作。\n\n是否仍要继续？",
                            icon='warning'
                        ):
                            return
        
        self.analyzing = True
        self._analysis_start_time = time.time()
        self._reset_ui()

        # Web 监控模式：启动 HTTP 服务器
        web_state = None
        if self.opt_vars.get('enable_web_monitor', tk.BooleanVar(value=False)).get():
            try:
                from report.web_monitor import WebMonitor
                if self.web_monitor is None:
                    self.web_monitor = WebMonitor()
                if self.web_monitor.start():
                    web_state = self.web_monitor.state
                    self._append_log(f"[Web] 监控模式已启动 — 端口 {self.web_monitor.port}", 'success')
                    if self.web_monitor.urls:
                        self._set_web_url(self.web_monitor.urls)
                else:
                    self._append_log("[Web] 监控模式启动失败", 'error')
            except Exception as e:
                self._append_log(f"[Web] 监控模式启动异常: {e}", 'error')

        # 隐藏结果面板
        if self.result_card_visible:
            self.result_card.pack_forget()
            self.result_card_visible = False
        
        # Setup logger queue for GUI
        LoggerManager().setup(gui_queue=self.log_queue)

        # 获取 web_state（如果监控模式已启动）
        web_state = self.web_monitor.state if self.web_monitor else None

        self._analysis_stop_event.clear()
        # 主线程读取所有勾选状态（Tkinter 变量不能跨线程安全读取）
        opts_snapshot = {
            k: v.get() for k, v in self.opt_vars.items()
        }
        opts_snapshot['archive_password'] = self.archive_password_var.get().strip()
        self._analysis_thread = threading.Thread(
            target=self._run_analysis,
            args=(file_path, web_state, opts_snapshot),
            daemon=True
        )
        self._analysis_thread.start()
        # _poll_log 已在初始化时启动
    
    def _run_analysis(self, file_path, web_state=None, opts=None):
        try:
            from orchestrator import MalwareAnalysisPlatform
            platform = MalwareAnalysisPlatform()
            opts = opts or {}
            enable_dynamic = opts.get('enable_dynamic', False)
            enable_vm_hide = opts.get('enable_vm_hide', True)
            enable_time_accel = opts.get('enable_time_accel', False)

            # 加密压缩包密码（已在主线程快照, 不能跨线程读 Tkinter 变量）
            pw_text = opts.get('archive_password', '') if opts else ''
            archive_passwords = [p.strip() for p in pw_text.split(',') if p.strip()] if pw_text else None

            self.current_report = platform.analyze(
                file_path,
                enable_dynamic=enable_dynamic,
                allow_dangerous=self._allow_dangerous,
                no_vm_hide=not enable_vm_hide,
                enable_time_accel=enable_time_accel,
                web_state=web_state,
                archive_passwords=archive_passwords,
                enable_static=opts.get('enable_static', True),
                enable_threat=opts.get('enable_threat', True),
                enable_yara=opts.get('enable_yara', True),
                enable_family=opts.get('enable_family', True),
                enable_advanced=opts.get('enable_advanced', True),
                enable_destruction=opts.get('enable_destruction', True),
                enable_network=opts.get('enable_network', False),
                enable_memory=opts.get('enable_memory', True),
                enable_deep_dive=opts.get('enable_deep_dive', False),
                enable_deep_dive_watch=opts.get('enable_deep_dive_watch', True),
                enable_cleanup=opts.get('enable_cleanup', False),
                scan_discovered_urls=opts.get('scan_discovered_urls', True),
                fake_user_env=bool(getattr(CONFIG.sandbox, 'fake_user_env', True)),
                stop_event=self._analysis_stop_event,
            )
            self.log_queue.put(('done', None))
        except Exception as e:
            self.log_queue.put(('error', str(e)))

    def _start_batch_analysis(self, dir_path=None):
        """批量扫描目录 — 复用单文件分析的全部选项"""
        if dir_path is None:
            dir_path = filedialog.askdirectory(title='选择要批量扫描的目录')
        if not dir_path:
            return
        if self.analyzing:
            return
        # 主线程读取所有勾选状态（Tkinter 变量不能跨线程安全读取）
        opts_snapshot = {
            k: v.get() for k, v in self.opt_vars.items()
        }
        opts_snapshot['archive_password'] = self.archive_password_var.get().strip()
        if opts_snapshot.get('enable_dynamic'):
            self._append_log(
                "[Batch] 已开启动态分析 — 每个样本都会经过 VM 环境门禁, "
                "物理机/非隔离环境将自动跳过动态部分 (仅静态分析)", 'warning')
        self._analysis_stop_event.clear()
        self.analyzing = True
        self._analysis_start_time = time.time()
        if self.result_card_visible:
            self.result_card.pack_forget()
            self.result_card_visible = False
        self.current_report = None
        self._reset_ui()
        LoggerManager().setup(gui_queue=self.log_queue)
        self._append_log(f"[Batch] 开始批量扫描目录: {dir_path}", 'header')
        self._analysis_thread = threading.Thread(
            target=self._run_batch_analysis,
            args=(dir_path, opts_snapshot),
            daemon=True
        )
        self._analysis_thread.start()

    def _run_batch_analysis(self, dir_path, opts=None):
        try:
            from orchestrator import MalwareAnalysisPlatform
            from analyzer.batch import scan_directory
            from report.index_generator import generate_batch_index
            platform = MalwareAnalysisPlatform()
            opts = opts or {}
            enable_dynamic = opts.get('enable_dynamic', False)
            enable_vm_hide = opts.get('enable_vm_hide', True)
            enable_time_accel = opts.get('enable_time_accel', False)

            # 加密压缩包密码（已在主线程快照, 不能跨线程读 Tkinter 变量）
            pw_text = opts.get('archive_password', '') if opts else ''
            archive_passwords = [p.strip() for p in pw_text.split(',') if p.strip()] if pw_text else None

            results = scan_directory(
                platform,
                dir_path,
                stop_event=self._analysis_stop_event,
                enable_dynamic=enable_dynamic,
                allow_dangerous=self._allow_dangerous,
                no_vm_hide=not enable_vm_hide,
                enable_time_accel=enable_time_accel,
                archive_passwords=archive_passwords,
                enable_static=opts.get('enable_static', True),
                enable_threat=opts.get('enable_threat', True),
                enable_family=opts.get('enable_family', True),
                enable_advanced=opts.get('enable_advanced', True),
                enable_destruction=opts.get('enable_destruction', True),
                enable_network=opts.get('enable_network', False),
                enable_memory=opts.get('enable_memory', True),
                enable_deep_dive=opts.get('enable_deep_dive', False),
                enable_deep_dive_watch=opts.get('enable_deep_dive_watch', True),
                enable_cleanup=opts.get('enable_cleanup', False),
                enable_yara=opts.get('enable_yara', True),
                scan_discovered_urls=opts.get('scan_discovered_urls', True),
                fake_user_env=bool(getattr(CONFIG.sandbox, 'fake_user_env', True)),
            )
            self._batch_index_path = ''
            try:
                index_path = generate_batch_index(CONFIG.report.output_dir, results)
                self._batch_index_path = index_path or ''
                if self._batch_index_path:
                    self.log_queue.put(f"[Batch] 批量扫描索引已生成: {index_path}")
            except Exception as _e:
                self._batch_index_path = ''
                self.log_queue.put(('warning', f"[Batch] 批量扫描索引生成失败: {_e}"))

            total = len(results) if results else 0
            failed = sum(1 for _, r in (results or []) if r is None)
            self.log_queue.put(f"[Batch] 批量扫描完成: {total} 个文件, {failed} 个失败")
            self.log_queue.put(('done', None))
        except Exception as e:
            self.log_queue.put(('error', f"[Batch] 批量扫描异常: {e}"))
            # 异常时也要复位界面, 避免 start/stop 按钮永久卡死
            self.log_queue.put(('done', None))
    
    def _poll_log(self):
        _str_batch = []
        try:
            while True:
                item = self.log_queue.get_nowait()
                if isinstance(item, tuple):
                    # 处理 tuple 前先 flush 字符串日志, 保持日志顺序
                    if _str_batch:
                        self._append_log('\n'.join(_str_batch))
                        _str_batch = []
                    if item[0] == 'done':
                        self.root.after(0, self._analysis_complete)
                    elif item[0] == 'done_install':
                        self.root.after(0, lambda msg=item[1]: self._append_log(msg, 'success'))
                    elif item[0] == 'done_install_all':
                        self.root.after(0, lambda msg=item[1]: self._on_install_all_done(msg))
                    elif item[0] == 'error':
                        self._append_log(f"[Error] {item[1]}", 'error')
                    elif item[0] == 'warning':
                        self._append_log(item[1], 'warning')
                    elif item[0] == 'urlscan_done':
                        self.root.after(0, lambda res=item[1]: self._on_urlscan_done(res))
                    elif item[0] == 'env_check':
                        self.root.after(0, lambda res=item[1]: self._handle_env_check(res))
                    elif item[0] == 'ui_call':
                        # 工作线程提交的 Tk 更新, 统一调度回主线程执行
                        self.root.after(0, item[1])
                elif isinstance(item, str):
                    # 合并字符串日志: 减少 Text insert/see 次数 (分析时 UI 未响应的元凶)
                    _str_batch.append(item)
        except queue.Empty:
            pass
        # 剩余字符串日志 flush (必须在 try/except 之后, 否则 queue.Empty 抛异常会跳过 flush 导致日志丢失)
        if _str_batch:
            self._append_log('\n'.join(_str_batch))
        
        if self._poll_running:
            self.root.after(100, self._poll_log)
    
    def _analysis_complete(self):
        self.analyzing = False
        self.progress.stop()
        self.progress['value'] = 100
        self.progress_label.config(text="分析完成!")
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        try:
            self._refresh_history()
        except Exception:
            pass

        has_batch_index = bool(getattr(self, '_batch_index_path', '') and os.path.isfile(self._batch_index_path))
        if hasattr(self, 'btn_open_batch_index'):
            if has_batch_index:
                self.btn_open_batch_index.pack(side='left', padx=(6, 0))
            else:
                try:
                    self.btn_open_batch_index.pack_forget()
                except Exception:
                    pass

        if self.current_report:
            r = self.current_report
            
            # 显示结果面板
            self.result_card.pack(fill='x', pady=(8, 0))
            self.result_card_visible = True
            
            # 构建结果文本
            result_lines = [
                f"扫描ID: {r.scan_id}",
                f"风险等级: {r.risk_level.upper()} ({r.risk_score}/100)",
            ]
            if r.file_info:
                result_lines.append(f"文件: {r.file_info.name}")
                result_lines.append(f"SHA256: {r.file_info.sha256[:32]}...")
            if r.malware_family and r.malware_family.primary_family != 'Unknown':
                result_lines.append(f"木马家族: {r.malware_family.primary_family} ({r.malware_family.primary_confidence}%)")
            if r.advanced_behavior:
                ab = r.advanced_behavior
                if ab.anti_vm:
                    result_lines.append(f"⚠️ 反VM检测: {len(ab.anti_vm)} 项技术")
                if ab.anti_sandbox:
                    result_lines.append(f"⚠️ 反沙箱检测: {len(ab.anti_sandbox)} 项技术")
                if ab.anti_debug:
                    result_lines.append(f"🛡️ 反调试检测: {len(ab.anti_debug)} 项技术")
            
            self.result_content.config(text='\n'.join(result_lines))
            
            # 报告输出确认 — 历史问题: 分析完成但用户看不到报告
            html_path = self._find_report_path(r.scan_id, '.html')
            json_path = self._find_report_path(r.scan_id, '.json')
            html_exists = bool(html_path and os.path.isfile(html_path))
            json_exists = bool(json_path and os.path.isfile(json_path))
            if html_exists or json_exists:
                paths = []
                if html_exists and html_path:
                    paths.append(html_path)
                if json_exists:
                    paths.append(json_path)
                self._append_log(f"✅ 报告已生成 ({len(paths)} 个文件):", 'success')
                for p in paths:
                    self._append_log(f"   {os.path.abspath(p)}", 'success')
                # 自动打开 HTML 报告（浏览器）
                if html_exists and html_path and getattr(self, '_auto_open_report', True):
                    try:
                        os.startfile(os.path.abspath(html_path))
                        self._append_log("📄 已在浏览器中打开 HTML 报告", 'info')
                    except Exception as e:
                        self._append_log(f"[!] 自动打开报告失败: {e}（可点击顶部按钮手动打开）", 'warning')
            else:
                self._append_log("[!] 报告文件未生成！请在日志中查找 'HTML 报告生成失败' 等错误", 'error')
                html_err = getattr(r, '_report_errors', None)
                if html_err:
                    self._append_log(f"    {html_err}", 'error')
            
            # 日志摘要
            self._append_log("=" * 60, 'header')
            self._append_log(f"Scan ID: {r.scan_id}", 'info')
            self._append_log(f"Risk: {r.risk_level.upper()} ({r.risk_score}/100)",
                           'warning' if r.risk_score > 50 else 'success')
            if r.malware_family:
                self._append_log(f"Family: {r.malware_family.primary_family} ({r.malware_family.primary_confidence}%)", 'info')
            if r.advanced_behavior and r.advanced_behavior.anti_vm:
                self._append_log(f"⚠️ Anti-VM detected: {len(r.advanced_behavior.anti_vm)} techniques", 'warning')
                self._append_log("    建议: 按 docs/vmware_hardening.md 配置VM伪装", 'info')
            self._append_log("=" * 60, 'header')

            # Web 监控：在顶栏持久显示浏览器访问地址
            if self.web_monitor and self.web_monitor._running:
                if self.web_monitor.urls:
                    self._set_web_url(self.web_monitor.urls)

        elif has_batch_index:
            # 批量扫描: 展示结果卡片与批量索引入口
            self.result_card.pack(fill='x', pady=(8, 0))
            self.result_card_visible = True
            self.result_title.config(text="📊 Batch Result")
            self.result_content.config(text=f"批量扫描索引: {self._batch_index_path}")
            self._append_log(f"📇 批量扫描索引: {os.path.abspath(self._batch_index_path)}", 'success')

        # 自动行为
        if getattr(self, '_auto_cleanup', False):
            self._do_cleanup()

        if getattr(self, '_auto_close', False):
            delay = 1000 if getattr(self, '_auto_cleanup', False) else 3000
            self.root.after(delay, self._on_close)

    def _do_cleanup(self):
        """清理临时文件和环境 — 仅处理超过 1 天的旧临时项, 避免误删其他程序
        正在使用的同前缀目录/文件"""
        self._append_log("[CLEANUP] 正在清理临时文件...", 'info')
        import shutil as _shutil
        import tempfile as _tmp
        tmp_root = _tmp.gettempdir()
        cutoff = time.time() - 24 * 3600
        count = 0
        try:
            for name in os.listdir(tmp_root):
                if not name.startswith(('sandbox_', 'pip_install_', 'sandbox_log_')):
                    continue
                path = os.path.join(tmp_root, name)
                try:
                    if os.path.getmtime(path) > cutoff:
                        continue  # 新的临时项可能是其他实例正在使用
                    if os.path.isdir(path):
                        _shutil.rmtree(path, ignore_errors=True)
                        count += 1
                    elif os.path.isfile(path):
                        os.remove(path)
                        count += 1
                except Exception:
                    pass
            if count:
                self._append_log(f"[CLEANUP] 已清理 {count} 个旧临时文件/目录", 'success')
            else:
                self._append_log("[CLEANUP] 无旧临时文件需清理", 'info')
        except Exception as e:
            self._append_log(f"[CLEANUP] 清理失败: {e}", 'error')
    
    def _reset_ui(self):
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', 'end')
        self.log_text.configure(state='disabled')
        self.progress['value'] = 0
        self.progress['mode'] = 'indeterminate'
        self.progress.start(50)  # 降频: 10ms→50ms, 降低报告生成阶段 GIL 争抢
        self.progress_label.config(text="正在启动分析引擎...")
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self._batch_index_path = ''
        try:
            if hasattr(self, 'btn_open_batch_index'):
                self.btn_open_batch_index.pack_forget()
        except Exception:
            pass
        self.web_url_var.set('')
    
    def _stop_analysis(self):
        self.analyzing = False
        self._analysis_stop_event.set()
        self.progress.stop()
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.progress_label.config(text="已停止")
        self._append_log("[!] 分析已手动停止，正在终止沙箱进程...", 'warning')

        try:
            import psutil
            current = psutil.Process()
            cutoff = (self._analysis_start_time or 0) - 2
            for child in current.children(recursive=True):
                try:
                    # 只终止本次分析启动后出现的子进程, 避免误杀无关的
                    # pip 安装/浏览器等本进程派生的其他子进程。
                    if cutoff and child.create_time() < cutoff:
                        continue
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except psutil.Error:
                    continue
        except ImportError:
            pass
    
    def _clear_log(self):
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', 'end')
        self.log_text.configure(state='disabled')
    
    def _copy_log(self):
        self.log_text.configure(state='normal')
        text = self.log_text.get('1.0', 'end')
        self.log_text.configure(state='disabled')
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._append_log("[+] 日志已复制到剪贴板", 'success')
    
    def _find_report_path(self, scan_id, ext='.html'):
        """按 scan_id 查找报告文件: 优先新命名 <scan_id>_<sample><ext>, 再兼容旧命名"""
        out_dir = CONFIG.report.output_dir
        try:
            patterns = [
                os.path.join(out_dir, f"{scan_id}_*{ext}"),
                os.path.join(out_dir, f"report_{scan_id}_*{ext}"),
            ]
            matches = []
            for pattern in patterns:
                matches.extend(glob.glob(pattern))
            if matches:
                return max(matches, key=os.path.getmtime)
        except Exception:
            pass
        fallback = os.path.join(out_dir, f"{scan_id}{ext}")
        return fallback if os.path.isfile(fallback) else None

    def _open_html_report(self):
        if self.current_report:
            path = self._find_report_path(self.current_report.scan_id, '.html')
            if path and os.path.exists(path):
                os.startfile(os.path.abspath(path))
            else:
                messagebox.showwarning("提示", f"HTML报告未找到:\n{path}")
    
    def _open_json_report(self):
        if self.current_report:
            path = self._find_report_path(self.current_report.scan_id, '.json')
            if path and os.path.exists(path):
                os.startfile(os.path.abspath(path))
            else:
                messagebox.showwarning("提示", f"JSON报告未找到:\n{path}")
    
    def _install_all_deps(self):
        """一键安装所有缺失库 — 逐个安装，避免一个失败导致全部回滚"""
        import sys as _sys
        if getattr(_sys, 'frozen', False):
            messagebox.showinfo("提示", "打包版本不支持pip安装。\n请使用源码运行，安装依赖后重新打包。")
            return
        if not self.dep_checker:
            messagebox.showinfo("提示", "依赖检测尚未完成，请稍候")
            return
        missing = self.dep_checker.get_missing() or []
        if not missing:
            messagebox.showinfo("提示", "所有库已安装")
            return
        
        # 过滤掉已知可能有兼容性问题的库（与编译无关的兼容性问题）
        problematic = set()
        # 现在统一用 --only-binary :all: 策略，有 wheel 就装，没有就跳过
        # 不再需要手动区分"需要编译"的库
        safe_missing = [m for m in missing if m['name'] not in problematic]
        problem_missing = [m for m in missing if m['name'] in problematic]
        
        msg_lines = [f"将逐个安装 {len(safe_missing)} 个库:"]
        for m in safe_missing:
            msg_lines.append(f"  • {m['name']} — {m['description']}")
        if problem_missing:
            msg_lines.append("\n以下库已知有兼容性问题，建议手动安装:")
            for m in problem_missing:
                msg_lines.append(f"  • {m['name']} — {m['description']}")
        msg_lines.append("\n需要网络连接，可能需要几分钟。\n是否继续?")
        
        if not messagebox.askyesno("确认安装", "\n".join(msg_lines)):
            return
        
        self._append_log(f"[*] 开始逐个安装 {len(safe_missing)} 个依赖库...", 'info')
        
        # 逐个安装（在后台线程中串行执行）
        def install_all_thread():
            total = len(safe_missing)
            success_count = 0
            failed_list = []
            skipped_list = []  # 无预编译 wheel 跳过的

            for i, info in enumerate(safe_missing, 1):
                if not info['install_cmd']:
                    continue
                self.log_queue.put(f"\n[{i}/{total}] 正在安装 {info['name']}...")
                # 先尝试 --only-binary（只装预编译 wheel，避免编译失败）
                ok, need_build = self._run_pip_with_progress(
                    info['install_cmd'], single_pkg=True
                )
                if ok:
                    success_count += 1
                elif need_build:
                    # 无预编译 wheel，给明确提示
                    skipped_list.append(info['name'])
                    self.log_queue.put(f"    [pip] {info['name']} 无预编译 wheel，需 Visual C++ Build Tools 编译 → 已跳过")
                else:
                    failed_list.append(info['name'])
                import time
                time.sleep(0.5)

            # 完成总结
            summary = f"\n{'='*50}\n安装完成: {success_count}/{total} 成功"
            if skipped_list:
                summary += f"\n跳过 (无预编译 wheel): {', '.join(skipped_list)}"
            if failed_list:
                summary += f"\n失败: {', '.join(failed_list)}"
            if problem_missing:
                summary += f"\n已跳过 (已知兼容性问题): {', '.join(m['name'] for m in problem_missing)}"
            summary += f"\n{'='*50}"
            self.log_queue.put(("done_install_all", summary))

        threading.Thread(target=install_all_thread, daemon=True).start()

    def _install_single(self, cmd):
        """单独安装一个库"""
        import sys as _sys
        if getattr(_sys, 'frozen', False):
            messagebox.showinfo("提示", "打包版本不支持pip安装。\n请使用源码运行，安装依赖后重新打包。")
            return
        if messagebox.askyesno("确认安装", f"执行: {cmd}\n\n是否继续?"):
            self._append_log(f"[*] 执行: {cmd}", 'info')
            threading.Thread(target=self._run_pip_with_progress, args=(cmd, True), daemon=True).start()
    
    def _run_pip_with_progress(self, cmd, single_pkg=False):
        """后台运行 pip，优先 --only-binary 避免编译，网络失败自动重试

        Returns: (ok: bool, need_build_tools: bool)
        """
        import shlex
        # 构建基本命令 — 始终用参数列表 (避免 shell=True 命令注入)
        if cmd.startswith('pip '):
            pip_args = [sys.executable, '-m', 'pip'] + shlex.split(cmd[4:])
        else:
            pip_args = shlex.split(cmd)

        if '--user' not in pip_args:
            pip_args.append('--user')

        # 默认加 --only-binary :all: 防编译失败（只装预编译 wheel）
        if '--only-binary' not in pip_args:
            pip_args.append('--only-binary')
            pip_args.append(':all:')

        # 第一次尝试
        ok, log_lines = self._run_pip_once(list(pip_args))
        if ok:
            if single_pkg:
                self.log_queue.put(("done_install", "[+] 安装成功"))
            else:
                self.log_queue.put(("done_install", "[+] 依赖库安装完成"))
            return True, False

        # 检查是否因为 --only-binary 导致失败（无预编译 wheel）
        full = '\n'.join(log_lines)
        if '--only-binary' in full and 'No matching distribution' in full:
            return False, True  # need_build_tools

        # 检查是否是网络错误，是则自动加 --trusted-host 重试
        is_network_error = any(k in full for k in [
            'getaddrinfo failed', 'Failed to establish a new connection',
            'Connection refused', 'Name or service not known',
            'Network is unreachable', 'Connection timed out',
            'Could not fetch URL',
        ])

        if is_network_error:
            self.log_queue.put("    [pip] 网络连接失败，尝试 --trusted-host 重试…")
            retry_args = list(pip_args) + ['--trusted-host', 'pypi.org', '--trusted-host', 'files.pythonhosted.org']
            ok2, _ = self._run_pip_once(retry_args)
            if ok2:
                if single_pkg:
                    self.log_queue.put(("done_install", "[+] 安装成功（--trusted-host）"))
                else:
                    self.log_queue.put(("done_install", "[+] 依赖库安装完成"))
                return True, False

        # 两次都失败
        if single_pkg:
            err_msg = self._diagnose_pip_error(log_lines)
            self.log_queue.put(("error", err_msg))
        else:
            self.log_queue.put(("error", "[!] 安装失败"))
        return False, False

    def _run_pip_once(self, pip_args):
        """执行一次 pip 命令，返回 (是否成功, 全部日志行)

        pip_args: 参数列表 (不带 --log), 不使用 shell 避免命令注入
        """
        import subprocess
        import tempfile
        import time
        import os

        tf = tempfile.NamedTemporaryFile(prefix='pip_install_', suffix='.log', delete=False)
        log_file = tf.name
        tf.close()
        pip_cmd_list = list(pip_args) + ['--log', log_file]

        self.log_queue.put(f"    [cmd] {' '.join(pip_cmd_list)}")

        process = None
        try:
            with open(os.devnull, 'w') as devnull:
                process = subprocess.Popen(
                    pip_cmd_list, stdout=devnull, stderr=devnull
                )
        except Exception as e:
            self.log_queue.put(("error", f"[!] 无法启动 pip: {e}"))
            return False, []

        last_size = 0
        retry_count = 0
        lines_reported = 0
        all_log_lines = []

        LOG_KEYWORDS = [
            'Installing', 'Successfully', 'ERROR', 'Failed',
            'Collecting', 'Downloading', 'Requirement already',
            'Traceback', 'ModuleNotFoundError', 'error:',
            'building', 'running', 'distutils', 'setuptools',
            'pkg_resources', 'compilation', 'C extension',
        ]

        while True:
            try:
                if not os.path.exists(log_file):
                    time.sleep(0.5)
                    retry_count += 1
                    if retry_count > 30:
                        self.log_queue.put("    [pip] 日志文件未创建")
                        break
                    continue

                with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                    f.seek(last_size)
                    while True:
                        line = f.readline()
                        if not line:
                            break
                        line = line.strip()
                        if line:
                            all_log_lines.append(line)
                            if any(k in line for k in LOG_KEYWORDS):
                                self.log_queue.put(f"    [pip] {line}")
                                lines_reported += 1
                        last_size = f.tell()

                if process.poll() is not None:
                    time.sleep(0.3)
                    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                        f.seek(last_size)
                        while True:
                            line = f.readline()
                            if not line:
                                break
                            line = line.strip()
                            if line:
                                all_log_lines.append(line)
                                if any(k in line for k in LOG_KEYWORDS):
                                    self.log_queue.put(f"    [pip] {line}")
                                    lines_reported += 1
                    break

                time.sleep(0.3)
            except Exception:
                time.sleep(0.5)

        if lines_reported == 0:
            self.log_queue.put("    [pip] 未获取到日志输出")

        try:
            return_code = process.wait(timeout=300)
        except subprocess.TimeoutExpired:
            process.kill()
            return_code = -1
            self.log_queue.put(("error", "[!] 安装超时（5分钟）"))

        try:
            if os.path.exists(log_file):
                os.remove(log_file)
        except:
            pass

        return return_code == 0, all_log_lines

    def _diagnose_pip_error(self, log_lines):
        """根据 pip 日志诊断真正的失败原因"""
        import re
        full = '\n'.join(log_lines)

        # 网络错误
        if any(k in full for k in ['getaddrinfo failed', 'Name or service not known',
                                     'Failed to establish a new connection',
                                     'Connection refused', 'Network is unreachable']):
            return "[!] 安装失败：网络连接错误（无法访问 PyPI，请检查网络/代理）"

        if 'Connection timed out' in full or 'Read timed out' in full or 'connect timeout' in full:
            return "[!] 安装失败：网络超时（PyPI 连接缓慢，可尝试切换镜像源）"

        if 'Could not fetch URL' in full and 'connection error' in full.lower():
            return "[!] 安装失败：无法连接 PyPI（网络不通或需配置代理）"

        # 包不存在
        if 'No matching distribution found' in full:
            pkg_match = re.search(r'No matching distribution found for (\S+)', full)
            pkg = pkg_match.group(1) if pkg_match else '该包'
            return f"[!] 安装失败：{pkg} 在当前 Python 版本/Python 中不可用（可能不支持或拼写错误）"

        # 编译错误
        if any(k in full for k in ['error: command', 'failed with exit status',
                                     "error: Microsoft Visual C++", 'gcc failed',
                                     'compilation terminated', 'error: could not build',
                                     'Failed to build installable wheels',
                                     'building wheel', 'pyproject.toml']):
            return ("[!] 安装失败：C 扩展编译错误（缺少编译工具）。\n"
                    "    解决方法: 下载安装 Visual C++ Build Tools → https://visualstudio.microsoft.com/visual-cpp-build-tools/\n"
                    "    或直接下载预编译 wheel: pip install xxx.whl")

        if 'pkg_resources' in full and ('ModuleNotFoundError' in full or 'ImportError' in full):
            return "[!] 安装失败：缺少 pkg_resources（Python 3.13+ 中 setuptools 不再包含，需 pip install setuptools）"

        # 权限错误
        if 'Permission denied' in full or 'Access is denied' in full:
            return "[!] 安装失败：权限不足（尝试用管理员身份运行或去掉 --user 标志）"

        # 磁盘空间
        if 'No space left on device' in full or 'disk full' in full.lower():
            return "[!] 安装失败：磁盘空间不足"

        # 依赖冲突
        if 'conflicting dependencies' in full.lower() or 'ResolutionImpossible' in full:
            return "[!] 安装失败：依赖冲突（与其他已安装包版本不兼容）"

        # 默认
        return "[!] 安装失败（返回码: 1）。请检查上方 pip 日志中的具体错误信息"

    def _on_install_all_done(self, summary):
        """批量安装完成后的回调（主线程）"""
        self._append_log(summary, 'success')
        self._refresh_dep_state()

    def _refresh_dep_state(self):
        """刷新依赖检查器状态并更新 UI"""
        from utils.dep_checker import DependencyChecker
        # 重新检测依赖
        self.dep_checker = DependencyChecker()

        # 刷新分析标签页中的选项警告标记
        for key, (cb, dep_label, dep_pkg) in list(self.opt_widgets.items()):
            if dep_pkg and dep_label:
                installed = self.dep_checker.results.get(dep_pkg, {}).get('installed', False)
                if installed:
                    dep_label.config(text="✅ 已安装", fg='#10b981')
                else:
                    dep_label.config(text="⚠️ 未安装", fg='#ef4444')

        # 刷新依赖库标签页
        self._rebuild_deps_tab()

        self._append_log("[+] 依赖状态已刷新", 'info')

    def _rebuild_deps_tab(self):
        """重建依赖库标签页内容"""
        # 查找现有的 deps tab（notebook 的第2个标签页，index=1）
        notebook = None
        for child in self.root.winfo_children():
            if isinstance(child, tk.PanedWindow):
                for pane_child in child.winfo_children():
                    if isinstance(pane_child, tk.Frame):
                        for nb in pane_child.winfo_children():
                            if isinstance(nb, ttk.Notebook):
                                notebook = nb
                                break

        if notebook is None:
            return

        # 找到 "依赖库" 标签页并销毁重建
        for i in range(notebook.index('end')):
            if notebook.tab(i, 'text') == "📦 依赖库":
                tab = notebook.nametowidget(notebook.tabs()[i])
                for widget in tab.winfo_children():
                    widget.destroy()
                self._build_deps_tab_content(tab)
                break

    def _build_deps_tab_content(self, tab):
        """构建依赖库标签页的内容（不含 tab 本身）"""
        import sys as _sys
        frozen = getattr(_sys, 'frozen', False)
        
        # 顶部说明
        header = tk.Frame(tab, bg='#f0f2f5')
        header.pack(fill='x', pady=(0, 8))
        tk.Label(header, text="可选依赖库检查 — 安装后可解锁更多功能",
                font=('Segoe UI', 10), bg='#f0f2f5', fg='#6b7280').pack(side='left')

        # 一键安装按钮 (exe中不显示)
        if not frozen:
            install_cmd = self.dep_checker.get_install_all_command()
            if install_cmd:
                tk.Button(header, text="📥 一键安装缺失库", command=self._install_all_deps,
                         bg='#10b981', fg='white', font=('Segoe UI', 9), relief='flat',
                         padx=10, pady=3, cursor='hand2').pack(side='right')
        
        if frozen:
            notice = tk.Frame(tab, bg='#fef3c7', highlightbackground='#f59e0b', highlightthickness=1, bd=0)
            notice.pack(fill='x', pady=(0, 8), padx=2)
            tk.Label(notice, text="⚠ 程序运行在打包环境中，pip 不可用。\n缺失的库请手动 pip install 后重新打包。",
                    font=('Segoe UI', 9), bg='#fef3c7', fg='#92400e', justify='left').pack(padx=12, pady=6)

        # 滚动区域
        canvas = tk.Canvas(tab, bg='#f0f2f5', highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient='vertical', command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg='#f0f2f5')

        scroll_frame.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.create_window((0, 0), window=scroll_frame, anchor='nw', width=440)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # 按类别显示
        for cat_key, cat_name in self.dep_checker.CATEGORY_NAMES.items():
            cat_items = [info for info in self.dep_checker.results.values() if info['category'] == cat_key]
            if not cat_items:
                continue

            cat_frame = tk.Frame(scroll_frame, bg='white', highlightbackground='#e5e7eb',
                                highlightthickness=1, bd=0)
            cat_frame.pack(fill='x', pady=(0, 8), padx=2)

            tk.Label(cat_frame, text=cat_name, font=('Segoe UI', 11, 'bold'),
                    bg='white', fg='#374151').pack(anchor='w', padx=12, pady=(8, 4))

            for info in cat_items:
                row = tk.Frame(cat_frame, bg='white')
                row.pack(fill='x', padx=12, pady=2)

                using_alt = info.get('using_alt', False)
                if info['installed']:
                    if using_alt:
                        status = "🔄"; color = '#06b6d4'
                        ver = f"v{info['version']}" if info['version'] and info['version'] != 'unknown' else ""
                        text = f"{info['name']} {ver} (纯Python替代)"
                    else:
                        status = "✅"; color = '#10b981'
                        ver = f"v{info['version']}" if info['version'] and info['version'] != 'unknown' else ""
                        text = f"{info['name']} {ver}"
                else:
                    status = "❌"; color = '#ef4444'
                    text = info['name']

                tk.Label(row, text=status, font=('Segoe UI', 10), bg='white', fg=color).pack(side='left')
                tk.Label(row, text=text, font=('Segoe UI', 10), bg='white', fg='#374151').pack(side='left', padx=(4, 0))
                tk.Label(row, text=info['description'], font=('Segoe UI', 9),
                        bg='white', fg='#6b7280').pack(side='left', padx=(8, 0))

                if not info['installed'] and info['install_cmd']:
                    has_alt = info.get('alt_import')
                    btn_text = "安装(纯Python)" if has_alt else "安装"
                    btn_bg = '#06b6d4' if has_alt else '#f3f4f6'
                    btn_fg = 'white' if has_alt else '#374151'
                    tk.Button(row, text=btn_text, font=('Segoe UI', 8),
                                   bg=btn_bg, fg=btn_fg, relief='flat', padx=8, pady=1,
                                   command=lambda cmd=info['install_cmd']: self._install_single(cmd)).pack(side='right')

    def _center_window(self):
        self.root.update_idletasks()
        w, h = self.root.winfo_width(), self.root.winfo_height()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f'+{(sw - w) // 2}+{(sh - h) // 2}')
    
    def run(self):
        self.root.mainloop()
