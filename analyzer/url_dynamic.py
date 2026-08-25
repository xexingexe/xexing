#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URL 动态行为监控沙箱 — 用真实浏览器(系统 Chrome) 执行目标网页, 捕获全部行为:
  - 网络请求 (URL/方法/类型/状态/大小) — 含 JS 动态发起的请求
  - 控制台消息 / 页面错误
  - 弹窗 (alert/confirm/prompt) 自动关闭
  - 下载文件 (保存到临时目录, 计算哈希)
  - 弹窗页面 (popup) 捕获 URL 后关闭
  - 执行后的 DOM 快照 → 静态检测器复扫 (JS 注入的 iframe/脚本无处遁形)
  - 截图
  - 行为时间线
浏览器进程用 Windows Job Object 约束 (内存限制/超时强杀/进程数上限), 无头模式执行。
依赖: playwright + 系统 Chrome (或 playwright 自带内核)。不可用时降级为 requests 深爬。
"""
import os
import re
import time
import json
import shutil
import hashlib
import tempfile
import traceback
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin

from logger import get_logger
from config import CONFIG

logger = get_logger('analyzer.url_dynamic')

PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# ================= Windows Job Object 加固 =================

def _harden_browser_job(pid: int, memory_limit_mb: int = 0, timeout_sec: int = 60,
                        max_processes: int = 40) -> Optional[int]:
    """把浏览器进程放入 Job Object: KILL_ON_CLOSE + 进程数限制 + 内存限制 + 时限
    返回 job handle (整数), 失败返回 None (不阻塞动态分析)"""
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x8
        JOB_OBJECT_LIMIT_JOB_TIME = 0x4
        JOB_OBJECT_LIMIT_JOB_MEMORY = 0x200

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        INFINITE = 0xffffffff

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [('PerProcessUserTimeLimit', ctypes.c_longlong),
                        ('PerJobUserTimeLimit', ctypes.c_longlong),
                        ('LimitFlags', wintypes.DWORD),
                        ('MinimumWorkingSetSize', ctypes.c_size_t),
                        ('MaximumWorkingSetSize', ctypes.c_size_t),
                        ('ActiveProcessLimit', wintypes.DWORD),
                        ('Affinity', ctypes.POINTER(ctypes.c_ulong)),
                        ('PriorityClass', wintypes.DWORD),
                        ('SchedulingClass', wintypes.DWORD)]

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [('ReadOperationCount', ctypes.c_ulonglong),
                        ('WriteOperationCount', ctypes.c_ulonglong),
                        ('OtherOperationCount', ctypes.c_ulonglong),
                        ('ReadTransferCount', ctypes.c_ulonglong),
                        ('WriteTransferCount', ctypes.c_ulonglong),
                        ('OtherTransferCount', ctypes.c_ulonglong)]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION),
                        ('IoInfo', IO_COUNTERS),
                        ('ProcessMemoryLimit', ctypes.c_size_t),
                        ('JobMemoryLimit', ctypes.c_size_t),
                        ('PeakProcessMemoryUsed', ctypes.c_size_t),
                        ('PeakJobMemoryUsed', ctypes.c_size_t)]

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        info.BasicLimitInformation.ActiveProcessLimit = max_processes
        if memory_limit_mb > 0:
            flags |= JOB_OBJECT_LIMIT_JOB_MEMORY
            info.JobMemoryLimit = memory_limit_mb * 1024 * 1024
        if timeout_sec > 0:
            flags |= JOB_OBJECT_LIMIT_JOB_TIME
            info.BasicLimitInformation.PerJobUserTimeLimit = timeout_sec * 10000000
        info.BasicLimitInformation.LimitFlags = flags

        kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))
        if not kernel32.AssignProcessToJobObject(job, ctypes.c_void_p(int(pid))):
            kernel32.CloseHandle(job)
            return None
        return int(job)
    except Exception as e:
        logger.debug(f"[JobObject] 浏览器加固失败: {e}")
        return None


class URLDynamicMonitor:
    """URL 行为监控 — 浏览器沙箱 (支持多浏览器引擎)"""

    # 支持的引擎: chrome/msedge 用系统浏览器, 其余需 playwright 内核
    ENGINE_LABELS = {
        'chrome': 'Chrome(系统)',
        'msedge': 'Edge(系统)',
        'chromium': 'Chromium(内核)',
        'firefox': 'Firefox(内核)',
        'webkit': 'WebKit(内核)',
    }
    SYSTEM_ENGINES = ('chrome', 'msedge')

    def __init__(self, timeout: int = None, wait_after_load: int = None,
                 max_resources: int = None, headless: bool = None,
                 use_system_chrome: bool = None, max_download_size: int = None,
                 capture_screenshots: bool = None, engine: str = None):
        cfg = CONFIG.url_scan
        self.timeout = timeout or getattr(cfg, 'dynamic_timeout', 25)
        self.wait = wait_after_load if wait_after_load is not None else getattr(cfg, 'dynamic_wait', 4)
        self.max_resources = max_resources or getattr(cfg, 'max_resources', 40)
        self.headless = getattr(cfg, 'headless', True) if headless is None else headless
        self.use_system_chrome = getattr(cfg, 'use_system_chrome', True) if use_system_chrome is None else use_system_chrome
        self.max_dl = max_download_size or getattr(cfg, 'max_download_size', 20 * 1024 * 1024)
        self.capture_shot = getattr(cfg, 'capture_screenshots', True) if capture_screenshots is None else capture_screenshots
        self.mem_limit = getattr(cfg, 'job_memory_limit_mb', 1024) or 0
        self.engine = (engine or 'chrome').lower()
        self._tmp_dir = None
        self._tmp_dirs = []  # 每个引擎的临时目录 — cleanup 全部清理, 防恶意文件残留
        self._job = None
        self._engine = 'none'

    # ---------- 浏览器进程 ----------

    @staticmethod
    def parse_engines(engines) -> List[str]:
        """解析引擎配置: 'all' → 系统引擎全部; 逗号分隔列表; 非法值忽略"""
        if isinstance(engines, (list, tuple)):
            raw = list(engines)
        else:
            raw = [e.strip() for e in str(engines or 'chrome').split(',') if e.strip()]
        out = []
        for e in raw:
            e = e.lower().strip()
            if e == 'all':
                out = list(URLDynamicMonitor.SYSTEM_ENGINES)
                continue
            if e in URLDynamicMonitor.ENGINE_LABELS and e not in out:
                out.append(e)
        return out or ['chrome']

    def _launch_browser(self):
        """按 self.engine 启动对应浏览器, 返回 (browser, playwright_ctx)。失败返回 (None, None)"""
        if not PLAYWRIGHT_AVAILABLE:
            return None, None
        pw = None
        try:
            pw = sync_playwright().start()
        except Exception as e:
            logger.warning(f"[URLDynamic] playwright 启动失败: {e}")
            return None, None
        launch_kwargs = {'headless': self.headless}
        browser = None
        last_err = ''
        try:
            if self.engine == 'chrome':
                browser = pw.chromium.launch(channel='chrome', **launch_kwargs)
            elif self.engine == 'msedge':
                browser = pw.chromium.launch(channel='msedge', **launch_kwargs)
            elif self.engine == 'firefox':
                browser = pw.firefox.launch(**launch_kwargs)
            elif self.engine == 'webkit':
                browser = pw.webkit.launch(**launch_kwargs)
            else:  # chromium / 默认
                browser = pw.chromium.launch(**launch_kwargs)
            self._engine = f'playwright({self.engine})'
            return browser, pw
        except Exception as e:
            last_err = str(e)[:200]
            try:
                pw.stop()
            except Exception:
                pass
        logger.warning(f"[URLDynamic] 浏览器 {self.engine} 启动失败: {last_err}")
        return None, None

    def _attach_job(self, browser):
        """把浏览器主进程放入 Job Object"""
        try:
            proc = getattr(browser, 'process', None)
            if proc is None:
                return
            pid = getattr(proc, 'pid', 0)
            if pid:
                self._job = _harden_browser_job(pid, memory_limit_mb=self.mem_limit,
                                                timeout_sec=self.timeout + self.wait + 10)
                if self._job:
                    logger.info(f"[URLDynamic] 浏览器已入 Job Object (PID={pid}, 内存≤{self.mem_limit}MB)")
        except Exception as e:
            logger.debug(f"[URLDynamic] Job 挂载失败: {e}")

    # ---------- 主入口 ----------

    def monitor(self, url: str, engine: str = None, scanner=None, stop_event=None) -> Dict:
        """监控目标 URL 的全部浏览器行为。
        engine: 覆盖实例引擎 (chrome/msedge/chromium/firefox/webkit)
        scanner: URLScanner 实例 (复用静态检测器分析 DOM 和 JS 资源)
        返回结果字典:
          {engine, error, final_url, events, requests, console, downloads,
           screenshots, resources, dom_injected, dom_html, redirects}
        """
        if engine:
            self.engine = engine.lower()
        result = {'engine': self.engine, 'error': '', 'final_url': url,
                  'events': [], 'requests': [], 'console': [], 'downloads': [],
                  'screenshots': [], 'resources': [], 'dom_injected': [], 'dom_html': '',
                  'redirects': [], 'cookies': []}
        start = time.time()

        if not PLAYWRIGHT_AVAILABLE:
            result['engine'] = 'requests-crawl'
            result['error'] = 'playwright 未安装, 使用 requests 深度爬取'
            self._crawl_fallback(url, scanner, result, stop_event)
            return result

        browser, pw = self._launch_browser()
        if browser is None:
            result['engine'] = 'requests-crawl'
            result['error'] = '浏览器启动失败, 使用 requests 深度爬取'
            self._crawl_fallback(url, scanner, result, stop_event)
            return result
        result['engine'] = self._engine

        self._tmp_dir = tempfile.mkdtemp(prefix='urlsandbox_')
        self._tmp_dirs.append(self._tmp_dir)
        try:
            self._attach_job(browser)
            context = browser.new_context(
                viewport={'width': 1280, 'height': 800},
                user_agent=getattr(CONFIG.url_scan, 'user_agent', 'Mozilla/5.0'),
                locale='zh-CN',
                ignore_https_errors=getattr(CONFIG.url_scan, 'ignore_https_errors', True),
                accept_downloads=True,
            )
            page = context.new_page()

            # ===== 事件捕获 =====
            ev = result['events']
            reqs = result['requests']
            seen_reqs = {}

            def _ev(type_, detail):
                ev.append({'t': round(time.time() - start, 2), 'type': type_, 'detail': detail[:400]})

            def _on_request(r):
                try:
                    rurl = r.url
                    key = rurl
                    seen_reqs[key] = {'url': rurl, 'method': r.method, 'type': r.resource_type,
                                      'status': 0, 'size': 0, 'headers': {}}
                    if len(reqs) < 500:
                        reqs.append(seen_reqs[key])
                except Exception:
                    pass

            def _on_response(r):
                try:
                    if r.url in seen_reqs:
                        seen_reqs[r.url]['status'] = r.status
                        try:
                            seen_reqs[r.url]['size'] = len(r.body())
                        except Exception:
                            pass
                except Exception:
                    pass

            def _on_console(msg):
                try:
                    m = {'level': msg.type, 'text': msg.text[:300]}
                    result['console'].append(m)
                    if len(result['console']) <= 200:
                        _ev('console', f"[{msg.type}] {msg.text[:200]}")
                except Exception:
                    pass

            def _on_pageerror(exc):
                try:
                    _ev('page_error', str(exc)[:200])
                except Exception:
                    pass

            def _on_dialog(dlg):
                try:
                    msg = dlg.message[:150]
                    _ev('dialog', f"{dlg.type}: {msg}")
                    try:
                        dlg.dismiss()
                    except Exception:
                        pass
                except Exception:
                    pass

            def _on_download(dl):
                try:
                    # 只取纯文件名, 拒绝路径分隔符/.. 防止写出临时目录
                    _suggested = dl.suggested_filename or f'dl_{int(time.time()*1000)}'
                    fn = os.path.basename(_suggested.replace('\\', '/'))
                    if fn in ('', '.', '..'):
                        fn = f'dl_{int(time.time()*1000)}'
                    dest = os.path.join(self._tmp_dir, fn)
                    info = {'url': dl.url, 'filename': fn, 'path': ''}
                    # 流式限量落盘: 旧实现 save_as 先写完整文件再检查大小, 可被超大文件撑爆磁盘
                    if hasattr(dl, 'create_read_stream'):
                        try:
                            with dl.create_read_stream() as src, open(dest, 'wb') as out:
                                total = 0
                                too_big = False
                                while True:
                                    blk = src.read(1 << 16)
                                    if not blk:
                                        break
                                    total += len(blk)
                                    if self.max_dl and total > self.max_dl:
                                        too_big = True
                                        break
                                    out.write(blk)
                            if too_big:
                                os.remove(dest)
                                info['size'] = total
                                info['error'] = f'下载超过上限 {self.max_dl} 字节, 已丢弃'
                                result['downloads'].append(info)
                                _ev('download_error', info['error'])
                                return
                            info['path'] = dest
                            info['size'] = os.path.getsize(dest)
                        except Exception as e:
                            info['error'] = str(e)[:150]
                    else:
                        try:
                            dl.save_as(dest)
                            size = os.path.getsize(dest)
                            if self.max_dl and size > self.max_dl:
                                os.remove(dest)
                                info['size'] = size
                                info['error'] = f'下载超过上限 {self.max_dl} 字节, 已丢弃'
                                result['downloads'].append(info)
                                _ev('download_error', info['error'])
                                return
                            info['path'] = dest
                            info['size'] = size
                        except Exception as e:
                            info['error'] = str(e)[:150]
                    if info.get('path') and os.path.isfile(info['path']):
                        with open(info['path'], 'rb') as f:
                            info['sha256'] = hashlib.sha256(f.read()).hexdigest()
                    result['downloads'].append(info)
                    _ev('download', f"{fn} ← {dl.url[:150]}")
                except Exception as e:
                    _ev('download_error', str(e)[:150])

            def _on_popup(p):
                try:
                    try:
                        p.wait_for_load_state('domcontentloaded', timeout=5000)
                    except Exception:
                        pass
                    try:
                        u = p.url
                    except Exception:
                        u = '(unknown)'
                    _ev('popup', f"弹窗页面: {u}")
                    try:
                        p.close()
                    except Exception:
                        pass
                except Exception:
                    pass

            page.on('request', _on_request)
            page.on('response', _on_response)
            page.on('console', _on_console)
            page.on('pageerror', _on_pageerror)
            page.on('dialog', _on_dialog)
            page.on('download', _on_download)
            page.on('popup', _on_popup)

            # ===== 导航 =====
            _ev('navigate', url)
            try:
                page.goto(url, timeout=self.timeout * 1000, wait_until='domcontentloaded')
            except Exception as e:
                _ev('load_error', str(e)[:150])
            # 等页面稳定
            try:
                page.wait_for_timeout(self.wait * 1000)
            except Exception:
                pass
            # 长轮询页等待静默
            try:
                page.wait_for_load_state('networkidle', timeout=min(self.timeout, 8) * 1000)
            except Exception:
                pass

            # 最终 URL / 跳转链
            try:
                result['final_url'] = page.url
            except Exception:
                pass
            try:
                result['redirects'] = list(getattr(page, 'history', []) or [])
            except Exception:
                pass

            # DOM 快照
            try:
                result['dom_html'] = page.content()[:500000]
            except Exception:
                pass

            # cookies / localStorage
            try:
                for c in context.cookies():
                    result['cookies'].append({'name': c.get('name'), 'domain': c.get('domain'),
                                              'httpOnly': c.get('httpOnly')})
            except Exception:
                pass

            # 截图
            if self.capture_shot:
                try:
                    out_dir = getattr(CONFIG, 'screenshots', None)
                    shot_dir = getattr(out_dir, 'dir', 'screenshots') if out_dir else 'screenshots'
                    os.makedirs(shot_dir, exist_ok=True)
                    host = re.sub(r'[<>:"/\\|?*]', '_', urlparse(url).netloc)[:30]
                    shot = os.path.join(shot_dir, f'urlshot_{self.engine}_{host}_{int(time.time())}.png')
                    page.screenshot(path=shot, full_page=False)
                    result['screenshots'].append(shot)
                except Exception as e:
                    logger.debug(f"[URLDynamic] 截图失败: {e}")

            # ===== 资源分析 (执行后的 DOM + 抓到的 JS/HTML) =====
            if scanner is not None:
                try:
                    dom = result['dom_html']
                    if dom:
                        finds = []
                        for det in ('_detect_hijack', '_detect_obfuscation', '_detect_driveby',
                                    '_detect_clickfix', '_detect_data_theft', '_detect_cryptominer',
                                    '_detect_websocket_c2', '_detect_phishing', '_detect_command_output',
                                    '_detect_php8_webshell'):
                            try:
                                fn = getattr(scanner, det, None)
                                if fn:
                                    if det == '_detect_hijack':
                                        finds += fn(dom, result['final_url'], urlparse(result['final_url']).netloc.split(':')[0] or '')
                                    elif det == '_detect_phishing':
                                        finds += fn(dom, result['final_url'], urlparse(result['final_url']).netloc.split(':')[0] or '')
                                    else:
                                        finds += fn(dom)
                            except Exception:
                                pass
                        result['dom_injected'] = scanner._dedup(finds)[:40]
                        for f in result['dom_injected']:
                            f['source'] = 'dom'
                            _ev('dom_suspicious', f"[{f['severity']}] {f['evidence'][:150]}")
                except Exception:
                    pass
                # JS/HTML 资源响应体分析
                try:
                    n = 0
                    for r in list(result['requests'])[:200]:
                        if n >= self.max_resources:
                            break
                        rtype = r.get('type', '')
                        if rtype not in ('script', 'document', 'xhr', 'fetch'):
                            continue
                        rurl = r.get('url', '')
                        if not rurl or rurl == result['final_url'] or rurl.startswith('data:'):
                            continue
                        try:
                            resp = page.request.get(rurl, timeout=5000,
                                                    headers={'User-Agent': getattr(CONFIG.url_scan, 'user_agent', 'Mozilla/5.0')})
                        except Exception:
                            continue
                        if resp is None:
                            continue
                        try:
                            body = resp.body()
                        except Exception:
                            continue
                        if len(body) > 10 * 1024 * 1024:
                            continue
                        text = body.decode('utf-8', errors='replace')
                        res_findings = []
                        for det in ('_detect_obfuscation', '_detect_driveby', '_detect_clickfix',
                                    '_detect_data_theft', '_detect_cryptominer', '_detect_websocket_c2',
                                    '_detect_php8_webshell'):
                            try:
                                fn = getattr(scanner, det, None)
                                if fn:
                                    res_findings += fn(text)
                            except Exception:
                                pass
                        res_findings = scanner._dedup(res_findings)
                        if res_findings:
                            result['resources'].append({'url': rurl, 'type': rtype,
                                                         'size': len(body), 'findings': res_findings})
                            for f in res_findings[:3]:
                                _ev('resource_suspicious', f"[{f['severity']}] {rurl[:100]} — {f['evidence'][:120]}")
                            n += 1
                except Exception:
                    pass

            _ev('done', f"总请求 {len(result['requests'])} 个, 下载 {len(result['downloads'])} 个")
            logger.info(f"[URLDynamic] 监控完成: {len(result['requests'])} 请求, "
                        f"{len(result['console'])} 控制台, {len(result['downloads'])} 下载, "
                        f"{len(result['dom_injected'])} DOM注入, {time.time()-start:.1f}s")
        except Exception as e:
            logger.error(f"[URLDynamic] 监控异常: {e}")
            result['error'] = str(e)[:300]
        finally:
            try:
                browser.close()
            except Exception:
                pass
            try:
                pw.stop()
            except Exception:
                pass
            if self._job:
                try:
                    import ctypes
                    ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(self._job))
                except Exception:
                    pass
                self._job = None

        # 下载文件分析: 哈希/扩展名/YARA
        self._analyze_downloads(result, scanner)
        return result

    def _analyze_downloads(self, result: Dict, scanner=None):
        """下载文件: 标记可疑 + 尝试 YARA"""
        from analyzer.threat_intel import ThreatIntelEngine
        ti = ThreatIntelEngine() if scanner is None else None
        for d in result.get('downloads', []):
            fn = (d.get('filename') or '').lower()
            url = (d.get('url') or '').lower()
            susp = False
            reasons = []
            if any(fn.endswith(e) for e in ('.exe', '.msi', '.scr', '.pif', '.bat', '.cmd', '.vbs', '.hta', '.jar', '.dll')):
                susp, reasons = True, ['可执行文件下载']
            elif '.zip' in fn and ('track=' in url or 'update' in url or 'crack' in url or 'keygen' in url):
                susp, reasons = True, ['可疑压缩包下载 (update/track 参数)']
            elif any(k in url for k in ('track=', 'update', 'download')):
                susp, reasons = True, ['更新/下载参数']
            d['suspicious'] = susp
            d['reasons'] = reasons
            # YARA 扫描小文件
            try:
                if d.get('path') and os.path.isfile(d['path']) and d.get('size', 0) < 50 * 1024 * 1024:
                    from analyzer.yara_scanner import YARAScanner
                    from utils.helpers import resource_path
                    ys = YARAScanner(rules_dir=resource_path('rules/yara'))
                    hits = ys.scan_file(d['path'])
                    if hits:
                        d['yara'] = [h.get('rule', '') for h in hits[:5]]
                        d['suspicious'] = True
                        d['reasons'] = (d.get('reasons') or []) + ['YARA命中']
            except Exception:
                pass

    # ---------- 多引擎监控 ----------

    def monitor_all(self, url: str, engines: List[str] = None, scanner=None,
                    stop_event=None) -> Dict:
        """用多个浏览器引擎分别监控同一 URL, 合并结果。
        返回与 monitor() 相同结构的结果字典, 事件/请求/下载带 engine 标记。
        """
        engines = self.parse_engines(engines)
        merged = {'engine': '+'.join(engines), 'error': '', 'final_url': url,
                  'events': [], 'requests': [], 'console': [], 'downloads': [],
                  'screenshots': [], 'resources': [], 'dom_injected': [], 'dom_html': '',
                  'redirects': [], 'cookies': [], 'engine_results': []}
        if len(engines) == 1:
            merged.update(self.monitor(url, engine=engines[0], scanner=scanner,
                                       stop_event=stop_event))
            merged['engine_results'] = [{'engine': engines[0], 'ok': not merged.get('error')}]
            return merged

        for eng in engines:
            if stop_event is not None and stop_event.is_set():
                break
            logger.info(f"[URLDynamic] 引擎 [{eng}] 监控 {url} ...")
            try:
                r = self.monitor(url, engine=eng, scanner=scanner, stop_event=stop_event)
            except Exception as e:
                logger.warning(f"[URLDynamic] 引擎 [{eng}] 异常: {e}")
                continue
            merged['engine_results'].append({'engine': eng, 'ok': not r.get('error'),
                                             'error': r.get('error', '')})
            if r.get('final_url') and r['final_url'] != url:
                merged['final_url'] = r['final_url']
            for e_ in r.get('events', []):
                e_ = dict(e_)
                e_['engine'] = eng
                merged['events'].append(e_)
            for q in r.get('requests', []):
                q = dict(q)
                q['engine'] = eng
                merged['requests'].append(q)
            for m in r.get('console', []):
                m = dict(m)
                m['engine'] = eng
                merged['console'].append(m)
            for d in r.get('downloads', []):
                d = dict(d)
                d['engine'] = eng
                merged['downloads'].append(d)
            for s in r.get('screenshots', []):
                merged['screenshots'].append(s)
            for res in r.get('resources', []):
                res = dict(res)
                res['engine'] = eng
                merged['resources'].append(res)
            for f in r.get('dom_injected', []):
                f = dict(f)
                f['engine'] = eng
                merged['dom_injected'].append(f)
            if r.get('dom_html'):
                merged['dom_html'] = r['dom_html']
            if not merged['error'] and r.get('error'):
                merged['error'] = r['error']
        # DOM 注入去重 (跨引擎)
        seen, dedup = set(), []
        for f in merged['dom_injected']:
            key = (f.get('type', ''), f.get('evidence', '')[:100])
            if key in seen:
                continue
            seen.add(key)
            dedup.append(f)
        merged['dom_injected'] = dedup[:60]
        merged['requests'] = merged['requests'][:800]
        merged['events'] = merged['events'][:500]
        logger.info(f"[URLDynamic] 多引擎完成: {'+'.join(engines)} → "
                    f"{len(merged['requests'])}请求 {len(merged['dom_injected'])}DOM注入 "
                    f"{len(merged['downloads'])}下载")
        return merged

    # ---------- 降级: requests 深爬 ----------

    def _crawl_fallback(self, url: str, scanner, result: Dict, stop_event=None):
        """无浏览器时: 深度爬取页面引用的全部资源 (脚本/iframe/表单/图片/链接) 并静态分析"""
        import requests as _req
        try:
            headers = {'User-Agent': getattr(CONFIG.url_scan, 'user_agent', 'Mozilla/5.0')}
            seen = set()
            queue = [(url, 0)]
            n = 0
            start = time.time()
            while queue and n < self.max_resources and (time.time() - start) < self.timeout:
                if stop_event is not None and stop_event.is_set():
                    break
                u, depth = queue.pop(0)
                if u in seen or u.startswith('data:'):
                    continue
                seen.add(u)
                try:
                    r = _req.get(u, headers=headers, timeout=8, verify=False,
                                 allow_redirects=True)
                    body = r.content[:5 * 1024 * 1024]
                    text = body.decode('utf-8', errors='replace')
                except Exception as e:
                    result['requests'].append({'url': u, 'status': 0, 'error': str(e)[:100]})
                    continue
                result['requests'].append({'url': u, 'method': 'GET', 'type': 'resource',
                                           'status': r.status_code, 'size': len(body)})
                if depth > 2:
                    continue
                if scanner is not None:
                    finds = []
                    if 'text/html' in r.headers.get('Content-Type', '') or depth == 0:
                        finds += scanner._detect_hijack(text, u, urlparse(u).netloc.split(':')[0] or '')
                    for det in ('_detect_obfuscation', '_detect_driveby', '_detect_clickfix',
                                '_detect_data_theft', '_detect_cryptominer', '_detect_websocket_c2',
                                '_detect_php8_webshell'):
                        try:
                            finds += getattr(scanner, det)(text)
                        except Exception:
                            pass
                    finds = scanner._dedup(finds)
                    if finds:
                        result['resources'].append({'url': u, 'type': 'html' if depth == 0 else 'resource',
                                                     'size': len(body), 'findings': finds})
                        n += 1
                # 收集下一层资源
                for m in re.finditer(r'(?is)(?:src|href)\s*=\s*["\']([^"\']+)["\']', text):
                    nxt = m.group(1)
                    if nxt.startswith('//'):
                        nxt = 'http:' + nxt
                    elif not nxt.startswith('http'):
                        nxt = urljoin(url, nxt)
                    if nxt.startswith(('http://', 'https://')):
                        queue.append((nxt, depth + 1))
                result['events'].append({'t': round(time.time() - start, 2),
                                         'type': 'crawl', 'detail': f'爬取 {u}'})
        except Exception as e:
            result['error'] = str(e)[:200]

    # ---------- 清理 ----------

    def cleanup(self):
        """删除所有引擎的临时下载目录 (防恶意文件残留)"""
        for d in self._tmp_dirs:
            try:
                if d and os.path.isdir(d):
                    shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass
        self._tmp_dirs.clear()
        self._tmp_dir = None
