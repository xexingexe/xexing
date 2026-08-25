#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Malware Analysis Platform v3.3.0
Usage: python main.py <file> [options]
       python main.py --gui
"""
import os
import sys
import time
import argparse

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import load_config, CONFIG
from logger import get_logger, LoggerManager
from version import APP_NAME, APP_VERSION


def _launch_gui(is_gui_mode: bool, logger):
    if is_gui_mode:
        logger.info("Launching GUI...")
    else:
        logger.info("No file specified, launching GUI...")
    from gui.main_window import AnalysisGUI
    app = AnalysisGUI()
    app.run()


def main():
    parser = argparse.ArgumentParser(
        description=f'{APP_NAME} v{APP_VERSION}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python main.py malware.exe
  python main.py malware.exe --dynamic
  python main.py --gui
  python main.py --config
        '''
    )
    parser.add_argument('--version', action='version', version=f'{APP_NAME} v{APP_VERSION}')
    parser.add_argument('file', nargs='?', help='File to analyze')
    parser.add_argument('--gui', action='store_true', help='Launch GUI mode')
    parser.add_argument('--dynamic', action='store_true', help='Enable dynamic analysis')
    parser.add_argument('--no-sandbox', action='store_true', help='Disable sandbox')
    parser.add_argument('--no-vm-hide', action='store_true', help='Do NOT hide VM processes before dynamic analysis')
    parser.add_argument('--no-fake-env', action='store_true',
                        help='动态分析时不创建虚假用户环境痕迹 (物理机测试建议开启, 避免写假注册表/桌面痕迹/清空剪贴板)')
    parser.add_argument('--time-accel', action='store_true', help='Enable time acceleration 1000x (Sleep/Delay compression)')
    parser.add_argument('--deep-dive', action='store_true', help='深度追踪分析 (DeepDive): 动态分析后默认自动启用; 长时观察窗随 config.deep_dive.watch_enabled')
    parser.add_argument('--no-deep-dive', action='store_true', help='禁用深度追踪分析 (覆盖 config.deep_dive.auto_enabled)')
    parser.add_argument('--allow-dangerous', action='store_true', help='ALLOW running dynamic analysis on host machine (DANGEROUS!)')
    parser.add_argument('--no-static', action='store_true', help='禁用静态分析')
    parser.add_argument('--no-threat', action='store_true', help='禁用威胁情报查询')
    parser.add_argument('--no-family', action='store_true', help='禁用木马家族分析')
    parser.add_argument('--no-advanced', action='store_true', help='禁用高级行为检测 (反VM/反沙箱/反调试)')
    parser.add_argument('--no-destruction', action='store_true', help='禁用破坏性行为检测')
    parser.add_argument('--no-memory', action='store_true', help='禁用内存分析')
    parser.add_argument('--no-yara', action='store_true', help='禁用 YARA 规则扫描')
    parser.add_argument('--enable-network', action='store_true', help='启用网络流量捕获 (默认关闭)')
    parser.add_argument('--archive-password', type=str, default=None, help='加密压缩包密码 (多个用逗号分隔)')
    parser.add_argument('--url', '--scan-url', action='append', metavar='URL', help='URL 挂马扫描: 抓取网页源码并检测挂马/命令执行/WebShell/免杀载荷 (可多次指定, 或逗号分隔)')
    parser.add_argument('--no-fetch-scripts', action='store_true', help='URL 扫描时禁用抓取外部 JS 脚本')
    parser.add_argument('--no-dynamic', action='store_true', help='URL 扫描时禁用浏览器动态行为监控 (不执行页面 JS)')
    parser.add_argument('--no-scan-discovered-urls', action='store_true',
                        help='文件分析时不自动扫描样本中发现的 URL (默认跟随 config.json 的 url_scan.scan_discovered_urls)')
    parser.add_argument('--url-timeout', type=int, default=None, help='URL 扫描请求超时(秒)')
    parser.add_argument('--url-browser', type=str, default=None,
                        help='URL 动态监控浏览器引擎, 逗号分隔: chrome,msedge,chromium,firefox,webkit 或 all (默认 chrome)')
    parser.add_argument('--url-parallel', type=int, default=None, help='URL 并行扫描并发数 (默认 3)')
    parser.add_argument('--config', type=str, help='Config file path')
    parser.add_argument('--output', '-o', type=str, default=None, help='Output directory')
    parser.add_argument('--threads', '-t', type=int, default=None, help='Number of threads')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--save-config', action='store_true', help='Save default config')
    # IoC 管理
    parser.add_argument('--add-ip', type=str, metavar='IP', help='添加自定义恶意IP (--add-tag 标签 --add-desc 描述)')
    parser.add_argument('--add-domain', type=str, metavar='DOMAIN', help='添加自定义恶意域名')
    parser.add_argument('--add-url', type=str, metavar='URL', help='添加自定义恶意URL')
    parser.add_argument('--add-tag', type=str, default='Custom', help='IoC的家族标签')
    parser.add_argument('--add-desc', type=str, default='', help='IoC的描述')
    parser.add_argument('--remove-ioc', type=str, metavar='VALUE', help='移除一个IoC (需配合 --ioc-type ip/domain/url)')
    parser.add_argument('--ioc-type', type=str, choices=['ip', 'domain', 'url'], default='ip', help='IoC类型')
    parser.add_argument('--list-iocs', action='store_true', help='列出所有自定义IoC')
    # 批量/热文件夹
    parser.add_argument('--batch', '--dir', type=str, metavar='DIR', help='批量扫描目录下所有样本')
    parser.add_argument('--watch', type=str, metavar='DIR', help='热文件夹监控: 新文件投放即自动分析 (持续运行)')

    args = parser.parse_args()

    # Load config
    load_config(args.config)

    # Override config from args
    if args.output is not None:
        CONFIG.report.output_dir = os.path.abspath(args.output)
    if args.threads is not None:
        CONFIG.threads = args.threads
    if args.no_sandbox:
        CONFIG.sandbox.enabled = False
    # 深度追踪: --deep-dive 强制启用; 默认跟随 config.deep_dive.auto_enabled; --no-deep-dive 关闭
    deep_dive_enabled = bool(args.deep_dive or (CONFIG.deep_dive.auto_enabled and not args.no_deep_dive))

    # Setup logging (once, before dependency check)
    LoggerManager().setup(
        log_level='DEBUG' if args.verbose else 'INFO',
        console_level='DEBUG' if args.verbose else 'INFO'
    )
    logger = get_logger('main')

    # === 依赖检查 (CLI 模式打印，GUI 模式由 GUI 后台执行) ===
    if not args.gui:
        from utils.dep_checker import check_and_print
        check_and_print()

    # === IoC 管理（CLI 命令）===
    if args.add_ip or args.add_domain or args.add_url or args.remove_ioc or args.list_iocs:
        from analyzer.threat_intel import ThreatIntelEngine
        engine = ThreatIntelEngine()
        if args.add_ip:
            ok = engine.add_ioc('ip', args.add_ip, args.add_tag, args.add_desc)
            print(f"[{'OK' if ok else 'FAIL'}] 添加IP: {args.add_ip}")
        if args.add_domain:
            ok = engine.add_ioc('domain', args.add_domain, args.add_tag, args.add_desc)
            print(f"[{'OK' if ok else 'FAIL'}] 添加域名: {args.add_domain}")
        if args.add_url:
            ok = engine.add_ioc('url', args.add_url, args.add_tag, args.add_desc)
            print(f"[{'OK' if ok else 'FAIL'}] 添加URL: {args.add_url}")
        if args.remove_ioc:
            ok = engine.remove_ioc(args.ioc_type, args.remove_ioc)
            print(f"[{'OK' if ok else 'FAIL'}] 移除: {args.remove_ioc}")
        if args.list_iocs:
            iocs = engine.list_custom_iocs()
            print(f"\n自定义IoC ({iocs['total']}个):")
            IOC_TYPE_MAP = {'ips': 'ip', 'domains': 'domain', 'urls': 'url'}
            for ioc_key, label in [('ips', 'IP'), ('domains', '域名'), ('urls', 'URL')]:
                items = iocs[ioc_key]
                if items:
                    print(f"\n  [{label}] ({len(items)}个):")
                    for v in items[:50]:
                        info = engine.get_ioc_info(IOC_TYPE_MAP[ioc_key], v)
                        print(f"    {v:40s} | {info.get('family', '?'):15s} | {info.get('description', '')}")
        # IoC 操作后退出，不进行分析
        if not args.file and not args.gui:
            return

    # Save default config
    if args.save_config:
        from config import save_default_config
        save_default_config('config.json')
        return

    # === URL 挂马扫描 (独立模式) ===
    if args.url:
        from analyzer.url_scanner import scan_urls
        urls = []
        for u in args.url:
            urls.extend(x.strip() for x in u.split(',') if x.strip())
        print(f"\n{'=' * 60}\n🌐 URL 挂马扫描 ({len(urls)} 个目标)\n{'=' * 60}")
        if args.url_timeout:
            from config import CONFIG as _C
            _C.url_scan.timeout = args.url_timeout
            print(f"   (请求超时: {args.url_timeout}s)")
        if args.url_browser:
            print(f"   浏览器引擎: {args.url_browser}")
        if args.url_parallel:
            print(f"   并发数: {args.url_parallel}")
        results = scan_urls(urls, fetch_external_scripts=not args.no_fetch_scripts,
                            enable_dynamic=not args.no_dynamic,
                            browser_engines=args.url_browser.split(',') if args.url_browser else None,
                            max_workers=args.url_parallel)
        from report.url_report_generator import generate_html, generate_json
        for r in results:
            print(f"\n[{'!' if r.risk_level in ('high', 'critical') else '+'}] {r.url}")
            print(f"    → {r.final_url or '连接失败'} | HTTP {r.status_code} {r.reason}")
            print(f"    IP: {', '.join(r.resolved_ips) or 'N/A'}")
            print(f"    风险: {r.risk_level.upper()} ({r.risk_score}/100)")
            print(f"    结论: {r.summary}")
            if r.dynamic_used:
                print(f"    动态监控: {r.dynamic_engine} | 请求={len(r.dynamic_requests)} 控制台={len(r.dynamic_console)} "
                      f"下载={len(r.dynamic_downloads)} DOM注入={len(r.dom_injected)}")
                for d in r.dynamic_downloads:
                    if d.get('suspicious'):
                        print(f"      [下载/危险] {d.get('filename')} ← {d.get('url', '')[:100]}")
                for f in r.dom_injected[:5]:
                    print(f"      [DOM注入/{f['severity']}] {f['evidence'][:120]}")
            if r.webshell_indicators:
                for f in r.webshell_indicators[:5]:
                    print(f"      [命令执行/{f['severity']}] {f['evidence'][:120]}")
            if r.malicious_iframes:
                for f in r.malicious_iframes[:5]:
                    print(f"      [挂马/{f['severity']}] {f['evidence'][:120]}")
            if r.obfuscated_scripts:
                for f in r.obfuscated_scripts[:5]:
                    print(f"      [混淆/{f['severity']}] {f['evidence'][:120]}")
            if r.drive_by_downloads:
                for f in r.drive_by_downloads[:5]:
                    print(f"      [免杀载荷/{f['severity']}] {f['evidence'][:120]}")
            if r.ioc_hits:
                for h in r.ioc_hits[:5]:
                    print(f"      [IoC] {h.get('family', '?')} — {h.get('description', '')[:80]}")
            html_path = os.path.join(CONFIG.report.output_dir,
                                     f'urlscan_{r.url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_").replace("?", "_")[:40]}_{int(time.time())}.html')
            generate_html(r, html_path)
            generate_json(r)
            print(f"    报告: {html_path}")
        try:
            from report.index_generator import generate_url_index
            url_index_path = generate_url_index(CONFIG.report.output_dir, results)
            print(f"URL 扫描索引: {url_index_path}")
        except Exception as _e:
            print(f"[!] URL 索引生成失败: {_e}")
        print(f"\n{'=' * 60}\nURL 扫描完成: {len(results)} 个目标")
        return

    # === 批量扫描 / 热文件夹监控 (独立模式) ===
    if args.batch or args.watch:
        from orchestrator import MalwareAnalysisPlatform
        platform = MalwareAnalysisPlatform()
        analyze_kwargs = dict(
            enable_dynamic=args.dynamic,
            allow_dangerous=args.allow_dangerous,
            no_vm_hide=args.no_vm_hide,
            enable_time_accel=args.time_accel,
            archive_passwords=args.archive_password.split(',') if args.archive_password else None,
            enable_static=not args.no_static,
            enable_threat=not args.no_threat,
            enable_family=not args.no_family,
            enable_advanced=not args.no_advanced,
            enable_destruction=not args.no_destruction,
            enable_network=args.enable_network,
            enable_memory=not args.no_memory,
            enable_yara=not args.no_yara,
            enable_deep_dive=deep_dive_enabled,
            scan_discovered_urls=not args.no_scan_discovered_urls,
            fake_user_env=not args.no_fake_env,
        )
        if args.batch:
            from analyzer.batch import scan_directory
            results = scan_directory(platform, args.batch, **analyze_kwargs)
            try:
                from report.index_generator import generate_batch_index
                batch_index_path = generate_batch_index(CONFIG.report.output_dir, results)
                print(f"批量扫描索引: {batch_index_path}")
            except Exception as _e:
                print(f"[!] 批量索引生成失败: {_e}")
            print(f"\n{'=' * 60}\n批量扫描完成: {len(results)} 个文件\n{'=' * 60}")
            for f, r in results:
                base = os.path.basename(f)
                if r:
                    mark = '!' if r.risk_level in ('high', 'critical') else '+'
                    print(f"  [{mark}] {base}: {r.risk_level.upper()} ({r.risk_score}/100)"
                          f"{' | ' + r.malware_family.primary_family if r.malware_family and r.malware_family.primary_family else ''}")
                else:
                    print(f"  [-] {base}: 分析失败")
            return
        else:
            from analyzer.batch import watch_directory
            watch_directory(platform, args.watch, **analyze_kwargs)
            return

    # GUI mode
    if args.gui or not args.file:
        _launch_gui(args.gui, logger)
        return

    # Command line mode
    file_path = args.file
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        sys.exit(1)

    platform = None
    try:
        # 懒加载: GUI/CLI 启动不解析重型模块树 (orchestrator → analyzer 全量), 加快启动
        from orchestrator import MalwareAnalysisPlatform
        platform = MalwareAnalysisPlatform()
        report = platform.analyze(
            file_path,
            enable_dynamic=args.dynamic,
            allow_dangerous=args.allow_dangerous,
            no_vm_hide=args.no_vm_hide,
            enable_time_accel=args.time_accel,
            archive_passwords=args.archive_password.split(',') if args.archive_password else None,
            enable_static=not args.no_static,
            enable_threat=not args.no_threat,
            enable_family=not args.no_family,
            enable_advanced=not args.no_advanced,
            enable_destruction=not args.no_destruction,
            enable_network=args.enable_network,
            enable_memory=not args.no_memory,
            enable_yara=not args.no_yara,
            enable_deep_dive=deep_dive_enabled,
            scan_discovered_urls=not args.no_scan_discovered_urls,
            fake_user_env=not args.no_fake_env
        )
        print(f"\nAnalysis complete: {report.scan_id}")
        print(f"Risk: {report.risk_level.upper()} ({report.risk_score}/100)")
        if report.malware_family:
            print(f"Family: {report.malware_family.primary_family}")
        print(f"Reports saved to: {CONFIG.report.output_dir}")
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
