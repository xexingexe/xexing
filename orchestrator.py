#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Malware Analysis Platform — Main orchestrator
"""
import os
import shutil
import tempfile
import hashlib
import time
import logging
import re
import threading
import zipfile
from datetime import datetime
from typing import Dict

from logger import get_logger
from config import CONFIG
from utils.helpers import format_size, is_pe_file_path, resource_path
from analyzer.models import AnalysisReport, NetworkTraffic
from analyzer.static import StaticAnalyzer
from analyzer.pe import PEAnalyzer
from analyzer.strings import StringAnalyzer
from analyzer.archive import ArchiveAnalyzer
from analyzer.script import ScriptAnalyzer
from analyzer.msi import MSIAnalyzer
from analyzer.dynamic import DynamicAnalyzer
from analyzer.network import NetworkAnalyzer
from analyzer.memory import MemoryAnalyzer
from analyzer.api_monitor import APIMonitor
from analyzer.destruction import DestructionDetector
from analyzer.family import FamilyAnalyzer
from analyzer.dropped_files import DroppedFileTracker
from analyzer.advanced_behavior import AdvancedBehaviorDetector
from analyzer.threat_intel import ThreatIntelEngine
from analyzer.sub_files import SubFileAnalyzer
from analyzer.vm_detector import VMDetector
from analyzer.deobfuscator import Deobfuscator
from analyzer.sandbox_monitor import SandboxEnhancer
from analyzer.disk_forensics import DiskForensics
from report.html_generator import HTMLReportGenerator
from report.json_generator import JSONReportGenerator
from report.pdf_generator import PDFReportGenerator

logger = get_logger('platform')

# 根 logger handler 管理锁 — 并行静态批量分析时避免 addHandler/removeHandler 互相破坏
_ROOT_LOG_LOCK = threading.Lock()
# 报告保留策略清理锁 — 并行批量分析时避免多线程同时按保留数清理报告
_PRUNE_LOCK = threading.Lock()


class MalwareAnalysisPlatform:
    """恶意文件分析平台主类"""
    
    def __init__(self):
        self.static_analyzer = StaticAnalyzer
        self.pe_analyzer = PEAnalyzer
        self.string_analyzer = StringAnalyzer
        self.archive_analyzer = ArchiveAnalyzer()
        self.script_analyzer = ScriptAnalyzer()
        self.msi_analyzer = MSIAnalyzer()
        self.dynamic_analyzer = DynamicAnalyzer
        self.network_analyzer = NetworkAnalyzer
        self.memory_analyzer = MemoryAnalyzer()
        self.api_monitor = APIMonitor()
        self.destruction_detector = DestructionDetector()
        self.family_analyzer = FamilyAnalyzer()
        self.dropped_tracker = DroppedFileTracker()
        self.advanced_detector = AdvancedBehaviorDetector()
        self.threat_intel = ThreatIntelEngine()
        self.sub_file_analyzer = SubFileAnalyzer
        self.html_generator = HTMLReportGenerator()
        self.json_generator = JSONReportGenerator()
        self.pdf_generator = PDFReportGenerator()
    
    def analyze(self, file_path: str, enable_dynamic: bool = False, allow_dangerous: bool = False, no_vm_hide: bool = False, enable_time_accel: bool = False, web_state=None, archive_passwords: list = None,
                enable_static: bool = True, enable_threat: bool = True, enable_family: bool = True,
                enable_advanced: bool = True, enable_destruction: bool = True, enable_network: bool = True,
                enable_memory: bool = True, enable_deep_dive: bool = False, enable_deep_dive_watch: bool = True,
                enable_cleanup: bool = False,
                urls_to_scan: list = None, scan_discovered_urls: bool = None,
                stop_event: threading.Event = None,
                enable_yara: bool = True, save_reports: bool = True,
                fake_user_env: bool = True) -> AnalysisReport:
        """执行完整分析
        
        Args:
            file_path: 样本文件路径
            enable_dynamic: 是否开启动态分析
            allow_dangerous: 是否允许在宿主机上执行动态分析（危险！）
            no_vm_hide: 是否禁用VM进程隐藏（默认自动隐藏）
        """
        logger.info(f"[DEBUG] enable_memory={enable_memory} enable_dynamic={enable_dynamic}")
        start_time = time.time()
        try:
            with open(file_path, 'rb') as f:
                content_hash = hashlib.md5(f.read(65536)).hexdigest()[:8]
        except Exception:
            content_hash = hashlib.md5(file_path.encode()).hexdigest()[:8]
        scan_id = f"SCAN-{int(time.time())}-{content_hash}"
        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        logger.info(f"\n{'='*60}")
        logger.info(f"🔍 Starting analysis: {file_path}")
        logger.info(f"{'='*60}\n")
        
        report = AnalysisReport(scan_id=scan_id, scan_time=scan_time)

        # Web 流式报告: 设置半成品落盘路径 (崩溃/重启后可从该文件恢复)
        if web_state:
            try:
                progress_path = os.path.join(CONFIG.report.output_dir, f"{scan_id}.progress.html")
                web_state.set_progress_file(progress_path)
            except Exception:
                pass

        # 设置日志收集到临时文件，供报告查看
        import tempfile as _tmp
        _log_file = os.path.join(_tmp.gettempdir(), f"sandbox_log_{scan_id}.txt")
        _log_handler = None
        with _ROOT_LOG_LOCK:
            try:
                _log_handler = logging.FileHandler(_log_file, encoding='utf-8')
                _log_handler.setLevel(logging.DEBUG)
                _log_handler.setFormatter(logging.Formatter('%(asctime)s [%(name)s] %(levelname)s: %(message)s'))
                logging.getLogger().addHandler(_log_handler)
            except Exception:
                _log_handler = None
        report._log_file = _log_file

        # 首次运行时下载社区YARA规则（有缓存则跳过）
        try:
            from analyzer.yara_downloader import download_yara_rules, count_yara_rules
            existing = count_yara_rules(resource_path('rules/yara'))
            if existing < 10:
                yara_stats = download_yara_rules(resource_path('rules/yara'))
                if yara_stats['downloaded'] > 0:
                    logger.info(f"[+] YARA规则: 下载{yara_stats['downloaded']}个")
        except Exception:
            pass

        # 安全检查：如果开启动态分析，检测是否运行在隔离环境

        # 安全检查：如果开启动态分析，检测是否运行在隔离环境
        env_result = None
        if enable_dynamic:
            vm = VMDetector()
            try:
                env_result = vm.detect()
            except Exception as e:
                logger.error(f"环境检测失败: {e}")
                env_result = {'risk_level': 'unknown', 'evidence': [f'检测异常: {e}'], 'is_vm': False}
            logger.info(f"[*] Environment check: {env_result.get('risk_level', 'unknown')}")
            
            if env_result.get('risk_level') == 'dangerous':
                logger.error("⚠️ 未检测到隔离环境！")
                logger.error("动态分析将直接执行恶意样本，可能导致系统感染！")
                logger.error("建议：在 VMware/VirtualBox 快照虚拟机中运行，")
                logger.error("      或使用 --allow-dangerous 参数（风险自负）")
                
                if not allow_dangerous:
                    logger.error("动态分析已取消。使用 --allow-dangerous 强制执行。")
                    report.errors.append("Dynamic analysis cancelled: not in isolated environment. Use --allow-dangerous to override.")
                    enable_dynamic = False
                else:
                    logger.warning("[!] 用户已确认使用 --allow-dangerous，将在宿主机上执行样本！")
                    for ev in env_result['evidence']:
                        logger.info(f"    {ev}")
            elif env_result.get('risk_level') == 'unknown':
                logger.warning("⚠️ 环境检测失败，无法确认隔离状态，保守禁用动态分析。")
                logger.warning("如需强制开启动态分析，请使用 --allow-dangerous 参数。")
                if not allow_dangerous:
                    enable_dynamic = False
                else:
                    logger.warning("[!] 用户已确认使用 --allow-dangerous，将继续执行。")
                    for ev in env_result['evidence']:
                        logger.info(f"    {ev}")
            else:
                logger.info(f"[+] 环境安全：{env_result['risk_level']}")
                for ev in env_result['evidence']:
                    logger.info(f"    {ev}")
        
        # 动态分析前：隐藏VM进程（对抗反VM检测，除非用户禁用）
        vm_hider = None
        if enable_dynamic and not no_vm_hide:
            # 只在VM环境内才执行隐藏！宿主机跳过，否则会破坏VMware Workstation
            if env_result.get('risk_level') == 'dangerous':
                logger.info("[*] 宿主机环境 — 跳过VM痕迹隐藏（非VM环境无需隐藏）")
            else:
                try:
                    from analyzer.vm_process_hider import VMProcessHider
                    vm_hider = VMProcessHider()
                    hide_result = vm_hider.hide()
                    if hide_result['status'] not in ('none', ''):
                        logger.info(f"[+] VM进程终止:  {len(hide_result.get('hidden', []))} 个")
                        logger.info(f"[+] VM服务停止:  {len(hide_result.get('stopped', []))} 个")
                        logger.info(f"[+] VM驱动禁用:  {len(hide_result.get('driver_stopped', []))} 个")
                        logger.info(f"[+] VM文件重命名: {len(hide_result.get('renamed', []))} 个")
                        logger.info(f"[+] VM注册表删除: {len(hide_result.get('registry_deleted', []))} 个")
                        logger.info(f"[+] VM注册表修改: {len(hide_result.get('registry_modified', []))} 个")
                except Exception as e:
                    logger.warning(f"[!] VM进程隐藏失败: {e}")
        elif enable_dynamic and no_vm_hide:
            logger.info("[*] 用户已禁用VM进程隐藏")

        # 虚假用户环境（对抗反沙箱指纹：USB历史/最近文档/剪贴板）
        # ⚠ 物理机测试时可关闭: 避免在真实系统写入假痕迹/清空剪贴板
        fake_env = None
        if enable_dynamic and fake_user_env:
            try:
                from analyzer.fake_user_env import FakeUserEnvironment
                fake_env = FakeUserEnvironment()
                if fake_env.setup():
                    logger.info("[+] 虚假用户环境已就绪（USB历史/最近文档/剪贴板/注册表痕迹）")
                else:
                    fake_env = None
            except Exception as e_fenv:
                logger.debug(f"虚假用户环境设置失败: {e_fenv}")
                fake_env = None
        elif enable_dynamic and not fake_user_env:
            logger.info("[*] 虚假用户环境已跳过 (fake_user_env=False)")
        
        try:
            # 0. Archive check — 每次分析使用独立 ArchiveAnalyzer 实例,
            # 避免并行批量扫描共享密码/预算状态 (线程安全)
            archive_analyzer = ArchiveAnalyzer()
            if archive_analyzer.is_archive(file_path):
                logger.info("[0] Archive detected, extracting...")
                # 手动密码优先
                if archive_passwords:
                    archive_analyzer.set_extra_passwords(archive_passwords)
                    logger.info(f"[0] 手动指定密码: {archive_passwords}")
                report.archive = archive_analyzer.analyze(file_path)
                report._original_path = file_path
                if report.archive.executable_files:
                    exes = report.archive.executable_files
                    # 路径穿越防护: 只用可解析回解压目录内的成员路径
                    safe_main_path = None
                    for _exe in exes:
                        _resolved = ArchiveAnalyzer.resolve_entry(report.archive.extracted_dir, _exe)
                        if _resolved:
                            safe_main_path = _resolved
                            break
                    if safe_main_path:
                        file_path = safe_main_path
                        logger.info(f"[*] 主分析目标: {file_path}")
                    else:
                        logger.error("[Archive] 归档内可执行文件路径越界/非法, 跳过主目标切换")
                        exes = []

                    # 对所有可执行文件做完整分析
                    child_reports = []
                    for idx, extra_file in enumerate(exes):
                        extra_path = ArchiveAnalyzer.resolve_entry(report.archive.extracted_dir, extra_file)
                        if not extra_path:
                            logger.warning(f"[Archive] 跳过路径非法的子文件: {extra_file}")
                            continue
                        if idx == 0:
                            continue  # 第一个在主流程中完整分析
                        # CAP 动态子分析: 只对前 3 个额外可执行文件开启动态分析, 约束总运行时间
                        child_enable_dynamic = enable_dynamic if idx <= 3 else False
                        if enable_dynamic and child_enable_dynamic:
                            logger.info(f"[0] 压缩包子动态分析 [{idx+1}/{len(exes)}]: {extra_file} (前3个额外exe限制内)")
                        else:
                            logger.info(f"[0] 压缩包子分析 [{idx+1}/{len(exes)}]: {extra_file}" + (" (动态分析已超出前3个额外exe上限, 仅静态)" if enable_dynamic else ""))
                        try:
                            child = self._analyze_archive_child(
                                extra_path, extra_file, report.scan_id,
                                enable_dynamic=child_enable_dynamic,
                                allow_dangerous=allow_dangerous,
                                enable_time_accel=enable_time_accel,
                                fake_user_env=fake_user_env,
                            )
                            if child:
                                child_reports.append(child)
                        except Exception as e_child:
                            logger.debug(f"压缩包子文件分析失败: {extra_file}: {e_child}")
                    report._archive_child_reports = child_reports
                    if child_reports:
                        logger.info(f"[0] 压缩包分析完成: 1个主文件 + {len(child_reports)}个子文件")
            
            # 0b. MSI check — extract + recursive analyze
            if self.msi_analyzer.is_msi(file_path):
                logger.info("[0] MSI detected, analyzing...")
                report.msi_actions = self.msi_analyzer.analyze_custom_actions(file_path)
                report.msi_registry_planned = self.msi_analyzer.analyze_registry_changes(file_path)

                # 提取 MSI 内嵌文件并递归分析
                msi_extract_dir = tempfile.mkdtemp(prefix='msi_extract_')
                try:
                    extracted_files = self.msi_analyzer.extract_files(file_path, msi_extract_dir)
                    if extracted_files:
                        logger.info(f"[0] MSI 提取 {len(extracted_files)} 个文件:")
                        first_sub = None
                        for ef in extracted_files:
                            logger.info(f"    {os.path.basename(ef)}")
                            if is_pe_file_path(ef):
                                try:
                                    sub_analyzer = self.sub_file_analyzer(ef)
                                    result = sub_analyzer.analyze()
                                    if result:
                                        if first_sub is None:
                                            first_sub = result
                                        else:
                                            if result.extracted_files:
                                                first_sub.extracted_files.extend(result.extracted_files)
                                            if result.embedded_resources:
                                                first_sub.embedded_resources.extend(result.embedded_resources)
                                            if result.overlay_data:
                                                first_sub.overlay_data.update(result.overlay_data)
                                            if result.certificate_data:
                                                first_sub.certificate_data.update(result.certificate_data)
                                except Exception as e_msi_sub:
                                    logger.debug(f"MSI sub-file analysis failed: {e_msi_sub}")
                        if first_sub:
                            if report.sub_files is not None:
                                report.sub_files.extracted_files.extend(first_sub.extracted_files)
                            else:
                                report.sub_files = first_sub
                except Exception as e:
                    logger.warning(f"MSI 提取失败: {e}")
                finally:
                    shutil.rmtree(msi_extract_dir, ignore_errors=True)
            
            # 0c. Script check
            if self.script_analyzer.is_script(file_path):
                logger.info("[0] Script detected, analyzing...")
                report.script_analysis = self.script_analyzer.analyze(file_path)

            # 0d. Office 宏分析 (docx/xlsm/pptm/.doc — Kimsuky/银狐 APT 常用投递)
            try:
                from analyzer.macro_analyzer import analyze_macro_file
                _is_office = file_path.lower().endswith(
                    ('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.dot', '.xlsm', '.pptm'))
                if _is_office:
                    macro = analyze_macro_file(file_path)
                    if macro and macro.has_vba:
                        logger.info(f"[Macro] 检测到 VBA 宏: {len(macro.modules)} 模块, "
                                    f"autoexec={macro.autoexec}, 行为={len(macro.suspicious)} 项")
                        report._macro_analysis = {
                            'has_vba': True,
                            'dpb_protected': macro.dpb_protected,
                            'autoexec': macro.autoexec,
                            'suspicious': macro.suspicious,
                            'urls': macro.urls,
                            'modules': macro.modules,
                            'container': macro.container,
                        }
                        # 宏 URL 并入威胁情报
                        if macro.urls:
                            report._macro_urls = macro.urls
                        # 有宏 + 自动触发 + 恶意行为 → 提升风险 (钓鱼文档)
                        if macro.autoexec and macro.suspicious:
                            from analyzer.models import ThreatIntel
                            if not report.threat_intel:
                                report.threat_intel = ThreatIntel()
                            report.threat_intel.threat_labels = \
                                list(dict.fromkeys((report.threat_intel.threat_labels or []) + ['macro_dropper']))
                            logger.warning("[Macro] 钓鱼宏文档: AutoExec + 恶意行为 — 疑似恶意投递")
            except Exception as e:
                logger.debug(f"Macro analysis failed: {e}")
            
            # 1. Static Analysis
            if enable_static:
                logger.info("[1] Static analysis...")
                if web_state: web_state.set_status('analyzing', 10, '静态分析中...')
                static = self.static_analyzer(file_path)
                report.file_info = static.analyze()
            else:
                logger.info("[1] Static analysis SKIPPED (disabled)")
            self._publish_web_section(web_state, 'overview', report)
            
            # 2. PE Analysis
            if is_pe_file_path(file_path):
                logger.info("[2] PE structure analysis...")
                if web_state: web_state.set_status('analyzing', 20, 'PE结构分析中...')
                pe = self.pe_analyzer(file_path)
                report.pe_info = pe.analyze()
            
            # 3. String Analysis
            logger.info("[3] String analysis...")
            if web_state: web_state.set_status('analyzing', 30, '字符串分析中...')
            try:
                data = None
                # MSI/OLE2 文件：提取 stream 后再分析（比 raw binary 有效百倍）
                if file_path.lower().endswith('.msi'):
                    try:
                        import olefile
                        ole = olefile.OleFileIO(file_path)
                        streams_data = []
                        for stream_name in ole.listdir():
                            try:
                                stream_path = '/'.join(stream_name)
                                stream_bytes = ole.openstream(stream_path).read()
                                streams_data.append(stream_bytes)
                            except:
                                pass
                        ole.close()
                        data = b'\n---STREAM---\n'.join(streams_data) if streams_data else None
                        if data:
                            logger.info(f"    从 MSI 中提取 {len(streams_data)} 个 OLE stream 用于字符串分析")
                    except ImportError:
                        logger.warning("    olefile 未安装，MSI 字符串分析降级为 raw binary")
                    except Exception as e:
                        logger.debug(f"    OLE 提取失败: {e}")

                if data is None:
                    # 大文件只读前 20MB 做字符串分析（足够覆盖代码段）
                    fsize = os.path.getsize(file_path)
                    cap = 20 * 1024 * 1024  # 20MB
                    with open(file_path, 'rb') as f:
                        if fsize > cap:
                            data = f.read(cap)
                            logger.info(f"    [Strings] 大文件 ({format_size(fsize)}), 仅分析前 {format_size(cap)}")
                        else:
                            data = f.read()

                strings = self.string_analyzer(data)
                report.strings = strings.analyze()
            except Exception as e:
                logger.error(f"String analysis failed: {e}")
            self._publish_web_section(web_state, 'strings', report)
            self._publish_web_section(web_state, 'overview', report)
            
            # 3b. PowerShell Deobfuscation (if applicable)
            if report.strings and any('powershell' in s.lower() for s in report.strings.suspicious_strings[:50] + report.strings.powershell_patterns[:20]):
                try:
                    from utils.ps_deobfuscate import PSDeobfuscator
                    ps_deob = PSDeobfuscator()
                    with open(file_path, 'rb') as f:
                        fsize = os.path.getsize(file_path)
                        ps_cap = 10 * 1024 * 1024
                        ps_data = f.read(ps_cap) if fsize > ps_cap else f.read()
                    decoded = ps_deob.deobfuscate(ps_data)
                    if decoded:
                        report._ps_deobfuscated = []
                        for t, d, raw in decoded:
                            if isinstance(raw, bytes):
                                text = raw.decode('utf-8', errors='ignore')[:500]
                            elif isinstance(raw, str):
                                text = raw[:500]
                            else:
                                text = str(raw)[:500]
                            report._ps_deobfuscated.append(
                                {'technique': t, 'description': d, 'decoded': text}
                            )
                        report._ps_iocs = ps_deob.get_iocs()
                        logger.info(f"[+] PowerShell 反混淆: {len(decoded)} 段解码, {len(ps_deob.get_iocs())} 个IOC")
                except Exception as ex:
                    logger.debug(f"PowerShell 反混淆失败: {ex}")
            
            # 3c. 反混淆检测 (XOR/Base64/zlib/LOLBin)
            if report.strings:
                logger.info("[3c] Deobfuscation detection...")
                try:
                    with open(file_path, 'rb') as f:
                        raw_data = f.read(min(os.path.getsize(file_path), 10 * 1024 * 1024))
                    deob_results = Deobfuscator.detect_obfuscation(
                        raw_data,
                        report.strings.suspicious_strings + report.strings.api_calls
                    )
                    if deob_results:
                        report._deobfuscation = [
                            {'technique': r.technique, 'confidence': r.confidence,
                             'preview': r.decoded_preview, 'offset': r.offset,
                             'key': r.key, 'mitre': r.mitre_tag}
                            for r in deob_results
                        ]
                        logger.info(f"[+] 反混淆: 发现 {len(deob_results)} 个编码/混淆技术")
                except Exception as ex:
                    logger.debug(f"反混淆检测失败: {ex}")

                try:
                    overlay_results = Deobfuscator.detect_payload_overlay(file_path)
                    if overlay_results:
                        if not hasattr(report, '_deobfuscation'):
                            report._deobfuscation = []
                        report._overlay_payloads = overlay_results
                        logger.info(f"[+] Overlay分析: {len(overlay_results)} 个潜在载荷")
                except Exception as ex:
                    logger.debug(f"Overlay检测失败: {ex}")

            # 3d. 字符串完成后，用新提取的密码重新尝试加密压缩包
            if self._cancelled(stop_event):
                report.errors.append("Analysis cancelled by user")
                report.risk_level = 'unknown'
                report.risk_score = 0
                return report
            if report.archive and report.archive.encrypted_files and report.strings:
                extra_pw = archive_analyzer.extract_password_candidates(report.strings)
                if extra_pw:
                    archive_analyzer.set_extra_passwords(extra_pw)
                    logger.info(f"[3d] 从字符串提取到 {len(extra_pw)} 个候选密码，重新尝试解压加密压缩包...")
                    new_archive = archive_analyzer.analyze(report._original_path or file_path)
                    if new_archive and new_archive.executable_files:
                        old_exe = report.archive.executable_files
                        report.archive = new_archive
                        # 如果新解压出了可执行文件且之前没有，补充子分析
                        new_exes = [e for e in new_archive.executable_files if e not in old_exe]
                        for extra_file in new_exes[:5]:
                            extra_path = ArchiveAnalyzer.resolve_entry(new_archive.extracted_dir, extra_file)
                            if not extra_path:
                                logger.warning(f"[Archive] 跳过路径非法的密码破解新增文件: {extra_file}")
                                continue
                            try:
                                child = self._analyze_archive_child(
                                    extra_path, extra_file, report.scan_id,
                                    enable_dynamic=enable_dynamic,
                                    allow_dangerous=allow_dangerous,
                                    enable_time_accel=enable_time_accel,
                                    fake_user_env=fake_user_env,
                                )
                                if child:
                                    if not hasattr(report, '_archive_child_reports'):
                                        report._archive_child_reports = []
                                    report._archive_child_reports.append(child)
                            except Exception:
                                pass
                        logger.info(f"[3d] 字符串密码破解后新增 {len(new_exes)} 个可执行文件")

            # 4. Sub-file Analysis
            if self._cancelled(stop_event):
                report.errors.append("Analysis cancelled by user")
                report.risk_level = 'unknown'
                report.risk_score = 0
                return report
            logger.info("[4] Sub-file analysis...")
            try:
                sub = self.sub_file_analyzer(file_path)
                sub_result = sub.analyze()
                if sub_result:
                    if report.sub_files is not None:
                        report.sub_files.extracted_files.extend(sub_result.extracted_files)
                        report.sub_files.embedded_resources.extend(sub_result.embedded_resources)
                        report.sub_files.overlay_data.update(sub_result.overlay_data)
                        report.sub_files.certificate_data.update(sub_result.certificate_data)
                    else:
                        report.sub_files = sub_result
            except Exception as e:
                logger.error(f"Sub-file analysis failed: {e}")
            
            # 5. Malware Family Analysis
            if self._cancelled(stop_event):
                report.errors.append("Analysis cancelled by user")
                report.risk_level = 'unknown'
                report.risk_score = 0
                return report
            if report.strings and enable_family:
                logger.info("[5] Malware family analysis...")
                report.malware_family = self.family_analyzer.analyze(report.strings, report.pe_info)
            elif not enable_family:
                logger.info("[5] Malware family SKIPPED (disabled)")
            self._publish_web_section(web_state, 'family', report)

            # 6. Advanced Behavior Detection
            if self._cancelled(stop_event):
                report.errors.append("Analysis cancelled by user")
                report.risk_level = 'unknown'
                report.risk_score = 0
                return report
            if report.strings and enable_advanced:
                logger.info("[6] Advanced behavior detection...")
                report.advanced_behavior = self.advanced_detector.analyze(report.strings, report.pe_info)
            self._publish_web_section(web_state, 'behavior', report)

            # 6b. Community Signatures (CAPE-style)
            if self._cancelled(stop_event):
                report.errors.append("Analysis cancelled by user")
                report.risk_level = 'unknown'
                report.risk_score = 0
                return report
            try:
                from analyzer.signature_engine import SignatureEngine
                sig_engine = SignatureEngine()
                report._community_signatures = sig_engine.run_all(report)
            except Exception as e_sig:
                logger.debug(f"Signature engine failed: {e_sig}")
                report._community_signatures = []

            # 6b2. Sigma Rules Engine
            if self._cancelled(stop_event):
                report.errors.append("Analysis cancelled by user")
                report.risk_level = 'unknown'
                report.risk_score = 0
                return report
            try:
                from analyzer.sigma_rules import SigmaEngine
                sigma_engine = SigmaEngine()
                report._sigma_matches = sigma_engine.run_all(report)
                if report._sigma_matches:
                    logger.info(f"[+] Sigma规则命中: {len(report._sigma_matches)} 条")
            except Exception as e_sigma:
                logger.debug(f"Sigma规则引擎失败: {e_sigma}")
                report._sigma_matches = []

            # 6c. YARA Scanning (纯 Python 降级)
            if self._cancelled(stop_event):
                report.errors.append("Analysis cancelled by user")
                report.risk_level = 'unknown'
                report.risk_score = 0
                return report
            if enable_yara:
                try:
                    from analyzer.yara_scanner import YARAScanner
                    yara_scanner = YARAScanner(rules_dir=resource_path('rules/yara'))
                    with open(file_path, 'rb') as f:
                        # 大文件只扫前 10MB（YARA 规则匹配 PE 头/代码段/字符串，不需全量）
                        yara_cap = 10 * 1024 * 1024
                        fsize = os.path.getsize(file_path)
                        yara_data = f.read(yara_cap) if fsize > yara_cap else f.read()
                        if fsize > yara_cap:
                            logger.info(f"    [YARA] 大文件 ({format_size(fsize)}), 仅扫描前 {format_size(yara_cap)}")
                        yara_hits = yara_scanner.scan_bytes(yara_data, os.path.basename(file_path))
                    report._yara_matches = yara_hits if yara_hits else []
                except Exception as e_yara:
                    logger.debug(f"YARA scanning failed: {e_yara}")
                    report._yara_matches = []
            else:
                logger.info("[6c] YARA scanning SKIPPED (disabled)")
                report._yara_matches = []

            # 6d. RAT/Stealer 配置提取
            if self._cancelled(stop_event):
                report.errors.append("Analysis cancelled by user")
                report.risk_level = 'unknown'
                report.risk_score = 0
                return report
            try:
                from analyzer.rat_config import RATConfigExtractor
                rat_extractor = RATConfigExtractor()
                with open(file_path, 'rb') as f:
                    fsize = os.path.getsize(file_path)
                    rat_cap = 10 * 1024 * 1024
                    rat_data = f.read(rat_cap) if fsize > rat_cap else f.read()
                rat_configs = rat_extractor.extract(rat_data, report.pe_info)
                report._rat_config = rat_configs
                if rat_configs:
                    logger.info(f"[+] RAT配置提取: {len(rat_configs)} 项")
                    # 立即用配置精炼家族 (云沙箱对照: RedLine配置应提升RedLine家族优先级)
                    if report.malware_family:
                        try:
                            report.malware_family = self.family_analyzer.refine_with_rat(
                                report.malware_family, rat_configs)
                        except Exception as e_rf:
                            logger.debug(f"RAT家族精炼失败: {e_rf}")
            except Exception as e_rat:
                logger.debug(f"RAT config extraction failed: {e_rat}")
                report._rat_config = []
            self._publish_web_section(web_state, 'yara', report)
            self._publish_web_section(web_state, 'family', report)
            
            # 7. Destruction Detection
            if self._cancelled(stop_event):
                report.errors.append("Analysis cancelled by user")
                report.risk_level = 'unknown'
                report.risk_score = 0
                return report
            if report.strings and enable_destruction:
                logger.info("[7] Destruction behavior detection...")
                report.destruction = self.destruction_detector.analyze_combined(report.strings)
                if report.pe_info:
                    report.destruction = self.destruction_detector.analyze_pe_imports(report.pe_info, report.destruction)

                # 磁盘取证：MBR/BootKit检测
                try:
                    disk_indicators = DiskForensics.detect_disk_destruction_indicators(
                        report.strings.suspicious_strings,
                        report.strings.api_calls
                    )
                    if any(disk_indicators.values()):
                        report._disk_forensics = disk_indicators
                        total = sum(len(v) for v in disk_indicators.values())
                        logger.warning(f"[DiskForensics] 磁盘破坏/取证指示器: {total} 项")
                except Exception as e:
                    logger.debug(f"磁盘取证分析失败: {e}")
            
            # 8. Threat Intelligence (多引擎)
            if self._cancelled(stop_event):
                report.errors.append("Analysis cancelled by user")
                report.risk_level = 'unknown'
                report.risk_score = 0
                return report
            if report.file_info and report.file_info.sha256 and enable_threat:
                logger.info("[8] Threat intelligence query...")
                report.threat_intel = self.threat_intel.query_all(report.file_info.sha256)
                # 威胁情报家族结论融入本地家族识别 (外部证据优先级高)
                if report.malware_family and report.threat_intel:
                    try:
                        report.malware_family = self.family_analyzer.refine_with_threat_intel(
                            report.malware_family, report.threat_intel)
                    except Exception as e_tif:
                        logger.debug(f"威胁情报家族精炼失败: {e_tif}")

            # 8a. ClamAV 本地扫描 (clamd 守护进程, 不可用则自动降级)
            try:
                from analyzer.clamav_scanner import scan_file as _clamav_scan, is_available as _clamav_ok
                if _clamav_ok():
                    _cv = _clamav_scan(file_path)
                    report._clamav = _cv
                    if _cv.get('detected'):
                        logger.warning(f"[ClamAV] 检出: {_cv.get('malware_name')}")
                        if report.threat_intel is None:
                            from analyzer.models import ThreatIntel
                            report.threat_intel = ThreatIntel()
                        if 'malicious' not in (report.threat_intel.threat_labels or []):
                            report.threat_intel.threat_labels.append('malicious')
                        report.threat_intel.engine_results.append({
                            'engine': 'ClamAV', 'result': {'hit': True, 'malware_name': _cv.get('malware_name')}
                        })
                    else:
                        logger.info("[ClamAV] 未检出")
                        # 未检出也写入引擎结果, 报告威胁情报表才能显示 ClamAV 扫描记录
                        if report.threat_intel is None:
                            from analyzer.models import ThreatIntel
                            report.threat_intel = ThreatIntel()
                        report.threat_intel.engine_results.append({
                            'engine': 'ClamAV', 'result': {'hit': False, 'malware_name': ''}
                        })
                else:
                    report._clamav = {'available': False, 'detected': False, 'malware_name': '', 'error': 'ClamAV 服务不可用'}
            except Exception as _e_cv:
                logger.debug(f"ClamAV 扫描异常: {_e_cv}")
                report._clamav = {'available': False, 'detected': False, 'malware_name': '', 'error': str(_e_cv)[:200]}

            # 8b. 本地 IoC 批量检查 — IP / 域名 / URL
            if self._cancelled(stop_event):
                report.errors.append("Analysis cancelled by user")
                report.risk_level = 'unknown'
                report.risk_score = 0
                return report
            if report.strings:
                ioc_result = self.threat_intel.check_iocs_batch(
                    ips=report.strings.ips[:50] if report.strings.ips else [],
                    domains=report.strings.domains[:50] if report.strings.domains else [],
                    urls=report.strings.urls[:50] if report.strings.urls else []
                )
                if ioc_result and ioc_result['total_hits'] > 0:
                    report._ioc_hits = ioc_result
                    logger.info(f"[+] 本地IoC命中: {ioc_result['total_hits']}项 (IP={len(ioc_result['ips'])} 域名={len(ioc_result['domains'])} URL={len(ioc_result['urls'])})")
                else:
                    report._ioc_hits = {'ips': [], 'domains': [], 'urls': [], 'total_hits': 0}
            
            # 9. Dynamic Analysis (if enabled)
            if enable_dynamic:
                if stop_event and stop_event.is_set():
                    logger.warning("[!] 分析已取消（用户停止）")
                    return report
                logger.info("[9] Dynamic analysis...")
                if web_state: web_state.set_status('analyzing', 60, '动态行为分析中 (执行样本)...')
                try:
                    dyn = self.dynamic_analyzer(
                        timeout=CONFIG.sandbox.timeout,
                        use_sandbox=CONFIG.sandbox.enabled,
                        enable_time_accel=enable_time_accel
                    )

                    # 网络捕获与动态分析并行运行（用后台线程）
                    if enable_network and getattr(CONFIG.network, 'capture_enabled', True):
                        import threading
                        net_result = [None]
                        net_done = threading.Event()
                        net_stop = threading.Event()
                        net = self.network_analyzer(timeout=CONFIG.network.capture_timeout)
                        _pcap_enabled = getattr(CONFIG.network, 'pcap_enabled', False)
                        _pcap_path = None
                        if _pcap_enabled:
                            _pcap_dir = os.path.abspath(getattr(CONFIG.network, 'pcap_dir', 'pcaps'))
                            _pcap_path = os.path.join(_pcap_dir, f"{scan_id}.pcap")

                        def _capture_net():
                            try:
                                net_result[0] = net.capture(stop_event=net_stop, pcap_path=_pcap_path)
                            except Exception as _net_exc:
                                # 抓包线程异常时不能静默返回 None (曾导致“开了网络却0连接”)
                                logger.warning(f"[-] 网络捕获线程失败, 将回退到进程级连接: {_net_exc}")
                            finally:
                                net_done.set()

                        net_thread = threading.Thread(target=_capture_net, daemon=True)
                        net_thread.start()
                    else:
                        net_result = [None]
                        net_done = None
                        net_stop = None
                        net_thread = None

                    # 沙箱增强：执行前快照（命名管道/注册表）
                    enhancer = SandboxEnhancer()
                    pre_snapshot = enhancer.pre_execution_snapshot()

                    # 执行动态分析（同时网络在后台抓包）
                    report.dynamic, report.api_monitor = dyn.analyze(file_path, stop_event=stop_event)

                    # 系统状态监控报告（注册表变更 + VSS/日志/安全产品检测）
                    if report.dynamic and hasattr(report.dynamic, '_system_monitor'):
                        report._system_monitor = report.dynamic._system_monitor
                        sm = report._system_monitor
                        if sm and sm.get('total_changes', 0) > 0:
                            logger.warning(f"[SystemMonitor] 注册表变更 {sm.get('registry_created',0)}新增/"
                                           f"{sm.get('registry_deleted',0)}删除/{sm.get('registry_modified',0)}修改 "
                                           f"+ {sm.get('system_detections',0)}条系统检测")
                            for h in sm.get('high_severity', []):
                                logger.warning(f"  [HIGH] {h['category']}: {h['count']}项")

                    # 传递关机拦截记录到报告
                    if report.api_monitor and report.api_monitor.shutdown_blocked:
                        report._shutdown_blocked = report.api_monitor.shutdown_blocked
                        logger.warning(f"[!] 关机拦截: 成功阻止 {len(report._shutdown_blocked)} 次关机/重启/休眠尝试")

                    # 沙箱增强：执行后对比分析
                    if report.dynamic and report.dynamic.sandbox_result:
                        try:
                            sr = report.dynamic.sandbox_result
                            pids = [c.get('pid') for c in (sr.child_processes or []) if c.get('pid')]
                            if pids:
                                post_analysis = enhancer.post_execution_analysis(pre_snapshot, pids[0])
                                report._sandbox_enhancements = post_analysis
                                if any(post_analysis.values()):
                                    logger.info(f"[+] 沙箱增强监控: {sum(len(v) for v in post_analysis.values())} 项")
                        except Exception as e:
                            logger.debug(f"沙箱增强分析失败: {e}")

                    # 动态分析结束，样本进程已被沙箱终止:
                    # 1) 立即恢复 VM 环境（不能再等网络捕获 — 历史版本此处被 300s
                    #    网络捕获阻塞, VM 隐藏状态最长保持 5 分钟, 中途退出则永不恢复）
                    if vm_hider:
                        try:
                            logger.info("[*] 恢复VM进程...")
                            vm_hider.restore()
                        except Exception as e:
                            logger.warning(f"[!] VM进程恢复失败: {e}")
                        vm_hider = None

                    # 2) 等待网络捕获完成（样本已死, 最多再等 30s 收尾流量）
                    if enable_network and net_done:
                        net_done.wait(timeout=30)
                    if net_stop:
                        net_stop.set()
                    if net_thread:
                        net_thread.join(timeout=5)
                    if net_result[0] and enable_network:
                        raw_net = net_result[0]
                        # 合并动态监控捕获的连接(按样本PID高频轮询, 短连接不漏)
                        # — 历史bug: 全局psutil轮询间隔大, 样本短连接全丢, 过滤后恒为0
                        self._merge_dynamic_connections(raw_net, report.dynamic)
                        # 用动态分析中监控到的 PID 过滤网络流量
                        report.network = self._filter_traffic_by_target(raw_net, report.dynamic)
                        # 附上进程信息供报告展示（动态添加属性）
                        if report.dynamic:
                            report.network._dynamic_behavior = report.dynamic
                        # 用 psutil IO 计数器填充逐连接字节数
                        self._populate_network_bytes(report.network, report.dynamic)
                        # 把 PCAP 路径带入报告（scapy 模式已设置, 这里防止过滤/合并流程丢失）
                        if getattr(raw_net, 'pcap_path', ''):
                            setattr(report.network, 'pcap_path', getattr(raw_net, 'pcap_path', ''))
                    else:
                        report.network = NetworkTraffic()
                        # 未开启抓包(--enable-network)时 pcap 为空, 但进程级网络监控
                        # 一直在采 (短连接/秒退样本也能抓到) — 合并进去, 避免银狐
                        # 这类外联后门在“网络分析”里显示 0 连接。
                        if report.dynamic:
                            self._merge_dynamic_connections(report.network, report.dynamic)
                            if report.dynamic:
                                report.network._dynamic_behavior = report.dynamic
                        setattr(report.network, 'pcap_path', '')

                    # DNS 缓存快照差异合并进网络报告 (scapy 可能漏抓, DNS缓存对比更可靠)
                    try:
                        _sm = getattr(report, '_system_monitor', None) or {}
                        _new_dns = (_sm.get('user_diff') or {}).get('new_dns', []) or []
                        if _new_dns and report.network is not None:
                            _existing = {d.domain for d in (report.network.dns_queries or [])}
                            from analyzer.models import DNSQuery
                            for _dname in _new_dns:
                                _dn = str(_dname).rstrip('.')
                                if _dn and _dn not in _existing:
                                    report.network.dns_queries.append(DNSQuery(
                                        domain=_dn, query_type='A',
                                        is_suspicious=False, suspicion_reason=''
                                    ))
                                    _existing.add(_dn)
                            logger.info(f"[+] DNS缓存差异合并: {len(_new_dns)} 条 → 网络报告")
                    except Exception as _e_dns:
                        logger.debug(f"DNS缓存差异合并失败: {_e_dns}")

                    # User-Agent 分析（网络流量中多UA检测）
                    if report.network and report.network.http_requests:
                        ua_result = NetworkAnalyzer.analyze_user_agents(report.network.http_requests)
                        if ua_result and (ua_result.get('diverse') or ua_result.get('malicious_hits') or ua_result.get('suspicious_anomalies')):
                            report._ua_analysis = ua_result
                            logger.info(f"[+] UA分析: {ua_result.get('unique_count',0)}种UA/{ua_result.get('ua_count',0)}次请求, 异常={len(ua_result.get('suspicious_anomalies',[]))}项")

                    # Dropped files — 含系统目录中的释放文件
                    files_created = getattr(report.dynamic, 'files_created', [])
                    if report.dynamic and (report.dynamic.sandbox_result or files_created):
                        logger.info("[9b] Dropped file tracking...")
                        all_dropped = list(files_created)
                        # 双重保险: 过滤浏览器/系统噪音(历史问题: 分析期间浏览网页的缓存被当释放文件)
                        try:
                            from analyzer.dynamic import FileSystemMonitor as _FSM
                            all_dropped = [f for f in all_dropped if not _FSM._is_noise_file(
                                f.get('path', f) if isinstance(f, dict) else str(f))]
                        except Exception:
                            pass
                        sandbox_dir = (
                            report.dynamic.sandbox_result.sandbox_dir
                            if report.dynamic.sandbox_result else None
                        )
                        report.dropped_files = self.dropped_tracker.track(
                            sandbox_dir=sandbox_dir,
                            dynamic_files=all_dropped
                        )

                        # YARA扫描释放文件
                        if report.dropped_files and report.dropped_files.dropped_files:
                            try:
                                from analyzer.yara_scanner import YARAScanner
                                dr_yara = YARAScanner(rules_dir=resource_path('rules/yara'))
                                for df in report.dropped_files.dropped_files:
                                    abs_path = getattr(df, 'abs_path', df.path)
                                    if os.path.isfile(abs_path) and os.path.getsize(abs_path) < 50 * 1024 * 1024:
                                        file_yara_hits = dr_yara.scan_file(abs_path)
                                        if file_yara_hits:
                                            df.yara_matches = [h.get('rule', h.get('name', '')) for h in file_yara_hits]
                                            detected = [h for h in file_yara_hits if h.get('rule')]
                                            if detected:
                                                df.detection = f"YARA: {len(detected)} rules"
                                                logger.warning(f"[YARA] 释放文件 {os.path.basename(abs_path)}: {len(detected)} 规则命中")
                            except Exception as e_dry:
                                logger.debug(f"Dropped file YARA scan failed: {e_dry}")

                    # Memory analysis — 从 ProcessTreeMonitor 快照 + 尝试实时分析
                    if report.dynamic and enable_memory:
                        logger.info(f"[9c] Memory analysis: entering (dynamic={bool(report.dynamic)} memory={enable_memory})")
                        all_pids = set()
                        for snap in (getattr(report.dynamic, 'memory_snapshots', []) or []):
                            all_pids.add(snap.get('pid', 0))
                        # 根进程显式加入 — 快照为空时(如长存活样本早期) live 分析也应尝试根进程
                        for p in (getattr(report.dynamic, 'processes_created', []) or [])[:3]:
                            if p.get('pid'):
                                all_pids.add(p['pid'])
                        if report.dynamic.sandbox_result:
                            for cp in (report.dynamic.sandbox_result.child_processes or []):
                                all_pids.add(cp.get('pid', 0))
                        all_pids.discard(0)

                        import psutil
                        live_results = []  # (pid, MemoryAnalysis) — 分析所有存活进程
                        for target_pid in sorted(all_pids, reverse=True):
                            if stop_event and stop_event.is_set():
                                break
                            alive = False
                            try:
                                alive = psutil.Process(target_pid).is_running()
                            except Exception:
                                pass
                            if not alive:
                                continue

                            logger.info(f"[9c] Memory analysis PID={target_pid}...")
                            try:
                                # ⚠ 内存分析无内置超时 — 对存活大进程可能跑很久,
                                # 放后台线程限时 30s, 超时跳过该进程 (防后分析卡死)
                                import threading as _th_mem
                                _mem_result = [None]
                                _mem_cancel = _th_mem.Event()

                                def _do_mem():
                                    try:
                                        _mem_result[0] = self.memory_analyzer.analyze_process(target_pid, stop_event=_mem_cancel)
                                    except Exception as _e_mem_inner:
                                        _mem_result[0] = None
                                        logger.warning(f"[9c] PID={target_pid} 内存分析异常: {_e_mem_inner}")

                                _mt = _th_mem.Thread(target=_do_mem, daemon=True)
                                _mt.start()
                                _mt.join(timeout=30)
                                if _mt.is_alive():
                                    _mem_cancel.set()
                                    logger.warning(f"[9c] 内存分析超时(30s), 跳过 PID={target_pid}")
                                    continue
                                r = _mem_result[0]
                                if r is not None:
                                    live_results.append((target_pid, r))
                                    summary = r.summary or ''
                                    logger.info(f"    PID={target_pid}: regions={r.total_regions} "
                                                f"suspicious={len(r.suspicious_regions)} "
                                                f"dumps={len(r.dumped_files)} | {summary[:120]}")
                            except Exception as e_mem:
                                logger.warning(f"Memory analysis PID={target_pid} failed: {e_mem}")

                        # 合并实时分析结果：取发现最多的进程，其余结果累加
                        if live_results:
                            live_results.sort(key=lambda x: (
                                len(x[1].suspicious_regions) + len(x[1].rwx_regions) +
                                len(x[1].dumped_files) + int(x[1].shellcode_found) +
                                int(x[1].pe_in_memory)), reverse=True)
                            report.memory = live_results[0][1]
                            report.memory.live_analyzed = True
                            report.memory.process_exited = False
                            for _pid, other in live_results[1:]:
                                if other.shellcode_found:
                                    report.memory.shellcode_found = True
                                    report.memory.shellcode_details.extend(other.shellcode_details)
                                if other.pe_in_memory:
                                    report.memory.pe_in_memory = True
                                    report.memory.pe_injected_modules.extend(other.pe_injected_modules)
                                report.memory.dumped_files.extend(other.dumped_files)
                                report.memory.suspicious_regions.extend(other.suspicious_regions)
                                report.memory.rwx_regions.extend(other.rwx_regions)
                            _dedup = {}
                            for _d in report.memory.shellcode_details:
                                _dedup.setdefault((_d.get('offset',''), _d.get('pattern','')), _d)
                            report.memory.shellcode_details = list(_dedup.values())[:50]
                            report.memory.dumped_files = list(dict.fromkeys(report.memory.dumped_files))
                            logger.info(f"[9c] 实时内存分析完成: {len(live_results)} 个存活进程被分析")

                        # 快照回填：执行期记录的快照（PE注入/Shellcode/Hook）必须并入报告，
                        # 不能被"存活进程分析无发现"遮蔽
                        snaps = (getattr(report.dynamic, 'memory_snapshots', None) or []) if report.dynamic else []
                        need_snapshot_fallback = bool(snaps) and (
                            report.memory is None or
                            (not report.memory.pe_in_memory and not report.memory.shellcode_found
                             and not report.memory.dumped_files)
                        )
                        if need_snapshot_fallback:
                            from analyzer.models import MemoryAnalysis, MemoryRegion
                            if report.memory is None:
                                report.memory = MemoryAnalysis()

                            # 收集所有类型的快照（PE注入、Shellcode、Hook）
                            all_snaps = snaps
                            # ⚠ "内存PE（加载模块）" 快照 = 已加载模块的常规 dump,
                            #    不是注入 (ModuleDump 的旁路产物), 排除出注入判定
                            pe_snaps = [s for s in all_snaps
                                        if 'PE' in s.get('type', '') and 'shellcode' not in s.get('type', '').lower()
                                        and '加载模块' not in s.get('type', '')]
                            sc_snaps = [s for s in all_snaps if 'Shellcode' in s.get('type', '') or 'shellcode' in s.get('type','').lower()]
                            hook_snaps = [s for s in all_snaps if 'Hook' in s.get('type', '') or 'hook' in s.get('type','').lower()]

                            if pe_snaps:
                                report.memory.pe_in_memory = True
                                report.memory.pe_injected_modules.extend([
                                    {'pid': s.get('pid', 0), 'address': s.get('address', ''),
                                     'architecture': s.get('architecture', ''),
                                     'type': s.get('type', ''), 'sections': s.get('sections', 0),
                                     'section_names': [], 'module': s.get('process', ''),
                                     'dump_path': s.get('dump_path', '')}
                                    for s in pe_snaps
                                ])
                            if sc_snaps:
                                report.memory.shellcode_found = True
                                report.memory.shellcode_details.extend([
                                    {'address': s.get('address', ''), 'size': s.get('size', ''),
                                     'details': s.get('type', '')}
                                    for s in sc_snaps
                                ])
                            if hook_snaps:
                                report.memory.hooks_detected = [
                                    {'address': s.get('address', ''), 'pattern': s.get('type', ''),
                                     'hex': ''}
                                    for s in hook_snaps
                                ]

                            report.memory.suspicious_regions.extend([
                                MemoryRegion(base_address=s.get('address', ''),
                                    region_size=s.get('size', 0),
                                    region_size_human=format_size(s.get('size', 0)),
                                    protect=s.get('region_protect', ''),
                                    state='MEM_COMMIT',
                                    type='MEM_PRIVATE',
                                    is_suspicious=True,
                                    suspicion_reason=s.get('type', ''))
                                for s in all_snaps
                            ])

                            for s in all_snaps:
                                dp = s.get('dump_path')
                                if dp and os.path.exists(dp) and dp not in report.memory.dumped_files:
                                    report.memory.dumped_files.append(dp)
                            report.memory.total_regions = max(report.memory.total_regions, len(all_snaps))
                            report.memory.rwx_regions.extend([
                                MemoryRegion(base_address=s.get('address', ''),
                                    region_size=s.get('size', 0),
                                    region_size_human=format_size(s.get('size', 0)),
                                    protect='RWX',
                                    is_suspicious=True)
                                for s in pe_snaps if 'RWX' in str(s.get('region_protect', ''))
                            ])

                            if report.memory.pe_in_memory:
                                logger.warning(f"[!] 内存PE: {len(pe_snaps)} 个注入PE映像")
                            if report.memory.shellcode_found:
                                logger.warning(f"[!] Shellcode: {len(sc_snaps)} 个特征")
                            # 标记证据来自执行期快照: 风险评分不再重复给 PE/Shellcode/RWX
                            # 加分 (动态行为里的"内存快照×N"已经计过)
                            report.memory._from_snapshots = True
                            logger.info(f"[9c] 执行期内存快照已并入报告 ({len(all_snaps)} 条)")

                        # ⚠ 补录: 沙箱终止残留载荷前 dump 的内存文件 (pid*.bin) —
                        #   进程已死无法实时分析, 但 dump 文件可做离线内存取证
                        try:
                            import glob as _glob
                            _md_dir = None
                            try:
                                import config as _cfg
                                ddir = getattr(getattr(_cfg, 'CONFIG', None), 'memory', None)
                                _md_dir = getattr(ddir, 'dump_dir', 'memory_dumps') if ddir else 'memory_dumps'
                            except Exception:
                                _md_dir = 'memory_dumps'
                            _residual = []
                            # 已知"加载模块"类快照 dump: 不能被残留补录重新定性为"注入PE"
                            _loaded_module_dumps = set()
                            for _s in snaps:
                                if '加载模块' in str(_s.get('type', '')) and _s.get('dump_path'):
                                    _loaded_module_dumps.add(os.path.abspath(_s.get('dump_path')).lower())
                            if _md_dir and os.path.isdir(_md_dir):
                                for _f in _glob.glob(os.path.join(_md_dir, 'pid*.bin'))[:60]:
                                    if _f.lower().endswith('_fixed.exe'):
                                        continue
                                    # ⚠ 只看本次分析开始后新生成的 dump — memory_dumps 是
                                    # 全局目录且从不清理, 历史扫描产物必须排除 (跨样本污染)
                                    try:
                                        if os.path.getmtime(_f) < start_time - 10:
                                            continue
                                    except OSError:
                                        continue
                                    _fb = os.path.basename(_f).lower()
                                    if any(_s in _fb for _s in ('frida-helper', 'frida-server',
                                                                'frida-gadget', 'conhost_',
                                                                'frida-agent')):
                                        continue
                                    if os.path.abspath(_f).lower() in _loaded_module_dumps:
                                        continue
                                    _residual.append(_f)
                            if _residual:
                                from analyzer.models import MemoryAnalysis, MemoryRegion
                                if report.memory is None:
                                    report.memory = MemoryAnalysis()
                                # 对每个 dump 做 PE/Shellcode/Hook 检测
                                from analyzer.memory import MemoryAnalyzer
                                _ma = MemoryAnalyzer()
                                for _f in _residual:
                                    try:
                                        with open(_f, 'rb') as _fh:
                                            _data = _fh.read()
                                        if not _data:
                                            continue
                                        _pe = _ma._detect_pe_in_memory(_data)
                                        if _pe:
                                            # ⚠ 排除系统进程 dump (文件名含系统模块名 →
                                            # kernel32/ntdll 等映像误报"注入")
                                            _fb = os.path.basename(_f).lower()
                                            _sys_names = ('kernel32', 'ntdll', 'user32', 'kernelbase',
                                                          'msvcrt', 'advapi32', 'ws2_32', 'shell32',
                                                          'gdi32', 'ole32', 'comctl32', 'winhttp',
                                                          'bcrypt', 'sechost', 'rpcrt4')
                                            if any(_sn in _fb for _sn in _sys_names):
                                                continue
                                            report.memory.pe_in_memory = True
                                            for _p in _pe[:4]:
                                                _p['module'] = os.path.basename(_f)
                                                _p['address'] = _p.get('address') or _p.get('offset', _f)
                                                _p['dump_path'] = _f
                                                report.memory.pe_injected_modules.append(_p)
                                            report.memory.dumped_files.append(_f)
                                        _sc = _ma._detect_shellcode(_data)
                                        if _sc:
                                            report.memory.shellcode_found = True
                                            report.memory.shellcode_details.extend(
                                                {'address': _f, 'size': len(_data), 'details': s.get('pattern', s)}
                                                for s in _sc[:3])
                                        report.memory.suspicious_regions.append(MemoryRegion(
                                            base_address=_f, region_size=len(_data),
                                            region_size_human=f'{len(_data)//1024}KB',
                                            is_suspicious=bool(_pe), type='MEM_PRIVATE',
                                            suspicion_reason=f'残留载荷dump: {os.path.basename(_f)}'))
                                    except Exception:
                                        continue
                                if _residual:
                                    logger.info(f"[9c] 补录 {len(_residual)} 个残留载荷内存dump 供取证")
                        except Exception as _e:
                            logger.debug(f"[9c] 残留dump补录失败: {_e}")

                        # 目标进程已退出的诊断: 不再只提示"内存退出" — 综合
                        # 分配/释放失衡、DEP/RWX 事件、快照、残留 dump 给出结论
                        if report.memory is None or (
                                report.memory is not None and not report.memory.live_analyzed
                                and not report.memory.exit_diagnosis):
                            try:
                                diag = self._build_memory_exit_diagnosis(report, all_pids)
                                if report.memory is None:
                                    report.memory = diag
                                else:
                                    report.memory.process_exited = True
                                    report.memory.exit_diagnosis = diag.exit_diagnosis
                                    if report.memory.summary and '已退出' not in report.memory.summary:
                                        report.memory.summary += ' | ' + diag.summary
                                    elif not report.memory.summary:
                                        report.memory.summary = diag.summary
                                if diag.exit_diagnosis.get('dep_bypass') or diag.exit_diagnosis.get('rop_like'):
                                    logger.warning(f"[9c] 退出诊断: DEP绕过/ROP事件在进程退出前已捕获")
                                if diag.exit_diagnosis.get('leaked_allocations'):
                                    logger.warning(f"[9c] 退出诊断: 内存分配×{diag.exit_diagnosis['alloc_calls']} "
                                                   f"释放×{diag.exit_diagnosis['free_calls']} (未释放/驻留特征)")
                            except Exception as e_diag:
                                logger.debug(f"[9c] 内存退出诊断失败: {e_diag}")

                        # 高级内存取证增强 (IAT Hook / Heaven's Gate / PEB篡改 / SEH覆写 / 反Dump / API Unhooking)
                        if report.memory and report.memory.dumped_files:
                            logger.info("[9d] Advanced memory forensics...")
                            try:
                                from analyzer.memory_forensics import enhance_memory_analysis
                                raw_data_map = {}
                                for dump_path in report.memory.dumped_files[:10]:
                                    # ⚠ 过滤沙箱自身 Frida 的 dump (frida-agent/symsrv/
                                    # dbghelp/frida-helper) — 否则会把 Frida 的注入代码
                                    # 误报为 Heaven's Gate/IAT Hook/SEH 覆写
                                    _dp = str(dump_path).lower()
                                    if 'frida' in _dp or _dp.endswith('symsrv.dll') \
                                            or _dp.endswith('dbghelp.dll'):
                                        continue
                                    try:
                                        with open(dump_path, 'rb') as df:
                                            raw_data_map[dump_path] = df.read()
                                    except Exception:
                                        pass
                                target_pid = report.memory.pid or (list(all_pids)[0] if all_pids else 0)
                                forensics = enhance_memory_analysis(target_pid, raw_data_map,
                                    report.memory.suspicious_regions)
                                report.memory.advanced_shellcode = forensics.get('advanced_shellcode', [])
                                report.memory.iat_hooks = forensics.get('iat_eat_hooks', [])
                                report.memory.heavens_gate = forensics.get('heavens_gate', [])
                                report.memory.peb_anomalies = forensics.get('peb_anomalies', forensics.get('peb_tamper', []))
                                report.memory.seh_overwrite = forensics.get('seh_overwrite', [])
                                report.memory.anti_dump_measures = forensics.get('anti_dump', [])
                                report.memory.api_unhooking = forensics.get('unhooking', [])
                                report.memory.kernel_backdoor = forensics.get('kernel_backdoor', [])
                                report.memory.hidden_regions = forensics.get('hidden_regions', [])
                                if forensics.get('summary'):
                                    logger.info(f"    {forensics['summary']}")
                            except Exception as e_fm:
                                logger.debug(f"Advanced memory forensics failed: {e_fm}")

                        # YARA扫描内存dump文件
                        if report.memory and report.memory.dumped_files and not report._yara_matches:
                            try:
                                from analyzer.yara_scanner import YARAScanner
                                mem_yara = YARAScanner(rules_dir=resource_path('rules/yara'))
                                for dump_path in report.memory.dumped_files[:5]:
                                    if os.path.isfile(dump_path) and os.path.getsize(dump_path) < 50 * 1024 * 1024:
                                        file_hits = mem_yara.scan_file(dump_path)
                                        if file_hits:
                                            report._yara_matches = (report._yara_matches or []) + file_hits
                                            logger.warning(f"[YARA] 内存dump {os.path.basename(dump_path)}: {len(file_hits)} 规则命中")
                            except Exception as e_my:
                                logger.debug(f"Memory dump YARA scan failed: {e_my}")

                        # 后备：把释放的 PE/DLL 文件纳入内存取证材料 (云沙箱同款做法)
                        # ⚠ 释放文件 ≠ 内存注入: 只记录为 released_pe_files,
                        # 不再把 pe_in_memory=True, 否则纯 dropper/安装包都会被
                        # 报告成"内存PE注入"并虚高评分。
                        if report.memory and report.dropped_files:
                            from analyzer.models import MemoryRegion
                            for df in report.dropped_files.dropped_files:
                                if not df.is_executable:
                                    continue
                                abs_path = getattr(df, 'abs_path', df.path)
                                if not abs_path or not os.path.isfile(abs_path):
                                    continue
                                # 复制到 memory_dumps/ 作为内存文件
                                try:
                                    dst_dir = CONFIG.memory.dump_dir
                                    os.makedirs(dst_dir, exist_ok=True)
                                    dst = os.path.join(dst_dir, os.path.basename(abs_path))
                                    if not os.path.exists(dst):
                                        shutil.copy2(abs_path, dst)
                                    if dst not in (report.memory.dumped_files or []):
                                        report.memory.dumped_files.append(dst)
                                    entry = {
                                        'path': abs_path,
                                        'name': os.path.basename(abs_path),
                                        'dump_path': dst,
                                        'type': 'released_pe',
                                    }
                                    if entry not in report.memory.released_pe_files:
                                        report.memory.released_pe_files.append(entry)
                                    logger.info(f"[Memory] Released PE recorded (not injection): {os.path.basename(abs_path)}")
                                except Exception:
                                    pass
                        # 释放了可执行文件的后备结论也不应伪称"内存注入"
                        if report.memory and report.dropped_files:
                            has_dropped_pe = any(df.is_executable for df in report.dropped_files.dropped_files)
                            if has_dropped_pe and not report.memory.released_pe_files:
                                for df in report.dropped_files.dropped_files:
                                    if df.is_executable:
                                        report.memory.released_pe_files.append({
                                            'path': getattr(df, 'abs_path', df.path),
                                            'name': os.path.basename(getattr(df, 'abs_path', df.path)),
                                            'type': 'released_pe (not copied)',
                                        })

                    # 第二轮行为检测：用动态数据补充
                    if report.advanced_behavior and report.dynamic:
                        try:
                            second_pass = self.advanced_detector.analyze(
                                report.strings, report.pe_info, report.dynamic,
                                api_records=(report.api_monitor.call_records
                                             if report.api_monitor else None)
                            )
                            if second_pass is not None:
                                report.advanced_behavior = second_pass
                        except Exception as e_ab2:
                            logger.debug(f"Second-pass advanced behavior failed: {e_ab2}")

                    # 第二轮破坏检测：用动态沙箱数据补充（杀软终止/危险驱动/BYOVD）
                    if report.destruction is not None and report.dynamic:
                        logger.info("[9d] Destruction re-analysis with dynamic data...")
                        report.destruction = self.destruction_detector.analyze_dynamic(
                            report.dynamic, report.destruction
                        )
                        logger.info(f"     Destruction={report.destruction.destruction_level} score={report.destruction.total_indicators}")

                    # Sigma规则第二轮：用完整动态数据重扫
                    try:
                        from analyzer.sigma_rules import SigmaEngine
                        sigma_engine2 = SigmaEngine()
                        full_matches = sigma_engine2.run_all(report)
                        if full_matches:
                            report._sigma_matches = full_matches
                            high = [m for m in full_matches if m.level == 'high']
                            med = [m for m in full_matches if m.level == 'medium']
                            logger.warning(f"[Sigma] 第二轮命中: {len(full_matches)}条 (高危{len(high)} 可疑{len(med)})")
                            for m in full_matches[:10]:
                                logger.info(f"    [{m.level}] {m.title}: {m.description[:80]}")
                    except Exception as e_s2:
                        logger.debug(f"Sigma第二轮失败: {e_s2}")

                    # 第二轮家族检测：用释放文件匹配
                    if report.malware_family and report.dropped_files:
                        report.malware_family = self.family_analyzer.refine_with_dropped(
                            report.malware_family, report.dropped_files
                        )

                    # 第三轮家族检测：用动态行为匹配
                    if report.malware_family and report.dynamic:
                        report.malware_family = self.family_analyzer.refine_with_behavior(
                            report.malware_family,
                            dynamic_behavior=report.dynamic,
                            api_monitor=report.api_monitor
                        )

                    # 第四轮家族检测：用YARA匹配
                    if report.malware_family and getattr(report, '_yara_matches', None):
                        report.malware_family = self.family_analyzer.refine_with_yara(
                            report.malware_family, report._yara_matches
                        )

                    # 动态分析后检查卷影副本（系统级操作仅在执行样本后做）
                    try:
                        vss = DiskForensics.check_volume_shadow_copy()
                        if not vss.get('shadow_copies_exist', True):
                            report._vss_deleted = True
                            logger.warning("[DiskForensics] 卷影副本已被删除（勒索行为可能）")
                    except Exception as e:
                        logger.debug(f"卷影副本检查失败: {e}")

                    # 交叉引用检测：主进程是否访问了同压缩包内的其他文件
                    child_reports = getattr(report, '_archive_child_reports', []) or []
                    if report.archive and report.archive.executable_files:
                        archive_extracted = getattr(report.archive, 'extracted_dir', '')
                        loaded_children = set()
                        for fentry in (report.dynamic.files_modified or []):
                            fpath = fentry['path'] if isinstance(fentry, dict) else fentry
                            if archive_extracted and fpath.startswith(archive_extracted):
                                loaded_children.add(os.path.basename(fpath))
                        # 检测DLL加载
                        if report.memory and report.memory.pe_injected_modules:
                            for mod in report.memory.pe_injected_modules:
                                mod_path = mod.get('module_path', '') if isinstance(mod, dict) else getattr(mod, 'module_path', '')
                                if mod_path and archive_extracted and mod_path.startswith(archive_extracted):
                                    loaded_children.add(os.path.basename(mod_path))
                        report._loaded_archive_children = list(loaded_children)
                        if loaded_children:
                            logger.warning(f"[!] 交叉引用: 主进程加载了压缩包内 {len(loaded_children)} 个文件: {loaded_children}")

                    # 交叉引用：非PE shellcode/脚本是否被主进程读取
                    archive_sc_loads = []
                    if getattr(report.archive, 'extracted_dir', '') and child_reports:
                        for cr in child_reports:
                            if cr.get('is_shellcode') or cr.get('is_script'):
                                child_path = cr.get('path', '')
                                if child_path in (report.dynamic.files_created or []) or \
                                   any(child_path in str(f) for f in (report.dynamic.files_modified or [])):
                                    archive_sc_loads.append(cr.get('filename', ''))
                        report._archive_shellcode_loads = archive_sc_loads
                        if archive_sc_loads:
                            logger.warning(f"[!] 主进程加载了压缩包内Shellcode/脚本: {archive_sc_loads}")

                except Exception as e:
                    logger.error(f"Dynamic analysis failed: {e}")
                    report.errors.append(f"Dynamic analysis: {e}")
                finally:
                    # 动态分析完成后：恢复VM进程（兜底，正常路径已在上方提前恢复）
                    if vm_hider:
                        try:
                            logger.info("[*] 恢复VM进程...")
                            vm_hider.restore()
                        except Exception as e:
                            logger.warning(f"[!] VM进程恢复失败: {e}")
                        vm_hider = None

            # 动态分析板块发布 (动态/内存/网络/释放文件 — 崩溃前尽可能多的数据)
            self._publish_web_section(web_state, 'dynamic', report)
            self._publish_web_section(web_state, 'memory', report)
            self._publish_web_section(web_state, 'network', report)
            self._publish_web_section(web_state, 'dropped', report)
            self._publish_web_section(web_state, 'behavior', report)

            # 9e. URL 挂马扫描 — 手动指定 URL + 样本中发现/访问的 URL
            try:
                from analyzer.url_scanner import URLScanner
                cfg_url = CONFIG.url_scan
                scan_flag = scan_discovered_urls if scan_discovered_urls is not None \
                    else getattr(cfg_url, 'scan_discovered_urls', True)
                if (urls_to_scan or (scan_flag and report.strings and report.strings.urls)):
                    candidates = list(urls_to_scan or [])
                    manual_urls = set(candidates)
                    auto_candidates = []
                    # 从字符串提取的 URL (全部收集后按可疑度排序, 不再盲取前3个)
                    if scan_flag and report.strings and report.strings.urls:
                        auto_candidates += [u for u in report.strings.urls if u]
                    # 动态访问的 HTTP 请求 URL (host + path) — 行为证据, 不过滤
                    if scan_flag and report.network and report.network.http_requests:
                        for hreq in report.network.http_requests[:5]:
                            try:
                                host = getattr(hreq, 'host', '') or ''
                                path = getattr(hreq, 'path', '') or ''
                                if host and len(host) < 200:
                                    auto_candidates.append(f'http://{host}{path[:100]}')
                            except Exception:
                                continue
                    # 宏/脚本内嵌 URL
                    if scan_flag and getattr(report, '_macro_urls', None):
                        auto_candidates += list(report._macro_urls[:3])

                    # 常见标准/文档/许可证站点: 自动扫描必然 ClickFix/混淆误报
                    _BENIGN_URL_HINTS = (
                        'w3.org', 'ns.adobe.com', 'adobe.com', 'apache.org',
                        'github.com', 'github.io', 'opengl.org', 'sil.org', 'iec.ch',
                        'creativecommons.org', 'gnu.org', 'ietf.org', 'mozilla.org',
                        'wikipedia.org', 'schemas.microsoft.com', 'microsoft.com',
                        'jrsoftware.org', 'inno', 'ishelp',
                        'googleapis.com', '/auth/', 'oauth', 'gstatic.com', 'google.com',
                        '/rdf-syntax-ns', '/xap/', '/licenses/', '/sdk/', '/fonts/',
                    )

                    def _auto_url_is_benign(u):
                        lu = str(u).lower()
                        return any(h in lu for h in _BENIGN_URL_HINTS)

                    def _auto_url_suspicion(u):
                        lu = str(u).lower()
                        score = 0
                        if re.search(r'(?:\d{1,3}\.){3}\d{1,3}', u):
                            score += 40          # IP 直连
                        if '.php' in lu or '.asp' in lu or '.aspx' in lu or '.jsp' in lu:
                            score += 30          # 动态脚本
                        if '?' in lu:
                            score += 10          # 带参数
                        if any(t in lu for t in ('pastebin', 'discord', 'telegram',
                                                 'bit.ly', 'shorturl', '.tk/', '.top/',
                                                 '.xyz/', '.ml/', '.ga/', '.cf/', '.gq/')):
                            score += 30
                        if _auto_url_is_benign(u):
                            score -= 100
                        return score

                    auto_candidates = [u for u in auto_candidates if not _auto_url_is_benign(u)]
                    auto_candidates.sort(key=_auto_url_suspicion, reverse=True)
                    candidates += auto_candidates

                    seen, final = set(), []
                    max_disc = int(getattr(cfg_url, 'max_discovered_urls', 3) or 3)
                    # 手动指定的 URL 永远保留; 自动候选按评分取满
                    ordered = [u for u in candidates if u in manual_urls]
                    ordered += [u for u in candidates if u not in manual_urls][:max_disc]
                    for u in ordered:
                        # 拆分逗号拼接的多个 URL (字符串提取可能把 OAuth scope 列表当单个 URL)
                        for _part in str(u).split(','):
                            _part = _part.strip()
                            if _part and _part not in seen and _part.startswith(('http://', 'https://')):
                                seen.add(_part)
                                final.append(_part)
                    final = final[:10]
                    if final:
                        logger.info(f"[9e] URL 挂马扫描: {len(final)} 个目标")
                        scanner = URLScanner()
                        url_results = []
                        for u in final:
                            if stop_event and stop_event.is_set():
                                break
                            try:
                                url_results.append(scanner.scan(u))
                            except Exception as e_u:
                                logger.debug(f"[9e] URL 扫描失败 {u}: {e_u}")
                        report._url_scans = url_results
                        critical = sum(1 for r in url_results if r.risk_level == 'critical')
                        high = sum(1 for r in url_results if r.risk_level == 'high')
                        if critical or high:
                            logger.warning(f"[9e] URL 扫描: {critical} 个高危 / {high} 个风险 URL")
            except Exception as e_urlscan:
                logger.debug(f"[9e] URL 扫描失败: {e_urlscan}")
            self._publish_web_section(web_state, 'urlscan', report)
            
            # 10. Calculate risk score
            logger.info("[10] Calculating risk score...")
            try:
                report.risk_score, report.risk_level = self._calc_risk(report)
            except Exception as e:
                # Fail-closed: 评分异常绝不能输出低风险误导用户
                logger.error(f"风险评分计算失败(标记为未知): {e}")
                import traceback
                logger.error(traceback.format_exc())
                report.risk_score, report.risk_level = 0, 'unknown'
                report.errors.append(f"Risk calc failed (marked unknown): {e}")
            self._publish_web_section(web_state, 'risk', report)

            # 11. Generate summary
            try:
                report.summary = self._generate_summary(report)
            except Exception as e:
                logger.warning(f"摘要生成失败: {e}")
                report.summary = ''
            report.analysis_duration = time.time() - start_time
            
            # 11b. 构建执行流程树（思维导图）
            try:
                report._execution_tree = self._build_execution_tree(file_path, report)
            except Exception as e:
                logger.warning(f"执行流程树构建失败(不影响报告): {e}")
                report._execution_tree = None

            # 11b2. 构建行为时间线
            try:
                report._behavior_timeline = self._build_behavior_timeline(report)
            except Exception as e:
                logger.warning(f"行为时间线构建失败(不影响报告): {e}")
                report._behavior_timeline = []

            # 11b3. 深度追踪分析 (DeepDive) — 长时程深度关联 + 叙事式报告
            if enable_deep_dive:
                if not report.dynamic:
                    logger.warning("[!] DeepDive 跳过: 动态分析未执行(环境不允许或未启用), 深度分析需要动态数据")
                else:
                    logger.info("[11b3] DeepDive 深度追踪分析...")
                    try:
                        from analyzer.deep_dive import DeepDiveAnalyzer
                        dd = DeepDiveAnalyzer().analyze(
                            report, file_path, stop_event=stop_event)
                        report._deep_dive = dd
                        # 长时观察窗: 动态结束后继续监控慢速样本 (新进程/外联/释放文件)
                        if dd and enable_deep_dive_watch and CONFIG.deep_dive.watch_enabled:
                            logger.info(f"[11b3] DeepDive 长时观察窗: {CONFIG.deep_dive.watch_timeout}s "
                                        f"(每{CONFIG.deep_dive.watch_interval}s)")
                            # 沙箱模式下: 观察窗发现"exe=样本释放文件"的载荷进程立即终止
                            # (计划任务 ITeWS 延迟拉起的 z2VIqs.exe 逃逸场景)
                            def _kill_watch_payload(pid, name, exe):
                                try:
                                    import psutil as _ps
                                    p = _ps.Process(pid)
                                    p.kill()
                                    logger.warning(f"[!] DeepDive观察窗: 终止逃逸载荷 {name} "
                                                   f"(PID={pid}, {exe})")
                                except Exception as e:
                                    logger.debug(f"观察窗终止载荷失败 PID={pid}: {e}")
                            dd = DeepDiveAnalyzer().watch_after(
                                report, dd,
                                timeout=CONFIG.deep_dive.watch_timeout,
                                interval=CONFIG.deep_dive.watch_interval,
                                max_files=CONFIG.deep_dive.max_watch_files,
                                max_processes=CONFIG.deep_dive.max_watch_processes,
                                stop_event=stop_event,
                                on_payload_kill=_kill_watch_payload if CONFIG.sandbox.enabled else None)
                            report._deep_dive = dd
                    except Exception as e:
                        logger.warning(f"[!] DeepDive 分析失败(不影响报告): {e}")
                        report._deep_dive = None
            self._publish_web_section(web_state, 'deepdive', report)
            self._publish_web_section(web_state, 'risk', report)
            
            # 11c. 收集分析日志
            report._analysis_logs = ''
            if _log_handler:
                with _ROOT_LOG_LOCK:
                    try:
                        _log_handler.flush()
                        logging.getLogger().removeHandler(_log_handler)
                        _log_handler.close()
                    except Exception:
                        pass
            try:
                if os.path.isfile(_log_file):
                    with open(_log_file, 'r', encoding='utf-8', errors='replace') as lf:
                        report._analysis_logs = lf.read()
            except Exception:
                report._analysis_logs = '(日志读取失败)'

            # 12. Save reports
            if web_state: web_state.set_status('analyzing', 90, '生成报告中...')
            if save_reports:
                try:
                    self._save_reports(report, web_state=web_state)
                except Exception as e:
                    logger.error(f"报告保存失败: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    report._report_errors = (getattr(report, '_report_errors', '') or '') + f" | 保存: {e}"
            else:
                logger.info("[12] 报告保存已跳过 (save_reports=False)")
                report._report_base = os.path.join(os.path.abspath(CONFIG.report.output_dir), f'{report.scan_id}_{self._safe_report_stem(report)}')

            # 12b. 生成杀毒清理脚本 (只生成, 不自动执行!)
            if enable_cleanup:
                try:
                    from report.cleanup_generator import SystemCleanupGenerator
                    out_dir = CONFIG.cleanup.output_dir or CONFIG.report.output_dir
                    SystemCleanupGenerator(output_dir=out_dir).generate(report, file_path)
                except Exception as e:
                    logger.warning(f"[!] 清理脚本生成失败(不影响报告): {e}")
            
            # 13. Print summary
            try:
                self._print_summary(report)
            except Exception as e:
                logger.warning(f"摘要输出失败: {e}")
            
        except KeyboardInterrupt:
            raise
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            report.errors.append(str(e))
        finally:
            # 出错/正常完成都要恢复VM进程
            if vm_hider is not None:
                try:
                    logger.info("[*] 恢复VM进程...")
                    vm_hider.restore()
                except Exception as ex:
                    logger.warning(f"[!] VM进程恢复失败: {ex}")
            # 清理虚假用户环境
            if fake_env:
                try:
                    fake_env.cleanup()
                except Exception:
                    pass
            # 清理日志 handler
            if _log_handler:
                with _ROOT_LOG_LOCK:
                    try:
                        _log_handler.flush()
                        logging.getLogger().removeHandler(_log_handler)
                        _log_handler.close()
                    except Exception:
                        pass
            if not getattr(report, '_analysis_logs', ''):
                try:
                    if os.path.isfile(_log_file):
                        with open(_log_file, 'r', encoding='utf-8', errors='replace') as lf:
                            report._analysis_logs = lf.read()
                except Exception:
                    pass
            if getattr(report, '_analysis_logs', '') and getattr(report, '_analysis_logs', '') != '(日志读取失败)':
                try:
                    if os.path.isfile(_log_file):
                        os.remove(_log_file)
                except Exception:
                    pass
        
        return report
    
    def _cancelled(self, stop_event) -> bool:
        """统一的取消检查"""
        return bool(stop_event and stop_event.is_set())
    
    @staticmethod
    def _safe_pid(conn) -> int:
        try:
            pid = getattr(conn, 'pid', 0)
            return int(pid) if pid else 0
        except (TypeError, ValueError):
            return 0
    
    def _merge_dynamic_connections(self, traffic: NetworkTraffic, dynamic_behavior):
        """把动态监控线程捕获的连接并入全局流量 (短连接兜底)

        关键: pcap 连接没有 PID, 而动态监控连接有 PID。同名远端已在 pcap 中时
        不能跳过 — 必须把 PID 回填到既有连接, 否则 _filter_traffic_by_target
        会把它们当系统噪音全部滤掉 (sysdiag 重跑回归: 动态连接17条, 报告TCP却为0)。
        """
        if not dynamic_behavior or not traffic:
            return
        try:
            from analyzer.models import NetworkConnection
            dyn_conns = getattr(dynamic_behavior, 'network_connections', []) or []
            if not dyn_conns:
                return
            tcp_existing = {}
            udp_existing = {}
            for c in traffic.tcp_connections:
                tcp_existing.setdefault((getattr(c, 'remote_addr', ''), getattr(c, 'remote_port', 0)), c)
            for c in traffic.udp_connections:
                udp_existing.setdefault((getattr(c, 'remote_addr', ''), getattr(c, 'remote_port', 0)), c)

            from analyzer.network import NetworkAnalyzer as _NA
            added = backfilled = 0
            for dc in dyn_conns:
                try:
                    remote = dc.get('remote', '')
                    if not remote:
                        continue
                    ip, _, port_s = remote.rpartition(':')
                    port = int(port_s) if port_s.isdigit() else 0
                    key = (ip, port)
                    pid = int(dc.get('pid', 0) or 0)
                    kind = str(dc.get('kind', '')).lower()
                    is_udp = 'dgram' in kind
                    is_susp_port = port in getattr(_NA, 'SUSPICIOUS_PORTS', set())
                    target_list = traffic.udp_connections if is_udp else traffic.tcp_connections
                    existing_map = udp_existing if is_udp else tcp_existing

                    if key in existing_map:
                        conn = existing_map[key]
                        if pid and MalwareAnalysisPlatform._safe_pid(conn) == 0:
                            conn.pid = pid
                            conn.status = dc.get('status', getattr(conn, 'status', '') or '')
                            conn.is_suspicious = bool(getattr(conn, 'is_suspicious', False) or is_susp_port)
                            backfilled += 1
                        continue

                    existing_map[key] = NetworkConnection(
                        protocol='UDP' if is_udp else 'TCP',
                        local_addr=dc.get('local', '').rsplit(':', 1)[0] if dc.get('local') else '',
                        local_port=int(dc.get('local', '').rsplit(':', 1)[1]) if dc.get('local') and dc['local'].rsplit(':', 1)[1].isdigit() else 0,
                        remote_addr=ip,
                        remote_port=port,
                        status=dc.get('status', 'ESTABLISHED'),
                        pid=pid,
                        is_suspicious=is_susp_port,
                        suspicion_reason=f'连接到可疑端口 {port}' if is_susp_port else '',
                    )
                    target_list.append(existing_map[key])
                    if is_susp_port:
                        traffic.suspicious_traffic.append({
                            'type': 'suspicious_port',
                            'remote': f'{ip}:{port}',
                            'reason': f'连接到可疑端口 {port}'
                        })
                    added += 1
                except Exception:
                    continue
            if added or backfilled:
                logger.info(f"[+] 合并动态监控连接: +{added} 回填PID×{backfilled} "
                            f"(TCP {len(traffic.tcp_connections)}/UDP {len(traffic.udp_connections)})")
        except Exception as e:
            logger.debug(f"动态连接合并失败: {e}")

    def _filter_traffic_by_target(self, traffic: NetworkTraffic, dynamic_behavior) -> NetworkTraffic:
        """用动态分析监控到的目标 PID 过滤网络流量，只保留恶意样本的连接"""
        if not dynamic_behavior:
            return traffic

        # 收集目标进程及其子进程的所有 PID
        target_pids = set()
        # ⚠ 沙箱自身进程 (frida-helper 等) 即使被补录进 processes_created,
        #   其流量也不是样本行为 — 必须排除 (曾把 frida 注入助手的连接算进样本)
        _SANDBOX_NOISE_NAMES = {
            'frida-helper.exe', 'frida-helper-x86.exe', 'frida-helper-x86_64.exe',
            'frida-server.exe', 'frida-gadget.exe', 'frida-inject.exe',
            'conhost.exe', 'sandboxanalyzer.exe',
        }
        if dynamic_behavior.processes_created:
            for p in dynamic_behavior.processes_created:
                pid = p.get('pid', 0)
                if not pid:
                    continue
                if (p.get('name', '') or '').lower() in _SANDBOX_NOISE_NAMES:
                    continue
                target_pids.add(pid)
        if dynamic_behavior.sandbox_result and dynamic_behavior.sandbox_result.child_processes:
            for cp in dynamic_behavior.sandbox_result.child_processes:
                pid = cp.get('pid', 0)
                if not pid:
                    continue
                if (cp.get('name', '') or '').lower() in _SANDBOX_NOISE_NAMES:
                    continue
                target_pids.add(pid)

        # 动态监控亲眼看到的连接 PID 也纳入目标集合 — 子进程可能未被
        # processes_created 覆盖 (如 WPS 下载器), 否则回填的 PID 仍会被过滤掉
        for dc in (getattr(dynamic_behavior, 'network_connections', []) or []):
            try:
                _dc_pid = int(dc.get('pid', 0) or 0)
                if _dc_pid:
                    target_pids.add(_dc_pid)
            except (TypeError, ValueError):
                continue

        if not target_pids:
            logger.warning("[!] 无法获取目标进程 PID，网络流量不过滤")
            return traffic

        logger.info(f"[*] 按目标 PID 过滤网络流量: {target_pids}")

        # 过滤 TCP 连接（psutil 模式有 pid 字段）
        before_tcp = len(traffic.tcp_connections)
        has_pid_data = any(self._safe_pid(c) for c in traffic.tcp_connections)
        dyn_conns = list(getattr(dynamic_behavior, 'network_connections', []) or [])
        if has_pid_data:
            traffic.tcp_connections = [
                c for c in traffic.tcp_connections
                if self._safe_pid(c) in target_pids
            ]
        elif not dyn_conns and before_tcp:
            # pcap 层没有 PID 归属, 而进程级高频监控(0.2s)未发现任何样本连接 —
            # 这些包基本是系统/DNS/浏览器噪音 (典型: 1.0.0.1:443 / 1.1.1.1:443),
            # 显示为样本网络行为会产生严重误判 (sysdiag 安装包被当成外联后门)。
            logger.warning("[Network] 抓包流量无法归属样本进程, 且进程级监控未发现样本连接 — 按系统噪音清空")
            traffic.tcp_connections = []
            traffic.udp_connections = []
            traffic.dns_queries = []
            traffic.http_requests = []
            traffic.suspicious_traffic = []
            traffic.total_packets = 0
            traffic.total_bytes = 0
            setattr(traffic, '_network_attribution', 'no_sample_connections')
            setattr(traffic, '_network_note',
                    '抓包流量无法归属样本进程, 且进程级监控未发现样本连接; 已按系统噪音隐藏')
            return traffic
        if before_tcp > 0:
            logger.info(f"    TCP: {before_tcp} -> {len(traffic.tcp_connections)} (过滤后)")

        # 过滤 UDP
        has_udp_pid = any(self._safe_pid(c) for c in traffic.udp_connections)
        if has_udp_pid:
            traffic.udp_connections = [
                c for c in traffic.udp_connections
                if self._safe_pid(c) in target_pids
            ]

        # 更新总计数
        traffic.total_packets = (
            len(traffic.dns_queries) +
            len(traffic.http_requests) +
            len(traffic.tcp_connections) +
            len(traffic.udp_connections)
        )

        # 可疑流量 — 保留全部（PID过滤对psutil模式已在上游完成）

        return traffic

    def _populate_network_bytes(self, traffic, dynamic_behavior):
        """用 psutil IO 计数器填充 TCP 连接的收发字节数"""
        if not dynamic_behavior or not traffic or not traffic.tcp_connections:
            return
        try:
            import psutil
            total_sent = 0
            total_recv = 0

            all_pids = set()
            if dynamic_behavior.processes_created:
                for p in dynamic_behavior.processes_created:
                    all_pids.add(p.get('pid', 0))
            if dynamic_behavior.sandbox_result and dynamic_behavior.sandbox_result.child_processes:
                for cp in dynamic_behavior.sandbox_result.child_processes:
                    all_pids.add(cp.get('pid', 0))
            all_pids.discard(0)

            for pid in all_pids:
                try:
                    proc = psutil.Process(pid)
                    io = proc.io_counters()
                    total_sent += io.write_bytes or 0
                    total_recv += io.read_bytes or 0
                except Exception:
                    pass

            conn_count = len(traffic.tcp_connections)
            if conn_count > 0 and (total_sent + total_recv) > 0:
                avg_sent = total_sent // conn_count
                avg_recv = total_recv // conn_count
                for conn in traffic.tcp_connections:
                    conn.bytes_sent = avg_sent
                    conn.bytes_recv = avg_recv
                traffic.total_bytes = total_sent + total_recv
                logger.info(f"[Network] 进程IO: 发送{total_sent//1024}KB, 接收{total_recv//1024}KB, {conn_count}个连接")

        except Exception as e:
            logger.debug(f"Network byte population failed: {e}")

    def _analyze_archive_child(self, child_path: str, filename: str, parent_scan_id: str,
                               enable_dynamic: bool = False, allow_dangerous: bool = False,
                               enable_time_accel: bool = False, fake_user_env: bool = False) -> dict:
        """对压缩包内子文件做完整分析（默认静态；开启后仅动态/网络/内存/深度等保持关闭）"""
        from utils.helpers import is_pe_file_path, calc_entropy, format_size
        result = {
            'filename': filename,
            'path': child_path,
            'size': 0,
            'size_human': '',
            'entropy': 0.0,
            'is_pe': False,
            'is_shellcode': False,
            'is_script': False,
            'sha256': '',
            'pe_info': None,
            'suspicious_strings': [],
            'api_calls': [],
            'urls': [],
            'ips': [],
            'risk_estimate': 'low',
            'risk_score': 0,
            'has_dynamic': False,
            'dynamic_summary': '',
            'full_report': None,
        }
        try:
            child_report = self.analyze(
                child_path,
                enable_dynamic=enable_dynamic,
                allow_dangerous=allow_dangerous,
                no_vm_hide=True,
                enable_time_accel=enable_time_accel,
                fake_user_env=False,
                enable_network=False,
                enable_memory=False,
                enable_deep_dive=False,
                enable_cleanup=False,
                scan_discovered_urls=False,
                urls_to_scan=[],
                save_reports=False,
            )
            if child_report is not None:
                result['full_report'] = child_report
                # 子文件动态分析结果: 升级压缩包报告展示 (进程/文件/风险摘要)
                if getattr(child_report, 'dynamic', None):
                    dyn = child_report.dynamic
                    _procs = getattr(dyn, 'processes_created', []) or []
                    _files = getattr(dyn, 'files_created', []) or []
                    result['has_dynamic'] = True
                    result['dynamic_summary'] = (
                        f"{len(_procs)}进程/{len(_files)}文件/"
                        f"{getattr(child_report, 'risk_level', 'unknown')}"
                    )

            fsize = os.path.getsize(child_path)
            result['size'] = fsize
            result['size_human'] = format_size(fsize)

            import hashlib
            # SHA256 必须覆盖完整文件 (分块流式计算, 避免大文件内存占用)
            _sha = hashlib.sha256()
            with open(child_path, 'rb') as f:
                while True:
                    _chunk = f.read(4 * 1024 * 1024)
                    if not _chunk:
                        break
                    _sha.update(_chunk)
            result['sha256'] = _sha.hexdigest()

            _fi = getattr(child_report, 'file_info', None) if child_report is not None else None
            if _fi is not None and getattr(_fi, 'sha256', ''):
                result['sha256'] = _fi.sha256

            data = b''
            with open(child_path, 'rb') as f:
                data = f.read(min(fsize, 10 * 1024 * 1024))

            if _fi is not None:
                result['entropy'] = float(getattr(_fi, 'entropy', 0.0) or 0.0)
            else:
                result['entropy'] = calc_entropy(data)

            result['is_pe'] = bool(is_pe_file_path(child_path)) or (
                bool(_fi is not None and getattr(child_report, 'pe_info', None) and getattr(child_report.pe_info, 'is_pe', False))
            )

            # 检测脚本文件
            ext = os.path.splitext(filename)[1].lower()
            script_exts = {'.ps1', '.vbs', '.vbe', '.js', '.jse', '.hta', '.bat', '.cmd', '.wsf', '.wsh', '.py', '.pyc'}
            if ext in script_exts:
                result['is_script'] = True

            # Shellcode 检测：高熵 + 非PE + 大小合适（与历史轻量分析一致）
            if not result['is_pe'] and not result['is_script']:
                if fsize > 512 and fsize < 5 * 1024 * 1024:
                    sc_indicators = 0
                    if b'MZ' not in data[:1024] and b'\xfc\x48\x83' in data[:512]:
                        sc_indicators += 1  # x64 shellcode prologue
                    if b'\xfc\xe8' in data[:256]:
                        sc_indicators += 1  # x86 shellcode prologue
                    if b'\x64\x48\x8b\x04\x25' in data[:1024]:
                        sc_indicators += 1  # x64 PEB access
                    if result['entropy'] > 6.5 and sc_indicators > 0:
                        result['is_shellcode'] = True
                    elif result['entropy'] > 7.0 and fsize > 1024 and fsize < 1048576:
                        result['is_shellcode'] = True  # 高熵+尺寸适中→疑似加密载荷

            # PE分析结果优先来自完整分析
            _pe = getattr(child_report, 'pe_info', None) if child_report is not None else None
            if _pe is not None:
                result['pe_info'] = {
                    'architecture': getattr(_pe, 'architecture', '') or '',
                    'is_dll': bool(getattr(_pe, 'is_dll', False)),
                    'sections': len(getattr(_pe, 'sections', []) or []),
                    'suspicious': (getattr(_pe, 'suspicious_features', []) or [])[:5],
                    'imphash': getattr(_pe, 'imphash', '') or '',
                }
            elif result['is_pe']:
                try:
                    pe = self.pe_analyzer(child_path)
                    pe_info = pe.analyze()
                    result['pe_info'] = {
                        'architecture': pe_info.architecture if pe_info else '',
                        'is_dll': pe_info.is_dll if pe_info else False,
                        'sections': len(pe_info.sections) if pe_info else 0,
                        'suspicious': pe_info.suspicious_features[:5] if pe_info else [],
                        'imphash': pe_info.imphash if pe_info else '',
                    }
                except Exception:
                    pass

            # 字符串提取优先来自完整分析
            _st = getattr(child_report, 'strings', None) if child_report is not None else None
            if _st is not None:
                result['suspicious_strings'] = (getattr(_st, 'suspicious_strings', []) or [])[:15]
                result['api_calls'] = [a for a in (getattr(_st, 'api_calls', []) or [])[:15] if len(a) > 3 and not a.startswith('_')]
                result['urls'] = (getattr(_st, 'urls', []) or [])[:10]
                result['ips'] = (getattr(_st, 'ips', []) or [])[:10]
            else:
                try:
                    strings_analyzer = self.string_analyzer(data)
                    st = strings_analyzer.analyze()
                    result['suspicious_strings'] = st.suspicious_strings[:15] if st else []
                    result['api_calls'] = [a for a in (st.api_calls or [])[:15] if len(a) > 3 and not a.startswith('_')]
                    result['urls'] = (st.urls or [])[:10] if st else []
                    result['ips'] = (st.ips or [])[:10] if st else []
                except Exception:
                    pass

            # 威胁情报优先来自完整分析, 否则本地轻量查询
            _ti = getattr(child_report, 'threat_intel', None) if child_report is not None else None
            if _ti is not None:
                if 'malicious' in (getattr(_ti, 'threat_labels', []) or []):
                    result['threat_malicious'] = True
                    result['threat_family'] = getattr(_ti, 'family', '') or ''
            elif result['sha256']:
                try:
                    ti = self.threat_intel.query_all(result['sha256'])
                    if ti and 'malicious' in (ti.threat_labels or []):
                        result['threat_malicious'] = True
                        result['threat_family'] = ti.family or ''
                except Exception:
                    pass

            # 风险评分：完整分析已计算则直接采用, 否则退回轻量启发式
            if child_report is not None:
                result['risk_score'] = int(getattr(child_report, 'risk_score', 0) or 0)
                result['risk_estimate'] = getattr(child_report, 'risk_level', 'low') or 'low'
            else:
                risk = 0
                if result['entropy'] > 7.5: risk += 30
                elif result['entropy'] > 6.5: risk += 15
                if result.get('pe_info') and result['pe_info'].get('suspicious'): risk += len(result['pe_info']['suspicious']) * 10
                if result.get('suspicious_strings'): risk += min(len(result['suspicious_strings']) * 3, 20)
                if result.get('threat_malicious'): risk += 25
                if result.get('is_shellcode'): risk += 20
                if result.get('is_script'): risk += 10
                result['risk_estimate'] = 'critical' if risk >= 60 else 'high' if risk >= 40 else 'medium' if risk >= 20 else 'low'
                result['risk_score'] = min(risk, 100)

        except Exception as e:
            result['error'] = str(e)
        return result

    def _calc_risk(self, report: AnalysisReport) -> tuple:
        """计算风险评分 — 综合所有检测维度的加权打分"""
        score = 0
        items = []
        breakdown = {}

        def add(category, label, points):
            nonlocal score
            if points == 0:
                return
            score += points
            breakdown[category] = breakdown.get(category, 0) + points
            items.append({'category': category, 'score': points, 'detail': label})

        # ===== 信誉: 合法签名 → 分级降权 (不再强制低风险) =====
        # 签名盗用/白加黑样本很常见, 因此:
        #   - 可信厂商签名降 20 分; 一般有效签名只降 10 分;
        #   - 删除了旧的 "有签名且 score<50 强制 low" 规则, 避免漏报。
        _TRUSTED_SIGNERS = (
            'microsoft', 'google', 'apple', 'adobe', 'oracle', 'vmware',
            'intel', 'amd', 'nvidia', 'mozilla', 'dell', 'hp', 'lenovo',
            'samsung', 'amazon', 'red hat', 'canonical', 'ibm', 'cisco',
        )
        if report.pe_info and report.pe_info.digital_signature:
            sig = report.pe_info.digital_signature
            signer = sig.get('signer', '')
            if sig.get('has_signature') and signer and signer != 'present':
                _signer_low = str(signer).lower()
                if any(_t in _signer_low for _t in _TRUSTED_SIGNERS):
                    add('信誉', f'可信厂商签名降权: {signer}', -20)
                else:
                    add('信誉', f'一般有效签名降权: {signer}', -10)

        # ===== 文件特征 =====
        if report.file_info:
            _fsize = getattr(report.file_info, 'size', 0) or 0
            if report.file_info.entropy > 7.5:
                # 大文件安装包整体高熵很常见 (压缩/内嵌资源), 权重减半
                _ent_points = 10 if _fsize > 50 * 1024 * 1024 else 20
                add('文件特征', f'熵值 {report.file_info.entropy:.2f} (>7.5)', _ent_points)
            elif report.file_info.entropy > 6.5:
                add('文件特征', f'熵值 {report.file_info.entropy:.2f} (>6.5)', 10)

        if report.pe_info:
            add('文件特征', f'PE可疑特征 ×{len(report.pe_info.suspicious_features)}', len(report.pe_info.suspicious_features) * 10)
            for feat in report.pe_info.suspicious_features:
                if 'Packed' in feat or 'packed' in feat:
                    add('文件特征', f'加壳特征: {feat}', 25)
                if 'Encrypted payload' in feat:
                    add('文件特征', f'加密载荷特征: {feat}', 15)

        # ===== 字符串/IoC =====
        if report.strings:
            add('字符串/IoC', f'可疑字符串 ×{len(report.strings.suspicious_strings)}', min(len(report.strings.suspicious_strings) * 2, 20))
            add('字符串/IoC', f'URL ×{len(report.strings.urls)}', min(len(report.strings.urls) * 2, 10))

        # ===== 威胁情报 =====
        if report.threat_intel:
            if 'malicious' in report.threat_intel.threat_labels:
                add('威胁情报', '多引擎标记 malicious', 25)
            if report.threat_intel.detection_rate and report.threat_intel.detection_rate > 0.3:
                add('威胁情报', f'检出率 {report.threat_intel.detection_rate:.0%}', min(int(report.threat_intel.detection_rate * 30), 20))

        # 本地 IoC 命中
        ioc_hits = getattr(report, '_ioc_hits', {}) or {}
        ioc_total = ioc_hits.get('total_hits', 0)
        if ioc_total > 0:
            add('威胁情报', f'本地IoC命中 ×{ioc_total}', min(ioc_total * 5, 25))

        # ===== 高级行为检测 — 环境对抗 =====
        if report.advanced_behavior and hasattr(report.advanced_behavior, 'anti_vm'):
            ab = report.advanced_behavior
            add('高级行为', f'反沙箱 ×{len(ab.anti_sandbox or [])}', min(len(ab.anti_sandbox or []) * 5, 25))
            add('高级行为', f'反VM ×{len(ab.anti_vm or [])}', min(len(ab.anti_vm or []) * 5, 25))
            add('高级行为', f'反调试 ×{len(ab.anti_debug or [])}', min(len(ab.anti_debug or []) * 5, 25))
            add('高级行为', f'反分析 ×{len(ab.anti_analysis or [])}', min(len(ab.anti_analysis or []) * 4, 20))
            add('高级行为', f'时序规避 ×{len(ab.timing_evasion or [])}', min(len(ab.timing_evasion or []) * 4, 20))

            # ===== 高级行为检测 — 提权/绕过 =====
            add('高级行为', f'提权 ×{len(ab.privilege_escalation or [])}', min(len(ab.privilege_escalation or []) * 10, 30))
            add('高级行为', f'UAC绕过 ×{len(ab.uac_bypass or [])}', min(len(ab.uac_bypass or []) * 12, 25))
            add('高级行为', f'令牌操纵 ×{len(ab.token_manipulation or [])}', min(len(ab.token_manipulation or []) * 8, 20))

            # ===== 高级行为检测 — 注入/劫持 =====
            add('高级行为', f'进程注入 ×{len(ab.process_injection or [])}', min(len(ab.process_injection or []) * 10, 30))
            add('高级行为', f'进程镂空 ×{len(ab.process_hollowing or [])}', min(len(ab.process_hollowing or []) * 18, 35))
            add('高级行为', f'APC注入 ×{len(ab.apc_injection or [])}', min(len(ab.apc_injection or []) * 10, 25))
            add('高级行为', f'线程劫持 ×{len(ab.thread_hijacking or [])}', min(len(ab.thread_hijacking or []) * 12, 25))

            # ===== 高级行为检测 — 窃取/监控 =====
            add('高级行为', f'凭证窃取 ×{len(ab.credential_theft or [])}', min(len(ab.credential_theft or []) * 10, 30))
            add('高级行为', f'键盘记录 ×{len(ab.keylogging or [])}', min(len(ab.keylogging or []) * 12, 30))
            add('高级行为', f'剪贴板监控 ×{len(ab.clipboard_monitoring or [])}', min(len(ab.clipboard_monitoring or []) * 8, 20))
            add('高级行为', f'截屏 ×{len(ab.screenshot_capture or [])}', min(len(ab.screenshot_capture or []) * 6, 15))
            add('高级行为', f'浏览器数据窃取 ×{len(ab.browser_data_theft or [])}', min(len(ab.browser_data_theft or []) * 8, 20))
            add('高级行为', f'隐写术 ×{len(ab.steganography or [])}', min(len(ab.steganography or []) * 6, 15))

            # ===== 高级行为检测 — 破坏/勒索 =====
            if ab.ransomware_indicators:
                add('高级行为', f'勒索指标 ×{len(ab.ransomware_indicators)}', min(len(ab.ransomware_indicators) * 15, 35))
            if ab.rootkit_indicators:
                add('高级行为', f'Rootkit指标 ×{len(ab.rootkit_indicators)}', min(len(ab.rootkit_indicators) * 18, 35))
            if ab.bootkit_indicators:
                add('高级行为', f'Bootkit指标 ×{len(ab.bootkit_indicators)}', min(len(ab.bootkit_indicators) * 22, 40))
            if ab.wiper_indicators:
                add('高级行为', f'Wiper指标 ×{len(ab.wiper_indicators)}', min(len(ab.wiper_indicators) * 15, 30))
            if ab.file_encryption:
                add('高级行为', f'文件加密 ×{len(ab.file_encryption)}', min(len(ab.file_encryption) * 12, 25))

            # ===== 高级行为检测 — 通信/传播 =====
            add('高级行为', f'C2通信 ×{len(ab.c2_communication or [])}', min(len(ab.c2_communication or []) * 8, 25))
            add('高级行为', f'横向移动 ×{len(ab.lateral_movement or [])}', min(len(ab.lateral_movement or []) * 12, 30))
            if ab.dga_detected:
                add('高级行为', 'DGA域名生成', 15)
            add('高级行为', f'域名生成 ×{len(ab.domain_generation or [])}', min(len(ab.domain_generation or []) * 5, 15))

            # ===== 高级行为检测 — 攻击链行为 =====
            add('高级行为', f'攻击链行为 ×{len(ab.attack_chain or [])}', min(len(ab.attack_chain or []) * 8, 25))

        # ===== 破坏性行为 =====
        if report.destruction:
            d = report.destruction
            if d.destruction_level == 'destructive':
                add('破坏行为', '破坏等级 destructive', 40)
            elif d.destruction_level == 'high':
                add('破坏行为', '破坏等级 high', 25)
            elif d.destruction_level == 'medium':
                add('破坏行为', '破坏等级 medium', 15)
            if d.mbr_access:
                add('破坏行为', 'MBR访问', 20)
            if d.shadow_copy_delete:
                add('破坏行为', '卷影副本删除', 15)
            if getattr(d, 'raw_disk_access', False):
                add('破坏行为', '磁盘直接访问', 15)
            if getattr(d, 'firewall_disable', False):
                add('破坏行为', '防火墙禁用', 10)
            add('破坏行为', f'终止AV ×{len(getattr(d, "av_termination", []) or [])}', min(len(getattr(d, 'av_termination', []) or []) * 10, 25))
            add('破坏行为', f'终止EDR ×{len(getattr(d, "edr_termination", []) or [])}', min(len(getattr(d, 'edr_termination', []) or []) * 12, 30))
            add('破坏行为', f'Defender注册表禁用 ×{len(getattr(d, "defender_registry_disable", []) or [])}', min(len(getattr(d, 'defender_registry_disable', []) or []) * 8, 20))
            add('破坏行为', f'危险驱动加载 ×{len(getattr(d, "dangerous_driver_load", []) or [])}', min(len(getattr(d, 'dangerous_driver_load', []) or []) * 15, 30))
            add('破坏行为', f'备份删除命令 ×{len(getattr(d, "backup_delete_commands", []) or [])}', min(len(getattr(d, 'backup_delete_commands', []) or []) * 5, 15))
            add('破坏行为', f'服务停止 ×{len(getattr(d, "service_stop", []) or [])}', min(len(getattr(d, 'service_stop', []) or []) * 4, 10))
            add('破坏行为', f'服务禁用 ×{len(getattr(d, "service_disable", []) or [])}', min(len(getattr(d, 'service_disable', []) or []) * 5, 12))
            add('破坏行为', f'服务删除 ×{len(getattr(d, "service_delete", []) or [])}', min(len(getattr(d, 'service_delete', []) or []) * 8, 20))
            if getattr(d, 'safe_mode_override', False):
                add('破坏行为', '安全模式覆写', 15)
            if getattr(d, 'hosts_file_modify', False):
                add('破坏行为', 'Hosts文件修改', 10)
            add('破坏行为', f'UAC绕过尝试 ×{len(getattr(d, "uac_bypass_attempts", []) or [])}', min(len(getattr(d, 'uac_bypass_attempts', []) or []) * 10, 20))

        # ===== 动态行为 =====
        if report.dynamic:
            add('动态行为', f'创建进程 ×{len(report.dynamic.processes_created)}', len(report.dynamic.processes_created) * 3)
            add('动态行为', f'创建文件 ×{len(report.dynamic.files_created)}', len(report.dynamic.files_created) * 3)
            if any('self_delete' in str(p.get('name', '')) for p in report.dynamic.processes_created):
                add('动态行为', '样本自删除', 25)
            snapshots = getattr(report.dynamic, 'memory_snapshots', [])
            if snapshots:
                # ⚠ 快照是同一进程的多次采样, 不是独立证据: 37 次采样直接 *20=740
                # 会把评分顶到 100, 完全掩盖其他维度 — 封顶 20 分
                add('动态行为', f'内存快照 ×{len(snapshots)}', min(len(snapshots) * 2, 20))
            if report.dynamic.sandbox_result:
                sr = report.dynamic.sandbox_result
                if any(r'\Run' in r or r'\RunOnce' in r for r in sr.registry_created):
                    add('动态行为', 'Run/RunOnce 持久化', 20)
                add('动态行为', f'注册表新增 ×{len(sr.registry_created)}', len(sr.registry_created) * 3)
                if sr.was_terminated:
                    add('动态行为', '进程被沙箱终止', 5)
            # 网络连接
            if report.network and report.network.tcp_connections:
                add('动态行为', f'TCP连接 ×{len(report.network.tcp_connections)}', min(len(report.network.tcp_connections), 15))
            if report.network and report.network.suspicious_traffic:
                add('动态行为', f'可疑流量 ×{len(report.network.suspicious_traffic)}', min(len(report.network.suspicious_traffic) * 5, 20))

            # ===== Frida 内存保护监控（云沙箱对照: RW→RX载荷解密/DEP绕过/ROP喷射/远程注入/枚举/睡眠）=====
            am = report.api_monitor
            if am is not None:
                mem_events = getattr(am, '_memprot_events', []) or []
                mem_stats = getattr(am, '_memprot_stats', {}) or {}
                if mem_events:
                    rwrx = sum(1 for e in mem_events if e.get('rw_to_rx'))
                    rwx = sum(1 for e in mem_events if e.get('rwx_alloc'))
                    inj = sum(1 for e in mem_events if e.get('injection'))
                    dep = sum(1 for e in mem_events if e.get('dep_bypass'))
                    rop = sum(1 for e in mem_events if e.get('rop_like'))
                    huge = sum(1 for e in mem_events if e.get('huge_alloc'))
                    if rwrx:
                        add('动态行为', f'RW→RX载荷解密 ×{rwrx}', min(rwrx * 15, 30))  # 载荷解密执行(核心恶意特征)
                    if rwx:
                        add('动态行为', f'RWX分配 ×{rwx}', min(rwx * 10, 20))   # RWX 分配
                    if rop:
                        # 超大 RWX 分配 = 云沙箱 stack_dep_bypass/heap_dep_bypass 对应特征
                        add('动态行为', f'DEP绕过/ROP喷射 ×{rop}', min(rop * 25, 35))
                    elif dep:
                        add('动态行为', f'DEP绕过(RWX) ×{dep}', min(dep * 12, 25))
                    if huge and not dep:
                        # 非 RWX 的超大内存分配同样有内存喷射嫌疑, 但权重较低
                        add('动态行为', f'超大内存分配 ×{huge}', min(huge * 8, 15))
                    if inj:
                        add('动态行为', f'远程注入链 ×{inj}', min(inj * 10, 25))   # 远程注入链
                    report._memprot_summary = {
                        'rw_to_rx': rwrx, 'rwx_alloc': rwx, 'injection': inj,
                        'dep_bypass': dep, 'rop_like': rop, 'huge_alloc': huge,
                        'events': mem_events[:50],
                    }
                enum_n = mem_stats.get('enum_snapshot_count', 0) or 0
                if enum_n >= 20:
                    add('动态行为', f'高频进程枚举 ×{enum_n}', 15)  # 高频进程枚举(反沙箱)
                    if not getattr(report, '_memprot_summary', None):
                        report._memprot_summary = {}
                    report._memprot_summary['enum_snapshot_count'] = enum_n
                sleep_ms = mem_stats.get('sleep_total_ms', 0) or 0
                if sleep_ms >= 60000:
                    add('动态行为', f'长时间睡眠 {sleep_ms}ms', 15)  # 长时间睡眠(时间规避)
                    if not hasattr(report, '_memprot_summary') or not report._memprot_summary:
                        report._memprot_summary = {}
                    report._memprot_summary['sleep_total_ms'] = sleep_ms
                if getattr(report, '_memprot_summary', None):
                    logger.warning(f"[Risk] Frida内存监控: {report._memprot_summary}")

                # ===== DLL 调用监控 (非系统DLL函数调用 = 释放/加载恶意DLL的行为) =====
                dll_calls = getattr(am, '_dll_calls', {}) or {}
                if dll_calls:
                    total_dll_calls = sum(dll_calls.values())
                    report._dll_call_summary = {
                        'total_calls': total_dll_calls,
                        'functions': sorted(dll_calls.items(), key=lambda x: -x[1])[:100],
                    }
                    # 被调用的非系统 DLL 数量本身就是风险信号
                    dlls = set(d for d, _ in dll_calls)
                    if len(dlls) >= 2:
                        add('动态行为', f'非系统DLL调用种类 ×{len(dlls)}', min(len(dlls) * 3, 15))
                    # 常见恶意/可疑 DLL 名命中
                    suspicious_dll_names = ['payload', 'beacon', 'inject', 'shell', 'loader',
                                            'hook', 'steal', 'crypt', 'silver', 'domo', 'nvgpu']
                    hits = [d for d in dlls if any(k in d.lower() for k in suspicious_dll_names)]
                    if hits:
                        add('动态行为', f'可疑DLL名 ×{len(hits)}', min(len(hits) * 5, 20))
                        report._dll_call_summary['suspicious_dlls'] = hits
                    spoof_actions = getattr(am, '_spoof_actions', []) or []
                    if spoof_actions:
                        report._spoof_summary = {
                            'count': len(spoof_actions),
                            'apis': sorted(set(a.get('api', '') for a in spoof_actions)),
                        }
                        logger.info(f"[Risk] 欺骗引擎: 假反馈 {len(spoof_actions)} 次")

                    # ===== AMSI / 特权 / 注册表 hive 专项监控计分 =====
                    _privs = getattr(am, '_priv_events', []) or []
                    _enabled_privs = [p for p in _privs if p.get('action') == 'ENABLED']
                    if _enabled_privs:
                        add('动态行为', f'特权启用 ×{len(_enabled_privs)} (SeDebug/SeBackup等)',
                            min(len(_enabled_privs) * 8, 20))
                    _regsaves = getattr(am, '_regsave_events', []) or []
                    if _regsaves:
                        add('动态行为', f'注册表hive保存 ×{len(_regsaves)} (离线凭据窃取)',
                            min(len(_regsaves) * 10, 25))
                    _amsi_events = getattr(am, '_amsi_events', []) or []
                    if any(e.get('api') == 'AmsiUninitialize' for e in _amsi_events):
                        add('动态行为', 'AMSI 卸载调用 (绕过信号)', 12)

        # ===== 内存取证 =====
        if report.memory:
            exit_diag = getattr(report.memory, 'exit_diagnosis', {}) or {}
            if getattr(report.memory, 'process_exited', False) and exit_diag:
                _leak_n = exit_diag.get('leaked_allocations', 0) or 0
                if _leak_n >= 3 and exit_diag.get('alloc_calls', 0) >= 3:
                    add('内存取证', f'内存分配未释放 ×{_leak_n} (驻留/泄漏特征)', min(_leak_n * 3, 15))
                # ⚠ 若 memprot 事件已在"动态行为"中计分, 退出诊断不再重复加分
                if not getattr(report, '_memprot_summary', None):
                    _exit_dep = (exit_diag.get('dep_bypass', 0) or 0) + (exit_diag.get('rop_like', 0) or 0)
                    if _exit_dep:
                        add('内存取证', f'进程退出前捕获DEP绕过/ROP事件 ×{_exit_dep}', min(_exit_dep * 12, 25))
                    _exit_rwrx = exit_diag.get('rw_to_rx', 0) or 0
                    if _exit_rwrx:
                        add('内存取证', f'进程退出前捕获RW→RX载荷解密 ×{_exit_rwrx}', min(_exit_rwrx * 8, 16))
            _from_snapshots = bool(getattr(report.memory, '_from_snapshots', False))
            if not _from_snapshots:
                add('内存取证', f'RWX区域 ×{len(report.memory.rwx_regions)}', len(report.memory.rwx_regions) * 15)
                if report.memory.shellcode_found:
                    add('内存取证', 'Shellcode', 20)
                if report.memory.pe_in_memory:
                    add('内存取证', 'PE注入', 25)
            # 执行期快照派生证据已在"动态行为 → 内存快照×N"中计分, 不重复加分
            if report.memory.openpgp_found:
                add('内存取证', 'OpenPGP载荷', 20)
            if report.memory.zlib_found:
                add('内存取证', 'zlib压缩载荷', 15)
            if report.memory.multi_payload:
                add('内存取证', '复合载荷', 30)
            if report.memory.heavens_gate:
                add('内存取证', f"Heaven's Gate ×{len(report.memory.heavens_gate)}", len(report.memory.heavens_gate) * 8)
            if report.memory.iat_hooks:
                add('内存取证', f'IAT Hook ×{len(report.memory.iat_hooks)}', len(report.memory.iat_hooks) * 10)
            if report.memory.peb_anomalies:
                add('内存取证', f'PEB异常 ×{len(report.memory.peb_anomalies)}', len(report.memory.peb_anomalies) * 10)
            if report.memory.seh_overwrite:
                add('内存取证', f'SEH覆写 ×{len(report.memory.seh_overwrite)}', len(report.memory.seh_overwrite) * 8)
            if report.memory.anti_dump_measures:
                add('内存取证', f'反Dump ×{len(report.memory.anti_dump_measures)}', len(report.memory.anti_dump_measures) * 8)
            if report.memory.api_unhooking:
                add('内存取证', f'API Unhooking ×{len(report.memory.api_unhooking)}', len(report.memory.api_unhooking) * 12)
            if report.memory.kernel_backdoor:
                add('内存取证', f'内核后门 ×{len(report.memory.kernel_backdoor)}', len(report.memory.kernel_backdoor) * 20)
            if report.memory.hidden_regions:
                add('内存取证', f'隐藏区域 ×{len(report.memory.hidden_regions)}', len(report.memory.hidden_regions) * 10)

        # ===== YARA / Sigma / 社区签名 =====
        yara_hits = getattr(report, '_yara_matches', []) or []
        if yara_hits:
            add('签名规则', f'YARA命中 ×{len(yara_hits)}', min(len(yara_hits) * 5, 25))
        sigma_hits = getattr(report, '_sigma_matches', []) or []
        if sigma_hits:
            add('签名规则', f'Sigma命中 ×{len(sigma_hits)}', min(len(sigma_hits) * 3, 15))
        comm_sigs = getattr(report, '_community_signatures', []) or []
        if comm_sigs:
            add('签名规则', f'社区签名命中 ×{len(comm_sigs)}', min(len(comm_sigs) * 2, 10))

        # ===== 勒索/磁盘取证 =====
        disk_forensics = getattr(report, '_disk_forensics', {}) or {}
        if any(disk_forensics.values()):
            add('磁盘取证', f'磁盘取证指标 ×{sum(len(v) for v in disk_forensics.values())}', sum(len(v) for v in disk_forensics.values()) * 5)
        if getattr(report, '_vss_deleted', False):
            add('磁盘取证', '卷影副本删除', 20)

        # ===== 家族识别 =====
        if report.malware_family and report.malware_family.primary_confidence > 60:
            has_specific = False
            if report.malware_family.all_families:
                family_core_words = ['mimikatz', 'mimilib', 'sekurlsa', 'silverfox',
                    'emotet', 'trickbot', 'qakbot', 'cobalt', 'meterpreter', 'dridex',
                    'redline', 'agenttesla', 'sliver', 'lazarus', 'wannacry', 'farfli', 'gh0st',
                    'xworm', 'remcos', 'asyncrat', 'nanocore', 'formbook', 'agenttesla']
                primary_name = str(report.malware_family.primary_family or '').lower()
                if any(fc in primary_name for fc in family_core_words):
                    has_specific = True
                for ind in report.malware_family.all_families[0].indicators:
                    if any(fc in ind.lower() for fc in family_core_words):
                        has_specific = True
                        break
            if has_specific:
                add('家族识别', '高置信度特定家族', 20)
            else:
                add('家族识别', '家族识别(非特定)', 5)

        # ===== URL 挂马扫描 =====
        url_scans = getattr(report, '_url_scans', None) or []
        if url_scans:
            # ⚠ 自动扫描样本字符串里的 URL 时, 常见标准/文档站点会产生 ClickFix/混淆误报,
            # 多个 critical 各加 30 分会把良性文件顶成 CRITICAL。整类封顶 30 分。
            url_points = 0
            url_danger = []
            for ur in url_scans:
                if ur.risk_level == 'critical':
                    url_points += 30
                    url_danger.append(f'critical: {getattr(ur, "url", "")}')
                elif ur.risk_level == 'high':
                    url_points += 20
                    url_danger.append(f'high: {getattr(ur, "url", "")}')
                elif ur.risk_level == 'medium':
                    url_points += 10
                    url_danger.append(f'medium: {getattr(ur, "url", "")}')
                if ur.ioc_hits:
                    url_points += min(len(ur.ioc_hits) * 5, 10)
                    url_danger.append(f'IoC×{len(ur.ioc_hits)}: {getattr(ur, "url", "")}')
            if url_points:
                add('URL扫描', f'URL扫描命中 {len(url_danger)} 项', min(url_points, 30))
            if any(r.risk_level in ('high', 'critical') for r in url_scans):
                logger.warning(f"[Risk] URL挂马扫描: {sum(1 for r in url_scans if r.risk_level in ('high','critical'))} 个危险 URL")

        # ===== 安装程序语义降权 (正常软件安装流程 — 卸载注册表/快捷方式/Program Files) =====
        # 背景: NSIS/InnoSetup 安装器 + 写卸载注册表 + 建快捷方式 + 释放 Program Files
        #       是数百万合法软件的标准安装流程, 不应单独拉高风险评分 (套壳木马除外)。
        try:
            _dyn = report.dynamic
            _file_paths = []
            if _dyn is not None:
                for _it in (list(getattr(_dyn, 'files_created', None) or [])
                            + list(getattr(_dyn, 'files_modified', None) or [])):
                    if isinstance(_it, str):
                        _file_paths.append(_it)
                    elif isinstance(_it, dict):
                        for _k in ('path', 'file', 'target', 'name'):
                            if _it.get(_k):
                                _file_paths.append(str(_it[_k]))
                                break
            _reg_keys = []
            if _dyn is not None:
                for _it in (list(getattr(_dyn, 'registry_created', None) or [])
                            + list(getattr(_dyn, 'registry_modified', None) or [])):
                    if isinstance(_it, str):
                        _reg_keys.append(_it)
                    elif isinstance(_it, dict):
                        for _k in ('key', 'path', 'name'):
                            if _it.get(_k):
                                _reg_keys.append(str(_it[_k]))
                                break
            _fl = ' '.join(_file_paths).lower()
            _rl = ' '.join(_reg_keys).lower()
            _installer_hints = 0
            if 'program files' in _fl:
                _installer_hints += 1
            if 'start menu' in _fl and ('.lnk' in _fl or '.url' in _fl):
                _installer_hints += 1
            if 'uninstall' in _rl:
                _installer_hints += 1
            _stext = ''
            if report.strings is not None:
                _stext = ' '.join(str(s) for s in (
                    list(getattr(report.strings, 'suspicious_strings', None) or [])
                    + list(getattr(report.strings, 'file_paths', None) or [])))
            _stext_low = _stext.lower()
            if ('nullsoft' in _stext_low or 'nsis' in _stext_low
                    or 'innosetup' in _stext_low or 'inno setup' in _stext_low):
                _installer_hints += 1
            _malicious_core = 0
            _ab = report.advanced_behavior
            if _ab is not None:
                _malicious_core = (
                    len(getattr(_ab, 'process_injection', None) or [])
                    + len(getattr(_ab, 'process_hollowing', None) or [])
                    + len(getattr(_ab, 'credential_theft', None) or [])
                    + len(getattr(_ab, 'keylogging', None) or [])
                    + len(getattr(_ab, 'ransomware_indicators', None) or [])
                    + len(getattr(_ab, 'rootkit_indicators', None) or [])
                    + len(getattr(_ab, 'bootkit_indicators', None) or [])
                )
            if _installer_hints >= 3 and _malicious_core == 0:
                add('安装语义', f'正常软件安装流程 (卸载注册表/快捷方式/Program Files ×{_installer_hints})', -30)
        except Exception:
            pass

        score = min(score, 100)
        score = max(score, 0)

        level = 'critical' if score >= 80 else 'high' if score >= 60 else 'medium' if score >= 40 else 'low'

        report._risk_breakdown = {
            'items': items,
            'total': score,
        }
        return score, level
    
    def _generate_summary(self, report: AnalysisReport) -> str:
        parts = []
        if report.risk_level == 'critical': parts.append("⚠️ Highly suspicious, immediate isolation recommended")
        elif report.risk_level == 'high': parts.append("🔴 High risk, multiple suspicious features")
        elif report.risk_level == 'medium': parts.append("🟡 Medium risk, further analysis recommended")
        elif report.risk_level == 'unknown': parts.append("❓ Risk scoring unavailable — treat as suspicious until reviewed")
        else: parts.append("🟢 Low risk, no obvious malicious features")

        # 自删除检测
        if report.dynamic and any('self_delete' in str(p.get('name', '')) for p in report.dynamic.processes_created):
            parts.append("🚨 原始样本自删除（反取证）")
        
        if report.malware_family and report.malware_family.primary_family != 'Unknown':
            _conf = report.malware_family.primary_confidence or 0
            _fam_note = f"Family: {report.malware_family.primary_family} ({_conf}%)"
            if _conf < 60:
                _fam_note += " — 低置信度, 可能误判 (仅作参考, 不排除正常软件)"
            parts.append(_fam_note)

        # 崩溃归因: 样本崩溃 → 行为链不完整, 崩溃后行为(WER文件/内存泄漏/单次SYN)降权
        try:
            _sr = getattr(report.dynamic, 'sandbox_result', None) if report.dynamic else None
            if _sr is not None and getattr(_sr, 'crashed', False):
                _cc = getattr(_sr, 'crash_code', 0)
                parts.append(f"💥 样本崩溃 (NTSTATUS=0x{_cc:08X}) — 崩溃后行为按降权处理")
        except Exception:
            pass

        # 安装程序语义标注
        try:
            _bd = getattr(report, '_risk_breakdown', {}) or {}
            if any(it.get('category') == '安装语义' for it in (_bd.get('items') or [])):
                parts.append("📦 安装程序语义: 符合正常软件安装流程 (卸载注册表/快捷方式/Program Files)")
        except Exception:
            pass
        
        # 反VM/反沙箱检测警告
        if report.advanced_behavior:
            ab = report.advanced_behavior
            if ab.anti_vm:
                parts.append(f"🛡️ Anti-VM detected ({len(ab.anti_vm)} techniques)")
            if ab.anti_sandbox:
                parts.append(f"🛡️ Anti-Sandbox detected ({len(ab.anti_sandbox)} techniques)")
            if ab.anti_debug:
                parts.append(f"🛡️ Anti-Debug detected ({len(ab.anti_debug)} techniques)")
            if ab.ransomware_indicators:
                parts.append("Ransomware indicators detected")
        
        if report.destruction and report.destruction.mbr_access:
            parts.append("MBR/Disk access detected")
        
        return " | ".join(parts)

    def _publish_web_section(self, web_state, name: str, report):
        """流式发布一个报告板块到 Web 端 (片段 + 半成品落盘)"""
        if not web_state:
            return
        try:
            # 部分 builder 方法名/签名与 _build_{name}_section 约定不一致, 单独适配
            if name == 'overview':
                risk_levels = {'critical': '严重', 'high': '高危', 'medium': '中', 'low': '低', 'unknown': '未知'}
                risk_color_map = {'critical': '#dc2626', 'high': '#ef4444', 'medium': '#f59e0b', 'low': '#22c55e', 'unknown': '#6b7280'}
                html = self.html_generator._build_overview(
                    report, risk_levels.get(report.risk_level, '未知'),
                    risk_color_map.get(report.risk_level, '#6b7280'))
            elif name == 'risk':
                html = self.html_generator._build_risk_score_detail(report)
            elif name == 'yara':
                html = self.html_generator._build_yara_section(
                    getattr(report, '_yara_matches', None) or [])
            elif name == 'sigma':
                html = self.html_generator._build_sigma_section(
                    getattr(report, '_sigma_matches', None) or [])
            else:
                builder = getattr(self.html_generator, f'_build_{name}_section', None)
                html = builder(report) if builder else None
            if html:
                web_state.set_section(name, html)
        except Exception as e:
            logger.debug(f"Web 板块发布失败 ({name}): {e}")

    @staticmethod
    def _safe_report_stem(report) -> str:
        """从样本名生成安全的报告文件名字干"""
        try:
            if getattr(report, 'file_info', None) and getattr(report.file_info, 'name', ''):
                name = report.file_info.name
            else:
                name = os.path.basename(getattr(report, '_original_path', '') or '')
            if not name:
                name = 'sample'
            stem = re.sub(r'[^A-Za-z0-9_\-\.\u4e00-\u9fff]', '_', str(name))[:60]
            return stem or 'sample'
        except Exception:
            return 'sample'

    def _save_reports(self, report: AnalysisReport, web_state=None):
        output_dir = os.path.abspath(CONFIG.report.output_dir)
        os.makedirs(output_dir, exist_ok=True)
        base = os.path.join(output_dir, f'{report.scan_id}_{self._safe_report_stem(report)}')
        report._report_base = base
        # 证据包路径在生成 HTML 前设置, 概览区块才能渲染下载链接
        _evidence_enabled = bool(getattr(CONFIG.report, 'evidence_pack', True))
        report._evidence_pack = base + '.zip'
        report._evidence_pack_rel = os.path.basename(base) + '.zip' if _evidence_enabled else ''

        if CONFIG.report.html_enabled:
            logger.info("[11] 生成 HTML 报告...")
            try:
                self.html_generator.generate(report, base + ".html", web_state=web_state)
            except Exception as e:
                logger.error(f"HTML 报告生成失败: {e}")
                import traceback
                logger.warning(traceback.format_exc())
                report._report_errors = (getattr(report, '_report_errors', '') or '') + f" | HTML: {e}"
        if CONFIG.report.json_enabled:
            logger.info("[11] 生成 JSON 报告...")
            try:
                # 总结性分析报告（人类可读的分章节 JSON）
                from report.summary_generator import SummaryReportGenerator
                SummaryReportGenerator().generate(report, base + ".json")
            except Exception as e:
                logger.error(f"JSON 报告生成失败: {e}")
                import traceback
                logger.warning(traceback.format_exc())
                report._report_errors = (getattr(report, '_report_errors', '') or '') + f" | JSON: {e}"
        if CONFIG.report.pdf_enabled:
            logger.info("[11] 生成 PDF 报告...")
            try:
                self.pdf_generator.generate(report, base + ".pdf")
            except Exception as e:
                logger.error(f"PDF 报告生成失败: {e}")
                report._report_errors = (getattr(report, '_report_errors', '') or '') + f" | PDF: {e}"

        # 证据包: 手动打包 HTML/JSON/PDF + PCAP + 小型 pid*.bin 内存转储
        if _evidence_enabled:
            try:
                zip_path = base + '.zip'
                with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                    for ext in ('.html', '.json', '.pdf'):
                        fpath = base + ext
                        if os.path.isfile(fpath):
                            zf.write(fpath, arcname=os.path.basename(fpath))
                    # PCAP 抓包文件
                    pcap_path = getattr(report.network, 'pcap_path', '') if report.network else ''
                    if pcap_path and os.path.isfile(pcap_path):
                        zf.write(pcap_path, arcname=os.path.join('pcap', os.path.basename(pcap_path)))
                    # 内存转储: 只打包 pid*.bin 且 < 50MB, 最多 5 个
                    mem_dumps = []
                    if report.memory:
                        for entry in (getattr(report.memory, 'dumped_files', []) or []):
                            if isinstance(entry, dict):
                                _p = entry.get('path', '') or entry.get('file', '') or ''
                            else:
                                _p = str(entry)
                            if _p and os.path.basename(_p).lower().startswith('pid') and \
                               os.path.basename(_p).lower().endswith('.bin'):
                                mem_dumps.append(_p)
                    added_dumps = 0
                    for dump_path in mem_dumps:
                        if added_dumps >= 5:
                            break
                        try:
                            if os.path.isfile(dump_path) and os.path.getsize(dump_path) < 50 * 1024 * 1024:
                                zf.write(dump_path, arcname=os.path.join('memory', os.path.basename(dump_path)))
                                added_dumps += 1
                        except OSError:
                            continue
                logger.info(f"[+] 证据包已生成: {zip_path}")
            except Exception as e:
                logger.error(f"证据包生成失败: {e}")
                import traceback
                logger.warning(traceback.format_exc())
                report._evidence_pack = ''

        self._prune_old_reports(output_dir)

    def _prune_old_reports(self, output_dir: str):
        """报告保留策略: 超过 max_keep_reports 时删除最旧的 HTML 及其同源 json/pdf。

        兼容两类文件名:
          - 新命名: <scan_id>_<sanitized_sample>.html (如 SCAN-123-abcdef_malware.exe.html)
          - 旧命名: report_<scan_id>.html / <scan_id>.html
        """
        try:
            max_keep = int(getattr(CONFIG.report, 'max_keep_reports', 100) or 0)
        except Exception:
            max_keep = 100
        if max_keep <= 0:
            return
        try:
            html_files = []
            for f in os.listdir(output_dir):
                if not f.endswith('.html') or f.endswith('.progress.html'):
                    continue
                if f.startswith('report_') or f.startswith('SCAN-'):
                    html_files.append(os.path.join(output_dir, f))
            if len(html_files) <= max_keep:
                return
            html_files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            with _PRUNE_LOCK:
                for old in html_files[max_keep:]:
                    stem = os.path.splitext(os.path.basename(old))[0]
                    try:
                        os.remove(old)
                    except OSError:
                        pass
                    for ext in ('.json', '.pdf', '.zip'):
                        side = os.path.join(output_dir, f'{stem}{ext}')
                        if os.path.isfile(side):
                            try:
                                os.remove(side)
                            except OSError:
                                pass
        except Exception as e:
            logger.debug(f"报告保留策略清理失败: {e}")
    
    def _build_memory_exit_diagnosis(self, report: AnalysisReport, all_pids: set):
        """目标进程已退出时的内存检测诊断 — 不再只提示"进程已退出"。

        综合 Frida API 调用记录中的分配/释放失衡、内存保护事件 (RWX/DEP/ROP)、
        执行期内存快照与残留 dump, 给出退出前发生了什么的结论。
        """
        from analyzer.models import MemoryAnalysis
        am = report.api_monitor
        records = getattr(am, 'call_records', []) or [] if am else []
        mem_events = getattr(am, '_memprot_events', []) or [] if am else []
        mem_stats = getattr(am, '_memprot_stats', {}) or {} if am else {}

        # ⚠ 只统计 Frida 实际挂钩的分配/释放 API (其他 Heap/Global API 无记录,
        # 混入会导致"泄漏"结论失真)
        alloc_apis = {'VirtualAlloc', 'VirtualAllocEx', 'NtAllocateVirtualMemory'}
        free_apis = {'VirtualFree', 'VirtualFreeEx'}
        alloc_n = 0
        free_n = 0
        for r in records:
            api = getattr(r, 'api_name', '') or ''
            if api in alloc_apis:
                alloc_n += 1
            elif api in free_apis:
                free_n += 1

        rwx_alloc = sum(1 for e in mem_events if e.get('rwx_alloc'))
        rw_to_rx = sum(1 for e in mem_events if e.get('rw_to_rx'))
        dep = sum(1 for e in mem_events if e.get('dep_bypass'))
        rop = sum(1 for e in mem_events if e.get('rop_like'))
        huge = sum(1 for e in mem_events if e.get('huge_alloc'))
        injection = sum(1 for e in mem_events if e.get('injection'))

        dumps = list(report.memory.dumped_files or []) if report.memory else []
        snapshots = len(getattr(report.dynamic, 'memory_snapshots', []) or []) if report.dynamic else 0

        leaked = max(0, alloc_n - free_n)
        leak_ratio = (alloc_n / max(free_n, 1))
        diagnosis = {
            'target_pids': sorted(int(p) for p in all_pids if p),
            'alloc_calls': alloc_n, 'free_calls': free_n,
            'leaked_allocations': leaked, 'leak_ratio': round(leak_ratio, 2),
            'rwx_alloc': rwx_alloc, 'rw_to_rx': rw_to_rx,
            'dep_bypass': dep, 'rop_like': rop, 'huge_alloc': huge,
            'injection': injection,
            'dump_files': dumps[:20],
            'execution_snapshots': snapshots,
            'sleep_total_ms': mem_stats.get('sleep_total_ms', 0),
            'enum_snapshot_count': mem_stats.get('enum_snapshot_count', 0),
        }

        parts = []
        if dep or rop:
            parts.append(f"⚠️ 退出前捕获 DEP绕过/ROP喷射 内存事件 ×{max(dep, rop)}")
        if rw_to_rx:
            parts.append(f"⚠️ RW→RX 载荷解密转换 ×{rw_to_rx}")
        if rwx_alloc:
            parts.append(f"⚠️ RWX 内存分配 ×{rwx_alloc}")
        if injection:
            parts.append(f"⚠️ 远程内存注入链 ×{injection}")
        if alloc_n >= 3 and alloc_n >= free_n * 2:
            parts.append(f"💾 内存未释放: 分配×{alloc_n} / 释放×{free_n} "
                         f"(驻留/泄漏特征, 未释放≈{leaked}次)")
        if huge:
            parts.append(f"💾 超大内存分配 ×{huge}")
        if snapshots:
            parts.append(f"📸 执行期内存快照 ×{snapshots}")
        if dumps:
            parts.append(f"📦 残留内存 dump ×{len(dumps)} 可离线取证")
        if not parts:
            parts.append("目标进程已退出且未捕获到可分析的内存行为证据")
        return MemoryAnalysis(
            pid=(sorted(int(p) for p in all_pids if p) or [0])[0],
            process_exited=True,
            live_analyzed=False,
            exit_diagnosis=diagnosis,
            summary=' | '.join(parts),
        )

    def _build_behavior_timeline(self, report: AnalysisReport) -> list:
        """构建按时间排序的行为事件时间线"""
        events = []
        ts = [0]
        _seen_api_counts = {}

        def _add(category, icon, title, detail=''):
            _title = str(title)
            # 同一种 API 跨小节 (api/sysmod/priv) 反复出现时, 全局最多保留10条,
            # 防止 OpenProcessToken 这类调用把时间线灌到 200+ 事件
            _m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\(', _title)
            if _m:
                _api_key = _m.group(1)
                if _seen_api_counts.get(_api_key, 0) >= 10:
                    return
                _seen_api_counts[_api_key] = _seen_api_counts.get(_api_key, 0) + 1
            ts[0] += 1
            events.append({'seq': ts[0], 'category': category, 'icon': icon,
                           'title': _title[:200],
                           'detail': str(detail)[:250] if detail else ''})

        def _join(items, sep=', '):
            """安全 join: 过滤 None/空串, 避免 'sequence item 0' 时间线构建崩溃"""
            return sep.join(str(x) for x in (items or []) if x is not None and str(x) != '')

        # 过滤辅助函数
        _SKIP_PROCS = {'conhost.exe', 'python.exe', 'pythonw.exe', 'cmd.exe',
                        'wscript.exe', 'cscript.exe', 'rundll32.exe', 'regsvr32.exe',
                        # 系统正常进程 — 分析期间系统活动不应算样本行为
                        'compatTelrunner.exe', 'applicationframehost.exe', 'sechealthui.exe',
                        'securityhealthhost.exe', 'audiodg.exe', 'dwm.exe', 'fontdrvhost.exe',
                        'taskhostw.exe', 'runtimebroker.exe', 'sihost.exe', 'smartscreen.exe',
                        'backgroundtaskhost.exe', 'werfault.exe', 'werfaultsecure.exe',
                        'ctfmon.exe', 'tabtip.exe', 'lockapp.exe', 'systemsettings.exe',
                        'shellExperiencehost.exe', 'startmenuexperiencehost.exe',
                        'textinputhost.exe', 'searchapp.exe', 'searchui.exe',
                        'splashscreen.exe', 'winstore.app.exe', 'securityhealthsystray.exe',
                        'securityhealthservice.exe', 'explorer.exe', 'msedge.exe', 'chrome.exe',
                        # 我们自己的 Frida 注入辅助进程 — 必须排除!
                        'frida-helper-x86_64.exe', 'frida-helper-x86.exe', 'frida-helper.exe',
                        'frida-server.exe', 'frida-gadget.exe',
                        # 沙箱自身组件
                        'sandboxanalyzer.exe', 'python313.dll'}
        _SKIP_FILE_NAMES = {'sandbox.log', 'sandbox_log_', 'MpCmdRun.log',
                            'wpndatabase.db', 'NotificationUx', 'NotifyIcon', 'BrowserMetrics'}
        _SKIP_FILE_DIRS = {'\\Microsoft\\Windows Defender\\Platform\\',
                           '\\Microsoft\\Windows Defender\\Definition ',
                           '\\Microsoft\\Windows Defender\\Scans\\',
                           '\\Microsoft\\Windows Defender\\Support\\',
                           '\\Microsoft\\Windows Defender\\Models\\',
                           '\\Microsoft\\Windows Defender\\IMpService',
                           '\\USOShared\\', '\\Notifications\\',
                           '\\Windows\\Caches\\',
                           '\\ConstraintIndex\\', '\\DeviceSearchCache\\',
                           '\\Service Worker\\', '\\Code Cache\\', '\\Sessions\\',
                           '\\BrowserMetrics\\', '\\WebStorage\\',
                           '\\CustomDestinations\\', '\\Network\\',
                           '\\AppRepository\\', '\\DashTracker'}  # Windows系统噪音目录
        _DEFENDER_CMDS = {'-ScheduleJob', '-RestartService', '-UnmanagedUpdate',
                          'SignatureUpdate', 'SignaturesUpdate', 'uninstall-manifest',
                          'install-manifest', '/stub', '/payload', 'MpCmdRun.exe',
                          'MsMpEng.exe', 'NisSrv.exe', 'MpDefenderCoreService',
                          'MpSigStub.exe', 'wevtutil.exe'}

        def _is_noise(name, cmdline):
            nl = name.lower() if name else ''
            cl = cmdline.lower() if cmdline else ''
            if nl in _SKIP_PROCS:
                return True
            if any(d in cl for d in _DEFENDER_CMDS):
                return True
            if any(d in cl.lower() for d in ['\\windows defender\\', 'wevtutil']):
                return True
            if 'msiexec' in nl and ('/v' in cl or '/V' in cl):
                return True
            if 'msiexec' in nl and '-Embedding' in cl:
                return True
            return False

        def _is_noise_file(fpath_str):
            fp = fpath_str.lower()
            if any(s.lower() in fp for s in _SKIP_FILE_DIRS):
                return True
            fn = os.path.basename(fpath_str).lower()
            if any(s.lower() in fn for s in _SKIP_FILE_NAMES):
                return True
            if fn.endswith(('.etl', '.db-wal', '.db-shm', '.pma')):
                return True
            return False

        # 0. 压缩包
        if report.archive:
            arc = report.archive
            _add('archive', '📦', f'识别压缩包: {arc.archive_type}', f'共 {arc.total_files} 个文件')
            if arc.encrypted_files:
                _add('archive', '🔐', f'加密文件 ({len(arc.encrypted_files)} 个)', _join(arc.encrypted_files[:5]))
            for exe in arc.executable_files[:8]:
                _add('archive', '📄', f'提取: {os.path.basename(exe)}')

        # 1. PE/静态分析发现
        if report.pe_info:
            pe = report.pe_info
            if pe.packer_info:
                _add('static', '📦', '加壳检测: ' + _join(pe.packer_info[:3]))
            for sf in (pe.suspicious_features or [])[:5]:
                _add('static', '⚠️', sf)
            if pe.tls_callbacks:
                _add('static', '🔗', f'TLS回调: {len(pe.tls_callbacks)} 个')

        # 2. 动态分析 — 进程（过滤沙箱/系统噪音）
        if report.dynamic:
            dyn = report.dynamic
            for p in (dyn.processes_created or []):
                if isinstance(p, dict):
                    name = p.get('name', '')
                    pid = p.get('pid', '')
                    cmd = (p.get('cmdline', '') or '')[:150]
                    if name and not _is_noise(name, cmd):
                        _add('process', '▶️', f'进程: {name} (PID={pid})', cmd)
            # 系统关键进程（BreakOnTermination）
            for evt in (dyn.critical_process_events or []):
                _add('critical', '💀', f'系统关键进程: {evt.get("name","")} (PID={evt.get("pid","")})',
                     f'通过NtSetInformationProcess(BreakOnTermination)设为系统关键 — '
                     f'终止将蓝屏 {"(已清除Critical标志)" if evt.get("cleared") else "(无法清除)"}')
            # 文件（过滤Defender更新等系统噪音）
            for f in (dyn.files_created or [])[:30]:
                fpath = f['path'] if isinstance(f, dict) else str(f)
                if _is_noise_file(fpath):
                    continue
                fname = os.path.basename(str(fpath))
                # 标记可执行文件
                ext = os.path.splitext(fname)[1].lower() if '.' in fname else ''
                tag = ' ⚠️可执行' if ext in ('.exe','.dll','.scr','.sys','.bat','.ps1','.vbs') else ''
                _add('file', '📄', f'创建文件: {fname}{tag}', str(fpath))
            for f in (dyn.files_deleted or [])[:15]:
                if _is_noise_file(str(f)):
                    continue
                _add('file', '🗑', f'删除文件: {os.path.basename(str(f))}', str(f))
            for f in (dyn.files_modified or [])[:15]:
                fp = f['path'] if isinstance(f, dict) else str(f)
                if _is_noise_file(str(fp)):
                    continue
                _add('file', '✏️', f'修改文件: {os.path.basename(str(fp))}', str(fp)[:200])
            # 文件重命名
            for f in (dyn.files_renamed or [])[:10]:
                if isinstance(f, dict):
                    old = f.get('old', '')
                    new = f.get('new', '')
                    _add('file', '🔄', f'重命名: {os.path.basename(str(old))} → {os.path.basename(str(new))}')
            # 服务操作
            for s in (dyn.services_created or [])[:5]:
                if isinstance(s, dict):
                    _add('registry', '🔧', f'创建服务: {s.get("name","")}', s.get('path',''))
            for s in (dyn.services_deleted or [])[:5]:
                _add('registry', '🔧', f'删除服务: {s}')
            # 计划任务
            for t in (dyn.scheduled_tasks or [])[:5]:
                if isinstance(t, dict):
                    _add('registry', '⏰', f'计划任务: {t.get("name","")}', t.get('command',''))

            # 注册表
            if dyn.sandbox_result:
                sr = dyn.sandbox_result
                for r in (sr.registry_created or [])[:15]:
                    _add('registry', '📝➕', f'注册表新增: {r}')
                for r in (sr.registry_modified or [])[:15]:
                    _add('registry', '📝✏️', f'注册表修改: {r}')
                for r in (sr.registry_deleted or [])[:10]:
                    _add('registry', '📝🗑', f'注册表删除: {r}')
            for r in (dyn.registry_modified or [])[:15]:
                key = r.get('key', '') if isinstance(r, dict) else str(r)
                val = r.get('value', '') if isinstance(r, dict) else ''
                op = r.get('operation', '') if isinstance(r, dict) else ''
                detail = f'{op}: {val}' if val else ''
                _add('registry', '📝✏️', f'注册表修改: {key}', detail[:150])
            # 网络
            for c in (dyn.network_connections or [])[:8]:
                _add('network', '🌐', f'连接: {c.get("remote","") if isinstance(c,dict) else str(c)}')
            # 互斥体
            for m in (dyn.mutexes or [])[:5]:
                _add('process', '🔒', f'互斥体: {m}')

        # 3. 网络分析
        if report.network:
            for d in report.network.dns_queries[:5]:
                _add('network', '🔍', f'DNS: {d.domain}', _join(d.resolved_ips))
            for c in report.network.tcp_connections[:8]:
                _add('network', '🔗', f'TCP: {c.remote_addr}:{c.remote_port}', c.status)
            for st in (report.network.suspicious_traffic or [])[:5]:
                _add('network', '⚠️', f'可疑流量: {st.get("type","") if isinstance(st,dict) else ""}', st.get("detail","") if isinstance(st,dict) else "")

        # 4. API调用
        if report.api_monitor and report.api_monitor.call_records:
            _TL_ADDED_APIS = 0
            # 这些 API 在下方有专用小节展示, 通用小节不再重复, 避免
            # OpenProcessToken 同时出现在 api/sysmod/priv 三段里灌满时间线
            _TL_DEDICATED_APIS = {
                'NtAllocateVirtualMemory', 'NtClose',
                'OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
                'NtCreateThreadEx', 'NtMapViewOfSection', 'NtUnmapViewOfSection',
                'SetThreadContext', 'QueueUserAPC', 'NtCreateSection', 'RtlCreateUserThread',
                'LoadLibraryA', 'LoadLibraryW', 'LdrLoadDll',
                'RegSetValueExW', 'RegSetValueExA', 'RegCreateKeyExW', 'RegCreateKeyExA',
                'RegDeleteKeyW', 'RegDeleteKeyExW', 'RegDeleteValueW',
                'CreateServiceW', 'DeleteService', 'ChangeServiceConfigW', 'ChangeServiceConfig2W',
                'StartServiceW', 'ControlService', 'OpenSCManagerW',
                'ShellExecuteW', 'ShellExecuteA', 'ShellExecuteExW',
                'CryptUnprotectData', 'CryptProtectData',
                'LookupPrivilegeValueW', 'LookupPrivilegeValueA', 'AdjustTokenPrivileges',
                'OpenProcessToken', 'DuplicateTokenEx', 'ImpersonateLoggedOnUser',
                'RtlAdjustPrivilege', 'NtSetInformationProcess',
            }
            for rec in report.api_monitor.call_records[:500]:
                api = rec.api_name if hasattr(rec, 'api_name') else ''
                # 高频内存分配/关闭调用会把时间线淹没 (一次分析可达数千条)
                if api in _TL_DEDICATED_APIS:
                    continue
                args = _join(rec.arguments[:3]) if hasattr(rec, 'arguments') and rec.arguments else ''
                _add('api', '🔧', api, args)
                _TL_ADDED_APIS += 1
                if _TL_ADDED_APIS >= 12:
                    break

        # 5. 内存取证
        if report.memory:
            mem = report.memory
            if mem.shellcode_found:
                _add('memory', '💀', f'Shellcode检测 ({len(mem.shellcode_details or [])} 处)')
            if mem.pe_in_memory:
                _add('memory', '🧩', f'PE注入 ({len(mem.pe_injected_modules or [])} 个模块)')
                for mod in (mem.pe_injected_modules or [])[:3]:
                    _add('memory', '🧩', str(mod.get('address','') if isinstance(mod,dict) else mod), str(mod.get('module','') if isinstance(mod,dict) else ''))

        # 6. 威胁情报
        if report.threat_intel:
            ti = report.threat_intel
            if 'malicious' in (ti.threat_labels or []):
                _add('threat', '🛡️', f'威胁情报: 恶意', f'家族: {ti.family} 检出: {ti.detection_rate:.0%}')
            for eng in (ti.engine_results or [])[:3]:
                if isinstance(eng, dict) and eng.get('result', {}).get('hit'):
                    _add('threat', '🛡️', f'{eng["engine"]} 命中')

        # 7. YARA/Sigma
        for y in (getattr(report, '_yara_matches', []) or [])[:5]:
            _add('threat', '🎯', 'YARA: ' + (y.get('rule','') or y.get('name','') or ''))
        for sm in (getattr(report, '_sigma_matches', []) or [])[:15]:
            level_icon = {'high': '🔴', 'medium': '🟡', 'low': '🟢', 'info': '🔵'}.get(sm.level, '⚪')
            _add('sigma', level_icon, f'Sigma[{sm.level}]: {sm.title}',
                 f'{sm.description} (MITRE: {sm.technique})' if hasattr(sm, 'technique') else sm.description)

        # 8. 关机/重启拦截
        for sb in (getattr(report, '_shutdown_blocked', []) or []):
            _add('defense', '🛑', f'拦截: {sb.get("api","")}', sb.get('desc','') or sb.get('reboot','') or '')

        # 9. 释放文件
        if report.dropped_files and report.dropped_files.dropped_files:
            for f in (report.dropped_files.suspicious_dropped or [])[:5]:
                fname = os.path.basename(getattr(f, 'path', '') or '')
                sz = getattr(f, 'size', 0) or 0
                ftype = getattr(f, 'file_type', '') or ''
                det = getattr(f, 'detection', '') or ''
                _add('file', '⚠️', f'可疑释放: {fname}', f'大小: {sz} 类型: {ftype} 检测: {det}')
            for f in report.dropped_files.dropped_files[:15]:
                fname = os.path.basename(getattr(f, 'path', '') or '')
                is_exe = getattr(f, 'is_executable', False)
                sz = getattr(f, 'size', 0)
                icon = '📄' if not is_exe else '📄⚠️'
                _add('file', icon, f'释放文件: {fname}', f'大小: {sz} 可执行: {"是" if is_exe else "否"}')

        # 10. 交叉引用
        for cf in (getattr(report, '_loaded_archive_children', []) or []):
            _add('process', '📎', f'加载同源: {cf}')
        for scf in (getattr(report, '_archive_shellcode_loads', []) or []):
            _add('memory', '💀', f'加载Shellcode: {scf}')

        # 11. 进程注入/高级行为 (从 Frida API 监控提取)
        if report.api_monitor:
            am = report.api_monitor
            # 注入相关序列
            inject_keywords = {'injection', 'hollowing', 'inject', 'NtCreateThreadEx', 'CreateRemoteThread',
                              'NtMapViewOfSection', 'Section mapping', 'NtUnmapViewOfSection'}
            sysmod_keywords = {'firewall', 'defender', 'registry', 'service', 'persist', 'scheduled task',
                              'user account', 'security policy', 'bcdedit', 'disk', 'vssadmin', 'shadow',
                              'credential', 'lsass', 'dpapi', 'privilege', 'token', 'self-delete',
                              'anti-forensics', 'event log', 'sc config', 'wmic', 'schtasks',
                              'icacls', 'secedit', 'auditpol', 'diskpart', 'format'}

            for seq in (am.suspicious_sequences or [])[:10]:
                seq_lower = seq.lower()
                if 'dep绕过' in seq_lower or 'rwx' in seq_lower or 'rop' in seq_lower:
                    _add('dep', '💥', seq)
                elif any(kw in seq_lower for kw in sysmod_keywords):
                    _add('sysmod', '⚙️', seq)
                elif any(kw in seq_lower for kw in inject_keywords):
                    _add('inject', '💉', seq)
                else:
                    _add('inject', '💉', seq)
            # 进程注入相关 API 调用
            inject_apis = {'OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
                           'NtCreateThreadEx', 'NtMapViewOfSection', 'NtUnmapViewOfSection',
                           'SetThreadContext', 'QueueUserAPC', 'NtCreateSection', 'RtlCreateUserThread',
                           'LoadLibraryA', 'LoadLibraryW', 'LdrLoadDll'}
            inject_calls = []
            for rec in (am.call_records or []):
                api = rec.api_name if hasattr(rec, 'api_name') else ''
                if api in inject_apis:
                    args_info = ''
                    if hasattr(rec, 'arguments') and rec.arguments:
                        args_info = _join(rec.arguments[:2])
                    inject_calls.append(f'{api}({args_info})')
            for call in inject_calls[:15]:
                _add('inject', '💉', call)

            # 系统设置/服务修改相关 API
            sysmod_apis = {'RegSetValueExW', 'RegSetValueExA', 'RegCreateKeyExW', 'RegCreateKeyExA',
                           'RegDeleteKeyW', 'RegDeleteKeyExW', 'RegDeleteValueW',
                           'CreateServiceW', 'DeleteService', 'ChangeServiceConfigW', 'ChangeServiceConfig2W',
                           'StartServiceW', 'ControlService', 'OpenSCManagerW',
                           'ShellExecuteW', 'ShellExecuteA', 'ShellExecuteExW',
                           'CryptUnprotectData', 'CryptProtectData',
                           'LookupPrivilegeValueW', 'AdjustTokenPrivileges', 'OpenProcessToken'}
            _sysmod_added = 0
            for rec in (am.call_records or []):
                api = rec.api_name if hasattr(rec, 'api_name') else ''
                if api in sysmod_apis:
                    args_info = ''
                    if hasattr(rec, 'arguments') and rec.arguments:
                        args_info = _join(rec.arguments[:2])
                    _add('sysmod', '⚙️', f'{api}({args_info})')
                    _sysmod_added += 1
                    if _sysmod_added >= 20:
                        break

        # 11.5 DEP 绕过 / 内存保护事件时间线 (Frida memprot 明细)
        if report.api_monitor:
            _mp_events = getattr(report.api_monitor, '_memprot_events', []) or []
            _mp_added = 0
            for ev in _mp_events[:20]:
                _mark = []
                if ev.get('dep_bypass'):
                    _mark.append('DEP绕过')
                if ev.get('rop_like'):
                    _mark.append('ROP喷射')
                if ev.get('rw_to_rx'):
                    _mark.append('RW→RX')
                if ev.get('rwx_alloc'):
                    _mark.append('RWX分配')
                if ev.get('huge_alloc'):
                    _mark.append('超大分配')
                if ev.get('injection'):
                    _mark.append('远程注入')
                _title = f"{ev.get('api', '')}: {'/'.join(_mark) or '内存保护变更'}"
                _detail = (f"base={ev.get('base', '')} size={ev.get('size', 0)} "
                           f"{ev.get('old_prot', '-')} → {ev.get('new_prot', '')} "
                           f"status={ev.get('status', '')}".strip())
                _add('dep', '💥' if (ev.get('dep_bypass') or ev.get('rop_like')) else '🧠',
                     _title, _detail)
                _mp_added += 1
                if _mp_added >= 10:
                    break

        # 11.6 进程退出内存诊断 (分配未释放 / 退出前 DEP 事件)
        _mem_diag = getattr(getattr(report, 'memory', None), 'exit_diagnosis', {}) or {}
        if _mem_diag:
            _diag_parts = []
            if (_mem_diag.get('alloc_calls') or 0) >= 3:
                _diag_parts.append(f"分配×{_mem_diag.get('alloc_calls')} / 释放×{_mem_diag.get('free_calls')}"
                                   f" (未释放≈{_mem_diag.get('leaked_allocations', 0)})")
            if _mem_diag.get('dep_bypass') or _mem_diag.get('rop_like'):
                _diag_parts.append(f"退出前DEP绕过/ROP事件×"
                                   f"{(_mem_diag.get('dep_bypass') or 0) + (_mem_diag.get('rop_like') or 0)}")
            if _mem_diag.get('rw_to_rx'):
                _diag_parts.append(f"RW→RX×{_mem_diag.get('rw_to_rx')}")
            if _mem_diag.get('rwx_alloc'):
                _diag_parts.append(f"RWX×{_mem_diag.get('rwx_alloc')}")
            if _mem_diag.get('dump_files'):
                _diag_parts.append(f"离线dump×{len(_mem_diag.get('dump_files'))}")
            if _diag_parts:
                _add('memory', '🪦', '目标进程退出 — 内存诊断', '; '.join(_diag_parts))

        # 12. 进程终止事件
        if report.dynamic:
            for p in (report.dynamic.processes_terminated or []):
                if isinstance(p, dict):
                    name = p.get('name', '')
                    pid = p.get('pid', '')
                    _add('process', '⏹', f'进程退出: {name} (PID={pid})')

        # 13. 模块/DLL 加载事件 (从内存快照)
        if report.dynamic:
            all_loaded_modules = set()
            for snap in (getattr(report.dynamic, 'memory_snapshots', []) or []):
                for mod in snap.get('loaded_modules', []) if isinstance(snap, dict) else []:
                    mod_name = mod.get('name', '') if isinstance(mod, dict) else str(mod)
                    if mod_name and mod_name not in all_loaded_modules:
                        all_loaded_modules.add(mod_name)
                        _add('inject', '📚', f'加载模块: {mod_name}',
                             mod.get('path', '') if isinstance(mod, dict) else '')

        # 14. 权限提升/Token 操作 (从 API 监控)
        if report.api_monitor:
            priv_apis = {'AdjustTokenPrivileges', 'OpenProcessToken', 'LookupPrivilegeValueA',
                         'LookupPrivilegeValueW', 'DuplicateTokenEx', 'ImpersonateLoggedOnUser',
                         'RtlAdjustPrivilege', 'NtSetInformationProcess'}
            _priv_added = 0
            for rec in (report.api_monitor.call_records or []):
                api = rec.api_name if hasattr(rec, 'api_name') else ''
                if api in priv_apis:
                    args_str = ''
                    if hasattr(rec, 'arguments') and rec.arguments:
                        args_str = _join(rec.arguments[:2])
                    _add('priv', '🔑', f'{api}({args_str})')
                    _priv_added += 1
                    if _priv_added >= 10:
                        break

        # 15. 系统状态检测（来自 system_monitor）
        sm = getattr(report, '_system_monitor', {}) or {}
        for det in sm.get('raw_detections', []):
            det_str = str(det)
            if 'VSS' in det_str:
                _add('sysmod', '🗑', '卷影副本已被删除（勒索行为）')
            elif 'LogCleared' in det_str:
                _add('sysmod', '🧹', f'事件日志已清除: {det_str}')
            elif 'SecurityKilled' in det_str or 'SecurityStopped' in det_str:
                _add('sysmod', '🛡️💀', f'安全产品被终止: {det_str}')
            elif 'HostsFile' in det_str:
                _add('sysmod', '📝', 'hosts文件被篡改')

        # 进程diff: 被杀的安全产品
        proc_diff = sm.get('process_diff', {})
        for name, info in (proc_diff.get('killed_security_products', {}) or {}).items():
            _add('sysmod', '🛡️💀', f'杀软进程被杀: {info["product"]} ({name})',
                 f'PID={info["pid"]} — 木马检测到安全软件并终止其进程（银狐/RedLine典型行为）')
        # 所有被杀的进程（过滤噪音）
        all_killed = proc_diff.get('killed_processes', {}) or {}
        killed_security_names = set(proc_diff.get('killed_security_products', {}).keys())
        _PROC_NOISE = {'cmd.exe', 'conhost.exe', 'msiexec.exe', 'wscript.exe', 'cscript.exe',
                       'powershell.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe',
                       'python.exe', 'pythonw.exe', 'SearchFilterHost.exe',
                       'svchost.exe', 'csrss.exe', 'smss.exe', 'wininit.exe', 'services.exe',
                       'lsass.exe', 'winlogon.exe', 'spoolsv.exe', 'dwm.exe', 'explorer.exe',
                       'taskhostw.exe', 'sihost.exe', 'ctfmon.exe', 'RuntimeBroker.exe',
                       'ShellExperienceHost.exe', 'SearchUI.exe', 'TextInputHost.exe',
                       'StartMenuExperienceHost.exe', 'SystemSettings.exe', 'ApplicationFrameHost.exe',
                       'MusNotification.exe', 'MusNotifyIcon.exe', 'sppsvc.exe',
                       'MicrosoftEdge', 'msedge.exe', 'chrome.exe',
                       # 我们自己的 Frida 辅助进程
                       'frida-helper-x86_64.exe', 'frida-helper-x86.exe', 'frida-helper.exe',
                       'frida-server.exe', 'frida-gadget.exe',
                       # 分析期间系统正常活动
                       'compatTelrunner.exe', 'sechealthui.exe', 'securityhealthhost.exe',
                       'audiodg.exe', 'fontdrvhost.exe', 'backgroundtaskhost.exe',
                       'werfault.exe', 'werfaultsecure.exe', 'lockapp.exe',
                       'securityhealthsystray.exe', 'securityhealthservice.exe',
                       'wermgr.exe', 'wmpnetwk.exe',
                       # Windows 搜索索引 (SearchIndexer/SearchProtocolHost 频繁自动
                       # 启停, 消失≠被样本终止 — 无 TerminateProcess 证据不可定论)
                       'searchindexer.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe'}
        for name, pid in all_killed.items():
            if name not in killed_security_names and name.lower() not in [p.lower() for p in _PROC_NOISE]:
                _add('process', '⏹', f'进程被终止: {name} (PID={pid})',
                     f'木马执行期间该进程消失（无 TerminateProcess/OpenProcess 调用证据, 仅低置信提示）')
        # 新增的进程（过滤沙箱/系统/Defender/Frida辅助进程）
        all_started = proc_diff.get('started_processes', {}) or {}
        _PROC_FILTER = {'cmd.exe', 'conhost.exe', 'msiexec.exe', 'wscript.exe', 'cscript.exe',
                         'powershell.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe',
                         'python.exe', 'pythonw.exe', 'WevtUtil.exe', 'wevtutil.exe',
                         'MsMpEng.exe', 'NisSrv.exe', 'MpCmdRun.exe', 'MpSigStub.exe',
                         'MpDefenderCoreService.exe', 'VSSVC.exe',
                         # 我们自己的 Frida 注入辅助进程 — 不能作为样本行为!
                         'frida-helper-x86_64.exe', 'frida-helper-x86.exe', 'frida-helper.exe',
                         'frida-server.exe', 'frida-gadget.exe',
                         # 分析期间系统正常活动进程
                         'compatTelrunner.exe', 'applicationframehost.exe', 'sechealthui.exe',
                         'securityhealthhost.exe', 'audiodg.exe', 'dwm.exe', 'fontdrvhost.exe',
                         'taskhostw.exe', 'runtimebroker.exe', 'sihost.exe', 'smartscreen.exe',
                         'backgroundtaskhost.exe', 'werfault.exe', 'werfaultsecure.exe',
                         'ctfmon.exe', 'tabtip.exe', 'lockapp.exe', 'systemsettings.exe',
                         'shellExperiencehost.exe', 'startmenuexperiencehost.exe',
                         'textinputhost.exe', 'searchapp.exe', 'searchui.exe',
                         'securityhealthsystray.exe', 'securityhealthservice.exe',
                         'explorer.exe', 'msedge.exe', 'chrome.exe', 'firefox.exe',
                         'searchindexer.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe',
                         'wmpnetwk.exe', 'wermgr.exe', 'MoUsoCoreWorker.exe',
                         'sandboxanalyzer.exe'}
        suspicious_new = [(n, p) for n, p in all_started.items() if n.lower() not in [f.lower() for f in _PROC_FILTER]]
        for name, pid in suspicious_new[:20]:
            _add('process', '▶️', f'新进程启动: {name} (PID={pid})',
                 '木马执行期间新增的非沙箱进程')

        # 16. 防火墙关闭
        for d in sm.get('raw_changes', []):
            cat = d.get('category', '')
            if cat == 'Firewall':
                _add('sysmod', '🔥', f'防火墙被关闭: {d.get("key","")}',
                     d.get('values', '')[:200])

        # 17. 新安装的服务
        for d in sm.get('raw_changes', []):
            cat = d.get('category', '')
            if cat == 'Service' and d.get('type') == 'created':
                _add('sysmod', '🔧', f'新服务: {d.get("key","")}',
                     d.get('values', '')[:200])
            elif cat == 'Service' and d.get('type') == 'modified':
                _add('sysmod', '🔧', f'服务修改: {d.get("key","")}',
                     d.get('values', '')[:200])

        # 18. 安全策略修改
        for d in sm.get('raw_changes', []):
            cat = d.get('category', '')
            if cat in ('SecurityPolicy', 'SafeBoot', 'RDP', 'ImageHijack'):
                _add('sysmod', '🔓', f'安全配置修改 [{cat}]: {d.get("key","")}',
                     d.get('values', '')[:200])

        # 19. 代理配置
        for d in sm.get('raw_changes', []):
            cat = d.get('category', '')
            if cat == 'Browser':
                _add('sysmod', '🌐', f'浏览器/代理配置修改: {d.get("key","")}',
                     d.get('values', '')[:200])
            elif cat == 'Network':
                _add('sysmod', '🌐', f'网络配置修改: {d.get("key","")}',
                     d.get('values', '')[:200])

        return sorted(events, key=lambda e: e['seq'])

    def _build_execution_tree(self, file_path: str, report: AnalysisReport) -> Dict:
        """构建执行流程树（思维导图），展示样本→子进程→释放文件→子文件的完整层级关系"""

        # 根节点：原始样本
        root = {
            'name': os.path.basename(file_path),
            'path': file_path,
            'type': 'sample',
            'icon': '🎯',
            'label': '原始样本',
            'details': {},
            'children': [],
        }
        if report.file_info:
            root['details'] = {
                '大小': report.file_info.size_human,
                '类型': report.file_info.file_type,
                'MD5': report.file_info.md5[:16] + '...' if report.file_info.md5 else '',
                'SHA256': report.file_info.sha256[:16] + '...' if report.file_info.sha256 else '',
                '熵值': f"{report.file_info.entropy:.2f}",
            }
        if report.malware_family and report.malware_family.primary_family != 'Unknown':
            root['label'] += f' [{report.malware_family.primary_family}]'
        if report.risk_level:
            root['risk'] = report.risk_level

        node_id = [0]  # 自增计数器
        def new_id(): node_id[0] += 1; return node_id[0]

        # ===== 层1: 压缩包/归档提取 =====
        if report.archive and report.archive.entries:
            arc_node = {
                'name': report.archive.archive_type,
                'path': report.archive.archive_path,
                'type': 'archive',
                'icon': '📦',
                'label': '压缩包提取',
                'id': new_id(),
                'details': {
                    '类型': report.archive.archive_type,
                    '总文件数': str(report.archive.total_files),
                    '可执行': str(len(report.archive.executable_files)),
                    '嵌套压缩包': str(len(report.archive.nested_archives)),
                },
                'children': [],
            }
            for entry in report.archive.entries[:30]:
                child = {
                    'name': entry.filename,
                    'path': '',
                    'type': 'file',
                    'icon': '📄',
                    'label': '提取文件',
                    'id': new_id(),
                    'details': {
                        '原始大小': format_size(entry.size_original),
                        '压缩大小': format_size(entry.size_compressed),
                        '加密': '是' if entry.is_encrypted else '否',
                        '可执行': '是 ⚠️' if entry.is_executable else '否',
                    },
                    'children': [],
                }
                if entry.is_suspicious:
                    child['label'] = '⚠️ 可疑文件'
                    child['suspicious'] = True
                arc_node['children'].append(child)
            root['children'].append(arc_node)

        # ===== 层1: MSI 安装包提取 =====
        if report.msi_actions or (report.sub_files and report.sub_files.extracted_files):
            msi_node = {
                'name': 'MSI 安装包',
                'path': file_path,
                'type': 'msi',
                'icon': '⚙️',
                'label': 'MSI 解包',
                'id': new_id(),
                'details': {},
                'children': [],
            }
            if report.msi_actions:
                msi_node['details']['自定义动作'] = str(len(report.msi_actions))
            if report.sub_files and report.sub_files.extracted_files:
                for ef in report.sub_files.extracted_files[:20]:
                    ef_name = ef.get('name', ef.get('path', '?'))
                    child = {
                        'name': os.path.basename(str(ef_name)) if '/' in str(ef_name) or '\\' in str(ef_name) else str(ef_name),
                        'path': str(ef.get('path', '')),
                        'type': 'file',
                        'icon': '📄',
                        'label': 'MSI内嵌文件',
                        'id': new_id(),
                        'details': {
                            '类型': str(ef.get('type', '')),
                            '大小': format_size(ef.get('size', 0)),
                            '所在文件夹': os.path.dirname(str(ef.get('path', ''))) + '\\' if ef.get('path') else '',
                        },
                        'children': [],
                    }
                    msi_node['children'].append(child)
            if msi_node['children']:
                root['children'].append(msi_node)

        # ===== 层2-N: 动态分析 — 进程树 + 文件树 =====
        if report.dynamic:
            dyn = report.dynamic
            # 先建立 PID→进程 索引
            pid_map = {}
            for p in dyn.processes_created:
                pid_map[p.get('pid', 0)] = p

            # 建立 PPID→子进程 映射
            children_map = {}
            roots_pids = []
            for p in dyn.processes_created:
                ppid = p.get('ppid', 0)
                pid = p.get('pid', 0)
                if ppid not in children_map:
                    children_map[ppid] = []
                children_map[ppid].append(p)
                # 判断根进程：ppid 不在已知列表中的
                if ppid not in pid_map:
                    roots_pids.append(pid)

            # 找出最小 PID 作为根进程（通常是直接启动的那个）
            if not roots_pids and dyn.processes_created:
                roots_pids = [min(p.get('pid', 99999) for p in dyn.processes_created)]

            def build_proc_tree(pid, depth=0):
                if depth > 8 or pid not in pid_map:
                    return None
                p = pid_map[pid]
                proc_name = p.get('name', '?')
                node = {
                    'name': proc_name,
                    'path': p.get('exe', ''),
                    'type': 'process',
                    'icon': '🔧' if depth == 0 else '▶️',
                    'label': f"进程 (PID={pid})",
                    'id': new_id(),
                    'details': {
                        'PID': str(pid),
                        'PPID': str(p.get('ppid', '?')),
                        '命令行': (p.get('cmdline', '') or '')[:200],
                        '启动时间': p.get('create_time', ''),
                    },
                    'children': [],
                }

                # 此进程创建的文件
                if dyn.files_created:
                    proc_exe_dir = os.path.dirname(p.get('exe', '')).lower()
                    for fentry in dyn.files_created:
                        fpath = fentry['path'] if isinstance(fentry, dict) else fentry
                        fdir = os.path.dirname(fpath).lower()
                        # 简单启发：同一目录树下的文件归属此进程
                        if proc_exe_dir and fdir.startswith(proc_exe_dir[:30]):
                            file_node = {
                                'name': os.path.basename(fpath),
                                'path': fpath,
                                'type': 'file',
                                'icon': '📄',
                                'label': '释放文件',
                                'id': new_id(),
                                'details': {
                                    '所在文件夹': os.path.dirname(fpath),
                                },
                                'children': [],
                            }
                            # 补充文件详情（从 dropped_files 中取）
                            if report.dropped_files:
                                for df in report.dropped_files.dropped_files:
                                    if df.path.lower() == fpath.lower():
                                        file_node['details'].update({
                                            '大小': format_size(df.size),
                                            '类型': df.file_type,
                                            '熵值': f"{df.entropy:.2f}",
                                            '可执行': '是' if df.is_executable else '否',
                                        })
                                        if df.detection:
                                            file_node['details']['检测'] = df.detection
                                        break
                            # 补充文件大小（如果 dropped_files 中未匹配）
                            if '大小' not in file_node['details']:
                                try:
                                    file_node['details']['大小'] = format_size(os.path.getsize(fpath))
                                except:
                                    pass
                            node['children'].append(file_node)

                # 子进程（递归）
                if pid in children_map:
                    for child_p in children_map[pid]:
                        child_node = build_proc_tree(child_p.get('pid', 0), depth + 1)
                        if child_node:
                            node['children'].append(child_node)

                return node

            # 构建进程树（只需要根进程）
            for root_pid in roots_pids[:3]:
                proc_root = build_proc_tree(root_pid)
                if proc_root:
                    if len(roots_pids) == 1:
                        proc_root['label'] = '动态执行'
                        proc_root['icon'] = '🚀'
                        root['children'].append(proc_root)
                    else:
                        # 多个根进程 → 加一个分组节点（复用已有）
                        proc_root['label'] = f"进程组#{root_pid}"
                        group_node = None
                        for c in root['children']:
                            if c.get('type') == 'proc_group':
                                group_node = c
                                break
                        if group_node is None:
                            group_node = {
                                'name': '动态执行',
                                'path': '',
                                'type': 'proc_group',
                                'icon': '🚀',
                                'label': f"动态执行 ({len(dyn.processes_created)}进程, {len(dyn.files_created)}文件)",
                                'id': new_id(),
                                'details': {},
                                'children': [],
                            }
                            root['children'].append(group_node)
                        group_node['children'].append(proc_root)

            # Frida hook 捕获的子进程 (psutil 轮询可能漏掉快速创建/退出的子进程, 如 hollowing target)
            _frida_children = getattr(getattr(report, 'api_monitor', None), '_child_processes', None) or []
            if _frida_children:
                _known_pids = set(pid_map.keys())
                _frida_only = [c for c in _frida_children if c.get('pid') and c['pid'] not in _known_pids]
                if _frida_only:
                    _frida_group = {
                        'name': 'Frida捕获子进程',
                        'path': '',
                        'type': 'proc_group',
                        'icon': '🕵️',
                        'label': f"Frida Hook 捕获子进程 ({len(_frida_only)})",
                        'id': new_id(),
                        'details': {'说明': 'psutil 轮询未覆盖, 由 CreateProcessW/A Hook 捕获'},
                        'children': [],
                    }
                    for _c in _frida_only[:20]:
                        _frida_group['children'].append({
                            'name': f"PID={_c.get('pid')}",
                            'path': '',
                            'type': 'process',
                            'icon': '▶️',
                            'label': f"子进程 PID={_c.get('pid')}",
                            'id': new_id(),
                            'details': {
                                'PID': str(_c.get('pid', '?')),
                                '命令行': (_c.get('cmdline', '') or '')[:200],
                                '捕获方式': _c.get('via', 'CreateProcess'),
                                '捕获时间': _c.get('timestamp', ''),
                            },
                            'children': [],
                        })
                    root['children'].append(_frida_group)

            # 没有进程树但有文件创建的 → 直接挂到根下
            if not roots_pids and dyn.files_created and not any(
                c.get('type') == 'proc_group' for c in root['children']
            ):
                for fentry in dyn.files_created[:30]:
                    fpath = fentry['path'] if isinstance(fentry, dict) else fentry
                    file_node = {
                        'name': os.path.basename(fpath),
                        'path': fpath,
                        'type': 'file',
                        'icon': '📄',
                        'label': '新创建文件',
                        'id': new_id(),
                        'details': {
                            '所在文件夹': os.path.dirname(fpath) + '\\',
                        },
                        'children': [],
                    }
                    try:
                        file_node['details']['大小'] = format_size(os.path.getsize(fpath))
                    except:
                        pass
                    root['children'].append(file_node)

        # ===== 层1: 释放文件分析（静态） =====
        if report.dropped_files and report.dropped_files.dropped_files:
            for df in report.dropped_files.dropped_files[:30]:
                # 检查是否已在进程树下出现过
                already_in_tree = False
                for child in root.get('children', []):
                    if child.get('type') == 'proc_group':
                        for gc in child.get('children', []):
                            for fc in gc.get('children', []):
                                if fc.get('path', '').lower() == df.path.lower():
                                    already_in_tree = True
                                    break
                    elif child.get('type') == 'file':
                        if child.get('path', '').lower() == df.path.lower():
                            already_in_tree = True
                            break
                if already_in_tree:
                    continue

                file_node = {
                    'name': os.path.basename(df.path),
                    'path': df.path,
                    'type': 'file',
                    'icon': '📄',
                    'label': '释放文件',
                    'id': new_id(),
                    'details': {
                        '大小': format_size(df.size),
                        '类型': df.file_type,
                        '熵值': f"{df.entropy:.2f}",
                        '可执行': '是 ⚠️' if df.is_executable else '否',
                        '所在文件夹': os.path.dirname(df.path) + '\\',
                    },
                    'children': [],
                }
                if any(df.path == s.path for s in report.dropped_files.suspicious_dropped):
                    file_node['label'] = '⚠️ 可疑释放'
                    file_node['suspicious'] = True
                if df.detection:
                    file_node['details']['检测'] = df.detection
                root['children'].append(file_node)

        return root

    def _print_summary(self, report: AnalysisReport):
        logger.info(f"\n{'='*60}")
        logger.info("📊 Analysis Summary")
        logger.info(f"{'='*60}")
        logger.info(f"Scan ID: {report.scan_id}")
        logger.info(f"Risk: {report.risk_level.upper()} ({report.risk_score}/100)")
        if report.file_info:
            logger.info(f"File: {report.file_info.name}")
            logger.info(f"SHA256: {report.file_info.sha256}")
        if report.malware_family:
            logger.info(f"Family: {report.malware_family.primary_family} ({report.malware_family.primary_confidence}%)")
        if report.advanced_behavior:
            ab = report.advanced_behavior
            logger.info(f"Advanced: {ab.summary}")
            if ab.anti_vm:
                logger.warning(f"⚠️ 样本包含反VM检测 ({len(ab.anti_vm)} 项)，可能逃避动态分析！")
                logger.info("    参考: docs/vmware_hardening.md")
            if ab.anti_sandbox:
                logger.warning(f"⚠️ 样本包含反沙箱检测 ({len(ab.anti_sandbox)} 项)")
            if ab.anti_debug:
                logger.info(f"🛡️ 反调试检测: {len(ab.anti_debug)} 项")
        if report.destruction and report.destruction.destruction_level != 'none':
            logger.info(f"Destruction: {report.destruction.summary}")
        if report.dropped_files:
            logger.info(f"Dropped: {report.dropped_files.summary}")
        logger.info(f"Duration: {report.analysis_duration:.1f}s")
        logger.info(f"{'='*60}\n")
