#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
总结性分析报告生成器 — 将平台检测结果组织为人类可读的深度分析报告

输出格式（JSON，按章节组织）：
  【文件基本信息】【整体架构概览】【静态分析结果】【动态行为分析】
  【完整攻击链 Kill Chain】【IOC 汇总】【防御/清除建议】【技术总结】
"""
import json
import os
from datetime import datetime

from logger import get_logger

logger = get_logger('report.summary')


class SummaryReportGenerator:
    """总结性报告生成器"""

    def generate(self, report, output_path):
        logger.info(f"[+] Generating summary report: {output_path}")
        data = self._build_summary(report)
        dirname = os.path.dirname(output_path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    # ============================================================
    # 主构建
    # ============================================================

    def _build_summary(self, report):
        risk_label = {'critical': '严重', 'high': '高危', 'medium': '中', 'low': '低'}.get(
            getattr(report, 'risk_level', 'low'), '低')
        return {
            '报告类型': '恶意文件分析总结报告',
            '扫描ID': report.scan_id,
            '分析时间': getattr(report, 'scan_time', ''),
            '风险等级': f'{risk_label} ({getattr(report, "risk_score", 0)}/100)',
            '文件基本信息': self._file_basic(report),
            '整体架构概览': self._architecture_overview(report),
            '静态分析结果': self._static_analysis(report),
            '动态行为分析': self._dynamic_analysis(report),
            '完整攻击链': self._kill_chain(report),
            'IOC汇总': self._ioc_summary(report),
            '防御清除建议': self._remediation(report),
            '技术总结': self._technical_summary(report),
        }

    # ============================================================
    # 文件基本信息
    # ============================================================

    def _file_basic(self, report):
        fi = report.file_info
        basic = {}
        if fi:
            basic = {
                '文件名': fi.name,
                '文件大小': fi.size_human or (f'{fi.size} 字节' if fi.size else ''),
                '文件类型': fi.file_type,
                '熵值': round(fi.entropy, 2) if fi.entropy is not None else '',
                'MD5': fi.md5 or '',
                'SHA1': fi.sha1 or '',
                'SHA256': fi.sha256 or '',
            }
        pe = report.pe_info
        if pe:
            basic['架构'] = pe.architecture
            basic['编译时间'] = pe.compile_time
            basic['入口点'] = pe.entry_point
            basic['子系统'] = pe.subsystem
            if pe.image_base:
                basic['映像基址'] = pe.image_base
            if pe.imphash:
                basic['Imphash'] = pe.imphash
            if pe.packer_info:
                basic['加壳检测'] = '; '.join(pe.packer_info[:5])
            if pe.digital_signature:
                ds = pe.digital_signature
                signer = ds.get('signer') or ds.get('subject') or ''
                if signer:
                    basic['数字签名'] = signer
                    if ds.get('valid') is not None:
                        basic['签名验证'] = '通过' if ds.get('valid') else '失败/无效'
            ts_anomaly = [f for f in (pe.suspicious_features or []) if '时间戳' in f or '编译时间' in f]
            if ts_anomaly:
                basic['时间戳异常'] = ts_anomaly[0]
        return basic

    # ============================================================
    # 整体架构概览
    # ============================================================

    def _architecture_overview(self, report):
        lines = []
        fi = report.file_info
        ftype = (fi.file_type if fi else '') or 'Unknown'
        pe = report.pe_info
        # 样本类型判定
        if report.archive and report.archive.archive_type:
            sample_type = f'压缩包投递 ({report.archive.archive_type}) → 内部可执行文件'
            lines.append(f'投递方式: {sample_type}')
            if report.archive.executable_files:
                lines.append(f'压缩包内可执行文件: {len(report.archive.executable_files)} 个')
        elif report.script_analysis:
            lines.append(f'脚本类型: {report.script_analysis.script_type if hasattr(report.script_analysis, "script_type") else "脚本"}')
        elif pe and pe.is_dll:
            lines.append('样本类型: DLL (动态链接库)')
        elif pe and pe.is_exe:
            lines.append('样本类型: PE 可执行文件 (EXE)')
        else:
            lines.append(f'样本类型: {ftype}')

        # 家族/功能判定
        fam = report.malware_family
        if fam and fam.primary_family != 'Unknown':
            lines.append(f'木马家族: {fam.primary_family} (置信度 {fam.primary_confidence}%)')
            fam_desc = getattr(fam, 'description', '') or getattr(fam, 'summary', '') or ''
            if fam_desc:
                lines.append(f'家族描述: {fam_desc}')

        # 多阶段判定（时间线 + 释放文件）
        timeline = getattr(report, '_behavior_timeline', []) or []
        stage_count = 0
        if report.archive:
            stage_count += 1
        if report.dynamic and report.dynamic.processes_created:
            stage_count += 1
        if report.dropped_files and report.dropped_files.dropped_files:
            stage_count += 1
        if stage_count >= 2:
            lines.append(f'多阶段攻击: 检测到 {stage_count} 个攻击阶段（投递→释放→执行→持久化）')
            lines.append(f'行为事件总数: {len(timeline)} 个')

        # 主要功能汇总（从高级行为分类统计）
        funcs = self._detect_functions(report)
        if funcs:
            lines.append(f'主要功能: {", ".join(funcs)}')
        return '\n'.join(lines) if lines else '无'

    def _detect_functions(self, report):
        funcs = []
        ab = report.advanced_behavior
        if ab:
            if ab.keylogging: funcs.append('键盘记录')
            if ab.screenshot_capture: funcs.append('屏幕捕获')
            if ab.clipboard_monitoring: funcs.append('剪贴板监控')
            if ab.credential_theft: funcs.append('凭证窃取')
            if ab.browser_data_theft: funcs.append('浏览器数据窃取')
            if ab.process_injection: funcs.append('进程注入')
            if ab.process_hollowing: funcs.append('进程镂空')
            if ab.ransomware_indicators: funcs.append('勒索加密')
            if ab.c2_communication: funcs.append('C2通信')
            if hasattr(ab, 'persistence') and ab.persistence: funcs.append('持久化')
            if ab.uac_bypass: funcs.append('UAC绕过')
            if ab.anti_vm: funcs.append('反虚拟机检测')
            if ab.anti_sandbox: funcs.append('反沙箱检测')
            if ab.anti_debug: funcs.append('反调试')
        if report.memory:
            if report.memory.pe_in_memory: funcs.append('内存注入/反射加载')
            if report.memory.shellcode_found: funcs.append('Shellcode执行')
        if report.destruction:
            if report.destruction.destruction_level in ('high', 'destructive'):
                funcs.append('破坏性行为')
        return list(dict.fromkeys(funcs))

    # ============================================================
    # 静态分析结果
    # ============================================================

    def _static_analysis(self, report):
        result = {}
        st = report.strings
        if st:
            result['可疑字符串'] = (st.suspicious_strings or [])[:15]
            result['提取的URL'] = (st.urls or [])[:10]
            result['提取的IP'] = (st.ips or [])[:10]
            result['提取的域名'] = (st.domains or [])[:10]
            result['可疑API调用'] = (st.api_calls or [])[:20]
            result['PowerShell模式'] = (st.powershell_patterns or [])[:5]

        deobs = getattr(report, '_deobfuscation', None)
        if deobs:
            result['反混淆/编码技术'] = [
                {'技术': d.get('technique', ''), '置信度': d.get('confidence', ''),
                 '预览': str(d.get('preview', ''))[:100]}
                for d in deobs[:10]
            ]
        ps_deobs = getattr(report, '_ps_deobfuscated', None)
        if ps_deobs:
            result['PowerShell反混淆'] = [
                {'技术': d.get('technique', ''), '解码内容': str(d.get('decoded', ''))[:200]}
                for d in ps_deobs[:5]
            ]
        overlay = getattr(report, '_overlay_payloads', None)
        if overlay:
            _ov_ioc = sum(
                sum(len(v) for v in (o.get('iocs') or {}).values())
                for o in overlay if isinstance(o, dict))
            _ov_dec = sum(1 for o in overlay if isinstance(o, dict) and o.get('decryption_attempts'))
            result['Overlay载荷'] = (f'{len(overlay)} 个载荷' + (f', 提取 IOC {_ov_ioc} 条' if _ov_ioc else '')
                                     + (f', {_ov_dec} 个已解密' if _ov_dec else ''))

        pe = report.pe_info
        if pe:
            if pe.suspicious_features:
                result['PE可疑特征'] = pe.suspicious_features[:10]
            suspicious_apis = []
            for imp in (pe.imports or []):
                for f in (imp.suspicious_functions or []):
                    suspicious_apis.append(f'{imp.dll}!{f}')
            if suspicious_apis:
                result['导入的可疑API'] = list(dict.fromkeys(suspicious_apis))[:20]

        yara = getattr(report, '_yara_matches', None) or []
        if yara:
            result['YARA规则命中'] = [
                {'规则': y.get('rule') or y.get('name', ''), '描述': str(y.get('description', ''))[:100]}
                for y in yara[:10]
            ]
        sigma = getattr(report, '_sigma_matches', None) or []
        if sigma:
            result['Sigma规则命中'] = [
                {'规则': getattr(s, 'title', ''), '等级': getattr(s, 'level', ''),
                 '描述': str(getattr(s, 'description', ''))[:120]}
                for s in sigma[:10]
            ]
        suricata = getattr(report, '_suricata_matches', None) or []
        if suricata:
            result['Suricata网络签名'] = [
                {'SID': getattr(s, 'sid', ''), '签名': getattr(s, 'msg', ''),
                 '级别': getattr(s, 'severity', '')}
                for s in suricata[:10]
            ]
        c2 = getattr(report, '_c2_candidates', None) or []
        if c2:
            _c2_hits = [c for c in c2 if c.get('is_c2')]
            result['C2通信评分'] = {
                '可疑连接数': len(c2),
                'C2判定数': len(_c2_hits),
                '高危端点': [f"{c.get('remote')}:{c.get('port')}" for c in _c2_hits[:5]],
            }
        btags = getattr(report, '_behavior_tags', None) or []
        if btags:
            result['行为标签'] = [
                f"{t.get('tag')} ({t.get('mitre')})" for t in btags[:20]
            ]
        fam = report.malware_family
        if fam:
            result['家族判定'] = {
                '家族': fam.primary_family,
                '置信度': f'{fam.primary_confidence}%',
            }
            fam_desc = getattr(fam, 'description', '') or getattr(fam, 'summary', '') or ''
            if fam_desc:
                result['家族描述'] = fam_desc
        rats = getattr(report, '_rat_config', None) or []
        if rats:
            result['RAT配置提取'] = rats[:5]
        return result

    # ============================================================
    # 动态行为分析
    # ============================================================

    def _dynamic_analysis(self, report):
        result = {}
        dyn = report.dynamic
        if dyn:
            procs = []
            for p in (dyn.processes_created or [])[:30]:
                if isinstance(p, dict):
                    procs.append({
                        '进程': p.get('name', ''), 'PID': p.get('pid', 0),
                        '命令行': str(p.get('cmdline', ''))[:200],
                    })
                else:
                    procs.append({
                        '进程': str(getattr(p, 'name', '') or ''),
                        'PID': getattr(p, 'pid', 0),
                        '命令行': str(getattr(p, 'cmdline', '') or '')[:200],
                    })
            if procs:
                result['执行的进程'] = procs
            if dyn.files_created:
                result['创建的文件'] = [str(f)[:200] for f in dyn.files_created[:30]]
            if dyn.files_deleted:
                result['删除的文件'] = [str(f)[:200] for f in dyn.files_deleted[:15]]

        sr = dyn.sandbox_result if dyn else None
        if sr:
            reg = []
            for r in (sr.registry_created or [])[:15]:
                reg.append(f'新增: {r}')
            for r in (sr.registry_modified or [])[:20]:
                reg.append(f'修改: {r}')
            for r in (sr.registry_deleted or [])[:10]:
                reg.append(f'删除: {r}')
            if reg:
                result['注册表变更'] = reg[:30]

        # 持久化
        persist = []
        sm = getattr(report, '_system_monitor', None) or {}
        reg_changes = sm.get('registry_changes', []) or []
        for c in reg_changes:
            if any(k in str(c) for k in ('Run', 'RunOnce', 'Service', 'Winlogon', 'Startup')):
                persist.append(str(c)[:200])
        if sr:
            for r in (sr.registry_created or []):
                if '\\Run' in r or 'Services' in r or 'Winlogon' in r:
                    persist.append(f'创建: {r}')
        enh = getattr(report, '_sandbox_enhancements', None) or {}
        for c in (enh.get('registry_changes', []) or []):
            persist.append(str(c)[:200])
        if persist:
            result['持久化机制'] = list(dict.fromkeys(persist))[:15]

        # 服务/计划任务
        if dyn:
            if dyn.services_created:
                result['创建的服务'] = dyn.services_created[:10]
            if dyn.scheduled_tasks:
                result['计划任务'] = dyn.scheduled_tasks[:10]

        # 内存分析
        mem = report.memory
        if mem:
            mem_res = {}
            if mem.pe_in_memory:
                mem_res['内存PE注入'] = [
                    {'地址': m.get('address', ''), '架构': m.get('architecture', ''),
                     '类型': m.get('type', ''), '模块': m.get('module', '')}
                    for m in (mem.pe_injected_modules or [])[:10]
                ]
            if mem.shellcode_found:
                mem_res['Shellcode'] = [
                    {'地址': s.get('address', ''), '特征': s.get('details', '')}
                    for s in (mem.shellcode_details or [])[:10]
                ]
            if mem.rwx_regions:
                mem_res['RWX区域'] = len(mem.rwx_regions)
            if mem.heavens_gate:
                mem_res['Heaven\'s Gate'] = len(mem.heavens_gate)
            if mem.iat_hooks:
                mem_res['IAT Hook'] = len(mem.iat_hooks)
            if mem.api_unhooking:
                mem_res['API Unhooking'] = len(mem.api_unhooking)
            if mem.anti_dump_measures:
                mem_res['反Dump措施'] = len(mem.anti_dump_measures)
            exit_diag = getattr(mem, 'exit_diagnosis', {}) or {}
            if exit_diag:
                mem_res['进程退出诊断'] = {
                    '分配调用': exit_diag.get('alloc_calls', 0),
                    '释放调用': exit_diag.get('free_calls', 0),
                    '未释放(失衡)': exit_diag.get('leaked_allocations', 0),
                    '退出前DEP绕过/ROP': (exit_diag.get('dep_bypass') or 0) + (exit_diag.get('rop_like') or 0),
                    '退出前RW→RX': exit_diag.get('rw_to_rx', 0),
                    '残留dump': len(exit_diag.get('dump_files', []) or []),
                }
            if mem_res:
                result['内存分析'] = mem_res
            memprot = getattr(report, '_memprot_summary', None)
            if memprot:
                mp = {}
                if memprot.get('rw_to_rx'):
                    mp['RW→RX内存转换(载荷解密)'] = memprot['rw_to_rx']
                if memprot.get('rwx_alloc'):
                    mp['RWX分配(DEP绕过特征)'] = memprot['rwx_alloc']
                if memprot.get('rop_like'):
                    mp['DEP绕过/ROP喷射(超大RWX)'] = memprot['rop_like']
                if memprot.get('huge_alloc'):
                    mp['超大内存分配(≥256MB)'] = memprot['huge_alloc']
                if memprot.get('injection'):
                    mp['远程注入API'] = memprot['injection']
                if memprot.get('enum_snapshot_count'):
                    mp['高频进程枚举'] = memprot['enum_snapshot_count']
                if memprot.get('sleep_total_ms'):
                    mp['长时间睡眠'] = f"{memprot['sleep_total_ms']/1000:.0f}s"
                if mp:
                    result['内存保护监控'] = mp

        # DLL 调用
        dll_sum = getattr(report, '_dll_call_summary', None)
        if dll_sum:
            result['DLL调用监控'] = {
                '总调用次数': dll_sum.get('total_calls', 0),
                '函数明细': [
                    {'DLL': d, '函数': f, '次数': c}
                    for (d, f), c in (dll_sum.get('functions', []) or [])[:20]
                ],
            }
            if dll_sum.get('suspicious_dlls'):
                result['DLL调用监控']['可疑DLL'] = dll_sum['suspicious_dlls']

        # 欺骗动作
        spoof = getattr(report, '_spoof_summary', None)
        if spoof:
            result['API欺骗(假反馈)'] = {
                '次数': spoof.get('count', 0),
                '欺骗的API': spoof.get('apis', []),
            }

        # 杀软对抗/破坏
        dest = report.destruction
        if dest:
            d_res = {}
            if dest.av_termination:
                d_res['终止的杀软'] = dest.av_termination[:10]
            if dest.edr_termination:
                d_res['终止的EDR'] = dest.edr_termination[:10]
            if dest.defender_registry_disable:
                d_res['Defender禁用项'] = dest.defender_registry_disable[:10]
            if getattr(dest, 'av_install_block', None):
                d_res['禁装杀软(禁用安装/更新服务)'] = dest.av_install_block[:10]
            if dest.dangerous_driver_load:
                d_res['危险驱动'] = dest.dangerous_driver_load[:10]
            if dest.backup_delete_commands:
                d_res['备份删除命令'] = dest.backup_delete_commands[:10]
            if dest.uac_bypass_attempts:
                d_res['UAC绕过尝试'] = dest.uac_bypass_attempts[:10]
            if d_res:
                result['破坏性/防御对抗'] = d_res

        # 网络
        net = report.network
        if net:
            net_res = {}
            if net.tcp_connections:
                net_res['TCP连接'] = [
                    {'远端': f"{c.remote_addr}:{c.remote_port}", '状态': c.status,
                     '可疑': c.is_suspicious}
                    for c in net.tcp_connections[:20]
                ]
            if net.dns_queries:
                net_res['DNS查询'] = [
                    {'域名': d.domain, '解析IP': d.resolved_ips}
                    for d in net.dns_queries[:10]
                ]
            if net.http_requests:
                net_res['HTTP请求'] = [
                    {'方法': h.method, '主机': h.host, '路径': str(h.path)[:100]}
                    for h in net.http_requests[:10]
                ]
            if net.suspicious_traffic:
                net_res['可疑流量'] = net.suspicious_traffic[:10]
            if net_res:
                result['网络行为'] = net_res
        return result

    # ============================================================
    # 完整攻击链
    # ============================================================

    def _kill_chain(self, report):
        chain = []
        fi = report.file_info
        fname = fi.name if fi else '样本'
        chain.append(f'[投放] 用户打开 "{fname}"')
        if report.archive:
            chain.append(f'[解包] 压缩包解压出 {len(report.archive.executable_files or [])} 个可执行文件')
        # 释放文件
        if report.dropped_files and report.dropped_files.dropped_files:
            exes = [os.path.basename(getattr(f, 'path', '') or '') for f in report.dropped_files.dropped_files if f.is_executable]
            if exes:
                chain.append(f'[释放] 释放可执行文件: {", ".join(exes[:5])}')
        # 进程创建
        if report.dynamic:
            procs = [p.get('name', '') for p in (report.dynamic.processes_created or [])[:10]]
            if procs:
                chain.append(f'[执行] 启动进程: {", ".join(procs[:5])}')
        # 内存注入
        mem = report.memory
        if mem:
            if mem.pe_in_memory:
                chain.append(f'[注入] 内存中发现注入PE映像 ({len(mem.pe_injected_modules or [])} 个)')
            if mem.shellcode_found:
                chain.append('[注入] 检测到 Shellcode 执行特征')
            memprot = getattr(report, '_memprot_summary', None)
            if memprot and memprot.get('rw_to_rx'):
                chain.append('[解密] RW→RX 内存保护转换 (载荷解密执行)')
            if memprot and memprot.get('rop_like'):
                chain.append('[DEP绕过] 超大 RWX 内存分配 (ROP/Shellcode 喷射)')
            elif memprot and memprot.get('rwx_alloc'):
                chain.append('[DEP绕过] RWX 内存分配')
        # 持久化
        persist = []
        sr = report.dynamic.sandbox_result if report.dynamic else None
        if sr:
            for r in (sr.registry_created or []):
                if '\\Run' in r or 'Services' in r:
                    persist.append(r)
            for r in (sr.registry_modified or []):
                if '\\Run' in r:
                    persist.append(f'修改: {r}')
        if report.dynamic and report.dynamic.services_created:
            persist.extend(report.dynamic.services_created)
        if persist:
            chain.append(f'[持久化] 注册表/服务持久化: {len(persist)} 项')
        # 杀软对抗
        dest = report.destruction
        if dest and dest.av_termination:
            chain.append(f'[对抗] 终止安全软件: {", ".join(str(x) for x in dest.av_termination[:3])}')
        if dest and dest.uac_bypass_attempts:
            chain.append('[提权] UAC 绕过尝试')
        if dest and dest.defender_registry_disable:
            chain.append('[对抗] 禁用 Defender 防护')
        if dest and getattr(dest, 'av_install_block', None):
            chain.append(f'[对抗] 禁装杀软(禁用安装/更新服务): {", ".join(str(x)[:60] for x in dest.av_install_block[:3])}')
        # 网络
        net = report.network
        if net and net.tcp_connections:
            sus = [c for c in net.tcp_connections if c.is_suspicious]
            if sus:
                chain.append(f'[C2] 可疑连接: {", ".join(f"{c.remote_addr}:{c.remote_port}" for c in sus[:5])}')
            elif net.tcp_connections:
                chain.append(f'[C2] 网络连接: {len(net.tcp_connections)} 条')
        # 反沙箱
        ab = report.advanced_behavior
        if ab:
            if ab.anti_vm:
                chain.append(f'[规避] 反虚拟机检测 ({len(ab.anti_vm)} 项技术)')
            if ab.anti_sandbox:
                chain.append(f'[规避] 反沙箱检测 ({len(ab.anti_sandbox)} 项技术)')
            if ab.anti_debug:
                chain.append(f'[规避] 反调试 ({len(ab.anti_debug)} 项技术)')
            if ab.timing_evasion:
                chain.append(f'[规避] 时间规避 ({len(ab.timing_evasion)} 项)')
        return chain

    # ============================================================
    # IOC 汇总
    # ============================================================

    def _ioc_summary(self, report):
        ioc = {'IP地址': [], '域名': [], 'URL': [], '文件哈希': [], '文件路径': [], '注册表': [], '进程': []}
        st = report.strings
        if st:
            ioc['IP地址'].extend(st.ips or [])
            ioc['域名'].extend(st.domains or [])
            ioc['URL'].extend(st.urls or [])
        net = report.network
        if net:
            for c in net.tcp_connections:
                if c.remote_addr:
                    ioc['IP地址'].append(f"{c.remote_addr}:{c.remote_port}")
            for d in net.dns_queries:
                if d.domain:
                    ioc['域名'].append(d.domain)
        fi = report.file_info
        if fi:
            for k, v in [('MD5', fi.md5), ('SHA1', fi.sha1), ('SHA256', fi.sha256)]:
                if v:
                    ioc['文件哈希'].append(f'{k}: {v}')
        if report.dropped_files and report.dropped_files.dropped_files:
            for f in report.dropped_files.dropped_files[:20]:
                p = getattr(f, 'abs_path', '') or getattr(f, 'path', '') or ''
                if p:
                    ioc['文件路径'].append(p)
        sr = report.dynamic.sandbox_result if report.dynamic else None
        if sr:
            for r in (sr.registry_created or [])[:20]:
                ioc['注册表'].append(r)
            for r in (sr.registry_modified or [])[:20]:
                ioc['注册表'].append(f'修改: {r}')
        if report.dynamic:
            for p in (report.dynamic.processes_created or [])[:10]:
                name = p.get('name', '')
                if name:
                    ioc['进程'].append(name)
        # 去重
        for k in ioc:
            ioc[k] = list(dict.fromkeys(ioc[k]))[:30]
        # 移除空项
        return {k: v for k, v in ioc.items() if v}

    # ============================================================
    # 防御/清除建议
    # ============================================================

    def _remediation(self, report):
        advice = []
        sr = report.dynamic.sandbox_result if report.dynamic else None
        # 持久化清理
        if sr and any('\\Run' in r for r in (sr.registry_created or []) + (sr.registry_modified or [])):
            advice.append('注册表恢复: 删除/恢复 HKCU\\...\\CurrentVersion\\Run 和 HKLM\\...\\Run 下的恶意启动项')
        if report.dynamic and report.dynamic.services_created:
            advice.append('服务清理: 删除样本创建的服务 (' + ', '.join(str(s)[:40] for s in report.dynamic.services_created[:3]) + ')')
        if report.dynamic and report.dynamic.scheduled_tasks:
            advice.append('计划任务清理: 删除样本创建的计划任务')
        # 文件清理
        if report.dropped_files and report.dropped_files.dropped_files:
            advice.append('文件清理: 删除样本释放的恶意文件（详见 IOC 汇总-文件路径）')
        # 杀软恢复
        dest = report.destruction
        if dest:
            if dest.av_termination or dest.defender_registry_disable:
                advice.append('安全软件恢复: 重新启动被终止的杀毒软件，恢复 Defender 防护设置')
            if getattr(dest, 'av_install_block', None):
                advice.append('禁装杀软修复: 样本禁用了 BITS/msiserver/wuauserv 等安装与更新服务 — 需恢复这些服务的启动类型后才能安装杀毒软件')
            if dest.uac_bypass_attempts:
                advice.append('UAC 恢复: 将 EnableLUA 恢复为 1，ConsentPromptBehaviorAdmin 恢复为默认值')
        # 网络
        net = report.network
        if net and net.tcp_connections:
            advice.append('网络检查: 检查系统代理设置和 hosts 文件，清理可疑连接')
        # 常规
        advice.append('全盘扫描: 使用杀毒软件进行全盘扫描，检查所有启动项')
        if getattr(report, 'risk_level', 'low') in ('critical', 'high'):
            advice.append('如果系统为重要生产环境，建议重装系统或从干净备份恢复')
        return advice

    # ============================================================
    # 技术总结
    # ============================================================

    def _technical_summary(self, report):
        summary = {}
        # MITRE 映射
        mitre = []
        sigma = getattr(report, '_sigma_matches', None) or []
        for s in sigma:
            t = getattr(s, 'title', '')
            if t:
                mitre.append(t)
        ab = report.advanced_behavior
        mitre_map = {
            'T1547.001': '启动项持久化 (Run键)', 'T1053.005': '计划任务持久化',
            'T1543.003': '服务持久化', 'T1548.002': 'UAC绕过',
            'T1055': '进程注入', 'T1055.012': '进程镂空', 'T1620': '反射加载',
            'T1059.001': 'PowerShell执行', 'T1059.007': 'JS/JScript执行',
            'T1218.011': 'Rundll32间接执行', 'T1027': '混淆',
            'T1562.001': '禁用安全工具', 'T1112': '修改注册表',
            'T1071.001': 'HTTP C2', 'T1497': '虚拟化/沙箱规避',
            'T1564.003': '隐藏窗口', 'T1070': '痕迹清除',
        }
        if ab:
            if getattr(ab, 'persistence', None): mitre.append('T1547/T1053/T1543 持久化')
            if ab.process_injection: mitre.append('T1055 进程注入')
            if ab.process_hollowing: mitre.append('T1055.012 进程镂空')
            if ab.uac_bypass: mitre.append('T1548.002 UAC绕过')
            if ab.anti_vm: mitre.append('T1497 反虚拟机')
            if ab.anti_sandbox: mitre.append('T1497.001 反沙箱')
            if ab.anti_debug: mitre.append('T1622 反调试')
            if ab.timing_evasion: mitre.append('T1497.003 时间规避')
            if ab.c2_communication: mitre.append('T1071 C2通信')
            if ab.keylogging: mitre.append('T1056.001 键盘记录')
            if ab.credential_theft: mitre.append('T1003 凭证窃取')
        if mitre:
            summary['MITRE ATT&CK'] = list(dict.fromkeys(mitre))[:20]

        # 混淆技术
        obf = []
        deobs = getattr(report, '_deobfuscation', None) or []
        for d in deobs[:10]:
            t = d.get('technique', '')
            if t:
                obf.append(t)
        if report.strings and report.strings.powershell_patterns:
            obf.append('PowerShell 编码/混淆')
        pe = report.pe_info
        if pe and pe.packer_info:
            obf.append(f"加壳: {'; '.join(pe.packer_info[:3])}")
        if obf:
            summary['混淆技术'] = list(dict.fromkeys(obf))[:10]

        # 关键检测
        detections = []
        if report.memory and report.memory.pe_in_memory:
            detections.append('内存PE注入/反射加载')
        if report.memory and report.memory.shellcode_found:
            detections.append('Shellcode')
        memprot = getattr(report, '_memprot_summary', None)
        if memprot and memprot.get('rw_to_rx'):
            detections.append('RW→RX 载荷解密执行')
        if memprot and memprot.get('rop_like'):
            detections.append('DEP绕过/ROP喷射 (超大RWX分配)')
        elif memprot and memprot.get('rwx_alloc'):
            detections.append('DEP绕过特征 (RWX分配)')
        if report.memory and report.memory.heavens_gate:
            detections.append('Heaven\'s Gate (32/64位切换)')
        yara = getattr(report, '_yara_matches', None) or []
        for y in yara[:3]:
            detections.append(f"YARA: {y.get('rule') or y.get('name', '')}")
        if detections:
            summary['关键检测'] = detections[:10]

        # 风险来源（评分最高的贡献项）
        summary['风险等级'] = f"{getattr(report, 'risk_level', 'low')} ({getattr(report, 'risk_score', 0)}/100)"
        return summary


# 便捷入口
def generate_summary_report(report, output_path):
    SummaryReportGenerator().generate(report, output_path)
