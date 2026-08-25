#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""清理脚本生成器 — 分析完成后生成杀毒清理 PowerShell 脚本

设计原则:
  - 只生成脚本, 绝不自动执行 (用户在目标机上手动运行)
  - 脚本自提权至 SYSTEM (schtasks 服务级任务, 已验证可行)
  - 清理清单来自分析报告: 源文件/释放物/进程/服务/计划任务/注册表/驱动
  - 银狐类随机名木马: 按"随机目录 + 无签名可执行文件"特征扫描清理
  - 重启验证: RunOnce 触发验证脚本, 检查清理项是否残留, 输出结果
  - 删除失败: 收集失败清单弹窗提醒用户
"""
import os
import re
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

# 系统白名单 — 清理脚本绝不触碰
_SYSTEM_DIRS = [
    'C:\\Windows', os.environ.get('SystemRoot', 'C:\\Windows').lower(),
]
_SYSTEM_PROCESSES = {
    'svchost.exe', 'conhost.exe', 'csrss.exe', 'lsass.exe', 'services.exe',
    'dwm.exe', 'wininit.exe', 'winlogon.exe', 'smss.exe', 'explorer.exe',
    'fontdrvhost.exe', 'dllhost.exe', 'msmpeng.exe', 'audiodg.exe',
    'runtimebroker.exe', 'searchindexer.exe', 'taskhostw.exe',
}

# 系统/用户常用工具进程 — 即使样本在沙箱中拉起过同名进程, 也不按名字
# 全局终止 (会误杀用户自己打开的同类进程); 有完整路径时才允许精确路径终止。
_SYSTEM_TOOL_PROCESSES = {
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'rundll32.exe', 'regsvr32.exe',
    'msiexec.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'schtasks.exe',
    'reg.exe', 'sc.exe', 'net.exe', 'netsh.exe', 'wmic.exe', 'taskkill.exe',
    'bcdedit.exe', 'vssadmin.exe', 'wevtutil.exe', 'icacls.exe', 'takeown.exe',
    'attrib.exe', 'whoami.exe', 'certutil.exe', 'curl.exe', 'bitsadmin.exe',
    'notepad.exe', 'mspaint.exe', 'explorer.exe',
}

# 随机名目录模式 (银狐/远控常用: C:\ProgramData\AbCd12ef\)
_RANDOM_DIR_PATTERNS = [
    (r'^[A-Za-z0-9]{5,9}$', '随机8字符目录(银狐特征)'),
    (r'^[A-Za-z]{1,3}[0-9]{2}[A-Za-z]{1,3}$', '随机字母数字目录'),
]
# 绝对不可视为随机名的目录段 (系统/用户目录)
_RANDOM_DIR_BLACKLIST = {
    'appdata', 'local', 'local', 'locallow', 'roaming', 'temp', 'users',
    'administrator', 'public', 'programdata', 'program files', 'program files (x86)',
    'windows', 'system32', 'syswow64', 'microsoft', 'desktop', 'documents',
    'downloads', 'pictures', 'music', 'videos', 'default', 'all users',
    'common', 'profile', 'onedrive', 'grabon', 'caches', 'cache',
}

_PS_ESCAPE_RE = re.compile(r'[^\x20-\x7e]')

# 变更箭头兼容 (diff 输出用 Unicode →, 外部数据可能用 ->)
_ARROW = r'(?:→|->)'


# 系统/厂商目录 — 任何清理操作(含特征扫描)绝不触碰 (防误杀: 曾误删 Defender 组件!)
_SAFE_DIR_PREFIXES = [
    r'C:\Windows', r'C:\ProgramData\Microsoft', r'C:\Program Files',
    r'C:\Program Files (x86)', r'C:\Users\Public\Microsoft',
    r'C:\Users\All Users\Microsoft', r'C:\ProgramData\Package Cache',
]
_SAFE_DIR_KEYWORDS = [
    r'\Windows Defender', r'\Microsoft', r'\System32', r'\SysWOW64',
    r'\Common Files', r'\WindowsApps',
]
# 放行区: 系统临时/缓存目录 (恶意服务镜像 ranchserv.jpg 等落在这里, 可清理)
_SAFE_PATH_ALLOW = [
    r'C:\Windows\Temp', r'C:\Windows\Prefetch',
]


def _is_safe_path(path: str) -> bool:
    """判定路径是否属于系统/厂商保护区 (清理永不触碰)

    安全优先: 宁可漏杀也不误删系统组件 (曾误删 Defender 组件导致系统防护瘫痪)
    """
    pl = (path or '').replace('/', '\\').lower()
    if not pl:
        return True
    # 显式放行区 (Windows\Temp 等)
    for a in _SAFE_PATH_ALLOW:
        if pl.startswith(a.lower()):
            return False
    for p in _SAFE_DIR_PREFIXES:
        if pl.startswith(p.lower()):
            return True
    for kw in _SAFE_DIR_KEYWORDS:
        if kw.lower() in pl:
            return True
    return False


def _ps_str(s: str) -> str:
    """转义 PowerShell 单引号字符串"""
    return "'" + str(s).replace("'", "''") + "'"


def _sanitize_scan_id(scan_id: str) -> str:
    """scan_id 只允许 [A-Za-z0-9_-], 防止注入生成脚本文件名/命令字符串"""
    sid = re.sub(r'[^A-Za-z0-9_-]', '_', str(scan_id or ''))
    return sid or 'scan'


def _register_kill_process(items: Dict, name: str, path: str = '') -> None:
    """登记要终止的进程。

    安全规则:
      1. 系统关键进程与常用系统工具进程绝不按名字登记 (否则会全机误杀);
      2. 有完整 exe 路径时按路径精确匹配; 仅当拿不到路径时才用名字兜底,
         且名字必须在非系统白名单之外。
    """
    name = str(name or '').strip()
    path = str(path or '').strip()
    nl = name.lower()
    if not name or not re.search(r'\.exe$', name, re.I):
        return
    if nl in _SYSTEM_PROCESSES or nl in _SYSTEM_TOOL_PROCESSES:
        # 系统工具只允许按完整路径精确终止 (样本释放的伪装文件除外)
        if not path or not os.path.isabs(path):
            return
        pl = path.lower().replace('/', '\\')
        if '\\windows\\' in pl or '\\program files' in pl:
            return  # 绝不登记系统目录里的真系统工具
        if path.lower().split('\\')[-1] != nl:
            return
    for item in items['kill_processes']:
        if item['name'].lower() == nl and (not path or item.get('path') == path):
            return
    items['kill_processes'].append({'name': name, 'path': path})


class SystemCleanupGenerator:
    """从分析报告生成杀毒清理脚本"""

    def __init__(self, output_dir: str = 'reports'):
        self.output_dir = output_dir

    # ==================== 主入口 ====================
    def generate(self, report, file_path: str = '') -> str:
        """生成清理脚本 + 验证脚本, 返回清理脚本路径; 无清理项时返回 ''"""
        items = self._collect_cleanup_items(report, file_path)
        if not items['has_items']:
            logger.info("[Cleanup] 无待清理项, 跳过脚本生成")
            return ''
        script = self._render(items, report)
        verify_script = self._render_verify(items)
        os.makedirs(self.output_dir, exist_ok=True)
        out = os.path.join(self.output_dir, f'cleanup_{items["scan_id"]}.ps1')
        with open(out, 'w', encoding='utf-8-sig', newline='\r\n') as f:
            f.write(script)
        if verify_script:
            vout = os.path.join(self.output_dir, f'verify_{items["scan_id"]}.ps1')
            with open(vout, 'w', encoding='utf-8-sig', newline='\r\n') as f:
                f.write(verify_script)
            logger.info(f"[Cleanup] 已生成重启验证脚本: {vout}")
        # CMD 启动器 — 双击运行, 规避执行策略提示 (Bypass)
        # ⚠ 必须 ASCII 无 BOM: cmd.exe 不识别 UTF-8 BOM, 中文注释会导致乱码
        ccmd = os.path.join(self.output_dir, f'run_cleanup_{items["scan_id"]}.cmd')
        with open(ccmd, 'w', encoding='ascii', newline='\r\n') as f:
            f.write('@echo off\r\n')
            f.write('rem Cleanup launcher - run with ExecutionPolicy Bypass\r\n')
            f.write('cd /d "%~dp0"\r\n')
            f.write(f'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0cleanup_{items["scan_id"]}.ps1" %*\r\n')
            f.write('pause\r\n')
        logger.info(f"[Cleanup] 已生成启动器(双击运行): {ccmd}")
        logger.warning(f"[Cleanup] 已生成杀毒清理脚本: {out}")
        logger.warning("[Cleanup] ⚠ 脚本不会自动执行 — 请确认环境后以管理员身份手动运行")
        return out

    def _render_verify(self, items: Dict) -> str:
        """重启验证脚本: 先重删失败项, 再检查清理项是否残留, 弹窗提醒"""
        if not items['verify_items']:
            return ''
        v = []
        a = v.append
        a('# ============================================================')
        a(f'# 重启验证脚本 — 扫描ID: {items["scan_id"]}')
        a('# 由 cleanup 脚本注册 RunOnce, 重启后自动运行')
        a('# ============================================================')
        a('$VerifyFile = Join-Path $env:ProgramData "cleanup_verify_' + items['scan_id'] + '.json"')
        a('$ResultFile = Join-Path $env:ProgramData "cleanup_result_' + items['scan_id'] + '.txt"')
        a('$RetryFile = Join-Path $env:ProgramData "cleanup_retry_' + items['scan_id'] + '.json"')
        a('')
        a('function Remove-ForceFile($path) {')
        a('    if (-not (Test-Path -LiteralPath $path)) { return $true }')
        a('    try { attrib -r -h -s -a "$path" 2>$null | Out-Null } catch {}')
        a('    try { takeown /f "$path" /a 2>$null | Out-Null } catch {}')
        a('    try { icacls "$path" /grant "*S-1-5-18:F" "*S-1-5-32-544:F" /c 2>$null | Out-Null } catch {}')
        a('    try {')
        a('        $acl = Get-Acl -LiteralPath $path -ErrorAction SilentlyContinue')
        a('        $denies = @($acl.Access | Where-Object { $_.AccessControlType -eq "Deny" })')
        a('        foreach ($d in $denies) { $null = $acl.RemoveAccessRule($d) }')
        a('        Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction SilentlyContinue')
        a('    } catch {}')
        a('    for ($i = 0; $i -lt 3; $i++) {')
        a('        try { Remove-Item -LiteralPath $path -Force -Recurse -ErrorAction Stop; return $true } catch { Start-Sleep -Seconds 2 }')
        a('    }')
        a('    return $false')
        a('}')
        a('')
        a('# ---- 1. 重启后重试删除失败项 (句柄已释放, ACL 已接管) ----')
        a('if (Test-Path $RetryFile) {')
        a('    try { $retry = Get-Content $RetryFile | ConvertFrom-Json } catch { $retry = @() }')
        a('    foreach ($it in $retry) {')
        a('        if ($it.path -and (Test-Path -LiteralPath $it.path)) {')
        a('            if (Remove-ForceFile $it.path) { Write-Host "[+] 重删成功: $($it.path)" -ForegroundColor Green }')
        a('            else { Write-Host "[-] 重删仍失败: $($it.path)" -ForegroundColor Red }')
        a('        }')
        a('    }')
        a('    Remove-Item $RetryFile -Force -ErrorAction SilentlyContinue')
        a('}')
        a('')
        a('# ---- 2. 检查清理项残留 ----')
        a('$remaining = @()')
        a('if (Test-Path $VerifyFile) {')
        a('    $items = Get-Content $VerifyFile | ConvertFrom-Json')
        a('    foreach ($it in $items) {')
        a('        if ($it.type -eq "file" -and (Test-Path -LiteralPath $it.path)) { [void]$remaining.Add("文件残留: $($it.path)") }')
        a('        elseif ($it.type -eq "dir" -and (Test-Path -LiteralPath $it.path)) { [void]$remaining.Add("目录残留: $($it.path)") }')
        a('        elseif ($it.type -eq "service" -and (Get-Service -Name $it.path -ErrorAction SilentlyContinue)) { [void]$remaining.Add("服务残留: $($it.path)") }')
        a('    }')
        a('    Remove-Item $VerifyFile -Force -ErrorAction SilentlyContinue')
        a('}')
        a('if ($remaining.Count -gt 0) {')
        a('    $remaining | Set-Content -Path $ResultFile -Encoding UTF8')
        a('    try {')
        a('        Add-Type -AssemblyName System.Windows.Forms')
        a('        [System.Windows.Forms.MessageBox]::Show("重启验证发现残留: $($remaining.Count) 项`n`n请查看: `n$ResultFile`n`n建议再次运行清理脚本或手动处理。", "杀毒验证 - 发现残留", "OK", "Warning") | Out-Null')
        a('    } catch { Start-Process notepad $ResultFile }')
        a('} else {')
        a('    Write-Host "[+] 重启验证通过: 清理项无残留" -ForegroundColor Green')
        a('}')
        a('Start-Sleep 3')
        return '\n'.join(v) + '\n'

    # ==================== 收集清理项 ====================
    def _collect_cleanup_items(self, report, file_path: str) -> Dict:
        items = {
            'has_items': False,
            'sample_file': '',
            'kill_processes': [],      # 终止项 {name, path} — 优先按完整路径精确终止
            'delete_files': [],        # 文件路径
            'delete_dirs': [],         # 目录路径
            'delete_services': [],     # 服务名
            'delete_tasks': [],        # 计划任务名
            'delete_registry': [],     # 要删除的注册表值 {key, value}
            'restore_registry': [],    # 要恢复的注册表值 {key, value, data, type} (原值还原)
            'clear_registry': [],      # 要清空的注册表值 {key, value}
            'restore_services': [],    # 要还原启动类型的服务 {name, start}
            'restore_defender': False, # 恢复被终止的 Windows Defender
            'check_defender_exclusion': False,  # 提示检查 Defender 排除
            'pattern_dirs': [],        # 随机名目录扫描根
            'verify_items': [],        # 重启验证项 {type, path}
            'delete_users': [],        # 新建恶意用户 (net user 删除)
            'remove_admins': [],       # 从 Administrators 组移除的成员
            'delete_fw_rules': [],     # 样本新增的防火墙规则 (交互确认)
            'restore_hosts': False,    # 还原被篡改的 hosts
            'report_listeners': [],    # 新增监听端口 (仅报告)
            'hijack_keys': [],         # 劫持键还原 {key, value, data} (Winlogon/AppInit)
            'delete_wmi': [],          # WMI 持久化订阅删除
            'report_ppl': [],          # PPL 保护进程 (仅报告)
            'report_sysfile': [],      # 被篡改的系统文件 (仅报告)
            'report_dns': [],          # 新增 DNS 解析 (C2 IoC 报告)
            'report_deleted_svc': [],  # 被删除的系统服务 (仅报告, 提示修复)
            'scan_id': _sanitize_scan_id(report.scan_id),
        }
        # 1. 样本源文件
        src = getattr(report, '_original_path', '') or (report.file_info.path if report.file_info else '')
        if src and os.path.exists(src):
            items['sample_file'] = src
            items['delete_files'].append(src)
        # 2. 释放文件 (可疑的)
        try:
            if report.dropped_files:
                for df in report.dropped_files.dropped_files:
                    p = getattr(df, 'abs_path', '') or ''
                    if not p or not os.path.exists(p):
                        continue
                    # ⚠ 安全边界: 系统/厂商目录(Defender/Microsoft/Windows)绝不清理
                    if _is_safe_path(p):
                        continue
                    items['delete_files'].append(p)
                    items['verify_items'].append({'type': 'file', 'path': p})
        except Exception:
            pass
        # 3. 随机名目录识别 (银狐) — 从释放路径提取目录特征
        #    ⚠ 优先检查"文件所在目录", 匹配即停; 不匹配才回溯父目录。
        #      避免把 AppData/Local/Temp/Users 等正常目录误判为随机目录
        try:
            seen_dirs = set()
            for df in report.dropped_files.dropped_files:
                p = str(getattr(df, 'abs_path', '') or '')
                parts = p.replace('/', '\\').split('\\')
                if len(parts) < 4:
                    continue
                for i in (len(parts) - 2, len(parts) - 3):
                    if i < 2:
                        break
                    d = parts[i]
                    dl = d.lower()
                    if dl in _RANDOM_DIR_BLACKLIST:
                        continue
                    if not any(re.match(pat, d) for pat, _ in _RANDOM_DIR_PATTERNS):
                        continue
                    base = '\\'.join(parts[:i + 1])
                    base_l = base.lower()
                    if any(base_l.startswith(sd.lower()) for sd in _SYSTEM_DIRS):
                        continue
                    if base not in seen_dirs:
                        seen_dirs.add(base)
                        items['delete_dirs'].append(base)
                        items['verify_items'].append({'type': 'dir', 'path': base})
                        items['pattern_dirs'].append(base)
                    break  # 命中即停, 不再回溯更上层
        except Exception:
            pass
        # 4. 进程
        try:
            for p in report.dynamic.processes_created or []:
                name = str(p.get('name', '') or '')
                exe = str(p.get('exe', '') or '')
                if name.lower() == os.path.basename(src or '').lower():
                    continue
                _register_kill_process(items, name, exe)
            # 4b. 进程 diff 的新启动进程 (bqGdr1.exe 等 — 不在 processes_created)
            #     ⚠ 误杀防护: 只对"exe 路径匹配样本释放物"的才加入 kill 列表;
            #     其余仅报告 (分析期间系统也可能启动新进程, 冒然全杀会误杀系统程序)
            try:
                sysmon = getattr(report.dynamic, '_system_monitor', None) or {}
                started = (sysmon.get('process_diff', {}) or {}).get('started_processes', {}) or {}
                # 样本释放物的路径集合 (用于匹配新进程 exe)
                released_paths = []
                try:
                    for df in report.dropped_files.dropped_files:
                        p = str(getattr(df, 'abs_path', '') or '')
                        if p:
                            released_paths.append(p.lower())
                except Exception:
                    pass
                for name, pid in (started.items() if isinstance(started, dict) else []):
                    name = str(name)
                    if name.lower() in _SYSTEM_PROCESSES:
                        continue
                    # 通过 pid 查 exe 路径 (进程可能已死, 尽力而为)
                    exe_path = ''
                    try:
                        import psutil as _ps
                        exe_path = (_ps.Process(pid).exe() or '').lower()
                    except Exception:
                        pass
                    # 规则: exe 匹配释放物 或 进程名与释放物文件名精确匹配 → 杀
                    # (进程可能已死拿不到 exe 路径, 名字匹配兜底; 系统进程不会与恶意释放物重名)
                    matched = False
                    if exe_path and any(exe_path == rp or exe_path.startswith(rp.rstrip('.exe'))
                                        for rp in released_paths):
                        matched = True
                    if not matched:
                        try:
                            import os as _os
                            matched = any(
                                _os.path.basename(rp).lower() == name.lower()
                                for rp in released_paths)
                        except Exception:
                            pass
                    if not matched:
                        logger.info(f"[Cleanup] 新进程(仅报告,不杀): {name} (PID={pid}, exe={exe_path or '未知'})")
                        continue
                    _register_kill_process(items, name, exe_path)
            except Exception:
                pass
        except Exception:
            pass
        # 5. 服务
        try:
            for s in report.dynamic.services_created or []:
                name = str(s.get('name', '') if isinstance(s, dict) else s)
                if name and name not in items['delete_services']:
                    items['delete_services'].append(name)
                    items['verify_items'].append({'type': 'service', 'path': name})
        except Exception:
            pass
        # 6. 计划任务
        try:
            for t in report.dynamic.scheduled_tasks or []:
                name = str(t.get('name', '') if isinstance(t, dict) else t)
                if name and name not in items['delete_tasks']:
                    items['delete_tasks'].append(name)
        except Exception:
            pass
        # 7. 注册表: 删除恶意项 / 恢复被改设置
        try:
            for r in report.dynamic.registry_modified or []:
                key = str(r.get('key', '') if isinstance(r, dict) else r)
                val = str(r.get('value_name', '') if isinstance(r, dict) else '')
                kl = key.lower()
                # 删除: 启动项/Console C2 配置/防御规避键
                if re.search(r'(?i)(\\run\b|runonce|console|policies\\system|defender)', key):
                    items['delete_registry'].append({'key': key, 'value': val})
                # 恢复: 代理设置
                if 'internet settings' in kl and 'proxyenable' in val.lower():
                    items['restore_registry'].append(
                        {'key': r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                         'value': 'ProxyEnable', 'data': '0', 'type': 'DWord'})
                # 恢复: UAC — 微软默认值: EnableLUA=1, ConsentPromptBehaviorAdmin=5,
                # PromptOnSecureDesktop=1 (旧代码固定写 1, ConsentPrompt 不符合默认)
                if 'policies\\system' in kl and val.lower() in ('enablelua', 'consentpromptbehavioradmin', 'promptonsecuredesktop'):
                    _uac_defaults = {'enablelua': '1',
                                     'consentpromptbehavioradmin': '5',
                                     'promptonsecuredesktop': '1'}
                    items['restore_registry'].append(
                        {'key': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                         'value': val, 'data': _uac_defaults.get(val.lower(), '1'),
                         'type': 'DWord'})
        except Exception:
            pass
        # 8. Defender 排除检查
        try:
            blob = ''
            if report.strings:
                blob += ' '.join(report.strings.suspicious_strings or []) + ' '
            if re.search(r'(?i)(add-mppreference|exclusionpath)', blob):
                items['check_defender_exclusion'] = True
        except Exception:
            pass
        # 9. 行为时间线/系统监控驱动的自适应还原 — 针对每个分析程序的实际行为
        #    (服务禁用原值还原/新服务ImagePath文件/被杀杀软恢复/Run值路径提取/PendingFileRename)
        self._collect_from_sysmon(report, items)
        # 9b. 系统状态扩展: 新建用户/管理员组/防火墙规则/hosts/监听端口/劫持键
        self._collect_from_system_state(report, items)
        # 10. 特征归纳 — 从分析结果提取泛化检测规则 (变种/随机名也可覆盖)
        self._collect_features(report, items)
        items['has_items'] = bool(
            items['delete_files'] or items['delete_dirs'] or items['kill_processes']
            or items['delete_services'] or items['delete_tasks']
            or items['delete_registry'] or items['restore_registry']
            or items['clear_registry'] or items['restore_services']
            or items['restore_defender'] or items['delete_users']
            or items['remove_admins'] or items['delete_fw_rules']
            or items['restore_hosts'] or items['hijack_keys']
            or items['delete_wmi'] or items['report_ppl'] or items['report_sysfile']
            or items['report_dns'] or items['report_deleted_svc'])
        return items

    def _collect_from_system_state(self, report, items: Dict):
        """系统状态扩展 — 新建用户/管理员组/防火墙规则/hosts/监听端口/劫持键"""
        if not report.dynamic:
            return
        sysmon = getattr(report.dynamic, '_system_monitor', None) or {}
        ud = (sysmon.get('user_diff', {}) or {})
        # 1) 新建用户 → 删除 (排除系统默认账户)
        _SYSTEM_ACCOUNTS = {'administrator', 'guest', 'defaultaccount', 'wdagutilityaccount',
                            'defaultuser0', 'system', 'local service', 'network service'}
        try:
            for u in (ud.get('new_users', []) or []):
                if u.lower() not in _SYSTEM_ACCOUNTS:
                    items['delete_users'].append(u)
        except Exception:
            pass
        # 2) 新增管理员成员 → 移出管理员组
        try:
            for m in (ud.get('new_admins', []) or []):
                if m.lower() not in _SYSTEM_ACCOUNTS:
                    items['remove_admins'].append(m)
        except Exception:
            pass
        # 3) 新增防火墙规则 → 删除 (交互确认, 防误删系统规则)
        try:
            for r in (ud.get('new_fw_rules', []) or [])[:20]:
                if r.strip() and not r.startswith('@') and '远程协助' not in r and 'RemoteAssistance' not in r:
                    items['delete_fw_rules'].append(r)
        except Exception:
            pass
        # 4) 新增监听端口 → 报告 (关联进程显示, 不自动处理)
        try:
            items['report_listeners'] = (ud.get('new_listeners', []) or [])[:10]
        except Exception:
            pass
        # 5) hosts 被篡改 → 还原 (银狐禁装杀软: 劫持杀软官网/更新域名到 127.0.0.1)
        #    ⚠ system_monitor 的判定 (非注释行>127.0.0.1行数) 在纯劫持文件下失效,
        #    这里直接扫描 hosts 内容, 命中杀软域名劫持即触发
        try:
            _hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
            if os.path.exists(_hosts_path):
                with open(_hosts_path, 'r', encoding='utf-8', errors='ignore') as _hf:
                    _hosts_content = _hf.read().lower()
                _av_kw = ('360.cn', '360safe.com', 'huorong', 'kaspersky', 'avast',
                          'defender', 'windowsupdate', 'microsoft.com', 'mcafee',
                          'symantec', 'trendmicro', 'bitdefender', 'eset', 'avg.com',
                          'qqpcmgr', 'rising', 'antivirus')
                _hijacked = any(
                    re.search(r'^\s*(?:127\.0\.0\.1|0\.0\.0\.0)\s+[^\s]*' + re.escape(k), _hosts_content, re.M)
                    for k in _av_kw)
                if _hijacked or any('Hosts' in d for d in (sysmon.get('raw_detections', []) or [])):
                    items['restore_hosts'] = True
        except Exception:
            pass
        # 6) 劫持键还原: Winlogon/AppInit_DLLs/IFEO (来自注册表 diff 类别)
        try:
            for ch in (sysmon.get('raw_changes', []) or []):
                cat = str(ch.get('category', '') or '')
                key = str(ch.get('key', '') or '')
                if cat == 'Winlogon':
                    items['hijack_keys'].append(
                        {'key': key, 'value': 'Userinit', 'data': 'C:\\Windows\\system32\\userinit.exe,'})
                    items['hijack_keys'].append(
                        {'key': key, 'value': 'Shell', 'data': 'explorer.exe'})
                elif cat == 'Persistence_DLL':
                    items['hijack_keys'].append({'key': key, 'value': 'AppInit_DLLs', 'data': ''})
                elif cat == 'ImageHijack':
                    items['delete_registry'].append({'key': key, 'value': ''})
                elif cat == 'Browser_BHO':
                    # BHO 劫持 → 删除新增的 CLSID 子键
                    items['delete_registry'].append({'key': key, 'value': ''})
                elif cat == 'Policies_Run':
                    # 组策略启动项 → 删除值
                    items['delete_registry'].append({'key': key, 'value': ''})
        except Exception:
            pass
        # 7) WMI 持久化订阅 → 删除 (远控常用持久化)
        try:
            ud = (sysmon.get('user_diff', {}) or {})
            wmi_new = (ud.get('new_wmi_filters', []) or []) + \
                      (ud.get('new_wmi_consumers', []) or []) + \
                      (ud.get('new_wmi_bindings', []) or [])
            for w in wmi_new[:10]:
                name = str(w).split('|')[0].strip()
                if name:
                    items['delete_wmi'].append(name)
        except Exception:
            pass
        # 7b) PPL 新增进程 → 报告 (受保护进程无法直接杀, 提示用户)
        try:
            ud = (sysmon.get('user_diff', {}) or {})
            items['report_ppl'] = (ud.get('ppl_added', []) or [])[:8]
        except Exception:
            pass
        # 7c) 系统文件被篡改 → 报告 (无法自动还原, 提示系统修复)
        #     ⚠ 用 extend 合并 — _collect_from_sysmon 的 KnownDLLs 分支也会写入该列表,
        #     用 = 覆盖会丢失 KnownDLLs 劫持报告!
        try:
            ud = (sysmon.get('user_diff', {}) or {})
            _sysf = (ud.get('sysfile_changed', []) or [])[:8]
            for _s in _sysf:
                if _s not in items['report_sysfile']:
                    items['report_sysfile'].append(_s)
        except Exception:
            pass
        # 7d) Code Integrity 策略 (CI/CiPolicies) → 还原
        try:
            for ch in (sysmon.get('raw_changes', []) or []):
                key = str(ch.get('key', '') or '')
                if 'CodeIntegrity' in key or 'CI\\Policy' in key:
                    items['delete_registry'].append({'key': key, 'value': ''})
        except Exception:
            pass
        # 7e) DNS 新增解析 → 报告 IoC (C2 域名)
        try:
            ud = (sysmon.get('user_diff', {}) or {})
            items['report_dns'] = (ud.get('new_dns', []) or [])[:10]
        except Exception:
            pass
        # 8) 服务 ServiceDll 注入 → 还原 (来自注册表 diff: 服务 modified 的 Parameters\ServiceDll)
        try:
            for ch in (sysmon.get('raw_changes', []) or []):
                if ch.get('category') == 'Service' and ch.get('type') == 'modified':
                    vals = str(ch.get('values', '') or '')
                    if 'ServiceDll' in vals:
                        svc = str(ch.get('key', '')).replace('Services\\', '').strip()
                        if svc:
                            items['hijack_keys'].append(
                                {'key': rf'HKLM\SYSTEM\CurrentControlSet\Services\{svc}\Parameters',
                                 'value': 'ServiceDll', 'data': ''})
        except Exception:
            pass

    def _collect_features(self, report, items: Dict):
        """特征归纳 — 面向结果编程的补强: 把分析结论转成泛化检测规则

        变种/随机名样本的应对:
          - 家族特征字符串 (家族库内置特征 — SilverFox 的 UxEnhance64/ranchserv 等)
          - C2 域名/URL 是最强家族特征 (换壳不换 C2, 含 RAT 配置提取)
          - 随机目录/文件名命名模式 (银狐随机8字符)
          - 无数字签名 + 非标准目录运行
          - PE 编译时间窗口 (同批次编译的变种)
          - 服务 ImagePath 异常 (指向数据文件/随机目录)
        """
        feats = {
            'c2_domains': [],          # 家族 C2 域名 (内容匹配 = 高置信)
            'c2_urls': [],             # C2 URL
            'random_dir_pattern': False,  # 启用随机目录模式扫描
            'unsigned_only': False,    # 样本/释放物无签名
            'compile_window': [],      # [ts_start, ts_end] 编译时间窗 (Unix 秒)
            'compile_str': '',         # 编译时间展示串
            'service_abnormal': False, # 服务 ImagePath 异常 (jpeg 等非exe/随机目录)
            'run_abnormal': False,     # Run 键指向非标准目录
            'family_names': [],        # 家族名 (SilverFox 等)
            'family_strings': [],      # 家族特征字符串 (内容匹配变种)
            'random_filename': False,  # 随机文件名模式 (银狐 8 字符 exe)
            'seed_files': [],          # 种子文件(样本+释放物), 用于内容特征提取
        }
        # 0) 家族名 — 优先提取 (家族字符串依赖)
        try:
            if report.malware_family and report.malware_family.primary_family not in ('Unknown', ''):
                feats['family_names'].append(report.malware_family.primary_family)
            for rc in (getattr(report, '_rat_config', []) or []):
                fam = rc.get('family', '')
                if fam and fam not in feats['family_names']:
                    feats['family_names'].append(fam)
        except Exception:
            pass
        # 0b) 家族特征字符串 — 家族库内置的家族专属特征 (变种共享, 内容匹配)
        try:
            from analyzer.family import FamilyAnalyzer
            fam_sigs = getattr(FamilyAnalyzer, 'FAMILY_SIGNATURES', {})
            for fam in feats['family_names']:
                sig = fam_sigs.get(fam)
                if sig:
                    for s in (sig.get('strings') or [])[:15]:
                        if len(s) >= 4 and s not in feats['family_strings']:
                            feats['family_strings'].append(s)
        except Exception:
            pass
        # 1) C2 域名/URL — 从威胁情报/字符串/RAT配置/DeepDive 提取
        try:
            seen = set()
            if report.network:
                for d in (report.network.dns_queries or []):
                    if d.domain and d.domain not in seen:
                        seen.add(d.domain)
                        feats['c2_domains'].append(d.domain)
                for conn in (report.network.tcp_connections or []) + (report.network.udp_connections or []):
                    if conn.is_suspicious and conn.remote_addr and re.search(
                            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', conn.remote_addr):
                        if conn.remote_addr not in seen:
                            seen.add(conn.remote_addr)
                            feats['c2_domains'].append(conn.remote_addr)
            if report.strings:
                for u in (report.strings.urls or [])[:10]:
                    m = re.search(r'https?://([^/]+)', u)
                    if m and m.group(1) not in seen:
                        seen.add(m.group(1))
                        feats['c2_domains'].append(m.group(1))
                        feats['c2_urls'].append(u[:150])
            try:
                dd_net = getattr(getattr(report, '_deep_dive', None), 'network_profile', None)
                if dd_net:
                    for c in (dd_net.c2_candidates or []):
                        h = c.get('host', '')
                        if h and h not in seen:
                            seen.add(h)
                            feats['c2_domains'].append(h)
            except Exception:
                pass
            # 1b) C2 从 RAT/Stealer 配置提取 (网络未外联时的最强特征来源!)
            try:
                for rc in (getattr(report, '_rat_config', []) or []):
                    cfg = rc.get('config', {}) or {}
                    if isinstance(cfg, dict):
                        for v in cfg.values():
                            if not isinstance(v, str):
                                continue
                            for m in re.finditer(r'https?://([^/\s"\']+)', v):
                                if m.group(1) not in seen:
                                    seen.add(m.group(1))
                                    feats['c2_domains'].append(m.group(1))
                            for m in re.finditer(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', v):
                                if m.group(0) not in seen:
                                    seen.add(m.group(0))
                                    feats['c2_domains'].append(m.group(0))
                    for k in ('host', 'server', 'c2', 'url', 'ip', 'domain'):
                        v = cfg.get(k, '') if isinstance(cfg, dict) else ''
                        if isinstance(v, str) and v and v not in seen:
                            seen.add(v)
                            feats['c2_domains'].append(v)
            except Exception:
                pass
            # 过滤本地地址
            feats['c2_domains'] = [d for d in feats['c2_domains']
                                   if d not in ('0.0.0.0', '127.0.0.1', 'localhost')][:12]
        except Exception:
            pass
        # 1c) 随机文件名模式 — 释放物文件名随机 (银狐 8 字符 exe/dll)
        try:
            for f in items['delete_files']:
                base = os.path.basename(f)
                name, ext = os.path.splitext(base)
                if ext.lower() in ('.exe', '.dll', '.scr') and re.match(r'^[A-Za-z0-9]{5,9}$', name):
                    feats['random_filename'] = True
                    break
        except Exception:
            pass
        # 2) 随机目录模式 — 已识别出随机目录则启用模式扫描
        if items['pattern_dirs']:
            feats['random_dir_pattern'] = True
        # 3) 无签名特征 — 样本/释放物均无有效签名
        try:
            unsigned = 0
            total = 0
            for f in items['delete_files']:
                if not os.path.exists(f):
                    continue
                total += 1
                try:
                    import subprocess as _sp
                    # ⚠ 路径必须经 _ps_str 转义, 含单引号/特殊字符的路径可注入命令
                    _ps_f = _ps_str(f)
                    r = _sp.run(['powershell', '-NoProfile', '-Command',
                                 f'$s=Get-AuthenticodeSignature -LiteralPath {_ps_f};'
                                 f'if($s.Status -eq "Valid"){{"VALID"}}else{{"INVALID"}}'],
                                capture_output=True, text=True, errors='ignore', timeout=20)
                    # ⚠ 精确匹配: 'VALID'/'INVALID' (子串匹配会误判: 'SIGNED' in 'UNSIGNED'!)
                    status = r.stdout.strip().splitlines()[-1].strip().upper() if r.stdout.strip() else ''
                    if status == 'VALID':
                        continue
                    unsigned += 1
                except Exception:
                    unsigned += 1
            if total > 0 and unsigned >= total * 0.5:
                feats['unsigned_only'] = True
        except Exception:
            pass
        # 4) 编译时间窗口 — 样本与释放物的 PE 时间戳
        try:
            ts_list = []
            for p in ([getattr(report, '_original_path', '') or ''] if report else []):
                pass
            paths = [getattr(report, '_original_path', '') or '']
            try:
                paths += [getattr(df, 'abs_path', '') or '' for df in report.dropped_files.dropped_files]
            except Exception:
                pass
            for p in paths:
                if not p or not os.path.exists(p) or os.path.getsize(p) < 0x40:
                    continue
                try:
                    with open(p, 'rb') as fh:
                        head = fh.read(0x100)
                    if head[:2] != b'MZ':
                        continue
                    pe_off = int.from_bytes(head[0x3C:0x40], 'little')
                    if pe_off + 8 > len(head):
                        continue
                    ts = int.from_bytes(head[pe_off + 8:pe_off + 12], 'little')
                    if 1000000000 < ts < 3000000000:  # 2001-2065 合理范围
                        ts_list.append(ts)
                except Exception:
                    continue
            if len(ts_list) >= 1:
                ts_list.sort()
                lo, hi = ts_list[0], ts_list[-1]
                feats['compile_window'] = [lo - 5 * 86400, hi + 5 * 86400]  # ±5天容差
                try:
                    import datetime
                    feats['compile_str'] = f"{datetime.datetime.fromtimestamp(lo).strftime('%Y-%m-%d')} ~ " \
                                           f"{datetime.datetime.fromtimestamp(hi).strftime('%Y-%m-%d')}"
                except Exception:
                    pass
        except Exception:
            pass
        # 5) 服务异常 — 新建服务 ImagePath 指向非 exe/sys 或非系统目录
        try:
            sysmon = getattr(report.dynamic, '_system_monitor', None) or {}
            for ch in (sysmon.get('raw_changes', []) or []):
                if ch.get('category') == 'Service' and ch.get('type') == 'created':
                    m = re.search(r'ImagePath\s*=\s*(.+?)(?:,|$)', str(ch.get('values', '')))
                    if m:
                        ip = m.group(1).replace(r'\??\\', '')
                        if not re.search(r'\.exe$|\.sys$', ip, re.I):
                            feats['service_abnormal'] = True
                            break
        except Exception:
            pass
        # 6) Run 键异常 — 指向 Public/ProgramData/随机目录
        try:
            for reg in items['delete_registry']:
                if '\\run' in reg.get('key', '').lower():
                    feats['run_abnormal'] = True
                    break
        except Exception:
            pass
        # 8) 种子文件 (样本+已知释放物) — 供脚本内容特征提取
        feats['seed_files'] = [f for f in (items['delete_files'] + items['delete_dirs'])
                               if os.path.exists(f)][:15]
        items['features'] = feats

    def _collect_from_sysmon(self, report, items: Dict):
        """从系统监控 diff 结果提取还原动作 (含原值!) — 让脚本随样本行为自适应"""
        if not report.dynamic:
            return
        sysmon = getattr(report.dynamic, '_system_monitor', None) or {}
        try:
            for ch in (sysmon.get('raw_changes', []) or []):
                t = ch.get('type', '')
                key = str(ch.get('key', '') or '')
                cat = str(ch.get('category', '') or '')
                vals = str(ch.get('values', '') or '')
                key_l = key.lower()
                if not key:
                    continue
                if cat == 'Service':
                    svc = key.replace('Services\\', '').strip()
                    if t == 'created':
                        # 新服务 → 删服务 + ImagePath 指向的文件(含 system32 驱动!)
                        if svc and svc not in items['delete_services']:
                            items['delete_services'].append(svc)
                        m = re.search(r'ImagePath\s*=\s*(.+?)(?:,|$)', vals)
                        if m:
                            path = m.group(1).strip().strip('"')
                            path = path.replace(r'\??\\', '')  # \??\C:\... 设备路径
                            # 新服务是样本创建的, 其 ImagePath 即样本释放物 — 无条件纳入清理
                            # (脚本运行时 Test-Path 判断, 不依赖生成时文件存在)
                            # ⚠ 安全边界: 指向系统/厂商目录的 ImagePath 不删 (防误删系统服务组件)
                            if path and not _is_safe_path(path) and path not in items['delete_files']:
                                items['delete_files'].append(path)
                                items['verify_items'].append({'type': 'file', 'path': path})
                    elif t == 'modified':
                        # 服务配置被改 → 还原 Start 原值 (UsoSvc/WaaSMedicSvc/wuauserv 场景)
                        # ⚠ diff 输出格式: "Start: DWORD:2 → DWORD:3" — 必须先吃掉 DWORD: 前缀
                        # 否则 (\w+) 吞掉 "DWORD" 后箭头永远不匹配, 服务还原全部失效!
                        m = re.search(
                            r'Start\s*:\s*(?:DWORD:)?(\w+)\s*' + _ARROW + r'\s*(?:DWORD:)?(\w+)',
                            vals)
                        if m and m.group(1) != m.group(2):
                            old_val = m.group(1)
                            if old_val.isdigit():
                                items['restore_services'].append({'name': svc, 'start': old_val})
                    elif t == 'deleted':
                        # 服务被整个删除 (银狐禁装杀软: 直接删 WinDefend/wdboot/wdfilter
                        # 等注册表项 → 杀软引擎/驱动无法加载)。无法自动重建服务项,
                        # 但需报告 + 归入 Defender 恢复流程 (sfc/dism 修复提示)。
                        items['report_deleted_svc'].append(svc)
                        if svc.lower() in ('windefend', 'wdboot', 'wdfilter', 'wdnisdrv',
                                           'wscsvc', 'securityhealthservice', 'sense'):
                            items['restore_defender'] = True
                elif cat == 'Persistence_Run':
                    # Run 值 → 删除值 + 提取指向路径删除文件 (zPef0a.exe 场景)
                    for m in re.finditer(r'([^\s,;]+)\s*' + _ARROW + r'\s*"([^"]+)"', vals):
                        vname, path = m.group(1).strip(), m.group(2).strip()
                        if vname:
                            items['delete_registry'].append({'key': key, 'value': vname})
                        if path.lower().endswith(('.exe', '.dll', '.bat', '.scr', '.ps1', '.vbs')) \
                                and os.path.exists(path) and path not in items['delete_files']:
                            items['delete_files'].append(path)
                            items['verify_items'].append({'type': 'file', 'path': path})
                            # 持久化进程必须先杀, 否则文件被占用删不掉
                            _proc_name = os.path.basename(path)
                            if _proc_name.lower().endswith('.exe'):
                                _register_kill_process(items, _proc_name, path)
                elif cat == 'SecurityPolicy':
                    # UAC 禁用等 → 还原原值 (不是固定 1, 是时间线给的原始值)
                    for m in re.finditer(r'(\w+)\s*:\s*(\S+)\s*' + _ARROW + r'\s*(\S+)', vals):
                        vname, old_v, new_v = m.group(1), m.group(2), m.group(3)
                        if vname.lower() in ('enablelua', 'consentpromptbehavioradmin',
                                             'promptonsecuredesktop'):
                            items['restore_registry'].append(
                                {'key': key, 'value': vname, 'data': old_v, 'type': 'DWord'})
                elif cat == 'Browser':
                    # 代理等 → 还原原值
                    for m in re.finditer(r'(\w+)\s*:\s*(\S+)\s*' + _ARROW + r'\s*(\S+)', vals):
                        vname, old_v = m.group(1), m.group(2)
                        if 'proxy' in vname.lower():
                            items['restore_registry'].append(
                                {'key': key, 'value': vname, 'data': old_v, 'type': 'DWord'})
                # Session Manager: PendingFileRenameOperations (样本安排的重启后文件操作)
                # ⚠ 整值删除会破坏系统既有待处理操作 (Windows Update 等) —
                # 只记录报告提示, 不自动清空。
                if 'session manager' in key_l and 'pendingfilerename' in vals.lower():
                    items['report_sysfile'].append(
                        f'Session Manager PendingFileRenameOperations 被修改: {key} ({vals[:200]})')
                # Defender 策略禁用 → 恢复 (银狐禁装杀软核心手法:
                # DisableAntiSpyware/DisableAntiVirus/DisableRealtimeMonitoring=1)
                if cat == 'Defender' or 'windows defender' in key_l:
                    for m in re.finditer(r'(\w+)\s*:\s*\S+\s*' + _ARROW + r'\s*(\S+)', vals):
                        vname = m.group(1)
                        if vname.lower() in ('disableantispyware', 'disableantivirus',
                                             'disablerealtimemonitoring',
                                             'disableavsecurityprovidersupdate'):
                            items['delete_registry'].append({'key': key, 'value': vname})
                            items['restore_defender'] = True
                # Defender 实际排除项被添加 (HKLM\...\Windows Defender\Exclusions —
                # 与 Policies 不同, 这是引擎实际生效的排除; 银狐必加自己)
                if cat == 'Defender_Exclusions':
                    # 值名为数字序号 (0,1,2...), 新值即被排除的路径 — 全部删除
                    for m in re.finditer(r'(?:^|;\s*)(\d+)\s*:', vals):
                        items['delete_registry'].append({'key': key, 'value': m.group(1)})
                    items['restore_defender'] = True
                # Defender Tamper Protection 被关闭
                if cat == 'Defender_Features':
                    for m in re.finditer(r'(\w+)\s*:\s*\S+\s*' + _ARROW + r'\s*(\S+)', vals):
                        vname = m.group(1)
                        if 'tamper' in vname.lower():
                            items['restore_registry'].append(
                                {'key': key, 'value': vname, 'data': '4', 'type': 'DWord'})
                            items['restore_defender'] = True
                # LSA 安全包/通知包 (SSP 注入 — 远控持久化) → 报告提示, 不整值删除
                # (整值删除会移除系统原有的合法安全包, 可能导致 LSA 认证异常)
                if cat == 'LSA_Security':
                    for vname in ('Security Packages', 'Notification Packages',
                                  'Authentication Packages'):
                        if vname.lower() in vals.lower():
                            items['report_sysfile'].append(
                                f'LSA {vname} 被修改: {key} ({vals[:200]})')
                    if 'uselogoncredential' in vals.lower():
                        items['restore_registry'].append(
                            {'key': key, 'value': 'UseLogonCredential', 'data': '0', 'type': 'DWord'})
                # KnownDLLs 系统 DLL 劫持 (白加黑全局钩子) → 报告
                if cat == 'KnownDLLs':
                    items['report_sysfile'].append(f'KnownDLLs 被修改: {key} ({vals[:120]})')
                # 文件关联劫持 (exe/txt/lnk 打开方式被改) → 删除默认值
                if cat == 'FileAssociation':
                    items['delete_registry'].append({'key': key, 'value': ''})
                # 用户环境变量 (UserInitMprLogonScript — 登录脚本持久化)
                if cat == 'UserEnvironment':
                    if 'userinitmprlogonscript' in vals.lower():
                        items['delete_registry'].append(
                            {'key': key, 'value': 'UserInitMprLogonScript'})
                # TimeProviders/PrintMonitors/NetworkProvider/ShellHooks (隐蔽持久化) → 删除新增项
                if cat in ('TimeProviders', 'PrintMonitors', 'NetworkProvider', 'ShellHooks'):
                    for m in re.finditer(r'([^:;]+?)\s*:\s*\S+\s*' + _ARROW + r'\s*\S+', vals):
                        vn = m.group(1).strip()
                        if vn:
                            items['delete_registry'].append({'key': key, 'value': vn})
                # 系统还原被禁用 (勒索) → 恢复 DisableSR=0
                if cat == 'SystemRestore':
                    for m in re.finditer(r'(\w+)\s*:\s*\S+\s*' + _ARROW + r'\s*(\S+)', vals):
                        if m.group(1).lower() in ('disablesr', 'disableconfig'):
                            items['restore_registry'].append(
                                {'key': key, 'value': m.group(1), 'data': '0', 'type': 'DWord'})
                # 屏幕保护程序劫持 (SCRNSAVE.EXE 指向恶意程序) → 删除
                if cat == 'ScreenSaver':
                    if 'scrnsave' in vals.lower():
                        items['delete_registry'].append({'key': key, 'value': 'SCRNSAVE'})
        except Exception:
            pass
        # 被杀的安全产品 → 恢复 Defender
        try:
            killed_sec = (sysmon.get('process_diff', {}) or {}).get('killed_security_products', {}) or {}
            if killed_sec or any('SecurityKilled' in d for d in (sysmon.get('raw_detections', []) or [])):
                items['restore_defender'] = True
        except Exception:
            pass
        return items

    # ==================== 脚本渲染 ====================
    def _render(self, items: Dict, report) -> str:
        s = []
        a = s.append
        a('# ============================================================')
        a(f'# 自动杀毒清理脚本 — 由沙箱分析平台生成')
        a(f'# 扫描ID: {items["scan_id"]}')
        a(f'# 生成时间: {__import__("time").strftime("%Y-%m-%d %H:%M:%S")}')
        a('#')
        a('# ⚠⚠⚠ 安全警告 ⚠⚠⚠')
        a('#  1. 本脚本会删除文件/服务/注册表项 — 请确认环境后运行')
        a('#  2. 首次运行默认进入「交互确认」模式, 逐项确认')
        a('#  3. 使用 -Auto 参数全自动运行 (自动提权至 SYSTEM)')
        a('#  4. 使用 -SkipReboot 跳过重启验证')
        a('#  用法: powershell -ExecutionPolicy Bypass -File ' + _ps_str(os.path.basename(
            f'cleanup_{items["scan_id"]}.ps1')) + ' [-Auto] [-SkipReboot]')
        a('# ============================================================')
        a('param([switch]$Auto, [switch]$SkipReboot)')
        a('$ErrorActionPreference = "Continue"')
        a('$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path')
        a('$VerifyFile = Join-Path $env:ProgramData "cleanup_verify_' + items['scan_id'] + '.json"')
        a('$ResultFile = Join-Path $env:ProgramData "cleanup_result_' + items['scan_id'] + '.txt"')
        a('$RetryFile = Join-Path $env:ProgramData "cleanup_retry_' + items['scan_id'] + '.json"')
        a('$Retry = New-Object System.Collections.ArrayList')
        a('$Failed = New-Object System.Collections.ArrayList')
        a('')
        a('function Show-Banner {')
        a('    Write-Host "==============================================" -ForegroundColor Cyan')
        a('    Write-Host "  自动杀毒清理脚本 (SYSTEM 提权)" -ForegroundColor Cyan')
        a(f'    Write-Host "  扫描ID: {items["scan_id"]}"')
        a('    Write-Host "=============================================="')
        a('}')
        a('')
        a('function Invoke-SystemElevation {')
        a('    # 通过计划任务以 SYSTEM 身份重跑自身 (已验证可行)')
        a('    $task = "SysCleanup_" + [guid]::NewGuid().ToString("N")')
        a('    $script = $MyInvocation.MyCommand.Path')
        a('    $cmd = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script`" -Auto"')
        a('    schtasks /create /tn $task /tr $cmd /sc once /st 00:00 /ru SYSTEM /f | Out-Null')
        a('    schtasks /run /tn $task | Out-Null')
        a('    Start-Sleep -Seconds 10')
        a('    schtasks /delete /tn $task /f | Out-Null')
        a('    exit')
        a('}')
        a('')
        a('$global:SYSTEM_PROCS = @("svchost","explorer","lsass","services","winlogon",')
        a('    "csrss","smss","wininit","dwm","conhost","fontdrvhost","dllhost",')
        a('    "searchindexer","runtimebroker","sihost","msmpeng","securityhealthservice","audiodg")')
        a('')
        a('# 厂商/系统目录 — 特征扫描永不触碰 (防误杀)')
        a('$global:VENDOR_DIRS = @(' + ','.join(_ps_str(x) for x in [
            r'C:\ProgramData\Microsoft', r'C:\Users\Public\Microsoft',
            r'C:\Program Files\Microsoft', r'C:\Program Files (x86)\Microsoft',
            r'C:\Program Files\Common Files', r'C:\Program Files (x86)\Common Files',
            r'C:\Program Files\VMware', r'C:\Program Files (x86)\VMware',
            r'C:\Program Files\Intel', r'C:\Program Files (x86)\Intel',
            r'C:\Program Files\NVIDIA', r'C:\Program Files (x86)\NVIDIA',
            r'C:\Program Files\Realtek', r'C:\Program Files (x86)\Realtek',
            r'C:\Program Files\Google', r'C:\Program Files (x86)\Google',
            r'C:\Program Files\Mozilla', r'C:\Program Files (x86)\Mozilla',
            r'C:\Program Files\Adobe', r'C:\Program Files (x86)\Adobe',
            r'C:\Program Files\WindowsApps', r'C:\Program Files\Windows Defender',
            r'C:\Windows\System32', r'C:\Windows\SysWOW64',
        ]) + ')')
        a('')
        a('# RestartManager — 列出占用指定文件的进程 (Windows 原生 API)')
        a('try { Add-Type -TypeDefinition @"')
        a('using System;')
        a('using System.Runtime.InteropServices;')
        a('using System.Collections.Generic;')
        a('public static class RM {')
        a('    [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)] static extern int RmStartSession(out uint h, int f, string k);')
        a('    [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint h);')
        a('    [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)] static extern int RmRegisterResources(uint h, uint nFiles, string[] files, uint nApps, IntPtr apps, uint nSvc, string[] svc);')
        a('    [DllImport("rstrtmgr.dll")] static extern int RmGetList(uint h, out uint nNeeded, ref uint nProc, [In,Out] RM_PROCESS_INFO[] p, ref uint l);')
        a('    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct RM_PROCESS_INFO {')
        a('        public uint ProcessId;')
        a('        public byte bApplicationType;')
        a('        public byte bRestartable;')
        a('        public byte bTerminateOnReboot;')
        a('        public byte bRestart;')
        a('        public byte bRebootRestart;')
        a('        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string strAppName;')
        a('        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=64)] public string strServiceShortName;')
        a('    }')
        a('    public static List<uint> GetLockingPids(string file) {')
        a('        var pids = new List<uint>();')
        a('        uint h = 0, nNeeded = 0, n = 0, l = 0;')
        a('        if (RmStartSession(out h, 0, Guid.NewGuid().ToString()) != 0) return pids;')
        a('        string[] files = { file };')
        a('        if (RmRegisterResources(h, 1, files, 0, IntPtr.Zero, 0, null) != 0) { RmEndSession(h); return pids; }')
        a('        RmGetList(h, out nNeeded, ref n, null, ref l);')
        a('        if (nNeeded == 0) { RmEndSession(h); return pids; }')
        a('        var procs = new RM_PROCESS_INFO[nNeeded];')
        a('        n = nNeeded;')
        a('        if (RmGetList(h, out nNeeded, ref n, procs, ref l) == 0) {')
        a('            for (uint i = 0; i < n; i++) pids.Add(procs[i].ProcessId);')
        a('        }')
        a('        RmEndSession(h);')
        a('        return pids;')
        a('    }')
        a('}')
        a('"@')
        a(' -ErrorAction SilentlyContinue } catch {}')
        a('')
        a('function Remove-ForceFile($path) {')
        a('    # 强制删除链 v4: 查杀占用进程 → 清属性 → 接管所有权 → ACL(.NET) → 重试')
        a('    if (-not (Test-Path -LiteralPath $path)) { return $true }')
        a('    # 1) RestartManager 查占用进程并终止 (跳过系统进程)')
        a('    try {')
        a('        $lockPids = [RM]::GetLockingPids($path)')
        a('        foreach ($lp in $lockPids) {')
        a('            try {')
        a('                $lpProc = Get-Process -Id $lp -ErrorAction Stop')
        a('                if ($lpProc.Name -in $global:SYSTEM_PROCS) { continue }')
        a('                $lpProc | Stop-Process -Force -ErrorAction SilentlyContinue')
        a('                Write-Host "[+] 已终止占用进程: $($lpProc.Name) (PID=$lp)" -ForegroundColor Yellow')
        a('                Start-Sleep -Milliseconds 600')
        a('            } catch {}')
        a('        }')
        a('    } catch {}')
        a('    # 2) 清属性 → 接管所有权 → 授权')
        a('    try { attrib -r -h -s -a "$path" 2>$null | Out-Null } catch {}')
        a('    try { takeown /f "$path" /a 2>$null | Out-Null } catch {}')
        a('    try { icacls "$path" /grant "*S-1-5-18:F" "*S-1-5-32-544:F" /c 2>$null | Out-Null } catch {}')
        a('    # 3) .NET ACL API: 移除所有 DENY 条目 (icacls 无法处理复杂 DACL 时的兜底)')
        a('    try {')
        a('        $acl = Get-Acl -LiteralPath $path -ErrorAction SilentlyContinue')
        a('        $denies = @($acl.Access | Where-Object { $_.AccessControlType -eq "Deny" })')
        a('        foreach ($d in $denies) { $null = $acl.RemoveAccessRule($d) }')
        a('        Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction SilentlyContinue')
        a('    } catch {}')
        a('    # 4) 重试删除 (等句柄释放)')
        a('    for ($i = 0; $i -lt 3; $i++) {')
        a('        try {')
        a('            Remove-Item -LiteralPath $path -Force -Recurse -ErrorAction Stop')
        a('            return $true')
        a('        } catch {')
        a('            Start-Sleep -Seconds 2')
        a('        }')
        a('    }')
        a('    return $false')
        a('}')
        a('')
        a('function Add-PendingDelete($path) {')
        a('    # 系统级重启删除: 写入 PendingFileRenameOperations (追加, 不覆盖系统已有项)')
        a('    try {')
        a('        $smKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"')
        a('        $existing = @((Get-ItemProperty -Path $smKey -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)')
        a('        $newList = @($existing + @("\\??\\$path", ""))')
        a('        Set-ItemProperty -Path $smKey -Name PendingFileRenameOperations -Value $newList -Type MultiString')
        a('        Write-Host "[*] 已注册重启删除: $path" -ForegroundColor Yellow')
        a('        return $true')
        a('    } catch { return $false }')
        a('}')
        a('')
        a('function Test-SafePath($path) {')
        a('    # ⚠ 最终安全防线: 系统/厂商目录或有效签名文件 → 永不清理 (曾误删 Defender 组件!)')
        a('    $pl = $path.ToLower()')
        a('    # 显式放行区: 系统临时/缓存目录 (恶意服务镜像 ranchserv.jpg 落于此, 可清理)')
        a('    foreach ($al in @("C:\\Windows\\Temp","C:\\Windows\\Prefetch")) {')
        a('        if ($pl.StartsWith($al.ToLower())) { return $true }')
        a('    }')
        a('    foreach ($vd in $global:VENDOR_DIRS) {')
        a('        if ($pl.StartsWith($vd.ToLower())) { return $false }')
        a('    }')
        a('    foreach ($kw in @("\\windows defender\\","\\microsoft\\","\\system32\\","\\syswow64\\","\\common files\\","\\windowsapps\\")) {')
        a('        if ($pl.Contains($kw)) { return $false }')
        a('    }')
        a('    try {')
        a('        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue')
        a('        if ($sig -and $sig.Status -eq "Valid") { return $false }')
        a('    } catch {}')
        a('    return $true')
        a('}')
        a('')
        a('# ---- 0. 权限检查与提权 ----')
        a('$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())')
        a('$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)')
        a('$isSystem = ([Security.Principal.WindowsIdentity]::GetCurrent().Name -eq "NT AUTHORITY\\SYSTEM")')
        a('if (-not $isSystem -and $Auto -and $isAdmin) {')
        a('    Write-Host "[*] 提权至 SYSTEM..." -ForegroundColor Yellow')
        a('    Invoke-SystemElevation')
        a('}')
        a('if (-not $isAdmin -and -not $isSystem) {')
        a('    Write-Host "[!] 需要管理员权限运行 (或以 -Auto 自动提权)" -ForegroundColor Red')
        a('    exit 1')
        a('}')
        a('Show-Banner')
        a('if (-not $Auto) {')
        a('    Write-Host ""')
        a('    Write-Host "本次清理将执行以下操作:" -ForegroundColor Yellow')
        # ⚠ 所有来自样本行为的名称/路径必须经 _ps_str 转成 PowerShell 字面量,
        # 防止样本构造 "$(恶意代码)"/双引号注入生成的 SYSTEM 清理脚本。
        def _ws(label: str, value: str):
            a('    Write-Host ' + _ps_str(label + str(value)))
        if items['kill_processes']:
            _kill_names = ', '.join(x['name'] for x in items['kill_processes'][:10])
            _ws('  [进程] 终止: ', _kill_names)
        if items['delete_files']:
            _ws('  [文件] 删除: ', f"{len(items['delete_files'])} 个")
        if items['delete_dirs']:
            _ws('  [目录] 删除: ', f"{len(items['delete_dirs'])} 个 (随机名目录特征)")
        if items['delete_services']:
            _ws('  [服务] 删除: ', ', '.join(items['delete_services'][:8]))
        if items['delete_tasks']:
            _ws('  [任务] 删除: ', ', '.join(items['delete_tasks'][:8]))
        if items['delete_registry']:
            _ws('  [注册表] 删除: ', f"{len(items['delete_registry'])} 项")
        if items['restore_registry']:
            _ws('  [注册表] 恢复: ', f"{len(items['restore_registry'])} 项 (UAC/代理原值)")
        if items['restore_services']:
            _svc_desc = ', '.join(f"{x['name']}(Start={x['start']})"
                                  for x in items['restore_services'][:6])
            _ws('  [服务] 还原启动类型: ', _svc_desc)
        if items['clear_registry']:
            _ws('  [注册表] 清空: ', f"{len(items['clear_registry'])} 项 (PendingFileRename 等)")
        if items['restore_defender']:
            a('    Write-Host "  [安全] 恢复 Windows Defender 服务 (样本曾终止)"')
        if items['delete_files'] or items['delete_dirs']:
            a('    Write-Host "  [删除] 先强制删除 → 失败提交 Defender 隔离 → 仍失败注册重启删除"')
        if items['delete_users']:
            _ws('  [用户] 删除: ', ', '.join(items['delete_users'][:5]))
        if items['remove_admins']:
            _ws('  [组] 移出管理员: ', ', '.join(items['remove_admins'][:5]))
        if items['delete_fw_rules']:
            _ws('  [防火墙] 删除规则: ', ', '.join(items['delete_fw_rules'][:5]))
        if items['restore_hosts']:
            a('    Write-Host "  [hosts] 还原被篡改的 hosts 文件"')
        if items['hijack_keys']:
            _ws('  [劫持键] 还原: ', f"{len(items['hijack_keys'])} 项 (Winlogon/AppInit)")
        a('    $yes = Read-Host "确认执行? [y/N]"')
        a('    if ($yes -notmatch "^[yY]") { Write-Host "已取消"; exit 0 }')
        a('}')
        a('')
        a('# ---- 1. 终止恶意进程 (优先按完整路径精确匹配, 避免同名误杀) ----')
        _kill_items = ','.join(
            '@{' + f"n={_ps_str(x['name'])}; p={_ps_str(x.get('path', '') or '')}" + '}'
            for x in items['kill_processes'])
        a('$killList = @(' + _kill_items + ')')
        a('foreach ($kp in $killList) {')
        a('    $procs = @()')
        a('    if ($kp.p) {')
        a('        $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -eq $kp.p } catch { $false } }')
        a('    }')
        a('    elseif ($kp.n) {')
        a('        $procs = Get-Process -Name $kp.n -ErrorAction SilentlyContinue')
        a('    }')
        a('    if (-not $procs) {')
        a('        Write-Host "[-] 进程未运行, 跳过: $($kp.n)" -ForegroundColor Gray')
        a('        continue')
        a('    }')
        a('    foreach ($proc in $procs) {')
        a('        try {')
        a('            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue')
        a('            Write-Host "[+] 进程已终止: $($proc.ProcessName) (PID=$($proc.Id))" -ForegroundColor Green')
        a('        } catch {')
        a('            [void]$Failed.Add("进程 $($kp.n) 终止失败: $_")')
        a('        }')
        a('    }')
        a('    Start-Sleep -Milliseconds 500   # 等句柄释放')
        a('}')
        a('')
        a('# ---- 2. 删除恶意服务 ----')
        a('$svcList = @(' + ','.join(_ps_str(x) for x in items['delete_services']) + ')')
        a('foreach ($sn in $svcList) {')
        a('    try {')
        a('        Stop-Service -Name $sn -Force -ErrorAction SilentlyContinue')
        a('        sc.exe delete $sn | Out-Null')
        a('        Write-Host "[+] 服务已删除: $sn" -ForegroundColor Green')
        a('    } catch {')
        a('        [void]$Failed.Add("服务 $sn 删除失败: $_")')
        a('    }')
        a('}')
        a('')
        a('# ---- 2b. 还原被样本禁用的服务启动类型 (UsoSvc/WaaSMedicSvc/wuauserv 场景) ----')
        a('$restoreSvc = @(' + ','.join(
            '@{' + f"Name={_ps_str(x['name'])}; Start={_ps_str(x['start'])}" + '}'
            for x in items['restore_services']) + ')')
        a('$svcStartName = @{ "0"="boot"; "1"="system"; "2"="auto"; "3"="demand"; "4"="disabled" }')
        a('foreach ($rs in $restoreSvc) {')
        a('    try {')
        a('        $cur = (Get-Service -Name $rs.Name -ErrorAction SilentlyContinue).StartType')
        a('        $startWord = $svcStartName[$rs.Start]')
        a('        if (-not $startWord) { $startWord = $rs.Start }')
        a('        sc.exe config $rs.Name start= $startWord 2>$null | Out-Null')
        a('        Write-Host "[+] 服务已还原: $($rs.Name) (Start $cur -> $($rs.Start))" -ForegroundColor Green')
        a('    } catch {')
        a('        [void]$Failed.Add("服务还原失败: $($rs.Name)")')
        a('    }')
        a('}')
        a('')
        a('# ---- 2c. 杀软安装解锁 — 修复样本禁用的安装/更新基础服务 ----')
        a('# 银狐禁装杀软原理: 把 BITS/wuauserv/msiserver(Windows Installer)/UsoSvc/')
        a('# WaaSMedicSvc 等服务的 Start 改为禁用(4), 导致杀软安装包(MSI)无法下载/')
        a('# 安装/更新。无论分析时是否捕获到 diff, 一律检查并修复这些服务。')
        a('$installSvcs = @(')
        a('    @{ Name="BITS";      Desired=2 },   # 后台智能传输 — 杀软更新下载')
        a('    @{ Name="wuauserv";  Desired=2 },   # Windows Update')
        a('    @{ Name="msiserver"; Desired=3 },   # Windows Installer — MSI 安装包必需!')
        a('    @{ Name="TrustedInstaller"; Desired=3 },')
        a('    @{ Name="UsoSvc";    Desired=3 },')
        a('    @{ Name="WaaSMedicSvc"; Desired=3 },')
        a('    @{ Name="DoSvc";     Desired=3 },   # 传递优化')
        a('    @{ Name="WinDefend"; Desired=2 },')
        a('    @{ Name="wscsvc";    Desired=3 },   # 安全中心')
        a('    @{ Name="SecurityHealthService"; Desired=2 },')
        a('    @{ Name="InstallService"; Desired=3 }')
        a(')')
        a('foreach ($issvc in $installSvcs) {')
        a('    $isvc = Get-Service -Name $issvc.Name -ErrorAction SilentlyContinue')
        a('    if (-not $isvc) { continue }')
        a('    try {')
        a('        $curSt = (Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$($issvc.Name)" -Name Start -ErrorAction SilentlyContinue).Start')
        a('        if ($curSt -ne $issvc.Desired) {')
        a('            $startWord = $svcStartName[[string]$issvc.Desired]')
        a('            sc.exe config $issvc.Name start= $startWord 2>$null | Out-Null')
        a('            Write-Host "[+] 解锁安装服务: $($issvc.Name) (Start $curSt -> $($issvc.Desired))" -ForegroundColor Green')
        a('        }')
        a('    } catch { }')
        a('    # 尝试启动 (WinDefend/wscsvc 等 — 修复后立即生效)')
        a('    if ($issvc.Desired -eq 2) {')
        a('        try { Start-Service -Name $issvc.Name -ErrorAction SilentlyContinue | Out-Null } catch {}')
        a('    }')
        a('}')
        a('')
        a('# ---- 3. 删除计划任务 ----')
        a('$taskList = @(' + ','.join(_ps_str(x) for x in items['delete_tasks']) + ')')
        a('foreach ($tn in $taskList) {')
        a('    schtasks /delete /tn $tn /f 2>$null | Out-Null')
        a('    Write-Host "[+] 任务已删除: $tn" -ForegroundColor Green')
        a('}')
        a('')
        a('# ---- 4. 删除恶意文件 (强制删除链; 失败的交由 Defender 隔离, 仍失败再重启删除) ----')
        a('$failedFiles = New-Object System.Collections.ArrayList')
        a('$fileList = @(' + ','.join(_ps_str(x) for x in items['delete_files']) + ')')
        a('foreach ($fp in $fileList) {')
        a('    if (-not (Test-Path -LiteralPath $fp)) { continue }')
        a('    if (-not (Test-SafePath $fp)) { Write-Host "[-] 安全边界拦截(系统/厂商/签名), 跳过: $fp" -ForegroundColor Gray; continue }')
        a('    if (Remove-ForceFile $fp) {')
        a('        Write-Host "[+] 文件已删除: $fp" -ForegroundColor Green')
        a('    } else {')
        a('        [void]$failedFiles.Add($fp)')
        a('        Write-Host "[-] 强删失败, 待 Defender 处理: $fp" -ForegroundColor Yellow')
        a('    }')
        a('}')
        a('')
        a('# ---- 5. 删除随机名目录 (银狐特征; 失败同样交 Defender 后重启删除) ----')
        a('$failedDirs = New-Object System.Collections.ArrayList')
        a('$dirList = @(' + ','.join(_ps_str(x) for x in items['delete_dirs']) + ')')
        a('foreach ($dp in $dirList) {')
        a('    if (-not (Test-Path -LiteralPath $dp)) { continue }')
        a('    if (-not (Test-SafePath $dp)) { Write-Host "[-] 安全边界拦截(系统/厂商/签名), 跳过: $dp" -ForegroundColor Gray; continue }')
        a('    if (Remove-ForceFile $dp) {')
        a('        Write-Host "[+] 随机目录已删除: $dp" -ForegroundColor Green')
        a('    } else {')
        a('        [void]$failedDirs.Add($dp)')
        a('        Write-Host "[-] 目录强删失败, 待 Defender 处理: $dp" -ForegroundColor Yellow')
        a('    }')
        a('}')
        a('')
        a('# ---- 5b. Defender 隔离 — 仅处理强删失败的文件/目录 (先修复Defender→清排除→扫描隔离) ----')
        a('$defenderTargets = @()')
        a('foreach ($ff in $failedFiles) { if (Test-Path -LiteralPath $ff) { $defenderTargets += $ff } }')
        a('foreach ($fd in $failedDirs) { if (Test-Path -LiteralPath $fd) { $defenderTargets += $fd } }')
        a('if ($defenderTargets.Count -gt 0 -and (Get-Service WinDefend -ErrorAction SilentlyContinue)) {')
        a('    Write-Host "[*] 强删失败文件提交 Defender 扫描隔离..." -ForegroundColor Cyan')
        a('    # 恢复实时保护 (样本可能关闭过)')
        a('    try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } catch {}')
        a('    # 定位 MpCmdRun (备用通道; 优先 Start-MpScan cmdlet, 不受 Device Guard/WDAC 阻止)')
        a('    $mp = $null')
        a('    try {')
        a('        $cands = @("C:\\Program Files\\Windows Defender\\MpCmdRun.exe",')
        a('                   "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MpCmdRun.exe")')
        a('        foreach ($c in $cands) {')
        a('            $found = Get-ChildItem $c -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1')
        a('            if ($found) { $mp = $found.FullName; break }')
        a('        }')
        a('    } catch {}')
        a('    foreach ($fp in $defenderTargets) {')
        a('        if (-not (Test-Path -LiteralPath $fp)) { continue }')
        a('        # 确保路径不在 Defender 排除列表')
        a('        try { Remove-MpPreference -ExclusionPath $fp -ErrorAction SilentlyContinue } catch {}')
        a('        Write-Host "[*] 提交 Defender 扫描: $fp" -ForegroundColor Yellow')
        a('        $submitOK = $false')
        a('        # 通道1: Start-MpScan cmdlet (WDAC 免疫)')
        a('        try { Start-MpScan -ScanType CustomScan -ScanPath $fp -ErrorAction Stop | Out-Null; $submitOK = $true } catch {}')
        a('        # 通道2: MpCmdRun.exe (被 WDAC 阻止时此通道失败, 自动忽略)')
        a('        if (-not $submitOK -and $mp) {')
        a('            try { & $mp -Scan -ScanType 3 -File $fp 2>$null | Out-Null; $submitOK = $true } catch {}')
        a('        }')
        a('        if ($submitOK) {')
        a('            # 轮询等待隔离结果 (最多 90s)')
        a('            $isolated = $false')
        a('            for ($i = 0; $i -lt 10; $i++) {')
        a('                Start-Sleep -Seconds 3')
        a('                if (-not (Test-Path -LiteralPath $fp)) { $isolated = $true; break }')
        a('            }')
        a('            if ($isolated) {')
        a('                Write-Host "[+] Defender 已隔离: $fp (Windows 安全中心-保护历史可复查)" -ForegroundColor Green')
        a('            } else {')
        a('                Write-Host "[-] Defender 未识别该文件, 注册重启删除: $fp" -ForegroundColor Yellow')
        a('            }')
        a('        } else {')
        a('            Write-Host "[-] Defender 扫描通道不可用, 注册重启删除: $fp" -ForegroundColor Yellow')
        a('        }')
        a('    }')
        a('} elseif ($defenderTargets.Count -gt 0) {')
        a('    Write-Host "[-] WinDefend 服务不可用, 跳过 Defender 扫描, 直接重启删除" -ForegroundColor Gray')
        a('}')
        a('')
        a('# ---- 6b. 重启删除 — 对 Defender 仍未隔离的注册 PendingFileRenameOperations ----')
        a('$stillThere = @()')
        a('foreach ($ff in $failedFiles) { if (Test-Path -LiteralPath $ff) { $stillThere += $ff } }')
        a('foreach ($fd in $failedDirs) { if (Test-Path -LiteralPath $fd) { $stillThere += $fd } }')
        a('foreach ($sp in $stillThere) {')
        a('    $pd = Add-PendingDelete $sp')
        a('    [void]$Failed.Add("删除失败(强删+Defender均未清除): $sp" + $(if($pd){" — 已注册重启删除"}else{""}))')
        a('    if (-not $pd) { [void]$Retry.Add(@{type="file"; path=$sp}) }')
        a('}')
        a('')
        # ---- 3c. 特征扫描器 — 变种/随机释放文件自适应 (特征归纳: C2域名/随机目录模式/无签名/编译时间窗/服务异常) ----
        feats = items.get('features') or {}
        has_feats = bool(feats.get('c2_domains') or feats.get('random_dir_pattern')
                         or feats.get('unsigned_only') or feats.get('compile_window')
                         or feats.get('service_abnormal') or feats.get('run_abnormal'))
        if has_feats:
            a('# ---- 3c. 特征扫描 — 从分析结果归纳的泛化规则 (变种/随机释放文件自适应) ----')
            a('Write-Host "[*] 特征扫描启动: 依据分析归纳的特征主动发现变种/随机释放物..." -ForegroundColor Cyan')
            a('$global:SIG_CACHE = @{}')
            # 特征总览 — 展示本次分析归纳出的特征 (让用户看到特征总结)
            a('Write-Host "  本次归纳特征: " -ForegroundColor Cyan')
            if feats.get('family_names'):
                a('    Write-Host "    家族: ' + ' / '.join(feats['family_names'][:3]) + '" -ForegroundColor Yellow')
            if feats.get('family_strings'):
                a('    Write-Host "    家族特征字符串: ' + ', '.join(feats['family_strings'][:8]) + '" -ForegroundColor Yellow')
            if feats.get('c2_domains'):
                a('    Write-Host "    C2 域名/IP: ' + ', '.join(feats['c2_domains'][:6]) + '" -ForegroundColor Yellow')
            if feats.get('random_dir_pattern'):
                a('    Write-Host "    随机目录模式: 5-9字符随机目录 (Public/ProgramData 等)" -ForegroundColor Yellow')
            if feats.get('random_filename'):
                a('    Write-Host "    随机文件名模式: 5-9字符 exe/dll" -ForegroundColor Yellow')
            if feats.get('compile_window'):
                a('    Write-Host "    编译时间窗: ' + (feats.get('compile_str') or '') + '" -ForegroundColor Yellow')
            if feats.get('unsigned_only'):
                a('    Write-Host "    无有效数字签名" -ForegroundColor Yellow')
            if feats.get('service_abnormal'):
                a('    Write-Host "    服务 ImagePath 异常" -ForegroundColor Yellow')
            a('')
            a('$featureHits = New-Object System.Collections.ArrayList')
            a('function Get-PESignatureState($path) {')
            a('    # 返回 1=有效签名 0=无签名 -1=非PE')
            a('    try {')
            a('        $bytes = [System.IO.File]::ReadAllBytes($path)')
            a('        if ($bytes.Length -lt 0x40 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { return -1 }')
            a('        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue')
            a('        if ($sig -and $sig.Status -eq "Valid") { return 1 }')
            a('        return 0')
            a('    } catch { return -1 }')
            a('}')
            a('function Get-PETimestamp($path) {')
            a('    # 读取 PE TimeDateStamp (编译时间)')
            a('    try {')
            a('        $bytes = [System.IO.File]::ReadAllBytes($path)')
            a('        if ($bytes.Length -lt 0x40 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { return 0 }')
            a('        $peOff = [BitConverter]::ToInt32($bytes, 0x3C)')
            a('        if ($peOff + 12 -gt $bytes.Length) { return 0 }')
            a('        return [BitConverter]::ToInt32($bytes, $peOff + 8)')
            a('    } catch { return 0 }')
            a('}')
            a('function Test-FeatureHits($path) {')
            a('    # 逐特征计分: >=2 高置信 (自动清理), 1 特征待确认')
            a('    # ⚠ 性能: 签名验证(WinVerifyTrust)极慢 — 先快特征, 有命中后才做签名检查 (缓存)')
            a('    $score = 0')
            a('    $reasons = @()')
            a('    $ext = [System.IO.Path]::GetExtension($path).ToLower()')
            a('    if ($ext -notin @(".exe",".dll",".scr",".sys",".bat",".ps1",".vbs",".js",".jse",".com")) { return $null }')
            a('    # ⚠ 安全边界2: 厂商/系统目录永不清理 (快速路径检查, 无需读文件)')
            a('    $pathL = $path.ToLower()')
            a('    foreach ($vd in $global:VENDOR_DIRS) {')
            a('        if ($pathL.StartsWith($vd)) { return $null }')
            a('    }')
            a('    # 特征1: 无有效签名 + ⚠ 安全边界1 (后置+缓存): 所有特征计分后, 有命中才验证签名')
            a('    # ⚠ 有效签名文件永不清理 — 避免慢速 WinVerifyTrust 阻塞扫描, 只对候选验证')
            if feats.get('compile_window'):
                a('    $ts = Get-PETimestamp $path')
                a('    if ($ts -ge ' + str(feats['compile_window'][0]) + ' -and $ts -le ' + str(feats['compile_window'][1]) + ') { $score++; $reasons += "编译时间在窗口内" }')
            a('    # 特征3: 随机目录模式 (Public/ProgramData 顶层 5-9 字符目录)')
            if feats.get('random_dir_pattern'):
                a('    if ($path -match "\\\\(Public|ProgramData|Program Files \\(x86\\)|AppData)\\\\[A-Za-z0-9]{5,9}\\\\") { $score++; $reasons += "随机名目录" }')
            a('    # 特征4: C2 域名/URL 内容匹配 (最强家族特征 — 换壳不换 C2)')
            if feats.get('c2_domains'):
                a('    try {')
                a('        $fs = [System.IO.File]::OpenRead($path)')
                a('        $buf = New-Object byte[] ([Math]::Min($fs.Length, 1MB))')
                a('        $n = $fs.Read($buf, 0, $buf.Length); $fs.Close()')
                a('        $content = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)')
                for _d in feats['c2_domains'][:8]:
                    a(f'        if ($content.IndexOf({_ps_str(_d)}, [StringComparison]::OrdinalIgnoreCase) -ge 0) {{ $score++; $reasons += ("命中C2: " + {_ps_str(_d)}) }}')
                a('    } catch {}')
            a('    # 特征5: 家族特征字符串 (家族库归纳 — 变种共享, 内容匹配)')
            if feats.get('family_strings'):
                a('    try {')
                a('        $fs = [System.IO.File]::OpenRead($path)')
                a('        $buf2 = New-Object byte[] ([Math]::Min($fs.Length, 512KB))')
                a('        $n2 = $fs.Read($buf2, 0, $buf2.Length); $fs.Close()')
                a('        $content2 = [System.Text.Encoding]::ASCII.GetString($buf2, 0, $n2)')
                for _s in feats['family_strings'][:10]:
                    a(f'        if ($content2.IndexOf({_ps_str(_s)}, [StringComparison]::OrdinalIgnoreCase) -ge 0) {{ $score++; $reasons += ("家族特征: " + {_ps_str(_s)}) }}')
                a('    } catch {}')
            a('    # 特征6: 随机文件名模式 (银狐 8 字符 exe/dll)')
            if feats.get('random_filename'):
                a('    if ([System.IO.Path]::GetFileNameWithoutExtension($path) -match "^[A-Za-z0-9]{5,9}$" -and $ext -in @(".exe",".dll",".scr")) { $score++; $reasons += "随机文件名" }')
            a('    # ⚠ 安全边界1 (后置+缓存): 有效签名文件永不清理 — 只有已有特征命中才验证签名')
            a('    if ($score -ge 1) {')
            a('        $sigKey = $path.ToLower()')
            a('        if (-not $global:SIG_CACHE.ContainsKey($sigKey)) {')
            a('            $global:SIG_CACHE[$sigKey] = Get-PESignatureState $path')
            a('        }')
            a('        $sigState = $global:SIG_CACHE[$sigKey]')
            a('        if ($sigState -eq 1) { return $null }')
            if feats.get('unsigned_only'):
                a('        if ($sigState -eq 0) { $score++; $reasons += "无有效签名" }')
            a('    }')
            a('    # 特征7: 服务异常目录 (ImagePath 指向数据文件/随机目录的服务)')
            if feats.get('service_abnormal'):
                a('    if ($path -match "\\\\(Temp|Public|ProgramData)\\\\" -and $ext -ne ".exe") { $score++; $reasons += "服务异常位置" }')
            a('    if ($score -ge 3) { return @{Path=$path; Score=$score; Reasons=($reasons -join " + "); Auto=$true} }')
            a('    if ($score -ge 1) { return @{Path=$path; Score=$score; Reasons=($reasons -join " + "); Auto=$false} }')
            a('    return $null')
            a('}')
            a('')
            a('# 扫描范围: 常见释放位置 (运行时 APPDATA, 不含 Program Files 等厂商目录)')
            a('$scanRoots = @(' + ','.join(_ps_str(x) for x in [r'C:\Users\Public', r'C:\ProgramData']) + ', $env:APPDATA)')
            a('$scannedTotal = 0')
            a('foreach ($root in $scanRoots) {')
            a('    if (-not (Test-Path -LiteralPath $root)) { continue }')
            a('    try {')
            a('        $topDirs = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue')
            a('        foreach ($d in $topDirs) {')
            a('            if ($scannedTotal -ge 120) { break }')
            a('            if ($d.Name -match "^[A-Za-z0-9]{5,9}$" -and (Test-SafePath $d.FullName)) {')
            a('                $files = Get-ChildItem -LiteralPath $d.FullName -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match "^.(exe|dll|scr|sys|bat|ps1|vbs|js)$" } | Select-Object -First 15')
            a('                foreach ($f in $files) {')
            a('                    if ($scannedTotal -ge 120) { break }')
            a('                    if (-not (Test-SafePath $f.FullName)) { continue }')
            a('                    $scannedTotal++')
            a('                    $hit = Test-FeatureHits $f.FullName')
            a('                    if ($hit) { [void]$featureHits.Add($hit) }')
            a('                }')
            a('            }')
            a('        }')
            a('    } catch {}')
            a('}')
            a('# 汇总特征命中')
            a('if ($featureHits.Count -gt 0) {')
            a('    Write-Host ""')
            a('    Write-Host "== 特征扫描命中: $($featureHits.Count) 个疑似变种/释放物 ==" -ForegroundColor Yellow')
            a('    $autoClean = @($featureHits | Where-Object { $_.Auto })')
            a('    $askClean = @($featureHits | Where-Object { -not $_.Auto })')
            a('    foreach ($h in $featureHits) {')
            a('        $mark = $(if ($h.Auto) { "[自动]" } else { "[确认]" })')
            a('        Write-Host "  $mark $($h.Path) (特征: $($h.Reasons))"')
            a('    }')
            a('    if ($autoClean.Count -gt 0 -and $Auto) {')
            a('        foreach ($h in $autoClean) {')
            a('            if (Test-Path -LiteralPath $h.Path) {')
            a('                if (Remove-ForceFile $h.Path) { Write-Host "[+] 特征命中已清理: $($h.Path)" -ForegroundColor Green }')
            a('                else { [void]$failedFiles.Add($h.Path); Write-Host "[-] 特征命中强删失败, 待 Defender: $($h.Path)" -ForegroundColor Yellow }')
            a('            }')
            a('        }')
            a('    } elseif ($askClean.Count -gt 0 -and -not $Auto) {')
            a('        $ans = Read-Host "清理以上特征命中文件? [y/N]"')
            a('        if ($ans -match "^[yY]") {')
            a('            foreach ($h in $featureHits) {')
            a('                if (Test-Path -LiteralPath $h.Path) {')
            a('                    if (Remove-ForceFile $h.Path) { Write-Host "[+] 已清理: $($h.Path)" -ForegroundColor Green }')
            a('                    else { [void]$failedFiles.Add($h.Path); Write-Host "[-] 特征命中强删失败, 待 Defender: $($h.Path)" -ForegroundColor Yellow }')
            a('                }')
            a('            }')
            a('        }')
            a('    } else {')
            a('        Write-Host "   (Auto 模式: 高置信命中自动清理; 单特征命中需人工确认)"')
            a('    }')
            a('} else {')
            a('    Write-Host "[-] 特征扫描: 未发现变种/随机释放物" -ForegroundColor Gray')
            a('}')
            a('')
        # ---- 6c. 特征扫描失败项的 Defender 第二轮 + 最终重启删除 ----
        if items['delete_files'] or items['delete_dirs']:
            a('# ---- 6c. Defender 第二轮 (特征扫描失败项) + 最终重启删除 ----')
            a('$defenderTargets2 = @()')
            a('foreach ($ff in $failedFiles) { if (Test-Path -LiteralPath $ff) { $defenderTargets2 += $ff } }')
            a('if ($defenderTargets2.Count -gt 0 -and (Get-Service WinDefend -ErrorAction SilentlyContinue)) {')
            a('    foreach ($fp in $defenderTargets2) {')
            a('        Write-Host "[*] Defender 扫描: $fp" -ForegroundColor Yellow')
            a('        try { Remove-MpPreference -ExclusionPath $fp -ErrorAction SilentlyContinue } catch {}')
            a('        $submitOK = $false')
            a('        try { Start-MpScan -ScanType CustomScan -ScanPath $fp -ErrorAction Stop | Out-Null; $submitOK = $true } catch {}')
            a('        if (-not $submitOK -and $mp) { try { & $mp -Scan -ScanType 3 -File $fp 2>$null | Out-Null; $submitOK = $true } catch {} }')
            a('        if ($submitOK) {')
            a('            $isolated = $false')
            a('            for ($i = 0; $i -lt 10; $i++) {')
            a('                Start-Sleep -Seconds 3')
            a('                if (-not (Test-Path -LiteralPath $fp)) { $isolated = $true; break }')
            a('            }')
            a('            if ($isolated) { Write-Host "[+] Defender 已隔离: $fp" -ForegroundColor Green }')
            a('        }')
            a('    }')
            a('}')
            a('foreach ($ff in $defenderTargets2) {')
            a('    if (Test-Path -LiteralPath $ff) {')
            a('        $pd = Add-PendingDelete $ff')
            a('        [void]$Failed.Add("删除失败(强删+Defender均未清除): $ff" + $(if($pd){" — 已注册重启删除"}else{""}))')
            a('        if (-not $pd) { [void]$Retry.Add(@{type="file"; path=$ff}) }')
            a('    }')
            a('}')
        a('# ---- 6. 注册表清理 ----')
        a('foreach ($reg in @(' + ','.join(
            '@{' + f"Key={_ps_str(x['key'])}; Value={_ps_str(x['value'])}" + '}'
            for x in items['delete_registry']) + ')) {')
        a('    try {')
        a('        $k = $reg.Key; $v = $reg.Value')
        a('        if ($k -match "^HKLM") { $base = "HKLM:" } elseif ($k -match "^HKCU") { $base = "HKCU:" } else { $base = "" }')
        a('        $path = $k -replace "^HKLM","HKLM:" -replace "^HKCU","HKCU:"')
        a('        if ($v) { Remove-ItemProperty -Path $path -Name $v -ErrorAction SilentlyContinue }')
        a('        else { Write-Host "[-] 注册表项缺少值名, 已跳过整键删除(安全保护): $k" -ForegroundColor Yellow }')
        a('        Write-Host "[+] 注册表已清理: $k :: $v" -ForegroundColor Green')
        a('    } catch { [void]$Failed.Add("注册表清理失败: $($reg.Key)") }')
        a('}')
        a('')
        a('# ---- 6b. 清空被样本写入的值 (Session Manager PendingFileRenameOperations 等) ----')
        a('foreach ($reg in @(' + ','.join(
            '@{' + f"Key={_ps_str(x['key'])}; Value={_ps_str(x['value'])}" + '}'
            for x in items['clear_registry']) + ')) {')
        a('    try {')
        a('        $path = $reg.Key -replace "^HKLM","HKLM:" -replace "^HKCU","HKCU:"')
        a('        Remove-ItemProperty -Path $path -Name $reg.Value -ErrorAction SilentlyContinue')
        a('        Write-Host "[+] 已清空: $($reg.Value) @ $($reg.Key)" -ForegroundColor Green')
        a('    } catch { [void]$Failed.Add("清空失败: $($reg.Key) :: $($reg.Value)") }')
        a('}')
        a('')
        a('# ---- 7. 恢复被修改的设置 ----')
        a('foreach ($reg in @(' + ','.join(
            '@{' + f"Key={_ps_str(x['key'])}; Value={_ps_str(x['value'])}; Data={_ps_str(x['data'])}; Type={_ps_str(x['type'])}" + '}'
            for x in items['restore_registry']) + ')) {')
        a('    try {')
        a('        $path = $reg.Key -replace "^HKLM","HKLM:" -replace "^HKCU","HKCU:"')
        a('        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }')
        a('        if ($reg.Type -eq "DWord") { New-ItemProperty -Path $path -Name $reg.Value -Value ([int]$reg.Data) -PropertyType DWord -Force | Out-Null }')
        a('        else { New-ItemProperty -Path $path -Name $reg.Value -Value $reg.Data -PropertyType String -Force | Out-Null }')
        a('        Write-Host "[+] 设置已恢复: $($reg.Value) = $($reg.Data)" -ForegroundColor Green')
        a('    } catch { [void]$Failed.Add("设置恢复失败: $($reg.Value)") }')
        a('}')
        a('')
        a('# ---- 8. 检查 Windows Defender 排除项 (若样本曾修改) ----')
        if items['check_defender_exclusion']:
            _excl_roots = []
            for _p in (items['delete_files'] or [])[:20]:
                _rp = os.path.dirname(str(_p))
                if _rp and _rp not in _excl_roots:
                    _excl_roots.append(_rp)
            if items['sample_file']:
                _sd = os.path.dirname(str(items['sample_file']))
                if _sd and _sd not in _excl_roots:
                    _excl_roots.append(_sd)
            a('Write-Host "[*] 检测到样本可能修改过 Defender 排除项, 检查中..." -ForegroundColor Yellow')
            a('$sampleRoots = @(' + ','.join(_ps_str(x) for x in _excl_roots) + ')')
            a('try {')
            a('    $excl = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath -ErrorAction SilentlyContinue')
            a('    if ($excl) {')
            a('        $suspectExcl = @(); $otherExcl = @()')
            a('        foreach ($ep in $excl) {')
            a('            $matched = $false')
            a('            foreach ($rp in $sampleRoots) {')
            a('                if ($ep -and $rp -and $ep.StartsWith($rp, [StringComparison]::OrdinalIgnoreCase)) { $matched = $true; break }')
            a('            }')
            a('            if ($matched -or $ep -like "*\\Temp\\*" -or $ep -like "*\\Users\\Public\\*" -or $ep -like "*\\ProgramData\\*") { $suspectExcl += $ep }')
            a('            else { $otherExcl += $ep }')
            a('        }')
            a('        Write-Host "[!] 疑似样本添加的排除路径: $suspectExcl" -ForegroundColor Red')
            a('        if ($otherExcl.Count -gt 0) { Write-Host "[*] 保留疑似用户自有排除路径(未删除): $otherExcl" -ForegroundColor Gray }')
            a('        if ($suspectExcl.Count -gt 0) {')
            a('            $ans = Read-Host "是否移除以上疑似样本排除项? [y/N]"')
            a('            if ($ans -match "^[yY]") { Remove-MpPreference -ExclusionPath $suspectExcl; Write-Host "[+] 已移除" -ForegroundColor Green }')
            a('        }')
            a('    } else { Write-Host "[+] 无 Defender 排除项" -ForegroundColor Green }')
            a('} catch { [void]$Failed.Add("Defender 排除检查失败: $_") }')
        else:
            a('# 样本未修改 Defender 排除项, 跳过')
        a('')
        a('# ---- 8b. 恢复被样本终止的 Windows Defender ----')
        if items['restore_defender']:
            a('Write-Host "[*] 检测到样本终止了安全产品进程, 恢复 Defender 防护..." -ForegroundColor Yellow')
            a('foreach ($svc in @("WinDefend", "wscsvc", "SecurityHealthService", "Sense", "MpDefenderCoreService")) {')
            a('    try {')
            a('        $st = (Get-Service -Name $svc -ErrorAction SilentlyContinue).StartType')
            a('        if ($st -eq "Disabled") { sc.exe config $svc start= auto 2>$null | Out-Null }')
            a('        Start-Service -Name $svc -ErrorAction SilentlyContinue')
            a('        Write-Host "[+] Defender 服务已恢复: $svc" -ForegroundColor Green')
            a('    } catch { [void]$Failed.Add("Defender 服务 $svc 恢复失败: $_") }')
            a('}')
            a('# 删除 Defender 禁用策略键 (银狐禁装杀软: DisableAntiSpyware/DisableAntiVirus/DisableRealtimeMonitoring)')
            a('$defPol = @(')
            a('    "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",')
            a('    "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"')
            a(')')
            a('foreach ($dp in $defPol) {')
            a('    foreach ($dv in @("DisableAntiSpyware","DisableAntiVirus","DisableRealtimeMonitoring",')
            a('                      "DisableAntiVirusFallback","DisableBehaviorMonitoring",')
            a('                      "DisableOnAccessProtection","DisableScanOnRealtimeEnable")) {')
            a('        try { Remove-ItemProperty -Path $dp -Name $dv -ErrorAction SilentlyContinue; Write-Host "[+] 删除 Defender 禁用键: $dv" -ForegroundColor Green } catch {}')
            a('    }')
            a('}')
            a('# 引擎驱动启动类型还原 (wdboot/wdfilter/wdnisdrv — 样本可能禁用)')
            a('foreach ($dv in @("wdboot","wdfilter","wdnisdrv","WdNisSvc")) {')
            a('    try {')
            a('        $cur = (Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$dv" -Name Start -ErrorAction SilentlyContinue).Start')
            a('        if ($cur -eq 4) { sc.exe config $dv start= 0 2>$null | Out-Null; Write-Host "[+] 还原 Defender 驱动: $dv" -ForegroundColor Green }')
            a('    } catch {}')
            a('}')
            a('# 清理样本对 Defender 的排除项 (ExclusionPath — 银狐常把自己加进排除)')
            a('try {')
            a('    $excl = (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath')
            a('    if ($excl) {')
            a('        foreach ($ep in $excl) {')
            a('            if ($ep -like "*Users*Public*" -or $ep -like "*ProgramData*" -or $ep -like "*Temp*" -or $ep -eq "C:\\") {')
            a('                Remove-MpPreference -ExclusionPath $ep -ErrorAction SilentlyContinue')
            a('                Write-Host "[+] 移除 Defender 排除项: $ep" -ForegroundColor Green')
            a('            }')
            a('        }')
            a('    }')
            a('} catch {}')
            a('Write-Host "[+] 建议: 如 Defender 仍异常, 请手动运行 Windows 安全中心重置" -ForegroundColor Gray')
        else:
            a('# 样本未终止安全产品, 跳过')
        a('')
        # ---- 8c. 新建用户 / 管理员组 / 防火墙规则 / hosts / 劫持键 ----
        if items['delete_users'] or items['remove_admins'] or items['delete_fw_rules'] \
                or items['restore_hosts'] or items['hijack_keys']:
            a('# ---- 8c. 用户/组/防火墙/hosts/劫持键清理 ----')
            if items['delete_users']:
                a('Write-Host "[*] 删除样本新建的用户..." -ForegroundColor Yellow')
                a('$userList = @(' + ','.join(_ps_str(x) for x in items['delete_users']) + ')')
                a('foreach ($un in $userList) {')
                a('    try { net user $un /delete 2>$null | Out-Null; Write-Host "[+] 用户已删除: $un" -ForegroundColor Green }')
                a('    catch { [void]$Failed.Add("用户删除失败: $un") }')
                a('}')
            if items['remove_admins']:
                a('Write-Host "[*] 将新增成员移出 Administrators 组..." -ForegroundColor Yellow')
                a('$admList = @(' + ','.join(_ps_str(x) for x in items['remove_admins']) + ')')
                a('foreach ($am in $admList) {')
                a('    try { net localgroup Administrators $am /delete 2>$null | Out-Null; Write-Host "[+] 已移出管理员组: $am" -ForegroundColor Green }')
                a('    catch { [void]$Failed.Add("移出管理员组失败: $am") }')
                a('}')
            if items['delete_fw_rules']:
                a('Write-Host "[*] 删除样本新增的防火墙规则 (需确认)..." -ForegroundColor Yellow')
                a('$fwList = @(' + ','.join(_ps_str(x) for x in items['delete_fw_rules']) + ')')
                a('foreach ($rn in $fwList) {')
                a('    try {')
                a('        netsh advfirewall firewall delete rule name=$rn 2>$null | Out-Null')
                a('        Write-Host "[+] 防火墙规则已删除: $rn" -ForegroundColor Green')
                a('    } catch { [void]$Failed.Add("防火墙规则删除失败: $rn") }')
                a('}')
            if items['restore_hosts']:
                a('Write-Host "[*] 修复被篡改的 hosts 文件 (移除杀软域名劫持行, 保留用户自定义条目)..." -ForegroundColor Yellow')
                a('$hostsPath = "$env:windir\\System32\\drivers\\etc\\hosts"')
                a('try {')
                a('    Copy-Item $hostsPath "$hostsPath.bak_cleanup" -Force -ErrorAction SilentlyContinue')
                a('    # 银狐禁装杀软: hosts 中把 360/火绒/卡巴/微软更新等域名指向 127.0.0.1')
                a('    $avDomains = @("360.cn","360safe.com","qh.360.cn","huorong.cn","kaspersky.com",')
                a('        "avast.com","avg.com","eset.com","nod32","mcafee.com","symantec.com",')
                a('        "trendmicro.com","bitdefender.com","defender","microsoft.com","windowsupdate.com",')
                a('        "update.microsoft.com","download.microsoft.com","windowsupdate.microsoft.com",')
                a('        "windowsupdate.com","ctldl.windowsupdate.com","ds.download.windowsupdate.com")')
                a('    $kept = @()')
                a('    $removed = @()')
                a('    Get-Content -Path $hostsPath | ForEach-Object {')
                a('        $line = $_.Trim()')
                a('        if (-not $line -or $line.StartsWith("#")) { $kept += $_; return }')
                a('        $hit = $false')
                a('        foreach ($ad in $avDomains) {')
                a('            if ($line -match [regex]::Escape($ad)) { $hit = $true; break }')
                a('        }')
                a('        if ($hit -and $line -match "^127\\.0\\.0\\.1|^0\\.0\\.0\\.0") {')
                a('            $removed += $line')
                a('        } else { $kept += $_ }')
                a('    }')
                a('    Set-Content -Path $hostsPath -Value $kept -Encoding ASCII')
                a('    if ($removed.Count -gt 0) {')
                a('        Write-Host "[+] 已移除 hosts 劫持行 $($removed.Count) 条:" -ForegroundColor Green')
                a('        $removed | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }')
                a('    } else {')
                a('        Write-Host "[*] hosts 无杀软域名劫持行, 已跳过 (备份: hosts.bak_cleanup)" -ForegroundColor Gray')
                a('    }')
                a('} catch { [void]$Failed.Add("hosts 修复失败: $_") }')
            if items['hijack_keys']:
                a('Write-Host "[*] 还原注册表劫持键 (Winlogon/AppInit)..." -ForegroundColor Yellow')
                a('foreach ($hk in @(' + ','.join(
                    '@{' + f"Key={_ps_str(x['key'])}; Value={_ps_str(x['value'])}; Data={_ps_str(x['data'])}" + '}'
                    for x in items['hijack_keys']) + ')) {')
                a('    try {')
                a('        $path = $hk.Key -replace "^HKLM","HKLM:" -replace "^HKCU","HKCU:"')
                a('        if ($hk.Data) { New-ItemProperty -Path $path -Name $hk.Value -Value $hk.Data -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null }')
                a('        else { Write-Host "[-] 劫持键缺少原始值, 已跳过删除(避免破坏服务): $($hk.Key) :: $($hk.Value) — 请人工检查还原" -ForegroundColor Yellow }')
                a('        Write-Host "[+] 劫持键已还原: $($hk.Key) :: $($hk.Value)" -ForegroundColor Green')
                a('    } catch { [void]$Failed.Add("劫持键还原失败: $($hk.Key)") }')
                a('}')
            a('')
        # ---- 8c2. WMI 持久化订阅删除 (远控常用持久化) ----
        if items['delete_wmi']:
            a('# ---- 8c2. WMI 持久化订阅清理 ----')
            a('Write-Host "[*] 删除样本创建的 WMI 持久化订阅..." -ForegroundColor Yellow')
            a('$wmiList = @(' + ','.join(_ps_str(x) for x in items['delete_wmi']) + ')')
            a('foreach ($wn in $wmiList) {')
            a('    try {')
            a('        # 按名称删除订阅组件 (filter/consumer/binding)')
            a('        Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter "Name=''$wn''" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue')
            a('        Get-WmiObject -Namespace root\\subscription -Class __EventConsumer -Filter "Name=''$wn''" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue')
            a('        Write-Host "[+] WMI 订阅已删除: $wn" -ForegroundColor Green')
            a('    } catch { [void]$Failed.Add("WMI 订阅删除失败: $wn") }')
            a('}')
            a('')
        # ---- 8d. 新增监听端口报告 (不自动处理) ----
        if items['report_listeners']:
            a('# ---- 8d. 新增监听端口 (样本开放端口迹象) ----')
            a('Write-Host "[!] 分析期间新增监听端口 (可能为样本开放):" -ForegroundColor Red')
            a('$listenList = @(' + ','.join(_ps_str(x) for x in items['report_listeners']) + ')')
            a('foreach ($lp in $listenList) { Write-Host "      $lp" -ForegroundColor Red }')
            a('Write-Host "      如需排查: netstat -ano | findstr LISTENING" -ForegroundColor Gray')
            a('')
        # ---- 8e. PPL 保护进程报告 ----
        if items['report_ppl']:
            a('# ---- 8e. PPL 保护进程 (样本设置防杀) ----')
            a('Write-Host "[!] 分析期间新增 PPL 受保护进程 (样本设置防杀, 需驱动级处理):" -ForegroundColor Red')
            a('$pplList = @(' + ','.join(_ps_str(x) for x in items['report_ppl']) + ')')
            a('foreach ($pp in $pplList) { Write-Host "      $pp" -ForegroundColor Red }')
            a('')
        # ---- 8f. 系统文件被篡改报告 ----
        if items['report_sysfile']:
            a('# ---- 8f. 系统文件被篡改 (文件劫持/感染) ----')
            a('Write-Host "[!] 检测到系统文件被篡改 (可能被劫持/感染):" -ForegroundColor Red')
            a('$sfList = @(' + ','.join(_ps_str(x) for x in items['report_sysfile']) + ')')
            a('foreach ($sf in $sfList) { Write-Host "      $sf" -ForegroundColor Red }')
            a('Write-Host "      建议: sfc /scannow 或 DISM /Online /Cleanup-Image /RestoreHealth" -ForegroundColor Gray')
            a('')
        # ---- 8f2. 被删除的系统服务报告 (银狐禁装杀软: 删杀软服务注册表项) ----
        if items['report_deleted_svc']:
            a('# ---- 8f2. 被删除的系统服务 (样本删除, 无法自动重建) ----')
            a('Write-Host "[!] 检测到系统服务被样本删除 (无法自动重建):" -ForegroundColor Red')
            a('$delSvcList = @(' + ','.join(_ps_str(x) for x in items['report_deleted_svc']) + ')')
            a('foreach ($ds in $delSvcList) { Write-Host "      $ds" -ForegroundColor Red }')
            a('Write-Host "      建议: sfc /scannow 修复; Defender 组件缺失时运行 DISM /Online /Cleanup-Image /RestoreHealth 后重启" -ForegroundColor Gray')
            a('')
        # ---- 8g. 新增 DNS 解析报告 (C2 IoC) ----
        if items['report_dns']:
            a('# ---- 8g. 新增 DNS 解析 (样本域名 — C2/IoC) ----')
            a('Write-Host "[!] 分析期间新增 DNS 解析 (可能为 C2/载荷域名):" -ForegroundColor Red')
            a('$dnsList = @(' + ','.join(_ps_str(x) for x in items['report_dns']) + ')')
            a('foreach ($dn in $dnsList) { Write-Host "      $dn" -ForegroundColor Red }')
            a('')
        a('# ---- 9. 重启验证准备 ----')
        if items['verify_items'] and not self._skip_verify:
            a('Write-Host "[*] 准备重启验证..."')
            a('$verify = @(' + ','.join(
                '@{' + f"type={_ps_str(v['type'])}; path={_ps_str(v['path'])}" + '}'
                for v in items['verify_items']) + ')')
            a('$verify | ConvertTo-Json | Set-Content -Path $VerifyFile -Encoding UTF8')
            a('$verifyScript = Join-Path $ScriptDir "verify_' + items['scan_id'] + '.ps1"')
            a('$verifyCmd = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$verifyScript`""')
            a('try { Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" -Name "CleanupVerify_' + items['scan_id'] + '" -Value $verifyCmd -Force } catch {}')
            a('Write-Host "[+] 已注册重启验证 (RunOnce)" -ForegroundColor Green')
            a('Write-Host "[*] 重启后系统将自动验证清理效果并弹出结果"')
        a('')
        a('# ---- 10. 结果汇总 ----')
        a('Write-Host ""')
        a('if ($Retry.Count -gt 0) {')
        a('    $Retry | ConvertTo-Json | Set-Content -Path $RetryFile -Encoding UTF8')
        a('    Write-Host "[*] 重启后将对 $($Retry.Count) 个失败项自动重试删除" -ForegroundColor Yellow')
        a('}')
        a('if ($Failed.Count -gt 0) {')
        a('    Write-Host "==============================================" -ForegroundColor Red')
        a('    Write-Host "  清理完成, 但存在失败项: $($Failed.Count)" -ForegroundColor Red')
        a('    $Failed | Set-Content -Path $ResultFile -Encoding UTF8')
        a('    Write-Host "失败清单已保存: $ResultFile" -ForegroundColor Red')
        a('    try {')
        a('        Add-Type -AssemblyName System.Windows.Forms')
        a('        [System.Windows.Forms.MessageBox]::Show("自动清理存在失败项`n`n请查看: `n$ResultFile", "杀毒清理 - 部分失败", "OK", "Warning") | Out-Null')
        a('    } catch { Start-Process notepad $ResultFile }')
        a('} else {')
        a('    Write-Host "==============================================" -ForegroundColor Green')
        a('    Write-Host "  清理完成, 全部成功!" -ForegroundColor Green')
        if items['verify_items'] and not self._skip_verify:
            a('    Write-Host "  重启后将自动验证清理效果" -ForegroundColor Yellow')
        a('}')
        a('Write-Host ""')
        return '\n'.join(s) + '\n'

    @property
    def _skip_verify(self) -> bool:
        return False
