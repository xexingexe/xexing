#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
沙箱增强监控 — 命名管道检测 / 进程注入检测 / 注册表持久化监控
"""
import os
import re
import subprocess
from typing import List, Dict

from logger import get_logger

logger = get_logger('analyzer.sandbox_monitor')


class NamedPipeMonitor:
    """命名管道监控 — 检测 CobaltStrike SMB Beacon、进程间通信后门"""

    CS_PIPE_PATTERNS = [
        r'\\\\.\\pipe\\msagent_\w+',
        r'\\\\.\\pipe\\postex_\w+',
        r'\\\\.\\pipe\\MSSE-\d+-server',
        # ⚠ ntsvcs 是 Windows 常规 RPC 管道, 曾误报为 CobaltStrike, 已移除
        r'\\\\.\\pipe\\status_\w+',
    ]

    KNOWN_MALICIOUS_PIPES = [
        # 仅保留真实恶意软件常用管道名 — 系统标准管道(spoolss/epmapper/lsarpc等)必须排除,
        # 否则每台 Windows 都会误报
        'mypipe-f', 'mypipe-h',
    ]

    @staticmethod
    def enumerate_pipes() -> List[Dict]:
        results = []
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 r'Get-ChildItem \\.\pipe\ | Select-Object -ExpandProperty Name'],
                capture_output=True, text=True, timeout=8, errors='ignore'
            )
            if result.returncode == 0:
                pipes = [p.strip() for p in result.stdout.split('\n') if p.strip()]
                logger.debug(f"[NamedPipe] 发现 {len(pipes)} 个命名管道")

                for pipe in pipes:
                    entry = {'name': pipe, 'suspicious': False, 'reason': ''}

                    # Get-ChildItem 返回裸管道名, 而 CS 模式带 \\.\pipe\ 前缀 →
                    # 补全为完整路径再匹配 (否则 re.match 永不命中)
                    pipe_path = pipe if pipe.lower().startswith('\\\\.\\pipe') else '\\\\.\\pipe\\' + pipe
                    for pattern in NamedPipeMonitor.CS_PIPE_PATTERNS:
                        if re.match(pattern, pipe_path, re.IGNORECASE):
                            entry['suspicious'] = True
                            entry['reason'] = f'CobaltStrike SMB Beacon 命名管道: {pattern}'
                            break

                    if not entry['suspicious']:
                        pipe_name = os.path.basename(pipe).lower()
                        if pipe_name in NamedPipeMonitor.KNOWN_MALICIOUS_PIPES:
                            entry['suspicious'] = True
                            entry['reason'] = f'已知恶意软件常用管道名: {pipe_name}'

                    results.append(entry)

                suspicious = [r for r in results if r['suspicious']]
                if suspicious:
                    logger.warning(f"[NamedPipe] 发现 {len(suspicious)} 个可疑命名管道")
                    for s in suspicious:
                        logger.warning(f"  {s['name']} → {s['reason']}")

        except Exception as e:
            logger.debug(f"[NamedPipe] 枚举失败: {e}")

        return results


class ProcessInjectionDetector:
    """进程注入检测 — 通过进程权限/内存操作特征"""

    SUSPICIOUS_FLAGS = {
        'PROCESS_VM_WRITE': 0x0020,
        'PROCESS_VM_OPERATION': 0x0008,
        'PROCESS_CREATE_THREAD': 0x0002,
        'PROCESS_SUSPEND_RESUME': 0x0800,
        'THREAD_SET_CONTEXT': 0x0010,
        'THREAD_SUSPEND_RESUME': 0x0002,
    }

    @staticmethod
    def detect_suspicious_handles(target_pid: int) -> List[Dict]:
        results = []
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 f'Get-Process -Id {target_pid} -ErrorAction SilentlyContinue | '
                 f'Select-Object Id, ProcessName, HandleCount, Threads'],
                capture_output=True, text=True, timeout=10, errors='ignore'
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    handle_count = 0
                    for line in lines[1:]:
                        parts = line.strip().split()
                        try:
                            handle_count = int(parts[-2]) if len(parts) > 2 else 0
                        except:
                            pass

                    if handle_count > 500:
                        results.append({
                            'type': 'high_handle_count',
                            'description': f'异常句柄数: {handle_count} (正常<500)',
                            'severity': 'medium'
                        })

        except Exception as e:
            logger.debug(f"[InjectionDetect] 进程检测失败: {e}")

        return results


class RegistryPersistenceMonitor:
    """注册表持久化监控 — 常见 Run / RunOnce / 服务注册"""

    PERSISTENCE_KEYS = [
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\SYSTEM\CurrentControlSet\Services',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
    ]

    @staticmethod
    def snapshot_persistence() -> Dict[str, List[str]]:
        snapshot = {}
        for key in RegistryPersistenceMonitor.PERSISTENCE_KEYS:
            values = RegistryPersistenceMonitor._read_reg_key(key)
            if values:
                snapshot[key] = values
        return snapshot

    @staticmethod
    def diff_persistence(before: Dict, after: Dict) -> List[Dict]:
        changes = []
        for key in after:
            if key not in before:
                for val in after[key]:
                    changes.append({'type': 'new_key', 'key': key, 'value': val,
                                   'severity': 'high' if 'Run' in key else 'medium'})
            else:
                new_vals = [v for v in after[key] if v not in before[key]]
                for val in new_vals:
                    severity = 'critical' if any(k in val.lower() for k in
                        ['powershell', 'cmd.exe', 'rundll32', 'mshta', 'certutil',
                         'vbs', 'wscript', 'exe']) else 'high'
                    changes.append({'type': 'new_value', 'key': key, 'value': val,
                                   'severity': severity})

        removed_keys = [k for k in before if k not in after]
        for key in removed_keys:
            changes.append({'type': 'key_removed', 'key': key, 'value': '',
                           'severity': 'low'})

        if changes:
            logger.warning(f"[Registry] 持久化注册表变更: {len(changes)} 项")
            for c in changes:
                logger.warning(f"  [{c['severity']}] {c['key']} → {c['value'][:80]}")

        return changes

    @staticmethod
    def _read_reg_key(key: str) -> List[str]:
        results = []
        try:
            ps_path = key.replace('HKCU', 'HKCU:').replace('HKLM', 'HKLM:')
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 f'if (Test-Path "{ps_path}") {{ '
                 f'Get-ItemProperty -Path "{ps_path}" | '
                 f'Format-List * -Force | Out-String -Width 4096 }}'],
                capture_output=True, text=True, timeout=8, errors='ignore'
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if ':' in line and not line.startswith('PSPath') and not line.startswith('PSParentPath'):
                        results.append(line)
        except Exception:
            pass
        return results


class SandboxEnhancer:
    """沙箱增强器 — 统一接口"""

    def pre_execution_snapshot(self) -> Dict:
        return {
            'pipes': NamedPipeMonitor.enumerate_pipes(),
            'registry': RegistryPersistenceMonitor.snapshot_persistence(),
        }

    def post_execution_analysis(self, pre_snapshot: Dict, target_pid: int) -> Dict:
        result = {
            'pipe_changes': [],
            'injection_indicators': [],
            'registry_changes': [],
        }

        post_pipes = NamedPipeMonitor.enumerate_pipes()
        pre_pipe_names = {p['name'] for p in pre_snapshot.get('pipes', [])}
        for pipe in post_pipes:
            if pipe['name'] not in pre_pipe_names and pipe.get('suspicious'):
                result['pipe_changes'].append(pipe)

        result['injection_indicators'] = ProcessInjectionDetector.detect_suspicious_handles(target_pid)

        post_registry = RegistryPersistenceMonitor.snapshot_persistence()
        result['registry_changes'] = RegistryPersistenceMonitor.diff_persistence(
            pre_snapshot.get('registry', {}), post_registry
        )

        return result
