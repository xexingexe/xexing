#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
持久化回滚 — 分析结束后清理样本注册的持久化机制 (对抗"退出后延迟重启"逃逸)

安全设计 (物理机/宿主机必须保守):
  1. 只删除"分析窗口内新增"的项 (before/after diff)
  2. 且该项的值/命令必须精确包含样本释放文件路径 (sample_paths)
  3. 所有删除 try/except 包裹, 失败仅告警不报错
  4. 只回滚 Run/RunOnce 键 + 计划任务; 服务/WMI 只检测不删除 (风险高, 交报告)
"""
import subprocess
import winreg
from typing import Dict, List, Set

from logger import get_logger

logger = get_logger('analyzer.persistence_rollback')

# (hive 标识, 子键) — 标准 Run/RunOnce 持久化位置 (含 WOW6432Node)
RUN_KEY_LOCATIONS = [
    ('HKCU', winreg.HKEY_CURRENT_USER,
     r'Software\Microsoft\Windows\CurrentVersion\Run'),
    ('HKCU', winreg.HKEY_CURRENT_USER,
     r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
    ('HKLM', winreg.HKEY_LOCAL_MACHINE,
     r'Software\Microsoft\Windows\CurrentVersion\Run'),
    ('HKLM', winreg.HKEY_LOCAL_MACHINE,
     r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
    ('HKLM', winreg.HKEY_LOCAL_MACHINE,
     r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
    ('HKLM', winreg.HKEY_LOCAL_MACHINE,
     r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'),
]


def _snapshot_run_keys() -> Dict[str, str]:
    """快照所有 Run/RunOnce 键值 → {f'{hive}|{subkey}|{value_name}': value}"""
    result = {}
    for hive_name, hive, subkey in RUN_KEY_LOCATIONS:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, vtype = winreg.EnumValue(key, i)
                        if vtype in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                            result[f'{hive_name}|{subkey}|{name}'] = str(value)
                        i += 1
                    except OSError:
                        break
        except (FileNotFoundError, OSError, PermissionError):
            pass
    return result


def _snapshot_scheduled_tasks() -> Dict[str, str]:
    """快照计划任务 → {task_path_name: 动作命令}"""
    result = {}
    try:
        ps = ("Get-ScheduledTask | ForEach-Object { $_.TaskPath + $_.TaskName + '|' "
              "+ (($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ';;') }")
        r = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps],
            capture_output=True, text=True, timeout=25, errors='ignore')
        if r.returncode != 0:
            return result
        for line in r.stdout.split('\n'):
            line = line.strip()
            if '|' in line:
                name, cmd = line.split('|', 1)
                result[name.strip()] = cmd.strip()
    except Exception as e:
        logger.debug(f"[Rollback] 计划任务快照失败: {e}")
    return result


def take_persistence_snapshot() -> Dict:
    """分析前调用: 快照 Run 键 + 计划任务"""
    return {
        'run_keys': _snapshot_run_keys(),
        'tasks': _snapshot_scheduled_tasks(),
    }


def _lower_paths(sample_paths) -> List[str]:
    paths = []
    for p in (sample_paths or []):
        lp = p.lower().strip().strip('"').rstrip('\\')
        if lp:
            paths.append(lp)
    return sorted(paths, key=len, reverse=True)


def rollback_run_keys(before: Dict[str, str], sample_paths) -> List[str]:
    """回滚样本新增的 Run 键 (值必须包含样本释放文件路径)"""
    after = _snapshot_run_keys()
    paths = _lower_paths(sample_paths)
    if not paths:
        return []
    removed = []
    for key, value in after.items():
        paths_hit = [sp for sp in paths if sp in value.lower()]
        if not paths_hit:
            continue
        hive_name, subkey, vname = key.split('|', 2)
        hive = winreg.HKEY_CURRENT_USER if hive_name == 'HKCU' else winreg.HKEY_LOCAL_MACHINE
        if key in before:
            # 样本可能把既有启动项改成自己的载荷: 写回分析前的旧值
            old_value = before[key]
            if old_value == value:
                continue
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.SetValueEx(k, vname, 0, winreg.REG_SZ, old_value)
                removed.append(f'Run键恢复: {subkey}\\{vname} = {old_value[:80]}')
                logger.warning(f"[Rollback] 恢复被样本修改的 Run 键: {subkey}\\{vname}")
            except Exception as e:
                logger.debug(f"[Rollback] Run 键恢复失败 {subkey}\\{vname}: {e}")
            continue
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, vname)
            removed.append(f'Run键: {subkey}\\{vname} = {value[:80]}')
            logger.warning(f"[Rollback] 删除样本 Run 键: {subkey}\\{vname}")
        except Exception as e:
            logger.debug(f"[Rollback] Run 键删除失败 {subkey}\\{vname}: {e}")
    return removed


def rollback_scheduled_tasks(before: Dict[str, str], sample_paths) -> List[str]:
    """回滚样本新增的计划任务 (动作命令必须包含样本释放文件路径)"""
    after = _snapshot_scheduled_tasks()
    paths = _lower_paths(sample_paths)
    if not paths:
        return []
    removed = []
    for name, cmd in after.items():
        if name in before:
            continue
        if not any(sp in cmd.lower() for sp in paths):
            continue
        try:
            r = subprocess.run(
                ['schtasks', '/delete', '/tn', name, '/f'],
                capture_output=True, timeout=20)
            if r.returncode == 0:
                removed.append(f'计划任务: {name} = {cmd[:80]}')
                logger.warning(f"[Rollback] 删除样本计划任务: {name}")
        except Exception as e:
            logger.debug(f"[Rollback] 计划任务删除失败 {name}: {e}")
    return removed


def rollback_persistence(snapshot_before: Dict, sample_paths) -> Dict:
    """分析结束后调用: diff 并回滚样本持久化 (Run 键 + 计划任务)

    返回 {'run_keys': [...], 'tasks': [...]} 供报告记录
    """
    if not snapshot_before:
        return {'run_keys': [], 'tasks': []}
    result = {'run_keys': [], 'tasks': []}
    try:
        result['run_keys'] = rollback_run_keys(snapshot_before.get('run_keys', {}), sample_paths)
    except Exception as e:
        logger.debug(f"[Rollback] Run 键回滚失败: {e}")
    try:
        result['tasks'] = rollback_scheduled_tasks(snapshot_before.get('tasks', {}), sample_paths)
    except Exception as e:
        logger.debug(f"[Rollback] 计划任务回滚失败: {e}")
    if result['run_keys'] or result['tasks']:
        logger.warning(f"[Rollback] 持久化回滚完成: Run键{len(result['run_keys'])}个, "
                       f"计划任务{len(result['tasks'])}个")
    return result
