#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量扫描 + 热文件夹监控 — 目录批量分析 & 投放即自动分析

热文件夹用轮询实现 (不引入 watchdog 依赖), 检测新文件稳定后自动分析。
"""
import os
import time
import queue
import threading
import concurrent.futures
from typing import List, Tuple

from logger import get_logger
from config import CONFIG

logger = get_logger('batch')

# 批量扫描时排除的噪音/中间文件
_SKIP_EXTENSIONS = {
    '.tmp', '.part', '.crdownload', '.log', '.html', '.json', '.xml',
    '.ini', '.txt', '.md', '.py', '.pyc', '.spec', '.bat', '.sh',
}

_SKIP_NAMES = {'thumbs.db', 'desktop.ini', '.ds_store'}


def _is_noise(path: str) -> bool:
    name = os.path.basename(path).lower()
    if name in _SKIP_NAMES:
        return True
    ext = os.path.splitext(name)[1].lower()
    return ext in _SKIP_EXTENSIONS


def list_samples(dir_path: str, recursive: bool = True) -> List[str]:
    """列出目录下的样本文件 (排除噪音)"""
    files = []
    if os.path.isfile(dir_path):
        return [dir_path]
    for root, dirs, names in os.walk(dir_path):
        for n in names:
            p = os.path.join(root, n)
            if not _is_noise(p) and os.path.isfile(p):
                files.append(p)
        if not recursive:
            break
    return sorted(files)


def _is_file_stable(path: str, min_stable_seconds: float = 2.0) -> bool:
    """文件是否稳定 (大小连续稳定 + 可写句柄打开) — 防止分析到写了一半的文件"""
    try:
        s1 = os.path.getsize(path)
        t1 = os.path.getmtime(path)
        time.sleep(min_stable_seconds)
        if not os.path.exists(path):
            return False
        s2 = os.path.getsize(path)
        t2 = os.path.getmtime(path)
        return s1 == s2 and t1 == t2 and s1 > 0
    except OSError:
        return False


def _analyze_one(platform, file_path: str, stop_event, analyze_kwargs: dict):
    """包装单文件分析: 异常时返回 (file_path, None) 并记录日志"""
    try:
        report = platform.analyze(file_path, stop_event=stop_event, **analyze_kwargs)
        return (file_path, report)
    except Exception as e:
        logger.error(f"[-] 分析失败 {file_path}: {e}")
        return (file_path, None)


def scan_directory(platform, dir_path: str, recursive: bool = True,
                   stop_event=None, **analyze_kwargs) -> List[Tuple[str, object]]:
    """批量扫描目录下所有样本, 返回 [(file_path, report)]"""
    files = list_samples(dir_path, recursive)
    if not files:
        logger.warning(f"[-] 目录 {dir_path} 下未发现可分析文件")
        return []
    logger.info(f"[*] 批量扫描: {len(files)} 个文件")

    # 动态分析必须串行 (沙箱/监控资源冲突)
    if analyze_kwargs.get('enable_dynamic'):
        results = []
        for i, f in enumerate(files, 1):
            if stop_event and stop_event.is_set():
                break
            logger.info(f"[*] ({i}/{len(files)}) 分析: {f}")
            results.append(_analyze_one(platform, f, stop_event, analyze_kwargs))
        return results

    workers = max(1, min(int(getattr(CONFIG, 'threads', 4) or 4), 8))
    results = [None] * len(files)
    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for i, f in enumerate(files, 1):
            if stop_event and stop_event.is_set():
                logger.info("[*] 批量扫描: 停止信号已置位, 跳过剩余文件")
                break
            logger.info(f"[*] ({i}/{len(files)}) 分析: {f}")
            futures.append((i, f, executor.submit(_analyze_one, platform, f, stop_event, analyze_kwargs)))
        for i, f, fut in futures:
            if stop_event and stop_event.is_set():
                logger.info("[*] 批量扫描: 停止信号已置位, 跳过剩余结果收集")
                break
            try:
                results[i - 1] = fut.result()
            except Exception as e:
                logger.error(f"[-] 分析失败 {f}: {e}")
                results[i - 1] = (f, None)
    return [r for r in results if r is not None]


def watch_directory(platform, dir_path: str, poll_interval: float = 3.0,
                    stop_event=None, **analyze_kwargs):
    """热文件夹监控: 新文件投放即自动分析 (阻塞运行, 直到 stop_event 或 Ctrl+C)

    已存在的文件不分析 (只监控监控启动后新增的文件)。
    """
    if not os.path.isdir(dir_path):
        logger.error(f"[-] 目录不存在: {dir_path}")
        return
    known = set()
    for root, dirs, names in os.walk(dir_path):
        for n in names:
            known.add(os.path.join(root, n).lower())
    logger.info(f"[*] 热文件夹监控启动: {dir_path} (轮询间隔 {poll_interval}s, 已跳过 {len(known)} 个已有文件)")

    pending = queue.Queue(maxsize=500)

    def _worker():
        """单后台线程: 串行等待文件稳定并分析 (稳定检查含 sleep, 不能阻塞发现循环)"""
        while True:
            item = pending.get()
            try:
                if item is None:
                    break
                p = item
                if stop_event and stop_event.is_set():
                    continue
                if not _is_file_stable(p):
                    continue
                logger.info(f"[Watch] 发现新文件: {p}")
                try:
                    platform.analyze(p, stop_event=stop_event, **analyze_kwargs)
                except Exception as e:
                    logger.error(f"[-] 分析失败 {p}: {e}")
            finally:
                pending.task_done()

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()

    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            try:
                time.sleep(poll_interval)
                for root, dirs, names in os.walk(dir_path):
                    for n in names:
                        p = os.path.join(root, n)
                        pl = p.lower()
                        if _is_noise(p) or pl in known:
                            continue
                        known.add(pl)  # 发现即入 known, 防止重复入队
                        if os.path.isfile(p):
                            pending.put(p)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.debug(f"[Watch] 监控循环异常: {e}")
    finally:
        try:
            pending.put(None, timeout=2)
        except queue.Full:
            pass
        worker.join(timeout=2)
    logger.info("[*] 热文件夹监控已停止")
