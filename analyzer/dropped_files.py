#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
释放文件追踪引擎 — 监控样本运行期间释放的所有文件
"""
import os
import hashlib
from typing import List

from logger import get_logger
from utils.helpers import calc_entropy, detect_file_type_file
from analyzer.models import DroppedFilesAnalysis, DroppedFile

logger = get_logger('analyzer.dropped_files')


class DroppedFileTracker:
    """释放文件追踪器"""

    SUSPICIOUS_PATHS = [
        '\\temp\\', '\\tmp\\', '\\appdata\\', '\\local\\',
        '\\roaming\\', '\\programdata\\', '\\windows\\',
        '\\system32\\', '\\syswow64\\', '\\start menu\\',
        '\\startup\\', '\\recycler\\', '\\$recycle',
    ]

    EXECUTABLE_EXTS = {'.exe', '.dll', '.scr', '.sys', '.com', '.pif', '.bat', '.cmd', '.ps1'}
    SCRIPT_EXTS = {'.vbs', '.js', '.hta', '.wsf', '.wsh', '.py', '.sh'}
    DOC_EXTS = {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf'}

    def __init__(self, monitor_dirs: List[str] = None):
        self.monitor_dirs = monitor_dirs or []
        self._tracked_files = []
        if self.monitor_dirs:
            self._take_baseline()

    def _take_baseline(self):
        """记录初始文件状态"""
        self._baseline_files = set()
        for d in self.monitor_dirs:
            if os.path.exists(d):
                for root, _, files in os.walk(d):
                    for f in files:
                        self._baseline_files.add(os.path.join(root, f).lower())

    def track(self, sandbox_dir: str = None, dynamic_files: List[str] = None) -> DroppedFilesAnalysis:
        """追踪释放文件"""
        result = DroppedFilesAnalysis()
        dropped = []
        seen_abs = set()  # 防重复：用绝对路径

        # 1. 遍历沙箱目录找文件
        if sandbox_dir and os.path.exists(sandbox_dir):
            sandbox_abs = os.path.abspath(sandbox_dir)
            for root, _, files in os.walk(sandbox_dir):
                if '_artifacts_' in root:
                    continue
                for f in files:
                    full_path = os.path.join(root, f)
                    if '_artifacts_' in full_path:
                        continue
                    rel_path = full_path.replace(sandbox_abs, '').lstrip('\\/')
                    seen_abs.add(full_path.lower())
                    dropped.append(self._analyze_file(full_path, rel_path))

        # 2. 处理动态监控捕获的文件（含沙箱 diff + FileSystemMonitor 的结果）
        if dynamic_files:
            for f in dynamic_files:
                # 从 FileSystemMonitor dict 中提取缓存的元数据
                cached_meta = {}
                if isinstance(f, dict):
                    cached_meta = dict(f)
                    fpath = f.get('path', '')
                else:
                    fpath = f

                # ⚠ 噪音过滤: DISM 系统临时文件/沙箱自身产物/浏览器缓存 —
                #   曾把 Temp\<GUID>\ 下几十个系统 DLL 当"样本释放"撑爆磁盘
                if isinstance(fpath, str):
                    try:
                        from analyzer.dynamic import FileSystemMonitor
                        if FileSystemMonitor._is_noise_file(fpath):
                            continue
                    except Exception:
                        pass

                # 解析为绝对路径
                abs_path = self._resolve_path(fpath, sandbox_dir)
                if not abs_path:
                    # 无法解析，尝试用路径字符串本身记录
                    dropped.append(self._make_dropped_from_path(fpath, fpath, cached_meta))
                    continue

                # 防重复
                if abs_path.lower() in seen_abs:
                    continue
                seen_abs.add(abs_path.lower())

                if os.path.exists(abs_path):
                    rel_path = self._make_rel_path(abs_path, sandbox_dir) if sandbox_dir else fpath
                    dropped.append(self._analyze_file(abs_path, rel_path))
                else:
                    # 文件已被清理/删除，优先用缓存元数据
                    display_path = fpath if not sandbox_dir else self._make_rel_path(abs_path, sandbox_dir)
                    dropped.append(self._make_dropped_from_path(abs_path, display_path, cached_meta))

        result.dropped_files = dropped
        result.total_dropped = len(dropped)
        result.executable_dropped = sum(1 for d in dropped if d.is_executable)
        result.dll_dropped = sum(1 for d in dropped if d.path.lower().endswith('.dll'))
        result.script_dropped = sum(1 for d in dropped if any(d.path.lower().endswith(e) for e in self.SCRIPT_EXTS))
        result.documents_dropped = sum(1 for d in dropped if any(d.path.lower().endswith(e) for e in self.DOC_EXTS))

        for d in dropped:
            if d.is_executable or d.entropy > 7.0 or any(p in d.path.lower() for p in self.SUSPICIOUS_PATHS):
                result.suspicious_dropped.append(d)

        # 归档释放文件: 解压并枚举子文件 (一层深度)
        archive_children = []
        for df in dropped:
            if not os.path.exists(df.abs_path):
                continue
            _ext = os.path.splitext(df.abs_path)[1].lower()
            if _ext in ('.zip', '.rar', '.7z', '.tar', '.gz'):
                try:
                    import zipfile, tarfile
                    children = []
                    if _ext == '.zip':
                        with zipfile.ZipFile(df.abs_path) as zf:
                            for zi in zf.namelist()[:50]:
                                if zi.endswith('/'): continue
                                info = zf.getinfo(zi)
                                if info.file_size > 0:
                                    children.append({'name': zi, 'size': info.file_size})
                    elif _ext in ('.tar', '.gz'):
                        mode = 'r:gz' if _ext == '.gz' else 'r:'
                        with tarfile.open(df.abs_path, mode) as tf:
                            for m in tf.getmembers()[:50]:
                                if m.isfile() and m.size > 0:
                                    children.append({'name': m.name, 'size': m.size})
                    elif _ext in ('.rar', '.7z'):
                        children.append({'name': '(需要专用解压库)', 'size': 0})
                    if children:
                        archive_children.append({
                            'parent': df.path, 'child_count': len(children),
                            'children': children[:20],
                        })
                except Exception:
                    pass
        result.archive_children = archive_children

        result.summary = f"释放 {len(dropped)} 个文件, 可执行 {result.executable_dropped}, 可疑 {len(result.suspicious_dropped)}"
        logger.info(f"[DroppedFiles] {result.summary}")
        return result

    def _resolve_path(self, f: str, sandbox_dir: str = None) -> str:
        """将相对路径解析为绝对路径"""
        if os.path.isabs(f):
            return os.path.abspath(f)
        # 相对路径 — 尝试用 sandbox_dir 解析
        if sandbox_dir:
            candidate = os.path.join(os.path.abspath(sandbox_dir), f)
            if os.path.exists(candidate):
                return candidate
            # 如果不存在，也返回这个路径（文件可能已被清理）
            return candidate
        # 没有 sandbox_dir，无法解析相对路径
        return ''

    def _make_rel_path(self, abs_path: str, sandbox_dir: str) -> str:
        """从绝对路径生成相对显示路径"""
        if not sandbox_dir:
            return abs_path
        sandbox_abs = os.path.abspath(sandbox_dir)
        if abs_path.lower().startswith(sandbox_abs.lower()):
            return abs_path[len(sandbox_abs):].lstrip('\\/')
        # 不在沙箱目录内 — 标记为外部路径，但保留关键子目录结构
        for marker in ['\\AppData\\', '\\ProgramData\\', '\\Windows\\Temp\\', '\\Temp\\']:
            ml = marker.lower()
            idx = abs_path.lower().find(ml)
            if idx >= 0:
                return '[外部] ' + abs_path[idx + len(ml):]
        return '[外部] ' + os.path.basename(abs_path)

    def _make_dropped_from_path(self, abs_path: str, display_path: str, cached_meta: dict = None) -> DroppedFile:
        """从路径字符串构造DroppedFile（文件已不存在时使用，优先用缓存元数据）"""
        ext = os.path.splitext(abs_path)[1].lower()
        is_exec = ext in self.EXECUTABLE_EXTS

        if cached_meta:
            return DroppedFile(
                path=display_path,
                size=cached_meta.get('size', 0),
                md5=cached_meta.get('md5', ''),
                sha256=cached_meta.get('sha256', ''),
                file_type=cached_meta.get('file_type', 'PE' if is_exec else 'Unknown'),
                entropy=cached_meta.get('entropy', 0.0),
                is_executable=cached_meta.get('is_executable', is_exec),
                abs_path=abs_path,
            )

        return DroppedFile(
            path=display_path,
            size=0,
            md5='',
            sha256='',
            file_type='PE' if is_exec else 'Unknown',
            entropy=0.0,
            is_executable=is_exec,
            abs_path=abs_path,
        )

    def _analyze_file(self, path: str, rel_path: str) -> DroppedFile:
        """分析单个文件"""
        size = os.path.getsize(path) if os.path.exists(path) else 0
        md5 = ''
        sha256 = ''
        entropy = 0.0
        ftype = 'Unknown'

        try:
            if size > 0 and size < 100 * 1024 * 1024:
                with open(path, 'rb') as f:
                    data = f.read()
                md5 = hashlib.md5(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
                if size < 10 * 1024 * 1024:
                    entropy = calc_entropy(data)
                ftype, _ = detect_file_type_file(path)
        except:
            pass

        ext = os.path.splitext(path)[1].lower()
        is_exec = ext in self.EXECUTABLE_EXTS

        # 轻量级内容特征提取
        analysis_note = ''
        try:
            if size > 0 and size < 10 * 1024 * 1024:
                with open(path, 'rb') as f:
                    data = f.read(min(size, 256 * 1024))
                if data[:2] == b'MZ':
                    pe_imports = data.lower().count(b'kernel32') + data.lower().count(b'ntdll')
                    analysis_note = f'PE | imports~{pe_imports}'
                elif any(kw in data[:4096].lower() for kw in [b'createprocess', b'virtualalloc', b'winexec', b'powershell', b'cmd.exe', b'download', b'http://', b'https://']):
                    suspicious_count = sum(1 for kw in [b'createprocess', b'virtualalloc', b'winexec', b'powershell', b'cmd.exe'] if kw in data.lower())
                    analysis_note = f'Script | suspiciousAPI~{suspicious_count}'
        except Exception:
            pass

        return DroppedFile(
            path=rel_path,
            size=size,
            md5=md5,
            sha256=sha256,
            file_type=ftype,
            entropy=entropy,
            is_executable=is_exec,
            abs_path=path,
            analysis_note=analysis_note,
        )
