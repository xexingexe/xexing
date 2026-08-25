#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
释放文件追踪引擎 — 监控样本运行期间释放的所有文件
"""
import os
import hashlib
import struct
from typing import List

from logger import get_logger
from utils.helpers import calc_entropy, detect_file_type_file
from analyzer.models import DroppedFilesAnalysis, DroppedFile

logger = get_logger('analyzer.dropped_files')


def detect_magic_kind(data: bytes):
    """魔数检测 — 按文件头内容识别真实类型（不依赖扩展名）

    返回 (kind, label)：kind 为 VT 风格分类，label 为人读类型描述。
    重点补漏：DOS_COM（MZ 无 PE 头）、PE_DLL（PE 且 DLL 标志位）、
    脚本/文本/压缩包等无扩展名或伪装扩展名的释放文件。
    """
    if not data:
        return ('unknown', 'Unknown')
    if len(data) < 2:
        return ('unknown', 'Unknown')

    if data[:2] == b'MZ':
        # 有 PE 签名 → 真 PE（区分 EXE/DLL）
        try:
            if len(data) >= 0x40:
                pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
                if data[pe_off:pe_off + 4] == b'PE\x00\x00' and len(data) >= pe_off + 6:
                    machine = struct.unpack('<H', data[pe_off + 4:pe_off + 6])[0]
                    arch = {0x14C: 'x86', 0x8664: 'x64', 0xAA64: 'ARM64', 0x1C0: 'ARM'}.get(machine, f'0x{machine:04X}')
                    # 读 COFF Characteristics (DLL 标志 0x2000)
                    chars = struct.unpack('<H', data[pe_off + 4 + 18:pe_off + 4 + 20])[0] \
                        if len(data) >= pe_off + 4 + 20 else 0
                    if chars & 0x2000:
                        return ('PE_DLL', f'PE32 DLL ({arch})')
                    # .sys 驱动 = PE 且 Subsystem 为 Native(1)
                    try:
                        opt_off = pe_off + 4 + 20
                        size_opt = struct.unpack('<H', data[opt_off:opt_off + 2])[0]
                        sub_off = opt_off + 68
                        if len(data) >= sub_off + 2:
                            subsystem = struct.unpack('<H', data[sub_off:sub_off + 2])[0]
                            if subsystem == 1:
                                return ('PE_DRIVER', f'PE 驱动 ({arch})')
                    except Exception:
                        pass
                    return ('PE_EXE', f'PE32 可执行文件 ({arch})')
        except Exception:
            pass
        # MZ 无有效 PE 头 → DOS 可执行文件 (DOS_COM/DOS MZ)
        return ('DOS_COM', 'DOS MZ 可执行文件（无 PE 头）')

    if data[:4] == b'\x7fELF':
        return ('ELF', 'ELF 可执行文件')
    if data[:4] == b'PK\x03\x04' or data[:4] == b'PK\x05\x06':
        return ('ZIP', 'ZIP 压缩包')
    if data[:4] == b'\x89PNG':
        return ('PNG', 'PNG 图片')
    if data[:2] == b'\xff\xd8':
        return ('JPEG', 'JPEG 图片')
    if data[:4] == b'%PDF':
        return ('PDF', 'PDF 文档')
    if data[:4] == b'7z\xbc\xaf':
        return ('7Z', '7-Zip 压缩包')
    if data[:3] == b'Rar':
        return ('RAR', 'RAR 压缩包')
    if data[:4] == b'\xd0\xcf\x11\xe0':
        return ('OLE', 'OLE 复合文档 (Office)')
    if data[:8] == b'\x00\x00\x00\x00\x00\x00\x00\x00':
        return ('EMPTY', '空文件/零填充')

    # 文本/脚本类（以可打印 ASCII 为主）
    head = data[:512]
    printable = sum(1 for b in head if 0x20 <= b <= 0x7E or b in (0x0A, 0x0D, 0x09))
    if len(head) and printable / len(head) > 0.85:
        text = head.decode('utf-8', errors='ignore')
        tl = text.lower()
        if tl.startswith('#!') or 'powershell' in tl or 'wscript' in tl or 'cscript' in tl:
            return ('SCRIPT', '脚本文件')
        if '<html' in tl or '<?xml' in tl or '<script' in tl:
            return ('HTML', 'HTML/XML 文档')
        return ('TEXT', '文本文件')

    return ('unknown', 'Unknown')



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
        result.dll_dropped = sum(1 for d in dropped
                                 if d.path.lower().endswith('.dll')
                                 or d.file_type.startswith('PE32 DLL')
                                 or getattr(d, 'file_kind', '') == 'PE_DLL')
        result.script_dropped = sum(1 for d in dropped
                                    if any(d.path.lower().endswith(e) for e in self.SCRIPT_EXTS)
                                    or getattr(d, 'file_kind', '') == 'SCRIPT')
        result.documents_dropped = sum(1 for d in dropped
                                       if any(d.path.lower().endswith(e) for e in self.DOC_EXTS)
                                       or getattr(d, 'file_kind', '') in ('PDF', 'OLE', 'TEXT'))

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
        magic_kind = ''

        try:
            if size > 0 and size < 100 * 1024 * 1024:
                with open(path, 'rb') as f:
                    data = f.read()
                md5 = hashlib.md5(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
                if size < 10 * 1024 * 1024:
                    entropy = calc_entropy(data)
                ftype, _ = detect_file_type_file(path)
                # 魔数检测 — 覆盖扩展名伪装/无扩展名/系统 file 识别失败的情况
                magic_kind, magic_label = detect_magic_kind(data)
                # 魔数结果优先于扩展名推断（file 库对 DOS/伪装文件常识别为 generic）
                if magic_kind not in ('unknown',):
                    ftype = magic_label
        except:
            pass

        ext = os.path.splitext(path)[1].lower()
        is_exec = (ext in self.EXECUTABLE_EXTS
                   or magic_kind in ('PE_EXE', 'PE_DLL', 'PE_DRIVER', 'DOS_COM', 'ELF', 'SCRIPT'))

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
            file_kind=magic_kind,
        )
