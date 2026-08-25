#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
压缩包分析引擎 — 自动解压并递归分析内容（含加密压缩包密码破解）
"""
import os
import re
import zipfile
import tarfile
from typing import List, Optional

from logger import get_logger
from utils.helpers import create_temp_dir
from analyzer.models import ArchiveAnalysis, ArchiveEntry

logger = get_logger('analyzer.archive')

# 解压炸弹预算: 限制累计解压文件数与未压缩总字节数
MAX_EXTRACT_FILES = 500
MAX_TOTAL_UNCOMPRESSED = 2 * 1024**3


class _ExtractBudget:
    """解压预算 — 防止压缩炸弹耗尽磁盘/文件句柄"""

    def __init__(self):
        self.total_files = 0
        self.total_uncompressed = 0

    @property
    def file_count(self) -> int:
        return self.total_files

    @property
    def total_size(self) -> int:
        return self.total_uncompressed

    def reserve(self, size: int) -> bool:
        if self.total_files >= MAX_EXTRACT_FILES:
            return False
        if self.total_uncompressed + size > MAX_TOTAL_UNCOMPRESSED:
            return False
        self.total_files += 1
        self.total_uncompressed += size
        return True

    def skipped_reason(self) -> str:
        if self.total_files >= MAX_EXTRACT_FILES:
            return f'文件数超限 (>= {MAX_EXTRACT_FILES})'
        return f'解压总量超限 (>{MAX_TOTAL_UNCOMPRESSED} bytes)'

# 可选依赖
rarfile = None
try:
    import rarfile as _rarfile
    rarfile = _rarfile
except ImportError:
    pass

py7zr = None
try:
    import py7zr as _py7zr
    py7zr = _py7zr
except ImportError:
    # exe 打包环境: backports.zstd 命名空间包收集冲突导致 py7zr 导入失败
    # → 注入 stub 绕过 (zstd 压缩方法不可用, 普通 7z/LZMA 正常; 已用 DepProbe 验证)
    try:
        import sys as _sys
        import types as _types
        if 'backports.zstd' not in _sys.modules:
            _stub = _types.ModuleType('backports.zstd')
            _stub.ZstdCompressor = None
            _stub.ZstdDecompressor = None
            _stub.zstd_version_info = (0, 0, 0)
            _sys.modules['backports.zstd'] = _stub
            try:
                import backports as _bp
                _bp.zstd = _stub
            except Exception:
                pass
        import py7zr as _py7zr
        py7zr = _py7zr
    except ImportError:
        py7zr = None


# ===== 恶意软件常用压缩密码字典 =====
MALWARE_PASSWORD_DICT = [
    # 年份
    '2026', '2025', '2024', '2023', '2022', '2021', '2020', '2019', '2018',
    # 简单数字
    '1234', '12345', '123456', '1234567', '12345678', '123456789',
    '666666', '888888', '9999', '1111', '0000', '000000',
    # 常见单词
    'infected', 'malware', 'virus', 'trojan', 'password', 'admin',
    'pass', 'pwd', 'secret', 'test', 'sample', 'crack',
    # 已知APT样本密码
    'xWp0LaAO',  # XWorm Python loader RC4 key (also used as zip password pattern)
    '2026',  # uzusy 7z password
    '<123456789>',  # XWorm config
    # 特殊
    'qwerty', 'QWERTY', 'Qwerty',
    'letmein', 'welcome', 'monkey', 'dragon',
    'iloveyou', 'trustno1', 'master', 'shadow',
    # 中文拼音
    'mima', 'jiami', '123456abc',
    # 常见钓鱼/APT投递包密码 (高频变体)
    '1', '12', '123', '1234567890', '00000000', '8888', '6666',
    'abcd', 'ABCD', 'abc123', 'Abc123', 'abc123456',
    'password123', 'Passw0rd', 'P@ssw0rd', 'Password123',
    'infected1', 'malware1', 'virus1', 'sample123',
    'virus123', 'infected123', 'malware123',
    '111111', '222222', '333333', '444444', '555555', '777777', '999999',
    'a123456', 'a12345', 'a1234', 'a123',
    'qwerty123', 'qwer1234', 'asdf', 'asdf1234', 'zxcv', 'zxcv1234',
    'admin123', 'root', 'root123', 'toor', 'pass123', 'passw0rd',
    'kali', 'kali2024', 'Kali2024', 'kali2025',
    'key', 'key123', 'keys', 'secret123', 'hidden', 'hidden123',
    'upload', 'download', 'attachment', 'document', 'report',
    '资料', '文档', '文件', '密码', '解压密码',
    '1qaz', '1qaz2wsx', 'qazwsx', 'zaq12wsx',
    '!@#$', '!@#$%', '!@#$%^',
    'woaini', '520520', '5201314', '1314520',
]


class ArchiveAnalyzer:
    """压缩包分析器 — 含加密密码自动破解"""

    ARCHIVE_SIGNATURES = {        b'PK\x03\x04': ('ZIP', 'zipfile'),
        b'PK\x05\x06': ('ZIP', 'zipfile'),
        b'PK\x07\x08': ('ZIP', 'zipfile'),
        b'Rar!\x1a\x07\x00': ('RAR', 'rarfile'),
        b'Rar!\x1a\x07\x01\x00': ('RAR5', 'rarfile'),
        b"7z\xbc\xaf'\x1c": ('7z', 'py7zr'),
        b'\x1f\x8b\x08': ('GZIP', 'tarfile'),
        b'BZh': ('BZIP2', 'tarfile'),
        b'\xfd7zXZ': ('XZ', 'tarfile'),
        b'ustar': ('TAR', 'tarfile'),
    }

    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.sys', '.com', '.pif',
        '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse',
        '.hta', '.msi', '.reg', '.wsf', '.wsh',
        '.docm', '.xlsm', '.pptm',
    }

    def __init__(self):
        self._password_found = None  # 成功破解的密码
        self._attempts = []          # 尝试过的密码列表
        self._extra_passwords = []   # 实例级候选密码 (不再修改全局字典)

    def set_extra_passwords(self, passwords: list):
        """从字符串分析中提取的候选密码 (仅本实例生效)"""
        for pw in passwords:
            if pw and len(pw) <= 64 and pw not in self._extra_passwords \
                    and pw not in MALWARE_PASSWORD_DICT:
                self._extra_passwords.insert(0, pw)

    def _password_candidates(self) -> list:
        """候选密码: 实例级优先, 内置字典兜底"""
        return self._extra_passwords + MALWARE_PASSWORD_DICT

    @staticmethod
    def extract_password_candidates(strings_analysis) -> list:
        """从字符串分析结果中提取可能的密码候选"""
        candidates = []
        if strings_analysis is None:
            return candidates
        all_strs = (strings_analysis.suspicious_strings or []) + \
                   (strings_analysis.api_calls or []) + \
                   (strings_analysis.file_paths or [])
        import re
        for s in all_strs:
            if not s:
                continue
            # 在命令行参数中查找 password=, pwd=, --pass, -p
            for m in re.finditer(r'(?:password|passwd|pwd|pass|key)\s*[=:]\s*["\']?([^"\'&\s]+)', s, re.IGNORECASE):
                pw = m.group(1).strip('"\'')
                if 3 <= len(pw) <= 64:
                    candidates.append(pw)
            # 数字字符串 6-8位可能是年份或PIN
            for m in re.finditer(r'\b(20[1-2]\d|19\d\d|66\d{4}|88\d{4}|99\d{2})\b', s):
                candidates.append(m.group(0))
        return list(set(candidates))[:20]
    
    # ===== 解压安全: 防止 Zip-Slip / 路径穿越 / 链接逃逸 =====
    @staticmethod
    def _is_safe_member_name(name: str) -> bool:
        """拒绝绝对路径、盘符、..、空字节与 ADS 冒号等危险成员名"""
        if not name or '\x00' in name or ':' in name:
            return False
        n = name.replace('\\', '/')
        if n.startswith('/') or re.match(r'^[A-Za-z]:', n):
            return False
        return not any(part == '..' for part in n.split('/'))

    @staticmethod
    def resolve_entry(extract_dir: str, name: str) -> Optional[str]:
        """把归档成员名解析为解压目录内的真实路径; 不安全/越界返回 None"""
        if not ArchiveAnalyzer._is_safe_member_name(name):
            return None
        try:
            base = os.path.realpath(extract_dir)
            target = os.path.realpath(os.path.join(base, name.replace('/', os.sep)))
            if os.path.commonpath([base, target]) != base:
                return None
            return target
        except Exception:
            return None

    def is_archive(self, file_path: str) -> bool:
        """判断是否为压缩包"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            for sig, _ in self.ARCHIVE_SIGNATURES.items():
                if header.startswith(sig):
                    return True
        except:
            pass
        return False
    
    def analyze(self, file_path: str, depth: int = 0) -> ArchiveAnalysis:
        """分析压缩包"""
        max_depth = 3
        if depth > max_depth:
            return ArchiveAnalysis(
                archive_path=file_path, archive_type='nested_too_deep',
                total_files=0, total_size_original=0,
                summary=f'嵌套深度超过 {max_depth} 层，停止递归'
            )
        
        atype = self._detect_type(file_path)
        if not atype:
            return ArchiveAnalysis(
                archive_path=file_path, archive_type='unknown',
                total_files=0, total_size_original=0,
                summary='不支持的压缩格式'
            )
        
        logger.info(f"[Archive] 分析压缩包: {os.path.basename(file_path)} (类型: {atype})")
        
        extract_dir = create_temp_dir(prefix=f"extract_{atype.lower()}_")
        entries = []
        errors = []
        budget = _ExtractBudget()
        
        try:
            entries = self._extract_recursive(file_path, extract_dir, atype, depth, budget)
            logger.info(f"[Archive] 解压预算统计: {budget.file_count} 个文件 / {budget.total_size} bytes")
        except Exception as e:
            errors.append(str(e))
        
        # 分析条目
        encrypted_files = []
        executable_files = []
        nested_archives = []
        suspicious_files = []
        total_original = 0
        total_compressed = 0
        
        for entry in entries:
            total_original += entry.size_original
            total_compressed += entry.size_compressed
            
            if entry.is_encrypted:
                encrypted_files.append(entry.filename)
            if entry.is_executable:
                executable_files.append(entry.filename)
            if entry.is_nested_archive:
                nested_archives.append(entry.filename)
        
        # 可疑检测
        suspicion_reasons = errors.copy()
        if len(entries) > 100:
            suspicion_reasons.append(f'文件数量异常多 ({len(entries)} 个)')
        
        if total_compressed > 0:
            ratio = total_original / total_compressed
            if ratio > 100:
                suspicion_reasons.append(f'压缩比炸弹 (ratio={ratio:.0f}:1)')
        
        if executable_files and len(executable_files) < len(entries):
            suspicion_reasons.append('可执行文件与非可执行文件混合')
        
        is_suspicious = bool(suspicion_reasons) or bool(encrypted_files)
        
        summary_parts = [f'类型: {atype}, 文件: {len(entries)}']
        if executable_files:
            summary_parts.append(f'可执行: {len(executable_files)}')
        if encrypted_files:
            summary_parts.append(f'加密: {len(encrypted_files)}')
            if self._password_found:
                summary_parts.append(f'密码已破解: {self._password_found} ({len(self._attempts)}次尝试)')
            else:
                summary_parts.append(f'密码破解失败 ({len(self._attempts)}次尝试)')
        if nested_archives:
            summary_parts.append(f'嵌套: {len(nested_archives)}')
        
        return ArchiveAnalysis(
            archive_path=file_path,
            archive_type=atype,
            total_files=len(entries),
            total_size_original=total_original,
            total_size_compressed=total_compressed,
            encrypted_files=encrypted_files,
            executable_files=executable_files,
            nested_archives=nested_archives,
            suspicious_files=suspicious_files,
            extracted_dir=extract_dir,
            entries=entries,
            is_suspicious=is_suspicious,
            suspicion_reasons=suspicion_reasons,
            summary=' | '.join(summary_parts)
        )
    
    def _detect_type(self, file_path: str) -> Optional[str]:
        """检测压缩包类型"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            for sig, (name, _) in self.ARCHIVE_SIGNATURES.items():
                if header.startswith(sig):
                    return name
        except:
            pass
        return None
    
    def _extract(self, file_path: str, extract_dir: str, atype: str,
                 budget: _ExtractBudget = None) -> List[ArchiveEntry]:
        """解压压缩包"""
        if atype == 'ZIP':
            return self._extract_zip(file_path, extract_dir, budget)
        elif atype in ('RAR', 'RAR5'):
            return self._extract_rar(file_path, extract_dir, budget)
        elif atype == '7z':
            return self._extract_7z(file_path, extract_dir, budget)
        elif atype in ('GZIP', 'BZIP2', 'XZ', 'TAR'):
            return self._extract_tar(file_path, extract_dir, atype, budget)
        return []

    def _extract_recursive(self, file_path: str, extract_dir: str, atype: str,
                           depth: int, budget: _ExtractBudget) -> List[ArchiveEntry]:
        """递归解压嵌套压缩包 — 子条目文件名统一加 _nested_<depth>_<index>/ 前缀"""
        max_depth = 3
        entries = self._extract(file_path, extract_dir, atype, budget)
        expanded = 0
        index = 0
        for entry in list(entries):
            if not (entry.is_nested_archive and entry.extraction_status == 'ok'
                    and depth < max_depth):
                continue
            nested_path = self.resolve_entry(extract_dir, entry.filename)
            if not nested_path or not os.path.isfile(nested_path):
                continue
            nested_type = self._detect_type(nested_path)
            if not nested_type:
                continue
            subdir = os.path.join(extract_dir, f'_nested_{depth}_{index}')
            os.makedirs(subdir, exist_ok=True)
            nested_index = index
            index += 1
            child_entries = self._extract_recursive(nested_path, subdir, nested_type,
                                                    depth + 1, budget)
            prefix = f'_nested_{depth}_{nested_index}/'
            for child in child_entries:
                child.filename = prefix + child.filename
            entries.extend(child_entries)
            expanded += 1
        if expanded:
            logger.info(f"[Archive] 展开嵌套压缩包 {expanded} 个")
        return entries
    
    def _extract_7z(self, file_path: str, extract_dir: str,
                    budget: _ExtractBudget = None) -> List[ArchiveEntry]:
        if not py7zr:
            logger.warning("py7zr 未安装，跳过 7z 解压")
            return []
        entries = []
        password = self._try_7z_password(file_path)
        try:
            with py7zr.SevenZipFile(file_path, 'r', password=password) as szf:
                all_info = szf.list() or []
                file_infos = [info for info in all_info
                              if getattr(info, 'filename', '')
                              and not getattr(info, 'is_directory', False)]
                unsafe_names = [getattr(info, 'filename', '') for info in all_info
                                if getattr(info, 'filename', '')
                                and not self._is_safe_member_name(getattr(info, 'filename', ''))]
                size_limited = False
                if unsafe_names:
                    logger.warning(f"[Archive] 7z 含不安全成员名, 跳过整体解压: {unsafe_names[:5]}")
                elif budget is not None and file_infos:
                    # 逐文件 reserve: 旧实现只 reserve 总字节数, 文件数限制被绕过
                    # (10 万个 1KB 文件同样会一次 extractall)
                    if len(file_infos) > MAX_EXTRACT_FILES - budget.file_count:
                        size_limited = True
                        logger.warning(f"[Archive] 7z 文件数超限 ({len(file_infos)}), 跳过整体解压")
                    else:
                        for info in file_infos:
                            if not budget.reserve(getattr(info, 'uncompressed', 0) or 0):
                                size_limited = True
                                logger.warning(
                                    f"[Archive] 7z 解压预算超限, 跳过整体解压 ({budget.skipped_reason()})")
                                break
                        if not size_limited:
                            szf.extractall(extract_dir)
                else:
                    szf.extractall(extract_dir)
                for info in file_infos:
                    fname = getattr(info, 'filename', '')
                    ext = os.path.splitext(fname)[1].lower()
                    if fname in unsafe_names:
                        status = 'path_unsafe'
                    elif unsafe_names:
                        status = 'skipped_unsafe_archive'
                    elif size_limited:
                        status = 'size_limit_skipped'
                    else:
                        status = 'ok'
                    entries.append(ArchiveEntry(
                        filename=fname,
                        size_original=getattr(info, 'uncompressed', 0) or 0,
                        size_compressed=getattr(info, 'compressed', 0) or 0,
                        file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                        is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                        is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                        extraction_status=status,
                    ))
                if password:
                    self._password_found = password
                    logger.info(f"[Archive] 7z加密破解成功! 密码: {password}")
        except Exception as e:
            logger.warning(f"[Archive] 7z解压失败: {e}")
        return entries

    def _try_7z_password(self, file_path: str) -> Optional[str]:
        """尝试用字典破解7z密码，返回成功密码或None

        ⚠ 必须让 py7zr 读取完整文件: 7z 的加密 Header 默认写在文件末尾, 只读前 64KB
        时 py7zr 永远无法解析。直接传文件路径给 py7zr 自行 seek, 避免把整个文件
        读入内存 (历史版本整体 read() 最高 512MB, 存在 OOM 风险)。
        """
        try:
            # 过大文件仅作性能保护, 跳过字典破解 (不再整体读入内存)
            size = os.path.getsize(file_path)
            if size > 512 * 1024 * 1024:
                logger.warning(f"[Archive] 7z 文件过大({size//1024//1024}MB), 跳过密码破解")
                return None
            # 确认确实需要密码 — 未加密的7z用密码参数也能打开, 会误报"破解成功"
            try:
                with py7zr.SevenZipFile(file_path, 'r') as szf:
                    szf.list()
                    return None  # 无需密码即可列出, 非加密包
            except py7zr.exceptions.PasswordRequired:
                pass  # 确实加密, 进入字典破解
            except Exception:
                return None
        except Exception:
            return None

        for pw in self._password_candidates():
            try:
                self._attempts.append(pw)
                with py7zr.SevenZipFile(file_path, 'r', password=pw) as szf:
                    szf.list()
                    return pw
            except py7zr.exceptions.PasswordRequired:
                continue
            except Exception:
                continue
        logger.info(f"[Archive] 7z密码破解失败 (尝试了 {len(self._attempts)} 个密码)")
        return None

    def _try_zip_password(self, file_path: str) -> Optional[str]:
        """尝试用字典破解ZIP密码（仅当条目真正加密时才尝试）

        支持两种加密:
          - 传统 zipcrypto: zipfile 原生支持
          - AES-256 (WinRAR/7-Zip): zipfile 不支持 → 用 pyzipper
        """
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                # 只找真正加密的条目(flag_bits & 0x1) — 未加密zip用pwd读取也会成功,
                # 历史版本因此把未加密zip误报为"密码已破解"
                test_file = None
                has_aes = False
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        test_file = info.filename
                        if self._is_aes_zip(info):
                            has_aes = True
                        break
                if not test_file:
                    return None
                # AES 加密 → pyzipper 破解
                if has_aes:
                    return self._try_zip_password_pyzipper(file_path, test_file)
                for pw in self._password_candidates():
                    self._attempts.append(pw)
                    try:
                        zf.read(test_file, pwd=pw.encode('utf-8') if isinstance(pw, str) else pw)
                        return pw
                    except RuntimeError:
                        continue
                    except zipfile.BadZipFile:
                        return None
                    except Exception:
                        continue
        except Exception:
            pass
        return None

    def _try_zip_password_pyzipper(self, file_path: str, test_file: str) -> Optional[str]:
        """用 pyzipper 破解 AES-256 加密 ZIP 密码"""
        try:
            import pyzipper
        except ImportError:
            logger.warning("[Archive] AES zip 需要 pyzipper 支持 (未安装), 跳过破解")
            return None
        try:
            for pw in self._password_candidates():
                self._attempts.append(pw)
                try:
                    with pyzipper.AESZipFile(file_path, 'r') as zf:
                        zf.read(test_file, pwd=pw.encode('utf-8') if isinstance(pw, str) else pw)
                        return pw
                except RuntimeError:
                    continue
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def _try_rar_password(self, file_path: str) -> Optional[str]:
        """尝试用字典破解RAR密码（仅当文件真正需要密码时）"""
        if not rarfile:
            return None
        try:
            # 环境检查: 需要 unrar/WinRAR 工具 (打包环境常缺失)
            try:
                rarfile.tool_setup()
            except Exception:
                logger.warning("[Archive] RAR 需要 unrar/WinRAR 工具支持 (当前环境缺失), 跳过 RAR 密码破解")
                return None
            with rarfile.RarFile(file_path, 'r') as rf:
                # rarfile 未加密时 testrar(pw=...) 也会成功, 必须先检测
                if not rf.needs_password():
                    return None
                for pw in self._password_candidates():
                    self._attempts.append(pw)
                    try:
                        rf.testrar(pw=pw)
                        return pw
                    except rarfile.RarWrongPassword:
                        continue
                    except Exception:
                        continue
        except Exception:
            pass
        return None

    def _extract_zip(self, file_path: str, extract_dir: str,
                     budget: _ExtractBudget = None) -> List[ArchiveEntry]:
        entries = []
        password = self._try_zip_password(file_path)
        pwd_bytes = password.encode('utf-8') if password else None
        # 预检测是否存在 AES 条目 — 若存在且密码已破解, 用 pyzipper 提取
        has_aes = False
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                has_aes = any(self._is_aes_zip(info) for info in zf.infolist())
        except Exception:
            pass
        try:
            # AES 包 + 密码已破解 → pyzipper 提取 (zipfile 无法解 AES)
            if has_aes and password:
                return self._extract_zip_pyzipper(file_path, extract_dir, password, pwd_bytes, budget)
            with zipfile.ZipFile(file_path, 'r') as zf:
                for info in zf.infolist():
                    if info.filename.endswith('/'):
                        continue
                    if not self._is_safe_member_name(info.filename):
                        logger.warning(f"[Archive] ZIP 不安全成员名, 跳过解压: {info.filename}")
                        ext = os.path.splitext(info.filename)[1].lower()
                        entries.append(ArchiveEntry(
                            filename=info.filename,
                            size_original=info.file_size,
                            size_compressed=info.compress_size,
                            crc32=f'{info.CRC:08X}',
                            is_encrypted=bool(info.flag_bits & 0x1),
                            file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                            is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                            extraction_status='path_unsafe',
                        ))
                        continue
                    ext = os.path.splitext(info.filename)[1].lower()
                    is_encrypted = bool(info.flag_bits & 0x1)
                    is_aes = self._is_aes_zip(info)
                    extracted_ok = False
                    size_limited = False
                    if not is_encrypted:
                        if budget is not None and not budget.reserve(info.file_size):
                            size_limited = True
                        else:
                            try:
                                zf.extract(info, extract_dir)
                                extracted_ok = True
                            except Exception:
                                pass
                    elif password and not is_aes:
                        if budget is not None and not budget.reserve(info.file_size):
                            size_limited = True
                        else:
                            try:
                                zf.extract(info, extract_dir, pwd=pwd_bytes)
                                extracted_ok = True
                            except Exception:
                                pass
                    elif is_aes and not password:
                        logger.warning(f"[Archive] ZIP条目AES加密, 密码未破解: {info.filename}")
                    if size_limited:
                        logger.warning(f"[Archive] ZIP 解压预算超限, 跳过: {info.filename} "
                                       f"({budget.skipped_reason()})")
                        entries.append(ArchiveEntry(
                            filename=info.filename,
                            size_original=info.file_size,
                            size_compressed=info.compress_size,
                            crc32=f'{info.CRC:08X}',
                            is_encrypted=is_encrypted,
                            compression_ratio=round(info.file_size / info.compress_size, 1) if info.compress_size > 0 else 1.0,
                            file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                            is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                            is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                            extraction_status='size_limit_skipped',
                        ))
                        continue
                    # 加密但密码未破解/AES: 文件没解出来, 不产生空文件污染分析
                    if not extracted_ok and (is_encrypted or is_aes):
                        entries.append(ArchiveEntry(
                            filename=info.filename,
                            size_original=info.file_size,
                            size_compressed=info.compress_size,
                            crc32=f'{info.CRC:08X}',
                            is_encrypted=True,
                            compression_ratio=round(info.file_size / info.compress_size, 1) if info.compress_size > 0 else 1.0,
                            file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                            is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                            is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                            extraction_status='encrypted_failed' if is_aes else 'password_missing',
                        ))
                        continue
                    entries.append(ArchiveEntry(
                        filename=info.filename,
                        size_original=info.file_size,
                        size_compressed=info.compress_size,
                        crc32=f'{info.CRC:08X}',
                        is_encrypted=is_encrypted,
                        compression_ratio=round(info.file_size / info.compress_size, 1) if info.compress_size > 0 else 1.0,
                        file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                        is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                        is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                        extraction_status='ok' if extracted_ok else 'failed',
                    ))
            if password:
                self._password_found = password
                logger.info(f"[Archive] ZIP加密破解成功! 密码: {password}")
        except Exception as e:
            logger.warning(f"[Archive] ZIP解压失败: {e}")
        return entries

    def _extract_zip_pyzipper(self, file_path: str, extract_dir: str,
                              password: str, pwd_bytes: bytes,
                              budget: _ExtractBudget = None) -> List[ArchiveEntry]:
        """用 pyzipper 提取含 AES-256 加密条目的 ZIP (密码已破解)"""
        import pyzipper
        entries = []
        try:
            with pyzipper.AESZipFile(file_path, 'r') as zf:
                for info in zf.infolist():
                    if info.filename.endswith('/'):
                        continue
                    if not self._is_safe_member_name(info.filename):
                        logger.warning(f"[Archive] AES-ZIP 不安全成员名, 跳过解压: {info.filename}")
                        ext = os.path.splitext(info.filename)[1].lower()
                        entries.append(ArchiveEntry(
                            filename=info.filename,
                            size_original=info.file_size,
                            size_compressed=info.compress_size,
                            crc32=f'{info.CRC:08X}',
                            is_encrypted=True,
                            file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                            is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                            extraction_status='path_unsafe',
                        ))
                        continue
                    ext = os.path.splitext(info.filename)[1].lower()
                    is_encrypted = bool(info.flag_bits & 0x1)
                    extracted_ok = False
                    if budget is not None and not budget.reserve(info.file_size):
                        logger.warning(f"[Archive] AES-ZIP 解压预算超限, 跳过: {info.filename} "
                                       f"({budget.skipped_reason()})")
                        entries.append(ArchiveEntry(
                            filename=info.filename,
                            size_original=info.file_size,
                            size_compressed=info.compress_size,
                            crc32=f'{info.CRC:08X}',
                            is_encrypted=is_encrypted,
                            compression_ratio=round(info.file_size / info.compress_size, 1) if info.compress_size > 0 else 1.0,
                            file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                            is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                            is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                            extraction_status='size_limit_skipped',
                        ))
                        continue
                    try:
                        zf.extract(info, extract_dir, pwd=pwd_bytes)
                        extracted_ok = True
                    except Exception:
                        pass
                    entries.append(ArchiveEntry(
                        filename=info.filename,
                        size_original=info.file_size,
                        size_compressed=info.compress_size,
                        crc32=f'{info.CRC:08X}',
                        is_encrypted=is_encrypted,
                        compression_ratio=round(info.file_size / info.compress_size, 1) if info.compress_size > 0 else 1.0,
                        file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                        is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                        is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                        extraction_status='ok' if extracted_ok else 'failed',
                    ))
            self._password_found = password
            logger.info(f"[Archive] AES-ZIP加密破解成功! 密码: {password}")
        except Exception as e:
            logger.warning(f"[Archive] AES-ZIP解压失败: {e}")
        return entries

    @staticmethod
    def _is_aes_zip(info) -> bool:
        """检测 ZIP 条目是否为 AES 加密 (extra field 0x9901 — WinRAR/7-Zip 的 AES-256)"""
        try:
            if not getattr(info, 'extra', None):
                return False
            extra = info.extra
            pos = 0
            while pos + 4 <= len(extra):
                hdr_id = int.from_bytes(extra[pos:pos+2], 'little')
                hdr_size = int.from_bytes(extra[pos+2:pos+4], 'little')
                if hdr_id == 0x9901:
                    return True
                pos += 4 + hdr_size
        except Exception:
            pass
        return False

    def _extract_rar(self, file_path: str, extract_dir: str,
                     budget: _ExtractBudget = None) -> List[ArchiveEntry]:
        if not rarfile:
            logger.warning("rarfile 未安装，跳过 RAR 解压")
            return []
        entries = []
        password = self._try_rar_password(file_path)
        try:
            with rarfile.RarFile(file_path, 'r') as rf:
                if password:
                    rf.setpassword(password)
                for info in rf.infolist():
                    if info.isdir():
                        continue
                    if not self._is_safe_member_name(info.filename):
                        logger.warning(f"[Archive] RAR 不安全成员名, 跳过解压: {info.filename}")
                        ext = os.path.splitext(info.filename)[1].lower()
                        entries.append(ArchiveEntry(
                            filename=info.filename,
                            size_original=info.file_size,
                            size_compressed=info.compress_size,
                            is_encrypted=bool(info.flags & 0x4) if hasattr(info, 'flags') else False,
                            file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                            is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                            is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                            extraction_status='path_unsafe',
                        ))
                        continue
                    ext = os.path.splitext(info.filename)[1].lower()
                    is_encrypted = bool(info.flags & 0x4) if hasattr(info, 'flags') else False
                    extracted_ok = False
                    if budget is not None and not budget.reserve(info.file_size):
                        logger.warning(f"[Archive] RAR 解压预算超限, 跳过: {info.filename} "
                                       f"({budget.skipped_reason()})")
                        entries.append(ArchiveEntry(
                            filename=info.filename,
                            size_original=info.file_size,
                            size_compressed=info.compress_size,
                            is_encrypted=is_encrypted,
                            file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                            is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                            is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                            extraction_status='size_limit_skipped',
                        ))
                        continue
                    try:
                        rf.extract(info, extract_dir)
                        extracted_ok = True
                    except Exception:
                        pass
                    entries.append(ArchiveEntry(
                        filename=info.filename,
                        size_original=info.file_size,
                        size_compressed=info.compress_size,
                        is_encrypted=is_encrypted,
                        file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                        is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                        is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                        extraction_status='ok' if extracted_ok else 'failed',
                    ))
            if password:
                self._password_found = password
                logger.info(f"[Archive] RAR加密破解成功! 密码: {password}")
        except Exception as e:
            logger.warning(f"[Archive] RAR解压失败: {e}")
        return entries
    
    def _extract_tar(self, file_path: str, extract_dir: str, atype: str,
                     budget: _ExtractBudget = None) -> List[ArchiveEntry]:
        mode = 'r'
        if atype == 'GZIP':
            mode = 'r:gz'
        elif atype == 'BZIP2':
            mode = 'r:bz2'
        elif atype == 'XZ':
            mode = 'r:xz'
        
        entries = []
        with tarfile.open(file_path, mode) as tf:
            for info in tf.getmembers():
                if info.isdir():
                    continue
                ext = os.path.splitext(info.name)[1].lower()
                if not self._is_safe_member_name(info.name):
                    logger.warning(f"[Archive] TAR 不安全成员名, 跳过解压: {info.name}")
                    entries.append(ArchiveEntry(
                        filename=info.name,
                        size_original=info.size,
                        size_compressed=info.size,
                        file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                        is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                        is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                        extraction_status='path_unsafe'
                    ))
                    continue
                if info.issym() or info.islnk():
                    logger.warning(f"[Archive] TAR 链接成员跳过解压 (防链接逃逸): {info.name}")
                    entries.append(ArchiveEntry(
                        filename=info.name,
                        size_original=info.size,
                        size_compressed=info.size,
                        file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                        is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                        is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                        extraction_status='skipped_link'
                    ))
                    continue
                extracted_ok = False
                if budget is not None and not budget.reserve(info.size):
                    logger.warning(f"[Archive] TAR 解压预算超限, 跳过: {info.name} "
                                   f"({budget.skipped_reason()})")
                    entries.append(ArchiveEntry(
                        filename=info.name,
                        size_original=info.size,
                        size_compressed=info.size,
                        file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                        is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                        is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                        extraction_status='size_limit_skipped'
                    ))
                    continue
                try:
                    # Python 3.12+: filter='data' 拒绝绝对路径/链接等危险成员
                    tf.extract(info, extract_dir, numeric_owner=True, filter='data')
                    extracted_ok = True
                except TypeError:
                    # 旧版 Python 无 filter 参数 — 上面已自行校验成员名并排除链接
                    try:
                        tf.extract(info, extract_dir, numeric_owner=True)
                        extracted_ok = True
                    except Exception:
                        pass
                except Exception:
                    pass
                entries.append(ArchiveEntry(
                    filename=info.name,
                    size_original=info.size,
                    size_compressed=info.size,
                    file_type=ext.replace('.', '').upper() if ext else 'Unknown',
                    is_executable=ext in self.SUSPICIOUS_EXTENSIONS,
                    is_nested_archive=ext in ('.zip', '.rar', '.7z', '.tar', '.gz'),
                    extraction_status='ok' if extracted_ok else 'failed'
                ))
        return entries
