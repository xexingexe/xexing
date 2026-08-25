#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
静态分析引擎 — 文件信息、哈希、熵值、魔数检测
"""
import os
from datetime import datetime
from typing import Tuple

from config import CONFIG
from logger import get_logger
from utils.helpers import (
    format_size, calc_entropy, calc_entropy_file, compute_hashes_file,
    detect_file_type_file, safe_read_file
)
from analyzer.models import FileInfo

logger = get_logger('analyzer.static')


class StaticAnalyzer:
    """静态分析引擎"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self._file_size = os.path.getsize(file_path)
        logger.info(f"初始化静态分析: {file_path} ({format_size(self._file_size)})")
    
    def analyze(self) -> FileInfo:
        """执行完整静态分析"""
        logger.info("[1/3] 计算文件哈希...")
        hashes = self._compute_hashes()
        
        logger.info("[2/3] 计算文件熵值...")
        entropy = self._compute_entropy()
        
        logger.info("[3/3] 检测文件类型...")
        file_type, mime_type = self._detect_file_type()
        
        # 获取时间戳
        stat = os.stat(self.file_path)
        created = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        accessed = datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')
        
        entropy_level = 'low' if entropy < 4 else 'normal' if entropy < 6 else 'high' if entropy < 7 else 'suspicious'
        
        return FileInfo(
            path=self.file_path,
            name=os.path.basename(self.file_path),
            size=self._file_size,
            size_human=format_size(self._file_size),
            file_type=file_type,
            mime_type=mime_type,
            md5=hashes['md5'],
            sha1=hashes['sha1'],
            sha256=hashes['sha256'],
            sha512=hashes['sha512'],
            entropy=entropy,
            entropy_level=entropy_level,
            created_time=created,
            modified_time=modified,
            access_time=accessed
        )
    
    def _compute_hashes(self) -> dict:
        """计算文件哈希"""
        try:
            return compute_hashes_file(self.file_path, chunk_size=CONFIG.chunk_size)
        except Exception as e:
            logger.error(f"哈希计算失败: {e}")
            return {'md5': '', 'sha1': '', 'sha256': '', 'sha512': ''}
    
    def _compute_entropy(self) -> float:
        """计算文件熵值"""
        try:
            if self._file_size > 10 * 1024 * 1024:  # >10MB 用流式
                return calc_entropy_file(self.file_path, chunk_size=CONFIG.chunk_size)
            else:
                data = safe_read_file(self.file_path, max_size=CONFIG.max_file_size)
                return calc_entropy(data)
        except Exception as e:
            logger.error(f"熵值计算失败: {e}")
            return 0.0
    
    def _detect_file_type(self) -> Tuple[str, str]:
        """检测文件类型"""
        try:
            return detect_file_type_file(self.file_path)
        except Exception as e:
            logger.error(f"文件类型检测失败: {e}")
            return 'Unknown', 'application/octet-stream'
