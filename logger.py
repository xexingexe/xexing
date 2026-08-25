#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一日志系统 — 支持控制台 + 文件双输出，支持分级和颜色
"""
import logging
import logging.handlers
import os
import sys
import threading
from pathlib import Path
from typing import Optional

# 颜色码（仅 Windows 控制台）
try:
    import ctypes
    _kernel32 = ctypes.windll.kernel32
    _stdout_handle = _kernel32.GetStdHandle(-11)
    _mode = ctypes.c_uint32()
    if _kernel32.GetConsoleMode(_stdout_handle, ctypes.byref(_mode)):
        _kernel32.SetConsoleMode(_stdout_handle, _mode.value | 0x0004)
except:
    pass

_COLORS = {
    'DEBUG': '\033[36m',      # 青色
    'INFO': '\033[32m',       # 绿色
    'WARNING': '\033[33m',    # 黄色
    'ERROR': '\033[31m',      # 红色
    'CRITICAL': '\033[35m',   # 紫色
    'RESET': '\033[0m',
}


class ColoredFormatter(logging.Formatter):
    """带颜色的格式化器"""
    
    def __init__(self, fmt: str, use_color: bool = True):
        super().__init__(fmt)
        self.use_color = use_color
    
    def format(self, record: logging.LogRecord) -> str:
        if self.use_color and record.levelname in _COLORS:
            record = logging.makeLogRecord(record.__dict__)
            record.levelname = f"{_COLORS[record.levelname]}{record.levelname}{_COLORS['RESET']}"
        return super().format(record)


class LogQueueHandler(logging.Handler):
    """用于 GUI 的日志队列处理器"""
    
    def __init__(self, queue):
        super().__init__()
        self.queue = queue
        self.setLevel(logging.DEBUG)
    
    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            self.queue.put(msg)
        except:
            pass


class LoggerManager:
    """日志管理器 — 单例模式"""
    
    _instance: Optional['LoggerManager'] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._logger = logging.getLogger('malware_sandbox')
        self._logger.setLevel(logging.DEBUG)
        self._handlers = []
        self._gui_queue = None
        self._initialized_handlers = False
    
    def setup(self, 
              log_dir: str = 'logs',
              log_level: str = 'INFO',
              console_level: str = 'INFO',
              file_level: str = 'DEBUG',
              max_bytes: int = 10 * 1024 * 1024,  # 10MB
              backup_count: int = 5,
              use_color: bool = True,
              gui_queue=None):
        """
        初始化日志系统
        
        Args:
            log_dir: 日志目录
            log_level: 全局日志级别
            console_level: 控制台日志级别
            file_level: 文件日志级别
            max_bytes: 单个日志文件最大大小
            backup_count: 保留的备份数量
            use_color: 控制台是否使用颜色
            gui_queue: GUI 日志队列（用于实时显示）
        """
        # 允许 GUI 在初始化后附加日志队列
        if self._initialized_handlers:
            if gui_queue is not None and self._gui_queue is None:
                self._gui_queue = gui_queue
                gui_handler = LogQueueHandler(gui_queue)
                gui_handler.setLevel(logging.DEBUG)
                gui_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
                self._logger.addHandler(gui_handler)
                self._handlers.append(gui_handler)
            return
        
        self._logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        self._gui_queue = gui_queue
        
        # 1. 控制台处理器 — Windows 下不包装 stdout 避免关闭时损坏 buffer
        if sys.stdout is None:
            console_target = sys.__stdout__ if sys.__stdout__ is not None else open(os.devnull, 'w')
        else:
            console_target = sys.stdout
            if sys.platform == 'win32' and hasattr(console_target, 'reconfigure'):
                console_target.reconfigure(encoding='utf-8', errors='replace')
        console_handler = logging.StreamHandler(console_target)
        console_handler.setLevel(getattr(logging, console_level.upper(), logging.INFO))
        console_fmt = '%(asctime)s [%(levelname)s] %(message)s'
        console_handler.setFormatter(ColoredFormatter(console_fmt, use_color=use_color))
        self._logger.addHandler(console_handler)
        self._handlers.append(console_handler)
        
        # 2. 文件处理器（按天轮转）
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        
        # 主日志文件
        file_handler = logging.handlers.RotatingFileHandler(
            log_path / 'sandbox.log',
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(getattr(logging, file_level.upper(), logging.DEBUG))
        file_fmt = '%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s'
        file_handler.setFormatter(logging.Formatter(file_fmt))
        self._logger.addHandler(file_handler)
        self._handlers.append(file_handler)
        
        # 错误日志（单独文件）
        error_handler = logging.handlers.RotatingFileHandler(
            log_path / 'error.log',
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(logging.Formatter(file_fmt))
        self._logger.addHandler(error_handler)
        self._handlers.append(error_handler)
        
        # 3. GUI 队列处理器（如果提供）
        if gui_queue is not None:
            gui_handler = LogQueueHandler(gui_queue)
            gui_handler.setLevel(logging.DEBUG)
            gui_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
            self._logger.addHandler(gui_handler)
            self._handlers.append(gui_handler)
        
        self._initialized_handlers = True
        self._logger.info("=" * 60)
        self._logger.info("日志系统初始化完成")
        self._logger.info("=" * 60)
    
    def set_level(self, level: str):
        """设置日志级别"""
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    @property
    def logger(self) -> logging.Logger:
        return self._logger
    
    def get_logger(self, name: str) -> logging.Logger:
        """获取子 logger"""
        return self._logger.getChild(name)


# 便捷访问
def get_logger(name: Optional[str] = None) -> logging.Logger:
    """获取 logger 实例"""
    manager = LoggerManager()
    if name:
        return manager.get_logger(name)
    return manager.logger


