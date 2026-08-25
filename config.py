#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理模块 — 支持 JSON/YAML 配置文件、环境变量覆盖
"""
import os
import sys
import json
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field, asdict

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 尝试导入 yaml
yaml = None
try:
    import yaml
except ImportError:
    pass


def _ensure_backports_zstd_stub():
    """exe 打包环境兼容: backports.zstd 命名空间包收集冲突导致 py7zr 导入失败

    注入 stub 绕过 (zstd 压缩方法不可用, 普通 7z/LZMA 正常; 已用 DepProbe 验证)。
    必须在任何 import py7zr 之前全局生效 (dep_checker/archive 都依赖)。
    """
    try:
        import sys as _sys
        if 'backports.zstd' in _sys.modules and _sys.modules['backports.zstd'] is not None:
            return
        import types as _types
        _stub = _types.ModuleType('backports.zstd')
        _stub.ZstdCompressor = None
        _stub.ZstdDecompressor = None
        _stub.ZstdError = Exception
        _stub.zstd_version_info = (0, 0, 0)
        _stub.zstd_license = ''
        _stub.ZstdDict = type('ZstdDict', (), {})
        _sys.modules['backports.zstd'] = _stub
        try:
            import backports as _bp
            _bp.zstd = _stub
        except Exception:
            pass
    except Exception:
        pass


_ensure_backports_zstd_stub()


@dataclass
class SandboxConfig:
    """沙箱配置"""
    enabled: bool = True
    timeout: int = 300  # 5分钟，GUI应用需要更长时间交互
    memory_limit_mb: int = 512
    process_limit: int = 20
    cpu_limit_sec: int = 0
    log_all_files: bool = True
    child_wait_timeout: int = 300  # 主进程退出后继续追踪子进程(含内存马)的最长时间
    analysis_total_timeout: int = 600  # 动态分析总时限(主进程+子进程)，超过强制结束
    frida_attach_timeout: int = 30  # Frida attach 超时，反调试样本可调大
    full_registry_snapshot: bool = False  # 全量注册表快照 (键名级, 覆盖白名单外位置; ⚠ 慢 40-60s, 默认关闭)
    restart_watch_timeout: int = 15  # 样本退出后重启观察窗(秒): 拦截"先退出再重启"逃逸的延迟拉起进程
    fake_user_env: bool = True  # 动态分析时创建虚假用户环境痕迹；物理机测试建议关闭
    # 反沙箱环境模拟: 样本要求"进程数≥10 / 内存≥2GB / 分辨率≥800 / 运行时长≥300s / CPU≥2 / 用户名不在黑名单"
    env_min_processes: int = 10       # 进程数下限 (不足时由 fake_user_env 拉起无害填充进程)
    env_fake_username: str = 'zhangwei'  # Frida 伪造的用户名 (规避 sandbox/malware/virus/sample/analysis/analyst 黑名单)


@dataclass
class MemoryConfig:
    """内存分析配置"""
    enabled: bool = True
    dump_enabled: bool = True
    dump_max_size: int = 100 * 1024 * 1024  # 100MB
    dump_dir: str = 'memory_dumps'
    analyze_rwx: bool = True
    detect_shellcode: bool = True
    detect_pe_injection: bool = True


@dataclass
class DeepDiveConfig:
    """深度追踪分析 (DeepDive) 配置"""
    auto_enabled: bool = True        # 动态分析完成后自动执行轻量深度追踪 (无需 --deep-dive)
    watch_enabled: bool = True        # 动态分析结束后启动长时观察窗
    watch_timeout: int = 60           # 观察窗时长(秒) — 慢速样本后续行为捕获 (默认180s太长, 拖慢后分析)
    watch_interval: int = 5           # 观察轮询间隔(秒)
    max_watch_files: int = 20         # 观察窗内新增文件深析上限
    max_watch_processes: int = 15     # 观察窗内新增进程上限


@dataclass
class ScreenshotConfig:
    """执行期桌面截图配置 (CAPE/微步同款能力, 默认关闭 — VM 内样本常隐藏窗口)"""
    enabled: bool = False
    interval: int = 30                # 截图间隔(秒)
    max_count: int = 6                # 最多截取张数
    dir: str = 'screenshots'


@dataclass
class URLScanConfig:
    """URL 扫描配置 (挂马检测 / 网页代码分析 / 命令执行检测 / 行为监控)"""
    enabled: bool = True
    timeout: int = 15                 # 单请求超时(秒)
    max_redirects: int = 5            # 最多跟随跳转次数
    max_body_size: int = 2 * 1024 * 1024   # 网页正文读取上限(2MB)
    fetch_external_scripts: bool = True    # 抓取页面引用的外部 JS 并分析
    max_external_scripts: int = 5          # 最多抓取多少个外部脚本
    scan_discovered_urls: bool = True      # 文件分析时自动扫描样本中发现的 URL (最多 max_discovered)
    max_discovered_urls: int = 3           # 样本中发现 URL 的扫描上限
    ignore_https_errors: bool = True       # 忽略 SSL 证书错误 (病毒站常见自签证书)
    user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
    # ==== 动态行为监控 (浏览器沙箱, 需 playwright + 系统 Chrome) ====
    dynamic_analysis: bool = True          # 是否启用浏览器动态行为监控
    dynamic_timeout: int = 25              # 页面加载/行为监控总超时(秒)
    dynamic_wait: int = 4                  # 加载完成后再观察的秒数 (捕获延迟 JS 行为)
    max_resources: int = 40                # 最多分析多少个 JS/HTML 资源响应体
    max_download_size: int = 20 * 1024 * 1024  # 下载文件大小上限
    headless: bool = True                  # 无头模式
    use_system_chrome: bool = True         # 优先使用系统 Chrome (免下载浏览器内核)
    capture_screenshots: bool = True       # 截图
    job_memory_limit_mb: int = 1024        # 浏览器进程内存限制(Job Object) 0=不限
    # ==== 多浏览器 / 多线程 ====
    browser_engines: str = 'chrome'        # 逗号分隔: chrome,msedge,chromium,firefox,webkit 或 all
                                           # chrome/msedge 用系统浏览器; 其余需 playwright install 内核
    max_parallel: int = 3                  # 同时扫描的 URL 数上限 (每 URL 每引擎一个浏览器实例)


@dataclass
class CleanupConfig:
    """分析后自动生成杀毒清理脚本 (只生成, 绝不自动执行!)"""
    enabled: bool = False             # 分析完成后生成清理脚本
    output_dir: str = 'reports'       # 脚本输出目录
    enable_reboot_verify: bool = True # 脚本包含重启验证逻辑
    enable_pattern_scan: bool = True  # 随机名目录特征杀毒(银狐场景)
    auto_confirm: bool = False        # 脚本默认自动模式(无交互确认)


@dataclass
class NetworkConfig:
    """网络分析配置"""
    capture_enabled: bool = True
    capture_timeout: int = 300
    pcap_enabled: bool = True
    pcap_dir: str = 'pcaps'
    analyze_dns: bool = True
    analyze_http: bool = True
    analyze_suspicious: bool = True
    # 可疑端口列表
    suspicious_ports: list = field(default_factory=lambda: [
        4444, 5555, 6666, 7777, 8888, 9999,  # 常见C2端口
        31337, 12345, 54321,  # 经典后门端口
        8080, 1080, 3128,  # 代理端口
    ])
    # 可疑域名模式
    suspicious_tlds: list = field(default_factory=lambda: [
        '.tk', '.ml', '.ga', '.cf', '.gq',  # 免费域名
    ])


@dataclass
class APIKeyConfig:
    """API 密钥配置"""
    virustotal: str = ''
    threatbook: str = ''
    _360: str = ''  # 360云查
    hybrid_analysis: str = ''
    malware_bazaar: str = ''


@dataclass
class ReportConfig:
    """报告配置"""
    output_dir: str = 'reports'
    max_keep_reports: int = 100  # 0 = 禁用报告数量清理
    html_enabled: bool = True
    json_enabled: bool = True
    pdf_enabled: bool = False
    template_dir: str = 'templates'
    include_raw_data: bool = False
    evidence_pack: bool = True  # 报告附加证据包 (PCAP/截图/日志等)


@dataclass
class DetectionConfig:
    """检测规则配置"""
    # 加壳检测
    packer_sections: list = field(default_factory=lambda: [
        '.upx', '.vmp', '.vmp0', '.vmp1', '.themida', '.enigma',
        '.petite', '.aspack', '.aspr', '.sg0', '.svkp',
    ])
    # 可疑节区名模式
    suspicious_section_patterns: list = field(default_factory=lambda: [
        r'^\.[a-z]{1,3}$',  # 极短节区名
        r'[^\x20-\x7e]',     # 非ASCII字符
    ])
    # 反调试 API
    anti_debug_apis: list = field(default_factory=lambda: [
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'NtQueryInformationProcess', 'NtSetInformationThread',
        'OutputDebugString', 'FindWindow', 'GetTickCount',
        'NtQuerySystemInformation', 'NtCreateThreadEx',
    ])
    # 持久化路径
    persistence_paths: list = field(default_factory=lambda: [
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\SYSTEM\CurrentControlSet\Services',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
        r'HKCU\Environment',  # 用户环境变量持久化
        r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    ])
    # 恶意软件家族签名
    family_signatures: dict = field(default_factory=dict)


@dataclass
class AppConfig:
    """全局应用配置"""
    # 基础配置
    debug: bool = False
    verbose: bool = False
    threads: int = 4
    max_file_size: int = 500 * 1024 * 1024  # 500MB
    chunk_size: int = 4 * 1024 * 1024  # 4MB
    
    # 子配置
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    api_keys: APIKeyConfig = field(default_factory=APIKeyConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    deep_dive: DeepDiveConfig = field(default_factory=DeepDiveConfig)
    screenshots: ScreenshotConfig = field(default_factory=ScreenshotConfig)
    url_scan: URLScanConfig = field(default_factory=URLScanConfig)
    cleanup: CleanupConfig = field(default_factory=CleanupConfig)
    
    # 路径配置
    rules_path: str = 'rules'
    temp_dir: str = 'temp'
    
    # 沙箱注册表监控键
    registry_keys: list = field(default_factory=lambda: [
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKLM\SYSTEM\CurrentControlSet\Services',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer',
    ])


class ConfigManager:
    """配置管理器 — 支持文件、环境变量、默认值三级配置"""
    
    CONFIG_FILE_NAMES = ['config.json', 'config.yaml', 'config.yml', '.sandboxrc']
    
    def __init__(self):
        self._config = AppConfig()
        self._config_path: Optional[Path] = None
    
    def load(self, config_path: Optional[str] = None) -> AppConfig:
        """加载配置，优先级：指定路径 > 环境变量 > 默认"""
        # 1. 从文件加载
        if config_path:
            self._load_from_file(config_path)
        else:
            self._auto_discover_config()
        
        # 2. 环境变量覆盖
        self._load_from_env()
        
        # 3. 相对路径解析为项目根目录绝对路径
        self._resolve_paths()

        # 4. 命令行参数会在 main 中处理
        return self._config
    
    def _auto_discover_config(self):
        """自动发现配置文件"""
        base_dir = Path(__file__).parent
        for name in self.CONFIG_FILE_NAMES:
            path = base_dir / name
            if path.exists():
                self._load_from_file(str(path))
                return
        # 打包运行时: 允许 exe 同级目录的 config.json (GUI 设置保存位置, 用户可编辑)
        if getattr(sys, 'frozen', False):
            exe_dir = Path(sys.executable).parent
            for name in self.CONFIG_FILE_NAMES:
                path = exe_dir / name
                if path.exists():
                    self._load_from_file(str(path))
                    return
        # 检查用户目录
        home = Path.home()
        for name in self.CONFIG_FILE_NAMES:
            path = home / name
            if path.exists():
                self._load_from_file(str(path))
                return
    
    def _load_from_file(self, path: str):
        """从文件加载配置"""
        p = Path(path)
        if not p.exists():
            return
        
        self._config_path = p
        suffix = p.suffix.lower()
        
        try:
            with open(p, 'r', encoding='utf-8') as f:
                if suffix in ('.yaml', '.yml'):
                    if yaml is None:
                        raise ImportError("PyYAML 未安装，无法解析 YAML 配置")
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            
            if data:
                self._merge_dict(data)
                
        except Exception as e:
            print(f"[!] 配置文件加载失败: {e}")
    
    def _load_from_env(self):
        """从环境变量加载配置"""
        env_map = {
            'SANDBOX_VT_API_KEY': ('api_keys', 'virustotal'),
            'SANDBOX_THREATBOOK_KEY': ('api_keys', 'threatbook'),
            'SANDBOX_360_KEY': ('api_keys', '_360'),
            'SANDBOX_HYBRID_KEY': ('api_keys', 'hybrid_analysis'),
            'SANDBOX_MALBAZAAR_KEY': ('api_keys', 'malware_bazaar'),
            'SANDBOX_TIMEOUT': ('sandbox', 'timeout'),
            'SANDBOX_MEMORY_LIMIT': ('sandbox', 'memory_limit_mb'),
            'SANDBOX_THREADS': ('', 'threads'),
            'SANDBOX_DEBUG': ('', 'debug'),
        }
        
        for env_name, (section, key) in env_map.items():
            value = os.environ.get(env_name)
            if value is None:
                continue
            
            # 类型转换
            try:
                int_val = int(value)
                if section:
                    sub = getattr(self._config, section, None)
                    if sub:
                        field_type = type(getattr(sub, key, None))
                        if field_type is bool:
                            value = bool(int_val)
                        elif field_type is int:
                            value = int_val
                else:
                    field_type = type(getattr(self._config, key, None))
                    if field_type is bool:
                        value = bool(int_val)
                    elif field_type is int:
                        value = int_val
            except (ValueError, TypeError):
                if value.lower() in ('true', 'yes'):
                    value = True
                elif value.lower() in ('false', 'no'):
                    value = False
                else:
                    # 目标字段类型为 str 时保留原值（如 API Key、UA 等）
                    if section:
                        sub = getattr(self._config, section, None)
                        if sub and type(getattr(sub, key, None)) is str:
                            pass  # 保留原字符串值
                        else:
                            continue
                    else:
                        if type(getattr(self._config, key, None)) is str:
                            pass  # 保留原字符串值
                        else:
                            continue
            
            if section:
                sub = getattr(self._config, section, None)
                if sub:
                    setattr(sub, key, value)
            else:
                setattr(self._config, key, value)
    
    def _resolve_paths(self):
        """将相对路径字段解析为项目根目录(BASE_DIR)下的绝对路径"""
        section_fields = [
            ('report', 'output_dir'),
            ('memory', 'dump_dir'),
            ('screenshots', 'dir'),
            ('network', 'pcap_dir'),
            ('cleanup', 'output_dir'),
        ]
        for section, key in section_fields:
            sub = getattr(self._config, section, None)
            if sub is None:
                continue
            value = getattr(sub, key, '')
            if value and not os.path.isabs(value):
                setattr(sub, key, os.path.join(BASE_DIR, value))
        if self._config.temp_dir and not os.path.isabs(self._config.temp_dir):
            self._config.temp_dir = os.path.join(BASE_DIR, self._config.temp_dir)

    @staticmethod
    def _coerce_value(current, value):
        """按现有字段类型收敛配置值; 无法安全转换时返回 None (调用方跳过)"""
        t = type(current)
        if t is bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return bool(value)
            if isinstance(value, str):
                lv = value.strip().lower()
                if lv in ('true', 'yes', '1', 'on'):
                    return True
                if lv in ('false', 'no', '0', 'off'):
                    return False
            return None
        if t is int:
            try:
                return int(value)
            except (ValueError, TypeError):
                return None
        if t is float:
            try:
                return float(value)
            except (ValueError, TypeError):
                return None
        if t is str:
            if isinstance(value, (str, int, float, bool)):
                return str(value)
            return None
        if t is list:
            return list(value) if isinstance(value, list) else None
        if t is dict:
            return dict(value) if isinstance(value, dict) else None
        return value

    def _merge_dict(self, data: Dict[str, Any]):
        """将字典合并到配置对象（带类型校验，坏类型跳过并告警）"""
        for key, value in data.items():
            if hasattr(self._config, key):
                attr = getattr(self._config, key)
                if isinstance(attr, (SandboxConfig, MemoryConfig, NetworkConfig,
                                     APIKeyConfig, ReportConfig, DetectionConfig,
                                     URLScanConfig, DeepDiveConfig, ScreenshotConfig,
                                     CleanupConfig)):
                    # 递归合并子配置
                    if isinstance(value, dict):
                        for sub_key, sub_value in value.items():
                            if hasattr(attr, sub_key):
                                coerced = self._coerce_value(getattr(attr, sub_key), sub_value)
                                if coerced is not None:
                                    setattr(attr, sub_key, coerced)
                                else:
                                    print(f"[!] 配置项 {key}.{sub_key} 类型无效, 已忽略: {sub_value!r}")
                else:
                    coerced = self._coerce_value(attr, value)
                    if coerced is not None:
                        setattr(self._config, key, coerced)
                    else:
                        print(f"[!] 配置项 {key} 类型无效, 已忽略: {value!r}")
    
    def save_default(self, path: str = 'config.json'):
        """生成默认配置文件"""
        data = asdict(self._config)
        p = Path(path)
        suffix = p.suffix.lower()
        
        with open(p, 'w', encoding='utf-8') as f:
            if suffix in ('.yaml', '.yml'):
                if yaml:
                    yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
                else:
                    print("[!] PyYAML 未安装，已转为 JSON 格式保存")
                    json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"[+] 默认配置已保存: {p.absolute()}")
    
    @property
    def config(self) -> AppConfig:
        return self._config


# 全局配置实例
_config_manager = ConfigManager()
CONFIG: AppConfig = _config_manager.config


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """加载配置并返回"""
    global CONFIG
    CONFIG = _config_manager.load(config_path)
    return CONFIG


def save_default_config(path: str = 'config.json'):
    """保存默认配置文件"""
    _config_manager.save_default(path)
