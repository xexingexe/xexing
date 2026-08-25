#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""数据模型"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

@dataclass
class FileInfo:
    path: str
    name: str
    size: int
    size_human: str = ''
    file_type: str = 'Unknown'
    mime_type: str = 'application/octet-stream'
    md5: str = ''
    sha1: str = ''
    sha256: str = ''
    sha512: str = ''
    imphash: str = ''
    ssdeep: str = ''
    entropy: float = 0.0
    entropy_level: str = 'low'
    magic: str = ''
    created_time: str = ''
    modified_time: str = ''
    access_time: str = ''

@dataclass
class SectionInfo:
    name: str
    virtual_address: str
    virtual_size: int
    raw_size: int
    raw_offset: int
    entropy: float
    characteristics: str
    is_executable: bool = False
    is_writable: bool = False
    is_suspicious: bool = False
    suspicion_reason: str = ''

@dataclass
class ImportInfo:
    dll: str
    functions: List[str] = field(default_factory=list)
    suspicious_functions: List[str] = field(default_factory=list)

@dataclass
class ExportInfo:
    name: str
    ordinal: int = 0
    address: str = ''

@dataclass
class ResourceInfo:
    type: str
    name: str = ''
    language: int = 0
    size: int = 0
    offset: int = 0
    is_executable: bool = False

@dataclass
class PEInfo:
    is_pe: bool = False
    is_dll: bool = False
    is_exe: bool = False
    is_driver: bool = False
    is_dotnet: bool = False
    architecture: str = ''
    compile_time: str = ''
    entry_point: str = ''
    image_base: str = ''
    subsystem: str = ''
    sections: List[SectionInfo] = field(default_factory=list)
    imports: List[ImportInfo] = field(default_factory=list)
    exports: List[ExportInfo] = field(default_factory=list)
    resources: List[ResourceInfo] = field(default_factory=list)
    tls_callbacks: List[str] = field(default_factory=list)
    digital_signature: Dict = field(default_factory=dict)
    suspicious_features: List[str] = field(default_factory=list)
    packer_info: List[str] = field(default_factory=list)
    rich_header: Dict = field(default_factory=dict)
    overlay: Dict = field(default_factory=dict)
    imphash: str = ''
    compile_stamp: int = 0

@dataclass
class StringAnalysis:
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    api_calls: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    base64_strings: List[str] = field(default_factory=list)
    hex_strings: List[str] = field(default_factory=list)
    crypto_wallets: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)
    cmdline_patterns: List[str] = field(default_factory=list)
    powershell_patterns: List[str] = field(default_factory=list)
    total_strings: int = 0

@dataclass
class SandboxResult:
    sandbox_type: str = ''
    execution_time: float = 0.0
    exit_code: int = -1
    was_terminated: bool = False
    files_created: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    files_deleted: List[str] = field(default_factory=list)
    registry_created: List[str] = field(default_factory=list)
    registry_modified: List[str] = field(default_factory=list)
    registry_deleted: List[str] = field(default_factory=list)
    memory_peak_mb: float = 0.0
    cpu_peak_percent: float = 0.0
    child_process_count: int = 0
    child_processes: List[Dict] = field(default_factory=list)
    sandbox_dir: str = ''
    artifacts_dir: str = ''
    summary: str = ''
    crashed: bool = False
    crash_code: int = 0

@dataclass
class DynamicBehavior:
    processes_created: List[Dict] = field(default_factory=list)
    memory_snapshots: List[Dict] = field(default_factory=list)  # 即时内存PE快照
    processes_terminated: List[Dict] = field(default_factory=list)
    files_created: List[Any] = field(default_factory=list)  # str | dict (dict from FileSystemMonitor with cached meta)
    files_deleted: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    files_renamed: List[Dict] = field(default_factory=list)
    registry_modified: List[Dict] = field(default_factory=list)
    registry_created: List[str] = field(default_factory=list)
    registry_deleted: List[str] = field(default_factory=list)
    network_connections: List[Dict] = field(default_factory=list)
    dns_queries: List[Dict] = field(default_factory=list)
    api_calls: List[Dict] = field(default_factory=list)
    mutexes: List[str] = field(default_factory=list)
    services_created: List[Dict] = field(default_factory=list)
    services_deleted: List[str] = field(default_factory=list)
    scheduled_tasks: List[Dict] = field(default_factory=list)
    wmi_events: List[Dict] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    critical_process_events: List[Dict] = field(default_factory=list)  # BreakOnTermination 检测
    execution_time: float = 0.0
    sandbox_result: Optional[Any] = None
    _etw_registry_events: List[Dict] = field(default_factory=list)  # ETW 内核注册表写事件 (全量覆盖)
    _system_injections: List[Dict] = field(default_factory=list)  # 系统进程非系统模块 (跨进程 DLL 注入检测)

@dataclass
class NetworkConnection:
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    remote_host: str = ''
    status: str = ''
    is_suspicious: bool = False
    suspicion_reason: str = ''
    process_name: str = ''
    pid: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0

@dataclass
class TrafficDetail:
    remote: str = ''
    pid: int = 0
    process: str = ''
    bytes_sent: int = 0
    bytes_recv: int = 0
    intel_tag: str = ''

@dataclass
class DNSQuery:
    domain: str
    query_type: str = 'A'
    is_suspicious: bool = False
    suspicion_reason: str = ''
    resolved_ips: List[str] = field(default_factory=list)

@dataclass
class HTTPRequest:
    method: str
    host: str
    path: str
    user_agent: str = ''
    headers: Dict = field(default_factory=dict)
    is_suspicious: bool = False
    suspicion_reason: str = ''

@dataclass
class NetworkTraffic:
    total_packets: int = 0
    total_bytes: int = 0
    dns_queries: List[DNSQuery] = field(default_factory=list)
    http_requests: List[HTTPRequest] = field(default_factory=list)
    tcp_connections: List[NetworkConnection] = field(default_factory=list)
    udp_connections: List[NetworkConnection] = field(default_factory=list)
    suspicious_traffic: List[Dict] = field(default_factory=list)
    pcap_file: str = ''
    protocol_stats: Dict = field(default_factory=dict)
    geolocation: Dict = field(default_factory=dict)
    tor_nodes: List[str] = field(default_factory=list)
    proxy_connections: List[str] = field(default_factory=list)
    tls_fingerprints: List[Dict] = field(default_factory=list)  # JA3/JA3S/SNI
    dga_domains: List[str] = field(default_factory=list)         # DGA 可疑域名
    dns_tunnel_indicators: List[Dict] = field(default_factory=list)  # DNS 隧道特征

@dataclass
class MemoryRegion:
    base_address: str = ''
    region_size: int = 0
    region_size_human: str = ''
    state: str = ''
    protect: str = ''
    type: str = ''
    is_suspicious: bool = False
    suspicion_reason: str = ''
    has_code: bool = False
    has_data: bool = False

@dataclass
class MemoryAnalysis:
    pid: int = 0
    total_regions: int = 0
    suspicious_regions: List[MemoryRegion] = field(default_factory=list)
    rwx_regions: List[MemoryRegion] = field(default_factory=list)
    hollowed_regions: List[MemoryRegion] = field(default_factory=list)
    shellcode_found: bool = False
    shellcode_details: List[Dict] = field(default_factory=list)
    pe_in_memory: bool = False
    pe_injected_modules: List[Dict] = field(default_factory=list)
    unpacked_pe: bool = False
    unpacked_modules: List[Dict] = field(default_factory=list)
    openpgp_found: bool = False
    openpgp_details: List[Dict] = field(default_factory=list)
    zlib_found: bool = False
    zlib_details: List[Dict] = field(default_factory=list)
    multi_payload: List[Dict] = field(default_factory=list)
    dumped_files: List[str] = field(default_factory=list)
    hooks_detected: List[Dict] = field(default_factory=list)
    summary: str = ''
    # 新增：进程退出诊断（目标进程已退出时仍给出有意义的检测结论, 而非仅提示"已退出"）
    process_exited: bool = False
    live_analyzed: bool = False
    exit_diagnosis: Dict = field(default_factory=dict)
    released_pe_files: List[Dict] = field(default_factory=list)  # 释放的 PE/DLL (不是内存注入证据)
    # 新增：高级内存取证
    advanced_shellcode: List[Dict] = field(default_factory=list)
    iat_hooks: List[Dict] = field(default_factory=list)
    heavens_gate: List[Dict] = field(default_factory=list)
    peb_anomalies: List[Dict] = field(default_factory=list)
    seh_overwrite: List[Dict] = field(default_factory=list)
    anti_dump_measures: List[Dict] = field(default_factory=list)
    api_unhooking: List[Dict] = field(default_factory=list)
    kernel_backdoor: List[Dict] = field(default_factory=list)
    hidden_regions: List[Dict] = field(default_factory=list)

@dataclass
class APIHookDetail:
    timestamp: str = ''
    module: str = ''
    api_name: str = ''
    arguments: List[str] = field(default_factory=list)
    return_value: str = ''
    thread_id: int = 0
    category: str = ''
    call_stack: List[str] = field(default_factory=list)

@dataclass
class APIMonitorResult:
    total_calls: int = 0
    call_records: List[APIHookDetail] = field(default_factory=list)
    suspicious_sequences: List[str] = field(default_factory=list)
    call_summary: Dict[str, int] = field(default_factory=dict)
    injection_chains: List[Dict] = field(default_factory=list)
    persistence_chains: List[Dict] = field(default_factory=list)
    evasion_chains: List[Dict] = field(default_factory=list)
    raw_log_file: str = ''
    shutdown_blocked: List[Dict] = field(default_factory=list)
    _antivm_active: bool = False
    _amsi_events: List[Dict] = field(default_factory=list)  # AMSI 扫描/初始化/卸载事件
    _priv_events: List[Dict] = field(default_factory=list)  # 特权启用事件 (SeDebug 等)
    _regsave_events: List[Dict] = field(default_factory=list)  # 注册表 hive 保存 (SAM 复制)
    _net_payloads: List[Dict] = field(default_factory=list)  # send/recv 载荷捕获
    _child_processes: List[Dict] = field(default_factory=list)  # CreateProcessW/A Hook 捕获的子进程 PID
    _http_urls: List[Dict] = field(default_factory=list)  # WinHTTP/WinINet 高层 API 捕获的明文 URL

@dataclass
class DroppedFile:
    path: str
    size: int
    md5: str
    sha256: str
    file_type: str
    entropy: float
    is_executable: bool = False
    abs_path: str = ''
    is_hidden: bool = False
    is_system: bool = False
    created_time: str = ''
    parent_pid: int = 0
    parent_process: str = ''
    detection: str = ''
    yara_matches: List[str] = field(default_factory=list)
    analysis_note: str = ''  # 轻量级内容分析备注

@dataclass
class DroppedFilesAnalysis:
    total_dropped: int = 0
    executable_dropped: int = 0
    dll_dropped: int = 0
    script_dropped: int = 0
    documents_dropped: int = 0
    dropped_files: List[DroppedFile] = field(default_factory=list)
    suspicious_dropped: List[DroppedFile] = field(default_factory=list)
    file_tree: Dict = field(default_factory=dict)
    timeline: List[Dict] = field(default_factory=list)
    summary: str = ''
    archive_children: list = field(default_factory=list)  # 归档子文件枚举

@dataclass
class MalwareFamilyIndicator:
    family_name: str
    confidence: float
    indicators: List[str] = field(default_factory=list)
    matched_rules: List[str] = field(default_factory=list)
    description: str = ''
    typical_behaviors: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)

@dataclass
class MalwareFamilyAnalysis:
    primary_family: str = 'Unknown'
    primary_confidence: float = 0.0
    all_families: List[MalwareFamilyIndicator] = field(default_factory=list)
    matched_signatures: int = 0
    total_rules: int = 0
    behavioral_similarity: Dict = field(default_factory=dict)
    network_signatures: List[str] = field(default_factory=list)
    crypto_signatures: List[str] = field(default_factory=list)
    summary: str = ''

@dataclass
class AdvancedBehavior:
    anti_sandbox: List[str] = field(default_factory=list)
    anti_vm: List[str] = field(default_factory=list)
    anti_debug: List[str] = field(default_factory=list)
    anti_analysis: List[str] = field(default_factory=list)
    proxy_manipulation: List[str] = field(default_factory=list)  # 代理设置操控
    timing_evasion: List[str] = field(default_factory=list)
    privilege_escalation: List[str] = field(default_factory=list)
    uac_bypass: List[str] = field(default_factory=list)
    token_manipulation: List[str] = field(default_factory=list)
    process_injection: List[str] = field(default_factory=list)
    process_hollowing: List[str] = field(default_factory=list)
    apc_injection: List[str] = field(default_factory=list)
    thread_hijacking: List[str] = field(default_factory=list)
    credential_theft: List[str] = field(default_factory=list)
    keylogging: List[str] = field(default_factory=list)
    audio_surveillance: List[str] = field(default_factory=list)  # 音频/麦克风/摄像头设备访问
    clipboard_monitoring: List[str] = field(default_factory=list)
    screenshot_capture: List[str] = field(default_factory=list)
    browser_data_theft: List[str] = field(default_factory=list)
    c2_communication: List[str] = field(default_factory=list)
    dga_detected: bool = False
    domain_generation: List[str] = field(default_factory=list)
    steganography: List[str] = field(default_factory=list)
    ransomware_indicators: List[str] = field(default_factory=list)
    file_encryption: List[str] = field(default_factory=list)
    ransom_note: str = ''
    bootkit_indicators: List[str] = field(default_factory=list)
    rootkit_indicators: List[str] = field(default_factory=list)
    wiper_indicators: List[str] = field(default_factory=list)
    lateral_movement: List[str] = field(default_factory=list)
    attack_chain: List[str] = field(default_factory=list)
    risk_score: int = 0
    summary: str = ''

@dataclass
class ThreatIntel:
    engine_results: List[Dict] = field(default_factory=list)
    iocs: List[Dict] = field(default_factory=list)
    threat_labels: List[str] = field(default_factory=list)
    family: str = 'Unknown'
    confidence: str = 'unknown'
    first_seen: str = ''
    last_seen: str = ''
    submission_count: int = 0
    detection_rate: float = 0.0

@dataclass
class ArchiveEntry:
    filename: str
    size_original: int
    size_compressed: int
    crc32: str = ''
    is_encrypted: bool = False
    compression_ratio: float = 1.0
    file_type: str = ''
    is_executable: bool = False
    is_nested_archive: bool = False
    is_suspicious: bool = False
    suspicion_reason: str = ''
    extraction_status: str = ''  # ok / failed / password_missing / encrypted_failed (AES)

@dataclass
class ArchiveAnalysis:
    archive_path: str
    archive_type: str
    total_files: int = 0
    total_size_original: int = 0
    total_size_compressed: int = 0
    encrypted_files: List[str] = field(default_factory=list)
    executable_files: List[str] = field(default_factory=list)
    nested_archives: List[str] = field(default_factory=list)
    suspicious_files: List[str] = field(default_factory=list)
    extracted_dir: str = ''
    entries: List[ArchiveEntry] = field(default_factory=list)
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)
    child_reports: List[Dict] = field(default_factory=list)
    summary: str = ''

@dataclass
class ScriptAnalysis:
    script_type: str = 'unknown'
    detections: List[str] = field(default_factory=list)
    suspicious_lines: List[Dict] = field(default_factory=list)
    risk_score: int = 0
    has_obfuscation: bool = False
    obfuscation_type: str = ''
    encoding_layers: int = 0
    embedded_files: List[str] = field(default_factory=list)
    embedded_urls: List[str] = field(default_factory=list)
    summary: str = ''

@dataclass
class DestructionIndicators:
    mbr_access: bool = False
    mbr_write_commands: List[str] = field(default_factory=list)
    disk_wipe_commands: List[str] = field(default_factory=list)
    raw_disk_access: bool = False
    shadow_copy_delete: bool = False
    backup_delete_commands: List[str] = field(default_factory=list)
    system_file_delete: List[str] = field(default_factory=list)
    system_file_rename: List[str] = field(default_factory=list)
    av_termination: List[str] = field(default_factory=list)
    edr_termination: List[str] = field(default_factory=list)
    security_registry_delete: List[str] = field(default_factory=list)
    safe_mode_override: bool = False
    uac_bypass_attempts: List[str] = field(default_factory=list)
    firewall_disable: bool = False
    hosts_file_modify: bool = False
    service_stop: List[str] = field(default_factory=list)
    service_delete: List[str] = field(default_factory=list)
    service_disable: List[str] = field(default_factory=list)
    defender_registry_disable: List[str] = field(default_factory=list)
    av_install_block: List[str] = field(default_factory=list)  # 禁止杀软安装/更新 (银狐核心手法: msiserver/BITS/wuauserv 等禁用)
    dangerous_driver_load: List[str] = field(default_factory=list)
    driver_privilege_escalation: bool = False
    destruction_level: str = 'none'
    total_indicators: int = 0
    summary: str = ''

@dataclass
class SubFileAnalysis:
    parent_file: str
    extracted_files: List[Dict] = field(default_factory=list)
    embedded_resources: List[Dict] = field(default_factory=list)
    overlay_data: Dict = field(default_factory=dict)
    certificate_data: Dict = field(default_factory=dict)
    icon_hashes: List[str] = field(default_factory=list)
    version_info: Dict = field(default_factory=dict)
    manifest_data: str = ''
    dotnet_resources: List[Dict] = field(default_factory=list)
    summary: str = ''

@dataclass
class AnalysisReport:
    scan_id: str = ''
    scan_time: str = ''
    file_info: Optional[FileInfo] = None
    pe_info: Optional[PEInfo] = None
    strings: Optional[StringAnalysis] = None
    dynamic: Optional[DynamicBehavior] = None
    network: Optional[NetworkTraffic] = None
    threat_intel: Optional[ThreatIntel] = None
    memory: Optional[MemoryAnalysis] = None
    api_monitor: Optional[APIMonitorResult] = None
    archive: Optional[ArchiveAnalysis] = None
    destruction: Optional[DestructionIndicators] = None
    msi_actions: Optional[Dict] = None
    msi_registry_planned: Optional[List] = None
    script_analysis: Optional[ScriptAnalysis] = None
    dropped_files: Optional[DroppedFilesAnalysis] = None
    malware_family: Optional[MalwareFamilyAnalysis] = None
    advanced_behavior: Optional[AdvancedBehavior] = None
    sub_files: Optional[SubFileAnalysis] = None
    risk_score: int = 0
    risk_level: str = 'low'
    summary: str = ''
    analysis_duration: float = 0.0
    errors: List[str] = field(default_factory=list)
    # 运行时附加数据（用于报告展示，由 orchestrator 填充）
    _original_path: str = ''
    _ps_deobfuscated: List[Dict] = field(default_factory=list)
    _ps_iocs: List[str] = field(default_factory=list)
    _deobfuscation: List[Dict] = field(default_factory=list)
    _overlay_payloads: List[Dict] = field(default_factory=list)
    _community_signatures: List[Dict] = field(default_factory=list)
    _yara_matches: List[Dict] = field(default_factory=list)
    _rat_config: List[Dict] = field(default_factory=list)
    _disk_forensics: Dict = field(default_factory=dict)
    _ioc_hits: Dict = field(default_factory=dict)
    _sandbox_enhancements: Dict = field(default_factory=dict)
    _ua_analysis: Dict = field(default_factory=dict)
    _vss_deleted: bool = False
    _execution_tree: Dict = field(default_factory=dict)
    _shutdown_blocked: List[Dict] = field(default_factory=list)
    _archive_child_reports: List[Dict] = field(default_factory=list)
    _behavior_timeline: List[Dict] = field(default_factory=list)
    # 深度追踪分析 (DeepDive) — 由 orchestrator 在动态分析后生成
    _deep_dive: Optional[Any] = None
    # URL 挂马扫描结果列表 (由 orchestrator / 独立扫描生成)
    _url_scans: List[Any] = field(default_factory=list)
    # ClamAV 本地扫描结果 (clamd 守护进程, 不可用则 available=False)
    _clamav: Dict = field(default_factory=dict)

@dataclass
class URLScanResult:
    """URL 扫描结果 — 网页源码分析 / 挂马检测 / 命令执行检测"""
    url: str = ''
    final_url: str = ''
    status_code: int = 0
    reason: str = ''
    server_headers: Dict = field(default_factory=dict)
    redirect_chain: List[str] = field(default_factory=list)
    redirect_to_external: bool = False
    resolved_ips: List[str] = field(default_factory=list)
    page_title: str = ''
    content_type: str = ''
    page_size: int = 0
    fetch_error: str = ''
    is_php: bool = False
    phpinfo_exposed: bool = False
    # 命令执行 / WebShell 指示器: {severity, type, evidence, line}
    webshell_indicators: List[Dict] = field(default_factory=list)
    # 挂马 (iframe 注入 / 隐藏加载 / 页面篡改): {severity, type, evidence, line}
    malicious_iframes: List[Dict] = field(default_factory=list)
    # 恶意/混淆脚本: {severity, type, evidence, line}
    obfuscated_scripts: List[Dict] = field(default_factory=list)
    # 免杀下载/释放载荷: {severity, type, evidence, line}
    drive_by_downloads: List[Dict] = field(default_factory=list)
    # 钓鱼指示器: {severity, type, evidence, line}
    phishing_indicators: List[Dict] = field(default_factory=list)
    # 社会工程攻击 (ClickFix 假验证码 / 假浏览器更新 / 剪贴板劫持)
    social_engineering: List[Dict] = field(default_factory=list)
    # 数据窃取 (Magecart 表单注入 / 键盘记录 / sendBeacon 外泄)
    data_theft: List[Dict] = field(default_factory=list)
    # 挖矿脚本
    crypto_mining: List[Dict] = field(default_factory=list)
    # PHP 8 新特性后门 / 命令输出泄漏
    php8_webshell: List[Dict] = field(default_factory=list)
    command_output_leak: List[Dict] = field(default_factory=list)
    suspicious_links: List[str] = field(default_factory=list)
    # ===== 动态行为监控 (浏览器沙箱执行结果) =====
    dynamic_used: bool = False                 # 是否执行了动态监控
    dynamic_error: str = ''                    # 动态监控失败原因
    dynamic_engine: str = ''                   # playwright / requests-crawl / none
    dynamic_events: List[Dict] = field(default_factory=list)    # 行为时间线 [{t, type, detail}]
    dynamic_requests: List[Dict] = field(default_factory=list)  # 浏览器发出的全部请求
    dynamic_console: List[Dict] = field(default_factory=list)   # 控制台消息
    dynamic_downloads: List[Dict] = field(default_factory=list) # 触发的下载
    dynamic_screenshots: List[str] = field(default_factory=list)# 截图路径
    dynamic_resources: List[Dict] = field(default_factory=list) # 抓取的 JS/HTML 资源分析
    dom_injected: List[Dict] = field(default_factory=list)      # JS 执行后 DOM 注入检测
    dom_html: str = ''                         # 执行后的 DOM HTML (截断保存)
    # 外部脚本抓取分析结果: {url, status, size, findings}
    external_scripts: List[Dict] = field(default_factory=list)
    # 本地 IoC 命中: ThreatIntelEngine.check_url 结果
    ioc_hits: List[Dict] = field(default_factory=list)
    # 全部发现汇总 (按严重度排序)
    all_findings: List[Dict] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = 'low'
    summary: str = ''
    scan_duration: float = 0.0
    scanned_at: str = ''


@dataclass
class DeepDiveFile:
    """深度分析-释放/关联文件画像"""
    path: str = ''
    role: str = ''                        # 主程序/释放物/载荷/驱动/配置/脚本
    size: int = 0
    entropy: float = 0.0
    md5: str = ''
    sha256: str = ''
    kind: str = ''                        # PE32/PE32+/DLL/脚本/文本/配置
    signature_verifier: str = ''          # 数字签名颁发者(驱动链关键)
    signature_valid: bool = False
    is_driver: bool = False               # 驱动文件(.sys/内核PE)
    exports: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    strings_found: List[str] = field(default_factory=list)
    yara_matches: List[str] = field(default_factory=list)
    family_hits: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

@dataclass
class DeepDiveMemoryCode:
    """深度分析-内存代码画像(反射加载/注入载荷)"""
    pid: int = 0
    process: str = ''
    address: str = ''
    size: int = 0
    kind: str = ''                        # 注入PE/Shellcode/镂空/钩子
    exports: List[str] = field(default_factory=list)
    decrypted_strings: List[Dict] = field(default_factory=list)
    theft_signatures: List[Dict] = field(default_factory=list)
    dump_path: str = ''

@dataclass
class DeepDiveProcessNode:
    """深度分析-进程链节点"""
    pid: int = 0
    name: str = ''
    ppid: int = 0
    cmdline: str = ''
    exe: str = ''
    create_time: str = ''
    alive_duration: float = 0.0
    exit_code: int = -1
    flags: List[str] = field(default_factory=list)

@dataclass
class DeepDiveNetwork:
    """深度分析-网络外联画像"""
    c2_candidates: List[Dict] = field(default_factory=list)
    targets: List[Dict] = field(default_factory=list)
    dns_interesting: List[str] = field(default_factory=list)
    http_summary: List[Dict] = field(default_factory=list)
    c2_config: Dict = field(default_factory=dict)  # C2 配置提取 (URL/密钥/路径/上线包格式)

@dataclass
class DeepDiveReport:
    """深度追踪分析报告(叙事式攻击链编排)"""
    execution_environment: List[Dict] = field(default_factory=list)  # 运行环境校验(目标进程检测等)
    defense_evasion: List[Dict] = field(default_factory=list)        # 反调试/对抗/隐藏
    payload_delivery: List[Dict] = field(default_factory=list)       # 载荷投递链(下载/释放/反射加载)
    driver_chain: List[Dict] = field(default_factory=list)           # 驱动加载链(白驱动黑驱动/签名)
    data_theft: List[Dict] = field(default_factory=list)             # 数据窃取线索(特征码命中/凭证)
    persistence: List[Dict] = field(default_factory=list)            # 持久化(注册表/服务/计划任务)
    network_profile: DeepDiveNetwork = field(default_factory=DeepDiveNetwork)
    files: List[DeepDiveFile] = field(default_factory=list)
    memory_codes: List[DeepDiveMemoryCode] = field(default_factory=list)
    process_chain: List[DeepDiveProcessNode] = field(default_factory=list)
    attack_chain: List[Dict] = field(default_factory=list)           # 攻击链时间线
    behavior_insights: List[Dict] = field(default_factory=list)      # 行为深析清单(反杀软/UAC/提权/键盘记录等)
    delivery_layers: List[Dict] = field(default_factory=list)        # 层级投递链 (L1→Ln)
    ioc_summary: Dict = field(default_factory=dict)                  # IOC 分类汇总(文件/网络/注册表/计划任务)
    conclusion: str = ''
    verdict: str = ''                     # 综合判定
    confidence: float = 0.0
