# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for Malware Analysis Platform v3.0
Entry: main.py (supports both GUI and CLI modes)
"""
import os
import sys
from pathlib import Path

# spec 所在目录即项目根目录（随项目移动而自适应）
PROJECT_ROOT = Path(SPECPATH)

# ── Collect all sub-package modules ──
def collect_modules(subdir):
    """Collect all .py files from a subdirectory as (src_path, dest_dir) tuples"""
    d = Path(PROJECT_ROOT) / subdir
    if not d.exists():
        return []
    return [(str(f), subdir) for f in d.glob("*.py")]

analyzer_modules = collect_modules("analyzer")
gui_modules = collect_modules("gui")
utils_modules = collect_modules("utils")

# ── Hidden imports (modules PyInstaller might miss) ──
hidden_imports = [
    # Core dependencies
    "pefile", "magic", "psutil", "requests",
    "jinja2", "jinja2.ext", "jinja2.nodes",
    # Optional - static analysis
    "capstone", "Crypto", "Cryptodome", "Cryptodome.Cipher",
    "Cryptodome.Cipher.AES", "Cryptodome.Hash", "Cryptodome.PublicKey",
    # Optional - dynamic
    "frida", "scapy", "scapy.all", "scapy.layers", "scapy.layers.inet",
    "clamd",  # ClamAV 本地扫描客户端 (clamd 守护进程)
    # ETW 内核监控 (pywintrace — 延迟导入, 必须显式收集)
    "etw", "etw.etw", "etw.evntrace", "etw.evntcons", "etw.evntprov",
    "etw.tdh", "etw.common", "etw.GUID", "etw.wmistr", "etw.in6addr",
    # Optional - Win32
    "pywintypes", "pythoncom",
    "win32com", "win32com.client",
    "win32api", "win32file", "win32process", "win32security",
    "win32event", "win32con", "win32service", "win32serviceutil",
    "win32pipe", "win32net", "win32wnet",
    "winreg",
    # Optional - compression
    "rarfile", "py7zr",
    "pyzipper",  # AES-256 zip 解包支持
    # Optional - report
    "fpdf", "fpdf.fonts", "fpdf.enums", "jinja2",
    # Optional - config
    "yaml",
    # GUI
  
 
 
 "PIL", "PIL.Image", "PIL.ImageTk", "PIL.ImageDraw",
    # Optional - network
    "pyshark",
    # Other
    "olefile", "lief",
    # Standard lib (PyInstaller sometimes misses)
    "hashlib", "json", "datetime", "threading", "queue",
    "argparse", "logging", "logging.handlers",
    "pathlib", "dataclasses", "typing",
    "struct", "re", "math", "tempfile", "ctypes", "subprocess",
    "xml", "xml.etree", "xml.etree.ElementTree",
    "email", "email.mime", "email.utils",
    "ipaddress", "socket", "ssl",
    "html", "urllib", "urllib.parse",
    "io", "base64", "binascii", "string", "shutil",
    "collections", "functools", "itertools",
    "traceback", "warnings", "copy",
    # Project internal packages
    "config", "logger", "orchestrator",
    "analyzer", "analyzer.models", "analyzer.static",
    "analyzer.pe", "analyzer.strings", "analyzer.archive",
    "analyzer.script", "analyzer.msi", "analyzer.dynamic",
    "analyzer.network", "analyzer.memory", "analyzer.api_monitor",
    "analyzer.destruction", "analyzer.family", "analyzer.dropped_files",
    "analyzer.advanced_behavior", "analyzer.vm_detector",
    "analyzer.vm_process_hider", "analyzer.system_monitor",
    "analyzer.sandbox", "analyzer.sandbox_monitor", "analyzer.deep_dive",
    "analyzer.rat_config", "analyzer.sigma_rules", "analyzer.yara_scanner",
    "analyzer.yara_downloader", "analyzer.deobfuscator",
    "analyzer.behavior_tags", "analyzer.suricata_rules",
    "analyzer.disk_forensics", "analyzer.memory_forensics",
    "analyzer.mem_api", "analyzer.sub_files", "analyzer.etw_monitor", "analyzer.tls_fingerprint",
    "analyzer.fake_user_env", "analyzer.signature_engine",
    "analyzer.batch", "analyzer.macro_analyzer", "analyzer.pe_rebuilder", "analyzer.persistence_rollback", "analyzer.threat_intel",
    # URL 挂马扫描 (静态 + 动态浏览器沙箱)
    "analyzer.url_scanner", "analyzer.url_dynamic",
    "analyzer.clamav_scanner",
    "report", "report.url_report_generator", "report.web_monitor", "report.html_generator", "report.json_generator", "report.pdf_generator", "report.summary_generator", "report.cleanup_generator", "report.index_generator",
    "gui", "gui.main_window",
    "utils", "utils.helpers", "utils.dep_checker", "utils.ps_deobfuscate",
]

# ── Excluded modules (reduce size, avoid bloat) ──
# 注意: 不能排除 distutils/setuptools/pip/wheel — PyInstaller 6.x 自带 hook 需要它们
excluded_modules = [
    "pytest", "black", "mypy",
    "tkinter.test", "test",
    "lib2to3",
    # ⚠ 意外引入的无关大包 (matplotlib 被依赖链引入 → 连带 numpy/PyQt5)
    # 报告用 fpdf + jinja2 + 前端 ECharts, 不需要这些 (省 ~126MB)
    "matplotlib", "numpy", "pandas", "scipy",
    "PyQt5", "PyQt6", "PySide2", "PySide6", "sip", "shiboken6",
    "IPython", "jedi", "parso",
    # ⚠ 注意: 不能排除 multiprocessing/unittest — py7zr 依赖 multiprocessing, fpdf 依赖 unittest
    # backports.zstd: 排除纯 Python 后端, 只用 C 扩展 (.pyd) — 避免收集/运行时导入冲突
    "backports.zstd._zstd", "backports.zstd._cffi",
]

# ── 数据文件（规则、模块源码）──
datas = analyzer_modules + gui_modules + utils_modules
datas += [('rules', 'rules')]  # YARA 规则 + 自定义 IoC
datas += [('clamav_engine', 'clamav_engine')]  # ClamAV 内置引擎 + 病毒库 (clamscan 开箱即用)
datas += [('config.json', '.')]  # 用户配置 (API Key 等, exe 同级可编辑)

# ── playwright (URL 动态监控浏览器沙箱) ──
# 必须收集 playwright 包本体 + driver (node.exe), 否则 exe 内动态监控不可用
pw_datas, pw_binaries, pw_hidden = [], [], []
try:
    from PyInstaller.utils.hooks import collect_all
    pw_datas, pw_binaries, pw_hidden = collect_all('playwright')
    datas += pw_datas
# tcl/tk from system Python (AutoClaw Python lacks Tk)
    _sys_py = os.path.join('C:', os.sep, 'Users', 'Administrator', 'AppData', 'Local', 'Programs', 'Python', 'Python313')
    _tk_datas = [(os.path.join(_sys_py, 'tcl'), 'tcl')]
    # tkinter .py files
    _tkinter_dir = os.path.join(_sys_py, 'Lib', 'tkinter')
    if os.path.isdir(_tkinter_dir):
        _tk_datas += [(f, 'tkinter') for f in [os.path.join(_tkinter_dir, x) for x in os.listdir(_tkinter_dir) if x.endswith('.py')]]
    datas += _tk_datas
    hidden_imports += pw_hidden
    print(f"[spec] playwright 收集: {len(pw_datas)} datas, {len(pw_binaries)} binaries")
except Exception as e:
    print(f"[spec] playwright 收集失败(动态监控将不可用): {e}")

binaries = []
# tcl/tk DLLs from system Python
_dll_dir = os.path.join('C:', os.sep, 'Users', 'Administrator', 'AppData', 'Local', 'Programs', 'Python', 'Python313', 'DLLs')
_tk_bins = []
for _d in ['tcl86t.dll', 'tk86t.dll', '_tkinter.pyd']:
    _p = os.path.join(_dll_dir, _d)
    if os.path.exists(_p):
        _tk_bins.append((_p, '.'))
binaries += _tk_bins

a = Analysis(
    [str(Path(PROJECT_ROOT) / "main.py")],
    pathex=[str(PROJECT_ROOT)],
binaries=pw_binaries + _tk_bins,
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[str(PROJECT_ROOT / "hooks")],
    hooksconfig={},
    runtime_hooks=[str(PROJECT_ROOT / 'hooks' / 'rth_tcl.py')],
    excludes=excluded_modules,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="样本动态分析工具",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="样本动态分析工具",
)
