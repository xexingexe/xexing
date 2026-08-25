"""ClamAV 本地扫描引擎 — 双重方案

优先级:
1. clamd 守护进程 (127.0.0.1:3310, 用户自装 ClamAV 服务时生效)
2. 内置 clamscan 引擎 (打包在 clamav_engine/, 开箱即用)

两种都不可用时自动降级 (available=False), 不影响其他分析流程。
"""
import os
import sys
import re
import subprocess
import logging

logger = logging.getLogger(__name__)

try:
    import clamd
    CLAMD_OK = True
except Exception:  # noqa: BLE001
    CLAMD_OK = False

_clamd_client = None
_clamd_checked = False
_clamd_available = False

_clamscan_path = None
_clamscan_checked = False
_clamscan_available = False

# clamd 常见监听地址 (Windows 默认 TCP 3310)
_SOCKETS = [
    ('127.0.0.1', 3310),
    ('localhost', 3310),
]


def _get_client():
    """获取 clamd 客户端 (懒连接 + 结果缓存)。不可用返回 None。"""
    global _clamd_client, _clamd_checked, _clamd_available
    if _clamd_checked:
        return _clamd_client if _clamd_available else None
    _clamd_checked = True
    if not CLAMD_OK:
        return None
    for host, port in _SOCKETS:
        try:
            cd = clamd.ClamdNetworkSocket(host, port, timeout=5)
            if cd.ping() == 'PONG':
                _clamd_client = cd
                _clamd_available = True
                logger.info(f"[ClamAV] 已连接 clamd 服务 {host}:{port}")
                return cd
        except Exception:  # noqa: BLE001
            continue
    return None


def _bundled_clamscan():
    """查找内置 clamscan.exe (打包引擎优先, 其次开发目录, 最后系统 PATH)。"""
    global _clamscan_path, _clamscan_checked, _clamscan_available
    if _clamscan_checked:
        return _clamscan_path if _clamscan_available else None
    _clamscan_checked = True
    candidates = []
    # PyInstaller onedir: sys._MEIPASS 指向 _internal 目录, data 在其下
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        candidates.append(os.path.join(meipass, 'clamav_engine', 'clamscan.exe'))
        candidates.append(os.path.join(os.path.dirname(meipass), 'clamav_engine', 'clamscan.exe'))
    # 开发环境: 项目根目录 (本文件在 analyzer/ 下, 上两级是项目根)
    proj = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(proj, 'clamav_engine', 'clamscan.exe'))
    # 系统 PATH
    for d in os.environ.get('PATH', '').split(os.pathsep):
        if d:
            candidates.append(os.path.join(d, 'clamscan.exe'))
    for c in candidates:
        if c and os.path.isfile(c):
            _clamscan_path = c
            _clamscan_available = True
            logger.info(f"[ClamAV] 使用内置引擎: {c}")
            return c
    return None


def is_available() -> bool:
    """ClamAV 是否可用 (clamd 服务或内置 clamscan 引擎)。"""
    return _get_client() is not None or _bundled_clamscan() is not None


def _scan_with_clamd(cd, path: str) -> dict:
    try:
        with open(path, 'rb') as f:
            result = cd.instream(f)
        stream = result.get('stream') if isinstance(result, dict) else None
        if stream and len(stream) >= 1:
            status = stream[0]
            name = stream[1] if len(stream) > 1 else ''
            if status == 'FOUND':
                return {'available': True, 'detected': True, 'malware_name': name or 'Malware', 'error': ''}
            if status == 'ERROR':
                return {'available': True, 'detected': False, 'malware_name': '', 'error': name or '扫描错误'}
        return {'available': True, 'detected': False, 'malware_name': '', 'error': ''}
    except Exception as e:  # noqa: BLE001
        return {'available': False, 'detected': False, 'malware_name': '', 'error': str(e)[:200]}


def _scan_with_clamscan(clamscan: str, path: str) -> dict:
    db = os.path.join(os.path.dirname(clamscan), 'database')
    cmd = [clamscan, '--no-summary']
    if os.path.isdir(db):
        cmd += ['--database=' + db]
    cmd += [path]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=120,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        out = r.stdout.decode('utf-8', errors='ignore')
        if 'FOUND' in out:
            m = re.search(r':\s*([^\r\n:]+?)\s+FOUND', out)
            name = (m.group(1).strip() if m else 'Malware')
            return {'available': True, 'detected': True, 'malware_name': name, 'error': ''}
        return {'available': True, 'detected': False, 'malware_name': '', 'error': ''}
    except Exception as e:  # noqa: BLE001
        return {'available': True, 'detected': False, 'malware_name': '', 'error': str(e)[:200]}


def scan_file(path: str) -> dict:
    """扫描单个文件。返回 {available, detected, malware_name, error}"""
    if not path or not os.path.exists(path):
        return {'available': False, 'detected': False, 'malware_name': '', 'error': '文件不存在'}
    # 1. clamd 优先
    cd = _get_client()
    if cd is not None:
        r = _scan_with_clamd(cd, path)
        if r.get('available'):
            return r
    # 2. 内置 clamscan
    cs = _bundled_clamscan()
    if cs:
        return _scan_with_clamscan(cs, path)
    return {'available': False, 'detected': False, 'malware_name': '', 'error': 'ClamAV 不可用'}


def scan_files(paths) -> dict:
    """批量扫描。返回 {available, detections, errors}"""
    detections = []
    errors = []
    available = is_available()
    if not available:
        return {'available': False, 'detections': detections, 'errors': ['ClamAV 不可用']}
    for p in paths or []:
        if not p or not os.path.exists(p):
            continue
        r = scan_file(p)
        if r.get('detected'):
            detections.append({'path': p, 'malware_name': r.get('malware_name', 'Malware')})
        elif r.get('error'):
            errors.append({'path': p, 'error': r.get('error')})
    return {'available': True, 'detections': detections, 'errors': errors}
