# -*- coding: utf-8 -*-
"""Office 宏分析器 — 提取并分析 docx/xlsm 等 OpenXML 内的 VBA 宏

背景: Kimsuky/银狐等 APT 常用"钓鱼文档 + 宏"初始投递, 宏藏在
docx 的 word/vbaProject.bin (OLE2 复合文档) 中。本模块:
  1. 识别 OpenXML 文档 (PK 头) 并解出 vbaProject.bin
  2. 用 olefile 读 VBA 模块流 (VBA/Module*, VBA/ThisDocument)
  3. 提取宏源码特征: AutoOpen/Document_Open 触发器、Shell/PowerShell/
     WScript.Shell/IEX 下载执行、C2 URL、DPB 伪加密标记
  4. 兼容传统 .doc (OLE2) — 直接 olefile 读 Macro 流
"""
import io
import logging
import re
import zipfile

logger = logging.getLogger('malware_sandbox.macro_analyzer')

try:
    import olefile
except ImportError:
    olefile = None

# 宏触发器 (AutoExec 类)
AUTOEXEC_PATTERNS = [
    r'AutoOpen|Auto_Open|AutoExec|Document_Open|Workbook_Open|DocumentOpen',
    r'FileSave|BeforeClose|Worksheet_Activate|Workbook_Open',
]

# 恶意行为模式
MACRO_SUSPICIOUS_PATTERNS = [
    (r'WScript\.Shell|Shell\.Application|CreateObject\("Shell', 'Shell 对象创建'),
    (r'powershell|PowerShell|pwsh', 'PowerShell 调用'),
    (r'iex\s*\(|IEX\s+\(|Invoke-Expression', 'IEX 动态执行'),
    (r'DownloadString|DownloadFile|Net\.WebClient|WinHttp|XMLHTTP|MSXML2',
     '远程下载'),
    (r'Chr\([0-9]+\)\s*&\s*Chr\(|ChrW\(\d+\)|Split\(.*Chr', 'Chr 字符串混淆'),
    (r'Replace\([^,]+,[^,]+,""\)', '字符串混淆 (Replace去杂)'),
    (r'CreateObject\(.*(?:ADODB|WMI|Scripting\.FileSystemObject|MSXML)',
     'COM 对象滥用'),
    (r'RegWrite|RegRead|HKCU|HKLM|CurrentVersion\\Run', '注册表操作/持久化'),
    (r'Shell\s*\(|Call\s+Shell|ShellExecute|\.Run\s*\(', 'Shell 执行'),
    (r'Encrypt|Decrypt|XOR|FromBase64|Base64|Convert\.FromBase64',
     '编码/解密操作'),
    (r'GetTempPath|%TEMP%|%APPDATA%|AppData\\Roaming', '临时目录/应用数据'),
    (r'systeminfo|tasklist|ipconfig|net\s+user|whoami|query\s+user',
     '系统信息收集'),
]

# DPB 伪加密标记 (宏密码保护 — 把 DPB 改 DPX 即可绕过, 是恶意文档常见手法)
DPB_MARKER = b'DPB'


class MacroAnalysis:
    """宏分析结果"""
    def __init__(self):
        self.has_vba = False
        self.dpb_protected = False      # 宏伪加密
        self.autoexec = []              # 自动执行触发器
        self.suspicious = []            # 可疑行为 (desc)
        self.urls = []                  # 提取的 URL
        self.modules = []               # 宏模块名
        self.source_preview = ''        # 宏源码预览 (前 2KB)
        self.container = ''             # docx / doc / xlsm ...


def _read_vba_streams(vba_bin: bytes) -> dict:
    """从 vbaProject.bin (OLE2) 提取 VBA 模块源码流"""
    if not olefile or not vba_bin:
        return {}
    try:
        ole = olefile.OleFileIO(io.BytesIO(vba_bin))
    except Exception:
        return {}
    streams = {}
    try:
        for name in ole.listdir():
            path = '/'.join(name).lower()
            # VBA 模块源码: VBA/Module1, VBA/ThisDocument, VBA/NewMacros 等
            if len(name) >= 2 and name[0].lower() == 'vba' and \
                    (path.endswith(('.bas', '.cls', '/thisdocument')) or
                     any(n.lower().startswith(('module', 'thisdocument', 'newmacros', 'class'))
                         for n in name[1:])):
                try:
                    streams[path] = ole.openstream(name).read()
                except Exception:
                    pass
    finally:
        ole.close()
    return streams


def _decode_vba_source(raw: bytes) -> str:
    """VBA 源码流是 UTF-16LE (带压缩), 尝试解码; 失败时做启发式提取"""
    try:
        return raw.decode('utf-16-le', errors='ignore')
    except Exception:
        return raw.decode('latin1', errors='ignore')


def analyze_macro_file(file_path: str) -> MacroAnalysis:
    """分析 Office 文档中的宏"""
    result = MacroAnalysis()
    try:
        with open(file_path, 'rb') as f:
            head = f.read(4)
            f.seek(0)
            data = f.read()
    except Exception as e:
        logger.debug(f"[Macro] 读取失败: {e}")
        return result

    vba_bin = b''
    if head[:2] == b'PK':
        # OpenXML (docx/xlsm/pptm) — 宏在 word/vbaProject.bin 等
        result.container = 'OpenXML'
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for name in zf.namelist():
                    low = name.lower()
                    if low.endswith('vbaproject.bin'):
                        result.has_vba = True
                        vba_bin = zf.read(name)
                        result.container = low.split('/')[0]  # word/xl/ppt
                        break
        except Exception:
            pass
    elif head[:4] == b'\xd0\xcf\x11\xe0':
        # 传统 OLE2 .doc/.xls — 宏在 Macro 流
        result.container = 'OLE2'
        if olefile:
            try:
                ole = olefile.OleFileIO(file_path)
                try:
                    if ole.exists('Macros/VBA'):
                        result.has_vba = True
                        for name in ole.listdir('Macros/VBA'):
                            path = '/'.join(name)
                            if path.lower().endswith(('.bas', '.cls')) or \
                                    name[-1].lower().startswith(('module', 'thisdocument')):
                                raw = ole.openstream(name).read()
                                if raw[:2] == b'DPB':
                                    result.dpb_protected = True
                                src = _decode_vba_source(raw)
                                result.modules.append(name[-1])
                                result.source_preview += src[:2000] + '\n'
                                # 从源码中提取特征
                                for pat, desc in MACRO_SUSPICIOUS_PATTERNS:
                                    if re.search(pat, src, re.IGNORECASE):
                                        if desc not in result.suspicious:
                                            result.suspicious.append(desc)
                                for m in re.finditer(
                                        r'https?://[^\s"\'<>]+', src, re.IGNORECASE):
                                    u = m.group(0).rstrip('.,;)')
                                    if u not in result.urls:
                                        result.urls.append(u)
                finally:
                    ole.close()
            except Exception:
                pass
        return result

    if not vba_bin:
        return result

    # OpenXML 的 vbaProject.bin — 检查 DPB 伪加密 + 提取模块
    if vba_bin[:2] == b'DPB':
        result.dpb_protected = True
    streams = _read_vba_streams(vba_bin)
    for path, raw in streams.items():
        src = _decode_vba_source(raw)
        result.modules.append(path.split('/')[-1])
        result.source_preview += src[:2000] + '\n'
        for m in re.finditer(r'Auto(?:Open|_Open|Exec)|Document_Open|Workbook_Open',
                             src, re.IGNORECASE):
            if m.group(0) not in result.autoexec:
                result.autoexec.append(m.group(0))
        for pat, desc in MACRO_SUSPICIOUS_PATTERNS:
            if re.search(pat, src, re.IGNORECASE):
                if desc not in result.suspicious:
                    result.suspicious.append(desc)
        for m in re.finditer(r'https?://[^\s"\'<>]+', src, re.IGNORECASE):
            u = m.group(0).rstrip('.,;)')
            if u not in result.urls:
                result.urls.append(u)
    return result
