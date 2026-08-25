#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PE 分析引擎 — 深度解析 PE 文件结构
"""
import re
from datetime import datetime, timedelta
from typing import Optional

from logger import get_logger
from analyzer.models import PEInfo, SectionInfo, ImportInfo, ExportInfo, ResourceInfo

logger = get_logger('analyzer.pe')

# 关注叾嗣exe谢谢喵

# 尝试导入 pefile
PEFILE_AVAILABLE = False
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    pass

# 尝试导入 lief
LIEF_AVAILABLE = False
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    pass


class PEAnalyzer:
    """PE 文件分析器"""

    @staticmethod
    def _extract_signer(filepath: str):
        """提取数字签名（兼容旧接口，返回 'STATUS|SIGNER' 字符串）"""
        full = PEAnalyzer._extract_signature_chain(filepath)
        if not full:
            return 'present'
        status = full.get('status', '')
        signer = full.get('signer', '')
        if status and signer:
            return f'{status}|{signer}'
        if status:
            return status
        return 'present'

    @staticmethod
    def _extract_signature_chain(filepath: str) -> dict:
        """数字签名链解析 — 状态/签名者/颁发CA/序列号/有效期/吊销状态

        返回 dict（解析失败返回空 dict）:
          status      有效状态 (Valid/NotSigned/HashMismatch/UnknownError/...)
          signer      签名者 CN
          issuer      颁发者 CA
          serial      证书序列号
          not_before  生效时间
          not_after   过期时间
          chain_valid 证书链是否可信
          chain_status 证书链状态描述
        """
        try:
            import subprocess, base64, json
            encoded = base64.b64encode(filepath.encode('utf-16-le')).decode('ascii')
            ps = (
                f"$p=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}'));"
                f"$s=Get-AuthenticodeSignature $p;"
                f"$o=[PSCustomObject]@{{Status=$s.Status.ToString();Subject='';Issuer='';"
                f"Serial='';NotBefore='';NotAfter='';ChainValid=$false;ChainStatus=''}};"
                f"$c=$s.SignerCertificate;"
                f"if($c){{$o.Subject=$c.Subject;$o.Issuer=$c.Issuer;$o.Serial=$c.SerialNumber;"
                f"try{{$o.NotBefore=$c.NotBefore.ToString('yyyy-MM-dd HH:mm:ss')}}catch{{}};"
                f"try{{$o.NotAfter=$c.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')}}catch{{}};"
                f"$chain=New-Object System.Security.Cryptography.X509Certificates.X509Chain;"
                f"$chain.ChainPolicy.RevocationMode="
                f"[System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck;"
                f"$o.ChainValid=$chain.Build($c);"
                f"$o.ChainStatus=(($chain.ChainStatus|ForEach-Object{{$_.Status.ToString()}})-join'; ');"
                f"}};"
                f"$o|ConvertTo-Json -Compress"
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps],
                capture_output=True, text=True, timeout=20, errors='ignore'
            )
            if result.returncode != 0 or not result.stdout.strip():
                return {}
            data = json.loads(result.stdout.strip())
            out = {
                'status': str(data.get('Status', '')),
                'signer': '',
                'issuer': str(data.get('Issuer', '')),
                'serial': str(data.get('Serial', '')),
                'not_before': str(data.get('NotBefore', '')),
                'not_after': str(data.get('NotAfter', '')),
                'chain_valid': bool(data.get('ChainValid', False)),
                'chain_status': str(data.get('ChainStatus', '')),
            }
            subject = str(data.get('Subject', ''))
            if subject:
                import re
                cn = re.search(r'CN=([^,\s]+)', subject)
                out['signer'] = cn.group(1) if cn else subject[:80]
            return out
        except Exception:
            return {}

    SUSPICIOUS_APIS = [
        'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
        'ReadProcessMemory', 'OpenProcess', 'TerminateProcess',
        'WSAStartup', 'socket', 'connect', 'send', 'recv',
        'InternetOpen', 'InternetConnect', 'InternetReadFile',
        'URLDownloadToFile', 'WinExec', 'CreateProcess',
        'ShellExecute', 'RegCreateKey', 'RegSetValue',
        'SetWindowsHookEx', 'GetKeyState', 'GetAsyncKeyState',
        'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',
        'EnumProcesses', 'CreateToolhelp32Snapshot', 'Process32First',
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'NtUnmapViewOfSection', 'NtCreateThreadEx', 'RtlCreateUserThread',
        'LoadLibrary', 'GetProcAddress', 'VirtualProtect',
        'NtAllocateVirtualMemory', 'NtWriteVirtualMemory',
        'QueueUserAPC', 'SetThreadContext', 'NtQueueApcThread',
    ]
    
    PACKER_SECTIONS = [
        '.upx', '.vmp', '.vmp0', '.vmp1', '.themida', '.enigma',
        '.petite', '.aspack', '.aspr', '.sg0', '.svkp', '.mpress',
        '.kkrunchy', '.nsp', '.pcle', '.winlic', '.morphine',
    ]
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self._data = None
        
    def analyze(self) -> Optional[PEInfo]:
        """分析 PE 文件"""
        if not PEFILE_AVAILABLE and not LIEF_AVAILABLE:
            logger.warning("PE 分析库未安装 (pefile/lief)，跳过 PE 分析")
            return None
        
        logger.info("[PE] 开始 PE 结构分析...")
        
        try:
            if PEFILE_AVAILABLE:
                return self._analyze_with_pefile()
            elif LIEF_AVAILABLE:
                return self._analyze_with_lief()
        except Exception as e:
            logger.error(f"PE 分析失败: {e}")
            return None
        
        return None
    
    def _analyze_with_pefile(self) -> PEInfo:
        """使用 pefile 分析"""
        # fast_load=True 跳过资源/调试信息解析，50MB+ 文件不会卡死
        pe = pefile.PE(self.file_path, fast_load=True)
        
        try:
            return self._analyze_pe_inner(pe)
        finally:
            pe.close()

    def _analyze_pe_inner(self, pe) -> PEInfo:
        """pefile 内部分析（确保 pe.close() 被调用）"""
        # 基本信息
        is_dll = pe.is_dll()
        is_exe = pe.is_exe()
        
        # 架构
        machine = pe.FILE_HEADER.Machine
        arch_map = {0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'ARM64'}
        architecture = arch_map.get(machine, f'Unknown(0x{machine:04x})')
        
        # 编译时间
        compile_time = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S')
        
        # 编译时间戳异常检测（云沙箱标准项: 未来时间/0/全F/1970基准）
        ts_raw = pe.FILE_HEADER.TimeDateStamp
        ts_anomalies = []
        try:
            ts_dt = datetime.fromtimestamp(ts_raw)
            if ts_raw == 0:
                # ⚠ Go 编译的程序默认 TimeDateStamp=0 (Go 链接器不填时间戳),
                # 是 Go 的默认行为不是加壳 — 误报极高频 (大量 Go 工具/恶意样本都是 Go)
                _is_go = False
                try:
                    _sec_names = [s.Name.decode('utf-8', errors='ignore').strip('\x00')
                                  for s in pe.sections]
                    _is_go = any(n in _sec_names for n in ('.symtab', '.gopclntab', '.itablink'))
                except Exception:
                    pass
                if not _is_go:
                    ts_anomalies.append('编译时间戳为0（常见于加壳/伪造）')
                else:
                    ts_anomalies.append('编译时间戳为0（Go 程序默认行为）')
            elif ts_raw == 0xFFFFFFFF:
                ts_anomalies.append('编译时间戳为全F（伪造/混淆）')
            elif ts_dt.year < 1990:
                ts_anomalies.append(f'编译时间异常早 ({ts_dt.year}) — 时间戳被篡改')
            elif ts_dt > datetime.now() + timedelta(days=2):
                # 微软自 Win10 1809 起对系统二进制做时间戳随机化,
                # 系统目录内文件不报"未来时间戳"避免误报
                fp_lower = (self.file_path or '').lower()
                is_system = ('\\windows\\' in fp_lower or '\\program files' in fp_lower
                             or '\\program files (x86)' in fp_lower)
                if not is_system:
                    ts_anomalies.append(f'编译时间为未来 ({ts_dt.strftime("%Y-%m-%d")}) — 时间戳被篡改')
        except Exception:
            ts_anomalies.append('编译时间戳无法解析')
        
        # 节区分析
        sections = []
        for sec in pe.sections:
            name = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
            entropy = sec.get_entropy()
            chars = sec.Characteristics
            is_exec = bool(chars & 0x20000000)
            is_write = bool(chars & 0x80000000)
            
            sections.append(SectionInfo(
                name=name,
                virtual_address=hex(sec.VirtualAddress),
                virtual_size=sec.Misc_VirtualSize,
                raw_size=sec.SizeOfRawData,
                raw_offset=sec.PointerToRawData,
                entropy=round(entropy, 4),
                characteristics=hex(chars),
                is_executable=is_exec,
                is_writable=is_write,
                is_suspicious=entropy > 7.0 or name in self.PACKER_SECTIONS,
                suspicion_reason=(
                    f"High entropy ({entropy:.1f})" + (' + Known packer' if name in self.PACKER_SECTIONS else '')
                    if entropy > 7.0 else
                    ('Known packer' if name in self.PACKER_SECTIONS else '')
                )
            ))
        
        # 导入表
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8', errors='ignore')
                funcs = []
                susp_funcs = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        funcs.append(func_name)
                        if func_name in self.SUSPICIOUS_APIS:
                            susp_funcs.append(func_name)
                imports.append(ImportInfo(dll=dll, functions=funcs, suspicious_functions=susp_funcs))
        
        # 导出表
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(ExportInfo(name=exp.name.decode('utf-8', errors='ignore')))
        
        # 资源
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                try:
                    rid = getattr(resource_type, 'id', None)
                    rname = getattr(resource_type, 'name', None)
                    type_name = str(rname) if rname else pefile.RESOURCE_TYPE.get(rid, f"Unknown({rid})") if rid else 'Unknown'
                except Exception:
                    type_name = 'Unknown'
                if not hasattr(resource_type, 'directory') or not resource_type.directory:
                    continue
                for entry in (resource_type.directory.entries if resource_type.directory else []):
                    try:
                        if not hasattr(entry, 'directory') or not entry.directory:
                            continue
                        data_entries = entry.directory.entries
                        for data_entry in data_entries:
                            try:
                                if not hasattr(data_entry, 'data') or not data_entry.data:
                                    continue
                                entry_name = ''
                                if hasattr(entry, 'name') and entry.name:
                                    entry_name = str(entry.name)
                                elif hasattr(entry, 'id') and entry.id is not None:
                                    entry_name = str(entry.id)
                                lang = getattr(data_entry.data, 'lang', 0)
                                offset = getattr(data_entry.struct, 'OffsetToData', 0) if hasattr(data_entry, 'struct') else 0
                                size = getattr(data_entry.data.struct, 'Size', 0) if hasattr(data_entry.data, 'struct') else 0
                                resources.append(ResourceInfo(
                                    type=type_name or '',
                                    name=entry_name or '',
                                    size=size if isinstance(size, int) else 0,
                                    language=lang if isinstance(lang, int) else 0,
                                    offset=offset if isinstance(offset, int) else 0,
                                    is_executable=bool(type_name in ('RT_ICON', 'RT_CURSOR', 'RT_BITMAP'))
                                ))
                            except Exception:
                                pass
                    except Exception:
                        pass
        
        # TLS 回调
        tls_callbacks = []
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
            if pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
                tls_callbacks.append(hex(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks))
        
        # 数字签名 — 提取签名者信息 + 签名有效性 + 签名链 (CA/有效期/吊销)
        # ⚠ 用 PowerShell Get-AuthenticodeSignature 判定 (比 pefile 安全目录可靠:
        #   部分系统文件 pefile 解析不到安全目录, PS 查证书存储总能有状态)
        signature = {'has_signature': False, 'signer': '', 'valid': False}
        try:
            chain = self._extract_signature_chain(self.file_path)
            if chain and chain.get('status'):
                sig_status = chain['status']
                signature['status'] = sig_status
                if sig_status != 'NotSigned':
                    signature['has_signature'] = True
                    signature['valid'] = (sig_status == 'Valid')
                    signature['signer'] = chain.get('signer', '')
                    signature['issuer'] = chain.get('issuer', '')
                    signature['serial'] = chain.get('serial', '')
                    signature['not_before'] = chain.get('not_before', '')
                    signature['not_after'] = chain.get('not_after', '')
                    signature['chain_valid'] = chain.get('chain_valid', False)
                    signature['chain_status'] = chain.get('chain_status', '')
                else:
                    signature['has_signature'] = False
                    signature['status'] = 'NotSigned'
        except Exception:
            pass
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and pe.DIRECTORY_ENTRY_SECURITY and not signature.get('has_signature'):
            # 兜底: 有证书表但 PS 无状态 → 至少标记有签名
            signature['has_signature'] = True
            signature['status'] = signature.get('status') or 'Present'
        
        # .NET 检测
        is_dotnet = False
        if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
            is_dotnet = True
        
        # 可疑特征检测
        suspicious = []
        if ts_anomalies:
            suspicious.append(' | '.join(ts_anomalies))
        # ⚠ patch 免杀核心特征: 签名存在但 HashMismatch/UnknownError =
        # 知名软件(如腾讯QQ浏览器)被二进制修改后注入恶意代码 —
        # 杀软按白名单放过, 是三年 VT 全绿的关键!
        if signature.get('has_signature') and not signature.get('valid'):
            suspicious.append(
                f"数字签名损坏/被篡改 (status={signature.get('status', '?')}) — 疑似白程序被patch免杀")
        total_entropy = max((s.get_entropy() for s in pe.sections), default=0) if pe.sections else 0
        if total_entropy > 7.5:
            suspicious.append("High entropy (possible packing/encryption)")
        
        for s in sections:
            if s.name.lower() in self.PACKER_SECTIONS:
                suspicious.append(f"Known packer section: {s.name}")
        
        if not imports:
            suspicious.append("No imports (possibly packed)")
        
        if tls_callbacks:
            suspicious.append("TLS callbacks present")
        
        # 加壳检测
        packer_info = []
        total_imported = sum(len(imp.functions) for imp in imports) if imports else 0
        if imports and len(imports) <= 2 and total_imported <= 5 and total_entropy > 6.5:
            packer_info.append(f"Packed: only {total_imported} imports from {len(imports)} DLL(s)")
        
        # RICH Header
        rich_header = {}
        if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER:
            rich_header = {
                'valid': True,
                'entries': len(pe.RICH_HEADER.values) // 2 if pe.RICH_HEADER.values else 0
            }
        
        # Overlay
        overlay = {}
        if pe.get_overlay_data_start_offset():
            overlay = {
                'offset': pe.get_overlay_data_start_offset(),
                'size': len(pe.get_overlay()) if pe.get_overlay() else 0
            }
        
        pe_info = PEInfo(
            is_pe=True,
            is_dll=is_dll,
            is_exe=is_exe,
            is_dotnet=is_dotnet,
            architecture=architecture,
            compile_time=compile_time,
            entry_point=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            image_base=hex(pe.OPTIONAL_HEADER.ImageBase),
            subsystem=str(pe.OPTIONAL_HEADER.Subsystem),
            sections=sections,
            imports=imports,
            exports=exports,
            resources=resources,
            tls_callbacks=tls_callbacks,
            digital_signature=signature,
            suspicious_features=suspicious,
            packer_info=packer_info,
            rich_header=rich_header,
            overlay=overlay,
            imphash=pe.get_imphash() if hasattr(pe, 'get_imphash') else ''
        )
        
        return pe_info
    
    def _analyze_with_lief(self) -> Optional[PEInfo]:
        """使用 lief 分析（备用）"""
        try:
            binary = lief.parse(self.file_path)
        except Exception as e:
            logger.warning(f"LIEF 解析失败: {e}")
            return None
        if not binary or not hasattr(binary, 'header'):
            return None
        
        try:
            is_pe = hasattr(binary, 'sections') and hasattr(binary.header, 'machine')
            architecture = ''
            try:
                machine = binary.header.machine
                arch_map = {0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'ARM64'}
                if isinstance(machine, int):
                    architecture = arch_map.get(machine, f'Unknown(0x{machine:04x})')
                else:
                    architecture = str(machine).split('.')[-1] if hasattr(machine, 'name') else str(machine)
            except:
                pass
            
            entry_point = ''
            try:
                entry_point = hex(binary.entrypoint) if binary.entrypoint else ''
            except:
                pass
            
            image_base = ''
            try:
                image_base = hex(binary.optional_header.imagebase) if binary.optional_header else ''
            except:
                pass
            
            sections = []
            if hasattr(binary, 'sections'):
                for sec in binary.sections:
                    try:
                        sections.append(SectionInfo(
                            name=sec.name,
                            virtual_address=hex(sec.virtual_address),
                            virtual_size=sec.virtual_size,
                            raw_size=len(sec.content) if hasattr(sec, 'content') and sec.content else 0,
                            raw_offset=sec.pointerto_raw_data if hasattr(sec, 'pointerto_raw_data') else 0,
                            entropy=round(sec.entropy, 4) if hasattr(sec, 'entropy') else 0.0,
                            characteristics=hex(sec.characteristics) if hasattr(sec, 'characteristics') else ''
                        ))
                    except:
                        pass
            
            return PEInfo(
                is_pe=is_pe,
                is_dll=binary.is_dll if hasattr(binary, 'is_dll') else False,
                architecture=architecture,
                entry_point=entry_point,
                image_base=image_base,
                sections=sections
            )
        except Exception as e:
            logger.warning(f"LIEF 分析异常: {e}")
            return None
