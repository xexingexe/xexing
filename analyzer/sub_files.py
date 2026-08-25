#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
子文件/嵌入文件分析引擎 — 提取 PE 中的资源、证书、版本信息等
"""
import hashlib

from logger import get_logger
from analyzer.models import SubFileAnalysis

logger = get_logger('analyzer.sub_files')

pefile = None
try:
    import pefile as _pefile
    pefile = _pefile
except ImportError:
    pass


class SubFileAnalyzer:
    """子文件分析器"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
    
    def analyze(self) -> SubFileAnalysis:
        """分析嵌入文件"""
        result = SubFileAnalysis(parent_file=self.file_path)
        
        if not pefile:
            logger.warning("pefile 未安装，跳过子文件分析")
            return result
        
        pe = None
        try:
            pe = pefile.PE(self.file_path)
            
            # 资源提取
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    res_type = str(entry.name) if entry.name else f"Type({entry.id})"
                    for res in entry.directory.entries if hasattr(entry, 'directory') else []:
                        for res_lang in res.directory.entries if hasattr(res, 'directory') else []:
                            try:
                                data = pe.get_data(res_lang.data.struct.OffsetToData, res_lang.data.struct.Size)
                                if data:
                                    result.embedded_resources.append({
                                        'type': res_type,
                                        'size': len(data),
                                        'md5': hashlib.md5(data).hexdigest(),
                                        'offset': res_lang.data.struct.OffsetToData
                                    })
                            except:
                                pass
            
            # 版本信息
            if hasattr(pe, 'VS_VERSIONINFO'):
                for entry in pe.VS_VERSIONINFO:
                    try:
                        if hasattr(entry, 'StringTable'):
                            for st in entry.StringTable:
                                for key, value in st.entries.items():
                                    key_str = key.decode('utf-8', errors='ignore') if isinstance(key, bytes) else str(key)
                                    val_str = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else str(value)
                                    result.version_info[key_str] = val_str
                    except:
                        pass
            
            # 证书
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                for entry in pe.DIRECTORY_ENTRY_SECURITY:
                    try:
                        data = pe.get_data(entry.VirtualAddress, entry.Size)
                        result.certificate_data = {
                            'size': len(data),
                            'md5': hashlib.md5(data).hexdigest() if data else ''
                        }
                    except:
                        pass
            
            # Overlay 数据
            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset:
                with open(self.file_path, 'rb') as f:
                    f.seek(overlay_offset)
                    # overlay 限制 5MB，大文件不卡
                    overlay_data = f.read(5 * 1024 * 1024)
                result.overlay_data = {
                    'offset': overlay_offset,
                    'size': len(overlay_data),
                    'md5': hashlib.md5(overlay_data).hexdigest(),
                    'entropy': 0.0
                }
        except Exception as e:
            if 'DOS Header' in str(e) or 'PE' in str(e) or 'truncated' in str(e):
                logger.info(f"子文件分析: 非 PE 文件，跳过 ({e})")
            else:
                logger.error(f"子文件分析失败: {e}")
        finally:
            if pe is not None:
                try:
                    pe.close()
                except:
                    pass
        
        result.summary = f"提取 {len(result.embedded_resources)} 个资源, {len(result.version_info)} 个版本信息项"
        return result
