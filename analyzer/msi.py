#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MSI 安装包分析引擎
"""
import os
import sys
import subprocess
from typing import List, Dict

from logger import get_logger

logger = get_logger('analyzer.msi')

msilib = None
try:
    import msilib as _msilib
    msilib = _msilib
except ImportError:
    pass

olefile = None
try:
    import olefile as _olefile
    olefile = _olefile
except ImportError:
    pass


class MSIAnalyzer:
    """MSI 分析器"""
    
    OLE2_MAGIC = bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
    
    SUSPICIOUS_ACTIONS = [
        'cmd.exe', 'powershell', 'wscript', 'cscript', 'mshta',
        'rundll32', 'regsvr32', 'certutil', 'bitsadmin', 'schtasks',
        'sc.exe', 'net.exe', 'wmic.exe', 'msiexec',
    ]
    
    def is_msi(self, file_path: str) -> bool:
        """检测是否为 MSI"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
            return header == self.OLE2_MAGIC or file_path.lower().endswith('.msi')
        except:
            return False
    
    def extract_files(self, file_path: str, output_dir: str) -> List[str]:
        """提取嵌入文件"""
        extracted = []
        if not sys.platform.startswith('win'):
            return extracted
        
        # msiexec /a
        try:
            subprocess.run(
                ['msiexec', '/a', file_path, '/qn', f'TARGETDIR={output_dir}'],
                capture_output=True, timeout=30, creationflags=0x08000000
            )
            for root, _, files in os.walk(output_dir):
                for f in files:
                    fpath = os.path.join(root, f)
                    if fpath != file_path and os.path.getsize(fpath) > 2:
                        extracted.append(fpath)
        except Exception as e:
            logger.error(f"msiexec 提取失败: {e}")
        
        return extracted
    
    def analyze_custom_actions(self, file_path: str) -> Dict:
        """分析自定义动作"""
        actions = {'total': 0, 'suspicious': [], 'all_actions': [], 'scripts': [], 'errors': []}
        
        if not msilib:
            actions['errors'].append('msilib 不可用')
            return actions
        
        db = None
        try:
            db = msilib.OpenDatabase(file_path, 0)
            for table, columns in [('CustomAction', 'Action, Type, Source, Target')]:
                try:
                    view = db.OpenView(f"SELECT {columns} FROM {table}")
                    view.Execute(None)
                    rec = view.Fetch()
                    while rec:
                        try:
                            action_name = rec.GetString(1) or ''
                            action_type = 0
                            try:
                                action_type = rec.GetInteger(2) if not rec.IsNull(2) else 0
                            except:
                                pass
                            source = rec.GetString(3) or ''
                            target = rec.GetString(4) or ''
                            
                            actions['total'] += 1
                            detail = {'name': action_name, 'type': action_type, 'source': source, 'target': target}
                            actions['all_actions'].append(detail)
                            
                            combined = f'{source} {target}'.lower()
                            if any(kw in combined for kw in self.SUSPICIOUS_ACTIONS):
                                actions['suspicious'].append(detail)
                            if action_type in (38, 50, 54):
                                type_names = {38: 'VBScript', 50: 'JavaScript', 54: 'PowerShell'}
                                detail['script_type'] = type_names.get(action_type, f'Script({action_type})')
                                actions['scripts'].append(detail)
                        except:
                            pass
                        rec = view.Fetch()
                except Exception as e:
                    actions['errors'].append(str(e))
        except Exception as e:
            actions['errors'].append(f'MSI 打开失败: {e}')
        finally:
            if db is not None:
                try:
                    db.Close()
                except:
                    pass
        
        return actions
    
    def analyze_registry_changes(self, file_path: str) -> List[Dict]:
        """分析注册表修改"""
        reg_changes = []
        if not msilib:
            return reg_changes
        
        db = None
        try:
            db = msilib.OpenDatabase(file_path, 0)
            for table in ['Registry']:
                try:
                    view = db.OpenView(f"SELECT * FROM {table}")
                    view.Execute(None)
                    rec = view.Fetch()
                    while rec:
                        try:
                            root = rec.GetString(1) or ''
                            key = rec.GetString(2) or ''
                            name = rec.GetString(3) or ''
                            value = rec.GetString(4) or ''
                            root_map = {'0': 'HKCR', '1': 'HKCU', '2': 'HKLM', '3': 'HKU'}
                            reg_changes.append({
                                'root': root_map.get(str(root), str(root)),
                                'key': key, 'name': name, 'value': value[:200]
                            })
                        except:
                            pass
                        rec = view.Fetch()
                except:
                    pass
        except:
            pass
        finally:
            if db is not None:
                try:
                    db.Close()
                except:
                    pass
        
        return reg_changes
