#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
脚本分析引擎 — 检测恶意 VBS/JS/PS1/BAT/HTA 等
"""
import re
import os
from logger import get_logger
from analyzer.models import ScriptAnalysis

logger = get_logger('analyzer.script')


class ScriptAnalyzer:
    """脚本分析器"""
    
    MALICIOUS_PATTERNS = [
        (r'(Invoke-WebRequest|Invoke-RestMethod|wget|curl|bitsadmin|Start-BitsTransfer).*\.(exe|dll|scr|msi|bat|ps1|vbs)', '下载执行'),
        (r'(new-object\s+Net\.WebClient).*\.(DownloadFile|DownloadString)', 'PowerShell 下载'),
        (r'(WinHttp|MSXML2\.XMLHTTP|MSXML2\.ServerXMLHTTP).*\.(open|send)', 'HTTP 请求'),
        (r'(VirtualAlloc|CreateThread|WriteProcessMemory|NtCreateThreadEx)', '进程注入'),
        (r'\[System\.Runtime\.InteropServices\.Marshal\]::Copy', '内存拷贝(可能注入)'),
        (r'(HKLM|HKCU).*(Run|RunOnce|Services|Winlogon)', '注册表持久化'),
        (r'New-Service|sc\.exe\s+create|schtasks\s+/create', '服务/计划任务创建'),
        (r'(WScript\.Sleep|Start-Sleep)\s+\d{4,}', '长时间延迟(反沙箱)'),
        (r'Get-WmiObject\s+Win32_ComputerSystem.*Manufacturer|Model', 'VM检测'),
        (r'VBox|VMware|VirtualBox|Xen|QEMU|Hyper-V', '虚拟机检测'),
        (r'(eval|execScript|Execute|Invoke-Expression|IEX)\s*\(', '动态代码执行'),
        (r'FromBase64String\(.*\)', 'Base64 解码执行'),
        (r'-enc(odedCommand)?\s+[A-Za-z0-9+/=]{50,}', 'PowerShell 编码命令'),
        (r'(Get-ExecutionPolicy|Set-ExecutionPolicy)\s+-Scope', '修改执行策略'),
        (r'Start-Process\s+-Verb\s+RunAs', '提权执行'),
        (r'SeBackupPrivilege|SeDebugPrivilege|SeTakeOwnershipPrivilege', '特权提升'),
        (r'(del\s+/f|rmdir\s+/s|Remove-Item\s+-Recurse)', '强制删除'),
        (r'(takeown|icacls)\s+/f.*\/grant', '文件权限篡改'),
        (r'CreateObject\s*\(\s*["\']WScript\.Shell', 'WScript Shell 对象'),
        (r'ActiveXObject\s*\(\s*["\']', 'ActiveX 对象'),
        (r'ShellExecute|Run\s+["\']', 'Shell 执行'),
        (r'reg\s+(add|delete|import)', '注册表操作'),
        (r'net\s+(user|localgroup|start|stop)', 'Net 命令'),
        (r'at\s+\\|schtasks', '计划任务'),
        (r'certutil\s+-encode|certutil\s+-decode', 'CertUtil 编码'),
        (r'mshta\s+javascript|mshta\s+vbscript', 'Mshta 执行脚本'),
        (r'rundll32\s+javascript|rundll32\s+vbscript', 'Rundll32 执行脚本'),
    ]
    
    SCRIPT_TYPES = {
        '.vbs': 'VBScript', '.vbe': 'VBScript (Encoded)',
        '.js': 'JavaScript', '.jse': 'JavaScript (Encoded)',
        '.ps1': 'PowerShell', '.psm1': 'PowerShell Module',
        '.bat': 'Batch', '.cmd': 'Batch',
        '.hta': 'HTML Application',
        '.wsf': 'Windows Script', '.wsh': 'Windows Script Host',
        '.py': 'Python', '.pyw': 'Python',
        '.sh': 'Shell', '.bash': 'Bash',
    }
    
    def is_script(self, file_path: str) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.SCRIPT_TYPES
    
    def analyze(self, file_path: str) -> ScriptAnalysis:
        """分析脚本文件"""
        result = ScriptAnalysis(
            script_type='unknown',
            detections=[],
            suspicious_lines=[],
            risk_score=0,
            has_obfuscation=False,
            obfuscation_type='',
            encoding_layers=0,
            embedded_files=[],
            embedded_urls=[],
        )
        
        ext = os.path.splitext(file_path)[1].lower()
        result.script_type = self.SCRIPT_TYPES.get(ext, 'Unknown Script')
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            try:
                with open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                    content = f.read()
            except:
                return result
        
        lines = content.split('\n')
        
        # 混淆检测
        if len(lines) < 5 and len(content) > 500:
            result.has_obfuscation = True
            result.obfuscation_type = '高度混淆 (单行/少量行)'
            result.detections.append('高度混淆 (单行/少量行)')
            result.risk_score += 20

        # 扩充混淆检测：长行数中的超长行
        long_line_ratio = sum(1 for l in lines if len(l) > 500) / max(len(lines), 1)
        if long_line_ratio > 0.3 and len(content) > 2000:
            result.has_obfuscation = True
            if not result.obfuscation_type:
                result.obfuscation_type = '超长行混淆'
            result.detections.append(f'超长行混淆 ({long_line_ratio*100:.0f}% 的行超过500字符)')
            result.risk_score += 15
        
        b64_count = len(re.findall(r'[A-Za-z0-9+/=]{100,}', content))
        if b64_count > 0:
            result.has_obfuscation = True
            result.obfuscation_type = 'Base64 编码' if not result.obfuscation_type else result.obfuscation_type + ' + Base64'
            result.detections.append(f'含 Base64 编码块 ({b64_count} 处)')
            result.risk_score += 15
        
        if re.search(r'charCodeAt|String\.fromCharCode|chr\(|Chr\(', content):
            result.has_obfuscation = True
            result.obfuscation_type = '字符编码混淆' if not result.obfuscation_type else result.obfuscation_type
            result.detections.append('字符编码混淆')
            result.risk_score += 10
        
        # URL 提取
        urls = re.findall(r'https?://[^\s<>"{}|\^`\[\]]+', content)
        result.embedded_urls = list(set(urls))[:20]
        
        # 模式匹配
        for pattern, desc in self.MALICIOUS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_no = content[:match.start()].count('\n') + 1
                snippet = match.group(0)[:120]
                result.detections.append(f'[{desc}] L{line_no}: {snippet}')
                result.suspicious_lines.append({
                    'line': line_no,
                    'pattern': desc,
                    'snippet': snippet,
                })
                result.risk_score += 5
        
        result.risk_score = min(result.risk_score, 100)
        result.summary = f"检测到 {len(result.detections)} 个恶意指标，风险评分 {result.risk_score}/100"
        
        return result
