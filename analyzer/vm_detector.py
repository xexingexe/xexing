#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
虚拟机环境检测器 — 检测是否运行在隔离环境（VM / Windows Sandbox / Docker）
用于防止用户在真实宿主机上误运行恶意样本
"""
import os
import sys
import re
from typing import Dict
from logger import get_logger

logger = get_logger('analyzer.vm_detector')


class VMDetector:
    """虚拟机/隔离环境检测器"""

    # 已知 VM 进程
    VM_PROCESSES = [
        'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe', 'vmacthlp.exe',
        'vboxservice.exe', 'vboxtray.exe', 'vboxguest.exe',
        'qemu-ga.exe', 'xenservice.exe', 'virtray.exe',
        'prl_tools.exe', 'prl_tools_service.exe',  # Parallels
        'vmusrvc.exe', 'vmsrvc.exe',  # 旧版 VMware
    ]

    # 已知 VM 文件/驱动（去重版）
    VM_FILES = [
        # VMware
        r'C:\Windows\System32\drivers\vmci.sys',
        r'C:\Windows\System32\drivers\vmhgfs.sys',
        r'C:\Windows\System32\drivers\vmmouse.sys',
        r'C:\Windows\System32\drivers\vmscsi.sys',
        r'C:\Windows\System32\drivers\vmusbmouse.sys',
        r'C:\Windows\System32\drivers\vmx_svga.sys',
        r'C:\Windows\System32\drivers\vmxnet.sys',
        r'C:\Windows\System32\drivers\vmx86.sys',
        r'C:\Windows\System32\drivers\vmrawdisk.sys',
        r'C:\Windows\System32\drivers\vmmemctl.sys',
        r'C:\Windows\System32\drivers\vmsrvc.sys',
        r'C:\Windows\System32\drivers\vmusrvc.sys',
        # VirtualBox
        r'C:\Windows\System32\drivers\vboxguest.sys',
        r'C:\Windows\System32\drivers\vboxmouse.sys',
        r'C:\Windows\System32\drivers\vboxsf.sys',
        r'C:\Windows\System32\drivers\vboxvideo.sys',
        r'C:\Windows\System32\drivers\VBoxMouse.sys',
        r'C:\Windows\System32\drivers\VBoxGuest.sys',
        r'C:\Windows\System32\drivers\VBoxSF.sys',
        r'C:\Windows\System32\drivers\VBoxVideo.sys',
    ]

    # VM MAC 地址前缀
    VM_MAC_PREFIXES = [
        '00:50:56', '00:0c:29', '00:05:69',  # VMware
        '08:00:27', '0a:00:27',  # VirtualBox
        '52:54:00',  # QEMU/KVM
        '00:16:3e',  # Xen
        '00:1c:42',  # Parallels
    ]

    # VM BIOS 字符串
    VM_BIOS_STRINGS = [
        'VMware', 'VirtualBox', 'KVM', 'Xen', 'Parallels',
        'innotek GmbH',  # VirtualBox
        'Microsoft Hv',  # Hyper-V VM
    ]

    def __init__(self):
        self.results = {
            'is_vm': False,
            'is_windows_sandbox': False,
            'is_docker': False,
            'is_hyperv': False,
            'evidence': [],
            'risk_level': 'unknown',  # safe, vm, sandbox, unknown, dangerous
        }
        self._cached_detect = None

    def detect(self) -> Dict:
        """Execute full detection with weighted evidence scoring"""
        if self._cached_detect is not None:
            return self._cached_detect
        self.results = {
            'is_vm': False,
            'is_windows_sandbox': False,
            'is_docker': False,
            'is_hyperv': False,
            'evidence': [],
            'risk_level': 'unknown',
        }

        self._check_processes()
        self._check_files()
        self._check_registry()
        self._check_mac_addresses()
        self._check_bios()
        self._check_windows_sandbox()
        self._check_docker()
        self._check_hyperv()
        self._check_memory()
        self._check_cpu_features()

        evidence = self.results['evidence']

        # Weighted scoring: different evidence types have different reliability
        file_evidence = [e for e in evidence if 'file' in e]
        mac_evidence = [e for e in evidence if 'mac' in e]
        process_evidence = [e for e in evidence if 'process' in e]
        registry_evidence = [e for e in evidence if 'registry' in e]
        bios_evidence = [e for e in evidence if 'bios' in e]
        memory_evidence = [e for e in evidence if 'memory' in e]

        # Score calculation (max 100)
        score = 0
        score += len(file_evidence) * 12       # driver files present
        score += len(mac_evidence) * 18        # VM MAC addresses
        score += len(process_evidence) * 15    # VM processes running
        score += len(registry_evidence) * 10   # VM registry keys
        score += len(bios_evidence) * 25       # BIOS strings (strong signal)
        score += len(memory_evidence) * 10     # low memory/CPU cores

        # False positive mitigation: drivers alone without process/mac/bios = weak
        if file_evidence and not (process_evidence or mac_evidence or bios_evidence):
            score = max(0, score - 20)
            logger.info(f"[VM] 仅检测到驱动文件 (得分={score}), 可能宿主机安装了 VM 软件")

        # Physical host with VMware installed: files + MAC but no processes/BIOS = likely host
        if file_evidence and mac_evidence and not (process_evidence or bios_evidence):
            score = max(0, score - 15)
            logger.info(f"[VM] 驱动+VM MAC但无进程/BIOS证据 (得分={score}), 可能是宿主机安装了VMware")

        # Registry keys that exist on physical Win10/11 with Hyper-V enabled
        hyperv_reg_only = [e for e in registry_evidence if 'hyperv' in e.lower() and 'Running' not in e]
        if hyperv_reg_only and not (process_evidence or mac_evidence or bios_evidence):
            score = max(0, score - 15)
            logger.info(f"[VM] Hyper-V 注册表键 (得分={score}), Win10+默认存在, 不足以判定 VM")

        if score >= 50:
            self.results['is_vm'] = True
            self.results['evidence'].append(f'[score] VM 证据得分: {score}/100')
        elif score >= 25:
            self.results['evidence'].append(f'[score] 弱VM证据得分: {score}/100 (不足以判定)')
            self.results['is_vm'] = False
        else:
            self.results['is_vm'] = False

        # Risk level determination
        # ⚠ 安全边界: 物理机必须判 dangerous (动态分析将因此被禁用)
        #   is_hyperv 已收紧(仅 baseboard=Virtual Machine 才标记), 但保险起见
        #   仍要求 is_hyperv 需配合 is_vm 证据, 防止误放行动态执行
        if self.results['is_windows_sandbox'] or self.results['is_docker']:
            self.results['risk_level'] = 'safe'
        elif self.results['is_vm']:
            self.results['risk_level'] = 'vm'
        elif self.results['is_hyperv']:
            # 有 Hyper-V VM 特征但无常规 VM 证据 — 保守按危险处理
            self._add_evidence('hyperv', 'Hyper-V 特征但无 VM 证据 — 保守按物理机处理')
            self.results['risk_level'] = 'dangerous'
        else:
            self.results['risk_level'] = 'dangerous'

        self._cached_detect = dict(self.results)
        return self.results

    def _add_evidence(self, category: str, detail: str):
        self.results['evidence'].append(f"[{category}] {detail}")
        logger.debug(f"VM detection: {category} - {detail}")

    def _check_processes(self):
        """检查 VM 进程"""
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                name = proc.info['name'].lower() if proc.info['name'] else ''
                for vm_proc in self.VM_PROCESSES:
                    if name == vm_proc.lower():
                        self.results['is_vm'] = True
                        self._add_evidence('process', f"Found {vm_proc} (PID={proc.info['pid']})")
        except ImportError:
            # 没有 psutil，使用 tasklist
            try:
                import subprocess
                result = subprocess.run(['tasklist', '/fo', 'csv'], capture_output=True, text=True, errors='ignore')
                output = result.stdout.lower()
                for vm_proc in self.VM_PROCESSES:
                    if vm_proc.lower() in output:
                        self.results['is_vm'] = True
                        self._add_evidence('process', f"Found {vm_proc}")
            except:
                pass

    def _check_files(self):
        """检查 VM 驱动是否已加载运行（不只是文件存在 — 残留文件不应误报）"""
        # 先获取已加载驱动列表
        loaded_drivers = set()
        try:
            import subprocess
            result = subprocess.run(
                ['driverquery', '/fo', 'csv'],
                capture_output=True, text=True, errors='ignore', timeout=15
            )
            for line in result.stdout.split('\n'):
                parts = line.strip('"').split('","')
                if parts and parts[0].strip():
                    loaded_drivers.add(parts[0].strip().lower())
        except Exception:
            pass

        # 如果 driverquery 拿不到结果，尝试 sc query
        if not loaded_drivers:
            try:
                import subprocess
                result = subprocess.run(
                    ['sc', 'query', 'type=', 'driver', 'state=', 'all'],
                    capture_output=True, text=True, errors='ignore', timeout=15
                )
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('SERVICE_NAME:'):
                        name = line.split(':', 1)[1].strip().lower()
                        loaded_drivers.add(name)
            except Exception:
                pass

        for f in self.VM_FILES:
            if not os.path.exists(f):
                continue

            driver_name = os.path.splitext(os.path.basename(f))[0].lower()

            # 如果拿到了驱动列表，检查驱动是否在运行；否则 fallback 到文件存在即 VM
            if loaded_drivers:
                if driver_name in loaded_drivers:
                    self.results['is_vm'] = True
                    self._add_evidence('file', f"VM driver loaded: {os.path.basename(f)}")
                else:
                    self._add_evidence('file', f"VM driver residue (not loaded): {os.path.basename(f)}")
            else:
                # 无法确认驱动是否在运行，仅记录为低置信度线索
                self._add_evidence('file', f"VM driver file found (unconfirmed): {os.path.basename(f)}")

    def _check_registry(self):
        """检查注册表 VM 标识"""
        if sys.platform != 'win32':
            return
        try:
            import winreg
            keys = [
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\VMware, Inc.\VMware Tools'),
                (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\VBoxGuest'),
                (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\VBoxMouse'),
                (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\VBoxSF'),
                (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\VBoxVideo'),
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Oracle\VirtualBox Guest Additions'),
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\ACPI\DSDT\VBOX__'),
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\ACPI\FADT\VBOX__'),
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\ACPI\RSDT\VBOX__'),
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\ACPI\DSDT\VMWARE'),
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\ACPI\FADT\VMWARE'),
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\ACPI\RSDT\VMWARE'),
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0',
                 'Identifier', 'VBOX'),  # VBOX HDD
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0',
                 'Identifier', 'VMware'),  # VMware HDD
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\BIOS',
                 'SystemProductName', 'Virtual'),  # Generic virtual
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\BIOS',
                 'SystemManufacturer', 'VMware'),
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\BIOS',
                 'SystemProductName', 'VMware'),
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\BIOS',
                 'SystemManufacturer', 'innotek GmbH'),
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\BIOS',
                 'SystemProductName', 'VirtualBox'),
                # 只有同时满足 Manufacturer=Microsoft 且 Product=Virtual Machine 才判为 VM
                # (避免误报 Surface 等 Microsoft 制造商设备)
                (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\BIOS',
                 'SystemProductName', 'HVM domU'),
            ]
            for item in keys:
                try:
                    if len(item) == 2:
                        hkey, subkey = item
                        key = winreg.OpenKey(hkey, subkey)
                        winreg.CloseKey(key)
                        self.results['is_vm'] = True
                        self._add_evidence('registry', f"VM registry key: {subkey}")
                    elif len(item) == 4:
                        hkey, subkey, value_name, check_value = item
                        key = winreg.OpenKey(hkey, subkey)
                        val, _ = winreg.QueryValueEx(key, value_name)
                        winreg.CloseKey(key)
                        if isinstance(val, str) and check_value.lower() in val.lower():
                            self.results['is_vm'] = True
                            self._add_evidence('registry', f"VM BIOS value: {val}")
                except:
                    pass
            # 组合检测：仅当同时满足 Manufacturer=Microsoft AND Product=Virtual Machine 才判 VM
            # 单独匹配 "Microsoft Corporation" 会误报 Surface 等物理设备
            try:
                mfg_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r'HARDWARE\DESCRIPTION\System\BIOS'
                )
                mfg_val, _ = winreg.QueryValueEx(mfg_key, 'SystemManufacturer')
                prod_val, _ = winreg.QueryValueEx(mfg_key, 'SystemProductName')
                winreg.CloseKey(mfg_key)
                if ('microsoft' in str(mfg_val).lower() and
                    'virtual' in str(prod_val).lower()):
                    self.results['is_vm'] = True
                    self._add_evidence('registry', f'Hyper-V VM BIOS: {mfg_val} / {prod_val}')
            except:
                pass

        except Exception as e:
            logger.debug(f"Registry check failed: {e}")

    def _check_mac_addresses(self):
        """检查 MAC 地址 — 只检查主网卡（排除 VMnet 等虚拟适配器的宿主残留）"""
        try:
            import psutil

            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:
                        mac = addr.address.lower().replace('-', ':')
                        for prefix in self.VM_MAC_PREFIXES:
                            if mac.startswith(prefix.lower()):
                                # 检查是否是 VMnet 虚拟适配器名
                                if_name_lower = interface.lower()
                                is_vmnet = any(k in if_name_lower for k in [
                                    'vmnet', 'virtualbox', 'vbox', 'vEthernet',
                                    'hyper-v', 'docker', 'wsl', 'vpn', 'tunnel'
                                ])
                                if is_vmnet:
                                    self._add_evidence('mac', f"VM MAC on virtual adapter '{interface}': {addr.address} (ignored)")
                                    continue
                                self.results['is_vm'] = True
                                self._add_evidence('mac', f"VM MAC on main interface '{interface}': {addr.address}")
        except Exception:
            pass

    @staticmethod
    def _query_win(cmd_list: list, timeout: int = 5) -> str:
        """Windows 系统信息查询兼容层

        Win11 24H2 已移除 wmic.exe — 查询失败自动降级 PowerShell CIM
        (wmic 若可用则优先, 输出格式保持 WMI 风格 key=value)
        """
        if sys.platform != 'win32':
            return ''
        import subprocess
        try:
            r = subprocess.run(cmd_list, capture_output=True, text=True,
                               errors='ignore', timeout=timeout)
            if r.returncode == 0 and r.stdout and r.stdout.strip():
                return r.stdout
        except Exception:
            pass
        # 降级: PowerShell CIM (Win11 24H2+ 无 wmic)
        try:
            _class_map = {'computersystem': 'Win32_ComputerSystem',
                          'bios': 'Win32_BIOS', 'baseboard': 'Win32_BaseBoard'}
            _cls = _class_map.get(cmd_list[1].lower() if len(cmd_list) > 1 else '',
                                  'Win32_ComputerSystem')
            _props = [x for x in cmd_list[3:] if not x.startswith('/')]
            _ps = f'Get-CimInstance {_cls}'
            if _props:
                _ps += ' | Format-List ' + ','.join(_props)
            r = subprocess.run(['powershell', '-NoProfile', '-Command', _ps],
                               capture_output=True, text=True, errors='ignore',
                               timeout=timeout)
            if r.returncode == 0 and r.stdout and r.stdout.strip():
                return r.stdout
        except Exception:
            pass
        return ''

    def _check_bios(self):
        """通过 WMI/CIM 检查 BIOS 信息 (Win11 24H2 无 wmic, 自动降级)"""
        if sys.platform != 'win32':
            return
        try:
            # SystemManufacturer
            output = self._query_win(
                ['wmic', 'computersystem', 'get', 'manufacturer', '/value'])
            for s in self.VM_BIOS_STRINGS:
                if s.lower() in output.lower():
                    self.results['is_vm'] = True
                    self._add_evidence('bios', f"VM manufacturer: {s}")

            # SystemProductName (model)
            output = self._query_win(
                ['wmic', 'computersystem', 'get', 'model', '/value'])
            for s in self.VM_BIOS_STRINGS:
                if s.lower() in output.lower():
                    self.results['is_vm'] = True
                    self._add_evidence('bios', f"VM model: {s}")

            # BIOS SerialNumber
            output = self._query_win(
                ['wmic', 'bios', 'get', 'serialnumber', '/value']).strip()
            if 'vmware' in output.lower() or 'virtual' in output.lower():
                self.results['is_vm'] = True
                self._add_evidence('bios', f"VM BIOS serial: {output}")

        except Exception as e:
            logger.debug(f"BIOS check failed: {e}")

    def _check_windows_sandbox(self):
        """检测 Windows Sandbox"""
        # 1. 检查 WindowsSandbox.exe 是否存在
        ws_path = r'C:\Windows\System32\WindowsSandbox.exe'
        if os.path.exists(ws_path):
            self._add_evidence('windows_sandbox', 'WindowsSandbox.exe found')
        
        # 2. 检测是否在 Windows Sandbox 内部运行
        # Windows Sandbox 内部有一个特征注册表键
        if sys.platform == 'win32':
            try:
                import subprocess
                result = subprocess.run(
                    ['powershell', '-NoProfile', '-Command',
                     'Get-Process -Name "WindowsSandboxClient" -ErrorAction SilentlyContinue | Select-Object -First 1'],
                    capture_output=True, text=True, errors='ignore', timeout=5
                )
                if 'WindowsSandboxClient' in result.stdout:
                    self.results['is_windows_sandbox'] = True
                    self._add_evidence('process', 'WindowsSandboxClient.exe 运行中')
            except Exception:
                pass
            
            # 检查是否通过 CExecSvc (Windows Sandbox 执行服务) 运行
            try:
                import psutil
                for proc in psutil.process_iter(['name']):
                    if proc.info['name'] and 'CExecSvc' in proc.info['name']:
                        self.results['is_windows_sandbox'] = True
                        self._add_evidence('windows_sandbox', 'Running inside Windows Sandbox (CExecSvc detected)')
            except:
                pass
            
            # 检查设备名
            try:
                import subprocess
                # Win11 24H2 无 wmic — 用兼容层查询 (自动降级 CIM)
                out1 = self._query_win(['wmic', 'baseboard', 'get', 'manufacturer', '/value'])
                if 'Microsoft Corporation' in out1:
                    # 可能是 Sandbox 或 Hyper-V
                    out2 = self._query_win(['wmic', 'baseboard', 'get', 'product', '/value'])
                    if 'Virtual Machine' in out2 or 'Virtual' in out2:
                        self.results['is_windows_sandbox'] = True
                        self.results['is_hyperv'] = True
                        self._add_evidence('wmic', 'Microsoft Virtual Machine (Windows Sandbox or Hyper-V)')
                        self._add_evidence('windows_sandbox', 'Windows Sandbox baseboard detected')
            except:
                pass

    def _check_docker(self):
        """检测是否真正运行在 Docker 容器内部。

        ⚠ 宿主安装 Docker Desktop 很常见 — 仅凭安装键绝不能判为容器,
        否则物理机会被放行动态分析 (危险!)。只有容器内证据 (/.dockerenv,
        cgroup 含 docker) 才置 is_docker=True。
        """
        # 检查 /.dockerenv 文件
        if os.path.exists('/.dockerenv'):
            self.results['is_docker'] = True
            self._add_evidence('docker', '/.dockerenv found')
        
        # 检查 cgroup
        try:
            with open('/proc/1/cgroup', 'r') as f:
                content = f.read()
                if 'docker' in content:
                    self.results['is_docker'] = True
                    self._add_evidence('docker', 'Docker cgroup detected')
        except:
            pass
        
        # Windows Docker Desktop 安装键 — 只作为宿主线索记录, 不代表运行在容器内
        if sys.platform == 'win32':
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Docker Inc.\Docker Desktop')
                winreg.CloseKey(key)
                self._add_evidence('docker', 'Docker Desktop installed (host evidence only, NOT a container)')
            except:
                pass

    def _check_hyperv(self):
        """检测是否运行在 Hyper-V 虚拟机内部（不是检测宿主机是否开启 Hyper-V）"""
        if sys.platform != 'win32':
            return
        try:
            import subprocess

            # 先检查 HypervisorPresent（宿主机也可能为 TRUE）
            result = subprocess.run(
                ['wmic', 'computersystem', 'get', 'HypervisorPresent', '/value'],
                capture_output=True, text=True, errors='ignore', timeout=5
            )
            hyperv_host = 'TRUE' in result.stdout.upper()

            # 注意: 物理机启用 Hyper-V 角色时 vmbus/storvsc 等驱动同样存在,
            #       不能作为 VM 判定依据 — 仅凭 baseboard=Virtual Machine 判定
            result2 = subprocess.run(
                ['wmic', 'baseboard', 'get', 'product', '/value'],
                capture_output=True, text=True, errors='ignore', timeout=5
            )
            is_hv_vm = 'Virtual Machine' in result2.stdout

            if hyperv_host and is_hv_vm:
                # 确认在 Hyper-V 虚拟机内部 (baseboard = Virtual Machine)
                self.results['is_hyperv'] = True
                self._add_evidence('hyperv', 'Running inside Hyper-V VM')
            elif hyperv_host:
                # 宿主机开启了 Hyper-V，但我们在宿主机上运行（物理机常见！）
                # ⚠ 不标记 is_hyperv — 物理机启用 Hyper-V 角色时 vmbus/storvsc 驱动
                #   同样存在, 若据此放行动态分析会把恶意样本直接执行在物理机上
                self._add_evidence('hyperv', 'Hyper-V enabled on host (physical machine, NOT a VM)')
        except:
            pass

    def _check_memory(self):
        """检查内存大小（VM 通常内存较小）"""
        try:
            import psutil
            mem = psutil.virtual_memory()
            if mem.total < 2 * 1024 * 1024 * 1024:  # < 2GB
                self._add_evidence('memory', f"Low memory: {mem.total / (1024**3):.1f} GB (possible VM)")
        except:
            pass

    def _check_cpu_features(self):
        """检查 CPU 特征（VM 可能缺少某些特征）"""
        if sys.platform != 'win32':
            return
        try:
            import subprocess
            result = subprocess.run(
                ['wmic', 'cpu', 'get', 'NumberOfLogicalProcessors', '/value'],
                capture_output=True, text=True, errors='ignore', timeout=5
            )
            # 解析逻辑处理器数量
            match = re.search(r'NumberOfLogicalProcessors=(\d+)', result.stdout)
            if match:
                cores = int(match.group(1))
                if cores <= 2:
                    self._add_evidence('cpu', f"Low CPU cores: {cores} (possible VM)")
        except:
            pass

    def is_safe_to_run(self) -> bool:
        """是否安全执行动态分析（VM 或 Sandbox 或 Docker）"""
        result = self.detect()
        return result['risk_level'] in ('safe', 'vm')

    def get_warning_message(self) -> str:
        """获取警告信息"""
        result = self.detect()
        if result['risk_level'] == 'safe':
            return "环境安全：已检测到隔离环境（Windows Sandbox / Docker / VM）"
        elif result['risk_level'] == 'vm':
            return "环境警告：已检测到虚拟机，但仍建议在快照回滚的 VM 中执行"
        else:
            lines = [
                "⚠️ 严重警告：未检测到任何隔离环境！",
                "",
                "您当前似乎正在宿主机（真实系统）上运行。",
                "动态分析将直接执行样本文件，恶意程序可能：",
                "  • 在系统目录创建持久化文件",
                "  • 修改注册表实现自启动",
                "  • 加密文件（勒索软件）",
                "  • 窃取敏感数据",
                "",
                "建议操作：",
                "  1. 在 VMware/VirtualBox 快照虚拟机中运行",
                "  2. 使用 Windows 10/11 Pro 的 Windows Sandbox",
                "  3. 仅使用静态分析（不加 --dynamic 参数）",
                "",
                "如果仍要执行，请使用 --allow-dangerous 参数，并自行承担风险。",
            ]
            return "\n".join(lines)
