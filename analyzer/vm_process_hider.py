#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
VM 环境隐藏器 v2 — 多维度隐藏虚拟机痕迹

对抗手段（按检测覆盖面排列）:
  1. 进程终止     — 杀掉 vmtoolsd.exe, VBoxTray.exe 等
  2. 服务停止     — net stop / sc stop 停 VM 服务
  3. **驱动禁用**  — sc stop + sc config start=disabled（新增）
  4. **注册表隐藏** — 备份+删除 SOFTWARE\VMware,Inc.* 等键（新增）
  5. 文件重命名   — .exe → .exe.bak（含驱动 .sys 文件）
  6. **验证检查**  — 隐藏后自检证明有效（新增）

局限性（NOTE）:
  - WMI 数据（Win32_BIOS, Win32_ComputerSystem）来自硬件层，本文无法伪造
  - CPUID 指令检测需要驱动级拦截（需配合 VMware Hardening 文档配置）
  - MAC 地址需在 VM 配置中手动修改（vmx 文件: ethernet0.addressType="static"）
"""
import os
import sys
import time
import json
import shutil
import subprocess
from typing import List, Dict, Tuple
from logger import get_logger

logger = get_logger('analyzer.vm_hider')


# ===== 进程列表 =====
VM_PROCESSES = [
    # VMware Workstation/Player
    'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe',
    'vmacthlp.exe', 'vmusrvc.exe', 'vmsrvc.exe',
    'vmware-authd.exe', 'vmware-usbarbitrator.exe',
    'vmnetdhcp.exe', 'vmnetbridge.exe', 'vmnat.exe',
    'vmware-unity-helper.exe',
    # VirtualBox
    'VBoxTray.exe', 'VBoxService.exe', 'VBoxGuest.exe',
    'VBoxClient.exe', 'VirtualBox.exe',
    # QEMU/KVM
    'qemu-ga.exe', 'virtio-win-guest-tools.exe',
    # Xen
    'XenService.exe', 'xenguestagent.exe',
    # Parallels
    'prl_tools.exe', 'prl_tools_service.exe', 'prl_cc.exe',
    # Hyper-V (host components that leak VM info)
    'vmcompute.exe', 'vmms.exe', 'vmwp.exe',
]

# ===== 服务列表 =====
VM_SERVICES = [
    # VMware
    'VMTools', 'VMwarePhysicalDisk', 'VMwareAuthorizationService',
    'VMnetDHCP', 'VMware NAT Service', 'VMUSBArbService',
    'VMwareHostd', 'VMwareWorkstationServer',
    # VirtualBox
    'VBoxService', 'VBoxGuest', 'VBoxSF',
    # Hyper-V
    'vmcompute', 'vmms', 'HvHost',
    # 其他
    'QEMU-GA', 'XenGuestAgent',
]

# ===== 驱动列表 =====
# 安全驱动（停止不会导致系统崩溃/重启）
VM_DRIVERS_SAFE = [
    # VMware — 通信/鼠标/共享文件夹/气球驱动，停了不蓝屏
    'vmci', 'vmmouse', 'vmusbmouse', 'vmhgfs', 'vmmemctl',
    # VirtualBox — 鼠标/共享文件夹/USB，停了不蓝屏
    'VBoxMouse', 'VBoxSF', 'VBoxUSB',
    # Hyper-V — 键盘/鼠标，停了不蓝屏
    'hyperkbd', 'VMBusHID',
]

# 危险驱动（停止会导致系统不稳定/蓝屏/重启，默认不碰）
VM_DRIVERS_DANGEROUS = [
    'vmscsi', 'vmx_svga', 'vmx86', 'vmxnet', 'vmxnet3',
    'vm3dmp', 'vmrawdisk', 'vmusrvc', 'vmsrvc',
    'VBoxGuest', 'VBoxVideo', 'VBoxNetAdp', 'VBoxNetLwf',
    'storvsc', 'vmbus', 'hypervideo', 'netvsc', 'storvsp', 'vhdmp', 'vsmraid',
    'qemufwcfg', 'viostor', 'vioscsi', 'netkvm',
]

# 默认只停安全驱动
VM_DRIVERS = VM_DRIVERS_SAFE

# ===== 文件重命名列表 =====
VM_FILE_PATHS = [
    # VMware Tools
    r'C:\Program Files\VMware\VMware Tools\vmtoolsd.exe',
    r'C:\Program Files (x86)\VMware\VMware Tools\vmtoolsd.exe',
    r'C:\Program Files\VMware\VMware Tools\vmwaretray.exe',
    r'C:\Program Files (x86)\VMware\VMware Tools\vmwaretray.exe',
    r'C:\Program Files\VMware\VMware Tools\vmwareuser.exe',
    r'C:\Program Files (x86)\VMware\VMware Tools\vmwareuser.exe',
    # VirtualBox Guest Additions
    r'C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxTray.exe',
    r'C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxService.exe',
    r'C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxControl.exe',
    r'C:\Program Files (x86)\Oracle\VirtualBox Guest Additions\VBoxTray.exe',
    r'C:\Program Files (x86)\Oracle\VirtualBox Guest Additions\VBoxService.exe',
    # QEMU
    r'C:\Program Files\QEMU-ga\qemu-ga.exe',
    # Xen
    r'C:\Program Files\Xen\XenGuestAgent\XenService.exe',
    # Parallels
    r'C:\Program Files\Parallels\Parallels Tools\prl_tools.exe',
    r'C:\Program Files\Parallels\Parallels Tools\prl_tools_service.exe',
]

# ===== 注册表键（备份后删除）=====
VM_REGISTRY_KEYS = [
    # VMware
    r'SOFTWARE\VMware, Inc.\VMware Tools',
    r'SOFTWARE\VMware, Inc.',
    # VirtualBox
    r'SOFTWARE\Oracle\VirtualBox Guest Additions',
    # Hyper-V / Windows Sandbox 客户机组件
    r'SOFTWARE\Microsoft\Virtual Machine\Guest\DetectedComponents',
    r'SOFTWARE\Microsoft\Virtual Machine\Guest',
    # 驱动服务注册
    r'SYSTEM\CurrentControlSet\Services\vmci',
    r'SYSTEM\CurrentControlSet\Services\vmhgfs',
    r'SYSTEM\CurrentControlSet\Services\vmmouse',
    r'SYSTEM\CurrentControlSet\Services\vmusbmouse',
    r'SYSTEM\CurrentControlSet\Services\VBoxGuest',
    r'SYSTEM\CurrentControlSet\Services\VBoxMouse',
    r'SYSTEM\CurrentControlSet\Services\VBoxSF',
    r'SYSTEM\CurrentControlSet\Services\VBoxVideo',
    r'SYSTEM\CurrentControlSet\Services\VBoxService',
    r'SYSTEM\CurrentControlSet\Services\VMTools',
    # 不会有写权限的跳过往常（HARDWARE 是 volatile 注册表，删不掉）
]

VM_REGISTRY_VALUES = [
    # 修改注册表值来欺骗检测
    (r'HARDWARE\DESCRIPTION\System\BIOS', 'SystemProductName', 'Standard PC'),
    (r'HARDWARE\DESCRIPTION\System\BIOS', 'SystemManufacturer', 'Dell Inc.'),
    (r'HARDWARE\DESCRIPTION\System\BIOS', 'BIOSVendor', 'American Megatrends Inc.'),
    (r'HARDWARE\DESCRIPTION\System\BIOS', 'BIOSVersion', '1.0'),
]


class VMProcessHider:
    """VM 环境隐藏器 v2 — 增强版"""

    def __init__(self):
        self._hidden_processes: List[Dict] = []
        self._stopped_services: List[str] = []
        self._stopped_drivers: List[str] = []
        self._drv_start_orig: Dict[str, int] = {}  # 驱动原 Start 值 (恢复写回)
        self._renamed_files: List[Tuple[str, str]] = []
        self._deleted_regkeys: List[Tuple[str, str, str]] = []  # (hkey, subkey, backup_data)
        self._modified_regvals: List[Tuple[str, str, str, str]] = []  # (hkey, subkey, value, original_value)
        self._was_hidden = False
        # 状态持久化: hide() 后进程崩溃/退出时, 下次 restore() 仍能恢复
        self._state_file = os.path.join(
            os.environ.get('TEMP', os.getcwd()), 'sandbox_vm_hider_state_v2.json')

    # ========================
    #  公开接口
    # ========================

    def hide(self) -> Dict:
        """隐藏 VM 痕迹 — 全维度执行"""
        result = {
            "status": "none",
            "hidden": [],      # 终止的进程
            "stopped": [],     # 停止的服务
            "driver_stopped": [],  # 禁用的驱动
            "renamed": [],     # 重命名的文件
            "registry_deleted": [],  # 删除的注册表键
            "registry_modified": [],  # 修改的注册表值
            "verification": {},  # 隐藏后自检结果
        }

        if sys.platform != 'win32':
            logger.warning("VM 隐藏仅支持 Windows")
            return result

        if not self._is_admin():
            logger.error("[!] VM 隐藏需要管理员权限！请以管理员身份运行。")
            result["status"] = "error: admin required"
            return result

        logger.info("=" * 50)
        logger.info("[*] VM 环境隐藏 v2 — 开始")
        logger.info("=" * 50)

        # 1. 终止 VM 进程
        self._kill_processes()
        result["hidden"] = [p['name'] for p in self._hidden_processes]

        # 2. 停止 VM 服务
        self._stop_services()
        result["stopped"] = list(self._stopped_services)

        # 3. 停止并禁用 VM 驱动
        self._stop_drivers()
        result["driver_stopped"] = list(self._stopped_drivers)

        # 4. 隐藏注册表
        self._hide_registry_keys()
        self._modify_registry_values()
        result["registry_deleted"] = [rk[1] for rk in self._deleted_regkeys]
        result["registry_modified"] = [rv[1] + "\\" + rv[2] for rv in self._modified_regvals]

        # 5. 重命名 VM 文件
        self._rename_executables()
        result["renamed"] = [f"{os.path.basename(o)} -> .bak" for o, _ in self._renamed_files]

        # 6. 验证隐藏效果
        result["verification"] = self._verify_hiding()

        # 状态判定
        total = (len(self._hidden_processes) + len(self._stopped_services) +
                 len(self._stopped_drivers) + len(self._renamed_files) +
                 len(self._deleted_regkeys))
        if total > 0:
            result["status"] = "ok" if len(self._stopped_drivers) > 0 else "partial"
            self._was_hidden = True

        logger.info(f"[+] 隐藏完成: 进程 {len(self._hidden_processes)}, "
                    f"服务 {len(self._stopped_services)}, 驱动 {len(self._stopped_drivers)}, "
                    f"文件 {len(self._renamed_files)}, 注册表 {len(self._deleted_regkeys)}")
        self._save_state()
        return result

    def _save_state(self):
        """把隐藏动作持久化到 %TEMP% — 独立进程执行 --restore 时也能恢复。"""
        try:
            state = {
                'hidden_processes': self._hidden_processes,
                'stopped_services': self._stopped_services,
                'stopped_drivers': self._stopped_drivers,
                'drv_start_orig': self._drv_start_orig,
                'renamed_files': [list(x) for x in self._renamed_files],
                'deleted_regkeys': [list(x) for x in self._deleted_regkeys],
                'modified_regvals': [list(x) for x in self._modified_regvals],
                'was_hidden': self._was_hidden,
            }
            with open(self._state_file, 'w', encoding='utf-8') as f:
                json.dump(state, f, ensure_ascii=False)
        except Exception as e:
            logger.debug(f"[!] 状态持久化失败: {e}")

    def _load_state(self) -> bool:
        """从 %TEMP% 加载上次隐藏动作 (用于新进程执行 restore)。"""
        if not os.path.isfile(self._state_file):
            return False
        try:
            with open(self._state_file, 'r', encoding='utf-8') as f:
                state = json.load(f)
            self._hidden_processes = state.get('hidden_processes', [])
            self._stopped_services = list(state.get('stopped_services', []))
            self._stopped_drivers = list(state.get('stopped_drivers', []))
            self._drv_start_orig = {str(k): int(v) for k, v in state.get('drv_start_orig', {}).items()}
            self._renamed_files = [tuple(x) for x in state.get('renamed_files', [])]
            self._deleted_regkeys = [tuple(x) for x in state.get('deleted_regkeys', [])]
            self._modified_regvals = [tuple(x) for x in state.get('modified_regvals', [])]
            self._was_hidden = bool(state.get('was_hidden', True))
            logger.info(f"[+] 已加载上次隐藏状态: 驱动{len(self._stopped_drivers)} "
                        f"文件{len(self._renamed_files)} 注册表{len(self._deleted_regkeys)}")
            return True
        except Exception as e:
            logger.warning(f"[!] 状态文件读取失败: {e}")
            return False

    def restore(self) -> Dict:
        """恢复 VM 痕迹"""
        result = {
            "status": "none",
            "renamed_back": [],
            "started_services": [],
            "started_drivers": [],
            "registry_restored": [],
            "registry_values_restored": [],
        }

        if not self._was_hidden and not self._load_state():
            logger.info("[*] 没有需要恢复的内容 (内存与 %TEMP% 均无隐藏状态)")
            return result

        logger.info("[*] 恢复 VM 环境...")

        # 恢复顺序：注册表 → 文件 → 驱动 → 服务
        result["registry_values_restored"] = self._restore_registry_values()
        result["registry_restored"] = self._restore_registry_keys()
        result["renamed_back"] = self._restore_executables()
        result["started_drivers"] = self._restart_drivers()
        result["started_services"] = self._restart_services()

        total = sum(len(v) for v in result.values() if isinstance(v, list))
        result["status"] = "ok" if total > 0 else "partial"

        logger.info(f"[+] 恢复完成: {total} 项")
        self._reset_state()
        return result

    def _reset_state(self):
        self._was_hidden = False
        self._hidden_processes = []
        self._stopped_services = []
        self._stopped_drivers = []
        self._renamed_files = []
        self._deleted_regkeys = []
        self._modified_regvals = []
        try:
            if os.path.isfile(self._state_file):
                os.remove(self._state_file)
        except Exception:
            pass

    # ========================
    #  进程 / 服务 / 驱动
    # ========================

    def _kill_processes(self):
        """终止 VM 进程"""
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                name = (proc.info['name'] or '').lower()
                for vm_proc in VM_PROCESSES:
                    if name == vm_proc.lower():
                        try:
                            p = psutil.Process(proc.info['pid'])
                            p.terminate()
                            try:
                                p.wait(timeout=3)
                            except psutil.TimeoutExpired:
                                p.kill()
                            self._hidden_processes.append({
                                'name': vm_proc, 'pid': proc.info['pid'],
                                'exe': proc.info['exe'] or ''
                            })
                            logger.info(f"  [+] 终止: {vm_proc} (PID={proc.info['pid']})")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
        except ImportError:
            for vm_proc in VM_PROCESSES:
                try:
                    r = subprocess.run(['taskkill', '/f', '/im', vm_proc],
                                       capture_output=True, text=True, errors='ignore', timeout=5)
                    if r.returncode == 0:
                        self._hidden_processes.append({'name': vm_proc, 'pid': 0, 'exe': ''})
                        logger.info(f"  [+] taskkill: {vm_proc}")
                except Exception:
                    pass

    def _stop_services(self):
        """停止 VM 服务"""
        for svc in VM_SERVICES:
            if self._service_exists(svc):
                try:
                    r = subprocess.run(['net', 'stop', svc],
                                       capture_output=True, text=True, errors='ignore', timeout=15)
                    if r.returncode == 0 or '停止' in r.stdout:
                        self._stopped_services.append(svc)
                        logger.info(f"  [+] 停止服务: {svc}")
                except Exception as e:
                    logger.debug(f"  [-] 停止服务 {svc}: {e}")

    def _stop_drivers(self):
        """停止并禁用 VM 驱动 (禁用前记录原 Start 值, 恢复时写回)"""
        import winreg as _wr
        for drv in VM_DRIVERS:
            service_name = drv if drv.lower().startswith('vbox') else drv.lower()
            if not self._service_exists(service_name):
                continue
            try:
                # 记录原 Start 值 (0=boot 1=system 2=auto 3=demand 4=disabled)
                try:
                    with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                                     rf'SYSTEM\CurrentControlSet\Services\{service_name}',
                                     0, _wr.KEY_READ) as k:
                        self._drv_start_orig[drv] = _wr.QueryValueEx(k, 'Start')[0]
                except Exception:
                    self._drv_start_orig[drv] = 3  # 默认 demand
                # 先停止
                subprocess.run(['sc', 'stop', service_name],
                               capture_output=True, timeout=10)
                time.sleep(0.3)
                # 再禁用
                r = subprocess.run(['sc', 'config', service_name, 'start=', 'disabled'],
                                   capture_output=True, text=True, errors='ignore', timeout=10)
                if r.returncode == 0:
                    self._stopped_drivers.append(drv)
                    logger.info(f"  [+] 禁用驱动: {drv} (原Start={self._drv_start_orig.get(drv)})")
                else:
                    # sc config 失败时注册表直改 (SYSTEM 权限)
                    try:
                        with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                                         rf'SYSTEM\CurrentControlSet\Services\{service_name}',
                                         0, _wr.KEY_SET_VALUE) as k:
                            _wr.SetValueEx(k, 'Start', 0, _wr.REG_DWORD, 4)
                        self._stopped_drivers.append(drv)
                        logger.info(f"  [+] 禁用驱动(注册表): {drv}")
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"  [-] 禁用驱动 {drv}: {e}")

    # ========================
    #  注册表操作
    # ========================

    @staticmethod
    def _delete_registry_tree(hkey, subkey):
        import winreg
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                while True:
                    try:
                        child = winreg.EnumKey(key, 0)
                        VMProcessHider._delete_registry_tree(hkey, f"{subkey}\\{child}")
                    except OSError:
                        break
            winreg.DeleteKey(hkey, subkey)
        except FileNotFoundError:
            pass

    def _hide_registry_keys(self):
        try:
            import winreg
        except ImportError:
            return

        for subkey in VM_REGISTRY_KEYS:
            try:
                hkey = winreg.HKEY_LOCAL_MACHINE
                backup_data = self._export_registry_key(hkey, subkey)
                if backup_data is None:
                    continue
                self._delete_registry_tree(hkey, subkey)
                self._deleted_regkeys.append(('HKLM', subkey, backup_data))
                logger.info(f"  [+] 删除注册表: HKLM\\{subkey}")
            except FileNotFoundError:
                pass  # 键不存在，正常
            except PermissionError:
                logger.debug(f"  [!] 权限不足: HKLM\\{subkey}")
            except Exception as e:
                logger.debug(f"  [-] 注册表 {subkey}: {e}")

    def _export_registry_key(self, hkey, subkey):
        """导出注册表键为 JSON（递归全量）— ⚠ 类型安全: DWORD/QWORD 保留数值, BINARY 用 base64

        历史 bug: 只备份两层, 但 _delete_registry_tree 递归删除整棵子树,
        深层子键 (如 VMware 安装状态、Services\\vmmouse\\Enum) 恢复时永久丢失。
        现在递归全量导出 (深度上限 12, 节点上限 20000 防失控)。
        """
        try:
            import winreg
            import base64

            def _encode(vtype, value):
                if vtype == winreg.REG_DWORD:
                    return {'value': int(value), 'type': vtype}
                if vtype == winreg.REG_QWORD:
                    return {'value': int(value), 'type': vtype}
                if vtype == winreg.REG_BINARY:
                    return {'value': base64.b64encode(bytes(value)).decode(), 'type': vtype}
                if vtype == winreg.REG_MULTI_SZ:
                    return {'value': list(value), 'type': vtype}
                return {'value': str(value), 'type': vtype}

            budget = [0]

            def _walk(key_handle, depth: int):
                if budget[0] > 20000:
                    return {'_values': {}, '_subkeys': {}, '_truncated': True}
                budget[0] += 1
                data = {'_values': {}, '_subkeys': {}}
                i = 0
                while True:
                    try:
                        name, value, vtype = winreg.EnumValue(key_handle, i)
                        data['_values'][name] = _encode(vtype, value)
                        i += 1
                    except OSError:
                        break
                if depth < 12:
                    i = 0
                    while True:
                        try:
                            child_name = winreg.EnumKey(key_handle, i)
                            i += 1
                            try:
                                child_handle = winreg.OpenKey(key_handle, child_name, 0, winreg.KEY_READ)
                                try:
                                    data['_subkeys'][child_name] = _walk(child_handle, depth + 1)
                                finally:
                                    winreg.CloseKey(child_handle)
                            except Exception:
                                pass
                        except OSError:
                            break
                return data

            key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
            try:
                data = _walk(key, 0)
            finally:
                winreg.CloseKey(key)
            return json.dumps(data, ensure_ascii=False)
        except Exception:
            return None

    def _modify_registry_values(self):
        """修改注册表值（BIOS 信息伪装）"""
        try:
            import winreg
        except ImportError:
            return

        for subkey, value_name, fake_value in VM_REGISTRY_VALUES:
            try:
                hkey = winreg.HKEY_LOCAL_MACHINE
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE)
                try:
                    orig_value, _ = winreg.QueryValueEx(key, value_name)
                except FileNotFoundError:
                    winreg.CloseKey(key)
                    continue
                self._modified_regvals.append(('HKLM', subkey, value_name, str(orig_value)))
                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, fake_value)
                winreg.CloseKey(key)
                logger.info(f"  [+] 修改注册表: {value_name} = '{fake_value}'")
            except PermissionError:
                logger.debug(f"  [!] BIOS 注册表修改需要 SYSTEM 权限: {value_name}")
            except Exception as e:
                logger.debug(f"  [-] 注册表修改 {value_name}: {e}")

    # ========================
    #  文件操作
    # ========================

    def _rename_executables(self):
        """重命名 VM 文件和驱动"""
        for path in VM_FILE_PATHS:
            if os.path.exists(path):
                try:
                    bak = path + '.sandbox_bak'
                    if not os.path.exists(bak):
                        shutil.move(path, bak)
                        self._renamed_files.append((path, bak))
                        logger.info(f"  [+] 重命名: {os.path.basename(path)}")
                    else:
                        logger.debug(f"  [!] 备份已存在，跳过: {path}")
                except PermissionError:
                    logger.debug(f"  [!] 权限不足: {path}")
                except Exception as e:
                    logger.debug(f"  [-] 重命名失败 {path}: {e}")

    # ========================
    #  恢复操作
    # ========================

    def _restore_executables(self) -> List[str]:
        restored = []
        for orig, bak in self._renamed_files:
            try:
                if os.path.exists(bak) and not os.path.exists(orig):
                    shutil.move(bak, orig)
                    restored.append(os.path.basename(orig))
                    logger.info(f"  [+] 恢复: {os.path.basename(orig)}")
            except Exception as e:
                logger.warning(f"  [!] 恢复失败 {orig}: {e}")
        return restored

    def _restart_services(self) -> List[str]:
        started = []
        for svc in self._stopped_services:
            try:
                r = subprocess.run(['net', 'start', svc],
                                   capture_output=True, text=True, errors='ignore', timeout=15)
                if r.returncode == 0 or '启动' in r.stdout:
                    started.append(svc)
                    logger.info(f"  [+] 启动服务: {svc}")
            except Exception as e:
                logger.warning(f"  [!] 启动服务 {svc}: {e}")
        return started

    def _restart_drivers(self) -> List[str]:
        """恢复被禁用的驱动 — 原 Start 值写回 (sc config + 注册表直改双保险 + 验证)

        修复: 恢复失败曾导致 vmmouse/vmusbmouse 等驱动保持禁用 → 重启后鼠标失效
        """
        restarted = []
        import winreg as _wr
        # Start 值映射: 原值数字直接写回, 无记录时按常见默认
        for drv in self._stopped_drivers:
            service_name = drv if drv.lower().startswith('vbox') else drv.lower()
            orig_start = self._drv_start_orig.get(drv)
            ok = False
            try:
                # 1) sc config 恢复 (服务管理器路径)
                if orig_start is not None:
                    mode = {0: 'boot', 1: 'system', 2: 'auto', 3: 'demand'}.get(orig_start, 'demand')
                    subprocess.run(['sc', 'config', service_name, 'start=', mode],
                                   capture_output=True, timeout=5)
                else:
                    subprocess.run(['sc', 'config', service_name, 'start=', 'auto'],
                                   capture_output=True, timeout=5)
            except Exception:
                pass
            # 2) 注册表直改 Start (sc config 依赖服务管理器, 注册表最可靠)
            try:
                with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                                 rf'SYSTEM\CurrentControlSet\Services\{service_name}',
                                 0, _wr.KEY_SET_VALUE) as k:
                    val = orig_start if orig_start is not None else 3
                    _wr.SetValueEx(k, 'Start', 0, _wr.REG_DWORD, int(val))
                    ok = True
            except Exception as e:
                logger.warning(f"  [!] 注册表恢复 {drv} Start: {e}")
            # 3) 验证: 读回 Start 值确认非 disabled
            try:
                with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                                 rf'SYSTEM\CurrentControlSet\Services\{service_name}',
                                 0, _wr.KEY_READ) as k:
                    cur = _wr.QueryValueEx(k, 'Start')[0]
                if cur != 4:
                    ok = True
            except Exception:
                pass
            if ok:
                restarted.append(drv)
                logger.info(f"  [+] 启用驱动: {drv} (Start→{orig_start if orig_start is not None else 3})")
            else:
                logger.warning(f"  [!] 驱动 {drv} 恢复失败, 重启后可能不加载 — 请手动: sc config {service_name} start= demand")
            # 尽力启动 (驱动已停, 当前会话尝试加载; 失败不影响重启后 auto 启动)
            try:
                subprocess.run(['sc', 'start', service_name], capture_output=True, timeout=10)
            except Exception:
                pass
        return restarted

    def _restore_registry_keys(self) -> List[str]:
        restored = []
        try:
            import winreg
            import base64
        except ImportError:
            return restored

        def _decode(vtype, val):
            """按注册表类型转换恢复值 — 修复 DWORD 字符串化 bug"""
            if vtype == winreg.REG_DWORD:
                try:
                    return int(val)
                except Exception:
                    return 0
            if vtype == winreg.REG_QWORD:
                try:
                    return int(val)
                except Exception:
                    return 0
            if vtype == winreg.REG_BINARY:
                try:
                    return base64.b64decode(val) if isinstance(val, str) else bytes(val)
                except Exception:
                    return b''
            if vtype == winreg.REG_MULTI_SZ:
                return list(val) if isinstance(val, list) else [str(val)]
            return str(val)

        def _restore_tree(key_handle, data: dict, depth: int = 0):
            for name, info in data.get('_values', {}).items():
                try:
                    vtype = info.get('type', winreg.REG_SZ)
                    val = _decode(vtype, info.get('value', ''))
                    winreg.SetValueEx(key_handle, name, 0, vtype, val)
                except Exception:
                    pass
            if depth < 12:
                for child, child_data in data.get('_subkeys', {}).items():
                    try:
                        ck = winreg.CreateKey(key_handle, child)
                        try:
                            _restore_tree(ck, child_data, depth + 1)
                        finally:
                            winreg.CloseKey(ck)
                    except Exception:
                        pass

        for hkey_name, subkey, backup_data in self._deleted_regkeys:
            try:
                hkey = winreg.HKEY_LOCAL_MACHINE
                # 重建键并递归恢复所有子键/值
                key = winreg.CreateKey(hkey, subkey)
                try:
                    data = json.loads(backup_data)
                    _restore_tree(key, data)
                finally:
                    winreg.CloseKey(key)
                restored.append(subkey)
                logger.info(f"  [+] 恢复注册表: {subkey}")
            except Exception as e:
                logger.warning(f"  [!] 恢复注册表 {subkey}: {e}")
        return restored

    def _restore_registry_values(self) -> List[str]:
        restored = []
        try:
            import winreg
        except ImportError:
            return restored

        for hkey_name, subkey, value_name, orig_value in self._modified_regvals:
            try:
                hkey = winreg.HKEY_LOCAL_MACHINE
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, orig_value)
                winreg.CloseKey(key)
                restored.append(f"{subkey}\\{value_name}")
            except Exception as e:
                logger.warning(f"  [!] 恢复注册表值 {value_name}: {e}")
        return restored

    # ========================
    #  验证
    # ========================

    def _verify_hiding(self) -> Dict:
        """隐藏后自检"""
        result = {
            "running_vm_processes": [],
            "running_vm_services": [],
            "existing_vm_regkeys": [],
            "loaded_vm_drivers": [],
        }

        # 检查进程
        try:
            import psutil
            for proc in psutil.process_iter(['name']):
                name = (proc.info['name'] or '').lower()
                for vm_proc in VM_PROCESSES:
                    if name == vm_proc.lower():
                        result["running_vm_processes"].append(vm_proc)
        except ImportError:
            pass

        # 检查服务
        for svc in VM_SERVICES:
            if self._service_exists(svc):
                r = subprocess.run(['sc', 'query', svc],
                                   capture_output=True, text=True, errors='ignore', timeout=5)
                if 'RUNNING' in r.stdout:
                    result["running_vm_services"].append(svc)

        # 检查注册表
        try:
            import winreg
            for subkey in VM_REGISTRY_KEYS:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey)
                    winreg.CloseKey(key)
                    result["existing_vm_regkeys"].append(subkey)
                except FileNotFoundError:
                    pass
        except ImportError:
            pass

        # 检查驱动
        r = subprocess.run(['driverquery', '/fo', 'csv'],
                           capture_output=True, text=True, errors='ignore', timeout=15)
        loaded = set()
        for line in r.stdout.split('\n'):
            parts = line.strip('"').split('","')
            if parts and parts[0].strip():
                loaded.add(parts[0].strip().lower())
        for drv in VM_DRIVERS:
            if drv.lower() in loaded:
                result["loaded_vm_drivers"].append(drv)

        # 汇总
        all_clear = all(len(v) == 0 for v in result.values())
        if all_clear:
            logger.info("[✓] 验证通过: 无可检测的 VM 痕迹")
        else:
            remaining = sum(len(v) for v in result.values())
            logger.warning(f"[!] 仍有 {remaining} 项 VM 痕迹残留")

        return result

    # ========================
    #  工具
    # ========================

    @staticmethod
    def _service_exists(name: str) -> bool:
        try:
            r = subprocess.run(['sc', 'query', name],
                               capture_output=True, text=True, errors='ignore', timeout=5)
            # 兼容中英文 Windows：检查返回码 + 服务名是否出现在输出中
            return r.returncode == 0 or name.lower() in r.stdout.lower()
        except Exception:
            return False

    @staticmethod
    def _is_admin() -> bool:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def get_status(self) -> Dict:
        """获取当前 VM 进程/服务/驱动状态"""
        return self._verify_hiding()


# ===== 命令行工具 =====
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='VM Process Hider v2')
    parser.add_argument('--hide', action='store_true')
    parser.add_argument('--restore', action='store_true')
    parser.add_argument('--status', action='store_true')
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()

    hider = VMProcessHider()

    if args.hide:
        result = hider.hide()
        print(f"\nStatus: {result['status']}")
        print(f"Stopped processes: {result.get('hidden', [])}")
        print(f"Stopped services:  {result.get('stopped', [])}")
        print(f"Disabled drivers:  {result.get('driver_stopped', [])}")
        print(f"Renamed files:     {result.get('renamed', [])}")
        print(f"Registry deleted:  {result.get('registry_deleted', [])}")
        print(f"Registry modified: {result.get('registry_modified', [])}")
        print(f"\nVerification: {json.dumps(result.get('verification', {}), indent=2, ensure_ascii=False)}")
    elif args.restore:
        result = hider.restore()
        print(f"Status: {result['status']}")
    elif args.verify:
        report = hider._verify_hiding()
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif args.status:
        status = hider.get_status()
        print(json.dumps(status, indent=2, ensure_ascii=False))
    else:
        print("Usage: --hide | --restore | --status | --verify")
