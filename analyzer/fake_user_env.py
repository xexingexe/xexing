#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
虚假用户环境模块 — 对抗反沙箱环境指纹检测

模拟真实用户系统的特征：
- USB 设备使用历史
- 最近打开的文档
- 剪贴板内容
- 浏览器历史/缓存路径
- 用户目录结构
- 注册表痕迹 (UserAssist, MUICache, ShellBags)
"""
import os
import struct
import ctypes
import tempfile
import subprocess
from datetime import datetime, timedelta

from logger import get_logger

logger = get_logger('fake_user_env')


def _delete_reg_tree(hkey, subkey):
    """递归删除注册表子树 (仅用于本次新创建的键)。"""
    import winreg
    try:
        with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
            while True:
                try:
                    child = winreg.EnumKey(key, 0)
                    _delete_reg_tree(hkey, f'{subkey}\\{child}')
                except OSError:
                    break
        winreg.DeleteKey(hkey, subkey)
    except (FileNotFoundError, OSError, PermissionError):
        pass


class FakeUserEnvironment:
    """创建虚假用户环境痕迹，对抗反沙箱指纹检测"""

    def __init__(self):
        self._created_paths = []
        self._created_reg = []           # 兼容旧记录 (显示用)
        self._created_reg_keys = []      # 完整键 (可递归删除 — 仅限本次新创建的键)
        self._created_reg_values = []    # (父键, 值名) — 只删值, 绝不整键删除
        self._clipboard_restore = None
        self._spawned_pads = []

    def setup(self) -> bool:
        """一键创建所有虚假痕迹"""
        try:
            self._create_usb_history()
            self._create_recent_docs()
            self._fake_clipboard()
            self._create_user_dirs()
            self._create_registry_traces()
            self._create_fake_programs()
            self._create_registry_complexity()
            self._ensure_process_count()
            logger.info(f"[FakeEnv] 虚假用户环境就绪: {len(self._created_paths)} 文件, {len(self._created_reg)} 注册表项")
            return True
        except Exception as e:
            logger.warning(f"[FakeEnv] 设置失败: {e}")
            return False

    def cleanup(self):
        """清理虚假痕迹"""
        for path in self._created_paths:
            try:
                if os.path.isfile(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    import shutil
                    shutil.rmtree(path, ignore_errors=True)
            except Exception:
                pass
        # 清理虚假注册表痕迹 (只删本次创建的键/值)
        import winreg as _wr
        for vkey, vname in self._created_reg_values:
            try:
                with _wr.OpenKey(_wr.HKEY_CURRENT_USER, vkey, 0,
                                 _wr.KEY_SET_VALUE) as k:
                    try:
                        _wr.DeleteValue(k, vname)
                    except FileNotFoundError:
                        pass
            except (FileNotFoundError, OSError, PermissionError):
                pass
        for rkey in self._created_reg_keys:
            try:
                _delete_reg_tree(_wr.HKEY_CURRENT_USER, rkey)
            except Exception:
                pass
        self._created_reg_values.clear()
        self._created_reg_keys.clear()
        # 清理进程数填充进程 (五条件反沙箱要求进程数>=10)
        # 用 taskkill /T 树级终止, 避免 cmd 死后 ping 子进程残留
        for p in self._spawned_pads:
            try:
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(p.pid)],
                               capture_output=True, timeout=8)
            except Exception:
                try:
                    p.terminate()
                except Exception:
                    pass
        for p in self._spawned_pads:
            try:
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        self._spawned_pads.clear()
        if self._clipboard_restore is not None:
            try:
                self._restore_clipboard()
            except Exception:
                pass
        self._created_paths.clear()
        self._created_reg.clear()

    # ===== USB 设备使用历史 =====
    def _create_usb_history(self):
        r"""在 HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR 创建虚假USB记录"""
        usb_root = r'SYSTEM\CurrentControlSet\Enum\USBSTOR'
        fake_devices = [
            r'Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\00147854488FE&0',
            r'Disk&Ven_SanDisk&Prod_Ultra_USB_3.0&Rev_1.00\4C530001230328111352&0',
            r'Disk&Ven_WD&Prod_Elements_25A2&Rev_1021\575839384141374E5634&0',
        ]
        for dev_path in fake_devices:
            full = f'{usb_root}\\{dev_path}'
            try:
                self._reg_write(full, None, 'FriendlyName',
                                dev_path.split('Prod_')[1].split('&')[0].replace('_', ' '), 'REG_SZ')
                self._reg_write(full, None, 'HardwareID',
                                 f'USB\\VID_{self._rand_hex(4)}&PID_{self._rand_hex(4)}', 'REG_SZ')
                self._created_reg.append(full)
                self._created_reg_keys.append(full)
            except Exception:
                pass

    # ===== 最近文档 =====
    def _create_recent_docs(self):
        """在用户 Recent 目录创建虚假最近文档"""
        recent_dir = os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Recent')
        if not os.path.exists(recent_dir):
            os.makedirs(recent_dir, exist_ok=True)
            self._created_paths.append(recent_dir)

        fake_files = [
            '项目计划2026.xlsx.lnk',
            '客户名单.xlsx.lnk',
            '财务报表_06月.xlsx.lnk',
            '技术方案评审.docx.lnk',
            '会议纪要_0625.docx.lnk',
            '系统架构图.png.lnk',
        ]
        fake_reg = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
        for i, fname in enumerate(fake_files):
            path = os.path.join(recent_dir, fname)
            try:
                with open(path, 'wb') as f:
                    self._write_lnk(f, fname.replace('.lnk', ''))
                self._created_paths.append(path)
            except Exception:
                pass
            try:
                self._reg_write(fake_reg, None, str(i), fname.encode('utf-16-le'), 'REG_BINARY')
                self._created_reg.append(f'{fake_reg}\\{i}')
                self._created_reg_values.append((fake_reg, str(i)))
            except Exception:
                pass

    # ===== 剪贴板 =====
    def _fake_clipboard(self):
        """向剪贴板写入虚假文本（真实用户通常有内容）"""
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            if not user32.OpenClipboard(0):
                return
            user32.EmptyClipboard()
            fake_text = "项目进度更新: 06-28 \u6d4b\u8bd5\u73af\u5883\u5df2\u90e8\u7f72\uff0c\u8bf7\u5404\u4f4d\u786e\u8ba4\u3002"
            gmem = kernel32.GlobalAlloc(0x0002, len(fake_text.encode('utf-16-le')) + 2)
            if gmem:
                locked = kernel32.GlobalLock(gmem)
                if locked:
                    ctypes.memmove(locked, fake_text.encode('utf-16-le'),
                                   len(fake_text.encode('utf-16-le')))
                    kernel32.GlobalUnlock(gmem)
                    user32.SetClipboardData(13, gmem)  # CF_UNICODETEXT=13
            user32.CloseClipboard()
            self._clipboard_restore = True
        except Exception:
            pass

    def _restore_clipboard(self):
        try:
            user32 = ctypes.windll.user32
            user32.OpenClipboard(0)
            user32.EmptyClipboard()
            user32.CloseClipboard()
        except Exception:
            pass

    # ===== 用户目录 =====
    def _create_user_dirs(self):
        """在用户目录创建常见文件夹和文件"""
        userprofile = os.environ.get('USERPROFILE', '')
        desktop = os.path.join(userprofile, 'Desktop')
        documents = os.path.join(userprofile, 'Documents')
        downloads = os.path.join(userprofile, 'Downloads')
        pictures = os.path.join(userprofile, 'Pictures')

        for d in [desktop, documents, downloads, pictures]:
            os.makedirs(d, exist_ok=True)

        fake_desktop_files = [
            ('工作计划.xlsx', 15234),
            ('客户资料汇总.docx', 28456),
            ('VPN配置说明.txt', 3201),
            ('周报_0628.docx', 19200),
        ]
        for fname, size in fake_desktop_files:
            path = os.path.join(desktop, fname)
            if not os.path.exists(path):
                try:
                    content = b'\x00' * min(size, 1024)
                    with open(path, 'wb') as f:
                        f.write(content)
                    os.utime(path, (datetime.now() - timedelta(days=7)).timestamp())
                    self._created_paths.append(path)
                except Exception:
                    pass

        # 浏览器 User Data 目录（不创建真实文件，只创建目录结构）
        browser_dirs = [
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default'),
            os.path.join(os.environ.get('APPDATA', ''), 'Mozilla', 'Firefox', 'Profiles', 'abcd1234.default-release'),
        ]
        for bd in browser_dirs:
            try:
                if not os.path.isdir(bd):
                    os.makedirs(bd, exist_ok=True)
                    self._created_paths.append(bd)
            except Exception:
                pass

    # ===== 注册表痕迹 =====
    def _create_registry_traces(self):
        """创建 UserAssist, MUICache 等注册表痕迹"""
        traces = [
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count',
             b'\x00' * 72,
             'REG_BINARY'),
            (r'SOFTWARE\Microsoft\Windows\ShellNoRoam\MUICache',
             None, None),
        ]
        for key, value, vtype in traces:
            try:
                if vtype == 'REG_BINARY' and value:
                    vname = r'HRZR_EHACNGU:P:\Hfref\Nqzva\Qrfxgbc\oevatre\oevatre.rkr'
                    self._reg_write(key, None, vname, value, vtype)
                    self._created_reg_values.append((key, vname))
                self._created_reg.append(key)
            except Exception:
                pass

    # ===== 伪装已安装程序（对抗 FEW_INSTALLED_PROGRAMS） =====
    def _create_fake_programs(self):
        """在 Start Menu 和 Program Files 创建虚假程序入口"""
        import random
        programs_dir = os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'),
                                    'Microsoft', 'Windows', 'Start Menu', 'Programs')
        os.makedirs(programs_dir, exist_ok=True)

        fake_apps = [
            'Microsoft Office', 'Adobe Acrobat', 'Google Chrome', 'Mozilla Firefox',
            '7-Zip', 'Notepad++', 'Visual Studio Code', 'Python 3.12',
            'WinRAR', 'VLC Media Player', 'Zoom', 'Slack', 'Discord',
            'Microsoft Teams', 'OneDrive', 'Dropbox', 'Spotify', 'Git',
            'Node.js', 'MySQL Workbench', 'Docker Desktop', 'Postman',
        ]
        for app in fake_apps:
            app_dir = os.path.join(programs_dir, app)
            try:
                os.makedirs(app_dir, exist_ok=True)
                lnk_path = os.path.join(app_dir, f'{app}.lnk')
                if not os.path.exists(lnk_path):
                    with open(lnk_path, 'wb') as f:
                        self._write_lnk(f, app)
                    self._created_paths.append(lnk_path)
            except Exception:
                pass

        # Uninstall 注册表项
        uninstall_base = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        vendors = {
            'Microsoft': ['Office 365', 'Visual C++ Redist', '.NET Runtime 8.0', 'Edge WebView2'],
            'Adobe': ['Acrobat Reader DC', 'Creative Cloud'],
            'Google': ['Chrome', 'Drive'],
            'Mozilla': ['Firefox (x64)'],
            'Python': ['Python 3.12.4 (64-bit)'],
            # ⚠ 绝不写 Oracle/VirtualBox: 样本枚举卸载项做 VM 检测时反而暴露虚拟机
            'Notepad++': ['Notepad++ (64-bit)'],
            '7-Zip': ['7-Zip 24.08'],
        }
        for vendor, products in vendors.items():
            for product in products:
                guid = f'{{{self._rand_guid()}}}'
                key = f'{uninstall_base}\\{guid}'
                try:
                    self._reg_write(key, None, 'DisplayName', f'{product}', 'REG_SZ')
                    self._reg_write(key, None, 'Publisher', vendor, 'REG_SZ')
                    self._reg_write(key, None, 'InstallDate',
                                    f'{random.randint(20240101, 20260531)}', 'REG_SZ')
                    self._created_reg.append(key)
                    self._created_reg_keys.append(key)
                except Exception:
                    pass

    # ===== 注册表复杂度增强（对抗 SIMPLE_REGISTRY） =====
    def _create_registry_complexity(self):
        """在 HKCU 下创建大量注册表键值对，增加注册表复杂度"""
        complex_keys = [
            (r'SOFTWARE\Microsoft\Office\16.0\Common\Internet', 'UseOnlineContent', '1'),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced', 'Hidden', '1'),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced', 'ShowSuperHidden', '0'),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced', 'HideFileExt', '0'),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket', 'NukeOnDelete', '0'),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyEnable', '0'),
            # 注意: 绝不修改 Themes\Personalize / DWM 外观设置!
            # 历史版本曾写入 AppsUseLightTheme/SystemUsesLightTheme=1 + AccentColor,
            # 导致用户的深色模式/任务栏透明被破坏, 已移除
            (r'SOFTWARE\Microsoft\InputPersonalization', 'RestoreEnabled', '1'),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run', '{01}', 'REG_BINARY'),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run', '{02}', 'REG_BINARY'),
            (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers', None, None),
            (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store', None, None),
            (r'SOFTWARE\Microsoft\SystemCertificates\Root\Certificates', None, None),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\HomeGroup', None, None),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Action Center\Checks', None, None),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications', 'ToastEnabled', '1'),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR', 'AppCaptureEnabled', '0'),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata', None, None),
            (r'SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore', None, None),
        ]
        for key, val_name, val in complex_keys:
            try:
                if val_name is None:
                    self._reg_write(key, None, '', '', 'REG_SZ')
                    self._created_reg_values.append((key, ''))
                elif val == 'REG_BINARY':
                    self._reg_write(key, None, val_name, b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'REG_BINARY')
                    self._created_reg_values.append((key, val_name))
                else:
                    self._reg_write(key, None, val_name, val, 'REG_SZ')
                    self._created_reg_values.append((key, val_name))
                self._created_reg.append(key)
            except Exception:
                pass

    # ===== 进程数填充 (反沙箱条件: 当前进程数 >= 10) =====
    def _ensure_process_count(self, min_count: int = None):
        """进程数不足时拉起无害的隐藏进程补足, 规避"进程数<10立即退出"的反沙箱检查。

        优先读取 config.sandbox.env_min_processes; 填充进程均为无窗口的
        cmd/ping 静默等待进程, 分析结束 cleanup() 会全部终止。
        """
        if os.name != 'nt':
            return
        try:
            from config import CONFIG
            min_count = int(getattr(getattr(CONFIG, 'sandbox', None),
                                    'env_min_processes', 10) or 10)
        except Exception:
            min_count = min_count or 10

        try:
            import psutil
            current = sum(1 for _ in psutil.process_iter())
        except Exception:
            try:
                out = subprocess.run(['tasklist', '/fo', 'csv'], capture_output=True,
                                     text=True, errors='ignore', timeout=10).stdout
                current = sum(1 for line in out.splitlines() if line.strip())
            except Exception:
                return

        need = max(0, min_count - current)
        if need <= 0:
            return
        # 每个填充进程 = cmd.exe + conhost.exe (2 个进程), 最多拉 6 个即可
        spawn_n = min(need, 6)
        create_flags = 0x08000000  # CREATE_NO_WINDOW
        for _ in range(spawn_n):
            try:
                p = subprocess.Popen(
                    ['cmd.exe', '/c', 'ping -t 127.0.0.1 >nul'],
                    creationflags=create_flags,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                )
                self._spawned_pads.append(p)
            except Exception:
                break
        if self._spawned_pads:
            logger.info(f"[FakeEnv] 进程数 {current} < {min_count}, 已拉起 {len(self._spawned_pads)} 个填充进程")

    @staticmethod
    def _rand_guid():
        import random
        return ''.join(random.choice('0123456789ABCDEF') for _ in range(8)) + '-' + \
               ''.join(random.choice('0123456789ABCDEF') for _ in range(4)) + '-' + \
               ''.join(random.choice('0123456789ABCDEF') for _ in range(4)) + '-' + \
               ''.join(random.choice('0123456789ABCDEF') for _ in range(4)) + '-' + \
               ''.join(random.choice('0123456789ABCDEF') for _ in range(12))

    # ===== 辅助方法 =====
    def _reg_write(self, key_path, subkey_name, value_name, value, reg_type='REG_SZ'):
        """写入注册表（使用 subprocess reg add）"""
        full_key = key_path
        if subkey_name:
            full_key = f'{key_path}\\{subkey_name}'

        if reg_type == 'REG_SZ':
            cmd = ['reg', 'add', f'HKCU\\{full_key}', '/v', value_name, '/t', 'REG_SZ',
                   '/d', str(value), '/f']
        elif reg_type == 'REG_BINARY':
            # reg add 要求连续十六进制字符串 (逗号分隔会导致静默失败)
            hexstr = ''.join(f'{b:02x}' for b in (value if isinstance(value, bytes) else value.encode()))
            cmd = ['reg', 'add', f'HKCU\\{full_key}', '/v', value_name, '/t', 'REG_BINARY',
                   '/d', hexstr, '/f']
        else:
            return

        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass

    @staticmethod
    def _rand_hex(n):
        import random
        return ''.join(random.choice('0123456789ABCDEF') for _ in range(n))

    @staticmethod
    def _write_lnk(f, target_name):
        """写入最小 .lnk 文件头"""
        # ShellLink header (minimal structure)
        header = struct.pack('<I', 0x0000004C)  # LinkCLSID size
        header += b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'  # CLSID
        header += struct.pack('<I', 0x00000003)  # LinkFlags (HasLinkTargetIDList + HasLinkInfo)
        header += struct.pack('<I', 0x00000002)  # FileAttributes (FILE_ATTRIBUTE_HIDDEN)
        header += struct.pack('<Q', int((datetime.now() - timedelta(days=3)).timestamp() * 10000000) + 116444736000000000)  # CreationTime
        header += struct.pack('<Q', 0)  # AccessTime
        header += struct.pack('<Q', 0)  # WriteTime
        header += struct.pack('<I', 15000)  # FileSize
        header += struct.pack('<I', 0x00000000)  # IconIndex
        header += struct.pack('<I', 1)  # ShowCommand (SW_SHOWNORMAL)
        header += struct.pack('<H', 0)  # HotKey
        header += struct.pack('<H', 0) * 2  # Reserved
        f.write(header)
