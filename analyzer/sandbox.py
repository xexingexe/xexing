#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
沙箱隔离引擎 — 基于 Windows Job Object 的进程级沙箱
"""
import os
import sys
import time
import uuid
import ctypes
import tempfile
import shutil
import subprocess
import hashlib
from typing import Optional, Dict

from logger import get_logger
from analyzer.models import SandboxResult
from config import CONFIG

logger = get_logger('analyzer.sandbox')

# 执行窗口兜底追踪时排除的系统进程（父死子生/孤儿进程候选过滤）
_SYSTEM_NOISE_PROCESSES = {
    'svchost.exe', 'conhost.exe', 'dllhost.exe', 'wmiprvse.exe', 'spoolsv.exe',
    'lsass.exe', 'services.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'searchindexer.exe', 'msmpeng.exe', 'nissrv.exe', 'dwm.exe', 'fontdrvhost.exe',
    'taskhostw.exe', 'runtimebroker.exe', 'shellexperiencehost.exe',
    'startmenuexperiencehost.exe', 'textinputhost.exe', 'securityhealthsystray.exe',
    'compatTelrunner.exe', 'audiodg.exe', 'sihost.exe', 'smartscreen.exe',
    'backgroundtaskhost.exe', 'applicationframehost.exe', 'werfault.exe',
    'werfaultsecure.exe', 'explorer.exe', 'onedrive.exe', 'msedge.exe', 'chrome.exe',
    'python.exe', 'pythonw.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe',
    'taskmgr.exe', 'vmtoolsd.exe', 'vm3dservice.exe', 'vmwaretray.exe',
    'vmwareuser.exe', 'mpcmdrun.exe', 'mssense.exe', 'samsrv.exe',
    'searchprotocolhost.exe', 'searchfilterhost.exe', 'settingssynchorization.exe',
    'settingcontentms.exe', 'windowsworker.exe', 'systemsettings.exe',
    'lockapp.exe', 'shellexperiencehost.exe', 'ctfmon.exe', 'tabtip.exe',
    'explorer.exe', 'outlook.exe', 'winword.exe', 'excel.exe', 'powerpnt.exe',
    'services.exe', 'registry.exe', 'smss.exe', 'win32kfull.sys',
    # ⚠ 沙箱自身 Frida 注入助手 (Temp\frida-*\frida-helper*.exe) — 不能当样本进程!
    'frida-helper.exe', 'frida-helper-x86.exe', 'frida-helper-x86_64.exe',
    'frida-server.exe', 'frida-gadget.exe', 'frida-inject.exe',
    # DISM 组件存储操作 (签名系统组件, Temp 工作目录实例是系统更新/DISM正常行为)
    'dismhost.exe', 'dismprov.dll', 'dismcoreps.dll', 'cbsprovider.dll',
    'setupcl.exe', 'trustedinstaller.exe', 'tisvc.exe', 'msiexec.exe',
}


# ===== 系统关键进程名 (反蓝屏保护 — 恶意样本把系统进程设 BreakOnTermination 时) =====
# 判定优先用 exe 路径(\\windows\\等), 路径不可读时用此名单兜底
_SYSTEM_CRITICAL_NAMES = {
    'csrss.exe', 'winlogon.exe', 'wininit.exe', 'services.exe',
    'lsass.exe', 'smss.exe', 'svchost.exe', 'explorer.exe',
    'dwm.exe', 'fontdrvhost.exe', 'audiodg.exe',
    'ntoskrnl.exe', 'registry.exe', 'system',
}


class Sandbox:
    """Windows Job Object 沙箱"""
    
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
    JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
    
    JobObjectExtendedLimitInformation = 9
    CREATE_SUSPENDED = 0x00000004
    
    def __init__(self, timeout: int = 60, memory_limit_mb: int = 512,
                 process_limit: int = 20, cpu_limit_sec: int = 0):
        self.timeout = timeout
        self.memory_limit_mb = memory_limit_mb
        self.process_limit = process_limit
        self.cpu_limit_sec = cpu_limit_sec
        self.job_handle = None
        self.work_dir = ''
        self.artifacts_dir = ''
        self._fs_before = {}
        self._reg_before = {}
        self.target_pid = None
        self._start_time = 0
        self._exit_code = None
        self._was_terminated = False
        self._crashed = False
        self._crash_code = 0
        # 兜底追踪发现的进程信息缓存 (供动态分析报告补录 PPID 链断裂场景的释放进程)
        self._tracked_processes = {}

    @staticmethod
    def _check_break_on_termination(pid: int) -> bool:
        """检测进程是否被设为系统关键（BreakOnTermination）"""
        try:
            PROCESS_QUERY_INFORMATION = 0x0400
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
            if not handle:
                return False
            BreakOnTermination = 29
            val = ctypes.c_ulong()
            status = ctypes.windll.ntdll.NtQueryInformationProcess(
                ctypes.c_void_p(handle),
                ctypes.c_ulong(BreakOnTermination),
                ctypes.byref(val),
                ctypes.c_ulong(ctypes.sizeof(val)),
                None
            )
            ctypes.windll.kernel32.CloseHandle(handle)
            return status == 0 and val.value != 0
        except Exception:
            return False

    @staticmethod
    def _clear_break_on_termination(pid: int) -> bool:
        """去掉 ProcessBreakOnTermination 标志，返回是否成功"""
        try:
            PROCESS_SET_INFORMATION = 0x0200
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_SET_INFORMATION, False, pid)
            if not handle:
                return False
            BreakOnTermination = 29
            val = ctypes.c_ulong(0)
            status = ctypes.windll.ntdll.NtSetInformationProcess(
                ctypes.c_void_p(handle),
                ctypes.c_ulong(BreakOnTermination),
                ctypes.byref(val),
                ctypes.c_ulong(ctypes.sizeof(val))
            )
            ctypes.windll.kernel32.CloseHandle(handle)
            return status == 0
        except Exception:
            return False

    def __enter__(self):
        self.setup()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False
    
    def setup(self):
        """初始化沙箱"""
        logger.info("[*] 沙箱: 初始化隔离环境...")
        
        # 创建 Job Object
        if sys.platform == 'win32':
            self._create_job_object()
        
        # 创建沙箱目录 — 使用配置的 temp_dir (配置加载时已锚定为绝对路径)。
        # 用 os.makedirs 直接创建唯一目录: 某些受限/容器环境下 tempfile.mkdtemp
        # 创建的目录 ACL 不允许继续创建子目录 (WinError 5)。
        _base = os.path.abspath(getattr(CONFIG, 'temp_dir', '') or tempfile.gettempdir())
        os.makedirs(_base, exist_ok=True)
        _uniq = f"sandbox_{os.getpid()}_{int(time.time() * 1_000_000)}_{uuid.uuid4().hex[:8]}"
        self.work_dir = os.path.join(_base, _uniq)
        os.makedirs(self.work_dir, exist_ok=False)
        self.artifacts_dir = os.path.join(self.work_dir, '_artifacts_')
        os.makedirs(self.artifacts_dir, exist_ok=True)
        
        # 快照
        self._fs_before = self._snapshot_directory(self.work_dir)
        self._reg_before = self._snapshot_registry()
        
        logger.info(f"[+] 沙箱: 环境就绪 (工作目录: {self.work_dir})")
    
    def build_command(self, file_path: str, args: list = None) -> list:
        """根据扩展名构建目标启动命令（.msi/.dll/.vbs/.js/.ps1/.bat/.hta/.wsf 等）"""
        sandbox_file = os.path.abspath(file_path)
        cmd = [sandbox_file] + (args or [])
        ext = os.path.splitext(sandbox_file)[1].lower()

        if ext == '.msi':
            cmd = ['msiexec', '/i', sandbox_file, '/qn']
        elif ext == '.dll':
            dll_lower = os.path.basename(sandbox_file).lower()
            if any(com_dll in dll_lower for com_dll in ['regsvr', 'dllreg', 'register']):
                cmd = ['regsvr32', '/s', sandbox_file]
            else:
                cmd = ['rundll32.exe', sandbox_file, '#1']
        elif ext in ('.vbs', '.vbe'):
            cmd = ['wscript.exe', '//B', sandbox_file]
        elif ext in ('.js', '.jse'):
            cmd = ['wscript.exe', '//B', sandbox_file]
        elif ext == '.ps1':
            cmd = ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', sandbox_file]
        elif ext in ('.bat', '.cmd'):
            cmd = ['cmd.exe', '/c', sandbox_file]
        elif ext == '.hta':
            # Win11 24H2+ mshta.exe 默认移除/禁用 (按需功能) — start_process 会做存在性检查
            cmd = ['mshta.exe', sandbox_file]
        elif ext == '.wsf':
            cmd = ['wscript.exe', '//B', sandbox_file]
        elif ext not in ('.exe', '.scr', '.com'):
            logger.warning(f"[-] 沙箱: 未知文件类型 '{ext}'，尝试以可执行文件方式运行")

        return cmd

    def start_process(self, file_path: str, args: list = None):
        """启动进程（挂起创建 → 加入 Job → 恢复运行），返回 Popen 对象"""
        # 直接使用原路径运行，不复制到沙箱临时目录
        # 原因是很多应用（尤其 .NET 单文件）依赖原始目录结构
        sandbox_file = os.path.abspath(file_path)
        if not os.path.exists(sandbox_file):
            logger.error(f"[-] 文件不存在: {sandbox_file}")
            return None

        logger.info(f"[*] 沙箱: 启动 {os.path.basename(sandbox_file)}")

        cmd = self.build_command(file_path, args)
        ext = os.path.splitext(sandbox_file)[1].lower()

        if ext == '.hta':
            # Win11 24H2+ mshta.exe 默认移除/禁用 (按需功能) — 明确报错而不是静默失败
            mshta = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'),
                                 'System32', 'mshta.exe')
            if not os.path.exists(mshta):
                logger.error("[-] HTA 启动失败: mshta.exe 不存在 (Win11 24H2+ 已移除 mshta)")
                logger.error("[!] 解决方法: 设置-系统-可选功能-添加\"Microsoft HTML 应用程序 (HTA)\"")
                self._sandbox_error = FileNotFoundError(
                    'mshta.exe not found — Win11 24H2 removed mshta by default. '
                    'Enable "Microsoft HTML Application (HTA)" optional feature.')
                return None
        
        try:
            # 竞态修复: 挂起创建 → 立即加入 Job → 立即恢复。
            # 进程恢复前不会执行任何指令; 恢复后 Frida 再 attach (attach 发生在
            # dynamic.py 后续流程, 因此不受挂起影响), 既不改变样本运行行为,
            # 又消除了"样本先运行、后入 Job"的逃逸窗口。
            creation_flags = 0
            suspended = False
            if sys.platform.startswith('win'):
                creation_flags = self.CREATE_SUSPENDED
                suspended = True

            self._start_time = time.time()
            proc = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(os.path.abspath(file_path)),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creation_flags
            )
            self.target_pid = proc.pid

            if suspended:
                if self.job_handle:
                    if not self.assign_to_job(proc.pid):
                        # 安全优先: 进程此时仍挂起, 未执行任何代码。
                        # Job 加入失败时绝不无隔离恢复执行 (物理机上等于裸跑样本)。
                        logger.error("[-] 沙箱: 样本加入 Job Object 失败 — 已终止挂起进程, 拒绝无隔离执行")
                        self._sandbox_error = RuntimeError(
                            'AssignProcessToJobObject failed — 拒绝在无 Job 隔离状态下运行样本')
                        try:
                            proc.terminate()
                            proc.wait(timeout=5)
                        except Exception:
                            try:
                                proc.kill()
                            except Exception:
                                pass
                        self.target_pid = proc.pid
                        return None
                # 入 Job 成功后才恢复: 样本此时才开始真正运行
                self.resume_process(proc.pid)

            logger.info(f"[+] 沙箱: 进程 PID={proc.pid} 已创建并已加入 Job")
            return proc

        except OSError as e:
            if getattr(e, 'winerror', None) == 225:
                logger.error("[-] 沙箱: Windows Defender 拦截了样本执行（WinError 225: 文件包含病毒）")
                logger.error("[!] 解决方法: 添加沙箱临时目录到 Defender 排除项，或临时禁用实时保护")
                from analyzer.models import SandboxResult
                sr = SandboxResult(exit_code=-225, was_terminated=False)
                sr.winerror = 225
                sr.message = "Windows Defender 实时保护拦截了样本执行，请将临时目录添加到排除项"
                self._sandbox_error = sr
            else:
                logger.error(f"[-] 沙箱: 启动失败: {e}")
            return None

        except Exception as e:
            logger.error(f"[-] 沙箱: 启动失败: {e}")
            return None
    
    def wait_process(self, proc: subprocess.Popen, on_child_pids: callable = None, stop_event=None):
        """等待进程及子进程结束或超时，on_child_pids(pid_list) 在每个等待周期被调用

        自删除木马场景: 主进程秒退/自删, 子进程(常为内存马)继续运行。
        策略: 主进程最多等 timeout 秒; 主进程死后继续追踪子进程最长
        child_wait_timeout 秒(期间持续内存扫描/Frida注入); 整个动态分析
        (主进程+子进程) 受 analysis_total_timeout 总时限约束, 超时强制结束。
        """
        if not proc:
            return
        root_pid = proc.pid
        # 提前缓存主进程创建时间 — 主进程死后 create_time() 拿不到,
        # 但父死子生/孤儿进程的窗口兜底追踪依赖它
        root_create_time = None
        try:
            import psutil as _ps
            root_create_time = _ps.Process(root_pid).create_time()
        except Exception:
            pass
        total_deadline = time.time() + getattr(CONFIG.sandbox, 'analysis_total_timeout', 600)
        try:
            main_wait = min(self.timeout, max(0, total_deadline - time.time()))
            proc.wait(timeout=main_wait)
            self._exit_code = proc.returncode
            logger.info(f"[+] 沙箱: 主进程退出 (code={proc.returncode})")
            # 崩溃归因: 识别 NTSTATUS 崩溃码 (0xC0000005 访问违规 / 0xC0000409 栈溢出 / 0xC0000374 堆损坏)
            if proc.returncode is not None and proc.returncode != 0:
                _nt = proc.returncode & 0xFFFFFFFF
                if _nt >= 0x80000000 and _nt != 0xC000013A:
                    self._crashed = True
                    self._crash_code = _nt
                    logger.warning(f"[!] 沙箱: 样本崩溃 (NTSTATUS=0x{_nt:08X}) — 后续行为按崩溃场景降权")
        except subprocess.TimeoutExpired:
            self._was_terminated = True
            logger.warning(f"[!] 沙箱: 主进程超时 ({main_wait}s)")

        # 主进程退出后，等待子进程并每秒 dump 模块 + 内存扫描（内存马检测）
        try:
            import psutil
            remaining = min(CONFIG.sandbox.child_wait_timeout,
                            max(0, total_deadline - time.time()))
            root_dead_since = None
            # 历史 bug: 用 root.children() 等子进程, 主进程一死立即 break,
            # 子进程(如父进程死后冒出的 00000B1000457EA6.exe)从未被等待
            known_child_pids = set()

            def _collect_sample_children():
                """收集与样本进程树相关的所有存活进程 (祖先链可达 root_pid)"""
                found = set()

                def _cache_process(pid):
                    """缓存进程信息 — 供动态分析报告补录 (进程可能在报告前退出)"""
                    try:
                        p = psutil.Process(pid)
                        info = self._tracked_processes.get(pid, {})
                        try:
                            info['name'] = p.name()
                        except Exception:
                            pass
                        try:
                            info['exe'] = p.exe()
                        except Exception:
                            pass
                        try:
                            info['cmdline'] = ' '.join(p.cmdline())[:500]
                        except Exception:
                            pass
                        try:
                            info['create_time'] = p.create_time()
                        except Exception:
                            pass
                        try:
                            info['ppid'] = p.ppid()
                        except Exception:
                            pass
                        self._tracked_processes[pid] = info
                    except Exception:
                        pass

                def _is_sample_related(pid):
                    """ppid 链上溯: 是否可达 root 或已知子进程集"""
                    seen = set()
                    p = pid
                    while p and p not in seen:
                        seen.add(p)
                        if p == root_pid or p in known_child_pids:
                            return True
                        try:
                            p = psutil.Process(p).ppid()
                        except Exception:
                            return False
                    return False

                try:
                    root = psutil.Process(root_pid)
                    for c in root.children(recursive=True):
                        found.add(c.pid)
                        _cache_process(c.pid)
                except Exception:
                    pass
                # 主进程死后: 全表扫描, 沿 ppid 链判断是否与样本相关
                try:
                    for proc in psutil.process_iter(['pid', 'ppid']):
                        pid = proc.info['pid']
                        ppid = proc.info['ppid'] or 0
                        if pid in known_child_pids or ppid in known_child_pids or ppid == root_pid:
                            found.add(pid)
                            _cache_process(pid)
                            continue
                        # 中间进程存活的祖先链可达 (根死后保链场景)
                        if _is_sample_related(pid):
                            found.add(pid)
                            _cache_process(pid)
                except Exception:
                    pass
                # 父死子生/孤儿进程兜底: 主进程死后才创建的子进程会被系统 reparent,
                # ppid 链断裂。用"执行窗口内创建 + 非系统白名单 + 非系统目录"兜底收集,
                # 后续内存扫描/Frida注入对这些候选只读操作, 不会误伤系统进程
                # 根进程创建时间拿不到(已死)时回退到沙箱启动时间 — 兜底扫描不能因此停摆
                window_start = min(root_create_time or time.time(),
                                   self._start_time or time.time()) - 5
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
                        try:
                            ct = proc.info['create_time']
                            if not ct or ct < window_start:
                                continue
                            name = (proc.info['name'] or '').lower()
                            if name in _SYSTEM_NOISE_PROCESSES:
                                continue
                            exe = (proc.info['exe'] or '').lower()
                            if exe and ('\\windows\\' in exe or '\\program files' in exe):
                                continue
                            found.add(proc.info['pid'])
                            _cache_process(proc.info['pid'])
                        except Exception:
                            continue
                except Exception:
                    pass
                return found
            while remaining > 0:
                if stop_event and stop_event.is_set():
                    logger.warning("[!] 沙箱: 子进程等待已取消（用户停止）")
                    break
                children = _collect_sample_children()
                known_child_pids |= children
                # 回调: 每秒对存活子进程做全内存PE/Shellcode扫描 + 模块dump + Frida注入
                # (自删除木马/内存马: 载荷常在主进程死后才注入子进程, 必须持续扫描)
                if on_child_pids:
                    try:
                        on_child_pids(list(children))
                    except Exception:
                        pass
                # 已知子进程全部结束后立即退出(不能空转到时限) — 防止 child_wait_timeout 内白等
                alive_known = False
                for pid in list(known_child_pids):
                    try:
                        p = psutil.Process(pid)
                        if not p.is_running():
                            continue
                        # PID 复用防护: 校验 create_time 与缓存一致,
                        # 防已死进程的 PID 被新进程复用后误判为仍存活 → 空转到总时限
                        ct_cached = (self._tracked_processes.get(pid) or {}).get('create_time')
                        if ct_cached:
                            try:
                                if abs(p.create_time() - ct_cached) < 1.0:
                                    alive_known = True
                                    break
                            except Exception:
                                continue
                        else:
                            alive_known = True
                            break
                    except Exception:
                        continue
                if not children and not alive_known:
                    # ⚠ 主进程死后不能立即 break: 残留进程可能延迟启动
                    # (父死子生场景, 如 MSI 释放器退出后 1~2 秒才冒出的守护进程)
                    # 保持观察窗, 让延迟进程暴露并被收集
                    if root_dead_since is None:
                        root_dead_since = time.time()
                    if time.time() - root_dead_since < 8:
                        time.sleep(1)
                        remaining = min(CONFIG.sandbox.child_wait_timeout,
                                        max(0, total_deadline - time.time()))
                        continue
                    logger.info("[+] 沙箱: 所有子进程已结束")
                    break
                else:
                    root_dead_since = None
                time.sleep(1)
                remaining = min(CONFIG.sandbox.child_wait_timeout,
                                max(0, total_deadline - time.time()))
            if remaining <= 0:
                logger.warning(f"[!] 沙箱: 动态分析总时限 "
                               f"({getattr(CONFIG.sandbox, 'analysis_total_timeout', 600)}s)已到，强制结束")
            elif children:
                logger.warning("[!] 沙箱: 子进程等待超时，强制结束")
            # 保存已知子进程供 kill_process 补杀 (主进程已死的父死子生场景)
            self._known_child_pids = set(known_child_pids)
        except ImportError:
            pass

    def kill_process(self, proc: subprocess.Popen, extra_exe_paths: set = None):
        """强制终止进程树，跳过无法清除 Critical 标记的进程防蓝屏

        extra_exe_paths: 样本释放的可执行文件绝对路径集合(小写)。
        计划任务/服务/WMI 延迟启动的载荷(如 MSI→计划任务→z2VIqs.exe)父进程链
        断裂, 不在进程树内; 按"exe == 释放文件"精确匹配全进程表补杀,
        比随机名启发式更准且不会误伤系统进程。
        """
        if not proc:
            return
        import psutil
        critical_pids = set()
        self._break_on_termination_log = []  # 记录检测到的系统关键进程
        try:
            root = psutil.Process(proc.pid)
            all_procs = [root] + (root.children(recursive=True) if root.is_running() else [])
        except psutil.NoSuchProcess:
            all_procs = []
        # 主进程已死(父死子生): 补杀 wait_process 期间收集的已知子进程/孤儿,
        # 否则样本残留进程会驻留到下次分析 (修复: root.children 抛 NoSuchProcess → 全部漏杀)
        try:
            for cpid in (getattr(self, '_known_child_pids', None) or set()):
                try:
                    all_procs.append(psutil.Process(cpid))
                except Exception:
                    pass
        except Exception:
            pass
        # ⚠ 已移除旧的"随机名进程全局启发式清理": 它只凭 5-9 位随机名 +
        # 位于 Public/ProgramData/AppData 就收集进程, 与进程树/创建时间/释放物
        # 无关, 会误杀物理机/宿主上的正常程序 (Dropbox/Updater 等)。
        # 延迟拉起的载荷改由下方 extra_exe_paths 精确匹配补杀。

        # 释放文件精确匹配补杀: 计划任务/服务启动的载荷(父进程链断裂, 不在树内)
        # 如 z2VIqs.exe 由 ITeWS 计划任务经 svchost 拉起 — 随机名启发式可能错过
        if extra_exe_paths:
            try:
                for p in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        exe = (p.info['exe'] or '').lower()
                        if not exe or exe not in extra_exe_paths:
                            continue
                        if p.pid in {x.pid for x in all_procs}:
                            continue
                        all_procs.append(p)
                        try:
                            self._tracked_processes.setdefault(p.pid, {
                                'name': p.name() or '', 'exe': exe,
                                'cmdline': ' '.join(p.cmdline())[:500] if p.cmdline() else '',
                                'create_time': p.create_time(),
                                'ppid': p.ppid() or 0,
                            })
                        except Exception:
                            pass
                        logger.warning(f"[!] 沙箱: 释放文件匹配 — 残留载荷进程 {p.info['name']} "
                                       f"(PID={p.pid}, {exe})")
                    except Exception:
                        continue
            except Exception:
                pass

        for p in all_procs:
            try:
                pid = p.pid
                # ⚠ PID 复用竞态防护: 收集 all_procs 到真正终止之间, 进程可能已退出,
                # PID 被系统进程复用 — 终止前必须校验进程身份 (名称+创建时间+存在性)
                try:
                    cur = psutil.Process(pid)
                    if not cur.is_running():
                        continue
                except psutil.NoSuchProcess:
                    continue
                except Exception:
                    continue

                if self._check_break_on_termination(pid):
                    logger.warning(f"[!] 沙箱: PID={pid}({p.name()}) 标记为系统关键进程，尝试清除...")
                    critical_pids.add(pid)
                    self._break_on_termination_log.append({
                        'pid': pid, 'name': p.name(), 'cleared': False,
                        'detail': f'进程 {p.name()}(PID={pid}) 通过 NtSetInformationProcess(BreakOnTermination=29) 将自身标记为系统关键进程 — 终止将导致蓝屏(0x000000EF)'
                    })
                    # ⚠ 反杀软陷阱: 恶意样本常把系统进程(csrss/winlogon/svchost等)
                    # 设为 BreakOnTermination, 诱导沙箱杀掉系统进程触发蓝屏。
                    # 按"exe 路径在系统目录"判断真系统进程 — 仅名字伪装(svchost.exe
                    # 从 Public 运行)的恶意进程不在此列, 仍可终止。
                    _is_real_system_proc = False
                    try:
                        _exe_path = (p.exe() or '').lower()
                        if _exe_path and ('\\windows\\' in _exe_path or '\\program files' in _exe_path):
                            _is_real_system_proc = True
                        elif not _exe_path:
                            # exe 路径不可读(权限): 按名字保守判定, 宁可漏杀不蓝屏
                            _sys_proc_name = (p.name() or '').lower()
                            if _sys_proc_name in _SYSTEM_CRITICAL_NAMES:
                                _is_real_system_proc = True
                    except Exception:
                        _is_real_system_proc = False
                    if _is_real_system_proc:
                        logger.warning(f"[!] 沙箱: PID={pid} 是系统进程({p.name()}, {_exe_path or '路径不可读'}), 跳过终止 (防蓝屏)")
                        self._break_on_termination_log[-1]['detail'] += ' — 系统进程, 已跳过终止'
                        self._break_on_termination_log[-1]['cleared'] = True
                        continue
                    if self._clear_break_on_termination(pid):
                        logger.info(f"[+] 沙箱: PID={pid} Critical 标志已清除")
                        self._break_on_termination_log[-1]['cleared'] = True
                        # ⚠ 清除后必须重新校验 PID 未复用再杀 (竞态窗口)
                        try:
                            cur2 = psutil.Process(pid)
                            if not cur2.is_running():
                                continue
                        except Exception:
                            continue
                        try:
                            p.kill()
                        except (psutil.NoSuchProcess, Exception):
                            pass
                    else:
                        logger.error(f"[-] 沙箱: PID={pid} Critical 标志清除失败，跳过终止以防蓝屏")
                else:
                    try:
                        # ⚠ 终止残留载荷前先 dump 内存 — 这是最后的取证机会!
                        # (9c 阶段进程已死, 无法实时分析; 残留载荷是银狐/加载器核心)
                        # ⚠ 必须过滤沙箱自身/系统进程: frida-helper/conhost 等
                        #   曾把 frida 注入助手 dump 60 区域污染内存取证
                        _dump_ok = True
                        try:
                            _pname = (p.name() or '').lower()
                            _pexe = (p.exe() or '').lower()
                            if _pname in _SYSTEM_NOISE_PROCESSES:
                                _dump_ok = False
                            elif 'frida-' in _pexe or '\\frida\\' in _pexe \
                                    or 'frida-agent.dll' in _pexe:
                                _dump_ok = False
                            elif _pexe and ('\\windows\\' in _pexe or '\\program files' in _pexe):
                                _dump_ok = False
                        except Exception:
                            pass
                        if _dump_ok:
                            try:
                                self._dump_process_memory(pid, p.name())
                            except Exception:
                                pass
                        # ⚠ 普通进程同样有 PID 复用风险: 再确认是同一进程
                        p.kill()
                    except (psutil.NoSuchProcess, Exception):
                        pass
            except (psutil.NoSuchProcess, Exception):
                pass

        if critical_pids:
            logger.warning(f"[!] 沙箱: {len(critical_pids)} 个系统关键进程未终止 (PIDs={sorted(critical_pids)})")
            if not hasattr(self, '_critical_pids'):
                self._critical_pids = []
            self._critical_pids.extend(sorted(critical_pids))
        else:
            logger.info("[*] 沙箱: 进程树已终止")

    def watch_for_restart(self, extra_exe_paths: set = None, watch_timeout: int = 15,
                          interval: int = 2, stop_event=None):
        """重启观察窗: 样本退出后拦截"先退出再重启"逃逸的延迟拉起进程。

        样本可经计划任务/服务/WMI 在退出后延迟重启, 父进程链断裂、不在进程树内。
        观察窗内对"新出现的进程"做 exe 精确匹配 (extra_exe_paths = 样本释放文件),
        命中即终止, 避免误伤系统进程。
        """
        extra_exe_paths = {e.lower() for e in (extra_exe_paths or set()) if e}
        if not extra_exe_paths:
            return
        import psutil
        known_pids = set()
        try:
            for p in psutil.process_iter(['pid']):
                known_pids.add(p.info['pid'])
        except Exception:
            pass
        deadline = time.time() + max(0, watch_timeout)
        logger.info(f"[*] 沙箱: 重启观察窗 {watch_timeout}s (检测样本退出后重启的进程)")
        while time.time() < deadline:
            if stop_event and stop_event.is_set():
                break
            try:
                for p in psutil.process_iter(['pid', 'name', 'exe']):
                    pid = p.info['pid']
                    if pid in known_pids:
                        continue
                    known_pids.add(pid)
                    exe = (p.info['exe'] or '').lower()
                    if not exe or exe not in extra_exe_paths:
                        continue
                    try:
                        p.terminate()
                        time.sleep(0.3)
                        if p.is_running():
                            p.kill()
                        logger.warning(f"[!] 沙箱: 拦截重启载荷 {p.info['name']} "
                                       f"(PID={pid}, {exe})")
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(interval)

    def execute(self, file_path: str, args: list = None) -> Optional[int]:
        """同步执行文件（简便接口）"""
        proc = self.start_process(file_path, args)
        if not proc:
            return None
        
        # start_process 已在进程恢复前完成 Job 加入与恢复, 无需重复操作
        
        # 等待结束
        self.wait_process(proc)
        
        return proc.pid
    
    def collect_artifacts(self) -> SandboxResult:
        """收集沙箱产物"""
        logger.info("[*] 沙箱: 收集分析产物...")
        
        fs_after = self._snapshot_directory(self.work_dir)
        
        files_created = []
        files_modified = []
        files_deleted = []
        
        all_before = set(self._fs_before.keys())
        all_after = set(fs_after.keys())
        
        for f in (all_after - all_before):
            if '_artifacts_' not in f:
                files_created.append(f)
        
        for f in (all_before & all_after):
            if self._fs_before[f].get('md5') != fs_after[f].get('md5'):
                if '_artifacts_' not in f:
                    files_modified.append(f)
        
        for f in (all_before - all_after):
            if '_artifacts_' not in f:
                files_deleted.append(f)
        
        logger.info(f"    新增: {len(files_created)}, 修改: {len(files_modified)}, 删除: {len(files_deleted)}")

        # 注册表变更对比
        reg_created = []
        reg_modified = []
        reg_after = self._snapshot_registry()
        for key, val in reg_after.items():
            if key not in self._reg_before:
                reg_created.append(f"{key}: {val[:120]}")
            elif self._reg_before[key] != val:
                reg_modified.append(f"{key}: {val[:120]}")

        return SandboxResult(
            sandbox_type='job_object',
            execution_time=time.time() - self._start_time if self._start_time else 0,
            exit_code=self._exit_code if self._exit_code is not None else -1,
            crashed=getattr(self, '_crashed', False),
            crash_code=getattr(self, '_crash_code', 0),
            was_terminated=self._was_terminated,
            files_created=files_created,
            files_modified=files_modified,
            files_deleted=files_deleted,
            registry_created=reg_created,
            registry_modified=reg_modified,
            sandbox_dir=self.work_dir,
            artifacts_dir=self.artifacts_dir
        )
    
    def cleanup(self):
        """清理沙箱: TerminateJobObject 杀死 Job 内所有进程(含手动 kill 漏掉的 breakaway/孤儿), 再关闭句柄"""
        logger.info("[*] 沙箱: 清理环境...")

        if self.job_handle:
            try:
                kernel32 = ctypes.windll.kernel32
                kernel32.TerminateJobObject(self.job_handle, 0)
                kernel32.CloseHandle(self.job_handle)
                self.job_handle = None
            except:
                pass

        if self.work_dir and os.path.exists(self.work_dir):
            shutil.rmtree(self.work_dir, ignore_errors=True)
    
    def _create_job_object(self):
        """创建 Job Object"""
        if not sys.platform.startswith('win'):
            return
        
        try:
            kernel32 = ctypes.windll.kernel32
            job_name = f"Sandbox_{int(time.time())}_{os.getpid()}"
            self.job_handle = kernel32.CreateJobObjectW(None, job_name)
            if not self.job_handle:
                return
            
            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", ctypes.c_uint32),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", ctypes.c_uint32),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", ctypes.c_uint32),
                    ("SchedulingClass", ctypes.c_uint32),
                ]
            
            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_uint64),
                    ("WriteOperationCount", ctypes.c_uint64),
                    ("OtherOperationCount", ctypes.c_uint64),
                    ("ReadTransferCount", ctypes.c_uint64),
                    ("WriteTransferCount", ctypes.c_uint64),
                    ("OtherTransferCount", ctypes.c_uint64),
                ]
            
            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]
            
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            # KILL_ON_JOB_CLOSE 只在 Job 句柄关闭/TerminateJobObject 时生效,
            # 分析期间句柄保持打开, 不影响 MSI/脚本类样本的载荷进程存活。
            # 不再启用 SILENT_BREAKAWAY_OK — 否则样本可 spawn 脱离 Job 的子进程后退出逃逸
            # (目标"先退出再重启"绕过沙箱的根因之一)。
            info.BasicLimitInformation.LimitFlags = (
                self.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
                self.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                self.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            
            if self.memory_limit_mb > 0:
                info.BasicLimitInformation.LimitFlags |= (
                    self.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
                    self.JOB_OBJECT_LIMIT_JOB_MEMORY
                )
                info.ProcessMemoryLimit = self.memory_limit_mb * 1024 * 1024
                info.JobMemoryLimit = self.memory_limit_mb * 2 * 1024 * 1024

            if self.cpu_limit_sec and self.cpu_limit_sec > 0:
                info.BasicLimitInformation.LimitFlags |= self.JOB_OBJECT_LIMIT_JOB_TIME
                info.BasicLimitInformation.PerJobUserTimeLimit = int(self.cpu_limit_sec * 10_000_000)
                logger.info(f"[+] 沙箱: CPU 时间限制 {self.cpu_limit_sec}s (Job Object)")

            info.BasicLimitInformation.ActiveProcessLimit = self.process_limit
            
            kernel32.SetInformationJobObject(
                self.job_handle,
                self.JobObjectExtendedLimitInformation,
                ctypes.byref(info),
                ctypes.sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
            )
            
            logger.info("[+] 沙箱: Job Object 已创建")
        
        except Exception as e:
            logger.error(f"[-] 沙箱: Job Object 创建失败: {e}")
            self.job_handle = None
    
    def assign_to_job(self, pid: int) -> bool:
        """将进程加入 Job，返回是否成功"""
        if not self.job_handle:
            return False
        try:
            kernel32 = ctypes.windll.kernel32
            h_process = kernel32.OpenProcess(0x0100 | 0x0001, False, pid)
            if not h_process:
                logger.debug(f"[-] 沙箱: OpenProcess 失败 PID={pid}")
                return False
            ok = kernel32.AssignProcessToJobObject(self.job_handle, h_process)
            kernel32.CloseHandle(h_process)
            if not ok:
                logger.warning(f"[-] 沙箱: AssignProcessToJobObject 失败 PID={pid}")
            return bool(ok)
        except Exception as e:
            logger.debug(f"[-] 沙箱: 加入 Job 异常 PID={pid}: {e}")
            return False

    def _dump_process_memory(self, pid: int, name: str, max_regions: int = 60):
        """终止残留载荷前 dump 内存 — 9c 阶段进程已死无法实时分析,
        dump 文件供 memory.py 分析 (PE注入/Shellcode/Hook 检测)。
        只读进程内存, 不执行任何代码。"""
        try:
            from analyzer.mem_api import open_process, virtual_query_ex, read_process_memory, close_handle
        except Exception:
            return
        h = open_process(pid)  # mem_api 内部已带 QUERY|VM_READ
        if not h:
            return
        try:
            import config as _cfg
            ddir = getattr(getattr(_cfg, 'CONFIG', None), 'memory', None)
            dump_dir = getattr(ddir, 'dump_dir', 'memory_dumps') if ddir else 'memory_dumps'
            os.makedirs(dump_dir, exist_ok=True)
            addr = 0
            dumped = 0
            while dumped < max_regions and addr < 0x7FFFFFFFFFFF:
                mbi = virtual_query_ex(h, addr)
                if not mbi:
                    break
                base = mbi.get('BaseAddress') or 0
                size = mbi.get('RegionSize') or 0
                if size <= 0:
                    break
                prot = (mbi.get('Protect') or 0) & ~0x100  # 去 PAGE_GUARD
                state = mbi.get('State') or 0
                # 只 dump COMMIT + 可读 + 非系统模块区 (PE 载荷在私有/映像内存)
                if state == 0x1000 and prot in (0x04, 0x08, 0x20, 0x40, 0x80, 0xC0) \
                        and size <= 20 * 1024 * 1024:
                    data = read_process_memory(h, base, size)
                    if data and len(data) > 0x200:
                        fname = os.path.join(dump_dir,
                            f'pid{pid}_{name.replace(".", "_")}_{base:016x}_{int(time.time()*1000)}.bin')
                        with open(fname, 'wb') as f:
                            f.write(data)
                        dumped += 1
                addr = base + size
            if dumped:
                logger.info(f"[+] 沙箱: 残留载荷内存 dump {dumped} 区域 (PID={pid} {name}) — 供内存取证")
        except Exception:
            pass
        finally:
            try:
                close_handle(h)
            except Exception:
                pass
    
    def resume_process(self, pid: int):
        """恢复挂起的进程"""
        if not sys.platform.startswith('win'):
            return
        try:
            kernel32 = ctypes.windll.kernel32
            THREAD_SUSPEND_RESUME = 0x0002
            snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)
            if snapshot == -1:
                return
            
            class THREADENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.c_uint32),
                    ("cntUsage", ctypes.c_uint32),
                    ("th32ThreadID", ctypes.c_uint32),
                    ("th32OwnerProcessID", ctypes.c_uint32),
                    ("tpBasePri", ctypes.c_int32),
                    ("tpDeltaPri", ctypes.c_int32),
                    ("dwFlags", ctypes.c_uint32),
                ]
            
            te = THREADENTRY32()
            te.dwSize = ctypes.sizeof(THREADENTRY32)
            
            if kernel32.Thread32First(snapshot, ctypes.byref(te)):
                while True:
                    if te.th32OwnerProcessID == pid:
                        h_thread = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, te.th32ThreadID)
                        if h_thread:
                            kernel32.ResumeThread(h_thread)
                            kernel32.CloseHandle(h_thread)
                    if not kernel32.Thread32Next(snapshot, ctypes.byref(te)):
                        break
            
            kernel32.CloseHandle(snapshot)
        except:
            pass
    
    def _snapshot_directory(self, root_dir: str) -> Dict[str, Dict]:
        """目录快照"""
        snapshot = {}
        if not os.path.exists(root_dir):
            return snapshot
        
        for dirpath, _, filenames in os.walk(root_dir):
            if '_artifacts_' in dirpath:
                continue
            for fname in filenames:
                full_path = os.path.join(dirpath, fname)
                try:
                    size = os.path.getsize(full_path)
                    if size > 50 * 1024 * 1024:
                        snapshot[full_path] = {'size': size, 'md5': 'skipped'}
                        continue
                    with open(full_path, 'rb') as f:
                        h = hashlib.md5()
                        while True:
                            chunk = f.read(4 * 1024 * 1024)
                            if not chunk:
                                break
                            h.update(chunk)
                        md5 = h.hexdigest()
                    snapshot[full_path] = {'size': size, 'md5': md5}
                except:
                    snapshot[full_path] = {'size': 0, 'md5': 'error'}
        return snapshot
    
    def _snapshot_registry(self) -> Dict[str, str]:
        snapshot = {}
        try:
            import subprocess
            keys = [
                r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
                r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                r'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            ]
            for key in keys:
                ps_path = key.replace('HKCU', 'HKCU:').replace('HKLM', 'HKLM:')
                result = subprocess.run(
                    ['powershell', '-NoProfile', '-Command',
                     f'if (Test-Path "{ps_path}") {{ Get-ItemProperty -Path "{ps_path}" }}'],
                    capture_output=True, text=True, timeout=5, errors='ignore'
                )
                if result.returncode == 0 and result.stdout.strip():
                    snapshot[key] = result.stdout.strip()
        except Exception:
            pass
        return snapshot
