#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida 辅助功能回归测试 — 纯内存, 不执行样本/不注入进程。

覆盖:
  - AMSI / 特权 / 注册表 hive 事件从 Frida 消息正确持久化到结果
  - shutdown_blocked 增量事件合并去重
  - DLL 调用字典上限裁剪
  - FRIDA 脚本源关键修复点存在 (base64 编码器 / TOKEN_PRIVILEGES 偏移 / 架构感知偏移)
  - HTML 报告展示 AMSI 以外的特权/hive 专项监控
"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.api_monitor import (
    APIMonitor, FRIDA_SPOOF_SCRIPT, FRIDA_SHUTDOWN_BLOCK_SCRIPT,
)
from analyzer.models import APIMonitorResult
from report.html_generator import HTMLReportGenerator


class TestAuxEventPersistence(unittest.TestCase):
    def test_amsi_priv_regsave_persist_to_result(self):
        mon = APIMonitor(timeout=1)
        mon._on_spoof_message({'type': 'send', 'payload': {
            'type': 'amsi', 'api': 'AmsiScanBuffer', 'len': 128,
            'preview': 'QUJD', 'content': 'evil.ps1'}}, None)
        mon._on_spoof_message({'type': 'send', 'payload': {
            'type': 'priv', 'api': 'AdjustTokenPrivileges',
            'privilege': 'SeDebugPrivilege', 'action': 'ENABLED'}}, None)
        mon._on_spoof_message({'type': 'send', 'payload': {
            'type': 'regsave', 'file': 'C:\\sam', 'api': 'RegSaveKeyW'}}, None)

        self.assertEqual(mon._amsi_events[0]['api'], 'AmsiScanBuffer')
        self.assertEqual(mon._priv_events[0]['privilege'], 'SeDebugPrivilege')
        self.assertEqual(mon._regsave_events[0]['file'], 'C:\\sam')

        result = APIMonitorResult()
        finalized = mon._finalize_result(result)
        self.assertEqual(finalized._amsi_events[0]['content'], 'evil.ps1')
        self.assertEqual(finalized._priv_events[0]['action'], 'ENABLED')
        self.assertEqual(finalized._regsave_events[0]['api'], 'RegSaveKeyW')

    def test_shutdown_events_merged_and_deduped(self):
        mon = APIMonitor(timeout=1)
        mon._on_antivm_message({'type': 'send', 'payload': {
            'type': 'shutdown_blocked',
            'blocked': [{'api': 'ExitWindowsEx', 'detail': 'flags=0x1'}]}}, None)
        mon._on_antivm_message({'type': 'send', 'payload': {
            'type': 'shutdown_blocked',
            'blocked': [{'api': 'ExitWindowsEx', 'detail': 'flags=0x1'},
                        {'api': 'NtShutdownSystem', 'detail': 'action=0'}]}}, None)
        self.assertEqual(len(mon._shutdown_blocked), 2)
        apis = [e['api'] for e in mon._shutdown_blocked]
        self.assertEqual(apis.count('ExitWindowsEx'), 1)

    def test_dll_call_dict_is_capped(self):
        mon = APIMonitor(timeout=1)
        mon._dll_calls = {(f'dll{i}.dll', f'func{i}'): 1 for i in range(2001)}
        mon._on_spoof_message({'type': 'send', 'payload': {
            'type': 'dllcall', 'dll': 'new.dll', 'func': 'newfunc'}}, None)
        self.assertLessEqual(len(mon._dll_calls), 2000)
        self.assertIn(('new.dll', 'newfunc'), mon._dll_calls)


class TestResultMerge(unittest.TestCase):
    def test_merge_preserves_aux_features(self):
        """dynamic.py 旧合并只保留 call_records, 丢光 memprot/DLL/spoof/AMSI/特权/hive — 回归"""
        r1 = APIMonitorResult()
        r1.call_records = [type('R', (), {'api_name': 'CreateFileW',
                                         'arguments': ['x']})()]
        r1._memprot_events = [{'api': 'VirtualProtect', 'rw_to_rx': True,
                               'size': 4096}]
        r1._memprot_stats = {'sleep_total_ms': 5000, 'enum_snapshot_count': 2}
        r1._dll_calls = {('bad.dll', 'run'): 2}
        r1._spoof_actions = [{'api': 'IsDebuggerPresent', 'detail': 'FALSE'}]
        r1._amsi_events = [{'api': 'AmsiScanBuffer', 'size': 100}]
        r1._priv_events = [{'api': 'AdjustTokenPrivileges',
                            'privilege': 'SeDebugPrivilege', 'action': 'ENABLED'}]
        r1._regsave_events = [{'api': 'RegSaveKeyW', 'file': 'C:\\sam'}]
        r1.shutdown_blocked = [{'api': 'ExitWindowsEx', 'detail': 'flags=0x1'}]
        r1.spawn_mode = True

        r2 = APIMonitorResult()
        r2.call_records = [type('R', (), {'api_name': 'WriteFile',
                                         'arguments': ['y']})()]
        r2._dll_calls = {('bad.dll', 'run'): 3}
        r2._memprot_events = [{'api': 'NtAllocateVirtualMemory', 'dep_bypass': True,
                               'rwx_alloc': True, 'size': 1000}]
        r2._priv_events = [{'api': 'AdjustTokenPrivileges',
                            'privilege': 'SeBackupPrivilege', 'action': 'attempt'}]

        merged = APIMonitor.merge_results([r1, r2])
        self.assertEqual(merged.total_calls, 2)
        self.assertTrue(merged.spawn_mode)
        self.assertEqual(len(merged._memprot_events), 2)
        self.assertEqual(merged._memprot_stats['sleep_total_ms'], 5000)
        self.assertEqual(merged._dll_calls[('bad.dll', 'run')], 5)
        self.assertEqual(len(merged._spoof_actions), 1)
        self.assertEqual(merged._amsi_events[0]['api'], 'AmsiScanBuffer')
        self.assertEqual(len(merged._priv_events), 2)
        self.assertEqual(merged._regsave_events[0]['file'], 'C:\\sam')
        self.assertEqual(len(merged.shutdown_blocked), 1)
        # 合并后重算序列: 主脚本记录里的注入 API 不应丢失判定能力
        merged2 = APIMonitor.merge_results([APIMonitorResult()])
        self.assertEqual(merged2.suspicious_sequences, [])


class TestFridaScriptFixesPresent(unittest.TestCase):
    def test_spoof_script_has_base64_and_struct_fixes(self):
        self.assertIn('function _arrayToB64', FRIDA_SPOOF_SCRIPT)
        # TOKEN_PRIVILEGES 首条 LUID 从偏移 4 开始 (旧代码 8 是错的)
        self.assertIn('newState.add(4 + i * 12)', FRIDA_SPOOF_SCRIPT)
        # CreateProcessW 钩子不再无条件 attach null
        self.assertIn('CreateProcessWRegSave = findExport', FRIDA_SPOOF_SCRIPT)

    def test_shutdown_script_reports_incrementally_and_arch_aware(self):
        self.assertIn("type: 'shutdown_blocked'", FRIDA_SHUTDOWN_BLOCK_SCRIPT)
        self.assertIn("(Process.pointerSize === 8) ? 8 : 4", FRIDA_SHUTDOWN_BLOCK_SCRIPT)

    def test_antivm_script_struct_offsets_fixed(self):
        from analyzer.api_monitor import FRIDA_ANTIVM_SCRIPT
        src = FRIDA_ANTIVM_SCRIPT
        # SYSTEM_INFO 与 SYSTEM_BASIC_INFORMATION 分开处理
        self.assertIn('function patchSystemInfoStruct', src)
        self.assertIn('function patchSystemBasicInfo', src)
        # OBJECT_ATTRIBUTES->ObjectName 按架构读
        self.assertIn('function readObjectName', src)
        self.assertIn('objNameOff = arch64 ? 16 : 8', src)
        # PROCESSENTRY32.szExeFile 偏移按架构 (x64=44/x86=36)
        self.assertIn('PROC_NAME_OFF = (Process.pointerSize === 8) ? 44 : 36', src)
        # GetUserName 缓冲区是 args[0], 不是 args[1]
        self.assertIn('this.buf = args[0]; this.sz = args[1]', src)


class TestHostSafetyFixes(unittest.TestCase):
    def test_docker_desktop_install_is_not_container(self):
        """物理机装 Docker Desktop 绝不能放行动态分析"""
        import inspect
        import analyzer.vm_detector as vd
        src = inspect.getsource(vd.VMDetector._check_docker)
        self.assertIn('host evidence only', src)
        # Docker Desktop 安装键分支不应再置 is_docker=True
        docker_install_branch = src.split('Windows Docker Desktop 安装键')[1]
        self.assertNotIn('is_docker', docker_install_branch)

    def test_sandbox_no_global_random_name_kill(self):
        import inspect
        import analyzer.sandbox as sb
        src = inspect.getsource(sb.Sandbox.kill_process)
        self.assertIn('已移除旧的', src)
        self.assertNotIn('5-9 字符随机文件名', src)


class TestAuxReportSections(unittest.TestCase):
    def test_spoof_section_shows_priv_and_regsave(self):
        am = APIMonitorResult()
        am._priv_events = [{'api': 'AdjustTokenPrivileges',
                            'privilege': 'SeDebugPrivilege', 'action': 'ENABLED'}]
        am._regsave_events = [{'api': 'RegSaveKeyW', 'file': 'C:\\sam'}]
        am._spoof_actions = [{'api': 'IsDebuggerPresent', 'detail': '返回 FALSE'}]
        report = SimpleNamespace()
        report.api_monitor = am
        report._spoof_summary = {'count': 1, 'apis': ['IsDebuggerPresent']}
        html = HTMLReportGenerator()._build_spoof_section(report)
        self.assertIn('特权启用监控', html)
        self.assertIn('SeDebugPrivilege', html)
        self.assertIn('注册表 hive 保存监控', html)
        self.assertIn('C:\\sam', html)


if __name__ == '__main__':
    unittest.main(verbosity=2)
