# 沙箱 v3.4 改进说明

## 1. DEP 绕过行为时间线与流程图
- `orchestrator._build_behavior_timeline` 现在会把 Frida `memprot` 事件
  （RW→RX / RWX 分配 / DEP绕过 / ROP喷射 / 超大分配 / 远程注入）写入行为时间线，
  类别 `dep`，并在报告顶部显示。
- HTML 报告新增「DEP 绕过行为时间线流程图」章节：
  `载荷准备/解密 → RWX 分配(DEP绕过) → 载荷写入 → 执行劫持 → 载荷执行/回连`
  五阶段节点，命中阶段自动点亮并附关键内存保护事件表。
- 行为检测章节新增 memprot 判定、DEP 动态参数确认
  （NtAllocateVirtualMemory/NtProtectVirtualMemory RWX 参数、写后执行链）。
- 相关测试: `tests/test_v34_improvements.py::TestDepBypassTimelineAndFlow`。

## 2. 行为检测 / 深度追踪分析
- 深度追踪分析 (DeepDive) 默认在动态分析后自动执行
  （`config.deep_dive.auto_enabled = true`；CLI 可用 `--no-deep-dive` 关闭，
  GUI 勾选项默认开启）。不再必须手动加 `--deep-dive`。
- 高级行为检测新增:
  - 七组条件反沙箱评分（IsDebuggerPresent + GetSystemMetrics + CPU +
    GetTickCount + 内存 + 进程数 + 用户名黑名单）静态与动态 API 双确认；
  - DEP 绕过 / RW→RX / 远程线程执行链的动态确认；
  - 内存分配未释放 (alloc/free 失衡) 行为；
  - 用户名黑名单字符串检测（仅在与 GetUserName/环境变量同上下文时触发，避免误报）。

## 3. 内存检测：目标进程退出不再只提示“内存退出”
- `MemoryAnalysis` 新增 `process_exited / live_analyzed / exit_diagnosis` 字段。
- 目标进程退出时，`_build_memory_exit_diagnosis` 综合:
  - API 调用记录中的分配/释放次数（VirtualAlloc/VirtualFree/NtAllocate/NtFree 等）；
  - memprot 事件（RWX/DEP/ROP/RW→RX/远程注入/超大分配）；
  - 执行期内存快照、残留 `pid*.bin` dump 离线取证；
  生成明确结论（如“内存未释放: 分配×10 / 释放×2；退出前 DEP绕过×1”）。
- HTML 内存章节新增统计项（分配/释放/未释放/退出前事件）与
  “目标进程已退出 — 内存检测结论”诊断块；风险评分对内存泄漏和退出前
  DEP/RW→RX 事件计分（memprot 已计分的部分不重复加分）。

## 4. 木马家族识别准确率
- 网络端口证据改为上下文匹配（`:443`、`port=443` 等），避免 URL/数字撞库。
- `_reselect_primary` 统一重选主家族并同步 summary；排序加入强证据数。
- 仅 API 名称/端口/通用字符串等弱证据凑出的低置信度匹配（<30 且无强证据）
  不再报具体家族，输出“不足以判定具体家族”。
- 新增 `refine_with_threat_intel`: 多引擎情报家族结论（外部证据）融入本地识别。
- HTML 家族章节展示候选家族证据、置信度条和命中规则，便于人工复核。

## 5. 沙箱环境伪装补全
针对 `IsSandboxEnvironment@0x140002E20` 七条件检查与 13 项 VM 检查:

| 检查项 | 伪装方式 |
| --- | --- |
| 注册表 3 条 | RegOpenKeyExW/A、NtOpenKey 拦截；VMProcessHider 备份删除 Hyper-V Guest 键 |
| 文件/设备 6 条 | CreateFileW/A、NtCreateFile、NtOpenFile、GetFileAttributesW/A 拦截 `\\.\vmci`、`\\.\HGFS`、`\\.\VBoxMiniRdrDN`、驱动 sys |
| 进程 4 条 | Process32First/Next W/A 改写 VM/Frida 进程名为 svchost.exe（保留条数，进程数不受影响） |
| !IsDebuggerPresent | Frida 返回 FALSE + ProcessDebugPort/Flags 伪造 |
| 分辨率>=800 | GetSystemMetrics 伪造 1920x1080、单显示器、本地会话 |
| CPU>=2 | GetSystemInfo/GetNativeSystemInfo/NtQuerySystemInformation(0) 伪造 8 核 |
| GetTickCount>=300000 | 反VM脚本默认 +15 分钟（无需开时间加速） |
| 内存>=2GB | GlobalMemoryStatusEx/GlobalMemoryStatus/GetPhysicallyInstalledSystemMemory 伪造 8GB |
| 进程数>=10 | FakeUserEnvironment 进程数不足时拉起无窗口填充进程（cleanup 树级 taskkill 清理） |
| 用户名黑名单 | GetUserNameA/W、GetUserNameExW、USERNAME 环境变量伪造为 `zhangwei`（config.sandbox.env_fake_username 可改） |

## 6. 其他修复
- 版本号升级为 `3.4.0`。
- 家族识别的威胁情报精炼链路接通（orchestrator 第 8 步）。
- `test_v34_improvements.py` 新增 12 个回归测试；全量 43 个测试通过。
- Frida 脚本通过 Node.js 语法检查。

## 7. DLL 调用监控 / API 欺骗 / AMSI / 特权 / hive 审计修复（第二轮）
审计 `FRIDA_SPOOF_SCRIPT`、关机拦截、时间加速、memprot 及 `dynamic.py` 结果合并后修复：

1. **最严重**：`dynamic.py` 合并多个 Frida 结果时只拼接 `call_records`，
   把 `_memprot_events / _dll_calls / _spoof_actions / _amsi_events /
   _priv_events / _regsave_events / shutdown_blocked` 全部丢弃，
   导致报告里的“DLL 调用监控 / API 欺骗 / 内存保护监控 / AMSI / 特权 / hive”章节永远为空。
   → 新增 `APIMonitor.merge_results()` 全量合并，并重算 `call_summary` 与可疑序列。
2. AMSI 脚本调用未定义的 `_arrayToB64` → AMSI 扫描事件被静默吞掉。
   → 内置 Base64 编码器；`amsi.dll` 延迟加载时也会补 hook。
3. `AdjustTokenPrivileges` 的 TOKEN_PRIVILEGES 解析偏移错误（8 应为 4），
   SeDebug/SeBackup 启用事件漏检 → 已修复。
4. 关机拦截脚本只在加载瞬间发送空数组，实际拦截记录永远到不了报告 → 改为每次拦截增量上报，Python 侧合并去重。
5. `NtLoadDriver` 的 UNICODE_STRING.Buffer 偏移在 32 位进程下错误（固定 8） → 按 `Process.pointerSize` 自适应。
6. DLL 调用字典超过 2000 项时裁剪逻辑永远不生效（新增的 key 一定在字典里） → 改为淘汰最旧项。
7. AMSI/特权/regsave 事件只存到临时局部列表，`_finalize_result` 不回填 → 初始化实例列表并在结果中回填。
8. 风险评分补充：特权启用、注册表 hive 保存、AMSI 卸载调用现在会计分。
9. HTML「API 欺骗与专项监控」章节现在展示假反馈明细、特权事件、注册表 hive 保存事件。
10. 新增 `tests/test_frida_aux_features.py`（7 个纯内存回归测试），全量测试增至 50 个，全部通过。

