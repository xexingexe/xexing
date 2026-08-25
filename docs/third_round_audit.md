# 第三轮全面审计 — 已修复与剩余风险

说明：以下审计全部只读代码 + 纯内存单元测试，未执行任何样本、未改动宿主系统。

## A. 已修复（本轮）

### A1. 反沙箱/伪装脚本结构偏移错误（高优先级）
- `GetUserNameA/W` 参数错位（缓冲区应为 `args[0]`，长度 `args[1]`）→ 已修复。
- `GetSystemInfo` 误用 `SYSTEM_BASIC_INFORMATION` 布局越界写 → 拆分 `patchSystemInfoStruct` / `patchSystemBasicInfo`。
- `RegQueryValueExW/A` onLeave 用易失寄存器/错误栈偏移 → 改为 onEnter 保存 `args[3..5]` 并检查缓冲区容量。
- `OBJECT_ATTRIBUTES->ObjectName` 偏移 x64/x86 混用 → 新增 `readObjectName()` 统一处理。
- `PROCESSENTRY32.szExeFile` 固定 36 → x64=44/x86=36；`MODULEENTRY32.szModule` 同理。
- `GetAdaptersInfo` 用错寄存器且 MAC 偏移错误 → 改为 `args[1]` + 408/404 架构自适应。
- `GetUserNameExW` 增加 NameSamCompatible/Domain 格式；补 `GetEnvironmentVariableA`、`RegQueryValueExA`。
- 假卸载项中删除 `Oracle VirtualBox 7.0`（会反向暴露 VM）。
- fake_user_env 现在记录并清理本次创建的桌面文件/浏览器目录/注册表键值。

### A2. 物理机安全（最高优先级）
- `vm_detector`：安装 Docker Desktop 不再被判定为容器/safe，只有容器内证据才放行动态分析。
- `sandbox.kill_process`：删除“随机名进程全局启发式清理”，不再按文件名误杀宿主进程；延迟载荷只按释放文件精确匹配补杀。
- `web_monitor`：HTTP 服务由 `0.0.0.0` 改为 `127.0.0.1`，避免局域网未授权读取报告。

### A3. 清理脚本生成安全
- 预览区所有来自样本行为的名称/路径统一 `_ps_str` 转义，堵住样本注入 SYSTEM PowerShell。
- 不再整值删除 `PendingFileRenameOperations` 与 LSA `Security/Notification/Authentication Packages`，改为报告提示（整删会破坏系统/合法安全包）。
- UAC 恢复默认值按微软标准：`EnableLUA=1, ConsentPromptBehaviorAdmin=5, PromptOnSecureDesktop=1`。
- `vm_process_hider`：`--restore` 现在从 `%TEMP%\sandbox_vm_hider_state_v2.json` 恢复上次状态；注册表备份改为递归全量导出/恢复（原只备份两层但递归删除）。

### A4. 内存/报告误报与污染
- 释放的 PE/DLL 不再伪称“内存 PE 注入”，新增 `released_pe_files` 单独展示且不参与注入计分。
- 残留 dump 补录只处理本次分析开始后新生成的文件，排除历史扫描产物与“加载模块”快照 dump。
- 内存退出诊断只统计真实挂钩的 `VirtualAlloc/VirtualAllocEx/NtAllocateVirtualMemory` 系列。
- 快照派生的 PE/Shellcode/RWX 不再与“内存快照×N”双重计分。
- 内存实时分析异常不再静默吞掉。
- 内存扫描兜底不再把模块区（含 Frida/样本自身）误报为注入。
- RWX 组合保护位（0xC0/0x140 等）按位判断，修复漏报。
- 64 位 PEB `NtGlobalFlag` 偏移 0xBC（32 位 0x68）。
- HTML 行为证据统一 `_esc`，`scan_id` 进入 JS 前 JSON 转义。

### A5. 静态引擎/情报/URL
- URL 扫描新增 SSRF 防线：逐跳拦截回环/内网/链路本地/云元数据；连接失败不再给 medium/30 分。
- `index.php/info.php` 文件名不再单独判 WebShell；可执行文件下载链接降为 low。
- YARA 纯 Python 解析器支持多行 condition 与 `//` 注释剥离；`Fake_Huorong` 条件收紧；`NSIS_Installer_Abuse` 降为 medium；`WebSocket_C2` 条件收紧。
- Sigma 文件规则正则 `\\.` → `\.`，修复 Temp/AppData 释放检测失效。
- `signature_engine`：删除 `0xFFFFFFFF` 单命中即键盘记录器的规则，要求与 SetWindowsHookEx 同现。
- `rat_config`：删除 `hex_config` 泛规则；通用 C2 至少 2 个证据；SMTP 凭据仅在已命中家族/强证据时提取。
- 自定义 IoC 文件改为临时文件 + `os.replace` 原子写；威胁情报异常日志对 apikey/token 脱敏。
- Tor 出口列表下载不再禁用 TLS 校验；psutil 网络监控补充 UDP/DNS 连接。
- URL 动态下载改为流式限量落盘；多引擎临时目录全部清理。
- `archive` 7z 按文件逐条 reserve，修复文件数限制绕过。

### A6. 家族/检测
- 家族置信度 <30 一律不报具体家族（修复 `au`→QakBot、`apple`→Lazarus 类误报）。
- `destruction.py` 移除常见导入表条目（CryptEncrypt/CryptGenKey/OpenProcess/WriteProcessMemory/通用注册表写）的破坏性计分；`sc start` 不再单独判驱动加载。
- 持久化回滚支持“样本修改既有 Run 键”时恢复旧值。

## B. 已记录但尚未修复（剩余风险）
1. Scapy 抓包路径仍无法按 `target_pid` 过滤，需按目标进程端口过滤或默认改用 psutil 模式。
2. URL 动态浏览器（Playwright）页面内 JS 访问内网仍缺少 SSRF 拦截，需 `context.route`/代理隔离。
3. URL 默认 `ignore_https_errors=True`，需评估是否改为默认严格校验。
4. 重定向域名判定仍按主机名而非注册域（`example.com → www.example.com` 可能误报外部跳转）。
5. cleanup 的 hosts 清理仍按域名黑名单删行，未完全按 diff 还原；建议后续只删系统监控 diff 中新增行。
6. `archive` 解压目录缺少统一清理入口，批量扫描会堆积解压文件。
7. ZIP 密码破解每次读取整个加密条目，建议只读前 64 字节验证。
8. `index_generator` URL stem 40 字符截断可能链到旧报告，建议加短哈希。
9. PDF 长字符串溢出/中文乱码问题（低优先级）。
10. `network.py` Tor 节点、URL 动态爬虫 body 读上限仍可继续收紧。

## C. 验证
- 新增/更新回归测试后全量 **53/53 通过**。
- `compileall` 通过；6 个 Frida JS 脚本通过 Node 语法检查。
- 未运行任何样本；动态分析在物理机仍默认被拒绝（需 `--allow-dangerous` 且不推荐）。
