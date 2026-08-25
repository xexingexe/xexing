# 叾嗣 (Malware Analysis Platform)

> 本地优先的 Windows 恶意软件分析沙箱 · 作者: xexing · v3.4.0

叾嗣是一款 Windows 平台的本地恶意软件分析沙箱，支持静态分析、动态行为分析、网络流量捕获、多引擎威胁情报、内存取证与可视化报告，用于判断可疑文件（exe/dll/脚本/压缩包/Office 文档/URL）是否恶意。

> ⚠️ **安全警告**：本工具会实际执行样本。**必须在隔离的虚拟机中运行**，切勿在物理机/宿主机上直接分析真实恶意样本。

## 功能特性

### 静态分析
- PE 结构分析（节区 / 导入表 / 熵值 / 加壳检测）
- 字符串提取、反混淆检测、Overlay 载荷检测
- Office 宏分析（docx / xlsm）
- YARA 规则扫描（38 规则集）
- Sigma 规则检测（31 规则）
- 木马家族识别

### 动态行为分析（Frida + 沙箱）
- Frida API 监控（177 个 API 规格）
- 内存保护监控：RW→RX 转换、RWX 分配、DEP 绕过、ROP 喷射、远程注入
- 反 VM / 反沙箱 / 反调试检测 + 自动绕过（磁盘 / 注册表 / MAC / SMBIOS 等 8 项）
- 子进程捕获与进程树还原
- 系统进程 DLL 注入检测（lsass / services / winlogon 等）
- 释放文件追踪与内容分析

### 网络分析
- PCAP 抓包（多网卡并发，需 Npcap）
- DNS 查询与 C2 情报关联
- TCP / UDP 连接 + 上下行流量统计
- HTTP 明文载荷还原（WinHTTP / WinINet 高层 API，HTTPS 加密前的明文）
- URL 挂马扫描（playwright 浏览器动态监控）

### 威胁情报（多引擎）
- 本地 IoC 库（支持自定义）
- MalwareBazaar / Triage / URLhaus（免费，无需 Key）
- VirusTotal（需 API Key）
- ThreatBook 微步在线（需 API Key）
- ClamAV（内置引擎 + 病毒库，开箱即用）

### 系统监控 & 内存取证
- ETW 内核注册表监控（写操作全覆盖）
- WMI 进程创建事件实时捕获
- 内存快照、Shellcode 检测、PE 注入检测

### 报告
- HTML 报告（ECharts 交互图表、MITRE ATT&CK 矩阵、执行流程思维导图、行为时间线）
- PDF / JSON 导出
- 证据包（PCAP / 截图 / 日志）

## 快速开始

### 方式一：打包版（推荐，免装环境）
1. 运行 `叾嗣.exe`（onedir 打包，含全部依赖与 ClamAV 引擎）
2. 双击进入 GUI，拖入样本文件开始分析

### 方式二：源码运行

```bash
# 环境: Windows 10/11 x64 + Python 3.12+
pip install -r requirements.txt

# 启动 GUI
python main.py --gui

# 或命令行分析
python main.py malware.exe --dynamic --enable-network
```

> 网络抓包需要额外安装 [Npcap](https://npcap.com/)（安装时勾选 "WinPcap API-compatible Mode"）。

## 命令行用法

```bash
python main.py <文件>                              # 静态分析
python main.py <文件> --dynamic                    # 静态 + 动态分析
python main.py <文件> --dynamic --enable-network   # 含网络抓包
python main.py --url http://example.com            # URL 挂马扫描
python main.py --batch <目录>                      # 批量扫描
python main.py --watch <目录>                      # 热文件夹监控
python main.py --version                           # 版本信息
```

常用参数：

| 参数 | 说明 |
|---|---|
| `--dynamic` | 开启动态分析 |
| `--enable-network` | 启用网络流量捕获 |
| `--no-sandbox` | 禁用沙箱 |
| `--allow-dangerous` | 允许在物理机运行（危险） |
| `--time-accel` | 时间加速（Sleep 压缩 1000x） |
| `--deep-dive` | 深度追踪分析 |
| `--archive-password` | 加密压缩包密码（逗号分隔） |

## 配置 API Key（可选）

威胁情报中的 VirusTotal / 微步在线需要 API Key：

1. 打开 GUI → 「⚙ 参数设置」→ 「威胁情报 API」分组
2. 填入微步在线 / VirusTotal 的 API Key（留空则不查询）
3. 点「保存并关闭」，写入 exe 同级的 `config.json`

也可直接编辑 `config.json`：

```json
{
  "api_keys": {
    "threatbook": "你的微步APIKey",
    "virustotal": "你的VT APIKey"
  }
}
```

## 目录结构

```
├── main.py            # 入口（GUI / CLI）
├── orchestrator.py    # 分析编排
├── analyzer/          # 分析模块（静态 / 动态 / 网络 / 威胁情报 / 内存）
├── gui/               # tkinter GUI
├── report/            # 报告生成（HTML / PDF / JSON）
├── rules/             # YARA 规则 + 自定义 IoC
├── docs/              # 说明文档
├── tests/             # 测试
└── config.json        # 配置（API Key 等）
```

## 安全与免责声明

- 仅供安全研究、恶意软件分析、授权测试使用，请遵守当地法律法规。
- 样本具有真实恶意行为，**必须在隔离的虚拟机中运行**，不要在物理机 / 生产环境执行。
- 使用本工具造成的任何后果由使用者自行承担。

## 作者

xexing
