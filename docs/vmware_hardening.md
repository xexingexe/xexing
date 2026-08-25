# VMware 虚拟机伪装指南 — 对抗恶意软件的反VM检测

> ⚠️ **重要前提**：必须在已经隔离的 VMware 虚拟机中执行此操作。此指南帮助你的 VM 更像"真实物理机"，但不能替代真正的隔离环境。

## 快速使用（自动模式）

本程序已内置 **自动VM进程隐藏** 功能。当开启动态分析时，程序会自动：
1. 停止 VMware Tools 服务
2. 终止 vmtoolsd.exe 等VM进程
3. 临时重命名VM可执行文件（防止服务自动重启）
4. 动态分析完成后自动恢复

```bash
# 正常开启动态分析（自动隐藏VM进程）
py main.py sample.exe --dynamic

# 禁用自动VM进程隐藏（如果你需要VMware Tools功能）
py main.py sample.exe --dynamic --no-vm-hide

# 手动查看当前VM进程状态
py analyzer/vm_process_hider.py --status

# 手动隐藏VM进程
py analyzer/vm_process_hider.py --hide

# 手动恢复VM进程
py analyzer/vm_process_hider.py --restore
```

## 为什么需要伪装？

现代恶意软件（特别是高级威胁 APT、勒索软件、信息窃取器）普遍带有反VM/反沙箱检测：

| 检测技术 | 原理 | 常见样本 |
|---------|------|---------|
| **注册表检测** | 查询 `HKLM\HARDWARE\DESCRIPTION\System\BIOS` 中的 VM 厂商字符串 | 90% 以上 |
| **MAC 地址检测** | 检查 MAC 前缀（如 `00:50:56` = VMware） | 80% |
| **进程/驱动检测** | 扫描 `vmtoolsd.exe`、`vmci.sys` 等 | 70% |
| **CPUID 指令** | 通过 `CPUID` 叶 0x40000000 读取虚拟机管理程序签名 | 40% |
| **WMI 查询** | `SELECT * FROM Win32_ComputerSystem WHERE Model LIKE '%VMware%'` | 60% |
| **时间差检测** | `GetTickCount` + `Sleep` 检查时间是否被加速/减速 | 30% |
| **硬件指纹** | 检查 CPU 核心数、内存大小、硬盘型号、显卡 BIOS | 50% |
| **交互检测** | 检查鼠标移动、键盘输入、窗口焦点 | 20% |

一旦检测到 VM，恶意程序会：
- **直接退出**（无行为记录）
- **执行无害伪装**（创建空文件、连接正常域名）
- **延迟执行**（等待真实环境）
- **自毁**（删除自身不留痕迹）

---

## 第一步：基础伪装（必须做）

### 1.1 修改 .vmx 文件

关闭虚拟机后，编辑 `.vmx` 配置文件（如 `Windows 10.vmx`），添加/修改以下行：

```ini
# ===== 隐藏 VMware 身份 =====
# 禁用 VMware 工具标识
guestOS.detailed.data = "false"

# 修改 SMBIOS/DMI 信息（模拟 Dell 笔记本）
smbios.reflectHost = "FALSE"
smbios.addHostConfig = "FALSE"

# 伪装 BIOS 信息（模拟真实 Dell 机器）
SMBIOS.useHostInfo = "FALSE"
SMBIOS.useHostMachineID = "FALSE"

# 隐藏虚拟化标志
cpuid.0.eax = "0000:0000:0000:0000:0000:0000:0000:1011"
cpuid.0.ebx = "0111:0101:0110:1110:0110:0101:0100:0111"
cpuid.0.ecx = "0110:1100:0110:0101:0111:0100:0110:1110"
cpuid.0.edx = "0100:1001:0110:0101:0110:1110:0110:1001"

# 禁用 hypervisor 标志（cpuid leaf 0x40000000）
cpuid.1.eax = "0000:0000:0000:0001:0000:0110:0111:0001"
cpuid.1.ebx = "0000:0000:0000:0000:0000:0010:0000:0000"
cpuid.1.ecx = "1000:0010:1001:1000:0010:0010:0000:0011"
cpuid.1.edx = "0000:1111:1010:1011:1111:1011:1111:1111"

# 移除 VMware 特定的 CPU 标志
hypervisor.cpuid.v0 = "FALSE"

# 禁用后门端口（disable backdoor）
isolation.tools.getPtrLocation.disable = "TRUE"
isolation.tools.setPtrLocation.disable = "TRUE"
isolation.tools.setVersion.disable = "TRUE"
isolation.tools.getVersion.disable = "TRUE"
isolation.tools.hgfs.disable = "TRUE"

# 禁用 VMware 拖放/复制粘贴（同时减少被检测面）
isolation.tools.dnd.disable = "TRUE"
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"

# 禁用共享文件夹（如果不需要）
sharedFolder0.present = "FALSE"
sharedFolder.maxNum = "0"

# 修改虚拟硬件版本（越低越像旧物理机）
virtualHW.version = "16"

# 禁用 EFI 安全检查（部分恶意软件检测 Secure Boot）
uefi.secureBoot.enabled = "FALSE"
```

### 1.2 修改 MAC 地址

在 VMware 设置中：
1. 虚拟机设置 → 网络适配器 → 高级
2. 点击 **生成新的 MAC 地址**
3. 确保前缀不是 `00:50:56`（VMware）或 `00:0c:29`（VMware自动）

或者手动在 `.vmx` 中设置：
```ini
ethernet0.address = "00:1A:2B:3C:4D:5E"
ethernet0.addressType = "static"
```

> 使用真实厂商前缀，如 `00:1A:2B`（Intel）、`00:14:22`（Dell）、`00:18:8B`（HP）

---

## 第二步：深度伪装（推荐做）

### 2.1 修改注册表 BIOS 信息（Windows 内部）

在虚拟机内运行以下 `.reg` 文件（管理员权限）：

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS]
"BaseBoardManufacturer"="Dell Inc."
"BaseBoardProduct"="0C1FJ9"
"BaseBoardVersion"="A00"
"BIOSVendor"="Dell Inc."
"BIOSVersion"="1.15.0"
"SystemFamily"="Inspiron"
"SystemManufacturer"="Dell Inc."
"SystemProductName"="Inspiron 15 3511"
"SystemSKU"="0C1FJ9"
"SystemVersion"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation]
"Manufacturer"="Dell Inc."
"Model"="Inspiron 15 3511"
```

### 2.2 卸载/隐藏 VMware Tools

**方案 A：完全卸载 VMware Tools**
```powershell
# 控制面板 → 程序和功能 → 卸载 VMware Tools
# 重启后安装 "vmware-tools-patches" 或完全不装
```

**方案 B：保留功能但隐藏进程**
如果仍需拖放/共享功能，可以：
```powershell
# 停止 VMware Tools 服务
Stop-Service -Name "VMTools" -Force
Stop-Service -Name "vmvss" -Force
Stop-Service -Name "vmicvss" -Force
# 注意：这也会禁用功能
```

### 2.3 修改系统属性（让 WMI 查询返回真实值）

```powershell
# 使用 WMI 修改系统信息（临时，重启失效）
$comp = Get-WmiObject -Class Win32_ComputerSystem
$comp.Manufacturer = "Dell Inc."
$comp.Model = "Inspiron 15 3511"
$comp.Put()

$bios = Get-WmiObject -Class Win32_BIOS
$bios.SerialNumber = "5CD1234ABC"
$bios.Put()
```

### 2.4 模拟真实硬件配置

```powershell
# 修改 CPU 信息（部分恶意软件检查 CPU 核心数）
# 在 .vmx 中设置：
# numvcpus = "4"
# cpuid.coresPerSocket = "4"
# 避免单核/双核（太像VM）

# 修改内存（避免 2GB/4GB 的 VM 默认值）
# memsize = "8192"
```

---

## 第三步：高级对抗（可选）

### 3.1 使用 VMware Workstation Pro 的 "虚拟化 Intel VT-x/EPT" 选项

在 VM 设置 → 处理器 → 勾选：
- [x] 虚拟化 Intel VT-x/EPT 或 AMD-V/RVI

这让 VM 内的 `CPUID` 指令更难检测到 hypervisor。

### 3.2 使用 VMCloak / VMwareHardeningLoader

开源工具（需要自己编译/配置）：
- **VMCloak**：自动修改 VMware 配置和注册表
- **pafish**：检测 VM 的测试工具，反向用于验证伪装效果

### 3.3 使用嵌套虚拟化（Nested Virtualization）

在 VMware 中运行 Windows Sandbox / Hyper-V，这样：
- 恶意软件检测到 Hyper-V 存在
- 可能误判为 "真实机器开启了 Hyper-V 虚拟化"（Windows 10/11 常见）
- 而非 "我在 VM 中"

```ini
# 在 .vmx 中启用嵌套虚拟化
vhv.enable = "TRUE"
hypervisor.cpuid.v0 = "FALSE"
```

### 3.4 使用物理磁盘直通（Raw Disk）

```ini
# 在 .vmx 中（需要管理员权限，危险！）
# 让 VM 直接访问物理磁盘，SCSI 型号会显示真实硬盘
scsi0.present = "TRUE"
scsi0.virtualDev = "lsisas1068"
scsi0:0.deviceType = "rawDisk"
```
> ⚠️ 这会破坏快照功能，且可能导致数据丢失。仅用于专业分析环境。

---

## 第四步：验证伪装效果

### 4.1 使用 Pafish 测试

Pafish（Paranoid Fish）是一个开源的 VM 检测测试工具：

```powershell
# 下载 pafish.exe
# 在 VM 中运行
pafish.exe
# 如果输出全部为 [normal] 或 [not detected]，说明伪装成功
```

### 4.2 使用本程序自检

```bash
py main.py pafish.exe --dynamic --allow-dangerous
# 查看 Advanced Behavior 中的 anti_vm 检测结果
```

### 4.3 手动检查常见检测点

```powershell
# 1. 检查注册表 BIOS
Get-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
# 应该没有 VMware/VirtualBox 字样

# 2. 检查 WMI
Get-WmiObject Win32_ComputerSystem | Select Manufacturer, Model
Get-WmiObject Win32_BIOS | Select SerialNumber, SMBIOSBIOSVersion

# 3. 检查 MAC
Get-NetAdapter | Select Name, MacAddress
# 应该不是 00:50:56 或 08:00:27

# 4. 检查进程
Get-Process | Where-Object { $_.Name -match "vmware|vbox|qemu" }
# 应该没有 VMware Tools 进程

# 5. 检查 CPUID
# 需要专门的工具，如 CPU-Z 或 cpuid.exe
```

---

## 第五步：分析时的行为引诱

即使伪装成功，部分高级样本仍会检查：

| 检查项 | 解决方案 |
|--------|---------|
| **无鼠标移动** | 运行前用鼠标在屏幕上画圈 5 秒 |
| **无键盘输入** | 在记事本中打几个字符再运行样本 |
| **窗口未激活** | 确保样本窗口有焦点 |
| **快速退出** | 延长监控时间（`--timeout 300`） |
| **仅特定时间运行** | 修改系统时间后运行（VM 快照可恢复） |
| **检测调试器** | 不使用附加调试器，仅依赖 Frida API Hook |
| **检测分析工具** | 运行样本前关闭 Process Monitor、Wireshark 等 |

---

## 快速检查清单

运行动态分析前，确认：

- [ ] `.vmx` 已添加伪装配置
- [ ] MAC 地址已改为非 VMware 前缀
- [ ] 注册表 BIOS 信息已修改为真实品牌
- [ ] VMware Tools 已卸载或隐藏
- [ ] CPU 核心数 >= 4
- [ ] 内存 >= 8GB
- [ ] 已运行 Pafish 验证伪装效果
- [ ] 已使用鼠标/键盘模拟真实用户
- [ ] 已关闭所有分析工具（Process Monitor、Wireshark 等）
- [ ] VMware 已创建快照（分析后回滚）

---

## 参考工具

| 工具 | 用途 | 链接 |
|------|------|------|
| **Pafish** | VM 检测测试 | github.com/a0rtega/pafish |
| **VMCloak** | 自动 VM 伪装 | github.com/hatching/vmcloak |
| **Al-Khaser** | 综合反分析检测 | github.com/LordNoteworthy/al-khaser |
| **SharpExec** | 反 VM 检测测试 | 内置于本程序 |

---

> 💡 **最佳实践**：创建两个 VM 快照 — "伪装前"（干净系统）和 "伪装后"（已配置）。每次分析前从 "伪装后" 快照恢复，分析后回滚。
