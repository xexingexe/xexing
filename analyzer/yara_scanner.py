#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""YARA 扫描引擎 — 加载规则文件，扫描样本和释放文件"""
import os
import glob
import re
from typing import List, Dict
from logger import get_logger

logger = get_logger('analyzer.yara')

try:
    __import__('yara')
    YARA_OK = True
except ImportError:
    YARA_OK = False


# 内置规则（纯文本 YARA，不需要编译）
BUILTIN_RULES = """
rule SilverFox_MSI_Installer {
    meta:
        description = "SilverFox malware MSI installer"
        family = "SilverFox"
        severity = "high"
        mitre = "T1218.007"
    strings:
        $s1 = "Ali Licensing Agent Dll" nocase
        $s2 = "ProductVersion" nocase
        $s3 = "ALLUSERS" nocase
        $s4 = "{DBE37440-1514-4BD7-8D8E-BFF5D9F3B754}"
    condition:
        2 of them
}

rule SilverFox_Payload_DLL {
    meta:
        description = "SilverFox UxEnhance64.dll sideload payload"
        family = "SilverFox"
        severity = "high"
        mitre = "T1574.002"
    strings:
        $s1 = "UxEnhance64" nocase
        $s2 = "msadox" nocase
        $s3 = "adoresd" nocase
    condition:
        any of them
}

rule Windows_Defender_Exclusion {
    meta:
        description = "Adds Windows Defender exclusion path"
        family = "DefenseEvasion"
        severity = "high"
        mitre = "T1562.001"
    strings:
        $reg1 = "Windows Defender\\\\Exclusions\\\\Paths" nocase
        $cmd1 = "reg add" nocase
        $excl = "Exclusions" nocase
    condition:
        ($reg1 and $cmd1) or ($reg1 and $excl)
}

rule Scheduled_Task_Persistence {
    meta:
        description = "Creates scheduled task for persistence"
        family = "Persistence"
        severity = "medium"
        mitre = "T1053.005"
    strings:
        $sch1 = "SCHTASKS /Create" nocase
        $sch2 = "schtasks /create" nocase
        $tn = "/TN" nocase
        $sc = "/SC" nocase
    condition:
        ($sch1 or $sch2) and $tn and $sc
}

rule MSI_AlwaysInstallElevated {
    meta:
        description = "MSI running with elevated SYSTEM privileges"
        family = "PrivilegeEscalation"
        severity = "high"
        mitre = "T1548.002"
    strings:
        $msi1 = "MsiExec.exe -Embedding" nocase
        $msi2 = "MSI" nocase
    condition:
        $msi1 and $msi2
}

rule VM_Detection_Disk_Size {
    meta:
        description = "Queries system disk size to determine if running in VM"
        family = "AntiVM"
        severity = "high"
        mitre = "T1082"
    strings:
        $disk1 = "GetDiskFreeSpace" nocase
        $disk2 = "GetDiskFreeSpaceEx" nocase
        $disk3 = "IOCTL_DISK_GET_DRIVE_GEOMETRY" nocase
        $disk4 = "IOCTL_STORAGE_GET_DEVICE_NUMBER" nocase
        $disk5 = "SMART_RCV_DRIVE_DATA" nocase
        $vm1 = "VMWARE" nocase
        $vm2 = "VBOX" nocase
        $vm3 = "VirtualBox" nocase
    condition:
        // ⚠ 收紧: GetDiskFreeSpaceEx/GlobalMemoryStatusEx/DeviceIoControl 单独出现
        //   是正常程序常态 (历史误报源), 需要 磁盘几何IOCTL + VM痕迹 组合才可信
        (($disk3 or $disk4 or $disk5) and ($vm1 or $vm2 or $vm3)) or
        (($disk1 or $disk2) and ($disk3 or $disk4 or $disk5))
}

rule Hidden_File_Attribute {
    meta:
        description = "Sets file attributes to hidden"
        family = "DefenseEvasion"
        severity = "medium"
        mitre = "T1564.001"
    strings:
        $a1 = "SetFileAttributes" nocase
        $a2 = "FILE_ATTRIBUTE_HIDDEN" nocase
        $a3 = "attrib +h" nocase
    condition:
        any of them
}

rule SilverFox_Dropped_Files {
    meta:
        description = "SilverFox characteristic dropped file pattern"
        family = "SilverFox"
        severity = "high"
    strings:
        $f1 = "UxEnhance64.dll"
        $f2 = "msadox.tb"
        $f3 = "adoresd.dat"
        $f4 = "ranchserv.jpg"
    condition:
        2 of them
}

rule SilverFox_OpenPGP_Key {
    meta:
        description = "SilverFox embedded OpenPGP public key for encrypted C2"
        family = "SilverFox"
        severity = "critical"
        mitre = "T1573.001"
    strings:
        $pgp1 = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        $pgp2 = "-----BEGIN PGP MESSAGE-----"
        $pgp3 = "OpenPGP Public Key"
        $pgp5 = "Version: " nocase
        $pgp6 = "Comment: " nocase
    condition:
        ($pgp1 or $pgp2 or $pgp3) and ($pgp5 or $pgp6)
}

rule SilverFox_Zlib_Payload {
    meta:
        description = "SilverFox zlib compressed data payload in memory"
        family = "SilverFox"
        severity = "high"
        mitre = "T1027"
    strings:
        $z1 = {78 9C}   // zlib default compression header
        $z2 = {78 DA}   // zlib max compression header
        $z3 = {78 01}   // zlib no compression header
        $s1 = "UxEnhance64" nocase
        $s2 = "msadox" nocase
    condition:
        (any of ($z1, $z2, $z3)) and ($s1 or $s2)
}

rule SilverFox_NvmlBin {
    meta:
        description = "SilverFox nvml.bin dropped file (OpenPGP key payload)"
        family = "SilverFox"
        severity = "high"
    strings:
        $f1 = "nvml.bin"
        $f2 = "nvml" nocase
        $pgp = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        $s1 = "UxEnhance64" nocase
        $s2 = "adoresd" nocase
    condition:
        ($f1 or ($f2 and $pgp)) or (($f1 or $f2) and ($s1 or $s2))
}

rule SilverFox_Memory_File_Payloads {
    meta:
        description = "SilverFox multi-type memory file payloads (PE+zlib+OpenPGP)"
        family = "SilverFox"
        severity = "critical"
    strings:
        $pe = "This program cannot be run in DOS mode"
        $zlib_hdr = {78 9C}
        $pgp_key = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        $s1 = "UxEnhance64" nocase
        $s2 = "adesd" nocase
    condition:
        ($pe or $zlib_hdr) and ($pgp_key or $s1 or $s2)
}

rule C2_Encrypted_OpenPGP {
    meta:
        description = "OpenPGP-based encrypted C2 communication"
        family = "C2"
        severity = "high"
        mitre = "T1573.001"
    strings:
        $pgp1 = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        $pgp2 = "-----BEGIN PGP MESSAGE-----"
        $pgp3 = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        $pgp4 = "OpenPGP Public Key"
        $c2_1 = "aliyuncs.com" nocase
        $c2_2 = "oss-cn-" nocase
    condition:
        // ⚠ 收紧: 裸 "pgp"/"gpg" 字符串 + 阿里云 OSS (正常云服务) 单独都不足信 —
        //   真实 PGP 密钥块头 + C2 域名才命中 (历史误报源)
        ($pgp1 or $pgp2 or $pgp3 or $pgp4) and ($c2_1 or $c2_2)
}

rule SilverFox_nvgpu_Payload {
    meta:
        description = "SilverFox nvgpu_x64.exe payload in Common Files"
        family = "SilverFox"
        severity = "high"
        mitre = "T1543.003"
    strings:
        $f1 = "nvgpu_x64.exe"
        $f2 = "nvgpu.exe"
        $d1 = "Common Files\\vgpu"
        $d2 = "Program Files\\\\Common Files"
    condition:
        ($f1 or $f2) and ($d1 or $d2)
}

rule COM_Surrogate_Abuse {
    meta:
        description = "COM Surrogate dllhost.exe abuse for lateral movement"
        family = "DefenseEvasion"
        severity = "high"
        mitre = "T1559.001"
    strings:
        $c1 = "dllhost.exe" nocase
        $c2 = "/Processid:" nocase
        $c3 = "DllSurrogate" nocase
        $c4 = "{F8284233"
    condition:
        // ⚠ 收紧: DllSurrogate/CLSID {F8284233 是系统 COM 正常运行注册表值,
        //   单独出现即命中会把所有含 COM 注册信息的程序误报 (历史误报源)
        ($c1 and $c2) or (($c3 or $c4) and $c1)
}

rule AntiSandbox_TimeDisk_Combo {
    meta:
        description = "GetTickCount64 + GetDiskFreeSpaceEx combo (anti-VM+anti-sandbox)"
        family = "AntiAnalysis"
        severity = "high"
        mitre = "T1497"
    strings:
        $t1 = "GetTickCount64" nocase
        $t2 = "GetTickCount" nocase
        $d1 = "GetDiskFreeSpaceEx" nocase
        $d2 = "GetDiskFreeSpace" nocase
    condition:
        ($t1 or $t2) and ($d1 or $d2)
}

rule WebSocket_C2 {
    meta:
        description = "WebSocket-based C2 realtime channel"
        family = "C2"
        severity = "medium"
        mitre = "T1071.001"
    strings:
        $ws1 = "Sec-WebSocket-Key" nocase
        $ws2 = "Sec-WebSocket-Version" nocase
        $ws3 = "ws://"
        $ws4 = "wss://"
        $ws5 = "Upgrade: websocket" nocase
    condition:
        ($ws3 or $ws4) and ($ws1 or $ws2 or $ws5)
}

rule Injection_ReflectiveDLL {
    meta:
        description = "Reflective DLL loading via RW->RX memory protection change"
        family = "Injection"
        severity = "critical"
        mitre = "T1620"
    strings:
        $v1 = "VirtualProtect" nocase
        $v2 = "NtProtectVirtualMemory" nocase
        $l1 = "LoadLibrary" nocase
        $l2 = "GetProcAddress" nocase
        $r1 = "PAGE_EXECUTE_READ" nocase
    condition:
        ($v1 or $v2) and ($l1 or $l2) and $r1
}

rule SilverFox_Domo_anti_exe {
    meta:
        description = "SilverFox anti.exe payload in Domo directory"
        family = "SilverFox"
        severity = "high"
    strings:
        $d1 = "Domo" nocase
        $d2 = "anti.exe" nocase
        $d3 = "\\\\AppData\\\\Roaming\\\\Domo" nocase
    condition:
        ($d1 and $d2) or $d3
}

rule SilverFox_XPSPLOG_DLL {
    meta:
        description = "SilverFox XPSPLOG.dll DLL side-loading payload"
        family = "SilverFox"
        severity = "high"
        mitre = "T1574.002"
    strings:
        $d1 = "XPSPLOG.dll" nocase
        $d2 = "XPSPLOG" nocase
        $d3 = "Program Files (x86)"
    condition:
        $d1 or ($d2 and $d3)
}

rule SilverFox_DropsJPG_Payload {
    meta:
        description = "SilverFox drops[N].jpg disguised payload in IE cache"
        family = "SilverFox"
        severity = "high"
    strings:
        $f1 = "drops[1].jpg" nocase
        $f2 = "drops[" nocase
        $f3 = "\\\\AppData\\\\Roaming\\\\IE\\\\" nocase
    condition:
        $f1 or ($f2 and $f3)
}

rule UAC_Bypass_Consent {
    meta:
        description = "UAC ConsentPromptBehavior modification"
        family = "PrivilegeEscalation"
        severity = "critical"
        mitre = "T1548.002"
    strings:
        $u1 = "ConsentPromptBehaviorAdmin" nocase
        $u2 = "EnableLUA" nocase
        $u3 = "Policies\\\\System" nocase
    condition:
        ($u1 or $u2) and $u3
}

rule HostsFile_Tampering {
    meta:
        description = "System hosts file modification"
        family = "DefenseEvasion"
        severity = "high"
        mitre = "T1562.001"
    strings:
        $h1 = "\\\\drivers\\\\etc\\\\hosts" nocase
        $h2 = "\\\\etc\\\\hosts" nocase
        $w1 = "WriteFile" nocase
        $w2 = "CreateFile" nocase
    condition:
        ($h1 or $h2) and ($w1 or $w2)
}

rule PowerShell_Registry_Persist {
    meta:
        description = "PowerShell adding registry keys for persistence"
        family = "Persistence"
        severity = "high"
        mitre = "T1059.001"
    strings:
        $ps1 = "powershell" nocase
        $reg1 = "reg add" nocase
        $reg2 = "Set-ItemProperty" nocase
        $reg3 = "New-ItemProperty" nocase
    condition:
        $ps1 and ($reg1 or $reg2 or $reg3)
}

rule AntiForensics_DeleteOnClose {
    meta:
        description = "File marked for delete on close (anti-forensics)"
        family = "DefenseEvasion"
        severity = "medium"
        mitre = "T1070.004"
    strings:
        $d1 = "FILE_FLAG_DELETE_ON_CLOSE" nocase
        $d2 = "MOVEFILE_DELAY_UNTIL_REBOOT" nocase
        $d3 = "DeleteOnClose" nocase
        $d4 = "NtDeleteFile" nocase
    condition:
        any of them
}

rule SilverFox_5Layer_Release {
    meta:
        description = "SilverFox 5-layer release chain (MSI+Public+Domo+PFx86+Temp)"
        family = "SilverFox"
        severity = "critical"
    strings:
        $m1 = "\\\\Windows\\\\Installer\\\\" nocase
        $p1 = "\\\\Users\\\\Public\\\\" nocase
        $d1 = "\\\\AppData\\\\Roaming\\\\Domo\\\\" nocase
        $x1 = "\\\\Program Files (x86)\\\\" nocase
        $t1 = "\\\\Windows\\\\Temp\\\\" nocase
        $pgp = "OpenPGP" nocase
    condition:
        3 of ($m1, $p1, $d1, $x1, $t1) or (2 of ($m1, $p1, $d1, $x1, $t1) and $pgp)
}

rule SilverFox_MSI_Metadata {
    meta:
        description = "SilverFox MSI installer metadata (Ali Licensing Agent Dll)"
        family = "SilverFox"
        severity = "high"
        mitre = "T1218.007"
    strings:
        $s1 = "Ali Licensing Agent Dll" nocase
        $s2 = "Ali Inc." nocase
        $s3 = "Ali Ali Client Dll" nocase
        $s4 = "WiX Toolset" nocase
        $s5 = "{DBE37440-1514-4BD7-8D8E-BFF5D9F3B754}"
    condition:
        ($s1 or $s2 or $s3) and ($s4 or $s5)
}

rule Windows_Update_Sabotage {
    meta:
        description = "Disables Windows Update services and destroys update DLLs"
        family = "DefenseEvasion"
        severity = "critical"
        mitre = "T1562.001"
    strings:
        $svc1 = "wuauserv" nocase
        $svc2 = "UsoSvc" nocase
        $dll1 = "wuaueng" nocase
        $dll2 = "WaaSMedicSvc" nocase
    condition:
        ($svc1 or $svc2) and ($dll1 or $dll2)
}

rule Schtasks_OneShot_DefenderExclusion {
    meta:
        description = "Schtasks Create/Run/Delete one-shot for Defender exclusion (SilverFox signature technique)"
        family = "SilverFox"
        severity = "critical"
        mitre = "T1053.005"
    strings:
        $sch1 = "SCHTASKS /Create" nocase
        $sch2 = "SCHTASKS /Run" nocase
        $def1 = "Defender\\\\Exclusions\\\\Paths" nocase
        $def2 = "reg add" nocase
    condition:
        $sch1 and $sch2 and ($def1 or $def2)
}

rule VSSAdmin_Delete_Shadows {
    meta:
        description = "Deletes Volume Shadow Copies (pre-ransomware/wiper behavior)"
        family = "Ransomware"
        severity = "critical"
        mitre = "T1490"
    strings:
        $v1 = "vssadmin delete shadows" nocase
        $v2 = "vssadmin.exe delete shadows" nocase
        $v3 = "/all /quiet" nocase
    condition:
        ($v1 or $v2) and $v3
}

rule ICACLS_Takeown_Permission {
    meta:
        description = "icacls/takeown file permission manipulation"
        family = "DefenseEvasion"
        severity = "high"
        mitre = "T1222.001"
    strings:
        $i1 = "icacls" nocase
        $i2 = "/inheritance:r" nocase
        $t1 = "takeown /f" nocase
        $g1 = "/grant" nocase
    condition:
        ($i1 and ($i2 or $g1)) or $t1
}

rule SilverFox_appinstall_MSI {
    meta:
        description = "SilverFox appinstall.NNNNNNN pattern MSI dropper"
        family = "SilverFox"
        severity = "high"
    strings:
        $a1 = "appinstall." nocase
        $a2 = ".msi" nocase
        $s1 = "Ali Licensing Agent" nocase
    condition:
        ($a1 and $a2) or $s1
}

rule Keylogger_SetWindowsHook {
    meta:
        description = "Keyboard input capture via SetWindowsHook (keylogger)"
        family = "Infostealer"
        severity = "high"
        mitre = "T1056.001"
    strings:
        $h1 = "SetWindowsHookEx" nocase
        $h2 = "SetWindowsHookExA" nocase
        $h3 = "SetWindowsHookExW" nocase
        $k1 = "WH_KEYBOARD" nocase
        $k2 = "WH_KEYBOARD_LL" nocase
        $k3 = "GetAsyncKeyState" nocase
        $k4 = "GetKeyState" nocase
    condition:
        ($h1 or $h2 or $h3) and ($k1 or $k2 or $k3 or $k4)
}

rule Keylogger_JournalRecord {
    meta:
        description = "WH_JOURNALRECORD system-level message capture hook"
        family = "Infostealer"
        severity = "critical"
        mitre = "T1056.001"
    strings:
        $j1 = "WH_JOURNALRECORD" nocase
        $j2 = "JOURNALRECORD" nocase
        $j3 = {FF FF FF FF}
        $h1 = "SetWindowsHookEx" nocase
    condition:
        ($j1 or $j2 or $j3) and $h1
}

rule Keylogger_NoModule_Hook {
    meta:
        description = "Window hook with NULL module handle (self-contained keylogger)"
        family = "Infostealer"
        severity = "high"
        mitre = "T1056.001"
    strings:
        $h1 = "SetWindowsHookEx" nocase
        $n1 = "module_address" nocase
        $n2 = {00 00 00 00}
    condition:
        $h1 and ($n1 or $n2)
}

rule InnoSetup_Packaged {
    meta:
        description = "InnoSetup-based installer package abuse"
        family = "Loader"
        severity = "medium"
        mitre = "T1105"
    strings:
        $i1 = "InnoSetup" nocase
        $i2 = "Inno Setup" nocase
        $i3 = "is-" nocase
        $i4 = "_isetup" nocase
        $i5 = "innounp" nocase
    condition:
        2 of them
}

rule Fake_Huorong_Security {
    meta:
        description = "Malware disguised as Huorong (火绒) security software"
        family = "Trojan"
        severity = "critical"
    strings:
        $h1 = "sys_HR" nocase
        $h2 = "allapp_x64" nocase
        $h3 = "huorong" nocase
        $h4 = "火绒" nocase
    condition:
        ($h1 or $h2) and ($h3 or $h4)
}

rule Browser_Install_Detection {
    meta:
        description = "Detecting installed browsers (infostealer reconnaissance)"
        family = "Infostealer"
        severity = "medium"
        mitre = "T1082"
    strings:
        $b1 = "chrome" nocase
        $b2 = "firefox" nocase
        $b3 = "opera" nocase
        $p1 = "App Paths" nocase
        $p2 = "Clients\\\\StartMenuInternet" nocase
    condition:
        ($b1 or $b2 or $b3) and ($p1 or $p2)
}

rule InnoSetup_msys64_Path {
    meta:
        description = "Malware using msys64 path with InnoSetup installer files"
        family = "Loader"
        severity = "high"
    strings:
        $m1 = "msys64" nocase
        $i1 = "is-" nocase
        $t1 = ".tmp" nocase
    condition:
        $m1 and $i1 and $t1
}

rule Dyreza_Banking_Trojan {
    meta:
        description = "Dyreza/Dyre banking trojan (fake Huorong + NSIS + DLL sideload)"
        family = "Dyreza"
        severity = "critical"
    strings:
        $d1 = "comain_ev2" nocase
        $d2 = "mfcsubs" nocase
        $d3 = "DcryptDll" nocase
        $d4 = "huorong_win_setup" nocase
        $n1 = "Nullsoft" nocase
    condition:
        2 of them
}

rule NSIS_Installer_Abuse {
    meta:
        description = "Nullsoft NSIS installer used for malware distribution"
        family = "Loader"
        severity = "medium"
        mitre = "T1105"
    strings:
        $n1 = "Nullsoft" nocase
        $n2 = "nsis" nocase
        $n3 = "nsExec" nocase
        $n4 = "nsDialogs" nocase
    condition:
        2 of them
}

rule AntiDebug_PageGuard {
    meta:
        description = "PAGE_GUARD memory page (anti-reverse-engineering trap)"
        family = "AntiDebug"
        severity = "high"
        mitre = "T1622"
    strings:
        $p1 = "PAGE_GUARD" nocase
        $v1 = "VirtualAlloc" nocase
        $v2 = "VirtualProtect" nocase
    condition:
        $p1 and ($v1 or $v2)
}

rule AntiSandbox_OfficeCheck {
    meta:
        description = "Checks for Microsoft Office installation (anti-sandbox)"
        family = "AntiAnalysis"
        severity = "medium"
        mitre = "T1497.001"
    strings:
        $o1 = "WINWORD" nocase
        $o2 = "EXCEL.EXE" nocase
        $o3 = "POWERPNT" nocase
        $o4 = "Software\\\\Microsoft\\\\Office" nocase
    condition:
        2 of them
}

// ===== CobaltStrike Beacon 检测规则 =====
rule CobaltStrike_Beacon_DLL {
    meta:
        description = "CobaltStrike Beacon DLL (reflective loader + beacon strings)"
        family = "CobaltStrike"
        severity = "critical"
        mitre = "S0154"
    strings:
        $s1 = "ReflectiveLoader" nocase
        $s2 = "beacon" nocase
        $s3 = "MSSE-" ascii
        $s4 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
    condition:
        ($s1 and $s2) or ($s3 and $s4)
}

rule CobaltStrike_NamedPipe {
    meta:
        description = "CobaltStrike SMB Beacon named pipe (MSSE-/msagent_/postex_)"
        family = "CobaltStrike"
        severity = "critical"
        mitre = "T1090"
    strings:
        $p1 = "MSSE-"
        $p2 = "-server" nocase
        $p3 = "msagent_" nocase
        $p4 = "postex_" nocase
        $p5 = "status_" nocase
    condition:
        ($p1 and $p2) or ($p3 or $p4 or $p5)
}

rule CobaltStrike_SleepMask {
    meta:
        description = "CobaltStrike sleep obfuscation mask decoder"
        family = "CobaltStrike"
        severity = "critical"
        mitre = "T1027"
    strings:
        // ⚠ 修复误报: 旧规则只要任意 2 个 XOR 字节模式就命中 (33 0F / 80 30 / 66 0F EF),
        // 这些是几乎所有加密/哈希代码的通用 XOR 操作, 误报极高频。
        // 改为要求 SleepMask 的完整特征序列: xor + 内存写循环 + 计数器递减 的组合。
        $xmm  = {66 0F EF}              // pxor xmm
        $dec  = {48 83 E9}              // sub rcx, imm8 (循环计数递减)
        $loop = {80 30}                 // xor byte [rax]
        $ret  = {C3}                    // ret (解码循环结束)
    condition:
        $xmm and $dec and $loop and $ret
}

rule CobaltStrike_Beacon_Config {
    meta:
        description = "CobaltStrike Beacon encoded XOR configuration"
        family = "CobaltStrike"
        severity = "critical"
    strings:
        $s1 = "beacon" nocase
        $s2 = "/g.pixel" ascii
        $s3 = "submit.php" ascii
    condition:
        $s1 and ($s2 or $s3)
}

rule CobaltStrike_MZReflectiveLoader {
    meta:
        description = "CobaltStrike MZ header ReflectiveLoader launcher"
        family = "CobaltStrike"
        severity = "critical"
        mitre = "T1620"
    strings:
        $mz = "This program cannot be run in DOS mode"
        $r1 = "ReflectiveLoader" nocase
        $r2 = {4D 5A}  // MZ header
    condition:
        ($mz or $r2) and $r1
}

rule FullDisk_DefenderExclusion {
    meta:
        description = "Full disk Defender exclusion (C:\\\\,D:\\\\,E:\\\\ etc.)"
        family = "DefenseEvasion"
        severity = "critical"
        mitre = "T1562.001"
    strings:
        $d1 = "Add-MpPreference" nocase
        $d2 = "-ExclusionPath" nocase
        $d3 = "C:\\\\" nocase
    condition:
        $d1 and $d2 and $d3
}
"""


class PurePythonYARA:
    """纯 Python YARA 替代 — 不依赖 yara-python C 扩展"""
    def __init__(self):
        import re
        self._re = re
        self._rules = []

    def compile(self, source: str):
        """编译 YARA 规则文本为内部格式"""
        rules = []
        current = None
        in_condition = False
        for raw_line in source.split('\n'):
            # 行内注释剥离 (YARA // 注释常见于 hex 字符串和 condition 行)
            line = raw_line.split('//')[0].strip()
            if not line:
                continue
            if line.startswith('rule '):
                name = line.split()[1].rstrip('{').rstrip(':').strip()
                current = {'name': name, 'meta': {}, 'strings': [], 'condition': ''}
                rules.append(current)
                in_condition = False
                continue
            if line.startswith('condition:') and current is not None:
                current['condition'] = line.split(':', 1)[1].strip()
                in_condition = True
                continue
            if in_condition and current is not None:
                # 多行 condition 直到遇到单独的行尾 '}' (闭规则花括号)
                if line == '}':
                    in_condition = False
                else:
                    current['condition'] += ' ' + line
                continue
            if '=' in line and current is not None and 'meta:' not in line:
                if line.startswith('$'):
                    parts = line.split('=', 1)
                    sid = parts[0].strip()
                    val = parts[1].strip().strip('"').strip("'")
                    nocase = 'nocase' in val
                    val = val.replace(' nocase', '').replace(' wide', '').replace(' ascii', '')
                    current['strings'].append({'id': sid, 'value': val, 'nocase': nocase})
                elif current and ':' not in line.split('=')[0]:
                    k, v = line.split('=', 1)
                    k = k.strip()
                    v = v.strip().strip('"')
                    current['meta'][k] = v
        self._rules = rules
        return self

    def _compile_yara_value(self, val: str):
        """编译 YARA 字符串值为正则 — 处理 hex 模式 {XX YY} 和普通文本"""
        if val.startswith('{') and val.endswith('}'):
            hex_bytes = val[1:-1].strip().split()
            pattern_parts = []
            for hb in hex_bytes:
                if hb == '??' or hb == '?':
                    pattern_parts.append(b'[\x00-\xff]')
                elif len(hb) == 2:
                    try:
                        byte_val = int(hb, 16)
                        pattern_parts.append(re.escape(bytes([byte_val])))
                    except ValueError:
                        return None
                else:
                    return None
            return b''.join(pattern_parts)
        escaped = re.escape(val).encode('utf-8')
        return escaped

    def _eval_condition(self, cond: str, matches: int, matched_ids: set, total: int) -> bool:
        """递归求值 YARA 条件表达式（支持 and/or/括号/计数）"""
        cond = cond.strip()
        # 去除外层括号（确保是真正的配对括号对）
        while cond.startswith('(') and cond.endswith(')'):
            depth = 0
            outer_pair = False
            for i, c in enumerate(cond):
                if c == '(': depth += 1
                elif c == ')': depth -= 1
                if depth == 0:
                    if i == len(cond) - 1:
                        outer_pair = True
                    break
            if outer_pair:
                cond = cond[1:-1].strip()
                if not cond:
                    return False
            else:
                break
        # or 优先级最低，先拆
        if ' or ' in cond:
            parts = re.split(r'\s+or\s+', cond)
            return any(self._eval_condition(p, matches, matched_ids, total) for p in parts)
        if ' and ' in cond:
            parts = re.split(r'\s+and\s+', cond)
            return all(self._eval_condition(p, matches, matched_ids, total) for p in parts)
        # 原子条件
        if cond == 'any of them':
            return matches > 0
        if cond == 'all of them':
            return matches >= total
        m = re.match(r'(\d+)\s+of\s+them', cond)
        if m:
            return matches >= int(m.group(1))
        m = re.match(r'(\d+)\s+of\s+\(([^)]+)\)', cond)
        if m:
            needed = int(m.group(1))
            ids_str = m.group(2)
            ids = re.findall(r'\$[a-zA-Z_]\w*', ids_str)
            cnt = sum(1 for sid in ids if sid in matched_ids)
            return cnt >= needed
        m = re.match(r'any\s+of\s+\(([^)]+)\)', cond)
        if m:
            ids_str = m.group(1)
            ids = re.findall(r'\$[a-zA-Z_]\w*', ids_str)
            return any(sid in matched_ids for sid in ids)
        m = re.match(r'\$([a-zA-Z_]\w*)', cond)
        if m:
            return f'${m.group(1)}' in matched_ids
        # 兜底：未知条件格式，保守返回 False
        return False

    def match(self, data: bytes):
        """匹配数据"""
        results = []
        for rule in self._rules:
            matches = 0
            matched_ids = set()
            for s in rule['strings']:
                val = s['value']
                pattern = self._compile_yara_value(val)
                if not pattern:
                    continue
                flags = self._re.IGNORECASE if s.get('nocase') else 0
                if self._re.search(pattern, data, flags):
                    matches += 1
                    matched_ids.add(s['id'])
            if self._eval_condition(rule['condition'], matches, matched_ids, len(rule['strings'])):
                results.append(self._make_result(rule, list(matched_ids)))
        return results

    def _make_result(self, rule, ids):
        class FakeString:
            def __init__(self, id): self.identifier = id
        class FakeMatch:
            rule = rule['name']
            meta = rule['meta']
            strings = [FakeString(s) for s in ids]
            tags = []
        return FakeMatch()


def _try_yara_or_fallback():
    """尝试 yara-python，不行用纯 Python"""
    try:
        import yara
        return yara, False
    except ImportError:
        return PurePythonYARA(), True


# YARA 合法转义字符（\\x## 单独处理）
# 注意: 只能用 YARA 真正支持的转义 (\\" \\\\ \\t \\n \\r \\x##),
# 不能包含 Python 才有的 \\v \\a \\f \\0 等
_YARA_VALID_ESC = set('"\\tnrx'.replace(' ', ''))


def fix_yara_escapes(rules_text: str) -> str:
    """修复规则文本中 Windows 路径的非法 YARA 转义（如 \\E \\P \\A -> \\\\E）

    原因: 规则作者写 "Windows Defender\\Exclusions" 时, Python 字符串运行时是
    "Windows Defender\\Exclusions", YARA 将 \\E 视为非法转义导致整个规则集编译失败
    （历史 bug: 内置规则从未生效, 失败被 debug 日志静默吞掉）
    """
    out = []
    i = 0
    n = len(rules_text)
    while i < n:
        ch = rules_text[i]
        if ch == '\\' and i + 1 < n:
            nxt = rules_text[i + 1]
            if nxt == 'x' or nxt in _YARA_VALID_ESC:
                # 特殊: \" 后跟非引号字符 = Windows路径末尾反斜杠误写(如 IE\" nocase)
                # 会导致字符串永不闭合, 修正为 \\ (YARA字面反斜杠)
                if nxt == '"' and (i + 2 >= n or rules_text[i + 2] != '"'):
                    out.append('\\\\')
                    out.append(nxt)
                    i += 2
                    continue
                out.append(ch)
                out.append(nxt)
                i += 2
                continue
            out.append('\\\\')
            out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


class YARAScanner:
    """YARA 扫描器 — 优先 yara-python，自动降级纯 Python"""

    def __init__(self, rules_dir: str = None):
        self.rules = None
        self.matches: List[Dict] = []
        self._yara_mod, self._is_fallback = _try_yara_or_fallback()
        self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: str = None):
        sources = {}
        yara_mod = self._yara_mod
        try:
            compiled = yara_mod.compile(source=fix_yara_escapes(BUILTIN_RULES))
            sources['builtin'] = compiled
        except Exception as e:
            # 编译失败必须可见 — 历史版本用 debug 级别, 导致内置规则静默失效
            logger.warning(f"[YARA] 内置规则编译失败: {e}")

        if rules_dir and os.path.isdir(rules_dir):
            for f in glob.glob(os.path.join(rules_dir, '*.yar')):
                try:
                    # 注意: 必须用 source= 编译! yara-python 的 compile(path) 在
                    # Windows 下用 ANSI API 打开文件, 含中文的绝对路径会报 No such file
                    with open(f, 'rb') as fh:
                        rule_bytes = fh.read()
                    try:
                        compiled = yara_mod.compile(source=rule_bytes.decode('utf-8', errors='ignore'))
                    except Exception:
                        compiled = yara_mod.compile(source=rule_bytes.decode('gbk', errors='ignore'))
                    sources[os.path.basename(f)] = compiled
                except Exception as e:
                    logger.warning(f"[YARA] 规则 {os.path.basename(f)} 编译失败: {e}")

        if sources:
            self.rules = sources
            logger.info(f"[+] YARA 规则加载: {len(sources)} 个规则集{' (纯Python模式)' if self._is_fallback else ''}")

    def scan_file(self, filepath: str) -> List[Dict]:
        """扫描单个文件"""
        if not self.rules or not os.path.exists(filepath):
            return []
        results = []
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            for name, rules in self.rules.items():
                try:
                    hits = rules.match(data=data)
                    for m in hits:
                        results.append({
                            'rule': m.rule,
                            'file': os.path.basename(filepath),
                            'meta': {k: v for k, v in m.meta.items()},
                            'strings': [s.identifier for s in m.strings],
                            'tags': list(m.tags),
                        })
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"YARA 扫描 {filepath} 失败: {e}")
        return results

    def scan_bytes(self, data: bytes, filename: str = 'sample') -> List[Dict]:
        """扫描字节数据"""
        if not self.rules or not data:
            return []
        results = []
        for name, rules in self.rules.items():
            try:
                hits = rules.match(data=data)
                for m in hits:
                    results.append({
                        'rule': m.rule,
                        'file': filename,
                        'meta': {k: v for k, v in m.meta.items()},
                        'strings': [s.identifier for s in m.strings],
                        'tags': list(m.tags),
                    })
            except Exception:
                pass
        return results

    def scan_dropped_files(self, dropped) -> List[Dict]:
        """扫描所有释放文件"""
        all_hits = []
        if not dropped or not dropped.dropped_files:
            return all_hits
        for df in dropped.dropped_files:
            if os.path.exists(df.path):
                hits = self.scan_file(df.path)
                all_hits.extend(hits)
        return all_hits
