/*
 * 家族规则: 企业级定向投递加载器 (LoadAndExecute / EDR-Aware Dropper)
 * 来源: 深度逆向分析 (CTF-级评分制环境检测 + ETW Hook + Halo's Gate + 线程劫持注入)
 *
 * 特征分层:
 *   A. 内嵌环境检测标记字符串 (评分制反沙箱, 家族专属命名约定)
 *      ⚠ 变种对标记做截断混淆 (FEW_SYSTEM_EVENTS → FEW_ETW_ / NO_NETWORK → NO_NETWOH /
 *         VM_VENDOR_ID → VM_VENDOH / HR_DETECTED → HR_DETECTH) — 必须支持前缀匹配!
 *   B. ETW Hook 7函数 FNV-1a 哈希表 (0xE8F45F7B 等)
 *   C. 上线包/UID 格式 (fingerprint=...&build_id= / CPU:|GUID:|PC:)
 *   D. C2 URL 路径特征 (/api/collections/create 等)
 *   E. 行为特征 (CreateProcess CREATE_SUSPENDED + 线程劫持注入链)
 *
 * 判定: 2个A(含截断) = 高置信家族命中; 1个A完整 + B/C/D/E = 中置信
 */

rule MALW_EnvScore_Loader {
    meta:
        description = "Enterprise-targeted dropper/loader with scored environment detection (EDR-aware)"
        family = "EnvScoreLoader"
        severity = "critical"
        mitre = "T1497, T1055, T1562, T1105"
        reference = "CTF analysis: scored anti-sandbox + ETW hook + Halo's Gate + thread hijack"
    strings:
        // --- A1. 完整环境检测标记字符串 (家族专属) ---
        $env1 = "SLEEP_HOOKED" ascii
        $env2 = "VM_EXIT_OVERHEAD" ascii
        $env3 = "LOW_RDTSC_JITTER" ascii
        $env4 = "SHORT_UPTIME" ascii
        $env5 = "NO_RECENT_INPUT" ascii
        $env6 = "EMPTY_CLIPBOARD" ascii
        $env7 = "NO_USB_HISTORY" ascii
        $env8 = "NO_JUMP_LISTS" ascii
        $env9 = "ROUND_DISK_SIZE" ascii
        $env10 = "VM_VENDOR_ID" ascii
        $env11 = "FEW_INSTALLED_PROGRAMS" ascii
        $env12 = "FEW_FONTS" ascii
        $env13 = "SIMPLE_REGISTRY" ascii
        $env14 = "FEW_SYSTEM_FILES" ascii
        $env15 = "FEW_PREFETCH_FILES" ascii
        $env16 = "FEW_SYSTEM_EVENTS" ascii
        $env17 = "NO_UPDATE_HISTORY" ascii
        $env18 = "FEW_COM_CLASSES" ascii
        $env19 = "SMALL_WMI_REPO" ascii
        $env20 = "CLUSTERED_PREFETCH_TIMESTAMPS" ascii
        $env21 = "TINY_RECYCLE_FILES" ascii
        $env22 = "SMART_CAPABLE" ascii
        $env23 = "NO_SMART_SUPPORT" ascii
        $env24 = "DEBUGGER_PRESENT" ascii
        $env25 = "NTGLOBALFLAG_SET" ascii
        $env26 = "EDR_DETECTED" ascii
        $env27 = "DEFINITE_SANDBOX" ascii
        $env28 = "POSSIBLE_SANDBOX" ascii

        // --- A2. 截断混淆标记 (变种: 标记被截断到 8-10 字符, 家族命名约定前缀) ---
        $trunc1 = "FEW_ETW_" ascii
        $trunc2 = "NO_NETWOH" ascii
        $trunc3 = "HOOKING_L" ascii
        $trunc4 = "VMWARE_MH" ascii
        $trunc5 = "HR_DETECTH" ascii
        $trunc6 = "VM_VENDOH" ascii
        $trunc7 = "VM_VENDOR" ascii
        $trunc8 = "HOOKED " ascii

        // --- B. ETW Hook 7函数 FNV-1a 哈希表 ---
        $etw1 = { E8 F4 5F 7B }  // EtwEventWriteEx
        $etw2 = { 67 16 97 A7 }  // EtwEventWriteFull
        $etw3 = { E5 F4 BD DE }  // EtwEventWrite
        $etw4 = { 21 41 9E 94 }  // NtTraceEvent
        $etw5 = { 32 6E 5E 8E }  // EtwEventRegister
        $etw6 = { B6 87 08 D5 }  // EtwEventWriteTransfer
        $etw7 = { 8D EF 08 8F }  // EtwEventWriteString

        // --- C. 上线包/UID 格式 ---
        $uid1 = "CPU:" ascii
        $uid2 = "GUID:" ascii
        $uid3 = "build_id=" ascii
        $uid4 = "fingerprint=" ascii

        // --- D. C2 URL 路径特征 ---
        $url1 = "/api/collections/create" ascii
        $url2 = "/api/downloads/" ascii

        // --- E. 线程劫持注入链 (行为特征) ---
        $hij1 = "ZwSetContextThread" ascii
        $hij2 = "ZwResumeThread" ascii
        $hij3 = "ZwProtectVirtualMemory" ascii
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($env*) or 2 of ($trunc*) or
         (1 of ($env*) and 1 of ($trunc*)) or
         ((1 of ($env*) or 1 of ($trunc*)) and
          (1 of ($etw*) or 1 of ($url*) or 1 of ($uid*) or 1 of ($hij*))))
}
