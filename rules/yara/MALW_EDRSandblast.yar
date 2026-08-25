/*
 * 家族规则: EDRSandBlast — 红队 EDR 绕过/LSASS 转储工具
 * 来源: https://github.com/wavestone-cdt/EDRSandblast
 *
 * 特征分层:
 *   A. 工具专属字符串 (NtoskrnlOffsets.csv / WdigestOffsets.csv / unhook_method /
 *      --kernelmode / audit|dump|credguard 模式)
 *   B. wdigest 凭据保护绕过 (g_fParameter_useLogonCredential / g_IsCredGuardEnabled)
 *   C. 漏洞驱动 (RTCore64.sys / DBUtil_2_3.sys) — BYOVD
 *   D. 内核回调/ETW 绕过相关 (PsSetCreateProcessNotifyRoutine / ObRegisterCallbacks /
 *      EtwThreatIntProvRegHandleOffset / ProviderEnableInfo)
 *   E. 解钩技术 (UNHOOK_WITH_NTPROTECTVIRTUALMEMORY / TRAMPOLINE / DIRECT_SYSCALL)
 *
 * 判定: A 中 2 个 = 高置信; 1 个 A + (B/C/D/E) 之一 = 中置信
 */

rule MALW_EDRSandblast {
    meta:
        description = "EDRSandBlast red team tool - EDR evasion / LSASS dump / credential guard bypass"
        family = "EDRSandblast"
        severity = "critical"
        mitre = "T1003.001, T1562.001, T1068"
        reference = "https://github.com/wavestone-cdt/EDRSandblast"

    strings:
        // --- A. 工具专属字符串 ---
        $tool1 = "EDRSandblast" ascii
        $tool2 = "NtoskrnlOffsets.csv" ascii
        $tool3 = "WdigestOffsets.csv" ascii
        $tool4 = "unhook_method" ascii
        $tool5 = "--kernelmode" ascii
        $tool6 = "--usermode" ascii
        $tool7 = "dont-restore-callbacks" ascii
        $tool8 = "dont-unload-driver" ascii
        $tool9 = "KernelMemoryPrimitives.h" ascii
        $tool10 = "RTCore64.sys" ascii
        $tool11 = "DBUtil_2_3.sys" ascii

        // --- B. wdigest / Credential Guard 绕过 ---
        $wd1 = "g_fParameter_useLogonCredential" ascii
        $wd2 = "g_IsCredGuardEnabled" ascii
        $wd3 = "wdigest" ascii

        // --- C. 内核回调/ETW 绕过 ---
        $cb1 = "PsSetCreateProcessNotifyRoutine" ascii
        $cb2 = "PsSetCreateThreadNotifyRoutine" ascii
        $cb3 = "PsSetLoadImageNotifyRoutine" ascii
        $cb4 = "ObRegisterCallbacks" ascii
        $cb5 = "ProviderEnableInfo" ascii
        $cb6 = "EtwThreatIntProvRegHandleOffset" ascii
        $cb7 = "PspCreateProcessNotifyRoutine" ascii
        $cb8 = "OB_CALLBACK_ENTRY" ascii

        // --- D. 解钩技术 ---
        $uh1 = "UNHOOK_WITH_NTPROTECTVIRTUALMEMORY" ascii
        $uh2 = "UNHOOK_WITH_INHOUSE_NTPROTECTVIRTUALMEMORY_TRAMPOLINE" ascii
        $uh3 = "UNHOOK_WITH_EDR_NTPROTECTVIRTUALMEMORY_TRAMPOLINE" ascii
        $uh4 = "UNHOOK_WITH_DIRECT_SYSCALL" ascii
        $uh5 = "ReadMemoryPrimitive_" ascii
        $uh6 = "WriteMemoryPrimitive_" ascii

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($tool*) or
         (1 of ($tool*) and (1 of ($wd*) or 1 of ($cb*) or 1 of ($uh*))))
}
