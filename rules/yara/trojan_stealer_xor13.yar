/*
    YARA Rule: Trojan_Stealer_Xor13_Packed
    Description: 检测使用XOR 0x13字符串加密、动态API解析的木马/窃密程序
    Author: Generated based on sample analysis
    Date: 2026-07-31
    Version: 1.0

    特征:
    - PE可执行文件，请求管理员权限
    - 使用XOR 0x13循环解密字符串
    - 动态API解析 (LoadLibraryA + GetProcAddress)
    - 高熵加密数据区域
    - 代码混淆和反分析技术
*/

rule Trojan_Stealer_Xor13_Packed {
    meta:
        description = "检测XOR 0x13加密的木马/窃密程序"
        author = "ThreatHunter"
        date = "2026-07-31"
        severity = "critical"

    strings:
        $decrypt_loop_r9 = { 41 0f b6 0c 11 48 8d 52 01 80 f1 13 88 4a ff 49 83 e8 01 75 eb }
        $decrypt_loop_r8 = { 43 0f b6 14 02 4d 8d 40 01 80 f2 13 41 88 50 ff 49 83 e9 01 75 ea }
        $decrypt_loop_variant1 = { 41 0f b6 0c 10 48 8d 52 01 80 f1 13 88 4a ff 49 83 e9 01 75 eb }
        $decrypt_loop_variant2 = { 43 0f b6 14 02 4d 8d 40 01 80 f2 13 41 88 50 ff 49 83 e9 01 75 ea }
        $strcpy_loop = { 48 8d 52 01 34 13 88 42 ff 49 83 e8 01 75 ec }
        $getproc_call = { 48 8b c8 ff 15 ?? ?? ?? ?? 48 83 c4 20 5b 48 ff 25 }
        $loadlib_call = { 48 8b d9 ff 15 ?? ?? ?? ?? 4c 8b c3 33 d2 48 8b c8 }
        $virtual_prep = { 41 b8 00 00 00 01 48 8d 8d ?? ?? ?? ?? 44 8b f6 }
        $dll_kernel32 = "kernel32.dll" nocase wide ascii
        $dll_ntdll = "ntdll.dll" nocase wide ascii
        $uac_admin = "requireAdministrator" wide ascii
        $antidebug_check = { 65 48 8b 04 25 60 00 00 00 48 8b 40 18 }
        $inject_prep = { 48 89 8f 00 02 00 00 }
        $file_ops = { c7 44 24 28 80 00 00 00 45 33 c9 ba 00 00 00 80 }
        $reg_ops = { 48 8d 54 24 58 48 89 74 24 58 48 8b c8 41 ff d7 }

    condition:
        uint16(0) == 0x5a4d and
        filesize > 100KB and filesize < 2MB and
        (
            ($decrypt_loop_r9 or $decrypt_loop_r8) and
            ($decrypt_loop_variant1 or $decrypt_loop_variant2 or $strcpy_loop)
        ) and
        ($getproc_call or $loadlib_call or ($dll_kernel32 and $dll_ntdll)) and
        ($virtual_prep or $inject_prep or $file_ops or $reg_ops or $uac_admin or $antidebug_check) and
        (#decrypt_loop_r9 + #decrypt_loop_r8 + #decrypt_loop_variant1 + #decrypt_loop_variant2 >= 2)
}

rule Trojan_Stealer_Xor13_Light {
    meta:
        description = "轻量级检测: XOR 0x13加密木马"
        author = "ThreatHunter"
        date = "2026-07-31"
        severity = "high"

    strings:
        $xor13 = { 80 f? 13 }
        $decrypt_core = { 0f b6 ?? ?? 80 ?? 13 88 ?? ?? 75 }

    condition:
        uint16(0) == 0x5a4d and
        filesize > 50KB and
        #xor13 >= 4 and
        #decrypt_core >= 2
}

rule Trojan_Stealer_Xor13_Memory {
    meta:
        description = "内存扫描: 检测已加载的XOR 0x13木马"
        author = "ThreatHunter"
        date = "2026-07-31"
        severity = "critical"

    strings:
        $mem_decrypt1 = { 41 0f b6 0c 11 48 8d 52 01 80 f1 13 }
        $mem_decrypt2 = { 43 0f b6 14 02 4d 8d 40 01 80 f2 13 }
        $mem_api_resolve = { ff 15 ?? ?? ?? ?? 48 83 c4 20 5b 48 ff 25 }
        $mem_admin = "requireAdministrator" wide ascii

    condition:
        ($mem_decrypt1 or $mem_decrypt2) and
        ($mem_api_resolve or $mem_admin)
}

rule Trojan_Stealer_Xor13_Network {
    meta:
        description = "网络检测: XOR 0x13木马的C2通信特征"
        author = "ThreatHunter"
        date = "2026-07-31"
        severity = "high"

    strings:
        $post_pattern = "POST /" wide ascii
        $get_pattern = "GET /" wide ascii

    condition:
        any of them and
        filesize < 10MB
}
