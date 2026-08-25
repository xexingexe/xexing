/*
 * 家族规则: resvr 感染型木马 (文件感染 + 远程控制 socket)
 * 来源: resvr.exe 感染型木马分析 (头部XOR加密感染 + 127.0.0.1:40118 监听)
 *
 * 特征分层:
 *   A. 感染标记 0xAABBCCDD (已感染文件标志)
 *   B. 远程控制命令协议 (ddCmdMsg 前8字节命令类型 / 0x3EB-0x458 命令常量)
 *   C. 本地监听 socket (127.0.0.1:40118)
 *   D. 感染目标扩展名 (doc/xls/jpg/rar) + 文件头 0x400 XOR
 *   E. DOS bat 释放 (Index.bat / X.bat) + Guest 账户创建
 *
 * 判定: A 或 (B 中 2 个) 或 (C+D) = 高置信; D+E = 中置信
 */

rule MALW_Resvr_Infector {
    meta:
        description = "resvr infector worm - file infection (XOR header) + remote control socket"
        family = "ResvrInfector"
        severity = "critical"
        mitre = "T1485, T1505.002, T1071"
        reference = "resvr.exe infector analysis (0xAABBCCDD mark + 40118 listen)"

    strings:
        // --- A. 感染标记 ---
        $a1 = {AA BB CC DD}

        // --- B. 远程控制命令常量 ---
        $b1 = {EB 03 00 00}  // dwCmdMsg=0x3EB 反馈
        $b2 = {50 04 00 00}  // 0x450 创建 Index.bat+关机
        $b3 = {51 04 00 00}  // 0x451 弹窗
        $b4 = {55 04 00 00}  // 0x455 全盘感染
        $b5 = {53 04 00 00}  // 0x453 创建Guest
        $b6 = {58 04 00 00}  // 0x458 释放Message.exe
        $b7 = "ddCmdMsg" ascii

        // --- C. 本地监听 ---
        $c1 = "127.0.0.1" ascii
        $c2 = "40118" ascii

        // --- D. 感染目标 ---
        $d1 = ".doc" ascii
        $d2 = ".xls" ascii
        $d3 = ".jpg" ascii
        $d4 = ".rar" ascii
        $d5 = {00 04 00 00}  // 0x400 文件头长度

        // --- E. bat + Guest ---
        $e1 = "Index.bat" ascii
        $e2 = "X.bat" ascii
        $e3 = "Microsoft Shared" ascii
        $e4 = "net user Guest" ascii

    condition:
        uint16(0) == 0x5A4D and
        ($a1 or
         (2 of ($b*) and 1 of ($e*)) or
         ($c1 and $c2) or
         (3 of ($d*) and $d5 and 1 of ($e*)))
}
