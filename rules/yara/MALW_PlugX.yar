/*
 * 家族规则: PlugX (RAT — 白加黑加载 / USB 蠕虫传播 / 文档窃取)
 * 来源: PlugX 样本分析 (AvastSvc.exe 白加黑 + wsc.dll + AvastAuth.dat 解密 shellcode)
 *
 * 特征分层:
 *   A. 持久化/文件特征: AvastSvcPYT / AvastAuth.dat / CEFHelper.exe
 *   B. USB 蠕虫: USB_NOTIFY_INF_ / USB_NOTIFY_COP_ 互斥体
 *   C. 注册表特征: ms-pu PROXY CLSID
 *   D. 反竞争: AdobeHelper/AdobeUpdates/AdobeARM 进程终止
 *   E. 信息收集命令: ipconfig /all + netstat -ano + arp -a + tasklist /v + systeminfo
 *   F. 文档窃取: base64 加密 doc/docx/ppt/xls/pdf 放入回收站
 *
 * 判定: A/B/C 任一 = 高置信; D+E 或 F+E = 中置信
 */

rule MALW_PlugX {
    meta:
        description = "PlugX RAT - sideloading / USB worm / document theft"
        family = "PlugX"
        severity = "critical"
        mitre = "T1574.002, T1091, T1005, T1113"
        reference = "PlugX sample analysis (AvastSvc sideload)"

    strings:
        // --- A. 持久化/文件特征 ---
        $a1 = "AvastSvcPYT" ascii
        $a2 = "AvastAuth.dat" ascii
        $a3 = "CEFHelper.exe" ascii
        $a4 = "AvastSvc.exe" ascii

        // --- B. USB 蠕虫互斥体 ---
        $b1 = "USB_NOTIFY_INF_" ascii
        $b2 = "USB_NOTIFY_COP_" ascii

        // --- C. 注册表特征 ---
        $c1 = "ms-pu" ascii
        $c2 = "{645FF040-5081-101B-9F08-00AA002F954E}" ascii

        // --- D. 反竞争杀 Adobe ---
        $d1 = "AdobeHelper.exe" ascii
        $d2 = "AdobeUpdates.exe" ascii
        $d3 = "AdobeARM.exe" ascii
        $d4 = "AAM Update.exe" ascii

        // --- E. 信息收集命令 ---
        $e1 = "ipconfig /all" ascii
        $e2 = "netstat -ano" ascii
        $e3 = "arp -a" ascii
        $e4 = "tasklist /v" ascii
        $e5 = "systeminfo" ascii

        // --- F. 文档窃取 ---
        $f1 = ".doc" ascii
        $f2 = ".xls" ascii
        $f3 = ".pdf" ascii
        $f4 = "RECYCLER.BIN" ascii

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($a*) or 1 of ($b*) or 1 of ($c*) or
         (1 of ($d*) and 2 of ($e*)) or
         (2 of ($f*) and 2 of ($e*)))
}
