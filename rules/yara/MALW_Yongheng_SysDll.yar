/*
 * 家族规则: 永恒小马 (系统 DLL 感染型木马 — SFC 绕过 + 原地插入感染)
 * 来源: 永恒小马病毒分析 (AION 标记 + Vch 临时文件 + sfc_os.dll 5号门)
 *
 * 特征分层:
 *   A. AION 感染标记 (PE头部 0x322 / .text 尾部)
 *   B. Vch 前缀临时文件 (GetTempFileNameA 释放 DLL 载体)
 *   C. SFC 绕过 (sfc_os.dll / SetSfcFileException)
 *   D. 感染目标系统 DLL (d3d9.dll / mshtml.dll)
 *   E. 系统 DLL 备份/替换 (.dll.rep / .dll.bak / MoveFileExA)
 *
 * 判定: A 或 (B 且 C) 或 (C 且 D) = 高置信; D+E = 中置信
 */

rule MALW_Yongheng_SysDLL_Infector {
    meta:
        description = "Yongheng (eternal pony) system DLL infector - SFC bypass + in-place infection"
        family = "SysDllInfector"
        severity = "critical"
        mitre = "T1546.008, T1480, T1071"
        reference = "Yongheng infector analysis (AION mark + d3d9/mshtml infection)"

    strings:
        // --- A. AION 感染标记 ---
        $a1 = "AION" ascii

        // --- B. Vch 临时文件 ---
        $b1 = "Vch~" ascii
        $b2 = "GetTempFileNameA" ascii
        $b3 = "GetTempFileNameW" ascii

        // --- C. SFC 绕过 ---
        $c1 = "sfc_os.dll" ascii
        $c2 = "SetSfcFileException" ascii
        $c3 = "SfcIsFileProtected" ascii

        // --- D. 感染目标系统 DLL ---
        $d1 = "d3d9.dll" ascii
        $d2 = "mshtml.dll" ascii
        $d3 = "d3d9.dll+mshtml.dll" ascii
        $d4 = "wininet.dll" ascii

        // --- E. 备份/替换流程 ---
        $e1 = ".dll.rep" ascii
        $e2 = ".dll.bak" ascii
        $e3 = "MoveFileExA" ascii
        $e4 = "DllCache" ascii

    condition:
        uint16(0) == 0x5A4D and
        // ⚠ AION 单独出现是正常词(游戏名), 必须与感染流程特征组合
        (($a1 and ($b1 or $c1 or $e1 or $e2 or $e4)) or
         (($b1 or $b2 or $b3) and ($c1 or $c2 or $c3)) or
         (($c1 or $c2 or $c3) and ($d1 or $d2 or $d4)) or
         (($d1 or $d2 or $d3) and ($e1 or $e2 or $e3 or $e4)))
}
