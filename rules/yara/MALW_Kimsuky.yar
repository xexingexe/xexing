/*
 * 家族规则: Kimsuky (Kimsuky APT — 朝鲜组织, 韩美目标定向攻击)
 * 来源: Kimsuky 样本分析 (宏病毒 + PowerShell 多阶段 C2 + 系统信息收集上传)
 *
 * 特征分层:
 *   A. 经典 multipart boundary (Kimsuky 长期使用): ----WebKitFormBoundarywhpFxMBe19cSjFnG
 *   B. 已知 C2 域名 (mybobo.mygamesonline.org / pingguo2.atwebpages.com /
 *      uekaf.myartsonline.com)
 *   C. 持久化键名 (Alzipupdate — 伪装阿里解压工具更新)
 *   D. 宏特征 (AutoOpen + WScript.Shell + IEX) 与混淆串 (vnsla/wra 垃圾串插入)
 *
 * 判定: A/B/C 任一 = 高置信家族命中; D 组合 = 中置信
 */

rule MALW_Kimsuky {
    meta:
        description = "Kimsuky APT - macro dropper / PowerShell multi-stage C2 / exfil"
        family = "Kimsuky"
        severity = "critical"
        mitre = "T1204.002, T1059.001, T1041, T1547.001"
        reference = "Kimsuky sample analysis (macro + PS C2)"

    strings:
        // --- A. 经典 multipart boundary ---
        $b1 = "----WebKitFormBoundarywhpFxMBe19cSjFnG" ascii
        $b2 = "WebKitFormBoundarywhpFxMBe19cSjFnG" ascii

        // --- B. 已知 C2 域名 ---
        $c1 = "mybobo.mygamesonline.org" ascii
        $c2 = "pingguo2.atwebpages.com" ascii
        $c3 = "uekaf.myartsonline.com" ascii
        $c4 = "myartsonline.com/ha/" ascii

        // --- C. 持久化键名 (伪装解压工具更新) ---
        $p1 = "Alzipupdate" ascii

        // --- D. 宏 + PowerShell 投递链 ---
        $m1 = "AutoOpen" ascii
        $m2 = "Document_Open" ascii
        $m3 = "WScript.Shell" ascii
        $m4 = "flower01" ascii
        $m5 = "bobo.txt" ascii
        $m6 = "flower01.ps1" ascii

        // --- E. 混淆垃圾串 (插入再 Replace 移除) ---
        $o1 = "vnslasla" ascii
        $o2 = "vnslavnsla" ascii
        $o3 = "Nwraew" ascii

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0xE011CFD0 or uint32(0) == 0x04034B50) and
        (1 of ($b*) or 1 of ($c*) or 1 of ($p*) or
         (2 of ($m*) and 1 of ($o*)))
}
