#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能依赖检查器 — 扫描所有可选库，提供安装提示
启动时自动检测，GUI和CLI都会显示缺失的库
"""
import sys
from typing import Dict, List, Tuple, Optional


DEPENDENCIES = [
    # 格式: (包名, 描述, 类别, 安装命令, 替代导入名)
    # alt_import: 编译版不可用时尝试导入的纯 Python 替代包

    # 静态分析
    ("pefile",     "PE文件解析",            "static",  "pip install pefile",              None),
    ("lief",       "PE高级解析(ELF/MachO)",  "static",  "pip install lief",                None),
    ("yara",       "YARA规则引擎(内置纯Python降级)", "static", "pip install yara-python",         "plyara"),
    ("capstone",   "反汇编引擎",             "static",  "pip install capstone",            None),
    ("ssdeep",     "模糊哈希",               "static",  "pip install ssdeep",              "ppdeep"),

    # 动态分析
    ("psutil",     "进程/网络监控",          "dynamic", "pip install psutil",              None),
    ("frida",      "API动态插桩",            "dynamic", "pip install frida",               None),
    ("pywin32",    "Windows API访问",        "dynamic", "pip install pywin32",             None),

    # 网络分析
    ("scapy",      "网络数据包捕获",         "network", "pip install scapy",               None),

    # 压缩包
    ("rarfile",    "RAR文件解压",            "archive", "pip install rarfile",             None),
    ("py7zr",      "7z文件解压",             "archive", "pip install py7zr",               None),
    ("zipfile",    "ZIP文件解压（内置）",     "archive", None,                              None),
    ("olefile",    "MSI/OLE2 流提取",        "archive", "pip install olefile",             None),

    # 报告生成
    ("jinja2",     "HTML模板引擎",           "report",  "pip install jinja2",              None),
    ("fpdf2",      "PDF报告生成",            "report",  "pip install fpdf2",               None),

    # 配置
    ("yaml",       "YAML配置文件解析",       "config",  "pip install pyyaml",              None),

    # 其他
    ("requests",   "Threat Intel API查询",   "intel",   "pip install requests",            None),
    ("python_magic","文件类型检测",           "static",
     "pip install python-magic python-magic-bin",  "puremagic"),
]

# 纯 Python 替代包的安装命令（无编译依赖，适合 VM 环境）
ALT_INSTALL_CMDS = {
    "plyara":    "pip install plyara",              # 纯 Python YARA 解析器
    "ppdeep":    "pip install ppdeep",               # 纯 Python ssdeep
    "puremagic": "pip install puremagic",            # 纯 Python 文件类型检测
    "py7zr":     "pip install py7zr",                # 纯 Python 7z（已是纯 Python）
    "yaramod":   "pip install yaramod",              # 另一个 YARA 解析器
    "reportlab": "pip install reportlab",           # 纯 Python PDF 生成（替代 fpdf2）
}


class DependencyChecker:
    """依赖检查器"""
    
    CATEGORY_NAMES = {
        "static": "静态分析",
        "dynamic": "动态分析",
        "network": "网络分析",
        "archive": "压缩包解析",
        "report": "报告生成",
        "config": "配置系统",
        "intel": "威胁情报",
    }
    
    def __init__(self):
        self.results: Dict[str, Dict] = {}
        self._check_all()
    
    @staticmethod
    def _is_frozen():
        """Check if running inside a PyInstaller bundle"""
        return getattr(sys, 'frozen', False)

    def _check_all(self):
        """检查所有依赖（编译版失败时尝试纯 Python 替代）"""
        frozen = self._is_frozen()
        # 模块名 → 导入名映射
        IMPORT_NAMES = {
            "python_magic": "magic", "puremagic": "puremagic",
            "yaml": "yaml", "yara": "yara", "plyara": "plyara",
            "pywin32": "win32api", "ssdeep": "ssdeep", "ppdeep": "ppdeep",
            "fpdf2": "fpdf",
        }
        VERSION_SPECIAL = {"yara": "YARA_VERSION"}

        for item in DEPENDENCIES:
            pkg_name, desc, category, install_cmd = item[:4]
            alt_import = item[4] if len(item) > 4 else None

            self.results[pkg_name] = {
                "name": pkg_name, "description": desc, "category": category,
                "install_cmd": install_cmd, "alt_import": alt_import,
                "installed": False, "version": None, "error": None, "using_alt": False,
            }

            if pkg_name == "zipfile":
                self.results[pkg_name]["installed"] = True
                self.results[pkg_name]["version"] = "builtin"
                continue

            # 尝试主包
            import_name = IMPORT_NAMES.get(pkg_name, pkg_name)
            ok, ver = self._try_import_module(import_name, VERSION_SPECIAL.get(pkg_name))
            if ok:
                self.results[pkg_name]["installed"] = True
                self.results[pkg_name]["version"] = ver
                continue

            # 主包失败，尝试纯 Python 替代
            if frozen and not alt_import:
                # 冻结环境 + 无替代包 → 清除安装命令(pip不可用)
                self.results[pkg_name]["install_cmd"] = ""
                self.results[pkg_name]["description"] += " (exe环境需手动安装)"
            
            if alt_import:
                alt_name = IMPORT_NAMES.get(alt_import, alt_import)
                ok, ver = self._try_import_module(alt_name, VERSION_SPECIAL.get(alt_import))
                if ok:
                    self.results[pkg_name]["installed"] = True
                    self.results[pkg_name]["version"] = ver
                    self.results[pkg_name]["using_alt"] = True
                    self.results[pkg_name]["install_cmd"] = ALT_INSTALL_CMDS.get(
                        alt_import, f"pip install {alt_import}"
                    )
                    self.results[pkg_name]["description"] += " (纯Python替代)"
                else:
                    # 替代包也没装 → 把安装命令改成替代包（无编译依赖）
                    if frozen:
                        # 冻结环境中 pip 不可用，只提示不提供安装按钮
                        self.results[pkg_name]["install_cmd"] = ""
                        self.results[pkg_name]["description"] += f" (需纯Python版: pip install {alt_import})"
                    else:
                        self.results[pkg_name]["install_cmd"] = ALT_INSTALL_CMDS.get(
                            alt_import, f"pip install {alt_import}"
                        )
                        self.results[pkg_name]["description"] += f" → 推荐装纯Python版: pip install {alt_import}"

    @staticmethod
    def _try_import_module(import_name, version_attr=None):
        """尝试导入模块，返回 (ok, version)"""
        try:
            mod = __import__(import_name)
            if version_attr:
                ver = getattr(mod, version_attr, "unknown")
            else:
                ver = getattr(mod, "__version__", "unknown")
            return True, ver
        except (ImportError, Exception) as e:
            # 记录真实错误 (诊断用, GUI/CLI 可显示); 日志文件限制 1MB 防无限增长
            _last_import_error = f"{type(e).__name__}: {e}"
            try:
                import os
                _log_path = os.path.join(os.environ.get('TEMP', '.'), 'dep_import_error.log')
                if os.path.isfile(_log_path) and os.path.getsize(_log_path) > 1024 * 1024:
                    os.remove(_log_path)
                with open(_log_path, 'a', encoding='utf-8') as f:
                    f.write(f'{import_name}: {_last_import_error}\n')
            except Exception:
                pass
            return False, None
    
    def get_missing(self, category: Optional[str] = None) -> List[Dict]:
        """获取缺失的依赖
        
        Args:
            category: 指定类别，None表示全部
        """
        missing = []
        for name, info in self.results.items():
            if not info["installed"]:
                if category is None or info["category"] == category:
                    missing.append(info)
        return missing
    
    def get_installed(self, category: Optional[str] = None) -> List[Dict]:
        """获取已安装的依赖"""
        installed = []
        for name, info in self.results.items():
            if info["installed"]:
                if category is None or info["category"] == category:
                    installed.append(info)
        return installed
    
    def is_critical_for(self, feature: str) -> bool:
        """检查某项功能的关键依赖是否缺失（含纯 Python 替代）"""
        critical = {
            "dynamic": ["psutil"],
            "network_capture": ["scapy"],
            "api_hook": ["frida"],
            "pe_deep": ["pefile", "lief"],
            "yara_scan": ["yara"],      # 含 plyara 替代
            "memory_dump": ["pywin32"],
            "fuzzy_hash": ["ssdeep"],   # 含 ppdeep 替代
            "magic_detect": ["python_magic"],  # 含 puremagic 替代
        }
        for pkg in critical.get(feature, []):
            if not self.results.get(pkg, {}).get("installed", False):
                return False
        return True
    
    def print_report(self, verbose: bool = False):
        """打印依赖报告到控制台"""
        print("\n" + "=" * 60)
        print("  📦 依赖库检查报告")
        print("=" * 60)
        
        for cat_key, cat_name in self.CATEGORY_NAMES.items():
            cat_installed = self.get_installed(cat_key)
            cat_missing = self.get_missing(cat_key)
            
            if not cat_missing and not verbose:
                continue
            
            print(f"\n  [{cat_name}]")
            
            # 已安装
            for info in cat_installed:
                if verbose:
                    print(f"    ✅ {info['name']:12s} v{info['version']}")
            
            # 缺失
            for info in cat_missing:
                if info["install_cmd"]:
                    print(f"    ❌ {info['name']:12s} 未安装  →  {info['install_cmd']}")
                else:
                    print(f"    ⚠️ {info['name']:12s} 未安装（无安装命令）")
        
        missing_all = self.get_missing()
        if missing_all:
            print(f"\n  ⚠️ 共 {len(missing_all)} 个可选库未安装")
            print("  部分功能可能受限，建议按需安装：")
            print("  " + "-" * 56)
            cmds = set()
            for info in missing_all:
                if info["install_cmd"]:
                    cmds.add(info["install_cmd"])
            for cmd in sorted(cmds):
                print(f"    {cmd}")
        else:
            print("\n  ✅ 所有依赖库均已安装！")
        
        print("=" * 60 + "\n")
    
    def get_gui_report(self) -> List[Tuple[str, str, str, bool, str]]:
        """获取GUI格式的报告
        
        返回: [(类别名, 库名, 描述, 是否安装, 安装命令), ...]
        """
        items = []
        for cat_key, cat_name in self.CATEGORY_NAMES.items():
            cat_items = [info for info in self.results.values() if info["category"] == cat_key]
            for info in cat_items:
                items.append((
                    cat_name,
                    info["name"],
                    info["description"],
                    info["installed"],
                    info["install_cmd"] or ""
                ))
        return items
    
    def get_install_all_command(self) -> str:
        """获取一键安装所有缺失库的命令"""
        missing = self.get_missing()
        cmds = []
        for info in missing:
            if info["install_cmd"]:
                # 提取 pip install 后面的包名
                cmd = info["install_cmd"]
                if cmd.startswith("pip install "):
                    pkgs = cmd[12:].strip()
                    cmds.append(pkgs)
        
        if cmds:
            return "pip install " + " ".join(sorted(set(cmds)))
        return ""


# 全局检查器实例
_dep_checker = None

def get_checker() -> DependencyChecker:
    """获取全局依赖检查器"""
    global _dep_checker
    if _dep_checker is None:
        _dep_checker = DependencyChecker()
    return _dep_checker


def check_and_print():
    """检查并打印报告（CLI启动时调用）"""
    checker = get_checker()
    checker.print_report(verbose=False)
    return checker


if __name__ == '__main__':
    checker = DependencyChecker()
    checker.print_report(verbose=True)
    
    cmd = checker.get_install_all_command()
    if cmd:
        print(f"\n一键安装所有缺失库：\n  {cmd}")
