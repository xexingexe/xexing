# -*- coding: utf-8 -*-
"""
Build script - Package Malware Analysis Platform to exe using PyInstaller
Usage: python build_exe.py
"""
import subprocess
import sys
import os

# Fix Windows console encoding
if sys.platform == 'win32':
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleCP(65001)
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except:
        pass
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
SPEC_FILE = os.path.join(PROJECT_DIR, "沙箱分析平台.spec")
# spec 历史上使用过多个 EXE 名称 — 任一存在都视为构建成功
EXE_OUTPUTS = [
    os.path.join(PROJECT_DIR, "dist", "SandboxAnalyzer.exe"),
    os.path.join(PROJECT_DIR, "dist", "Windows入侵检测系统.exe"),
]


def run(cmd, **kwargs):
    """Run a command and return success, gathering output"""
    print(f"  -> {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        r = subprocess.run(cmd, capture_output=False, **kwargs)
        return r.returncode == 0
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def main():
    print("=" * 60)
    print("  Malware Analysis Platform v3.0 - EXE Builder")
    print("=" * 60)

    # 1. Check spec exists
    if not os.path.exists(SPEC_FILE):
        print(f"\n[ERROR] Spec file not found: {SPEC_FILE}")
        sys.exit(1)
    print(f"\n[1/4] Spec: {SPEC_FILE}")

    # 2. Check/fix PyInstaller
    print("[2/4] Checking PyInstaller...")
    try:
        import PyInstaller
        print(f"      PyInstaller {PyInstaller.__version__} OK")
    except ImportError:
        print("      Installing PyInstaller...")
        ok = run([sys.executable, "-m", "pip", "install", "pyinstaller"])
        if not ok:
            print("[ERROR] Failed to install PyInstaller")
            print("        Manual: pip install pyinstaller")
            sys.exit(1)
        import PyInstaller
        print(f"      PyInstaller {PyInstaller.__version__} installed")

    # 3. Check core deps
    print("[3/4] Checking core dependencies...")
    core_deps = ["pefile", "psutil", "PIL"]
    all_ok = True
    for dep in core_deps:
        try:
            __import__(dep)
            print(f"      OK  {dep}")
        except ImportError:
            print(f"      MISS {dep}")
            all_ok = False
    if not all_ok:
        print("\n      Missing core deps. Install with:")
        print("      pip install -r requirements.txt")
        ans = input("      Continue anyway? (y/n): ").strip().lower()
        if ans != 'y':
            sys.exit(0)

    # 4. Build
    print("[4/4] Running PyInstaller...")
    print(f"      Output: {os.path.join(PROJECT_DIR, 'dist')}")
    print()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
        "--log-level=INFO",
        SPEC_FILE,
    ]

    ok = run(cmd, cwd=PROJECT_DIR)

    found_exe = next((p for p in EXE_OUTPUTS if os.path.exists(p)), None)
    if ok and found_exe:
        size_mb = os.path.getsize(found_exe) / (1024 * 1024)
        print("\n" + "=" * 60)
        print("  BUILD SUCCESS!")
        print(f"  EXE: {found_exe}")
        print(f"  Size: {size_mb:.1f} MB")
        print("=" * 60)
        print("\n  Usage:")
        print("    SandboxAnalyzer.exe                       # Launch GUI")
        print("    SandboxAnalyzer.exe malware.exe           # CLI analysis")
        print("    SandboxAnalyzer.exe --dynamic malware.exe")
    else:
        print("\n" + "=" * 60)
        print("  BUILD FAILED")
        print("  Check output above for details")
        print("=" * 60)
        print("\n  Common fixes:")
        print("  1. pip install -r requirements.txt")
        print("  2. Delete build/ and dist/ folders, retry")
        print("  3. Check antivirus isn't blocking PyInstaller")


if __name__ == "__main__":
    main()
