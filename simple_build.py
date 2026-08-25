# -*- coding: utf-8 -*-
"""
Build Malware Analysis Platform to exe
- Bundles all pure-Python alternatives (puremagic, ppdeep, plyara, etc.)
- Properly handles optional native extensions
"""
import subprocess
import sys
import os
import shutil


def main():
    PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
    MAIN_PY = os.path.join(PROJECT_DIR, "main.py")
    LOG_FILE = os.path.join(PROJECT_DIR, "_build_log.txt")

    # All pure-Python alternative packages that should be bundled
    PURE_PYTHON_PACKAGES = [
        "puremagic",   # Pure Python file type detection (alt for python-magic)
        "ppdeep",      # Pure Python fuzzy hash (alt for ssdeep)
        "plyara",      # Pure Python YARA parser (alt for yara-python)
        "fpdf",        # Pure Python PDF generation (fpdf2, import name is fpdf)
        "rarfile",     # Pure Python RAR extraction
        "py7zr",       # Pure Python 7z extraction
    ]

    # All hidden imports for project modules
    PROJECT_HIDDEN_IMPORTS = [
        "config", "logger", "orchestrator",
        "analyzer", "analyzer.models", "analyzer.static",
        "analyzer.pe", "analyzer.strings", "analyzer.archive",
        "analyzer.script", "analyzer.msi", "analyzer.dynamic",
        "analyzer.network", "analyzer.memory", "analyzer.api_monitor",
        "analyzer.destruction", "analyzer.family", "analyzer.dropped_files",
        "analyzer.advanced_behavior", "analyzer.vm_detector",
        "analyzer.vm_process_hider", "analyzer.persistence_rollback",
        "analyzer.tls_fingerprint", "analyzer.batch",
        "gui", "gui.main_window",
        "utils", "utils.helpers", "utils.dep_checker",
    ]

    # GUI related
    GUI_HIDDEN_IMPORTS = [
        "tkinter", "tkinter.ttk", "tkinter.filedialog",
        "tkinter.messagebox", "tkinter.scrolledtext",
        "tkinter.font", "tkinter.colorchooser",
        "PIL", "PIL.Image", "PIL.ImageTk", "PIL.ImageDraw",
        "ttkthemes",
    ]

    # Common optional packages (may or may not be installed)
    OPTIONAL_IMPORTS = [
        "pefile", "psutil", "requests", "jinja2", "jinja2.ext",
        "yaml", "olefile",
        "Crypto", "Cryptodome",
        "capstone",
    ]

    with open(LOG_FILE, "w", encoding="utf-8") as log:
        def w(msg):
            log.write(msg + "\n")
            log.flush()
        def w_both(msg):
            w(msg)
            print(msg)

        w_both("=== Build started ===")
        w_both(f"Python: {sys.version}")

        # Check PyInstaller
        try:
            import PyInstaller
            w_both(f"PyInstaller: {PyInstaller.__version__}")
        except ImportError:
            w_both("Installing PyInstaller...")
            r = subprocess.run(
                [sys.executable, "-m", "pip", "install", "pyinstaller"],
                capture_output=True, text=True
            )
            if r.returncode != 0:
                w_both(f"FATAL: Cannot install PyInstaller\n{r.stderr}")
                sys.exit(1)
            w_both("Installed")

        # Clean
        for d in ["build", "dist"]:
            dp = os.path.join(PROJECT_DIR, d)
            if os.path.exists(dp):
                shutil.rmtree(dp, ignore_errors=True)
                w_both(f"Cleaned {d}/")

        # Collect all --hidden-import args
        hidden_import_args = []
        for pkg in PURE_PYTHON_PACKAGES + PROJECT_HIDDEN_IMPORTS + GUI_HIDDEN_IMPORTS + OPTIONAL_IMPORTS:
            hidden_import_args += ["--hidden-import", pkg]

        # Add --collect-all for pure Python alternatives (forces bundling)
        collect_all_args = []
        copy_metadata_args = []
        # import 名 → 发行版 metadata 名 (fpdf2 的 import 名是 fpdf, 但发行版名是 fpdf2)
        METADATA_NAME_OVERRIDE = {"fpdf": "fpdf2"}
        for pkg in PURE_PYTHON_PACKAGES:
            try:
                __import__(pkg)
                collect_all_args += ["--collect-all", pkg]
                copy_metadata_args += ["--copy-metadata", METADATA_NAME_OVERRIDE.get(pkg, pkg)]
                w_both(f"  Will bundle: {pkg}")
            except ImportError:
                w_both(f"  Skipping (not installed): {pkg}")

        # Build command
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onedir",
            "--clean",
            "--noconfirm",
            "--name", "SandboxAnalyzer",
            "--add-data", f"analyzer{os.pathsep}analyzer",
            "--add-data", f"gui{os.pathsep}gui",
            "--add-data", f"utils{os.pathsep}utils",
            "--add-data", f"rules{os.pathsep}rules",
        ] + copy_metadata_args + hidden_import_args + collect_all_args + [MAIN_PY]

        w_both(f"\nBuilding with {len(hidden_import_args)//2} hidden imports...")
        w_both("This may take a few minutes...\n")

        try:
            r = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=600,
                cwd=PROJECT_DIR,
            )
            w(f"\nReturn code: {r.returncode}")
            w("\n--- STDOUT (last 3000 chars) ---")
            w(r.stdout[-3000:] if len(r.stdout) > 3000 else r.stdout)
            w("\n--- STDERR (last 2000 chars) ---")
            w(r.stderr[-2000:] if len(r.stderr) > 2000 else r.stderr)

            if r.returncode == 0:
                dist = os.path.join(PROJECT_DIR, "dist", "SandboxAnalyzer")
                exe = os.path.join(dist, "SandboxAnalyzer.exe")
                if os.path.exists(exe):
                    size_mb = os.path.getsize(exe) / (1024 * 1024)
                    w_both(f"\n{'='*50}")
                    w_both("  BUILD SUCCESS!")
                    w_both(f"  EXE: {exe}")
                    w_both(f"  Size: {size_mb:.1f} MB")
                    w_both(f"{'='*50}")
                else:
                    w_both(f"\nERROR: exe not found at {exe}")
                    w_both("dist/ contents:")
                    for item in sorted(os.listdir(dist)):
                        w_both(f"  {item}")
            else:
                w_both(f"\nBUILD FAILED (code {r.returncode})")

        except subprocess.TimeoutExpired:
            w_both("TIMEOUT (>10 min)")
        except Exception as e:
            w_both(f"ERROR: {e}")
            import traceback
            traceback.print_exc(file=log)

        w_both(f"\nLog saved to: {LOG_FILE}")


if __name__ == "__main__":
    main()
