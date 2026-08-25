# -*- coding: utf-8 -*-
"""
Diagnostic + Build script — captures all output to a log file
Double-click this file to run, then check _build_log.txt for results
"""
import subprocess
import sys
import os
import datetime


def main():
    PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
    LOG_FILE = os.path.join(PROJECT_DIR, "_build_log.txt")

    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write(f"Build started: {datetime.datetime.now()}\n")
        log.write(f"Python: {sys.version}\n")
        log.write(f"Executable: {sys.executable}\n")
        log.write(f"CWD: {os.getcwd()}\n\n")

        # Step 1: Check project
        log.write("=" * 60 + "\n")
        log.write("STEP 1: Project Structure\n")
        log.write("=" * 60 + "\n")
        for item in sorted(os.listdir(PROJECT_DIR)):
            full = os.path.join(PROJECT_DIR, item)
            if os.path.isdir(full):
                log.write(f"  [DIR]  {item}\n")
                for sub in sorted(os.listdir(full)):
                    log.write(f"         {sub}\n")
            else:
                log.write(f"  [FILE] {item}\n")

        # Step 2: Check PyInstaller
        log.write("\n" + "=" * 60 + "\n")
        log.write("STEP 2: PyInstaller Check\n")
        log.write("=" * 60 + "\n")
        try:
            import PyInstaller
            log.write(f"PyInstaller version: {PyInstaller.__version__}\n")
        except ImportError as e:
            log.write(f"PyInstaller NOT installed: {e}\n")
            log.write("Installing...\n")
            r = subprocess.run(
                [sys.executable, "-m", "pip", "install", "pyinstaller"],
                capture_output=True, text=True, timeout=120
            )
            log.write(f"pip stdout:\n{r.stdout}\n")
            log.write(f"pip stderr:\n{r.stderr}\n")
            if r.returncode != 0:
                log.write("FAILED to install PyInstaller!\n")
                print(f"Log written to {LOG_FILE}")
                sys.exit(1)
            import PyInstaller
            log.write(f"Installed PyInstaller {PyInstaller.__version__}\n")

        # Step 3: Validate spec file
        log.write("\n" + "=" * 60 + "\n")
        log.write("STEP 3: Spec File Validation\n")
        log.write("=" * 60 + "\n")
        spec_file = os.path.join(PROJECT_DIR, "沙箱分析平台.spec")
        if not os.path.exists(spec_file):
            log.write(f"Spec file NOT FOUND: {spec_file}\n")
            print(f"Log written to {LOG_FILE}")
            sys.exit(1)
        log.write(f"Spec file: {spec_file}\n")
        log.write(f"Size: {os.path.getsize(spec_file)} bytes\n")

        # Try to compile the spec as Python
        try:
            with open(spec_file, "r", encoding="utf-8") as f:
                spec_code = f.read()
            compile(spec_code, spec_file, "exec")
            log.write("Spec file: VALID Python syntax\n")
        except SyntaxError as e:
            log.write(f"Spec file: SYNTAX ERROR! {e}\n")

        # Step 4: Check key imports
        log.write("\n" + "=" * 60 + "\n")
        log.write("STEP 4: Key Import Check\n")
        log.write("=" * 60 + "\n")
        os.chdir(PROJECT_DIR)
        sys.path.insert(0, PROJECT_DIR)
        for mod in ["config", "logger", "orchestrator", "utils.helpers", "utils.dep_checker",
                    "analyzer.models", "analyzer.static", "gui.main_window"]:
            try:
                __import__(mod)
                log.write(f"  OK  {mod}\n")
            except Exception as e:
                log.write(f"  FAIL {mod}: {e}\n")

        # Step 5: Run PyInstaller
        log.write("\n" + "=" * 60 + "\n")
        log.write("STEP 5: PyInstaller Build\n")
        log.write("=" * 60 + "\n")
        log.flush()

        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--clean",
            "--noconfirm",
            "--log-level=DEBUG",
            spec_file,
        ]
        log.write(f"Command: {' '.join(cmd)}\n\n")

        try:
            r = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=600,
                cwd=PROJECT_DIR,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"}
            )
            log.write(f"Return code: {r.returncode}\n\n")
            log.write("--- STDOUT ---\n")
            log.write(r.stdout)
            log.write("\n--- STDERR ---\n")
            log.write(r.stderr)
        except subprocess.TimeoutExpired:
            log.write("BUILD TIMEOUT (>10 minutes)\n")
        except Exception as e:
            log.write(f"BUILD ERROR: {e}\n")
            import traceback
            traceback.print_exc(file=log)

        # Step 6: Check results
        log.write("\n" + "=" * 60 + "\n")
        log.write("STEP 6: Results\n")
        log.write("=" * 60 + "\n")
        dist_dir = os.path.join(PROJECT_DIR, "dist")
        if os.path.exists(dist_dir):
            log.write("dist/ contents:\n")
            for item in sorted(os.listdir(dist_dir)):
                full = os.path.join(dist_dir, item)
                if os.path.isdir(full):
                    log.write(f"  [DIR]  {item}\n")
                else:
                    size_mb = os.path.getsize(full) / (1024 * 1024)
                    log.write(f"  [FILE] {item} ({size_mb:.1f} MB)\n")
        else:
            log.write("dist/ directory NOT FOUND\n")

        log.write(f"\nBuild finished: {datetime.datetime.now()}\n")

    print(f"Done! Full log saved to: {LOG_FILE}")
    print("Open _build_log.txt to see details")


if __name__ == "__main__":
    main()
