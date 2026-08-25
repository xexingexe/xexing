import subprocess
import sys
import os


def main():
    output_log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_build_log.txt")

    with open(output_log, "w", encoding="utf-8") as f:
        f.write("=== Build Execution Log ===\n")

        # Step 1: Check Python
        f.write(f"\n[1] Python: {sys.version}\n")
        f.write(f"    executable: {sys.executable}\n")

        # Step 2: Check project dir
        project_dir = os.path.dirname(os.path.abspath(__file__))
        f.write(f"\n[2] Project dir: {project_dir}\n")
        f.write(f"    exists: {os.path.exists(project_dir)}\n")

        if os.path.exists(project_dir):
            files = os.listdir(project_dir)
            f.write(f"    files ({len(files)}):\n")
            for item in sorted(files):
                full = os.path.join(project_dir, item)
                if os.path.isdir(full):
                    f.write(f"      [DIR]  {item}\n")
                else:
                    f.write(f"      [FILE] {item}\n")

        # Step 3: Check PyInstaller
        f.write("\n[3] PyInstaller:\n")
        try:
            import PyInstaller
            f.write(f"    version: {PyInstaller.__version__}\n")
        except ImportError as e:
            f.write(f"    NOT INSTALLED: {e}\n")
            f.write("    Installing...\n")
            try:
                r = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "pyinstaller"],
                    capture_output=True, text=True, timeout=120,
                    cwd=project_dir
                )
                f.write(f"    pip stdout: {r.stdout[-500:]}\n")
                f.write(f"    pip stderr: {r.stderr[-500:]}\n")
            except Exception as e2:
                f.write(f"    install error: {e2}\n")

        # Step 4: Check pip
        f.write("\n[4] pip:\n")
        try:
            r = subprocess.run(
                [sys.executable, "-m", "pip", "--version"],
                capture_output=True, text=True, timeout=10
            )
            f.write(f"    {r.stdout.strip()}\n")
        except Exception as e:
            f.write(f"    error: {e}\n")

        # Step 5: Try running build_exe.py
        f.write("\n[5] Running build_exe.py:\n")
        build_script = os.path.join(project_dir, "build_exe.py")
        if not os.path.exists(build_script):
            f.write(f"    NOT FOUND: {build_script}\n")
        else:
            f.write(f"    executing: {build_script}\n")
            try:
                r = subprocess.run(
                    [sys.executable, build_script],
                    capture_output=True, text=True, timeout=300,
                    cwd=project_dir,
                    env={**os.environ, "PYTHONIOENCODING": "utf-8"}
                )
                f.write(f"    returncode: {r.returncode}\n")
                f.write(f"    --- STDOUT ---\n{r.stdout}\n")
                f.write(f"    --- STDERR ---\n{r.stderr}\n")
            except subprocess.TimeoutExpired:
                f.write("    TIMEOUT (>300s)\n")
            except Exception as e:
                f.write(f"    error: {e}\n")

        f.write("\n=== DONE ===\n")

    print("Log written to:", output_log)


if __name__ == "__main__":
    main()
