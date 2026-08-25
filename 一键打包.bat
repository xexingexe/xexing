@echo off
cd /d "%~dp0"

echo ==========================================
echo   Malware Analysis Platform v3.0 - Build
echo   Bundling puremagic, ppdeep, plyara...
echo ==========================================
echo.

echo [1/3] Installing dependencies...
pip install -r requirements.txt
pip install puremagic ppdeep plyara fpdf2
if %errorlevel% neq 0 (
    echo [WARN] Some dependencies failed, continuing...
)

echo.
echo [2/3] Installing PyInstaller...
pip install pyinstaller
if %errorlevel% neq 0 (
    echo [ERROR] PyInstaller install failed!
    pause
    exit /b 1
)

echo.
echo [3/3] Building exe...
python simple_build.py

echo.
echo Done! Press any key to exit...
pause > nul
