@echo off
cd /d "%~dp0"
echo Running diagnostic build...
echo This will save all output to _build_log.txt
echo.
python diagnose_and_build.py
echo.
echo Check _build_log.txt for results.
pause
