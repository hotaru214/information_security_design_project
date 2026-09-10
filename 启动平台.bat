@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Starting platform...
python scripts\start_platform.py --open
pause
