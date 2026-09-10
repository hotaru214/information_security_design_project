@echo off
%SystemRoot%\System32\chcp.com 65001 >nul
cd /d "%~dp0"
echo ============================================
echo   恶意攻击行为溯源分析平台 - 启动中
echo   (启动后浏览器自动打开, Ctrl+C 停止)
echo ============================================
python scripts\start_platform.py
echo.
pause
