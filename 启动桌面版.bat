@echo off
%SystemRoot%\System32\chcp.com 65001 >nul
title 恶意攻击行为溯源分析系统 - 桌面版
cd /d "%~dp0electron"
if not exist node_moduleslectron\r
(
  echo 首次运行：安装桌面版依赖（约 1-2 分钟，走国内镜像）...
  call npm install
)
echo 启动桌面窗口（关闭窗口即停止平台）...
call npm start
pause
