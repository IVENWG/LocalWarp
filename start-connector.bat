@echo off
title LocalWarp Connector
echo =============================================
echo    LocalWarp Connector Daemon for Windows
echo =============================================

set SCRIPT_DIR=%~dp0
set STANDALONE_EXE=%SCRIPT_DIR%dist\connectors\LocalWarp-Connector-windows-x64.exe

if exist "%STANDALONE_EXE%" (
    echo [+] Found standalone LocalWarp Connector executable.
    echo [+] Starting LocalWarp Connector on 0.0.0.0:28888...
    "%STANDALONE_EXE%" %*
    pause
    exit /b 0
)

echo [*] Standalone .exe not found. Falling back to Python...
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found in your system PATH.
    echo Please download LocalWarp-Connector-windows-x64.exe or install Python 3.10+.
    pause
    exit /b 1
)

echo [1/2] Checking LocalWarp dependencies...
python -c "import fastapi, uvicorn, pymobiledevice3" >nul 2>nul
if %errorlevel% neq 0 (
    echo Installing required packages...
    rem 与 requirements-connector.txt 保持一致（pystray/pillow 供托盘 GUI 入口使用）
    pip install fastapi uvicorn pydantic requests cryptography construct construct-typing zeroconf pymobiledevice3 pytun-pmd3 pystray pillow
    if %errorlevel% neq 0 (
        echo [ERROR] Package installation failed. Check your network and retry.
        pause
        exit /b 1
    )
)

rem PYTHONPATH 未定义时避免残留尾部分号（空条目等价于把 cwd 引入模块搜索路径）
if defined PYTHONPATH (
    set "PYTHONPATH=%SCRIPT_DIR%src\poc;%PYTHONPATH%"
) else (
    set "PYTHONPATH=%SCRIPT_DIR%src\poc"
)

echo [2/2] Starting LocalWarp Connector on 0.0.0.0:28888...
echo Open your workbench at: https://localwarp.com/app
echo Press Ctrl+C to stop.
echo ---------------------------------------------
python "%SCRIPT_DIR%src\backend\server.py" %*

pause
