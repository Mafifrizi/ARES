@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m ares.cli.console %*
) else (
    python -m ares.cli.console %*
)
endlocal
