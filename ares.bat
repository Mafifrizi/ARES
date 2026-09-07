@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m ares.cli.main %*
) else (
    python -m ares.cli.main %*
)
endlocal
