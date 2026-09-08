@echo off
setlocal
call "%~dp0ares.bat" mcp %*
set EXIT_CODE=%ERRORLEVEL%
endlocal & exit /b %EXIT_CODE%
