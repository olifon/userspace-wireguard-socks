@echo off
setlocal
set "SCRIPT_REF=main"
if not "%VERSION%"=="" set "SCRIPT_REF=%VERSION%"
set "SCRIPT_URL=https://raw.githubusercontent.com/reindertpelsma/userspace-wireguard-socks/%SCRIPT_REF%/install.ps1"
set "SCRIPT_PATH=%TEMP%\uwgsocks-install-%RANDOM%%RANDOM%.ps1"
curl.exe -fsSL -A "uwgsocks-installer" "%SCRIPT_URL%" -o "%SCRIPT_PATH%"
if errorlevel 1 exit /b %errorlevel%
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" %*
set "STATUS=%ERRORLEVEL%"
del "%SCRIPT_PATH%" >nul 2>&1
endlocal & exit /b %STATUS%
