@echo off
pushd "%~dp0"

:: Check for admin privileges
net session >nul 2>&1
if NOT %errorLevel% == 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process -FilePath '%~dp0start-windows.bat' -Verb RunAs"
    exit /b
)

echo Installing dependencies for ClamShield...
call npm install
echo Building ClamShield...
call npm run build
echo Starting ClamShield Desktop App...
call npm run desktop
pause
