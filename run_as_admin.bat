@echo off
echo Local Network Analyzer - Administrator Launch
echo ===============================================
echo.
echo This script will restart the application with administrator privileges.
echo.
pause

cd /d "%~dp0"
powershell -Command "Start-Process python -ArgumentList 'src/main.py' -Verb RunAs"

echo.
echo If a UAC prompt appeared, please click 'Yes' to continue.
echo.
pause
