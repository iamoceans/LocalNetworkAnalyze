@echo off
echo ============================================
echo Network Capture Test - Administrator Mode
echo ============================================
echo.
echo This script will run the capture test with administrator privileges.
echo.
PAUSE

cd /d "%~dp0"
powershell -Command "Start-Process python -ArgumentList 'test_capture.py' -Verb RunAs"

echo.
echo If UAC prompt appears, click 'Yes' to continue.
echo.
PAUSE
