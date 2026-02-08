@echo off
REM Local Network Analyzer - Windows Startup Script
REM Run this batch file to start the application

echo Starting Local Network Analyzer...
echo.

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo No virtual environment found.
    echo Creating one now...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo Installing dependencies...
    pip install -r requirements.txt
)

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges - OK
) else (
    echo WARNING: Not running as administrator.
    echo Packet capture may not work correctly.
    echo Right-click and select "Run as Administrator"
    echo.
)

REM Start the application
echo.
echo Starting GUI application...
python run.py

pause
