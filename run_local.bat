
@echo off
echo 🛡️  ExfilEye DLP Email Security Monitor - Windows Launcher
echo ======================================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.11+ from https://python.org
    pause
    exit /b 1
)

REM Check if we're in the right directory
if not exist "app_fixed.py" (
    echo ❌ app_fixed.py not found
    echo Please ensure you're running this from the correct directory
    pause
    exit /b 1
)

REM Run the Python launcher
python run_local.py

pause
