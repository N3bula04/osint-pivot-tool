@echo off
REM One-time setup for Windows. Double-click this file, or run it from PowerShell.
cd /d "%~dp0"
echo [1/4] Checking Python...
py -3 --version >nul 2>&1 || (echo Python 3 not found. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH". & pause & exit /b 1)
py -3 --version
echo [2/4] Creating private environment (.venv)...
py -3 -m venv .venv || (pause & exit /b 1)
echo [3/4] Installing dependencies...
.venv\Scripts\python.exe -m pip install --quiet --upgrade pip
.venv\Scripts\python.exe -m pip install --quiet -r requirements.txt || (pause & exit /b 1)
echo [4/4] Running self-check...
.venv\Scripts\python.exe test_rating.py
echo.
echo Setup complete. To run a report, open PowerShell in this folder and type:
echo     .\run.bat example.com
pause
