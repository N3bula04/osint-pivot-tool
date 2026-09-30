@echo off
REM Run the tool without activating anything:  .\run.bat example.com [options]
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (echo Run setup.bat first. & exit /b 1)
.venv\Scripts\python.exe pivot.py %*
exit /b %ERRORLEVEL%
