@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
  echo Please run setup_windows.bat first.
  pause
  exit /b 1
)
start "mindyourownbytes" ".venv\Scripts\pythonw.exe" "%~dp0main.py"
