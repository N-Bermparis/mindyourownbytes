@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.10 or newer, then run setup_windows.bat again.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 goto :error
)
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto :error
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :error
echo.
echo Setup complete. Run start_windows.bat to launch mindyourownbytes.
pause
exit /b 0
:error
echo Setup failed. Check the error messages above.
pause
exit /b 1
