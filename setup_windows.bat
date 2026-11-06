@echo off
setlocal
cd /d "%~dp0"
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if not defined PY goto :nopython
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
if errorlevel 1 goto :nopython
if not exist ".venv\Scripts\python.exe" (
  %PY% -m venv .venv
  if errorlevel 1 goto :error
)
rem --require-hashes refuses any package that differs from the reviewed lock file.
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check --require-hashes -r requirements.txt
if errorlevel 1 goto :error
echo.
echo Setup complete. Run start_windows.bat to launch mindyourownbytes.
pause
exit /b 0
:nopython
echo Python 3.11 or newer was not found. Install it from https://www.python.org/downloads/
echo and then run setup_windows.bat again.
pause
exit /b 1
:error
echo Setup failed. Check the error messages above.
pause
exit /b 1
