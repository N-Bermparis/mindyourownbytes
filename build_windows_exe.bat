@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup_windows.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check --require-hashes -r requirements.txt -r requirements-build.txt
if errorlevel 1 goto :error
".venv\Scripts\python.exe" packaging\build_windows.py
if errorlevel 1 goto :error
echo.
echo The download is in dist\release\
echo This build is unsigned, and it is not a security review.
pause
exit /b 0
:error
echo Build failed.
pause
exit /b 1
