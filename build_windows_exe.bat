@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup_windows.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check "pyinstaller==6.22.3"
if errorlevel 1 goto :error
rem One folder rather than --onefile: nothing unpacks to a temp directory at each
rem launch, antivirus raises fewer false alarms, and each bundled library stays
rem visible and replaceable.
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onedir --windowed --name "mindyourownbytes" --icon "packaging\app.ico" --paths . --add-data "mindyourownbytes\styles.qss;mindyourownbytes" mindyourownbytes\__main__.py
if errorlevel 1 goto :error
echo.
echo The application is in dist\mindyourownbytes\
echo This build is unsigned, and it is not a security review.
echo Gpg4win must still be installed on the destination computer.
pause
exit /b 0
:error
echo Build failed.
pause
exit /b 1
