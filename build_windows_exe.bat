@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup_windows.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install pyinstaller
if errorlevel 1 goto :error
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --name "mindyourownbytes" --add-data "styles.qss;." main.py
if errorlevel 1 goto :error
echo Your executable is in the dist folder.
echo Gpg4win must still be installed on the destination computer.
pause
exit /b 0
:error
echo Build failed.
pause
exit /b 1
