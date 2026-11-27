@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
if not exist "%~dp0HONGAI-Environment.exe" (
  echo Package incomplete: HONGAI-Environment.exe is missing.
  echo Extract the complete package into a local folder before running this entry.
  pause
  exit /b 2
)
"%~dp0HONGAI-Environment.exe" environment open %*
set "HONGAI_SETUP_EXIT=%ERRORLEVEL%"
if not "%HONGAI_SETUP_EXIT%"=="0" (
  echo.
  echo Installation did not finish. Keep the error code above for service review.
  echo Do not remove Claude, change the system network, or restart this computer.
  pause
)
exit /b %HONGAI_SETUP_EXIT%
