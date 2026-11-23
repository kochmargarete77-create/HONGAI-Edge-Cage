@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"

set "HONGAI_SCRIPT=%~dp0Abandon-HONGAI-Delivery.ps1"
set "HONGAI_SYSTEM_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%HONGAI_SCRIPT%" (
  echo [HONG AI] Explicit-abandon launcher is missing.
  pause
  exit /b 1
)
if not exist "%HONGAI_SYSTEM_POWERSHELL%" (
  echo [HONG AI] Trusted Windows PowerShell is missing.
  pause
  exit /b 1
)

echo [HONG AI] This is a terminal action. Continue only after recovery has been deliberately abandoned.
"%HONGAI_SYSTEM_POWERSHELL%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%HONGAI_SCRIPT%"
set "HONGAI_EXIT=%ERRORLEVEL%"
echo.
if "%HONGAI_EXIT%"=="0" (
  echo [HONG AI] Explicit abandonment completed or was durably queued.
) else (
  echo [HONG AI] Nothing was abandoned; command stopped with exit code %HONGAI_EXIT%.
)
echo Press any key to close this window.
pause >nul
exit /b %HONGAI_EXIT%
