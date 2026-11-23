@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"

if not exist "%~dp0Retry-HONGAI-Receipt.ps1" (
  echo [HONG AI] Receipt retry launcher is missing.
  pause
  exit /b 1
)
set "HONGAI_SYSTEM_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%HONGAI_SYSTEM_POWERSHELL%" (
  echo [HONG AI] Trusted Windows PowerShell is missing.
  pause
  exit /b 1
)

"%HONGAI_SYSTEM_POWERSHELL%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0Retry-HONGAI-Receipt.ps1"
set "HONGAI_EXIT=%ERRORLEVEL%"
echo.
if "%HONGAI_EXIT%"=="0" (
  echo [HONG AI] Receipt retry completed successfully.
) else (
  echo [HONG AI] Receipt retry stopped with exit code %HONGAI_EXIT%.
)
echo Press any key to close this window.
pause >nul
exit /b %HONGAI_EXIT%
