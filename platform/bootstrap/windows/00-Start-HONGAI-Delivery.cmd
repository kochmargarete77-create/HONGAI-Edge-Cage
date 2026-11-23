@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"

set "HONGAI_LAUNCH_SCRIPT=%~dp0Start-HONGAI-Delivery.ps1"
set "HONGAI_SYSTEM_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%HONGAI_LAUNCH_SCRIPT%" (
  echo [HONG AI] Delivery launcher is missing.
  pause
  exit /b 1
)
if not exist "%HONGAI_SYSTEM_POWERSHELL%" (
  echo [HONG AI] Trusted Windows PowerShell is missing.
  pause
  exit /b 1
)

echo [HONG AI] Requesting Windows administrator approval...
"%HONGAI_SYSTEM_POWERSHELL%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$script=$env:HONGAI_LAUNCH_SCRIPT; $quoted='"' + $script + '"'; $trusted=Join-Path $PSHOME 'powershell.exe'; $p=Start-Process -FilePath $trusted -Verb RunAs -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$quoted) -Wait -PassThru; exit $p.ExitCode"
set "HONGAI_EXIT=%ERRORLEVEL%"

echo.
if "%HONGAI_EXIT%"=="0" (
  echo [HONG AI] Delivery command completed successfully.
) else (
  echo [HONG AI] Delivery stopped with exit code %HONGAI_EXIT%.
)
echo Press any key to close this window.
pause >nul
exit /b %HONGAI_EXIT%
