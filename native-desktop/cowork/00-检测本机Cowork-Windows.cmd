@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Check-Cowork-Windows.ps1" -Mode Unknown -OutputPath "%~dp0cowork-readiness.json"
echo.
pause
