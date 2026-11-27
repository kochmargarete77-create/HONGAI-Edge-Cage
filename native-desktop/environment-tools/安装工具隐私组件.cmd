@echo off
if not exist "%~dp0request.json" (
  echo Prepare the approved local request.json first. No changes were made.
  exit /b 2
)
"%~dp0hongai-tools.exe" install --request "%~dp0request.json"
exit /b %errorlevel%
