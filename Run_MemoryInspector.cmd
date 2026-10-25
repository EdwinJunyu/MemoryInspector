@echo off
setlocal
REM Uses Windows PowerShell 5.1 and a per-process execution policy; no permanent system setting change.
powershell.exe -NoProfile -STA -ExecutionPolicy RemoteSigned -File "%~dp0MemoryInspector.ps1"
if errorlevel 1 (
  echo.
  echo MemoryInspector could not start. Review the error above.
  echo RemoteSigned is retained. Downloaded unsigned scripts require source verification and explicit trust.
  echo Do not lower the execution policy or automatically unblock the project folder.
  pause
)
