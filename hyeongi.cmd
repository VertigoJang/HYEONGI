@echo off
rem HYEONGI launcher for Windows (wraps packaging\windows\hyeongi.ps1)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0packaging\windows\hyeongi.ps1" %*
