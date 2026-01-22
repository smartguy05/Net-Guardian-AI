@echo off
echo Starting NetGuardian AI...
echo.
echo NOTE: This script requires Administrator privileges for port forwarding.
echo       If port forwarding fails, right-click and "Run as administrator"
echo.
powershell -ExecutionPolicy Bypass -File "%~dp0scripts\start-dev.ps1"
pause
