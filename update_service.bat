@echo off
echo Stopping RDP Security Service...
sc stop RDPSecurityService
timeout /t 3 /nobreak >nul

echo Updating service executable...
copy /Y "c:\Users\samoilenkod\source\repos\Winservice\artifacts\final\winservice\WinService.exe" "C:\Program Files\RDPSecurityService\WinService.exe"

echo Starting RDP Security Service...
sc start RDPSecurityService

echo.
echo Service updated and restarted!
pause
