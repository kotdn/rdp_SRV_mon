@echo off
REM Administrator restart script for RDP Security Service with firewall update
REM This script restarts the RDP Security Service and updates firewall rules

echo RDP Security Service Restart Script
echo ====================================
echo.

REM Stop the service
echo Stopping RDPSecurityService...
net stop RDPSecurityService
if errorlevel 1 (
    echo Warning: Could not stop service via net command
    taskkill /IM WinService.exe /F
)

echo Waiting for process to terminate...
timeout /t 3 /nobreak

REM Start the service
echo Starting RDPSecurityService...
net start RDPSecurityService

echo.
echo Checking service status...
sc query RDPSecurityService

echo.
echo Service restart complete!
echo Waiting 3 seconds then checking firewall rule...
timeout /t 3 /nobreak

echo.
echo Current firewall rule status:
netsh advfirewall firewall show rule name="RDP_BLOCK_ALL"

echo.
echo Done!
pause
