@echo off
REM Copy new Program.cs to service directory
copy Program.cs "C:\Program Files\RDPSecurityService\Program.cs"

REM Restart service
net stop RDPSecurityService
timeout /t 3
net start RDPSecurityService

echo Service restarted successfully
