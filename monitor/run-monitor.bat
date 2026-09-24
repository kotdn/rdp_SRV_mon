@echo off
cd /d "%~dp0"
echo Starting RDP Security Monitor...
start "" "bin\Debug\net8.0-windows\RDPMonitor.exe"
