# Canonical Installation Path (WinService/RDPMonitor)

This repository now supports only one production installation path:

- service: WinService (RDPSecurityService)
- monitor UI: RDPMonitor
- install root: C:\Program Files\RDPSecurityService
- runtime/config/logs: C:\ProgramData\RDPSecurityService

## Supported installer entry points

Use one of these scripts from release package:

- release/RDP-Security-Suite-ZIP/install-clean.ps1
- release/RDP-Security-Suite-ZIP-PUBLIC/install-clean.ps1

Run as Administrator.

## Recommended install command

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
cd .\release\RDP-Security-Suite-ZIP
.\install-clean.ps1 -StartMonitor
```

For public package:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
cd .\release\RDP-Security-Suite-ZIP-PUBLIC
.\install-clean.ps1 -StartMonitor
```

## What this does

- copies service and monitor binaries to C:\Program Files\RDPSecurityService
- creates/repairs RDPSecurityService Windows service
- prepares required runtime layout for service assemblies
- ensures service startup and startup diagnostics
- creates monitor shortcuts (desktop and start menu)

## Validation checklist

```powershell
Get-Service RDPSecurityService
Get-Content C:\ProgramData\RDPSecurityService\service.log -Tail 100
```

Monitor executable:

```powershell
& "C:\Program Files\RDPSecurityService\RDPMonitor.exe"
```

## Legacy status

The following legacy WebApp deployment flow is deprecated and must not be used:

- deploy.ps1 / deploy.bat
- server-startup.ps1 / server-startup.bat
- DEPLOYMENT.md / SERVER_DEPLOYMENT.md / QUICKSTART.md / LOCAL_SETUP.md
