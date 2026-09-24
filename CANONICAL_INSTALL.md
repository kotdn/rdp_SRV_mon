# Canonical Installation Path (WinService/RDPMonitor)

This repository now supports only one production installation path:

- service: WinService (RDPSecurityService)
- monitor UI: RDPMonitor
- install root: C:\Program Files\RDPSecurityService
- runtime/config/logs: C:\ProgramData\RDPSecurityService

## Supported installer entry point

- Install/install.ps1 (see [Install/README.md](Install/README.md))

Run as Administrator.

## Recommended install command

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
cd Install
.\install.ps1 -StartMonitor
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
