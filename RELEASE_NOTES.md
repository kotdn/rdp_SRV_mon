# RDP Security Service - Release v2026-03-06

## 🎉 Release Information

**Version:** v2026-03-06  
**Release Date:** March 6, 2026  
**Platform:** Windows x64  
**Package Size:** ~115 MB  
**Build Type:** Self-contained (no .NET runtime required)

## 📦 What's Included

- ✅ **RDP Security Service** - Windows Service for real-time RDP brute-force protection
- ✅ **RDP Monitor** - GUI application for monitoring and management
- ✅ **Automated Installer** - PowerShell script for easy deployment
- ✅ **Documentation** - Complete installation and usage guides

## 🧪 Test Focus (for external testers)

Please focus on these scenarios:

- **Install flow**: unzip package, run `run-public-install.bat` as Administrator, complete installation.
- **SmartScreen handling**: if warning appears, click "More info" -> "Run anyway" and continue.
- **Service health**: verify `RDPSecurityService` is running after install.
- **Firewall model**: confirm single rule `RDP_BLOCK_ALL` is used, and blocked IPs are updated in its `RemoteIP` list.
- **Brute-force behavior**: repeated failed logons from one IP lead to ban by configured levels.
- **Monitor behavior**: logs update in real time, blocked list is visible, manual unblock works.
- **No private tools in public zip**: package must not contain internal report-reader tools.

Quick check command:

```powershell
netsh advfirewall firewall show rule name="RDP_BLOCK_ALL"
```

## 🆕 New Features (v2026-03-06)

### Security & Performance
- **Real-time protection** with 1-second check interval (anti-DDoS optimized)
- **Multi-level blocking system** - Progressive ban durations based on attempt count
- **SQLite database** for persistent ban tracking across reboots
- **Windows Firewall integration** - Automatic rule management

### User Interface
- **Adaptive layout** - TabControl with proper 50px bottom margin, resizes with window
- **Full localization** - Ukrainian and English interface (Russian completely removed)
- **Configuration display** - Shows refresh interval and block levels
- **Desktop shortcut** - Automatic creation during installation
- **Language selector** - Choose UA/EN on startup

### Fixed Issues
- ✅ Fixed bottom UI elements being cut off in monitor
- ✅ Fixed all hardcoded English strings (now properly localized)
- ✅ Corrected typo: "СПРОМИ" → "СПРОБИ"
- ✅ Improved panel layout and spacing

## 🔧 Default Configuration

```json
{
  "port": 3389,
  "levels": [
    { "attempts": 1, "blockMinutes": 20 },
    { "attempts": 2, "blockMinutes": 128 },
    { "attempts": 7, "blockMinutes": 240 },
    { "attempts": 10, "blockMinutes": 1440 }
  ]
}
```

**Blocking Logic:**
- 1 failed attempt → 20 minutes ban
- 2 failed attempts → 128 minutes ban (2.1 hours)
- 7 failed attempts → 240 minutes ban (4 hours)
- 10+ failed attempts → 1440 minutes ban (24 hours)

## 📋 System Requirements

- Windows 10/11 or Windows Server 2016+
- Administrator privileges
- 100 MB free disk space
- RDP service enabled (port 3389 or custom)
- Windows Firewall enabled

## 🚀 Quick Installation

1. Download `RDPSecurityService-v2026-03-06.zip`
2. Extract to any folder
3. Right-click `install.ps1` → **Run with PowerShell**
4. Follow on-screen instructions
5. Launch monitor from desktop shortcut

**Detailed instructions:** See [INSTALL.md](https://github.com/yourusername/yourrepo/blob/main/INSTALL.md)

## 📊 Performance Metrics

- **CPU Usage:** < 1% (idle), < 5% (under attack)
- **Memory Usage:** ~30-50 MB
- **Check Interval:** 1 second (real-time)
- **Startup Time:** < 2 seconds
- **Firewall Update:** < 500ms

## 🔒 Security Features

- ✅ Real-time Windows Security Event Log monitoring
- ✅ Automatic IP blocking via Windows Firewall
- ✅ White-list support for trusted IPs
- ✅ Persistent ban database (survives reboots)
- ✅ Multi-level progressive blocking
- ✅ Manual IP management via GUI
- ✅ Runs as Windows Service (SYSTEM privileges)

## 📁 Installation Paths

| Component | Path |
|-----------|------|
| Service | `C:\Program Files\RDPSecurityService\WinService.exe` |
| Monitor | `C:\Program Files\RDPSecurityService\Monitor\RDPMonitor.exe` |
| Config | `C:\ProgramData\RDPSecurityService\config.json` |
| Logs | `C:\ProgramData\RDPSecurityService\*.log` |
| Database | `C:\ProgramData\RDPSecurityService\s.db` |

## 🛠️ Service Management

```powershell
# Check status
Get-Service RDPSecurityService

# Start service
Start-Service RDPSecurityService

# Stop service
Stop-Service RDPSecurityService

# Restart service
Restart-Service RDPSecurityService

# View logs
Get-Content "C:\ProgramData\RDPSecurityService\access.log" -Tail 20
```

## 🌐 Monitor Application

RDP Monitor provides:
- **Current Logs** - Real-time event feed
- **Banned IPs** - View and unblock IPs
- **White List** - Manage trusted IPs
- **Manual Block** - Block specific IP with custom duration
- **Configuration** - View current settings and refresh interval
- **Language** - Switch between Ukrainian and English

## 📝 Upgrade Notes

### From Previous Versions
1. Backup your config: `C:\ProgramData\RDPSecurityService\config.json`
2. Stop the service
3. Run new installer
4. Restore custom config if needed
5. Restart service

### Breaking Changes
- Russian language removed (UA/EN only)
- Monitor UI layout changed (improved spacing)
- Desktop shortcut name changed to "RDP Monitor"

## 🐛 Known Issues

None at this time. Please report issues on GitHub.

## 📞 Support

- **Documentation:** See README.md and INSTALL.md in release package
- **Issues:** Create issue on GitHub repository
- **Logs:** Check `C:\ProgramData\RDPSecurityService\access.log`
- **Event Viewer:** Application log → Source: RDPSecurityService

## 🗑️ Uninstallation

```powershell
# Run as Administrator
Stop-Service RDPSecurityService
sc.exe delete RDPSecurityService
Remove-Item "C:\Program Files\RDPSecurityService" -Recurse -Force
Remove-Item "C:\ProgramData\RDPSecurityService" -Recurse -Force
Remove-Item "$env:USERPROFILE\Desktop\RDP Monitor.lnk"
```

## 📜 License

© 2026 RDP Security Service. All rights reserved.

## 🙏 Acknowledgments

Built with:
- .NET 8.0
- C# / WinForms
- SQLite
- Windows Security Event Log API

---

**Download:** [RDPSecurityService-v2026-03-06.zip](https://github.com/yourusername/yourrepo/releases/download/v2026-03-06/RDPSecurityService-v2026-03-06.zip)

**SHA-256 Checksum:** (to be calculated)

**Release Build:** 2026-03-06T21:48:03Z
