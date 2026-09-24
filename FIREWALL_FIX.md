# RDP Security Service - Firewall Sync Fix 

## Problem Summary

The RDP Security Service was successfully blocking IPs and logging them to `block_list.log`, but the Windows Firewall rule `RDP_BLOCK_ALL` was not being synchronized with the blocked IPs from the log file. This meant:

- **Detection**: ✅ Working - failed RDP attempts were detected and logged
- **Blocking Decision**: ✅ Working - service decided which IPs to block based on config
- **Log Recording**: ✅ Working - blocked IPs were written to `block_list.log`  
- **Firewall Sync**: ❌ BROKEN - firewall rule contained stale IPs (1.1.1.1) instead of actual blocked IPs

## Root Cause

The original firewall update method in `UpdateFirewallRuleFromBlockList()` used PowerShell cmdlets:
- `Remove-NetFirewallRule` 
- `New-NetFirewallRule`
- `Set-NetFirewallAddressFilter`

These cmdlets had reliability issues with error messages like:
- "InputObjectNotBound" parameter binding exceptions
- Race conditions between delete and add operations

## Solution Implemented

Replaced PowerShell cmdlet approach with direct `netsh` command-line tool calls:

```csharp
// Delete old rule
netsh advfirewall firewall delete rule name="RDP_BLOCK_ALL"

// Create new rule with all current blocked IPs
netsh advfirewall firewall add rule name="RDP_BLOCK_ALL" \
  dir=in action=block protocol=tcp localport=3389 \
  remoteip="192.168.1.100/32,192.168.1.174/32,..." \
  profile=any enable=yes
```

Benefits:
- More reliable - netsh is the native firewall management tool
- Better error handling and logging
- Simpler command structure without complex pipelines
- Wraps commands through `cmd.exe` for robustness

## Files Modified

- `WinService/Program.cs`
  - Line 168: Added `InitBanDb()` method call to initialize ban database
  - Line ~219-225: Fixed OnStop() to handle missing gateThread variable gracefully
  - Line 550-590: Rewrote `UpdateFirewallRuleFromBlockList()` to use `netsh` instead of PowerShell cmdlets

## Testing & Deployment

### For Administrator

1. **Stop the service** (run as Administrator):
   ```batch
   restart_service_admin.bat
   ```
   Or manually:
   ```cmd
   net stop RDPSecurityService
   net start RDPSecurityService
   ```

2. **Verify firewall rule** created correctly:
   ```powershell
   netsh advfirewall firewall show rule name="RDP_BLOCK_ALL"
   ```

### Manual Firewall Update (if needed)

Run as Administrator:
```powershell
# PowerShell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\update_firewall.ps1
```

### Monitoring

Check service logs at:
- `C:\ProgramData\RDPSecurityService\service.log` - general service log
- `C:\ProgramData\RDPSecurityService\access.log` - all RDP attempts
- `C:\ProgramData\RDPSecurityService\block_list.log` - blocked IPs

## Expected Behavior After Fix

1. Failed RDP attempt from new IP → logged to `access.log`
2. Attempt count exceeds threshold → logged to `block_list.log`
3. Service detects `block_list.log` change → calls `UpdateFirewallRuleFromBlockList()`
4. Method reads IPs from log → calls netsh to update firewall rule
5. Firewall rule `RDP_BLOCK_ALL` updated with new IPs
6. Subsequent attempts from blocked IPs → rejected by firewall

## Threshold Configuration

Config file: `C:\ProgramData\RDPSecurityService\config.json`

Default blocking levels (can be customized):
- **Level 1**: 3 failed attempts → 30 minutes
- **Level 2**: 5 failed attempts → 180 minutes (3 hours)  
- **Level 3**: 7 failed attempts → 2880 minutes (48 hours)

## Testing Checklist

- [ ] Service starts without errors after binary deployment
- [ ] Monitor shows real-time connections
- [ ] Failed RDP attempt → appears in `access.log`
- [ ] After threshold hits → appears in `block_list.log` 
- [ ] Firewall rule contains correct blocked IPs (not 1.1.1.1)
- [ ] Monitor "Blocked IPs" tab shows correct IP with ban status
- [ ] Manual refresh button works on blocked IPs tab
- [ ] Second attempt from same IP blocked by firewall (fast rejection)
- [ ] After ban timeout → IP removed and connected again allowed (if retry)

## Known Limitations & Notes

- Service runs as SYSTEM account (required for Event Log access and firewall modification)
- Block duration TTL based on config or "Until" field in block_list.log
- Whitelisted IPs are exempt from blocking
- Firewall rule profiles: Domain, Private, Public (all checked)
- RDP port is configurable via config.json (default 3389)

