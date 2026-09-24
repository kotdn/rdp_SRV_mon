#Requires -RunAsAdministrator
<#
.DESCRIPTION
Emergency firewall rule update script for RDP Security Service.
Run as Administrator to manually sync firewall with block_list.log.
#>

$ErrorActionPreference = "Stop"

$blockListPath = "C:\ProgramData\RDPSecurityService\block_list.log"
$port = 3389

function ExtractBlockedIPs {
    param([string]$logPath)
    $ips = @()
    if (Test-Path $logPath) {
        Get-Content $logPath | ForEach-Object {
            if ($_ -match "BLOCKED IP:\s*([\d\.]+)") {
                $ip = $matches[1]
                if ($ips -notcontains $ip) {
                    $ips += $ip
                }
            }
        }
    }
    return $ips
}

# Get blocked IPs from log
$blockedIPs = ExtractBlockedIPs $blockListPath
Write-Host "Found blocked IPs: $($blockedIPs -join ', ')" -ForegroundColor Green

if ($blockedIPs.Count -eq 0) {
    # Delete rule if no IPs
    Write-Host "No blocked IPs found. Deleting firewall rule..." -ForegroundColor Yellow
    netsh advfirewall firewall delete rule name="RDP_BLOCK_ALL" 2>&1 | Out-Null
    Write-Host "Done." -ForegroundColor Green
} else {
    # Delete old rule
    Write-Host "Deleting old firewall rule..." -ForegroundColor Yellow
    netsh advfirewall firewall delete rule name="RDP_BLOCK_ALL" 2>&1 | Out-Null
    
    # Build IP list
    $remoteIpList = ($blockedIPs | ForEach-Object { "$_/32" }) -join ","
    
    # Create new rule
    Write-Host "Creating new firewall rule with IPs: $remoteIpList" -ForegroundColor Yellow
    $cmd = "netsh advfirewall firewall add rule name=`"RDP_BLOCK_ALL`" dir=in action=block protocol=tcp localport=$port remoteip=`"$remoteIpList`" profile=any enable=yes"
    Invoke-Expression $cmd
    
    # Verify
    Write-Host "`nVerifying rule..." -ForegroundColor Cyan
    netsh advfirewall firewall show rule name="RDP_BLOCK_ALL"
}

Write-Host "`nFirewall update complete!" -ForegroundColor Green
