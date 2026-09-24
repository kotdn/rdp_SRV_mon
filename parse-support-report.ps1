param(
    [Parameter(Mandatory = $true)]
    [string]$ZipPath
)

$ErrorActionPreference = "Stop"

if (!(Test-Path -LiteralPath $ZipPath)) {
    throw "ZIP not found: $ZipPath"
}

$tempRoot = Join-Path $env:TEMP ("rdp-support-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $tempRoot -Force

    $jsonPath = Join-Path $tempRoot "support-report.json"
    if (!(Test-Path -LiteralPath $jsonPath)) {
        throw "support-report.json not found in archive"
    }

    $report = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json

    Write-Host "=== RDP Support Report ==="
    Write-Host "Report ID: $($report.reportId)"
    Write-Host "Generated: $($report.generatedLocal)"
    Write-Host "Machine: $($report.machineName)"
    Write-Host "User: $($report.userName)"
    Write-Host "OS: $($report.osVersion)"
    Write-Host "Monitor Version: $($report.monitorVersion)"
    Write-Host "Service Status: $($report.serviceStatus)"
    Write-Host ""
    Write-Host "Access attempts total: $($report.accessAttemptsTotal)"
    Write-Host "Access attempts last 24h: $($report.accessAttemptsLast24h)"
    Write-Host "Active blocked targets: $($report.activeBlockedTargets)"
    Write-Host "Active blocked direct IPs: $($report.activeBlockedDirectIps)"
    Write-Host "Active blocked subnets: $($report.activeBlockedSubnets)"
    Write-Host "Firewall remote target count: $($report.firewallRemoteTargetCount)"
    Write-Host "Whitelist entries: $($report.whitelistEntries)"
    Write-Host ""
    Write-Host "Top blocked targets:"
    if ($report.topBlockedTargets -and $report.topBlockedTargets.Count -gt 0) {
        $report.topBlockedTargets | ForEach-Object {
            Write-Host (" - {0}: {1}" -f $_.target, $_.hits)
        }
    }
    else {
        Write-Host " - (none)"
    }
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
