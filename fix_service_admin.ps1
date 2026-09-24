$ErrorActionPreference = 'Stop'

$serviceName = 'RDPSecurityService'
$exePath = 'C:\Users\samoilenkod\source\repos\Winservice\artifacts\final\winservice\WinService.exe'

if (-not (Test-Path $exePath)) {
    throw "Service binary not found: $exePath"
}

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    if ($existing.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 1
}

sc.exe create $serviceName binPath= "\"$exePath\"" start= auto DisplayName= "RDP Security Service" | Out-Null
Start-Sleep -Seconds 1
Start-Service -Name $serviceName
Start-Sleep -Seconds 2

Get-Service -Name $serviceName | Select-Object Name, Status, StartType
