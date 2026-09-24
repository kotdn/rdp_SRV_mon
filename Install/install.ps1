param(
    [string]$InstallRoot = "C:\Program Files\RDPSecurityService",
    [switch]$StartMonitor = $false,
    [switch]$SkipGeoCheck = $false,
    [string]$MessagesConfigPath
)

$ErrorActionPreference = "Stop"

# Text shown on the two install "pages" (welcome banner, then the geo-IP result) comes from
# install.config.json next to this script, so it can be edited without touching install.ps1.
# Defaults below are used for any key missing from that file (or if it's absent entirely).
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $MessagesConfigPath) {
    $MessagesConfigPath = Join-Path $scriptRoot "install.config.json"
}

$installMessages = [PSCustomObject]@{
    welcome    = "Ласкаво просимо до встановлення RDP Security Suite!"
    secondPage = [PSCustomObject]@{
        ua    = "Слава Україні!"
        other = "WELCOME TO UKRAINE!"
    }
}

if (Test-Path $MessagesConfigPath) {
    try {
        $loaded = Get-Content -LiteralPath $MessagesConfigPath -Raw | ConvertFrom-Json
        if ($loaded.welcome) { $installMessages.welcome = [string]$loaded.welcome }
        if ($loaded.secondPage) {
            if ($loaded.secondPage.ua) { $installMessages.secondPage.ua = [string]$loaded.secondPage.ua }
            if ($loaded.secondPage.other) { $installMessages.secondPage.other = [string]$loaded.secondPage.other }
        }
    } catch {
        Write-Warning "Failed to read ${MessagesConfigPath}: $($_.Exception.Message). Using default messages."
    }
}

# --- Page 1: welcome ---
Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host $installMessages.welcome -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

function Test-InstallCountry {
    try {
        $geo = Invoke-RestMethod -Uri "http://ip-api.com/json/?fields=countryCode" -TimeoutSec 5
        return $geo.countryCode
    } catch {
        return $null
    }
}

# --- Page 2: geo-IP check ---
if (-not $SkipGeoCheck) {
    $countryCode = Test-InstallCountry
    if ($countryCode -eq "UA") {
        Write-Host $installMessages.secondPage.ua -ForegroundColor Yellow
    } elseif ($null -eq $countryCode) {
        Write-Warning "Could not determine install location (no internet access or geo-IP lookup failed). Continuing anyway. Use -SkipGeoCheck to silence this check entirely."
    } else {
        $blockedMessage = $installMessages.secondPage.other -f $countryCode
        Write-Host $blockedMessage -ForegroundColor Red
        exit 1
    }
}

function Write-Step([string]$msg) {
    Write-Host "[INFO] $msg" -ForegroundColor Cyan
}

function Write-Ok([string]$msg) {
    Write-Host "[OK] $msg" -ForegroundColor Green
}

function Write-Warn([string]$msg) {
    Write-Host "[WARN] $msg" -ForegroundColor Yellow
}

function New-ShortcutFile([string]$ShortcutPath, [string]$TargetPath, [string]$WorkingDirectory, [string]$Description) {
    $shortcutDir = Split-Path -Parent $ShortcutPath
    if (-not (Test-Path $shortcutDir)) {
        New-Item -Path $shortcutDir -ItemType Directory -Force | Out-Null
    }

    $wsh = New-Object -ComObject WScript.Shell
    $shortcut = $wsh.CreateShortcut($ShortcutPath)
    $shortcut.TargetPath = $TargetPath
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.Description = $Description
    $shortcut.IconLocation = "$TargetPath,0"
    $shortcut.Save()
}

function Ensure-MonitorShortcuts([string]$InstallRootPath) {
    $monitorExe = Join-Path $InstallRootPath "RDPMonitor.exe"
    if (-not (Test-Path $monitorExe)) {
        Write-Warn "RDPMonitor.exe not found. Shortcuts were not created."
        return
    }

    $publicDesktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonDesktopDirectory)
    $programsFolder = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)
    $startMenuDir = Join-Path $programsFolder "RDPSecurityService"

    try {
        $desktopShortcut = Join-Path $publicDesktop "RDP Monitor.lnk"
        New-ShortcutFile -ShortcutPath $desktopShortcut -TargetPath $monitorExe -WorkingDirectory $InstallRootPath -Description "RDP Security Monitor"
        Write-Ok "Desktop shortcut created: $desktopShortcut"
    } catch {
        Write-Warn "Failed to create desktop shortcut: $($_.Exception.Message)"
    }

    try {
        $menuShortcut = Join-Path $startMenuDir "RDP Monitor.lnk"
        New-ShortcutFile -ShortcutPath $menuShortcut -TargetPath $monitorExe -WorkingDirectory $InstallRootPath -Description "RDP Security Monitor"
        Write-Ok "Start menu shortcut created: $menuShortcut"
    } catch {
        Write-Warn "Failed to create start menu shortcut: $($_.Exception.Message)"
    }
}

function Stop-ProcessIfRunning([string]$name) {
    try {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($procs) {
            $procs | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-Step "Stopped process: $name"
        }
    } catch {
        Write-Warn "Failed to stop process '$name': $($_.Exception.Message)"
    }
}

function Remove-DirectoryRobust([string]$path) {
    if (-not (Test-Path $path)) {
        return
    }

    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            if (-not (Test-Path $path)) {
                return
            }
        } catch {
            Write-Warn "Remove attempt ${attempt} failed: $($_.Exception.Message)"

            try { takeown.exe /F $path /R /D Y | Out-Null } catch {}
            try { icacls.exe $path /grant "Administrators:(OI)(CI)F" /T /C | Out-Null } catch {}

            Start-Sleep -Seconds 1
        }
    }

    if (Test-Path $path) {
        throw "Failed to remove install root after retries: $path"
    }
}

function Show-ServiceStartupDiagnostics([string]$name) {
    Write-Warn "Collecting startup diagnostics for service '$name'..."

    try {
        Write-Host "[DIAG] sc query $name"
        sc.exe query $name | Out-Host
    } catch {
        Write-Warn "Failed to query service state: $($_.Exception.Message)"
    }

    $serviceLogPath = "C:\ProgramData\RDPSecurityService\service.log"
    if (Test-Path $serviceLogPath) {
        try {
            Write-Host "[DIAG] Last 80 lines of service.log ($serviceLogPath)"
            Get-Content -LiteralPath $serviceLogPath -Tail 80 | Out-Host
        } catch {
            Write-Warn "Failed to read service.log: $($_.Exception.Message)"
        }
    } else {
        Write-Warn "service.log not found at $serviceLogPath"
    }
}

function Assert-RequiredServiceFiles([string]$root) {
    $required = @(
        "WinService.exe",
        "WinService.deps.json",
        "WinService.runtimeconfig.json",
        "System.Diagnostics.EventLog.dll",
        "System.ServiceProcess.ServiceController.dll"
    )

    foreach ($file in $required) {
        $path = Join-Path $root $file
        if (-not (Test-Path $path)) {
            throw "Required file missing after extraction: $path"
        }
    }

    Write-Ok "Required service files are present."
}

function Ensure-ServiceRuntimeLayout([string]$root) {
    $runtimeDir = Join-Path $root "runtimes\win\lib\net8.0"
    New-Item -Path $runtimeDir -ItemType Directory -Force | Out-Null

    $files = @(
        "System.Diagnostics.EventLog.dll",
        "System.Diagnostics.EventLog.Messages.dll",
        "System.ServiceProcess.ServiceController.dll"
    )

    foreach ($file in $files) {
        $source = Join-Path $root $file
        if (-not (Test-Path $source)) {
            continue
        }

        $dest = Join-Path $runtimeDir $file
        try {
            Copy-Item -LiteralPath $source -Destination $dest -Force -ErrorAction Stop
        } catch {
            Write-Warn "Failed to prepare runtime layout for '$file': $($_.Exception.Message)"
        }
    }

    Write-Ok "Service runtime layout prepared."
}

function Get-ServiceBinaryPath([string]$name) {
    try {
        $qc = sc.exe qc $name | Out-String
        $match = [regex]::Match($qc, 'BINARY_PATH_NAME\s*:\s*(.+)')
        if (-not $match.Success) { return "" }

        $raw = $match.Groups[1].Value.Trim()
        if ($raw.StartsWith('"')) {
            $quoted = [regex]::Match($raw, '^"([^"]+)"')
            if ($quoted.Success) { return $quoted.Groups[1].Value }
        }

        return ($raw -split '\s+')[0].Trim('"')
    } catch {
        return ""
    }
}

function Get-ServiceProcessId([string]$name) {
    try {
        $query = sc.exe queryex $name | Out-String
        $match = [regex]::Match($query, 'PID\s*:\s*(\d+)')
        if (-not $match.Success) { return 0 }
        return [int]$match.Groups[1].Value
    } catch {
        return 0
    }
}

function Remove-ServiceWithRetries([string]$name, [int]$maxAttempts = 6) {
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Ok "Service '$name' is removed."
            return $true
        }

        Write-Warn "Service '$name' still exists (status: $($svc.Status)). Force cleanup attempt ${attempt}/${maxAttempts}."

        try { sc.exe stop $name | Out-Null } catch {}
        try {
            $svcPid = Get-ServiceProcessId -name $name
            if ($svcPid -gt 0) { taskkill.exe /F /PID $svcPid /T | Out-Null }
        } catch {}
        try { taskkill.exe /F /IM WinService.exe /T | Out-Null } catch {}

        if ($attempt -ge 3) {
            try { Stop-ProcessIfRunning -name "mmc" } catch {}
        }

        try { sc.exe delete $name | Out-Null } catch {}
        Start-Sleep -Seconds 2
    }

    return $false
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
}

$packageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$serviceName = "RDPSecurityService"
$serviceExeTarget = Join-Path $InstallRoot "WinService.exe"

$winServiceZip = Join-Path $packageRoot "WinService.zip"
$monitorZip = Join-Path $packageRoot "RDPMonitor.zip"
if (-not (Test-Path $winServiceZip)) { throw "WinService.zip not found next to install.ps1: $winServiceZip" }
if (-not (Test-Path $monitorZip)) { throw "RDPMonitor.zip not found next to install.ps1: $monitorZip" }

Write-Step "Package root: $packageRoot"
Write-Step "Target root: $InstallRoot"

# 1) Stop and uninstall existing service
Write-Step "Checking existing service state..."
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Warn "Found existing service '$serviceName' (status: $($existingService.Status)). Cleanup will be performed."

    Write-Step "Stopping existing service..."
    try {
        if ($existingService.Status -ne 'Stopped') { sc.exe stop $serviceName | Out-Null }
    } catch {
        Write-Warn "Failed to stop service via sc.exe (ignored)."
    }
    Start-Sleep -Seconds 2

    Write-Step "Deleting existing service registration..."
    try { sc.exe delete $serviceName | Out-Null } catch { Write-Warn "Service delete failed (ignored)." }

    if (-not (Remove-ServiceWithRetries -name $serviceName -maxAttempts 6)) {
        throw "Failed to remove existing service '$serviceName' after force retries."
    }
} else {
    Write-Step "Existing service not found. Proceeding with clean install."
}

Stop-ProcessIfRunning -name "WinService"
Stop-ProcessIfRunning -name "RDPMonitor"

# 2) Remove existing install root completely (firewall rules and ProgramData state are untouched)
if (Test-Path $InstallRoot) {
    Write-Step "Removing existing install root..."
    Remove-DirectoryRobust -path $InstallRoot
    Write-Ok "Old install root removed."
}

# 3) Extract packages into target
Write-Step "Creating clean install root..."
New-Item -Path $InstallRoot -ItemType Directory -Force | Out-Null

Write-Step "Extracting WinService.zip..."
Expand-Archive -LiteralPath $winServiceZip -DestinationPath $InstallRoot -Force

Write-Step "Extracting RDPMonitor.zip..."
Expand-Archive -LiteralPath $monitorZip -DestinationPath $InstallRoot -Force

$exampleConfig = Join-Path $packageRoot "config.example.json"
if (Test-Path $exampleConfig) {
    Copy-Item -LiteralPath $exampleConfig -Destination (Join-Path $InstallRoot "config.example.json") -Force
}

try {
    Get-ChildItem -Path $InstallRoot -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
    Write-Ok "Extracted files were unblocked."
} catch {
    Write-Warn "Could not unblock some extracted files: $($_.Exception.Message)"
}

Write-Ok "Files extracted."
Assert-RequiredServiceFiles -root $InstallRoot
Ensure-ServiceRuntimeLayout -root $InstallRoot

# 4) Install and start service
if (-not (Test-Path $serviceExeTarget)) {
    throw "Service executable not found after extraction: $serviceExeTarget"
}

Write-Step "Installing service..."
& $serviceExeTarget install | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "WinService install command failed with exit code $LASTEXITCODE"
}

$installedService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $installedService) {
    throw "Service '$serviceName' was not created. Installation failed."
}

Write-Step "Starting service..."
sc.exe start $serviceName | Out-Host

$startedService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
for ($i = 0; $i -lt 20; $i++) {
    $startedService.Refresh()
    Write-Step "Service status check [$($i + 1)/20]: $($startedService.Status)"
    if ($startedService.Status -eq 'Running') { break }
    Start-Sleep -Seconds 1
}

if ($startedService.Status -ne 'Running') {
    Show-ServiceStartupDiagnostics -name $serviceName
    throw "Service '$serviceName' is not running after install/start. Current status: $($startedService.Status)"
}

Write-Ok "Service installed and running."

# 5) Monitor: optional immediate start (this is the "install monitor too" switch) + shortcuts
$monitorExe = Join-Path $InstallRoot "RDPMonitor.exe"
if ($StartMonitor) {
    if (Test-Path $monitorExe) {
        Write-Step "Starting monitor process..."
        Start-Process -FilePath $monitorExe -WorkingDirectory $InstallRoot | Out-Null
        Write-Ok "Monitor started."
    } else {
        Write-Warn "RDPMonitor.exe not found, monitor was not started."
    }
}

Write-Step "Creating monitor shortcuts..."
Ensure-MonitorShortcuts -InstallRootPath $InstallRoot

Write-Host ""
Write-Ok "Clean installation completed successfully."
Write-Host "Service: $serviceName"
Write-Host "Path: $InstallRoot"
Write-Host "Config/logs: C:\ProgramData\RDPSecurityService"
