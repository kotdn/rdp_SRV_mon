param(
    [string]$OutputDir = "D:\realise",
    [int]$KeepCount = 3,
    [string]$Tag = "release"
)

$ErrorActionPreference = "Stop"

if ($KeepCount -lt 1) {
    throw "KeepCount must be >= 1"
}

$repoRoot = $PSScriptRoot
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$tempDir = Join-Path $env:TEMP ("rdp_release_" + $stamp)

$safeTag = ($Tag -replace "[^a-zA-Z0-9_-]", "-").Trim("-")
if ([string]::IsNullOrWhiteSpace($safeTag)) {
    $safeTag = "release"
}

$zipName = "reliz_{0}_portable_install_selfcontained_{1}.zip" -f $stamp, $safeTag
$zipPath = Join-Path $OutputDir $zipName

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    dotnet publish (Join-Path $repoRoot "WinService\WinService.csproj") -c Release -r win-x64 --self-contained true -o $tempDir -p:IncludeNativeLibrariesForSelfExtract=true --nologo
    dotnet publish (Join-Path $repoRoot "monitor\RDPMonitor.csproj") -c Release -r win-x64 --self-contained true -o $tempDir -p:IncludeNativeLibrariesForSelfExtract=true --nologo

    Copy-Item (Join-Path $repoRoot "release\RDP-Security-Suite-ZIP\install-clean.ps1") (Join-Path $tempDir "install-clean.ps1") -Force
    Copy-Item (Join-Path $repoRoot "release\RDP-Security-Suite-ZIP\install-clean.bat") (Join-Path $tempDir "install-clean.bat") -Force
    Copy-Item (Join-Path $repoRoot "WinService\config.example.json") (Join-Path $tempDir "config.example.json") -Force

    @(
        '@echo off',
        'setlocal EnableExtensions',
        '',
        'net session >nul 2>&1',
        'if not "%errorlevel%"=="0" (',
        '  echo [INFO] Requesting Administrator privileges...',
        '  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath ''%~f0'' -Verb RunAs"',
        '  exit /b',
        ')',
        '',
        'echo [INFO] Starting installation...',
        'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-clean.ps1" -StartMonitor',
        'set "RC=%errorlevel%"',
        'if not "%RC%"=="0" (',
        '  echo [ERROR] Installation failed. Exit code: %RC%',
        '  pause',
        '  exit /b %RC%',
        ')',
        '',
        'echo [OK] Installation completed successfully.',
        'pause'
    ) | Set-Content -Path (Join-Path $tempDir "VASYA-INSTALL.cmd") -Encoding Ascii

    [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

    $releaseZips = Get-ChildItem -Path $OutputDir -File -Filter "reliz_*_portable_install_selfcontained*.zip" |
        Sort-Object LastWriteTime -Descending

    $toRemove = @($releaseZips | Select-Object -Skip $KeepCount)
    foreach ($oldZip in $toRemove) {
        Remove-Item -LiteralPath $oldZip.FullName -Force
    }

    Write-Host "Created: $zipPath" -ForegroundColor Green
    Write-Host "Kept latest: $KeepCount archive(s)" -ForegroundColor Green

    Get-ChildItem -Path $OutputDir -File -Filter "reliz_*_portable_install_selfcontained*.zip" |
        Sort-Object LastWriteTime -Descending |
        Select-Object Name, Length, LastWriteTime |
        Format-Table -AutoSize
}
finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
