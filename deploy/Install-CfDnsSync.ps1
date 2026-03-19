#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs, configures and registers CfDnsSync as a Windows Service.

.DESCRIPTION
    This script:
    1. Copies service binaries to the install directory
    2. Registers the Windows Service (LocalSystem, auto-start, recovery options)
    3. Creates a custom Windows Event Log source
    4. Runs interactive configuration (Zone ID, domain, sync interval, etc.)
    5. Stores the Cloudflare API token encrypted with DPAPI (CurrentUser scope)
    6. Creates a Windows Firewall inbound Allow rule for the dashboard port
    7. Optionally starts the service

.NOTES
    Must be run as Administrator on the Domain Controller.
    Self-contained build: no .NET runtime required.

.EXAMPLE
    .\Install-CfDnsSync.ps1
    .\Install-CfDnsSync.ps1 -InstallDir "D:\Services\CfDnsSync" -Port 9000 -StartAfterInstall
#>

param(
    [string]$InstallDir   = "C:\Services\CfDnsSync",
    [string]$ServiceName  = "CfDnsSync",
    [string]$DisplayName  = "Cloudflare DNS Sync Service",
    [string]$Description  = "One-way sync of DNS records from Cloudflare to local Active Directory DNS zone.",
    [int]   $Port         = 8765,
    [switch]$StartAfterInstall
)

$ErrorActionPreference = "Stop"
$ServiceExe  = "CfDnsSync.exe"
$FirewallRule = "CfDnsSync Dashboard (TCP-$Port)"
$SourceDir   = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "        CfDnsSync -- Service Installer          " -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ?? 1. Prepare install directory ??????????????????????????????????????????????
Write-Host "[ 1/7 ] Preparing install directory: $InstallDir" -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Host "        Copying binaries..." -ForegroundColor Gray
$publishDir = Join-Path $SourceDir "publish"
if (Test-Path $publishDir) {
    Copy-Item -Path "$publishDir\*" -Destination $InstallDir -Recurse -Force
} elseif (Test-Path (Join-Path $SourceDir $ServiceExe)) {
    Copy-Item -Path "$SourceDir\$ServiceExe" -Destination $InstallDir -Force
} else {
    Write-Host "ERROR: Cannot find $ServiceExe or publish\ directory next to this script." -ForegroundColor Red
    Write-Host "       Build the project first: dotnet publish -c Release" -ForegroundColor Red
    exit 1
}

$ExePath = Join-Path $InstallDir $ServiceExe

# ?? 2. Remove existing service if present ?????????????????????????????????????
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[ 2/7 ] Removing existing service..." -ForegroundColor Yellow
    if ($existing.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
} else {
    Write-Host "[ 2/7 ] No existing service found." -ForegroundColor Gray
}

# ?? 3. Register Windows Service ???????????????????????????????????????????????
Write-Host "[ 3/7 ] Registering Windows Service '$ServiceName'..." -ForegroundColor Yellow

$scArgs = @(
    "create", $ServiceName,
    "binPath=", "`"$ExePath`"",
    "DisplayName=", "`"$DisplayName`"",
    "start=", "auto",
    "obj=", "LocalSystem"
)
$result = & sc.exe @scArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: sc.exe create failed: $result" -ForegroundColor Red
    exit 1
}

& sc.exe description $ServiceName "$Description" | Out-Null

# Recovery: restart after 1st (30s), 2nd (60s), 3rd+ (2min) failure; reset counter after 24h
& sc.exe failure $ServiceName reset= 86400 actions= restart/30000/restart/60000/restart/120000 | Out-Null

Write-Host "        Service registered successfully." -ForegroundColor Green

# ?? 4. Register Event Log source ??????????????????????????????????????????????
Write-Host "[ 4/7 ] Registering Event Log source '$ServiceName'..." -ForegroundColor Yellow
if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {
    New-EventLog -LogName "Application" -Source $ServiceName
    Write-Host "        Event Log source '$ServiceName' created." -ForegroundColor Gray
} else {
    Write-Host "        Event Log source '$ServiceName' already exists." -ForegroundColor Gray
}

# ?? 5. Interactive configuration ??????????????????????????????????????????????
Write-Host "[ 5/7 ] Running interactive configuration..." -ForegroundColor Yellow
Write-Host ""

Push-Location $InstallDir
& $ExePath setup-config
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Config setup returned non-zero exit code." -ForegroundColor Yellow
}
Pop-Location

# ?? 6. Store Cloudflare API Token ?????????????????????????????????????????????
Write-Host ""
Write-Host "[ 6/7 ] Storing Cloudflare API Token (DPAPI encrypted)..." -ForegroundColor Yellow
Write-Host "        Token is encrypted with Windows DPAPI (CurrentUser scope)." -ForegroundColor Gray
Write-Host "        Alternative: place the token in 'token.txt' in $InstallDir" -ForegroundColor Gray
Write-Host "        The service will encrypt it automatically on first start." -ForegroundColor Gray
Write-Host ""

Push-Location $InstallDir
& $ExePath setup-token
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to save token." -ForegroundColor Red
    exit 1
}
Pop-Location

# ?? 7. Windows Firewall Allow rule ????????????????????????????????????????????
Write-Host "[ 7/7 ] Configuring Windows Firewall for dashboard port $Port..." -ForegroundColor Yellow

$existingRule = Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue
if ($existingRule) {
    Remove-NetFirewallRule -DisplayName $FirewallRule
    Write-Host "        Removed existing firewall rule." -ForegroundColor Gray
}

New-NetFirewallRule `
    -DisplayName  $FirewallRule `
    -Description  "Allow inbound HTTPS access to CfDnsSync web dashboard" `
    -Direction    Inbound `
    -Protocol     TCP `
    -LocalPort    $Port `
    -Action       Allow `
    -Profile      Domain, Private `
    -Program      $ExePath `
    -Enabled      True | Out-Null

Write-Host "        Firewall rule '$FirewallRule' created (Domain + Private profiles)." -ForegroundColor Green

# ?? Done ??????????????????????????????????????????????????????????????????????
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "          Installation Complete!                " -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Install dir  : $InstallDir" -ForegroundColor White
Write-Host "  Service name : $ServiceName" -ForegroundColor White
Write-Host "  Dashboard    : https://$($env:COMPUTERNAME):$Port" -ForegroundColor White
Write-Host "  Logs         : $InstallDir\logs\" -ForegroundColor White
Write-Host ""
Write-Host "  NOTE: Service starts in DRY RUN mode by default." -ForegroundColor Yellow
Write-Host "        Review planned changes in the dashboard, then" -ForegroundColor Yellow
Write-Host "        disable Dry Run in Settings to go live." -ForegroundColor Yellow
Write-Host ""

if ($StartAfterInstall) {
    Write-Host "Starting service..." -ForegroundColor Yellow
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 3
    $svc = Get-Service -Name $ServiceName
    $color = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
    Write-Host "  Service status: $($svc.Status)" -ForegroundColor $color
} else {
    Write-Host "To start the service, run:" -ForegroundColor Gray
    Write-Host "  Start-Service -Name $ServiceName" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Or from Services Manager (services.msc)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Gray
Write-Host "  Get-Service $ServiceName                           # Check status"     -ForegroundColor DarkGray
Write-Host "  Start-Service / Stop-Service / Restart-Service    # Control service"  -ForegroundColor DarkGray
Write-Host "  cd '$InstallDir'; .\$ServiceExe sync-now          # Manual sync"      -ForegroundColor DarkGray
Write-Host "  .\Uninstall-CfDnsSync.ps1                         # Remove service"   -ForegroundColor DarkGray
Write-Host ""
