#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Uninstalls the CfDnsSync Windows Service.

.DESCRIPTION
    This script:
    1. Stops and removes the Windows Service
    2. Removes the Windows Firewall rule
    3. Removes the Event Log source
    4. Optionally deletes all data files from the install directory

.PARAMETER InstallDir
    Path where CfDnsSync was installed. Default: C:\Services\CfDnsSync

.PARAMETER ServiceName
    Windows Service name. Default: CfDnsSync

.PARAMETER Port
    Dashboard port used for the Firewall rule. Default: 8765

.PARAMETER KeepData
    If specified, config.json, token, logs, and record_modes.json are preserved.
    Useful when re-installing or upgrading.

.EXAMPLE
    .\Uninstall-CfDnsSync.ps1

    # Keep config and data files (useful before upgrade)
    .\Uninstall-CfDnsSync.ps1 -KeepData

    # Custom install directory
    .\Uninstall-CfDnsSync.ps1 -InstallDir "D:\Services\CfDnsSync"
#>

param(
    [string]$InstallDir  = "C:\Services\CfDnsSync",
    [string]$ServiceName = "CfDnsSync",
    [int]   $Port        = 8765,
    [switch]$KeepData
)

$ErrorActionPreference = "SilentlyContinue"
$FirewallRule = "CfDnsSync Dashboard (TCP-$Port)"

Write-Host ""
Write-Host "================================================" -ForegroundColor Red
Write-Host "        CfDnsSync -- Service Uninstaller        " -ForegroundColor Red
Write-Host "================================================" -ForegroundColor Red
Write-Host ""

if (-not $KeepData) {
    $confirm = Read-Host "This will remove the service and ALL data files. Type YES to confirm"
    if ($confirm -ne "YES") {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
} else {
    Write-Host "  -KeepData specified: config, token, and logs will be preserved." -ForegroundColor Yellow
    Write-Host ""
}

# 1. Stop and remove service
Write-Host "[ 1/4 ] Stopping and removing service '$ServiceName'..." -ForegroundColor Yellow

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Write-Host "        Stopping service..." -ForegroundColor Gray
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
    sc.exe delete $ServiceName | Out-Null
    Write-Host "        Service removed." -ForegroundColor Green
} else {
    Write-Host "        Service '$ServiceName' not found -- skipping." -ForegroundColor Gray
}

# 2. Remove Firewall rule
Write-Host "[ 2/4 ] Removing Windows Firewall rule..." -ForegroundColor Yellow
$rule = Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue
if ($rule) {
    Remove-NetFirewallRule -DisplayName $FirewallRule
    Write-Host "        Firewall rule '$FirewallRule' removed." -ForegroundColor Green
} else {
    # Try wildcard in case port differs
    $rules = Get-NetFirewallRule -DisplayName "CfDnsSync*" -ErrorAction SilentlyContinue
    if ($rules) {
        $rules | Remove-NetFirewallRule
        Write-Host "        Removed $($rules.Count) CfDnsSync firewall rule(s)." -ForegroundColor Green
    } else {
        Write-Host "        No matching firewall rules found -- skipping." -ForegroundColor Gray
    }
}

# 3. Remove Event Log source
Write-Host "[ 3/4 ] Removing Event Log source..." -ForegroundColor Yellow
if ([System.Diagnostics.EventLog]::SourceExists($ServiceName)) {
    Remove-EventLog -Source $ServiceName -ErrorAction SilentlyContinue
    Write-Host "        Event Log source '$ServiceName' removed." -ForegroundColor Green
} else {
    Write-Host "        Event Log source not found -- skipping." -ForegroundColor Gray
}

# Remove custom log if it exists
$customLog = Get-WinEvent -ListLog $ServiceName -ErrorAction SilentlyContinue
if ($customLog) {
    wevtutil.exe cl $ServiceName 2>$null
    Write-Host "        Custom Event Log '$ServiceName' cleared." -ForegroundColor Gray
}

# 4. Remove files
Write-Host "[ 4/4 ] Removing files..." -ForegroundColor Yellow

if (Test-Path $InstallDir) {
    if ($KeepData) {
        # Remove only the binary, keep config/data
        $filesToRemove = @("CfDnsSync.exe")
        foreach ($f in $filesToRemove) {
            $path = Join-Path $InstallDir $f
            if (Test-Path $path) {
                Remove-Item $path -Force
                Write-Host "        Removed: $f" -ForegroundColor Gray
            }
        }
        Write-Host "        Data files preserved in: $InstallDir" -ForegroundColor Yellow
        Write-Host "        (config.json, cf_token.dat, record_modes.json, logs\)" -ForegroundColor Gray
    } else {
        # Remove entire install directory
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-Host "        Removed install directory: $InstallDir" -ForegroundColor Green
    }
} else {
    Write-Host "        Install directory not found -- skipping." -ForegroundColor Gray
}

# Done
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "          Uninstall Complete!                   " -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""

if ($KeepData) {
    Write-Host "  Data files preserved at: $InstallDir" -ForegroundColor White
    Write-Host "  To reinstall: run Install-CfDnsSync.ps1" -ForegroundColor Gray
    Write-Host "  Your config, token, and record ownership assignments are intact." -ForegroundColor Gray
}

Write-Host ""
