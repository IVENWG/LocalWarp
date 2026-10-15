# ==============================================================================
# LocalWarp Connector: Windows Uninstaller
# Usage: powershell -ExecutionPolicy Bypass -c "irm https://localwarp.com/uninstall.ps1 | iex"
# ==============================================================================

$ErrorActionPreference = "Continue"
$InstallDir = "$env:LOCALAPPDATA\LocalWarp"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "    LocalWarp Connector Uninstall (Windows)       " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Stop running connector processes
$ExistingProc = Get-Process -Name "LocalWarp-Connector*" -ErrorAction SilentlyContinue
if ($ExistingProc) {
    Stop-Process -InputObject $ExistingProc -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Stopped running connector process." -ForegroundColor Green
}

# 2. Remove Startup shortcut
$ShortcutPath = "$([Environment]::GetFolderPath('Startup'))\LocalWarp-Connector.lnk"
if (Test-Path $ShortcutPath) {
    Remove-Item $ShortcutPath -Force
    Write-Host "[+] Removed Startup auto-start shortcut." -ForegroundColor Green
}

# 3. Remove install directory (binary lives there)
if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "[+] Removed $InstallDir" -ForegroundColor Green
}

Write-Host ""
Write-Host "Done. Your iPhone pairing records and iTunes are NOT affected." -ForegroundColor Green
