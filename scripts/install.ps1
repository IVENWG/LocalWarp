# ==============================================================================
# LocalWarp Connector: Windows PowerShell One-Line Installer
# Usage: powershell -ExecutionPolicy Bypass -c "irm https://localwarp.com/install.ps1 | iex"
# ==============================================================================

$ErrorActionPreference = "Stop"

# 老 Win10 的 PowerShell 5.1 默认不启用 TLS 1.2，GitHub 下载会握手失败
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$Repo = "IVENWG/LocalWarp"
$InstallDir = "$env:LOCALAPPDATA\LocalWarp"
$BinaryName = "LocalWarp-Connector-windows-x64.exe"
$TargetPath = "$InstallDir\$BinaryName"
$DownloadUrl = "https://github.com/$Repo/releases/latest/download/$BinaryName"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "    LocalWarp iPhone Location Connector (Windows)  " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Create target directory
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 2. Download executable
Write-Host "[*] Downloading standalone LocalWarp Connector for Windows x64..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TargetPath -UseBasicParsing
    Write-Host "[+] Download complete: $TargetPath" -ForegroundColor Green
} catch {
    Write-Host "[-] GitHub release download failed ($($_.Exception.Message))" -ForegroundColor Red
    Write-Host "[*] Looking for local build in current directory..." -ForegroundColor Yellow
    $LocalBuild = ".\dist\connectors\$BinaryName"
    if (Test-Path $LocalBuild) {
        Copy-Item -Path $LocalBuild -Destination $TargetPath -Force
        Write-Host "[+] Copied from local build." -ForegroundColor Green
    } else {
        Write-Host "[-] Executable not found. Please build via scripts/build_connector.py first." -ForegroundColor Red
        exit 1
    }
}

# 3. Create Startup Shortcut
$StartupFolder = [Environment]::GetFolderPath("Startup")
$ShortcutPath = "$StartupFolder\LocalWarp-Connector.lnk"
try {
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $TargetPath
    $Shortcut.WorkingDirectory = $InstallDir
    $Shortcut.WindowStyle = 7 # Minimized
    $Shortcut.Description = "LocalWarp iPhone Location Service Daemon"
    $Shortcut.Save()
    Write-Host "[+] Auto-start shortcut created in Startup folder." -ForegroundColor Green
} catch {
    Write-Host "[-] Note: Could not create startup shortcut, you can start it manually." -ForegroundColor Gray
}

# 4. Start the Connector Process
Write-Host "[*] Starting LocalWarp Connector daemon..." -ForegroundColor Yellow
$ExistingProc = Get-Process -Name "LocalWarp-Connector*" -ErrorAction SilentlyContinue
if ($ExistingProc) {
    Stop-Process -InputObject $ExistingProc -Force
}

Start-Process -FilePath $TargetPath -WindowStyle Hidden

Start-Sleep -Seconds 2

# 5. Check Health
try {
    $Health = Invoke-RestMethod -Uri "http://127.0.0.1:28888/health" -TimeoutSec 3
    if ($Health.status -eq "healthy") {
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "  LocalWarp Connector is ONLINE and ready!         " -ForegroundColor Green
        Write-Host "  Listening on: http://127.0.0.1:28888            " -ForegroundColor Green
        Write-Host "==================================================" -ForegroundColor Cyan
        Start-Process "https://localwarp.com/app"
    }
} catch {
    Write-Host "[!] Service started. Open https://localwarp.com/app to begin." -ForegroundColor Yellow
}
