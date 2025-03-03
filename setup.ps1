# setup_fixed.ps1 - Streamlined version that will definitely exit properly

# Display header
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Registry Forensics Lab: Tracking the Dark Kittens" -ForegroundColor Cyan
Write-Host "Advanced Technical Lab by Angel Sayani" -ForegroundColor Cyan
Write-Host "Setup " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# Create all necessary registry keys
$paths = @(
    "HKCU:\Software\DarkKittensLab",
    "HKCU:\Software\DarkKittensLab\Baseline",
    "HKCU:\Software\DarkKittensLab\Artifacts",
    "HKCU:\Software\DarkKittensLab\Workspace",
    "HKCU:\Software\DarkKittensLab\Evidence",
    "HKCU:\Software\DarkKittensLab\Configuration"
)

foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
        Write-Host "Created registry key: $path" -ForegroundColor Green
    } else {
        Write-Host "Registry key already exists: $path" -ForegroundColor Yellow
    }
}

# Configure registry settings
$configPath = "HKCU:\Software\DarkKittensLab\Configuration"
Set-ItemProperty -Path $configPath -Name "SuspiciousPathThreshold" -Value 5 -Type DWORD -Force
Set-ItemProperty -Path $configPath -Name "DetectionSensitivity" -Value "Medium" -Type String -Force
Set-ItemProperty -Path $configPath -Name "EnableAdvancedDetection" -Value 1 -Type DWORD -Force

# Create necessary directories
$labDir = "$env:USERPROFILE\Documents\RegistryForensicsLab"
$dirs = @(
    $labDir,
    "$labDir\Evidence",
    "$labDir\Reports",
    "$labDir\Registry-based",
    "$labDir\File-based",
    "$labDir\WMI-based"
)

foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        Write-Host "Created directory: $dir" -ForegroundColor Green
    } else {
        Write-Host "Directory already exists: $dir" -ForegroundColor Yellow
    }
}

# Create terraform directory if needed
$terraformDir = ".\terraform"
if (-not (Test-Path $terraformDir)) {
    New-Item -Path $terraformDir -ItemType Directory -Force | Out-Null
    Write-Host "Created terraform directory" -ForegroundColor Green
}

# Set timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Set-ItemProperty -Path "HKCU:\Software\DarkKittensLab" -Name "LabSetupTime" -Value $timestamp -Type String -Force

# Final message
Write-Host ""
Write-Host "Lab environment setup complete at $timestamp" -ForegroundColor Green
Write-Host "You can now proceed with the lab by running 'create_artifacts.ps1'" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan