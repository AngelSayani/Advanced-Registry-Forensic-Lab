# setup.ps1
# Registry Forensics Lab: Tracking the Dark Kittens
# This script sets up a safe testing environment for the lab

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Registry Forensics Lab: Tracking the Dark Kittens" -ForegroundColor Cyan
Write-Host "Setup Script" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# Verify PowerShell running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Please restart PowerShell as Administrator." -ForegroundColor Red
    exit
}

# Create safe registry test area
$labRegistryPath = "HKCU:\Software\DarkKittensLab"
$baselinePath = "HKCU:\Software\DarkKittensLab\Baseline"
$artifactsPath = "HKCU:\Software\DarkKittensLab\Artifacts"
$workspacePath = "HKCU:\Software\DarkKittensLab\Workspace"
$evidencePath = "HKCU:\Software\DarkKittensLab\Evidence"
$configPath = "HKCU:\Software\DarkKittensLab\Configuration"

# Create base registry key for lab
if (-not (Test-Path $labRegistryPath)) {
    New-Item -Path $labRegistryPath -Force | Out-Null
    Write-Host "Created lab registry key: $labRegistryPath" -ForegroundColor Green
} else {
    Write-Host "Lab registry key already exists: $labRegistryPath" -ForegroundColor Yellow
}

# Create baseline registry key
if (-not (Test-Path $baselinePath)) {
    New-Item -Path $baselinePath -Force | Out-Null
    Write-Host "Created baseline registry key: $baselinePath" -ForegroundColor Green
} else {
    Write-Host "Baseline registry key already exists: $baselinePath" -ForegroundColor Yellow
}

# Create artifacts registry key
if (-not (Test-Path $artifactsPath)) {
    New-Item -Path $artifactsPath -Force | Out-Null
    Write-Host "Created artifacts registry key: $artifactsPath" -ForegroundColor Green
} else {
    Write-Host "Artifacts registry key already exists: $artifactsPath" -ForegroundColor Yellow
}

# Create workspace registry key
if (-not (Test-Path $workspacePath)) {
    New-Item -Path $workspacePath -Force | Out-Null
    Write-Host "Created workspace registry key: $workspacePath" -ForegroundColor Green
} else {
    Write-Host "Workspace registry key already exists: $workspacePath" -ForegroundColor Yellow
}

# Create evidence registry key
if (-not (Test-Path $evidencePath)) {
    New-Item -Path $evidencePath -Force | Out-Null
    Write-Host "Created evidence registry key: $evidencePath" -ForegroundColor Green
} else {
    Write-Host "Evidence registry key already exists: $evidencePath" -ForegroundColor Yellow
}

# Create configuration registry key
if (-not (Test-Path $configPath)) {
    New-Item -Path $configPath -Force | Out-Null
    Write-Host "Created configuration registry key: $configPath" -ForegroundColor Green
    
    # Set default configuration values
    New-ItemProperty -Path $configPath -Name "SuspiciousPathThreshold" -Value 5 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $configPath -Name "DetectionSensitivity" -Value "Medium" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $configPath -Name "EnableAdvancedDetection" -Value 1 -PropertyType DWORD -Force | Out-Null
} else {
    Write-Host "Configuration registry key already exists: $configPath" -ForegroundColor Yellow
}

# Create lab directories
$labDir = "$env:USERPROFILE\Documents\RegistryForensicsLab"
$evidenceDir = "$labDir\Evidence"
$reportsDir = "$labDir\Reports"

if (-not (Test-Path $labDir)) {
    New-Item -Path $labDir -ItemType Directory -Force | Out-Null
    Write-Host "Created lab directory: $labDir" -ForegroundColor Green
} else {
    Write-Host "Lab directory already exists: $labDir" -ForegroundColor Yellow
}

if (-not (Test-Path $evidenceDir)) {
    New-Item -Path $evidenceDir -ItemType Directory -Force | Out-Null
    Write-Host "Created evidence directory: $evidenceDir" -ForegroundColor Green
} else {
    Write-Host "Evidence directory already exists: $evidenceDir" -ForegroundColor Yellow
}

if (-not (Test-Path $reportsDir)) {
    New-Item -Path $reportsDir -ItemType Directory -Force | Out-Null
    Write-Host "Created reports directory: $reportsDir" -ForegroundColor Green
} else {
    Write-Host "Reports directory already exists: $reportsDir" -ForegroundColor Yellow
}

# Create persistence category folders automatically
$registryPersistenceDir = "$labDir\Registry-based"
$filePersistenceDir = "$labDir\File-based"
$wmiPersistenceDir = "$labDir\WMI-based"

# Automatically create the required directories
if (-not (Test-Path $registryPersistenceDir)) {
    New-Item -Path $registryPersistenceDir -ItemType Directory -Force | Out-Null
    Write-Host "Created Registry-based persistence directory: $registryPersistenceDir" -ForegroundColor Green
} else {
    Write-Host "Registry-based persistence directory already exists: $registryPersistenceDir" -ForegroundColor Yellow
}

if (-not (Test-Path $filePersistenceDir)) {
    New-Item -Path $filePersistenceDir -ItemType Directory -Force | Out-Null
    Write-Host "Created File-based persistence directory: $filePersistenceDir" -ForegroundColor Green
} else {
    Write-Host "File-based persistence directory already exists: $filePersistenceDir" -ForegroundColor Yellow
}

if (-not (Test-Path $wmiPersistenceDir)) {
    New-Item -Path $wmiPersistenceDir -ItemType Directory -Force | Out-Null
    Write-Host "Created WMI-based persistence directory: $wmiPersistenceDir" -ForegroundColor Green
} else {
    Write-Host "WMI-based persistence directory already exists: $wmiPersistenceDir" -ForegroundColor Yellow
}

# Create terraform directory and files if they don't exist
$terraformDir = "$PSScriptRoot\terraform"
if (-not (Test-Path $terraformDir)) {
    New-Item -Path $terraformDir -ItemType Directory -Force | Out-Null
    Write-Host "Created terraform directory: $terraformDir" -ForegroundColor Green
}

# Save registry paths as global variables for other scripts
$Global:LabRegistryPath = $labRegistryPath
$Global:BaselinePath = $baselinePath
$Global:ArtifactsPath = $artifactsPath
$Global:WorkspacePath = $workspacePath
$Global:EvidencePath = $evidencePath
$Global:ConfigPath = $configPath
$Global:LabDir = $labDir
$Global:EvidenceDir = $evidenceDir
$Global:ReportsDir = $reportsDir

# Create a baseline export of the lab registry key
reg export "HKCU\Software\DarkKittensLab" "$evidenceDir\baseline_registry.reg" | Out-Null

# Set lab timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
New-ItemProperty -Path $labRegistryPath -Name "LabSetupTime" -Value $timestamp -PropertyType String -Force | Out-Null

Write-Host ""
Write-Host "Lab environment successfully set up at $timestamp" -ForegroundColor Green
Write-Host "Configuration summary:" -ForegroundColor Green
Write-Host "  Detection Sensitivity: Medium" -ForegroundColor White
Write-Host "  Advanced Detection: Enabled" -ForegroundColor White
Write-Host ""
Write-Host "You can now proceed with the lab by running 'create_artifacts.ps1'" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# force PowerShell to exit the script
[System.Environment]::Exit(0)