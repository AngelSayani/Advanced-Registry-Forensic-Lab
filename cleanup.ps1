# cleanup.ps1
# Registry Forensics Lab: Tracking the Dark Kittens
# This script safely removes all test registry keys and restores the system to its original state

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Registry Forensics Lab: Tracking the Dark Kittens" -ForegroundColor Cyan
Write-Host "Cleanup Script" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# Verify PowerShell running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Please restart PowerShell as Administrator." -ForegroundColor Red
    exit
}

# Check if lab environment is set up
if (-not (Test-Path "HKCU:\Software\DarkKittensLab")) {
    Write-Host "Lab environment not found. Nothing to clean up." -ForegroundColor Yellow
    exit
}

$labRegistryPath = "HKCU:\Software\DarkKittensLab"
$labDir = "$env:USERPROFILE\Documents\RegistryForensicsLab"
$evidenceDir = "$labDir\Evidence"
$reportsDir = "$labDir\Reports"

Write-Host "This script will clean up all lab-related registry keys and files." -ForegroundColor Yellow
Write-Host "Your evidence files and reports will NOT be deleted." -ForegroundColor Yellow
Write-Host ""
$confirmation = Read-Host "Are you sure you want to clean up? (Y/N)"

if ($confirmation -ne "Y") {
    Write-Host "Cleanup cancelled." -ForegroundColor Yellow
    exit
}

# Remove registry keys
Write-Host "Removing registry keys..." -ForegroundColor Yellow
try {
    Remove-Item -Path $labRegistryPath -Recurse -Force -ErrorAction Stop
    Write-Host "Registry keys successfully removed." -ForegroundColor Green
} catch {
    Write-Host "Error removing registry keys: $_" -ForegroundColor Red
}

# Confirm cleanup
Write-Host ""
Write-Host "Lab cleanup completed successfully." -ForegroundColor Green
Write-Host "Your evidence files and reports are still available at:" -ForegroundColor Green
Write-Host "  Evidence: $evidenceDir" -ForegroundColor White
Write-Host "  Reports: $reportsDir" -ForegroundColor White
Write-Host ""
Write-Host "To completely remove all lab files, delete the following directory:" -ForegroundColor Yellow
Write-Host "  $labDir" -ForegroundColor White
Write-Host ""
Write-Host "Thank you for using the Registry Forensics Lab!" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
