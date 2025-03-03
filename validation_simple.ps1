Write-Host "Simple validation script is working!" -ForegroundColor Green
Write-Host "This confirms the PowerShell script execution is functional." -ForegroundColor Cyan

# Check if lab environment is set up
if (Test-Path "HKCU:\Software\DarkKittensLab") {
    Write-Host "Lab environment found." -ForegroundColor Green
} else {
    Write-Host "Lab environment not found." -ForegroundColor Red
}

Write-Host "Script completed successfully." -ForegroundColor Green