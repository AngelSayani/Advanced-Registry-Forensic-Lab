

Write-Host "Starting validation..." -ForegroundColor Green

# Check lab environment
if (Test-Path "HKCU:\Software\DarkKittensLab") {
    Write-Host "Lab environment detected." -ForegroundColor Green
    
    # Check if evidence has been collected
    $evidencePath = "HKCU:\Software\DarkKittensLab\Evidence"
    $evidenceCollected = (Test-Path $evidencePath) -and ((Get-ChildItem -Path $evidencePath -ErrorAction SilentlyContinue).Count -gt 0)
    
    if ($evidenceCollected) {
        Write-Host "Evidence has been collected!" -ForegroundColor Green
        Write-Host "Great job! You've made progress in the lab." -ForegroundColor Green
    } else {
        Write-Host "No evidence collected yet." -ForegroundColor Yellow
        Write-Host "Use evidence_collector.ps1 to document your findings." -ForegroundColor Yellow
    }
} else {
    Write-Host "Lab environment not found. Run setup.ps1 first." -ForegroundColor Red
}

Write-Host "Validation completed." -ForegroundColor Green
