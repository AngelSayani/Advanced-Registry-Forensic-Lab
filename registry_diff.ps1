# registry_diff.ps1
# Registry Forensics Lab: Tracking the Dark Kittens
# This script compares registry states to identify changes

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Registry Forensics Lab: Tracking the Dark Kittens" -ForegroundColor Cyan
Write-Host "Registry Difference Analyzer" -ForegroundColor Cyan
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
    Write-Host "Lab environment not found. Please run setup.ps1 first." -ForegroundColor Red
    exit
}

$labDir = "$env:USERPROFILE\Documents\RegistryForensicsLab"
$evidenceDir = "$labDir\Evidence"
$baselinePath = "HKCU:\Software\DarkKittensLab\Baseline"
$workspacePath = "HKCU:\Software\DarkKittensLab\Workspace"

function Take-RegistrySnapshot {
    param (
        [string]$KeyPath,
        [string]$SnapshotName
    )
    
    if (-not $KeyPath) {
        $KeyPath = Read-Host "Enter registry key path to snapshot"
    }
    
    if (-not (Test-Path $KeyPath)) {
        Write-Host "Registry key not found: $KeyPath" -ForegroundColor Red
        return
    }
    
    if (-not $SnapshotName) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $SnapshotName = "Snapshot_$timestamp"
    }
    
    $snapshotPath = "$workspacePath\Snapshots\$SnapshotName"
    
    # Create snapshot directory in registry
    if (-not (Test-Path "$workspacePath\Snapshots")) {
        New-Item -Path "$workspacePath\Snapshots" -Force | Out-Null
    }
    
    if (Test-Path $snapshotPath) {
        $overwrite = Read-Host "Snapshot '$SnapshotName' already exists. Overwrite? (Y/N)"
        if ($overwrite -ne "Y") {
            Write-Host "Snapshot operation cancelled." -ForegroundColor Yellow
            return
        }
        Remove-Item -Path $snapshotPath -Recurse -Force
    }
    
    New-Item -Path $snapshotPath -Force | Out-Null
    
    # Store snapshot metadata
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    New-ItemProperty -Path $snapshotPath -Name "SourcePath" -Value $KeyPath -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $snapshotPath -Name "CreationTime" -Value $timestamp -PropertyType String -Force | Out-Null
    
    # Export the registry key to a file
    $regFile = "$evidenceDir\${SnapshotName}.reg"
    $standardKeyPath = $KeyPath.Replace("HKCU:", "HKEY_CURRENT_USER").Replace("HKLM:", "HKEY_LOCAL_MACHINE")
    
    Start-Process -FilePath "reg.exe" -ArgumentList "export", "`"$standardKeyPath`"", "`"$regFile`"", "/y" -NoNewWindow -Wait -PassThru | Out-Null
    
    # Store file path in snapshot metadata
    New-ItemProperty -Path $snapshotPath -Name "RegFilePath" -Value $regFile -PropertyType String -Force | Out-Null
    
    Write-Host "Registry snapshot '$SnapshotName' created successfully." -ForegroundColor Green
    Write-Host "Source: $KeyPath" -ForegroundColor Green
    Write-Host "Exported to: $regFile" -ForegroundColor Green
    
    return $SnapshotName
}

function Compare-RegistrySnapshots {
    param (
        [string]$Snapshot1,
        [string]$Snapshot2
    )
    
    $snapshotsPath = "$workspacePath\Snapshots"
    
    if (-not (Test-Path $snapshotsPath)) {
        Write-Host "No snapshots found. Please create snapshots first." -ForegroundColor Red
        return
    }
    
    # List available snapshots if none specified
    $availableSnapshots = (Get-ChildItem -Path $snapshotsPath).PSChildName
    
    if ($availableSnapshots.Count -eq 0) {
        Write-Host "No snapshots found. Please create snapshots first." -ForegroundColor Red
        return
    }
    
    if (-not $Snapshot1) {
        Write-Host "Available snapshots:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $availableSnapshots.Count; $i++) {
            Write-Host "  $($i+1): $($availableSnapshots[$i])" -ForegroundColor White
        }
        
        $selection1 = Read-Host "Select first snapshot (number)"
        if (-not [int]::TryParse($selection1, [ref]$null) -or [int]$selection1 -lt 1 -or [int]$selection1 -gt $availableSnapshots.Count) {
            Write-Host "Invalid selection." -ForegroundColor Red
            return
        }
        $Snapshot1 = $availableSnapshots[[int]$selection1 - 1]
    }
    
    if (-not $Snapshot2) {
        Write-Host "Available snapshots (excluding $Snapshot1):" -ForegroundColor Yellow
        $remainingSnapshots = $availableSnapshots | Where-Object { $_ -ne $Snapshot1 }
        
        if ($remainingSnapshots.Count -eq 0) {
            Write-Host "No other snapshots available. Please create another snapshot." -ForegroundColor Red
            return
        }
        
        for ($i = 0; $i -lt $remainingSnapshots.Count; $i++) {
            Write-Host "  $($i+1): $($remainingSnapshots[$i])" -ForegroundColor White
        }
        
        $selection2 = Read-Host "Select second snapshot (number)"
        if (-not [int]::TryParse($selection2, [ref]$null) -or [int]$selection2 -lt 1 -or [int]$selection2 -gt $remainingSnapshots.Count) {
            Write-Host "Invalid selection." -ForegroundColor Red
            return
        }
        $Snapshot2 = $remainingSnapshots[[int]$selection2 - 1]
    }
    
    $snapshot1Path = "$snapshotsPath\$Snapshot1"
    $snapshot2Path = "$snapshotsPath\$Snapshot2"
    
    if (-not (Test-Path $snapshot1Path) -or -not (Test-Path $snapshot2Path)) {
        Write-Host "One or both snapshots not found." -ForegroundColor Red
        return
    }
    
    # Get source paths from snapshots
    $sourcePath1 = (Get-ItemProperty -Path $snapshot1Path).SourcePath
    $sourcePath2 = (Get-ItemProperty -Path $snapshot2Path).SourcePath
    
    # Get registry files
    $regFile1 = (Get-ItemProperty -Path $snapshot1Path).RegFilePath
    $regFile2 = (Get-ItemProperty -Path $snapshot2Path).RegFilePath
    
    if (-not (Test-Path $regFile1) -or -not (Test-Path $regFile2)) {
        Write-Host "Registry export files not found." -ForegroundColor Red
        return
    }
    
    # Get creation times
    $creationTime1 = (Get-ItemProperty -Path $snapshot1Path).CreationTime
    $creationTime2 = (Get-ItemProperty -Path $snapshot2Path).CreationTime
    
    Write-Host "Comparing snapshots..." -ForegroundColor Yellow
    Write-Host "Snapshot 1: $Snapshot1, Created: $creationTime1" -ForegroundColor White
    Write-Host "Snapshot 2: $Snapshot2, Created: $creationTime2" -ForegroundColor White
    Write-Host ""
    
    # Read the registry files
    $regContent1 = Get-Content -Path $regFile1 -Encoding Unicode
    $regContent2 = Get-Content -Path $regFile2 -Encoding Unicode
    
    # Compare the files
    $comparison = Compare-Object -ReferenceObject $regContent1 -DifferenceObject $regContent2
    
    # Filter out header differences
    $filteredComparison = $comparison | Where-Object { 
        $_.InputObject -notmatch "Windows Registry Editor" -and
        $_.InputObject -notmatch "^;.*$"
    }
    
    if ($filteredComparison.Count -eq 0) {
        Write-Host "No differences found between the snapshots." -ForegroundColor Green
        return
    }
    
    Write-Host "Differences found:" -ForegroundColor Yellow
    
    # Process in order to show keys and values in a more organized way
    $currentKey = ""
    $addedLines = $filteredComparison | Where-Object { $_.SideIndicator -eq "=>" } | ForEach-Object { $_.InputObject }
    $removedLines = $filteredComparison | Where-Object { $_.SideIndicator -eq "<=" } | ForEach-Object { $_.InputObject }
    
    # Create output comparison file
    $comparisonFile = "$evidenceDir\Comparison_${Snapshot1}_vs_${Snapshot2}.txt"
    
    "Comparison of Registry Snapshots" | Out-File -FilePath $comparisonFile -Force
    "------------------------------" | Out-File -FilePath $comparisonFile -Append
    "Snapshot 1: $Snapshot1, Created: $creationTime1" | Out-File -FilePath $comparisonFile -Append
    "Source: $sourcePath1" | Out-File -FilePath $comparisonFile -Append
    "Snapshot 2: $Snapshot2, Created: $creationTime2" | Out-File -FilePath $comparisonFile -Append
    "Source: $sourcePath2" | Out-File -FilePath $comparisonFile -Append
    "------------------------------" | Out-File -FilePath $comparisonFile -Append
    "" | Out-File -FilePath $comparisonFile -Append
    
    # Display added content (in Snapshot 2 but not in Snapshot 1)
    if ($addedLines.Count -gt 0) {
        Write-Host "ADDED in $Snapshot2 (not in $Snapshot1):" -ForegroundColor Green
        "ADDED in $Snapshot2 (not in $Snapshot1):" | Out-File -FilePath $comparisonFile -Append
        
        foreach ($line in $addedLines) {
            if ($line -match "^\[(.+)\]$") {
                $currentKey = $Matches[1]
                Write-Host "  Key: $currentKey" -ForegroundColor Cyan
                "  Key: $currentKey" | Out-File -FilePath $comparisonFile -Append
            } elseif ($line -match '^"(.+)"=(.*)$') {
                $valueName = $Matches[1]
                $valueData = $Matches[2]
                Write-Host "    Value: $valueName = $valueData" -ForegroundColor White
                "    Value: $valueName = $valueData" | Out-File -FilePath $comparisonFile -Append
            } else {
                Write-Host "    $line" -ForegroundColor White
                "    $line" | Out-File -FilePath $comparisonFile -Append
            }
        }
        Write-Host ""
        "" | Out-File -FilePath $comparisonFile -Append
    }
    
    # Display removed content (in Snapshot 1 but not in Snapshot 2)
    if ($removedLines.Count -gt 0) {
        Write-Host "REMOVED in $Snapshot2 (present in $Snapshot1):" -ForegroundColor Red
        "REMOVED in $Snapshot2 (present in $Snapshot1):" | Out-File -FilePath $comparisonFile -Append
        
        foreach ($line in $removedLines) {
            if ($line -match "^\[(.+)\]$") {
                $currentKey = $Matches[1]
                Write-Host "  Key: $currentKey" -ForegroundColor Cyan
                "  Key: $currentKey" | Out-File -FilePath $comparisonFile -Append
            } elseif ($line -match '^"(.+)"=(.*)$') {
                $valueName = $Matches[1]
                $valueData = $Matches[2]
                Write-Host "    Value: $valueName = $valueData" -ForegroundColor White
                "    Value: $valueName = $valueData" | Out-File -FilePath $comparisonFile -Append
            } else {
                Write-Host "    $line" -ForegroundColor White
                "    $line" | Out-File -FilePath $comparisonFile -Append
            }
        }
    }
    
    Write-Host ""
    Write-Host "Comparison saved to: $comparisonFile" -ForegroundColor Green
}

function Compare-LiveRegistry {
    param (
        [string]$BaseKeyPath,
        [string]$CompareKeyPath
    )
    
    if (-not $BaseKeyPath) {
        $BaseKeyPath = Read-Host "Enter base registry key path"
    }
    
    if (-not (Test-Path $BaseKeyPath)) {
        Write-Host "Base registry key not found: $BaseKeyPath" -ForegroundColor Red
        return
    }
    
    if (-not $CompareKeyPath) {
        $CompareKeyPath = Read-Host "Enter registry key path to compare"
    }
    
    if (-not (Test-Path $CompareKeyPath)) {
        Write-Host "Compare registry key not found: $CompareKeyPath" -ForegroundColor Red
        return
    }
    
    Write-Host "Comparing live registry keys..." -ForegroundColor Yellow
    Write-Host "Base: $BaseKeyPath" -ForegroundColor White
    Write-Host "Compare: $CompareKeyPath" -ForegroundColor White
    Write-Host ""
    
    # Create temporary snapshots
    $baseSnapshot = Take-RegistrySnapshot -KeyPath $BaseKeyPath -SnapshotName "TempBase"
    $compareSnapshot = Take-RegistrySnapshot -KeyPath $CompareKeyPath -SnapshotName "TempCompare"
    
    # Compare the snapshots
    Compare-RegistrySnapshots -Snapshot1 $baseSnapshot -Snapshot2 $compareSnapshot
    
    # Clean up temporary snapshots
    Remove-Item -Path "$workspacePath\Snapshots\$baseSnapshot" -Recurse -Force
    Remove-Item -Path "$workspacePath\Snapshots\$compareSnapshot" -Recurse -Force
    
    # Clean up temporary files
    Remove-Item -Path "$evidenceDir\$baseSnapshot.reg" -Force
    Remove-Item -Path "$evidenceDir\$compareSnapshot.reg" -Force
}

function Export-StructureToCSV {
    param (
        [string]$KeyPath,
        [string]$OutputFile
    )
    
    if (-not $KeyPath) {
        $KeyPath = Read-Host "Enter registry key path to export structure"
    }
    
    if (-not (Test-Path $KeyPath)) {
        Write-Host "Registry key not found: $KeyPath" -ForegroundColor Red
        return
    }
    
    if (-not $OutputFile) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $keyName = Split-Path -Leaf $KeyPath
        $OutputFile = "$evidenceDir\${keyName}_structure_$timestamp.csv"
    } elseif (-not $OutputFile.EndsWith(".csv")) {
        $OutputFile = "$OutputFile.csv"
    }
    
    if (-not $OutputFile.StartsWith($evidenceDir)) {
        $OutputFile = "$evidenceDir\$(Split-Path -Leaf $OutputFile)"
    }
    
    Write-Host "Exporting registry structure to CSV..." -ForegroundColor Yellow
    
    $results = @()
    
    function Process-RegistryKey {
        param (
            [string]$Path,
            [int]$Depth = 0
        )
        
        # Process the key itself
        $key = Get-Item -Path $Path -ErrorAction SilentlyContinue
        
        if ($key) {
            # Add key entry
            $keyItem = [PSCustomObject]@{
                Path = $Path
                Type = "Key"
                Name = Split-Path -Leaf $Path
                Value = ""
                Depth = $Depth
                ParentPath = Split-Path -Parent $Path
            }
            $results += $keyItem
            
            # Process values
            foreach ($propName in $key.Property) {
                $value = $key.GetValue($propName)
                $type = $key.GetValueKind($propName)
                
                # Format value based on type
                $formattedValue = ""
                if ($type -eq "Binary") {
                    $formattedValue = ($value | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
                } elseif ($type -eq "MultiString") {
                    $formattedValue = $value -join "|"
                } else {
                    $formattedValue = $value.ToString()
                }
                
                $valueItem = [PSCustomObject]@{
                    Path = $Path
                    Type = "Value ($type)"
                    Name = $propName
                    Value = $formattedValue
                    Depth = $Depth + 1
                    ParentPath = $Path
                }
                $results += $valueItem
            }
            
            # Process subkeys
            Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {
                Process-RegistryKey -Path $_.PSPath -Depth ($Depth + 1)
            }
        }
    }
    
    Process-RegistryKey -Path $KeyPath
    
    # Export to CSV
    $results | Export-Csv -Path $OutputFile -NoTypeInformation
    
    Write-Host "Registry structure exported to: $OutputFile" -ForegroundColor Green
}

# Main menu
function Show-Menu {
    Write-Host "Registry Difference Analyzer Menu:" -ForegroundColor Yellow
    Write-Host "1: Take Registry Snapshot" -ForegroundColor Green
    Write-Host "2: Compare Registry Snapshots" -ForegroundColor Green
    Write-Host "3: Compare Live Registry Keys" -ForegroundColor Green
    Write-Host "4: Export Registry Structure to CSV" -ForegroundColor Green
    Write-Host "5: Exit" -ForegroundColor Green
    Write-Host ""
}

$running = $true
while ($running) {
    Show-Menu
    $choice = Read-Host "Enter your choice (1-5)"
    
    switch ($choice) {
        "1" { 
            $keyPath = Read-Host "Enter registry key path to snapshot"
            $snapshotName = Read-Host "Enter snapshot name (press Enter for auto-generated name)"
            Take-RegistrySnapshot -KeyPath $keyPath -SnapshotName $snapshotName 
        }
        "2" { 
            Compare-RegistrySnapshots 
        }
        "3" { 
            $baseKeyPath = Read-Host "Enter base registry key path"
            $compareKeyPath = Read-Host "Enter registry key path to compare"
            Compare-LiveRegistry -BaseKeyPath $baseKeyPath -CompareKeyPath $compareKeyPath 
        }
        "4" { 
            $keyPath = Read-Host "Enter registry key path to export structure"
            $outputFile = Read-Host "Enter output CSV file name (press Enter for auto-generated name)"
            Export-StructureToCSV -KeyPath $keyPath -OutputFile $outputFile 
        }
        "5" { 
            $running = $false
            Write-Host "Exiting Registry Difference Analyzer." -ForegroundColor Cyan
        }
        default { Write-Host "Invalid choice. Please enter a number between 1 and 5." -ForegroundColor Red }
    }
    
    if ($running) {
        Write-Host ""
        Write-Host "Press Enter to continue..." -ForegroundColor Yellow
        Read-Host | Out-Null
        
        Clear-Host
        Write-Host "========================================================" -ForegroundColor Cyan
        Write-Host "Registry Forensics Lab: Tracking the Dark Kittens" -ForegroundColor Cyan
        Write-Host "Registry Difference Analyzer" -ForegroundColor Cyan
        Write-Host "========================================================" -ForegroundColor Cyan
        Write-Host ""
    }
}
