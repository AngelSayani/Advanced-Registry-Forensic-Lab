# forensic_tools.ps1
# Registry Forensics Lab: Tracking the Dark Kittens
# This script provides tools for registry analysis

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Registry Forensics Lab: Tracking the Dark Kittens" -ForegroundColor Cyan
Write-Host "Registry Forensic Tools" -ForegroundColor Cyan
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

$labRegistryPath = "HKCU:\Software\DarkKittensLab"
$artifactsPath = "HKCU:\Software\DarkKittensLab\Artifacts"
$workspacePath = "HKCU:\Software\DarkKittensLab\Workspace"
$evidencePath = "HKCU:\Software\DarkKittensLab\Evidence"

Write-Host "Registry Forensic Tools Menu:" -ForegroundColor Yellow
Write-Host "1: Examine Registry Key" -ForegroundColor Green
Write-Host "2: Search for Registry Values" -ForegroundColor Green
Write-Host "3: Decode Base64 Value" -ForegroundColor Green
Write-Host "4: Compare Registry Timestamps" -ForegroundColor Green
Write-Host "5: Extract Registry Data" -ForegroundColor Green
Write-Host "6: Save Evidence to File" -ForegroundColor Green
Write-Host "7: Registry Hive Analysis" -ForegroundColor Green
Write-Host "8: Search for Suspicious Paths" -ForegroundColor Green
Write-Host "9: Check Value Data Type" -ForegroundColor Green
Write-Host "10: Exit" -ForegroundColor Green
Write-Host ""

function Examine-RegistryKey {
    param (
        [string]$KeyPath
    )
    
    if (-not $KeyPath) {
        $KeyPath = Read-Host "Enter registry key path to examine"
    }
    
    if (-not (Test-Path $KeyPath)) {
        Write-Host "Registry key not found: $KeyPath" -ForegroundColor Red
        return
    }
    
    Write-Host "Registry Key Analysis: $KeyPath" -ForegroundColor Yellow
    Write-Host "-----------------------------------" -ForegroundColor Gray
    
    # Get key properties
    $key = Get-Item -Path $KeyPath
    $properties = $key.Property
    
    if ($properties.Count -eq 0) {
        Write-Host "This key has no values." -ForegroundColor Yellow
    } else {
        Write-Host "Values:" -ForegroundColor Cyan
        foreach ($prop in $properties) {
            $value = $key.GetValue($prop)
            $type = $key.GetValueKind($prop)
            
            # Format the output based on type
            if ($type -eq "Binary") {
                $hexValue = ($value | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
                Write-Host "  $prop = [$type] $hexValue" -ForegroundColor White
            } elseif ($type -eq "MultiString") {
                Write-Host "  $prop = [$type]" -ForegroundColor White
                foreach ($line in $value) {
                    Write-Host "    $line" -ForegroundColor White
                }
            } else {
                Write-Host "  $prop = [$type] $value" -ForegroundColor White
            }
        }
    }
    
    # Get subkeys
    $subkeys = Get-ChildItem -Path $KeyPath -ErrorAction SilentlyContinue
    
    if ($subkeys.Count -eq 0) {
        Write-Host "This key has no subkeys." -ForegroundColor Yellow
    } else {
        Write-Host "Subkeys:" -ForegroundColor Magenta
        foreach ($subkey in $subkeys) {
            Write-Host "  $($subkey.PSChildName)" -ForegroundColor White
        }
    }
    
    Write-Host "-----------------------------------" -ForegroundColor Gray
}

function Search-RegistryValues {
    param (
        [string]$SearchTerm,
        [string]$StartPath = "HKCU:\Software\DarkKittensLab"
    )
    
    if (-not $SearchTerm) {
        $SearchTerm = Read-Host "Enter search term"
    }
    
    Write-Host "Searching for: $SearchTerm under $StartPath" -ForegroundColor Yellow
    Write-Host "This may take a moment..." -ForegroundColor Yellow
    
    $results = @()
    
    function Search-KeyRecursive {
        param (
            [string]$Path
        )
        
        try {
            # Search key properties
            $key = Get-Item -Path $Path -ErrorAction SilentlyContinue
            if ($key -and $key.Property) {
                foreach ($prop in $key.Property) {
                    $value = $key.GetValue($prop)
                    $valueString = $value.ToString()
                    
                    if ($prop -like "*$SearchTerm*" -or $valueString -like "*$SearchTerm*") {
                        $result = [PSCustomObject]@{
                            Path = $Path
                            Name = $prop
                            Value = $valueString
                            Type = $key.GetValueKind($prop)
                        }
                        $results += $result
                    }
                }
            }
            
            # Recurse through subkeys
            Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {
                Search-KeyRecursive -Path $_.PSPath
            }
        } catch {
            # Silently continue if access is denied
        }
    }
    
    Search-KeyRecursive -Path $StartPath
    
    if ($results.Count -eq 0) {
        Write-Host "No matches found for: $SearchTerm" -ForegroundColor Red
    } else {
        Write-Host "Found $($results.Count) matches:" -ForegroundColor Green
        $results | Format-Table -AutoSize -Property Path, Name, Value, Type
    }
}

function Decode-Base64Value {
    param (
        [string]$EncodedValue
    )
    
    if (-not $EncodedValue) {
        $EncodedValue = Read-Host "Enter Base64 encoded value"
    }
    
    try {
        $decodedBytes = [System.Convert]::FromBase64String($EncodedValue)
        $decodedText = [System.Text.Encoding]::Unicode.GetString($decodedBytes)
        
        Write-Host "Decoded value:" -ForegroundColor Yellow
        Write-Host $decodedText -ForegroundColor Green
    } catch {
        Write-Host "Error decoding Base64 value: $_" -ForegroundColor Red
    }
}

function Compare-RegistryTimestamps {
    $registryKeys = Get-ChildItem -Path $artifactsPath -Recurse | Where-Object { $_.Property -contains "Timestamp" }
    
    Write-Host "Registry Timestamp Analysis" -ForegroundColor Yellow
    Write-Host "-----------------------------------" -ForegroundColor Gray
    
    if ($registryKeys.Count -eq 0) {
        Write-Host "No timestamps found in the registry artifacts." -ForegroundColor Red
        return
    }
    
    $timestamps = @()
    
    foreach ($key in $registryKeys) {
        $timestamp = $key.GetValue("Timestamp")
        $keyPath = $key.PSPath.Replace("Microsoft.PowerShell.Core\Registry::", "")
        
        $timestamps += [PSCustomObject]@{
            Path = $keyPath
            Timestamp = [datetime]$timestamp
            FormattedTime = $timestamp
        }
    }
    
    # Sort by timestamp
    $sortedTimestamps = $timestamps | Sort-Object -Property Timestamp
    
    # Display results
    $sortedTimestamps | Format-Table -AutoSize -Property Path, FormattedTime
    
    # Timeline analysis
    $firstActivity = $sortedTimestamps[0]
    $lastActivity = $sortedTimestamps[-1]
    $timespan = $lastActivity.Timestamp - $firstActivity.Timestamp
    
    Write-Host "Timeline Analysis:" -ForegroundColor Cyan
    Write-Host "First activity: $($firstActivity.FormattedTime) at $($firstActivity.Path)" -ForegroundColor White
    Write-Host "Last activity: $($lastActivity.FormattedTime) at $($lastActivity.Path)" -ForegroundColor White
    Write-Host "Total timespan of activity: $($timespan.Hours) hours, $($timespan.Minutes) minutes, $($timespan.Seconds) seconds" -ForegroundColor White
    Write-Host "-----------------------------------" -ForegroundColor Gray
}

function Extract-RegistryData {
    param (
        [string]$KeyPath,
        [string]$ValueName
    )
    
    if (-not $KeyPath) {
        $KeyPath = Read-Host "Enter registry key path"
    }
    
    if (-not $ValueName) {
        $ValueName = Read-Host "Enter value name (press Enter for all values)"
    }
    
    if (-not (Test-Path $KeyPath)) {
        Write-Host "Registry key not found: $KeyPath" -ForegroundColor Red
        return
    }
    
    $key = Get-Item -Path $KeyPath
    
    if ([string]::IsNullOrEmpty($ValueName)) {
        # Extract all values
        $values = @()
        foreach ($prop in $key.Property) {
            $value = $key.GetValue($prop)
            $type = $key.GetValueKind($prop)
            
            $values += [PSCustomObject]@{
                Name = $prop
                Value = $value
                Type = $type
            }
        }
        
        $values | Format-Table -AutoSize
    } else {
        # Extract specific value
        if ($key.GetValue($ValueName) -eq $null) {
            Write-Host "Value not found: $ValueName" -ForegroundColor Red
            return
        }
        
        $value = $key.GetValue($ValueName)
        $type = $key.GetValueKind($ValueName)
        
        Write-Host "Name: $ValueName" -ForegroundColor Yellow
        Write-Host "Type: $type" -ForegroundColor Yellow
        Write-Host "Value:" -ForegroundColor Yellow
        
        if ($type -eq "Binary") {
            $hexValue = ($value | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
            Write-Host $hexValue -ForegroundColor Green
        } elseif ($type -eq "MultiString") {
            foreach ($line in $value) {
                Write-Host $line -ForegroundColor Green
            }
        } else {
            Write-Host $value -ForegroundColor Green
        }
    }
}

function Save-EvidenceToFile {
    param (
        [string]$KeyPath,
        [string]$OutputFile
    )
    
    if (-not $KeyPath) {
        $KeyPath = Read-Host "Enter registry key path to export"
    }
    
    if (-not (Test-Path $KeyPath)) {
        Write-Host "Registry key not found: $KeyPath" -ForegroundColor Red
        return
    }
    
    $evidenceDir = "$env:USERPROFILE\Documents\RegistryForensicsLab\Evidence"
    
    if (-not $OutputFile) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $keyName = Split-Path -Leaf $KeyPath
        $OutputFile = "$evidenceDir\${keyName}_$timestamp.reg"
    } elseif (-not $OutputFile.EndsWith(".reg")) {
        $OutputFile = "$OutputFile.reg"
    }
    
    if (-not $OutputFile.StartsWith($evidenceDir)) {
        $OutputFile = "$evidenceDir\$(Split-Path -Leaf $OutputFile)"
    }
    
    try {
        # Convert key path from PS format to standard format
        $standardKeyPath = $KeyPath.Replace("HKCU:", "HKEY_CURRENT_USER")
        
        # Export registry key
        $process = Start-Process -FilePath "reg.exe" -ArgumentList "export", "`"$standardKeyPath`"", "`"$OutputFile`"", "/y" -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Host "Evidence successfully saved to: $OutputFile" -ForegroundColor Green
            
            # Add evidence record to the evidence registry
            $evidenceKeyName = Split-Path -Leaf $OutputFile
            $evidenceKeyPath = "$evidencePath\$evidenceKeyName"
            
            if (-not (Test-Path $evidenceKeyPath)) {
                New-Item -Path $evidenceKeyPath -Force | Out-Null
            }
            
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            New-ItemProperty -Path $evidenceKeyPath -Name "Source" -Value $KeyPath -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $evidenceKeyPath -Name "FilePath" -Value $OutputFile -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $evidenceKeyPath -Name "CollectionTime" -Value $timestamp -PropertyType String -Force | Out-Null
        } else {
            Write-Host "Failed to export registry key. Exit code: $($process.ExitCode)" -ForegroundColor Red
        }
    } catch {
        Write-Host "Error exporting registry key: $_" -ForegroundColor Red
    }
}

function Analyze-RegistryHive {
    param (
        [string]$HivePath = $artifactsPath
    )
    
    if (-not (Test-Path $HivePath)) {
        Write-Host "Registry path not found: $HivePath" -ForegroundColor Red
        return
    }
    
    Write-Host "Registry Hive Analysis: $HivePath" -ForegroundColor Yellow
    Write-Host "-----------------------------------" -ForegroundColor Gray
    
    # Analyze key structure
    $keyStructure = Get-ChildItem -Path $HivePath -Recurse | 
                    Select-Object -Property PSPath, PSChildName |
                    Group-Object -Property PSParentPath |
                    Select-Object Name, Count
    
    Write-Host "Key Structure:" -ForegroundColor Cyan
    $keyStructure | ForEach-Object {
        $parentPath = $_.Name.Replace("Microsoft.PowerShell.Core\Registry::", "")
        Write-Host "  $parentPath has $($_.Count) subkeys" -ForegroundColor White
    }
    
    # Analyze value types
    $valueTypes = Get-ChildItem -Path $HivePath -Recurse |
                 ForEach-Object { 
                     if ($_.Property) {
                         foreach ($prop in $_.Property) {
                             [PSCustomObject]@{
                                 Type = $_.GetValueKind($prop)
                             }
                         }
                     }
                 } |
                 Group-Object -Property Type |
                 Select-Object Name, Count
    
    Write-Host "Value Types:" -ForegroundColor Cyan
    $valueTypes | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count) values" -ForegroundColor White
    }
    
    # Analyze timestamps
    $timestamps = Get-ChildItem -Path $HivePath -Recurse | 
                  Where-Object { $_.Property -contains "Timestamp" } |
                  ForEach-Object { [datetime]$_.GetValue("Timestamp") } |
                  Sort-Object
    
    if ($timestamps.Count -gt 0) {
        Write-Host "Timestamp Analysis:" -ForegroundColor Cyan
        Write-Host "  Earliest: $($timestamps[0])" -ForegroundColor White
        Write-Host "  Latest: $($timestamps[-1])" -ForegroundColor White
        Write-Host "  Total timestamp markers: $($timestamps.Count)" -ForegroundColor White
    }
    
    Write-Host "-----------------------------------" -ForegroundColor Gray
}

function Search-SuspiciousPaths {
    param (
        [string]$StartPath = $artifactsPath
    )
    
    Write-Host "Searching for suspicious paths..." -ForegroundColor Yellow
    
    # Define suspicious path patterns
    $suspiciousPatterns = @(
        "\\Temp\\",
        "\\ProgramData\\",
        "\\Windows\\Temp\\",
        "\\Tasks\\",
        ".dll",
        ".exe",
        ".ps1",
        ".scr",
        "powershell.exe",
        "cmd.exe",
        "-EncodedCommand",
        "-WindowStyle Hidden",
        "autochk",
        "svchost.exe"
    )
    
    $results = @()
    
    # Recursive function to search registry keys
    function Search-KeyRecursive {
        param (
            [string]$Path
        )
        
        try {
            # Search key properties
            $key = Get-Item -Path $Path -ErrorAction SilentlyContinue
            if ($key -and $key.Property) {
                foreach ($prop in $key.Property) {
                    $value = $key.GetValue($prop).ToString()
                    
                    foreach ($pattern in $suspiciousPatterns) {
                        if ($value -like "*$pattern*") {
                            $result = [PSCustomObject]@{
                                Path = $Path
                                Name = $prop
                                Value = $value
                                MatchedPattern = $pattern
                            }
                            $results += $result
                            break  # Only match once per pattern
                        }
                    }
                }
            }
            
            # Recurse through subkeys
            Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {
                Search-KeyRecursive -Path $_.PSPath
            }
        } catch {
            # Silently continue if access is denied
        }
    }
    
    Search-KeyRecursive -Path $StartPath
    
    if ($results.Count -eq 0) {
        Write-Host "No suspicious paths found." -ForegroundColor Red
    } else {
        Write-Host "Found $($results.Count) suspicious paths:" -ForegroundColor Green
        $results | Sort-Object -Property MatchedPattern | Format-Table -AutoSize -Property Path, Name, Value, MatchedPattern
    }
}

function Check-ValueDataType {
    param (
        [string]$KeyPath,
        [string]$ValueName
    )
    
    if (-not $KeyPath) {
        $KeyPath = Read-Host "Enter registry key path"
    }
    
    if (-not $ValueName) {
        $ValueName = Read-Host "Enter value name"
    }
    
    if (-not (Test-Path $KeyPath)) {
        Write-Host "Registry key not found: $KeyPath" -ForegroundColor Red
        return
    }
    
    $key = Get-Item -Path $KeyPath
    
    if ($key.GetValue($ValueName) -eq $null) {
        Write-Host "Value not found: $ValueName" -ForegroundColor Red
        return
    }
    
    $value = $key.GetValue($ValueName)
    $type = $key.GetValueKind($ValueName)
    
    Write-Host "Data Type Analysis:" -ForegroundColor Yellow
    Write-Host "Name: $ValueName" -ForegroundColor White
    Write-Host "Registry Type: $type" -ForegroundColor White
    
    if ($type -eq "String" -or $type -eq "ExpandString") {
        Write-Host "Content Analysis:" -ForegroundColor Cyan
        
        # Check if it might be Base64
        if ($value -match "^[A-Za-z0-9+/=]+$" -and $value.Length % 4 -eq 0) {
            Write-Host "  Possible Base64 encoding detected" -ForegroundColor Magenta
            try {
                $decodedBytes = [System.Convert]::FromBase64String($value)
                $decodedText = [System.Text.Encoding]::ASCII.GetString($decodedBytes)
                if ($decodedText -match "[\x20-\x7E]{8,}") {  # ASCII printable characters
                    Write-Host "  ASCII Decoded: $decodedText" -ForegroundColor Green
                }
                
                $decodedTextUnicode = [System.Text.Encoding]::Unicode.GetString($decodedBytes)
                if ($decodedTextUnicode -match "[\x20-\x7E]{8,}") {  # ASCII printable characters
                    Write-Host "  Unicode Decoded: $decodedTextUnicode" -ForegroundColor Green
                }
            } catch {
                Write-Host "  Not valid Base64" -ForegroundColor Red
            }
        }
        
        # Check for file paths
        if ($value -match "\\") {
            Write-Host "  Contains file path" -ForegroundColor Magenta
            if ($value -match "\.exe|\.dll|\.ps1|\.bat|\.cmd|\.vbs|\.js") {
                Write-Host "  Contains reference to executable file" -ForegroundColor Red
            }
        }
        
        # Check for PowerShell commands
        if ($value -match "powershell|cmd|IEX|invoke-expression|downloadstring|scriptblock|frombase64string") {
            Write-Host "  Contains potential command execution" -ForegroundColor Red
        }
    } elseif ($type -eq "Binary") {
        Write-Host "Binary Data Analysis:" -ForegroundColor Cyan
        $hexValue = ($value | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
        Write-Host "  Hex: $hexValue" -ForegroundColor White
        
        # Try to convert to ASCII/Unicode
        try {
            $ascii = [System.Text.Encoding]::ASCII.GetString($value)
            if ($ascii -match "[\x20-\x7E]{4,}") {  # ASCII printable characters
                Write-Host "  ASCII: $ascii" -ForegroundColor Green
            }
            
            $unicode = [System.Text.Encoding]::Unicode.GetString($value)
            if ($unicode -match "[\x20-\x7E]{4,}") {  # ASCII printable characters
                Write-Host "  Unicode: $unicode" -ForegroundColor Green
            }
        } catch {
            # Ignore conversion errors
        }
    } elseif ($type -eq "DWord" -or $type -eq "QWord") {
        Write-Host "Numeric Analysis:" -ForegroundColor Cyan
        Write-Host "  Decimal: $value" -ForegroundColor White
        Write-Host "  Hexadecimal: 0x$($value.ToString("X"))" -ForegroundColor White
        Write-Host "  Binary: $([Convert]::ToString($value, 2))" -ForegroundColor White
        
        # Check for common flag values
        if ($value -eq 0) {
            Write-Host "  Common value: Disabled/Off" -ForegroundColor Magenta
        } elseif ($value -eq 1) {
            Write-Host "  Common value: Enabled/On" -ForegroundColor Magenta
        } elseif ($value -eq 2) {
            Write-Host "  Common value: Auto/Normal" -ForegroundColor Magenta
        } elseif ($value -eq 4) {
            Write-Host "  Common value: Hidden" -ForegroundColor Magenta
        }
    }
}

# Main interactive loop
$running = $true
while ($running) {
    $choice = Read-Host "Enter your choice (1-10)"
    
    switch ($choice) {
        "1" { 
            $keyPath = Read-Host "Enter registry key path to examine (press Enter for Artifacts root)"
            if ([string]::IsNullOrEmpty($keyPath)) {
                $keyPath = $artifactsPath
            }
            Examine-RegistryKey -KeyPath $keyPath 
        }
        "2" { 
            $searchTerm = Read-Host "Enter search term"
            Search-RegistryValues -SearchTerm $searchTerm 
        }
        "3" { 
            $encodedValue = Read-Host "Enter Base64 encoded value"
            Decode-Base64Value -EncodedValue $encodedValue 
        }
        "4" { Compare-RegistryTimestamps }
        "5" { 
            $keyPath = Read-Host "Enter registry key path"
            $valueName = Read-Host "Enter value name (press Enter for all values)"
            Extract-RegistryData -KeyPath $keyPath -ValueName $valueName 
        }
        "6" { 
            $keyPath = Read-Host "Enter registry key path to export"
            $outputFile = Read-Host "Enter output file name (press Enter for auto-generated name)"
            Save-EvidenceToFile -KeyPath $keyPath -OutputFile $outputFile 
        }
        "7" { 
            $hivePath = Read-Host "Enter registry path to analyze (press Enter for Artifacts root)"
            if ([string]::IsNullOrEmpty($hivePath)) {
                $hivePath = $artifactsPath
            }
            Analyze-RegistryHive -HivePath $hivePath 
        }
        "8" { Search-SuspiciousPaths }
        "9" { 
            $keyPath = Read-Host "Enter registry key path"
            $valueName = Read-Host "Enter value name"
            Check-ValueDataType -KeyPath $keyPath -ValueName $valueName 
        }
        "10" { 
            $running = $false
            Write-Host "Exiting Registry Forensic Tools." -ForegroundColor Cyan
        }
        default { Write-Host "Invalid choice. Please enter a number between 1 and 10." -ForegroundColor Red }
    }
    
    if ($running) {
        Write-Host ""
        Write-Host "Press Enter to continue..." -ForegroundColor Yellow
        Read-Host | Out-Null
        
        Clear-Host
        Write-Host "========================================================" -ForegroundColor Cyan
        Write-Host "Registry Forensics Lab: Tracking the Dark Kittens" -ForegroundColor Cyan
        Write-Host "Registry Forensic Tools" -ForegroundColor Cyan
        Write-Host "========================================================" -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "Registry Forensic Tools Menu:" -ForegroundColor Yellow
        Write-Host "1: Examine Registry Key" -ForegroundColor Green
        Write-Host "2: Search for Registry Values" -ForegroundColor Green
        Write-Host "3: Decode Base64 Value" -ForegroundColor Green
        Write-Host "4: Compare Registry Timestamps" -ForegroundColor Green
        Write-Host "5: Extract Registry Data" -ForegroundColor Green
        Write-Host "6: Save Evidence to File" -ForegroundColor Green
        Write-Host "7: Registry Hive Analysis" -ForegroundColor Green
        Write-Host "8: Search for Suspicious Paths" -ForegroundColor Green
        Write-Host "9: Check Value Data Type" -ForegroundColor Green
        Write-Host "10: Exit" -ForegroundColor Green
        Write-Host ""
    }
}
