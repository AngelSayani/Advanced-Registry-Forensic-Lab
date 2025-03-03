# evidence_collector.ps1
# Registry Forensics Lab: Tracking the Dark Kittens
# This script helps collect and document registry findings

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Registry Forensics Lab: Tracking the Dark Kittens" -ForegroundColor Cyan
Write-Host "Registry Evidence Collector" -ForegroundColor Cyan
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
$reportsDir = "$labDir\Reports"
$evidencePath = "HKCU:\Software\DarkKittensLab\Evidence"

# Ensure directories exist
if (-not (Test-Path $evidenceDir)) {
    New-Item -Path $evidenceDir -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path $reportsDir)) {
    New-Item -Path $reportsDir -ItemType Directory -Force | Out-Null
}

# Define evidence types
$evidenceTypes = @(
    "Registry Key",
    "Registry Value",
    "Base64 Encoded Command",
    "Suspicious Path",
    "Persistence Mechanism",
    "Timestamp",
    "Other"
)

# Function to collect evidence
function Collect-Evidence {
    param (
        [string]$EvidenceSource,
        [string]$EvidenceType,
        [string]$Description,
        [string]$Notes
    )
    
    Write-Host "========== EVIDENCE COLLECTION FORM ==========" -ForegroundColor Yellow
    Write-Host "Complete this form to document a piece of evidence found during your investigation." -ForegroundColor Yellow
    Write-Host "This is similar to how security analysts document findings in real investigations." -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Yellow
    Write-Host ""
    
    if (-not $EvidenceSource) {
        Write-Host "Step 1: Evidence Source Location" -ForegroundColor Cyan
        Write-Host "Where did you find this evidence? Enter a registry path or other source identifier." -ForegroundColor White
        Write-Host "Examples:" -ForegroundColor Gray
        Write-Host "- HKCU:\Software\DarkKittensLab\Artifacts\RunKey" -ForegroundColor Gray
        Write-Host "- HKCU:\Software\DarkKittensLab\Artifacts\Services\GloboSync" -ForegroundColor Gray
        $EvidenceSource = Read-Host "Evidence source"
        Write-Host ""
    }
    
    if (-not $EvidenceType) {
        Write-Host "Step 2: Evidence Type Classification" -ForegroundColor Cyan
        Write-Host "Categorize this evidence based on what type of artifact it represents." -ForegroundColor White
        Write-Host "Select evidence type:" -ForegroundColor White
        for ($i = 0; $i -lt $evidenceTypes.Count; $i++) {
            Write-Host "  $($i+1): $($evidenceTypes[$i])" -ForegroundColor Green
        }
        
        $typeSelection = Read-Host "Enter number"
        if (-not [int]::TryParse($typeSelection, [ref]$null) -or [int]$typeSelection -lt 1 -or [int]$typeSelection -gt $evidenceTypes.Count) {
            Write-Host "Invalid selection. Defaulting to 'Other'." -ForegroundColor Red
            $EvidenceType = $evidenceTypes[-1]
        } else {
            $EvidenceType = $evidenceTypes[[int]$typeSelection - 1]
        }
        Write-Host ""
    }
    
    # Provide hints based on selected evidence type
    $descriptionHints = @{
        "Registry Key" = "Example: 'Suspicious registry key that launches PowerShell at startup'"
        "Registry Value" = "Example: 'Modified Winlogon Userinit value to load malicious DLL'"
        "Base64 Encoded Command" = "Example: 'PowerShell command that downloads and executes code from remote server'"
        "Suspicious Path" = "Example: 'Path to unexpected executable in Windows Temp directory'"
        "Persistence Mechanism" = "Example: 'Run key that provides persistence for malware'"
        "Timestamp" = "Example: 'Artifacts created at 2:30 AM when no legitimate activity expected'"
        "Other" = "Example: 'Unusual configuration setting that may indicate compromise'"
    }
    
    if (-not $Description) {
        Write-Host "Step 3: Evidence Description" -ForegroundColor Cyan
        Write-Host "Describe what this evidence shows and why it's suspicious." -ForegroundColor White
        
        if ($descriptionHints.ContainsKey($EvidenceType)) {
            Write-Host $descriptionHints[$EvidenceType] -ForegroundColor Gray
        }
        $Description = Read-Host "Evidence description"
        Write-Host ""
    }
    
    if (-not $Notes) {
        Write-Host "Step 4: Investigative Notes" -ForegroundColor Cyan
        Write-Host "Add any additional context, observations, or analysis." -ForegroundColor White
        Write-Host "This might include:" -ForegroundColor Gray
        Write-Host "- How this connects to other evidence" -ForegroundColor Gray
        Write-Host "- Why you believe this is malicious" -ForegroundColor Gray
        Write-Host "- Recommended remediation steps" -ForegroundColor Gray
        $Notes = Read-Host "Additional notes (press Enter to skip)"
        Write-Host ""
    }
    
    # Generate unique ID for evidence item
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
    $evidenceId = "EVIDENCE_$timestamp"
    
    # Create evidence record in registry
    $evidenceItemPath = "$evidencePath\$evidenceId"
    New-Item -Path $evidenceItemPath -Force | Out-Null
    
    # Store evidence metadata
    New-ItemProperty -Path $evidenceItemPath -Name "Source" -Value $EvidenceSource -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $evidenceItemPath -Name "Type" -Value $EvidenceType -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $evidenceItemPath -Name "Description" -Value $Description -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $evidenceItemPath -Name "Notes" -Value $Notes -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $evidenceItemPath -Name "CollectionTime" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -PropertyType String -Force | Out-Null
    
    # If the evidence is a registry path, try to capture its value
    if (-not [string]::IsNullOrWhiteSpace($EvidenceSource) -and (Test-Path $EvidenceSource)) {
        try {
            # Check if it's a registry key
            $item = Get-Item -Path $EvidenceSource -ErrorAction SilentlyContinue
            if ($item) {
                # Export to registry file
                $regFileName = "$evidenceId.reg"
                $regFilePath = "$evidenceDir\$regFileName"
                
                # Convert PS path to standard registry path
                $standardPath = $EvidenceSource.Replace("HKCU:", "HKEY_CURRENT_USER").Replace("HKLM:", "HKEY_LOCAL_MACHINE")
                
                $process = Start-Process -FilePath "reg.exe" -ArgumentList "export", "`"$standardPath`"", "`"$regFilePath`"", "/y" -NoNewWindow -Wait -PassThru
                
                if ($process.ExitCode -eq 0) {
                    New-ItemProperty -Path $evidenceItemPath -Name "ExportFile" -Value $regFilePath -PropertyType String -Force | Out-Null
                }
            }
        } catch {
            # Silently continue if export fails
        }
    }
    
    Write-Host "Evidence collected and recorded with ID: $evidenceId" -ForegroundColor Green
    Write-Host "Source: $EvidenceSource" -ForegroundColor Green
    Write-Host "Type: $EvidenceType" -ForegroundColor Green
    
    return $evidenceId
}

# Function to view collected evidence
function View-CollectedEvidence {
    $evidenceItems = Get-ChildItem -Path $evidencePath -ErrorAction SilentlyContinue
    
    if ($evidenceItems.Count -eq 0) {
        Write-Host "No evidence has been collected yet." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Collected Evidence Items:" -ForegroundColor Yellow
    Write-Host "-----------------------------------" -ForegroundColor Gray
    
    foreach ($item in $evidenceItems) {
        $id = $item.PSChildName
        $source = $item.GetValue("Source")
        $type = $item.GetValue("Type")
        $description = $item.GetValue("Description")
        $time = $item.GetValue("CollectionTime")
        
        Write-Host "ID: $id" -ForegroundColor Cyan
        Write-Host "  Source: $source" -ForegroundColor White
        Write-Host "  Type: $type" -ForegroundColor White
        Write-Host "  Description: $description" -ForegroundColor White
        Write-Host "  Collection Time: $time" -ForegroundColor White
        
        if ($item.GetValue("ExportFile")) {
            Write-Host "  Export File: $($item.GetValue("ExportFile"))" -ForegroundColor White
        }
        
        if ($item.GetValue("Notes") -and $item.GetValue("Notes") -ne "") {
            Write-Host "  Notes: $($item.GetValue("Notes"))" -ForegroundColor White
        }
        
        Write-Host "-----------------------------------" -ForegroundColor Gray
    }
}

# Function to generate evidence report
function Generate-EvidenceReport {
    param (
        [string]$ReportTitle,
        [string]$InvestigatorName,
        [string]$OutputFile
    )
    
    $evidenceItems = Get-ChildItem -Path $evidencePath -ErrorAction SilentlyContinue
    
    if ($evidenceItems.Count -eq 0) {
        Write-Host "No evidence has been collected yet. Cannot generate report." -ForegroundColor Red
        return
    }
    
    if (-not $ReportTitle) {
        $ReportTitle = Read-Host "Enter report title (e.g., 'Dark Kittens Incident - Registry Forensics Report')"
    }
    
    if (-not $InvestigatorName) {
        $InvestigatorName = Read-Host "Enter investigator name"
    }
    
    if (-not $OutputFile) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputFile = "$reportsDir\Evidence_Report_$timestamp.html"
    } elseif (-not $OutputFile.EndsWith(".html")) {
        $OutputFile = "$OutputFile.html"
    }
    
    if (-not $OutputFile.StartsWith($reportsDir)) {
        $OutputFile = "$reportsDir\$(Split-Path -Leaf $OutputFile)"
    }
    
    Write-Host "Generating evidence report..." -ForegroundColor Yellow
    
    # Prepare HTML content
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>$ReportTitle</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #2c3e50;
            margin-top: 20px;
        }
        .evidence-item {
            background-color: #f9f9f9;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .evidence-header {
            background-color: #3498db;
            color: white;
            padding: 8px;
            border-radius: 3px;
            margin-bottom: 10px;
        }
        .evidence-details {
            margin-left: 20px;
        }
        .label {
            font-weight: bold;
            color: #2c3e50;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .suspicious {
            color: #c0392b;
            font-weight: bold;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .summary {
            background-color: #e8f4fc;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            margin-bottom: 20px;
        }
        .footer {
            margin-top: 30px;
            padding-top: 10px;
            border-top: 1px solid #eee;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <h1>$ReportTitle</h1>
    
    <div class="summary">
        <p><span class="label">Report Generated:</span> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p><span class="label">Investigator:</span> $InvestigatorName</p>
        <p><span class="label">Total Evidence Items:</span> $($evidenceItems.Count)</p>
    </div>
    
    <h2>Evidence Summary Table</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Source</th>
            <th>Description</th>
            <th>Collection Time</th>
        </tr>
"@

    # Add evidence summary rows
    foreach ($item in $evidenceItems) {
        $id = $item.PSChildName
        $source = $item.GetValue("Source")
        $type = $item.GetValue("Type")
        $description = $item.GetValue("Description")
        $time = $item.GetValue("CollectionTime")
        
        $html += @"
        <tr>
            <td>$id</td>
            <td>$type</td>
            <td>$source</td>
            <td>$description</td>
            <td>$time</td>
        </tr>
"@
    }

    $html += @"
    </table>
    
    <h2>Detailed Evidence Items</h2>
"@

    # Add detailed evidence items
    foreach ($item in $evidenceItems) {
        $id = $item.PSChildName
        $source = $item.GetValue("Source")
        $type = $item.GetValue("Type")
        $description = $item.GetValue("Description")
        $time = $item.GetValue("CollectionTime")
        $notes = $item.GetValue("Notes")
        $exportFile = $item.GetValue("ExportFile")
        
        $html += @"
    <div class="evidence-item">
        <div class="evidence-header">Evidence ID: $id</div>
        <div class="evidence-details">
            <p><span class="label">Source:</span> $source</p>
            <p><span class="label">Type:</span> $type</p>
            <p><span class="label">Description:</span> $description</p>
            <p><span class="timestamp">Collected: $time</span></p>
"@

        if ($notes -and $notes -ne "") {
            $html += @"
            <p><span class="label">Notes:</span> $notes</p>
"@
        }

        if ($exportFile) {
            $html += @"
            <p><span class="label">Export File:</span> $exportFile</p>
"@
        }

        $html += @"
        </div>
    </div>
"@
    }

    # Add persistence techniques found
    $persistenceTypes = $evidenceItems | Where-Object { $_.GetValue("Type") -eq "Persistence Mechanism" }
    
    if ($persistenceTypes.Count -gt 0) {
        $html += @"
    <h2>Persistence Techniques Identified</h2>
    <div class="summary">
        <p>The analysis identified $($persistenceTypes.Count) persistence techniques used by the threat actor:</p>
        <ul>
"@

        foreach ($item in $persistenceTypes) {
            $description = $item.GetValue("Description")
            $html += @"
            <li>$description</li>
"@
        }

        $html += @"
        </ul>
    </div>
"@
    }

    # Add conclusion
    $html += @"
    <h2>Conclusion</h2>
    <div class="summary">
        <p>The forensic analysis of registry artifacts has uncovered evidence of unauthorized access and persistence mechanisms established by the threat actor known as "Dark Kittens." The findings show deliberate attempts to maintain access to the system through various registry-based techniques.</p>
        <p>Recommended next steps include:</p>
        <ul>
            <li>Contain the incident by isolating affected systems</li>
            <li>Remove identified persistence mechanisms</li>
            <li>Perform a broader investigation to identify other potentially compromised systems</li>
            <li>Implement enhanced monitoring for the specific techniques identified</li>
        </ul>
    </div>
    
    <div class="footer">
        <p>Report generated using the Registry Forensics Lab - Dark Kittens Investigation Toolkit</p>
        <p>© $(Get-Date -Format "yyyy") Globomantics Cybersecurity Team</p>
    </div>
</body>
</html>
"@

    # Save the HTML report
    $html | Out-File -FilePath $OutputFile -Encoding utf8 -Force
    
    Write-Host "Evidence report generated successfully: $OutputFile" -ForegroundColor Green
    
    # Try to open the report in the default browser
    try {
        Start-Process $OutputFile
    } catch {
        Write-Host "Report created, but could not open automatically. Please open manually: $OutputFile" -ForegroundColor Yellow
    }
}

# Function to export evidence to CSV
function Export-EvidenceToCSV {
    param (
        [string]$OutputFile
    )
    
    $evidenceItems = Get-ChildItem -Path $evidencePath -ErrorAction SilentlyContinue
    
    if ($evidenceItems.Count -eq 0) {
        Write-Host "No evidence has been collected yet. Cannot export to CSV." -ForegroundColor Red
        return
    }
    
    if (-not $OutputFile) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputFile = "$reportsDir\Evidence_Export_$timestamp.csv"
    } elseif (-not $OutputFile.EndsWith(".csv")) {
        $OutputFile = "$OutputFile.csv"
    }
    
    if (-not $OutputFile.StartsWith($reportsDir)) {
        $OutputFile = "$reportsDir\$(Split-Path -Leaf $OutputFile)"
    }
    
    Write-Host "Exporting evidence to CSV..." -ForegroundColor Yellow
    
    $csvData = @()
    
    foreach ($item in $evidenceItems) {
        $id = $item.PSChildName
        $source = $item.GetValue("Source")
        $type = $item.GetValue("Type")
        $description = $item.GetValue("Description")
        $notes = $item.GetValue("Notes")
        $time = $item.GetValue("CollectionTime")
        $exportFile = $item.GetValue("ExportFile")
        
        $csvItem = [PSCustomObject]@{
            EvidenceID = $id
            Source = $source
            Type = $type
            Description = $description
            Notes = $notes
            CollectionTime = $time
            ExportFile = $exportFile
        }
        
        $csvData += $csvItem
    }
    
    $csvData | Export-Csv -Path $OutputFile -NoTypeInformation
    
    Write-Host "Evidence exported to CSV: $OutputFile" -ForegroundColor Green
}

# Main menu
function Show-Menu {
    Write-Host "Evidence Collector Menu:" -ForegroundColor Yellow
    Write-Host "1: Collect New Evidence" -ForegroundColor Green
    Write-Host "2: View Collected Evidence" -ForegroundColor Green
    Write-Host "3: Generate HTML Evidence Report" -ForegroundColor Green
    Write-Host "4: Export Evidence to CSV" -ForegroundColor Green
    Write-Host "5: Exit" -ForegroundColor Green
    Write-Host ""
}

$running = $true
while ($running) {
    Show-Menu
    $choice = Read-Host "Enter your choice (1-5)"
    
    switch ($choice) {
        "1" { 
            # LEARNER TASK: Manual Evidence Collection
            Write-Host ""
            Write-Host "LEARNER TASK:" -ForegroundColor Magenta
            Write-Host "You'll now document evidence you've found during your investigation." -ForegroundColor Magenta
            Write-Host "First, we'll guide you through a specific piece of evidence, then you'll collect" -ForegroundColor Magenta
            Write-Host "additional evidence on your own." -ForegroundColor Magenta
            Write-Host ""
            
            # Guided evidence collection for Run key
            Write-Host "Let's document the Run key persistence evidence first:" -ForegroundColor Yellow
            $runKeyPath = "HKCU:\Software\DarkKittensLab\Artifacts\RunKey"
            
            if (Test-Path $runKeyPath) {
                $runKey = Get-Item -Path $runKeyPath
                $properties = $runKey.Property | Where-Object { $_ -ne "Timestamp" }
                
                if ($properties.Count -gt 0) {
                    Write-Host "Run key evidence found:" -ForegroundColor Green
                    foreach ($prop in $properties) {
                        $value = $runKey.GetValue($prop)
                        Write-Host "  Name: $prop" -ForegroundColor White
                        Write-Host "  Value: $value" -ForegroundColor White
                        Write-Host ""
                    }
                    
                    # Guide the user through evidence collection
                    Write-Host "Now, let's document this as evidence:" -ForegroundColor Yellow
                    Collect-Evidence -EvidenceSource $runKeyPath -EvidenceType "Persistence Mechanism" -Description "Run key persistence mechanism that executes PowerShell with encoded command"
                    
                    # Now ask them to find and document something else
                    Write-Host ""
                    Write-Host "Great job! Now, find and document at least one more piece of evidence on your own." -ForegroundColor Yellow
                    Write-Host "Look for evidence such as:" -ForegroundColor Yellow
                    Write-Host "- WinLogon helper DLL modifications (HKCU:\Software\DarkKittensLab\Artifacts\Winlogon)" -ForegroundColor White
                    Write-Host "- Malicious service (HKCU:\Software\DarkKittensLab\Artifacts\Services)" -ForegroundColor White
                    Write-Host "- File association hijacking (HKCU:\Software\DarkKittensLab\Artifacts\FileAssoc)" -ForegroundColor White
                    
                    Collect-Evidence
                } else {
                    Write-Host "No Run key values found. Let's collect evidence manually." -ForegroundColor Yellow
                    Collect-Evidence
                }
            } else {
                Write-Host "Run key evidence not found. Let's collect evidence manually." -ForegroundColor Yellow
                Collect-Evidence
            }
            
            # Check if they've collected at least 2 pieces of evidence
            $evidenceCount = (Get-ChildItem -Path $evidencePath -ErrorAction SilentlyContinue).Count
            
            if ($evidenceCount -ge 2) {
                Write-Host ""
                Write-Host "Excellent! You've documented multiple pieces of evidence." -ForegroundColor Green
                Write-Host "In a real investigation, you would continue this process for all suspicious findings." -ForegroundColor Green
            } else {
                Write-Host ""
                Write-Host "You should document at least one more piece of evidence to practice this skill." -ForegroundColor Yellow
                Write-Host "Select option 1 again to collect more evidence." -ForegroundColor Yellow
            }
        }
        "2" { 
            View-CollectedEvidence 
        }
        "3" { 
            Write-Host ""
            Write-Host "LEARNER TASK:" -ForegroundColor Magenta
            Write-Host "Generate a professional evidence report that you could present to management" -ForegroundColor Magenta
            Write-Host "or to a security team. This report should clearly document your findings" -ForegroundColor Magenta
            Write-Host "in a way that non-technical stakeholders can understand the security implications." -ForegroundColor Magenta
            Write-Host ""
            
            $reportTitle = Read-Host "Enter report title (e.g., 'Dark Kittens Incident - Registry Forensics Report')"
            $investigatorName = Read-Host "Enter your name as the investigator"
            
            # Ensure they've collected enough evidence for a meaningful report
            $evidenceCount = (Get-ChildItem -Path $evidencePath -ErrorAction SilentlyContinue).Count
            
            if ($evidenceCount -lt 2) {
                Write-Host ""
                Write-Host "You should collect more evidence before generating a report." -ForegroundColor Yellow
                Write-Host "Please collect at least 2 pieces of evidence using option 1." -ForegroundColor Yellow
            } else {
                Generate-EvidenceReport -ReportTitle $reportTitle -InvestigatorName $investigatorName
                
                Write-Host ""
                Write-Host "TASK:" -ForegroundColor Magenta
                Write-Host "Review the HTML report that was just generated and answer the following questions:" -ForegroundColor Magenta
                
                $reportReviewed = Read-Host "Have you reviewed the report? (Y/N)"
                
                if ($reportReviewed -eq "Y") {
                    Write-Host ""
                    Write-Host "What key information is included in the report that would help management understand the severity of the incident?" -ForegroundColor Yellow
                    $answer1 = Read-Host "Your answer"
                    
                    Write-Host ""
                    Write-Host "How would you improve this report for a real-world incident response situation?" -ForegroundColor Yellow
                    $answer2 = Read-Host "Your answer"
                    
                    Write-Host ""
                    Write-Host "Thanks for your feedback! In a real-world scenario, clear and comprehensive reporting" -ForegroundColor Green
                    Write-Host "is critical for effective incident response and communication with stakeholders." -ForegroundColor Green
                }
            }
        }
        "4" { 
            Export-EvidenceToCSV 
        }
        "5" { 
            $running = $false
            Write-Host "Exiting Evidence Collector." -ForegroundColor Cyan
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
        Write-Host "Registry Evidence Collector" -ForegroundColor Cyan
        Write-Host "========================================================" -ForegroundColor Cyan
        Write-Host ""
    }
}
