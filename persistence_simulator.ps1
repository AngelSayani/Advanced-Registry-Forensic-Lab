# persistence_simulator.ps1
# Registry Forensics Lab: Tracking the Dark Kittens
# This script explains common registry persistence techniques

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Registry Forensics: Tracking the Dark Kittens Lab by Angel Sayani" -ForegroundColor Cyan
Write-Host "Registry Persistence Techniques Explainer" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# Verify PowerShell running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Please restart PowerShell as Administrator." -ForegroundColor Red
    exit
}

function Show-PersistenceTechnique {
    param (
        [string]$Name,
        [string]$Description,
        [string]$RegistryPath,
        [string]$Example,
        [string]$DetectionMethod
    )
    
    Write-Host "TECHNIQUE: $Name" -ForegroundColor Yellow
    Write-Host "Description: $Description"
    Write-Host "Registry Path: $RegistryPath"
    Write-Host "Example: $Example"
    Write-Host "Detection Method: $DetectionMethod"
    Write-Host "--------------------------------------------------------" -ForegroundColor Gray
}

Write-Host "REGISTRY PERSISTENCE TECHNIQUES REFERENCE GUIDE" -ForegroundColor Green
Write-Host "This script explains common techniques that attackers use to achieve persistence using the Windows Registry." -ForegroundColor Green
Write-Host ""
Write-Host "You can use this information to better understand the simulated artifacts in the lab." -ForegroundColor Green
Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

# 1. Run Key Persistence
Show-PersistenceTechnique -Name "Run Key Persistence" `
    -Description "The Run and RunOnce keys cause programs to run each time a user logs on. Attackers often add malicious programs to these keys to maintain persistence." `
    -RegistryPath "HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" `
    -Example "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater = C:\malware.exe" `
    -DetectionMethod "Check for unusual or suspicious program paths in Run/RunOnce keys. Look for recently added entries or obfuscated commands."

# 2. WinLogon Helper DLL
Show-PersistenceTechnique -Name "WinLogon Helper DLL" `
    -Description "WinLogon registry keys control actions during the Windows logon process. Attackers can modify these to load malicious DLLs or executables." `
    -RegistryPath "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -Example "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit = C:\Windows\system32\userinit.exe,C:\malware.dll" `
    -DetectionMethod "Check if Userinit or Shell values have been modified to include additional executables or DLLs separated by commas."

# 3. Service Creation
Show-PersistenceTechnique -Name "Service Creation" `
    -Description "Attackers create or modify Windows services to execute malicious code. Services run with SYSTEM privileges and start automatically." `
    -RegistryPath "HKLM\SYSTEM\CurrentControlSet\Services\[ServiceName]" `
    -Example "HKLM\SYSTEM\CurrentControlSet\Services\MalService\ImagePath = C:\malware.exe" `
    -DetectionMethod "Look for services with unusual names or descriptions, suspicious ImagePath values, or services pointing to uncommon locations."

# 4. COM Object Hijacking
Show-PersistenceTechnique -Name "COM Object Hijacking" `
    -Description "Component Object Model (COM) objects are used by Windows for inter-process communication. Attackers can hijack legitimate COM objects to execute malicious code." `
    -RegistryPath "HKCU\Software\Classes\CLSID\{CLSID-VALUE}\InprocServer32
HKLM\Software\Classes\CLSID\{CLSID-VALUE}\InprocServer32" `
    -Example "HKLM\Software\Classes\CLSID\{00000000-0000-0000-C000-000000000046}\InprocServer32 = C:\malware.dll" `
    -DetectionMethod "Search for COM objects pointing to unusual file locations or recently modified COM registry entries."

# 5. Scheduled Task Persistence
Show-PersistenceTechnique -Name "Scheduled Task Persistence" `
    -Description "Scheduled tasks can be used to execute programs at specific times or when specific events occur. Registry entries can be used to register tasks." `
    -RegistryPath "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache" `
    -Example "Task is created with malicious actions that execute on schedule" `
    -DetectionMethod "Examine scheduled tasks for unusual command lines, executable paths, or trigger conditions."

# 6. AppInit_DLLs Persistence
Show-PersistenceTechnique -Name "AppInit_DLLs Persistence" `
    -Description "Windows loads all DLLs specified in the AppInit_DLLs registry value into every process that loads user32.dll (which is almost all GUI applications)." `
    -RegistryPath "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs" `
    -Example "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs = C:\malware.dll" `
    -DetectionMethod "Check if AppInit_DLLs contains any values and if LoadAppInit_DLLs is set to 1. Any DLL listed here should be investigated carefully."

# 7. Screensaver Persistence
Show-PersistenceTechnique -Name "Screensaver Persistence" `
    -Description "Attackers can replace the legitimate screensaver with a malicious one. When the screensaver activates, the malicious code executes." `
    -RegistryPath "HKCU\Control Panel\Desktop\SCRNSAVE.EXE" `
    -Example "HKCU\Control Panel\Desktop\SCRNSAVE.EXE = C:\malware.scr" `
    -DetectionMethod "Check if the screensaver points to an unusual or unexpected location, especially outside the Windows directory."

# 8. File Association Hijacking
Show-PersistenceTechnique -Name "File Association Hijacking" `
    -Description "Attackers can modify file associations to execute malicious code when a user opens a specific file type." `
    -RegistryPath "HKCU\Software\Classes\[extension]\shell\open\command
HKLM\Software\Classes\[extension]\shell\open\command" `
    -Example "HKCU\Software\Classes\.txt\shell\open\command = C:\malware.exe %1" `
    -DetectionMethod "Check for modified file associations, especially common file types. Look for command values that run additional executables."

# 9. DLL Search Order Hijacking
Show-PersistenceTechnique -Name "DLL Search Order Hijacking" `
    -Description "Windows searches for DLLs in specific locations in a predetermined order. Attackers place malicious DLLs in locations that are searched before the legitimate DLL." `
    -RegistryPath "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\PATH" `
    -Example "Modified PATH environment variable to include directory with malicious DLL" `
    -DetectionMethod "Check for unusual directories in the PATH environment variable, especially those added recently or pointing to user-writable locations."

# 10. Boot Execute
Show-PersistenceTechnique -Name "Boot Execute" `
    -Description "The BootExecute registry value lists programs that run during the Windows boot process, before user logon." `
    -RegistryPath "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute" `
    -Example "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute = autocheck autochk * malware.exe" `
    -DetectionMethod "Verify that BootExecute only contains legitimate entries like 'autocheck autochk *'. Any additional entries should be investigated."

Write-Host ""
Write-Host "This reference guide is meant to help you understand common registry-based persistence techniques." -ForegroundColor Green
Write-Host "Use this knowledge to analyze the simulated malicious artifacts in the lab environment." -ForegroundColor Green
Write-Host "You can now proceed with the investigation using forensic_tools.ps1." -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
