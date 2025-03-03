# analysis_guide.ps1
# Registry Forensics Lab: Tracking the Dark Kittens
# This script provides a guided analysis for finding and documenting evidence

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Registry Forensics Lab: Tracking the Dark Kittens Lab by Angel Sayani" -ForegroundColor Cyan
Write-Host "Guided Analysis Steps" -ForegroundColor Cyan
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

# Check if artifacts have been created
if (-not (Test-Path "HKCU:\Software\DarkKittensLab\Artifacts")) {
    Write-Host "Artifacts not found. Please run create_artifacts.ps1 first." -ForegroundColor Red
    exit
}

$artifactsPath = "HKCU:\Software\DarkKittensLab\Artifacts"

# Define the steps
$steps = @(
    @{
        Title = "Understand the Scenario"
        Description = "The notorious hacking group Dark Kittens has infiltrated a Globomantics workstation. Your task is to find evidence of their persistence mechanisms in the Windows Registry."
        TaskAction = {
            Write-Host "To begin this investigation, you should understand what registry-based persistence techniques attackers typically use." -ForegroundColor Yellow
            Write-Host "You can learn more about these techniques by running persistence_simulator.ps1" -ForegroundColor Yellow
            
            $runSim = Read-Host "Would you like to run persistence_simulator.ps1 now? (Y/N)"
            if ($runSim -eq "Y") {
                & "$PSScriptRoot\persistence_simulator.ps1"
            }
        }
    },
    @{
        Title = "Examine the Registry Structure"
        Description = "Start by examining the overall structure of the simulated registry artifacts to get a sense of what areas have been modified."
        TaskAction = {
            Write-Host "Let's examine the overall structure of the registry artifacts." -ForegroundColor Yellow
            
            $keys = Get-ChildItem -Path $artifactsPath | Select-Object -ExpandProperty PSChildName
            
            Write-Host "Top-level keys found in artifacts:" -ForegroundColor Green
            foreach ($key in $keys) {
                Write-Host "  - $key" -ForegroundColor White
            }
            
            Write-Host ""
            Write-Host "To investigate further, use forensic_tools.ps1 and select option 1 (Examine Registry Key)" -ForegroundColor Yellow
            Write-Host "Enter HKCU:\Software\DarkKittensLab\Artifacts as the registry key path to examine." -ForegroundColor Yellow
            
            $runTools = Read-Host "Would you like to run forensic_tools.ps1 now? (Y/N)"
            if ($runTools -eq "Y") {
                & "$PSScriptRoot\forensic_tools.ps1"
            }
        }
    },
    @{
        Title = "Look for Suspicious Paths"
        Description = "Search for suspicious executable paths, encoded commands, or unusual file locations in the registry."
        TaskAction = {
            Write-Host "Now let's search for suspicious paths that might indicate malicious activity." -ForegroundColor Yellow
            Write-Host "Common indicators include paths to unexpected executables, PowerShell encoded commands, and unusual file locations." -ForegroundColor Yellow
            
            Write-Host ""
            Write-Host "LEARNER TASK:" -ForegroundColor Magenta
            Write-Host "Instead of using the automated tool, let's practice searching for suspicious paths manually." -ForegroundColor Magenta
            Write-Host "This skill is important for real-world investigations where automated tools may not be available." -ForegroundColor Magenta
            Write-Host ""
            
            Write-Host "Here's a small PowerShell command to find registry values containing 'powershell' or '.exe':" -ForegroundColor Yellow
            Write-Host "Get-ChildItem -Path $artifactsPath -Recurse | ForEach-Object { Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue } | Where-Object { $_ -match 'powershell|\.exe' }" -ForegroundColor White
            
            $manualSearch = Read-Host "Would you like to try this command yourself? (Y/N)"
            if ($manualSearch -eq "Y") {
                Write-Host "Type or paste this command in the PowerShell prompt:" -ForegroundColor Yellow
                Write-Host "Get-ChildItem -Path '$artifactsPath' -Recurse | ForEach-Object { if (`$_.Property) { foreach (`$prop in `$_.Property) { `$value = `$_.GetValue(`$prop); if (`$value -match 'powershell|\.exe') { [PSCustomObject]@{ Path = `$_.PSPath; Property = `$prop; Value = `$value } } } } } | Format-Table -AutoSize" -ForegroundColor White
                
                $searchDone = Read-Host "Press Enter when you've executed the command and reviewed the results"
                
                Write-Host ""
                Write-Host "ANALYSIS QUESTION:" -ForegroundColor Magenta
                $answer = Read-Host "How many suspicious paths containing 'powershell' or '.exe' did you find? (Enter a number)"
                
                Write-Host ""
                Write-Host "The expected number is at least 4 suspicious paths:" -ForegroundColor Yellow
                Write-Host "1. Run key (GloboUpdater) with PowerShell encoded command" -ForegroundColor White
                Write-Host "2. Your custom run key with executable reference" -ForegroundColor White
                Write-Host "3. Scheduled task execution" -ForegroundColor White
                Write-Host "4. File association command execution" -ForegroundColor White
                
                if ($answer -ge 4) {
                    Write-Host "Great job! You found all or more of the expected suspicious paths." -ForegroundColor Green
                } else {
                    Write-Host "You may have missed some suspicious paths. Let's continue and we'll find more evidence." -ForegroundColor Yellow
                }
            } else {
                Write-Host "Let's use the forensic_tools.ps1 instead for an automated search." -ForegroundColor Yellow
                Write-Host "To search for suspicious paths, use forensic_tools.ps1 and select option 8 (Search for Suspicious Paths)" -ForegroundColor Yellow
                
                $runTools = Read-Host "Would you like to run forensic_tools.ps1 now? (Y/N)"
                if ($runTools -eq "Y") {
                    & "$PSScriptRoot\forensic_tools.ps1"
                }
            }
        }
    },
    @{
        Title = "Analyze Run Key Persistence"
        Description = "Examine Run and RunOnce keys for persistence mechanisms."
        TaskAction = {
            Write-Host "Run keys are a common persistence mechanism. Let's examine if the attackers used this technique." -ForegroundColor Yellow
            
            if (Test-Path "$artifactsPath\RunKey") {
                $runKeyPath = "$artifactsPath\RunKey"
                $runKey = Get-Item -Path $runKeyPath
                $properties = $runKey.Property
                
                if ($properties.Count -gt 0) {
                    Write-Host "Found potential Run key persistence:" -ForegroundColor Green
                    foreach ($prop in $properties | Where-Object { $_ -ne "Timestamp" }) {
                        $value = $runKey.GetValue($prop)
                        Write-Host "  Name: $prop" -ForegroundColor White
                        Write-Host "  Value: $value" -ForegroundColor White
                        Write-Host ""
                        
                        if ($value -match "powershell.*-EncodedCommand") {
                            Write-Host "Suspicious encoded PowerShell command detected!" -ForegroundColor Red
                            Write-Host "This is likely a persistence mechanism using base64 encoding to hide the actual command." -ForegroundColor Red
                            Write-Host ""
                            Write-Host "To decode this command, use forensic_tools.ps1 and select option 3 (Decode Base64 Value)" -ForegroundColor Yellow
                            
                            # Extract the encoded part
                            if ($value -match "-EncodedCommand\s+([A-Za-z0-9+/=]+)") {
                                $encodedCommand = $Matches[1]
                                Write-Host "Encoded part: $encodedCommand" -ForegroundColor White
                            }
                        }
                    }
                    
                    Write-Host ""
                    Write-Host "You should collect this as evidence using evidence_collector.ps1" -ForegroundColor Yellow
                } else {
                    Write-Host "No values found in Run key." -ForegroundColor Yellow
                }
            } else {
                Write-Host "No Run key found in artifacts. Continue to the next step." -ForegroundColor Yellow
            }
            
            $collectEvidence = Read-Host "Would you like to collect this evidence now using evidence_collector.ps1? (Y/N)"
            if ($collectEvidence -eq "Y") {
                & "$PSScriptRoot\evidence_collector.ps1"
            }
        }
    },
    @{
        Title = "Check for Service-Based Persistence"
        Description = "Examine service registry entries for signs of malicious services."
        TaskAction = {
            Write-Host "Services are another common persistence mechanism. Let's check for suspicious services." -ForegroundColor Yellow
            
            if (Test-Path "$artifactsPath\Services") {
                $servicesPath = "$artifactsPath\Services"
                $services = Get-ChildItem -Path $servicesPath
                
                if ($services.Count -gt 0) {
                    Write-Host "Found potential malicious services:" -ForegroundColor Green
                    foreach ($service in $services) {
                        $servicePath = $service.PSPath
                        $serviceItem = Get-Item -Path $servicePath
                        
                        $displayName = $serviceItem.GetValue("DisplayName")
                        $imagePath = $serviceItem.GetValue("ImagePath")
                        $description = $serviceItem.GetValue("Description")
                        $startType = $serviceItem.GetValue("Start")
                        
                        Write-Host "  Service: $($service.PSChildName)" -ForegroundColor White
                        Write-Host "  Display Name: $displayName" -ForegroundColor White
                        Write-Host "  Image Path: $imagePath" -ForegroundColor White
                        Write-Host "  Description: $description" -ForegroundColor White
                        Write-Host "  Start Type: $startType (2 = Automatic)" -ForegroundColor White
                        Write-Host ""
                        
                        if ($imagePath -match "svchost.exe.*-p") {
                            Write-Host "Suspicious service configuration detected!" -ForegroundColor Red
                            Write-Host "This service is configured to run with unusual parameters." -ForegroundColor Red
                        }
                    }
                    
                    Write-Host ""
                    Write-Host "You should collect this as evidence using evidence_collector.ps1" -ForegroundColor Yellow
                } else {
                    Write-Host "No services found in artifacts." -ForegroundColor Yellow
                }
            } else {
                Write-Host "No Services key found in artifacts. Continue to the next step." -ForegroundColor Yellow
            }
            
            $collectEvidence = Read-Host "Would you like to collect this evidence now using evidence_collector.ps1? (Y/N)"
            if ($collectEvidence -eq "Y") {
                & "$PSScriptRoot\evidence_collector.ps1"
            }
        }
    },
    @{
        Title = "Investigate WinLogon Modifications"
        Description = "Check for modifications to WinLogon registry entries that could allow persistence."
        TaskAction = {
            Write-Host "WinLogon registry keys control actions during the Windows logon process." -ForegroundColor Yellow
            Write-Host "Attackers can modify these to load malicious DLLs or executables." -ForegroundColor Yellow
            
            if (Test-Path "$artifactsPath\Winlogon") {
                $winlogonPath = "$artifactsPath\Winlogon"
                $winlogon = Get-Item -Path $winlogonPath
                $properties = $winlogon.Property
                
                if ($properties.Count -gt 0) {
                    Write-Host "Found potential WinLogon modifications:" -ForegroundColor Green
                    foreach ($prop in $properties | Where-Object { $_ -ne "Timestamp" }) {
                        $value = $winlogon.GetValue($prop)
                        Write-Host "  Name: $prop" -ForegroundColor White
                        Write-Host "  Value: $value" -ForegroundColor White
                        Write-Host ""
                        
                        if ($prop -eq "Userinit" -and $value -match ",") {
                            Write-Host "Suspicious Userinit configuration detected!" -ForegroundColor Red
                            Write-Host "Multiple executables in Userinit indicates potential persistence." -ForegroundColor Red
                            Write-Host "Normal value is 'C:\Windows\system32\userinit.exe' without additional executables." -ForegroundColor Red
                        }
                    }
                    
                    Write-Host ""
                    Write-Host "You should collect this as evidence using evidence_collector.ps1" -ForegroundColor Yellow
                } else {
                    Write-Host "No values found in Winlogon key." -ForegroundColor Yellow
                }
            } else {
                Write-Host "No Winlogon key found in artifacts. Continue to the next step." -ForegroundColor Yellow
            }
            
            $collectEvidence = Read-Host "Would you like to collect this evidence now using evidence_collector.ps1? (Y/N)"
            if ($collectEvidence -eq "Y") {
                & "$PSScriptRoot\evidence_collector.ps1"
            }
        }
    },
    @{
        Title = "Examine COM Object Hijacking"
        Description = "Look for evidence of COM object hijacking that could be used for persistence."
        TaskAction = {
            Write-Host "COM object hijacking is a technique where attackers modify COM object registry entries" -ForegroundColor Yellow
            Write-Host "to point to their malicious DLLs instead of legitimate ones." -ForegroundColor Yellow
            
            if (Test-Path "$artifactsPath\COMHijack") {
                $comHijackPath = "$artifactsPath\COMHijack"
                
                Write-Host "Found potential COM hijacking:" -ForegroundColor Green
                
                # Check if there are CLSID entries
                if (Test-Path "$comHijackPath\CLSID") {
                    $clsidPath = "$comHijackPath\CLSID"
                    $clsids = Get-ChildItem -Path $clsidPath
                    
                    foreach ($clsid in $clsids) {
                        Write-Host "  CLSID: $($clsid.PSChildName)" -ForegroundColor White
                        
                        # Check InprocServer32
                        if (Test-Path "$($clsid.PSPath)\InprocServer32") {
                            $serverPath = "$($clsid.PSPath)\InprocServer32"
                            $server = Get-Item -Path $serverPath
                            $defaultValue = $server.GetValue("")
                            
                            Write-Host "  Server Path: $defaultValue" -ForegroundColor White
                            Write-Host ""
                            
                            if ($defaultValue -match "\\Windows\\Tasks\\") {
                                Write-Host "Suspicious COM server location detected!" -ForegroundColor Red
                                Write-Host "COM server pointing to unusual location (Tasks folder)." -ForegroundColor Red
                            }
                        }
                    }
                    
                    Write-Host ""
                    Write-Host "You should collect this as evidence using evidence_collector.ps1" -ForegroundColor Yellow
                } else {
                    Write-Host "No CLSID entries found in COM hijack artifacts." -ForegroundColor Yellow
                }
            } else {
                Write-Host "No COM hijack key found in artifacts. Continue to the next step." -ForegroundColor Yellow
            }
            
            $collectEvidence = Read-Host "Would you like to collect this evidence now using evidence_collector.ps1? (Y/N)"
            if ($collectEvidence -eq "Y") {
                & "$PSScriptRoot\evidence_collector.ps1"
            }
        }
    },
    @{
        Title = "Check for AppInit_DLLs Persistence"
        Description = "Examine AppInit_DLLs registry entries for DLL injection persistence."
        TaskAction = {
            Write-Host "AppInit_DLLs is a registry value that causes DLLs to be loaded into every process that uses user32.dll." -ForegroundColor Yellow
            Write-Host "This is a powerful persistence mechanism that attackers can leverage." -ForegroundColor Yellow
            
            if (Test-Path "$artifactsPath\AppInit") {
                $appInitPath = "$artifactsPath\AppInit"
                $appInit = Get-Item -Path $appInitPath
                $properties = $appInit.Property
                
                if ($properties.Count -gt 0) {
                    Write-Host "Found potential AppInit_DLLs persistence:" -ForegroundColor Green
                    foreach ($prop in $properties | Where-Object { $_ -ne "Timestamp" }) {
                        $value = $appInit.GetValue($prop)
                        Write-Host "  Name: $prop" -ForegroundColor White
                        Write-Host "  Value: $value" -ForegroundColor White
                        Write-Host ""
                        
                        if ($prop -eq "AppInit_DLLs" -and $value -ne "") {
                            Write-Host "Suspicious AppInit_DLLs configuration detected!" -ForegroundColor Red
                            Write-Host "Any DLL listed in AppInit_DLLs will be loaded into processes that use user32.dll" -ForegroundColor Red
                            
                            # Check if LoadAppInit_DLLs is enabled
                            if ($appInit.GetValue("LoadAppInit_DLLs") -eq 1) {
                                Write-Host "LoadAppInit_DLLs is enabled (set to 1), confirming this persistence mechanism is active." -ForegroundColor Red
                            }
                        }
                    }
                    
                    Write-Host ""
                    Write-Host "You should collect this as evidence using evidence_collector.ps1" -ForegroundColor Yellow
                } else {
                    Write-Host "No values found in AppInit key." -ForegroundColor Yellow
                }
            } else {
                Write-Host "No AppInit key found in artifacts. Continue to the next step." -ForegroundColor Yellow
            }
            
            $collectEvidence = Read-Host "Would you like to collect this evidence now using evidence_collector.ps1? (Y/N)"
            if ($collectEvidence -eq "Y") {
                & "$PSScriptRoot\evidence_collector.ps1"
            }
        }
    },
    @{
        Title = "Analyze Boot Execute Persistence"
        Description = "Check for BootExecute registry entries that could allow persistence during system boot."
        TaskAction = {
            Write-Host "The BootExecute registry value lists programs that run during the Windows boot process." -ForegroundColor Yellow
            Write-Host "Attackers can add their malicious executables to this list for persistence." -ForegroundColor Yellow
            
            if (Test-Path "$artifactsPath\BootExecute") {
                $bootExecPath = "$artifactsPath\BootExecute"
                $bootExec = Get-Item -Path $bootExecPath
                $properties = $bootExec.Property
                
                if ($properties.Count -gt 0) {
                    Write-Host "Found potential BootExecute persistence:" -ForegroundColor Green
                    foreach ($prop in $properties | Where-Object { $_ -ne "Timestamp" }) {
                        $value = $bootExec.GetValue($prop)
                        
                        if ($prop -eq "BootExecute") {
                            Write-Host "  Name: $prop" -ForegroundColor White
                            if ($value -is [array]) {
                                Write-Host "  Value (MultiString):" -ForegroundColor White
                                foreach ($item in $value) {
                                    Write-Host "    $item" -ForegroundColor White
                                }
                            } else {
                                Write-Host "  Value: $value" -ForegroundColor White
                            }
                            Write-Host ""
                            
                            # Check for suspicious entries
                            $suspicious = $false
                            foreach ($item in $value) {
                                if ($item -ne "autocheck autochk *" -and $item -notmatch "^autocheck ") {
                                    $suspicious = $true
                                    Write-Host "Suspicious BootExecute entry detected: $item" -ForegroundColor Red
                                    Write-Host "Normal value should only contain 'autocheck autochk *'" -ForegroundColor Red
                                }
                            }
                            
                            if (-not $suspicious) {
                                Write-Host "No suspicious entries found in BootExecute." -ForegroundColor Yellow
                            }
                        } else {
                            Write-Host "  Name: $prop" -ForegroundColor White
                            Write-Host "  Value: $value" -ForegroundColor White
                            Write-Host ""
                        }
                    }
                    
                    Write-Host ""
                    Write-Host "You should collect this as evidence using evidence_collector.ps1" -ForegroundColor Yellow
                } else {
                    Write-Host "No values found in BootExecute key." -ForegroundColor Yellow
                }
            } else {
                Write-Host "No BootExecute key found in artifacts. Continue to the next step." -ForegroundColor Yellow
            }
            
            $collectEvidence = Read-Host "Would you like to collect this evidence now using evidence_collector.ps1? (Y/N)"
            if ($collectEvidence -eq "Y") {
                & "$PSScriptRoot\evidence_collector.ps1"
            }
        }
    },
    @{
        Title = "Examine File Association Hijacking"
        Description = "Look for evidence of file association hijacking that could be used to execute malicious code."
        TaskAction = {
            Write-Host "File association hijacking involves modifying registry entries that control what happens when a file is opened." -ForegroundColor Yellow
            Write-Host "Attackers can modify these to execute their malicious code when a user opens a file." -ForegroundColor Yellow
            
            if (Test-Path "$artifactsPath\FileAssoc") {
                $fileAssocPath = "$artifactsPath\FileAssoc"
                $extensions = Get-ChildItem -Path $fileAssocPath
                
                if ($extensions.Count -gt 0) {
                    Write-Host "Found potential file association hijacking:" -ForegroundColor Green
                    foreach ($ext in $extensions) {
                        # Check for command entry
                        $commandPath = "$($ext.PSPath)\shell\open\command"
                        if (Test-Path $commandPath) {
                            $command = Get-Item -Path $commandPath
                            $defaultValue = $command.GetValue("")
                            
                            Write-Host "  Extension: $($ext.PSChildName)" -ForegroundColor White
                            Write-Host "  Command: $defaultValue" -ForegroundColor White
                            Write-Host ""
                            
                            if ($defaultValue -match "&") {
                                Write-Host "Suspicious command detected!" -ForegroundColor Red
                                Write-Host "Command contains the '&' character, indicating multiple commands will be executed." -ForegroundColor Red
                                Write-Host "This is likely a technique to execute malicious code when a file is opened." -ForegroundColor Red
                            }
                        }
                    }
                    
                    Write-Host ""
                    Write-Host "You should collect this as evidence using evidence_collector.ps1" -ForegroundColor Yellow
                } else {
                    Write-Host "No file extensions found in FileAssoc key." -ForegroundColor Yellow
                }
            } else {
                Write-Host "No FileAssoc key found in artifacts. Continue to the next step." -ForegroundColor Yellow
            }
            
            $collectEvidence = Read-Host "Would you like to collect this evidence now using evidence_collector.ps1? (Y/N)"
            if ($collectEvidence -eq "Y") {
                & "$PSScriptRoot\evidence_collector.ps1"
            }
        }
    },
    @{
        Title = "Generate Evidence Report"
        Description = "Generate a comprehensive report of your findings."
        TaskAction = {
            Write-Host "Now that you've collected evidence of various persistence mechanisms," -ForegroundColor Yellow
            Write-Host "it's time to generate a comprehensive report of your findings." -ForegroundColor Yellow
            
            Write-Host ""
            Write-Host "Use evidence_collector.ps1 and select option 3 (Generate HTML Evidence Report)" -ForegroundColor Yellow
            
            $runCollector = Read-Host "Would you like to run evidence_collector.ps1 now? (Y/N)"
            if ($runCollector -eq "Y") {
                & "$PSScriptRoot\evidence_collector.ps1"
            }
        }
    }
)

# Function to run the guided analysis
function Start-GuidedAnalysis {
    for ($i = 0; $i -lt $steps.Count; $i++) {
        $step = $steps[$i]
        
        Clear-Host
        Write-Host "========================================================" -ForegroundColor Cyan
        Write-Host "Registry Forensics Lab: Tracking the Dark Kittens" -ForegroundColor Cyan
        Write-Host "Guided Analysis Steps" -ForegroundColor Cyan
        Write-Host "========================================================" -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "Step $($i+1) of $($steps.Count): $($step.Title)" -ForegroundColor Yellow
        Write-Host $step.Description -ForegroundColor White
        Write-Host ""
        
        # Execute the step's action
        & $step.TaskAction
        
        # If not the last step, ask to continue
        if ($i -lt $steps.Count - 1) {
            Write-Host ""
            Write-Host "Press Enter to continue to the next step, or 'Q' to quit..." -ForegroundColor Yellow
            $key = Read-Host
            
            if ($key -eq "Q") {
                Write-Host "Guided analysis stopped. You can resume from this point later." -ForegroundColor Yellow
                return
            }
        } else {
            Write-Host ""
            Write-Host "You have completed all the guided analysis steps." -ForegroundColor Green
            Write-Host "Make sure to validate your findings using the validation.ps1 script." -ForegroundColor Green
        }
    }
}

# Start the guided analysis
Start-GuidedAnalysis
