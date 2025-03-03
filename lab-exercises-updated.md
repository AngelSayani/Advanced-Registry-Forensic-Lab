# Registry Forensics Lab: Exercises and Tasks

This lab provides a series of hands-on exercises and tasks to complete throughout the Registry Forensics Lab. These exercises are designed to reinforce your understanding of registry-based persistence techniques and forensic analysis.

## Phase 1: Environment Setup

### Exercise 1: Configure Lab Environment

1. Run `setup.ps1` as Administrator
2. Create three new folders under the lab directory:
   - `Registry-based` - For registry persistence artifacts
   - `File-based` - For file-based persistence artifacts
   - `WMI-based` - For WMI-based persistence artifacts
3. Configure detection sensitivity in the registry to your preferred level:
   - Low: Fewer detections, minimal false positives
   - Medium: Balanced approach (recommended for beginners)
   - High: Aggressive detection, may produce false positives
4. Enable advanced detection by changing the registry value

**Learning Objective:** Understand how configuration settings in a security tool affect detection capabilities.

## Phase 2: Cloud Infrastructure Review

### Exercise 2: Review Cloud Deployment Option

Before proceeding to create artifacts, review the Terraform files in the `terraform/` directory to understand how this lab could be deployed in a cloud environment.

1. Open and review the following files:
   - `terraform/main.tf` - Main infrastructure definition
   - `terraform/variables.tf` - Configuration variables
   - `terraform/security.tf` - Security settings
   - `terraform/outputs.tf` - Outputs and connection information

2. Create a file named `terraform/review_answers.txt` and answer the following questions:
   - What EC2 instance type is being used for the lab workstation?
   - What security risks can you identify in the security.tf file?
   - How would you improve the security of this cloud deployment?
   - Why would a cloud deployment be useful for this type of lab?
   - What additional AWS services could enhance security monitoring?

3. Run this PowerShell command to verify your completion of this task:
   ```powershell
   if (Test-Path "./terraform/review_answers.txt") { 
     Write-Host "Cloud infrastructure review completed!" -ForegroundColor Green 
   } else { 
     Write-Host "Please complete the cloud infrastructure review task." -ForegroundColor Red 
   }
   ```

**Learning Objective:** Understand how on-premises forensic concepts translate to cloud environments and identify security considerations in infrastructure-as-code.

## Phase 3: Artifact Creation

### Exercise 3: Create Custom Persistence Mechanisms

1. Run `create_artifacts.ps1` as Administrator
2. Create your own malicious run key entry when prompted
3. Create a file association hijack for a file extension of your choice
4. Take the persistence techniques quiz

**Learning Objective:** Understand how attackers establish various persistence mechanisms in Windows Registry.

## Phase 4: Forensic Analysis

### Exercise 4: Identify Malicious Registry Entries

1. Run `forensic_tools.ps1` as Administrator
2. Use the "Search for Suspicious Paths" feature to identify potentially malicious paths
3. Use the "Decode Base64 Value" feature to decode the encoded PowerShell command
4. Use the "Examine Registry Key" feature to inspect the following keys:
   - `HKCU:\Software\DarkKittensLab\Artifacts\RunKey`
   - `HKCU:\Software\DarkKittensLab\Artifacts\Services\GloboSync`
   - `HKCU:\Software\DarkKittensLab\Artifacts\FileAssoc`

**Learning Objective:** Develop skills in identifying suspicious registry entries and understanding attack indicators.

## Phase 5: Registry Differential Analysis

### Exercise 5: Compare Registry States

1. Run `registry_diff.ps1` as Administrator
2. Take a snapshot of the `HKCU:\Software\DarkKittensLab\Artifacts` registry key
3. Create a simple modification to the registry (add a new value or modify an existing one)
4. Take another snapshot
5. Compare the two snapshots to see the differences
6. Export the registry structure to CSV for examination

**Learning Objective:** Learn how to identify changes in the registry that might indicate malicious activity.

## Phase 6: Evidence Collection

### Exercise 6: Document Findings

1. Run `evidence_collector.ps1` as Administrator
2. Collect evidence for at least three different persistence mechanisms
3. Generate an HTML evidence report with your findings
4. Review the report to ensure all critical information is included

**Your evidence report should include:**
- Run key persistence mechanism
- Service-based persistence
- File association hijacking

**Learning Objective:** Practice proper documentation of security findings for incident response.

## Phase 7: Guided Analysis

### Exercise 7: Follow a Structured Analysis

1. Run `analysis_guide.ps1` as Administrator
2. Follow the guided analysis steps to investigate all persistence mechanisms
3. Answer the analysis questions at each step
4. Make sure to manually examine keys rather than just accepting the automated analysis

**Questions to answer during analysis:**
1. What indicators suggest the Run key entry is malicious?
2. How does file association hijacking work to maintain persistence?
3. What makes the WinLogon helper DLL suspicious?

**Learning Objective:** Develop a methodical approach to security investigation following industry best practices.

## Phase 8: Validation and Verification

### Exercise 8: Validate Findings

1. Complete all previous exercises
2. Run `validation.ps1` as Administrator
3. Ensure you've identified at least 5 different persistence techniques
4. Aim for a score of at least 70%

**Learning Objective:** Verify the completeness of a security investigation to ensure no threats are missed.

## Phase 9: Cloud Security Considerations

### Exercise 9: Apply On-premises Findings to Cloud Security

1. Based on your registry forensics investigation, open the file `terraform/security_improvements.tf` in a text editor
2. Write at least three Terraform resources that would enhance the security of the cloud deployment
3. Focus on how the persistence techniques you discovered in the lab could be mitigated in a cloud environment
4. Save your changes

Example resource to get you started:
```terraform
# Example: Add a security monitoring solution
resource "aws_guardduty_detector" "forensics_lab_detector" {
  enable = true
}
```

**Learning Objective:** Translate on-premises security findings to cloud security improvements.

## Challenge Exercise: Create Your Own Detection

This exercise is for advanced learners who want to go beyond the basics.

1. Create a new PowerShell script called `custom_detection.ps1`
2. Write code to detect one of the persistence mechanisms not explicitly covered in the lab
3. Test your detection script against the artifacts
4. Document how your detection method works

**Sample Script Structure:**
```powershell
# custom_detection.ps1
Write-Host "Custom Persistence Detection Tool" -ForegroundColor Cyan
Write-Host "--------------------------------" -ForegroundColor Cyan

# Your detection code here
# Example: Detect COM Object Hijacking

$artifactsPath = "HKCU:\Software\DarkKittensLab\Artifacts"

# Your detection logic
function Detect-COMHijacking {
    # Your implementation
}

# Execute your detection
Detect-COMHijacking
```

## Final Submission

After completing all exercises, ensure you've:

1. Created a comprehensive HTML report of your findings
2. Saved your quiz results
3. Documented at least 5 different persistence techniques
4. Created the three required persistence category folders
5. Validated your findings using the validation script
6. Completed the cloud infrastructure review
7. Added security improvements to the Terraform configuration

This will ensure you've mastered both the core concepts of registry forensics and understood how these security concerns translate to cloud environments.
