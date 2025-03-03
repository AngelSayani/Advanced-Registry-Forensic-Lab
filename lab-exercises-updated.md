# Registry Forensics Lab: Exercises and Tasks

This lab provides a series of hands-on exercises and tasks to complete throughout the Registry Forensics Lab. These exercises are designed to reinforce your understanding of registry-based persistence techniques and forensic analysis.

## Lab Execution Step-by-Step Guide

Follow these detailed steps to complete the lab. Each step includes specific instructions on what to do and how to do it.

### Phase 1: Environment Setup

1. **Download and Extract Lab Files**
   - Create a folder named "RegistryForensicsLab" on your desktop
   - Download all lab files to this folder
   - Make sure all files have .ps1 extension (except README.md and LAB_EXERCISES.md)

2. **Open PowerShell as Administrator**
   - Right-click on the Start menu
   - Select "Windows PowerShell (Admin)"
   - When the UAC prompt appears, click "Yes"

3. **Navigate to Lab Directory**
   - Type: `cd "C:\Registry Forensics Lab"`
   - Press Enter

4. **Set PowerShell Execution Policy**
   - Type: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process`
   - Press Enter
   - Type "A" when prompted to confirm

5. **Run the Setup Script**
   - Type: `.\setup.ps1`
   - Press Enter
   - The script will automatically set up the lab environment

### Phase 2: Cloud Infrastructure Review

6. **Review the Terraform Files**
   - Open the `terraform` folder in your lab directory
   - Open each of these files in a text editor (like Notepad++ or VS Code):
     - `main.tf` - Main infrastructure definition, review the AWS resources being deployed
     - `variables.tf` - Configuration variables, look at the configuration variables
     - `security.tf` -  Security settings, examine the security settings carefully
     - `outputs.tf` - Outputs and connection information, understand what information is provided after deployment

7. **Create Review Answers**
   - Create a new text file: `terraform/review_answers.txt`
   - Answer these specific questions in the file:
     - What EC2 instance type is being used for the lab workstation?
     - What security risks can you identify in the security.tf file?
     - How would you improve the security of this cloud deployment?
     - Why would a cloud deployment be useful for this type of lab?
     - What additional AWS services could enhance security monitoring?
   - Save the file

8. **Verify Terraform Review Completion**
   - Run this PowerShell command to verify:
   ```powershell
   if (Test-Path "./terraform/review_answers.txt") { 
     Write-Host "Cloud infrastructure review completed!" -ForegroundColor Green 
   } else { 
     Write-Host "Please complete the cloud infrastructure review task." -ForegroundColor Red 
   }
   ```

### Phase 3: Creating Artifacts (create_artifacts.ps1)

9. **Run the Artifacts Creation Script**
   - Type: `.\create_artifacts.ps1`
   - Press Enter
   - When prompted to create a custom run key:
     - Enter a name for your run key (e.g., "SystemUpdate"), to create your own malicious run key entry when prompted
     - Choose a payload type (1, 2, or 3)
   - When prompted to create a file association hijack:
     - Choose a file extension from the options (1-5) to create a file association hijack for a file extension of your choice
     - Enter your custom command or press Enter for default
   - Complete the quiz by answering each question (take the persistence techniques quiz)
     - Select your answer (1-4) for each question 
     - Your quiz results will be saved automatically

### Phase 4: Learning Persistence Techniques

10. **Study Registry Persistence Methods**
   - Type: `.\persistence_simulator.ps1`
   - Press Enter
   - For each persistence technique shown:
     - Read the description carefully
     - Note the registry path and how it works
     - Observe the examples and detection methods
   - Keep the PowerShell window open or take notes for reference

### Phase 5: Conducting the Investigation

11. **Follow the Guided Analysis (analysis_guide.ps1)**
   - Type: `.\analysis_guide.ps1`
   - Press Enter
   - For each step in the guided analysis:
     - Read the instructions carefully
     - Perform the required actions
     - Answer any questions when prompted
   - When asked to search for suspicious paths manually:
     - Type or paste the provided PowerShell command
     - Review the results and count the suspicious paths
     - Enter the number when prompted
   - When instructed to collect evidence:
     - Type "Y" to run the evidence collector
     - Follow the evidence collection process as guided

12. **Identify Malicious Registry Entries (forensic_tools.ps1)**
   - Type: `.\forensic_tools.ps1`
   - Press Enter
   - When the menu appears, try each of these tasks:
     - Option 1: Examine Registry Key
       * Enter: `HKCU:\Software\DarkKittensLab\Artifacts\RunKey`
       * Review the results
     - Option 3: Decode Base64 Value
       * Copy the encoded command from the RunKey value
       * Paste it when prompted
       * Review the decoded command to understand what it does
     - Option 8: Search for Suspicious Paths
       * Review all paths flagged as suspicious
     - Option 9: Check Value Data Type
       * Enter: `HKCU:\Software\DarkKittensLab\Artifacts\RunKey`
       * Enter: `GloboUpdater`
       * Review the detailed analysis of this value
   - Use the "Examine Registry Key" feature to inspect the following keys:

    HKCU:\Software\DarkKittensLab\Artifacts\RunKey
    HKCU:\Software\DarkKittensLab\Artifacts\Services\GloboSync
    HKCU:\Software\DarkKittensLab\Artifacts\FileAssoc

   - Exit the tool by selecting option 10 when done

### Phase 6: Collecting and Documenting Evidence (evidence_collector.ps1)

13. **Collect Evidence**
    - Type: `.\evidence_collector.ps1`
    - Press Enter
    - Select option 1 to collect evidence
    - For the guided Run key evidence collection:
      * Review the evidence information displayed
      * Complete the evidence form with detailed information
    - For the independent evidence collection:
      * Choose another artifact (e.g., WinLogon or Services)
      * Complete the evidence form:
        - Step 1: Enter the correct registry path
        - Step 2: Select the appropriate evidence type
        - Step 3: Write a detailed description
        - Step 4: Add your investigative notes
    - Collect at least 3 different types of evidence
    - Exit and return to the main menu

14. **Generate an Evidence Report**
    - In the evidence collector, select option 3
    - Enter a title for your report (e.g., "Dark Kittens Incident - Registry Forensics Report")
    - Enter your name as the investigator
    - When the report is generated, it will open in your browser
    - Review the report carefully
    - Answer the reflection questions:
      * What key information is included that management would need?
      * How would you improve this report for a real-world scenario?

   **Document Findings**
   **Your evidence report should include:**
   - Run key persistence mechanism
   - Service-based persistence
   - File association hijacking

15. **Validate Your Findings (validation.ps1)**
    - Return to PowerShell
    - Type: `.\validation.ps1`
    - Press Enter
    - Review your score and identified techniques
    - If your score is below 70%, go back to evidence collection
    - If your score is 70% or higher, proceed to the next step

### Phase 7: Apply Findings to Cloud Security

16. **Improve Cloud Infrastructure Security**
    - Based on your registry forensics findings, open: `terraform/security_improvements.tf`
    - Review the example security resource at the top of the file
    - Add at least three new Terraform resources that would enhance cloud security
    - Focus on mitigating the persistence techniques you discovered in the lab
    - Save your changes to the file
    - Example improvement to add:
    ```
    resource "aws_config_configuration_recorder" "forensics_lab_recorder" {
      name     = "forensics-lab-recorder"
      role_arn = aws_iam_role.forensics_config_role.arn
      recording_group {
        all_supported = true
        include_global_resource_types = true
      }
    }
    ```

17. **Verify Security Improvements**
    - Run the validation script again:
    - Type: `.\validation.ps1`
    - Press Enter
    - Check that your security improvements are recognized
    - Your score should increase if they are properly implemented
   
## Phase 8: Registry Differential Analysis (registry_diff.ps1)

### Exercise 8: Compare Registry States

1. Run `registry_diff.ps1` as Administrator
2. Take a snapshot of the `HKCU:\Software\DarkKittensLab\Artifacts` registry key
3. Create a simple modification to the registry (add a new value or modify an existing one)
4. Take another snapshot
5. Compare the two snapshots to see the differences
6. Export the registry structure to CSV for examination

**Learning Objective:** Learn how to identify changes in the registry that might indicate malicious activity.

### Exercise 9: Follow a Structured Analysis

1. Run `analysis_guide.ps1` as Administrator
2. Follow the guided analysis steps to investigate all persistence mechanisms
3. Answer the analysis questions at each step
4. Make sure to manually examine keys rather than just accepting the automated analysis

**Questions to answer during analysis:**
1. What indicators suggest the Run key entry is malicious?
2. How does file association hijacking work to maintain persistence?
3. What makes the WinLogon helper DLL suspicious?

**Learning Objective:** Develop a methodical approach to security investigation following industry best practices.

## Phase 10: Cloud Security Considerations

### Exercise 10: Apply On-premises Findings to Cloud Security

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

### Phase 11: Cleanup and Reflection

18. **Clean up the Lab Environment**
    - Type: `.\cleanup.ps1`
    - Press Enter
    - Type "Y" when prompted to confirm cleanup
    - Note that your evidence reports will be preserved in your Documents folder

19. **Final Steps**
    - Review your quiz results and evidence report
    - Compare your findings with the expected persistence techniques
    - Complete any tasks in the LAB_EXERCISES.md file you haven't finished


## Optional Challenge Exercise: Create Your Own Detection

This exercise is for advanced learners who want to go beyond what we've learned so far.

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
