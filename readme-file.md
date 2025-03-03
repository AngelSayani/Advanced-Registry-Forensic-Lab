# Registry Forensics Lab: Tracking the Dark Kittens

## Overview

The notorious hacking group Dark Kittens has struck again! Globomantics, an international conglomerate that runs an artificial island in the Gulf of Mexico for their "ideal society" experiment, has fallen victim to repeated attacks. As a security analyst for Globomantics, your task is to investigate the compromised system, identify how the Dark Kittens maintain persistence, and collect forensic evidence of their activities.

This lab focuses on Windows Registry forensics, providing a safe environment to learn and practice identifying common registry-based persistence techniques used by attackers.

## Lab Environment

This lab is designed to run entirely on a Windows 10 Home system with PowerShell, without requiring any virtual machines or cloud resources. The lab creates a safe, isolated testing environment within the Windows Registry that simulates a compromised system without affecting your actual system's security or stability.

## Prerequisites

- Windows 10 Home (or any edition)
- PowerShell 5.1 or later
- Administrator access to your local machine

## Network Diagram

This lab runs entirely on your local machine and does not require any network connections. The environment is contained within a dedicated registry key (`HKCU:\Software\DarkKittensLab`) that simulates various registry artifacts of a compromised system.

```
+-----------------------------------------------------+
|                  Your Windows 10 PC                 |
|                                                     |
|  +-----------------------------------------------+  |
|  |               PowerShell Scripts              |  |
|  +-----------------------------------------------+  |
|  |                                               |  |
|  |  +-------------------+  +------------------+  |  |
|  |  | Registry Artifacts |  | Forensic Tools  |  |  |
|  |  | (Simulated)       |  |                  |  |  |
|  |  +-------------------+  +------------------+  |  |
|  |                                               |  |
|  |  +-------------------+  +------------------+  |  |
|  |  | Evidence          |  | Reports          |  |  |
|  |  | Collection        |  |                  |  |  |
|  |  +-------------------+  +------------------+  |  |
|  |                                               |  |
|  +-----------------------------------------------+  |
|                                                     |
+-----------------------------------------------------+
```

## Lab Files

1. `README.md` - This file with lab instructions and overview
2. `setup.ps1` - Sets up the safe testing environment
3. `create_artifacts.ps1` - Creates simulated malicious registry artifacts
4. `persistence_simulator.ps1` - Explains common registry persistence techniques
5. `forensic_tools.ps1` - Provides tools for registry analysis
6. `registry_diff.ps1` - Compares registry states to identify changes
7. `evidence_collector.ps1` - Collects and documents registry findings
8. `cleanup.ps1` - Removes all test registry keys
9. `analysis_guide.ps1` - Provides guided analysis steps
10. `validation.ps1` - Validates findings and progress
11. `LAB_EXERCISES.md` - Detailed exercise guide with specific tasks
12. `terraform/main.tf` - Infrastructure definition for cloud deployment
13. `terraform/variables.tf` - Variables for Terraform configuration
14. `terraform/security.tf` - Security group and IAM configurations
15. `terraform/outputs.tf` - Outputs from Terraform deployment
16. `terraform/security_improvements.tf` - File for learners to add security enhancements

## Learning Objectives

By completing this lab, you will:

1. Understand common registry-based persistence techniques used by attackers
2. Learn to identify suspicious registry keys and values
3. Practice using PowerShell for registry forensic analysis
4. Develop skills in evidence collection and documentation
5. Experience the process of investigating a compromised system
6. Create and document your own simulated malicious registry entries
7. Generate professional incident response reports
8. Apply critical thinking to security analysis scenarios
9. Develop skills in differential registry analysis
10. Practice manual investigation techniques essential for real-world forensics

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
   - Type "Y" when prompted to confirm

5. **Run the Setup Script**
   - Type: `.\setup.ps1`
   - Press Enter
   - The script will automatically set up the lab environment

### Phase 1.5: Cloud Infrastructure Review

6. **Review the Terraform Files**
   - Open the `terraform` folder in your lab directory
   - Open each of these files in a text editor (like Notepad++ or VS Code):
     - `main.tf` - Review the AWS resources being deployed
     - `variables.tf` - Look at the configuration variables
     - `security.tf` - Examine the security settings carefully
     - `outputs.tf` - Understand what information is provided after deployment

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

### Phase 2: Creating Artifacts

9. **Run the Artifacts Creation Script**
   - Type: `.\create_artifacts.ps1`
   - Press Enter
   - When prompted to create a custom run key:
     - Enter a name for your run key (e.g., "SystemUpdate")
     - Choose a payload type (1, 2, or 3)
   - When prompted to create a file association hijack:
     - Choose a file extension from the options (1-5)
     - Enter your custom command or press Enter for default
   - Complete the quiz by answering each question
     - Select your answer (1-4) for each question
     - Your quiz results will be saved automatically

### Phase 3: Learning Persistence Techniques

10. **Study Registry Persistence Methods**
   - Type: `.\persistence_simulator.ps1`
   - Press Enter
   - For each persistence technique shown:
     - Read the description carefully
     - Note the registry path and how it works
     - Observe the examples and detection methods
   - Keep the PowerShell window open or take notes for reference

### Phase 4: Conducting the Investigation

11. **Follow the Guided Analysis**
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

12. **Use the Forensic Tools**
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
   - Exit the tool by selecting option 10 when done

### Phase 5: Collecting and Documenting Evidence

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

15. **Validate Your Findings**
    - Return to PowerShell
    - Type: `.\validation.ps1`
    - Press Enter
    - Review your score and identified techniques
    - If your score is below 70%, go back to evidence collection
    - If your score is 70% or higher, proceed to the next step

### Phase 6: Apply Findings to Cloud Security

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

### Phase 7: Cleanup and Reflection

18. **Clean up the Lab Environment**
    - Type: `.\cleanup.ps1`
    - Press Enter
    - Type "Y" when prompted to confirm cleanup
    - Note that your evidence reports will be preserved in your Documents folder

19. **Final Steps**
    - Review your quiz results and evidence report
    - Compare your findings with the expected persistence techniques
    - Complete any tasks in the LAB_EXERCISES.md file you haven't finished

## Troubleshooting Common Issues

- **PowerShell Execution Issues**: If scripts won't run, make sure you've set the execution policy and are running as Administrator
- **Registry Access Errors**: Ensure you're running with Administrator privileges
- **Missing Artifacts**: If artifacts aren't appearing, confirm you ran setup.ps1 before other scripts
- **Report Generation Problems**: Make sure you've collected at least 3 pieces of evidence before generating a report
- **Terraform Review Validation**: If validation.ps1 keeps failing, check that you've created terraform/review_answers.txt with answers to all questions

For any other issues, refer to the LAB_EXERCISES.md file for more detailed instructions on each task.

## Safety Considerations

This lab has been designed to be completely safe for your host system. All registry modifications are contained to a dedicated test key under `HKCU:\Software\DarkKittensLab`, which will not affect system operations. The cleanup script will remove all test registry keys created during the lab.

## Expected Completion Time

The lab is designed to take approximately 15 minutes to complete once the environment is set up. However, you can spend additional time exploring the simulated artifacts and learning about registry-based persistence techniques.

## Success Criteria

You will successfully complete this lab when you can:

1. Identify at least 5 different registry-based persistence mechanisms
2. Document the registry paths and values associated with each technique
3. Explain how each technique works to maintain persistence
4. Generate a comprehensive forensic report of your findings

## Support

If you encounter any issues with the lab, please check the following:

1. Ensure you're running PowerShell as Administrator
2. Verify that all the lab files are in the same directory
3. Make sure you run the scripts in the recommended order
