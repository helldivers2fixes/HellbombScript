# 💣Hellbomb💣 Script for fixing Helldivers 2 Issues

![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/004ccb81-356a-4d89-80f5-63363060b561)

## How to Use:

 1. **Open** PowerShell (no need to run as an Administrator)

    Note: For a few users, the script errors when running the **Get-NetFirewallRule** command-let (which only reads Firewall rules. No changes are made to the firewall). If this happens, you may need to run PowerShell as Administrator (Before opening PowerShell, right-click it and click "Run as Administrator"). This _shouldn't_ be the norm for most users, and should be avoided unless absolutely necessary.
 3. Click on [the Hell Bomb PowerShell Script](https://github.com/helldivers2fixes/HellbombScript/blob/main/Hellbomb%20Script.ps1)
 4. **Copy** entire script by clicking the copy button in the top right by the script
    
       <img src = "https://github.com/helldivers2fixes/HellbombScript/assets/166264070/5a600b1c-64f6-4956-ba2f-f82c9a317f81" height=50>
       
 6. **Paste** into PowerShell Must use Ctrl + V (Right-clicking in terminal to paste will cause errors if running as Admin).
 7. Acknowledge the warning prompt and click **Paste Anyway**
 8. Press **Enter** until the program runs, and the menu appears (depending on how you paste you may have to press **Enter** a couple of times)
 9. Choose a selection using the corresponding letters
 10. Expect Administrator prompts depending on what you're doing. Check to make sure the prompts match what you wanted to do.

## Security Info:

**VirusTotal Results:** https://www.virustotal.com/gui/file/1a7de4fc5f00c1408298a8dc61b745b1f501d6a04890d8962e8d4722f55c4205

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``1a7de4fc5f00c1408298a8dc61b745b1f501d6a04890d8962e8d4722f55c4205``.

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 1a7de4fc5f00c1408298a8dc61b745b1f501d6a04890d8962e8d4722f55c4205``
5. The statement should return/evaluate to ``True``

**Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/1a7de4fc5f00c1408298a8dc61b745b1f501d6a04890d8962e8d4722f55c4205

No security software should detect the script as malicious.
## Screenshots:

Running the Status Checks:
![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/6b922c41-39bc-41e4-b535-bfd81e6f47a4)


Selecting Help (?) from the menu:
![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/02cacb2b-bc4a-4cd9-9447-949b40c1630a)


