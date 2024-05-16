# 💣Hellbomb💣 Script for fixing Helldivers 2 Issues

![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/cc30472b-83ab-4b2f-90b9-2f1ec2170e50)



## How to Use:

 1. **Open** PowerShell (no need to run as an Administrator)

    Note: For a few users, the script errors when running the **Get-NetFirewallRule** command-let (which only reads Firewall rules. No changes are made to the firewall). If this happens, you may need to run PowerShell as Administrator (Before opening PowerShell, right-click it and click "Run as Administrator"). This _shouldn't_ be the norm for most users, and should be avoided unless absolutley necessary.
 3. Click on [the Hell Bomb PowerShell Script](https://github.com/helldivers2fixes/HellbombScript/blob/main/Hellbomb%20Script.ps1)
 4. **Copy** entire script by clicking the copy button in the top right by the script
    
       <img src = "https://github.com/helldivers2fixes/HellbombScript/assets/166264070/5a600b1c-64f6-4956-ba2f-f82c9a317f81" height=50>
       
 6. **Paste** into PowerShell (Right-clicking in terminal **only** will paste).
 7. Acknolwedge the warning prompt and click **Paste Anyway**
 8. Press **Enter** until the program runs, and the menu appears (depending on how you paste you may have to press **Enter** a couple of times)
 9. Choose a selection using the corresponding letters
 10. Expect Administrator prompts depending on what you're doing. Check to make sure the prompts match what you wanted to do.

## Security Info:

VirusTotal results: https://www.virustotal.com/gui/file/a0555b7cdbd3cc4a1017c7e4a422e672a3d0c7dc1ab42bc41b495ed4f4fba9aa

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``a0555b7cdbd3cc4a1017c7e4a422e672a3d0c7dc1ab42bc41b495ed4f4fba9aa``.

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq a0555b7cdbd3cc4a1017c7e4a422e672a3d0c7dc1ab42bc41b495ed4f4fba9aa``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.
## Screenshots:

Running the Status Checks:
![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/f35b87dc-0329-431f-bc30-1dd4b89f366c)

Selecting Help (?) from the menu:

![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/fb9b7443-e688-4347-83c1-62c9c51b92b6)
