# 💣Hellbomb💣 Script for fixing Helldivers 2 Issues

![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/cc30472b-83ab-4b2f-90b9-2f1ec2170e50)



## How to Use:

 1. **Open** PowerShell (no need to run as an Administrator)
    For a few users, the script errors when running the **Get-NetFirewallRule** command-let (which only reads Firewall rules. No changes are made to the firewall). If this happens, you may need to run PowerShell as Administrator. This _shouldn't_ be the norm for most users though.
 3. Click on [the PowerShell script]([url](https://github.com/helldivers2fixes/HellbombScript/blob/main/Hellbomb%20Script.ps1))
 4. **Copy** entire script by clicking the copy button in the top right by the script
    
       <img src = "https://github.com/helldivers2fixes/HellbombScript/assets/166264070/5a600b1c-64f6-4956-ba2f-f82c9a317f81" height=50>
       
 6. **Paste** into PowerShell (right-clicking **only** will paste)
 7. Press **Enter** until the program runs, and the menu appears (depending on how you paste you may have to press **Enter** a couple of times)
 8. Choose a selection using the corresponding letters
 9. Expect Administrator prompts depending on what you're doing. Check to make sure the prompts match what you wanted to do.

**Security Info:**

VirusTotal results: https://www.virustotal.com/gui/file/7d03fe183c4f632671f7a0f508ffbaac5f32a22f19bb298e23944fdd0f19eccb for HellbombScript.ps1
You can check the File Hash by:

1. Saving the script as a .ps1
2. Changing to the directory where the script is saved
3. Running ``Get-FileHash 'Hellbomb Script.ps1' -eq 7d03fe183c4f632671f7a0f508ffbaac5f32a22f19bb298e23944fdd0f19eccb`` should return ``True``

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``7d03fe183c4f632671f7a0f508ffbaac5f32a22f19bb298e23944fdd0f19eccb``.

No security software should detect the script as malicious.
