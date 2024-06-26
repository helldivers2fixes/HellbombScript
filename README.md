# 💣Hellbomb💣 Script for fixing Helldivers 2 Issues

![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/901687d6-1991-4fe4-8cfc-8d662f11b33e)



## How to Use:

Grab the latest EXE from the Releases on the right-hand side. Or you can copy and paste the script manually per instructions below.
EXE [VirusTotal](https://www.virustotal.com/gui/file/117688a9f23e067a7b93978252baf3dc408989abdefef6b2a626b24c61a4dc14) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/117688a9f23e067a7b93978252baf3dc408989abdefef6b2a626b24c61a4dc14) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

 1. **Open** PowerShell (no need to run as an Administrator)
    
       ⚠️ If the error in the image occurs when you select the **HD2 Status Checks** option, follow the Note below.
    
     ![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/734e2757-7a65-4bbf-8d6a-732275cecc51)
    
       Note: For a few users, the script errors when running the **Get-NetFirewallRule** command-let (which only reads Firewall rules. No changes are made to the firewall).
       If this happens, you may need to run PowerShell with Administrator privlieges.
       (Before opening PowerShell, right-click it and click "Run as Administrator").
       This _shouldn't_ be the norm for most users, and should be avoided unless you receive the error depicted above.
    
 3. Click on [the Hellbomb PowerShell Script](https://github.com/helldivers2fixes/HellbombScript/blob/main/Hellbomb%20Script.ps1)
 4. **Copy** entire script by clicking the copy button in the top right by the script
    
       <img src = "https://github.com/helldivers2fixes/HellbombScript/assets/166264070/5a600b1c-64f6-4956-ba2f-f82c9a317f81" height=50>
       
 6. **Paste** into PowerShell. Must use ``Ctrl`` + ``V`` (Right-clicking in terminal to paste will cause errors!).
 7. Acknowledge the warning prompt and click **Paste Anyway**
 8. Press ``Enter`` until the program runs, and the menu appears (depending on how you paste you may have to press **Enter** a couple of times)
 9. Choose a selection using the corresponding letters
 10. Expect Administrator prompts depending on what you're doing. Check to make sure the prompts match what you wanted to do.

## Security Info:

**VirusTotal Results:** https://www.virustotal.com/gui/file/f0382e5ff42a0fedf2e62c5efdf3b105d857c735470a525ae8d995ceb8385679

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``f0382e5ff42a0fedf2e62c5efdf3b105d857c735470a525ae8d995ceb8385679``.

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq f0382e5ff42a0fedf2e62c5efdf3b105d857c735470a525ae8d995ceb8385679``
5. The statement should return/evaluate to ``True``

**Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/f0382e5ff42a0fedf2e62c5efdf3b105d857c735470a525ae8d995ceb8385679

No security software should detect the script as malicious (except KingSoft, because it ❤️ false positives).
## Screenshots:

Running the Status Checks:
![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/ebba092a-4c62-4963-bfe9-5d353b983d26)



Selecting Help (?) from the menu:
![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/584dde89-139c-47a3-afd0-c2ece81f2379)




