# 💣Hellbomb💣 Script for fixing Helldivers 2 Issues

![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/901687d6-1991-4fe4-8cfc-8d662f11b33e)

## Using the EXE:

1.) Grab the latest EXE from the Releases on the right-hand side and run it. If it closes immediately, you'll need to run it with Admin privileges.

2.) Choose a selection using the corresponding letters. (``H`` is always a good place to start.) Press ``Enter`` to confirm the selection.

3.) Expect Administrator prompts depending on what you're doing. Check to make sure the prompts match what you wanted to do.

## Using the Script in PowerShell Console (Manual Method)
Copy and paste the script manually per instructions below.

 1. **Open** PowerShell (no need to run as an Administrator unless you get lots of red text when running the **HD2 Status Checks** as depicted below)
    
      ![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/734e2757-7a65-4bbf-8d6a-732275cecc51)
    
       Why? For a few users, the script errors when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
       If this happens, run PowerShell with Administrator privileges.
       (Before opening PowerShell, right-click it and click "Run as Administrator").
       This _shouldn't_ be the norm for most users, and should be avoided unless you receive the error depicted above.
    
 3. Click on [the Hellbomb PowerShell Script](https://github.com/helldivers2fixes/HellbombScript/blob/main/Hellbomb%20Script.ps1)
 4. **Copy** entire script by clicking the copy button in the top right by the script
    
       <img src = "https://github.com/helldivers2fixes/HellbombScript/assets/166264070/5a600b1c-64f6-4956-ba2f-f82c9a317f81" height=50>
       
 6. **Paste** into PowerShell. Must use ``Ctrl`` + ``V`` (Right-clicking in terminal to paste will cause errors!).
 7. Acknowledge the warning prompt and click **Paste Anyway**
 8. Press ``Enter`` until the program runs, and the menu appears (depending on how you paste you may have to press **Enter** a couple of times)
 9. Choose a selection using the corresponding letters. Press ``Enter`` to confirm the selection.
 10. Expect Administrator prompts depending on what you're doing. Check to make sure the prompts match what you wanted to do.

## Screenshots (formatting will differ based on PowerShell version):

Running the HD2 Status Checks (H) in PowerShell 7:

![HellbombScript](https://github.com/user-attachments/assets/227b2ee7-60a1-4e29-8eff-54dec4d512fa)




Selecting Help (?) from the menu:
![image](https://github.com/user-attachments/assets/73d16568-8063-4ee3-a6b6-b17facc87041)





