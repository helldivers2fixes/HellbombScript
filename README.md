# 💣Hellbomb💣 Script for fixing Helldivers 2 Issues

![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/901687d6-1991-4fe4-8cfc-8d662f11b33e)

## Using the EXE:

1.) Grab the latest EXE from [the Releases on the right-hand side](https://github.com/helldivers2fixes/HellbombScript/releases) and run it. If it closes immediately, you'll need to run it with Admin privileges.

2.) Choose a selection using the corresponding letters. (``H`` is always a good place to start.) Press ``Enter`` to confirm the selection.

3.) Expect Administrator prompts depending on what you're doing. Check to make sure the prompts match what you wanted to do.

## Copy and paste using Terminal Console (Manual Method)
Copy and paste the script manually per instructions below.

 1. **Open** Terminal by pressing `Windows Key` + `X` and click `Terminal`    
 2. Click on [the Hellbomb PowerShell Script](https://github.com/helldivers2fixes/HellbombScript/blob/main/Hellbomb%20Script.ps1)
 3. **Copy** entire script by clicking the copy button in the top right by the script
    
       <img src = "https://github.com/helldivers2fixes/HellbombScript/assets/166264070/5a600b1c-64f6-4956-ba2f-f82c9a317f81" height=50>
       
 4. **Paste** into Terminal. Use ``Ctrl`` + ``V`` (Right-clicking in Terminal can cause errors!).
 5. Acknowledge the warning prompt and click **Paste Anyway**
 6. Press ``Enter`` until the program runs, and the menu appears (depending on how you paste you may have to press **Enter** a couple of times)
    (If the output looks like below. Close Terminal, press `Windows Key` + `X` and click `Terminal (Admin)`. Then re-paste the script.)
    
      ![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/734e2757-7a65-4bbf-8d6a-732275cecc51)
    
       Why? For a few users, the script errors when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
       If this happens, run PowerShell with Administrator privileges.
       (Before opening PowerShell, right-click it and click "Run as Administrator").
       This _shouldn't_ be the norm for most users, and should be avoided unless you receive the error depicted above.
 8. Choose a selection using the corresponding letters. (``H`` is always a good place to start.) Press ``Enter`` to confirm the selection.
 9. Expect Administrator prompts depending on what you're doing. Check to make sure the prompts match what you wanted to do.

## Screenshots (formatting will differ based on PowerShell version):

Running the HD2 Status Checks (H) in PowerShell 7:

![HellbombScript](https://github.com/user-attachments/assets/b7ca4e29-d90d-4f5a-96db-71e92f3d1bb9)





Selecting Help (?) from the menu:
![image](https://github.com/user-attachments/assets/73d16568-8063-4ee3-a6b6-b17facc87041)





