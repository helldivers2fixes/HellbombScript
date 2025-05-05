# 💣Hellbomb💣 Script for troubleshooting [Helldivers 2](https://store.steampowered.com/app/553850/HELLDIVERS_2/)   
  [![GitHub operatingsystem](https://img.shields.io/badge/os-windows-blue)](https://github.com/helldivers2fixes/HellbombScript/releases/download/v3.1/Hellbomb.Script.v31.exe)
  [![GitHub release](https://img.shields.io/github/v/release/helldivers2fixes/HellbombScript?include_prereleases&sort=date&display_name=release&style=flat-square)](https://github.com/helldivers2fixes/HellbombScript/releases/latest)
  [![GitHub liscense](https://img.shields.io/github/license/helldivers2fixes/HellbombScript)](https://github.com/helldivers2fixes/HellbombScript/tree/main?tab=MIT-1-ov-file)
  [![GitHub forks](https://img.shields.io/github/forks/helldivers2fixes/HellbombScript)]()
  [![GitHub contributors](https://img.shields.io/github/contributors/helldivers2fixes/HellbombScript)](https://github.com/helldivers2fixes/HellbombScript/graphs/contributors)
  [![GitHub lastcommit](https://img.shields.io/github/last-commit/helldivers2fixes/HellbombScript)]()
  [![GitHub downloads](https://img.shields.io/github/downloads/helldivers2fixes/HellbombScript/total)](https://github.com/helldivers2fixes/HellbombScript/releases/latest)

## HOW TO USE:

1.) [DOWNLOAD](https://github.com/helldivers2fixes/HellbombScript/releases) the latest **EXE** and run it.

Or, you can avoid using an EXE completely and [copy & paste the latest code directly](https://github.com/helldivers2fixes/HellbombScript/tree/main#copy-and-paste-using-terminal-console-manual-method) ⚠️ Latest code may have issues, so you may need to [select a release tag](https://github.com/helldivers2fixes/HellbombScript/tags) for it to run successfully.

2.) The menu uses letters to select choices. (Always start with ``H``.) Type ``H`` Press ``Enter`` to confirm the selection.

3.) Expect Administrator prompts depending on what you're doing. Check to make sure the prompts match what you wanted to do.

## Start by pressing ``Enter`` to run the default choice (``H``) or type ``H`` and press ``Enter``
### Read through **all** the output for anything that is a [FAIL] or looks incorrect.

Then you can work through the things below if you have specific issues.

| Symptoms          | Recommended Things to Try                                       |
|-------------------|-----------------------------------------------------------------|
| Controller/Key binding Issues          | Option ``M``|
| Crashing          | Option ``H`` and **read carefully & take any recommended fixes** then Option ``C`` then Option ``S``         |
| Game Won't Start  | Option ``C`` then Option ``G`` then try Option ``U`` restart then option ``I``                            |
| High CPU Usage  | Option ``G``                            |
| Memory Leaks      | Option ``S`` Note: If you have VRAM leaks instead, use [DDU](https://www.guru3d.com/download/display-driver-uninstaller-download/)                                                   |
| Out of Disk Space | Option ``S`` (Caused by memory leak overflowing to the page file)       |
| Total Game Reset (No progress loss) | Option ``C`` and Option ``M``        |

## Copy and Paste using Terminal Console (Manual Method)
Copy and paste the script manually per instructions below.

 1. **Open** Terminal (Admin) or PowerShell (Admin) by pressing `Windows Key` + `X` and click `Terminal (Admin)` or `Windows PowerShell (Admin)`
 2. Middle/Ctrl + click on [the Hellbomb PowerShell Script](https://github.com/helldivers2fixes/HellbombScript/blob/main/Hellbomb%20Script.ps1) so that these instructions stay open
 3. **Copy** entire script by clicking the copy button in the top right by the script
    
       <img src = "https://github.com/helldivers2fixes/HellbombScript/assets/166264070/5a600b1c-64f6-4956-ba2f-f82c9a317f81" height=50>
       
 4. **Paste** into Terminal (Admin) or Windows PowerShell (Admin). Use ``Ctrl`` + ``V`` (Right-clicking in Terminal can cause errors!).
 5. Acknowledge the warning prompt and click **Paste Anyway**
 6. Press ``Enter`` until the program runs, and the menu appears (depending on how you paste you may have to press **Enter** a couple of times)         
 7. Choose a selection using the corresponding letters. (``H`` is always a good place to start.) Press ``Enter`` to confirm the selection.
 8. Expect Administrator prompts depending on what you're doing. Check to make sure the prompts match what you wanted to do.

## Screenshots (formatting will differ based on Terminal/PowerShell version):
Main Menu in EXE
![image](https://github.com/user-attachments/assets/4028ab27-bb86-4c52-8e0f-70d06627e039)

Main Menu in PowerShell 7
![image](https://github.com/user-attachments/assets/3f7291f6-44b0-46f6-958f-6247c995d848)

Running the HD2 Status Checks (H) from the EXE:
![Hellbomb Script Animation](https://github.com/user-attachments/assets/8781f62f-3f5b-4530-9085-ea3042833220)


Selecting Help (?) from the menu in PowerShell 7:
![image](https://github.com/user-attachments/assets/e664df63-d848-4d31-9b34-be8aa05bd13f)
