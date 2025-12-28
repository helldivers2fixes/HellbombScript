# 💣Hellbomb💣 Script for troubleshooting [Helldivers 2](https://store.steampowered.com/app/553850/HELLDIVERS_2/)   
  [![GitHub operatingsystem](https://img.shields.io/badge/os-windows-blue)](https://github.com/helldivers2fixes/HellbombScript/releases/download/v4.0alpha2r3/Hellbomb_Script_v4.0-signed.exe)
  [![GitHub operatingsystem](https://img.shields.io/badge/os-linux-green)]
  [![GitHub release](https://img.shields.io/github/v/release/helldivers2fixes/HellbombScript?include_prereleases&sort=date&display_name=release&style=flat-square)](https://github.com/helldivers2fixes/HellbombScript/releases/latest)
  [![GitHub liscense](https://img.shields.io/github/license/helldivers2fixes/HellbombScript)](https://github.com/helldivers2fixes/HellbombScript/tree/main?tab=MIT-1-ov-file)
  [![GitHub forks](https://img.shields.io/github/forks/helldivers2fixes/HellbombScript)]()
  [![GitHub contributors](https://img.shields.io/github/contributors/helldivers2fixes/HellbombScript)](https://github.com/helldivers2fixes/HellbombScript/graphs/contributors)
  [![GitHub lastcommit](https://img.shields.io/github/last-commit/helldivers2fixes/HellbombScript)]()
  [![GitHub downloads](https://img.shields.io/github/downloads/helldivers2fixes/HellbombScript/total)](https://github.com/helldivers2fixes/HellbombScript/releases/latest)
  
[![PSScriptAnalyzer](https://github.com/helldivers2fixes/HellbombScript/actions/workflows/powershell.yml/badge.svg)](https://github.com/helldivers2fixes/HellbombScript/actions/workflows/powershell.yml)
[![Build Hellbomb Script EXE & Update Hashes](https://github.com/helldivers2fixes/HellbombScript/actions/workflows/ps2exe.yml/badge.svg)](https://github.com/helldivers2fixes/HellbombScript/actions/workflows/ps2exe.yml)
## HOW TO USE (Pick 1 of the 3 options below):

## Option 1: EXE
1.) [DOWNLOAD](https://github.com/helldivers2fixes/HellbombScript/releases) the latest **EXE**

2.) Right-click on the EXE >> **Properties** >> select the checkbox to Unblock the EXE >> click **OK**. See image: <img width="405" height="568" alt="image" src="https://github.com/user-attachments/assets/d70fd5e9-d08a-4c4f-8e71-746277a0caac" />

Then run the EXE

Or, you can avoid using an EXE completely and [copy & paste the latest code directly](https://github.com/helldivers2fixes/HellbombScript?tab=readme-ov-file#copy-and-paste-using-terminal-console-semi-automated) ⚠️ Latest code may have issues, so you may need to [select a release tag](https://github.com/helldivers2fixes/HellbombScript/tags) for it to run successfully.

3.) The menu uses letters to select choices. (Always start with ``H``.) Type ``H`` Press ``Enter`` to confirm the selection.

4.) Expect Administrator prompts depending on what you're doing. Check to make sure the prompts match what you wanted to do.

## Option 2: Copy and Paste using Terminal Console (Semi-Automated)
 1. **Open** Terminal (Admin) or PowerShell (Admin) by pressing `Windows Key` + `X` and click `Terminal (Admin)` or `Windows PowerShell (Admin)`
 2. Copy (use the copy button on the far right) and paste the below line into Terminal/PowerShell and press ``Enter``
    ```powershell
    Invoke-RestMethod https://raw.githubusercontent.com/helldivers2fixes/HellbombScript/refs/tags/v4.0alpha2r3/Hellbomb%20Script.ps1 | Invoke-Expression
    ```
    If you would like to use the latest code, feel free to try it! It will have the latest features, but may not work right, or be incomplete.
    ```powershell
    Invoke-RestMethod https://raw.githubusercontent.com/helldivers2fixes/HellbombScript/refs/heads/main/Hellbomb%20Script.ps1 | Invoke-Expression
    ```
    💡 It's always a good idea to read what you're executing. In this case, you're telling PowerShell to download the script text and then execute it.
    If you want to verify, paste the URL into the browser and it will reveal the raw script text.

## Running on Arch Linux or CachyOS (Alpha & not all features are supported on Linux)
```bash
sudo paru -S powershell-bin
pwsh # Launch PowerShell
Invoke-RestMethod https://raw.githubusercontent.com/helldivers2fixes/HellbombScript/refs/heads/InitialLinuxSupport/Hellbomb%20Script.ps1 | Invoke-Expression
```

## Start by pressing ``Enter`` to run the default choice (``H``) or press ``H``

### Read through **all** the output for anything that is a [FAIL] or looks incorrect.

Then you can work through the things below if you have specific issues.

| Symptoms          | Recommended Things to Try AFTER running ``H``                                  |
|-------------------|-----------------------------------------------------------------|
| Controller/Key binding Issues          | Option ``M``|
| Crashing          | Option ``H`` and **read carefully & take any recommended fixes** then Option ``C`` then Option ``S``         |
| Game Won't Start  | Option ``H`` and address any issues. Then option ``C`` then option ``G`` then try option ``U`` Restart, then option ``I``                            |
| Game Guard 114 Error  | Option ``H`` and address any issues. Then option ``U`` Restart, then option ``I``                            |
| Game launches, but version mismatch errors even though game seems up-to-date | Option ``S``. Then [verify integrity](https://help.steampowered.com/en/faqs/view/0C48-FCBD-DA71-93EB)
| **Abnormally** High CPU Usage  | Option ``G``                            |
| Memory Leaks      | Option ``S`` Note: If you have VRAM leaks instead, use [DDU](https://www.guru3d.com/download/display-driver-uninstaller-download/)                                                   |
| Out of Disk Space | Option ``S`` (Caused by memory leak overflowing to the page file)       |
| Total Game Reset (No progress loss) | Option ``C`` and Option ``M``        |
| WinLicense Error: An error has occurred while loading imports. Wrong DLL present. | Option ``S`` then [verify integrity](https://help.steampowered.com/en/faqs/view/0C48-FCBD-DA71-93EB)    |

## Option 3: Copy and Paste using Terminal Console (Manual Method)
Copy and paste the script manually per instructions below.

 1. **Open** Terminal (Admin) or PowerShell (Admin) by pressing `Windows Key` + `X` and click `Terminal (Admin)` or `Windows PowerShell (Admin)`
 2. Middle/Ctrl + click on [the Hellbomb PowerShell Script](https://github.com/helldivers2fixes/HellbombScript/blob/main/Hellbomb%20Script.ps1) so that these instructions stay open
 3. **Copy** entire script by clicking the copy button in the top right by the script
    
       <img src="https://github.com/helldivers2fixes/HellbombScript/assets/166264070/5a600b1c-64f6-4956-ba2f-f82c9a317f81" width="300">
       
 4. **Paste** into Terminal (Admin) or Windows PowerShell (Admin). Use ``Ctrl`` + ``V`` (Right-clicking in Terminal can cause errors!).
 5. Acknowledge the warning prompt and click **Paste Anyway**
 6. Press ``Enter`` until the program runs, and the menu appears (depending on how you paste you may have to press **Enter** a couple of times)         
 7. Choose a selection using the corresponding letters. (``H`` is always a good place to start.) Press ``Enter`` to confirm the selection.
 8. Expect Administrator prompts depending on what you're doing. Check to make sure the prompts match what you wanted to do.

## The Windows version uses CPU-Z for some functions. Special thanks to Franck at CPU-Z for granting me permission to use it.
<img src = "https://github.com/user-attachments/assets/dc21811d-b124-4962-bf1f-773b45d5b69b" width="200">

## Screenshots (formatting will differ based on Terminal/PowerShell version):
Main Menu
<img width="1115" height="324" alt="image" src="https://github.com/user-attachments/assets/cde7b49e-f420-451f-a526-636a4100e593" />

Running the HD2 Status Checks (H) from the EXE (out-dated recording):
![Hellbomb Script Animation](https://github.com/user-attachments/assets/8781f62f-3f5b-4530-9085-ea3042833220)

# Code signing policy:
“Free code signing provided by SignPath.io, certificate by SignPath Foundation”
https://github.com/signpath

Committers and reviewers: helldivers2fixes

Approvers: helldivers2fixes

