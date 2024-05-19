# Hellbomb Script
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Function Print-Vars {
    If ($AppIDFound = $true) {
        Clear
        Write-Host ("AppID: " + $AppID + " is located in directory:") -ForegroundColor Green
        Write-Host $AppInstallPath -ForegroundColor White
        Write-Host ("Current build of AppID " + $AppID + " is: " +
        $BuildID) -ForegroundColor Cyan
    }
    Else {
    Write-Host "Error. AppID was not found." -ForegroundColor Red
    }
    Return
}

# Function adapted from: https://stackoverflow.com/questions/20886243/press-any-key-to-continue#:~:text=Function%20pause%20(%24message)
Function pause ($message)
{
    # Check if running Powershell ISE
    if (Test-Path variable:global:psISE)
    {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$message")
    }
    else
    {
        Write-Host "$message" -ForegroundColor Yellow
        $x = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

Function Reset-GameGuard {
    # Delete GameGuard files
    $Error.Clear()
    Try { Remove-Item $AppInstallPath\bin\GameGuard\*.*}
    Catch {Write-Host ("Error occurred deleting GameGuard files in " +
    $AppInstallPath+"\bin\GameGuard") -ForegroundColor Red}
    If (!$Error) {Write-Host "Helldivers 2\bin\GameGuard cleared successfully!" -ForegroundColor Green}
    # Uninstall GameGuard
    $Error.Clear()
    Try { Start-Process $AppInstallPath\tools\gguninst.exe -Wait}
    Catch {Write-Host "Error occurred uninstalling GameGuard" -ForegroundColor Red}
    If (!$Error) {Write-Host "GameGuard Uninstalled Successfully" -ForegroundColor Green}
    # Install GameGuard
    $Error.Clear()
    Try { Start-Process $AppInstallPath\tools\GGSetup.exe -Wait}
    Catch {Write-Host "Error occurred installing GameGuard" -ForegroundColor Red}
    If (!$Error) {Write-Host "GameGuard installed successfully" -ForegroundColor Green}
    Return
}

Function Clear-AppData {
    $Error.Clear()
    Try { Remove-Item $env:APPDATA\Arrowhead\Helldivers2\* -Recurse}
    Catch {Write-Host "Error occurred deleting contents of $env:APPDATA\Arrowhead\Helldivers2\" -ForegroundColor Red}
    If (!$Error) {Write-Host "Helldivers 2 AppData has been cleared successfully!" -ForegroundColor Green}
    Menu
}

Function Check-IsProcessRunning {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [Object[]]$InputObject
    )

    If (Get-Process -ProcessName $InputObject.ProcessName -ErrorAction SilentlyContinue) {
    Write-Host $InputObject.ErrorMsg -ForegroundColor Red
    pause "Press any key to Exit..."
    Exit
    }
}

Function Install-VCRedist {
    $VCRedist = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe"
    Invoke-WebRequest $VCRedist -OutFile $env:USERPROFILE\Downloads\VisualC++Redist2012.exe
    $Error.Clear()
    Try { Start-Process $env:USERPROFILE\Downloads\VisualC++Redist2012.exe -ArgumentList "/q" -Wait}
    Catch {Write-Host "Error occurred installing 2012 Visual C++ Redistributable" -ForegroundColor Red}
    If (!$Error) {
        Remove-Item $env:USERPROFILE\Downloads\VisualC++Redist2012.exe
        Write-Host "2012 Visual C++ Redistributable installed successfully!" -ForegroundColor Green
    }
    Return
}

Function Check-BlacklistedDrivers {
    $FoundBlacklistedDevice = $False
    $BadDeviceList = @(
        'Hamachi'
        'Nahimic'
        'Sonic'      
    )
    Write-Host "`nChecking for devices that are known to cause issues..." -ForegroundColor Cyan
    $DeviceDatabase = Get-PnpDevice
    ForEach ($device in $DeviceDatabase) {
        ForEach ($baddevice in $BadDeviceList) {
            If ($device.FriendlyName -like "*$baddevice*") {
                Write-Host ("⚠️ " + $device.FriendlyName +
                " device detected! Known compatibiltiy issues!
                Please disable.") -ForegroundColor Red
                $FoundBlacklistedDevice = $true
            }
        }
    }
    If ($FoundBlacklistedDevice -eq $False) {
        Write-Host "No problematic devices found." -ForegroundColor Green
    }
    Return
}

Function Check-ProblematicPrograms {
# This portion modified from:
# https://devblogs.microsoft.com/scripting/use-powershell-to-quickly-find-installed-software/

$array = @()
    # Define the variable to hold the location of Currently Installed Programs
    $UninstallKey=”SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall”
    # Create an instance of the Registry Object and open the HKLM base key
    $reg=[microsoft.win32.registrykey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64) 
    # Drill down into the Uninstall key using the OpenSubKey Method
    $regkey=$reg.OpenSubKey($UninstallKey)
    # Retrieve an array of string that contain all the subkey names
    $subkeys=$regkey.GetSubKeyNames()
    # Open each Subkey and use GetValue Method to return the required values for each

    foreach($key in $subkeys){
        if ($UninstallKey+”\\”+$key -and $reg.OpenSubKey($UninstallKey+”\\”+$key)) {
        $thisKey=($UninstallKey+”\\”+$key)
        $thisSubKey=$reg.OpenSubKey($thisKey) 

        $obj = New-Object PSObject
        $obj | Add-Member -MemberType NoteProperty -Name “DisplayName” -Value $($thisSubKey.GetValue(“DisplayName”))
        $obj | Add-Member -MemberType NoteProperty -Name “DisplayVersion” -Value $($thisSubKey.GetValue(“DisplayVersion”))
        $obj | Add-Member -MemberType NoteProperty -Name “InstallLocation” -Value $($thisSubKey.GetValue(“InstallLocation”))
        $obj | Add-Member -MemberType NoteProperty -Name “Publisher” -Value $($thisSubKey.GetValue(“Publisher”))
        $array += $obj
        }
    }

# Remove empties
$array = $array | Where {$_.DisplayName -ne $null} | Sort-Object -Property DisplayName
    
$ProblematicPrograms = @()
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="AMD Chipset Software";RecommendedVersion='6.02.07.2300';Installed=$false;Notes="Outdated versions are known to cause issues."}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="Cepstral SwiftTalker";RecommendedVersion='0.0';Installed=$false;Notes="Known to cause crashes in the past."}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="ESET";RecommendedVersion='0.0';Installed=$false;Notes="Known to cause crashes. Please disable or add Exclusions for the .des files in the tools folder." }
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="Hamachi";RecommendedVersion='0.0';Installed=$false;Notes="Will prevent connectivity. Recommend uninstall or disable IN DEVICE MANAGER"}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="iCue";RecommendedVersion='0.0';Installed=$false;Notes="Outdated versions are known to cause issues."}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="MSI Afterburner";RecommendedVersion='4.6.5';Installed=$false;Notes="Outdated versions are known to cause issues."}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="Outplayed";RecommendedVersion='0.0';Installed=$false;Notes="Known to cause stuttering & VRAM leaks. Disable Outplayed Autoclipping or disable/uninstall completely."}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="Overwolf";RecommendedVersion='0.0'; Installed=$false;Notes="Known to cause stuttering & VRAM leaks. Disable Outplayed Autoclipping or disable/uninstall completely."}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="Radmin";RecommendedVersion='0.0';Installed=$false;Notes="Will cause network issues. Recommend uninstalling or disabling in DEVICE MANAGER."}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="Razer Cortex";RecommendedVersion='0.0';Installed=$false;Notes="Known to cause CPU Threading issues & possibly other issues. Recommend disabling/uninstalling."}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="Ryzen Master";RecommendedVersion='2.13.0.2908';Installed=$false;Notes="Known to cause RAM leaks & general issues. Recommend uninstalling."}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="Samsung Magician";RecommendedVersion='8.1';Installed=$false;Notes="Outdated versions are known to completely prevent connectivity."}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="Surfshark";RecommendedVersion='0.0';Installed=$false;Notes="Will prevent connectivity. Recommend uninstall or disable IN DEVICE MANAGER"}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="Wargaming.net Game Center";Installed=$false;RecommendedVersion='0.0';Notes="Reported to cause issues."}
$ProblematicPrograms += New-Object PSObject -Property @{ProgramName="Webroot";Installed=$false;RecommendedVersion='0.0';Notes="Causes low FPS. Uninstall or launch HD2 & THEN shutdown Webroot."}

$bool = $false
Write-Host "`nChecking for installed problematic programs..." -ForegroundColor Cyan
ForEach ($program in $ProblematicPrograms)
{
    ForEach($installedApp in $array)
    {
        $bool = $false
        If ($installedApp.DisplayName -like "*"+$program.ProgramName+"*" -and ([System.Version]$program.RecommendedVersion -gt [System.Version]$installedApp.DisplayVersion)) {
        $bool=$true
        Break
        }
    }
    If ($bool) {$program.Installed = $true}
    
}

$result = $null
$result = $ProblematicPrograms | Where-Object {$_.Installed -eq $true}

If ($result -ne $null) {
    Write-Host "`nFound the following programs that are known to cause issues:`n" -ForegroundColor Red
    Write-Host ($result | Sort-Object ProgramName | Format-Table -Property ProgramName,RecommendedVersion,Notes -AutoSize | Out-String).Trim() -ForegroundColor Yellow
}
Else {
    Write-Host "Checks complete. No problematic programs found!" -ForegroundColor Green
    }
Return
}

Function Network-Checks {
    Write-Host (("`nChecking for two Inbound rules named Helldivers") + [char]0x2122 + " 2 or Helldivers 2...") -ForegroundColor Cyan
    $HD2FirewallRules = Get-NetFirewallRule -Action Allow -Enabled True -Direction Inbound | Where DisplayName -in ("Helldivers"+[char]0x2122+" 2"),"Helldivers 2"
    If ($HD2FirewallRules -ne $null -and $HD2FirewallRules.Count -gt 1) {
        Write-Host "Helldivers 2 has Inbound rules set in the Windows Firewall." -ForegroundColor Green
    }
    Else {
        Write-Host ("⚠️ Windows Firewall is likely blocking Helldivers 2. No Inbound firewall rules were found that match the typical rule names. Please add 2 Inbound rules, one for TCP and one for UDP.") -ForegroundColor Red
    }
    Return
}

Function Check-AMDNVIDIACombo {
    If ((Get-CimInstance Win32_Processor | Where-Object {$_.Name -like "AMD*"}) -and (Get-CimInstance Win32_VideoController | Where-Object {$_.Name -like "NVIDIA*"}))
    {
        Write-Host "`n⚠️ AMD CPU & NVIDIA GPU detected. For proper operation, ensure the latest AMD Chipset drivers are installed from:" -ForegroundColor Red
        Write-Host "https://www.amd.com/en/support/download/drivers.html" -ForegroundColor Yellow
    }
    Return
}

Function Reset-Steam {
    $SteamProcess = [PSCustomObject]@{
    ProcessName  = 'steam'
    ErrorMsg = '
    ⚠️ Steam is currently running. ⚠️
        Please close Steam first.
        '
    }
    Check-IsProcessRunning $SteamProcess
    # Remove CEF Cache
    Remove-Item $env:LOCALAPPDATA\Steam\* -Recurse
    $PropertyName = "Parent"
    Get-ChildItem -Path $SteamPath -File -Recurse |
    Where-Object { (%{if([bool]$_.PSObject.Properties["PSParentPath"])
    {$_.Name -ne "steam.exe" -and $_.PSObject.Properties["PSParentPath"].Value -notlike
    "*"+$SteamPath+"\steamapps*" -and $_.PSObject.Properties["PSParentPath"].Value -notlike
    "*"+$SteamPath+"\userdata*" -and $_.PSObject.Properties["PSParentPath"].Value -notlike
    "*"+$SteamPath+"\logs*" -and $_.PSObject.Properties["PSParentPath"].Value -notlike
    "*"+$SteamPath+"\dumps*"}})} | Remove-Item
    Start-Process $SteamPath\steam.exe
    Return
}

Function Open-AdvancedGraphics {
    Start-Process ms-settings:display-advancedgraphics
    Write-Host "`nVerify HellDivers 2 is set to use the correct GPU.",
    "`nIf HD2 is not listed, click " -NoNewLine -ForegroundColor Cyan
    Write-Host "Add desktop app " -NoNewline -ForegroundColor Yellow
    Write-Host "and browse to:" -ForegroundColor Cyan
    Write-Host $AppInstallPath,"\bin\helldivers2.exe" -ForegroundColor Yellow
    Return
}

Function Menu {
    $Title = "💣 Hellbomb 💣 Script for Fixing Helldivers 2"
    $Prompt = "Enter your choice:"
    $Choices = @(
        [System.Management.Automation.Host.ChoiceDescription]::new("&HD2 Status Checks", "Provides various status checks.")
        [System.Management.Automation.Host.ChoiceDescription]::new("&Clear HD2 Settings (AppData)", "Clears your profile data. Settings will be reset, but progress will not be lost.")
        [System.Management.Automation.Host.ChoiceDescription]::new("&Install VC++ Redist 2012", "Installs the Microsoft Visual C++ Redistributable 2012. Required for HD2. Can fix MSVCR110.dll errors.")
        [System.Management.Automation.Host.ChoiceDescription]::new("Re-install &GameGuard", "Performs a full GameGuard re-install. If Windows Ransomware Protection is enabled, may trigger security alert.")
        [System.Management.Automation.Host.ChoiceDescription]::new("Re&set Steam", "Performs a reset of Steam. This can fix various issues including VRAM memory leaks.")
        [System.Management.Automation.Host.ChoiceDescription]::new("Set HD2 G&PU", "Brings up the Windows GPU settings.")
        [System.Management.Automation.Host.ChoiceDescription]::new("E&xit", "Exits the script.")
    )
    $Default = 0
    $Choice = $Host.UI.PromptForChoice($Title, $Prompt, $Choices, $Default)
        switch ($choice) {
        0{Print-Vars
            Network-Checks
            Check-BlacklistedDrivers
            Check-AMDNVIDIACombo
            Check-ProblematicPrograms
            Menu}
        1{Clear-AppData
            Menu}
        2{Install-VCRedist
            Menu}
        3{Reset-GameGuard
            Menu}
        4{Reset-Steam
            Menu}
        5{Open-AdvancedGraphics
            Menu}
        6{Return}
        }
}

# Set AppID
$AppID = "553850"
$AppIDFound = $false
$LineOfInstallDir = 8
$LineOfBuildID = 13
$SteamPath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam").InstallPath
$LibraryData = Get-Content -Path $SteamPath\steamapps\libraryfolders.vdf

# Read each line of the Steam library.vdf file
# Save a library path, then scan that library for $AppID
# If AppID is found, return current library path
ForEach ($line in $($LibraryData -split "`r`n"))
{
    If ($line -like '*path*') {
        $AppInstallPath = ($line|%{$_.split('"')[3]})
        Write-host $AppInstallPath
        $AppInstallPath = $AppInstallPath.Replace('\\','\')
    }

    If (($line|%{$_.split('"') | Select-Object -Skip 1}) -like "*$AppID*") {
        $AppIDFound = $true
        # Since we found the App location, let's get some data about it
        $GameData = Get-Content -Path $AppInstallPath\steamapps\appmanifest_$AppID.acf
        $BuildID = ($GameData[$LineOfBuildID-1]|%{$_.split('"') | Select-Object -Skip 2})
        $GameFolderName = ($GameData[$LineOfInstallDir-1]|%{$_.split('"') | Select-Object -Skip 2})
        # Update the AppInstallPath with the FULL path
        $AppInstallPath = ($AppInstallPath + "\steamapps\common\" + $GameFolderName[1])
        Break
    }
}

$HelldiversProcess = [PSCustomObject]@{
    ProcessName  = 'helldivers2'
    ErrorMsg = '
    ⚠️ The Helldivers 2 process is currently running. ⚠️
         Please close the game. If the game appears closed, restart the system, and re-run this script.    
    '
}
Clear
Check-IsProcessRunning $HelldiversProcess
Menu
