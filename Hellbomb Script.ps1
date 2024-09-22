# Hellbomb Script
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Function Show-Variables {
    If ($global:AppIDFound -eq $true) {
        Clear-Host
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
Function pause ($message) {
    # Check if running Powershell ISE
    If (Test-Path variable:global:psISE) {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$message")
    }
    Else {
        Write-Host "$message"`n -ForegroundColor Yellow
        $x = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

Function Install-EXE {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $DownloadURL,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $DownloadPath,
        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $FileName,
        [Parameter(Mandatory = $true, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $SHA256Hash,
        [Parameter(Mandatory = $true, Position = 4)]
        [ValidateNotNullOrEmpty()]
        [string] $CommonName
    )
    # Turn off progress bar to speed up download
    $ProgressPreference = 'SilentlyContinue'
    Write-Host "`nDownloading $CommonName..." -Foreground Cyan
    Invoke-WebRequest $DownloadURL -OutFile ($DownloadPath + $FileName)
    If ( (Get-FileHash ($DownloadPath + $FileName)).Hash -eq $SHA256Hash) {
        Write-Host 'Installing... look for UAC prompts' -Foreground Cyan
        $Error.Clear()
        Try {
            $installProcess = Start-Process ($DownloadPath + $FileName) -ArgumentList "/q" -PassThru -Wait
            
            If ( $installProcess.ExitCode -ne 0) {
                Write-Host "`nUAC prompt was canceled, or another error occurred installing $CommonName`n" -ForegroundColor Red
                Remove-Item ($DownloadPath + $FileName)
                # Re-enable Progress Bar
                $ProgressPreference = 'Continue'
                Return
            }
        }
        Catch { Write-Host "Error occurred installing $CommonName" -ForegroundColor Red }
        If (!$Error) {
            Write-Host "$CommonName installed successfully!" -ForegroundColor Green
        }
    }
    Else {
        Write-Host "Installer file hash verification failed. Aborting $CommonName" -ForegroundColor Yellow
    }
    Remove-Item ($DownloadPath + $FileName)
    # Re-enable Progress Bar
    $ProgressPreference = 'Continue'
}

Function Reset-GameGuard {
    # Delete GameGuard files
    $Error.Clear()
    Try { Remove-Item $AppInstallPath\bin\GameGuard\*.* }
    Catch {
        Write-Host ("Error occurred deleting GameGuard files in " +
            $AppInstallPath + "\bin\GameGuard") -ForegroundColor Red
    }
    If (!$Error) { Write-Host "Helldivers 2\bin\GameGuard cleared successfully!" -ForegroundColor Green }
    # Uninstall GameGuard
    $Error.Clear()
    Try { Start-Process $AppInstallPath\tools\gguninst.exe -Wait }
    Catch { Write-Host "Error occurred uninstalling GameGuard" -ForegroundColor Red }
    If (!$Error) { Write-Host "GameGuard Uninstalled Successfully" -ForegroundColor Green }
    # Install GameGuard
    $Error.Clear()
    Try { Start-Process $AppInstallPath\tools\GGSetup.exe -Wait }
    Catch { Write-Host "Error occurred installing GameGuard" -ForegroundColor Red }
    If (!$Error) { Write-Host "GameGuard installed successfully"`n -ForegroundColor Green }
    Return
}
Function Remove-HD2AppData {
    $Error.Clear()
    Try { Remove-Item $env:APPDATA\Arrowhead\Helldivers2\* -Recurse }
    Catch { Write-Host "Error occurred deleting contents of $env:APPDATA\Arrowhead\Helldivers2\" -ForegroundColor Red }
    If (!$Error) { Write-Host "Helldivers 2 AppData has been cleared successfully!" -ForegroundColor Green }
    Menu
}

Function Get-IsProcessRunning {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [Object[]]$InputObject
    )
    If (Get-Process -ProcessName $InputObject.ProcessName -ErrorAction SilentlyContinue) {
        Write-Host $InputObject.ErrorMsg -ForegroundColor Red
        Pause 'Press any key to Exit...'
        Exit
    }
}

Function Install-VCRedist {
    Install-EXE -DownloadURL 'https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe' `
        -DownloadPath ("$env:USERPROFILE\Downloads\") -FileName 'VisualC++Redist2012.exe' `
        -SHA256Hash '681BE3E5BA9FD3DA02C09D7E565ADFA078640ED66A0D58583EFAD2C1E3CC4064' -CommonName '2012 Visual C++ Redistributable'

    Install-EXE -DownloadURL 'https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe' `
        -DownloadPath ("$env:USERPROFILE\Downloads\") -FileName 'VisualC++Redist2013.exe' `
        -SHA256Hash 'E554425243E3E8CA1CD5FE550DB41E6FA58A007C74FAD400274B128452F38FB8' -CommonName '2013 Visual C++ Redistributable'

    Install-EXE -DownloadURL 'https://download.visualstudio.microsoft.com/download/pr/1754ea58-11a6-44ab-a262-696e194ce543/3642E3F95D50CC193E4B5A0B0FFBF7FE2C08801517758B4C8AEB7105A091208A/VC_redist.x64.exe' `
        -DownloadPath ("$env:USERPROFILE\Downloads\") -FileName 'VisualC++Redist2019.exe' `
        -SHA256Hash '3642E3F95D50CC193E4B5A0B0FFBF7FE2C08801517758B4C8AEB7105A091208A' -CommonName '2019 Visual C++ Redistributable'

    Pause "`nPlease restart the computer before continuing." -ForegroundColor Yellow
    Exit
}
Function Find-BlacklistedDrivers {
    $FoundBlacklistedDevice = $False
    $BadDeviceList = @(
        'A-Volute'
        'Hamachi'
        'Nahimic'
        'LogMeIn Hamachi'
        'Sonic'
    )
    Write-Host "`nChecking for devices that are known to cause issues..." -ForegroundColor Cyan
    $DeviceDatabase = Get-PnpDevice
    ForEach ($device in $DeviceDatabase) {
        ForEach ($baddevice in $BadDeviceList) {
            If ($device.FriendlyName -like "$baddevice*") {
                Write-Host ("⚠️ " + $device.FriendlyName +
                    " device detected! Known compatibility issues!
                Please disable.") -ForegroundColor Red
                $FoundBlacklistedDevice = $true
            }
        }
    }
    If ($FoundBlacklistedDevice -eq $False) {
        Write-Host "No problematic devices found." -ForegroundColor Green
    }
    # Hack to quickly check for missing chipset drivers
    $MissingDriverCounter = 0
    ForEach ($device in $DeviceDatabase) {
        If ($device.FriendlyName -like "Base System Device") {
        $MissingDriverCounter++
        }
    }
    If ($MissingDriverCounter -gt 4) {
        Write-Host "`n It appears you are missing your chipset driver." -ForegroundColor Yellow
        Write-Host "`n This is a critical driver for performance & function." -ForegroundColor Yellow
        Write-Host "`n Please install it from your motherboard manufacturer or OEM system support site." -ForegroundColor Yellow
    }
    Return
}
Function Find-CPUInfo {
    $motherboardInfo = @(
    [pscustomobject]@{ 'Motherboard Info' = 'Manufacturer: '+(Get-CimInstance -ClassName Win32_BaseBoard).Manufacturer.Trim();
    'UEFI Info' = 'SMBIOS Version: '+(Get-CimInstance -ClassName Win32_BIOS).SMBIOSBIOSVersion.Trim() }
    [pscustomobject]@{ 'Motherboard Info' = 'Product: '+(Get-CimInstance -ClassName Win32_BaseBoard).Product.Trim();
    'UEFI Info' = 'Manufacturer: '+(Get-CimInstance -ClassName Win32_BIOS).Manufacturer.Trim() }
    [pscustomobject]@{ 'Motherboard Info' = '';
    'UEFI Info' = 'BIOS Version:'+(Get-CimInstance -ClassName Win32_BIOS).Name.Trim() }
    )
    $motherboardInfo | Format-Table 'Motherboard Info', 'UEFI Info' -AutoSize
        
    Write-Host "`nChecking CPU model to determine if it is affected by the Intel CPU stability & permanent degradation issues..." -ForegroundColor Cyan
    $AffectedCPUStrings = @("13900", "13700", "13790", "13700", "13600", "13500", "13490", "13400", "14900", "14790", "14700", "14600", "14500", "14490", "14400")
    $cpuInfo = Get-CimInstance -ClassName Win32_Processor
    $cpuName = $cpuInfo.Name.Trim()
    $containsAny = $false
    ForEach ($sub in $AffectedCPUStrings) {
        If (($cpuName).Contains($sub)) {
            $containsAny = $true
            Break
            }
        }
        If ($containsAny) {
            # Check Microcode; adapted from: https://www.xf.is/2018/06/28/view-cpu-microcode-revision-from-powershell/
            $registrypath = "Registry::HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0\"
            $processor = (Get-ItemProperty -Path $registrypath )."ProcessorNameString"
            $biosMicrocode = (Get-ItemProperty -Path $registrypath )."Previous Update Revision"
            $runningMicrocode = (Get-ItemProperty -Path $registrypath )."Update Revision"
            # Convert to string and remove leading zeros
            $runningMicrocodeInHex = (-join ( $runningMicrocode[0..4] | ForEach { $_.ToString("X12") } )).TrimStart('0')
            If ($runningMicrocodeInHex -ge '0x29') {
                Write-Host "Your CPU model: " -ForegroundColor Cyan -NoNewLine ; Write-Host "$cpuName " -NoNewLine
                Write-Host "is running updated microcode ver. $runningMicrocodeInHex" -ForegroundColor Green
                Write-Host 'However, if stability issues occured before the microcode was updated, then the CPU may already be permanently damaged.' -ForegroundColor Yellow
                Write-Host "`n        For more information, visit: `n        https://www.theverge.com/2024/7/26/24206529/intel-13th-14th-gen-crashing-instability-cpu-voltage-q-a" -ForegroundColor Cyan
                Pause "`n        Any proposed fixes by this tool may fail to work if your CPU is damaged.`n`nPress any key to continue..." -ForegroundColor Yellow
                Return
            }
            Else {
            
            Write-Host "`nAffected CPU Model with unpatched microcode Detected!! " -ForegroundColor Red -NoNewLine; Write-Host "$cpuName" -ForeGroundColor White
            Write-Host "`n        WARNING: If you are NOT currently having stability issues, please update `n        your motherboard UEFI (BIOS) ASAP to prevent permanent damage to the CPU." -ForegroundColor Yellow
            Write-Host "`n        If you ARE experiencing stability issues, your CPU may be unstable & permanently damaged." -ForegroundColor Red
            Write-Host "`n        For more information, visit: `n        https://www.theverge.com/2024/7/26/24206529/intel-13th-14th-gen-crashing-instability-cpu-voltage-q-a" -ForegroundColor Cyan
            Pause "`n        Any proposed fixes by this tool may fail to work if your CPU is damaged.`n`nPress any key to continue..." -ForegroundColor Yellow
            Return
            }
        }
        Write-Host "Your CPU model: " -ForegroundColor Cyan -NoNewLine ; Write-Host "$cpuName " -NoNewLine
        Write-Host "is not affected by the Intel CPU issues." -ForegroundColor Green
    Return
}
Function Test-Programs {
    # This portion modified from:
    # https://devblogs.microsoft.com/scripting/use-powershell-to-quickly-find-installed-software/
    Write-Host "`nChecking for installed problematic programs..." -ForegroundColor Cyan
    Write-Host "`nYou may encounter errors converting program version numbers. This is normal." -ForegroundColor Cyan
    $array = @()
    # Define the variable to hold the location of Currently Installed Programs
    $UninstallPaths = @()
    $UninstallPaths += "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    $UninstallPaths += "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    ForEach ($path in $UninstallPaths) {
    # Create an instance of the Registry Object and open the HKLM base key
    $reg = [microsoft.win32.registrykey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    # Drill down into the Uninstall key using the OpenSubKey Method
    $regkey = $reg.OpenSubKey($path)
    # Retrieve an array of string that contain all the subkey names
    $subkeys = $regkey.GetSubKeyNames()
    # Open each Subkey and use GetValue Method to return the required values for each
    ForEach ($key in $subkeys) {
        If ($path + "\\" + $key -and $reg.OpenSubKey($path + "\\" + $key)) {
            $thisKey = ($path + "\\" + $key)
            $thisSubKey = $reg.OpenSubKey($thisKey)
            # Remove extraneous version strings if not null
            $s = $null
            If (-not ([string]::IsNullOrEmpty($($thisSubKey.GetValue("DisplayVersion"))))) {
                $s = $thisSubKey.GetValue("DisplayVersion")
                $s = $s.Trim()
                $s = $s -replace '^[a-zA-Z]+'
                $s = $s -replace '[a-zA-Z]$'
                $Error.Clear()
                Try { $null = [System.Version]$s }
                Catch {
                    Write-Host ('Error occurred converting program version number ' +
                        ($thisSubKey.GetValue("DisplayVersion"))) 'for' ($thisSubKey.GetValue('DisplayName')) -ForegroundColor White
                    # Set version to 0.0.0 due to version error
                    $s = '0.0.0'
                }
            }
            $obj = New-Object PSObject
            $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"))
            $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $s
            $obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $($thisSubKey.GetValue("InstallLocation"))
            $obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $($thisSubKey.GetValue("Publisher"))
            $array += $obj
        }
    }
    # Remove empties
    $array = $array | Where-Object { $null -ne $_.DisplayName } | Sort-Object -Property DisplayName
    }
   
    # Avast Web Shield checks
    $regPath = "HKLM:\SOFTWARE\Avast Software\Avast\properties\WebShield\Common"
    $regName = "ProviderEnabled"

    Try {
    $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
    If ($value.$regName -eq 1)
        {
            Write-Host "`n⚠️ Avast Webshield is enabled!" -ForegroundColor Yellow
            Write-Host 'Add an exception for ' -ForegroundColor Cyan -NoNewline
            Write-Host 'https://microsoft.com ' -NoNewline
            Write-Host 'to prevent HTTPS CRL access issues.' -ForegroundColor Cyan
        }
    }
    Catch { # Value does not exist
    }
    # Hack to check for Avast and Nahimic without requiring the script to need Admin privileges
    $InstalledServices = Get-Service -Exclude McpManagementService, NPSMSvc_*, WaaSMedicSvc
    ForEach ($service in $InstalledServices)
    {
        If ($service.Name -like 'avast*') {
            $obj = New-Object PSObject
            $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value 'Avast Internet Security'
            $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value '0.0.0'
            $array += $obj
        }
        If ($service.Name -like 'Nahimic*') {
            $obj = New-Object PSObject
            $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value 'Nahimic'
            $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value '0.0.0'
            $array += $obj
        }
    }    

    $ProblematicPrograms = @()
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'AMD Chipset Software'; RecommendedVersion = '6.05.28.016'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Your version may be SLIGHTLY older. Latest @ https://www.amd.com/en/support/download/drivers.html Old versions cause various issues.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Avast Internet Security'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Known to cause performance issues. Recommend uninstalling. Disabling while playing MAY resolve issues.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Cepstral SwiftTalker'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Known to cause crashes in the past.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'ESET'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Known to cause crashes. Note: May be falsely detected. Please disable or add Exclusions for the .des files in the tools folder.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Hamachi'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Will prevent connectivity. Recommend uninstall or disable IN DEVICE MANAGER' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'iCue'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Outdated versions are known to cause issues.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'MSI Afterburner'; RecommendedVersion = '4.6.5'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Outdated versions are known to cause issues.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Mullvad VPN'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Causes connection issues. Recommend uninstall or disable in DEVICE MANAGER.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Nahimic'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Myriad of issues. Recommend removing all devices and services.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Norton 360'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Will destroy FPS if Game Optimizer is enabled. Disable Game Optimizer in Norton 360.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Outplayed'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Known to cause stuttering & VRAM leaks. Disable Outplayed Autoclipping or disable/uninstall completely.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Overwolf'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Known to cause stuttering & VRAM leaks. Disable Outplayed Autoclipping or disable/uninstall completely.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Radmin'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Will cause network issues. Recommend uninstall or disable in DEVICE MANAGER.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Razer Cortex'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Known to cause CPU Threading issues & possibly other issues. Recommend disabling/uninstalling.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Ryzen Master'; RecommendedVersion = '2.13.0.2908'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Known to cause RAM leaks & general issues. Recommend uninstalling.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Samsung Magician'; RecommendedVersion = '8.1'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Outdated versions are known to completely prevent connectivity.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Surfshark'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Will prevent connectivity. Recommend uninstall or disable IN DEVICE MANAGER' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Wargaming.net Game Center'; Installed = $false; RecommendedVersion = '100.100'; InstalledVersion = '0.0.0'; Notes = 'Reported to cause issues.' }
    $ProblematicPrograms += New-Object PSObject -Property @{ProgramName = 'Webroot'; Installed = $false; RecommendedVersion = '100.100'; InstalledVersion = '0.0.0'; Notes = 'Causes low FPS. Uninstall or launch HD2 & THEN shutdown Webroot.' }
    $bool = $false
    ForEach ($program in $ProblematicPrograms) {
        ForEach ($installedApp in $array) {
            $bool = $false
            If ($installedApp.DisplayName -like "*" + $program.ProgramName + "*" -and ([System.Version]$program.RecommendedVersion -gt [System.Version]$installedApp.DisplayVersion)) {
                $bool = $true
                Break
            }
        }
        If ($bool) { 
        $program.Installed = $true
        $program.InstalledVersion = [System.Version]$installedApp.DisplayVersion
        }
    }
    $result = $null
    $result = $ProblematicPrograms | Where-Object { $_.Installed -eq $true }
    If ($null -ne $result) {
        Write-Host "`nFound the following programs that are known to cause issues:`n" -ForegroundColor Yellow
        Write-Host ("{0,-32} {1,-20} {2,-35}" -f "Program Name", "Installed Version", "Notes") -ForegroundColor Cyan
        foreach ($row in $result) {
            Write-Host '[FAIL] ' -ForegroundColor Red -NoNewline
            Write-Host ("{0,-25}" -f $row.ProgramName) -ForegroundColor Yellow -NoNewline
            Write-Host (" {0,-20} {1,-132}" -f $row.InstalledVersion, $row.Notes)
        }
    }
    Else {
        Write-Host 'Checks complete. No problematic programs found!'`n -ForegroundColor Green
    }
    Return
}
Function Test-Network {
Write-Host (("`nChecking for two Inbound Firewall rules named Helldivers") + [char]0x2122 + " 2 or Helldivers 2...") -ForegroundColor Cyan
    # Cast as array due to PowerShell returning object (no count property) if one rule, but array if two rules
    [array]$HD2FirewallRules = Get-NetFirewallRule -Action Allow -Enabled True -Direction Inbound | Where-Object DisplayName -In ("Helldivers" + [char]0x2122 + " 2"), "Helldivers 2"
    If ($null -eq $HD2FirewallRules) {
        Write-Host '⚠️ Windows Firewall is blocking Helldivers 2. No Inbound firewall rules were found that match the original rule names. Please add 2 Inbound rules, one for TCP and one for UDP.' -ForegroundColor Red
        Start-Process wf.msc
    }
    Else {
        $TCPRule = $false
        $UDPRule = $false
        ForEach ( $rule in $HD2FirewallRules) {
            If ( !$TCPRule -and $rule.Enabled -and (($rule | Get-NetFirewallPortFilter).Protocol -eq 'TCP')) {
                $TCPRule = $true
                Write-Host 'Inbound TCP Rule ' -NoNewline
                Write-Host '[OK]' -ForegroundColor Green
            }
            If ( !$UDPRule -and $rule.Enabled -and (($rule | Get-NetFirewallPortFilter).Protocol -eq 'UDP')) {
                $UDPRule = $true
                Write-Host 'Inbound UDP Rule ' -NoNewline
                Write-Host '[OK]' -ForegroundColor Green
                }
        }
        If (!$TCPRule) {
            Write-Host 'Inbound TCP Rule ' -NoNewline
            Write-Host '[FAIL]' -ForegroundColor Red
            }
        If (!$UDPRule) {
            Write-Host 'Inbound UDP Rule ' -NoNewline
            Write-Host '[FAIL]' -ForegroundColor Red
            }
        If (!$TCPRule -or !$UDPRule) {

        Write-Host "`n⚠️ Windows Firewall is blocking Helldivers 2." -Foregroundcolor Red
        Write-Host 'On game launch, Steam should request Admin privleges and add the Inbound rule(s) for you.' -Foregroundcolor Yellow
        Write-Host 'You may need to add the rule(s) manually if this does not happen.' -Foregroundcolor Yellow
        Write-Host "`nLaunching firewall settings..." -ForegroundColor Cyan
        Start-Process wf.msc
        }
        Write-Host "`nFirewall checks complete!" -ForegroundColor Cyan
        }

    Write-Host "`nClearing the DNS Cache..." -ForegroundColor Cyan -NoNewline
    Clear-DnsClientCache
    Write-Host " complete!`n"

    [string[]]$RequiredDomains = 
    'akamaihd.net',
    'api.live.prod.thehelldiversgame.com',
    'cluster-a.playfabapi.com',
    'gameguard.co.kr',
    'gameguard.thehelldiversgame.com',
    'mgr.gameguard.co.kr',
    'ocsp.digicert.com',
    'playfabapi.com',
    'pss-cloud.net',
    'steamcommunity.com',
    'steamcontent.com',
    'steamgames.com',
    'steampowered.com',
    'steamstatic.com',
    'steamusercontent.com',
    'testament.api.wwsga.me'


    ForEach ($domain in $RequiredDomains) {
        Write-Host 'Resolving ' -NoNewline -ForegroundColor Cyan
        Write-Host $domain -NoNewline
    
        # If not running in ISE or old PowerShell, let's make it pretty
        If ((Get-Host).Name -ne 'Windows PowerShell ISE Host' -and (Get-Host).Version -ge '7.0.0') {
            $x, $y = [Console]::GetCursorPosition() -split '\D' -ne '' -as 'int[]'
            [Console]::SetCursorPosition(46 , $y)
        }
    
        If (Resolve-DnsName -Name $domain -DnsOnly -ErrorAction SilentlyContinue) {        
            Write-Host ' [OK]' -ForegroundColor Green
        }
        Else {
            Write-Host ' [FAIL]' -ForegroundColor Red
        }
    }
    
    Write-Host "`nTesting Certificate Revocation List (CRL) connections..." -ForegroundColor Cyan
    # Adapted from: https://stackoverflow.com/questions/11531068/powershell-capturing-standard-out-and-error-with-process-object
    # This overly-complicated mess with curl is used to ensure that a HTTP and an HTTPS request are used. I'm not sure Invoke-WebRequest
    # will actually do an HTTP request and an HTTPS request.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.FileName = 'curl.exe'
    $psi.Arguments = @('-X HEAD -I http://www.microsoft.com/pkiops/crl/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2003.crl')
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()
    $output = $process.StandardOutput.ReadToEnd()
    $process.WaitForExit()
    $output = $output.Split("`n")
    Write-Host 'HTTP  CRL access ' -NoNewline
    If ($output[0].Trim() -eq 'HTTP/1.1 200 OK') {
        Write-Host '[OK]' -ForegroundColor Green
    }
    Else {
        Write-Host '[FAIL]' -ForegroundColor Red
        Write-Host 'Security software may be blocking the connection.' -ForegroundColor Yellow
    }
    $psi.Arguments = @('-X HEAD -I https://www.microsoft.com/pkiops/crl/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2003.crl')
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()
    $output = $process.StandardOutput.ReadToEnd()
    $process.WaitForExit()
    $output = $output.Split("`n")
    Write-Host 'HTTPS CRL access ' -NoNewline
    If ($output[0].Trim() -eq 'HTTP/1.1 200 OK') {
        Write-Host '[OK]' -ForegroundColor Green
    }
    Else {
        Write-Host '[FAIL]' -ForegroundColor Red
    }

    Write-Host "`nTesting OCSP connection to oneocsp.microsoft.com..." -ForegroundColor Cyan
    If ( Test-NetConnection 'oneocsp.microsoft.com' -ErrorAction SilentlyContinue -InformationLevel Quiet )
    {
        Write-Host "OCSP Connection " -NoNewLine
        Write-Host ' [OK]' -Foreground Green
    }
    Else {
        Write-Host 'OCSP Connection' -NoNewLine
        Write-Host ' [FAIL]' -ForegroundColor Red
        Write-Host 'Do you have a Pi-Hole or other DNS-blocking security software? Please whitelist oneocsp.microsoft.com.' -ForegroundColor Yellow
    }
    Test-ClientDnsConfig
    Return
}

Function Test-DnsResolution {
    param (
        [string]$hostname,
        [string[]]$dnsServers
    )
    ForEach ($server in $dnsServers) {
        Try {
            Resolve-DnsName -Name $hostname -Server $server -ErrorAction Stop | Out-Null
            Write-Host '[PASS]' -ForegroundColor Green -NoNewline
            Write-Host " DNS Server $server successfully resolved $hostname"
        }
        Catch {
            Write-Host '[FAIL]' -ForegroundColor Red -NoNewline
            Write-Host " DNS Server $server failed to resolve $hostname"
        }
    }
}

Function Test-ClientDnsConfig {
    # Define the hostname to test
    $hostname = "www.google.com"
    # Get the main network adapter with the default route
    $mainAdapter = Get-NetIPConfiguration | Where-Object { $null -ne $_.IPv4DefaultGateway -or $null -ne $_.IPv6DefaultGateway }
    # Get the DNS servers for IPv4
    Try {
            $dnsServersIPv4 = Get-DnsClientServerAddress -InterfaceIndex $mainAdapter.InterfaceIndex -AddressFamily IPv4
        } Catch {
            # Will check if null or empty in next part of script
        }
    # Get the DNS servers for IPv6
    Try {
            $dnsServersIPv6 = Get-DnsClientServerAddress -InterfaceIndex $mainAdapter.InterfaceIndex -AddressFamily IPv6
        } Catch {
            # Will check if null or empty in next part of script
        }
    
    Write-Host "`nCHECKING IPV4 DNS..." -ForegroundColor Cyan
    # Print and test DNS servers for IPv4
    If ((-not ([string]::IsNullOrEmpty($dnsServersIPv4))) -and ($dnsServersIPv4.PSObject.Properties.Name -contains 'ServerAddresses')) {
        Write-Host "[PASS]" -ForegroundColor Green -NoNewline
        Write-Host " Detected IPv4 DNS servers:"
        $dnsServersIPv4.ServerAddresses | ForEach-Object { Write-Host "       $_"
        }    
        Write-Host "`n       Testing IPv4 DNS server(s)..." -ForegroundColor Cyan
        Test-DnsResolution -hostname $hostname -dnsServers $dnsServersIPv4.ServerAddresses
    }
    Else {
        Write-Host '[FAIL] No IPv4 DNS servers found!' -ForegroundColor Yellow
        Write-Host '      Your internet is probably down right now.'
    }

    # Print and test DNS servers for IPv6
    Write-Host "`nCHECKING IPV6 DNS..." -ForegroundColor Cyan
    If ((-not ([string]::IsNullOrEmpty($dnsServersIPv6.ServerAddresses))) -and ($dnsServersIPv6.PSObject.Properties.Name -contains 'ServerAddresses')) {
        Write-Host "[PASS]" -ForegroundColor Green -NoNewline
        Write-Host ' Detected IPv6 DNS server(s):'
        $dnsServersIPv6.ServerAddresses | ForEach-Object { Write-Host "       $_" }
    
        Write-Host "`n       Testing IPv6 DNS servers..." -ForegroundColor Cyan
        Test-DnsResolution -hostname $hostname -dnsServers $dnsServersIPv6.ServerAddresses
    }
    Else {
        Write-Host "[FAIL]" -ForegroundColor Yellow -NoNewline
        Write-Host ' No IPv6 DNS servers found!'
        Write-Host 'Consider setting an IPv6 DNS server like'
        Write-Host '2606:4700:4700::1111' -ForegroundColor Cyan -NoNewline
        Write-Host ' on your network adapter.'
    }
}
Function Test-Wifi {
    # This is not very robust code and has race conditions and other issues, but it works well-enough for now
    # It pings the default gateway for 30 seconds and collects statistics
    $mainAdapter = Get-NetIPConfiguration | Where-Object { $null -ne $_.IPv4DefaultGateway -or $null -ne $_.IPv6DefaultGateway }
    Write-Host "`nTesting the connection to the default gateway..." -ForegroundColor Cyan
        If ((Get-NetAdapter -InterfaceIndex $mainAdapter.InterfaceIndex).PhysicalMediaType -ne '802.11') {
            Write-Host "`nThis is not a wireless connection. Testing anyway..." -ForegroundColor Yellow
        }
    $ipAddress = ($mainAdapter.IPv4DefaultGateway).NextHop
    $endTime = (Get-Date).AddSeconds(30)
    $pingResults = @()

    While ((Get-Date) -lt $endTime) {
        $pingResult = Test-Connection $ipAddress -Count 1 -ErrorAction SilentlyContinue
        if ($pingResult) {
            $pingResults += $pingResult
        }
    }

    # Summarize results
    $sent = $pingResults.Count
    # If Statements for PowerShell version compatibility
    If ([bool]($pingResult.PSobject.Properties.name -like 'Status')) {
    $received = $pingResults | Where-Object { $_.Status -eq 'Success' } |
    Measure-Object | Select-Object -ExpandProperty Count
    $responseTimes = $pingResults | Select-Object -ExpandProperty Latency
    }
    If ([bool]($pingResult.PSobject.Properties.name -like 'StatusCode')) {
    $received = $pingResults | Where-Object { $_.StatusCode -eq 0 } |
    Measure-Object | Select-Object -ExpandProperty Count
    $responseTimes = $pingResults | Select-Object -ExpandProperty ResponseTime
    }
    $lost = $sent - $received
    $minTime = $responseTimes | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum
    $maxTime = $responseTimes | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
    $avgTime = $responseTimes | Measure-Object -Average | Select-Object -ExpandProperty Average

    # Calculate standard deviation
    $mean = $avgTime
    $squaredDifferences = $responseTimes | ForEach-Object { ($_ - $mean) * ($_ - $mean) }
    $variance = ($squaredDifferences | Measure-Object -Sum).Sum / $responseTimes.Count
    $stdDev = [math]::Sqrt($variance)
    
    # Format to 3 significant digits
    $avgTimeFormatted = "{0:N3}" -f $avgTime
    $stdDevFormatted = "{0:N3}" -f $stdDev
    
    $packetLossPercentage = ($lost / $sent) * 100
    
    # Output results
    $results = [PSCustomObject]@{
        Sent = $sent
        Received = $received
        Lost = $lost
        PacketLossPercentage = "$packetLossPercentage %"
        MinResponseTime = "$minTime ms"
        MaxResponseTime = "$maxTime ms"
        AvgResponseTime = "$avgTimeFormatted ms"
        StdDevResponseTime = "$stdDevFormatted ms"
    }
    
    $results
    
    If ($stdDev -gt 5) {
        Write-Host "`nYour connection to your default gateway has signifcant jitter (latency variance)." -ForegroundColor Yellow
    }
    If ($packetLossPercentage -gt 1) {
        Write-Host "`nYour connection to your default gateway has more than 1% packet loss." -ForegroundColor Yellow
    } 
    If ($stdDev -le 5 -and $packetLossPercentage -le 1) {
        Write-Host "`nYour connection appears to be operating normally." -ForegroundColor Green
    }
}
Function Test-BTAGService {
    If ((Get-Service -Name BTAGService).Status -eq 'Running')
    {
        Write-Host "`n⚠️ Bluetooth Audio Gateway (BTAG) Service is running.",
        "`nThis will cause audio routing issues with Bluetooth Headphones.",
        "`nToggle this service ON or OFF from the menu (Select option B)"  -ForegroundColor Yellow
    }
    Else {
        Write-Host "`nBluetooth Audio Gateway (BTAG) Service: DISABLED",
        "`nIf using a Bluetooth Headset, this is the correct configuration." -ForegroundColor Cyan
    }
    Return
}
Function Reset-Steam {
    $SteamProcess = [PSCustomObject]@{
        ProcessName = 'steam'
        ErrorMsg    = '
    ⚠️ Steam is currently running. ⚠️
        Please close Steam first.
        '
    }
    Get-IsProcessRunning $SteamProcess
    # Remove CEF Cache
    Write-Host "`nClearing contents of $env:LOCALAPPDATA\Steam\" -ForegroundColor Cyan
    Remove-Item $env:LOCALAPPDATA\Steam\* -Recurse -ErrorAction Continue
    Write-Host "Clearing contents of $SteamPath. Keeping \steamapps, \userdata, \logs and \dumps" -ForegroundColor Cyan
    $PropertyName = "Parent"
    Get-ChildItem -Path $SteamPath -File -Recurse |
        Where-Object { (ForEach-Object { If ([bool]$_.PSObject.Properties["PSParentPath"]) {
                        $_.Name -ne "steam.exe" -and $_.PSObject.Properties["PSParentPath"].Value -notlike
                        "*" + $SteamPath + "\steamapps*" -and $_.PSObject.Properties["PSParentPath"].Value -notlike
                        "*" + $SteamPath + "\userdata*" -and $_.PSObject.Properties["PSParentPath"].Value -notlike
                        "*" + $SteamPath + "\logs*" -and $_.PSObject.Properties["PSParentPath"].Value -notlike
                        "*" + $SteamPath + "\dumps*"
                    } }) } | Remove-Item
    Write-Host 'Steam Data cleared successfully!' -ForegroundColor Green
    Write-Host 'Launching Steam now...'`n -ForegroundColor Cyan
    Start-Process $SteamPath\steam.exe
    Return
}
Function Open-AdvancedGraphics {
    Start-Process ms-settings:display-advancedgraphics
    Write-Host "`nVerify HellDivers 2 is set to use the correct GPU.",
    "`nIf HD2 is not listed, click " -NoNewline -ForegroundColor Cyan
    Write-Host "Add desktop app " -NoNewline -ForegroundColor Yellow
    Write-Host "and browse to:" -ForegroundColor Cyan
    Write-Host $AppInstallPath, "\bin\helldivers2.exe"`n -ForegroundColor Yellow
    Return
}
Function Test-PrivateIP {
    <#
        .SYNOPSIS
            Use to determine if a given IP address is within the IPv4 private address space ranges.
        .DESCRIPTION
            Returns $true or $false for a given IP address string depending on whether or not is is within the private IP address ranges.
        .PARAMETER IP
            The IP address to test.
        .EXAMPLE
            Test-PrivateIP -IP 172.16.1.2
        .EXAMPLE
            '10.1.2.3' | Test-PrivateIP
    #>
    param(
        [parameter(Mandatory, ValueFromPipeline)]
        [string]
        $IP
    )
    process {
        If ($IP -Match '(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)') {
            $true
        }
        Else {
            $false
        }
    }
}
Function Test-DualNAT {
    Write-Host "`nRunning Dual-NAT test... this will take a minute" -ForegroundColor Cyan
    $server = 'cloudflare.com'
    $ip = Resolve-DnsName -Type A $server |
        Select-Object -Expand IPAddress
    $tracedroute = Test-NetConnection -Hops 10 -TraceRoute $ip[0] -WarningAction:SilentlyContinue
    $privateIPs = @()
    ForEach ($hop in $tracedroute.TraceRoute) {
        If (Test-PrivateIP $hop) {
            $privateIPs += $hop
        }
    }
    If ($privateIPs.Count -gt 1) {
        Write-Host '⚠️ Possible Dual-NAT connection detected.' -ForegroundColor Yellow
        Write-Host 'Private IPs detected are:'
        Write-Host $privateIPs -Separator "`n"
        Write-Host "`nIf you're not sure what these results mean, the IP results are safe to share with others." -ForegroundColor Cyan
    }
    Else {
        Write-Host "`nNo Dual-NAT connection detected." -ForegroundColor Green
    }
    Pause "`nPress any key to continue..."
}
Function Switch-BTAGService {
    If (-NOT ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544')) {
    Write-Host 'This command requires Administrator privileges.',
    "`nTo run PowerShell with admin privileges:",
    "`nRight-click on PowerShell and click Run as Administrator",
    "`nThen run the script again.`n" -ForegroundColor Cyan
    } Else {
        If ((Get-Service -Name BTAGService).Status -eq 'Running') {
            Set-Service -Name BTAGService -StartupType Disabled
            Stop-Service -Name BTAGService
            Start-Sleep -Seconds 1.5
            Write-Host "`nBluetooth Audio Gateway Service", 
            "is now " -ForegroundColor Cyan
            Write-Host (Get-Service -Name BTAGService).Status`n -ForegroundColor Yellow            
        } Else {
            If ((Get-Service -Name BTAGService).Status -eq 'Stopped') {
                Set-Service -Name BTAGService -StartupType Automatic
                Set-Service -Name BTAGService -Status Running
                Start-Sleep -Seconds 1.5
                Write-Host "`nBluetooth Audio Gateway Service", 
                "is now " -ForegroundColor Cyan
                Write-Host (Get-Service -Name BTAGService).Status`n -ForegroundColor Green
            }
        }
    }
}
Function Menu {
    $Title = "💣 Hellbomb 💣 Script for Fixing Helldivers 2"
    $Prompt = "Enter your choice:"
    $Choices = @(
        [System.Management.Automation.Host.ChoiceDescription]::new('&HD2 Status Checks', 'Provides various status checks & flushes the DNS Cache.')
        [System.Management.Automation.Host.ChoiceDescription]::new('&Clear HD2 Settings (AppData)', 'Clears your profile data. Settings will be reset, but progress will not be lost.')
        [System.Management.Automation.Host.ChoiceDescription]::new('&Install VC++ Redists', 'Installs the Microsoft Visual C++ Redistributables required for HD2. Fixes startup and dll errors.')
        [System.Management.Automation.Host.ChoiceDescription]::new('Re-install &GameGuard', 'Performs a full GameGuard re-install. If Windows Ransomware Protection is enabled, may trigger security alert.')
        [System.Management.Automation.Host.ChoiceDescription]::new('Re&set Steam', 'Performs a reset of Steam. This can fix various issues including VRAM memory leaks.')
        [System.Management.Automation.Host.ChoiceDescription]::new('Set HD2 G&PU', 'Brings up the Windows GPU settings.')
        [System.Management.Automation.Host.ChoiceDescription]::new('Dual NAT &Test', 'Tests network for Dual NAT.')
        [System.Management.Automation.Host.ChoiceDescription]::new('&Wi-Fi LAN Test', 'Tests the connection to the default gateway.')
        [System.Management.Automation.Host.ChoiceDescription]::new('Toggle &Bluetooth Telephony Service', 'Toggles the BTAGService on or off. Disabling it fixes Bluetooth Headphones.')
        [System.Management.Automation.Host.ChoiceDescription]::new('E&xit', 'Exits the script.')
    )
    $Default = 0
    $Choice = $Host.UI.PromptForChoice($Title, $Prompt, $Choices, $Default)
    switch ($choice) {
        0 {
            Show-Variables
            Find-CPUInfo
            Test-Network
            Find-BlacklistedDrivers
            Test-BTAGService
            Test-Programs
            Menu
        }
        1 {
            Remove-HD2AppData
            Menu
        }
        2 {
            Install-VCRedist
            Menu
        }
        3 {
            Reset-GameGuard
            Menu
        }
        4 {
            Reset-Steam
            Menu
        }
        5 {
            Open-AdvancedGraphics
            Menu
        }
        6 {
            Test-DualNat
            Menu
        }
        7 {
            Test-WiFi
            Menu
        }
        8 {
            Switch-BTAGService
            Menu
        }
        9 { Return }
    }
}
# Set AppID
$AppID = "553850"
$global:AppIDFound = $false
$LineOfInstallDir = 8
$LineOfBuildID = 13
$SteamPath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam").InstallPath
$LibraryData = Get-Content -Path $SteamPath\steamapps\libraryfolders.vdf
# Read each line of the Steam library.vdf file
# Save a library path, then scan that library for $AppID
# If AppID is found, return current library path
ForEach ($line in $($LibraryData -split "`r`n")) {
    If ($line -like '*path*') {
        $AppInstallPath = ($line | ForEach-Object { $_.split('"')[3] })
        Write-Host $AppInstallPath
        $AppInstallPath = $AppInstallPath.Replace('\\', '\')
    }
    If (($line | ForEach-Object { $_.split('"') | Select-Object -Skip 1 }) -like "*$AppID*") {
        $global:AppIDFound = $true
        # Since we found the App location, let's get some data about it
        $GameData = Get-Content -Path $AppInstallPath\steamapps\appmanifest_$AppID.acf
        $BuildID = ($GameData[$LineOfBuildID - 1] | ForEach-Object { $_.split('"') | Select-Object -Skip 2 })
        $GameFolderName = ($GameData[$LineOfInstallDir - 1] | ForEach-Object { $_.split('"') | Select-Object -Skip 2 })
        # Update the AppInstallPath with the FULL path
        $AppInstallPath = ($AppInstallPath + "\steamapps\common\" + $GameFolderName[1])
        Break
    }
}
$HelldiversProcess = [PSCustomObject]@{
    ProcessName = 'helldivers2'
    ErrorMsg    = '
    ⚠️ The Helldivers 2 process is currently running. ⚠️
         Please close the game. If the game appears closed, restart the system, and re-run this script.
    '
}
Clear-Host
Get-IsProcessRunning $HelldiversProcess
Menu
