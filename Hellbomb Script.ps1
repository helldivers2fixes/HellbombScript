using namespace System.Management.Automation.Host
# Hellbomb Script
# Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$global:Tests = @{
    "IntelMicrocodeCheck" = @{
        'TestPassed' = $null
        'AffectedModels' = @("13900", "13700", "13790", "13700", "13600", "13500", "13490", "13400", "14900", "14790", "14700", "14600", "14500", "14490", "14400")
        'LatestMicrocode' = 0x12B
        'TestFailMsg' = @'
        Write-Host "`n[FAIL] " -ForegroundColor Red -NoNewLine
        Write-Host "`CPU model with unpatched microcode detected!! " -ForegroundColor Yellow -NoNewLine; Write-Host "$global:myCPU" -ForegroundColor White
        Write-Host "`n        WARNING: If you are NOT currently having stability issues, please update `n        your motherboard UEFI (BIOS) ASAP to prevent permanent damage to the CPU." -ForegroundColor Yellow
        Write-Host "`n        If you ARE experiencing stability issues, your CPU may be unstable`n        and permanently damaged." -ForegroundColor Red
        Write-Host "`n        For more information, visit: `n        https://www.theverge.com/2024/7/26/24206529/intel-13th-14th-gen-crashing-instability-cpu-voltage-q-a" -ForegroundColor Cyan
        Pause "`n        Any proposed fixes by this tool may fail to work if your CPU is damaged.`nPress any key to continue..." -ForegroundColor Yellow
'@
        'TestPassMsg' = @'
        Write-Host "Your CPU model: " -ForegroundColor Cyan -NoNewLine ; Write-Host "$global:myCPU " -NoNewLine
        Write-Host "is not affected by the Intel CPU issues." -ForegroundColor Green
'@
        'NotApplicableMsg' = @'
        Write-Host "Your CPU model: " -ForegroundColor Cyan -NoNewLine ; Write-Host "$global:myCPU " -NoNewLine
        Write-Host "is not affected by the Intel CPU issues." -ForegroundColor Green
'@
    }
    "PendingReboot" = @{
        'TestPassed' = $null
        'rebootRequired' = $false
        'keys' = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations")
        'TestFailMsg' = @'
        Write-Host "`n[FAIL] " -ForegroundColor Red -NoNewLine
        Write-Host " Windows is reporting a pending reboot is required." -Foreground Yellow -NoNewLine
        Write-Host "`nPlease exit the script and reboot your machine..." -ForegroundColor Cyan
'@
    }
    "BadPrinter" = @{
        'TestPassed' = $null
        'TestFailMsg' = @'
        Write-Host "`n[FAIL] " -ForegroundColor Red -NoNewLine
        Write-Host "OneNote for Windows 10 printer detected! This can cause crashes on game startup." -Foreground Yellow -NoNewLine
        Write-Host "`nPlease remove this printer from your computer." -ForegroundColor Cyan
'@
    }
    "Starlink" = @{
        'TestPassed' = $null
        'TestFailMsg' = @'
        Write-Host "`n[WARNING] " -NoNewline -ForegroundColor Yellow
        Write-Host 'Starlink detected! You need to use Wi-Fi, or disable IPv6.' -ForegroundColor Cyan
        Write-Host 'Restart your PC after making those changes.' -ForegroundColor Cyan
'@
    }

}
Function Show-Variables {
    If ($global:AppIDFound -eq $true) {
        Clear-Host
        Write-Host "AppID: $AppID is located in directory:" -ForegroundColor Green
        Write-Host $AppInstallPath -ForegroundColor White
        Write-Host "Current build of AppID $AppID is:$BuildID" -ForegroundColor Cyan
    }
    Else {
        Write-Host 'Error. AppID was not found.' -ForegroundColor Red
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
                Remove-Item -Path $DownloadPath$FileName
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
    Remove-Item -Path $DownloadPath$FileName
    # Re-enable Progress Bar
    $ProgressPreference = 'Continue'
}

Function Reset-GameGuard {
    # Delete GameGuard files
    $Error.Clear()
    Try { Remove-Item -Path $AppInstallPath\bin\GameGuard\*.* }
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
    Try { Remove-Item -Path $env:APPDATA\Arrowhead\Helldivers2\* -Recurse }
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
    Pause "`n This function will likely cause your computer to restart. Save any work before continuing..." -ForegroundColor Yellow
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
    # Hack to quickly check for missing drivers that are probably critical
     $DeviceDatabase = Get-PnpDevice
     $MissingDriverCounter = 0
     $filteredDevices = $DeviceDatabase | Where-Object {
        # Look for issues with AMD and Intel drivers only
        $_.InstanceId -match "VEN_1022|VEN_8086"
        }
        ForEach ($device in $filteredDevices) {
            If ($device.FriendlyName -match "Base System Device|Unknown" -or $device.Status -eq 'Unknown') {
            $MissingDriverCounter++
            }
        }
        
        If ($MissingDriverCounter -gt 1) {
            Write-Host "`n It appears you are missing critical AMD and/or Intel drivers." -ForegroundColor Yellow
            Write-Host "`n Please install them from your motherboard manufacturer or OEM system support site." -ForegroundColor Yellow
        }
        Return
}
Function Test-BadPrinters {
    # Get the Print Spooler service status
    $spoolerService = Get-Service -Name "Spooler"

    If ($spoolerService.StartType -ne "Disabled") {
        If ($spoolerService.Status -ne "Running") {
            # Restart the Print Spooler service if it's not running and not disabled
            Start-Service -Name "Spooler"
        }

        Get-Printer | ForEach-Object {
            If ($_.Name -eq 'OneNote for Windows 10') {
                $global:Tests.BadPrinter.TestPassed = $false
            }
        }
        $global:Tests.BadPrinter.TestPassed = $global:Tests.BadPrinter.TestPassed -ne $false
        }
    } Else { $global:Tests.BadPrinter.TestPassed = $true }
}

Function Find-CPUInfo {
    $global:myCPU = (Get-CimInstance -ClassName Win32_Processor).Name.Trim()
    ForEach ($cpuModel in $global:Tests.IntelMicrocodeCheck.AffectedModels) {
        If (($global:myCPU).Contains($cpuModel)) {
            # Check Microcode; adapted from: https://www.xf.is/2018/06/28/view-cpu-microcode-revision-from-powershell/
            $registrypath = "Registry::HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0\"
            $CPUProperties = Get-ItemProperty -Path $registrypath
            $runningMicrocode = $CPUProperties."Update Revision"
            # Convert to string and remove leading zeros
            Try { $runningMicrocodeInHex = 0x100 + ('0x'+(-join ( $runningMicrocode[0..4] | ForEach-Object { $_.ToString("X12") } )).TrimStart('0'))
                If ($runningMicrocodeInHex -lt $global:Tests.IntelMicrocodeCheck.LatestMicrocode) {
                    $global:Tests.IntelMicrocodeCheck.TestPassed = $false
                    Return
                }
            }
            Catch { $global:Tests.IntelMicrocodeCheck.TestPassed = $false }
        }
    }
    $global:Tests.IntelMicrocodeCheck.TestPassed = $true
    Return
}
Function Show-MotherboardInfo {
    $motherboardInfo = @(
    [pscustomobject]@{ 'Motherboard Info' = 'Manufacturer: '+(Get-CimInstance -ClassName Win32_BaseBoard).Manufacturer.Trim();
    'UEFI Info' = 'SMBIOS Version: '+(Get-CimInstance -ClassName Win32_BIOS).SMBIOSBIOSVersion.Trim() }
    [pscustomobject]@{ 'Motherboard Info' = 'Product: '+(Get-CimInstance -ClassName Win32_BaseBoard).Product.Trim();
    'UEFI Info' = 'Manufacturer: '+(Get-CimInstance -ClassName Win32_BIOS).Manufacturer.Trim() }
    [pscustomobject]@{ 'Motherboard Info' = '';
    'UEFI Info' = 'BIOS Version: '+(Get-CimInstance -ClassName Win32_BIOS).Name.Trim() }
    )
    $motherboardInfo | Format-Table 'Motherboard Info', 'UEFI Info' -AutoSize
}
Function Show-GPUInfo {
    $GPUS = Get-CimInstance -ClassName Win32_VideoController

    # Print GPU information
    ForEach ($gpu in $gpus) {
        Write-Host "-----------------------------------"
        Write-Host "GPU Model: $($gpu.Name)"
        Write-Host "Drvr Ver.: $($gpu.DriverVersion)"
        Write-Host "Status: $($gpu.Status)"
        Write-Host "-----------------------------------"
    }
}

Function Get-InstalledPrograms {
    # This portion modified from:
    # https://devblogs.microsoft.com/scripting/use-powershell-to-quickly-find-installed-software/
       Write-Host "`nGathering installed programs..." -ForegroundColor Cyan

    $UninstallPaths = @(
        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    
    $installedPrograms = @()
    
    $regKeys = @(
        [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64),
        [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
    )

    ForEach ($baseKey in $regKeys) {
        ForEach ($path in $UninstallPaths) {
            $regKey = $baseKey.OpenSubKey($path)
            If ($regKey) {
                ForEach ($subKeyName in $regKey.GetSubKeyNames()) {
                    $subKey = $regKey.OpenSubKey($subKeyName)
                    If ($subKey) {
                        $displayName = $subKey.GetValue("DisplayName")
                        $displayVersion = $subKey.GetValue("DisplayVersion") -replace '^[a-zA-Z]+|[a-zA-Z]$', '' -replace '\s+', ''
                        $installLocation = $subKey.GetValue("InstallLocation")
                        $publisher = $subKey.GetValue("Publisher")

                        If ($displayName) {
                            $installedPrograms += [PSCustomObject]@{
                                DisplayName     = $displayName
                                DisplayVersion  = If ($displayVersion) { Try { [System.Version]$displayVersion } Catch { '0.0.0' } } Else { '0.0.0' }
                                InstallLocation = $installLocation
                                Publisher       = $publisher
                            }
                        }
                    }
                }
            }
        }
    }

    Return $installedPrograms | Where-Object { $_.DisplayName } | Sort-Object DisplayName
}

Function Test-Programs {
    Write-Host "`nChecking for programs that interfere with Helldivers 2..." -ForegroundColor Cyan
    # Avast Web Shield checks
    $regPath = "HKLM:\SOFTWARE\Avast Software\Avast\properties\WebShield\Common"
    $regName = "ProviderEnabled"

    Try {
    $value = Get-ItemProperty -Path $regPath -Name $regName
    If ($value.$regName -eq 1)
        {
            Write-Host "`n⚠️ Avast Webshield is enabled!" -ForegroundColor Yellow
            Write-Host 'Ensure an exception is added for ' -ForegroundColor Cyan -NoNewline
            Write-Host 'https://microsoft.com ' -NoNewline
            Write-Host 'to prevent HTTPS CRL access issues.' -ForegroundColor Cyan
            Write-Host 'More information can be found here: https://discord.com/channels/1102970375731691612/1218153537914273802/1273154218022408252'
        }
    }
    Catch { # Value does not exist
    }
    # Hack to check for Avast and Nahimic without requiring the script to need Admin privileges
    $InstalledServices = Get-Service -Exclude McpManagementService, NPSMSvc_*, WaaSMedicSvc
    ForEach ($service in $InstalledServices)
    {
        If ($service.Name -like 'avast*' -and $service.StartType -ne 'Disabled') {
            $obj = [PSCustomObject]@{
                DisplayName    = 'Avast Internet Security'
                DisplayVersion = '0.0.0'
            }
            $array += $obj
        }
        If ($service.Name -like 'Nahimic*' -and $service.StartType -ne 'Disabled') {
            $obj = [PSCustomObject]@{
                DisplayName    = 'Nahimic'
                DisplayVersion = '0.0.0'
            }
            $array += $obj
        }
    }    

    $ProblematicPrograms = @(
    [PSCustomObject]@{ProgramName = 'AMD Chipset Software'; RecommendedVersion = '6.05.28.016'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Your ver. may be SLIGHTLY older. Latest @ https://www.amd.com/en/support/download/drivers.html.' }
    [PSCustomObject]@{ProgramName = 'Avast Internet Security'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause performance issues. Recommend uninstalling. Disabling when playing MAY resolve issues.' }
    [PSCustomObject]@{ProgramName = 'Cepstral SwiftTalker'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Known to cause crashes in the past.' }
    [PSCustomObject]@{ProgramName = 'ESET Endpoint'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause crashes. Please disable/add exclusions for *.des files in tools folder.' }
    [PSCustomObject]@{ProgramName = 'ESET File'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause crashes. Please disable/add exclusions for *.des files in tools folder.' }
    [PSCustomObject]@{ProgramName = 'ESET Management'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause crashes. Please disable/add exclusions for *.des files in tools folder.' }
    [PSCustomObject]@{ProgramName = 'ESET PROTECT'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause crashes. Please disable/add exclusions for *.des files in tools folder.' }
    [PSCustomObject]@{ProgramName = 'ESET Rogue'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause crashes. Please disable/add exclusions for *.des files in tools folder.' }
    [PSCustomObject]@{ProgramName = 'ESET Security'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause crashes. Please disable/add exclusions for *.des files in tools folder.' }
    [PSCustomObject]@{ProgramName = 'Hamachi'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Breaks connectivity. Recommend uninstalling or disable IN DEVICE MANAGER.' }
    [PSCustomObject]@{ProgramName = 'iCue'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Outdated versions are known to cause issues.' }
    [PSCustomObject]@{ProgramName = 'Lunar Client'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Exit Lunar Client before launching HD2 to prevent connectivity issues.' }
    [PSCustomObject]@{ProgramName = 'MSI Afterburner'; RecommendedVersion = '4.6.5'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Outdated versions cause crashing & performance issues.' }
    [PSCustomObject]@{ProgramName = 'Mullvad VPN'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Causes connection issues. Recommend uninstall or disable in DEVICE MANAGER.' }
    [PSCustomObject]@{ProgramName = 'Nahimic'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Myriad of issues. Recommend removing all devices and services.' }
    [PSCustomObject]@{ProgramName = 'Norton 360'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Will destroy FPS if Game Optimizer is enabled. Disable Game Optimizer in Norton 360.' }
    [PSCustomObject]@{ProgramName = 'Outplayed'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause stuttering & VRAM leaks. Disable Outplayed Autoclipping or disable/uninstall.' }
    [PSCustomObject]@{ProgramName = 'Overwolf'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause stuttering & VRAM leaks. Disable Outplayed Autoclipping or disable/uninstall.' }
    [PSCustomObject]@{ProgramName = 'Process Lasso'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Causes threading and stability issues. Please uninstall.' }
    [PSCustomObject]@{ProgramName = 'Radmin'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Will cause network issues. Recommend uninstall or disable in DEVICE MANAGER.' }
    [PSCustomObject]@{ProgramName = 'Razer Cortex'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Causes severe performance issues. Must disable/uninstall.' }
    [PSCustomObject]@{ProgramName = 'Ryzen Master'; RecommendedVersion = '2.13.0.2908'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Known to cause RAM leaks & general issues. Recommend uninstalling.' }
    [PSCustomObject]@{ProgramName = 'Samsung Magician'; RecommendedVersion = '8.1'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Outdated versions break connectivity completely.' }
    [PSCustomObject]@{ProgramName = 'Surfshark'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Will prevent connectivity. Recommend uninstall or disable IN DEVICE MANAGER.' }
    [PSCustomObject]@{ProgramName = 'Wargaming.net Game Center'; Installed = $false; RecommendedVersion = '100.100'; InstalledVersion = '0.0.0'; Notes = 'Reported to cause issues.' }
    [PSCustomObject]@{ProgramName = 'Webroot'; Installed = $false; RecommendedVersion = '100.100'; InstalledVersion = '0.0.0'; Notes = 'Causes low FPS. Uninstall or launch HD2 & THEN shutdown Webroot.' }
    [PSCustomObject]@{ProgramName = 'Wemod'; Installed = $false; RecommendedVersion = '100.100'; InstalledVersion = '0.0.0'; Notes = 'Has a kernel-level driver that enables cheats. Disable/Exit/Uninstall if having issues.' }
    [PSCustomObject]@{ProgramName = 'ZeroTier One'; Installed = $false; RecommendedVersion = '100.100'; InstalledVersion = '0.0.0'; Notes = 'Causes connectivity issues. Recommend uninstalling or disable IN DEVICE MANAGER.'})
    $bool = $false
    ForEach ($program in $ProblematicPrograms) {
        ForEach ($installedApp in $global:InstalledProgramsList) {
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
        Write-Host ("{0,-33} {1,-20} {2,-35}" -f "Program Name", "Installed Version", "Notes") -ForegroundColor Cyan
        Write-Host ("{0,-33} {1,-20} {2,-35}" -f '--------------------------------',
        '-----------------',
        '------------------------------------------------------------------------------------------------')
        ForEach ($row in $result) {
            Write-Host '[FAIL] ' -ForegroundColor Red -NoNewline
            Write-Host ("{0,-26}" -f $row.ProgramName) -ForegroundColor Yellow -NoNewline
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

        Write-Host "`n⚠️ Windows Firewall is blocking Helldivers 2." -ForegroundColor Red
        Write-Host 'On game launch, Steam should request Admin privileges and add the Inbound rule(s) for you.' -ForegroundColor Yellow
        Write-Host 'You may need to add the rule(s) manually if this does not happen.' -ForegroundColor Yellow
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
    # This overly-complicated mess with curl is used to ensure that an HTTP and an HTTPS request are used. Invoke-WebRequest
    # will return false positives when it's actually broken.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.FileName = 'curl.exe'
    $psi.Arguments = @('-X HEAD -I http://www.microsoft.com/pkiops/crl/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2003.crl')
    # Set encoding to UTF8 so that Unicode compilation doesn't break curl arguments
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
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
    Write-Progress -Completed -Activity "make progress bar dissapear"
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
    $mainAdapter = Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
    Sort-Object -Property { $_.InterfaceMetric + $_.RouteMetric } |
    Select-Object -First 1 | Get-NetAdapter
    $IPv6Status = Get-NetAdapterBinding -Name $mainAdapter.Name -ComponentID ms_tcpip6

    # Get the DNS servers for IPv4
    Try {
            $dnsServersIPv4 = Get-DnsClientServerAddress -InterfaceIndex $mainAdapter.InterfaceIndex -AddressFamily IPv4
        } Catch {
            # Will check if null or empty in next part of script
        }
        Write-Host "`nCHECKING IPv4 DNS..." -ForegroundColor Cyan
        # Print and test DNS servers for IPv4
        If (-not ([string]::IsNullOrEmpty(($dnsServersIPv4 | Get-Member -Name 'ServerAddresses')))) {
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

    # Get the DNS servers for IPv6
    If ($IPv6Status.Enabled) {
        Try {
                $dnsServersIPv6 = Get-DnsClientServerAddress -InterfaceIndex $mainAdapter.InterfaceIndex -AddressFamily IPv6
            } Catch {
                Write-Host '[FAIL] ' -ForegroundColor Red -NoNewline
                Write-Host 'IPv6 issues detected. Please disable IPv6 on your network adapter.' -ForegroundColor Yellow
                Write-Host 'Opening the Network Adapters screen now...' -ForegroundColor Cyan
                Start-Process 'ncpa.cpl'
            }
        # Print and test DNS servers for IPv6
        Write-Host "`nCHECKING IPv6 DNS..." -ForegroundColor Cyan
        If (-not ([string]::IsNullOrEmpty(($dnsServersIPv6 | Get-Member -Name 'ServerAddresses')))) {
        Write-Host "[PASS]" -ForegroundColor Green -NoNewline
        Write-Host ' Detected IPv6 DNS server(s):'
        $dnsServersIPv6.ServerAddresses | ForEach-Object { Write-Host "       $_"
        }
        Write-Host "`n       Testing IPv6 DNS servers..." -ForegroundColor Cyan
        Try { 
            Test-DnsResolution -hostname $hostname -dnsServers $dnsServersIPv6.ServerAddresses
        } Catch {
            Write-Host '[FAIL] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No IPv6 DNS servers found!'
            Write-Host 'Consider setting an IPv6 DNS server like'
            Write-Host '2606:4700:4700::1111' -ForegroundColor Cyan -NoNewline
            Write-Host ' on your network adapter.'
        }
        
        }
        Else {
            Write-Host '[FAIL] ' -ForegroundColor Yellow -NoNewline
            Write-Host 'No IPv6 DNS servers found!'
            Write-Host 'Consider setting an IPv6 DNS server like'
            Write-Host '2606:4700:4700::1111' -ForegroundColor Cyan -NoNewline
            Write-Host ' on your network adapter.'
        }
    }
    Else { Write-Host "`nSkipping IPv6 checks because IPv6 is disabled." -ForegroundColor Cyan }       
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
        If ($pingResult) {
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
        Write-Host "Your connection to your default gateway has significant jitter (latency variance).`n`n" -ForegroundColor Yellow
    }
    If ($packetLossPercentage -gt 1) {
        Write-Host "Your connection to your default gateway has more than 1% packet loss.`n`n" -ForegroundColor Yellow
    } 
    If ($stdDev -le 5 -and $packetLossPercentage -le 1) {
        Write-Host "Your connection appears to be operating normally.`n`n" -ForegroundColor Green
    }
}
Function Test-BTAGService {
    If ((Get-Service -Name BTAGService).Status -eq 'Running')
    {
        Write-Host "`n⚠️ Bluetooth Audio Gateway (BTAG) Service is running." -ForegroundColor Yellow
        Write-Host 'This will cause audio routing issues with ' -NoNewLine -ForegroundColor Cyan
        Write-Host 'Bluetooth Headphones.' -NoNewline -ForegroundColor Yellow 
        Write-Host "`nToggle this service ON or OFF from the menu (Select option B)" -ForegroundColor Cyan
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
    Pause "You will need to sign into Steam after this process completes.`nPress any key to continue..." ForegroundColor Yellow
    # Remove CEF Cache
    Write-Host "`nClearing contents of $env:LOCALAPPDATA\Steam\" -ForegroundColor Cyan
    Remove-Item -Path $env:LOCALAPPDATA\Steam\* -Recurse -ErrorAction Continue
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
Function Test-DoubleNAT {
    Write-Host "`nRunning Double-NAT test... this will take a minute" -ForegroundColor Cyan
    $server = 'cloudflare.com'
    $ip = Resolve-DnsName -Type A $server |
        Select-Object -Expand IPAddress
    $tracedroute = Test-NetConnection -Hops 10 -TraceRoute $ip[0] -WarningAction:SilentlyContinue
    Write-Progress -Completed -Activity "make progress bar dissapear"
    $privateIPs = @()
    ForEach ($hop in $tracedroute.TraceRoute) {
        If (Test-PrivateIP $hop) {
            $privateIPs += $hop
        }
    }
    If ($privateIPs.Count -gt 1) {
        Write-Host '⚠️ Possible Double-NAT connection detected.' -ForegroundColor Yellow
        Write-Host 'Private IPs detected are:'
        Write-Host $privateIPs -Separator "`n"
        Write-Host "`nIf you're not sure what these results mean, the IP results are safe to share with others." -ForegroundColor Cyan
    }
    Else {
        Write-Host "`nNo Double-NAT connection detected." -ForegroundColor Green
    }
    Pause "`nPress any key to continue..."
}
Function Switch-BTAGService {
    If (-not ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544')) {
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
            Write-Host (Get-Service -Name BTAGService).Status -ForegroundColor Yellow
            Write-Host 'Please disconnect and re-connect your Bluetooth device.'`n -ForegroundColor Cyan
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
Function Test-VisualC++Redists {
    $VCRedists = @(
    [PSCustomObject]@{ProgramName = 'Microsoft Visual C++ 2012 Redistributable (x64)'; Installed = $false},
    [PSCustomObject]@{ProgramName = 'Microsoft Visual C++ 2013 Redistributable (x64)'; Installed = $false},
    [PSCustomObject]@{ProgramName = 'Microsoft Visual C++ 2015-2022 Redistributable (x64)'; Installed = $false}
    )
    
    Write-Host "`nChecking for required Microsoft Visual C++ Redistributables..." -ForegroundColor Cyan
     # Speed up the search by checking if the program name starts with 'Microsoft' before entering nested loop
    $filteredApps = $global:InstalledProgramsList | Where-Object { $_.DisplayName -like 'Microsoft Visual*' }
    
    ForEach ($vcRedist in $VCRedists) {
            If ($filteredApps.DisplayName -like "$($vcRedist.ProgramName)*") {
                $vcRedist.Installed = $true
            }
        }
    $missingRedists = $VCRedists | Where-Object { $_.Installed -eq $false }
    If ($missingRedists) {
        Write-Host "`nYou are missing critical Visual C++ Redists. The game will not run.`n" -ForegroundColor Yellow
        Write-Host ("{0,-33}" -f "Missing Visual C++ Redistributable(s)") -ForegroundColor Cyan
        Write-Host ("{0,-33}" -f '-------------------------------------')
        ForEach ($redist in $missingRedists) {
            Write-Host '[FAIL] ' -ForegroundColor Red -NoNewline
            Write-Host ("{0,-26}" -f $redist.ProgramName) -ForegroundColor Yellow
        }
        Write-Host "`nPlease install them using the [" -ForegroundColor Yellow -NoNewline
        Write-Host 'I' -NoNewLine
        Write-Host '] option on the menu.' -ForegroundColor Yellow
    }
    Else {
        Write-Host 'All required Visual C++ Redists found!' -ForegroundColor Green
    }
    Return
}
Function Test-MemoryChannels {
    Write-Host 'Checking to see if multi-channel memory is enabled...' -ForegroundColor Cyan
    $TextHolder = $null
    $SystemMemoryInfoObj = Get-CimInstance Win32_PhysicalMemory
    $DeviceLocatorChannels = 1
    $BankLabelChannels = 1
    Try { 
            $DeviceLocatorChannels = ($SystemMemoryInfoObj.DeviceLocator | Sort-Object -Unique).Count
            $BankLabelChannels = ($SystemMemoryInfoObj.BankLabel | Sort-Object -Unique).Count
        }
            
    Catch {
            # If that errors, then there is only one DIMM installed
    }
    $NumberofChannels = [Math]::Max($DeviceLocatorChannels, $BankLabelChannels)
    $MemoryTextStrings = @(
    [PSCustomObject]@{ChannelCount = '2'; String = 'Dual'},
    [PSCustomObject]@{ChannelCount = '3'; String = 'Triple'},
    [PSCustomObject]@{ChannelCount = '4'; String = 'Quad'}
    )
    $TextHolder = $MemoryTextStrings | Where-Object {$_.ChannelCount -match $NumberofChannels}
    If ( $TextHolder ) {
        Write-Host '[PASS] ' -NoNewLine -ForegroundColor Green
        Write-Host ($TextHolder.String) -NoNewline
        Write-Host '-channel Memory is enabled!'
        } Else {
            Write-Host '[FAIL] ' -NoNewLine -ForegroundColor Red
            Write-Host "WARNING: It appears your system is running in single-channel memory mode." -ForegroundColor Yellow
            Write-Host '       This detection is not perfect, but if true, this will usually cause severe performance issues.' -ForegroundColor Yellow
    }
}
# Function to check if a reboot is required
Function Test-PendingReboot {
    ForEach ($key in $global:Tests.PendingReboot.keys) {
        If (Test-Path $key) {
            $global:Tests.PendingReboot.RebootRequired = $true
            Break
        }
    }
    If ($global:Tests.PendingReboot.RebootRequired) {
        $global:Tests.PendingReboot.TestPassed = $false
    } Else {
        $global:Tests.PendingReboot.TestPassed = $true
    }
}
Function Reset-HD2SteamCloud {
    Clear-Host
    Write-Host "`nThis function will reset your HD2 Steam Cloud saved data." -ForegroundColor Cyan
    Write-Host 'You will lose any custom key bindings. ' -NoNewline
    Write-Host 'No game progress will be lost.' -ForegroundColor Yellow
    Write-Host "This can resolve a myriad of input issues, and in some instances,`ncan resolve the game not running at all."
    Write-Host "If you have multiple Steam user profiles,`nthis function will clear the LAST USED HD2 Steam Cloud profile."-Foreground Yellow
    Write-Host "If you need to switch Steam profiles before running this script,`nplease close the script or press " -NoNewline
    Write-Host 'Ctrl + C' -NoNewline -ForegroundColor Cyan
    Write-Host " to stop the script...`nOpen Steam using the correct Steam profile and re-run this script."
    Write-Host "`nThese are the steps that will be completed:"
    Write-Host "1.) Script will close Steam if it is running`n2.) Script will temporarily disable Steam Cloud saves for HD2`n3.) Script will delete your HD2 Steam Cloud data`n4.) Script will pause`n5.) Script will request for you to run Helldivers 2`n    and load into the ship to generate new Steam Cloud files."
    Write-Host "6.) You will close the game, and continue the script."
    Write-Host "7.) Script will re-enable Steam Cloud saves for HD2. `n    The new files to be synced to Steam Cloud next time Steam is launched."
    Pause 'Press any key to continue.'
    # Shutdown Steam and disable SteamCloud
    # Get the Steam process
    $steamProcess = Get-Process -Name "Steam" -ErrorAction SilentlyContinue
    
    # Check if the Steam process is running
    If ($steamProcess) {
        # Stop the Steam process
        Stop-Process -Name "Steam" -Force
        Write-Host "Steam has been stopped... continuing"
    } Else {
        Write-Host "Steam is not running... continuing"
    }

    # Get all immediate subfolders
    $subfolders = Get-ChildItem -Path (Join-Path $SteamPath -ChildPath 'userdata') -Directory
    
    # Initialize variables to track the most recently modified subfolder
    $mostRecentTime = [datetime]::MinValue
    
    # Iterate through each subfolder to find the most recently modified files
    ForEach ($subfolder in $subfolders) {
        $files = Get-ChildItem -Path $subfolder.FullName -Recurse -File
        ForEach ($file in $files) {
            If ($file.LastWriteTime -gt $mostRecentTime) {
                $mostRecentTime = $file.LastWriteTime
                $global:mostRecentSteamUserProfilePath = $subfolder
            }
        }
    }
    
    $HD2SteamCloudSaveFolder = Join-Path $mostRecentSteamUserProfilePath.FullName -ChildPath $AppID

    # Define the path to the sharedconfig.vdf file
    $sharedConfigPath = Join-Path $mostRecentSteamUserProfilePath.FullName -ChildPath '\7\remote\sharedconfig.vdf'
    
    $configContent = Get-Content -Path $sharedConfigPath
    
    $inAppSection = $false
    $modifiedContent = @()
    
    # Parse the sharedconfig.vdf file and modify the cloudenabled value to '0'
    ForEach ($line in $configContent) {
        If ($line -match $global:AppID) {
            $inAppSection = $true
        } ElseIf ($inAppSection -and $line -match '"cloudenabled"') {
            $line = $line -replace '("cloudenabled"\s+)"\d+"', '$1"0"'
            $inAppSection = $false
        }
        $modifiedContent += $line
    }
    
    # Write the modified content back to the sharedconfig.vdf file and then clear the modifiedContent array
    $modifiedContent | Out-File -FilePath $sharedConfigPath -Encoding UTF8 -Force
    $modifiedContent = @()
    
    Write-Host 'Cloud save for HD2 has been disabled.' -Foreground Cyan
    Remove-Item -Path $HD2SteamCloudSaveFolder\* -Recurse
    Write-Host "Cleared cloud save folder $HD2SteamCloudSaveFolder" -Foreground Cyan
    
    Write-Host "STOP! Please open Helldivers 2 and skip intro/wait until it gets to the menu BEFORE continuing the script..." -ForegroundColor Red
    pause 'Press any key to continue...'

    Write-Host 'Re-enabling Cloud Save for HD2...' -Foreground Cyan
    $configContent = Get-Content -Path $sharedConfigPath
    ForEach ($line in $configContent) {
        Ff ($line -match $global:AppID) {
            $inAppSection = $true
        } ElseIf ($inAppSection -and $line -match '"cloudenabled"') {
            $line = $line -replace '("cloudenabled"\s+)"\d+"', '$1"1"'
            $inAppSection = $false
        }
        $modifiedContent += $line
    }
    $modifiedContent | Out-File -FilePath $sharedConfigPath -Encoding UTF8 -Force
    $modifiedContent = $null
    Write-Host 'HD2 Steam Cloud clearing procedures completed!' -Foreground Cyan
}
Function Switch-FullScreenOptimizations
{
    # Define the path to the executable
    $exePath = "$global:AppInstallPath\bin\helldivers2.exe"
    # Define the registry path
    $regPath = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
    # Check if the registry key exists, create it if it doesn't
    If (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    # Check if the property exists within the registry key
    $currentProperty = Get-ItemProperty -Path $regPath -Name $exePath -ErrorAction SilentlyContinue
    If ($null -eq $currentProperty)
    {
        # Create the property if it doesn't exist
        New-ItemProperty -Path $regPath -Name $exePath -Value 'DISABLEDXMAXIMIZEDWINDOWEDMODE' -PropertyType String | Out-Null
    } Else {
            # Check the current value of the property
            $currentValue = ($currentProperty | Select-Object -ExpandProperty $exePath -ErrorAction SilentlyContinue).Trim()
            If ($currentValue -like "*DISABLEDXMAXIMIZEDWINDOWEDMODE*") {
                $newValue = ($currentValue -replace "DISABLEDXMAXIMIZEDWINDOWEDMODE", "").Trim()
                If ($newValue) {
                    Set-ItemProperty -Path $regPath -Name $exePath -Value $newValue
                } Else {
                    Remove-ItemProperty -Path $regPath -Name $exePath
                }
                Return Write-Host "`nFullscreen optimizations enabled for $exePath. This is probably not desired." -ForegroundColor Yellow
            } Else {
                # Append DISABLEDXMAXIMIZEDWINDOWEDMODE to the current value
                $newValue = "$currentValue DISABLEDXMAXIMIZEDWINDOWEDMODE"
                Set-ItemProperty -Path $regPath -Name $exePath -Value $newValue
            }
        }
        Return Write-Host "`nFullscreen optimizations disabled for $exePath. This is probably the desired setting." -ForegroundColor Green
    }
Function Reset-HostabilityKey {
    $configPath = "$env:APPDATA\Arrowhead\Helldivers2\user_settings.config"
    Try { $OriginalHash = Get-FileHash $configPath }
    Catch {
        Write-Host '[FAIL] ' -NoNewLine -ForegroundColor Red
        Write-Host 'User_settings.config is missing.' -ForegroundColor Yellow
        Return
    }
    $content = Get-Content $configPath
    $content = $content -replace 'hostability\s*=.*', 'hostability = ""'
    Set-Content $configPath -Value $content
    If ( $OriginalHash -ne (Get-FileHash $configPath) ) {
        Write-Host "Hostability key removed successfully!`n" -ForegroundColor Green
    }
    Else {
        Write-Host '[FAIL] ' -NoNewLine -ForegroundColor Red
        Write-host 'Hostabiltiy key could not be removed.`n' -ForegroundColor Yellow
    }    
}

Function Get-PublicIPAddress {
    $ip = (Invoke-WebRequest -URI "http://ifconfig.me/ip").Content.Trim()
    Return $ip
}

Function Get-ISPInfo {
    Param (
        [string]$ipAddress
    )
    $URL = "http://ipinfo.io/$ipAddress/json"
    $response = Invoke-RestMethod -Uri $url
    Return $response
}

Function Get-ISPName {
# Get the public IP address
$PublicIP = Get-PublicIPAddress

# Get the ISP information
Try { $ISPInfo = Get-ISPInfo -ipAddress $PublicIP }
Catch {
    $ispInfo = [PSCustomObject]@{
        org = $null
    }
    $ispInfo.org = 'Denied'
    Write-Host "`nCould not determine if on Starlink internet.`n" -Foreground Cyan
}

# Check if the ISP is Starlink
If ( $ispInfo.org -like "*Starlink*" ) {
    $global:Tests.Starlink.TestPassed =  $false
    }
    Else { $global:Tests.Starlink.TestPassed =  $true }
}

Function Restart-Resume {
    Return ( Test-Path $PSScriptRoot\HellbombRestartResume )
}
Function Menu {
    $Title = "-------------------------------------------------------------------------------------------------------
    💣 Hellbomb 💣 Script for Fixing Helldivers 2 Version 2.3.1.1 🎅❄️🎄✝️
-------------------------------------------------------------------------------------------------------"
    $Prompt = "Enter your choice:"
    $Choices = [ChoiceDescription[]](
        [ChoiceDescription]::new("&HD2 Status Checks`n", 'Provides various status checks & flushes the DNS Cache.'),
        [ChoiceDescription]::new("&Clear HD2 Settings (AppData)", 'Clears your profile data. Settings will be reset, but progress will not be lost.'),
        [ChoiceDescription]::new("&Install VC++ Redists", 'Installs the Microsoft Visual C++ Redistributables required for HD2. Fixes startup and DLL errors.'),
        [ChoiceDescription]::new("Re-install &GameGuard", 'Performs a full GameGuard re-install. If Windows Ransomware Protection is enabled, may trigger security alert.'),
        [ChoiceDescription]::new("Re&set Steam`n", 'Performs a reset of Steam. This can fix various issues including VRAM memory leaks.'),
        [ChoiceDescription]::new("Set HD2 G&PU    ", 'Brings up the Windows GPU settings.'),
        [ChoiceDescription]::new("Full-Screen &Optimizations Toggle`n", 'Despite the name, having this off is usually recommended.'),
        [ChoiceDescription]::new("Double-NAT &Test", 'Tests network for Double NAT.'),
        [ChoiceDescription]::new("🛜 &Wi-Fi LAN Test`n", 'Tests the connection to the default gateway.'),
        [ChoiceDescription]::new("Toggle &Bluetooth Telephony Service`n", 'Toggles the BTAGService on or off. Disabling it fixes Bluetooth Headphones.'),
        [ChoiceDescription]::new("Clear HD2 Stea&m Cloud", 'Resets HD2 Steam Cloud. For input issues & game not opening on any device. No progress will be lost.'),
        [ChoiceDescription]::new("Clear &Z Hostability Key`n", 'Fixes some game join issues by removing the current hostability key in user_settings.config'),
        [ChoiceDescription]::new('E&xit', 'Exits the script.')
    )
    $DefaultChoice = 0
    $Choice = $Host.UI.PromptForChoice($Title, $Prompt, $Choices, $DefaultChoice)
    switch ($Choice) {
        0 {
            Show-Variables
            Show-MotherboardInfo
            Show-GPUInfo
            Test-PendingReboot
            Reset-HostabilityKey
            Get-ISPName
            Find-CPUInfo
            Test-MemoryChannels
            Test-Network
            Find-BlacklistedDrivers
            Test-BadPrinters
            Test-BTAGService
            Test-VisualC++Redists
            Test-Programs
            Show-TestResults
            Write-Host "`n"
            Menu
        }
        1 {
            Remove-HD2AppData
            Write-Host "`n"
            Menu
        }
        2 {
            Install-VCRedist
            Write-Host "`n"
            Menu
        }
        3 {
            Reset-GameGuard
            Write-Host "`n"
            Menu
        }
        4 {
            Reset-Steam
            Write-Host "`n"
            Menu
        }
        5 {
            Open-AdvancedGraphics
            Write-Host "`n"
            Menu
        }
        6 {
            Switch-FullScreenOptimizations
            Write-Host "`n"
            Menu
        }
        7 {
            Test-DoubleNat
            Write-Host "`n"
            Menu
        }
        8 {
            Test-WiFi
            Write-Host "`n"
            Menu
        }
        9 {
            Switch-BTAGService
            Write-Host "`n"
            Menu
        }
        10 {
            Reset-HD2SteamCloud
            Write-Host "`n"
            Menu
        }
        11 {
            Reset-HostabilityKey
            Write-Host "`n"
            Menu
        }
        12 { Return }
    }
}
Function Show-TestResults {
    $global:Tests.GetEnumerator() | ForEach-Object {

        If ($_.Value.TestPassed -ne $true) {
            Invoke-Expression $_.Value.TestFailMsg
        }
    }
}
Write-Host 'Locating Steam...' -ForegroundColor Cyan
# Set AppID
$global:AppID = "553850"
$global:AppIDFound = $false
$LineOfInstallDir = 8
$LineOfBuildID = 13
Try { 
    $global:SteamPath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam").InstallPath
}
Catch { 
    Write-Host '[FAIL]' -NoNewline -ForegroundColor Red
    Write-Host 'Steam was not detected. Exiting Steam to fix this issue.'
    # Get the Steam process
    $steamProcess = Get-Process -Name "steam" -ErrorAction SilentlyContinue
    If ($steamProcess) {
    # Stop the Steam process
    Stop-Process -Name "steam" -Force
    }
    $global:SteamPath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam").InstallPath
}
Write-Host 'Locating Steam Library Data...' -ForegroundColor Cyan
$LibraryData = Get-Content -Path $SteamPath\steamapps\libraryfolders.vdf
# Read each line of the Steam library.vdf file
# Save a library path, then scan that library for $AppID
# If AppID is found, return current library path
ForEach ($line in $($LibraryData -split "`r`n")) {
    If ($line -like '*path*') {
        $global:AppInstallPath = ($line | ForEach-Object { $_.split('"')[3] })
        Write-Host $global:AppInstallPath
        $global:AppInstallPath = $global:AppInstallPath.Replace('\\', '\')
    }
    If (($line | ForEach-Object { $_.split('"') | Select-Object -Skip 1 }) -like "*$AppID*") {
        $global:AppIDFound = $true
        # Since we found the App location, let's get some data about it
        $GameData = Get-Content -Path $global:AppInstallPath\steamapps\appmanifest_$AppID.acf
        $BuildID = ($GameData[$LineOfBuildID - 1] | ForEach-Object { $_.split('"') | Select-Object -Skip 2 }).Trim()
        $GameFolderName = ($GameData[$LineOfInstallDir - 1] | ForEach-Object { $_.split('"') | Select-Object -Skip 2 })
        # Update the AppInstallPath with the FULL path
        $global:AppInstallPath = ( $global:AppInstallPath + "\steamapps\common\" + $GameFolderName[1] )
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
$global:InstalledProgramsList = $null
Write-Host 'Checking to see if Helldivers 2 is currently running...' -ForegroundColor Cyan
Get-IsProcessRunning $HelldiversProcess
$global:InstalledProgramsList = Get-InstalledPrograms
Write-Host "Building menu... `n`n"
Menu
