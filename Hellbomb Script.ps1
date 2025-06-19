using namespace System.Management.Automation.Host
# Get the current host UI RawUI object
$pshost = Get-Host
$psWindow = $pshost.UI.RawUI
# Set the window size (height and width)
$newWindowSize = $psWindow.WindowSize
$newWindowSize.Height = 50   # Adjust height as needed
$psWindow.WindowSize = $newWindowSize
# Hellbomb Script
# Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$script:Tests = @{
    "IntelMicrocodeCheck" = @{
        'TestPassed' = $null
        'AffectedModels' = @("13900", "13700", "13790", "13700", "13600", "13500", "13490", "13400", "14900", "14790", "14700", "14600", "14500", "14490", "14400")
        'LatestMicrocode' = @("12F", "3A")
        'TestFailMsg' = @'
        Write-Host "$([Environment]::NewLine)[FAIL] " -ForegroundColor Red -NoNewLine
        Write-Host "CPU model with unpatched microcode detected!! " -ForegroundColor Yellow -NoNewLine; Write-Host "$script:myCPU" -ForegroundColor White
        Write-Host "$([Environment]::NewLine)        WARNING: If you are NOT currently having stability issues, please update $([Environment]::NewLine)        your motherboard UEFI (BIOS) ASAP to prevent permanent damage to the CPU." -ForegroundColor Yellow
        Write-Host "$([Environment]::NewLine)        If you ARE experiencing stability issues, your CPU may be unstable$([Environment]::NewLine)        and permanently damaged." -ForegroundColor Red
        Write-Host "$([Environment]::NewLine)        For more information, visit: $([Environment]::NewLine)        https://www.theverge.com/2024/7/26/24206529/intel-13th-14th-gen-crashing-instability-cpu-voltage-q-a" -ForegroundColor Cyan
        Pause "$([Environment]::NewLine)        Any proposed fixes by this tool may fail to work if your CPU is damaged.$([Environment]::NewLine)Press any key to continue..." -ForegroundColor Yellow
'@
        'TestPassedIntelMsg' = @'
        Write-Host "Your CPU: " -ForegroundColor Cyan -NoNewLine ; Write-Host "$script:myCPU " -NoNewLine
        Write-Host "is running the latest " -NoNewLine -ForegroundColor Green
        Write-Host "$script:runningMicrocode " -NoNewLine -ForegroundColor Cyan
        Write-Host "microcode." -ForegroundColor Green
'@
        'NotApplicableMsg' = @'
        Write-Host "Your CPU model: " -ForegroundColor Cyan -NoNewLine ; Write-Host "$script:myCPU " -NoNewLine
        Write-Host "is not affected by the Intel CPU issues." -ForegroundColor Green
'@
        'ErrorMsg' = @'
        Write-Host "Error occured determining microcode version for CPU model: " -ForegroundColor Red -NoNewLine ; Write-Host "$script:myCPU "
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
        Write-Host "$([Environment]::NewLine)[FAIL] " -ForegroundColor Red -NoNewLine
        Write-Host "Windows is reporting a pending reboot is required." -ForegroundColor Yellow -NoNewLine
        Write-Host "$([Environment]::NewLine)       Please exit the script and reboot your machine..." -ForegroundColor Cyan
'@
    }
    "BadPrinter" = @{
        'TestPassed' = $null
        'TestFailMsg' = @'
        Write-Host "$([Environment]::NewLine)[FAIL] " -ForegroundColor Red -NoNewLine
        Write-Host "OneNote for Windows 10 virtual printer detected! This can cause crashes on game startup." -ForegroundColor Yellow -NoNewLine
        Write-Host "$([Environment]::NewLine)       Please remove this printer driver from your computer. Opening Printers window..." -ForegroundColor Cyan
        Start-Process "explorer.exe" -ArgumentList "shell:PrintersFolder"
'@
    }
   "LongSysUptime" = @{
        'TestPassed' = $null
        'TestFailMsg' = @'
        Write-Host "$([Environment]::NewLine)[FAIL] " -ForegroundColor Red -NoNewLine
        Write-Host "Your computer has not been restarted in $($script:Tests.LongSysUptime.SystemUptime) days." -ForegroundColor Yellow
        Write-Host "       Please restart your computer. Restart only. Do not use 'Shutdown'." -ForegroundColor Cyan
'@
    }
       "AVX2" = @{
        'TestPassed' = $null
        'TestFailMsg' = @'
        Write-Host "$([Environment]::NewLine)[FAIL] " -ForegroundColor Red -NoNewLine
        Write-Host "Your CPU does not support the AVX2 instruction set." -ForegroundColor Yellow
'@
    }
    "MultiChannelMemory" = @{
        'TestPassed' = $null
        'TestFailMsg' = @'
        Write-Host "$([Environment]::NewLine)[FAIL] " -ForegroundColor Red -NoNewLine
        Write-Host "Memory running in single-channel mode. This will hurt performance." -ForegroundColor Yellow
'@
    }
    "MatchingMemory" = @{
        'TestPassed' = $null
        'RAMInfo' = $null
        'TestFailMsg' = @'
        Write-Host "$([Environment]::NewLine)[FAIL] " -ForegroundColor Red -NoNewLine
        Write-Host "You have mixed memory. This can cause performance and stability issues." -ForegroundColor Yellow
'@
        'TestPassedMsg' = @'
        Write-Host "$([Environment]::NewLine)RAM Information:" -ForegroundColor Cyan
'@
        'AlwaysDisplayMsg' = @'
        $formattedTable = $script:Tests.MatchingMemory.RAMInfo | Format-Table -AutoSize | Out-String
        $indentedTable = $formattedTable -split "$([Environment]::NewLine)" | ForEach-Object { "       $_" }
        $indentedTable | ForEach-Object { Write-Host $_ -ForegroundColor White }
'@
    }
    "DomainTest" = @{
        'TestPassed' = $null
        'DomainList' = @(
            [PSCustomObject]@{ RequiredDomains = 'akamaihd.net'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'api.live.prod.thehelldiversgame.com'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'cluster-a.playfabapi.com'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'gameguard.co.kr'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'gameguard.thehelldiversgame.com'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'mgr.gameguard.co.kr'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'ocsp.digicert.com'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'playfabapi.com'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'pss-cloud.net'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'steamcommunity.com'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'steamcontent.com'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'steamgames.com'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'steampowered.com'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'steamstatic.com'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'steamusercontent.com'; PassedTest = $null },
            [PSCustomObject]@{ RequiredDomains = 'testament.api.wwsga.me'; PassedTest = $null }
        )
        'TestFailMsg' = @'
        Write-Host "$([Environment]::NewLine)[FAIL] " -ForegroundColor Red -NoNewLine
        Write-Host "The following URLs failed to resolve with DNS" -ForegroundColor Yellow
        $script:Tests.DomainTest.DomainList | Where-Object { $_.PassedTest -ne $true } | ForEach-Object { "       $($_.RequiredDomains)" } | Write-Host -ForegroundColor White
'@
    }
    "FirewallRules" = @{
        'TestPassed' = $null
        'Rules' = @(
            [PSCustomObject]@{ RuleName = 'Inbound TCP Rule'; PassedTest = $null },
            [PSCustomObject]@{ RuleName = 'Inbound UDP Rule'; PassedTest = $null }
        )
        'TestFailMsg' = @'
        Write-Host "$([Environment]::NewLine)[FAIL] " -ForegroundColor Red -NoNewLine
        Write-Host "The Windows Firewall is missing the following required rules: " -ForegroundColor Yellow
        $script:Tests.FirewallRules.Rules | Where-Object {$_.PassedTest -ne $true } | ForEach-Object { "       Helldivers 2 $($_.Rulename)" } | Write-Host -ForegroundColor White
        Start-Process wf.msc
'@
    }
"GameMods" = @{
    'TestPassed' = $null
    'TestFailMsg' = @'
    Write-Host "$([Environment]::NewLine)[FAIL] " -ForegroundColor Red -NoNewLine
    Write-Host 'Mods were detected!' -ForegroundColor Yellow
    Write-Host '       Use option ' -ForegroundColor Cyan -NoNewLine
    Write-Host 'Q'-ForegroundColor White -BackgroundColor Black -NoNewLine
    Write-Host ' to attempt removal.' -ForegroundColor Cyan
'@
    }
"PageFileEnabled" = @{
    'TestPassed' = $null
    'TestFailMsg' = @'
    Write-Host "$([Environment]::NewLine)[WARN] " -ForegroundColor Yellow -NoNewLine
    Write-Host 'Your page file is set to zero. This may cause the game to crash on launch.' -ForegroundColor Cyan
'@
}
"SecureBootEnabled" = @{
    'TestPassed' = $null
    'SecureBootNotSupported' = $null
    'TestFailMsg' = @'
    If ( $script:Tests.SecureBootEnabled.SecureBootNotSupported -eq $true ) {
    	Write-Host 'Secure Boot is not supported on this platform. If you experience constant GameGuard errors, ensure that no unverified drivers are loaded at boot.'
    } Else {
    Write-Host "$([Environment]::NewLine)[WARN] " -ForegroundColor Yellow -NoNewLine
    Write-Host 'Secure Boot is disabled! Can cause GameGuard errors & disables Above 4G Decoding/Nvidia Resizeable BAR/AMD SAM on Windows 11.' -ForegroundColor Cyan
    }
'@
    }
"SystemClockAccurate" = @{
    'TestPassed' = $null
    'TestFailMsg' = @'
    Write-Host "$([Environment]::NewLine)[FAIL] " -ForegroundColor Red -NoNewLine
    Write-Host 'Your time and/or date is inaccurate. This will cause connection issues.' -ForegroundColor Yellow
'@
    }
"VSyncDisabled" = @{
    'TestPassed' = $null
    'TestFailMsg' = @'
    Write-Host "$([Environment]::NewLine)[WARN] " -ForegroundColor Yellow -NoNewLine
    Write-Host 'V-Sync is enabled in game settings. This may cause framerate issues.' -ForegroundColor Cyan
'@
    }
}
Function Show-Variables {
    If ($script:AppIDFound -eq $true) {
        Clear-Host
        Write-Host "AppID: $AppID is located in directory:" -ForegroundColor Green
        Write-Host $script:AppInstallPath -ForegroundColor White
        Write-Host "Current build of AppID $AppID is: $script:BuildID" -ForegroundColor Cyan
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
        Write-Host "$message"$([Environment]::NewLine) -ForegroundColor Yellow
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
    Write-Host "$([Environment]::NewLine)Downloading $CommonName..." -ForegroundColor Cyan
    Invoke-WebRequest $DownloadURL -OutFile ($DownloadPath + $FileName)
    If ( (Get-FileHash ($DownloadPath + $FileName)).Hash -eq $SHA256Hash) {
        Write-Host 'Installing... look for UAC prompts' -ForegroundColor Cyan
        $Error.Clear()
        Try {
            $installProcess = Start-Process ($DownloadPath + $FileName) -ArgumentList "/q" -PassThru -Wait
            
            If ( $installProcess.ExitCode -ne 0) {
                Write-Host "$([Environment]::NewLine)UAC prompt was canceled, or another error occurred installing $CommonName$([Environment]::NewLine)" -ForegroundColor Red
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
    Try { Remove-Item -Path $script:AppInstallPath\bin\GameGuard\*.* }
    Catch {
        Write-Host ("Error occurred deleting GameGuard files in " +
            $script:AppInstallPath + "\bin\GameGuard") -ForegroundColor Red
    }
    If (!$Error) { Write-Host "Helldivers 2\bin\GameGuard cleared successfully!" -ForegroundColor Green }
    # Uninstall GameGuard
    $Error.Clear()
    Try { Start-Process $script:AppInstallPath\tools\gguninst.exe -Wait }
    Catch { Write-Host "Error occurred uninstalling GameGuard" -ForegroundColor Red }
    If (!$Error) { Write-Host "GameGuard Uninstalled Successfully" -ForegroundColor Green }
    # Install GameGuard
    $Error.Clear()
    Try { Start-Process $script:AppInstallPath\tools\GGSetup.exe -Wait }
    Catch { Write-Host "Error occurred installing GameGuard" -ForegroundColor Red }
    If (!$Error) { Write-Host "GameGuard installed successfully"$([Environment]::NewLine) -ForegroundColor Green }
    Return
}
Function Remove-HD2AppData {
    $Error.Clear()
    Try { Remove-Item -Path $env:APPDATA\Arrowhead\Helldivers2\* -Recurse }
    Catch { Write-Host "Error occurred deleting contents of $env:APPDATA\Arrowhead\Helldivers2\" -ForegroundColor Red }
    If (!$Error) { 
        Write-Host "Helldivers 2 AppData has been cleared successfully!" -ForegroundColor Green
        Write-Host "Now please use Steam's " -NoNewLine -ForegroundColor Cyan
        Write-Host 'Verify Integrity of Game Files ' -NoNewLine
        Write-Host 'function.' -ForegroundColor Cyan
    }
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
Function Uninstall-VCRedist {
    # List of Visual C++ Redistributables to uninstall
    $redistributables = @(
        'Microsoft Visual C++ 2012 Redistributable (x64)',
        'Microsoft Visual C++ 2013 Redistributable (x64)',
        'Microsoft Visual C++ 2015-2022 Redistributable (x64)'
    )

    ForEach ($programName in $redistributables) {
        $programlist = @($script:InstalledProgramsList | Where-Object { $_.DisplayName -like "$programName*" })
        Write-Host "$([Environment]::NewLine)⚠️ Please restart the computer once this process completes." -ForegroundColor Yellow
        If ($programlist.Count -gt 0) {
            ForEach ( $program in $programlist )
                { Write-Host $program.QuietUninstallString -ForegroundColor Cyan
                    Try {
                            Invoke-Expression "& $($program.QuietUninstallString.ToString())"
                            Write-Host "Uninstallation of $programName completed."
                        } Catch {
                                Write-Host "Failed to uninstall $programName $_" -ForegroundColor Red
                            }
                        }
        } Else {
            Write-Host "Program $programName not found."
        }
    }
}
Function Install-VCRedist {
    Pause "$([Environment]::NewLine) ⚠️ Make sure you used option U to uninstall current VC++ Redists before using this option..." -ForegroundColor Yellow
    Pause "$([Environment]::NewLine) This function will likely cause your computer to restart. Save any work before continuing..." -ForegroundColor Cyan
    Install-EXE -DownloadURL 'https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe' `
        -DownloadPath ((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path) -FileName 'VisualC++Redist2012.exe' `
        -SHA256Hash '681BE3E5BA9FD3DA02C09D7E565ADFA078640ED66A0D58583EFAD2C1E3CC4064' -CommonName '2012 Visual C++ Redistributable'

    Install-EXE -DownloadURL 'https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe' `
        -DownloadPath ((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path) -FileName 'VisualC++Redist2013.exe' `
        -SHA256Hash 'E554425243E3E8CA1CD5FE550DB41E6FA58A007C74FAD400274B128452F38FB8' -CommonName '2013 Visual C++ Redistributable'

    Install-EXE -DownloadURL 'https://download.visualstudio.microsoft.com/download/pr/1754ea58-11a6-44ab-a262-696e194ce543/3642E3F95D50CC193E4B5A0B0FFBF7FE2C08801517758B4C8AEB7105A091208A/VC_redist.x64.exe' `
        -DownloadPath ((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path) -FileName 'VisualC++Redist2019.exe' `
        -SHA256Hash '3642E3F95D50CC193E4B5A0B0FFBF7FE2C08801517758B4C8AEB7105A091208A' -CommonName '2019 Visual C++ Redistributable'

    Pause "$([Environment]::NewLine)Please restart the computer before continuing." -ForegroundColor Yellow
    Exit
}
Function Find-BlacklistedDrivers {
    $BadDeviceList = @('A-Volute', 'Hamachi', 'Nahimic', 'LogMeIn Hamachi', 'Sonic')
    $FoundBlacklistedDevice = $false
    Write-Host "$([Environment]::NewLine)Checking for devices that are known to cause issues..." -ForegroundColor Cyan
    $DeviceDatabase = Get-PnpDevice
    # Check for blacklisted devices
    ForEach ($device in $DeviceDatabase) {
        ForEach ($badDevice in $BadDeviceList) {
            If ($device.FriendlyName -like "$badDevice*" -and $device.Status -eq "OK") {
                Write-Host ("⚠️ " + $device.FriendlyName + " device detected! Known compatibility issues! Please disable using Device Manager.") -ForegroundColor Red
                $FoundBlacklistedDevice = $true
                Break # Exit the inner loop if a bad device is found
            }
        }
    }
    If (-not $FoundBlacklistedDevice) {
        Write-Host "No problematic devices found." -ForegroundColor Green
    }
    # Check for missing critical drivers (AMD and Intel only)
    $MissingDriverPresentCounter = ($DeviceDatabase | Where-Object {
        $_.Present -eq $true -and $_.InstanceId -match "VEN_1022|VEN_8086" -and 
        ( $_.FriendlyName -match "Base System Device|Unknown" -or $_.Status -eq 'Unknown' )
    } | Measure-Object).Count
    $MissingDriverDisconnectedCounter = ($DeviceDatabase | Where-Object {
        $_.Present -eq $false -and $_.InstanceId -match "VEN_1022|VEN_8086" -and 
        ( $_.FriendlyName -match "Base System Device|Unknown" -or $_.Status -eq 'Unknown' )
    } | Measure-Object).Count
    If ( $MissingDriverPresentCounter -gt 0 ) {
        Write-Host "$([Environment]::NewLine)⚠️You are missing critical AMD and/or Intel drivers." -ForegroundColor Yellow
        Write-Host "Please install them from your motherboard manufacturer or OEM system support site." -ForegroundColor Yellow
    }
    If ( $MissingDriverDisconnectedCounter -gt 2 ) {    
        Write-Host "$([Environment]::NewLine)ℹ️ It appears your motherboard/CPU was upgraded without re-installing Windows." -ForegroundColor Yellow
        Write-Host "If this applies to you, recommend using the Reset Windows feature or re-installing Windows." -ForegroundColor Yellow
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
                    $script:Tests.BadPrinter.TestPassed = $false
                }
            }
            $script:Tests.BadPrinter.TestPassed = $script:Tests.BadPrinter.TestPassed -ne $false
    }
    Else { $script:Tests.BadPrinter.TestPassed = $true }
}

Function Find-CPUInfo {
    $script:myCPU = (Get-CimInstance -ClassName Win32_Processor).Name.Trim()
    If ( $script:myCPU.Contains('Intel') ) {
        ForEach ($cpuModel in $script:Tests.IntelMicrocodeCheck.AffectedModels) {
            If (($script:myCPU).Contains($cpuModel)) {
                # Check Microcode; adapted from: https://www.xf.is/2018/06/28/view-cpu-microcode-revision-from-powershell/
                $registrypath = "Registry::HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0\"
                $CPUProperties = Get-ItemProperty -Path $registrypath
	            $script:runningMicrocode = $CPUProperties."Update Revision"
                # Convert to string and remove leading zeros
                Try { $script:runningMicrocodeInHex = ('0x'+(-join ( $runningMicrocode[0..4] | ForEach-Object { $_.ToString("X2") } )).TrimStart('0'))
                        If ( ($script:runningMicrocodeInHex -match $script:Tests.IntelMicrocodeCheck.LatestMicrocode[0] -or $script:runningMicrocodeInHex -match $script:Tests.IntelMicrocodeCheck.LatestMicrocode[1]) ) {
                            $script:Tests.IntelMicrocodeCheck.TestPassed = $true
                            Invoke-Expression $script:Tests.IntelMicrocodeCheck.TestPassedIntelMsg
                            Return
                        }    
                        Else {
                        $script:Tests.IntelMicrocodeCheck.TestPassed = $false
                        Return
                        }
                    }
                Catch { 
                    Invoke-Expression $script:Tests.IntelMicrocodeCheck.ErrorMsg
                    $script:Tests.IntelMicrocodeCheck.TestPassed = $false
                    Return
                 }
            }
        }
    }
    $script:Tests.IntelMicrocodeCheck.TestPassed = $true
    Invoke-Expression $script:Tests.IntelMicrocodeCheck.NotApplicableMsg
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
        $OEMDriverVersionNum = $gpu.DriverVersion
        If ( $gpu.Name.Contains( 'AMD' ) ) {
            Try {
                $OEMDriverVersionNum = (Get-ItemProperty -Path "HKLM:\SOFTWARE\ATI Technologies\Install" -Name RadeonSoftwareVersion).RadeonSoftwareVersion
            } Catch {
                $OEMDriverVersionNum = $gpu.DriverVersion + ' ( Windows Driver Version Format ) '
            }
        }
        If ( $gpu.Name.Contains( 'NVIDIA' ) ) {
            Try { 
                    $process = New-Object System.Diagnostics.Process
                    $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $process.StartInfo.FileName = "nvidia-smi"
                    $process.StartInfo.Arguments = "--query-gpu=driver_version --format=csv,noheader"
                    $process.StartInfo.RedirectStandardOutput = $true
                    $process.StartInfo.UseShellExecute = $false
                    $process.StartInfo.CreateNoWindow = $true
                    # Start the process
                    $process.Start() | Out-Null
                    # Read the output as a string
                    $OEMDriverVersionNum = New-Object System.IO.StreamReader($process.StandardOutput.BaseStream, [System.Text.Encoding]::UTF8)
                    $OEMDriverVersionNum =  $OEMDriverVersionNum.ReadToEnd().Trim()
                    $process.WaitForExit()
                } Catch {
                    $OEMDriverVersionNum = $gpu.DriverVersion + ' ( Windows Driver Version Format ) '
                }
        }
        Write-Host "-------------------------------------"
        Write-Host "  GPU Model: $($gpu.Name)"
        Write-Host "  Drvr Ver.: $OEMDriverVersionNum"
        Write-Host "     Status: " -NoNewLine
        If ( $gpu.Status -ne 'OK' ) {
                Write-Host $gpu.Status -ForegroundColor Red
            }
        Else { Write-Host $gpu.Status -ForegroundColor Green }
        Write-Host "-------------------------------------"
    }
} 
Function Show-OSInfo {
    $script:OSVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    Write-Host ($([Environment]::NewLine)+'Operating System:').Trim() -NoNewLine -ForegroundColor Cyan
    Write-Host '' $script:OSversion
}
Function Show-GameLaunchOptions {
    $script:localconfigVDF = Join-Path -Path $script:mostRecentSteamUserProfilePath -ChildPath 'config\localconfig.vdf'

    If (-Not (Test-Path $script:localconfigVDF)) {
        Write-Host "Error: File not found at $script:localconfigVDF" -ForegroundColor Red
        Return
    }

    $Content = Get-Content -Path $script:localconfigVDF -Raw
    $pattern = '(?sm)"553850"\s*\{(?:[^{}]|(?<open>\{)|(?<-open>\}))*(?(open)(?!))[^}]*?"LaunchOptions"\s*"([^"]*)"[^}]*?\}'
    $allMatches = [regex]::Matches($Content, $pattern)

    If ($allMatches.Count -eq 0) {
        Write-Host "Error: '553850' block or 'LaunchOptions' within it not found in $script:localconfigVDF." -ForegroundColor Red
    } Else {
        Foreach ($match in $allMatches) {
            # Check if the "LaunchOptions" capture group actually has a value for this match
            If ($match.Groups[1].Success) {
                $LaunchOptions = $match.Groups[1].Value

                Write-Host 'HD2 Launch Optns: ' -NoNewline -ForegroundColor Cyan
                If ( $LaunchOptions -match '--use-d3d11' ) {
                    Write-Host " $LaunchOptions" -ForegroundColor Yellow
                }
                ElseIf ( -not [string]::IsNullOrWhiteSpace($LaunchOptions) ) {
      			Write-Host $LaunchOptions
      		}
	 	Else {
       			Write-Host 'No launch options currently in use.'
	  	}
            } Else {
                # This case means a "553850" block was found, but "LaunchOptions" wasn't inside it
                Write-Host 'No launch options currently in use.'
            }
        }
        Write-Host 'Launch options retrieved from LAST USED Steam Profile' # This message should probably be moved inside the loop if it's per-block.
    }
}
Function Test-AVX2 {
    # Check for AVX2
    # Define the pattern to match the line
    $pattern = "^\tInstructions\ssets\t.*AVX2"
    # Search for the line that matches the pattern
    $match = $script:HardwareInfoText | Select-String -Pattern $pattern
    If ($match) {
        $script:Tests.AVX2.TestPassed = $true
    } Else {
        $script:Tests.AVX2.TestPassed = $false
    }
}
Function Get-MemorySpeed {
    # RAM Speed
    $pattern = '^Memory Frequency.*$'
    # Find and display lines matching the pattern
    $match = $script:HardwareInfoText | Select-String -Pattern $pattern
    $null = If ($match) {
        $pattern = '\d\d\d\d.\d'
        $match -match $pattern
        $RAMFrequency = [int]$Matches[0]
        Write-Host "$([Environment]::NewLine)RAM is currently running at " -NoNewLine -ForegroundColor Cyan
        Write-Host ([string]::Concat(($RAMFrequency * 2), ' MHz')) -ForegroundColor White
    }
}
Function Get-MemoryPartNumber{
    # Load DIMM Data
    $dimmData = @()
    # Temporary storage for the current DIMM data
    $currentDimm = @{}
    $skipDimm = $false

    # Iterate through each line
    foreach ($line in $script:HardwareInfoText) {
        If ($line -match "^DIMM #\s+(\d+)") {
            # Save the current DIMM data if it exists
            If ($currentDimm.Count -gt 0 -and -not $skipDimm) {
                $dimmData += [PSCustomObject]@{
                    DIMM = $currentDimm['DIMM']
                    Size = $currentDimm['Size']
                    PartNumber = $currentDimm['Part Number']
                }
            }
            # Reset for the new DIMM
            $currentDimm = @{}
            $skipDimm = $false

            # Add the DIMM number
            $currentDimm['DIMM'] = $Matches[1]
        } ElseIf ($line -match "^\s*SPD Registers") {
            # Skip processing this DIMM if "SPD Registers" is the first line after "DIMM #"
            $skipDimm = $true
        } ElseIf (-not $skipDimm) {
            If ($line -match "^\s+Size\s+(.+)") {
                $currentDimm["Size"] = $Matches[1]
            } ElseIf ($line -match "^\s+Part number\s+(.+)") {
                $currentDimm['Part Number'] = $Matches[1]
            }
        }
    }
    # Save the last DIMM data if it wasn't skipped
    If ($currentDimm.Count -gt 0 -and -not $skipDimm) {
        $dimmData += [PSCustomObject]@{
            DIMM = $currentDimm['DIMM']
            Size = $currentDimm['Size']
            PartNumber = $currentDimm['Part Number']
        }
    }
    $script:Tests.MatchingMemory.RAMInfo = $dimmData
    If ( ($dimmData.PartNumber | Select-Object -Unique | Measure-Object).Count -eq 1 -and
     ($dimmData.Size | Select-Object -Unique | Measure-Object).Count -eq 1 ) {
       $script:Tests.MatchingMemory.TestPassed = $true
    } Else {
        $script:Tests.MatchingMemory.TestPassed = $false
    }
}
Function Get-HardwareInfo { 
    $workingDirectory = (New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path
    # Define URLs and paths
    $CPUZUrl = "https://download.cpuid.com/cpu-z/cpu-z_2.15-en.zip"
    $CPUZZip = "$workingDirectory\cpu-z_2.15-en.zip"
    $CPUZExe = "$workingDirectory\cpuz_x64.exe"
    $CPUZFile = "cpuz_x64.exe"
    # Download and extract CPU-Z if it does not exist
    If (-Not (Test-Path $CPUZExe)) {
        If (-Not (Test-Path $CPUZZip)) {
            Try {
                Invoke-WebRequest -Uri $CPUZUrl -OutFile $CPUZZip -ErrorAction Continue
            } Catch {
                Return Write-Error "Failed to download cpuz_2.15-en.zip: $_" -ForegroundColor Red
            }
        }
    If ( (Get-FileHash $CPUZZip) -ne 'C8461D995D77A8FE1E8C5823403E88B04B733165CC151083B26379F1FE4B9501' ) {
        Remove-Item $CPUZZip
        Invoke-WebRequest -Uri $CPUZUrl -OutFile $CPUZZip -ErrorAction Continue
    }
        Try {
            Get-CPUZ -zipPath $CPUZZip -extractTo $workingDirectory -targetFile $CPUZFile
        }
        Catch {
            Return Write-Error 'CPU-Z extraction failed. Download cpuz_2.15-en.zip from https://download.cpuid.com/cpu-z/cpu-z_2.15-en.zip and place in your Downloads.'
        }
    }
    $CPUZSHA256 = (Get-FileHash $workingDirectory\cpuz_x64.exe).Hash
    If ( $CPUZSHA256 -ne 'FCAC6AA0D82943D6BB40D07FDA5C1A1573D7EA9259B9403F3607304ED345DBB9' ) {
        Return Write-Error 'cpuz_x64.exe failed hash verification... cannot scan hardware.'
    }
    
    # Run CPU-Z and dump report to file
    Write-Host "$([Environment]::NewLine)Scanning hardware using CPU-Z. Please wait..." -ForegroundColor Cyan -NoNewline
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.FileName = "$workingDirectory\cpuz_x64.exe"
    $psi.Arguments = @('-accepteula -txt=CPUZHellbombReport')
    # Set encoding to UTF8 so that Unicode compilation doesn't break CPU-Z console output
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()
    $process.WaitForExit()
    $script:HardwareInfoText = Get-Content "$workingDirectory\CPUZHellbombReport.txt"
    Write-Host ' complete!'
 }
Function Get-CPUZ {
    param ($zipPath, $extractTo, $targetFile)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Try {
        # Open the zip file
        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        # Find the target file in the zip archive
        $entry = $zip.Entries | Where-Object { $_.FullName -eq $targetFile }
        If ($entry) {
            # Extract the file manually using streams
            $targetPath = Join-Path -Path $extractTo -ChildPath $targetFile
            $fileStream = [System.IO.File]::Create($targetPath)
            $entryStream = $entry.Open()
            $entryStream.CopyTo($fileStream)
            $fileStream.Close()
            $entryStream.Close()
        } Else {
            Write-Error "cpuz_x64.exe not found in the zip file." -ForegroundColor Yellow
        }
    } Catch {
        Write-Error "Failed to extract cpuz_x64.exe: $_"
        Throw
    } Finally {
        If ($null -ne $zip) {
            Try {
                $zip.Dispose()
            } Catch {}
        }
    }
}
Function Remove-File {
    Param ($filePath)
    If (Test-Path $filePath) {
        Try {
            Remove-Item -Path $filePath -Force
        } Catch {
            Write-Warning "Failed to delete $filePath $_" -ForegroundColor Red
        }
    }
}
Function Get-InstalledPrograms {
    # This portion modified from:
    # https://devblogs.microsoft.com/scripting/use-powershell-to-quickly-find-installed-software/
       Write-Host "$([Environment]::NewLine)Gathering installed programs..." -ForegroundColor Cyan

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
                        $QuietUninstallString = $subKey.GetValue("QuietUninstallString")
                        $UninstallString = $subKey.GetValue("UninstallString")

                        If ($displayName) {
                            $installedPrograms += [PSCustomObject]@{
                                DisplayName     = $displayName
                                DisplayVersion  = If ($displayVersion) { Try { [System.Version]$displayVersion } Catch { '0.0.0' } } Else { '0.0.0' }
                                InstallLocation = $installLocation
                                Publisher       = $publisher
                                QuietUninstallString = $QuietUninstallString
                                UninstallString = $UninstallString
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
    Write-Host "$([Environment]::NewLine)Checking for programs that interfere with Helldivers 2..." -ForegroundColor Cyan
    $ProblematicPrograms = @(
    [PSCustomObject]@{ProgramName = 'AMD Chipset Software'; RecommendedVersion = '6.05.28.016'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Your ver. may be SLIGHTLY older. Latest @ https://www.amd.com/en/support/download/drivers.html.' }
    [PSCustomObject]@{ProgramName = 'Avast Internet Security'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause performance issues. Recommend uninstalling. Disabling when playing MAY resolve issues.' }
    [PSCustomObject]@{ProgramName = 'Avast Free Antivirus'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause performance issues. Recommend uninstalling. Disabling when playing MAY resolve issues.' }
    [PSCustomObject]@{ProgramName = 'AVG Antivirus'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause performance issues. Recommend uninstalling. Disabling when playing MAY resolve issues.' }
    [PSCustomObject]@{ProgramName = 'Cepstral SwiftTalker'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Known to cause crashes in the past.' }
    [PSCustomObject]@{ProgramName = 'cFosSpeed'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Uninstall. Unecessary networking stack that causes network issues.' }
    [PSCustomObject]@{ProgramName = 'Cisco Webex'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'If the process is running, Webex will control certain keyboard shortcuts. Close completely using Task Manager.' }
    [PSCustomObject]@{ProgramName = 'ESET Endpoint'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause crashes. Please disable/add exclusions for *.des files in tools folder.' }
    [PSCustomObject]@{ProgramName = 'ESET File'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause crashes. Please disable/add exclusions for *.des files in tools folder.' }
    [PSCustomObject]@{ProgramName = 'ESET Management'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause crashes. Please disable/add exclusions for *.des files in tools folder.' }
    [PSCustomObject]@{ProgramName = 'ESET PROTECT'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause crashes. Please disable/add exclusions for *.des files in tools folder.' }
    [PSCustomObject]@{ProgramName = 'ESET Rogue'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause crashes. Please disable/add exclusions for *.des files in tools folder.' }
    [PSCustomObject]@{ProgramName = 'ESET Security'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause crashes. Please disable/add exclusions for *.des files in tools folder.' }
    [PSCustomObject]@{ProgramName = 'EVGA Precision'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Reported to cause issues. Disabling the OSD may resolve the issue.' }
    [PSCustomObject]@{ProgramName = 'ExpressVPN'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause networking issues. Open Device Manager and disable the adapter there.' }
    [PSCustomObject]@{ProgramName = 'Gigabyte Speed'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Uninstall. Unecessary networking stack that causes network issues.' }
    [PSCustomObject]@{ProgramName = 'Hamachi'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Breaks connectivity. Recommend uninstalling or disable IN DEVICE MANAGER.' }
    [PSCustomObject]@{ProgramName = 'iCue'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Outdated versions are known to cause issues.' }
    [PSCustomObject]@{ProgramName = 'Lunar Client'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Exit Lunar Client before launching HD2 to prevent connectivity issues.' }
    [PSCustomObject]@{ProgramName = 'Medal'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause slowdowns, crashes, etc. Turn off/Disable/uninstall.' }
    [PSCustomObject]@{ProgramName = 'MSI Afterburner'; RecommendedVersion = '4.6.5'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Outdated versions cause crashing & performance issues.' }
    [PSCustomObject]@{ProgramName = 'Mullvad VPN'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Causes connection issues. Recommend uninstall or disable in DEVICE MANAGER.' }
    [PSCustomObject]@{ProgramName = 'Nahimic'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Myriad of issues. Recommend removing all devices and services.' }
    [PSCustomObject]@{ProgramName = 'Norton 360'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Will destroy FPS if Game Optimizer is enabled. Disable Game Optimizer in Norton 360.' }
    [PSCustomObject]@{ProgramName = 'Outplayed'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause stuttering & VRAM leaks. Disable Outplayed Autoclipping or disable/uninstall.' }
    [PSCustomObject]@{ProgramName = 'Overwolf'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Can cause stuttering & VRAM leaks. Disable Outplayed Autoclipping or disable/uninstall.' }
    [PSCustomObject]@{ProgramName = 'Process Lasso'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Causes threading and stability issues. Please uninstall.' }
    [PSCustomObject]@{ProgramName = 'Radmin'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Will cause network issues. Recommend uninstall or disable in DEVICE MANAGER.' }
    [PSCustomObject]@{ProgramName = 'Razer Cortex'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Causes severe performance issues. Must disable/uninstall.' }
    [PSCustomObject]@{ProgramName = 'Ryzen Master'; RecommendedVersion = '2.14.2.3341'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Known to cause RAM leaks & general issues. Recommend uninstalling.' }
    [PSCustomObject]@{ProgramName = 'Samsung Magician'; RecommendedVersion = '8.1'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Outdated versions break connectivity completely.' }
    [PSCustomObject]@{ProgramName = 'Surfshark'; RecommendedVersion = '100.100'; Installed = $false; InstalledVersion = '0.0.0'; Notes = 'Will prevent connectivity. Recommend uninstall or disable IN DEVICE MANAGER.' }
    [PSCustomObject]@{ProgramName = 'Wallpaper Engine'; Installed = $false; RecommendedVersion = '100.100'; InstalledVersion = '0.0.0'; Notes = 'Can crash AMD GPUs in some instances. If setup improperly, can limit FPS of games.' }
    [PSCustomObject]@{ProgramName = 'Wargaming.net Game Center'; Installed = $false; RecommendedVersion = '100.100'; InstalledVersion = '0.0.0'; Notes = 'Reported to cause issues.' }
    [PSCustomObject]@{ProgramName = 'Webroot'; Installed = $false; RecommendedVersion = '100.100'; InstalledVersion = '0.0.0'; Notes = 'Causes low FPS. Uninstall or launch HD2 & THEN shutdown Webroot.' }
    [PSCustomObject]@{ProgramName = 'Wemod'; Installed = $false; RecommendedVersion = '100.100'; InstalledVersion = '0.0.0'; Notes = 'Has a kernel-level driver that enables cheats. Disable/Exit/Uninstall if having issues.' }
    [PSCustomObject]@{ProgramName = 'ZeroTier One'; Installed = $false; RecommendedVersion = '100.100'; InstalledVersion = '0.0.0'; Notes = 'Causes connectivity issues. Recommend uninstalling or disable IN DEVICE MANAGER.'})
    # Avast Web Shield checks
    $regPath = "HKLM:\SOFTWARE\Avast Software\Avast\properties\WebShield\Common"
    $regName = "ProviderEnabled"

    Try {
    $value = Get-ItemProperty -Path $regPath -Name $regName
    If ($value.$regName -eq 1)
        {
            Write-Host "$([Environment]::NewLine)⚠️ Avast Webshield is enabled!" -ForegroundColor Yellow
            Write-Host 'Ensure an exception is added for ' -ForegroundColor Cyan -NoNewline
            Write-Host 'https://microsoft.com ' -NoNewline
            Write-Host 'to prevent HTTPS CRL access issues.' -ForegroundColor Cyan
            Write-Host 'More information can be found here: https://discord.com/channels/1102970375731691612/1218153537914273802/1273154218022408252'
        }
    }
    Catch { # Value does not exist
    }
    
    $bool = $false
    ForEach ($program in $ProblematicPrograms) {
        ForEach ($installedApp in $script:InstalledProgramsList) {
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
        Write-Host "$([Environment]::NewLine)Found the following programs that are known to cause issues:$([Environment]::NewLine)" -ForegroundColor Yellow
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
        Write-Host 'Checks complete. No problematic programs found!' -ForegroundColor Green
    }
    Return
}
Function Get-SystemUptime {
    $lastBoot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $uptime = ([math]::Round(((Get-Date) - $lastBoot).TotalDays, 0))
    If ( $uptime -lt 1 ) {
        $script:Tests.LongSysUptime.TestPassed = $true
    }
    Else {
        $script:Tests.LongSysUptime.SystemUptime = $uptime
        $script:Tests.LongSysUptime.TestPassed = $false
        }
}
Function Test-SystemClockAccuracy {
    # Define the NTP server
    $NtpServer = "time.windows.com"
    # Query the NTP server for its time offset using a process to support the EXE
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName = "w32tm"
    $process.StartInfo.Arguments = "/stripchart /computer:$NtpServer /samples:1 /dataonly"
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.Start() | Out-Null
    # Read the time output as a string
    $NtpQuery = New-Object System.IO.StreamReader($process.StandardOutput.BaseStream, [System.Text.Encoding]::UTF8)
    $NtpQuery =  $NtpQuery.ReadToEnd().Trim()
    $process.WaitForExit()    
    $OffsetString = $NtpQuery | Select-String "[+-]([\d]+)\.([\d]+)s"    
    If ($OffsetString) {
        $OffsetValue = [Math]::Abs([double]$OffsetString.Matches[0].Groups[1].Value)
        If ($OffsetValue -lt 5.0) {
            $script:Tests.SystemClockAccurate.TestPassed = $true
        } Else {
            $script:Tests.SystemClockAccurate.TestPassed = $false
        }
    }
}
Function Test-Firewall {
    Write-Host (("$([Environment]::NewLine)Checking for two Inbound Firewall rules named Helldivers") + [char]0x2122 + " 2 or Helldivers 2...") -ForegroundColor Cyan -NoNewline
    # Cast as array due to PowerShell returning object (no count property) if one rule, but array if two rules
    [array]$HD2FirewallRules = Get-NetFirewallRule -Action Allow -Enabled True -Direction Inbound | Where-Object DisplayName -In ("Helldivers" + [char]0x2122 + " 2"), "Helldivers 2"
    If ($null -eq $HD2FirewallRules) {
        $script:Tests.FirewallRules.TestPassed = $false
    }
    Else {
        $script:Tests.FirewallRules.Rules[0].PassedTest = $false
        $script:Tests.FirewallRules.Rules[1].PassedTest = $false
        ForEach ( $rule in $HD2FirewallRules) {
            If ( $rule.Enabled -and (($rule | Get-NetFirewallPortFilter).Protocol -eq 'TCP')) {
                $script:Tests.FirewallRules.Rules[0].PassedTest = $true
            }
            If ( $rule.Enabled -and (($rule | Get-NetFirewallPortFilter).Protocol -eq 'UDP')) {
                $script:Tests.FirewallRules.Rules[1].PassedTest = $true
            }
        }
        If ( $script:Tests.FirewallRules.Rules[0].PassedTest -eq $true -and $script:Tests.FirewallRules.Rules[1].PassedTest -eq $true) {
            $script:Tests.FirewallRules.TestPassed = $true
        }
    }
    Write-Host ' complete!'
}
Function Test-CRL {
    Write-Host "$([Environment]::NewLine)Testing Certificate Revocation List (CRL) connections..." -ForegroundColor Cyan
    # Adapted from: https://stackoverflow.com/questions/11531068/powershell-capturing-standard-out-and-error-with-process-object
    # This overly-complicated mess with curl is used to ensure that an HTTP and an HTTPS request are used. Invoke-WebRequest
    # will return false positives when it's actually broken.
    Clear-DnsClientCache
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
    $output = $output.Split("$([Environment]::NewLine)")
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
    $output = $output.Split("$([Environment]::NewLine)")
    Write-Host 'HTTPS CRL access ' -NoNewline
    If ($output[0].Trim() -eq 'HTTP/1.1 200 OK') {
        Write-Host '[OK]' -ForegroundColor Green
    }
    Else {
        Write-Host '[FAIL]' -ForegroundColor Red
        Write-Host 'Anti-Virus WebShields can cause this issue. Please whitelist microsoft.com or disable them.' -ForegroundColor Yellow
        Write-Host 'Pi-Holes/DNS-blocking software can also cause this issue. Whitelist oneocsp.microsoft.com.' -ForegroundColor Yellow
    }

    Write-Host "$([Environment]::NewLine)Testing OCSP connection to oneocsp.microsoft.com..." -ForegroundColor Cyan
    If ( Test-NetConnection 'oneocsp.microsoft.com' -ErrorAction SilentlyContinue -InformationLevel Quiet )
    {
        Write-Host "OCSP Connection " -NoNewLine
        Write-Host ' [OK]' -ForegroundColor Green
    }
    Else {
        Write-Host 'OCSP Connection' -NoNewLine
        Write-Host ' [FAIL]' -ForegroundColor Red
    }
    Write-Progress -Completed -Activity "make progress bar dissapear"
    Test-ClientDnsConfig
    Return
}
Function Test-RequiredURLs {
    Clear-DnsClientCache
    ForEach ($domain in $script:Tests.DomainTest.DomainList) {
        # If not running in ISE or old PowerShell, let's make it pretty
        If ((Get-Host).Name -ne 'Windows PowerShell ISE Host' -and (Get-Host).Version -ge '7.0.0') {
            $x, $y = [Console]::GetCursorPosition() -split '\D' -ne '' -as 'int[]'
            [Console]::SetCursorPosition(46 , $y)
        }
        If (Resolve-DnsName -Name $domain.RequiredDomains -DnsOnly -ErrorAction SilentlyContinue) {        
            # Logic to handle intermittent domain connectivity. If it was marked false already, do not set to pass
            If ( $domain.PassedTest -ne $false ) {
                $domain.PassedTest = $true
            }
        }
        Else {
            $domain.PassedTest = $false
        }
    }
    # Filter and print RequiredDomains where PassedTest is false
    If ($script:Tests.DomainTest.DomainList | Where-Object { $_.PassedTest -ne $true }) {
        $script:Tests.DomainTest.TestPassed = $false
    }
    Else {
        $script:Tests.DomainTest.TestPassed = $true
    }
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
        Write-Host "$([Environment]::NewLine)CHECKING IPv4 DNS..." -ForegroundColor Cyan
        # Print and test DNS servers for IPv4
        If (-not ([string]::IsNullOrEmpty(($dnsServersIPv4 | Get-Member -Name 'ServerAddresses')))) {
            Write-Host "[PASS]" -ForegroundColor Green -NoNewline
            Write-Host " Detected IPv4 DNS servers:" -ForegroundColor Cyan
            $dnsServersIPv4.ServerAddresses | ForEach-Object { Write-Host "       $_"
            }    
            Write-Host "$([Environment]::NewLine)       Testing IPv4 DNS server(s)..." -ForegroundColor Cyan
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
        Write-Host "$([Environment]::NewLine)CHECKING IPv6 DNS..." -ForegroundColor Cyan
        If (-not ([string]::IsNullOrEmpty(($dnsServersIPv6 | Get-Member -Name 'ServerAddresses')))) {
        Write-Host "[PASS]" -ForegroundColor Green -NoNewline
        Write-Host ' Detected IPv6 DNS server(s):' -ForegroundColor Cyan
        $dnsServersIPv6.ServerAddresses | ForEach-Object { Write-Host "       $_"
        }
        Write-Host "$([Environment]::NewLine)       Testing IPv6 DNS servers..." -ForegroundColor Cyan
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
    Else { Write-Host "$([Environment]::NewLine)Skipping IPv6 checks because IPv6 is disabled." -ForegroundColor Cyan }       
}
Function Test-Wifi {
    # Ping the default gateway for 30 seconds and collect statistics
    $mainAdapter = Get-NetIPConfiguration | Where-Object { $null -ne $_.IPv4DefaultGateway -or $null -ne $_.IPv6DefaultGateway }
    If ($null -eq $mainAdapter -or $null -eq $mainAdapter.IPv4DefaultGateway) {
        Write-Host "No default gateway available." -ForegroundColor Yellow
        Break
        }
    Write-Host "$([Environment]::NewLine)Testing the connection to the default gateway..." -ForegroundColor Cyan
        If ((Get-NetAdapter -InterfaceIndex $mainAdapter.InterfaceIndex).PhysicalMediaType -ne '802.11') {
            Write-Host "$([Environment]::NewLine)This is not a wireless connection. Testing anyway..." -ForegroundColor Yellow
        }
    $ipAddress = ($mainAdapter.IPv4DefaultGateway).NextHop
    $endTime = ([datetime]::UtcNow).AddSeconds(30)
    $pingResults = New-Object System.Collections.Generic.List[Object]
    While ([datetime]::UtcNow -lt $endTime) {
        Try {
            $pingResult = Test-Connection $ipAddress -Count 1
        }
        Catch { 
            Write-Host 'Error pinging the default gateway... returning to menu' -ForegroundColor Yellow
            Return
        }
        If ($pingResult) {
            $pingResults.Add($pingResult)
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
        Write-Host "Your connection to your default gateway has significant jitter (latency variance).$([Environment]::NewLine)$([Environment]::NewLine)" -ForegroundColor Yellow
    }
    If ($packetLossPercentage -gt 1) {
        Write-Host "Your connection to your default gateway has more than 1% packet loss.$([Environment]::NewLine)$([Environment]::NewLine)" -ForegroundColor Yellow
    } 
    If ($stdDev -le 5 -and $packetLossPercentage -le 1) {
        Write-Host "Your connection appears to be operating normally.$([Environment]::NewLine)$([Environment]::NewLine)" -ForegroundColor Green
    }
}
Function Test-BTAGService {
    If ((Get-Service -Name BTAGService).Status -eq 'Running')
    {
        Write-Host "$([Environment]::NewLine)⚠️ Bluetooth Audio Gateway (BTAG) Service is running." -ForegroundColor Yellow
        Write-Host 'This will cause audio routing issues with ' -NoNewLine -ForegroundColor Cyan
        Write-Host 'Bluetooth Headphones.' -NoNewline -ForegroundColor Yellow 
        Write-Host "$([Environment]::NewLine)Toggle this service ON or OFF from the menu (Select option B)" -ForegroundColor Cyan
    }
    Else {
        Write-Host "$([Environment]::NewLine)Bluetooth Audio Gateway (BTAG) Service: DISABLED",
        "$([Environment]::NewLine)If using a Bluetooth Headset, this is the correct configuration." -ForegroundColor Cyan
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
    Pause "You will need to sign into Steam after this process completes.$([Environment]::NewLine)Press any key to continue..." -ForegroundColor Yellow
    # Remove CEF Cache
    Write-Host "$([Environment]::NewLine)Clearing contents of $env:LOCALAPPDATA\Steam\" -ForegroundColor Cyan
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
    Write-Host 'Launching Steam now...'$([Environment]::NewLine) -ForegroundColor Cyan
    Start-Process $SteamPath\steam.exe
    Return
}
Function Open-AdvancedGraphics {
    Start-Process ms-settings:display-advancedgraphics
    Write-Host "$([Environment]::NewLine)Verify HellDivers 2 is set to use the correct GPU.",
    "$([Environment]::NewLine)If HD2 is not listed, click " -NoNewline -ForegroundColor Cyan
    Write-Host "Add desktop app " -NoNewline -ForegroundColor Yellow
    Write-Host "and browse to:" -ForegroundColor Cyan
    Write-Host $script:AppInstallPath, "\bin\helldivers2.exe"$([Environment]::NewLine) -ForegroundColor Yellow
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
    Write-Host "$([Environment]::NewLine)Running Double-NAT test... this will take a minute" -ForegroundColor Cyan
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
        Write-Host $privateIPs -Separator "$([Environment]::NewLine)"
        Write-Host "$([Environment]::NewLine)If you're not sure what these results mean, these results are safe to share with others." -ForegroundColor Cyan
    }
    Else {
        Write-Host "$([Environment]::NewLine)No Double-NAT connection detected." -ForegroundColor Green
    }
    Pause "$([Environment]::NewLine)Press any key to continue..."
}
Function Switch-BTAGService {
    If (-not ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544')) {
    Write-Host 'This command requires Administrator privileges.',
    "$([Environment]::NewLine)To run PowerShell with admin privileges:",
    "$([Environment]::NewLine)Right-click on PowerShell and click Run as Administrator",
    "$([Environment]::NewLine)Then run the script again.$([Environment]::NewLine)" -ForegroundColor Cyan
    } Else {
        If ((Get-Service -Name BTAGService).Status -eq 'Running') {
            Set-Service -Name BTAGService -StartupType Disabled
            Stop-Service -Name BTAGService
            Start-Sleep -Seconds 1.5
            Write-Host "$([Environment]::NewLine)Bluetooth Audio Gateway Service", 
            "is now " -ForegroundColor Cyan
            Write-Host (Get-Service -Name BTAGService).Status -ForegroundColor Yellow
            Write-Host 'Please disconnect and re-connect your Bluetooth device.'$([Environment]::NewLine) -ForegroundColor Cyan
        } Else {
            If ((Get-Service -Name BTAGService).Status -eq 'Stopped') {
                Set-Service -Name BTAGService -StartupType Automatic
                Set-Service -Name BTAGService -Status Running
                Start-Sleep -Seconds 1.5
                Write-Host "$([Environment]::NewLine)Bluetooth Audio Gateway Service", 
                "is now " -ForegroundColor Cyan
                Write-Host (Get-Service -Name BTAGService).Status$([Environment]::NewLine) -ForegroundColor Green
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
    
    Write-Host "$([Environment]::NewLine)Checking for required Microsoft Visual C++ Redistributables..." -ForegroundColor Cyan
     # Speed up the search by checking if the program name starts with 'Microsoft' before entering nested loop
    $filteredApps = $script:InstalledProgramsList | Where-Object { $_.DisplayName -like 'Microsoft Visual*' }
    
    ForEach ($vcRedist in $VCRedists) {
            If ($filteredApps.DisplayName -like "$($vcRedist.ProgramName)*") {
                $vcRedist.Installed = $true
            }
        }
    $missingRedists = $VCRedists | Where-Object { $_.Installed -eq $false }
    If ($missingRedists) {
        Write-Host "$([Environment]::NewLine)You are missing critical Visual C++ Redists. The game will not run.$([Environment]::NewLine)" -ForegroundColor Yellow
        Write-Host ("{0,-33}" -f "Missing Visual C++ Redistributable(s)") -ForegroundColor Cyan
        Write-Host ("{0,-33}" -f '-------------------------------------')
        ForEach ($redist in $missingRedists) {
            Write-Host '[FAIL] ' -ForegroundColor Red -NoNewline
            Write-Host ("{0,-26}" -f $redist.ProgramName) -ForegroundColor Yellow
        }
        Write-Host "$([Environment]::NewLine)Please install them using the [" -ForegroundColor Yellow -NoNewline
        Write-Host 'I' -NoNewLine
        Write-Host '] option on the menu.' -ForegroundColor Yellow
    }
    Else {
        Write-Host 'All required Visual C++ Redists found!' -ForegroundColor Green
    }
    Return
}
Function Test-MemoryChannels {
    # Dual-Channel RAM test
    # Define single-channel pattern to search for
    $SingleChannelpattern = "^Channels\s*\b((1\s+x\s+\b(32|64)\b-bit)|(Single))$"
    If ( $script:HardwareInfoText -match $SingleChannelPattern ) {
        $script:Tests.MultiChannelMemory.TestPassed = $false
    }
    Else {
        $script:Tests.MultiChannelMemory.TestPassed = $true
    }
}

# Function to check if a reboot is required
Function Test-PendingReboot {
    ForEach ($key in $script:Tests.PendingReboot.keys) {
        If (Test-Path $key) {
            $script:Tests.PendingReboot.RebootRequired = $true
            Break
        }
    }
    If ($script:Tests.PendingReboot.RebootRequired) {
        $script:Tests.PendingReboot.TestPassed = $false
    } Else {
        $script:Tests.PendingReboot.TestPassed = $true
    }
}
Function Reset-HD2SteamCloud {
    Clear-Host
    Write-Host "$([Environment]::NewLine)This function will reset your HD2 Steam Cloud saved data." -ForegroundColor Cyan
    Write-Host 'You will lose any custom key bindings & character customizations will be reset to defaults. ' -NoNewline
    Write-Host 'No game progress will be lost.' -ForegroundColor Yellow
    Write-Host "This can resolve a myriad of input issues, and in some instances,$([Environment]::NewLine)can resolve the game not running at all."
    Write-Host "If you have multiple Steam user profiles,$([Environment]::NewLine)this function will clear the LAST USED HD2 Steam Cloud profile."-ForegroundColor Yellow
    Write-Host "If you need to switch Steam profiles before running this script,$([Environment]::NewLine)please close the script or press " -NoNewline
    Write-Host 'Ctrl + C' -NoNewline -ForegroundColor Cyan
    Write-Host " to stop the script...$([Environment]::NewLine)Open Steam using the correct Steam profile and re-run this script."
    Write-Host "$([Environment]::NewLine)These are the steps that will be completed:"
    Write-Host "1.) Script will close Steam if it is running$([Environment]::NewLine)2.) Script will temporarily disable Steam Cloud saves for HD2$([Environment]::NewLine)3.) Script will delete your HD2 Steam Cloud data$([Environment]::NewLine)4.) Script will pause$([Environment]::NewLine)5.) Script will request for you to run Helldivers 2$([Environment]::NewLine)    and load into the ship to generate new Steam Cloud files."
    Write-Host "6.) You will close the game, and continue the script."
    Write-Host "7.) Script will re-enable Steam Cloud saves for HD2. $([Environment]::NewLine)    The new files to be synced to Steam Cloud next time Steam is launched."
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
  
    $HD2SteamCloudSaveFolder = Join-Path $script:mostRecentSteamUserProfilePath -ChildPath $AppID

    # Define the path to the sharedconfig.vdf file
    $sharedConfigPath = Join-Path $script:mostRecentSteamUserProfilePath -ChildPath '\7\remote\sharedconfig.vdf'
    
    $configContent = Get-Content -Path $sharedConfigPath
    
    $inAppSection = $false
    $modifiedContent = @()
    
    # Parse the sharedconfig.vdf file and modify the cloudenabled value to '0'
    ForEach ($line in $configContent) {
        If ($line -match $script:AppID) {
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
    
    Write-Host 'Cloud save for HD2 has been disabled.' -ForegroundColor Cyan
    Remove-Item -Path $HD2SteamCloudSaveFolder\* -Recurse
    Write-Host "Cleared cloud save folder $HD2SteamCloudSaveFolder" -ForegroundColor Cyan
    
    Write-Host "STOP! Please open Helldivers 2 and skip intro/wait until it gets to the menu BEFORE continuing the script..." -ForegroundColor Red
    pause 'Press any key to continue...'

    Write-Host 'Re-enabling Cloud Save for HD2...' -ForegroundColor Cyan
    $configContent = Get-Content -Path $sharedConfigPath
    ForEach ($line in $configContent) {
        If ($line -match $script:AppID) {
            $inAppSection = $true
        } ElseIf ($inAppSection -and $line -match '"cloudenabled"') {
            $line = $line -replace '("cloudenabled"\s+)"\d+"', '$1"1"'
            $inAppSection = $false
        }
        $modifiedContent += $line
    }
    $modifiedContent | Out-File -FilePath $sharedConfigPath -Encoding UTF8 -Force
    $modifiedContent = $null
    Write-Host 'HD2 Steam Cloud clearing procedures completed!' -ForegroundColor Cyan
    Return
}
Function Switch-FullScreenOptimizations
{
    # Define the path to the executable
    $exePath = "$script:AppInstallPath\bin\helldivers2.exe"
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
                Return Write-Host "$([Environment]::NewLine)Fullscreen optimizations enabled for $exePath. This is probably not desired." -ForegroundColor Yellow
            } Else {
                # Append DISABLEDXMAXIMIZEDWINDOWEDMODE to the current value
                $newValue = "$currentValue DISABLEDXMAXIMIZEDWINDOWEDMODE"
                Set-ItemProperty -Path $regPath -Name $exePath -Value $newValue
            }
        }
        Return Write-Host "$([Environment]::NewLine)Fullscreen optimizations disabled for $exePath. This is probably the desired setting." -ForegroundColor Green
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
        Write-Host "$([Environment]::NewLine)Hostability key removed successfully!$([Environment]::NewLine)" -ForegroundColor Green
    }
    Else {
        Write-Host '[FAIL] ' -NoNewLine -ForegroundColor Red
        Write-host 'Hostabiltiy key could not be removed.$([Environment]::NewLine)' -ForegroundColor Yellow
    }    
}
Function Get-VSyncConfig {
    $configPath = "$env:APPDATA\Arrowhead\Helldivers2\user_settings.config"
    Try {
            If ( Select-String $configPath -Pattern "vsync = false" -Quiet ) {
                $script:Tests.VSyncDisabled.TestPassed = $true
                }
            Else {
                $script:Tests.VSyncDisabled.TestPassed = $false
            }
        }
    Catch {
            Return
    }
}
Function Find-Mods {
    If (-not $script:AppInstallPath)
    {
        Write-Host 'Helldivers 2 not found. Skipping mod detection.'
        Return
    }    
    $directoryPath = $script:AppInstallPath + '\data'
    $patchFiles = Get-ChildItem -Path $directoryPath -File | Where-Object { $_.Name -match "\.patch_" }
    If ( $null -eq $patchFiles ) {
        $script:Tests.GameMods.TestPassed = $true
    } Else {
        $script:Tests.GameMods.TestPassed = $false
}

}
Function Show-ModRemovalWarning {  
    Write-Host "$([Environment]::NewLine)WARNING: " -ForegroundColor Red -NoNewline
    Write-Host 'This script is about to delete modified game files in' -ForegroundColor Yellow
    Write-Host "$script:AppInstallPath\data\" -ForegroundColor Cyan
    Write-Host 'If this location looks incorrect, press ' -ForegroundColor Yellow -NoNewline
    Write-Host 'Ctrl ' -NoNewline
    Write-Host '+ ' -ForegroundColor Yellow -NoNewline
    Write-Host 'C ' -NoNewLine
    Write-Host 'now to exit.' -ForegroundColor Yellow
    Pause "$([Environment]::NewLine) Press any key to continue"
}
Function Remove-AllMods {
        If (-not $script:AppInstallPath)
    {
        Write-Host 'Helldivers 2 not found. Skipping mod removal.'
        Return
    } 
    $dataFolder = $script:AppInstallPath + '\data\'
    $filesFound = $false
    Foreach ($file in Get-ChildItem -Path $dataFolder -File) {
        $filePath = $dataFolder + $file.Name
        If ($file.Name -match "([0-9a-fA-F]{16})\.patch_") {
            $filesFound = $true
            $hex = $matches[1]
            If (Test-Path $filePath) {
                Remove-Item -Path $filePath -Force
            }
            Foreach ($matchingFile in Get-ChildItem -Path $dataFolder -File | Where-Object { $_.Name -match "$hex" }) {
                $matchingFilePath = $dataFolder + $matchingFile.Name
                if (Test-Path $matchingFilePath) {
                    Remove-Item -Path $matchingFilePath -Force
                }
            }
        }
    }
    If (-not $filesFound) {
        Write-Host 'No mod files were found to remove.' -ForegroundColor Cyan
    } Else {
        Write-Host 'Removed all .patch_ files and sibling files sharing the same IDs. Please verify game integrity before launching.' -ForegroundColor Cyan
    }
}

Function Get-PageFileSize {
    If ( (Get-CimInstance Win32_PageFileUsage).AllocatedBaseSize -ne 0 ) {
        $script:Tests.PageFileEnabled.TestPassed = $true
    }
    Else {
        $script:Tests.PageFileEnabled.TestPassed = $false
    }
}
Function Get-SecureBootStatus {
    Try {
    	$secureBoot = Confirm-SecureBootUEFI
     	If ( $secureBoot -eq $true) { $script:Tests.SecureBootEnabled.TestPassed = $true }
    }
      Catch { 
    	  If ( $_.Exception.Message -like "*Cmdlet not supported on this platform:*" ) {
       		$script:Tests.SecureBootEnabled.SecureBootNotSupported = $true
	 	$script:Tests.SecureBootEnabled.TestPassed = $false
          }
      }
}
Function Restart-Resume {
    Return ( Test-Path $PSScriptRoot\HellbombRestartResume )
}

Function Menu {
    $Title = "-------------------------------------------------------------------------------------------------------
    💣 Hellbomb 💣 Script for Troubleshooting Helldivers 2       ||      Version 3.3.0.5
-------------------------------------------------------------------------------------------------------"
    $Prompt = "Enter your choice:"
    $Choices = [ChoiceDescription[]](
        [ChoiceDescription]::new("🔍 &HD2 Status Checks$([Environment]::NewLine)", 'Provides various status checks, resets the hostability key & flushes the DNS Cache.'),
        [ChoiceDescription]::new("🧹 &Clear HD2 Settings (AppData)$([Environment]::NewLine)", 'Clears your profile data. Settings will be reset, but progress will not be lost.'),
        [ChoiceDescription]::new("🧹 Clear HD2 Stea&m Cloud$([Environment]::NewLine)", 'Resets HD2 Steam Cloud. For input issues & game not opening on any device. No progress will be lost.'),
        [ChoiceDescription]::new("🧹 Clear &Z Hostability Key$([Environment]::NewLine)", 'Fixes some game join issues by removing the current hostability key in user_settings.config'),
        [ChoiceDescription]::new("🔁 Re-install &GameGuard$([Environment]::NewLine)", 'Performs a full GameGuard re-install. If Windows Ransomware Protection is enabled, may trigger security alert.'),
        [ChoiceDescription]::new("🔁 Re&set Steam$([Environment]::NewLine)", 'Performs a reset of Steam. This can fix various issues including VRAM memory leaks.'),
        [ChoiceDescription]::new("🗑️ &Uninstall VC++ Redists$([Environment]::NewLine)", 'Preps for installing VC++ Redists. Restart required.'),
        [ChoiceDescription]::new("➕ &Install VC++ Redists$([Environment]::NewLine)", 'Installs Microsoft Visual C++ Redistributables required by HD2. Fixes startup issues. Restart required.'),
        [ChoiceDescription]::new("🛠️ Set HD2 G&PU$([Environment]::NewLine)", 'Brings up the Windows GPU settings.'),
        [ChoiceDescription]::new("📺 Full-Screen &Optimizations (FSO) Toggle$([Environment]::NewLine)", 'Despite the name, having this off is usually recommended.'),
        [ChoiceDescription]::new("🛜 &Wi-Fi LAN Test$([Environment]::NewLine)", 'Tests the connection to the default gateway.'),
        [ChoiceDescription]::new("Double-NAT &Test$([Environment]::NewLine)", 'Tests network for Double NAT.'),
        [ChoiceDescription]::new("❌ &Quick Mod Removal$([Environment]::NewLine)", 'Will remove ALL mods from the \data\ folder.'),
        [ChoiceDescription]::new("🔈 Toggle &Bluetooth Telephony Service$([Environment]::NewLine)$([Environment]::NewLine)", 'Toggles the BTAGService on or off. Disabling it fixes Bluetooth Headphones.'),
        [ChoiceDescription]::new('E&xit', 'Exits the script.')
    )
    $DefaultChoice = 0
    $Choice = $Host.UI.PromptForChoice($Title, $Prompt, $Choices, $DefaultChoice)
    switch ($Choice) {
        0 {
            Show-Variables
            Show-MotherboardInfo
            Show-GPUInfo
            Show-OSInfo
            Show-GameLaunchOptions
            Test-PendingReboot
            Reset-HostabilityKey
            Find-CPUInfo
            Test-Firewall
            Test-CRL
            Test-RequiredURLs
            Test-RequiredURLs
            Test-RequiredURLs
            Test-RequiredURLs
            Test-SystemClockAccuracy
            Find-BlacklistedDrivers
            Test-BadPrinters
            Test-BTAGService
            Test-VisualC++Redists
            Test-Programs
            Get-PageFileSize
            Get-SystemUptime
            Get-HardwareInfo
            Get-SecureBootStatus
            Test-AVX2
            Test-MemoryChannels
            Get-MemoryPartNumber
            Get-MemorySpeed
            Find-Mods
            Get-VSyncConfig
            Show-TestResults
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        1 {
            Remove-HD2AppData
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        2 {
            Reset-HD2SteamCloud
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        3 {
            Reset-HostabilityKey
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        4 {
            Reset-GameGuard
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        5 {
            Reset-Steam
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        6 {
            Uninstall-VCRedist
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        7 {
            Install-VCRedist
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        8 {
            Open-AdvancedGraphics
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        9 {
            Switch-FullScreenOptimizations
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        10 {
            Test-WiFi
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        11 {
            Test-DoubleNat
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        12 {
            Show-ModRemovalWarning
            Remove-AllMods
            Menu
        }
        13 {
            Switch-BTAGService
            Write-Host "$([Environment]::NewLine)"
            Menu
        }
        14 { Return }
    }
}
Function Show-TestResults {
    $script:Tests.GetEnumerator() | ForEach-Object {
    $test = $_.Value
    If ($test.TestPassed -ne $true) {
        Invoke-Expression $test.TestFailMsg
    }
    Else {
        # Check if TestPassedMsg exists using Get-Member
        If ( $test.ContainsKey('TestPassedMsg') ) {
            Invoke-Expression $test.TestPassedMsg
        }
    }
    If ( $test.ContainsKey('AlwaysDisplayMsg') ) {
        Invoke-Expression $test.AlwaysDisplayMsg
    }
}
    # After showing, reset URL tests
    ForEach ($domain in $script:Tests.DomainTest.DomainList) {
        $domain.PassedTest = $null
    }
}
Function Get-MostRecentlyUsedSteamProfilePath {
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
                $script:mostRecentSteamUserProfilePath = $subfolder.FullName
            }
        }
    }
}
Write-Host 'Locating Steam...' -ForegroundColor Cyan
# Set AppID
$script:AppID = "553850"
$script:AppIDFound = $false
$LineOfInstallDir = 8
$LineOfBuildID = 13
Try { 
    $script:SteamPath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam").InstallPath
}
Catch { 
    Write-Host '[FAIL]' -NoNewline -ForegroundColor Red
    Write-Host 'Steam was not detected. Exiting Steam to fix this issue.' -ForegroundColor Cyan
    # Get the Steam process
    $steamProcess = Get-Process -Name "steam" -ErrorAction SilentlyContinue
    If ($steamProcess) {
    # Stop the Steam process
    Stop-Process -Name "steam" -Force
    }
    $script:SteamPath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam").InstallPath
}
Write-Host 'Locating Steam Library Data...' -ForegroundColor Cyan
$LibraryData = Get-Content -Path $SteamPath\steamapps\libraryfolders.vdf
# Read each line of the Steam library.vdf file
# Save a library path, then scan that library for $AppID
# If AppID is found, return current library path
ForEach ($line in $($LibraryData -split "$([Environment]::NewLine)")) {
    If ($line -like '*path*') {
        $script:AppInstallPath = ($line | ForEach-Object { $_.split('"')[3] })
        Write-Host $script:AppInstallPath
        $script:AppInstallPath = $script:AppInstallPath.Replace('\\', '\')
    }
    If (($line | ForEach-Object { $_.split('"') | Select-Object -Skip 1 }) -like "*$AppID*") {
        $script:AppIDFound = $true
        # Since we found the App location, let's get some data about it
        Try {
                $GameData = Get-Content -Path $script:AppInstallPath\steamapps\appmanifest_$AppID.acf
                }
        Catch {
                Write-Host "Error retrieving $script:AppInstallPath\steamapps\appmanifest_$AppID.acf" -ForegroundColor Yellow
                Write-Host 'If you moved Helldivers 2 without telling Steam, this can cause problems.' -ForegroundColor Cyan
                Write-Host 'See https://help.steampowered.com/en/faqs/view/4578-18A7-C819-8620.' -ForegroundColor Cyan
                Write-Host 'Several options will crash the script including mod deletion, resetting GameGuard, Full Screen Optimizations toggle and setting GPU options.' -ForegroundColor Yellow
                $script:AppInstallPath = $false
                Break
            }
        $script:BuildID = ($GameData[$LineOfBuildID - 1] | ForEach-Object { $_.split('"') | Select-Object -Skip 2 }).Trim() | Where-Object { $_ }
        $GameFolderName = ($GameData[$LineOfInstallDir - 1] | ForEach-Object { $_.split('"') | Select-Object -Skip 2 })
        # Update the AppInstallPath with the FULL path
        $script:AppInstallPath = ( $script:AppInstallPath + "\steamapps\common\" + $GameFolderName[1] )
        Break
    }
}
Get-MostRecentlyUsedSteamProfilePath
$HelldiversProcess = [PSCustomObject]@{
    ProcessName = 'helldivers2'
    ErrorMsg    = '
    ⚠️ The Helldivers 2 process is currently running. ⚠️
         Please close the game. If the game appears closed, restart the system, and re-run this script.
    '
}
$script:InstalledProgramsList = $null
Write-Host 'Checking to see if Helldivers 2 is currently running...' -ForegroundColor Cyan
Get-IsProcessRunning $HelldiversProcess
$script:InstalledProgramsList = Get-InstalledPrograms
Write-Host "Building menu... $([Environment]::NewLine)$([Environment]::NewLine)"
Menu
