# Security Policy
 
## Code Signing
 
Builds are signed free of charge by [**SignPath.io**](https://signpath.org/), with certificates provided by the **SignPath Foundation**.
 
| Role | GitHub User |
|------|-------------|
| Authors | `helldivers2fixes` |
| Reviewers | `helldivers2fixes` |
| Approvers | `helldivers2fixes` |

> **Note** Note: This project currently has a single maintainer. All code changes, including those authored by the maintainer are submitted via pull request from a personal account and reviewed/merged under the dedicated `helldivers2fixes` account before release. This ensures every change passes through a deliberate review step, even though review and approval are currently performed by the same person.
 
## Verifying Your Download
 
We strongly encourage you to verify any downloaded file before running it. A few independent ways to do that are described below.
 
Steps #2 and below assume you've downloaded the [latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) (`Hellbomb_Script_v4.0-signed.exe`) and opened a terminal or PowerShell window in the folder it's in, e.g.:
 
```powershell
cd (Join-Path $HOME "Downloads")
```
 
*(Adjust the path if you saved the file elsewhere.)*
 
### 1. Check the Scan Results
 
We submit every release to VirusTotal and Hybrid Analysis. You can review the reports for the current release below, or submit your own sample to these services.
 
| Artifact | VirusTotal | Hybrid Analysis |
|---|---|---|
| `Hellbomb_Script_v4.0-signed.exe` | [Report](https://www.virustotal.com/gui/file/ED0EE2CA907A17B96A98167495555228CCE1A2579AFF8CC5569B68DCF0D892B2) | [Report](https://www.hybrid-analysis.com/sample/ED0EE2CA907A17B96A98167495555228CCE1A2579AFF8CC5569B68DCF0D892B2) |
| `Hellbomb Script.ps1` | [Report](https://www.virustotal.com/gui/file/4DF39AA22EF24565E3AE4F259894BF889ACE7665B7FB1F44E04D9FD9AA7311A0) | [Report](https://www.hybrid-analysis.com/sample/4DF39AA22EF24565E3AE4F259894BF889ACE7665B7FB1F44E04D9FD9AA7311A0) |
 
> **Note:** These hashes and reports correspond to the current release only. Hashes will differ for any other version.
 
### 2. Verify the Executable's Hash
 
Compute the file's hash and compare it to the value above (`ED0EE2CA907A17B96A98167495555228CCE1A2579AFF8CC5569B68DCF0D892B2`):
 
```powershell
Get-FileHash 'Hellbomb_Script_v4.0-signed.exe'
```
 
To check automatically instead of comparing by eye:
 
```powershell
(Get-FileHash 'Hellbomb_Script_v4.0-signed.exe').Hash -eq 'ED0EE2CA907A17B96A98167495555228CCE1A2579AFF8CC5569B68DCF0D892B2'
```
 
This should return `True`.


### 3. Extract the Script from the Signed Executable
 
If you don't fully trust the compiled `.exe`, you can extract the underlying PowerShell script and compare it against the source in this repository. Below are a few ways to do that.

#### Option A: Our extraction script

For convenience, we provide [Extract-EmbeddedResources.ps1](https://github.com/helldivers2fixes/HellbombScript/blob/main/tools/Extract-EmbeddedResources.ps1), which detects your PowerShell version automatically and runs the matching approach from Option B below. It's under 150 lines, so we'd encourage reading through it before running it:

```powershell
./Extract-EmbeddedResources.ps1 -AssemblyPath "Hellbomb_Script_v4.0-signed.exe" -OutputDir "extracted_resources"
```

This writes `Hellbomb Script.ps1`, along with any other embedded resources, to the output directory, where you can open and review it directly.

> **Note:** If you receive the error `File ../Extract-EmbeddedResources.ps1 cannot be loaded because running scripts is disabled on this system`, you'll need to adjust your PowerShell execution policy. See Microsoft's documentation for details:
> - [Set-ExecutionPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.6)
> - [about_Execution_Policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.6)

#### Option B: Manual extraction
 
If you'd rather not download anything new, you can extract the script by typing these lines directly into a PowerShell prompt (not saving/running them as a file). Check `$PSVersionTable.PSVersion` first and use the matching snippet. The underlying API differs between PowerShell 5.1 and PowerShell 7:
 
**Windows PowerShell 5.1 (.NET Framework):**
 
```powershell
$asm = [System.Reflection.Assembly]::ReflectionOnlyLoadFrom((Resolve-Path "Hellbomb_Script_v4.0-signed.exe"))
$stream = $asm.GetManifestResourceStream("Hellbomb Script.ps1")
$reader = New-Object IO.StreamReader($stream)
$reader.ReadToEnd() | Out-File (Join-Path (Get-Location) "Hellbomb Script.ps1") -Encoding UTF8 -NoNewline
$reader.Dispose(); $stream.Dispose()
```
 
`ReflectionOnlyLoadFrom` loads the assembly in a reflection-only context, which the .NET Framework runtime guarantees cannot execute any code from the target file, only metadata and embedded resources are accessible. This API does not exist in PowerShell 7 (.NET Core removed reflection-only loading), so PS7 users need the snippet below instead.
For more information, see https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assembly.reflectiononlyloadfrom?view=netframework-4.8
 
**PowerShell 7 (.NET Core / .NET 5+):**
 
```powershell
Add-Type -AssemblyName System.Reflection.Metadata
$fileStream = [System.IO.File]::OpenRead((Resolve-Path "Hellbomb_Script_v4.0-signed.exe"))
$peReader = [System.Reflection.PortableExecutable.PEReader]::new($fileStream)
$mdReader = [System.Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($peReader)
$resourcesBlock = $peReader.GetSectionData($peReader.PEHeaders.CorHeader.ResourcesDirectory.RelativeVirtualAddress)
$handle = $mdReader.ManifestResources | Where-Object { $mdReader.GetString($mdReader.GetManifestResource($_).Name) -eq "Hellbomb Script.ps1" }
$resource = $mdReader.GetManifestResource($handle)
$length = $resourcesBlock.GetReader([int]$resource.Offset, 4).ReadUInt32()
$dataReader = $resourcesBlock.GetReader([int]$resource.Offset + 4, [int]$length)
$buffer = [byte[]]::new($length)
$dataReader.ReadBytes([int]$length, $buffer, 0)
[System.IO.File]::WriteAllBytes((Join-Path (Get-Location) "Hellbomb Script.ps1"), $buffer)
$peReader.Dispose(); $fileStream.Dispose()
```
 
This parses the PE/COFF file's metadata directly via `System.Reflection.Metadata` and never loads the assembly into the CLR at all, so execution isn't possible.
For more information, see https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

#### Option C: 3rd Party tools

If you do not trust anything provided by this repository there are 3rd party tools that allow you to inspect and extract embedded resources for .NET executables, however you will now be placing your trust in that 3rd party and their tools.
 
### 4. Verify the Script Hash
 
After extracting the script, check its hash the same way as the executable. The latest release's `Hellbomb Script.ps1` should have a SHA-256 hash matching `4DF39AA22EF24565E3AE4F259894BF889ACE7665B7FB1F44E04D9FD9AA7311A0`:
 
```powershell
Get-FileHash 'Hellbomb Script.ps1'
```
 
To check automatically instead of comparing by eye:
 
```powershell
(Get-FileHash 'Hellbomb Script.ps1').Hash -eq '4DF39AA22EF24565E3AE4F259894BF889ACE7665B7FB1F44E04D9FD9AA7311A0'
```
 
This should return `True`.
 
 
## Why Does the Script Need Administrator Privileges?
 
Administrator privileges are required because the script, among other things:
 
- Reads firewall rules
- Installs the Microsoft Visual C++ Redistributables
- Downloads and runs the zip release of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID

If you have concerns about any of these actions, we recommend reviewing the script contents directly (see verification steps above) before running it.
 
## Reporting a Vulnerability
 
Please **do not** open a public GitHub issue for security vulnerabilities. This could expose the issue to bad actors before a fix is available.
 
Instead, please report it privately using one of the following:
 
- [GitHub Security Advisories](https://github.com/helldivers2fixes/HellbombScript/security/advisories/new) for this repository, or
- Direct message to a maintainer listed in the Code Signing table above.
Please include a description of the issue, steps to reproduce it, and its potential impact. We'll acknowledge your report and work with you on a fix and coordinated disclosure timeline.