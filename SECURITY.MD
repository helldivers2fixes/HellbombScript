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
 
We strongly encourage you to verify any downloaded file before running it. Below are several independent ways to do that.
 
### 1. Scan Results
We submit all our releases to VirusTotal and Hybrid Analysis for analysis. You can review the reports for the current release below.
 
| Artifact | VirusTotal | Hybrid Analysis |
|---|---|---|
| `Hellbomb_Script_v4.0-signed.exe` | [Report](https://www.virustotal.com/gui/file/ED0EE2CA907A17B96A98167495555228CCE1A2579AFF8CC5569B68DCF0D892B2) | [Report](https://www.hybrid-analysis.com/sample/ED0EE2CA907A17B96A98167495555228CCE1A2579AFF8CC5569B68DCF0D892B2) |
| `Hellbomb Script.ps1` | [Report](https://www.virustotal.com/gui/file/4DF39AA22EF24565E3AE4F259894BF889ACE7665B7FB1F44E04D9FD9AA7311A0) | [Report](https://www.hybrid-analysis.com/sample/4DF39AA22EF24565E3AE4F259894BF889ACE7665B7FB1F44E04D9FD9AA7311A0) |

> **Note:** These hashes and reports correspond to the current release only. If you download a newer or older version, the hashes will differ.
 
### 2. Verify the Executable's hash
1. Download the [latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) - `Hellbomb_Script_v4.0-signed.exe`
2. Open Terminal or PowerShell and navigate to the folder containing the script:
    ```powershell
        cd (Join-Path $HOME "Downloads")
    ```
   *(Use this if you downloaded it to your Downloads folder. Otherwise, `cd` to the correct directory.)*
3. Compute the file's hash and compare it to the value above:
    ```powershell
    Get-FileHash 'Hellbomb_Script_v4.0-signed.exe'
    ```
4. Confirm the output matches `ED0EE2CA907A17B96A98167495555228CCE1A2579AFF8CC5569B68DCF0D892B2`.
   To check this automatically instead of comparing by eye:
    ```powershell
    (Get-FileHash 'Hellbomb_Script_v4.0-signed.exe').Hash -eq 'ED0EE2CA907A17B96A98167495555228CCE1A2579AFF8CC5569B68DCF0D892B2'
    ```
    This should return `True`.

### 3. Extract the Script from the signed executable
 
If you don't fully trust the compiled `.exe`, you can extract the underlying PowerShell script from it and compare the result against the source in this repository:

1. Download the [latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) -  `Hellbomb_Script_v4.0-signed.exe`
2. Open Terminal or PowerShell and navigate to the folder containing the script:
    ```powershell
        cd (Join-Path $HOME "Downloads")
    ```
   *(Use this if you downloaded it to your Downloads folder. Otherwise, `cd` to the correct directory.)*
3. Use the tool included in this repository [Extract-EmbeddedResources.ps1](https://github.com/Plootie/HellbombScript/blob/Plootie-SecurityInfo/tools/Extract-EmbeddedResources.ps1) to extract the embedded `Hellbomb Script.ps1` script, as well as any other embedded resources.
    ```powershell
    ./ Extract-EmbeddedResources.ps1 -AssemblyPath "Hellbomb_Script_v4.0-signed.exe" -OutputDir "extracted_resources"
    ```
 
This writes `Hellbomb Script.ps1` and any other embedded resources, to the current working directory, where you can then open and review directly.
 
### 4. Verify the Script Hash
 
The latest release `Hellbomb Script.ps1` file should have a SHA-256 hash matching:
`4DF39AA22EF24565E3AE4F259894BF889ACE7665B7FB1F44E04D9FD9AA7311A0`
 
**Steps:**
 
1. Download the [latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) -  `Source Code.zip`, then extract `Hellbomb Script.ps1` from the archive.
2. Open Terminal or PowerShell and navigate to the folder containing the script:
```powershell
cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)
```
   *(Use this if you downloaded it to your Downloads folder. Otherwise, `cd` to the correct directory.)*
3. Compute the file's hash and compare it to the value above:
```powershell
Get-FileHash 'Hellbomb Script.ps1'
```
4. Confirm the output matches `4DF39AA22EF24565E3AE4F259894BF889ACE7665B7FB1F44E04D9FD9AA7311A0`.
   To check this automatically instead of comparing by eye:
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
