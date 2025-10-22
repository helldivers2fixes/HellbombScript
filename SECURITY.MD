## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/2AC6F504852697B69CDC500C945AE88A109AC93FB7FE5049A630C25D57C043B2) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/2AC6F504852697B69CDC500C945AE88A109AC93FB7FE5049A630C25D57C043B2) link.

Not sure you trust the EXE? You can run
```powershell
"Hellbomb_Script_v4.0-5c36c40.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"
```
in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version** [VirusTotal Results](https://www.virustotal.com/gui/file/629009208D1023EE4DFCCC4CE7E352E31F3688EBB21BB94B69A9C9233491613B)

The ``Hellbomb Script.ps1`` SHA256 hash should match the VirusTotal file hash of ``629009208D1023EE4DFCCC4CE7E352E31F3688EBB21BB94B69A9C9233491613B``.

**Script Version** [Hybrid-Analysis Link](https://www.hybrid-analysis.com/sample/629009208D1023EE4DFCCC4CE7E352E31F3688EBB21BB94B69A9C9233491613B)

You can compare the file hash to the VirusTotal link to ensure that the VirusTotal results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. In Terminal or PowerShell ``cd`` (Change to the directory) where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run
```powershell
cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)
```
4. Run
```powershell
Get-FileHash 'Hellbomb Script.ps1' -eq 629009208D1023EE4DFCCC4CE7E352E31F3688EBB21BB94B69A9C9233491613B
```
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privileges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
