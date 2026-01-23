## Code signing policy:
“Free code signing provided by SignPath.io, certificate by SignPath Foundation”

Committers and reviewers: helldivers2fixes

Approvers: helldivers2fixes

## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/DBF21FC9253648007A2B6C27BDC655D8F927AE81AFF5A1A4E6831BA83F0C193D) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/DBF21FC9253648007A2B6C27BDC655D8F927AE81AFF5A1A4E6831BA83F0C193D) link.

Not sure you trust the EXE? You can run
```powershell
& "Hellbomb_Script_v4.0-signed.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"
```
in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version** [VirusTotal Results](https://www.virustotal.com/gui/file/CD54D76397C3236C261FC881464F8BFA85BB1B1A9535F95CF032A5406B7AF539)

The ``Hellbomb Script.ps1`` SHA256 hash should match the VirusTotal file hash of ``CD54D76397C3236C261FC881464F8BFA85BB1B1A9535F95CF032A5406B7AF539``.

**Script Version** [Hybrid-Analysis Link](https://www.hybrid-analysis.com/sample/CD54D76397C3236C261FC881464F8BFA85BB1B1A9535F95CF032A5406B7AF539)

You can compare the file hash to the VirusTotal link to ensure that the VirusTotal results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. In Terminal or PowerShell ``cd`` (Change to the directory) where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run
```powershell
cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)
```
4. Run
```powershell
Get-FileHash 'Hellbomb Script.ps1' -eq CD54D76397C3236C261FC881464F8BFA85BB1B1A9535F95CF032A5406B7AF539
```
5. The statement should return/evaluate to ``True``

## Why does it need Admin Privileges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
