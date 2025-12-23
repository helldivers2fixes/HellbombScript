## Code signing policy:
“Free code signing provided by SignPath.io, certificate by SignPath Foundation”

Committers and reviewers: helldivers2fixes

Approvers: helldivers2fixes

## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/08BA03BE82515CDE6C68E32C5947AEB4595A6860537285E11B4673B2559DE5BC) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/08BA03BE82515CDE6C68E32C5947AEB4595A6860537285E11B4673B2559DE5BC) link.

Not sure you trust the EXE? You can run
```powershell
& "Hellbomb_Script_v4.0-signed.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"
```
in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version** [VirusTotal Results](https://www.virustotal.com/gui/file/CB80DDEEF742EA8A99EE88A0E8D8788F0BACFEF92BE2462899E1A96CF571826D)

The ``Hellbomb Script.ps1`` SHA256 hash should match the VirusTotal file hash of ``CB80DDEEF742EA8A99EE88A0E8D8788F0BACFEF92BE2462899E1A96CF571826D``.

**Script Version** [Hybrid-Analysis Link](https://www.hybrid-analysis.com/sample/CB80DDEEF742EA8A99EE88A0E8D8788F0BACFEF92BE2462899E1A96CF571826D)

You can compare the file hash to the VirusTotal link to ensure that the VirusTotal results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. In Terminal or PowerShell ``cd`` (Change to the directory) where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run
```powershell
cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)
```
4. Run
```powershell
Get-FileHash 'Hellbomb Script.ps1' -eq CB80DDEEF742EA8A99EE88A0E8D8788F0BACFEF92BE2462899E1A96CF571826D
```
5. The statement should return/evaluate to ``True``

## Why does it need Admin Privileges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
