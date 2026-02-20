## Code signing policy:
“Free code signing provided by SignPath.io, certificate by SignPath Foundation”

Committers and reviewers: helldivers2fixes

Approvers: helldivers2fixes

## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/44EA50386798F2B623B9A1BA11A98B4E95414119C77AC5AD8CD749C33E7A3F2A) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/44EA50386798F2B623B9A1BA11A98B4E95414119C77AC5AD8CD749C33E7A3F2A) link.

Not sure you trust the EXE? You can run
```powershell
& "Hellbomb_Script_v4.0-signed.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"
```
in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version** [VirusTotal Results](https://www.virustotal.com/gui/file/CAF377FE80BD62842A7D5D57AC81A947EA41C7FD25E2A3D12CDCB1273D72EEB1)

The ``Hellbomb Script.ps1`` SHA256 hash should match the VirusTotal file hash of ``CAF377FE80BD62842A7D5D57AC81A947EA41C7FD25E2A3D12CDCB1273D72EEB1``.

**Script Version** [Hybrid-Analysis Link](https://www.hybrid-analysis.com/sample/CAF377FE80BD62842A7D5D57AC81A947EA41C7FD25E2A3D12CDCB1273D72EEB1)

You can compare the file hash to the VirusTotal link to ensure that the VirusTotal results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. In Terminal or PowerShell ``cd`` (Change to the directory) where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run
```powershell
cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)
```
4. Run
```powershell
Get-FileHash 'Hellbomb Script.ps1' -eq CAF377FE80BD62842A7D5D57AC81A947EA41C7FD25E2A3D12CDCB1273D72EEB1
```
5. The statement should return/evaluate to ``True``

## Why does it need Admin Privileges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
