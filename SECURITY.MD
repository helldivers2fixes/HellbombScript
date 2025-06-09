## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/e122eb1de63de8eb7cb4ff1f3459c3adccea3b47348378a90542246bd76aaf7b) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/e122eb1de63de8eb7cb4ff1f3459c3adccea3b47348378a90542246bd76aaf7b) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/cda8f196fc9bccc69a04a09477adfbc5d9b0dd89c985a02e227fc9c38ebc8901

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``cda8f196fc9bccc69a04a09477adfbc5d9b0dd89c985a02e227fc9c38ebc8901``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/cda8f196fc9bccc69a04a09477adfbc5d9b0dd89c985a02e227fc9c38ebc8901

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. In Terminal or PowerShell ``cd`` (Change to the directory) where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq cda8f196fc9bccc69a04a09477adfbc5d9b0dd89c985a02e227fc9c38ebc8901``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
