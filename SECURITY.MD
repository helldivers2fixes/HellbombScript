## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/29A791FBCED99DEF31BAC3645CE435A3ACE976CBB2C3FA7E774E3E15B3F0BF71) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/29A791FBCED99DEF31BAC3645CE435A3ACE976CBB2C3FA7E774E3E15B3F0BF71) link.

Not sure you trust the EXE? You can run
```powershell
"Hellbomb_Script_v4.0-5c36c40.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"
```
in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version** [VirusTotal Results](https://www.virustotal.com/gui/file/6F8EE7B41C4706CDA04F6FDB03A1EDC955358F3698C28AA5EBFA6153FB47A8B1)

The ``Hellbomb Script.ps1`` SHA256 hash should match the VirusTotal file hash of ``6F8EE7B41C4706CDA04F6FDB03A1EDC955358F3698C28AA5EBFA6153FB47A8B1``.

**Script Version** [Hybrid-Analysis Link](https://www.hybrid-analysis.com/sample/6F8EE7B41C4706CDA04F6FDB03A1EDC955358F3698C28AA5EBFA6153FB47A8B1)

You can compare the file hash to the VirusTotal link to ensure that the VirusTotal results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. In Terminal or PowerShell ``cd`` (Change to the directory) where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run
```powershell
cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)
```
4. Run
```powershell
Get-FileHash 'Hellbomb Script.ps1' -eq 6F8EE7B41C4706CDA04F6FDB03A1EDC955358F3698C28AA5EBFA6153FB47A8B1
```
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privileges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
