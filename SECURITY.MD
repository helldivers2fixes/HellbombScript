## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/bddb0b14f4052f0cb6145ca0e0b7c387a740ffc08f1142eeee890734d09997e6) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/bddb0b14f4052f0cb6145ca0e0b7c387a740ffc08f1142eeee890734d09997e6) link.

Not sure you trust the EXE? You can run
```powershell
"Hellbomb Script v36.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"
```
in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version** [VirusTotal Results](https://www.virustotal.com/gui/file/c1dc4ee8a79f09a1c58cb490001fe1e27cacf376f31e1fe79982bd1bcd4f4a10)

The ``Hellbomb Script v36.ps1`` SHA256 hash should match the VirusTotal file hash of ``c6f0145e960f5c35983db4b7e5ce9c3691e39c95a607789b6c05861f3c0f4802``.

**Script Version** [Hybrid-Analysis Link](https://www.virustotal.com/gui/file/c6f0145e960f5c35983db4b7e5ce9c3691e39c95a607789b6c05861f3c0f4802)

You can compare the file hash to the VirusTotal link to ensure that the VirusTotal results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. In Terminal or PowerShell ``cd`` (Change to the directory) where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run
```powershell
cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)
```
4. Run
```powershell
Get-FileHash 'Hellbomb Script v36.ps1' -eq c6f0145e960f5c35983db4b7e5ce9c3691e39c95a607789b6c05861f3c0f4802
```
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privileges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
