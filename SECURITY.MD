## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/4924aa21fc8c4a89ebade3a44d55e011f204c29c938afddf48c5c46fd3b386ae) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/4924aa21fc8c4a89ebade3a44d55e011f204c29c938afddf48c5c46fd3b386ae) link.

Not sure you trust the EXE? You can run
```powershell
"Hellbomb Script v40.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"
```
in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version** [VirusTotal Results](https://www.virustotal.com/gui/file/8b672fbaf2b14bda775e8cd46675934e2a9f2c2e758e853756b278a8c0e85010)

The ``Hellbomb Script.ps1`` SHA256 hash should match the VirusTotal file hash of ``8b672fbaf2b14bda775e8cd46675934e2a9f2c2e758e853756b278a8c0e85010``.

**Script Version** [Hybrid-Analysis Link](https://www.virustotal.com/gui/file/8b672fbaf2b14bda775e8cd46675934e2a9f2c2e758e853756b278a8c0e85010)

You can compare the file hash to the VirusTotal link to ensure that the VirusTotal results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. In Terminal or PowerShell ``cd`` (Change to the directory) where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run
```powershell
cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)
```
4. Run
```powershell
Get-FileHash 'Hellbomb Script v40.ps1' -eq 8b672fbaf2b14bda775e8cd46675934e2a9f2c2e758e853756b278a8c0e85010
```
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privileges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
