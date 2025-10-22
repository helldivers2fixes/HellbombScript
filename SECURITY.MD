## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/CFDE8DD9AC5731F361686D1D660BB72A3B88CD43C75FF256BD913F29A6F25220) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/CFDE8DD9AC5731F361686D1D660BB72A3B88CD43C75FF256BD913F29A6F25220) link.

Not sure you trust the EXE? You can run
```powershell
"Hellbomb_Script_v4.0-5c36c40.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"
```
in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version** [VirusTotal Results](https://www.virustotal.com/gui/file/F210D8CD94A481E0BD3296B1DFDF33569EE666BAA83873F8E4543FC9918264AB)

The ``Hellbomb Script.ps1`` SHA256 hash should match the VirusTotal file hash of ``F210D8CD94A481E0BD3296B1DFDF33569EE666BAA83873F8E4543FC9918264AB``.

**Script Version** [Hybrid-Analysis Link](https://www.hybrid-analysis.com/sample/F210D8CD94A481E0BD3296B1DFDF33569EE666BAA83873F8E4543FC9918264AB)

You can compare the file hash to the VirusTotal link to ensure that the VirusTotal results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. In Terminal or PowerShell ``cd`` (Change to the directory) where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run
```powershell
cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)
```
4. Run
```powershell
Get-FileHash 'Hellbomb Script.ps1' -eq F210D8CD94A481E0BD3296B1DFDF33569EE666BAA83873F8E4543FC9918264AB
```
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privileges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
