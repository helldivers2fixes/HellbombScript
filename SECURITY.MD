## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/22a537dc88cfa45d192c49f5b3a08fd98accd90809622c51a0c657e233efb2e1) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/22a537dc88cfa45d192c49f5b3a08fd98accd90809622c51a0c657e233efb2e1) link.

Not sure you trust the EXE? You can run
```powershell
"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"
```
in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:**

https://www.virustotal.com/gui/file/c1dc4ee8a79f09a1c58cb490001fe1e27cacf376f31e1fe79982bd1bcd4f4a10

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``c1dc4ee8a79f09a1c58cb490001fe1e27cacf376f31e1fe79982bd1bcd4f4a10``.

**Script Version Hybrid-Analysis Link:**

https://www.hybrid-analysis.com/sample/c1dc4ee8a79f09a1c58cb490001fe1e27cacf376f31e1fe79982bd1bcd4f4a10

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. In Terminal or PowerShell ``cd`` (Change to the directory) where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run
```powershell
cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)
```
4. Run
```powershell
Get-FileHash 'Hellbomb Script.ps1' -eq c1dc4ee8a79f09a1c58cb490001fe1e27cacf376f31e1fe79982bd1bcd4f4a10
```
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
