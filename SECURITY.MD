## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/a3d914bc92d41be2241be0a5ca85fda1f8bf62a5bf69f52a4b420f0f7bd9e6b2) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/a3d914bc92d41be2241be0a5ca85fda1f8bf62a5bf69f52a4b420f0f7bd9e6b2) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/7fc8c1390900740c06b7420ba6385a8791a0d46ed866e785044dc3365c0757b8

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``7fc8c1390900740c06b7420ba6385a8791a0d46ed866e785044dc3365c0757b8``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/7fc8c1390900740c06b7420ba6385a8791a0d46ed866e785044dc3365c0757b8

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 7fc8c1390900740c06b7420ba6385a8791a0d46ed866e785044dc3365c0757b8``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
