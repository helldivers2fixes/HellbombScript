## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/a6d2426b1245f6b0d6548ef576ffc97a838ba9d303cbb9d537a5957eed6857da) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/a6d2426b1245f6b0d6548ef576ffc97a838ba9d303cbb9d537a5957eed6857da) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/9b6febd8c88b832b216bed6ada0369778141f17298a8bf0eecc78c49224f5609

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``9b6febd8c88b832b216bed6ada0369778141f17298a8bf0eecc78c49224f5609``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/9b6febd8c88b832b216bed6ada0369778141f17298a8bf0eecc78c49224f5609

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 9b6febd8c88b832b216bed6ada0369778141f17298a8bf0eecc78c49224f5609``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
