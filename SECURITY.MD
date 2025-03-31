## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/4db6f708845f42dbf23f278143668f7d449d526f2f034886eb300acfe5ebc695) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/4db6f708845f42dbf23f278143668f7d449d526f2f034886eb300acfe5ebc695) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/a23f94b4938bdbd72c172eeba27c1997c2cd353b3cbfa1c312aacf0c82c8be01

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``a23f94b4938bdbd72c172eeba27c1997c2cd353b3cbfa1c312aacf0c82c8be01``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/a23f94b4938bdbd72c172eeba27c1997c2cd353b3cbfa1c312aacf0c82c8be01

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq a23f94b4938bdbd72c172eeba27c1997c2cd353b3cbfa1c312aacf0c82c8be01``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs [Coreinfo64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/coreinfo) from Microsoft as Administrator
