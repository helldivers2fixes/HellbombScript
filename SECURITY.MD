## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/78b19db22f9a583397138e0f568066cf86ef4cb978899b4d0f8ec1f519c29590) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/78b19db22f9a583397138e0f568066cf86ef4cb978899b4d0f8ec1f519c29590) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/2508ffd5c6fa744672f2d997b7f991a251775a542c536a18fe5d2abe740b8da0

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``2508ffd5c6fa744672f2d997b7f991a251775a542c536a18fe5d2abe740b8da0``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/2508ffd5c6fa744672f2d997b7f991a251775a542c536a18fe5d2abe740b8da0

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 2508ffd5c6fa744672f2d997b7f991a251775a542c536a18fe5d2abe740b8da0``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs [Coreinfo64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/coreinfo) from Microsoft as Administrator
