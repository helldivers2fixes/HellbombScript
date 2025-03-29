## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/6a3072ab72b596702e71f8c5062770558e8d38d41528007dde62035d8cb66c89) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/6a3072ab72b596702e71f8c5062770558e8d38d41528007dde62035d8cb66c89) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/608411464de7fc20f9cfd033e610a79bc9f28839829a13cf25c81aca9f452115

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``608411464de7fc20f9cfd033e610a79bc9f28839829a13cf25c81aca9f452115``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/608411464de7fc20f9cfd033e610a79bc9f28839829a13cf25c81aca9f452115

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 608411464de7fc20f9cfd033e610a79bc9f28839829a13cf25c81aca9f452115``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs [Coreinfo64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/coreinfo) from Microsoft as Administrator
