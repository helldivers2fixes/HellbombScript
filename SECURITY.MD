## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/40449940b248b0bc2bd1289ef768910d16ec22850bf134f6dfd0b9c960340bbb) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/40449940b248b0bc2bd1289ef768910d16ec22850bf134f6dfd0b9c960340bbb) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/03d098d31c39f23263beef1dd040bae5f3061a4a4f1c5fba1384d482b805760f

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``03d098d31c39f23263beef1dd040bae5f3061a4a4f1c5fba1384d482b805760f``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/03d098d31c39f23263beef1dd040bae5f3061a4a4f1c5fba1384d482b805760f

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 03d098d31c39f23263beef1dd040bae5f3061a4a4f1c5fba1384d482b805760f``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs [Coreinfo64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/coreinfo) from Microsoft as Administrator
