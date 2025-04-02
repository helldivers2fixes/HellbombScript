## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/09ef80c6ee2d5172ff13dee7be0d165ab33b0a57883bc63f95dd4bbf582873c2) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/09ef80c6ee2d5172ff13dee7be0d165ab33b0a57883bc63f95dd4bbf582873c2) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/a3cb9d446a816793520e778202e87ab0c9581347ecae868c7d9496fc258b5153

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``a3cb9d446a816793520e778202e87ab0c9581347ecae868c7d9496fc258b5153``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/a3cb9d446a816793520e778202e87ab0c9581347ecae868c7d9496fc258b5153

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq a3cb9d446a816793520e778202e87ab0c9581347ecae868c7d9496fc258b5153``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs [Coreinfo64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/coreinfo) from Microsoft as Administrator
