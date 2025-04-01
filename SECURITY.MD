## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/f37b69f7274d5068ca1602369ab3090b5ae8f8096d2dc12911717f1776df7c78) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/f37b69f7274d5068ca1602369ab3090b5ae8f8096d2dc12911717f1776df7c78) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/f8bd8b05108eb035c7bfb5e12caaf1f983b6b2791ea1d9efb0cd35162cadcea4

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``f8bd8b05108eb035c7bfb5e12caaf1f983b6b2791ea1d9efb0cd35162cadcea4``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/f8bd8b05108eb035c7bfb5e12caaf1f983b6b2791ea1d9efb0cd35162cadcea4

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq f8bd8b05108eb035c7bfb5e12caaf1f983b6b2791ea1d9efb0cd35162cadcea4``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs [Coreinfo64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/coreinfo) from Microsoft as Administrator
