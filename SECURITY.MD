## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/90e4029182cf431a4e233a63561e308d2e0cea36d44e977389007aad03f5b3c6) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/90e4029182cf431a4e233a63561e308d2e0cea36d44e977389007aad03f5b3c6) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/f06dc373ee07984de619b1d632457b9af2f5340e6e7e545a12813f07eb0b6319

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``f06dc373ee07984de619b1d632457b9af2f5340e6e7e545a12813f07eb0b6319``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/f06dc373ee07984de619b1d632457b9af2f5340e6e7e545a12813f07eb0b6319

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq f06dc373ee07984de619b1d632457b9af2f5340e6e7e545a12813f07eb0b6319``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs [Coreinfo64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/coreinfo) from Microsoft as Administrator
