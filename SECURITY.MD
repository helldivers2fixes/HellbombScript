## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/8d011305f1d11346d078d28a62b9cce74065054cf1761a8b75d7f24e82905a5d) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/8d011305f1d11346d078d28a62b9cce74065054cf1761a8b75d7f24e82905a5d) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/20f202aeecf117cc7314d59e3dd90ab7ce54ffc06e58be4b8a2617c2b7b1823e

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``20f202aeecf117cc7314d59e3dd90ab7ce54ffc06e58be4b8a2617c2b7b1823e``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/20f202aeecf117cc7314d59e3dd90ab7ce54ffc06e58be4b8a2617c2b7b1823e

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 20f202aeecf117cc7314d59e3dd90ab7ce54ffc06e58be4b8a2617c2b7b1823e``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs [Coreinfo64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/coreinfo) from Microsoft as Administrator
