## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/1681e3b27afbea695db2e28d2cadce14ce30fe4de5165cc754a97712f6847f56) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/1681e3b27afbea695db2e28d2cadce14ce30fe4de5165cc754a97712f6847f56) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/1ddb9c73782bad272c5ac0875e529314c2bd4f28aecbf4394542ddcae6df8a09

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``1ddb9c73782bad272c5ac0875e529314c2bd4f28aecbf4394542ddcae6df8a09``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/1ddb9c73782bad272c5ac0875e529314c2bd4f28aecbf4394542ddcae6df8a09

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 1ddb9c73782bad272c5ac0875e529314c2bd4f28aecbf4394542ddcae6df8a09``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs [Coreinfo64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/coreinfo) from Microsoft as Administrator
