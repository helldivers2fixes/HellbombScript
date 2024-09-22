## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/f23f1189542ccabf02acc69361ede1cf54ca1fbf02da1be5b52045ef8d1dabe6) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/f23f1189542ccabf02acc69361ede1cf54ca1fbf02da1be5b52045ef8d1dabe6) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/e97f87c67d6002cfd4b70bd0f099238e3e2370dbdbac6ed3db123409f0daae5a

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``e97f87c67d6002cfd4b70bd0f099238e3e2370dbdbac6ed3db123409f0daae5a``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/e97f87c67d6002cfd4b70bd0f099238e3e2370dbdbac6ed3db123409f0daae5a

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq e97f87c67d6002cfd4b70bd0f099238e3e2370dbdbac6ed3db123409f0daae5a``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.
