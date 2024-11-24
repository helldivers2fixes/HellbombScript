## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/5625f60d7de92e4ed19f147ff2ba0b0de2e9f84c18621363c9dce5227cb1bbfd) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/5625f60d7de92e4ed19f147ff2ba0b0de2e9f84c18621363c9dce5227cb1bbfd) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/dacaedc8d7c560553447cd5d306fa4c20f68f1e133076aa6badd5de36d1c559f

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``dacaedc8d7c560553447cd5d306fa4c20f68f1e133076aa6badd5de36d1c559f``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/dacaedc8d7c560553447cd5d306fa4c20f68f1e133076aa6badd5de36d1c559f

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq dacaedc8d7c560553447cd5d306fa4c20f68f1e133076aa6badd5de36d1c559f``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
