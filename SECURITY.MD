## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/3d717f7fb52acf4a6efb2fe87a3278c95fd6f3935e738f4558ccce6cbbd0a136) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/3d717f7fb52acf4a6efb2fe87a3278c95fd6f3935e738f4558ccce6cbbd0a136) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/4d19047ef84abcb513a7d74229e3aaf6b23c513d6c0aeddff20b3c897249fcf6

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``4d19047ef84abcb513a7d74229e3aaf6b23c513d6c0aeddff20b3c897249fcf6``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/4d19047ef84abcb513a7d74229e3aaf6b23c513d6c0aeddff20b3c897249fcf6

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 4d19047ef84abcb513a7d74229e3aaf6b23c513d6c0aeddff20b3c897249fcf6``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
