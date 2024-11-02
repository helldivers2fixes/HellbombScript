## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/07726452dce8bba953ab48fb313a56a5a08c902958106bfe22d6e155b77d4d56) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/07726452dce8bba953ab48fb313a56a5a08c902958106bfe22d6e155b77d4d56) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/c9b8b7e05908f49cb4c033422d01aa2cca80a96e8434ad2a07ab4e45dd7d6627

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``c9b8b7e05908f49cb4c033422d01aa2cca80a96e8434ad2a07ab4e45dd7d6627``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/c9b8b7e05908f49cb4c033422d01aa2cca80a96e8434ad2a07ab4e45dd7d6627

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq c9b8b7e05908f49cb4c033422d01aa2cca80a96e8434ad2a07ab4e45dd7d6627``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
