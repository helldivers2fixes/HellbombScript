## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/fec96f6fad3f108f77943b20299e24d8dae0df5ec5ccad4adb443edb5f8c5dd7) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/fec96f6fad3f108f77943b20299e24d8dae0df5ec5ccad4adb443edb5f8c5dd7) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/2f7960625635f8bdec9076c8529339494e4a7b02da4388b6284f718d770967d9

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``2f7960625635f8bdec9076c8529339494e4a7b02da4388b6284f718d770967d9``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/2f7960625635f8bdec9076c8529339494e4a7b02da4388b6284f718d770967d9

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 2f7960625635f8bdec9076c8529339494e4a7b02da4388b6284f718d770967d9``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
