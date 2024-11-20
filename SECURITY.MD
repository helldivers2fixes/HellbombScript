## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/cd77d9b8736299a9ed39b33c87f13e470bd474a71715e103baef84d037e6e1ce) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/cd77d9b8736299a9ed39b33c87f13e470bd474a71715e103baef84d037e6e1ce) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/6b249c579768b844a52f8fde30820a08f3be68927dbaf88e54c4372d196a2316

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``6b249c579768b844a52f8fde30820a08f3be68927dbaf88e54c4372d196a2316``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/6b249c579768b844a52f8fde30820a08f3be68927dbaf88e54c4372d196a2316

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 6b249c579768b844a52f8fde30820a08f3be68927dbaf88e54c4372d196a2316``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
