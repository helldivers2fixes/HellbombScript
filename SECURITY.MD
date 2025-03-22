## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/2d1eb39ebbc1287ead01dd6d0f7f4b3020804ba2c017590add440a03e343cc9e) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/2d1eb39ebbc1287ead01dd6d0f7f4b3020804ba2c017590add440a03e343cc9e) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/ca29b429c23ce5e3d2b08057b20efb7ac77df07928e348c956ed6f71d95cf5c6

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``ca29b429c23ce5e3d2b08057b20efb7ac77df07928e348c956ed6f71d95cf5c6``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/ca29b429c23ce5e3d2b08057b20efb7ac77df07928e348c956ed6f71d95cf5c6

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq ca29b429c23ce5e3d2b08057b20efb7ac77df07928e348c956ed6f71d95cf5c6``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
