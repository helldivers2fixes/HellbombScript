## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/5944568d4e4fe2d219cf4bffb2ff6edb78981b381d356a89465cd36d97501e4a) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/5944568d4e4fe2d219cf4bffb2ff6edb78981b381d356a89465cd36d97501e4a) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/bf4ea533717a1390dd67fe3d066523903b6d2501b1ea939f0be3092f57a79862

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``bf4ea533717a1390dd67fe3d066523903b6d2501b1ea939f0be3092f57a79862``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/bf4ea533717a1390dd67fe3d066523903b6d2501b1ea939f0be3092f57a79862

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq bf4ea533717a1390dd67fe3d066523903b6d2501b1ea939f0be3092f57a79862``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
       Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
      ![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/734e2757-7a65-4bbf-8d6a-732275cecc51)
