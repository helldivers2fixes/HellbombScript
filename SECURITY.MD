## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/aed727a077628688078391775f688bfbfd46a35cfba836051acfbefd50062dbb) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/aed727a077628688078391775f688bfbfd46a35cfba836051acfbefd50062dbb) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/51e4441718274ab0442b4cdfcaf17721b5fb22ca323fdc6a01f915bb4f89fc91

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``51e4441718274ab0442b4cdfcaf17721b5fb22ca323fdc6a01f915bb4f89fc91``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/51e4441718274ab0442b4cdfcaf17721b5fb22ca323fdc6a01f915bb4f89fc91

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 51e4441718274ab0442b4cdfcaf17721b5fb22ca323fdc6a01f915bb4f89fc91``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
      ![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/734e2757-7a65-4bbf-8d6a-732275cecc51)
