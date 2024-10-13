## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/1daeae50f85c3192c1567642bc9c05f90d5249a83f5e1b094ed05eec490f3536) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/1daeae50f85c3192c1567642bc9c05f90d5249a83f5e1b094ed05eec490f3536) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/9bb51ff6aae19688e070bc338b83e9d943d7e38720f0063ebe73eb023bade4ec

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``9bb51ff6aae19688e070bc338b83e9d943d7e38720f0063ebe73eb023bade4ec``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/9bb51ff6aae19688e070bc338b83e9d943d7e38720f0063ebe73eb023bade4ec

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 9bb51ff6aae19688e070bc338b83e9d943d7e38720f0063ebe73eb023bade4ec``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
       Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
      ![image](https://github.com/helldivers2fixes/HellbombScript/assets/166264070/734e2757-7a65-4bbf-8d6a-732275cecc51)
