## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/8e0f9924512dbb97c6cd4037548d5b14839087db29295aab196b4c1eee4a4db5) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/8e0f9924512dbb97c6cd4037548d5b14839087db29295aab196b4c1eee4a4db5) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/b4f2be6b7e9662d6e3344344570c60bc581a50ec7c75f9893bbc4b953564b000

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``b4f2be6b7e9662d6e3344344570c60bc581a50ec7c75f9893bbc4b953564b000``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/b4f2be6b7e9662d6e3344344570c60bc581a50ec7c75f9893bbc4b953564b000

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq b4f2be6b7e9662d6e3344344570c60bc581a50ec7c75f9893bbc4b953564b000``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
