## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/0a61ba553c4038e0ed29bf3f0d297bb9739d22e09a06728c6176abd499856e6f) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/0a61ba553c4038e0ed29bf3f0d297bb9739d22e09a06728c6176abd499856e6f) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/0e2a3869e9fd8523dbc487a8dee1cfde5a237c10421bf46bddbed32c789c019c

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``0e2a3869e9fd8523dbc487a8dee1cfde5a237c10421bf46bddbed32c789c019c``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/0e2a3869e9fd8523dbc487a8dee1cfde5a237c10421bf46bddbed32c789c019c

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 0e2a3869e9fd8523dbc487a8dee1cfde5a237c10421bf46bddbed32c789c019c``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
