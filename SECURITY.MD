## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/e57af5e8731e53ce9d2a95d6210b80de20c0ad05a389ec0ec4cc646f0dd7a1af) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/e57af5e8731e53ce9d2a95d6210b80de20c0ad05a389ec0ec4cc646f0dd7a1af) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/ea48ae13faefd27ca63dc1638cd69effb173f76d0098ab6fa208201006d944bd

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``ea48ae13faefd27ca63dc1638cd69effb173f76d0098ab6fa208201006d944bd``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/ea48ae13faefd27ca63dc1638cd69effb173f76d0098ab6fa208201006d944bd

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq ea48ae13faefd27ca63dc1638cd69effb173f76d0098ab6fa208201006d944bd``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
