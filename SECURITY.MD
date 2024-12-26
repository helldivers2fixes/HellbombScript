## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/8965fd8d005e0c2546855c7961c1f3bc40b145b5e9a7e3eb5a0f454eeaa0d6c6) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/8965fd8d005e0c2546855c7961c1f3bc40b145b5e9a7e3eb5a0f454eeaa0d6c6) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/f58862e5fcf1ab75b544397815069cfab0ab86874d851893e2545b9ab9ac8002

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``f58862e5fcf1ab75b544397815069cfab0ab86874d851893e2545b9ab9ac8002``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/f58862e5fcf1ab75b544397815069cfab0ab86874d851893e2545b9ab9ac8002

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq f58862e5fcf1ab75b544397815069cfab0ab86874d851893e2545b9ab9ac8002``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
Why? For some users, the script will error if it does not have Admin privleges when running the **Get-NetFirewallRule** command-let which **reads** Firewall rules. No changes are made to the firewall.
