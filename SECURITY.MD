## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/4585360c927437111a855f73bc36a4ed6e56fb542ab0ef3e133a69d378129afc) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/4585360c927437111a855f73bc36a4ed6e56fb542ab0ef3e133a69d378129afc) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/a2710326018a386930702883d437c3f4be3abe7db8c2b75d73d3203111b4716f

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``a2710326018a386930702883d437c3f4be3abe7db8c2b75d73d3203111b4716f``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/a2710326018a386930702883d437c3f4be3abe7db8c2b75d73d3203111b4716f

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq a2710326018a386930702883d437c3f4be3abe7db8c2b75d73d3203111b4716f``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.
