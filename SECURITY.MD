## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/0ed6ce60daaa1507ff288731b661273b7dfc20e0cbb8f65e430494cfcd108cc0) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/0ed6ce60daaa1507ff288731b661273b7dfc20e0cbb8f65e430494cfcd108cc0) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

**VirusTotal Results:** https://www.virustotal.com/gui/file/ca1998c8d70a6ef9c548efebeacb56974e8bbee95b1716c98cb89973f00d4dc1

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``ca1998c8d70a6ef9c548efebeacb56974e8bbee95b1716c98cb89973f00d4dc1``.

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq ca1998c8d70a6ef9c548efebeacb56974e8bbee95b1716c98cb89973f00d4dc1``
5. The statement should return/evaluate to ``True``

**Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/ca1998c8d70a6ef9c548efebeacb56974e8bbee95b1716c98cb89973f00d4dc1

No security software should detect the script as malicious (except KingSoft, because it ❤️ false positives).
