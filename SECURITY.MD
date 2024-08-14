## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/7882103f3c0b15fa3b0ba156cda883f7efe724251a4d3cb0126a238f793882ae) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/7882103f3c0b15fa3b0ba156cda883f7efe724251a4d3cb0126a238f793882ae) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**VirusTotal Results:** https://www.virustotal.com/gui/file/1ff47dfd06dca7e935d097cffde8a1118aad45a28fd75a1ebd94727d7096a7cb

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``1ff47dfd06dca7e935d097cffde8a1118aad45a28fd75a1ebd94727d7096a7cb``.

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 1ff47dfd06dca7e935d097cffde8a1118aad45a28fd75a1ebd94727d7096a7cb``
5. The statement should return/evaluate to ``True``

**Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/1ff47dfd06dca7e935d097cffde8a1118aad45a28fd75a1ebd94727d7096a7cb

No security software should detect the script as malicious (except KingSoft, because it ❤️ false positives).
