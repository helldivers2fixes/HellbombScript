## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/b6ca278365ca0992e46f38f95daa79dba825f4b04efeb9bf1489083c9b14f7f0) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/b6ca278365ca0992e46f38f95daa79dba825f4b04efeb9bf1489083c9b14f7f0) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**VirusTotal Results:** https://www.virustotal.com/gui/file/9cd69f59d233a1fb3a17cb7e4d8b0b24c8618a377711bc5e1001a30d34268b72

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``9cd69f59d233a1fb3a17cb7e4d8b0b24c8618a377711bc5e1001a30d34268b72``.

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 9cd69f59d233a1fb3a17cb7e4d8b0b24c8618a377711bc5e1001a30d34268b72``
5. The statement should return/evaluate to ``True``

**Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/9cd69f59d233a1fb3a17cb7e4d8b0b24c8618a377711bc5e1001a30d34268b72

No security software should detect the script as malicious (except KingSoft, because it ❤️ false positives).
