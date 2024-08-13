## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/ccb311f1b889fa03e74695709804240d9a702225e252ca4167c8ff82c2269bd0) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/ccb311f1b889fa03e74695709804240d9a702225e252ca4167c8ff82c2269bd0) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**VirusTotal Results:** https://www.virustotal.com/gui/file/c7d9c4e4e922cc2c748c4941d4212c549efcfc5db868d6d81b36ae2b53c2d507

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``c7d9c4e4e922cc2c748c4941d4212c549efcfc5db868d6d81b36ae2b53c2d507``.

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq c7d9c4e4e922cc2c748c4941d4212c549efcfc5db868d6d81b36ae2b53c2d507``
5. The statement should return/evaluate to ``True``

**Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/c7d9c4e4e922cc2c748c4941d4212c549efcfc5db868d6d81b36ae2b53c2d507

No security software should detect the script as malicious (except KingSoft, because it ❤️ false positives).
