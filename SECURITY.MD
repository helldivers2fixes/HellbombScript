## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/5fab5ebff7316ad49f2f00108ec8e9fa42639011f0833964e9e52849a9746b67) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/5fab5ebff7316ad49f2f00108ec8e9fa42639011f0833964e9e52849a9746b67) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**VirusTotal Results:** https://www.virustotal.com/gui/file/e02714d7b6d6f1f54ce87698c14dc25545c4f5adcb7381fcdfdec2e61f025411

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``e02714d7b6d6f1f54ce87698c14dc25545c4f5adcb7381fcdfdec2e61f025411``.

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq e02714d7b6d6f1f54ce87698c14dc25545c4f5adcb7381fcdfdec2e61f025411``
5. The statement should return/evaluate to ``True``

**Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/e02714d7b6d6f1f54ce87698c14dc25545c4f5adcb7381fcdfdec2e61f025411

No security software should detect the script as malicious (except KingSoft, because it ❤️ false positives).
