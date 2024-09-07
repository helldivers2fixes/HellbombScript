## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/e24a6bb3dc2276fb8892c24cf7846b2ccc65bc59791a774631be589e86986300) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/e24a6bb3dc2276fb8892c24cf7846b2ccc65bc59791a774631be589e86986300) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**VirusTotal Results:** https://www.virustotal.com/gui/file/500cad54d5d70575cff51c8921a4c930d592a1c30dd2f56fd7fd555c170d5805

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``500cad54d5d70575cff51c8921a4c930d592a1c30dd2f56fd7fd555c170d5805``.

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 500cad54d5d70575cff51c8921a4c930d592a1c30dd2f56fd7fd555c170d5805``
5. The statement should return/evaluate to ``True``

**Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/500cad54d5d70575cff51c8921a4c930d592a1c30dd2f56fd7fd555c170d5805

No security software should detect the script as malicious (except KingSoft, because it ❤️ false positives).
