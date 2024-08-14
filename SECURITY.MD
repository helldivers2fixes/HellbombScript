## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/16ff07d93cdac9f71f13c100e5433b4ea4b5288b1f795aeeafac905517c8718f) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/16ff07d93cdac9f71f13c100e5433b4ea4b5288b1f795aeeafac905517c8718f) link. Seems AV software hates the EXE, and Hybrid Analysis hates it even more than the PowerShell script 😆

Still don't trust it? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's not malicious.

**VirusTotal Results:** https://www.virustotal.com/gui/file/313740e37d28f82da38b4f5392afe357816b61cbf75487680bd009fd74184181

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``313740e37d28f82da38b4f5392afe357816b61cbf75487680bd009fd74184181``.

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 313740e37d28f82da38b4f5392afe357816b61cbf75487680bd009fd74184181``
5. The statement should return/evaluate to ``True``

**Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/313740e37d28f82da38b4f5392afe357816b61cbf75487680bd009fd74184181

No security software should detect the script as malicious (except KingSoft, because it ❤️ false positives).
