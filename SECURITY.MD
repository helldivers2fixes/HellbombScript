## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/ddd64c954ffbcb41015f600f4db21ab61d82a54956077a2db12aafe9c9c308dd) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/ddd64c954ffbcb41015f600f4db21ab61d82a54956077a2db12aafe9c9c308dd) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/b576446b3de9a8603cdaf03248122a7b3bb28563d916f2b742b169334313ad33

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``b576446b3de9a8603cdaf03248122a7b3bb28563d916f2b742b169334313ad33``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/b576446b3de9a8603cdaf03248122a7b3bb28563d916f2b742b169334313ad33

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq b576446b3de9a8603cdaf03248122a7b3bb28563d916f2b742b169334313ad33``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
