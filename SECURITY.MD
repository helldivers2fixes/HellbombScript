## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/46c2aee4e11017a3a404a41153b219322a1aa3350e0e3a7986839dde2506ba72) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/46c2aee4e11017a3a404a41153b219322a1aa3350e0e3a7986839dde2506ba72) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/2aefb5de58c39272126785fb482ee84ec94a6b6883aad4494194ee8e46fdc916

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``2aefb5de58c39272126785fb482ee84ec94a6b6883aad4494194ee8e46fdc916``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/2aefb5de58c39272126785fb482ee84ec94a6b6883aad4494194ee8e46fdc916

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. In Terminal or PowerShell ``cd`` (Change to the directory) where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 2aefb5de58c39272126785fb482ee84ec94a6b6883aad4494194ee8e46fdc916``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
