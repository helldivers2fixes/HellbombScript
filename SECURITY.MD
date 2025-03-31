## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/df2669aa00fb11118abec58f0d5b3506b8522599d9e03299073c9d0e349248c6) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/df2669aa00fb11118abec58f0d5b3506b8522599d9e03299073c9d0e349248c6) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/50b138f97ebce119c1f42354729d1ebe66f97c1203d0aac2e022f1cd776a96db

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``50b138f97ebce119c1f42354729d1ebe66f97c1203d0aac2e022f1cd776a96db``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/50b138f97ebce119c1f42354729d1ebe66f97c1203d0aac2e022f1cd776a96db

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 50b138f97ebce119c1f42354729d1ebe66f97c1203d0aac2e022f1cd776a96db``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs [Coreinfo64.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/coreinfo) from Microsoft as Administrator
