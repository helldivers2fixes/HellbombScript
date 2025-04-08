## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/7ddc067eac6d9fc5687ccd8c4d9d1ffb7ab577382fd67ed9312d2b43cf222b65) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/7ddc067eac6d9fc5687ccd8c4d9d1ffb7ab577382fd67ed9312d2b43cf222b65) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/e4fb55b1b275700672dac1b7f78c44fbd91d527b453b5b4f31acee30af6813df

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``e4fb55b1b275700672dac1b7f78c44fbd91d527b453b5b4f31acee30af6813df``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/e4fb55b1b275700672dac1b7f78c44fbd91d527b453b5b4f31acee30af6813df

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Save the script as Hellbomb Script.ps1
2. Change to the directory where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $env:USERPROFILE\Downloads``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq e4fb55b1b275700672dac1b7f78c44fbd91d527b453b5b4f31acee30af6813df``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
