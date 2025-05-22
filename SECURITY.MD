## Security Info:

EXE [VirusTotal](https://www.virustotal.com/gui/file/f60d3b75f512ed3c8fced1529b97d02bcb3dc1b23af3aad94329d3a9c3668c4e) & [Hybrid Analysis](https://www.hybrid-analysis.com/sample/f60d3b75f512ed3c8fced1529b97d02bcb3dc1b23af3aad94329d3a9c3668c4e) link.

Not sure you trust the EXE? You can run ``"Hellbomb Script.exe" -extract:$env:USERPROFILE"\Downloads\Hellbomb Script.ps1"`` in PowerShell to extract the script from the EXE to verify it's the same source code as what's shown here.

**Script Version VirusTotal Results:** https://www.virustotal.com/gui/file/5a252fee47835369a409a0993b05d808bbfabe9461f17896a410bf8809969400

The ``Hellbomb Script.ps1`` SHA265 hash should match the VirusTotal file hash of ``17f856931371e0d07aaa8c01e86a95db9846d3b67e508ec1f328ce31cb2ddf4e``.

**Script Version Hybrid-Analysis Link:** https://www.hybrid-analysis.com/sample/17f856931371e0d07aaa8c01e86a95db9846d3b67e508ec1f328ce31cb2ddf4e

You can compare the File Hash to the Virus Total link to ensure that the Virus Total results match the file you're attempting to run.

1. Download [the latest release](https://github.com/helldivers2fixes/HellbombScript/releases/latest) by clicking on Source Code.zip. Drill down into the folders and extract Hellbomb Script.ps1
2. In Terminal or PowerShell ``cd`` (Change to the directory) where the script is saved
3. If you downloaded the .ps1 file to your Downloads folder, run ``cd $((New-Object -ComObject Shell.Application).Namespace('shell:Downloads').Self.Path)``
4. Run ``Get-FileHash 'Hellbomb Script.ps1' -eq 17f856931371e0d07aaa8c01e86a95db9846d3b67e508ec1f328ce31cb2ddf4e``
5. The statement should return/evaluate to ``True``

No security software should detect the script as malicious.

## Why does it need Admin Privleges?
- Reads firewall rules
- Installs Microsoft Visual C++ redistributables
- Downloads and runs the zip file version of [CPU-Z](https://www.cpuid.com/softwares/cpu-z.html) from CPUID
