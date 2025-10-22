
import sys
import re

# Usage: python update_security_info.py <exe_hash> <ps1_hash> <exe_filename> <ps1_filename>
exe_hash = sys.argv[1]
ps1_hash = sys.argv[2]
exe_filename = sys.argv[3]
ps1_filename = sys.argv[4]

vt_exe = f"https://www.virustotal.com/gui/file/{exe_hash}"
ha_exe = f"https://www.hybrid-analysis.com/sample/{exe_hash}"
vt_ps1 = f"https://www.virustotal.com/gui/file/{ps1_hash}"
ha_ps1 = f"https://www.hybrid-analysis.com/sample/{ps1_hash}"

new_section = f"""## Security Info:

EXE VirusTotal & Hybrid Analysis link.

Not sure you trust the EXE? You can run
```powershell
"{exe_filename}" -extract:$env:USERPROFILE"\\Downloads\\{ps1_filename}"
