import sys
import re

import os
print("Files in current directory:", os.listdir(".."))

if len(sys.argv) != 5:
    print("Usage: python update_security_info.py <exe_hash> <exe_filename> <ps1_hash> <ps1_filename>")
    sys.exit(1)

exe_hash = sys.argv[1]
exe_filename = sys.argv[2]
ps1_hash = sys.argv[3]
ps1_filename = sys.argv[4]

vt_exe = f"https://www.virustotal.com/gui/file/{exe_hash}"
ha_exe = f"https://www.hybrid-analysis.com/sample/{exe_hash}"
vt_ps1 = f"https://www.virustotal.com/gui/file/{ps1_hash}"
ha_ps1 = f"https://www.hybrid-analysis.com/sample/{ps1_hash}"

with open("../../SECURITY.MD", "r", encoding="utf-8") as f:
    content = f.read()

# Replace all EXE filenames (dynamic version)
content = re.sub(r'"Hellbomb Script v[\w\.\-]+\.exe"', f'"{exe_filename}"', content)
content = re.sub(r"Hellbomb Script v[\w\.\-]+\.exe", exe_filename, content)

# Replace all PS1 filenames (dynamic version)
content = re.sub(r'"Hellbomb Script v[\w\.\-]+\.ps1"', f'"{ps1_filename}"', content)
content = re.sub(r"Hellbomb Script v[\w\.\-]+\.ps1", ps1_filename, content)

# Replace EXE VirusTotal and Hybrid Analysis links (first occurrence)
content = re.sub(r"https://www\.virustotal\.com/gui/file/[a-fA-F0-9]{64}", vt_exe, content, count=1)
content = re.sub(r"https://www\.hybrid-analysis\.com/sample/[a-fA-F0-9]{64}", ha_exe, content, count=1)

# Replace PS1 VirusTotal and Hybrid Analysis links (all other occurrences)
content = re.sub(r"https://www\.virustotal\.com/gui/file/[a-fA-F0-9]{64}", vt_ps1, content)
content = re.sub(r"https://www\.hybrid-analysis\.com/sample/[a-fA-F0-9]{64}", ha_ps1, content)

# Replace all PS1 SHA256 hashes (64 hex digits) in code blocks and markdown
content = re.sub(r"``[a-fA-F0-9]{64}``", f"``{ps1_hash}``", content)
content = re.sub(r"(?<=-eq )[a-fA-F0-9]{64}", ps1_hash, content)

with open("SECURITY.md", "w", encoding="utf-8") as f:
    f.write(content)

print("SECURITY.md updated with dynamic filenames and hashes.")
