import sys
import re

exe_hash = sys.argv[1]
exe_filename = sys.argv[2]
ps1_hash = sys.argv[3]
ps1_filename = sys.argv[4]

vt_exe = f"https://www.virustotal.com/gui/file/{exe_hash}"
ha_exe = f"https://www.hybrid-analysis.com/sample/{exe_hash}"
vt_ps1 = f"https://www.virustotal.com/gui/file/{ps1_hash}"
ha_ps1 = f"https://www.hybrid-analysis.com/sample/{ps1_hash}"

markdown_file = "SECURITY.MD"

with open(markdown_file, "r", encoding="utf-8") as f:
    content = f.read()

content = re.sub(r'"Hellbomb Script v[\w.\-]+\.exe"', f'"{exe_filename}"', content, flags=re.IGNORECASE)
content = re.sub(r"Hellbomb Script v[\w.\-]+\.exe", exe_filename, content, flags=re.IGNORECASE)
content = re.sub(r'"Hellbomb Script v[\w.\-]+\.ps1"', f'"{ps1_filename}"', content, flags=re.IGNORECASE)
content = re.sub(r"Hellbomb Script v[\w.\-]+\.ps1", ps1_filename, content, flags=re.IGNORECASE)

content = re.sub(
    r'(\[VirusTotal\]\()[\S]+',
    rf'\1{vt_exe})',
    content,
    count=1
)

content = re.sub(
    r'(\[Hybrid Analysis\]\()[\S]+',
    rf'\1{ha_exe})',
    content,
    count=1
)

content = re.sub(
    r'(\*\*Script\s+Version\*\*.*?\[VirusTotal\s+Results\]\()[\S]+',
    rf'\1{vt_ps1})',
    content
)

content = re.sub(
    r'(\*\*Script\s+Version\*\*.*?\[Hybrid\-Analysis\s+Link\]\()[\S]+',
    rf'\1{ha_ps1})',
    content
)

content = re.sub(r"``[a-fA-F0-9]{64}``", f"``{ps1_hash}``", content)
content = re.sub(r"(?<=-eq )[a-fA-F0-9]{64}", ps1_hash, content)

with open(markdown_file, "w", encoding="utf-8") as f:
    f.write(content)

print(f"Successfully updated {markdown_file} with new hashes, links, and filenames.")
