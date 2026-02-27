---
{"dg-publish":true,"permalink":"/soc-l1-complete-knowledge-base/10-forensics/forensics-basics/"}
---

# Forensics Basics
#Forensics #DFIR #Memory #Volatility #Autopsy

---

## What is Digital Forensics?

Digital Forensics is the process of identifying, preserving, analyzing, and presenting digital evidence in a manner that is legally acceptable. In a SOC context, forensics is what you do AFTER containment to understand what happened, what was accessed, and how the attacker operated.

**Why it matters in real SOC:** You need forensics to answer: How did they get in? What did they access? Did they exfiltrate data? What's the full scope?

---

## Order of Volatility (Collect Most Volatile First)

```
1. CPU registers, cache (nanoseconds to live)
2. RAM / Memory (lost on shutdown)
3. Network connections (active sessions, ARP cache)
4. Running processes (gone on reboot)
5. File system (temp files, recently accessed)
6. Logs (can be overwritten)
7. Hard disk (persistent)
8. Backups, archives (most permanent)
```

**Critical rule:** Always collect RAM BEFORE imaging disk, and BEFORE rebooting or isolating.

---

## Evidence Handling Rules

```
1. NEVER modify original evidence — always work on copies
2. Hash everything BEFORE and AFTER collection (SHA-256)
3. Maintain chain of custody — document who handled evidence and when
4. Use write blockers for disk acquisition
5. Document every action with timestamp
6. Photograph physical environment if physical investigation
7. Store evidence in clean containers/anti-static bags
8. Maintain integrity — every command you run changes something
```

### Chain of Custody Template
```
Evidence Item: [Description]
Case Number: INC-YYYY-MMDD-NNN
Collected By: [Name]
Collection Date/Time: [UTC timestamp]
Collection Method: [Tool + version]
Hash (SHA-256): [Before collection hash]
Storage Location: [Where it's stored]

Transfer History:
Date | From | To | Reason | Signature
```

---

## Memory Forensics

### Why Memory Matters
- Running processes, network connections, credentials, encryption keys
- Malware running entirely in memory (fileless) only visible here
- Decrypted content of encrypted files visible in RAM
- Attacker tools and commands visible even if logs were cleared

### Memory Acquisition

**Windows:**
```powershell
# DumpIt (best for live acquisition)
.\DumpIt.exe /O memory.raw

# WinPmem (open source)
winpmem_x64.exe memory.raw

# Magnet RAM Capture (GUI, free)
# Download: magnetforensics.com

# FTK Imager (free, all-in-one)
# File → Capture Memory → Select output path
```

**Linux:**
```bash
# LiME (Linux Memory Extractor) — most reliable
sudo insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime"

# dd (basic, may miss some memory regions)
sudo dd if=/dev/mem of=/tmp/memory.raw bs=1M

# /proc/kcore
sudo dd if=/proc/kcore of=/tmp/memory.raw
```

---

## Volatility 3 (Memory Analysis Framework)

**Install:**
```bash
pip install volatility3
# Or: git clone https://github.com/volatilityfoundation/volatility3
```

### Essential Volatility Commands

```bash
# Always start with: identify the image profile
vol -f memory.raw windows.info

# === PROCESS ANALYSIS ===

# List running processes (like tasklist)
vol -f memory.raw windows.pslist

# Process tree (parent-child relationships)
vol -f memory.raw windows.pstree

# Include hidden/unlinked processes (rootkit detection)
vol -f memory.raw windows.psscan

# Compare pslist vs psscan (discrepancy = rootkit)
# If process appears in psscan but NOT pslist → ROOTKIT HIDING IT

# Process executable and DLLs
vol -f memory.raw windows.dlllist --pid 1234

# Command line used to start process
vol -f memory.raw windows.cmdline

# Process environment variables
vol -f memory.raw windows.envars --pid 1234

# === NETWORK ANALYSIS ===

# Active network connections (like netstat)
vol -f memory.raw windows.netstat

# All network connections including closed ones
vol -f memory.raw windows.netscan

# === FILE AND ARTIFACT ANALYSIS ===

# List files cached in memory
vol -f memory.raw windows.filescan

# Dump specific file from memory
vol -f memory.raw windows.dumpfiles --virtaddr 0xXXXXX

# Dump all files matching pattern
vol -f memory.raw windows.dumpfiles --filter "\.exe$"

# Registry hives in memory
vol -f memory.raw windows.registry.hivelist

# Registry key contents
vol -f memory.raw windows.registry.printkey --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# === INJECTION DETECTION ===

# Find injected code (empty VAD regions with executable code)
vol -f memory.raw windows.malfind

# Dump injected regions for analysis
vol -f memory.raw windows.malfind --dump

# === CREDENTIALS ===

# Dump LSASS credentials (hashes, some plaintext if WDigest enabled)
vol -f memory.raw windows.hashdump

# Cached domain credentials
vol -f memory.raw windows.cachedump

# LSA secrets
vol -f memory.raw windows.lsadump

# === ARTIFACTS ===

# Clipboard contents
vol -f memory.raw windows.clipboard

# Browser history from memory
vol -f memory.raw windows.iehistory

# Handles (open files, keys, objects per process)
vol -f memory.raw windows.handles --pid 1234

# === LINUX MEMORY ===
vol -f linux_memory.raw linux.pslist
vol -f linux_memory.raw linux.netstat
vol -f linux_memory.raw linux.bash  # Bash command history from memory
```

### Volatility Typical Investigation Flow
```bash
# 1. Identify image
vol -f memory.raw windows.info

# 2. Look for suspicious processes
vol -f memory.raw windows.psscan > psscan.txt
vol -f memory.raw windows.pslist > pslist.txt
# Compare: any in psscan NOT in pslist?

# 3. Check process trees
vol -f memory.raw windows.pstree
# Look for: unusual parent-child (svchost.exe parent = not services.exe = suspicious)

# 4. Check command lines
vol -f memory.raw windows.cmdline
# Look for: encoded PowerShell, unusual paths, suspicious arguments

# 5. Check network connections
vol -f memory.raw windows.netscan
# Look for: connections to unusual IPs, listening on unexpected ports

# 6. Scan for injection
vol -f memory.raw windows.malfind
# Look for: executable code in unexpected memory regions

# 7. Dump suspicious processes
vol -f memory.raw windows.procdump --pid 1234
# Then: submit to VirusTotal, run strings, YARA scan

# 8. Check for rootkits
# Compare psscan vs pslist — gaps indicate hidden processes
```

---

## Disk Forensics

### Disk Imaging
```bash
# dd (Linux) — bit-for-bit copy
sudo dd if=/dev/sda of=/mnt/evidence/disk.img bs=64K conv=sync,noerror

# dcfldd — enhanced dd with hashing
sudo dcfldd if=/dev/sda of=/mnt/evidence/disk.img bs=64K hash=sha256 hashlog=disk.sha256

# FTK Imager (Windows GUI — free)
# Best practice: Use hardware write blocker + FTK Imager

# Verify integrity
sha256sum disk.img > disk.img.sha256
```

### Autopsy (Free Forensic Platform)

Autopsy is the open-source digital forensics GUI built on The Sleuth Kit.

**Key modules:**
- Timeline Analysis — Events graphed over time
- File Metadata — Creation, modification, access times
- Keyword Search — Search for terms across disk
- Hash Lookup — Match files against known-bad hash sets
- Email Analysis — Parse email files (PST, MBOX)
- Web Artifacts — Browser history, downloads, cache
- Recent Documents — MRU lists, recent files
- Registry Viewer — Parse Windows registry

```
Workflow:
1. Create new case → Enter case details
2. Add data source → Select disk image (.E01, .img, .raw)
3. Configure ingest modules → Select what to analyze
4. Let it process (can take hours for large disks)
5. Analyze results in left panel:
   - Data Sources → navigate files
   - Analysis Results → what modules found
   - Timeline → chronological view
```

### KAPE (Kroll Artifact Parser and Extractor)

KAPE is a triage tool that collects and processes forensic artifacts FAST. Used when you need quick answers without full disk imaging.

```bash
# Collect artifacts to output folder
kape.exe --tsource C: --tdest C:\Output --target !SANS_Triage

# Common targets:
!SANS_Triage         → Comprehensive SOC triage collection
RegistryHives        → Registry files
EventLogs            → Windows Event Logs
PowerShellHistory    → PS command history
BrowserHistory       → All browser artifacts
LNKFilesAndJumpLists → Recent files and LNK shortcuts
Prefetch             → Program execution artifacts
$MFT                 → Master File Table

# Process collected artifacts
kape.exe --msource C:\Output --mdest C:\Processed --module !EZParser
```

---

## Windows Forensic Artifacts

### Prefetch Files
Windows stores data about program execution to speed up loading.
```
Location: C:\Windows\Prefetch\
Format: PROGRAMNAME-XXXXXXXX.pf
Contains: Execution count, last run time, files accessed

# Analysis tool:
WinPrefetchView (NirSoft - free)
PECmd.exe (Eric Zimmermann tools)
PECmd.exe -f "C:\Windows\Prefetch\CMD.EXE-089F1A9B.pf"
```

### Registry Forensic Keys
```
# Last logged on user
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon → LastUsedUsername

# User recent activity
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist (executed programs)

# USB devices connected
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
HKLM\SYSTEM\CurrentControlSet\Enum\USB

# Network connections history
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles

# Run at startup
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Timezone (important for timeline reconstruction)
HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation
```

### Windows Event Log Forensic Events
```
4624 - Successful logon
4625 - Failed logon
4688 - Process created
4720 - User created
4732 - User added to group
4663 - File accessed
1102 - Audit log cleared (ATTACKER!)
104  - System log cleared (ATTACKER!)
4698 - Scheduled task created
7045 - Service installed
```

### LNK Files and Jump Lists
```
# Recent file LNK files:
C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\

# Jump Lists (recently opened files per application):
C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\

# Analysis: LECmd.exe, JLECmd.exe (Eric Zimmermann tools)
LECmd.exe -f suspicious.lnk
# Reveals: original file path, machine name, MAC address, timestamps
```

---

## File Analysis Tools

### strings — Extract Human-Readable Text
```bash
# Basic extraction
strings suspicious.exe

# Minimum length 8 characters
strings -n 8 suspicious.exe

# With file offset
strings -t x suspicious.exe  # Hex offsets
strings -t d suspicious.exe  # Decimal offsets

# Unicode strings
strings -e l suspicious.exe  # Little-endian 16-bit (Windows wide strings)

# Extract and search
strings suspicious.exe | grep -iE "http|ftp|cmd|powershell|password"
strings suspicious.exe | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}"  # IPs
```

### exiftool — Metadata Extraction
```bash
# Install
sudo apt install exiftool

# Extract metadata from any file
exiftool suspicious.doc
exiftool suspicious.pdf
exiftool suspicious.jpg

# Useful outputs:
# Author name (who created the document?)
# Creation software
# GPS coordinates (photos)
# Last modified by
# Company name

# Extract from all files in directory
exiftool /forensics/evidence/

# Specific fields
exiftool -Author -CreateDate suspicious.doc

# Remove metadata (for privacy)
exiftool -all= suspicious.jpg
```

### binwalk — Firmware/File Analysis
```bash
# Install
sudo apt install binwalk

# Scan for embedded files
binwalk suspicious.bin

# Extract embedded files
binwalk -e suspicious.bin
binwalk --extract suspicious.bin

# Analyze firmware image
binwalk firmware.bin

# Entropy analysis (high entropy = compressed/encrypted content)
binwalk -E suspicious.exe

# Output:
# DECIMAL    HEXADECIMAL    DESCRIPTION
# 0          0x0            ELF, 64-bit LSB executable
# 1234       0x4D2          Zip archive
```

### foremost — File Carving
```bash
# Install
sudo apt install foremost

# Carve files from disk image/raw data
foremost -i disk.img -o /output/carved/

# Carve specific file types
foremost -t jpg,png,pdf,doc -i disk.img -o /output/

# Carve from memory dump
foremost -i memory.raw -o /output/memory_carved/

# Output: Creates folders per file type with recovered files
```

### HashCalc / Hash Verification
```bash
# Calculate hashes (Linux)
sha256sum suspicious.exe
md5sum suspicious.exe
sha1sum suspicious.exe

# Calculate hashes (Windows PowerShell)
Get-FileHash suspicious.exe -Algorithm SHA256
Get-FileHash suspicious.exe -Algorithm MD5

# Compare hash to known value
echo "a1b2c3... suspicious.exe" | sha256sum -c

# Hash entire directory
find /evidence/ -type f -exec sha256sum {} \; > evidence_hashes.txt
```

---

## Network Forensics

### PCAP Analysis with Wireshark/Tshark
```bash
# Extract files from HTTP traffic
tshark -r capture.pcap --export-objects http,/output/

# Extract credentials from HTTP
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data

# Find DNS queries
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e frame.time -e ip.src -e dns.qry.name

# Find large transfers
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e frame.len | awk '{sum[$1,$2]+=$3} END {for(k in sum) print sum[k], k}' | sort -rn

# Follow specific TCP stream
tshark -r capture.pcap -z "follow,tcp,ascii,0" -q
```

---

## Timeline Analysis

Building a timeline is the core skill in DFIR — correlating events across multiple sources.

```
Sources to correlate:
- Windows Event Logs (Security, System, PowerShell)
- Sysmon logs
- Prefetch files (execution times)
- Registry last-write times
- File system timestamps (Created, Modified, Accessed, MFT Entry)
- Browser history timestamps
- Email timestamps
- Network log timestamps
- EDR telemetry

Tools:
- log2timeline + plaso (Python): Ingest multiple sources → timeline.csv
- Autopsy Timeline Analysis module
- KAPE + EZParser
- Splunk (correlate across log sources by time)
```

---

## MITRE ATT&CK Forensic Relevance

| Artifact | MITRE Technique | What to Look For |
|----------|-----------------|------------------|
| Prefetch | T1059 | Execution of suspicious binaries |
| Registry Run keys | T1547.001 | Persistence entries |
| LNK files | T1204 | User executed malicious file |
| Event 4688/Sysmon 1 | T1059 | Command execution |
| Memory (malfind) | T1055 | Process injection |
| LSASS access (Sysmon 10) | T1003.001 | Credential dumping |
| Scheduled tasks | T1053.005 | Persistence |
| VSS/Shadow copies | T1490 | Ransomware indicator |

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/11_Malware/Malware_Basics\|Malware_Basics]]
- [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/Incident_Response_Lifecycle\|Incident_Response_Lifecycle]]
- [[SOC_L1_Complete_Knowledge_Base/03_Windows/Windows_Event_Logs\|Windows_Event_Logs]]
- [[SOC_L1_Complete_Knowledge_Base/04_Linux/Linux_Logs_and_Commands\|Linux_Logs_and_Commands]]
- [[SOC_L1_Complete_Knowledge_Base/07_MITRE/MITRE_ATTACK_Overview\|MITRE_ATTACK_Overview]]
