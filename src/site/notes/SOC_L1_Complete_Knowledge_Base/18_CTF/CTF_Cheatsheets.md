---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/18-ctf/ctf-cheatsheets/","dgPassFrontmatter":true}
---

# CTF Blue Team Cheatsheets
#CTF #BlueTeam #Forensics #Challenges

---

## 20 Blue Team CTF Practice Challenges

### Challenge 1: PCAP Analysis — Find the C2
**Scenario:** You're given a PCAP file. A host was infected. Find the C2 IP and what data was exfiltrated.

**Approach:**
```bash
# Open in Wireshark, apply filter:
http or dns or tcp

# Find unusual long duration connections
Statistics → Conversations → TCP (sort by bytes)

# Look for beaconing pattern:
Statistics → IO Graphs → Add a line for specific IP

# Extract HTTP objects (potential files exfiltrated):
File → Export Objects → HTTP

# Find DNS tunneling:
Display filter: dns.qry.name and string length
dns.qry.name.len > 40

# Answer format: C2_IP, domain, exfiltrated file
```

**Key skills:** Wireshark filters, network artifact identification, beaconing detection

---

### Challenge 2: Memory Forensics — Find the Malware
**Scenario:** You're given a memory dump (`.raw` or `.mem`). Find what malware is running and extract IOCs.

**Approach:**
```bash
# Identify OS
vol -f memory.raw windows.info

# Find suspicious processes
vol -f memory.raw windows.pstree
# Look for: unusual parent, processes in AppData/Temp

# Find injected code
vol -f memory.raw windows.malfind
# Look for executable code in unexpected regions

# Extract process for hash check
vol -f memory.raw windows.procdump --pid [suspicious_pid]
sha256sum pid.XXXX.0x400000.exe

# Find C2 connections
vol -f memory.raw windows.netscan
# Look for ESTABLISHED connections to external IPs

# Check command lines
vol -f memory.raw windows.cmdline
```

**Key skills:** Volatility, process analysis, memory artifacts

---

### Challenge 3: Log Analysis — Find the Brute Force
**Scenario:** You have auth.log from a Linux server. Find the attacker IP, what they were trying, and if they succeeded.

**Approach:**
```bash
# Count failed SSH by IP
grep "Failed password" auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# Find the brute force IP (highest count)

# Check if they succeeded
grep "Accepted" auth.log | grep [attacker_ip]

# What username did they succeed with?
grep "Accepted password" auth.log

# What did they do after login?
grep -A5 "Accepted password" auth.log
```

**Key skills:** grep, awk, Linux log analysis

---

### Challenge 4: Windows Event Log Analysis
**Scenario:** You have Security.evtx. Find unauthorized account creation and privilege escalation.

**Approach:**
```powershell
# Load the log
Get-WinEvent -Path Security.evtx | Where-Object {$_.Id -in @(4720, 4732, 4728)}

# Account creation
Get-WinEvent -Path Security.evtx | Where-Object {$_.Id -eq 4720} | Select-Object TimeCreated, Message

# Group membership change
Get-WinEvent -Path Security.evtx | Where-Object {$_.Id -eq 4732} | Select-Object TimeCreated, Message

# Correlate: who created the account? What groups were they added to?
```

**Key skills:** PowerShell log analysis, Windows Event ID knowledge

---

### Challenge 5: Email Phishing Analysis
**Scenario:** You're given a .eml file. Determine if it's phishing and extract all IOCs.

**Approach:**
```bash
# View raw email headers
cat suspicious.eml | head -100

# Check authentication results
grep -i "Authentication-Results\|spf\|dkim\|dmarc" suspicious.eml

# Extract URLs from email body
grep -oP 'https?://[^\s"<>]+' suspicious.eml | sort -u

# Extract attachment
cat suspicious.eml | grep "Content-Disposition: attachment"
# Use munpack or email library to extract

# Hash the attachment
sha256sum attachment.doc

# Check the originating IP
grep -i "X-Originating-IP\|Received:" suspicious.eml
```

**Key skills:** Email header analysis, SPF/DKIM/DMARC, IOC extraction

---

### Challenge 6: Steganography + Forensics
**Scenario:** An image file was used as exfiltration vehicle. Find the hidden data.

**Approach:**
```bash
# Check metadata
exiftool suspicious.jpg

# Check for hidden files embedded
binwalk suspicious.jpg
binwalk -e suspicious.jpg  # Extract

# Look for steganography
steghide extract -sf suspicious.jpg
zsteg suspicious.png       # For PNG
strings suspicious.jpg | grep -v "^\."  # Quick string check

# Check file magic bytes (is it really a JPG?)
file suspicious.jpg
xxd suspicious.jpg | head -20  # Check hex header
```

**Key skills:** exiftool, binwalk, steghide, file format analysis

---

### Challenge 7: Malware Static Analysis
**Scenario:** You have a suspicious binary. Determine what it does without executing it.

**Approach:**
```bash
# File type
file malware.exe

# Hash check
sha256sum malware.exe
# Submit to VirusTotal

# Extract strings
strings -n 8 malware.exe | tee strings.txt

# Look for IOCs in strings
grep -iE "http|ftp|\.com|\.net|\.ru|\.cn" strings.txt
grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" strings.txt  # IPs
grep -iE "registry|HKEY|cmd|powershell|exec" strings.txt

# Detect if packed
# High entropy in strings output = packed/encrypted

# PE analysis (if Windows binary)
rabin2 -i malware.exe  # Imports
rabin2 -E malware.exe  # Exports
```

**Key skills:** strings, file analysis, static PE analysis

---

### Challenge 8: Ransomware Investigation
**Scenario:** Windows event logs from a ransomware incident. Find patient zero, infection time, and persistence.

**Approach:**
```powershell
# Find shadow copy deletion (key ransomware indicator)
Get-WinEvent -Path Security.evtx | Where-Object {$_.Id -eq 4688} | 
  Where-Object {$_.Message -match "vssadmin|wbadmin|bcdedit"}

# Find process that started the ransomware
Get-WinEvent -Path Security.evtx | Where-Object {$_.Id -eq 4688} |
  Where-Object {$_.Message -match "\.exe"} | 
  Sort-Object TimeCreated | Select-Object -First 50

# Look for mass file creation (Sysmon Event 11)
# Look for scheduled task creation (4698) for persistence
```

---

### Challenge 9: Network Forensics — Identify Lateral Movement
**Scenario:** PCAP or firewall logs. Identify which internal host was used to laterally move to another host.

**Approach:**
```bash
# Filter SMB traffic
tshark -r network.pcap -Y "smb or smb2" -T fields -e ip.src -e ip.dst -e smb2.filename

# Filter RDP
tshark -r network.pcap -Y "tcp.dstport==3389" -T fields -e ip.src -e ip.dst

# Splunk: Authentication from workstation to workstation
index=wineventlog EventCode=4624 Logon_Type=3
| where NOT match(Computer,"DC*") AND NOT match(src_ip,"10.0.0.1")  # Not from DC
| stats dc(Computer) by src_ip, User
| where dc(Computer) > 2
```

---

### Challenge 10: Web Attack Log Analysis
**Scenario:** Apache access.log provided. Find SQL injection attempts, successful attacks, and web shell.

**Approach:**
```bash
# Find SQLi attempts
grep -E "UNION|SELECT|DROP|OR\+1|%27|%3D" access.log

# Find 200 responses to suspicious requests (success indicators)
grep "200" access.log | grep -iE "union|select|system\(|eval\(|base64"

# Find web shell access pattern (POST to unusual PHP)
grep "POST.*\.php" access.log | grep -v "login\|contact\|checkout"

# Find directory traversal
grep -E "\.\.\/|%2e%2e%2f" access.log

# Top attacking IPs
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head 20

# Find 4xx/5xx storm (scanning indicator)
awk '$9 ~ /[4-5][0-9][0-9]/ {print $1}' access.log | sort | uniq -c | sort -rn
```

---

## CTF Quick Reference Commands

### File Investigation
```bash
file unknown_file           # Identify file type by magic bytes
xxd unknown_file | head     # Hex dump first bytes
strings -n 8 file.exe       # Extract printable strings
sha256sum file              # Calculate hash
exiftool file               # Metadata extraction
binwalk -e file             # Extract embedded files
foremost -i file -o output/ # File carving
```

### Network Analysis (Wireshark/tshark)
```bash
# Extract all HTTP requests
tshark -r file.pcap -Y "http.request" -T fields -e frame.time -e ip.src -e http.host -e http.request.uri

# Extract DNS queries
tshark -r file.pcap -Y "dns.qry.name" -T fields -e ip.src -e dns.qry.name

# Export HTTP objects (files in HTTP traffic)
tshark -r file.pcap --export-objects http,./output/

# Follow TCP stream number 0
tshark -r file.pcap -z "follow,tcp,ascii,0" -q

# Find credentials in cleartext
tshark -r file.pcap -Y "http.request.method==POST" -T fields -e http.file_data
```

### Hash Cracking (CTF)
```bash
# Identify hash type
hashid 'hash_value_here'
hash-identifier 'hash_value_here'

# Crack MD5
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
john --format=raw-md5 --wordlist=rockyou.txt hash.txt

# Crack NTLM
hashcat -m 1000 -a 0 ntlm_hash.txt rockyou.txt
john --format=NT --wordlist=rockyou.txt ntlm.txt

# Base64 decode
echo "base64string==" | base64 -d
```

### Encoding/Decoding (Common in CTF)
```bash
# Base64
echo "SGVsbG8=" | base64 -d
echo "Hello" | base64

# URL decode
python3 -c "import urllib.parse; print(urllib.parse.unquote('%48%65%6C%6C%6F'))"

# ROT13
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Hex decode
echo "48656c6c6f" | xxd -r -p
python3 -c "print(bytes.fromhex('48656c6c6f').decode())"

# XOR decode (requires key)
python3 -c "ct=bytes.fromhex('hex_data'); key=0x42; print(''.join(chr(b^key) for b in ct))"
```

### Memory Forensics (CTF)
```bash
vol -f mem.raw windows.info              # Profile identification
vol -f mem.raw windows.pslist            # Process list
vol -f mem.raw windows.pstree           # Process tree
vol -f mem.raw windows.cmdline          # Command lines
vol -f mem.raw windows.netscan          # Network connections
vol -f mem.raw windows.malfind          # Injected code
vol -f mem.raw windows.filescan         # Files in memory
vol -f mem.raw windows.dumpfiles --virtaddr 0xXXX  # Dump file
vol -f mem.raw windows.hashdump         # Password hashes
vol -f mem.raw windows.registry.printkey --key "Run"  # Registry
```

---

## CTF Mindset Tips

```
1. Always run 'file' on unknown files — don't trust extensions
2. Check file headers (magic bytes): PNG=89504E47, ZIP=504B0304, PDF=25504446
3. Try strings on EVERYTHING — flags often hide in plain sight
4. Check metadata (exiftool) on images and documents
5. If PCAP: check ALL protocols, not just HTTP
6. Follow the timeline — events in chronological order tell the story
7. Google the Event ID you don't know — knowledge check
8. Read the challenge description twice — hints are often embedded
9. Document your steps — in CTF and real SOC
10. If stuck: try different decoding (base64, hex, ROT13, XOR)
```

---

## Magic Bytes Reference (File Type by Header)

| File Type | Magic Bytes (Hex) | ASCII |
|-----------|------------------|-------|
| PNG | 89 50 4E 47 0D 0A 1A 0A | .PNG... |
| JPEG | FF D8 FF | ... |
| GIF | 47 49 46 38 | GIF8 |
| PDF | 25 50 44 46 | %PDF |
| ZIP | 50 4B 03 04 | PK.. |
| RAR | 52 61 72 21 | Rar! |
| ELF | 7F 45 4C 46 | .ELF |
| PE (EXE) | 4D 5A | MZ |
| DOCX/XLSX | 50 4B 03 04 | PK (it's a ZIP) |
| 7z | 37 7A BC AF 27 1C | 7z... |

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/10_Forensics/Forensics_Basics\|Forensics_Basics]]
- [[SOC_L1_Complete_Knowledge_Base/02_Networking/Networking_Fundamentals\|Networking_Fundamentals]]
- [[SOC_L1_Complete_Knowledge_Base/13_Brute_Force/Brute_Force_Password_Attacks\|Brute_Force_Password_Attacks]]
- [[Web_Attacks_Basics\|Web_Attacks_Basics]]
- [[SOC_L1_Complete_Knowledge_Base/11_Malware/Malware_Basics\|Malware_Basics]]
