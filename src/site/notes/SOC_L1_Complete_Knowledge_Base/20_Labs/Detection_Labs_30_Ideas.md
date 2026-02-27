---
{"dg-publish":true,"permalink":"/soc-l1-complete-knowledge-base/20-labs/detection-labs-30-ideas/"}
---

# 30 Hands-On Detection Labs
#Labs #Practical #SOC #BlueTeam #Detection

---

## How to Use These Labs

Each lab below is a structured detection exercise. For each:
1. **Set up the environment** (use the Home Lab Setup note)
2. **Execute the attack** (Kali or Windows attacker VM)
3. **Find the evidence** in Splunk/ELK or log files
4. **Write/tune the detection rule**
5. **Document your findings** using the investigation template

**Skill levels:** 🟢 Beginner | 🟡 Intermediate | 🔴 Advanced

---

## CATEGORY 1 — Authentication & Account Attacks

### Lab 1 — SSH Brute Force on Linux 🟢
**Objective:** Detect a brute force attack against SSH from auth.log

**Setup:**
- VM: Ubuntu server + attacker Kali VM
- On Kali: `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://[ubuntu_ip]`

**What to find:**
- Which IP performed the attack?
- How many attempts were made?
- Did they succeed?
- What username was targeted most?

**Detection Commands:**
```bash
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
grep "Accepted" /var/log/auth.log
```

**Success Criteria:** Write a detection rule that fires after 10 failures from same IP in 5 minutes, with a suppression for scanner IPs.

---

### Lab 2 — Windows RDP Brute Force 🟢
**Objective:** Detect RDP brute force using Windows Event IDs

**Setup:**
- Windows Server VM with RDP enabled
- Attacker: `hydra -l administrator -P rockyou.txt rdp://[windows_ip]`

**What to find:**
- Event ID 4625 spike from single IP
- Was there a successful 4624 Type 10 event?
- Account lockout 4740?

**Splunk Query to Build:**
```spl
index=wineventlog EventCode=4625
| stats count by src_ip, TargetUserName
| where count > 15
```

**Success Criteria:** Alert fires within 1 minute of attack starting. FP rate < 5%.

---

### Lab 3 — Password Spraying Detection 🟡
**Objective:** Distinguish password spray from normal brute force

**Setup:**
- Windows AD environment
- Attacker script: Try "Password123" against 50 different accounts

**What to find:**
- Single password, many accounts (opposite of brute force)
- Under lockout threshold (3 failures per account)
- Slow enough to bypass threshold-based rules

**Key Insight:** A spray produces `dc(TargetUserName) >> count per account`.

**Splunk Query:**
```spl
index=wineventlog EventCode=4625
| bucket _time span=30m
| stats dc(TargetUserName) as unique_accounts, count as total by _time, src_ip
| where unique_accounts > 20 AND total < (unique_accounts * 3)
```

---

### Lab 4 — Kerberoasting Detection 🟡
**Objective:** Detect Kerberoasting from Windows DC Security log

**Setup:**
- Windows AD environment
- Attacker: Run Rubeus or GetUserSPNs.py from impacket

**What to find:**
- Event 4769 with TicketEncryptionType 0x17 (RC4)
- Many TGS requests from single host in short time
- Requesting tickets for service accounts with SPNs

**Splunk Query:**
```spl
index=wineventlog EventCode=4769 TicketEncryptionType=0x17
| stats count by Account_Name, ServiceName, Client_Address
| where count > 3
```

---

### Lab 5 — Pass-the-Hash Detection 🔴
**Objective:** Detect PTH attack via NTLM Type 3 anomalies

**Setup:**
- Windows AD domain
- Attacker: Use Mimikatz to dump hashes, then use Impacket's psexec.py for lateral movement

**What to find:**
- 4624 Type 3 with NTLM from unusual host
- 4624 Type 9 (NewCredentials / runas /netonly)
- Same user authenticating to multiple hosts rapidly

**Key Challenge:** NTLM Type 3 from workstations to other workstations is the giveaway.

---

## CATEGORY 2 — Execution & Malware

### Lab 6 — Malicious PowerShell Detection 🟢
**Objective:** Detect common PowerShell-based attacks

**Setup:**
- Windows workstation with Sysmon + PowerShell logging
- Run these commands to generate events:
```powershell
# Command 1: Encoded command
powershell.exe -enc JABhAD0AIgBoAHQAdABwAA==

# Command 2: Download cradle simulation
# (Don't execute - just type the command in PS)
# IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/test.ps1')
```

**What to find:**
- Event 4104 with script block content
- The base64 decoded content
- Parent process of PowerShell

**Decode the base64:**
```python
import base64
encoded = "JABhAD0AIgBoAHQAdABwAA=="
decoded = base64.b64decode(encoded).decode('utf-16-le')
print(decoded)
```

---

### Lab 7 — Office Macro Execution Chain 🟡
**Objective:** Detect phishing → macro → PowerShell chain

**Setup:**
- Create a Word document with a simple macro:
```vba
Sub AutoOpen()
    Shell "cmd.exe /c whoami > C:\Users\Public\output.txt"
End Sub
```
- Enable Sysmon, then open the document

**What to find:**
- Sysmon Event 1: winword.exe → cmd.exe (parent-child)
- Sysmon Event 11: File creation in Public folder
- Correlate the process tree

**Splunk Query:**
```spl
index=sysmon EventCode=1
| where ParentImage LIKE "%winword.exe%" AND Image LIKE "%cmd.exe%"
```

---

### Lab 8 — LOLBin Detection: certutil 🟢
**Objective:** Detect certutil being used for file download

**Setup:**
- Windows with Sysmon
- Run: `certutil.exe -urlcache -split -f http://localhost/test.txt C:\test.txt`

**What to find:**
- Sysmon Event 1: certutil.exe with -urlcache or -decode
- Sysmon Event 3: Network connection from certutil.exe
- File created in suspicious location

---

### Lab 9 — Scheduled Task Persistence 🟢
**Objective:** Detect persistence via scheduled task

**Setup:**
- Run: `schtasks /create /tn "WindowsUpdate" /tr "C:\Users\Public\backdoor.bat" /sc daily /st 02:00`

**What to find:**
- Event 4698: Task created
- Task content containing unusual binary path
- Who created it?

---

### Lab 10 — Registry Run Key Persistence 🟢
**Objective:** Detect registry-based persistence

**Setup:**
- Run: `reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "UpdateHelper" /t REG_SZ /d "C:\Users\Public\update.exe"`

**What to find:**
- Sysmon Event 13: Registry value set
- Target key is a Run key
- Value points to unusual path

---

## CATEGORY 3 — Credential Dumping

### Lab 11 — Mimikatz Detection (Sysmon Method) 🟡
**Objective:** Detect LSASS access by Mimikatz

**Setup:**
- Windows VM (Test environment ONLY)
- Download and run Mimikatz: `sekurlsa::logonpasswords`

**What to find:**
- Sysmon Event 10: TargetImage=lsass.exe with suspicious GrantedAccess
- Source process (Mimikatz.exe or renamed version)
- Access mask: 0x1010, 0x1410, 0x147a

**Important:** Rename mimikatz.exe to svchost_test.exe to simulate attacker renaming. Does your detection still fire?

---

### Lab 12 — Procdump + LSASS 🟡
**Objective:** Detect alternative LSASS dumping method

**Setup:**
- Run: `procdump.exe -ma lsass.exe C:\lsass.dmp`

**What to find:**
- Sysmon Event 10: procdump.exe accessing lsass.exe
- Sysmon Event 11: .dmp file created
- Command line of procdump

---

## CATEGORY 4 — Lateral Movement

### Lab 13 — PsExec Lateral Movement 🟡
**Objective:** Detect PsExec-based lateral movement

**Setup:**
- Two Windows VMs on same network
- Run: `psexec.exe \\[target_ip] -u admin -p password cmd.exe`

**What to find:**
- Event 5140: Admin$ share accessed
- Sysmon Event 3: Network connection from psexec
- Event 7045: PSEXESVC service installed on target
- Event 4624 Type 3 on target

---

### Lab 14 — WMI Remote Execution 🟡
**Objective:** Detect WMI-based lateral movement

**Setup:**
- Run: `wmic /node:[target_ip] /user:admin /password:pass process call create "cmd.exe /c whoami > C:\output.txt"`

**What to find:**
- Sysmon Event 1: wmiprvse.exe spawning cmd.exe
- Sysmon Event 3: WMI network connection
- Output file created

---

## CATEGORY 5 — Network Detection

### Lab 15 — C2 Beaconing Detection 🟡
**Objective:** Identify regular HTTP beaconing in proxy logs

**Setup:**
- Python script to simulate beaconing:
```python
import requests, time, random
while True:
    requests.get("http://192.168.1.200/beacon", timeout=5)
    time.sleep(60 + random.randint(-5, 5))  # 60s ± jitter
```

**What to find:**
- Regular interval HTTP connections in proxy logs
- Low byte variance per request
- Connection to same domain repeatedly

**Splunk Analysis:**
```spl
index=proxy
| stats count, stdev(bytes_out) as stdev by src_ip, dest_domain
| where count > 20 AND stdev < 100
```

---

### Lab 16 — DNS Tunneling Detection 🟡
**Objective:** Detect DNS tunneling using query length analysis

**Setup:**
- Install `iodine` DNS tunnel tool
- Set up DNS tunnel: `iodine -f -P password [dns_server_ip] tunnel.test.local`

**What to find:**
- DNS queries with very long subdomains
- High query volume to single domain
- Base32/Base64 encoded subdomains

---

### Lab 17 — Nmap Port Scan Detection 🟢
**Objective:** Detect Nmap scanning from IDS/Firewall logs

**Setup:**
- Run: `nmap -sS -T4 192.168.1.0/24` from attacker VM
- Capture firewall deny logs

**What to find:**
- Many different destination ports from single IP in short time
- SYN-only packets (no ACK follow-up = SYN scan)
- Pattern of RST responses from targets

---

### Lab 18 — DGA Domain Detection 🔴
**Objective:** Identify DGA-generated domains in DNS logs

**Concept:** DGA malware generates pseudo-random domains using a seed (often the date). Most will NXDOMAIN.

**Exercise:**
- Generate 100 fake DGA domains and add to DNS query log
- Write a detection based on high NXDOMAIN count from single host
- Calculate entropy of domain name (high entropy = random = DGA)

---

## CATEGORY 6 — Web Attacks

### Lab 19 — SQLi Detection in Web Logs 🟢
**Objective:** Find SQL injection attempts in Apache access log

**Setup:**
- Download sample malicious Apache log from SecLists or GitHub
- Import to Splunk/ELK

**What to find:**
- HTTP requests with SQL keywords in URL or POST body
- Which IPs performed the attacks?
- Did any return 200 (potentially successful)?

---

### Lab 20 — Web Shell Detection 🟡
**Objective:** Find a web shell in Apache logs and file system

**Setup:**
- Deploy DVWA (Damn Vulnerable Web Application)
- Upload a PHP web shell via file upload
- Access it via browser

**What to find:**
- POST request to upload endpoint
- Subsequent GET/POST to new PHP file
- Commands being executed via web shell (cmd= parameter)
- File system: New .php file in uploads directory

---

### Lab 21 — Directory Traversal Detection 🟢
**Objective:** Detect path traversal attempts in web logs

**Setup:**
- Deploy any vulnerable web app
- Run: `curl "http://localhost/view?page=../../../../etc/passwd"`

**What to find:**
- `../` patterns in web logs
- URL-encoded variants: `%2e%2e%2f`
- Successful traversal (200 response with /etc/passwd content)

---

## CATEGORY 7 — Forensics

### Lab 22 — Memory Forensics with Volatility 🟡
**Objective:** Analyze a memory dump to find malware

**Setup:**
- Download memory forensics challenges from: 
  - MemLabs (github.com/stuxnet999/MemLabs)
  - CyberDefenders Memory challenges
  - Volatility Foundation sample images

**Tasks:**
```bash
vol -f memory.raw windows.info        # Identify OS
vol -f memory.raw windows.pstree      # Find suspicious processes
vol -f memory.raw windows.cmdline     # Find encoded commands
vol -f memory.raw windows.netscan     # Find C2 connections
vol -f memory.raw windows.malfind     # Find injected code
vol -f memory.raw windows.hashdump    # Extract credentials
```

---

### Lab 23 — PCAP Analysis: Find the Malware 🟡
**Objective:** Analyze malicious PCAP to extract IOCs

**Setup:**
- Download malicious PCAPs from:
  - malware-traffic-analysis.net
  - Packettotal.com
  - Wireshark sample captures

**Tasks:**
1. Find all unique external IPs contacted
2. Identify the C2 IP and domain
3. Find any file downloads (export HTTP objects)
4. Identify the malware family from traffic patterns

---

### Lab 24 — Email Header Analysis 🟢
**Objective:** Analyze phishing email headers

**Setup:**
- Download sample phishing .eml files from PhishTank
- Or create your own test phishing email

**Tasks:**
1. Extract the true sender IP from Received headers
2. Check SPF, DKIM, DMARC results
3. Identify spoofed From address
4. Extract all URLs and defang them
5. Look up sending IP on AbuseIPDB

---

### Lab 25 — Prefetch Analysis 🟡
**Objective:** Use Windows Prefetch files to prove execution

**Setup:**
- Windows system with Prefetch enabled
- Run a suspicious binary (use a legit tool like PsExec)
- Analyze the resulting .pf file

**Tools:**
```
PECmd.exe -f "C:\Windows\Prefetch\PSEXEC.EXE-XXXXXXXX.pf"
```

**What to find:**
- Execution count
- Last run time
- Files accessed during execution
- Directories accessed

---

## CATEGORY 8 — SIEM Engineering

### Lab 26 — Build a Brute Force Detection Rule 🟢
**Objective:** Create a Splunk alert from scratch

**Steps:**
1. Ingest auth.log or Windows Security logs to Splunk
2. Write the base query detecting 10+ failures in 5 min
3. Add threshold alert
4. Test with real data
5. Tune to reduce FPs
6. Document exclusions

---

### Lab 27 — Write a Sigma Rule 🟡
**Objective:** Create a Sigma rule for Office→PowerShell execution

**Steps:**
1. Review the Sigma rule format
2. Write a rule detecting winword.exe → powershell.exe
3. Convert to Splunk SPL using sigma-cli
4. Test against your Sysmon data
5. Add to your detection library

---

### Lab 28 — Correlate Multiple Log Sources 🟡
**Objective:** Build a phishing kill chain correlation

**Scenario:** User received phishing email → clicked link → visited phishing site → downloaded malware → malware executed

**Steps:**
1. Import email logs, proxy logs, and Sysmon logs
2. Identify the common field (workstation IP or username)
3. Build a query that correlates all 3 sources
4. Alert when all 3 stages occur within 1 hour from same workstation

---

### Lab 29 — Alert Tuning Exercise 🟡
**Objective:** Reduce FP rate of an over-sensitive rule

**Setup:**
- Take a generic PowerShell detection rule (catches any PS execution)
- Ingest 1 week of real-looking PS logs (mix of benign and malicious)
- Measure baseline FP rate

**Task:**
1. Analyze what's causing FPs (SCCM, Intune, IT scripts)
2. Add exclusions one by one
3. Re-measure FP rate
4. Document each exclusion with justification
5. Target: < 10% FP rate

---

### Lab 30 — Full Incident Simulation 🔴
**Objective:** End-to-end detection of a multi-stage attack

**Scenario:** APT-style attack simulation
1. Phishing email delivered (set up fake email server)
2. User opens attachment, macro executes
3. PowerShell downloads Cobalt Strike beacon (use a safe test beacon)
4. Beacon establishes C2 (local test server)
5. Attacker runs net commands (discovery)
6. Attacker creates persistence (scheduled task)
7. Attacker dumps credentials (test with procdump on LSASS)
8. Attacker performs lateral movement (PsExec)

**Your job:** Detect every stage, correlate the full kill chain, write the incident report.

---

## Platform Recommendations for Labs

| Platform | URL | Cost | Best For |
|----------|-----|------|---------|
| TryHackMe | tryhackme.com | Free/Paid | Guided labs, beginner |
| HackTheBox | hackthebox.eu | Free/Paid | More challenging |
| CyberDefenders | cyberdefenders.org | Free | Blue team focused |
| BTLO (Blue Team Labs Online) | blueteamlabs.online | Free/Paid | SOC specific |
| PicoCTF | picoctf.org | Free | CTF skills |
| DetectionLab | github.com/clong/DetectionLab | Free | Full home lab |
| AttackIQ Academy | academy.attackiq.com | Free | MITRE ATT&CK |
| Splunk Boss of the SOC | splunk.com/BOTS | Free | Splunk-specific |

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/19_Career/Home_Lab_Setup_Guide\|Home_Lab_Setup_Guide]]
- [[SOC_L1_Complete_Knowledge_Base/18_CTF/CTF_Cheatsheets\|CTF_Cheatsheets]]
- [[SOC_L1_Complete_Knowledge_Base/19_Career/SOC_L1_to_L2_Roadmap\|SOC_L1_to_L2_Roadmap]]
- [[SOC_L1_Complete_Knowledge_Base/08_Detection_Engineering/Detection_Engineering\|Detection_Engineering]]
- [[SOC_L1_Complete_Knowledge_Base/07_MITRE/MITRE_ATT&CK_SOC_L1_Detection_Matrix\|MITRE_ATT&CK_SOC_L1_Detection_Matrix]]
