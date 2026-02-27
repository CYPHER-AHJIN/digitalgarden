---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/07-mitre/mitre-attack-overview/","dgPassFrontmatter":true}
---

# MITRE ATT&CK Overview
#MITRE #ThreatIntel #Frameworks #Detection

---

## What is MITRE ATT&CK?

MITRE ATT&CK® (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. It is THE standard framework for categorizing attacker behavior.

**Website:** https://attack.mitre.org

**Why it matters in real SOC:**
- Write detection rules mapped to techniques (not just IOCs)
- Communicate with team using standard language ("T1059.001 detected")
- Assess SOC coverage gaps
- Required knowledge for nearly every SOC interview

---

## ATT&CK Structure

```
Enterprise ATT&CK
├── Tactics (14 total) — The "WHY" — Attacker's goal
│   └── Techniques — The "HOW" — Method to achieve tactic
│       └── Sub-techniques — More specific variation
│           └── Procedure — Specific real-world implementation
```

---

## The 14 Enterprise Tactics

| # | Tactic | Description | Kill Chain Stage |
|---|--------|-------------|-----------------|
| TA0043 | Reconnaissance | Info gathering before attack | Recon |
| TA0042 | Resource Development | Build/acquire attack infrastructure | Weaponize |
| TA0001 | Initial Access | Gaining entry into network | Delivery/Exploit |
| TA0002 | Execution | Running malicious code | Exploit |
| TA0003 | Persistence | Maintain foothold | Install |
| TA0004 | Privilege Escalation | Gain higher permissions | Install/Actions |
| TA0005 | Defense Evasion | Avoid detection | All stages |
| TA0006 | Credential Access | Steal credentials | Actions |
| TA0007 | Discovery | Learn about environment | Actions |
| TA0008 | Lateral Movement | Move through network | Actions |
| TA0009 | Collection | Gather target data | Actions |
| TA0010 | Exfiltration | Steal data out of network | Actions |
| TA0011 | Command & Control | Communicate with attacker | C2 |
| TA0040 | Impact | Manipulate/destroy/interrupt | Actions |

---

## Critical Techniques for SOC L1

### TA0001 — Initial Access

**T1566 — Phishing**
- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link
- Detection: Email gateway logs, proxy blocks, endpoint execution

**T1078 — Valid Accounts**
- T1078.001 — Default Accounts
- T1078.002 — Domain Accounts
- T1078.003 — Local Accounts
- Detection: Failed logins, unusual time/location, credential stuffing patterns

**T1190 — Exploit Public-Facing Application**
- Detection: WAF alerts, error logs, unusual HTTP requests (SQLi, LFI, RCE patterns)

---

### TA0002 — Execution

**T1059 — Command and Scripting Interpreter**
- T1059.001 — PowerShell
- T1059.003 — Windows Command Shell
- T1059.005 — Visual Basic (VBScript/VBA)
- T1059.006 — Python
- Detection: Process creation events, script block logging, suspicious parent-child

**T1204 — User Execution**
- T1204.001 — Malicious Link
- T1204.002 — Malicious File
- Detection: Process created from Office apps, unusual child processes of email clients

**T1106 — Native API**
- Malware using Windows API calls directly
- Detection: EDR behavioral analysis

---

### TA0003 — Persistence

**T1053 — Scheduled Task/Job**
- T1053.005 — Scheduled Task (Windows)
- T1053.003 — Cron (Linux)
- Detection: Event ID 4698, schtasks audit, /etc/cron* monitoring

**T1547 — Boot or Logon Autostart Execution**
- T1547.001 — Registry Run Keys / Startup Folder
- Detection: Registry monitoring, Sysmon Event 13, startup folder changes

**T1543 — Create or Modify System Process**
- T1543.003 — Windows Service
- Detection: Event ID 7045, sc.exe in process logs, unusual service paths

**T1136 — Create Account**
- T1136.001 — Local Account
- T1136.002 — Domain Account
- Detection: Event ID 4720, net user commands

**T1505 — Server Software Component**
- T1505.003 — Web Shell
- Detection: New PHP/ASPX files in web root, unusual HTTP requests to scripts

---

### TA0004 — Privilege Escalation

**T1068 — Exploitation for Privilege Escalation**
- Exploiting kernel/service vulnerabilities
- Detection: Process integrity changes, exploit-like behavior in EDR

**T1134 — Access Token Manipulation**
- T1134.001 — Token Impersonation/Theft
- Detection: SeImpersonatePrivilege usage, unusual token handling

**T1548 — Abuse Elevation Control Mechanism**
- T1548.002 — Bypass User Account Control (UAC Bypass)
- Detection: eventvwr.exe, fodhelper.exe spawning unusual children, Sysmon

---

### TA0005 — Defense Evasion

**T1070 — Indicator Removal**
- T1070.001 — Clear Windows Event Logs (wevtutil cl)
- T1070.003 — Clear Command History
- T1070.004 — File Deletion
- Detection: Event ID 1102 (log cleared), HISTFILE=/dev/null

**T1027 — Obfuscated Files or Information**
- Base64 encoding, compression, encryption
- Detection: PowerShell script block logging, strings with encoded content

**T1218 — System Binary Proxy Execution (LOLBins)**
- T1218.005 — Mshta
- T1218.010 — Regsvr32
- T1218.011 — Rundll32
- Detection: Unusual command lines for these trusted binaries

**T1562 — Impair Defenses**
- T1562.001 — Disable or Modify Tools (kill AV)
- T1562.004 — Disable or Modify System Firewall
- Detection: AV service stop events, firewall modification events

---

### TA0006 — Credential Access

**T1003 — OS Credential Dumping**
- T1003.001 — LSASS Memory (Mimikatz)
- T1003.002 — Security Account Manager (SAM)
- T1003.003 — NTDS (Domain Controller)
- Detection: Sysmon Event 10 on lsass, procdump usage, Volume Shadow Copy access

**T1110 — Brute Force**
- T1110.001 — Password Guessing
- T1110.002 — Password Cracking
- T1110.003 — Password Spraying
- T1110.004 — Credential Stuffing
- Detection: Event ID 4625 thresholds, 4771 Kerberos failures, 4776 NTLM failures

**T1558 — Steal or Forge Kerberos Tickets**
- T1558.003 — Kerberoasting
- T1558.001 — Golden Ticket
- Detection: Event ID 4769 (TGS requests), 4768 anomalies, unusual service ticket requests

**T1555 — Credentials from Password Stores**
- Browser credentials, credential manager
- Detection: Browser process accessing credential files, registry access for stored creds

---

### TA0007 — Discovery

**T1082 — System Information Discovery**
- Detection: systeminfo, ver, hostname commands in process logs

**T1083 — File and Directory Discovery**
- Detection: dir /s /b, ls -la -R in unusual contexts

**T1087 — Account Discovery**
- T1087.001 — Local Account (net user)
- T1087.002 — Domain Account (net group /domain, ldap queries)
- Detection: net.exe commands, ldapsearch, BloodHound-like queries

**T1018 — Remote System Discovery**
- Detection: ping sweeps, nmap-like scanning from internal hosts

**T1046 — Network Service Discovery**
- Detection: Port scanning from internal hosts

---

### TA0008 — Lateral Movement

**T1021 — Remote Services**
- T1021.001 — Remote Desktop Protocol (RDP)
- T1021.002 — SMB/Windows Admin Shares
- T1021.004 — SSH
- T1021.006 — Windows Remote Management (WinRM)
- Detection: Event ID 4624 Type 10 (RDP), Type 3 from new hosts, wsman events

**T1550 — Use Alternate Authentication Material**
- T1550.002 — Pass the Hash
- T1550.003 — Pass the Ticket
- Detection: NTLM auth from hosts that shouldn't use it, Event 4624 analysis

**T1570 — Lateral Tool Transfer**
- Detection: Files copied via SMB shares, unusual file transfers, certutil downloads

---

### TA0011 — Command & Control

**T1071 — Application Layer Protocol**
- T1071.001 — Web Protocols (HTTP/HTTPS C2)
- T1071.004 — DNS (DNS tunneling)
- Detection: Proxy logs, DNS query volume anomalies, long DNS subdomain queries

**T1573 — Encrypted Channel**
- T1573.001 — Symmetric Cryptography
- T1573.002 — Asymmetric Cryptography
- Detection: JA3/JA3S fingerprinting, unusual SSL certs, cert transparency logs

**T1568 — Dynamic Resolution**
- T1568.002 — Domain Generation Algorithms (DGA)
- Detection: High-entropy domain names, NX domain responses, short TTLs

**T1572 — Protocol Tunneling**
- DNS tunneling, ICMP tunneling, SSH tunneling
- Detection: Unusually large DNS packets, ICMP with payload data

---

### TA0010 — Exfiltration

**T1041 — Exfiltration Over C2 Channel**
- Detection: Large uploads over established C2 connection

**T1048 — Exfiltration Over Alternative Protocol**
- T1048.001 — Exfiltration Over Symmetric Encrypted Non-C2 Protocol
- T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol (FTP, HTTP)
- Detection: Unusual protocol usage, large transfers on non-standard ports

**T1567 — Exfiltration Over Web Service**
- T1567.002 — Exfiltration Over Code Repository (GitHub)
- Detection: Large uploads to cloud services (Dropbox, Drive, Pastebin, GitHub)

---

### TA0040 — Impact

**T1486 — Data Encrypted for Impact (Ransomware)**
- Detection: Mass file rename/modification, shadow copy deletion, canary files triggered

**T1490 — Inhibit System Recovery**
- vssadmin delete shadows, wbadmin delete catalog
- Detection: Event 4688 with vssadmin/wmic/wbadmin process creation

**T1489 — Service Stop**
- Stopping backup/AV/database services
- Detection: Service control events, net stop commands

---

## SOC L1 MITRE ATT&CK Cheatsheet

| Scenario You See | MITRE Technique | Event IDs |
|-----------------|----------------|-----------|
| Multiple failed logins | T1110 - Brute Force | 4625, 4771, 4776 |
| PowerShell download cradle | T1059.001 + T1105 | 4104, Sysmon 3 |
| New admin account created | T1136.001 | 4720, 4732 |
| Scheduled task with PS | T1053.005 | 4698 |
| Run key modification | T1547.001 | Sysmon 13 |
| lsass access | T1003.001 | Sysmon 10 |
| Base64 encoded command | T1027 | 4104 |
| vssadmin delete | T1490 | 4688 |
| RDP login at 3 AM | T1021.001 | 4624 Type 10 |
| DNS to DGA domain | T1568.002 | DNS/Proxy |
| Word spawning cmd | T1566.001 + T1204.002 | Sysmon 1 |
| Kerberoasting | T1558.003 | 4769 |
| Pass the Hash | T1550.002 | 4624 Type 3 NTLM |
| File exfil via web | T1041/T1567 | Proxy |
| wmic /node: remote | T1047/T1021 | 4688 |
| Mimikatz strings | T1003.001 | Sysmon 1, 10 |

---

## Related Notes
- [[Cyber Kill Chain\|Cyber Kill Chain]]
- [[Pyramid of Pain\|Pyramid of Pain]]
- [[Detection Engineering\|Detection Engineering]]
- [[Windows Event Logs\|Windows Event Logs]]
- [[SIEM Overview\|SIEM Overview]]
- [[MITRE ATT&CK Matrix - SOC L1 Detections\|MITRE ATT&CK Matrix - SOC L1 Detections]]
