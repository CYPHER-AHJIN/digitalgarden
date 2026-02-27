---
{"dg-publish":true,"permalink":"/soc-l1-complete-knowledge-base/01-soc-foundations/cyber-kill-chain/"}
---

# Cyber Kill Chain
#SOC #Frameworks #CyberKillChain #MITRE

---

## Overview

Developed by Lockheed Martin in 2011, the Cyber Kill Chain describes the seven stages of a targeted cyberattack. Understanding this model helps SOC analysts understand WHERE in an attack they've detected activity, and what comes NEXT if not contained.

**Why it matters in real SOC:** Knowing the kill chain stage of an alert tells you urgency. Stage 6 (C2) means the attacker already has a foothold. Stage 2 (Weaponization) means you caught them before they even arrived.

---

## The Seven Stages

### Stage 1: Reconnaissance
**What:** Attacker gathers information about the target before the attack.
**Techniques:**
- Passive: OSINT — LinkedIn, Shodan, WHOIS, Google dorking
- Active: Port scanning (nmap), DNS enumeration, email harvesting

**MITRE Techniques:**
- T1595 - Active Scanning
- T1592 - Gather Victim Host Information
- T1591 - Gather Victim Org Information
- T1589 - Gather Victim Identity Information

**Detection:**
- Unusual port scanning from external IPs
- DNS zone transfer attempts
- Multiple 404s from same IP on web servers
- Shodan/Censys hits on your external IPs (threat intel)

**Detection Query (Splunk):**
```spl
index=firewall action=denied 
| stats count by src_ip dest_port 
| where count > 50 
| sort -count
```

**False Positives:** Legitimate vulnerability scanners (Qualys, Nessus), security researchers, search engine crawlers

---

### Stage 2: Weaponization
**What:** Attacker creates the malware payload combined with an exploit. This happens OFF your network — you rarely see this.

**What attackers do:**
- Embed exploit in document (malicious macro, PDF exploit)
- Create dropper with C2 callback configured
- Bundle exploit with payload (e.g., Cobalt Strike beacon)

**Detection opportunity:** Threat intelligence — see if tools/techniques match known threat actor TTPs.

**MITRE Techniques:**
- T1587 - Develop Capabilities
- T1588 - Obtain Capabilities

---

### Stage 3: Delivery
**What:** Attacker delivers the weaponized payload to the target.

**Methods:**
- Phishing email with malicious attachment or link
- Watering hole attack (compromised website)
- Malicious USB drop
- Supply chain compromise
- Exploit kit via drive-by download

**MITRE Techniques:**
- T1566.001 - Spearphishing Attachment
- T1566.002 - Spearphishing Link
- T1195 - Supply Chain Compromise

**Detection:**
- Email gateway alerts on suspicious attachments
- URL filtering blocking malicious links
- Proxy logs showing malicious domain access
- File hash matching known malware IOC

**Detection Query (Email Logs):**
```spl
index=email_logs 
| search attachment_type IN ("*.exe","*.js","*.vbs","*.hta","*.bat","*.ps1","*.iso","*.lnk")
| table _time, sender, recipient, subject, attachment_name, attachment_type
```

**False Positives:** Legitimate software delivery (IT sending patches), vendors sending tools

---

### Stage 4: Exploitation
**What:** The malicious code executes. A vulnerability is triggered.

**Common exploits:**
- Browser exploits (malicious JavaScript)
- Office macro execution
- PDF embedded shellcode
- Phishing link → credential harvest → account takeover

**MITRE Techniques:**
- T1203 - Exploitation for Client Execution
- T1059 - Command and Scripting Interpreter
- T1204 - User Execution

**Detection:**
- EDR alert on suspicious child process spawning
- AV/EDR flags malicious code execution
- Windows Event ID 4688 (new process created) with suspicious parent-child relationship
- PowerShell script block logging (Event ID 4104)

**Real-world example:**
```
Word.exe → cmd.exe → powershell.exe -nop -w hidden -enc [BASE64]
```
This parent-child chain is a textbook phishing → exploitation → PowerShell execution.

**Detection Query (Splunk + Sysmon):**
```spl
index=sysmon EventCode=1 
| where ParentImage IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
AND Image IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine
```

---

### Stage 5: Installation
**What:** Attacker installs persistence mechanism to maintain access after reboot.

**Common persistence methods:**
- Registry Run keys
- Scheduled tasks
- Startup folder
- Services (malicious service creation)
- DLL hijacking
- WMI subscriptions

**MITRE Techniques:**
- T1547.001 - Registry Run Keys / Startup Folder
- T1053.005 - Scheduled Task
- T1543.003 - Windows Service
- T1546.003 - WMI Event Subscription

**Detection:**
- Sysmon Event ID 13 (Registry value set) on Run keys
- Event ID 4698 (Scheduled task created)
- Event ID 7045 (New service installed)
- Unusual files in Startup folder

**Detection Query:**
```spl
index=wineventlog EventCode=4698
| table _time, Computer, SubjectUserName, TaskName, TaskContent
```

**False Positives:** Software installers creating legitimate scheduled tasks, IT deploying software via GPO

---

### Stage 6: Command & Control (C2)
**What:** Malware beacons home to the attacker's infrastructure. This is the attacker's persistent communication channel.

**C2 protocols:**
- HTTP/HTTPS (most common, blends with traffic)
- DNS tunneling (covert channel via DNS queries)
- ICMP tunneling
- Social media APIs (Twitter, GitHub)
- Custom encrypted protocols

**Beaconing patterns:**
- Regular intervals (e.g., every 60 seconds) = automated beacon
- Jitter added to avoid detection (58-62 second range)

**MITRE Techniques:**
- T1071 - Application Layer Protocol
- T1071.001 - Web Protocols
- T1071.004 - DNS
- T1132 - Data Encoding
- T1573 - Encrypted Channel

**Detection:**
- Regular outbound connections to rare/new domain
- High frequency DNS queries to same domain
- Long-duration connections to unusual destinations
- Connections to newly registered domains (< 30 days old)
- HTTP connections with unusual user agents
- Beaconing pattern analysis

**Detection Query (Beacon Detection):**
```spl
index=proxy 
| stats count, avg(bytes_out), stdev(bytes_out), earliest(_time) as first_seen, latest(_time) as last_seen 
  by src_ip, dest_domain 
| where count > 50 AND stdev(bytes_out) < 100
| eval duration = last_seen - first_seen
| eval interval = duration / count
| where interval > 30 AND interval < 300
| sort -count
```

**False Positives:** Legitimate software update checks (antivirus, browsers), monitoring agents, backup software

---

### Stage 7: Actions on Objectives
**What:** The attacker achieves their goal. This is the "crown jewel" phase.

**Common objectives:**
- **Data exfiltration**: Intellectual property, PII, credentials
- **Ransomware deployment**: Encrypt files, demand payment
- **Lateral movement**: Move to other systems, especially AD
- **Privilege escalation**: Gain SYSTEM/Domain Admin
- **Destruction**: Wipe systems, delete backups
- **Persistence for long-term access**: APT-style campaigns

**MITRE Techniques:**
- T1041 - Exfiltration Over C2 Channel
- T1567 - Exfiltration Over Web Service
- T1021 - Remote Services (lateral movement)
- T1486 - Data Encrypted for Impact (ransomware)
- T1490 - Inhibit System Recovery (delete shadow copies)

**Critical Detection:**
- Large data transfers outbound
- vssadmin delete shadows (ransomware indicator)
- wmic /node: commands (lateral movement)
- Abnormal access to file shares
- Credentials dumped (lsass.exe access, mimikatz signatures)

---

## Kill Chain Mapping to Detection Priorities

| Stage          | Detection Priority | Containment Impact            |
| -------------- | ------------------ | ----------------------------- |
| Reconnaissance | Low                | Prevent early intel gathering |
| Weaponization  | None (off-network) | N/A                           |
| Delivery       | **HIGH**           | Stop before execution         |
| Exploitation   | **CRITICAL**       | Contain before persistence    |
| Installation   | **CRITICAL**       | Eradicate persistence         |
| C2             | **CRITICAL**       | Cut off attacker access       |
| Actions        | **CRITICAL**       | Minimize damage               |

**Rule of thumb:** The later the kill chain stage you detect, the more damage has likely occurred and the more work remediation will take.

---

## Real-World Attack Example: BEC via Phishing
```
1. Recon: Attacker scrapes LinkedIn for CFO email
2. Weaponize: Creates Office document with macro + embedded payload
3. Deliver: Sends spearphish to CFO: "Urgent invoice review needed"
4. Exploit: CFO opens doc, enables macros, macro executes
5. Install: Cobalt Strike beacon installed in AppData
6. C2: Beacon phones home every 60s to attacker's CDN
7. Objective: Attacker intercepts email thread, requests wire transfer
```

---

## Related Notes
- [[MITRE ATT&CK Overview\|MITRE ATT&CK Overview]]
- [[Pyramid of Pain\|Pyramid of Pain]]
- [[SOC Fundamentals\|SOC Fundamentals]]
- [[Phishing Analysis\|Phishing Analysis]]
- [[Incident Response Lifecycle\|Incident Response Lifecycle]]
