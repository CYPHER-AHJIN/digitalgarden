---
{"dg-publish":true,"permalink":"/vault-index/"}
---

# 🛡️ SOC L1 Complete Knowledge Base — Vault Index
#Index #SOC #BlueTeam #Vault

> **Purpose:** Complete knowledge base for SOC L1 analysts covering TryHackMe SOC Level 1 path, real-world detection, incident response, forensics, and career progression.
> 
> **Use this note as your starting point.** Every note in the vault links back here.

---

## 📁 Vault Structure

```
SOC Complete Knowledge Base/
├── 📂 01_SOC_Foundations/
│   ├── SOC_Fundamentals
│   ├── SOC_L1_Survival_Guide
│   ├── Cyber_Kill_Chain
│   └── Pyramid_of_Pain
│
├── 📂 02_Networking/
│   └── Networking_Fundamentals
│
├── 📂 03_Windows/
│   ├── Windows_Event_Logs
│   └── Windows_Commands
│
├── 📂 04_Linux/
│   └── Linux_Logs_and_Commands
│
├── 📂 05_SIEM/
│   └── SIEM_Overview_Splunk_ELK
│
├── 📂 06_Threat_Intel/
│   └── Threat_Intelligence
│
├── 📂 07_MITRE/
│   ├── MITRE_ATTACK_Overview
│   └── MITRE_ATT&CK_SOC_L1_Detection_Matrix  ← NEW
│
├── 📂 08_Detection_Engineering/
│   └── Detection_Engineering
│
├── 📂 09_Incident_Response/
│   ├── Incident_Response_Lifecycle
│   └── SOC_Investigation_Playbooks
│
├── 📂 10_Forensics/
│   └── Forensics_Basics
│
├── 📂 11_Malware/
│   └── Malware_Basics
│
├── 📂 12_Phishing/
│   └── Phishing_Analysis
│
├── 📂 13_Brute_Force/
│   └── Brute_Force_Password_Attacks
│
├── 📂 14_Web_Attacks/
│   └── Web_Attacks_Basics  ← NEW
│
├── 📂 15_IDS_IPS/
│   └── IDS_IPS
│
├── 📂 16_Tools/
│   └── Tools_Reference
│
├── 📂 17_Interview_Prep/
│   └── Interview_Questions
│
├── 📂 18_CTF/
│   └── CTF_Cheatsheets
│
├── 📂 19_Career/
│   ├── SOC_L1_to_L2_Roadmap  ← NEW
│   └── Home_Lab_Setup_Guide  ← NEW
│
└── 📂 20_Labs/
    └── Detection_Labs_30_Ideas  ← NEW
```

---

## 🚀 Start Here — By Your Goal

### 🎯 "I have a SOC job interview next week"
1. [[SOC_L1_Complete_Knowledge_Base/17_Interview_Prep/Interview_Questions\|Interview_Questions]] — Read all Q&A sections
2. [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/SOC_Fundamentals\|SOC_Fundamentals]] — Know the fundamentals cold
3. [[SOC_L1_Complete_Knowledge_Base/03_Windows/Windows_Event_Logs\|Windows_Event_Logs]] — Event IDs from memory
4. [[SOC_L1_Complete_Knowledge_Base/07_MITRE/MITRE_ATTACK_Overview\|MITRE_ATTACK_Overview]] — Map techniques to IDs
5. [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/Cyber_Kill_Chain\|Cyber_Kill_Chain]] — Know all 7 stages
6. [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/Pyramid_of_Pain\|Pyramid_of_Pain]] — Key framework question
7. [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/Incident_Response_Lifecycle\|Incident_Response_Lifecycle]] — NIST 4 phases
8. [[SOC_L1_Complete_Knowledge_Base/05_SIEM/SIEM_Overview_Splunk_ELK\|SIEM_Overview_Splunk_ELK]] — Basic SPL queries

---

### 🎯 "I'm starting my first SOC L1 job"
1. [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/SOC_L1_Survival_Guide\|SOC_L1_Survival_Guide]] — Read first, bookmark it
2. [[SOC_L1_Complete_Knowledge_Base/03_Windows/Windows_Event_Logs\|Windows_Event_Logs]] — Your daily bread
3. [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/SOC_Investigation_Playbooks\|SOC_Investigation_Playbooks]] — Step-by-step for every scenario
4. [[SOC_L1_Complete_Knowledge_Base/12_Phishing/Phishing_Analysis\|Phishing_Analysis]] — Most common L1 task
5. [[SOC_L1_Complete_Knowledge_Base/13_Brute_Force/Brute_Force_Password_Attacks\|Brute_Force_Password_Attacks]] — Second most common alert
6. [[SOC_L1_Complete_Knowledge_Base/16_Tools/Tools_Reference\|Tools_Reference]] — Know every tool you'll use
7. [[SOC_L1_Complete_Knowledge_Base/06_Threat_Intel/Threat_Intelligence\|Threat_Intelligence]] — Enrichment workflow

---

### 🎯 "I want to practice CTF blue team challenges"
1. [[SOC_L1_Complete_Knowledge_Base/18_CTF/CTF_Cheatsheets\|CTF_Cheatsheets]] — 20 practice challenges with solutions
2. [[SOC_L1_Complete_Knowledge_Base/20_Labs/Detection_Labs_30_Ideas\|Detection_Labs_30_Ideas]] — 30 hands-on labs
3. [[SOC_L1_Complete_Knowledge_Base/10_Forensics/Forensics_Basics\|Forensics_Basics]] — Volatility commands
4. [[SOC_L1_Complete_Knowledge_Base/02_Networking/Networking_Fundamentals\|Networking_Fundamentals]] — Wireshark/tshark
5. [[SOC_L1_Complete_Knowledge_Base/13_Brute_Force/Brute_Force_Password_Attacks\|Brute_Force_Password_Attacks]] — Hydra, John, Hashcat
6. [[SOC_L1_Complete_Knowledge_Base/04_Linux/Linux_Logs_and_Commands\|Linux_Logs_and_Commands]] — Log analysis commands

---

### 🎯 "I want to move from L1 to L2"
1. [[SOC_L1_Complete_Knowledge_Base/19_Career/SOC_L1_to_L2_Roadmap\|SOC_L1_to_L2_Roadmap]] — Full roadmap with timeline
2. [[SOC_L1_Complete_Knowledge_Base/19_Career/Home_Lab_Setup_Guide\|Home_Lab_Setup_Guide]] — Build your practice environment
3. [[SOC_L1_Complete_Knowledge_Base/20_Labs/Detection_Labs_30_Ideas\|Detection_Labs_30_Ideas]] — Structured practice
4. [[SOC_L1_Complete_Knowledge_Base/10_Forensics/Forensics_Basics\|Forensics_Basics]] — L2 core skill
5. [[SOC_L1_Complete_Knowledge_Base/11_Malware/Malware_Basics\|Malware_Basics]] — L2 core skill
6. [[SOC_L1_Complete_Knowledge_Base/08_Detection_Engineering/Detection_Engineering\|Detection_Engineering]] — Write production rules

---

### 🎯 "I want to build detection rules"
1. [[SOC_L1_Complete_Knowledge_Base/08_Detection_Engineering/Detection_Engineering\|Detection_Engineering]] — Sigma rules, SPL, KQL
2. [[SOC_L1_Complete_Knowledge_Base/07_MITRE/MITRE_ATT&CK_SOC_L1_Detection_Matrix\|MITRE_ATT&CK_SOC_L1_Detection_Matrix]] — Coverage mapping
3. [[SOC_L1_Complete_Knowledge_Base/05_SIEM/SIEM_Overview_Splunk_ELK\|SIEM_Overview_Splunk_ELK]] — Query patterns
4. [[SOC_L1_Complete_Knowledge_Base/03_Windows/Windows_Event_Logs\|Windows_Event_Logs]] — What events to use
5. [[SOC_L1_Complete_Knowledge_Base/15_IDS_IPS/IDS_IPS\|IDS_IPS]] — Snort/Suricata rules

---

## 📋 Quick Reference Cards

### Most Important Windows Event IDs
| ID | What It Means | Alert If |
|----|---------------|----------|
| **4624** | Successful logon | Type 3 NTLM, Type 10 at odd hours, foreign IP |
| **4625** | Failed logon | >10 in 5min from same IP |
| **4648** | Explicit credential logon | Non-IT hosts, runas anomaly |
| **4672** | Privileged logon | Non-admin accounts |
| **4688** | Process created | Office→shell, cmd with suspicious args |
| **4698** | Scheduled task created | Path in Temp/AppData |
| **4720** | Account created | By non-admin or after-hours |
| **4732** | Added to local group | Added to Administrators |
| **4769** | Kerberos TGS | Encryption type 0x17 (RC4) = Kerberoasting |
| **1102** | Security log cleared | ANY time = ESCALATE |
| **7045** | Service installed | Path not in System32/Program Files |
| **Sysmon 1** | Process created | Full CommandLine + ParentImage |
| **Sysmon 10** | ProcessAccess lsass | GrantedAccess = Mimikatz |
| **Sysmon 13** | Registry modified | Run key changes |
| **Sysmon 22** | DNS query | Long subdomain = DNS tunnel |

---

### Kill Chain → Detection Mapping
| Kill Chain Stage | What to Detect | Log Source |
|-----------------|----------------|------------|
| Reconnaissance | Port scans, DNS enumeration | Firewall, IDS |
| Delivery | Malicious email, phishing URL | Email GW, Proxy |
| Exploitation | Office→shell, exploit code | Sysmon, EDR |
| Installation | Sched task, Run key, service | Windows Security |
| C2 | Beaconing, DNS tunnel | Proxy, DNS |
| Actions | Credential dump, exfil, lateral | Sysmon, Security |

---

### Pyramid of Pain — Detection Priority
```
TTPs (hardest to change) ← Build rules here
Tools (weeks to change)
Network/Host Artifacts (annoying to change)
Domain Names (simple to change)
IP Addresses (easy to change)
File Hashes (trivial to change) ← Don't rely on this alone
```

---

### Investigation Enrichment Tools Quick Reference
| Need | Tool | URL |
|------|------|-----|
| File hash | VirusTotal | virustotal.com |
| IP reputation | AbuseIPDB | abuseipdb.com |
| IP services | Shodan | shodan.io |
| URL/domain | URLScan.io | urlscan.io |
| Domain history | SecurityTrails | securitytrails.com |
| SSL certs | crt.sh | crt.sh |
| Email headers | MXToolbox | mxtoolbox.com/headers |
| Malware sandbox | Any.run | any.run |
| Hash lookup | MalwareBazaar | bazaar.abuse.ch |
| Phishing URLs | PhishTank | phishtank.org |
| IOC sharing | AlienVault OTX | otx.alienvault.com |

---

### Common Attack Patterns — Quick Recognition

**Brute Force:** Many 4625 from same IP against same account → check for 4624 success

**Password Spray:** Many 4625 from same IP against MANY accounts, 1-3 attempts each → check for 4624

**Phishing Chain:** Email received → User opens → Office spawns shell process (Sysmon 1) → Network connection (Sysmon 3) → File dropped (Sysmon 11)

**C2 Beaconing:** Regular HTTP/DNS requests at fixed intervals → low byte variance → to newly registered domain

**Lateral Movement:** 4624 Type 3 from workstation to workstation → 5140 Admin$ access → New service on target (7045)

**Ransomware:** vssadmin delete shadows → Mass file modifications → Ransom note creation → All in rapid succession

**Credential Dumping:** Sysmon 10 (lsass access) with specific GrantedAccess values → Followed by 4624 Type 3 from many hosts (PTH)

---

## 🔗 All Notes — Complete List

### Foundations
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/SOC_Fundamentals\|SOC_Fundamentals]] — What a SOC is, tiers, CIA triad, alert types
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/SOC_L1_Survival_Guide\|SOC_L1_Survival_Guide]] — Daily workflow, ticket templates, escalation criteria
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/Cyber_Kill_Chain\|Cyber_Kill_Chain]] — 7 stages, detection at each stage
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/Pyramid_of_Pain\|Pyramid_of_Pain]] — IOC types, detection priorities

### Networking
- [[SOC_L1_Complete_Knowledge_Base/02_Networking/Networking_Fundamentals\|Networking_Fundamentals]] — TCP/IP, protocols, Wireshark, Nmap, tshark

### Windows
- [[SOC_L1_Complete_Knowledge_Base/03_Windows/Windows_Event_Logs\|Windows_Event_Logs]] — All Event IDs, Sysmon, PowerShell logging, detection queries
- [[SOC_L1_Complete_Knowledge_Base/03_Windows/Windows_Commands\|Windows_Commands]] — whoami, netstat, tasklist, reg query, schtasks, wmic, wevtutil, Get-WinEvent

### Linux
- [[SOC_L1_Complete_Knowledge_Base/04_Linux/Linux_Logs_and_Commands\|Linux_Logs_and_Commands]] — journalctl, grep, awk, sed, ps, netstat, tcpdump, find, strings

### SIEM
- [[SOC_L1_Complete_Knowledge_Base/05_SIEM/SIEM_Overview_Splunk_ELK\|SIEM_Overview_Splunk_ELK]] — Splunk SPL, ELK KQL, detection queries, tuning

### Threat Intel
- [[SOC_L1_Complete_Knowledge_Base/06_Threat_Intel/Threat_Intelligence\|Threat_Intelligence]] — IOC types, MISP, enrichment platforms, OSINT

### MITRE ATT&CK
- [[SOC_L1_Complete_Knowledge_Base/07_MITRE/MITRE_ATTACK_Overview\|MITRE_ATTACK_Overview]] — All 14 tactics, critical techniques, detection queries
- [[SOC_L1_Complete_Knowledge_Base/07_MITRE/MITRE_ATT&CK_SOC_L1_Detection_Matrix\|MITRE_ATT&CK_SOC_L1_Detection_Matrix]] — Full detection coverage matrix ← NEW

### Detection Engineering
- [[SOC_L1_Complete_Knowledge_Base/08_Detection_Engineering/Detection_Engineering\|Detection_Engineering]] — Sigma rules, correlation logic, tuning strategy

### Incident Response
- [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/Incident_Response_Lifecycle\|Incident_Response_Lifecycle]] — NIST phases, evidence handling, IR report template
- [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/SOC_Investigation_Playbooks\|SOC_Investigation_Playbooks]] — Brute force, PowerShell, malware, phishing, RDP, privilege escalation, web shell

### Forensics
- [[SOC_L1_Complete_Knowledge_Base/10_Forensics/Forensics_Basics\|Forensics_Basics]] — Volatility, Autopsy, KAPE, disk forensics, Windows artifacts

### Malware
- [[SOC_L1_Complete_Knowledge_Base/11_Malware/Malware_Basics\|Malware_Basics]] — Malware types, behavior, analysis tools, MITRE mapping

### Phishing
- [[SOC_L1_Complete_Knowledge_Base/12_Phishing/Phishing_Analysis\|Phishing_Analysis]] — Email headers, SPF/DKIM/DMARC, URL analysis, investigation workflow

### Attacks
- [[SOC_L1_Complete_Knowledge_Base/13_Brute_Force/Brute_Force_Password_Attacks\|Brute_Force_Password_Attacks]] — Hydra, John, Hashcat, detection queries
- [[Web_Attacks_Basics\|Web_Attacks_Basics]] — SQLi, XSS, LFI, RFI, command injection, web shells ← NEW
- [[SOC_L1_Complete_Knowledge_Base/15_IDS_IPS/IDS_IPS\|IDS_IPS]] — Snort rules, Suricata, rule syntax, SIEM integration

### Tools
- [[SOC_L1_Complete_Knowledge_Base/16_Tools/Tools_Reference\|Tools_Reference]] — VirusTotal, AbuseIPDB, Shodan, Sysinternals, Splunk, Volatility, Autopsy, KAPE, MISP

### Interview Prep
- [[SOC_L1_Complete_Knowledge_Base/17_Interview_Prep/Interview_Questions\|Interview_Questions]] — Technical Q&A, scenario questions, log analysis challenges

### CTF
- [[SOC_L1_Complete_Knowledge_Base/18_CTF/CTF_Cheatsheets\|CTF_Cheatsheets]] — 20 blue team CTF challenges, encoding/decoding, magic bytes

### Career
- [[SOC_L1_Complete_Knowledge_Base/19_Career/SOC_L1_to_L2_Roadmap\|SOC_L1_to_L2_Roadmap]] — Skills, certs, timeline, 90-day plan ← NEW
- [[SOC_L1_Complete_Knowledge_Base/19_Career/Home_Lab_Setup_Guide\|Home_Lab_Setup_Guide]] — Free tools, VM setup, Splunk/ELK, AD lab ← NEW

### Labs
- [[SOC_L1_Complete_Knowledge_Base/20_Labs/Detection_Labs_30_Ideas\|Detection_Labs_30_Ideas]] — 30 structured hands-on detection labs ← NEW

---

## 📊 Vault Statistics

| Category | Note Count | Status |
|----------|-----------|--------|
| SOC Foundations | 4 | ✅ Complete |
| Networking | 1 | ✅ Complete |
| Windows | 2 | ✅ Complete |
| Linux | 1 | ✅ Complete |
| SIEM | 1 | ✅ Complete |
| Threat Intel | 1 | ✅ Complete |
| MITRE ATT&CK | 2 | ✅ Complete |
| Detection Engineering | 1 | ✅ Complete |
| Incident Response | 2 | ✅ Complete |
| Forensics | 1 | ✅ Complete |
| Malware | 1 | ✅ Complete |
| Phishing | 1 | ✅ Complete |
| Attacks | 3 | ✅ Complete |
| IDS/IPS | 1 | ✅ Complete |
| Tools | 1 | ✅ Complete |
| Interview | 1 | ✅ Complete |
| CTF | 1 | ✅ Complete |
| Career | 2 | ✅ Complete |
| Labs | 1 | ✅ Complete |
| **TOTAL** | **28** | **✅** |

---

*This vault covers the complete TryHackMe SOC Level 1 path and beyond. Updated to include all practical skills for real SOC L1 employment, blue team CTF competition, and SOC L2 career progression.*
