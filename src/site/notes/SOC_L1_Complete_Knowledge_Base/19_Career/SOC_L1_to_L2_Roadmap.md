---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/19-career/soc-l1-to-l2-roadmap/","dgPassFrontmatter":true}
---

# SOC L1 → SOC L2 Career Roadmap
#Career #SOC #Roadmap #Skills #Certifications

---

## Overview

The jump from SOC L1 to SOC L2 is one of the most important career transitions in cybersecurity. At L1 you triage, enrich, and escalate. At L2 you investigate deeply, perform forensics, hunt threats, and own the incident from start to close.

**Typical Timeline:** 12–24 months at L1 before a solid L2 transition. Some move faster with focused self-study. Some take 3 years. It depends entirely on how deliberately you build skills outside shift work.

**Key Insight:** L2 doesn't just mean "more of L1." It requires fundamentally different thinking — from reactive (what is this alert?) to proactive (what is the attacker doing that we're NOT alerting on?).

---

## Phase 1: Master L1 Completely (Months 0–6)

### What "Mastered L1" Means
You know you're ready to advance when you can:
- Triage any alert without needing to look up what the Event ID means
- Close or escalate any ticket confidently within 15 minutes
- Explain every detection query your team uses
- Identify a False Positive within 30 seconds of seeing the alert
- Write proper investigation notes that L2 doesn't have to re-investigate
- Know when something is wrong even if no alert fired

### Checklist to Complete Before Moving On

```
Core Knowledge:
[ ] Know Event IDs 4624, 4625, 4648, 4688, 4698, 4720, 4732, 4769, 1102, 7045 cold
[ ] Can explain Logon Types 2, 3, 4, 5, 9, 10 from memory
[ ] Can write basic Splunk queries without reference
[ ] Know Cyber Kill Chain and MITRE ATT&CK well enough to map any alert
[ ] Understand SPF/DKIM/DMARC and can analyze any email header
[ ] Can perform IOC enrichment (VT, AbuseIPDB, Shodan, URLScan) without checklists

Skills:
[ ] Can analyze a PCAP and find C2 traffic using Wireshark
[ ] Can analyze auth.log for brute force without prompting
[ ] Have written at least 5 investigation reports
[ ] Have handled a real P1/P2 incident (even if just observing)
[ ] Understand your SOC's tooling deeply (SIEM, EDR, ticketing)
```

---

## Phase 2: Build L2 Skills During L1 Work (Months 3–12)

The best strategy is to start building L2 skills WHILE working L1. Use quiet shift time to study. Shadow L2 analysts on escalations.

### Skill Area 1: Deep Windows Forensics

**What to learn:**
- Windows artifact locations and what they prove
- Prefetch, LNK files, Jump Lists, Shellbags, UserAssist
- Windows Registry forensics (persistence, user activity)
- Browser forensics (history, downloads, cache)
- Event log deep parsing (reading raw XML, not just SIEM fields)
- NTFS metadata (timestamps, $MFT analysis)

**How to practice:**
- Run KAPE on your home lab Windows VM and analyze every artifact
- Complete: TryHackMe "Windows Forensics" rooms
- Complete: BlueTeamLabs "Sticky Situation" and similar forensics challenges
- Study: Eric Zimmermann's Forensics Tools (PECmd, LECmd, JLECmd, MFTECmd)

**Timeline:** 2–3 months part-time study

---

### Skill Area 2: Memory Forensics

**What to learn:**
- Volatility 3 commands (pslist, psscan, malfind, netscan, cmdline, hashdump)
- Difference between pslist vs psscan (rootkit detection)
- Process injection artifacts (hollow processes, reflective DLL loading)
- Network connection artifacts in memory
- Credential artifacts in memory

**How to practice:**
- Complete: MemLabs 1-6 (github.com/stuxnet999/MemLabs)
- Complete: CyberDefenders "Seized" and memory forensics challenges
- Complete: TryHackMe "Volatility" room
- Build: Create your own memory dumps by running known malware in a VM

**Timeline:** 2–3 months part-time study

---

### Skill Area 3: Malware Analysis (Static + Behavioral)

**What to learn:**
- Static analysis: strings, PE headers, imports/exports, entropy analysis
- Behavioral sandbox analysis: interpreting Any.run, Hybrid Analysis reports
- Identifying malware families by behavior
- C2 indicators from malware analysis
- Cobalt Strike recognition (default configs, malleable profiles, named pipes)
- Understanding common malware capabilities (RAT, loader, dropper, beacon)

**How to practice:**
- Complete: TryHackMe "Malware Analysis Fundamentals"
- Submit real samples to Any.run and analyze 5 different malware families
- Read: Malware Traffic Analysis (malware-traffic-analysis.net) — practice with each exercise
- Tools to learn: PEStudio, FLOSS, x64dbg basics, CyberChef for decoding

**Timeline:** 3–4 months part-time study

---

### Skill Area 4: Threat Hunting

**What to learn:**
- Hypothesis-based hunting (start with a TTP, look for evidence)
- Baselining (what is normal in your environment?)
- MITRE ATT&CK navigator for hunt planning
- Using Splunk/ELK for hunting (not just alerting)
- Hunting for LOLBin abuse, fileless malware, anomalous behavior
- Writing hunt reports and turning hunts into detection rules

**How to practice:**
- Build MITRE ATT&CK-based hunt plans for your environment
- Read: "The ThreatHunting Project" (threathunting.net)
- Complete: SANS FOR508 materials or similar
- Practice with Mordor datasets (github.com/OTRF/Security-Datasets)

**Timeline:** Ongoing — 1 hunt per week is a good target

---

### Skill Area 5: Detection Engineering

**What to learn:**
- Sigma rule syntax and writing
- Converting Sigma to Splunk/KQL/ELK
- Alert tuning methodology (measure, analyze FPs, add exclusions, re-measure)
- Coverage mapping with MITRE ATT&CK Navigator
- Understanding your SIEM's data model

**How to practice:**
- Write 5 custom Sigma rules for techniques not currently covered
- Convert existing Splunk queries to Sigma format
- Use sigma-cli to convert to multiple SIEM formats
- Build a coverage heatmap of your detection library vs ATT&CK matrix

**Timeline:** 2–3 months

---

### Skill Area 6: Incident Response

**What to learn:**
- NIST IR Lifecycle phases in practice (not just theory)
- Containment decisions (when to isolate, when not to)
- Evidence collection (chain of custody, order of volatility)
- Root cause analysis methodology
- Writing professional IR reports
- Communication during incidents (stakeholders, management, legal)

**How to practice:**
- Shadow every L2 escalation — ask to observe containment decisions
- Write mock post-incident reports for every real incident you handle
- Complete: Blue Team Labs Online "Incident Response" challenges
- Tabletop exercise: Walk through a ransomware scenario on paper

**Timeline:** Ongoing with each escalation

---

## Phase 3: Certifications to Pursue

### Entry Level (Validate L1 Mastery)

| Cert | Provider | Focus | Cost |
|------|----------|-------|------|
| **CompTIA Security+** | CompTIA | Broad security foundation | ~$380 |
| **CompTIA CySA+** | CompTIA | SOC analyst focused | ~$380 |
| **Blue Team Level 1 (BTL1)** | Security Blue Team | Practical blue team | ~$500 |
| **TryHackMe SOC Level 1 Path** | TryHackMe | Practical hands-on | ~$14/mo |

**Recommendation:** BTL1 is the most practical and respected for SOC roles. Get this first if budget allows.

---

### Intermediate (L2 Level Skills)

| Cert | Provider | Focus | Cost |
|------|----------|-------|------|
| **GIAC GCIH** | SANS | Incident handling | ~$2,500 |
| **GIAC GCIA** | SANS | Network intrusion analysis | ~$2,500 |
| **GIAC GCFE** | SANS | Windows forensics | ~$2,500 |
| **GIAC GREM** | SANS | Reverse engineering malware | ~$2,500 |
| **Elastic Certified Analyst** | Elastic | Elastic SIEM | ~$400 |
| **Splunk Core Certified User** | Splunk | Splunk skills | Free exam |

**Note on SANS:** Expensive but industry gold standard. Many employers will pay for these. Ask for training budget at your organization.

---

### Advanced (Specialization)

| Cert | Provider | Focus | Cost |
|------|----------|-------|------|
| **OSCP** | Offensive Security | Penetration testing (understand attacker) | ~$1,499 |
| **GIAC GCFA** | SANS | Advanced forensics | ~$2,500 |
| **GIAC GCDA** | SANS | Cloud detection | ~$2,500 |
| **PNPT** | TCM Security | Practical network pentesting | ~$400 |

---

## Phase 4: Skills Matrix — L1 vs L2 Comparison

| Skill | L1 Level | L2 Level |
|-------|----------|----------|
| SIEM Query Writing | Basic filtering | Complex correlation, custom SPL functions |
| Windows Logs | Know key Event IDs | Read raw XML, parse all fields |
| Linux Logs | grep/awk for auth.log | Full audit framework, systemd journals |
| Memory Forensics | None | Volatility deep analysis |
| Malware Analysis | Sandbox submission | Static analysis, string extraction, behavioral |
| Threat Hunting | None | Hypothesis-based, MITRE-driven |
| Forensics | None | Disk imaging, timeline analysis, artifact parsing |
| Detection Engineering | Understand rules | Write and tune production rules |
| Incident Response | Triage and escalate | Own the incident end-to-end |
| Reporting | Ticket notes | Executive report + timeline + IOC list |
| Scripting | None | Python/PowerShell for automation |
| Network Analysis | Basic Wireshark | PCAP forensics, protocol analysis |
| Threat Intel | Lookups | Platform management, pivot analysis |

---

## Phase 5: Technical Depth to Build

### Python for SOC Automation

Start learning Python with SOC-specific use cases:

```python
# Level 1: Basic IOC enrichment script
import requests

def check_virustotal(hash_value, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    data = response.json()
    malicious = data['data']['attributes']['last_analysis_stats']['malicious']
    total = sum(data['data']['attributes']['last_analysis_stats'].values())
    return f"{malicious}/{total} engines detected as malicious"

# Level 2: Parse Windows event logs
import xml.etree.ElementTree as ET
import subprocess

def get_failed_logins():
    cmd = 'wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:100 /f:xml'
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    # Parse XML output
    events = []
    # ... parse and return events
    return events
```

**Study Path:**
- Python for Everybody (Coursera, free)
- Automate the Boring Stuff (free)
- Build 3 tools: IOC enricher, log parser, phishing header analyzer

---

### PowerShell for Windows Forensics

```powershell
# Build a triage script that collects:
# Processes, network connections, scheduled tasks, services, registry persistence
# Then exports to JSON for easy review

$triage = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
    Hostname = $env:COMPUTERNAME
    CurrentUser = whoami
    Processes = Get-Process | Select Name, Id, CPU, Path, Company
    NetworkConnections = Get-NetTCPConnection -State Established | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
    ScheduledTasks = Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select TaskName, TaskPath, State
    Services = Get-Service | Where-Object {$_.Status -eq 'Running'} | Select Name, DisplayName, Status
}

$triage | ConvertTo-Json -Depth 4 | Out-File "C:\triage_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
```

---

## Reading List — Books for L1→L2 Transition

**Must-Read:**
1. "The Practice of Network Security Monitoring" — Richard Bejtlich
2. "Intelligence-Driven Incident Response" — Scott Roberts & Rebekah Brown
3. "Blue Team Handbook" — Don Murdoch
4. "The Art of Memory Forensics" — Ligh, Case, Levy, Walters
5. "Applied Incident Response" — Steve Anson

**Online:**
- SANS Reading Room (sans.org/reading-room) — free papers
- Mandiant/FireEye threat reports — free
- Microsoft MSTIC blog — free
- Elastic Security research — free
- Red Canary Threat Detection Report (annual) — free

---

## 90-Day L2 Transition Plan

### Days 1–30: Foundation Building
```
Week 1-2: Complete one Memory Forensics challenge (MemLabs)
Week 3: Windows artifact deep dive — run KAPE, analyze all outputs
Week 4: Write 2 Sigma rules and convert to Splunk
Throughout: Shadow every L2 escalation at your org
```

### Days 31–60: Skill Building
```
Week 5-6: Malware sandbox analysis — 5 different families on Any.run
Week 7: Build Python IOC enrichment tool
Week 8: Complete one PCAP challenge (malware-traffic-analysis.net)
Throughout: One threat hunt per week based on MITRE ATT&CK technique
```

### Days 61–90: Production Readiness
```
Week 9-10: Write mock post-incident reports for past escalations
Week 11: Detection coverage gap analysis — map your rules to ATT&CK
Week 12: Present threat hunt findings to your team
Final: Discuss promotion with manager, show evidence of skills
```

---

## Signs You're Ready for L2

✅ You're regularly catching things L2 missed during your enrichment  
✅ You can handle an escalation independently without L2 handholding  
✅ You have a threat hunt under your belt  
✅ You've written at least 3 detection rules that are in production  
✅ You can explain the full kill chain of an incident you handled  
✅ You feel bored by L1 triage because it's too easy  
✅ Other analysts ask you for help  
✅ You think like an attacker, not just a defender  

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/SOC_Fundamentals\|SOC_Fundamentals]]
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/SOC_L1_Survival_Guide\|SOC_L1_Survival_Guide]]
- [[SOC_L1_Complete_Knowledge_Base/08_Detection_Engineering/Detection_Engineering\|Detection_Engineering]]
- [[SOC_L1_Complete_Knowledge_Base/10_Forensics/Forensics_Basics\|Forensics_Basics]]
- [[SOC_L1_Complete_Knowledge_Base/11_Malware/Malware_Basics\|Malware_Basics]]
- [[SOC_L1_Complete_Knowledge_Base/19_Career/Home_Lab_Setup_Guide\|Home_Lab_Setup_Guide]]
- [[SOC_L1_Complete_Knowledge_Base/17_Interview_Prep/Interview_Questions\|Interview_Questions]]
