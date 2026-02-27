---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/09-incident-response/incident-response-lifecycle/","dgPassFrontmatter":true}
---

# Incident Response Lifecycle
#IR #IncidentResponse #Playbooks #SOC

---

## Overview

Incident Response (IR) is the structured approach to handling security incidents. Every SOC analyst must understand this process — it defines what you do when an alert becomes a confirmed incident.

**Standard:** NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)

**Why it matters:** Without a defined process, incidents turn into chaos. The IR lifecycle ensures systematic containment, eradication, and recovery while preserving evidence for legal/regulatory purposes.

---

## NIST IR Lifecycle (4 Phases)

```
┌─────────────────────────────────────────────────────────────────┐
│                    NIST IR LIFECYCLE                            │
│                                                                 │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ Preparation │ →  │  Detection & │ →  │   Containment    │   │
│  │             │    │  Analysis    │    │   Eradication    │   │
│  └─────────────┘    └──────────────┘    │   Recovery       │   │
│         ↑                               └──────────────────┘   │
│         │                                        ↓             │
│         │           ┌────────────────────────────┘             │
│         └───────────│ Post-Incident Activity (Lessons Learned) │
│                     └──────────────────────────────────────────┘
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Preparation

**Goal:** Be ready BEFORE an incident happens.

### What This Includes:
- Define IR team roles and contacts
- Develop and document playbooks
- Deploy and configure security tools (SIEM, EDR, NDR, SOAR)
- Set up communication channels (Slack channel, bridge numbers)
- Establish relationships with external parties (ISPs, law enforcement, IR retainer)
- Train analysts on playbooks and tools
- Tabletop exercises
- Define what constitutes an "incident" vs. "event"
- Maintain asset inventory and network diagrams

### Documentation to Prepare:
- Contact list (management, legal, PR, IT, law enforcement)
- Asset criticality list
- Network diagrams
- IR playbooks (one per scenario)
- Evidence collection procedures
- Escalation matrix

---

## Phase 2: Detection & Analysis

**Goal:** Identify that an incident has occurred and understand its scope.

### Detection Sources:
- SIEM alert fires
- EDR alert fires
- User reports suspicious activity
- Threat intelligence match on IOC
- External notification (CERT, FBI, partner)
- Anomaly detected by threat hunter

### Triage Steps (SOC L1 Responsibility):
```
1. Receive alert
2. Initial classification (severity, category)
3. Verify alert is not false positive
4. Enrich:
   - IP reputation (AbuseIPDB, VirusTotal, Shodan)
   - Hash lookup (VirusTotal, MalwareBazaar)
   - User context (HR lookup, last activity)
   - Asset context (criticality, owner, location)
5. Determine scope:
   - Single endpoint? Multiple?
   - User account compromised?
   - Data accessed?
6. Document all findings in ticket
7. Escalate to L2 if confirmed TP
```

### Incident Classification Matrix:
```
Category      | Examples
──────────────|───────────────────────────────────────────
Malware       | Ransomware, RAT, Trojan, Rootkit
Web Attack    | SQLi, XSS, LFI, RFI, RCE
Account       | Brute force, credential stuffing, account takeover
Insider       | Data theft, policy violation, sabotage
DoS/DDoS      | Volumetric, application layer
Data Breach   | Exfiltration, unauthorized access to PII
APT           | Nation-state, sophisticated persistent threat
Physical      | Stolen device, unauthorized access
```

### Severity Definitions:
```
CRITICAL: Active attack in progress, data exfiltration occurring, ransomware spreading, or critical system compromised
HIGH:     Confirmed compromise, malware on endpoint, privilege escalation, lateral movement
MEDIUM:   Suspicious activity requiring investigation, policy violation, account anomaly
LOW:      Single failed login, informational, policy reminder needed
```

---

## Phase 3: Containment, Eradication, Recovery

### 3a. Containment

**Short-term containment (first action — stop the bleeding):**
- Isolate compromised endpoint from network (EDR: isolate host)
- Block malicious IP/domain on firewall
- Disable compromised user account
- Reset credentials if stolen
- Take memory snapshot BEFORE isolation if possible (volatile evidence)

**Long-term containment:**
- Patch exploited vulnerability
- Update firewall/IPS rules
- Enhance monitoring around affected systems
- Rebuild if necessary

**Containment Decision Factors:**
- Business impact of isolating (critical production server?)
- Evidence preservation needs
- Attack persistence (will containment alert attacker?)
- Time sensitivity (active exfiltration?)

### 3b. Eradication

**Goal:** Remove all traces of attacker from environment.

```
1. Identify all affected systems (scope)
2. Remove malware:
   - AV/EDR remediation
   - Manual file removal
   - Registry cleanup
3. Remove persistence mechanisms:
   - Scheduled tasks
   - Registry run keys
   - Malicious services
   - Backdoor accounts
4. Remove lateral movement artifacts:
   - Attacker tools dropped on systems
   - Credential harvesting tools
5. Verify eradication:
   - Re-scan with updated signatures
   - Check all persistence locations
   - Verify no remaining C2 connections
```

### 3c. Recovery

**Goal:** Restore systems to normal operation securely.

```
1. Restore from known-good backup (if needed)
2. Rebuild compromised system (if severely affected)
3. Reconnect to network only after verified clean
4. Reset ALL potentially compromised credentials:
   - Affected user passwords
   - Service account passwords
   - API keys
   - If DC compromised: krbtgt reset (twice, 10 hours apart)
5. Monitor intensively post-recovery:
   - Increased logging verbosity
   - More frequent threat hunting
   - Extra alert sensitivity for 30 days
6. Verify services restored and business operations normal
```

---

## Phase 4: Post-Incident Activity

**Goal:** Learn from the incident to prevent recurrence.

### Lessons Learned Meeting
- Conduct within 2 weeks of incident closure
- Attendees: SOC team, IT, management, affected stakeholders
- Cover: timeline, what went well, what could improve, action items

### Post-Incident Report Template
```markdown
# Incident Report: [INC-YYYY-MMDD-NNNN]

## Executive Summary
[2-3 sentence non-technical summary for management]

## Incident Timeline
| Time (UTC) | Event |
|-----------|-------|
| | |

## Root Cause Analysis
- Initial Vector:
- Contributing Factors:
- Why It Wasn't Caught Earlier:

## Impact Assessment
- Systems Affected:
- Data Affected:
- Business Impact:
- Estimated Cost:

## Containment & Remediation Actions
- 
- 

## Indicators of Compromise (IOCs)
- IPs:
- Hashes:
- Domains:
- File Paths:

## Recommendations
1. 
2. 

## Lessons Learned
- What went well:
- What could improve:
- Action items with owners and due dates:
```

---

## Evidence Handling

### Order of Volatility (Collect Most Volatile First)
```
1. CPU registers, cache
2. RAM (memory)           ← Volatile — lost on reboot
3. Running processes
4. Network connections (netstat)
5. ARP cache, routing table
6. Temp files, swap space
7. Disk (hard drive)      ← Persistent
8. Remote logs
9. Physical media backups
```

### Evidence Collection Rules
- **Never modify original evidence** — work on copies
- **Hash everything** (SHA-256) before and after collection
- **Chain of custody** document for all evidence
- **Use write blockers** for disk acquisition
- **Document your actions** with timestamps
- **Maintain integrity** — every tool you run modifies the system

### Memory Acquisition Commands
```powershell
# Windows - DumpIt (third party, most reliable)
.\DumpIt.exe /O memory.raw

# Windows - winpmem
winpmem_x64.exe memory.raw

# Windows - Task Manager (quick, less complete)
# Right-click lsass → Create dump file (captures lsass only)

# Linux - dd
dd if=/dev/mem of=/tmp/memory.raw bs=1M

# Linux - LiME module (best option)
insmod lime.ko "path=/tmp/memory.lime format=lime"
```

---

## Incident Communication Templates

### Initial Notification (Management)
```
Subject: Security Incident Detected - [SEVERITY]

A [SEVERITY] security incident has been detected at [TIME UTC].

Type: [Malware/Brute Force/Data Exfiltration/etc.]
Affected System(s): [List]
Current Status: [Investigating/Contained/In Recovery]
Impact: [Known impact so far]
Next Update: [Time of next update]

IR Team Lead: [Name]
```

### Stakeholder Update
```
Incident Update - [INC-ID] - [Time]

Status: [Investigating/Contained/Eradicated/Recovered]
New Findings: [Brief summary]
Actions Taken: [What was done since last update]
Next Steps: [What's happening next]
ETA to Resolution: [Estimate if known]
```

---

## SOC L1 vs L2 Responsibilities in IR

| Task | L1 | L2 |
|------|----|----|
| Initial alert triage | ✅ Primary | Reviews escalations |
| Basic enrichment | ✅ Primary | Deeper enrichment |
| Ticket creation & updates | ✅ Primary | ✅ Adds analysis |
| Host isolation | With L2 approval | ✅ Primary |
| Deep malware analysis | ❌ | ✅ Primary |
| Forensic evidence collection | ❌ | ✅ Primary |
| Threat hunting | ❌ | ✅ Primary |
| Root cause analysis | ❌ | ✅ Primary |
| IR report writing | ❌ | ✅ Primary |
| Stakeholder communication | ❌ | ✅ Primary |

---

## Related Notes
- [[SOC L1 Survival Guide\|SOC L1 Survival Guide]]
- [[Brute Force Playbook\|Brute Force Playbook]]
- [[Malware on Endpoint Playbook\|Malware on Endpoint Playbook]]
- [[Phishing Playbook\|Phishing Playbook]]
- [[RDP Brute Force Playbook\|RDP Brute Force Playbook]]
- [[Forensics Basics\|Forensics Basics]]
- [[MITRE ATT&CK Overview\|MITRE ATT&CK Overview]]
