---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/01-soc-foundations/soc-l1-survival-guide/","dgPassFrontmatter":true}
---

# SOC L1 Survival Guide
#SOC #BlueTeam #Foundations

> "Your job is not to panic. Your job is to triage, document, and escalate with precision."

---

## 🧭 What is a SOC?

A **Security Operations Center (SOC)** is the centralized team responsible for monitoring, detecting, analyzing, and responding to cybersecurity incidents. The SOC is the frontline defense of an organization.

**Why it matters in real SOC:**
Every alert, every log, every anomaly passes through the SOC before any response happens. L1 Analysts are the gatekeepers — miss something critical and an incident becomes a breach.

---

## 🔄 Daily SOC Workflow

### Shift Start (First 15 Minutes)
1. **Log into all platforms**: SIEM (Splunk/ELK), ticketing (ServiceNow/Jira), threat intel feeds
2. **Read shift handover notes**: What was the previous shift working on? Any open incidents?
3. **Check SIEM dashboard**: Any high-severity alerts fired overnight?
4. **Check email/Slack for escalations** from management or other teams
5. **Review open tickets** assigned to you — status, age, priority

### Core Daily Cycle
```
Alert Fires in SIEM
       ↓
L1 Analyst Triages (Is this real or FP?)
       ↓
Investigate using enrichment tools (VT, AbuseIPDB, MISP)
       ↓
Document findings in ticket
       ↓
Escalate to L2 (if confirmed TTP) OR Close as FP (with justification)
       ↓
Update SIEM tuning notes if FP is recurring
```

### Alert Triage Priority
| Severity | Response Time | Examples |
|----------|--------------|---------|
| Critical | Immediate (<15 min) | Active ransomware, confirmed data exfil, admin account compromise |
| High | <1 hour | Lateral movement, new persistence mechanism, malware detected |
| Medium | <4 hours | Suspicious PowerShell, brute force attempts, unusual login |
| Low | <24 hours | Policy violations, single failed login, recon activity |
| Informational | As time permits | Successful VPN login from new country |

---

## 🎫 Ticket Handling Structure

### Ticket Template
```
TICKET ID: SOC-YYYY-MMDD-NNNN
DATE/TIME: 
ANALYST: 
SEVERITY: Critical / High / Medium / Low

=== ALERT SUMMARY ===
Alert Name: 
SIEM Rule: 
Source System: 
Affected Asset(s): 
User(s) Involved: 

=== TIMELINE ===
[HH:MM UTC] - Event description
[HH:MM UTC] - Investigation step taken
[HH:MM UTC] - Finding

=== INVESTIGATION NOTES ===
Initial Finding:
Enrichment (VT/AbuseIPDB/etc):
Log Evidence:
  - [Paste relevant log snippets with timestamps]
IOCs Identified:
  - IPs: 
  - Hashes: 
  - Domains: 
  - File paths: 

=== VERDICT ===
[ ] True Positive - Escalating to L2
[ ] False Positive - Closing (Reason: )
[ ] Benign True Positive - No action needed (Reason: )

=== ACTIONS TAKEN ===
- 
- 

=== ESCALATION NOTES ===
Escalated to: 
Time of Escalation: 
Method: (Slack/Phone/Email/Ticket)
```

---

## 📈 Escalation Criteria

**Escalate to L2 IMMEDIATELY when:**
- Active malware execution confirmed on any endpoint
- Admin/privileged account compromise detected
- Lateral movement between hosts observed
- Data exfiltration indicators (large outbound transfers, DNS tunneling)
- Ransomware behavior (mass file encryption, shadow copy deletion)
- APT-level TTPs identified (living-off-the-land, multi-stage attack)
- Attack targeting critical infrastructure (AD, backup servers, firewalls)
- Incident scope exceeds 3+ affected hosts
- C2 communication confirmed

**Do NOT escalate for:**
- Known scanner IPs hitting your perimeter (verify against allowlist)
- Single failed login from a valid user
- Dev/pentest team activity (verify with change management)
- Recurring false positives (tune the rule instead)

---

## 🔄 Shift Handover Template

```
=== SHIFT HANDOVER REPORT ===
Date: 
Outgoing Analyst: 
Incoming Analyst: 
Shift Period: [START TIME] - [END TIME] UTC

=== OPEN INCIDENTS (REQUIRES IMMEDIATE ATTENTION) ===
1. [Ticket ID] - [Brief description] - [Current status] - [Next steps]

=== COMPLETED DURING SHIFT ===
- Tickets closed: [IDs]
- Tickets escalated: [IDs]
- Alerts reviewed: [Count]
- True positives: [Count]
- False positives: [Count]

=== ONGOING INVESTIGATIONS ===
[Ticket ID]: [Status and what still needs to be done]

=== THREAT INTEL UPDATES ===
- New IOCs added to blocklist: [Count]
- Active campaigns observed: 
- Threat actor TTPs seen today:

=== SIEM/TOOL ISSUES ===
- [Any platform outages, gaps in logging, forwarding issues]

=== TUNING RECOMMENDATIONS ===
- [Rules generating too many FPs - needs tuning]

=== NOTES FOR INCOMING ANALYST ===
- 
```

---

## 🧠 Investigation Mental Models

### The 5 W's of Alert Investigation
1. **Who** - Which user/system generated this?
2. **What** - What exactly happened? (Process, command, connection)
3. **When** - Timestamp — normal business hours or 2 AM?
4. **Where** - Source/dest IP, hostname, file path
5. **Why** - Does this behavior make sense for this user/system?

### Analyst Mindset
- **Assume breach mentality**: Don't look for reasons it's fine. Look for evidence of compromise.
- **Context is king**: `cmd.exe` spawning is normal. `Word.exe` spawning `cmd.exe` is not.
- **Chain the events**: One alert is rarely the whole story. Look before and after.
- **Think attacker**: If you were attacking, what would this behavior enable?

---

## 📋 Common L1 Tasks

| Task | Tool | Frequency |
|------|------|-----------|
| Alert triage | SIEM | Constant |
| IP reputation lookup | VirusTotal, AbuseIPDB | Per alert |
| Hash lookup | VirusTotal, MalwareBazaar | Malware alerts |
| Log analysis | Splunk/ELK | Daily |
| Ticket updates | ServiceNow/Jira | Every investigation |
| Threat intel check | MISP, OpenCTI | Daily |
| Vulnerability verification | Tenable/Qualys | Weekly |
| Report writing | Word/Confluence | Weekly |

---

## 🔗 Related Notes
- [[SOC Fundamentals\|SOC Fundamentals]]
- [[SIEM Overview\|SIEM Overview]]
- [[Incident Response Lifecycle\|Incident Response Lifecycle]]
- [[Alert Triage Process\|Alert Triage Process]]
- [[Escalation Playbook\|Escalation Playbook]]
- [[Windows Event Logs\|Windows Event Logs]]
- [[Linux Logs\|Linux Logs]]
