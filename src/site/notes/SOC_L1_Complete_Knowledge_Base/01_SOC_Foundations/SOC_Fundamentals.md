---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/01-soc-foundations/soc-fundamentals/","dgPassFrontmatter":true}
---

# SOC Fundamentals
#SOC #BlueTeam #Foundations

---

## What is a SOC?

A Security Operations Center (SOC) is a centralized unit that deals with security issues on an organizational and technical level. It combines people, processes, and technology to continuously monitor and improve an organization's security posture.

**Core Mission:** Detect, contain, and eradicate threats before they cause damage.

---

## SOC Tiers

### Tier 1 — Alert Analyst (SOC L1)
- Monitor SIEM alerts in real-time
- Initial triage and classification
- Basic enrichment (IP lookup, hash lookup)
- Document findings, escalate or close
- **You are here**

### Tier 2 — Incident Responder (SOC L2)
- Deep-dive investigation of escalated incidents
- Malware analysis
- Threat hunting
- Forensic analysis
- Containment actions

### Tier 3 — Threat Hunter / SME (SOC L3)
- Proactive threat hunting
- Advanced malware reverse engineering
- Red team collaboration
- Detection engineering
- Attack simulation review

### Supporting Roles
- **SOC Manager**: Oversees operations, metrics, reporting
- **Threat Intelligence Analyst**: Feeds IOCs and context into the SOC
- **Detection Engineer**: Writes and tunes detection rules
- **DFIR Analyst**: Handles post-breach forensic investigations

---

## SOC Metrics (KPIs you'll see in interviews)

| Metric | Definition | Why It Matters |
|--------|-----------|----------------|
| MTTD | Mean Time to Detect | How fast you find breaches |
| MTTR | Mean Time to Respond | How fast you contain/resolve |
| MTTI | Mean Time to Investigate | Alert-to-verdict speed |
| False Positive Rate | % alerts that are not real | High FP = analyst fatigue = missed attacks |
| Alert Volume | Alerts per day per analyst | Capacity planning |
| Dwell Time | Time attacker was undetected | Lower = better |

**Real-world example:** Industry average dwell time is 21 days (Mandiant 2023). Your job is to cut that down.

---

## The CIA Triad

Every security decision maps back to:
- **Confidentiality** — Data visible only to authorized parties
  - Attack: Data theft, credential harvesting
  - Detection: DLP alerts, unusual data access patterns
- **Integrity** — Data is accurate and unmodified
  - Attack: Tampering, SQL injection, file modification
  - Detection: File integrity monitoring, hash comparison
- **Availability** — Systems accessible when needed
  - Attack: DDoS, ransomware, destructive malware
  - Detection: Network anomaly detection, endpoint alerts

---

## Alert Categories

### True Positive (TP)
The alert is real. An attack or policy violation actually occurred.
- Action: Investigate, document, escalate or remediate

### False Positive (FP)
The alert fired but the activity is legitimate.
- Action: Document reason, close ticket, recommend tuning
- Example: AV flags a legitimate pentest tool, or a scanner IP hits your firewall

### True Negative (TN)
No alert, no attack. Normal operations.

### False Negative (FN)
An attack occurred but no alert fired. **This is the most dangerous.**
- Action: Gap analysis, new detection rule needed

---

## The Cyber Kill Chain (Lockheed Martin)
[[Cyber Kill Chain\|Cyber Kill Chain]]

1. **Reconnaissance** — OSINT, scanning
2. **Weaponization** — Malware + exploit combo
3. **Delivery** — Phishing, drive-by, USB
4. **Exploitation** — Code execution on target
5. **Installation** — Persistence mechanism
6. **Command & Control (C2)** — Attacker talks to implant
7. **Actions on Objectives** — Data theft, destruction, lateral movement

**SOC Use:** Map detections to kill chain stages. If you catch Delivery, you prevent Exploitation.

---

## The Diamond Model of Intrusion Analysis

Four core features of every intrusion:
- **Adversary** (who)
- **Infrastructure** (how — IPs, domains, C2)
- **Capability** (what — tools, malware)
- **Victim** (target)

Used for attribution and threat intel correlation.

---

## Common Log Sources in a SOC

| Log Source | Data Provided | Key Use |
|-----------|--------------|---------|
| Windows Event Logs | Auth, process, policy changes | Endpoint detection |
| Syslog (Linux) | Auth, cron, service events | Linux server monitoring |
| Firewall Logs | Allow/deny network flows | Network threat detection |
| Proxy Logs | HTTP/HTTPS web traffic | Web threat detection |
| DNS Logs | Domain lookups | C2, data exfil detection |
| EDR Logs | Process trees, file activity | Endpoint forensics |
| DHCP Logs | IP-to-hostname mapping | Asset tracking |
| VPN Logs | Remote access sessions | Anomalous login detection |
| Email Logs | Sender, recipient, attachments | Phishing analysis |
| WAF Logs | Web application attacks | Web attack detection |

---

## SIEM Architecture (High Level)
[[SIEM Overview\|SIEM Overview]]

```
Log Sources → Log Collector/Agent → SIEM Indexer → SIEM Search Head
                                                           ↓
                                                    Correlation Rules
                                                           ↓
                                                    Alert Generated
                                                           ↓
                                                    Analyst Dashboard
```

---

## Related Notes
- [[SOC L1 Survival Guide\|SOC L1 Survival Guide]]
- [[Cyber Kill Chain\|Cyber Kill Chain]]
- [[MITRE ATT&CK Overview\|MITRE ATT&CK Overview]]
- [[SIEM Overview\|SIEM Overview]]
- [[Windows Event Logs\|Windows Event Logs]]
- [[Incident Response Lifecycle\|Incident Response Lifecycle]]
