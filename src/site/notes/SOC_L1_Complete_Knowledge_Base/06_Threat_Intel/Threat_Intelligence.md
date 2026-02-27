---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/06-threat-intel/threat-intelligence/","dgPassFrontmatter":true}
---

# Threat Intelligence
#ThreatIntel #IOC #MISP #CTI #SOC

---

## What is Threat Intelligence?

Threat Intelligence (TI) is evidence-based knowledge about existing or emerging threats, including context, mechanisms, indicators, implications, and actionable advice. It transforms raw data into actionable insights SOC analysts use to detect, prevent, and respond faster.

**Why it matters in real SOC:** Threat intel feeds your SIEM with known-bad IPs, domains, and hashes. Without it, you're only detecting what your rules explicitly define. With it, you catch attacker infrastructure the moment it touches your network.

---

## Intelligence Types

### Strategic Intelligence
- High-level: "Nation-state actors targeting energy sector"
- Audience: CISO, management
- Timeframe: Months to years
- Source: Mandiant reports, CrowdStrike reports, government advisories

### Operational Intelligence
- Campaign-specific: "APT29 phishing campaign using ISO attachments targeting healthcare"
- Audience: SOC managers, IR team
- Timeframe: Weeks

### Tactical Intelligence
- Specific TTPs: "Threat actor uses T1059.001 with base64 encoding and -nop flag"
- Audience: Detection engineers, threat hunters
- Timeframe: Days to weeks

### Technical Intelligence
- IOCs: IP addresses, domains, hashes, URLs, registry keys
- Audience: SOC L1/L2, SIEM engineers
- Timeframe: Hours to days (can expire quickly)

---

## IOC Types and Lifespan

| IOC Type      | Example                | Lifespan          | Pyramid Level        |
| ------------- | ---------------------- | ----------------- | -------------------- |
| File hash     | SHA256: a3b1c2...      | Hours-Days        | Low (trivial change) |
| IP address    | 185.220.101.x          | Days              | Low                  |
| Domain        | evil-c2.com            | Weeks             | Medium               |
| URL pattern   | /gate.php?id=          | Weeks-Months      | Medium-High          |
| Email subject | "Urgent Invoice"       | Campaign duration | Medium               |
| Mutex         | Global\MalwareMutex123 | Months            | High                 |
| Registry key  | HKCU\...\Run\Updater   | Months            | High                 |
| TTP           | T1059.001 + -nop + IEX | Years             | Highest              |

**Rule:** The higher up the Pyramid of Pain, the longer-lasting and more valuable the intel.

---

## MISP (Malware Information Sharing Platform)

MISP is the open-source threat intelligence platform used in most enterprise SOCs for managing and sharing IOCs.

### Key Concepts
- **Event:** A threat report/incident containing IOCs
- **Attribute:** Individual IOC (IP, hash, domain, URL)
- **Tag:** MITRE technique, TLP classification, threat actor
- **Galaxy:** Structured threat actor/malware profiles
- **Feed:** External IOC feeds ingested automatically

### TLP (Traffic Light Protocol)
| Classification  | Meaning          | Who Can See             |
| --------------- | ---------------- | ----------------------- |
| TLP:RED         | Highly sensitive | Named recipients only   |
| TLP:AMBER       | Restricted       | Organization + partners |
| TLP:GREEN       | Community        | Security community      |
| TLP:WHITE/CLEAR | Public           | Anyone                  |

### MISP API Usage
```python
# Connect and search for IOC
from pymisp import PyMISP

misp = PyMISP('https://your-misp-instance', 'your-api-key', ssl=True)

# Search for an IP
result = misp.search(value='185.220.101.1', type_attribute='ip-dst')

# Search for domain
result = misp.search(value='evil.com', type_attribute='domain')

# Add new IOC to event
event_id = 123
misp.add_attribute(event_id, {
    'type': 'ip-dst',
    'value': '1.2.3.4',
    'to_ids': True,
    'comment': 'C2 IP from IR case INC-2024-001'
})
```

---

## Threat Intelligence Platforms and Sources

### Free Platforms
| Platform        | URL                 | Best For                             |
| --------------- | ------------------- | ------------------------------------ |
| VirusTotal      | virustotal.com      | File/IP/Domain/URL analysis          |
| AbuseIPDB       | abuseipdb.com       | IP reputation with community reports |
| Shodan          | shodan.io           | Internet-exposed assets, banner data |
| Censys          | censys.io           | Certificate/banner data              |
| URLScan.io      | urlscan.io          | Safe URL analysis with screenshots   |
| Any.run         | any.run             | Interactive malware sandbox          |
| MalwareBazaar   | bazaar.abuse.ch     | Malware sample hash lookup           |
| URLhaus         | urlhaus.abuse.ch    | Malicious URLs                       |
| ThreatFox       | threatfox.abuse.ch  | IOCs by threat actor                 |
| OpenCTI         | opencti.io          | Open-source TI platform              |
| AlienVault OTX  | otx.alienvault.com  | Community threat intelligence        |
| Hybrid Analysis | hybrid-analysis.com | Free sandbox analysis                |

### OSINT Techniques
```bash
# Reverse DNS lookup
host 185.220.101.1
dig -x 185.220.101.1

# WHOIS information
whois evil.com
whois 185.220.101.1

# DNS history
# Use: viewdns.info, securitytrails.com

# SSL certificate lookup
# Use: crt.sh, censys.io/certificates
curl "https://crt.sh/?q=evil.com&output=json" | python3 -m json.tool

# ASN lookup (whose infrastructure is this?)
whois -h whois.radb.net 185.220.101.1

# Passive DNS (what domains has this IP hosted?)
# Use: passivedns.mnemonic.no, virustotal.com

# Threat actor lookup
# Use: mitre.org/groups, malpedia, aptgroups.wiki
```

---

## IOC Enrichment Workflow (SOC L1 Process)

```
Alert fires with suspicious IP/domain/hash
         ↓
Step 1: VirusTotal check
  - File hash: Detection ratio, behavioral tags
  - IP: Malicious votes, resolved domains, related files
  - Domain: Malicious votes, registrar, IP history

Step 2: AbuseIPDB (for IPs)
  - Confidence score (> 80% = very likely malicious)
  - Abuse categories (port scan, brute force, C2)
  - Country of origin
  - ISP (AWS/DigitalOcean/Tor = suspicious)

Step 3: Shodan (for IPs)
  - What services is this IP running?
  - Is it a Tor exit node?
  - Has it appeared in prior campaigns?

Step 4: URLScan.io (for URLs/domains)
  - Screenshot of the page
  - What resources did it load?
  - Is it serving malware?

Step 5: ThreatFox/MalwareBazaar (for hashes/domains)
  - What malware family?
  - What threat actor?
  - Related IOCs from same campaign

Step 6: MISP internal
  - Is this IOC in any of our prior incidents?
  - Has another analyst already investigated this?
```

---

## Threat Actor Profiling

### Key Threat Actor Categories
- **APT (Advanced Persistent Threat):** Nation-state sponsored, long-term, stealthy
  - APT29 (Cozy Bear) — Russia, SVR
  - APT41 — China, dual espionage + cybercrime
  - Lazarus Group — North Korea
- **Financially Motivated:** Ransomware groups, BEC, banking trojans
  - Conti, LockBit, ALPHV/BlackCat
- **Hacktivists:** Ideological motivation, DDoS, data leaks
  - Anonymous, KillNet
- **Insider Threat:** Employee or contractor misusing access

### MITRE ATT&CK Groups
Use https://attack.mitre.org/groups/ to:
- Look up which techniques a threat actor uses
- Identify if activity matches known actor TTPs
- Improve detection rules to target specific actors

---

## Threat Intel Integration in SIEM

### Splunk Threat Intel Lookup
```spl
# IP reputation lookup
index=firewall dest_ip=*
| lookup threat_intel_ips ip AS dest_ip OUTPUT category, confidence, threat_actor
| where isnotnull(category)
| table _time, src_ip, dest_ip, category, confidence, threat_actor

# Domain reputation
index=dns query_name=*
| lookup threat_intel_domains domain AS query_name OUTPUT threat_level, malware_family
| where threat_level IN ("malicious","suspicious")
| table _time, src_ip, query_name, threat_level, malware_family

# Hash lookup
index=sysmon EventCode=1
| lookup malware_hashes hash AS SHA256 OUTPUT malware_name, threat_actor
| where isnotnull(malware_name)
```

### ELK Threat Intel Module
```
Elasticsearch has built-in threat intel module:
Stack Management → Security → Threat Intelligence
Supports: AlienVault OTX, MISP, Anomali, custom feeds
```

---

## IOC Decay and Lifecycle Management

IOCs don't last forever. Managing their lifecycle prevents false positives from stale intel.

```
IOC Created (fresh from incident or feed)
    ↓
Active monitoring in SIEM (block + alert)
    ↓
After 30 days: Re-evaluate (is this IP still malicious?)
    ↓
After 90 days: Consider moving to alert-only (not block)
    ↓
After 180 days: Archive (keep for historical hunting only)
    ↓
Retired: Remove from active blocks
```

**Why this matters:** Blocking a legitimate CDN IP because it was once flagged 2 years ago causes business disruption. Set expiry dates on your IOCs.

---

## Hunting with Threat Intel

### Diamond Model Pivoting
When you have one IOC, pivot to find related infrastructure:
```
Known IP → VirusTotal → passive DNS → Related domains → New C2 infrastructure
Known domain → crt.sh → SSL cert → Same cert on other IPs → Expand IOC set
Known hash → MalwareBazaar → Malware family → TTPs → Detection rules
```

### Campaign Tracking Query
```spl
# Find all activity from known threat actor IOC set
index=* 
| where dest_ip IN ("1.2.3.4","5.6.7.8") OR 
       dest_domain IN ("evil.com","c2.evil.net") OR
       SHA256 IN ("abc123...","def456...")
| stats count by src_ip, dest_ip, dest_domain, Computer
| sort -count
```

---

## MITRE ATT&CK Resource Development Techniques
- T1583 — Acquire Infrastructure (C2 servers, domains)
- T1584 — Compromise Infrastructure (hijack legitimate sites)
- T1585 — Establish Accounts (create fake social media)
- T1587 — Develop Capabilities (build malware)
- T1588 — Obtain Capabilities (buy/steal malware)

**Detection opportunity:** Monitor newly registered domains, recently acquired IPs that suddenly appear in your traffic.

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/Pyramid_of_Pain\|Pyramid_of_Pain]]
- [[SOC_L1_Complete_Knowledge_Base/07_MITRE/MITRE_ATTACK_Overview\|MITRE_ATTACK_Overview]]
- [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/SOC_Investigation_Playbooks\|SOC_Investigation_Playbooks]]
- [[SOC_L1_Complete_Knowledge_Base/08_Detection_Engineering/Detection_Engineering\|Detection_Engineering]]
- [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/Incident_Response_Lifecycle\|Incident_Response_Lifecycle]]
