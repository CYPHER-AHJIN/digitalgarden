---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/15-ids-ips/ids-ips/","dgPassFrontmatter":true}
---

# IDS/IPS Fundamentals
#IDS #IPS #Snort #Suricata #NetworkDetection #SOC

---

## What is IDS/IPS?

- **IDS (Intrusion Detection System):** Monitors network traffic and ALERTS on suspicious activity. Passive — does not block traffic.
- **IPS (Intrusion Prevention System):** Monitors AND BLOCKS suspicious traffic inline. Active.

**Why it matters in real SOC:** IDS/IPS alerts are a primary alert source alongside SIEM. Understanding how rules work helps you tune alerts, reduce false positives, and write custom detections.

---

## IDS vs IPS Deployment

```
IDS — Passive (Mirror/TAP port):
Traffic → Switch (port mirror) → IDS sensor
                ↓
           Alerts only, traffic continues

IPS — Inline (Block capable):
Traffic → IPS → Router/Firewall
               ↓
          Can drop malicious traffic
```

### Detection Methods

| Method | How It Works | Pros | Cons |
|--------|-------------|------|------|
| Signature-based | Match known attack patterns | Fast, low FP for known threats | Misses zero-days, evasion by encoding |
| Anomaly-based | Baseline normal, alert on deviation | Catches novel attacks | High FP until baseline established |
| Policy-based | Enforce defined rules (block FTP) | Simple, predictable | Doesn't catch unknown attacks |
| Reputation-based | Block known-bad IPs/domains | Easy wins | IPs change, shared infrastructure FPs |

---

## Snort — Open Source NIDS

Snort is the most widely used open source IDS/IPS. Understanding Snort rules is essential for understanding how network detections work.

### Snort Rule Structure
```
[action] [protocol] [src_ip] [src_port] -> [dst_ip] [dst_port] (options)
```

### Rule Actions
```
alert    → Generate alert and log
log      → Log only (no alert)
pass     → Ignore (whitelist)
drop     → Block AND alert (IPS mode)
reject   → Block + send TCP RST/ICMP unreachable
sdrop    → Block silently
```

### Snort Rule Examples
```
# Alert on any ICMP traffic (ping detection)
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping detected"; sid:1000001; rev:1;)

# Alert on Nmap SYN scan
alert tcp any any -> $HOME_NET any (msg:"Nmap SYN Scan"; flags:S; threshold:type threshold, track by_src, count 20, seconds 5; sid:1000002;)

# Alert on SQL injection attempt
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; content:"' OR '1'='1"; nocase; sid:1000003;)

# Alert on PowerShell download cradle
alert tcp $HOME_NET any -> any any (msg:"PowerShell DownloadString"; content:"DownloadString"; nocase; content:"powershell"; nocase; sid:1000004;)

# Alert on Cobalt Strike default beacon (check-in path)
alert http $HOME_NET any -> any any (msg:"Cobalt Strike Beacon Checkin"; http.uri; content:"/dpixel"; sid:1000005;)
```

### Snort Rule Option Keywords
```
# Content matching:
content:"string"         → Match exact string
content:"|41 42 43|"    → Match hex bytes
nocase                  → Case insensitive
offset:5                → Start matching at byte 5
depth:10                → Match within 10 bytes from offset

# Protocol-specific:
http.uri               → Match in HTTP URI
http.header            → Match in HTTP header
http.method            → Match HTTP method
pcre:"/regex/i"        → Perl-compatible regex (expensive)

# Flow control:
flow:established        → Only established connections
flow:to_server          → Client to server
flow:from_server        → Server to client

# Thresholding:
threshold:type limit, track by_src, count 5, seconds 60  → Alert max 5 times/min per src
threshold:type threshold, track by_src, count 10, seconds 60 → Alert every 10th event
threshold:type both, track by_src, count 5, seconds 60  → Suppress if <5, then alert

# Metadata:
msg:"Alert message"     → Human-readable description
sid:1000001             → Signature ID (custom rules > 1,000,000)
rev:1                   → Revision number
classtype:trojan-activity
reference:url,attack.mitre.org/techniques/T1059
```

### Snort Commands
```bash
# Test configuration
snort -T -c /etc/snort/snort.conf

# Run in detection mode on interface
snort -c /etc/snort/snort.conf -i eth0

# Run on pcap file (offline analysis)
snort -c /etc/snort/snort.conf -r capture.pcap -A console

# List rules
cat /etc/snort/rules/local.rules

# Run with custom rule
snort -c snort.conf --rule 'alert icmp any any -> any any (msg:"Test"; sid:999;)' -i eth0

# Verbose output
snort -v -i eth0
```

---

## Suricata — Modern IDS/IPS

Suricata is the modern replacement for Snort with better performance and multi-threading.

### Suricata vs Snort
| Feature | Snort | Suricata |
|---------|-------|---------|
| Multi-threading | No | Yes |
| Performance | Good | Better |
| Rule format | Snort rules | Snort-compatible + extra |
| Output | Text | JSON (EVE format) |
| Protocol support | Basic | App-layer protocols |
| Lua scripting | No | Yes |

### Suricata EVE JSON Log
Suricata outputs structured JSON — much easier for SIEM ingestion.

```json
{
  "timestamp": "2024-01-15T02:31:42.000000+0000",
  "event_type": "alert",
  "src_ip": "185.220.101.1",
  "src_port": 54321,
  "dest_ip": "10.0.0.100",
  "dest_port": 443,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2025001,
    "rev": 1,
    "signature": "ET MALWARE Cobalt Strike Malleable C2 Profile",
    "category": "Malware Command and Control Activity Detected",
    "severity": 1
  },
  "http": {
    "hostname": "evil-c2.com",
    "url": "/api/v1/check",
    "http_user_agent": "Mozilla/5.0"
  }
}
```

### Suricata Commands
```bash
# Test config
suricata -T -c /etc/suricata/suricata.yaml

# Run on interface
suricata -c /etc/suricata/suricata.yaml -i eth0

# Run on pcap
suricata -c /etc/suricata/suricata.yaml -r capture.pcap

# EVE log location
tail -f /var/log/suricata/eve.json | python3 -m json.tool

# Update rules (Suricata-update)
suricata-update
suricata-update update-sources
suricata-update list-sources
```

### Custom Suricata Rule Example
```
# Detect DNS query to known C2 domain
alert dns any any -> any any (msg:"Known C2 Domain Query"; dns.query; content:"evil-c2.com"; nocase; sid:9000001; rev:1; metadata:affected_product Any, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, tag C2;)

# Detect large DNS query (potential DNS tunneling)
alert dns any any -> any 53 (msg:"Possible DNS Tunneling - Long Query"; dns.query; pcre:"/[a-z0-9]{50,}/i"; sid:9000002; rev:1;)

# Detect Nmap OS detection probe
alert tcp any any -> $HOME_NET any (msg:"Nmap OS Detection"; flags:SFPU; sid:9000003; rev:1;)
```

---

## SIEM Integration of IDS/IPS Alerts

### Splunk Query for IDS Alerts
```spl
-- Top triggered signatures
index=ids
| stats count by signature, src_ip, dest_ip
| sort -count | head 20

-- High severity alerts
index=ids severity=1 OR priority=high
| table _time, src_ip, dest_ip, signature, category

-- Malware C2 traffic
index=ids category IN ("Malware Command and Control","Trojan Activity")
| table _time, src_ip, dest_ip, signature

-- Correlate IDS alert with firewall allow (did it get through?)
index=ids [search index=firewall action=allowed | rename src_ip AS src_ip | return src_ip]
| table _time, src_ip, dest_ip, signature

-- Alert volume over time (spike detection)
index=ids | timechart span=1h count by category
```

---

## IDS/IPS Tuning — Reducing Alert Fatigue

```
High FP sources:
1. Vulnerability scanners → Add scanner IPs to passlist
2. Penetration tests → Coordinate and suppress during tests
3. Monitoring agents (Nagios, Zabbix) → Passlist their traffic
4. Business application fingerprints → Custom suppress rules

Tuning approach:
1. Identify high-volume, low-fidelity rules
2. Check if they generate real incidents (TPs)
3. If FP rate > 80%: Suppress or tune
4. Add context (only alert if src_ip is NOT in scanner_whitelist)
5. Document every suppression decision
```

### Snort/Suricata Suppression
```
# Suricata suppression.rules
suppress gen_id 1, sig_id 2016716, track by_src, ip 10.0.0.10/32
# Suppress Qualys scanner

suppress gen_id 1, sig_id 2100366, track by_dst, ip 192.168.0.0/24
# Suppress internal scanning to internal nets
```

---

## Emerging Threats / Community Rule Sources

| Source | URL | Description |
|--------|-----|-------------|
| Emerging Threats | rules.emergingthreats.net | Free Suricata/Snort rules (ET Open) |
| Snort Community | snort.org/downloads | Official Snort rules |
| PTRS | github.com/ptresearch | ProofPoint Emerging Threats |
| Cisco Talos | talos-intelligence.com | Commercial rules |

```bash
# Install ET Open for Suricata:
suricata-update add-source et/open
suricata-update update
```

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/08_Detection_Engineering/Detection_Engineering\|Detection_Engineering]]
- [[SOC_L1_Complete_Knowledge_Base/02_Networking/Networking_Fundamentals\|Networking_Fundamentals]]
- [[SOC_L1_Complete_Knowledge_Base/05_SIEM/SIEM_Overview_Splunk_ELK\|SIEM_Overview_Splunk_ELK]]
- [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/SOC_Investigation_Playbooks\|SOC_Investigation_Playbooks]]
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/Cyber_Kill_Chain\|Cyber_Kill_Chain]]
