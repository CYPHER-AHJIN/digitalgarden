---
{"dg-publish":true,"permalink":"/soc-l1-complete-knowledge-base/05-siem/siem-overview-splunk-elk/"}
---

# SIEM Overview — Splunk & ELK
#SIEM #Splunk #ELK #Detection #Queries

---

## What is a SIEM?

A **Security Information and Event Management (SIEM)** system collects, normalizes, correlates, and stores log data from across your environment. It is the central nervous system of a SOC.

**Why it matters:** Without a SIEM, analysts would need to log into every system individually to check logs. The SIEM brings everything into one place, enables correlation across systems, and powers automated alerting.

---

## SIEM Architecture

```
Data Sources
├── Windows Event Logs (via WinRM/Agent)
├── Linux Syslog (via Syslog/Agent)
├── Firewall Logs (via Syslog/API)
├── EDR (via API)
├── Cloud Logs (AWS CloudTrail, Azure Activity Logs)
├── Email Logs
├── Proxy/Web Logs
└── Network Devices

       ↓ (Log Forwarding)

Log Aggregator / Indexer
├── Parse & normalize fields
├── Apply timestamps
└── Index for search

       ↓

SIEM Platform (Splunk/ELK/Sentinel/QRadar)
├── Search & Query Engine
├── Correlation Rules (Alert Logic)
├── Dashboards
├── Case Management
└── Threat Intelligence Integration
```

---

## Splunk

### Core Concepts

**Index:** Storage partition. Logs are written to indexes. You always specify the index in queries.
```
index=windows   → Windows event logs
index=linux     → Linux syslog
index=firewall  → Firewall logs
index=web       → Web server logs
```

**Source:** The originating file or input
```
source=/var/log/auth.log
source=WinEventLog:Security
```

**Sourcetype:** The log format template for parsing
```
sourcetype=WinEventLog:Security
sourcetype=syslog
sourcetype=access_combined (Apache)
```

**Host:** The machine that generated the log

**Time:** Splunk's powerful time-picker. Always specify time range to avoid slow queries.

---

### Splunk Search Language (SPL) — Essential Queries

#### Basic Search Syntax
```spl
# Search keyword across all indexes
error

# Search specific index
index=windows error

# Search specific field value
index=windows EventCode=4625

# Search multiple values
index=windows EventCode IN (4624, 4625, 4648)

# Wildcard search
index=windows User="admin*"

# Time range
index=windows earliest=-24h latest=now

# Pipe to command
index=windows EventCode=4625 | stats count by User
```

#### stats — Aggregation
```spl
# Count events by field
index=windows EventCode=4625 | stats count by src_ip

# Count with multiple groupings
index=windows EventCode=4625 | stats count by src_ip, User, Computer

# Count distinct values
index=windows | stats dc(User) as unique_users by Computer

# Average, min, max
index=proxy | stats avg(bytes) as avg_bytes, max(bytes) as max_bytes by src_ip

# Multiple stats functions
index=windows EventCode=4625 
| stats count as failures, dc(src_ip) as unique_ips by User
```

#### timechart — Time-Based Analysis
```spl
# Events over time
index=windows EventCode=4625 | timechart count

# Events by source over time
index=windows EventCode=4625 | timechart count by src_ip

# Span control
index=firewall | timechart span=1h count by action
```

#### eval — Field Creation
```spl
# Create new field
index=proxy | eval size_mb = bytes / 1024 / 1024

# Conditional field
index=windows EventCode=4624 
| eval logon_type_name = case(
    Logon_Type="2", "Interactive",
    Logon_Type="3", "Network",
    Logon_Type="10", "RemoteInteractive (RDP)",
    true(), "Other"
)

# String manipulation
index=proxy | eval domain = replace(url, "https?://([^/]+).*", "\1")
```

#### where — Filter Results
```spl
# Numeric comparison
index=proxy | stats sum(bytes) as total_bytes by src_ip | where total_bytes > 1000000000

# String comparison
index=windows | where match(CommandLine, "(?i)mimikatz")

# Multiple conditions
index=proxy | stats count by src_ip | where count > 100 AND count < 1000
```

#### table / rename / fields
```spl
# Select specific fields
index=windows EventCode=4624 | table _time, Computer, User, src_ip, Logon_Type

# Rename fields
index=windows | rename EventCode as "Event ID", Computer as "Hostname"

# Remove unwanted fields
index=windows | fields - _raw, punct
```

#### lookup — Threat Intelligence Integration
```spl
# IP reputation lookup
index=firewall dest_ip=* 
| lookup threat_intel_ips ip AS dest_ip OUTPUT category, confidence
| where isnotnull(category)

# User lookup (HR data)
index=windows EventCode=4624 
| lookup users_list username AS User OUTPUT department, title, manager
```

#### transaction — Session/Timeline Analysis
```spl
# Group events into sessions by IP
index=windows EventCode IN (4624, 4625, 4634)
| transaction src_ip maxspan=1h
| table _time, src_ip, EventCode, duration, eventcount
```

---

### Essential Splunk Detection Queries

#### Brute Force Detection
```spl
index=wineventlog EventCode=4625
| bucket _time span=5m
| stats count as failures by _time, src_ip, TargetUserName
| where failures > 10
| sort -failures
```

#### Suspicious PowerShell
```spl
index=sysmon OR index=wineventlog EventCode=4104 OR EventCode=1
| search Image="*powershell*" OR ScriptBlockText="*powershell*"
| search "*-enc*" OR "*IEX*" OR "*Invoke-Expression*" OR "*DownloadString*" OR "*bypass*"
| table _time, Computer, User, CommandLine, ScriptBlockText
```

#### New Local Admin Account
```spl
index=wineventlog EventCode=4720 OR EventCode=4732
| eval event_type = if(EventCode=4720, "Account Created", "Added to Group")
| table _time, event_type, SubjectUserName, TargetUserName, GroupName, Computer
```

#### Large Data Exfiltration
```spl
index=proxy
| stats sum(bytes_out) as total_out by src_ip, dest_domain
| eval total_gb = round(total_out/1073741824, 2)
| where total_gb > 1
| sort -total_gb
```

#### C2 Beaconing
```spl
index=proxy
| stats count, min(_time) as first, max(_time) as last, avg(bytes_out) as avg_bytes, stdev(bytes_out) as stdev_bytes 
  by src_ip, dest_domain
| eval duration_min = round((last - first)/60, 0)
| eval interval = round(duration_min/count, 1)
| where count > 20 AND stdev_bytes < 200 AND interval > 0 AND interval < 60
| sort -count
```

#### Lateral Movement Detection
```spl
index=wineventlog EventCode=4624 Logon_Type=3
| stats dc(Computer) as unique_hosts, values(Computer) as hosts by User, src_ip
| where unique_hosts > 3
| sort -unique_hosts
```

#### Scheduled Task Creation
```spl
index=wineventlog EventCode=4698
| rex field=TaskContent "<Command>(?P<command>[^<]+)</Command>"
| eval suspicious = if(match(command, "(?i)powershell|cmd|wscript|mshta|regsvr32|certutil"), 1, 0)
| where suspicious=1
| table _time, Computer, SubjectUserName, TaskName, command
```

---

## ELK Stack (Elasticsearch, Logstash, Kibana)

### Architecture
```
Log Sources → Filebeat/Winlogbeat → Logstash (parse/enrich) → Elasticsearch (index/store) → Kibana (visualize/query)
```

**Components:**
- **Elasticsearch:** Distributed search/analytics engine (stores data)
- **Logstash:** Data pipeline (parse, transform, enrich logs)
- **Kibana:** Web UI for search, dashboards, alerting
- **Beats:** Lightweight data shippers (Filebeat, Winlogbeat, Packetbeat)

---

### KQL (Kibana Query Language)

```kql
# Simple field search
event.code: "4625"

# Multiple values
event.code: ("4624" or "4625" or "4648")

# Range query
event.created >= "2024-01-01" and event.created <= "2024-01-02"

# Wildcard
user.name: admin*

# NOT
not event.code: "4624"

# AND/OR
event.code: "4625" and source.ip: "192.168.1.100"

# Field exists
source.ip: *

# Nested field
winlog.event_data.TargetUserName: "administrator"

# Phrase search
message: "Failed password for"

# Regex (expensive - use sparingly)
event.code: /464[0-9]/
```

---

### Elasticsearch Query DSL (JSON)

```json
// Search for failed logins
{
  "query": {
    "bool": {
      "must": [
        {"term": {"event.code": "4625"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "aggs": {
    "by_ip": {
      "terms": {"field": "source.ip", "size": 10}
    }
  }
}
```

---

### Elastic Security / SIEM Module

**Detection Rules in Elastic:** Written in EQL (Event Query Language)

```eql
// Suspicious parent-child process (EQL)
sequence by host.name
  [process where event.type == "start" and
   process.name in ("winword.exe", "excel.exe", "outlook.exe")]
  [process where event.type == "start" and
   process.name in ("cmd.exe", "powershell.exe", "wscript.exe")]
```

```eql
// Mimikatz-style lsass access
process where event.type == "start" and
  process.pe.original_file_name == "mimikatz.exe"

// Or behavior-based:
// (Use Sysmon EventID 10 in Elastic)
```

---

## SIEM Alert Tuning Strategy

### The FP Spiral Problem
Too many false positives → Analysts get alert fatigue → Real alerts get missed → Breach

### Tuning Process
```
1. Identify high-FP rule
2. Analyze what's causing FPs
3. Add exclusions (whitelist known-good):
   - Internal scanner IPs
   - Service accounts doing legitimate auth
   - Software update processes
4. Add thresholds (alert only if count > N)
5. Add time windows (alert only outside business hours)
6. Validate: Run rule for 1 week, check FP rate
7. Document exclusions with justification
```

### Example Tuning - Brute Force Rule
```spl
# Before tuning (too many FPs)
index=wineventlog EventCode=4625 | stats count by src_ip | where count > 5

# After tuning
index=wineventlog EventCode=4625
| search NOT src_ip IN ("10.0.0.10","10.0.0.11")  # Exclude known scanners
| search NOT TargetUserName IN ("svc_backup","svc_monitoring")  # Exclude service accounts
| bucket _time span=5m
| stats count by _time, src_ip, TargetUserName
| where count > 15  # Raised threshold
```

---

## Common SIEM Use Cases

| Use Case | Log Sources | Detection Logic |
|----------|------------|----------------|
| Brute Force | Auth logs | > N failures in time window |
| C2 Beaconing | Proxy/DNS | Regular intervals, low byte variance |
| Data Exfiltration | Proxy, DLP | Large outbound transfers |
| Lateral Movement | Windows Auth | Auth from N hosts by same user |
| Privilege Escalation | Windows Security | Group modification events |
| Malware Execution | EDR, Sysmon | Suspicious process chains |
| Phishing | Email gateway | Malicious attachment/link clicked |
| Insider Threat | UEBA | Abnormal data access patterns |

---

## Related Notes
- [[Windows Event Logs\|Windows Event Logs]]
- [[Detection Engineering\|Detection Engineering]]
- [[Sigma Rules\|Sigma Rules]]
- [[Splunk Labs\|Splunk Labs]]
- [[Incident Response Lifecycle\|Incident Response Lifecycle]]
