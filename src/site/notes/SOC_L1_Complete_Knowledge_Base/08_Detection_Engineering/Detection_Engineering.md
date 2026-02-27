---
{"dg-publish":true,"permalink":"/soc-l1-complete-knowledge-base/08-detection-engineering/detection-engineering/"}
---

# Detection Engineering
#Detection #Sigma #Splunk #KQL #SIEM #Rules

---

## What is Detection Engineering?

Detection Engineering is the practice of designing, building, testing, and maintaining detection logic — the rules and queries that convert raw log data into actionable security alerts.

**Why it matters:** SOC L1 uses detections built by Detection Engineers. Understanding how they work helps you tune, troubleshoot, and eventually contribute to building them (SOC L2+).

---

## Detection Types

### Signature-Based
Matches specific, known indicators.
```
File hash = a1b2c3... → Alert
```
**Pros:** Fast, low FP, definitive  
**Cons:** Only catches known threats, trivially evaded by changing the signature

### Threshold-Based  
Alert when a count exceeds a limit.
```
Failed logins > 10 in 5 minutes → Alert
```
**Pros:** Simple, catches volume-based attacks  
**Cons:** Attackers can spread below the threshold (slow spray)

### Behavioral / Anomaly-Based
Alert when behavior deviates from baseline.
```
User normally logs in from US, today login from Russia → Alert
```
**Pros:** Can catch unknown threats, novel TTPs  
**Cons:** High FP rate until baseline is established, complex to tune

### Correlation
Alert when multiple events co-occur.
```
Brute force (4625) + Successful login (4624) from same IP → Alert
```
**Pros:** High fidelity, low FP  
**Cons:** Complex to build, events must arrive in time window

---

## Sigma Rules

Sigma is a **generic signature format for SIEM systems**. Write once, convert to Splunk/ELK/QRadar/Microsoft Sentinel.

**Website:** https://github.com/SigmaHQ/sigma

### Sigma Rule Structure

```yaml
title: Suspicious PowerShell Encoded Command
id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: test
description: Detects execution of PowerShell with encoded command flags indicating obfuscation
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe
author: SOC Team
date: 2024/01/01
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - '-EC '
    filter_legitimate:
        CommandLine|contains:
            - 'SCCM'
            - 'ConfigMgr'
    condition: selection and not filter_legitimate
fields:
    - CommandLine
    - ParentImage
    - User
falsepositives:
    - Management software using legitimate encoded commands (SCCM, Intune)
    - Developers testing PowerShell features
level: high
```

### Sigma Detection Logic Keywords

```yaml
# Field conditions
CommandLine|contains: 'value'        # Field contains string
CommandLine|contains|all:            # Field contains ALL strings
    - 'string1'
    - 'string2'
CommandLine|contains|any:            # Field contains ANY string
    - 'string1'
    - 'string2'
CommandLine|startswith: 'C:\Windows' # Field starts with
CommandLine|endswith: '.exe'          # Field ends with
CommandLine|re: '.*evil.*'            # Regex match

Image: 'C:\Windows\System32\cmd.exe'  # Exact match
Image|endswith: '\cmd.exe'            # Endswith (handles path variations)

# Condition logic
condition: selection                  # Match selection
condition: selection and filter       # Must match selection, not filter
condition: selection1 or selection2   # Either selection
condition: not filter                 # NOT filter
condition: 1 of selection*            # 1 of multiple selections named selection_*
condition: all of selection*          # All of multiple selections

# Aggregation (for threshold rules)
condition: selection | count() by Image > 5        # Count events
condition: selection | count(CommandLine) by User > 10
```

### Real-World Sigma Examples

**Mimikatz Detection:**
```yaml
title: Mimikatz-like LSASS Access
id: a5b6c7d8-e9f0-1a2b-3c4d-5e6f7a8b9c0d
description: Detects LSASS process access with specific access rights used by Mimikatz
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x147a'
            - '0x1418'
    filter_legitimate:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Program Files\'
    condition: selection and not filter_legitimate
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
```

**Scheduled Task with Encoded Command:**
```yaml
title: Scheduled Task with Encoded PowerShell Command
logsource:
    product: windows
    service: security
detection:
    selection_event:
        EventID: 4698
    selection_content:
        TaskContent|contains:
            - 'powershell'
            - '-enc'
            - '-EncodedCommand'
    condition: selection_event and selection_content
level: high
tags:
    - attack.persistence
    - attack.t1053.005
```

### Converting Sigma to Splunk
```bash
# Using sigma-cli (modern tool)
pip install sigma-cli
sigma convert -t splunk -p sysmon rule.yml

# Output: Splunk SPL query
# source="WinEventLog:*" EventCode=1 (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *")
```

---

## Log Correlation Logic

### Time-Based Correlation
Alert when events occur in sequence within a time window.

```spl
# Brute force followed by success
| eval is_failure = if(EventCode=4625, 1, 0)
| eval is_success = if(EventCode=4624, 1, 0)

# Use transaction to group by source IP
| transaction src_ip maxspan=10m
| where mvcount(mvfilter(match(EventCode, "4625"))) > 5 
    AND mvcount(mvfilter(match(EventCode, "4624"))) > 0
```

### Sequence Correlation (Elastic EQL)
```eql
sequence by host.name with maxspan=5m
  [process where process.name == "winword.exe"]
  [process where process.parent.name == "winword.exe" 
     and process.name in ("cmd.exe", "powershell.exe")]
  [network where process.parent.name in ("cmd.exe", "powershell.exe")]
```

### Multi-Source Correlation
Correlate events across different log sources for higher confidence.

```spl
# Phishing correlation: email opened + URL visited + process spawned
[search index=email attachment_opened=true earliest=-1h | rename src_ip as workstation_ip]
[search index=proxy url="*suspicious_domain*" earliest=-1h | rename src_ip as workstation_ip]
[search index=sysmon EventCode=1 ParentImage="*outlook*" earliest=-1h]
| stats count by workstation_ip
| where count >= 2
```

---

## Alert Tuning Strategy

### The False Positive Life Cycle
```
New Rule Created
      ↓
High FP Rate (initial)
      ↓
Analyze FPs — understand why they fire
      ↓
Add exclusions (specific IPs, accounts, processes)
      ↓
Raise threshold (if volumetric rule)
      ↓
Add context (time of day, user group)
      ↓
Validate — run for 1 week, measure FP rate
      ↓
Target: < 10% FP rate for effective rules
```

### Exclusion Strategies

```spl
# Exclude known scanner IPs
| search NOT src_ip IN ("10.0.0.10","10.0.0.11","qualys_ip","nessus_ip")

# Exclude service accounts
| search NOT User IN ("svc_backup","svc_monitoring","svc_deploy")

# Exclude known-good file paths
| search NOT CommandLine IN ("C:\\Program Files\\*","C:\\Windows\\System32\\*")

# Time-based exclusion (only alert outside business hours)
| eval hour = strftime(_time, "%H")
| where hour < 7 OR hour > 19

# Exclude processes signed by trusted certificates
| lookup legitimate_signed_binaries Image AS Image OUTPUT legitimate
| where NOT legitimate="true"
```

### Tuning Documentation Template
```markdown
Rule: [Name]
Date Tuned: 
Analyst: 
Reason for Tuning: [High FP from XYZ]
Exclusion Added: [IP 10.0.0.10 - Qualys scanner]
Risk Assessment: [Exclusion creates minimal risk because Qualys scanner is internal]
Review Date: [Quarterly]
```

---

## Detection Coverage Assessment

### Mapping Detections to MITRE ATT&CK
Use the ATT&CK Navigator to visualize coverage:
https://mitre-attack.github.io/attack-navigator/

**Questions to ask:**
- Which techniques do we have detections for?
- Which critical techniques have NO detection?
- What's our coverage for Initial Access?
- Do we detect every step of lateral movement?

### Coverage Matrix Example

| Tactic | Technique | Detection Rule | Status |
|--------|-----------|---------------|--------|
| Initial Access | T1566.001 Phishing Attachment | Email GW + Endpoint rule | ✅ Covered |
| Execution | T1059.001 PowerShell | PowerShell script block logging rule | ✅ Covered |
| Persistence | T1053.005 Scheduled Task | Event 4698 rule | ✅ Covered |
| Defense Evasion | T1070.001 Log Clearing | Event 1102 rule | ✅ Covered |
| Credential Access | T1003.001 LSASS Dump | Sysmon 10 rule | ✅ Covered |
| Lateral Movement | T1021.001 RDP | Event 4624 type 10 rule | ✅ Covered |
| C2 | T1568.002 DGA | DNS entropy rule | ⚠️ Partial |
| Exfiltration | T1041 C2 Exfil | Proxy volume threshold | ⚠️ Partial |
| Exfiltration | T1048 Alt Protocol | ❌ | ❌ Gap |

---

## Detection Quality Criteria

A good detection rule has:
- **High sensitivity** (catches real attacks) — few False Negatives
- **High specificity** (few false alarms) — few False Positives
- **Mapped to MITRE** — clear technique reference
- **Clear title and description** — anyone can understand what it detects
- **Documented FP cases** — analysts know what legitimate activity looks like
- **Tunable** — can adjust thresholds without rewriting
- **Tested** — validated against lab data before production

---

## Related Notes
- [[SIEM Overview\|SIEM Overview]]
- [[MITRE ATT&CK Overview\|MITRE ATT&CK Overview]]
- [[Sigma Rules\|Sigma Rules]]
- [[Windows Event Logs\|Windows Event Logs]]
- [[Alert Tuning\|Alert Tuning]]
