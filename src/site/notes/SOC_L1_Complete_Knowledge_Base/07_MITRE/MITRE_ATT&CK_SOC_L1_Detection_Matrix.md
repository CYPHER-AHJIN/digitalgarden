---
{"dg-publish":true,"permalink":"/soc-l1-complete-knowledge-base/07-mitre/mitre-att-and-ck-soc-l1-detection-matrix/"}
---

# MITRE ATT&CK Matrix — SOC L1 Detection Coverage
#MITRE #Detection #Matrix #Coverage #SOC

---

## How to Use This Note

This matrix maps every **critical MITRE ATT&CK technique** an SOC L1 analyst needs to detect against:
- The **log sources** you need
- The **detection query** logic
- The **Event IDs / fields** that fire
- The **False Positive** risks
- The **Escalation threshold**

Use this as your detection coverage checklist. For each technique, ask: **"Do we have a rule? Does it fire? Is it tuned?"**

Navigator: https://mitre-attack.github.io/attack-navigator/

---

## TACTIC: TA0001 — Initial Access

### T1566.001 — Spearphishing Attachment
| Field | Detail |
|-------|--------|
| **Log Sources** | Email gateway, EDR, Sysmon |
| **Key Indicators** | Malicious attachment extension, macro execution, Office spawning child process |
| **Primary Event IDs** | Sysmon 1 (Office → cmd/PS), Email gateway alerts |
| **Splunk Query** | `index=sysmon EventCode=1 ParentImage IN ("*winword*","*excel*","*outlook*") Image IN ("*cmd*","*powershell*","*wscript*")` |
| **False Positives** | Legitimate software launched from Outlook (rare), IT sending tool attachments |
| **Escalation** | Any confirmed Office → shell spawn = ESCALATE |
| **MITRE ID** | T1566.001 |

---

### T1566.002 — Spearphishing Link
| Field | Detail |
|-------|--------|
| **Log Sources** | Email gateway, Web proxy, DNS logs |
| **Key Indicators** | User clicked link → visited phishing domain → credential entry or download |
| **Primary Event IDs** | Proxy 200 to suspicious domain, DNS query to phishing domain |
| **Splunk Query** | `index=proxy url="*newly_registered_domain*" status=200 | where bytes_in > 5000` |
| **False Positives** | Legitimate links from marketing emails, shortened URLs to legitimate sites |
| **Escalation** | Credentials submitted (POST to phishing page) = ESCALATE |
| **MITRE ID** | T1566.002 |

---

### T1190 — Exploit Public-Facing Application
| Field | Detail |
|-------|--------|
| **Log Sources** | WAF, Web server access logs, IDS/IPS |
| **Key Indicators** | SQLi patterns, LFI, RCE in HTTP requests, 200 response to exploit payload |
| **Primary Event IDs** | WAF block/alert events, web log anomalies |
| **Splunk Query** | `index=web_logs | search uri_path IN ("*UNION*","*SELECT*","*../../../*","*cmd=*") | where status=200` |
| **False Positives** | Security scanners, pen test activity, researchers |
| **Escalation** | 200 response to exploit payload + subsequent unusual server activity = ESCALATE |
| **MITRE ID** | T1190 |

---

### T1078 — Valid Accounts
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows Security, VPN, Cloud auth logs |
| **Key Indicators** | Successful login from unusual location, time, or device |
| **Primary Event IDs** | 4624 from unexpected geo/IP, VPN from new country |
| **Splunk Query** | `index=wineventlog EventCode=4624 | iplocation src_ip | where Country != "United States" | table _time, src_ip, Country, TargetUserName` |
| **False Positives** | User travel, VPN use, legitimate remote work |
| **Escalation** | Admin account from foreign IP + no travel record = ESCALATE |
| **MITRE ID** | T1078 |

---

## TACTIC: TA0002 — Execution

### T1059.001 — PowerShell
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows PowerShell/Operational (4104), Sysmon 1 |
| **Key Indicators** | Encoded commands, download cradles, AMSI bypass attempts |
| **Primary Event IDs** | 4104 (Script block logging) |
| **Splunk Query** | `index=wineventlog EventCode=4104 | search ScriptBlockText IN ("*IEX*","*DownloadString*","*EncodedCommand*","*AmsiUtils*","*bypass*")` |
| **False Positives** | SCCM scripts, IT automation, software installers |
| **Escalation** | Encoded + download cradle + external IP contact = ESCALATE |
| **MITRE ID** | T1059.001 |

---

### T1059.003 — Windows Command Shell
| Field | Detail |
|-------|--------|
| **Log Sources** | Sysmon 1, Windows Security 4688 |
| **Key Indicators** | cmd.exe with unusual parent, or unusual commands (whoami, net user, dir /s) |
| **Primary Event IDs** | 4688 with command line logging, Sysmon 1 |
| **Splunk Query** | `index=sysmon EventCode=1 Image="*cmd.exe" | where ParentImage NOT IN ("*explorer*","*services*","*cmd*") | table _time, Computer, ParentImage, CommandLine` |
| **False Positives** | Admin scripts, software installers running cmd.exe |
| **Escalation** | cmd.exe from Office app parent + external network connection = ESCALATE |
| **MITRE ID** | T1059.003 |

---

### T1204.002 — User Execution: Malicious File
| Field | Detail |
|-------|--------|
| **Log Sources** | EDR, Sysmon, Email gateway |
| **Key Indicators** | Execution of file from Downloads/Temp/Appdata, Office macro execution |
| **Primary Event IDs** | Sysmon 1 (process from Downloads), Sysmon 11 (file created) |
| **Splunk Query** | `index=sysmon EventCode=1 | where match(Image, "(?i)\\\\Downloads\\\\|\\\\AppData\\\\|\\\\Temp\\\\") | table _time, Computer, User, Image, CommandLine` |
| **False Positives** | User legitimately downloading and running software installers |
| **Escalation** | Execution from temp + outbound network connection = ESCALATE |
| **MITRE ID** | T1204.002 |

---

## TACTIC: TA0003 — Persistence

### T1053.005 — Scheduled Task/Job: Scheduled Task
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows Security, Task Scheduler operational log |
| **Key Indicators** | Task created with unusual path, PowerShell encoded command, non-admin creating task |
| **Primary Event IDs** | **4698** (task created), 4702 (task updated) |
| **Splunk Query** | `index=wineventlog EventCode=4698 | rex field=TaskContent "<Command>(?P<cmd>[^<]+)</Command>" | where match(cmd, "(?i)powershell|cmd|wscript|mshta|regsvr32|AppData|Temp")` |
| **False Positives** | Software installers (antivirus updates, Office updates), IT management tools |
| **Escalation** | Task running encoded PS from Temp path = ESCALATE |
| **MITRE ID** | T1053.005 |

---

### T1547.001 — Registry Run Keys / Startup Folder
| Field | Detail |
|-------|--------|
| **Log Sources** | Sysmon 13 (registry modify) |
| **Key Indicators** | New value in Run/RunOnce keys pointing to suspicious path |
| **Primary Event IDs** | **Sysmon 13** |
| **Splunk Query** | `index=sysmon EventCode=13 TargetObject IN ("*\\CurrentVersion\\Run*","*\\CurrentVersion\\RunOnce*") | where NOT match(Details, "(?i)C:\\\\Program Files|C:\\\\Windows") | table _time, Computer, User, TargetObject, Details` |
| **False Positives** | Software installations adding legitimate run keys (Office, Chrome, Teams) |
| **Escalation** | Run key pointing to Temp/AppData/unusual path = ESCALATE |
| **MITRE ID** | T1547.001 |

---

### T1543.003 — Create or Modify System Process: Windows Service
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows System log, Security log |
| **Key Indicators** | New service installed with unusual binary path |
| **Primary Event IDs** | **7045** (new service installed), 4697 (service installed - Security) |
| **Splunk Query** | `index=wineventlog EventCode=7045 | where NOT match(ImagePath, "(?i)C:\\\\Windows\\\\System32|C:\\\\Program Files") | table _time, Computer, ServiceName, ImagePath, ServiceType` |
| **False Positives** | Software installers, IT management agents |
| **Escalation** | Service binary in Temp/AppData = ESCALATE |
| **MITRE ID** | T1543.003 |

---

### T1505.003 — Web Shell
| Field | Detail |
|-------|--------|
| **Log Sources** | Web server access logs, File integrity monitoring, EDR |
| **Key Indicators** | POST to unusual PHP file, web server spawning shell processes, new PHP in upload dirs |
| **Primary Event IDs** | Web logs (POST anomaly), Sysmon 1 (apache/nginx → cmd/sh) |
| **Splunk Query** | `index=web_logs method=POST | search uri_path IN ("*upload*","*images*","*media*") AND uri_path="*.php" | table _time, src_ip, uri_path, status, bytes` |
| **False Positives** | Legitimate file upload functionality |
| **Escalation** | Web server spawning OS commands = CRITICAL ESCALATE |
| **MITRE ID** | T1505.003 |

---

## TACTIC: TA0004 — Privilege Escalation

### T1134.001 — Token Impersonation/Theft
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows Security, EDR |
| **Key Indicators** | SeImpersonatePrivilege enabled, token manipulation functions called |
| **Primary Event IDs** | 4624 Type 9 (NewCredentials), 4672 (special privileges) |
| **Splunk Query** | `index=wineventlog EventCode=4624 Logon_Type=9 | table _time, Computer, TargetUserName, src_ip` |
| **False Positives** | runas /netonly for legitimate admin tasks |
| **Escalation** | Type 9 from non-IT workstation = ESCALATE |
| **MITRE ID** | T1134.001 |

---

### T1548.002 — Abuse Elevation Control Mechanism: Bypass UAC
| Field | Detail |
|-------|--------|
| **Log Sources** | Sysmon 1, Windows Security 4688 |
| **Key Indicators** | eventvwr.exe, fodhelper.exe, sdclt.exe spawning unexpected children |
| **Primary Event IDs** | Sysmon 1 |
| **Splunk Query** | `index=sysmon EventCode=1 ParentImage IN ("*eventvwr.exe*","*fodhelper.exe*","*sdclt.exe*") | table _time, Computer, User, ParentImage, Image, CommandLine` |
| **False Positives** | Very rare — these processes rarely spawn children legitimately |
| **Escalation** | Any match = HIGH confidence = ESCALATE |
| **MITRE ID** | T1548.002 |

---

## TACTIC: TA0005 — Defense Evasion

### T1070.001 — Indicator Removal: Clear Windows Event Logs
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows Security, Windows System |
| **Key Indicators** | Log cleared event |
| **Primary Event IDs** | **1102** (Security log cleared), **104** (System log cleared) |
| **Splunk Query** | `index=wineventlog EventCode IN (1102,104) | table _time, Computer, SubjectUserName, Channel` |
| **False Positives** | IT clearing logs for maintenance (should be change-managed) |
| **Escalation** | Cleared during active incident = CRITICAL — attacker covering tracks |
| **MITRE ID** | T1070.001 |

---

### T1027 — Obfuscated Files or Information
| Field | Detail |
|-------|--------|
| **Log Sources** | PowerShell script block logging (4104), Sysmon 1 |
| **Key Indicators** | Base64 encoding, character replacement, string concatenation in commands |
| **Primary Event IDs** | 4104 |
| **Splunk Query** | `index=wineventlog EventCode=4104 | search ScriptBlockText IN ("*-enc*","*-EncodedCommand*","*[Convert]::FromBase64String*","*[char[]*","*-join*\"") | table _time, Computer, ScriptBlockText` |
| **False Positives** | SCCM/Intune management using encoded commands |
| **Escalation** | Encoded + download cradle = ESCALATE |
| **MITRE ID** | T1027 |

---

### T1218 — System Binary Proxy Execution (LOLBins)

**Key LOLBins to Monitor:**

| Binary | Suspicious Use | Splunk Filter |
|--------|---------------|---------------|
| `mshta.exe` | Execute VBS/JS via HTA | `Image="*mshta*" CommandLine="*http*"` |
| `regsvr32.exe` | Execute DLL or remote script | `CommandLine IN ("*/i:http*","*/s /u /i*")` |
| `rundll32.exe` | Load DLL from unusual path | `CommandLine="*\\Temp\\*"` |
| `certutil.exe` | Download files / decode base64 | `CommandLine IN ("*-urlcache*","*-decode*")` |
| `bitsadmin.exe` | Download files | `CommandLine="*/Transfer*"` |
| `wscript.exe` | Execute VBS/JS scripts | `Image="*wscript*" ParentImage NOT IN ("*services*")` |
| `cscript.exe` | Execute VBS/JS scripts | `Image="*cscript*" CommandLine="*\\Temp\\*"` |

**Splunk - LOLBin Detection:**
```spl
index=sysmon EventCode=1
| eval lolbin = case(
    match(Image,"(?i)mshta\.exe") AND match(CommandLine,"(?i)http"), "mshta_remote",
    match(Image,"(?i)certutil\.exe") AND match(CommandLine,"(?i)urlcache|decode"), "certutil_download",
    match(Image,"(?i)regsvr32\.exe") AND match(CommandLine,"(?i)/s /u /i:http"), "regsvr32_squiblydoo",
    match(Image,"(?i)rundll32\.exe") AND match(CommandLine,"(?i)AppData|Temp|Public"), "rundll32_suspicious",
    true(), null()
  )
| where isnotnull(lolbin)
| table _time, Computer, User, lolbin, CommandLine
```

---

## TACTIC: TA0006 — Credential Access

### T1003.001 — OS Credential Dumping: LSASS Memory
| Field | Detail |
|-------|--------|
| **Log Sources** | **Sysmon 10** (ProcessAccess), EDR |
| **Key Indicators** | Process accessing lsass.exe with specific access masks used by Mimikatz |
| **Primary Event IDs** | **Sysmon Event ID 10** |
| **Splunk Query** | `index=sysmon EventCode=10 TargetImage="*lsass.exe" GrantedAccess IN ("0x1010","0x1410","0x147a","0x1418","0x40","0x1438") | where NOT match(SourceImage,"(?i)C:\\\\Windows\\\\System32\\\\") | table _time, Computer, SourceImage, GrantedAccess` |
| **False Positives** | AV/EDR doing legitimate LSASS access, Windows Defender |
| **Escalation** | Non-system process accessing LSASS with elevated rights = ESCALATE |
| **MITRE ID** | T1003.001 |

---

### T1110.001 — Brute Force: Password Guessing
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows Security, Linux auth.log, VPN logs |
| **Key Indicators** | High count of 4625 from same source, SSH failures in auth.log |
| **Primary Event IDs** | **4625**, 4771 (Kerberos), 4776 (NTLM) |
| **Splunk Query** | `index=wineventlog EventCode=4625 | bucket _time span=5m | stats count by _time, src_ip, TargetUserName | where count > 10 | sort -count` |
| **False Positives** | Misconfigured service account, user forgetting password, lock-screen issues |
| **Escalation** | Brute force + successful login (4624) from same IP = ESCALATE P1 |
| **MITRE ID** | T1110.001 |

---

### T1110.003 — Brute Force: Password Spraying
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows Security |
| **Key Indicators** | Many unique accounts getting 1-3 failures each from one source |
| **Primary Event IDs** | 4625 (many different TargetUserName values) |
| **Splunk Query** | `index=wineventlog EventCode=4625 | bucket _time span=30m | stats dc(TargetUserName) as unique_accounts, count as total by _time, src_ip | where unique_accounts > 20 AND total < (unique_accounts * 3)` |
| **False Positives** | Active Directory replication issues, misconfigured LDAP queries |
| **Escalation** | Spray + any successful login = ESCALATE P1 |
| **MITRE ID** | T1110.003 |

---

### T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows Security (Domain Controller) |
| **Key Indicators** | Unusual volume of TGS requests for service accounts with SPNs |
| **Primary Event IDs** | **4769** (Kerberos service ticket requested) with TicketEncryptionType=0x17 (RC4) |
| **Splunk Query** | `index=wineventlog EventCode=4769 TicketEncryptionType=0x17 | where NOT match(ServiceName,"$") | stats count by Account_Name, ServiceName, Client_Address | where count > 5` |
| **False Positives** | Legacy systems requiring RC4, Kerberos delegation, monitoring tools |
| **Escalation** | Bulk TGS requests for multiple service accounts from single host = ESCALATE |
| **MITRE ID** | T1558.003 |

---

## TACTIC: TA0007 — Discovery

### T1087 — Account Discovery
| Field | Detail |
|-------|--------|
| **Log Sources** | Sysmon 1, Windows Security 4688 |
| **Key Indicators** | net user, net group, LDAP queries, AD enumeration tools (BloodHound) |
| **Primary Event IDs** | Sysmon 1 (net.exe CommandLine) |
| **Splunk Query** | `index=sysmon EventCode=1 Image="*net.exe" | search CommandLine IN ("*user*","*group*","*localgroup*","*accounts*") | table _time, Computer, User, CommandLine` |
| **False Positives** | IT helpdesk checking group membership, monitoring scripts |
| **Escalation** | net commands + BloodHound artifacts + not IT staff = ESCALATE |
| **MITRE ID** | T1087 |

---

### T1046 — Network Service Discovery
| Field | Detail |
|-------|--------|
| **Log Sources** | Firewall, IDS/IPS, Sysmon 3 |
| **Key Indicators** | Port scanning behavior from internal host — many different ports/hosts |
| **Primary Event IDs** | Sysmon 3 (network connections) to many destinations |
| **Splunk Query** | `index=sysmon EventCode=3 | bucket _time span=5m | stats dc(DestinationPort) as unique_ports, dc(DestinationIp) as unique_hosts by _time, SourceIp | where unique_ports > 20 OR unique_hosts > 20` |
| **False Positives** | Vulnerability scanners, monitoring agents |
| **Escalation** | Internal workstation scanning internal network = ESCALATE |
| **MITRE ID** | T1046 |

---

## TACTIC: TA0008 — Lateral Movement

### T1021.001 — Remote Services: Remote Desktop Protocol
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows Security |
| **Key Indicators** | RDP logon (Type 10) from unusual source, 3AM RDP access, admin account RDP to workstations |
| **Primary Event IDs** | **4624 Logon_Type=10** |
| **Splunk Query** | `index=wineventlog EventCode=4624 Logon_Type=10 | eval hour=strftime(_time,"%H") | where hour < 7 OR hour > 19 | table _time, Computer, TargetUserName, src_ip, hour` |
| **False Positives** | IT admins working late, legitimate remote workers, monitoring tools |
| **Escalation** | Admin account RDP at 3AM from foreign IP = ESCALATE |
| **MITRE ID** | T1021.001 |

---

### T1021.002 — Remote Services: SMB/Windows Admin Shares
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows Security |
| **Key Indicators** | Workstation accessing Admin$ or C$ shares of another workstation (not DC) |
| **Primary Event IDs** | **5140** (network share accessed), 4624 Type 3 |
| **Splunk Query** | `index=wineventlog EventCode=5140 | search ShareName IN ("*ADMIN$*","*C$*","*IPC$*") | where NOT match(Computer,"DC*") | table _time, Computer, SubjectUserName, ShareName, IpAddress` |
| **False Positives** | IT deploying software via admin shares, backup agents |
| **Escalation** | Workstation accessing another workstation's admin share = ESCALATE |
| **MITRE ID** | T1021.002 |

---

### T1550.002 — Use Alternate Authentication Material: Pass the Hash
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows Security |
| **Key Indicators** | NTLM Type 3 logon from unusual host, no prior failed attempts |
| **Primary Event IDs** | **4624 Logon_Type=3** with AuthenticationPackage=NTLM from workstations |
| **Splunk Query** | `index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM | where NOT match(SubjectUserName,"\\$") | stats dc(Computer) as hosts by TargetUserName, src_ip | where hosts > 3` |
| **False Positives** | Legacy NTLM authentication, some scanning tools |
| **Escalation** | Admin hash used across multiple hosts in short time = ESCALATE |
| **MITRE ID** | T1550.002 |

---

## TACTIC: TA0011 — Command & Control

### T1071.001 — Application Layer Protocol: Web Protocols
| Field | Detail |
|-------|--------|
| **Log Sources** | Proxy/web gateway logs |
| **Key Indicators** | Beaconing (regular intervals), unusual User-Agent, connection to new/low-reputation domain |
| **Primary Event IDs** | Proxy logs |
| **Splunk Query** | `index=proxy | stats count, stdev(bytes_out) as stdev by src_ip, dest_domain | where count > 50 AND stdev < 200 | sort -count` |
| **False Positives** | Software update checks, monitoring agents, analytics beacons |
| **Escalation** | Beaconing to newly registered domain = ESCALATE |
| **MITRE ID** | T1071.001 |

---

### T1071.004 — Application Layer Protocol: DNS
| Field | Detail |
|-------|--------|
| **Log Sources** | DNS server logs, Sysmon 22 |
| **Key Indicators** | Long subdomains, high query volume to single domain, TXT record queries |
| **Primary Event IDs** | Sysmon 22, DNS logs |
| **Splunk Query** | `index=dns | eval sub_len=len(mvindex(split(query_name,"."),-3)) | where sub_len > 40 | stats count by src_ip, query_name | sort -count` |
| **False Positives** | CDN domains with long subdomains, legitimate TXT record lookups |
| **Escalation** | High entropy + high volume to single domain = DNS tunneling = ESCALATE |
| **MITRE ID** | T1071.004 |

---

### T1568.002 — Dynamic Resolution: Domain Generation Algorithms
| Field | Detail |
|-------|--------|
| **Log Sources** | DNS logs, proxy logs |
| **Key Indicators** | High NXDOMAIN rate, random-looking domain names, high entropy |
| **Primary Event IDs** | DNS logs (response_code=NXDOMAIN) |
| **Splunk Query** | `index=dns response_code="NXDOMAIN" | stats count as nxdomain_count, dc(query_name) as unique_domains by src_ip | where unique_domains > 50 | sort -unique_domains` |
| **False Positives** | Misconfigured applications, browser bug reporting |
| **Escalation** | 100+ NXDOMAIN unique domains in short window = DGA = ESCALATE |
| **MITRE ID** | T1568.002 |

---

## TACTIC: TA0010 — Exfiltration

### T1041 — Exfiltration Over C2 Channel
| Field | Detail |
|-------|--------|
| **Log Sources** | Proxy, firewall, DLP |
| **Key Indicators** | Large outbound transfer to C2 domain, upload spike |
| **Primary Event IDs** | Proxy logs (large bytes_out) |
| **Splunk Query** | `index=proxy | stats sum(bytes_out) as total_out by src_ip, dest_domain | eval gb=round(total_out/1073741824,2) | where gb > 1 | sort -gb` |
| **False Positives** | Cloud backup, video uploads, software updates to CDN |
| **Escalation** | >1GB to unknown external domain = ESCALATE |
| **MITRE ID** | T1041 |

---

### T1567.002 — Exfiltration Over Web Service: Code Repository
| Field | Detail |
|-------|--------|
| **Log Sources** | Proxy logs |
| **Key Indicators** | Large uploads to GitHub, GitLab, Pastebin from non-developer |
| **Primary Event IDs** | Proxy logs (POST to github.com, pastebin.com with large payload) |
| **Splunk Query** | `index=proxy method=POST dest_domain IN ("github.com","pastebin.com","gitlab.com","transfer.sh") | where bytes_out > 1000000 | table _time, src_ip, user, dest_domain, bytes_out` |
| **False Positives** | Developers pushing code, legitimate Git operations |
| **Escalation** | Non-developer uploading to pastebin/transfer.sh = ESCALATE |
| **MITRE ID** | T1567.002 |

---

## TACTIC: TA0040 — Impact

### T1486 — Data Encrypted for Impact (Ransomware)
| Field | Detail |
|-------|--------|
| **Log Sources** | EDR, File integrity monitoring, Windows Security, Sysmon |
| **Key Indicators** | Mass file modifications, shadow copy deletion, ransom note creation |
| **Primary Event IDs** | Sysmon 11 (mass file creation with new extensions), 4688 with vssadmin |
| **Splunk Query** | `index=sysmon EventCode=11 | bucket _time span=1m | stats dc(TargetFilename) as files_modified, values(TargetFilename) as files by _time, Computer, Image | where files_modified > 50` |
| **False Positives** | Mass file operations by legitimate software, backup tools |
| **Escalation** | Mass file modification + shadow copy deletion = RANSOMWARE = CRITICAL |
| **MITRE ID** | T1486 |

---

### T1490 — Inhibit System Recovery
| Field | Detail |
|-------|--------|
| **Log Sources** | Windows Security (4688), Sysmon 1 |
| **Key Indicators** | vssadmin delete shadows, wbadmin delete catalog, bcdedit changes |
| **Primary Event IDs** | **4688** / Sysmon 1 |
| **Splunk Query** | `index=sysmon EventCode=1 | search CommandLine IN ("*vssadmin*delete*shadows*","*wbadmin*delete*catalog*","*bcdedit*/set*recoveryenabled*no*","*wmic*shadowcopy*delete*") | table _time, Computer, User, CommandLine` |
| **False Positives** | Almost NONE — this is extremely rare in legitimate operations |
| **Escalation** | ANY match = CRITICAL — isolate host immediately |
| **MITRE ID** | T1490 |

---

## Quick Reference: Event ID to MITRE Mapping

| Event ID | Source | Technique | MITRE ID |
|----------|--------|-----------|----------|
| 4624 Type 3 NTLM | Security | Pass the Hash | T1550.002 |
| 4624 Type 10 | Security | RDP | T1021.001 |
| 4625 | Security | Brute Force | T1110.001 |
| 4648 | Security | Explicit Creds / PtH | T1550.002 |
| 4672 | Security | Privileged Logon | T1078 |
| 4688 + vssadmin | Security | Inhibit Recovery | T1490 |
| 4698 | Security | Scheduled Task | T1053.005 |
| 4719 | Security | Audit Policy Change | T1562.002 |
| 4720 + 4732 | Security | Create Account | T1136 |
| 4769 RC4 | Security | Kerberoasting | T1558.003 |
| 1102 / 104 | Security/System | Clear Logs | T1070.001 |
| 7045 | System | Malicious Service | T1543.003 |
| 4104 + IEX | PS/Operational | PowerShell | T1059.001 |
| Sysmon 1 (Office→PS) | Sysmon | Phishing Execution | T1566.001 |
| Sysmon 8 | Sysmon | Process Injection | T1055 |
| Sysmon 10 + lsass | Sysmon | LSASS Dump | T1003.001 |
| Sysmon 13 + Run key | Sysmon | Registry Persistence | T1547.001 |
| Sysmon 22 (long DNS) | Sysmon | DNS Tunneling | T1071.004 |

---

## Detection Coverage Self-Assessment Checklist

Use this to evaluate your SOC's coverage. For each technique, answer:
- Do we have a **log source** that would capture this?
- Do we have a **detection rule** for it?
- Is the rule **tuned** (low FP)?
- Have we **tested** it with a known benign or attack sample?

```
[ ] T1566.001 - Spearphishing Attachment
[ ] T1566.002 - Spearphishing Link
[ ] T1190 - Exploit Public-Facing Application
[ ] T1059.001 - PowerShell Execution
[ ] T1059.003 - Windows Command Shell
[ ] T1053.005 - Scheduled Task Persistence
[ ] T1547.001 - Registry Run Key Persistence
[ ] T1543.003 - Malicious Service Creation
[ ] T1505.003 - Web Shell
[ ] T1070.001 - Event Log Clearing
[ ] T1003.001 - LSASS Credential Dumping
[ ] T1110.001 - Password Guessing (Brute Force)
[ ] T1110.003 - Password Spraying
[ ] T1558.003 - Kerberoasting
[ ] T1021.001 - RDP Lateral Movement
[ ] T1021.002 - SMB Lateral Movement
[ ] T1550.002 - Pass the Hash
[ ] T1071.001 - C2 over HTTP (Beaconing)
[ ] T1071.004 - DNS Tunneling
[ ] T1568.002 - DGA
[ ] T1041 - Exfiltration over C2
[ ] T1486 - Ransomware File Encryption
[ ] T1490 - Shadow Copy Deletion
```

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/07_MITRE/MITRE_ATTACK_Overview\|MITRE_ATTACK_Overview]]
- [[SOC_L1_Complete_Knowledge_Base/08_Detection_Engineering/Detection_Engineering\|Detection_Engineering]]
- [[SOC_L1_Complete_Knowledge_Base/03_Windows/Windows_Event_Logs\|Windows_Event_Logs]]
- [[SOC_L1_Complete_Knowledge_Base/05_SIEM/SIEM_Overview_Splunk_ELK\|SIEM_Overview_Splunk_ELK]]
- [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/SOC_Investigation_Playbooks\|SOC_Investigation_Playbooks]]
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/Pyramid_of_Pain\|Pyramid_of_Pain]]
