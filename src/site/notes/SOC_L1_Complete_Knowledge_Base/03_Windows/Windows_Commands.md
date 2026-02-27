---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/03-windows/windows-commands/","dgPassFrontmatter":true}
---

# Windows Commands Reference
#Windows #Commands #DFIR #Investigation

---

## System Information & Enumeration

### whoami
```cmd
# Current user context
whoami

# All user details (groups, privileges)
whoami /all

# Current privileges only
whoami /priv

# Groups the user belongs to
whoami /groups

# Example Output (suspicious if you see SeDebugPrivilege enabled):
# Privilege Name                  State
# SeDebugPrivilege               Enabled  ← Can dump process memory (Mimikatz)
# SeImpersonatePrivilege         Enabled  ← Can impersonate tokens (privilege escalation)
```

**SOC Use:** Run on compromised host to understand attacker's privilege level. Check for dangerous privileges.

---

### ipconfig
```cmd
# Basic IP info
ipconfig

# Full info including DNS cache, WINS
ipconfig /all

# Display DNS cache (what domains has this machine resolved?)
ipconfig /displaydns

# Flush DNS cache
ipconfig /flushdns

# Release/renew DHCP
ipconfig /release && ipconfig /renew
```

**SOC Use:** Identify network configuration, check DNS cache for C2 domains, identify machine's actual IP vs expected.

---

### netstat
```cmd
# All active connections with process IDs
netstat -ano

# All connections with executable names (requires elevation)
netstat -b

# Listening ports only
netstat -ano | findstr LISTENING

# Established connections (active sessions)
netstat -ano | findstr ESTABLISHED

# Find what's connecting to suspicious IP
netstat -ano | findstr "evil_ip_here"

# Map PID to process name
tasklist | findstr "1234"   ← where 1234 is PID from netstat

# Statistics by protocol
netstat -s

# Example Investigation Flow:
netstat -ano | findstr ESTABLISHED
# See PID 3456 connecting to 185.220.101.x
tasklist /FI "PID eq 3456"
# Returns: svchost.exe   ← Legitimate? Check with process tree
```

**SOC Use:** Identify active connections to C2, find listening backdoors, map PIDs to processes.

---

### tasklist
```cmd
# All running processes
tasklist

# Verbose (includes memory usage)
tasklist /v

# Show DLLs loaded by process
tasklist /m

# Show DLLs for specific process
tasklist /m /fi "imagename eq lsass.exe"

# Filter by name
tasklist /fi "imagename eq powershell.exe"

# Filter by PID
tasklist /fi "pid eq 1234"

# Show services per process
tasklist /svc

# Remote machine
tasklist /s RemoteServer /u domain\admin /p password
```

**SOC Use:** Hunt for suspicious processes (svchost.exe running from wrong path, duplicate explorer.exe, etc.)

**Red Flags in Process List:**
```
# Legitimate processes running from wrong path:
svchost.exe in C:\Users\Public\  (should be C:\Windows\System32\)
explorer.exe in C:\Temp\         (should be C:\Windows\)
lsass.exe with unusual parent   (should parent be wininit.exe only)

# Suspicious names (typosquatting common processes):
svch0st.exe, lssas.exe, csrss_.exe, winlogin.exe

# Tools that shouldn't be there in production:
mimikatz.exe, meterpreter.exe, cobalt_strike.exe
psexec.exe, pwdump.exe, procdump.exe
```

---

### net user / net group
```cmd
# All local users
net user

# Specific user details (password change date, last login, group membership)
net user username

# All local groups
net localgroup

# Members of Administrators group
net localgroup Administrators

# All domain groups
net group /domain

# Domain Admins members
net group "Domain Admins" /domain

# Enterprise Admins members  
net group "Enterprise Admins" /domain

# Add user (attacker technique - detect via 4720)
net user attacker P@ssword1! /add

# Add to Administrators (detect via 4732)
net localgroup Administrators attacker /add

# Show shared resources
net share

# Show active sessions (who's connected to this machine)
net session

# Show connections to remote resources
net use
```

**SOC Use:** Enumerate users, check group membership for unauthorized admins, detect attacker persistence via new accounts.

---

### schtasks (Scheduled Tasks)
```cmd
# List all scheduled tasks
schtasks /query /fo LIST /v

# Specific task details
schtasks /query /fo LIST /v /tn "TaskName"

# Export all tasks to CSV
schtasks /query /fo CSV /v > C:\tasks.csv

# Create task (attacker technique - detect via 4698)
schtasks /create /tn "Windows Update" /tr "C:\backdoor.exe" /sc daily /st 02:00

# Delete task
schtasks /delete /tn "TaskName" /f

# Run task immediately
schtasks /run /tn "TaskName"
```

**SOC Investigation:** Look for tasks in unusual locations, running from AppData/Temp, using PowerShell with encoded commands, unusual run accounts.

**Red Flag Task Characteristics:**
```
# Suspicious scheduled task indicators:
- Running from: C:\Users\*\AppData\, C:\Temp\, C:\ProgramData\
- Command includes: powershell.exe -enc, -nop, -w hidden
- Runs as: SYSTEM but created by non-admin user
- Task name mimics legitimate Windows tasks
- Action references deleted/missing file (ghost task)
```

---

### reg query (Registry)
```cmd
# Query Run key (common persistence location)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# All autorun locations
reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders

# Services (look for unusual services)
reg query HKLM\SYSTEM\CurrentControlSet\Services

# SAM database (local accounts)
reg query HKLM\SAM\SAM\Domains\Account\Users\Names

# Installed software
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s

# Recent files (evidence of user activity)
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

# Last logged on user
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LastUsedUsername

# Find registry key containing string
reg query HKLM /f "malware" /s
```

---

### arp
```cmd
# Show ARP cache (IP to MAC mapping)
arp -a

# ARP cache for specific interface
arp -a -N 192.168.1.1

# Delete ARP entry
arp -d IP_ADDRESS
```

**SOC Use:** Identify machines on the local network segment, detect ARP poisoning (same MAC for multiple IPs), correlate IP addresses to physical machines.

---

## Process Investigation

### tasklist (Advanced)
```cmd
# Check DLLs loaded by specific process (detect DLL injection)
tasklist /m /fi "imagename eq lsass.exe"

# Check services hosted in svchost
tasklist /svc | findstr svchost

# Verify process signature (PowerShell)
Get-AuthenticodeSignature -FilePath "C:\Windows\System32\lsass.exe"
```

### wmic
```cmd
# Process list with details
wmic process list full

# Specific process details
wmic process where "name='lsass.exe'" get ProcessId,ParentProcessId,ExecutablePath,CommandLine

# All process command lines (very useful for incident response)
wmic process get ProcessId,ParentProcessId,Name,CommandLine | more

# Startup items
wmic startup list full

# Services
wmic service where "state='Running'" get Name,PathName,StartName

# Installed software
wmic product get Name,Version

# Remote process execution (lateral movement technique)
wmic /node:REMOTE_HOST process call create "cmd.exe /c command"
```

**SOC Use:** wmic is heavily used by attackers (LOLBIN). Monitor wmic.exe process creation with remote /node: parameters.

---

## Network Investigation

### netsh
```cmd
# Show firewall rules
netsh advfirewall show allprofiles

# Firewall rule list
netsh advfirewall firewall show rule name=all

# Disable firewall (defense evasion - detect this)
netsh advfirewall set allprofiles state off

# Show all network adapters
netsh interface show interface

# Proxy settings (check for malicious proxy)
netsh winhttp show proxy
```

---

## Evidence Collection Commands

### Complete Host Triage (PowerShell)
```powershell
# Quick triage script - run on suspected compromised host
$output = @{}

$output.SystemInfo = Get-ComputerInfo
$output.Users = Get-LocalUser
$output.LocalAdmins = Get-LocalGroupMember -Group "Administrators"
$output.ProcessList = Get-Process | Select Name,Id,CPU,Path
$output.NetworkConnections = Get-NetTCPConnection | Where-Object State -eq 'Established'
$output.ScheduledTasks = Get-ScheduledTask | Where-Object State -ne 'Disabled'
$output.Services = Get-Service | Where-Object Status -eq 'Running'
$output.StartupItems = Get-CimInstance Win32_StartupCommand
$output.RecentFiles = Get-ChildItem $env:USERPROFILE\Downloads -Recurse | Sort LastWriteTime -Descending | Select -First 20

$output | ConvertTo-Json -Depth 3 | Out-File C:\triage_output.json
```

### Hash Files for IOC Comparison
```powershell
# Hash a single file
Get-FileHash C:\suspicious.exe -Algorithm SHA256

# Hash all files in directory
Get-ChildItem C:\Users\Public -Recurse -File | 
    Get-FileHash -Algorithm SHA256 | 
    Select Hash, Path | 
    Export-Csv C:\hashes.csv -NoTypeInformation

# Compare hash to known malware
$knownBadHash = "a3b1c2d3..."
$fileHash = (Get-FileHash C:\suspect.exe -Algorithm SHA256).Hash
if ($fileHash -eq $knownBadHash) { Write-Host "MATCH - MALICIOUS" }
```

### Find Recently Modified Files
```powershell
# Files modified in last 24 hours
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)} |
    Sort-Object LastWriteTime -Descending |
    Select FullName, LastWriteTime, Length

# Files in suspicious locations
Get-ChildItem -Path "C:\Users\*\AppData\*" -Include "*.exe","*.dll","*.ps1","*.bat" -Recurse -ErrorAction SilentlyContinue

# Hidden files
Get-ChildItem C:\ -Recurse -Hidden -ErrorAction SilentlyContinue
```

---

## Credential Hunting (Attacker Techniques to Detect)

**What attackers look for:**
```cmd
# Search for passwords in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Search for credentials in files
findstr /si password *.xml *.ini *.txt
findstr /si password *.config *.properties

# Unattend files (post-deployment credentials)
dir c:\*vnc* /s /b
dir C:\Windows\Panther\ /b
dir C:\Windows\System32\sysprep /b
```

**Detection:** Monitor for these command patterns in process creation logs (Event 4688 / Sysmon 1).

---

## Related Notes
- [[Windows Event Logs\|Windows Event Logs]]
- [[PowerShell Detection\|PowerShell Detection]]
- [[Incident Response Lifecycle\|Incident Response Lifecycle]]
- [[SOC L1 Survival Guide\|SOC L1 Survival Guide]]
