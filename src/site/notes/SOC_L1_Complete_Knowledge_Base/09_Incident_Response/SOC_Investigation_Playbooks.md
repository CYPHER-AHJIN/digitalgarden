---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/09-incident-response/soc-investigation-playbooks/","dgPassFrontmatter":true}
---

# SOC Investigation Playbooks
#Playbooks #IR #SOC #Detection

---

# Playbook 1: Brute Force Detection

## Alert Trigger
- Multiple failed logins (Event ID 4625) from same source IP
- Threshold: > 10 failures in 5 minutes against same account
- Also: 4771 (Kerberos), 4776 (NTLM), SSH auth.log failures

## Triage Steps

```
Step 1: Identify scope
  - How many failed attempts?
  - Against which account(s)?
  - From single IP or distributed (credential stuffing)?
  - What time? (Business hours = more likely legitimate, 2 AM = suspicious)

Step 2: Enrich source IP
  - AbuseIPDB: Is this a known malicious IP?
  - Shodan: What services does this IP run?
  - Is it internal or external?
  - Is it a known scanner (Qualys, Nessus)?

Step 3: Check for success
  - Did Event ID 4624 fire from the SAME source IP?
  - If yes → ESCALATE IMMEDIATELY, account likely compromised

Step 4: Enrich target account
  - Is this a privileged account? (admin, service account, exec)
  - Is the account currently locked? (4740)
  - When was this account last used legitimately?
  - Does the user travel? Could this be from abroad?

Step 5: Check post-authentication activity
  - If account was accessed: what did they do? (Event 4688, file access, lateral movement)
```

## Detection Query (Splunk)
```spl
index=wineventlog EventCode=4625
| bucket _time span=5m
| stats count as failures, dc(src_ip) as unique_ips, values(src_ip) as ips by _time, TargetUserName
| where failures > 10
| sort -failures
```

## Password Spray Detection (Low-and-slow across many accounts)
```spl
index=wineventlog EventCode=4625
| bucket _time span=1h
| stats dc(TargetUserName) as unique_accounts, count as failures by _time, src_ip
| where unique_accounts > 10 AND failures < 50  # Many accounts, few per account
| sort -unique_accounts
```

## Escalation Criteria
- Successful login AFTER failures from same IP → **ESCALATE P1**
- Target is privileged account → **ESCALATE P1**
- Source IP is internal (insider or compromised internal host) → **ESCALATE P1**
- Distributed attack (credential stuffing, many source IPs) → **ESCALATE P2**

## False Positive Considerations
- Vulnerability scanner (check against scanner IP list)
- User forgot password / account lockout scenario
- Service account with cached wrong password
- Legitimate pentest (check change management)

## Response Actions
- Block source IP on perimeter firewall (if external brute force)
- Disable account temporarily if successful login detected
- Reset user password and force MFA
- Notify user if account was accessed

---

# Playbook 2: Suspicious PowerShell Activity

## Alert Trigger
- PowerShell with encoded command (`-enc`, `-EncodedCommand`)
- PowerShell download cradle (`DownloadString`, `WebClient`)
- PowerShell with bypass flags (`-ExecutionPolicy Bypass`, `-nop`)
- Unusual parent process spawning PowerShell (Word, Excel, Outlook)
- Script block logging (Event 4104) matching suspicious patterns
- PowerShell spawning network connections (Sysmon Event 3)

## Triage Steps

```
Step 1: Identify the PowerShell invocation
  - Full command line (from Event 4688 or Sysmon 1)
  - Parent process (what spawned PowerShell?)
  - User context (admin? service account? regular user?)
  - Host criticality

Step 2: Decode if encoded
  - Base64 decode the -EncodedCommand value
  - Python: import base64; base64.b64decode("...").decode('utf-16')
  - CyberChef: From Base64 → Decode text (UTF-16LE)

Step 3: Analyze decoded/actual command
  - Is there a download URL? Look it up in VirusTotal/URLScan
  - Is there execution of downloaded code? (IEX, Invoke-Expression)
  - Is there network activity? Check Sysmon Event 3 for outbound connections
  - Is there AMSI bypass attempt? (AmsiUtils in script)

Step 4: Check for continuation
  - Did PowerShell spawn further processes?
  - Was a file dropped? (Sysmon Event 11)
  - Was there registry modification? (Sysmon Event 13)
  - Was there network connection? (Sysmon Event 3)

Step 5: Scope assessment
  - Is this isolated to one host?
  - Any other hosts with similar activity?
```

## Base64 Decode Cheatsheet
```python
# Python
import base64, sys
encoded = "cG93ZXJzaGVsbC..."
decoded = base64.b64decode(encoded).decode('utf-16')
print(decoded)
```

```bash
# Linux command line
echo "cG93ZXJzaGVsbC..." | base64 -d | iconv -f utf-16le -t utf-8
```

## Detection Query (Splunk)
```spl
index=sysmon EventCode=1 Image="*powershell*"
| eval suspicious_flags = if(
    match(CommandLine, "(?i)-enc|-nop|-noprofile|-noninteractive|-executionpolicy bypass|-windowstyle hidden"),
    1, 0)
| eval download_cradle = if(
    match(CommandLine, "(?i)downloadstring|webclient|urldownloadtofile|bitsadmin|certutil"),
    1, 0)
| eval exec_cmd = if(
    match(CommandLine, "(?i)iex|invoke-expression|invoke-command"),
    1, 0)
| where suspicious_flags=1 OR download_cradle=1 OR exec_cmd=1
| table _time, Computer, User, ParentImage, CommandLine
```

## Escalation Criteria
- Download + Execute pattern (`IEX (Invoke-WebRequest...)`) → **ESCALATE P1**
- Spawned by Office app → **ESCALATE P1** (confirms phishing)
- Successful network connection in Sysmon → **ESCALATE P1**
- AMSI bypass detected → **ESCALATE P1**

## False Positive Considerations
- IT admin running legitimate scripts
- Software deployment tools (SCCM, Ansible running PowerShell)
- Legitimate backup/monitoring agents
- Security tools (they often use these flags legitimately)

---

# Playbook 3: Malware Detected on Endpoint

## Alert Trigger
- AV/EDR detects and quarantines malware
- Behavioral detection in EDR
- Hash match to known malware in SIEM

## Triage Steps

```
Step 1: Gather basic information
  - What was detected? (Name, type, family)
  - On which host? (Criticality? Crown jewel?)
  - Which user was logged in?
  - Was it quarantined automatically?
  - What file path was the malware in?

Step 2: Determine infection vector
  - What spawned the malware? (Parent process?)
  - Email attachment? (Check email logs for user's inbox)
  - Downloaded from web? (Check proxy logs for downloads)
  - Dropped by another process? (Lateral movement?)
  - USB/removable media?

Step 3: Check for execution
  - Did malware actually execute? Or just found at rest?
  - Process creation events before quarantine
  - Network connections made?
  - Files dropped/modified?

Step 4: IOC Extraction
  - Hash (SHA256) → VirusTotal
  - File paths created
  - Registry keys modified
  - Network connections (C2 IPs/domains)
  - Mutexes created

Step 5: Scope check
  - Search IOCs across all endpoints in SIEM
  - Search C2 IPs/domains in proxy/DNS logs
  - Check if malware spread (lateral movement indicators)
```

## IOC Hunting Query (Splunk)
```spl
# Search for malware hash across all hosts
index=sysmon EventCode=1 Hashes="SHA256=a1b2c3..."
| table _time, Computer, User, Image, CommandLine

# Search for C2 domain in proxy logs
index=proxy dest_domain IN ("evil.com","c2.evil.net")
| table _time, src_ip, dest_domain, url, bytes_out

# Search for dropped file paths
index=sysmon EventCode=11 TargetFilename="*malware_name*"
| table _time, Computer, User, TargetFilename, Image
```

## Escalation Criteria
- Any malware on endpoint → **Minimum P2 (High)**
- Malware on critical system (DC, backup, financial) → **ESCALATE P1**
- Confirmed C2 communication → **ESCALATE P1**
- Lateral movement detected → **ESCALATE P1**
- Data exfiltration possible → **ESCALATE P1**
- Multiple hosts affected → **ESCALATE P1**

## Response Actions (L1 scope)
- Isolate host via EDR (with L2 approval)
- Block C2 IPs/domains on firewall
- Notify user not to use device
- Preserve logs for forensics
- Document all IOCs in ticket

---

# Playbook 4: Suspicious Outbound Connection

## Alert Trigger
- Connection to known malicious IP/domain (threat intel match)
- Unusual protocol/port (e.g., HTTP on port 4444)
- Connection to newly registered domain (< 30 days)
- High-frequency connection to same destination (beaconing)
- Large data transfer to external IP
- DNS query for DGA-like domain

## Triage Steps

```
Step 1: Enrich destination
  - VirusTotal: Is the IP/domain known malicious?
  - AbuseIPDB: Reported abuse? By whom?
  - Shodan/Censys: What services does this IP expose?
  - WHOIS: When was the domain registered? (New domain = suspicious)
  - Threat intel platform: Any known campaigns using this IOC?

Step 2: Analyze the connection
  - What protocol/port?
  - What process made the connection?
  - How much data transferred? (bytes_out)
  - How long was the connection?
  - Was it a single connection or repeated?

Step 3: Check the source host
  - Is this host an endpoint or server?
  - Who is logged in?
  - What's the host's function?
  - Any recent changes (new software, patches)?

Step 4: Beaconing analysis
  - Check if connections occur at regular intervals
  - Calculate standard deviation of connection timing
  - Compare to known legitimate software update intervals

Step 5: Data transfer analysis
  - How much data left the network?
  - Is this unusual for this host?
  - What time of day?
```

## Detection Query - C2 Beaconing
```spl
index=proxy
| stats count, 
    min(_time) as first, 
    max(_time) as last, 
    avg(bytes_out) as avg_bytes, 
    stdev(bytes_out) as stdev 
  by src_ip, dest_domain
| eval duration = round((last-first)/3600, 1)
| eval interval_min = round(((last-first)/count)/60, 1)
| where count > 30 AND stdev < 500 AND interval_min > 0.5 AND interval_min < 120
| lookup threat_intel_domains domain AS dest_domain OUTPUT threat_level
| sort -count
```

## Escalation Criteria
- Known C2 indicator → **ESCALATE P1**
- Active data exfiltration → **ESCALATE P1**
- Beaconing confirmed → **ESCALATE P1**
- Connection from server/DC → **ESCALATE P1**

---

# Playbook 5: Phishing Reported by User

## Alert Trigger
- User forwards suspicious email to security mailbox
- User calls SOC reporting suspicious email
- Email gateway blocked/quarantined a message (auto-alert)
- User clicked a link and is reporting strange behavior

## Triage Steps

```
Step 1: Collect the email
  - Obtain the original email (with headers) — NOT forwarded version
  - Ask user to send as attachment (preserves headers)
  - Or pull from email gateway/quarantine

Step 2: Analyze email headers
  - SPF check: Did source domain pass SPF?
  - DKIM check: Is signature valid?
  - DMARC: Did it pass DMARC policy?
  - Reply-To: Does it differ from From: field?
  - Received-from path: Does it make sense?
  - X-Originating-IP: What IP sent this?

Step 3: Analyze URLs/attachments
  - DO NOT click links directly
  - URLScan.io: Submit URL for safe analysis
  - VirusTotal: Check URL
  - Attachment hash: Check in VirusTotal, MalwareBazaar
  - Use sandboxes (Any.run, Cuckoo, Joe Sandbox) for file analysis

Step 4: Check if user clicked/opened
  - Proxy logs: Did source IP access the suspicious URL?
  - Email gateway: Was attachment opened?
  - Endpoint: Any new process activity after email received?
  - DNS logs: Did workstation resolve the phishing domain?

Step 5: Scope check
  - How many users received this email?
  - Were others targeted? (Same campaign, similar emails)
  - Did anyone else click?
```

## Email Header Analysis
```bash
# Key headers to analyze:
From: display_name@domain.com           # What user sees
Reply-To: attacker@evil.com             # Where replies go (often different)
Return-Path: bounce@evil.com            # Bounce address
Received: from evil.com                 # Mail server hops
X-Originating-IP: 1.2.3.4             # Actual sending IP
Authentication-Results: spf=fail        # SPF/DKIM/DMARC results
Message-ID: <unique-id@domain>         # Should match sender domain

# SPF result values:
# pass   - email authorized by domain
# fail   - email NOT authorized (likely spoofed)
# softfail - Not authorized but not hard fail
# none   - No SPF record
```

## Detection Query - Did User Click?
```spl
# Check proxy logs for phishing URL access
index=proxy url="*phishing-domain.com*"
| table _time, src_ip, url, user, status_code

# Check DNS for phishing domain resolution
index=dns query_name="phishing-domain.com"
| table _time, src_ip, query_name, answer
```

## Escalation Criteria
- User CLICKED the link AND visited → **ESCALATE P2**
- User OPENED the attachment → **ESCALATE P1**
- User entered credentials on phishing page → **ESCALATE P1**
- Malware execution detected after opening → **ESCALATE P1**
- Large-scale campaign targeting multiple users → **ESCALATE P2**

## Response Actions
- Quarantine email from all mailboxes (email admin)
- Block phishing domain/URL at proxy and DNS
- Reset credentials if entered on phishing page
- Notify affected users
- File report with email provider if spoofing real domain

---

# Playbook 6: RDP Brute Force

## Alert Trigger
- Multiple failed Event ID 4625 with Logon_Type=10 (RDP)
- Multiple 4771 failures for same user
- Firewall alerts on repeated connections to port 3389

## Triage Steps

```
Step 1: Identify source
  - Internal IP? → Possible compromised internal host or insider
  - External IP? → External attacker targeting public RDP
  - Is RDP supposed to be exposed externally?

Step 2: Target analysis
  - What system is being targeted?
  - Is it a server? Domain controller? Workstation?
  - What accounts are being targeted? (Admin? Domain accounts?)

Step 3: Success check
  - Event ID 4624 with Logon_Type=10 from attacker IP?
  - If yes: what did they do after login?

Step 4: Volume analysis
  - How many attempts in what timeframe?
  - Is it targeted (few accounts) or spray (many accounts)?
```

## Detection Query
```spl
index=wineventlog EventCode=4625 LogonType=10
| stats count as rdp_failures, dc(TargetUserName) as accounts_targeted, 
    values(TargetUserName) as accounts 
  by src_ip
| where rdp_failures > 20
| sort -rdp_failures
```

## Escalation Criteria
- Successful RDP login after failures → **ESCALATE P1**
- Targeting Domain Controller → **ESCALATE P1**
- External RDP brute force on production server → **ESCALATE P2**
- Using valid username list (targeted attack) → **ESCALATE P1**

## Response Actions
- Block source IP on perimeter
- Enable Account Lockout Policy if not active
- Disable external RDP if not business-required
- Enforce NLA (Network Level Authentication)
- Implement Geo-blocking on RDP port
- Recommend VPN + RDP instead of direct RDP

---

# Playbook 7: Privilege Escalation Detection

## Alert Trigger
- Event ID 4728/4732 — User added to privileged group
- Event ID 4720 followed by 4732 — New account immediately made admin
- Unusual privilege assignment (4704)
- Token manipulation detected by EDR

## Triage Steps

```
Step 1: Identify what happened
  - What privilege was gained?
  - What account gained it?
  - Who made the change? (SubjectUserName)
  - Is the action authorized?

Step 2: Context analysis
  - Is SubjectUserName an IT admin with rights to do this?
  - Is TargetUserName a legitimate user?
  - Was there a change ticket for this?
  - Time of change (business hours vs off-hours)?

Step 3: Attacker context check
  - Was SubjectUserName involved in prior suspicious activity?
  - Is there a brute force event before this?
  - Is there a prior successful login event from external IP?
```

## Detection Query
```spl
index=wineventlog EventCode IN (4728, 4732, 4756)
| search GroupName IN ("Domain Admins","Enterprise Admins","Administrators","Schema Admins")
| table _time, SubjectUserName, MemberName, GroupName, Computer
| sort -_time
```

## Escalation Criteria
- Unauthorized user added to Domain Admins → **ESCALATE P1**
- New account immediately added to admin group → **ESCALATE P1**
- Change performed outside business hours without ticket → **ESCALATE P2**

---

# Playbook 8: Web Shell Detection

## Alert Trigger
- New PHP/ASPX file in web root
- Unusual HTTP requests (POST to newly created script)
- Web server process spawning OS commands (cmd.exe, bash)
- File integrity monitoring alert on web directory
- EDR detecting web server spawning shells

## Triage Steps

```
Step 1: Identify suspected web shell
  - File path and name
  - When was it created/modified?
  - What does the content look like? (eval, system, shell_exec keywords)

Step 2: Analyze web logs
  - Who accessed this file via HTTP?
  - What parameters were passed?
  - What was the response code and size?
  - What IP accessed it?

Step 3: Check commands executed
  - Web server process creation events
  - What OS commands were run via the web shell?
  - Any downloads? (wget, curl, certutil)
  - Any persistence? (crontab, registry)

Step 4: Determine persistence
  - Was another account created?
  - Were SSH keys added?
  - Are there other web shells?
```

## Web Shell Detection (Linux)
```bash
# Find PHP files with dangerous functions
find /var/www -name "*.php" -exec grep -l "eval\|base64_decode\|system\|shell_exec\|passthru\|exec\|popen" {} \;

# Find recently created web files
find /var/www -newer /var/www/html/index.php -name "*.php" -type f

# Check file permissions (writable PHP files)
find /var/www -name "*.php" -perm -002

# Check web server spawning shells
grep -r "cmd.exe\|/bin/bash\|/bin/sh" /var/log/apache2/
```

## Detection Query (Splunk)
```spl
# Web server process spawning shell
index=sysmon EventCode=1 
| where ParentImage IN ("httpd","apache2","nginx","w3wp.exe","php-fpm")
AND Image IN ("cmd.exe","bash","sh","powershell.exe","python","perl")
| table _time, Computer, ParentImage, Image, CommandLine
```

## Escalation Criteria
- Any web shell confirmed → **ESCALATE P1**
- Commands executed via web shell → **ESCALATE P1**
- Privilege escalation via web shell → **ESCALATE P1**

---

## Related Notes
- [[Incident Response Lifecycle\|Incident Response Lifecycle]]
- [[Windows Event Logs\|Windows Event Logs]]
- [[Linux Logs and Commands\|Linux Logs and Commands]]
- [[SIEM Overview\|SIEM Overview]]
- [[MITRE ATT&CK Overview\|MITRE ATT&CK Overview]]
- [[Phishing Analysis\|Phishing Analysis]]
