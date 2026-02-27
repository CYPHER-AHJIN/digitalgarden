---
{"dg-publish":true,"permalink":"/soc-l1-complete-knowledge-base/12-phishing/phishing-analysis/"}
---

# Phishing Analysis
#Phishing #EmailSecurity #SOC #Analysis

---

## Overview

Phishing is the #1 initial access vector used in cyberattacks. As a SOC L1 analyst, phishing triage is one of your most common daily tasks. This note covers everything needed to analyze a phishing email professionally.

**MITRE Techniques:**
- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link
- T1566.003 — Spearphishing via Service (LinkedIn, Teams)

---

## Email Structure You Need to Know

### Email Header Fields
```
From: Display Name <sender@domain.com>    ← What user sees (SPOOFABLE)
Reply-To: attacker@evil.com              ← Where replies go (often differs)
Return-Path: bounce@evil.com            ← Bounce address
To: victim@company.com
Subject: Urgent Invoice Review
Date: Mon, 1 Jan 2024 02:15:33 -0500

Received: from mail.evil.com [1.2.3.4]  ← Last hop (closest to you)
Received: from smtp.evil.com [5.6.7.8]  ← Earlier hop
X-Originating-IP: 5.6.7.8             ← True sender IP (not always present)
Message-ID: <abc123@evil.com>          ← Should match sender domain
MIME-Version: 1.0
Content-Type: multipart/mixed

Authentication-Results: mx.company.com;
    spf=fail smtp.mailfrom=evil.com;    ← SPF FAILED
    dkim=none header.d=evil.com;        ← No DKIM
    dmarc=fail header.from=evil.com     ← DMARC FAILED
```

### Reading the Received Headers
Received headers are added by each mail server the email passes through. Read them **bottom to top** for chronological order.
```
Received: from legitimate-hop.com  ← Third hop (most recent, your server)
Received: from relay.evil.com      ← Second hop
Received: from evil-origin.com     ← First hop (ATTACKER'S SERVER) ← Read this first
```

---

## Email Authentication Deep Dive

### SPF (Sender Policy Framework)
SPF defines which mail servers are authorized to send email for a domain.

```bash
# Check SPF record for a domain
dig txt google.com | grep spf
nslookup -type=TXT google.com

# SPF result values:
# pass     → Server is authorized to send for this domain
# fail     → Server NOT authorized. Likely spoofed.
# softfail → Not authorized but soft policy (~all) — suspicious but not hard failure
# neutral  → Domain makes no claim
# none     → No SPF record exists
# permerror → SPF record syntax error
# temperror → DNS lookup failed
```

**Real-world example:**
- Email claims to be from `@paypal.com`
- SPF check fails because it came from `1.2.3.4` which is NOT PayPal's mail server
- Conclusion: Likely spoofed/phishing

### DKIM (DomainKeys Identified Mail)
DKIM adds a cryptographic signature to email headers/body. Receiving server validates signature using public key in sender's DNS.

```bash
# DKIM check result values:
# pass  → Signature valid, email not tampered
# fail  → Signature invalid (modified in transit or spoofed)
# none  → No DKIM signature (suspicious for corporate email)

# Check DKIM public key:
dig txt default._domainkey.domain.com
```

### DMARC (Domain-based Message Authentication, Reporting & Conformance)
DMARC ties SPF and DKIM together and specifies policy.

```bash
# Check DMARC record:
dig txt _dmarc.google.com

# DMARC policies:
# p=none     → Monitor only, no action
# p=quarantine → Put in spam if fails
# p=reject   → Reject if fails (strictest)

# DMARC pass: Either SPF OR DKIM passes, AND aligns with From: domain
# DMARC fail: Both SPF and DKIM fail
```

### SPF/DKIM/DMARC Quick Analysis Matrix
| SPF | DKIM | DMARC | Verdict |
|-----|------|-------|---------|
| Pass | Pass | Pass | Likely legitimate |
| Fail | None | Fail | **HIGHLY SUSPICIOUS** |
| Pass | Fail | Fail | Possible tampering |
| Softfail | None | Fail | Suspicious |
| Pass | Pass | Fail | Alignment issue (possible cousin domain) |

---

## Attachment Analysis

### Dangerous Attachment Types
```
High Risk (execute code):
.exe, .dll, .bat, .cmd, .ps1, .vbs, .js, .hta, .wsf, .jar

Medium Risk (can contain macros/exploits):
.doc, .docx, .docm, .xls, .xlsx, .xlsm, .ppt, .pptm
.pdf (can contain JavaScript, embedded executables)

Modern Phishing Containers (bypass email filters):
.iso, .img  → Contains executable inside, bypasses Mark of Web
.zip, .rar, .7z → Password-protected archives
.lnk → Shortcut files (can execute commands)
.one → OneNote files with embedded scripts (2022-2023 wave)
```

### Static Analysis of Attachments
```bash
# File type check (don't trust extension)
file suspicious_attachment.doc

# Hash and VirusTotal lookup
sha256sum suspicious.exe
# Submit hash to: virustotal.com

# Extract strings from binary
strings suspicious.exe | grep -iE "http|cmd|powershell|download|exec"

# OLE/Office document analysis
pip install oletools
oleid malicious.doc          # Check for macros, Flash, encryption
olevba malicious.doc         # Extract VBA macro code
mraptor malicious.doc        # Detect malicious macros

# PDF analysis
pip install pdfid pdf-parser
pdfid.py malicious.pdf       # Check for JS, actions, embedded files
pdf-parser.py -a malicious.pdf  # Full object analysis

# OneNote analysis
strings malicious.one | grep -iE "http|cmd|powershell"
```

### Olevba Output Interpretation
```bash
olevba suspicious.doc

# Red flags in output:
AutoOpen/AutoExec    → Runs when document opens (no user click needed)
Shell               → Executes system commands
WScript.Shell       → Run external processes
CreateObject        → COM object abuse
URLDownloadToFile   → Downloads from internet
PowerShell          → PS execution
Base64              → Obfuscation indicator
```

---

## URL/Link Analysis

**NEVER click suspicious links directly. Always use safe analysis tools.**

### URL Analysis Tools
```
URLScan.io:    urlscan.io
  → Safe browsing, screenshots, resource analysis, DNS lookup

VirusTotal:    virustotal.com/gui/url/
  → Multi-engine URL scan

Any.run:       any.run
  → Interactive sandbox, see full page behavior

URLVoid:       urlvoid.com
  → Reputation check against 30+ databases

PhishTank:     phishtank.org
  → Community-sourced phishing URL database

Google Safe:   safebrowsing.google.com/safebrowsing/report_phish/
  → Check against Google's blocklist
```

### URL Red Flags
```
# Typosquatting (common targets):
paypa1.com        (number instead of letter)
microsoft-login.com  (adds word to trusted brand)
paypаl.com        (Cyrillic 'а' looks like 'a' — punycode)
app-paypal.com    (prepends subdomain)

# Suspicious URL patterns:
http (not https) for login pages
Long random subdomain: a8h2k9m.randomsite.com/paypal/login
IP address instead of domain: http://185.220.101.1/invoice.php
Base64 in URL: /redir?url=aHR0cHM6...
URL shorteners hiding final destination: bit.ly, tinyurl.com

# Deceptive paths:
http://evil.com/www.paypal.com/login  ← evil.com is the domain, path is fake
```

### Safe URL Defanging (for documentation)
```
# Defang URLs for safe sharing in reports:
http://evil.com    → hxxp://evil[.]com
192.168.1.1        → 192[.]168[.]1[.]1
evil@domain.com    → evil[@]domain[.]com
```

---

## Phishing Investigation Workflow

### Step 1: Collect the Email Safely
```
- Ask user to send as attachment (File → Send As Attachment in Outlook)
  This preserves headers — forwarding strips them
- Or: Pull from email gateway quarantine
- Or: Pull raw .eml file from mail server
- NEVER ask user to click/re-test
```

### Step 2: Analyze Headers
```
Use online tools:
- MXToolbox Header Analyzer: mxtoolbox.com/EmailHeaders.aspx
- Google Admin Toolbox: toolbox.googleapps.com/apps/messageheader/
- Mail Header Analyzer: mailheader.org

Check:
✓ SPF result
✓ DKIM result
✓ DMARC result
✓ X-Originating-IP (true sender IP)
✓ Received hops (first received = attacker origin)
✓ Reply-To differs from From
✓ Message-ID domain matches From domain
```

### Step 3: Analyze Payload
```
Attachment:
✓ File type (file command, don't trust extension)
✓ Hash to VirusTotal
✓ OLE/VBA analysis (olevba for Office docs)
✓ PDF analysis (pdfid)
✓ Sandbox submission (Any.run, Hybrid Analysis)

Links:
✓ Defang URL first
✓ URLScan.io submission
✓ VirusTotal URL check
✓ PhishTank check
```

### Step 4: Check If User Was Compromised
```spl
-- Check proxy logs: Did user visit phishing URL?
index=proxy url="*phishing-domain.com*" earliest=-24h
| table _time, src_ip, url, user, status_code, bytes_in

-- Check DNS: Did user's workstation resolve phishing domain?
index=dns query_name="phishing-domain.com" earliest=-24h
| table _time, src_ip, query_name, answer

-- Check endpoint: Any new process from expected infection path?
index=sysmon EventCode=1 earliest=-24h
| where Computer="[USER_WORKSTATION]"
AND ParentImage IN ("outlook.exe","thunderbird.exe","chrome.exe")
AND Image IN ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
| table _time, ParentImage, Image, CommandLine

-- Check if credentials submitted (from email containing login form)
-- Look for POST requests to phishing domain
index=proxy method=POST url="*phishing-domain.com*"
```

### Step 5: Scope — How Many Users Received It?
```spl
-- Find all recipients of same phishing campaign
index=email_logs sender="phisher@evil.com" earliest=-7d
| stats count by recipient
| sort -count

-- Find emails with same subject
index=email_logs subject="Urgent Invoice Review" earliest=-7d
| table _time, sender, recipient, attachment_name

-- Check who else clicked/visited
index=proxy url="*phishing-domain.com*" earliest=-24h
| stats count by src_ip, user
```

---

## Phishing IOC Extraction Checklist

```
From email analysis:
□ Sender email address (true, not display name)
□ Reply-To address (if different from From)
□ X-Originating-IP (true sending IP)
□ Mail server IPs from Received headers
□ Phishing domain/URL

From attachment:
□ SHA256 hash of attachment
□ Malware family (from sandbox/VT)
□ C2 IPs/domains (from sandbox behavioral analysis)
□ File paths dropped (from sandbox)
□ Registry keys modified (from sandbox)
□ Mutex names (from sandbox)
□ Spawned process names

IOC Documentation format:
ATTACHMENT_SHA256: a1b2c3...
C2_IP: 185.220.101.1
PHISHING_URL: hxxp://evil[.]com/login
PHISHING_DOMAIN: evil[.]com
```

---

## Response Actions After Phishing Confirmed

```
1. Block phishing domain and URL at:
   - Email gateway (add to blocklist)
   - Web proxy (block domain)
   - DNS (RPZ block)
   - Firewall (if C2 identified)

2. Quarantine/delete email from all mailboxes
   - O365: Remove-QuarantineMessage
   - Google: Admin Console → Google Vault
   - Exchange: Search-Mailbox -DeleteContent

3. If user clicked and potentially compromised:
   - Isolate workstation (EDR isolation)
   - Reset user credentials
   - Force MFA re-enrollment
   - Initiate malware investigation playbook

4. Notify affected users:
   - What happened
   - What NOT to do (don't click/open anything again)
   - Who to contact if they notice strange behavior

5. Threat intel sharing:
   - Add IOCs to MISP
   - Share with ISAC if applicable
   - Block IOCs in SIEM feeds
```

---

## Phishing Types Reference

| Type | Description | Example |
|------|-------------|---------|
| Spearphishing | Targeted at specific individual using personal info | Email mentioning victim's boss name, project |
| Whaling | Targeting executives (C-suite) | CEO impersonation to CFO for wire transfer |
| Vishing | Voice phishing (phone calls) | "IT support" calling for credentials |
| Smishing | SMS phishing | "Your package is held — click to release" |
| BEC (Business Email Compromise) | Impersonating executive to request wire transfer | Fake CEO email to finance department |
| Credential Harvesting | Fake login page to steal username/password | Fake Office 365 login |
| Malware Delivery | Attachment or link delivers malware | Malicious Word doc with macro |
| OAuth Phishing | Tricks user into granting app permissions | Fake productivity app requesting email access |

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/SOC_Investigation_Playbooks\|SOC_Investigation_Playbooks]]
- [[SOC_L1_Complete_Knowledge_Base/11_Malware/Malware_Basics\|Malware_Basics]]
- [[SOC_L1_Complete_Knowledge_Base/03_Windows/Windows_Event_Logs\|Windows_Event_Logs]]
- [[SOC_L1_Complete_Knowledge_Base/06_Threat_Intel/Threat_Intelligence\|Threat_Intelligence]]
- [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/Incident_Response_Lifecycle\|Incident_Response_Lifecycle]]
