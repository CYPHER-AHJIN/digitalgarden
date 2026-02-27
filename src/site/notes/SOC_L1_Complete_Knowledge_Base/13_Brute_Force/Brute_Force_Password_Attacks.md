---
{"dg-publish":true,"permalink":"/soc-l1-complete-knowledge-base/13-brute-force/brute-force-password-attacks/"}
---

# Brute Force & Password Attacks
#BruteForce #Hydra #John #Hashcat #Passwords #SOC

---

## Overview

Password-based attacks are among the most common techniques attackers use. SOC analysts need to detect them from both an alert-triage perspective AND understand the tools attackers use to contextualize what they're seeing.

**MITRE Techniques:**
- T1110.001 — Password Guessing
- T1110.002 — Password Cracking
- T1110.003 — Password Spraying
- T1110.004 — Credential Stuffing

---

## Attack Types

### Brute Force
Try every possible combination.
- **Impact:** Account lockout, detection via high failure count
- **Detection:** Event 4625 > threshold from single source

### Dictionary Attack
Try list of common passwords.
- **Common wordlists:** rockyou.txt, SecLists, CEWL-generated custom list
- **Detection:** Same as brute force but faster

### Password Spraying
Try ONE common password against MANY accounts.
- Avoids account lockout by staying under lockout threshold
- **Pattern:** 1 attempt per account, across 100+ accounts
- **Detection:** Many unique accounts getting 1-2 failures, spread over time
- **Event IDs:** 4625 (many different TargetUserName, same Password)

### Credential Stuffing
Use breached username/password pairs from data breaches.
- **Breached data sources:** HaveIBeenPwned, dark web dumps
- **Pattern:** Distributed sources (botnet), legitimate credentials
- **Detection:** High geographic diversity in source IPs, low failure rate (they know valid creds)

### Hash Cracking
Crack password hashes offline after stealing hash database.
- **No network traffic** — purely offline activity
- **Post-compromise** — attacker already has hashes

---

## Hydra — Network Authentication Brute Force

Hydra is the most common online brute force tool.

```bash
# === INSTALLATION ===
sudo apt install hydra

# === BASIC SYNTAX ===
hydra [options] target protocol

# === SSH BRUTE FORCE ===
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100
# -l: single username
# -P: password list file

hydra -L usernames.txt -P passwords.txt ssh://192.168.1.100
# -L: username list

# Custom port:
hydra -l admin -P rockyou.txt ssh://192.168.1.100 -s 2222

# === HTTP FORM BRUTE FORCE ===
# First identify: form action URL, username field name, password field name, failure message
hydra -l admin -P rockyou.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"
# Format: "/path:params:failure_string"
# ^USER^ and ^PASS^ are replaced by hydra

# HTTP GET form:
hydra -l admin -P rockyou.txt 192.168.1.100 http-get-form "/login?user=^USER^&pass=^PASS^:Login failed"

# HTTPS:
hydra -l admin -P rockyou.txt https-post-form "192.168.1.100/login:user=^USER^&pass=^PASS^:incorrect"

# === FTP BRUTE FORCE ===
hydra -l admin -P rockyou.txt ftp://192.168.1.100

# === RDP BRUTE FORCE ===
hydra -l administrator -P rockyou.txt rdp://192.168.1.100

# === SMB BRUTE FORCE ===
hydra -l administrator -P rockyou.txt smb://192.168.1.100

# === DATABASE ===
hydra -l root -P rockyou.txt mysql://192.168.1.100
hydra -l postgres -P rockyou.txt postgres://192.168.1.100

# === CONTROL OPTIONS ===
hydra -l admin -P rockyou.txt ssh://192.168.1.100 \
  -t 4 \      # 4 parallel tasks (threads)
  -w 3 \      # Wait 3 seconds between attempts (evade detection)
  -v \        # Verbose output
  -V \        # Very verbose (show each attempt)
  -o output.txt  # Save found credentials

# Resume interrupted session:
hydra -R

# === USEFUL WORDLISTS ===
/usr/share/wordlists/rockyou.txt         # Most common - 14 million passwords
/usr/share/wordlists/metasploit/unix_passwords.txt
/usr/share/seclists/Passwords/           # SecLists collection
/usr/share/seclists/Usernames/           # Username lists

# === WHEN TO USE ===
# CTF: Brute force web login, SSH, FTP
# Pentest: Test default credentials on services
# NOT in production: Can cause account lockouts, high noise
```

---

## John the Ripper — Hash Cracking

John is used to crack password hashes offline.

```bash
# === INSTALLATION ===
sudo apt install john
# Or: git clone https://github.com/openwall/john (Jumbo version, more features)

# === BASIC USAGE ===
john hashes.txt

# With wordlist:
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# With rules (variations of wordlist):
john --wordlist=rockyou.txt --rules hashes.txt

# Show cracked passwords:
john --show hashes.txt

# === HASH FORMATS ===
# John auto-detects format, but specify if needed:
john --format=NT hashes.txt         # Windows NTLM
john --format=md5crypt hashes.txt   # Linux MD5
john --format=sha256crypt hashes.txt # Linux SHA-256
john --format=bcrypt hashes.txt      # bcrypt
john --format=md5 hashes.txt         # Raw MD5

# === LINUX /etc/shadow CRACKING ===
# First, unshadow (combine passwd and shadow):
sudo unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=rockyou.txt unshadowed.txt

# === WINDOWS HASHES ===
# NTLM hash format: username:RID:LM_hash:NT_hash:::
# Example: administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
john --format=NT --wordlist=rockyou.txt ntlm_hashes.txt

# === ZIP/RAR/PDF PASSWORD ===
# Extract hash from protected file first:
zip2john protected.zip > zip_hash.txt
john zip_hash.txt --wordlist=rockyou.txt

rar2john protected.rar > rar_hash.txt
john rar_hash.txt

pdf2john protected.pdf > pdf_hash.txt
john pdf_hash.txt

ssh2john private_key > ssh_hash.txt
john ssh_hash.txt --wordlist=rockyou.txt

# === HASH IDENTIFICATION ===
john --list=formats | grep -i md5
john --list=formats | grep -i sha

# === SESSION MANAGEMENT ===
john --session=mysession hashes.txt    # Named session
john --restore=mysession               # Restore session

# === WHEN TO USE ===
# CTF: Crack hashes found in challenges
# DFIR: Crack hashes from compromised systems to understand attacker access
# Never: Against systems you don't have permission to test
```

---

## Hashcat — GPU-Accelerated Hash Cracking

Hashcat is much faster than John for GPU-equipped systems.

```bash
# === INSTALLATION ===
sudo apt install hashcat
# Or: Download from hashcat.net

# === BASIC SYNTAX ===
hashcat -m [hash_type] -a [attack_mode] hashfile wordlist

# === COMMON HASH TYPES (-m) ===
# -m 0    → MD5
# -m 100  → SHA-1
# -m 1400 → SHA-256
# -m 3200 → bcrypt
# -m 1000 → NTLM (Windows)
# -m 5600 → NetNTLMv2 (captured with Responder)
# -m 1800 → sha512crypt (Linux $6$)
# -m 500  → md5crypt (Linux $1$)
# -m 1500 → DES (old Linux)
# -m 2500 → WPA/WPA2 (WiFi)
# -m 22000 → WPA-PBKDF2-PMKID (WPA2 newer)

# Full list: hashcat --help | grep -A500 "Hash modes"

# === ATTACK MODES (-a) ===
# -a 0 → Dictionary attack
# -a 1 → Combination attack
# -a 3 → Brute-force/mask attack
# -a 6 → Hybrid: wordlist + mask
# -a 7 → Hybrid: mask + wordlist

# === DICTIONARY ATTACK ===
hashcat -m 0 -a 0 hashes.txt rockyou.txt

# With rules:
hashcat -m 0 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# === BRUTE FORCE / MASK ATTACK ===
# Mask characters:
# ?l = lowercase letter
# ?u = uppercase letter
# ?d = digit
# ?s = special character
# ?a = all printable

# 6-character lowercase:
hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?l?l

# 8-char: uppercase + lowercase + digit:
hashcat -m 0 -a 3 hashes.txt ?u?l?l?l?l?l?d?d

# Password pattern "Password123":
hashcat -m 0 -a 3 hashes.txt ?u?l?l?l?l?l?l?d?d?d

# === NTLM HASH CRACK (Windows) ===
hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt

# === NetNTLMv2 CRACK (from Responder) ===
hashcat -m 5600 -a 0 netntlmv2.txt rockyou.txt

# === SHOW CRACKED ===
hashcat -m 1000 hashes.txt --show

# === PERFORMANCE OPTIONS ===
hashcat -m 0 -a 0 hashes.txt rockyou.txt \
  --force \          # Override warnings (use carefully)
  -w 3 \             # Workload profile (1=low, 4=highest)
  --status \         # Show status during run
  --status-timer=10  # Update every 10 seconds

# === IDENTIFY HASH TYPE ===
# Online: hashes.com, hashid.exe
# Tool: hashid
hashid '$1$xyz$hashed_value_here'
hashid -e '5f4dcc3b5aa765d61d8327deb882cf99'  # md5("password")

# === WHEN TO USE ===
# CTF challenges with hash files
# DFIR: Understanding attacker-cracked credentials
# Security testing: Test password policy effectiveness
```

---

## Hash Identification Cheatsheet

```
MD5:       32 hex chars  - 5f4dcc3b5aa765d61d8327deb882cf99
SHA-1:     40 hex chars  - 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
SHA-256:   64 hex chars  - 5e884898da28047151d0e56f8dc...
SHA-512:   128 hex chars
NTLM:      32 hex chars  (same length as MD5 but different algorithm)
bcrypt:    $2y$10$...    (starts with $2b$ or $2y$)
md5crypt:  $1$...        (Linux MD5)
sha512crypt: $6$...      (Linux SHA-512, most modern)
NetNTLMv2: username::domain:challenge:hash:blob
```

---

## SOC Detection of Password Attacks

### Windows Event IDs
```
4625 - Failed logon → Brute force trigger
4771 - Kerberos pre-auth failed → Kerberos brute force
4776 - NTLM authentication → NTLM brute force
4624 - Successful logon → Check if after failures (compromise)
4740 - Account locked out → Result of brute force
```

### Detection Queries
```spl
-- Classic brute force detection
index=wineventlog EventCode=4625
| bucket _time span=5m
| stats count as failures, dc(TargetUserName) as unique_accounts, values(TargetUserName) as accounts by _time, src_ip
| where failures > 10
| sort -failures

-- Password spray detection (many accounts, few attempts each)
index=wineventlog EventCode=4625
| bucket _time span=30m
| stats dc(TargetUserName) as unique_accounts, count as total_failures by _time, src_ip
| where unique_accounts > 20 AND total_failures < (unique_accounts * 3)
| sort -unique_accounts

-- Credential stuffing (distributed sources, low failure rate)
index=wineventlog EventCode IN (4624,4625)
| bucket _time span=1h
| stats dc(src_ip) as unique_sources, 
         sum(eval(if(EventCode=4625,1,0))) as failures,
         sum(eval(if(EventCode=4624,1,0))) as successes
  by _time, TargetUserName
| where unique_sources > 10 AND successes > 0

-- SSH brute force on Linux
index=linux_auth 
| rex "Failed password for (?P<user>\S+) from (?P<src_ip>[\d.]+)"
| bucket _time span=5m
| stats count by _time, src_ip, user
| where count > 10
```

### Linux auth.log Pattern
```bash
# Failed SSH:
Jan 15 02:31:42 server sshd[12345]: Failed password for invalid user admin from 185.220.101.1 port 54321 ssh2

# Success after failures = ALERT:
Jan 15 02:35:10 server sshd[12345]: Accepted password for root from 185.220.101.1 port 54322 ssh2

# Count failures by IP:
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head 20
```

---

## Defensive Recommendations

| Defense | Addresses |
|---------|-----------|
| Account lockout policy | Brute force |
| Multi-Factor Authentication | All password attacks (hashes useless with MFA) |
| Password length ≥ 12 chars | Hash cracking resistance |
| Password complexity | Dictionary attacks |
| Rate limiting on login | Online attacks |
| CAPTCHA | Automated attacks |
| Geographic/IP-based restrictions | Credential stuffing |
| HIBP integration | Breached password detection |
| Privileged Access Workstations | Limit attack surface |
| Fail2ban (Linux) | SSH/service brute force |

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/09_Incident_Response/SOC_Investigation_Playbooks\|SOC_Investigation_Playbooks]]
- [[SOC_L1_Complete_Knowledge_Base/03_Windows/Windows_Event_Logs\|Windows_Event_Logs]]
- [[SOC_L1_Complete_Knowledge_Base/04_Linux/Linux_Logs_and_Commands\|Linux_Logs_and_Commands]]
- [[SOC_L1_Complete_Knowledge_Base/10_Forensics/Forensics_Basics\|Forensics_Basics]]
- [[SOC_L1_Complete_Knowledge_Base/07_MITRE/MITRE_ATTACK_Overview\|MITRE_ATTACK_Overview]]
