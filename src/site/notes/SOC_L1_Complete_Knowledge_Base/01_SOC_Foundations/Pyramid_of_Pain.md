---
{"dg-publish":true,"permalink":"/soc-l1-complete-knowledge-base/01-soc-foundations/pyramid-of-pain/"}
---

# Pyramid of Pain
#SOC #ThreatIntel #Frameworks #Detections

---

## Overview

Created by David Bianco, the Pyramid of Pain describes how difficult it is for an attacker to change their TTPs when you detect and block different types of indicators. The higher up the pyramid, the more PAIN you cause the attacker.

**Why it matters in real SOC:** This framework tells you what kind of detection work has the most lasting value. Blocking an IP takes an attacker 30 seconds to change. Detecting their techniques requires months of retooling.

---

## The Pyramid (Bottom to Top)

```
                    /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
                   /    TTPs (Top)    \   ← Hardest for attacker to change
                  /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
                 /   Tools / Malware   \
                /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
               /   Network/Host Artifacts \
              /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
             /         Domain Names        \
            /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
           /         IP Addresses           \
          /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
         /              File Hashes           \   ← Trivial for attacker to change
        /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
```

---

## Level 1: Hash Values (Trivial to Bypass)

**What they are:** MD5, SHA1, SHA256 hashes of malicious files

**Pain caused:** Trivial. Attacker changes one byte, hash changes completely.

**Value:** Still useful for known malware matching. Speed of detection is high.

**Use cases:**
- AV/EDR signature matching
- VirusTotal lookups
- Malware sample identification

**Example:**
```
SHA256: a3b5c1234... → matches known Cobalt Strike beacon
```

**Limitation:** Zero-day and polymorphic malware evades hash detection entirely.

**Detection tools:** VirusTotal, MalwareBazaar, MISP

---

## Level 2: IP Addresses (Easy to Bypass)

**What they are:** Attacker-controlled IP addresses (C2, phishing origins, exfil destinations)

**Pain caused:** Easy. Attacker spins up new VPS in minutes. $5/month.

**Value:** Immediate blocking for known malicious IPs. Good for short-term protection.

**Use cases:**
- Firewall blocklists
- SIEM rules triggering on known bad IPs
- AbuseIPDB/VirusTotal IP enrichment

**Detection Query (Splunk):**
```spl
index=firewall dest_ip IN (threat_intel_ip_list) action=allowed
| table _time, src_ip, dest_ip, dest_port, bytes
```

**Limitation:** Attackers use VPNs, TOR, CDNs (Cloudflare, Amazon) to hide. Blocking Cloudflare IPs breaks legitimate traffic.

**False Positives:** Shared hosting (legitimate sites on same IP as malicious ones), CDN IPs, Tor exit nodes used by privacy-conscious legitimate users.

---

## Level 3: Domain Names (Simple to Bypass)

**What they are:** Malicious domains used for C2, phishing, malware delivery

**Pain caused:** Simple but slightly more costly. Domains cost $5-$15/year. Takes some setup.

**Value:** More stable than IPs. Domain reputation feeds are valuable.

**Use cases:**
- DNS RPZ (Response Policy Zone) blocking
- Proxy category blocking
- Threat intel feed ingestion

**Red flags in domains:**
- Recently registered (< 30 days)
- DGA (Domain Generation Algorithm) patterns: `xkqpaz.club`
- Typosquatting: `micros0ft.com`, `paypa1.com`
- Fast flux (IP changes constantly)
- Punycode domains: `аррlе.com` (Cyrillic characters)

**Detection Query (DNS):**
```spl
index=dns 
| lookup threat_intel_domains domain AS query OUTPUT threat_level
| where threat_level="malicious"
| table _time, src_ip, query, answer
```

**MITRE:** T1568 - Dynamic Resolution

---

## Level 4: Network/Host Artifacts (Annoying to Change)

**What they are:** Observable patterns left by attacker tools.

**Network artifacts:**
- Specific URI patterns: `/a/b/c/gate.php`
- Custom HTTP headers
- Unusual User-Agent strings: `Mozilla/5.0 (compatible; MSIE 9.0;)` (outdated)
- Specific byte sequences in packets
- SSL certificate subjects/fingerprints (JA3/JA3S hashes)

**Host artifacts:**
- Registry key names
- Specific file paths: `C:\Users\Public\svhost.exe`
- Mutex names (malware creates mutexes to avoid double-infection)
- Named pipes
- Service names
- Scheduled task names

**Pain caused:** Annoying. Attacker must modify their tooling code, recompile, retest.

**Detection Example:**
```spl
index=sysmon EventCode=11 TargetFilename="C:\\Users\\Public\\*"
| table _time, Computer, User, TargetFilename, Image
```

---

## Level 5: Tools (Significant Pain)

**What they are:** The actual software the attacker uses.

**Examples:**
- Cobalt Strike (commercial C2)
- Mimikatz (credential dumping)
- BloodHound (AD enumeration)
- PsExec (lateral movement)
- Metasploit modules
- Custom implants

**Pain caused:** Significant. Attacker must write new tools, test them, ensure they evade detection. Takes weeks to months.

**Value:** Tool-based detection is very powerful. Most attackers reuse tools across campaigns.

**Detection approaches:**
- Behavior-based detection (what does the tool DO, not what it IS)
- YARA rules targeting tool signatures
- Memory scanning for tool artifacts
- Specific API call patterns

**Example - Detecting Mimikatz:**
```spl
index=sysmon EventCode=10 TargetImage="C:\\Windows\\System32\\lsass.exe"
GrantedAccess IN ("0x1010","0x1410","0x147a","0x1418")
| table _time, Computer, SourceImage, SourceProcessGUID
```

---

## Level 6: TTPs (Tactics, Techniques, Procedures) — Maximum Pain

**What they are:** The attacker's behavior patterns. HOW they operate.

**Examples:**
- Always uses spearphishing with ISO attachments
- Always creates scheduled tasks named "Windows Update"
- Always targets LSASS within 5 minutes of initial access
- Always uses DNS over HTTPS for C2

**Pain caused:** Extreme. The attacker must fundamentally change how they operate. Learn new techniques, new tradecraft. Takes months.

**Why this is the goal of mature SOC detection:**
Blocking a hash or IP gives you protection until the attacker changes it (trivial). Detecting the technique means you'll catch them even with new tools and infrastructure.

**This is what MITRE ATT&CK is for.**

**Detection example - detecting lateral movement technique:**
```spl
index=sysmon EventCode=1 
Image="C:\\Windows\\System32\\net.exe" 
CommandLine IN ("*use*","*share*","*admin$*")
| table _time, Computer, User, CommandLine
```

---

## Practical Takeaway for SOC

| Indicator Type | Detection Effort | Longevity | Priority |
|----------------|-----------------|-----------|----------|
| Hash | Low | Days | Useful but weak |
| IP | Low | Days | Block + monitor |
| Domain | Medium | Weeks | Good for early detection |
| Network Artifact | Medium | Weeks-Months | Very valuable |
| Tool | High | Months | High value |
| TTP | High | Years | Highest value |

**Interview Answer:** "The Pyramid of Pain shows that hash and IP-based detections are easily bypassed. Mature SOC programs focus on TTP-based detection using MITRE ATT&CK as the framework, because attackers cannot easily change their fundamental techniques."

---

## Related Notes
- [[MITRE ATT&CK Overview\|MITRE ATT&CK Overview]]
- [[Cyber Kill Chain\|Cyber Kill Chain]]
- [[Threat Intelligence\|Threat Intelligence]]
- [[Detection Engineering\|Detection Engineering]]
- [[Sigma Rules\|Sigma Rules]]
