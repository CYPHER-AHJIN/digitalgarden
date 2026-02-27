---
{"dg-publish":true,"permalink":"/soc-l1-complete-knowledge-base/16-tools/tools-reference/"}
---

# Tools Reference
#Tools #SOC #DFIR #ThreatIntel #Forensics

---

## Investigation Tools

### VirusTotal
**What it does:** Multi-engine malware scanner for files, URLs, IPs, and domains. Aggregates 70+ antivirus engines and threat intelligence sources.

**When SOC uses it:**
- Check file hash before/after quarantine
- Enrich suspicious IPs and domains
- Identify malware family name
- Find related samples (pivoting)

**Typical workflow:**
```
Alert fires with hash → paste into virustotal.com → check detection count
- 0/70: Unknown (not necessarily clean — could be new)
- 1-5/70: Possibly malicious (check what vendors flag it as)
- 30+/70: Definitely malicious
- Look at: Detection names, behavior tab, relations tab, community comments

For IPs: Check "Relations" → what malware used this IP?
For Domains: Check "Details" → registration date, history
```

**API for automation:**
```python
import requests
API_KEY = "your_key"
url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
headers = {"x-apikey": API_KEY}
response = requests.get(url, headers=headers)
data = response.json()
detection_count = data['data']['attributes']['last_analysis_stats']['malicious']
```

**Limitations:** File privacy concern — don't upload confidential files. Free API limited to 4 lookups/minute. Known malware can be cleaned to change hash.

---

### AbuseIPDB
**What it does:** Community-driven database of IP addresses reported for malicious activity (spam, brute force, DDoS, port scan, etc.)

**When SOC uses it:** Every time you need to quickly determine if an IP is malicious.

**Typical workflow:**
```
Get suspicious IP from alert → check abuseipdb.com/check/[IP]
Confidence Score > 80%: Very likely malicious
Abuse Categories tell you WHAT the IP was reported for:
- Category 18: Brute force
- Category 14: Port scan  
- Category 20: DDoS
- Category 21: Bad web bot
- Category 15: Hacking
ISP = "OVH/DigitalOcean/Vultr" + high confidence = cloud VPS used for attacks
```

**API:**
```bash
curl https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=185.220.101.1" \
  -H "Key: YOUR_API_KEY" \
  -H "Accept: application/json"
```

**Limitations:** IP can be reassigned. Tor exit nodes always show high confidence — not necessarily targeted at you.

---

### Shodan
**What it does:** Search engine for internet-connected devices. Shows open ports, running services, banners, certificates.

**When SOC uses it:**
- Investigate suspicious external IPs
- Find what services an attacker's server exposes
- Check if your org's assets are exposed
- Identify Tor nodes (filter: tag:tor)
- Identify malware infrastructure

**Typical workflow:**
```
# Check specific IP:
shodan host 185.220.101.1

# Search for specific banners:
shodan search "Apache 2.2" country:US
shodan search port:3389 org:"company.com"  # RDP exposed

# CLI:
pip install shodan
shodan init YOUR_API_KEY
shodan host 1.2.3.4
shodan search "product:Cobalt Strike"
```

**Useful Shodan filters:**
```
ip:1.2.3.4             # Specific IP
hostname:evil.com      # By hostname
port:4444              # Specific port
org:"AS12345"          # By ASN
country:RU             # By country
ssl:"evil cert"        # By SSL cert content
tag:tor                # Tor exit nodes
product:"Cobalt Strike"  # Known C2 framework
```

**Limitations:** Passive — snapshot data, not real-time. Might miss recently deployed infrastructure.

---

### URLScan.io
**What it does:** Scans URLs safely, captures screenshots, analyzes resources, DNS, certificates. Shows what a page loads without you visiting it.

**When SOC uses it:** Analyze phishing URLs, check suspicious links from user reports.

**Workflow:**
```
1. Take suspicious URL from alert/user report
2. Defang it: http://evil.com → hxxp://evil[.]com (for documentation)
3. Submit DEFANGED URL to urlscan.io (re-fang before submitting)
4. Review:
   - Screenshot: What does the page look like? (Phishing login?)
   - Certificates: Is it using a Let's Encrypt cert? (Common with phishing)
   - Domains contacted: What other domains does it load?
   - IP address: Where is it hosted?
   - Technology: What framework/CMS?
```

**API:**
```bash
curl -X POST "https://urlscan.io/api/v1/scan/" \
  -H "API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com", "visibility": "private"}'
```

---

### Any.run
**What it does:** Interactive online malware sandbox. Run malware in browser and watch what it does in real time.

**When SOC uses it:** Analyze suspicious files safely, understand malware behavior without installing anything.

**Workflow:**
```
1. Upload suspicious file or URL
2. Select OS environment (Windows 10, 7, etc.)
3. Watch real-time:
   - Process tree created
   - Network connections made
   - Files created/modified
   - Registry changes
4. Download IOCs from report:
   - C2 IPs/domains
   - File hashes created
   - Registry persistence keys
   - Network indicators
5. Note: Free tier — public results. Use paid for private.
```

---

### Sysinternals Suite
Free Microsoft tools for deep Windows analysis. **Every SOC analyst needs these.**

| Tool                 | Purpose                                | SOC Use                                     |
| -------------------- | -------------------------------------- | ------------------------------------------- |
| **Process Explorer** | Process tree viewer with details       | Hunt for suspicious processes, parent-child |
| **Autoruns**         | ALL persistence locations              | Find malware persistence                    |
| **TCPView**          | Live network connections with process  | Map connections to processes                |
| **Process Monitor**  | Real-time file/registry/network events | Trace malware activity                      |
| **Sigcheck**         | File signature verification            | Verify binaries are signed                  |
| **PsExec**           | Remote process execution               | Also attacker tool (detect it)              |
| **Sysmon**           | Advanced logging daemon                | Core SOC telemetry                          |
| **AccessChk**        | Check file/registry permissions        | Privilege escalation hunting                |
| **Strings**          | Extract strings from binary            | Quick malware analysis                      |
| **Handle**           | Open file handles                      | Find locked/suspicious files                |

**Process Explorer usage:**
```
1. Run as Administrator
2. Options → Verify Image Signatures
3. Options → Check VirusTotal.com
4. Look for:
   - Red entries: Not signed or VirusTotal detections
   - Purple: Packed/unusual
   - Processes not matching expected parent (svchost.exe under cmd.exe)
   - Process running from AppData/Temp
```

**Autoruns usage:**
```
1. Run as Administrator → File → Analyze Offline System (for dead forensics)
2. Options → Scan Options → Check VirusTotal.com
3. Options → Filter Microsoft entries (hide Windows system entries)
4. Review ALL tabs: Logon, Scheduled Tasks, Services, Drivers, Boot Execute
5. Red/Orange entries = not signed or VT flagged → investigate
```

---

### Splunk
**What it does:** SIEM platform for log ingestion, search, alerting, and visualization.

**SOC use:** Primary tool for alert investigation, log correlation, threat hunting.

**Typical workflow:**
```
Alert fires → Open ticket → Navigate to Splunk
1. Set time range (alert time ± 30 minutes)
2. Run index=relevant_source EventCode=XXXX
3. Add filters to narrow results
4. Use stats to aggregate
5. Pivot to related events (same IP, same host, same user)
6. Export relevant events to ticket
```

**Limitations:** SPL learning curve. Slow on very large date ranges. License cost for full retention.

---

### Elastic (ELK) / Kibana
**What it does:** Open-source alternative to Splunk. Elasticsearch + Logstash + Kibana.

**SOC use:** Same as Splunk — log correlation and alerting.

**Typical workflow:**
```
1. Open Kibana at https://kibana-host:5601
2. Navigate: Discover (for search) or Security (for SIEM alerts)
3. Use KQL in search bar
4. Set time range in top right
5. Add filters by clicking on field values
6. Save useful queries as filters
```

---

### Volatility
**What it does:** Memory forensics framework. Analyze RAM dumps for running processes, network connections, injected code, credentials.

**SOC use:** Advanced incident response — understand what malware was doing in memory, extract injected shellcode, find credentials.

See: [[SOC_L1_Complete_Knowledge_Base/10_Forensics/Forensics_Basics\|Forensics_Basics]] for full Volatility command reference.

---

### Autopsy
**What it does:** GUI digital forensics platform. Timeline analysis, file recovery, keyword search, registry analysis.

**SOC use:** Full disk forensics after incident. Analyze seized drives or disk images.

**Limitations:** Requires disk image. Takes time to ingest large volumes.

---

### KAPE (Kroll Artifact Parser and Extractor)
**What it does:** Fast forensic triage tool. Collects specific artifacts from live system and/or processes them.

**SOC use:** Quick triage when full disk image isn't needed. Collect event logs, registry, prefetch, etc. in minutes.

```bash
# Triage live system:
kape.exe --tsource C: --tdest C:\Triage --target !SANS_Triage --tflush

# Process collected artifacts:
kape.exe --msource C:\Triage --mdest C:\Processed --module !EZParser
```

---

### MISP
**What it does:** Threat intelligence sharing platform. Store, share, and correlate IOCs.

**SOC use:** Store incident IOCs, search existing intel, share with community.

See: [[SOC_L1_Complete_Knowledge_Base/06_Threat_Intel/Threat_Intelligence\|Threat_Intelligence]] for MISP API and workflow.

---

### OSINT Tools Summary

| Tool                   | Use                               |
| ---------------------- | --------------------------------- |
| WhoisXML / DomainTools | Domain registration history       |
| SecurityTrails         | DNS history, passive DNS          |
| crt.sh                 | SSL certificate transparency logs |
| Hunter.io              | Find email addresses for a domain |
| SpiderFoot             | Automated OSINT reconnaissance    |
| Maltego                | Visual link analysis for OSINT    |
| theHarvester           | Email/IP/domain harvesting        |
| Recon-ng               | OSINT framework                   |

---

## Free Analysis Websites Quick Reference

```
Files/Hashes:
  virustotal.com            Hash, file, URL, IP lookup
  bazaar.abuse.ch           Malware sample lookup
  hybrid-analysis.com       Free sandbox
  any.run                   Interactive sandbox

IPs:
  abuseipdb.com             IP reputation
  shodan.io                 IP banner/service info
  censys.io                 Certificate/banner data
  ipinfo.io                 IP geolocation/ASN
  whois.domaintools.com     IP WHOIS

Domains:
  urlscan.io                URL analysis
  urlvoid.com               Domain reputation
  securitytrails.com        DNS history
  crt.sh                    SSL certificates
  mxtoolbox.com             Email/DNS diagnostics

Email:
  mxtoolbox.com/headers     Email header analysis
  toolbox.googleapps.com    Google header analyzer
  phishtank.org             Known phishing URLs

Threat Intel:
  otx.alienvault.com        Community threat intel
  threatfox.abuse.ch        IOCs by malware family
  attack.mitre.org          ATT&CK matrix
  mitre.org/cve             CVE database
  nvd.nist.gov              National vulnerability database
```

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/06_Threat_Intel/Threat_Intelligence\|Threat_Intelligence]]
- [[SOC_L1_Complete_Knowledge_Base/10_Forensics/Forensics_Basics\|Forensics_Basics]]
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/SOC_L1_Survival_Guide\|SOC_L1_Survival_Guide]]
- [[SOC_L1_Complete_Knowledge_Base/12_Phishing/Phishing_Analysis\|Phishing_Analysis]]
- [[SOC_L1_Complete_Knowledge_Base/11_Malware/Malware_Basics\|Malware_Basics]]
