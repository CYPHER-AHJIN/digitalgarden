---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/02-networking/networking-fundamentals/","dgPassFrontmatter":true}
---

# Networking Fundamentals for SOC
#Networking #TCP #UDP #DNS #HTTP #SOC

---

## Why Networking Matters in SOC

Every attack traverses a network. Understanding protocols, packet structure, and normal vs. abnormal network behavior is fundamental to detecting C2, data exfiltration, lateral movement, and scanning.

---

## OSI Model — SOC Perspective

| Layer | Name | Protocol | SOC Relevance |
|-------|------|----------|---------------|
| 7 | Application | HTTP, DNS, SMTP, FTP | Most attack traffic, C2, phishing |
| 6 | Presentation | SSL/TLS, encoding | Encrypted C2, HTTPS inspection |
| 5 | Session | NetBIOS, PPTP | Session hijacking |
| 4 | Transport | TCP, UDP | Port-based detection, firewall rules |
| 3 | Network | IP, ICMP | IP-based blocking, ICMP tunneling |
| 2 | Data Link | Ethernet, ARP | ARP poisoning, MAC spoofing |
| 1 | Physical | Cables, WiFi | Physical access attacks |

---

## TCP/IP Fundamentals

### TCP Handshake
```
Client                    Server
  |                          |
  |------- SYN ------------>|   (Client initiates)
  |<------ SYN-ACK ---------|   (Server acknowledges)
  |------- ACK ------------>|   (Client confirms)
  |     [Connection]         |
  |------- FIN ------------>|   (Close)
  |<------ FIN-ACK ---------|
```

**SOC Use:** 
- SYN flood = DoS attack (many SYNs, no ACK completion)
- RST responses = port is closed (port scanning indicator)
- Half-open connections = scanner behavior

### TCP Flags
| Flag | Meaning | Attack Context |
|------|---------|----------------|
| SYN | Connection initiation | Port scan (SYN scan) |
| ACK | Acknowledgment | ACK scan (firewall bypass) |
| FIN | Connection close | FIN scan |
| RST | Reset connection | Port closed response |
| PSH | Push data immediately | Data transfer |
| URG | Urgent data | Rarely seen legitimately |

---

## Key Protocols for SOC

### DNS (Port 53)
```
Normal DNS:
Client → DNS Query for "google.com" → DNS Server
DNS Server → Returns A record: 142.250.80.78 → Client

DNS Tunneling (Data Exfiltration):
Client → "eGF0YWRhdGEK.evil.com" DNS Query
         (data encoded in subdomain)
Attacker → Receives data in their DNS server logs
```

**Suspicious DNS Patterns:**
- Very long subdomains (> 50 chars in subdomain)
- High-entropy subdomains: `xkqpazmbvqrst.evil.com`
- Unusually high query volume to single domain
- Many NXDOMAIN responses (DGA)
- Querying TXT records (uncommon, used for C2)
- PTR record lookups in bulk (reverse DNS scanning)

**DNS Log Fields:**
```
timestamp, src_ip, query_name, query_type, response_code, answer
```

**Detection Query - DNS Tunneling:**
```spl
index=dns
| eval subdomain_length = len(mvindex(split(query_name, "."), 0))
| where subdomain_length > 40
| stats count by src_ip, query_name
| sort -count
```

**Detection Query - DGA Detection:**
```spl
index=dns response_code="NXDOMAIN"
| stats count as nxdomain_count by src_ip, query_name
| stats count as total_nxdomain, dc(query_name) as unique_domains by src_ip
| where unique_domains > 100
```

---

### HTTP/HTTPS (Ports 80/443)
```
HTTP Request:
GET /page.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...
Accept: text/html
Cookie: session=abc123

HTTP Response:
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: session=abc123; Secure; HttpOnly
```

**HTTP Status Codes:**
| Code | Meaning | Attack Context |
|------|---------|----------------|
| 200 | OK | Successful request |
| 301/302 | Redirect | Phishing redirect chains |
| 400 | Bad Request | Fuzzing/scanning |
| 401/403 | Unauthorized/Forbidden | Auth bypass attempts |
| 404 | Not Found | Forced browsing, scanning |
| 500 | Server Error | Exploitation attempts |
| 503 | Service Unavailable | DoS, overloaded server |

**Suspicious HTTP Patterns:**
```
# SQL injection in URL
GET /search?q=1'+OR+'1'='1

# Directory traversal
GET /../../../etc/passwd

# Command injection
GET /ping?host=127.0.0.1;cat /etc/passwd

# Unusual User-Agents (malware beacons, tools)
User-Agent: python-requests/2.28.0
User-Agent: curl/7.68.0
User-Agent: Go-http-client/1.1
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0;...)  # Outdated, suspicious

# Encoded payloads
GET /page?param=%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

**Proxy Log Fields:**
```
timestamp, src_ip, dest_domain, dest_ip, dest_port, url, method, 
status_code, bytes_in, bytes_out, user_agent, referrer
```

---

### SMTP (Email) — Ports 25, 587, 465

**Email Header Fields:**
```
From: display@legitimate.com           # What you see
Reply-To: attacker@evil.com           # Where replies go
Return-Path: bounce@evil.com          # Bounce address
Received: from [1.2.3.4]             # Mail server hops (last = final hop)
X-Originating-IP: 5.6.7.8           # True origin
Authentication-Results: spf=fail     # Email auth results
DKIM-Signature: ...                  # Email signature
```

**Email Authentication:**
- **SPF (Sender Policy Framework):** DNS record specifying which IPs can send for domain
  - `spf=pass` → Authorized sender
  - `spf=fail` → Not authorized (likely spoofed)
- **DKIM (DomainKeys Identified Mail):** Cryptographic signature on email
  - `dkim=pass` → Signature valid
  - `dkim=fail` → Signature invalid (tampered or spoofed)
- **DMARC:** Policy combining SPF and DKIM
  - `dmarc=pass` → Passes SPF or DKIM, aligns with domain
  - `dmarc=fail` → Failed both SPF and DKIM

---

### Common Ports for SOC

| Port | Protocol | Notes |
|------|----------|-------|
| 21 | FTP | File transfer, clear text |
| 22 | SSH | Encrypted remote shell |
| 23 | Telnet | Clear text, very rare legitimate use |
| 25 | SMTP | Email sending |
| 53 | DNS | Domain resolution |
| 80 | HTTP | Web (clear text) |
| 110 | POP3 | Email retrieval |
| 143 | IMAP | Email retrieval |
| 443 | HTTPS | Web (encrypted) |
| 445 | SMB | File sharing, lateral movement vector |
| 1433 | MSSQL | Microsoft SQL Server |
| 1521 | Oracle DB | Oracle database |
| 3306 | MySQL | MySQL database |
| 3389 | RDP | Remote Desktop Protocol |
| 4444 | Metasploit | Default Meterpreter listener |
| 5985/5986 | WinRM | Windows Remote Management |
| 8080/8443 | HTTP/HTTPS alt | Web apps, C2 channels |
| 8888 | Jupyter | Data science (also used in attacks) |
| 47001 | WinRM | Alternative WinRM port |

**Red Flag Ports:**
- Outbound connections to high ports (> 10000) — often C2
- Internal hosts connecting to each other on 4444, 1234, etc.
- Services on non-standard ports (HTTP on 8888)
- DNS over non-53 ports (DNS tunneling on 443)

---

## Nmap — Network Scanning

```bash
# Basic scan (most common ports)
nmap target_ip

# Full port scan (all 65535 ports)
nmap -p- target_ip

# Specific ports
nmap -p 22,80,443,3389 target_ip

# Port range
nmap -p 1-1000 target_ip

# Service version detection
nmap -sV target_ip

# OS detection (requires root)
nmap -O target_ip

# Aggressive scan (OS, version, scripts, traceroute)
nmap -A target_ip

# SYN scan (stealth, default for root)
nmap -sS target_ip

# TCP connect scan (no root required)
nmap -sT target_ip

# UDP scan (slower)
nmap -sU target_ip

# Ping scan only (no port scan)
nmap -sn 192.168.1.0/24

# Skip host discovery, scan even if no ping response
nmap -Pn target_ip

# Speed (T0=slowest, T5=fastest/noisy)
nmap -T4 target_ip  # Fast

# Script scan (NSE - vulnerability checking)
nmap --script=default target_ip
nmap --script=vuln target_ip          # Vulnerability scanning
nmap --script=smb-vuln* target_ip     # SMB vulnerabilities

# Output formats
nmap -oN output.txt target_ip         # Normal
nmap -oX output.xml target_ip         # XML
nmap -oG output.grep target_ip        # Greppable
nmap -oA output target_ip             # All formats

# Full recon scan
nmap -sV -sC -O -T4 -p- target_ip -oA full_scan

# Detect firewall evasion
nmap -f target_ip                      # Fragment packets
nmap -D RND:10 target_ip              # Decoy scan
nmap --spoof-mac 0 target_ip          # Random MAC

# Scan entire subnet
nmap -sn 192.168.1.0/24              # Host discovery
nmap -sV -T4 192.168.1.0/24         # Service scan on subnet
```

---

## Wireshark Filters

### Display Filters (Applied to captured traffic)
```
# Protocol filter
http
dns
tcp
udp
icmp
ssl or tls

# IP address
ip.addr == 192.168.1.100
ip.src == 192.168.1.100
ip.dst == 8.8.8.8

# Port
tcp.port == 443
tcp.dstport == 80
udp.port == 53

# HTTP method
http.request.method == "POST"
http.response.code == 404

# DNS query
dns.qry.name == "evil.com"
dns.qry.name contains "evil"
dns.flags.response == 0   # Requests only

# TCP flags
tcp.flags.syn == 1 && tcp.flags.ack == 0    # SYN (new connections)
tcp.flags.rst == 1                           # RST (connection resets)

# Packet size
frame.len > 1000

# Containing specific string
frame contains "password"
http contains "malware"

# Conversation between two hosts  
ip.addr == 192.168.1.100 && ip.addr == 10.0.0.1

# Follow TCP stream
right-click packet → Follow → TCP Stream

# Time-based filter
frame.time >= "2024-01-01 00:00:00" && frame.time <= "2024-01-01 23:59:59"

# Exclude common traffic (clean up noise)
not arp and not dns and not broadcast

# Find credentials in HTTP (non-HTTPS)
http.request.method == "POST" && http contains "password"

# SSL/TLS without SNI (suspicious)
ssl && !ssl.handshake.extension.type == 0

# Large packets (potential data exfil)
frame.len > 1400
```

### Capture Filters (Applied at capture time — BPF syntax)
```
# Specific host
host 192.168.1.100

# Specific network
net 192.168.1.0/24

# Specific port
port 443
port 80 or port 443

# Traffic TO specific host
dst host 8.8.8.8

# Traffic FROM specific host
src host 192.168.1.100

# Protocol
tcp
udp
icmp

# Port range
portrange 1-1024

# Exclude SSH noise
not port 22
```

---

## tshark — Command Line Wireshark

```bash
# List interfaces
tshark -D

# Capture on interface
tshark -i eth0

# Capture and save to file
tshark -i eth0 -w /tmp/capture.pcap

# Read pcap file
tshark -r capture.pcap

# Display filter (same as Wireshark)
tshark -r capture.pcap -Y "http"
tshark -r capture.pcap -Y "ip.src == 192.168.1.100"

# Extract specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e http.host

# Count connections by IP
tshark -r capture.pcap -T fields -e ip.dst | sort | uniq -c | sort -rn

# Extract HTTP URIs
tshark -r capture.pcap -Y http.request -T fields -e http.host -e http.request.uri

# Extract DNS queries
tshark -r capture.pcap -Y dns.qry.name -T fields -e frame.time -e ip.src -e dns.qry.name

# Export objects (files transferred in HTTP)
tshark -r capture.pcap --export-objects http,/tmp/extracted_files/

# Follow TCP stream
tshark -r capture.pcap -z "follow,tcp,ascii,0" -q  # Stream index 0

# Statistics
tshark -r capture.pcap -z io,phs -q           # Protocol hierarchy
tshark -r capture.pcap -z conv,tcp -q         # TCP conversations
tshark -r capture.pcap -z endpoints,ip -q     # IP endpoints
```

---

## Network Forensics Checklist

```
When analyzing suspicious network traffic:

□ Identify all unique source/destination IPs
□ Check IPs against threat intel (VirusTotal, AbuseIPDB)
□ Identify all protocols and ports used
□ Look for unusual ports or protocols
□ Analyze DNS queries (DGA detection, long subdomains)
□ Examine HTTP user agents
□ Look for clear-text credentials in HTTP/FTP/SMTP
□ Analyze data volumes per conversation
□ Check for beaconing patterns
□ Look for encoded/encrypted payloads
□ Identify any file transfers and extract files
□ Check TLS certificates (self-signed = suspicious)
□ Look for tunneling indicators
□ Correlate with endpoint logs for same timeframe
```

---

## Related Notes
- [[tcpdump & Wireshark\|tcpdump & Wireshark]]
- [[Linux Logs and Commands\|Linux Logs and Commands]]
- [[SIEM Overview\|SIEM Overview]]
- [[Threat Intelligence\|Threat Intelligence]]
- [[C2 Detection\|C2 Detection]]
