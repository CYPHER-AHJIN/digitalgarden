---
{"dg-publish":true,"permalink":"/soc-l1-complete-knowledge-base/17-interview-prep/interview-questions/"}
---

# SOC Interview Questions — Technical Q&A
#Interview #SOC #BlueTeam #TechnicalQA

---

## How to Use This Note

These are real questions asked in SOC L1/L2 interviews. For each question, understand the concept deeply — not just memorize the answer. Interviewers follow up with "why?" and "what would you do if...?"

---

## Fundamental Concepts

**Q: What is a SIEM and why do we use it?**
A: A Security Information and Event Management system collects, normalizes, correlates, and stores log data from across the environment in one central place. It enables: (1) real-time alerting via correlation rules, (2) historical log search for investigation, (3) compliance reporting, and (4) threat hunting. Without a SIEM, analysts would have to log into every system individually — impossible at scale.

---

**Q: Explain the difference between a True Positive, False Positive, True Negative, and False Negative. Which is the most dangerous?**
A:
- **TP (True Positive):** Alert fired AND attack is real
- **FP (False Positive):** Alert fired but activity is legitimate
- **TN (True Negative):** No alert AND no attack (normal operation)
- **FN (False Negative):** Attack occurred but NO alert fired

The most dangerous is **False Negative** — an attack happens and you don't know. This leads to undetected breaches, long dwell times, and maximum damage.

---

**Q: What is the Cyber Kill Chain? Name the stages.**
A: The Cyber Kill Chain (Lockheed Martin, 2011) models the stages of a targeted attack:
1. Reconnaissance — OSINT, scanning
2. Weaponization — Creating malware payload
3. Delivery — Phishing, drive-by, USB
4. Exploitation — Code execution
5. Installation — Persistence
6. Command & Control — Attacker communication
7. Actions on Objectives — Exfil, ransomware, lateral movement

**Why it matters:** Knowing the kill chain stage tells you urgency. C2 detected = attacker already has foothold.

---

**Q: What is the Pyramid of Pain? Why does it matter?**
A: David Bianco's model shows how difficult it is for attackers to change different types of indicators:
- Hash values (trivial — change one byte)
- IP addresses (easy — new VPS in minutes)
- Domain names (simple — $10 domain)
- Network/host artifacts (annoying — requires code change)
- Tools (significant — weeks of work)
- TTPs (hard — months to change tradecraft)

It matters because it shows that **hash/IP-based detection is easily bypassed**. Mature SOCs focus on TTP-based detection (MITRE ATT&CK) which causes maximum pain to attackers.

---

**Q: Explain the NIST IR Lifecycle.**
A: Four phases:
1. **Preparation** — Build IR capability before incidents (playbooks, tools, training)
2. **Detection & Analysis** — Identify incidents, triage, determine scope
3. **Containment, Eradication, Recovery** — Stop bleeding, remove threat, restore operations
4. **Post-Incident Activity** — Lessons learned, update defenses

---

**Q: What is MITRE ATT&CK?**
A: A globally accessible knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations. Organized by 14 tactics (the "why") and hundreds of techniques (the "how"). Used by SOC to: categorize detections, identify coverage gaps, communicate with standard language, and track threat actor behavior.

---

## Windows Specific

**Q: What Windows Event ID would you check to detect a brute force attack?**
A: Event ID **4625** — Failed logon. Look for high count of failures from the same source IP within a short time window. Also: 4771 (Kerberos pre-auth failed), 4776 (NTLM auth failure). If followed by **4624** (Successful logon) from same IP — account is likely compromised. Escalate immediately.

---

**Q: What logon types are associated with RDP, lateral movement, and scheduled tasks?**
A:
- **Type 2** — Interactive (local console)
- **Type 3** — Network (lateral movement via file share, WMI)
- **Type 4** — Batch (scheduled task)
- **Type 5** — Service (service account logon)
- **Type 10** — RemoteInteractive (RDP)
- **Type 9** — NewCredentials (runas /netonly — Pass the Hash indicator)

---

**Q: An alert fires showing `winword.exe` spawning `powershell.exe`. What does this mean and how do you investigate?**
A: This is a **phishing macro execution pattern**. Word macro ran and spawned PowerShell — classic T1566.001 + T1059.001. Steps:
1. Check the PowerShell command line (4688 or Sysmon 1) — is it encoded? Downloading something?
2. Decode if -EncodedCommand present (CyberChef/Python base64 decode UTF-16LE)
3. Check Sysmon Event 3 — did PowerShell make a network connection?
4. Check Sysmon Event 11 — did it drop a file?
5. Check Sysmon Event 13 — did it touch registry?
6. Review email logs — was there a phishing email to this user recently?
7. Isolate host and escalate to L2 if confirmed.

---

**Q: What Event ID tells you a scheduled task was created?**
A: Event ID **4698** — Scheduled task created. Check: TaskName (is it suspicious?), TaskContent (what command does it run?), SubjectUserName (who created it?). Red flags: task runs from AppData/Temp, uses powershell with -enc, created by non-admin user.

---

**Q: How would you detect Mimikatz in your environment?**
A: Multiple approaches:
1. **Sysmon Event 10** — Process accessing lsass.exe with specific access rights (0x1410, 0x1010, 0x147a)
2. **Process name** (but attackers rename it) — look for strings in script block logs
3. **EDR alert** on credential dumping behavior
4. **Event 4624 Logon Type 9** from unusual hosts (pass-the-hash using dumped credentials)
5. **Strings** `sekurlsa::logonpasswords` in PowerShell script block logs (Event 4104)

---

## Network Specific

**Q: What is DNS tunneling and how would you detect it?**
A: DNS tunneling encodes data in DNS query/response packets to exfiltrate data or maintain C2 communication through firewalls (DNS is rarely blocked). Detection:
- Very long subdomains (> 50 characters) — data encoded in subdomain
- High query volume to same domain
- High NXDOMAIN rate (DGA-based tunneling)
- Unusually large DNS responses
- DNS queries for TXT records (often used for C2)

Detection query:
```spl
index=dns
| eval subdomain_len = len(mvindex(split(query_name,"."),-3))
| where subdomain_len > 40
| stats count by src_ip, query_name
```

---

**Q: Explain SPF, DKIM, and DMARC.**
A:
- **SPF** — DNS record specifying which mail servers can send for a domain. `spf=fail` = email sent from unauthorized server = likely spoofed.
- **DKIM** — Cryptographic signature on email headers. `dkim=pass` = signature valid, email wasn't tampered. `dkim=fail` = spoofed or modified.
- **DMARC** — Policy combining SPF and DKIM. `dmarc=fail` = both failed = high confidence spoofing.

In phishing analysis: Check all three. `spf=fail; dkim=none; dmarc=fail` = very suspicious.

---

**Q: What is beaconing and how do you detect it?**
A: Beaconing is regular, periodic communication from an infected host to an attacker's C2 server. Malware "checks in" at intervals (e.g., every 60 seconds) to receive commands. Detection:
- High connection count to same destination
- Regular intervals (calculate standard deviation of connection times — should be low)
- Low byte variance (same sized requests each time)
- Outside business hours

```spl
index=proxy
| stats count, stdev(bytes_out) as stdev by src_ip, dest_domain
| where count > 50 AND stdev < 100
```

---

## Scenario-Based Questions

**Q: An alert fires for a failed login from an IP in Russia for the CEO's account. What do you do?**
A:
1. Check AbuseIPDB — is this IP known malicious?
2. Check if there was a successful login after the failures from this IP (4624)
3. Check if CEO has any travel or VPN that might explain this
4. Check if this account has MFA enabled
5. Check how many failures and over what time period
6. If no success: Document, monitor, consider blocking IP, notify security management
7. If success detected: **ESCALATE P1** immediately — account compromise

---

**Q: You receive a phishing email report from a user. They say they may have clicked a link. Walk me through your investigation.**
A:
1. Ask user to forward email as attachment (preserves headers)
2. Analyze headers: SPF/DKIM/DMARC, originating IP
3. Defang and submit URL to URLScan.io — is it a phishing page?
4. Check proxy logs: Did user's IP actually visit the URL?
5. Check DNS logs: Did user's workstation resolve the phishing domain?
6. Check endpoint: Any new process after email received? (Sysmon 1, Office spawning shell)
7. If user visited and potentially submitted credentials: Force password reset, disable account temporarily
8. If malware executed: Isolate endpoint, escalate to L2
9. Block domain at proxy/firewall
10. Check for other users who received same email

---

**Q: What is lateral movement and how would you detect it in your SIEM?**
A: Lateral movement is when an attacker moves from their initial foothold to other systems in the network, typically looking for crown jewels (AD, file servers, sensitive data). Detection:
- **Event 4624 Type 3** (Network logon) from workstations that don't normally authenticate to each other
- **4648** — Logon with explicit credentials (common in lateral movement tools)
- A single user authenticating to many different hosts in short period
- wmic /node: commands or PsExec in process logs
- SMB connections to Admin$ or C$

```spl
index=wineventlog EventCode=4624 Logon_Type=3
| stats dc(Computer) as unique_hosts, values(Computer) as host_list by User, src_ip
| where unique_hosts > 3
```

---

**Q: What does it mean when you see `vssadmin delete shadows` in a process creation log?**
A: This is a **critical ransomware indicator**. Shadow Volume Copies (VSS) are Windows backup snapshots. Attackers delete them before encrypting files to prevent recovery without paying the ransom. MITRE: T1490 — Inhibit System Recovery. Response: **ESCALATE P1 immediately**, isolate affected systems, check for mass file encryption, check other systems for same activity — ransomware may be spreading.

---

**Q: What is pass-the-hash and how is it different from credential stuffing?**
A:
- **Pass-the-Hash (PTH):** Using the NTLM hash directly for authentication without knowing the plaintext password. Attacker extracts hash from memory (Mimikatz) and uses it to authenticate to other systems. MITRE: T1550.002
- **Credential Stuffing:** Using known username/password combinations from data breaches against other services (people reuse passwords)

PTH detection: Event 4624 Logon Type 3 with NTLM authentication from unusual source, or Logon Type 9 (NewCredentials/runas). No brute force pattern — one attempt, succeeds.

---

**Q: A user calls saying their files all suddenly have weird extensions and there's a file called RANSOM_NOTE.txt. What do you do immediately?**
A:
1. **Immediately disconnect network cable** (or call user to do it) / EDR isolation
2. Do NOT reboot — memory evidence
3. Note the time, machine name, user
4. Escalate to L2/manager immediately — P1 incident
5. Begin checking other machines for similar symptoms
6. Check proxy/firewall for C2 or exfiltration before encryption
7. Check for shadow copy deletion events
8. Identify the malware strain if possible (check ransom note for name)
9. Alert management, legal, potentially law enforcement per policy
10. Begin IR process per ransomware playbook

---

## Log Analysis Challenge Examples

**Q: Looking at this Splunk output, what's happening?**
```
src_ip: 185.220.101.1  failures: 1847  accounts_targeted: 342  time: 02:15 AM
```
A: This is a **password spraying attack**. One IP targeting 342 different accounts with a low number of attempts per account (about 5 each) to stay under lockout thresholds. The 2:15 AM timing and likely Tor/VPS IP suggests automated attack. Check if any accounts had successful logins after this.

---

**Q: What does this command line tell you?**
```
powershell.exe -nop -w hidden -enc JABhAD0AIgBoAHQAdABwADoALwAvAA==...
```
A: This is suspicious PowerShell execution with:
- `-nop` (no profile) — avoids triggering profile-based detection
- `-w hidden` — hidden window, user won't see a terminal
- `-enc` — Base64 encoded command — **obfuscation/evasion**

Next step: Decode the base64 (UTF-16LE in PowerShell): `base64 -d | iconv -f utf-16le -t utf-8`. Look for download cradles (IEX, DownloadString), AMSI bypass, persistence commands.

---

## Common Interview Mistakes to Avoid

1. Saying "I would block the IP" without first verifying it's not legitimate scanning
2. Not mentioning false positive consideration for every detection scenario
3. Forgetting to document everything in the ticket
4. Not escalating when you should — when in doubt, escalate
5. Confusing MITRE tactics (the "why") with techniques (the "how")
6. Not knowing the difference between T1059.001 (PowerShell) and T1059.003 (cmd.exe)
7. Saying "just reinstall the OS" without preserving forensic evidence first

---

## Questions YOU Should Ask the Interviewer

- What SIEM platform do you use? (Splunk, Elastic, Sentinel?)
- What's the average alert volume per analyst per day?
- What's the escalation process like?
- Do you have EDR deployed on all endpoints?
- What's the process for L1 to move to L2?
- What logging coverage do you have? (Windows + Sysmon? Linux? Cloud?)
- Do you have a threat intel platform? (MISP, OpenCTI?)

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/SOC_Fundamentals\|SOC_Fundamentals]]
- [[SOC_L1_Complete_Knowledge_Base/03_Windows/Windows_Event_Logs\|Windows_Event_Logs]]
- [[SOC_L1_Complete_Knowledge_Base/07_MITRE/MITRE_ATTACK_Overview\|MITRE_ATTACK_Overview]]
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/Cyber_Kill_Chain\|Cyber_Kill_Chain]]
- [[SOC_L1_Complete_Knowledge_Base/01_SOC_Foundations/Pyramid_of_Pain\|Pyramid_of_Pain]]
- [[SOC_L1_Complete_Knowledge_Base/19_Career/SOC_L1_to_L2_Roadmap\|SOC_L1_to_L2_Roadmap]]
