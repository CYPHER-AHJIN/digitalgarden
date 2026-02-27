---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/19-career/home-lab-setup-guide/","dgPassFrontmatter":true}
---

# Home Lab Setup Guide — Free Tools Only
#HomeLab #Setup #Practical #SOC #BlueTeam

---

## Why Build a Home Lab?

Every skill in your SOC notes requires hands-on practice to actually stick. You cannot learn memory forensics by reading. You cannot learn Splunk by watching YouTube. The home lab is where reading becomes skill.

**What you can do in your lab that you CAN'T do at work:**
- Actually run malware (safely isolated)
- Break things and fix them
- Test attack tools to understand what defenders see
- Build and tune detection rules with full control
- Practice forensics on known-compromised systems

**Cost:** $0 (all free tools) — only requirement is a decent computer (8GB+ RAM recommended, 16GB ideal)

---

## Core Architecture

```
Your Physical Machine
├── Hypervisor (VirtualBox or VMware Workstation Player)
│   ├── Windows 10/11 Victim VM
│   │   ├── Sysmon installed
│   │   └── Winlogbeat or NXLog forwarding to SIEM
│   ├── Windows Server 2019 VM (optional - Active Directory)
│   │   └── Domain Controller
│   ├── Ubuntu Server VM (SIEM + Log Collector)
│   │   ├── Splunk Free or ELK Stack
│   │   └── Receives logs from all VMs
│   └── Kali Linux VM (Attacker)
│       └── Isolated on attacker network segment
│
└── Network Segmentation
    ├── Victim network: 192.168.56.0/24 (VirtualBox Host-Only)
    └── Attacker: Same or NAT (can reach victims, not internet)
```

---

## Step 1: Hypervisor Setup

### VirtualBox (Free — Recommended for Beginners)
```
Download: virtualbox.org/wiki/Downloads
- Select your OS version
- Install normally
- Also install: Extension Pack (same page) for USB support

Key settings after install:
- File → Preferences → Network → Host-Only Networks
  → Create: 192.168.56.0/24 (this isolates VMs from internet)
```

### VMware Workstation Player (Free for Personal Use)
```
Download: vmware.com/products/workstation-player
- Better performance than VirtualBox
- More compatible with enterprise labs (uses same .vmdk format as work)
```

---

## Step 2: Download VM Images

### Windows Evaluation VMs (Free — 90-day trial, fully functional)
```
Source: microsoft.com/en-us/evalcenter/

Windows 10 Enterprise: 
https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise
→ Download ISO
→ Install in VirtualBox (create new VM → attach ISO)

Windows Server 2019:
https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019
→ Same process

IMPORTANT: Take a snapshot BEFORE installing tools
           Take a snapshot AFTER base configuration
           Revert snapshot instead of rebuilding each time
```

### Kali Linux (Free — Attacker VM)
```
Source: kali.org/get-kali/

Options:
1. Kali VirtualBox image (pre-built, easiest):
   kali.org/get-kali/#kali-virtual-machines
   → Download VirtualBox image → Import in VirtualBox

2. Kali ISO (manual install):
   kali.org/get-kali/#kali-installer-images

Default credentials: kali/kali
First command: sudo apt update && sudo apt upgrade -y
```

### Ubuntu Server 22.04 (SIEM Host)
```
Source: ubuntu.com/download/server
→ Download ISO
→ Create VM: 4GB+ RAM, 50GB+ disk
→ Install with defaults
→ Set static IP on host-only network adapter
```

---

## Step 3: Configure Windows Victim VM

### Install Sysmon (Most Important Step)
```powershell
# Download Sysmon
# From: docs.microsoft.com/sysinternals/downloads/sysmon

# Download SwiftOnSecurity's config (community-maintained, production-quality)
# From: github.com/SwiftOnSecurity/sysmon-config

# Install command (run as Administrator):
sysmon64.exe -accepteula -i sysmonconfig-export.xml

# Verify installation:
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

### Enable Windows Audit Policies
```cmd
# Enable process creation with command line (CRITICAL)
# Via GPO or directly:
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Enable logon auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Enable account management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Enable object access (for file/share auditing)
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable

# Enable PowerShell Script Block Logging
# Registry method:
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# Verify:
auditpol /get /category:*
```

### Install Winlogbeat (Log Forwarding to ELK)
```yaml
# Download: elastic.co/downloads/beats/winlogbeat
# Extract to C:\Program Files\Winlogbeat

# Edit winlogbeat.yml:
winlogbeat.event_logs:
  - name: Security
    event_id: 4624, 4625, 4648, 4688, 4698, 4720, 4732, 1102, 7045
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104

output.elasticsearch:
  hosts: ["192.168.56.10:9200"]   # Your ELK VM IP
  # OR for Splunk:
output.logstash:
  hosts: ["192.168.56.10:5044"]

# Install as service:
cd "C:\Program Files\Winlogbeat"
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

---

## Step 4: Set Up SIEM

### Option A: Splunk Free (Recommended — Most Jobs Use Splunk)

```bash
# On Ubuntu SIEM VM:

# Download Splunk Free (500MB/day limit — more than enough for lab)
# https://www.splunk.com/en_us/download/splunk-enterprise.html
# Create free account, download .deb package

# Install:
sudo dpkg -i splunk-*.deb
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start

# Access at: http://[siem_ip]:8000
# Default: admin / changeme

# Install Splunk Add-on for Sysmon:
# Apps → Find More Apps → "Splunk Add-on for Microsoft Sysmon"

# Install Windows TA:
# Apps → Find More Apps → "Splunk Add-on for Microsoft Windows"

# Configure receiving port for Splunk Universal Forwarder:
# Settings → Forwarding and Receiving → Configure Receiving → New Port: 9997

# Create index:
# Settings → Indexes → New Index
# Name: wineventlog
# Name: sysmon
```

**On Windows VM — Install Splunk Universal Forwarder:**
```powershell
# Download: splunk.com/en_us/download/universal-forwarder.html
# Install with GUI or silent:
msiexec.exe /i splunkforwarder.msi RECEIVING_INDEXER="192.168.56.10:9997" WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_APP_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 /quiet

# Monitor Sysmon logs:
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" add monitor "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" -index sysmon
```

---

### Option B: ELK Stack (Elastic + Logstash + Kibana) — Free and Open Source

```bash
# On Ubuntu SIEM VM (20.04 or 22.04):

# Install Java
sudo apt install default-jdk -y

# Add Elastic repo
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update

# Install Elasticsearch
sudo apt install elasticsearch -y
sudo systemctl enable elasticsearch && sudo systemctl start elasticsearch

# Install Kibana
sudo apt install kibana -y
sudo systemctl enable kibana && sudo systemctl start kibana

# Install Logstash (optional - for log parsing)
sudo apt install logstash -y

# Install Beats (for Windows log collection):
sudo apt install filebeat -y

# Access Kibana at: http://[siem_ip]:5601
# Run enrollment token command shown at startup

# Enable Security plugin:
# /etc/elasticsearch/elasticsearch.yml
# xpack.security.enabled: true
```

---

## Step 5: Set Up Active Directory (Optional but Recommended)

Having a real AD domain lets you practice:
- Kerberoasting, AS-REP Roasting
- Pass-the-Hash, Pass-the-Ticket
- BloodHound enumeration
- LDAP attacks

```powershell
# On Windows Server 2019 VM:

# Install AD DS role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest `
    -DomainName "lab.local" `
    -DomainNetbiosName "LAB" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
    -InstallDns `
    -Force

# Server will restart. After restart, join your Windows 10 VM to the domain:
# System Properties → Computer Name → Change → Domain: lab.local

# Create test users:
New-ADUser -Name "John Smith" -SamAccountName "jsmith" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Service Account" -SamAccountName "svc_sql" -AccountPassword (ConvertTo-SecureString "ServicePass1!" -AsPlainText -Force) -Enabled $true

# Create service principal (for Kerberoasting lab):
Set-ADUser svc_sql -ServicePrincipalNames @{Add='MSSQLSvc/server01.lab.local:1433'}
```

---

## Step 6: Kali Linux Configuration

```bash
# Update everything:
sudo apt update && sudo apt upgrade -y

# Tools pre-installed that matter for blue team understanding:
# - nmap (port scanning)
# - hydra (brute force)
# - john / hashcat (password cracking)
# - metasploit (exploitation framework)
# - wireshark (PCAP analysis)
# - impacket (AD attack tools)

# Install additional blue team tools:
sudo apt install -y volatility3 autopsy sleuthkit foremost binwalk exiftool

# Install CyberChef (local web app for encoding/decoding):
# Download: github.com/gchq/CyberChef/releases → CyberChef_v9.x.x.zip
# Open index.html in browser - no installation needed
```

---

## Step 7: Essential Free Tool Downloads

### For Windows Forensics
```
Eric Zimmermann's Tools (MUST HAVE):
  Source: ericzimmerman.github.io
  Tools: PECmd (Prefetch), LECmd (LNK), JLECmd (Jump Lists),
         MFTECmd (MFT), AmcacheParser, AppCompatCacheParser,
         EvtxECmd (Event logs), RECmd (Registry), TimelineExplorer

Sysinternals Suite:
  Source: docs.microsoft.com/sysinternals/downloads/sysinternals-suite
  Tools: Process Explorer, Autoruns, TCPView, Process Monitor, Sysmon, etc.

KAPE (Forensic Triage):
  Source: ericzimmerman.github.io/#!index.md (KAPE section)
  Run on: Live Windows system or image

FTK Imager (Disk/Memory Imaging):
  Source: accessdata.com/product-download (free)
  Use: Memory capture, disk imaging

Autopsy (Digital Forensics Platform):
  Source: sleuthkit.org/autopsy/download.php (free)
  Use: Full disk forensic analysis
```

### For Malware Analysis
```
PEStudio (PE file analysis):
  Source: winitor.com (free)

x64dbg (Windows Debugger):
  Source: x64dbg.com (free)

dnSpy (.NET decompiler):
  Source: github.com/dnSpy/dnSpy/releases (free)

FLOSS (FireEye Labs Obfuscated String Solver):
  Source: github.com/mandiant/flare-floss (free)

CyberChef (Encoding/Decoding):
  Source: gchq.github.io/CyberChef/ (web, free)
  Or: Download offline version from GitHub releases
```

### For Network Analysis
```
Wireshark:
  Source: wireshark.org (free)
  
NetworkMiner (PCAP Analysis):
  Source: netresec.com/?page=NetworkMiner (free version)

Zeek (formerly Bro - network security monitor):
  Source: zeek.org (free)
  Good for: Generating conn.log, dns.log, http.log from PCAP
```

---

## Step 8: Practice Resources

### Free PCAP Collections
```
Malware Traffic Analysis: malware-traffic-analysis.net
  → Weekly exercises with PCAP + answers

Wireshark Sample Captures: wiki.wireshark.org/SampleCaptures

NETRESEC: netresec.com/?page=PcapFiles
  → Collection of interesting PCAPs

SecurityDatasets: github.com/OTRF/Security-Datasets
  → Simulated attack datasets including PCAPs and logs
```

### Free Memory Dump Collections
```
MemLabs: github.com/stuxnet999/MemLabs
  → 6 progressive memory forensics CTF challenges

CyberDefenders: cyberdefenders.org
  → Memory forensics challenges

Digital Corpora: digitalcorpora.org
  → Academic forensics datasets
```

### Free Vulnerable Applications (For Web Attack Practice)
```
DVWA (Damn Vulnerable Web Application):
  Source: github.com/digininja/DVWA
  Deploy with: docker run --rm -it -p 80:80 vulnerables/web-dvwa

WebGoat:
  Source: github.com/WebGoat/WebGoat
  Deploy: java -jar webgoat-server.jar --server.port=8080

Juice Shop (OWASP):
  Source: github.com/juice-shop/juice-shop
  Deploy: docker pull bkimminich/juice-shop && docker run -d -p 3000:3000 bkimminich/juice-shop

Metasploitable2 (Full vulnerable Linux VM):
  Source: sourceforge.net/projects/metasploitable/
```

---

## Minimum Viable Lab (Low-End Hardware)

If your computer has less than 8GB RAM, use this minimal setup:

```
Option 1: TryHackMe/HackTheBox (No local setup needed)
  - Pay $14/month TryHackMe
  - Complete SOC Level 1 path entirely in-browser
  - Zero local resource requirement

Option 2: Single VM approach
  - 1x Kali VM (2GB RAM)
  - Run Splunk free tier locally on your main OS (Windows)
  - Import log files instead of live forwarding

Option 3: Cloud Lab (AWS/Azure free tier)
  - AWS free tier: t2.micro EC2 for Splunk
  - Windows Server 2019 EC2 for event log generation
  - ~$0-5/month if managed carefully
```

---

## Lab Validation Tests

After setup, verify everything works:

```
[ ] Can you see Sysmon events in Splunk/ELK from Windows VM?
[ ] Does running cmd.exe on Windows VM create a Sysmon Event 1?
[ ] Does running nmap from Kali show up in firewall/IDS logs?
[ ] Can you SSH brute force Ubuntu and see it in auth.log?
[ ] Can Volatility parse a memory dump from your Windows VM?
[ ] Can Wireshark capture traffic between VMs?
[ ] Does your SIEM alert fire when you simulate a brute force?
[ ] Can you access DVWA and generate SQL injection attempts that appear in web logs?
```

---

## Related Notes
- [[SOC_L1_Complete_Knowledge_Base/20_Labs/Detection_Labs_30_Ideas\|Detection_Labs_30_Ideas]]
- [[SOC_L1_Complete_Knowledge_Base/19_Career/SOC_L1_to_L2_Roadmap\|SOC_L1_to_L2_Roadmap]]
- [[SOC_L1_Complete_Knowledge_Base/10_Forensics/Forensics_Basics\|Forensics_Basics]]
- [[SOC_L1_Complete_Knowledge_Base/05_SIEM/SIEM_Overview_Splunk_ELK\|SIEM_Overview_Splunk_ELK]]
- [[SOC_L1_Complete_Knowledge_Base/04_Linux/Linux_Logs_and_Commands\|Linux_Logs_and_Commands]]
- [[SOC_L1_Complete_Knowledge_Base/03_Windows/Windows_Event_Logs\|Windows_Event_Logs]]
