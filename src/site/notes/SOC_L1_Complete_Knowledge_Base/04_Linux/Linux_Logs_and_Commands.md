---
{"dg-publish":true,"dg-home":null,"permalink":"/soc-l1-complete-knowledge-base/04-linux/linux-logs-and-commands/","dgPassFrontmatter":true}
---

# Linux Logs & Commands
#Linux #Logs #Commands #DFIR #Detection

---

## Overview

Linux log analysis is essential for monitoring servers, containers, and network infrastructure. Unlike Windows Event IDs, Linux logging varies by distribution and configuration.

**Why it matters in real SOC:** Most servers, cloud infrastructure, and network devices run Linux. Understanding Linux logs is critical for detecting attacks against web servers, SSH, databases, and cloud workloads.

---

## Key Log File Locations

```bash
# Authentication logs
/var/log/auth.log          # Debian/Ubuntu - SSH, sudo, su, PAM auth
/var/log/secure            # RHEL/CentOS equivalent

# System logs
/var/log/syslog            # Ubuntu general system messages
/var/log/messages          # RHEL/CentOS general messages
/var/log/kern.log          # Kernel messages

# Service-specific logs
/var/log/apache2/          # Apache web server
/var/log/nginx/            # Nginx web server
/var/log/mysql/            # MySQL
/var/log/postgresql/       # PostgreSQL

# Package management
/var/log/dpkg.log          # Debian package installs
/var/log/yum.log           # RHEL/CentOS package installs
/var/log/dnf.log           # Fedora/RHEL8+ package installs

# Cron jobs
/var/log/cron              # Cron execution log
/var/log/cron.log          # Ubuntu cron log

# Audit logs (auditd)
/var/log/audit/audit.log   # Linux audit framework - most comprehensive

# Systemd journal
journalctl                 # Access via command (not a file path)

# Bash history
~/.bash_history            # User command history
/root/.bash_history        # Root command history
```

---

## journalctl — Systemd Journal Query

```bash
# View all logs
journalctl

# Follow live (like tail -f)
journalctl -f

# Last N lines
journalctl -n 100

# Logs since specific time
journalctl --since "2024-01-01 00:00:00"
journalctl --since "1 hour ago"
journalctl --since today

# Time range
journalctl --since "2024-01-01" --until "2024-01-02"

# Specific service
journalctl -u ssh
journalctl -u apache2
journalctl -u cron

# Priority filter (0=emergency to 7=debug)
journalctl -p err             # errors and above
journalctl -p warning..err    # warnings to errors

# Boot-specific logs
journalctl -b                 # Current boot
journalctl -b -1              # Previous boot
journalctl --list-boots       # All recorded boots

# Kernel messages only
journalctl -k

# By user
journalctl _UID=1001

# JSON output for parsing
journalctl -o json | python3 -m json.tool

# Grep within journal
journalctl | grep "Failed password"
journalctl -u ssh | grep "Invalid user"

# Show logs from a specific PID
journalctl _PID=1234
```

---

## grep — Pattern Searching

```bash
# Basic search
grep "Failed password" /var/log/auth.log

# Case insensitive
grep -i "failed" /var/log/auth.log

# Show line number
grep -n "Failed password" /var/log/auth.log

# Recursive (search all files in directory)
grep -r "error" /var/log/

# Count matches
grep -c "Failed password" /var/log/auth.log

# Show context (3 lines before and after)
grep -A 3 -B 3 "Failed password" /var/log/auth.log

# Extended regex
grep -E "Failed|Invalid|error" /var/log/auth.log

# Invert match (show lines NOT matching)
grep -v "Accepted publickey" /var/log/auth.log

# Multiple patterns
grep -e "Failed password" -e "Invalid user" /var/log/auth.log

# Show only matching part
grep -o "from [0-9.]*" /var/log/auth.log

# Pipe chain for brute force detection
grep "Failed password" /var/log/auth.log | 
    grep -oP "from \K[0-9.]+" | 
    sort | uniq -c | sort -rn | head -20
```

---

## awk — Field Processing

```bash
# Print specific field (space-delimited)
awk '{print $1}' /var/log/auth.log        # Timestamps
awk '{print $11}' /var/log/auth.log       # IP address in auth.log

# Extract failed login IPs
awk '/Failed password/{print $13}' /var/log/auth.log

# Count occurrences
awk '/Failed password/{ips[$13]++} END {for(ip in ips) print ips[ip], ip}' /var/log/auth.log | sort -rn

# Conditional print
awk '$5=="sshd"' /var/log/auth.log

# Print specific columns from CSV
awk -F',' '{print $1,$3,$5}' access.log

# Sum a column
awk '{sum += $10} END {print sum}' access.log

# Apache log - count unique IPs
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# Filter by HTTP status code (Apache log)
awk '$9 == "404"' /var/log/apache2/access.log

# Count requests per status code
awk '{print $9}' /var/log/apache2/access.log | sort | uniq -c | sort -rn
```

---

## sed — Stream Editor

```bash
# Replace text
sed 's/old_text/new_text/g' file.log

# Delete matching lines
sed '/^#/d' file.conf          # Remove comment lines
sed '/Failed/d' auth.log       # Remove lines matching pattern

# Print specific line numbers
sed -n '10,20p' file.log       # Print lines 10-20

# Print lines matching pattern
sed -n '/Failed password/p' auth.log

# Extract timestamp from log line
sed 's/\(.*\) sshd.*/\1/' auth.log

# In-place edit with backup
sed -i.bak 's/old/new/g' file.log

# Remove blank lines
sed '/^$/d' file.log
```

---

## ps — Process Status

```bash
# All processes, full info
ps aux

# Process tree (visual hierarchy)
ps auxf          # Or:
pstree -p        # More visual

# Find specific process
ps aux | grep "apache"
ps aux | grep "python"

# Sort by CPU usage
ps aux --sort=-%cpu | head -20

# Sort by memory
ps aux --sort=-%mem | head -20

# Processes for specific user
ps -u www-data
ps -u root

# Full command line info
ps -ef | grep python

# Process with PID details
ps -p 1234 -o pid,ppid,user,command

# Show threads
ps -eLf | grep httpd

# Monitor continuously (alternatives to top)
ps aux | sort -k3 -rn | head -10   # CPU
watch -n 2 'ps aux | sort -k3 -rn | head -10'
```

**SOC Use:** Identify unusual processes, check process parent-child relationships, find persistence via long-running processes.

**Red Flags:**
```bash
# Process running from suspicious location
ps aux | grep "/tmp/"
ps aux | grep "/var/tmp/"
ps aux | grep "/dev/shm/"   # Memory-based execution

# Shell running from unusual parent
ps aux | grep "bash" | grep -v "pts"

# Python/Perl/Ruby HTTP servers (exfil)
ps aux | grep "python.*http.server"
ps aux | grep "ruby.*webrick"

# Netcat listeners (backdoor)
ps aux | grep "nc -l"
ps aux | grep "ncat"
```

---

## netstat & ss — Network Connections

```bash
# All connections (netstat)
netstat -tulpn      # TCP/UDP listening ports with PID
netstat -anp        # All connections with PID
netstat -ano        # All connections without hostname resolution

# ss (modern replacement for netstat - faster)
ss -tulpn           # Listening ports
ss -anp             # All connections with process
ss -tp              # TCP with process names
ss -s               # Summary statistics

# Show established connections only
netstat -anp | grep ESTABLISHED
ss -tp state established

# Find what's listening on specific port
netstat -tulpn | grep :22
ss -tulpn | grep :22

# Find process using specific port
netstat -tulpn | grep :4444
lsof -i :4444

# Connections to specific remote IP
netstat -an | grep "192.168.1.100"

# Count connections by state
netstat -an | awk '{print $6}' | sort | uniq -c | sort -rn

# Count connections by remote IP
netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
```

---

## lsof — List Open Files

```bash
# All open files
lsof

# Open files for specific process
lsof -p 1234

# Open files for specific user
lsof -u www-data

# Network connections (all)
lsof -i

# TCP connections
lsof -i tcp

# Specific port
lsof -i :4444
lsof -i :80

# Files in specific directory
lsof +D /var/www/

# Deleted files still open (evidence of file hiding)
lsof | grep deleted

# Find process holding specific file
lsof /var/log/auth.log
```

---

## tcpdump — Packet Capture

```bash
# Capture all traffic on interface
tcpdump -i eth0

# Save to pcap file
tcpdump -i eth0 -w /tmp/capture.pcap

# Read pcap file
tcpdump -r /tmp/capture.pcap

# Capture specific host
tcpdump -i eth0 host 192.168.1.100

# Capture specific port
tcpdump -i eth0 port 443
tcpdump -i eth0 port 22

# Capture traffic to/from subnet
tcpdump -i eth0 net 192.168.1.0/24

# Show packet contents (ascii)
tcpdump -i eth0 -A

# Show packet contents (hex + ascii)
tcpdump -i eth0 -XX

# Don't resolve hostnames (faster)
tcpdump -n -i eth0

# Capture with filter
tcpdump -i eth0 'tcp and port 80 and host 10.0.0.1'

# Capture DNS queries (C2 detection)
tcpdump -i eth0 -n port 53

# Capture ICMP (ping-based C2)
tcpdump -i eth0 icmp

# Verbose output
tcpdump -v -i eth0

# Limit packet count
tcpdump -c 100 -i eth0

# Complex filter - exclude SSH, capture everything else
tcpdump -i eth0 'not port 22'

# Capture traffic and pipe to tshark for analysis
tcpdump -i eth0 -w - | tshark -r -
```

---

## find — File Search

```bash
# Find by name
find /var/www -name "*.php"
find / -name "mimikatz" 2>/dev/null

# Find recently modified files (last 24 hours)
find / -mtime -1 -type f 2>/dev/null

# Find recently modified files in last 10 minutes
find / -mmin -10 -type f 2>/dev/null

# Find SUID files (privilege escalation targets)
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Find world-writable files (config tampering)
find / -perm -002 -type f 2>/dev/null

# Find hidden files
find / -name ".*" -type f 2>/dev/null

# Find files larger than 100MB (data staging for exfil)
find / -size +100M -type f 2>/dev/null

# Find files owned by specific user
find /var/www -user www-data -type f

# Find executables in web directory (webshell detection)
find /var/www -name "*.php" -newer /var/www/html/index.php
find /var/www -name "*.php" -executable

# Find files modified in specific date range
find / -newermt "2024-01-01" ! -newermt "2024-01-02" -type f 2>/dev/null

# Find files with specific permissions
find / -perm 777 -type f 2>/dev/null

# Execute command on found files
find /tmp -name "*.sh" -exec ls -la {} \;
find /var/www -name "*.php" -exec grep -l "eval\|base64_decode\|system\|shell_exec" {} \;
```

---

## strings — Extract Human-Readable Text

```bash
# Extract strings from binary
strings malware.exe

# Minimum string length (default 4)
strings -n 8 malware.exe

# Offset information
strings -t x malware.exe    # Hex offsets
strings -t d malware.exe    # Decimal offsets

# From specific file section
strings malware.exe | grep -i "http"
strings malware.exe | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}"  # IP addresses
strings malware.exe | grep -i "password\|passwd\|credential"

# All strings including unicode
strings -e l malware.exe     # Little-endian 16-bit
strings -e b malware.exe     # Big-endian 16-bit

# Analysis pipeline
strings malware.bin | sort | uniq > strings_output.txt
```

---

## Linux Persistence Investigation

```bash
# Crontabs to check
crontab -l                      # Current user crontab
crontab -l -u root              # Root crontab (requires sudo)
cat /etc/crontab                # System-wide crontab
ls -la /etc/cron.d/             # Per-package cron jobs
ls -la /etc/cron.daily/         # Daily jobs
ls -la /etc/cron.hourly/        # Hourly jobs

# Startup scripts
ls -la /etc/init.d/             # SysV init scripts
ls -la /etc/systemd/system/     # Systemd service files
systemctl list-units --type=service --state=running

# User-specific startup
cat ~/.bashrc
cat ~/.bash_profile
cat ~/.profile
cat /etc/profile
cat /etc/profile.d/*.sh

# SSH authorized keys (backdoor entry)
cat ~/.ssh/authorized_keys
cat /root/.ssh/authorized_keys
find / -name "authorized_keys" 2>/dev/null

# AT jobs (scheduled one-time execution)
atq
at -l
```

---

## Authentication Log Analysis

### SSH Brute Force Detection
```bash
# Count failed SSH attempts by IP
grep "Failed password" /var/log/auth.log | 
    awk '{print $11}' | 
    sort | uniq -c | sort -rn | head -20

# Extract username attempts
grep "Failed password" /var/log/auth.log | 
    awk '{print $9}' | 
    sort | uniq -c | sort -rn | head -20

# Successful logins
grep "Accepted password\|Accepted publickey" /var/log/auth.log

# Invalid user attempts
grep "Invalid user" /var/log/auth.log | 
    awk '{print $8,$10}' | sort | uniq -c | sort -rn

# Show all SSH sessions (login + logout)
grep "session opened\|session closed" /var/log/auth.log

# Sudo usage
grep "sudo" /var/log/auth.log
```

### Privilege Escalation Detection
```bash
# Su/sudo events
grep "sudo\|su\[" /var/log/auth.log | grep -v "pam_unix"

# Failed sudo
grep "authentication failure" /var/log/auth.log

# New user creation
grep "useradd\|adduser" /var/log/auth.log

# Password changes
grep "passwd" /var/log/auth.log

# Who has logged in recently
last
lastlog | grep -v "Never logged in"
w          # Currently logged in users
who        # Also shows current logged in
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Linux Detection |
|-----------|----|----|
| Cron Job | T1053.003 | `/var/log/cron`, `crontab -l` |
| SSH Keys | T1098.004 | `authorized_keys` monitoring |
| Web Shell | T1505.003 | `find /var/www -name "*.php"` with eval |
| Valid Accounts | T1078 | `/var/log/auth.log` |
| Sudo | T1548.003 | auth.log grep sudo |
| History Tampering | T1070.003 | `HISTFILE=/dev/null` in bash |
| Network Sniffing | T1040 | `tcpdump` in processes |

---

## Related Notes
- [[tcpdump & Wireshark\|tcpdump & Wireshark]]
- [[Linux Privilege Escalation\|Linux Privilege Escalation]]
- [[Web Attack Detection\|Web Attack Detection]]
- [[Incident Response Lifecycle\|Incident Response Lifecycle]]
- [[Commands - Network\|Commands - Network]]
