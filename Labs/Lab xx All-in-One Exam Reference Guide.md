

> SOC Level 1 Analyst | Labs 1–18 | Full Commands · Queries · Strategies · TTPs

---

## 1. TLP & PAP Quick Reference

### TLP — Traffic Light Protocol (HOW WIDELY to share)

|Level|Share With|Use When|
|---|---|---|
|**TLP:CLEAR**|Anyone, publicly|No sensitivity; informational only|
|**TLP:GREEN**|Community / trusted peers|Sector-wide sharing OK|
|**TLP:AMBER**|Your org + clients (need-to-know)|Active incident, internal sensitivity|
|**TLP:AMBER+STRICT**|Your org only|Highly sensitive internal matter|
|**TLP:RED**|Named recipients only|Critical / exec-level, no redistribution|

### PAP — Permissible Actions Protocol (WHAT YOU CAN DO with the info)

|Level|Allowed Actions|Use When|
|---|---|---|
|**PAP:CLEAR**|No restrictions|False positive, informational|
|**PAP:GREEN**|Active: block traffic, ping, interact|Confirmed threat, active response|
|**PAP:AMBER**|Passive: WHOIS, VirusTotal, honeypot|Active investigation, no direct target contact|
|**PAP:RED**|Non-detectable only: log review, offline analysis|Covert / sensitive investigation|

> **Exam Tip:** For most real incident cases → TLP:AMBER + PAP:AMBER. For false positives → TLP:CLEAR + PAP:CLEAR. For ransomware hashes/payloads → TLP:RED + PAP:RED.

---

## 2. TheHive — Case Management Workflow

### Standard Case Creation Steps

1. **Create Case** → Empty Case
2. **Fill Details:** Title, Date, Severity, TLP, PAP, Tags, Description
3. **Add Observables** (IOCs) → types: `ip`, `hostname`, `filename`, `hash`, `url`, `domain`, `uri_path`, `other`, `mail-subject`, `fqdn`
4. **Add TTPs** → Catalog: Enterprise Attack → Select techniques with dates
5. **Add Tasks** → Assign to SOC 2 (soc2@syntrix.com), mark Mandatory: YES
6. **Escalate** → Change case owner to SOC 2

### Observable Fields Cheat Sheet

|Field|What to put|
|---|---|
|Type|`ip`, `hostname`, `filename`, `hash`, `url`, `domain`, `uri_path`, `other`|
|Is IOC|Yes = confirmed malicious / attacker artifact; No = victim asset or contextual|
|Has been sighted|Yes + timestamp from the log|
|Ignore Similarity|Yes for victim hosts/common strings; No for malicious artifacts|

### Severity Guidelines

- **LOW** → False positive, internal activity, no impact
- **MEDIUM** → Suspicious activity, unconfirmed threat
- **HIGH** → Confirmed malicious activity, credential theft, web shell, privilege escalation
- **CRITICAL** → Ransomware, active compromise, C2 confirmed

### TheHive Credentials (lab default)

```
URL: http://localhost:9000
Username: soc1@syntrix.com
Password: pass123
SOC2: soc2@syntrix.com
```

---

## 3. Wireshark — Packet Analysis

### Essential Filters

```wireshark
# Show only HTTP traffic
http

# Filter by two IPs (C2 beaconing)
http && ip.addr==10.0.0.155 && ip.addr==10.0.0.156

# Email protocols (phishing investigation)
smtp || imap || pop

# Filter for DNS
dns

# Filter SMB
smb || smb2
```

### Key Workflow Steps

```
1. Open PCAP → Filter for protocol of interest
2. Right-click frame → Follow > HTTP Stream / TCP Stream
3. Statistics > I/O Graphs → visualize beaconing patterns
4. File > Export Objects > HTTP → extract binaries/files
5. Copy packet bytes as Hex Dump for manual analysis
```

### Extracting File Hash from PCAP

```powershell
# After exporting file via Wireshark > File > Export Objects > HTTP
cd Desktop
Get-FileHash -Algorithm MD5 checkmate.exe
# Then search MD5 on https://www.virustotal.com
```

### Havoc C2 — Traffic Identification & Decryption

**Magic bytes:** `de ad be ef` (deadbeef)

**Key Extraction Formula:**

```
Find: deadbeef in hex dump
→ Skip next 12 bytes
→ Next 32 bytes = AES Key
→ Next 16 bytes = AES IV (Initialization Vector)
```

**CyberChef Decryption Steps:**

1. Go to https://gchq.github.io/CyberChef/
2. Copy File Data value from Wireshark (right-click → Copy > Value)
3. Add operation: **AES Decrypt**
4. Paste AES Key and IV
5. Set mode: **CTR** (Havoc C2 uses Counter mode)
6. Remove first **20 bytes (40 hex characters)** from input to strip headers
7. Read decrypted output (e.g., `whoami /all` output)

**Beaconing Pattern:** ~every 2 seconds = active C2 connection

**Havoc C2 References:**

- `https://github.com/HavocFramework/Havoc`
- Magic bytes confirmed in: `Defines.h`
- AES mode confirmed in: `AesCrypt.h`

### Phishing PCAP Analysis

```wireshark
# Look for email traffic
smtp || imap || pop

# Follow the TCP stream of first IMAP frame
# Look for:
# - Subject field (urgency keywords)
# - From address (typosquatted domain)
# - X-Mailer header (sendEmail = red flag)
# - Attachments (.hta, .exe, unusual formats)
# - Links (shortened URLs, HTTP not HTTPS)
```

**Red Flags in Email Headers:**

- `X-Mailer: sendEmail-1.56` → attacker used script mailer
- `Received: from ec2-*.compute.amazonaws.com` → AWS-hosted infrastructure
- Sender: `billing@paypa1.com` → note "1" instead of "l" = typosquatting
- Subject: urgency + poor grammar

---

## 4. Splunk — SPL Queries & Strategies

### Credentials & Access

```
URL: http://localhost:8000
Default index for labs: syntrix or blue or botsv1
```

### Fundamental Queries

```splunk
# All events in index
index=syntrix

# All events all time (change time range to "All time" too)
index=* earliest=0

# Events from specific host
index=* host=DC01
index=* host=linux01

# Filter by sourcetype
index=syntrix sourcetype=syslog

# Filter by source file
index=* host=linux01 source="/var/log/auth.log"

# List available sourcetypes
| metadata type=sourcetypes index="botsv1"

# List all hosts
| metadata type=hosts index="botsv1" | convert ctime(firstTime) as firstTime

# Convert epoch time
| convert ctime(firstTime) as firstTime | convert ctime(lastTime) as lastTime
```

### Windows Security Log Queries

```splunk
# Windows Firewall Rule Modifications
index=syntrix source="WinEventLog:Security" EventCode=4947

# Firewall Rule Modified (detailed)
index=syntrix source="WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" EventCode=2005

# PowerShell Script Block Logging
index=syntrix source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104

# PowerShell Module Logging
index=syntrix EventCode=4103

# SMB Authentication Failures
index=syntrix source="WinEventLog:Microsoft-Windows-SMBServer/Security" EventCode=551

# Sysmon Network Connections
index=syntrix source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3

# Look up user by SID
index=syntrix "S-1-5-21-3250466395-192540623-711299986-1010" EventCode=4103

# WinRM confirmation (wsmprovhost.exe)
index=blue LogName="Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\wsmprovhost.exe"

# Network connection on port 5985 (WinRM)
index=blue LogName="Microsoft-Windows-Sysmon/Operational" EventCode=3

# PowerShell file download to Temp
index=blue source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 "C:\\Windows\\Temp\\*.exe"

# LSASS access
index=blue source="WinEventLog:Microsoft-Windows-Sysmon/Operational" *lsass.exe* *Administrator*

# Credential dumping keywords (Mimikatz)
index=blue LogName=Microsoft-Windows-PowerShell/Operational EventCode=4104 "*privilege::debug*"

# DLL written to System32
index=blue LogName="Windows PowerShell" EventCode=800 "C:\\Windows\\System32\\*.dll"

# Registry modification (NetSh helper DLL persistence)
index=blue LogName=Microsoft-Windows-Sysmon/Operational EventCode=13 "*NetSh*"

# Password change events
index=blue LogName=Security EventCode=4724

# Account deleted events
index=blue LogName=Security EventCode=4726
index=blue EventCode=4726 *Account Name*

# Process creation with specific command line
index=blue source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine="*Administrator*"

# Service installation
index=syntrix EventCode=4697
# OR
index=syntrix EventCode=7045
```

### Web Traffic / Apache Log Queries

```splunk
# All Apache access logs
index=syntrix source="/var/log/apache2/access.log"

# POST requests (suspicious uploads)
index=syntrix source="/var/log/apache2/access.log" "POST"

# Web shell commands
index=syntrix source="/var/log/apache2/access.log" "cmd"

# Error logs
index=syntrix source="/var/log/apache2/error.log"
```

### Threat Hunting Scenario (BOTSv1 / Wayne Enterprises)

```splunk
# All data
index=botsv1 earliest=0

# HTTP traffic to target website
index=botsv1 imreallynotbatman.com sourcetype=stream:http

# Identify source IPs (attackers)
index=botsv1 imreallynotbatman.com sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort - Requests

# Suricata alerts for suspicious IP
index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata

# HTTP POST requests (brute-force / exploitation)
index=botsv1 sourcetype=stream:http dest="192.168.250.70" http_method=POST

# Extract password from form data
index=botsv1 sourcetype=stream:http form_data=*username*passwd* dest_ip=192.168.250.70 | rex field=form_data "passwd=(?P<userpassword>\w+)" | stats count by userpassword | sort - count

# Confirm successful login
index=botsv1 sourcetype=stream:http | rex field=form_data "passwd=(?P<userpassword>\w+)" | search userpassword=batman | table _time userpassword src

# Uploaded executables via HTTP
index=botsv1 sourcetype=stream:http dest="192.168.250.70" *.exe

# Suricata confirming upload
index=botsv1 sourcetype=suricata dest="192.168.250.70" http.http_method=POST *.exe

# Sysmon process creation for uploaded malware
index=botsv1 3791.exe sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1

# Extract MD5 hash
index=botsv1 3791.exe CommandLine=3791.exe | stats values(md5)

# DNS query to find C2 domain
index=botsv1 answer=23.22.63.114 sourcetype=stream:dns | stats values("name{}")

# DGA domain detection
index=botsv1 sourcetype=stream:dns record_type=A | stats count by query{} | sort count

# Cerber ransomware VSS deletion
index=botsv1 source="wineventlog:microsoft-windows-sysmon/operational" EventCode=1 process=\\vssadmin.exe | search CommandLine="vssadmin" CommandLine="Delete" CommandLine="Shadows*"

# Identify obfuscated commands (long command lines)
index=botsv1 source="wineventlog:microsoft-windows-sysmon/operational" | eval len=len(CommandLine) | table User, len, CommandLine | sort - len

# Malicious USB (removable drive detection)
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" "d:\\" | stats count by Computer,CommandLine
index=botsv1 sourcetype=winregistry friendlyname | table host object data

# Malicious VBS files
index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" ".vbs" AND (ParentCommandLine=* OR CommandLine=*) | table _time process process_id ParentProcessId ParentImage CommandLine ParentCommandLine
```

### Linux Auth Log Analysis

```splunk
# All Linux logs
index=* host=linux01 sourcetype=syslog source="/var/log/auth.log"

# Filter for specific account
index=* host=linux01 sourcetype=syslog source="/var/log/auth.log" maliciousaccount

# Filter for newadmin activity
index=* host=linux01 sourcetype=syslog source="/var/log/auth.log" newadmin

# Widen search (remove source filter)
index=* host=linux01 sourcetype=syslog

# Widen further (all log types)
index=* host=linux01
```

---

## 5. ELK / Kibana — Queries & Detection

### Access

```
URL: http://localhost:5601
Index pattern: syntrix
Time range: Last 1 year (or adjust per lab)
```

### PowerShell Investigation (ELK)

```elk
# PowerShell Script Block Logging (Event 4104)
winlog.channel:"Microsoft-Windows-PowerShell/Operational" AND winlog.event_id:4104

# Sysmon Process Creation (Event 1)
winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:1

# Sysmon Network Connections (Event 3)
winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:3
```

### What to Look For in PowerShell Event 4104 Logs

- `IEX(New-Object Net.WebClient).DownloadString(...)` → downloads + executes script in memory
- `-nop -w hidden -e <base64>` → no profile, hidden window, encoded command
- Base64 encoded commands (after `-e` or `-EncodedCommand`) → decode to see payload
- URLs containing unusual paths or port 4444, 8080

### Wazuh via ELK (Lab 15)

```elk
# FIM events (ransomware file modifications)
agent.ip:10.0.0.67 AND rule.groups:"syscheck"

# Sysmon process creation
agent.ip:10.0.0.67 AND data.win.system.providerName:"Microsoft-Windows-Sysmon" AND data.win.system.eventID:1
```

### ELK Detection Searches (Lab 3)

```elk
# Files named like system processes (masquerading)
event_data.Image:("*\\rundll32.exe" "*\\svchost.exe" "*\\lsass.exe" "*\\winlogon.exe" "*\\csrss.exe" "*\\services.exe")
AND NOT event_data.Image:("*\\system32\\*" "*\\syswow64\\*" "*\\winsxs\\*")

# Suspicious services with Windows executables
(event_id:("4697" "7045") OR (log_name:Autoruns AND event_data.Category:Services))
AND event_data.CommandLine.keyword:/.*%[sS][yY][sS][tT][eE][mM][rR][oO][oO][tT]%\\[^\\]*\.exe/
AND -event_data.CommandLine:(*paexe* *psexesvc* *winexesvc* *remcomsvc*)

# Code injection (CreateRemoteThread)
event_id:8 AND source_name:"Microsoft-Windows-Sysmon"

# Privilege escalation via weak service permissions
event_data.Image:"*\\sc.exe" AND (event_data.CommandLine:(*start* *sdshow*) OR
(event_data.CommandLine:*config* AND event_data.CommandLine:*binPath*))
AND event_data.IntegrityLevel:Medium

# Session hijacking via tscon
event_data.Image:"*\\tscon.exe" AND event_data.User:"NT AUTHORITY\\SYSTEM"

# whoami with SYSTEM privileges
event_data.Image:"*\\whoami.exe" AND (event_data.LogonId:0x3e7 OR event_data.User:"NT AUTHORITY\\SYSTEM")

# LSASS loading non-Microsoft DLL
event_id:7 AND event_data.Image:"*\\lsass.exe" AND -event_data.Signature:*Microsoft*
```

---

## 6. Wazuh — Threat Hunting & Detection

### Access Credentials (labs)

```
URL: https://localhost  (or https://wazuh.ine.local)
Username: admin
Password: (varies by lab — check lab environment)
```

### Wazuh Navigation Path for Alert Analysis

```
1. Wazuh Dashboard → Agents Summary
2. Click on agent → More → MITRE ATT&CK
3. Go to "Framework" tab → Set date range → Hide techniques with no alerts
4. Click on technique tab (Brute Force, Create Account, etc.)
5. Expand log entries for details
```

### Key Wazuh Alert Categories to Check

|MITRE Tab|What to Look For|
|---|---|
|**Brute Force**|Failed logins, SSH attempts, attacker IP, targeted account|
|**Create Account**|New user creation, username, timestamp, agent|
|**Remote Services**|SSH logins post account creation, source IP|
|**Sudo and Sudo Caching**|/etc/sudoers access, privilege escalation|
|**Pass the Hash**|Successful network logon (Logon Type 3), same attacker IP|
|**SMB/Windows Admin Shares**|SMB access attempts, share names|
|**Account Manipulation**|New user creation by attacker post-compromise|

### Wazuh FIM (File Integrity Monitoring)

- Module: `syscheck`
- ELK filter: `rule.groups:"syscheck"`
- Look for: files deleted then re-added with different extension (`.wncry` = WannaCry)
- Key fields: `full_log`, process that modified file, user

### WannaCry Indicators in Wazuh

- Files renamed with `.wncry` extension
- Process: `CleanXpro.exe` → spawns `cmd.exe`
- Registry persistence: `tasksche.exe` added to `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- VSS deletion: `vssadmin delete shadows /all /quiet`
- `@WanaDecryptor@.exe` → MD5: `7BF2B57F2A205768755C07F238FB32CC` (confirmed malicious on VT)

### Wazuh + AI Chatbot (Lab 18)

```
Chatbot URL: http://wazuhbot.ine.local/
Example queries:
  - "Were there any SSH brute-force attempts? Give me all the details."
  - "Is there any new account creation on 'ubuntu-machine'? Give me all the details."
  - "Was there any Account Manipulation Attempts?"
```

The chatbot uses RAG (Retrieval-Augmented Generation) + Mistral LLM via Ollama to answer queries from alert context. Always **verify chatbot answers** against the actual Wazuh dashboard logs.

---

## 7. Malware Fundamentals — Static Analysis

### Tools

|Tool|Purpose|
|---|---|
|**HxD**|Raw hex editor — examine file bytes, magic bytes, headers|
|**BinText**|Extract ASCII/Unicode strings from binary|
|**PE-Tree**|Parse PE structure: headers, imports, entropy, hashes|

### HxD Analysis Steps

1. Open malware sample in HxD
2. Check offset `0x00000000` for magic bytes:
    - `4D 5A` = **MZ** → valid Windows PE executable
3. Check offset `0x00000040` for DOS stub: `"This program cannot be run in DOS mode."`
4. Search for **Rich Header** (Search > Find > Text string: `Rich`)
    - Presence confirms compiled with **Microsoft Visual C++ (MSVC)**
    - Fingerprint for linking variants

### BinText Analysis — What to Extract

|String Category|Examples|Significance|
|---|---|---|
|**Ransomware ID**|`LockBit 2.0 Ransom`, `.lockbit`, `RESTORE-MY-FILES.TXT`|Family identification|
|**C2 / Infrastructure**|`.onion` URLs, ToxID, clearnet URLs|IOC for blocklists|
|**Persistence**|`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`|Autorun keys|
|**Lateral Movement**|`LDAP://rootDSE`, `gpupdate.exe`, `NETLOGON`, `\sysvol\`|AD abuse|
|**Defense Evasion**|`DisableAntiSpyware`, `DisableRealtimeMonitoring`|Defender disabling|
|**Encryption**|`Libsodium`, `.lockbit` extension|Crypto library|
|**Anti-forensics**|`fsutil file setZeroData`, `Del /f /q`|Self-deletion|
|**Privilege Escalation**|`Elevation:Administrator!new:`, COM CLSID|UAC bypass|

### PE-Tree Analysis — Key Fields

```
File Hashes:     MD5, SHA1, SHA256 → submit to VirusTotal
Architecture:    I386 = 32-bit
Compile Date:    From TimeDateStamp
Sections:        .text (code), .data, .idata (imports)
Entropy:         < 7.0 = not packed; ≥ 7.0 = likely packed/encrypted
Import Table:    Small import table + large binary = dynamic API resolution (evasion)
```

### LockBit 2.0 — Lab 14 Sample Summary

|Property|Value|
|---|---|
|MD5|`6fc418ce9b5306b4fd97f815cc9830e5`|
|SHA256|`0545f842ca2eb77bcac0fd17d6d0a8c607d7dbc8669709f3096e5c1828e1c049`|
|Compiler|Visual Studio 2017 (MSVC)|
|Compile Date|July 26, 2021|
|File Type|PE32 (32-bit GUI executable)|
|Key Behavior|Group Policy abuse for domain-wide spread|
|Encryption|libsodium (NaCl)|
|File extension|`.lockbit`|
|Ransom note|`RESTORE-MY-FILES.TXT`|
|C2|Tor onion address + Tox chat|

---

## 8. LOKI — IOC Scanning

### Commands

```powershell
# Navigate to LOKI directory
cd Desktop\loki

# View help
.\loki.exe --help

# Scan all local hard drives
.\loki.exe --allhds
```

### LOKI Output Interpretation

|Alert Type|What It Means|
|---|---|
|`ALERT`|High confidence IOC match (YARA rule, known hash)|
|`WARNING`|Suspicious but not definitive|
|Risk Score ≥ 100|High malicious likelihood|
|Risk Score ≥ 400|Very high / confirmed malicious|

### Lab 16 Findings Summary (LOKI Scan)

|File|Location|Risk Score|Matched|MD5|
|---|---|---|---|---|
|`haha.exe`|`C:\ProgramData\`|415|Mimikatz x64|`29efd64dd3c7fe1e2b022b7ad73a1ba5`|
|`winfix.exe`|`C:\Users\Administrator\AppData\Roaming\...\Startup\`|130|Metasploit payload|`622e51a67dbe059cc907753da1178b39`|
|`89852140...`|`C:\Users\Public\`|—|SAM hive backup|`7d77408e1c6d11bf5623cd777444e8b8`|
|`Disable.ps1`|`C:\Windows\`|100|Disables Windows security|—|

**winfix.exe listening process:**

```
PID: 4680 | IP: 0.0.0.0 | Port: 4444 → Bind shell / Metasploit backdoor
```

**MITRE TTPs for Lab 16:**

- T1059.001 – PowerShell (Disable.ps1)
- T1547.001 – Registry Run Keys / Startup Folder (winfix.exe)
- T1562.001 – Impair Defenses (Disable.ps1)
- T1003.002 – OS Credential Dumping: SAM (SAM hive copy)

---

## 9. MITRE ATT&CK Quick Reference

### Most Common Techniques in Labs

|Technique ID|Name|Example from Labs|
|---|---|---|
|T1021.004|Remote Services: SSH|eviluser SSH from 10.0.0.11|
|T1021.006|Remote Services: WinRM|wsmprovhost.exe on port 5985|
|T1027|Obfuscated Files|Base64 encoded PowerShell (`-e` flag)|
|T1047|WMI|WmiPrvSE.exe modifying firewall|
|T1059.001|PowerShell|IEX DownloadString, encoded commands|
|T1059.003|Windows Command Shell|cmd.exe spawned by malware|
|T1059.004|Unix Shell|Web shell cmd= execution|
|T1071.001|Web Protocols (C2)|HTTP GET with cmd= queries|
|T1078|Valid Accounts|SSH/SMB using stolen credentials|
|T1098|Account Manipulation|Password changed via `net user`|
|T1103|Archive Collected Data|—|
|T1105|Ingress Tool Transfer|PowerShell download to \Temp\|
|T1136|Create Account|adduser eviluser|
|T1190|Exploit Public-Facing App|File upload via handler.php|
|T1204.002|User Execution: Malicious File|CleanXpro.exe, MirandaTate.scr.exe|
|T1484.001|Group Policy Modification|LockBit AD propagation|
|T1486|Data Encrypted for Impact|.wncry files (WannaCry), .lockbit|
|T1490|Inhibit System Recovery|vssadmin delete shadows|
|T1505.003|Web Shell|bingo.php in /img/|
|T1531|Account Access Removal|Deleting admin accounts|
|T1546.007|Netsh Helper DLL|evil_netsh.dll registry persistence|
|T1547.001|Registry Run Keys|tasksche.exe in Run key|
|T1548.002|UAC Bypass|COM elevation technique|
|T1548.003|Sudo and Sudo Caching|/etc/sudoers modification|
|T1562.001|Disable Security Tools|Windows Defender GPO disable|
|T1562.004|Disable/Modify Firewall|Set-NetFirewallRule -RemoteAddress Any|
|T1566.001|Spearphishing Attachment|Invoice_5550199.hta|
|T1566.002|Spearphishing Link|bit.ly shortened URL|
|T1570|Lateral Tool Transfer|Script downloaded from attacker host|
|T1574|Hijack Execution Flow|Unsigned DLL in System32|
|T1003.001|LSASS Memory|gotyou.exe → GrantedAccess 0x1010|
|T1003.002|SAM Credential Dumping|SAM hive copied to C:\Users\Public\|

---

## 10. Incident Types & Response Playbooks

### Ransomware Incident

**Indicators:**

- Files renamed with new extension (`.wncry`, `.lockbit`)
- VSS deletion commands (`vssadmin delete shadows /all /quiet`)
- Registry persistence for tasksche.exe / ransom executable
- `@WanaDecryptor@.exe` or similar decryptor dropped

**Response:**

1. Isolate affected host immediately
2. Document all IOCs (file hashes, filenames, registry keys)
3. Check FIM logs for encrypted file list
4. Submit hashes to VirusTotal
5. Severity: CRITICAL | TLP:Amber | PAP:Amber (passive only)

### Web Shell Compromise

**Indicators:**

- POST to file-upload endpoint (`handler.php`) from external IP
- GET request to PHP file in non-PHP directory (`/img/bingo.php?cmd=whoami`)
- `cmd=` parameter with 200 OK response → commands executing
- Varying response sizes = command output returned

**Response:**

1. Document attacker IP, victim server IP, web shell path, commands executed
2. TTPs: T1190 (exploit), T1505.003 (web shell), T1071.001 (C2), T1059.004 (shell)
3. Severity: HIGH | Tasks for SOC2: validate exploit, assess source IP, review upload code

### Privilege Escalation

**Indicators:**

- New user created (`eviluser`, `evil-user`)
- SSH/RDP login with new account
- `/etc/sudoers` accessed or `sudo` first use by new account
- Registry modification for Run key persistence

**Sequence (Lab 10):**

```
Account Created (T1136)
→ Remote SSH Login (T1021.004 + T1078)
→ Sudo/sudoers access (T1548.003)
```

### Firewall Misconfiguration + SMB Brute Force

**Indicators:**

- Event ID 4947 (firewall rule changed)
- Event ID 2005 (firewall rule modified, shows new setting)
- PowerShell: `Set-NetFirewallRule -RemoteAddress Any` (WMI via WmiPrvSE.exe)
- Event ID 551 (failed SMB auth) — large volume = brute force

**Lookup chain:**

```
EventCode=4947 → identifies firewall change on PC02
EventCode=2005 → reveals "Allow Any" change + SID
SID + EventCode=4103 → reveals username (brandon)
Sysmon EventCode=3 → reveals PC02 IP (10.0.0.101)
EventCode=551 → confirms external brute-force attempts
```

### Phishing Email

**7 Red Flags to Document:**

1. Typosquatted sender domain (paypa1.com vs paypal.com)
2. Non-professional mailer (`X-Mailer: sendEmail-1.56`)
3. AWS EC2 origin (not PayPal infrastructure)
4. Urgency + poor grammar in subject
5. Generic greeting (`Hello Valued Customer`)
6. Shortened URL (`bit.ly`) + HTTP not HTTPS
7. Unusual attachment type (`.hta` not `.pdf`)

### C2 Communication (Havoc)

**Indicators:**

- Initial GET request downloading `.exe` via PowerShell User-Agent
- Python SimpleHTTP server on port 8000
- POST requests to internal IP with `deadbeef` magic bytes
- Regular beaconing (~every 2 seconds)
- Encrypted POST bodies (AES-CTR)

### Credential Dumping (Mimikatz)

**Command signature:**

```cmd
.\gotyou.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > creds.txt
```

**Sysmon EventCode 10** (Process Access) → SourceImage = dumper, TargetImage = lsass.exe

- GrantedAccess mask: `0x1010`

### Persistence via NetSh Helper DLL

**Registry path:** `HKLM\SOFTWARE\Microsoft\NetSh` **Value name:** `evil_helper` **DLL path:** `C:\Windows\System32\evil_netsh.dll` **MITRE:** T1546.007

### Account Removal (Post-Exploitation)

**Event ID 4726** = account deleted **Attacker tactic:** delete legitimate admin accounts to prevent recovery/lockout defenders

---

## 11. Key Windows Event IDs

|Event ID|Source|Description|
|---|---|---|
|**4103**|PowerShell|Module Logging|
|**4104**|PowerShell|Script Block Logging (full command captured)|
|**4697**|Security|Service installed on system|
|**4724**|Security|Attempt to reset account password|
|**4726**|Security|User account deleted|
|**4947**|Security|Windows Firewall rule modified|
|**7045**|System|New service installed|
|**551**|SMBServer/Security|Failed SMB authentication|
|**800**|Windows PowerShell|Pipeline execution|
|**2005**|Windows Firewall/Firewall|Firewall rule changed (shows new settings)|

---

## 12. Key Sysmon Event IDs

|Event ID|Name|Use Case|
|---|---|---|
|**1**|Process Create|See what ran, CommandLine, ParentImage|
|**3**|Network Connection|Outbound connections, ports, destination IPs|
|**7**|Image Loaded|DLLs loaded by process (LSASS monitoring)|
|**8**|CreateRemoteThread|Code injection detection|
|**10**|Process Access|Credential dumping (LSASS access)|
|**13**|Registry Value Set|Persistence via registry|

### WinRM Confirmation

- Sysmon EventCode 1: `wsmprovhost.exe` spawned
- Sysmon EventCode 3: Network connection on **port 5985** (WinRM HTTP)

---

## 13. C2 Frameworks — Identification

### Havoc C2

- **Magic bytes:** `de ad be ef` (deadbeef)
- **Encryption:** AES-CTR
- **Key location:** After deadbeef → skip 12 bytes → 32 bytes key → 16 bytes IV
- **Beaconing:** Regular POST requests every ~2 seconds
- **User-Agent download:** `WindowsPowerShell/5.1` downloading from Python SimpleHTTP

### Cobalt Strike / Metasploit Indicators

- `winfix.exe` listening on port **4444** = bind shell
- Staged payloads, encoded commands
- `wsmprovhost.exe` for WinRM-based lateral movement

### WannaCry Ransomware

- Extension: `.wncry`
- Dropped files: `@WanaDecryptor@.exe`, `tasksche.exe`
- Registry key: `twjtlpfianyg777` → runs tasksche.exe at startup
- Hash: `7BF2B57F2A205768755C07F238FB32CC` (confirmed on VirusTotal)
- VSS deletion: `vssadmin delete shadows /all /quiet & wmic shadowcopy delete`

### LockBit 2.0

- Extension: `.lockbit`
- Ransom note: `RESTORE-MY-FILES.TXT` + `LockBit_Ransomware.hta`
- Crypto library: `Libsodium`
- GPO abuse: pushes ransomware domain-wide
- Defender disable via Group Policy registry keys
- TOR C2: `lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion`
- Anti-forensics: `fsutil file setZeroData` + self-delete

### Cerber Ransomware

- DGA domain: `cerberhhyed5frqa.xmfir0.win`
- Delivery: `.vbs` script → `wscript.exe` → `cmd.exe` → `121214.tmp`
- Hash: `EE0828A4E4C195D97313BFC7D4B531F1`
- Process chain: `20429.vbs` (obfuscated) → `osk.exe` (masquerading)

---

## 14. Phishing Analysis Checklist

### Wireshark PCAP Phishing Workflow

```
1. Apply filter: smtp || imap || pop
2. Right-click first frame → Follow > TCP Stream
3. Check:
   - Recipient email (who was targeted)
   - Subject line (urgency keywords?)
   - Sender address (typosquatted domain?)
   - X-Mailer header (sendEmail = attacker script)
   - Received header (AWS EC2? Unexpected origin?)
   - Links in body (shortened URL? HTTP not HTTPS?)
   - Attachment (unusual format? .hta, .exe, .vbs?)
   - Body grammar/tone (generic greeting? errors?)
```

### TheHive Phishing Case

**Tags:** `phishing, paypal, typosquatted-domain, malicious-attachment, hta, shortened-url, social-engineering`

**TTPs:**

- T1566.001 – Spearphishing Attachment (`.hta` file)
- T1566.002 – Spearphishing Link (shortened URL)
- T1204.002 – User Execution: Malicious File

**Observables to add:**

|Type|Value|IOC?|
|---|---|---|
|domain|paypa1.com|Yes|
|ip|52.221.249.45|Yes|
|hostname|ec2-52-221-249-45.ap-southeast-1.compute.amazonaws.com|Yes|
|other|X-Mailer: sendEmail-1.56|Optional|
|mail-subject|Urgent invoice - PAYMENT required now!|No (behavioral)|
|url|http://bit.ly/paypal-pay-now|Yes|
|filename|Invoice_5550199.hta|Yes|

---

## 15. Splunk Forwarder Setup (Linux & Windows)

### Windows (DC01) — Splunk Universal Forwarder

```
1. Run installer → Accept license → "On-premises Splunk Enterprise instance"
2. Customize Options → Accept defaults for SSL
3. Account: Local System
4. Select: Security Logs + Enable AD monitoring
5. Deployment Server: (leave empty)
6. Receiving Indexer: [SERVER01 IP]:9997
```

### Linux (LINUX01) — Splunk Universal Forwarder

```bash
# Prerequisites
sudo useradd -m splunk
export SPLUNK_HOME="/opt/splunkforwarder"
sudo mkdir $SPLUNK_HOME

# Install
sudo dpkg -i splunkforwarder-9.0.4-de405f4a7979-linux-2.6-amd64.deb

# Set ownership
sudo chown splunk:splunk $SPLUNK_HOME -R

# Start (accept license)
cd $SPLUNK_HOME/bin
sudo ./splunk start --accept-license

# Configure forwarding to Splunk server
sudo ./splunk add forward-server 172.31.115.110:9997

# Monitor specific log file
sudo ./splunk add monitor /var/log/auth.log

# Restart to apply settings
sudo ./splunk restart
```

### Configure Splunk SERVER to Receive (SERVER01)

```
Splunk UI → Settings → Forwarding and receiving → Add new (Configure receiving)
Port: 9997 → Save

Windows Firewall:
Inbound Rules → New Rule → Port → TCP → 9997 → Allow → All profiles → Name: "Splunk Forwarder"
```

### Verify Logs Arriving

```splunk
index=* host=DC01
index=* host=ip-172-31-115-111
```

---

## 16. Lab Quick-Answer Cards

### Lab 1 — Wireshark / Havoc C2

- C2 Framework: **Havoc C2** (identified by `deadbeef` magic bytes)
- Victim IP: `10.0.0.156` | C2 Server: `10.0.0.155`
- AES Mode: **CTR** (Counter)
- After decryption: output of `whoami /all` → admin-level access confirmed
- Beaconing interval: ~2 seconds

### Lab 7 — Splunk Threat Hunting (Blue Index)

|Question|Answer|
|---|---|
|WinRM confirmation|`wsmprovhost.exe` (EventCode 1) + port **5985** (EventCode 3)|
|Downloaded executable|**gotyou.exe** from `http://10.0.0.56:8000/gotyou.exe`|
|LSASS access process|**gotyou.exe** with `GrantedAccess: 0x1010`|
|Full Mimikatz command|`.\gotyou.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > creds.txt`|
|DLL filename|**evil_netsh.dll**|
|Registry value|**evil_helper** at `HKLM\SOFTWARE\Microsoft\NetSh`|
|Password change tool|`net user` command|
|4 accounts deleted|**sysadmin, netadmin, itadmin, servadmin**|

### Lab 8 — Wazuh Threat Hunting (Windows Agent)

- Attacker IP: `3.110.33.3`
- Target: `192.168.1.120` (Windows agent)
- Targeted account: **Administrator**
- Attack sequence: Brute Force → Pass the Hash (Logon Type 3) → SMB access → Created `evil-user`

### Lab 9 — False Positive Validation

- Event: SSH failed logins from `10.0.0.11`
- Verdict: **FALSE POSITIVE** — `10.0.0.11` is the trusted Syntrix admin workstation
- Severity: **LOW** | TLP: **CLEAR** | PAP: **CLEAR**

### Lab 10 — Account Creation + Privilege Escalation

- New user: `eviluser` on `ip-10-0-0-100`
- SSH from: `10.0.0.11`
- Suspicious access: `/etc/sudoers`
- Severity: **HIGH** | TLP:Amber | PAP:Amber

### Lab 11 — PowerShell Execution (ELK)

- User: `sarah` on `PC01` (10.0.0.50)
- Attacker host: `10.0.0.11`
- Initial script: `http://10.0.0.11/haha.ps1`
- Follow-on payload: `http://10.0.0.11:8080/nj6VXD4hquF64Q/Z2oecggFq`
- Ports used: **80, 8080, 4444**
- Flags: `-nop -w hidden -e` (no profile, hidden, base64 encoded)

### Lab 12 — Web Traffic / Web Shell (Splunk)

- Attacker IP: `13.203.202.168`
- Web server: `172.31.10.177`
- Upload endpoint: `/codebase/handler.php`
- Web shell: `/img/bingo.php?cmd=whoami`
- First command: `whoami` → confirmed execution → server compromised

### Lab 13 — Firewall Modification + SMB Brute Force (Splunk)

- Changed rules: "File and Printer Sharing (SMB-In)" + "File Server Remote Management (SMB-In)" → **Allow Any**
- Changed via: `Set-NetFirewallRule` (PowerShell) through `WmiPrvSE.exe`
- SID: `S-1-5-21-3250466395-192540623-711299986-1010` → user: **brandon**
- Victim PC: `10.0.0.101` (PC02)
- Result: External brute-force on SMB (Event ID 551)

### Lab 14 — Malware Fundamentals (LockBit 2.0)

- Malware family: **LockBit 2.0**
- MD5: `6fc418ce9b5306b4fd97f815cc9830e5`
- SHA256: `0545f842ca2eb77bcac0fd17d6d0a8c607d7dbc8669709f3096e5c1828e1c049`
- Encrypted extension: `.lockbit`
- Dangerous capability: **Group Policy abuse** for domain-wide deployment

### Lab 15 — WannaCry Detection (Wazuh)

- Agent IP: `10.0.0.67` (Syntrix-PC04)
- User: `daisy`
- Initial malware: `CleanXpro.exe` (downloaded to Downloads)
- Ransomware: `@WanaDecryptor@.exe` | MD5: `7BF2B57F2A205768755C07F238FB32CC`
- Persistence: `tasksche.exe` via registry Run key (`twjtlpfianyg777`)
- VSS deletion command confirms WannaCry behavior

### Lab 16 — LOKI IOC Scan

- `haha.exe` in `C:\ProgramData` → **Mimikatz** (risk 415)
- `winfix.exe` in Startup folder → **Metasploit** payload listening on **port 4444**
- SAM hive copy in `C:\Users\Public\` → credential theft
- `Disable.ps1` in `C:\Windows\` → disables security features

### Lab 17 — Phishing Analysis (Wireshark)

- Target: `millybrown@syntrix.com`
- Date: November 11, 2025 at 06:24:32 UTC
- Sender domain: `paypa1.com` (typosquatted)
- Mail server IP: `52.221.249.45` (AWS EC2, Singapore)
- Mailer: `sendEmail-1.56`
- Link: `http://bit.ly/paypal-pay-now`
- Attachment: `Invoice_5550199.hta`

### Lab 18 — AI-Powered Wazuh

- Attacker IP: `10.160.0.113`
- New user created: **bob** (UID=1005, GID=1006)
- Password changed for: **bob**
- Always validate AI responses against actual Wazuh dashboard logs

---

## 17. AI-Augmented SOC (Wazuh + Ollama)

### How It Works

```
Wazuh Alerts (JSON) → Embeddings → Vector DB
User Query → LLM (Mistral via Ollama) → RAG retrieval → Human-readable answer
```

### Key Concepts

- **RAG (Retrieval-Augmented Generation):** AI retrieves relevant alert context before generating answer
- **Ollama:** Local LLM runner — keeps data on-premise (no cloud)
- **Mistral:** Open-source LLM used for natural language alert interpretation
- **LLM Limitations:** May vary in output; always cross-validate with raw logs

### AI SOC Use Cases

- Summarize brute-force activity patterns
- Identify new account creation details
- Correlate related events (same attacker IP across events)
- Explain alert context in plain language for Tier 1 analysts

### AI SOC Limitations (Important for Exam)

- LLMs can hallucinate — never trust AI output without verification
- AI cannot replace human judgment for escalation decisions
- Response may vary even for same prompt
- AI is a **force multiplier**, not a replacement for analyst skill

---

## 🎯 Exam Strategy Tips

### Alert Triage Workflow (Tier 1 Checklist)

```
1. Read the alert → Note: source IP, target IP, account, time, severity
2. Go to SIEM (Splunk/ELK/Wazuh) → Apply filters for the alert details
3. Correlate: Check related events before/after (+/- 5 min)
4. Classify: True Positive or False Positive?
5. False Positive → LOW severity, TLP:CLEAR, PAP:CLEAR
6. True Positive → Document in TheHive with proper severity
7. Add Observables → Add TTPs → Add Tasks → Escalate to SOC2
```

### Severity Decision Guide

```
CRITICAL → Ransomware, active C2, confirmed malware execution
HIGH     → Web shell, privilege escalation, credential theft, confirmed attack
MEDIUM   → Suspicious activity, unconfirmed threat, needs investigation  
LOW      → False positive, policy violation, informational
```

### Common Exam Traps

- **Port 4444** = almost always Metasploit/bind shell (not legitimate)
- **Port 5985** = WinRM HTTP (lateral movement)
- **Port 9997** = Splunk Forwarder
- **Logon Type 3** = Network logon (SMB, WinRM, remote) — not interactive
- **Logon Type 10** = Remote interactive (RDP)
- `/etc/sudoers` access = privilege escalation attempt
- `sendEmail-1.56` = attacker scripted mailer
- `X-Mailer: PHPMailer` or `sendEmail` = phishing toolkit
- `.hta` attachment = HTML Application — can execute scripts = malicious
- Files in `C:\ProgramData\` or `C:\Windows\` without proper context = suspicious
- `IEX` + `DownloadString` = in-memory execution (Living off the Land)
- `-e` or `-EncodedCommand` in PowerShell = Base64 obfuscation = suspicious

### Quick OSINT Tools Reference

|Tool|URL|Use For|
|---|---|---|
|VirusTotal|https://www.virustotal.com|Hash/IP/domain reputation|
|CyberChef|https://gchq.github.io/CyberChef/|Decode, decrypt, analyze data|
|Robtex|https://www.robtex.com|IP → domain associations|
|ThreatMiner|https://www.threatminer.org|IP → malware samples|
|ThreatCrowd|https://threatcrowd.org|Domain/IP threat intel|
|WHOIS|whois.domaintools.com|Domain registration info|
|AbuseIPDB|https://www.abuseipdb.com|IP abuse reports|

---

_Last updated: May 2026 | INE eSOC Labs 1–18 All-in-One Reference_