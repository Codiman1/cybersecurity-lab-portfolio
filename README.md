# Cybersecurity Lab Portfolio

**Ludovic JT**
Diploma in Information Systems Security — SAIT, Calgary AB (Expected December 2026)
Email: ludovicjoan.18@gmail.com | Calgary, AB | BSCP Certification In Progress

---

## About This Repository

Hands-on cybersecurity lab work completed during the Information Systems Security diploma at SAIT. Covers penetration testing, malware analysis, digital forensics, detection engineering, reverse engineering, network security, and GRC — across 20+ structured lab environments.

---

## Projects

### Multi-Service Python Honeypot
**Course:** ITSC-203 Scripting for Tool Construction
**Skills:** Python, multi-threading, SQLite, SSH/FTP/HTTP simulation, threat intelligence

Multi-threaded honeypot simulating 3 real network services to capture attacker behaviour. Logs 5 categories of telemetry (credentials, commands, sessions, file transfers, HTTP requests) into a centralized SQLite database for forensic analysis and SIEM rule development.

---

### Malware Analysis and Detection Engineering
**Course:** ITSC-304 Penetration Testing
**Skills:** Ghidra, FLOSS, ProcMon, Regshot, Sysmon, YARA, MITRE ATT&CK, ClamAV, FlareVM

- Static analysis of malware samples: imported DLLs, obfuscated strings, control flow reconstruction
- Dynamic analysis using ProcMon, Wireshark, Regshot — structured evidence timelines per sample
- YARA rule engineering (triage + hardened rules); validated fragility under hash/filename/string changes
- Behavioral detection strategies mapped to MITRE ATT&CK; deployed across EDR, Sysmon, and SIEM
- Solved 3 CrackMe reverse engineering challenges in Ghidra — XOR obfuscation, inlined functions, data encoding

---

### Digital Forensics
**Course:** SAIT — 2025
**Skills:** Autopsy, Volatility, VHD analysis, USB forensics, registry artifacts, Windows event logs

- Disk forensics on partial images: recovered deleted files, browser cache, registry execution artifacts
- Live memory forensics on shrapnel RAM captures: process trees, injected code identification, defensible conclusions
- Led 2-person insider threat investigation (Case 2026-AE-099): analyzed 6 forensic disk images to prove IP exfiltration via USB

---

### Web Application Penetration Testing
**Course:** ITSC Web Security
**Skills:** Burp Suite, SQLi, XSS, CSRF, DOM manipulation, web reconnaissance, ffuf

- SQL injection: schema extraction, credential dumping, authentication bypass
- XSS (reflected, stored, DOM-based) across 4 lab scenarios
- CSRF: token bypass, SameSite bypass, Referer-based bypass against a live micro-blogging app

---

### Exploit Development and Privilege Escalation
**Course:** ITSC-304 Penetration Testing
**Skills:** Metasploit, msfvenom, shellcode, Windows internals, ACL abuse, PowerShell

- Exploited vsftpd 2.3.4 via Metasploit; custom shellcode with msfvenom (bind/reverse shell ELF)
- Identified 8 misconfigurations in a seeded Windows 11 environment
- Achieved persistent reverse shell from low-privileged user via SYSTEM scheduled task abuse

---

### Network Security and IDS/IPS
**Course:** ITSC Network Security
**Skills:** Scapy, Snort, Suricata, pfSense, IPsec VPN, Active Directory, Kerberos, Wireshark

- 4-VLAN segmented network with OSPF, DHCP snooping, DAI
- Custom Scapy XMAS packet IDS; Snort/Suricata rule authoring on pfSense
- Site-to-site IPsec VPN (Phase 1 and 2); AD deployment, Kerberos ticket extraction, hash cracking
- Defense-in-depth network security plan covering 7 zones with logical diagrams

---

### Identity Access Control and Security Policy Design
**Course:** ITSC Security Policies and Operations
**Skills:** IAM policy, MFA, VPN architecture, physical security, data lifecycle

- Identity access control policy for pharmaceutical research system (directory service, ID standards, MFA, session controls, audit plan)
- 2FA VPN architecture diagram with DMZ placement and authentication service justification
- Physical access control plan for data centre covering 8 vulnerability areas

---

### Offline CVE Vulnerability Scanner
**Course:** ITSC-203 Scripting for Tool Construction
**Skills:** Python, Nmap, CSV parsing, file I/O, structured reporting

Python tool that parses Nmap scan output against an offline CVE database (1,000+ entries) and generates structured findings reports — simulating an air-gapped security assessment workflow.

---

## Skills Demonstrated

| Category | Tools and Technologies |
|---|---|
| Web App Security | Burp Suite, SQLi, XSS, CSRF, SSRF, SSTI, ffuf, threat modeling |
| Penetration Testing | Metasploit, msfvenom, Nmap, privilege escalation, shellcode |
| Malware Analysis | Ghidra, FLOSS, ProcMon, Regshot, Sysmon, YARA, ClamAV, MITRE ATT&CK |
| Digital Forensics | Autopsy, Volatility, disk/memory forensics, VHD/USB analysis |
| Detection Engineering | YARA rules, behavioral detection, indicator fragility, EDR/SIEM deployment |
| Network Security | Scapy, Snort, Suricata, Wireshark, pfSense, IPsec VPN |
| Programming | Python, Bash, PowerShell, x86_64 assembly basics |
| GRC and IAM | Identity access control, MFA, audit planning, data lifecycle security |

---

## Certifications

- Burp Suite Certified Practitioner (BSCP) — In Progress (PortSwigger Web Security Academy)

---

## Notes

All lab work conducted in isolated VM environments for educational purposes only. No real systems were targeted. Lab reports available upon request.