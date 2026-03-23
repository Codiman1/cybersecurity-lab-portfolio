# Cybersecurity Lab Portfolio

**Ludovic JT**
Diploma in Information Systems Security - SAIT, Calgary AB (Expected December 2026)
Email: ludovicjoan.18@gmail.com | Calgary, AB | BSCP Certification In Progress

---

## About This Repository

This repository documents hands-on cybersecurity lab work completed as part of the Information Systems Security diploma program at the Southern Alberta Institute of Technology (SAIT). Each project folder contains lab reports, scripts, and technical writeups demonstrating applied skills in penetration testing, network security, exploit development, and defensive tool construction.

---

## Projects

### Multi-Service Python Honeypot
**Course:** ITSC-203 Scripting for Tool Construction
**Skills:** Python, multi-threading, SQLite, SSH/FTP/HTTP protocol simulation, threat intelligence

A multi-threaded honeypot simulating 3 real network services (SSH, FTP, HTTP) to capture attacker behaviour. Logs 5 categories of attacker telemetry into a centralized SQLite database for forensic analysis and SIEM rule development.

**Key highlights:**
- Concurrent session handling across 3 protocol listeners using Python threading
- Dual-output logging (flat file + SQLite) for forensic evidence
- Captures attacker TTPs usable for detection rule development and security awareness training

---

### Web Application Penetration Testing
**Course:** ITSC Web Security
**Skills:** Burp Suite, SQLi, XSS, CSRF, DOM manipulation, web reconnaissance, ffuf

Structured labs covering the full web application attack lifecycle from reconnaissance through exploitation.

**Labs covered:**
- DOM manipulation and client-side JavaScript exploitation
- SQL injection (manual + Burp Suite) - schema extraction, credential dumping, auth bypass
- Cross-Site Scripting (XSS) - reflected, stored, DOM-based across 4 lab scenarios
- CSRF attacks - token bypass, SameSite bypass, Referer-based bypass

---

### Exploit Development and Privilege Escalation
**Course:** ITSC-304 Penetration Testing
**Skills:** Metasploit, msfvenom, shellcode, Windows internals, ACL abuse, scheduled task exploitation

Labs focused on exploit development and Windows privilege escalation using real-world techniques in isolated VM environments.

**Labs covered:**
- Exploiting vsftpd 2.3.4 backdoor via Metasploit
- Custom shellcode generation with msfvenom (bind shell, reverse shell, ELF payloads)
- Windows privilege escalation via ACL misconfigurations and writable scheduled tasks
- Persistent reverse shell from low-privileged user abusing SYSTEM-level scheduled task
- Analysis of 8 security misconfigurations seeded into a Windows 11 environment

---

### Network Security and IDS/IPS
**Course:** ITSC Network Security
**Skills:** Scapy, Snort, Suricata, pfSense, VPN, Active Directory, Kerberos, Wireshark

Comprehensive network security labs covering offensive techniques and defensive countermeasures.

**Labs covered:**
- 4-VLAN network design with OSPF routing, DHCP snooping, and Dynamic ARP Inspection
- ARP and DHCP spoofing attacks + custom Scapy-based XMAS packet IDS
- Snort/Suricata IDS/IPS rule writing and deployment on pfSense
- Site-to-site IPsec VPN (Phase 1 and 2) between 2 pfSense firewalls
- Active Directory + Kerberos ticket extraction (Rubeus) + hash cracking (John the Ripper)

---

### Offline CVE Vulnerability Scanner
**Course:** ITSC-203 Scripting for Tool Construction
**Skills:** Python, Nmap, CSV parsing, file I/O, structured reporting

Python tool that parses Nmap scan output, cross-references findings against an offline CVE database (1,000+ entries), and generates a structured security findings report simulating an air-gapped workflow.

---

## Skills Demonstrated

| Category | Tools and Technologies |
|---|---|
| Web App Security | Burp Suite, SQLi, XSS, CSRF, SSRF, SSTI, ffuf, DOM manipulation |
| Penetration Testing | Metasploit, msfvenom, Nmap, privilege escalation, shellcode |
| Network Security | Scapy, Snort, Suricata, Wireshark, pfSense, IPsec VPN |
| Programming | Python, Bash, PowerShell, x86_64 assembly basics |
| Operating Systems | Kali Linux, Windows 11, Windows Server, pfSense |
| Defensive Tools | Honeypot development, IDS scripting, CVE scanning, SQLite logging |
| Active Directory | Kerberos, Rubeus, John the Ripper, domain controller setup |
| Cryptography | RSA, ECC, AES, Diffie-Hellman, PBKDF2, Argon2 |

---

## Certifications

- Burp Suite Certified Practitioner (BSCP) - In Progress (PortSwigger Web Security Academy)

---

## Notes

All lab work was conducted in isolated virtual machine environments for educational purposes only. No real systems were targeted. Lab reports available upon request.