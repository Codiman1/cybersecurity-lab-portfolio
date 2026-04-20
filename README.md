# Cybersecurity Lab Portfolio
### Ludovic Joan Siatou Tchouaffi

> Information Systems Security student at SAIT (graduating December 2026) with hands-on depth across defensive security, threat detection, digital forensics, and security automation. This portfolio documents structured lab work across six technical domains aligned to entry-level SOC analyst, security analyst, and application security roles.

---

## 📋 Portfolio Overview

| Project | Domain | Key Tools | Status |
|---|---|---|---|
| [SIEM Operations & Threat Hunting](#-siem-operations--threat-hunting) | Blue Team / Detection | Security Onion, Suricata, Wazuh, Zeek, Elastic SIEM | ✅ Complete |
| [Web Application Security Testing](#-web-application-security-testing) | Offensive / AppSec | Burp Suite, OWASP Top 10, SQLi, XSS, CSRF | ✅ Complete |
| [Malware Analysis](#-malware-analysis) | Reverse Engineering | Ghidra, x64dbg, FakeNet-NG, ProcMon, FLOSS | ✅ Complete |
| [Digital Forensics & Incident Response](#-digital-forensics--incident-response) | DFIR | Autopsy, Volatility, VHD/RAM forensics | ✅ Complete |
| [Security Automation & Threat Intelligence](#-security-automation--threat-intelligence) | Python / Automation | Python, SQLite, Pandas, Matplotlib, APIs | ✅ Complete |
| [Network Security & IDS/IPS](#-network-security--idsips) | Network Defense | pfSense, Suricata, Scapy, Wireshark, VLANs | ✅ Complete |

---

## 🔵 SIEM Operations & Threat Hunting

**Objective:** Operate a full SIEM platform end-to-end — from log ingestion through alert triage, structured threat hunting, and defensible investigation reporting.

**Platform:** Security Onion (Suricata · Wazuh/OSSEC · Zeek · Elastic SIEM · MITRE ATT&CK)

**What I did:**
- Ingested multi-source logs (Suricata network alerts, Wazuh host events, Zeek flow data, Windows Event Logs) into Security Onion for SIEM correlation
- Executed structured threat hunting across three tracks: web activity (HTTP), network activity (DNS/TLS/flows), and host activity (authentication, processes, files)
- Identified path enumeration, anomalous beaconing, and privilege escalation events from raw telemetry
- Built time-ordered investigative narratives mapping findings to MITRE ATT&CK tactics
- Produced structured investigation reports for both technical and executive audiences

**Key skills demonstrated:** Log ingestion · Event correlation · Alert triage · Threat hunting · MITRE ATT&CK · Incident documentation

📁 [`/siem-threat-hunting/`](./siem-threat-hunting/)

---

## 🔴 Web Application Security Testing

**Objective:** Perform manual and automated web application security testing against intentionally vulnerable targets, documenting findings in structured vulnerability reports.

**Tools:** Burp Suite · OWASP Top 10 · SQLmap · Manual testing techniques · DVWA · WebGoat

**What I did:**
- Performed web application security testing using Burp Suite's proxy, repeater, and scanner modules
- Identified and exploited SQL injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), authentication bypass, and directory traversal vulnerabilities
- Applied attack surface analysis to map entry points, trust boundaries, and data flows
- Documented each vulnerability with OWASP category, severity rating, proof-of-concept, and remediation recommendation
- Produced structured findings reports suitable for developer handoff

**Key skills demonstrated:** Burp Suite · SQLi · XSS · CSRF · Authentication bypass · OWASP Top 10 · Vulnerability reporting

📁 [`/web-app-security/`](./web-app-security/)

---

## 🟠 Malware Analysis

**Objective:** Perform static and dynamic analysis of malware samples to understand behavior, extract indicators of compromise, and produce analyst reports mapped to MITRE ATT&CK.

**Tools:** Ghidra · x64dbg · FLOSS · ProcMon · Regshot · API Monitor · FakeNet-NG

**What I did:**
- Conducted static analysis using Ghidra (disassembly, function mapping) and FLOSS (string extraction) to understand malware structure before execution
- Performed dynamic analysis in an isolated sandbox: monitored registry changes (Regshot), API calls (API Monitor), network callbacks (FakeNet-NG), and file system activity (ProcMon)
- Identified C2 communication patterns, persistence mechanisms, and evasion techniques
- Extracted IOCs (file hashes, registry keys, network indicators, mutexes) and produced MITRE ATT&CK-mapped analyst reports
- Analyzed 2 distinct malware families across both static and dynamic methodologies

**Key skills demonstrated:** Static analysis · Dynamic analysis · IOC extraction · C2 detection · Sandbox analysis · MITRE ATT&CK mapping

📁 [`/malware-analysis/`](./malware-analysis/)

---

## 🟢 Digital Forensics & Incident Response

**Objective:** Conduct structured forensic investigations of disk images and memory captures, applying IR lifecycle principles to produce defensible, chain-of-custody investigation reports.

**Tools:** Autopsy · Volatility · Wireshark · Registry artifact analysis · Windows Event Logs

**What I did:**
- **Case 2026-AE-099 (Insider Threat Investigation):** Led a two-person forensic investigation analyzing 6 forensic disk images (5 VHD + 1 raw .img); recovered deleted files, geolocation EXIF metadata, and browser cache artifacts to prove IP exfiltration via USB — produced a defensible chain-of-custody investigation report
- **Memory forensics:** Analyzed shrapnel RAM captures using Volatility — extracted process trees, identified injected code, and produced defensible conclusions from incomplete volatile evidence
- **Registry & event log analysis:** Recovered execution artifacts (MRU, ShellBags, UserAssist) and correlated Windows event log evidence to reconstruct system activity timelines for audit-ready reporting
- Applied full IR lifecycle: preparation → detection → containment → eradication → recovery → lessons learned

**Key skills demonstrated:** Autopsy · Volatility · Memory forensics · Disk forensics · Chain-of-custody · Windows artifacts · IR lifecycle

📁 [`/digital-forensics/`](./digital-forensics/)

---

## 🐍 Security Automation & Threat Intelligence

**Objective:** Build practical security automation tools in Python that reduce manual toil, accelerate analysis, and surface insights from large security datasets.

**Tools:** Python · SQLite · Pandas · Matplotlib · REST APIs · Multi-threading · ML anomaly detection

**What I built:**

### CVE Vulnerability Scanner
- Parses Nmap scan output against a 1,000+ entry CVE database
- Cross-references service versions against known vulnerabilities
- Generates structured risk findings reports with severity ratings in under 60 seconds
- Designed for offline/air-gapped environments

### Honeypot with ML Anomaly Detection Pipeline
- Multi-threaded honeypot simulating 3 real services
- Collects 100+ attacker interactions across 5 telemetry categories into SQLite
- Integrates external threat intelligence APIs for IOC enrichment
- Applies ML-based anomaly detection to distinguish attacker behaviour from benign traffic
- Pandas for automated dataset analysis · Matplotlib for trend visualization

### Supporting Tools (15+ total)
- Log parser and alert correlator
- YARA rule generator and validator
- Structured report generator
- Threat intelligence API client

**Key skills demonstrated:** Python · Security automation · CVE analysis · Threat intelligence · ML anomaly detection · API integration · Data analysis

📁 [`/security-automation/`](./security-automation/)

---

## 🌐 Network Security & IDS/IPS

**Objective:** Design, segment, and defend multi-network environments — configuring IDS/IPS detection rules, monitoring traffic, and validating network security controls.

**Tools:** pfSense · Suricata · Snort · Scapy · Wireshark · Active Directory · IPsec VPN

**What I did:**
- Designed a 4-VLAN segmented network with OSPF routing, DHCP snooping, Dynamic ARP Inspection, and port security
- Authored Suricata IDS/IPS detection rules for ARP spoofing and DHCP starvation attacks
- Configured site-to-site IPsec VPN (Phase 1 and Phase 2) between network segments
- Used Scapy to craft custom packets for testing detection rule accuracy
- Captured and analyzed traffic with Wireshark to verify rule triggering and validate segmentation
- Deployed Active Directory with domain controller, user/group management, GPO, and Kerberos

**Key skills demonstrated:** pfSense · Suricata · IDS/IPS rule authoring · VLAN segmentation · IPsec VPN · Packet crafting · Wireshark · Active Directory

📁 [`/network-security/`](./network-security/)

---

## 🛠 Technical Stack

```
Languages        Python · PowerShell · Bash · C
SIEM             Security Onion · Elastic SIEM · Splunk · Wazuh · Zeek · Suricata
Forensics        Autopsy · Volatility · FTK Imager
Malware          Ghidra · x64dbg · ProcMon · Regshot · FakeNet-NG · FLOSS
Network          Wireshark · Nmap · Scapy · pfSense · Snort · Suricata
Web AppSec       Burp Suite · SQLmap · OWASP Top 10
Frameworks       MITRE ATT&CK · NIST CSF · OWASP · Zero Trust
Platforms        Windows Server · Active Directory · Linux (Kali, Ubuntu, Debian)
Cryptography     RSA · ECC · AES · Diffie-Hellman · Padding oracle attacks
```

---

## 📜 Certifications

| Certification | Status | Provider |
|---|---|---|
| Certified in Cybersecurity (CC) |
| SOC Analyst Level 1 | In progress | HackTheBox Academy |

---

## 📫 Contact

**Ludovic Joan Siatou Tchouaffi**  
🌐 [LinkedIn](https://linkedin.com/in/ludovic-jt)

---

*All lab work was performed in isolated, controlled environments. No real systems were harmed.*
