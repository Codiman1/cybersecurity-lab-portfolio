# SIEM Operations & Threat Hunting

> Hands-on operation of Security Onion — a production-grade SIEM and network security monitoring platform — covering log ingestion, multi-source event correlation, structured threat hunting, and defensible incident reporting.

---

## Overview

| Item | Detail |
|---|---|
| **Platform** | Security Onion 2.x |
| **SIEM Engine** | Elastic Stack (Elasticsearch, Kibana, Logstash) |
| **Network IDS** | Suricata |
| **Host IDS** | Wazuh / OSSEC |
| **Network Flow** | Zeek (Bro) |
| **Framework** | MITRE ATT&CK |
| **Semester** | Semester 4 — January 2026 to April 2026 |

---

## Data Sources Ingested

| Source | Data Type | Purpose |
|---|---|---|
| Suricata | Network alerts (IDS/IPS) | Detect known attack signatures |
| Wazuh/OSSEC | Host events (auth, process, file) | Monitor endpoint activity |
| Zeek | Network flow metadata | Passive traffic analysis |
| Windows Event Logs | Auth, process creation, account mgmt | Host activity correlation |

---

## Investigation Methodology

Each investigation followed a three-track hunting model:

**Track 1 — Web Activity (HTTP)**
- Identified unusual HTTP methods, URI patterns, and user-agent strings
- Detected path enumeration attempts and directory traversal patterns
- Correlated web requests with host-side process creation events

**Track 2 — Network Activity (DNS / TLS / Flows)**
- Analysed DNS query patterns for domain generation algorithm (DGA) indicators
- Identified anomalous TLS certificate characteristics
- Detected beaconing behaviour through periodic connection interval analysis

**Track 3 — Host Activity (Authentication / Processes / Files)**
- Reviewed failed authentication sequences and privilege escalation events
- Correlated process creation chains with lateral movement patterns
- Identified file access anomalies consistent with data staging

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection Source |
|---|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application | Suricata + HTTP logs |
| Discovery | T1046 — Network Service Scanning | Zeek flow data |
| Discovery | T1083 — File and Directory Discovery | Windows Event Logs |
| Lateral Movement | T1021 — Remote Services | Wazuh auth logs |
| Collection | T1074 — Data Staged | File access events |
| C2 | T1071 — Application Layer Protocol | DNS + TLS analysis |
| Privilege Escalation | T1055 — Process Injection | Wazuh + Sysmon |

---

## Sample Investigation Output

```
Investigation ID: INV-2026-001
Severity:         HIGH
Status:           Closed — Confirmed Threat
Duration:         3h 40m

Timeline:
  14:23 — Suricata alert: ET SCAN Nmap TCP SYN Scan
  14:26 — Zeek: 47 connections to port 445 in 90s from 10.0.1.15
  14:31 — Wazuh: Failed authentication x12, user 'administrator'
  14:35 — Wazuh: Successful login, user 'administrator'
  14:37 — Windows Event 4672: Special privileges assigned
  14:41 — Sysmon Event 1: cmd.exe spawned by svchost.exe
  14:44 — Zeek: Outbound DNS to randomised subdomain (DGA indicator)

ATT&CK Mapping:
  T1046 (Network Service Scanning)
  T1110.001 (Brute Force: Password Guessing)
  T1078 (Valid Accounts)
  T1059.003 (Windows Command Shell)
  T1071.004 (DNS C2)

Recommendation: Isolate host 10.0.1.15. Reset compromised credentials.
  Implement account lockout policy. Block identified C2 domain at DNS layer.
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| Security Onion | SIEM platform, alert management, investigation interface |
| Kibana | Log querying, dashboard visualisation, hunt queries |
| Suricata | Network IDS — signature-based alerting |
| Wazuh | Host IDS — file integrity, auth monitoring, process tracking |
| Zeek | Passive network flow analysis — DNS, HTTP, TLS, connection logs |
| MITRE ATT&CK Navigator | Tactic and technique mapping |

---

## Key Takeaways

- Multi-source correlation is essential — no single data source tells the full story
- Time-ordering events across sources reveals attacker progression that individual alerts miss
- MITRE ATT&CK mapping transforms technical findings into actionable defensive recommendations
- Executive-readable reporting requires translating technical evidence into clear narrative conclusions
