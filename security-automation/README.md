# Security Automation & Threat Intelligence

> Python-based security tools built to reduce manual toil, accelerate analysis, and surface insights from security datasets. Includes a CVE vulnerability scanner, an ML-powered honeypot, and 15+ supporting automation scripts.

---

## Overview

| Item | Detail |
|---|---|
| **Primary Language** | Python 3 |
| **Supporting** | PowerShell · Bash |
| **Libraries** | Pandas · Matplotlib · SQLite · Requests · Scapy · Threading |
| **Semester** | Semesters 3 & 4 — September 2025 to April 2026 |

---

## Tool 1 — CVE Vulnerability Scanner

### What It Does
Parses Nmap scan output and cross-references discovered services against a local CVE database to generate structured risk findings reports — designed for offline and air-gapped environments.

### Architecture

```
Nmap Scan Output (.xml)
        │
        ▼
┌───────────────────────┐
│  XML Parser           │ → Extracts: host, port, service, version
└───────────────────────┘
        │
        ▼
┌───────────────────────┐
│  CVE Matcher          │ → Cross-references against 1,000+ CVE entries
│                       │   Matches on: product name + version range
└───────────────────────┘
        │
        ▼
┌───────────────────────┐
│  Report Generator     │ → Structured findings report:
│                       │   - Host / Port / Service
│                       │   - CVE ID + CVSS score
│                       │   - Severity rating (Critical/High/Medium/Low)
│                       │   - Remediation recommendation
└───────────────────────┘
```

### Sample Output

```
╔══════════════════════════════════════════════════════╗
║           VULNERABILITY ASSESSMENT REPORT            ║
║           Target: 192.168.1.0/24                     ║
║           Scan Date: 2026-03-15  Findings: 7         ║
╚══════════════════════════════════════════════════════╝

[CRITICAL] 192.168.1.10 — Port 445 (SMB)
  CVE-2017-0144 (EternalBlue) | CVSS: 9.3
  Affected: Windows Server 2008 R2 SP1 (unpatched)
  Remediation: Apply MS17-010 immediately. Isolate host if patch
  cannot be applied immediately.

[HIGH] 192.168.1.22 — Port 21 (vsftpd 2.3.4)
  CVE-2011-2523 | CVSS: 7.5
  Affected: vsftpd 2.3.4 — backdoor command execution
  Remediation: Upgrade to vsftpd 3.0.5 or later.

[MEDIUM] 192.168.1.10 — Port 443 (Apache 2.2.31)
  CVE-2016-8740 | CVSS: 5.0
  Affected: mod_http2 denial of service
  Remediation: Upgrade to Apache 2.4.x.

Report generated in 0.8 seconds | 3 hosts scanned | 7 findings
```

### Key Features
- Offline-capable — no external API calls required
- Processes Nmap XML output directly
- CVSS-based severity classification
- Generates both terminal output and structured text reports
- Sub-60-second processing for typical network scans

---

## Tool 2 — Honeypot with ML Anomaly Detection Pipeline

### What It Does
A multi-threaded honeypot that simulates real services, collects attacker telemetry, enriches it with threat intelligence, and applies ML-based anomaly detection to distinguish attacker behaviour from benign traffic.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    HONEYPOT LAYER                        │
│  Thread 1: SSH emulator (port 22)                        │
│  Thread 2: HTTP emulator (port 80)                       │
│  Thread 3: FTP emulator (port 21)                        │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                  TELEMETRY COLLECTION                    │
│  Source IP · Timestamp · Port · Payload · Session ID    │
│  → Written to SQLite database (honeypot.db)             │
└─────────────────────────────────────────────────────────┘
                          │
                    ┌─────┴─────┐
                    ▼           ▼
          ┌──────────────┐  ┌──────────────────────┐
          │  Threat Intel│  │  ML Anomaly Detection │
          │  API Enrichmt│  │  (Isolation Forest)   │
          │  VirusTotal  │  │  Detects: beaconing,  │
          │  AbuseIPDB   │  │  scanning, brute force│
          └──────────────┘  └──────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│                ANALYSIS & VISUALISATION                  │
│  Pandas: session analysis, frequency patterns           │
│  Matplotlib: attack timeline, source distribution       │
│  Structured report: top attackers, TTPs, IOCs           │
└─────────────────────────────────────────────────────────┘
```

### Data Collected (Sample)

```python
{
    "session_id": "a3f8c2d1",
    "timestamp": "2026-03-01T14:23:11Z",
    "source_ip": "185.234.x.x",
    "source_port": 54821,
    "target_port": 22,
    "protocol": "SSH",
    "payload": "root\nadmin\npassword\n123456",
    "session_duration": 4.2,
    "attempt_count": 47,
    "threat_intel": {
        "abuse_score": 98,
        "country": "RU",
        "known_scanner": true
    },
    "anomaly_score": -0.847,
    "classification": "ATTACKER"
}
```

### Observations (100+ Interactions Collected)

| Metric | Value |
|---|---|
| Total interactions | 134 |
| Unique source IPs | 41 |
| Most targeted service | SSH (port 22) — 67% |
| Top credential attempt | root/admin/password |
| Average session duration | 3.8 seconds |
| ML anomaly detection accuracy | 94% (validated against labelled subset) |

---

## Supporting Tools

| Tool | Description |
|---|---|
| `log_parser.py` | Parses Security Onion and syslog formats into structured JSON |
| `alert_correlator.py` | Correlates Suricata + Wazuh alerts by time window and source IP |
| `yara_validator.py` | Tests YARA rules against sample sets and reports match rates |
| `report_generator.py` | Produces formatted markdown and PDF security findings reports |
| `threat_intel_client.py` | Queries VirusTotal and AbuseIPDB APIs for IP/hash enrichment |
| `cve_lookup.py` | Standalone CVE lookup by product name and version |

---

## Key Takeaways

- Multi-threading is essential for realistic honeypot behaviour — single-threaded emulators are trivially fingerprinted
- ML anomaly detection on small datasets requires careful feature engineering — raw connection count alone is insufficient
- Threat intelligence enrichment transforms IP addresses into actionable context
- Automation eliminates the bottleneck between raw telemetry and analyst-ready findings
