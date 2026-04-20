# Multi-Service Honeypot System

A production-grade Python honeypot that emulates SSH, FTP, and HTTP services to capture attacker behaviour, enrich telemetry with threat intelligence, and generate structured forensic reports — with ML-based anomaly detection and real-time desktop alerting.

> Built for ITSC-203: Scripting for Tool Construction — SAIT Information Systems Security

---

## What It Does

Attackers interact with what appears to be a legitimate server. Every credential attempt, command, file transfer, and HTTP probe is silently captured, stored, and classified — without exposing any real system.

```
ATTACKER
    |
    +------ SSH :2222  ---->  [Auth logging] --> [Trigger: proxy to backend]
    |                          [Brute force detection]
    |                          [Command capture (bidirectional)]
    |
    +------ FTP :2121  ---->  [Credential capture]
    |                          [File transfer logging]
    |                          [Directory enumeration]
    |
    +------ HTTP:8080  ---->  [Path + User-Agent logging]
                               [Scanner identification]
                               [Reconnaissance profiling]
                                      |
                               [SQLite Evidence Store]
                               [AbuseIPDB Threat Intel]
                               [Desktop Alert System]
                               [JSON + HTML Reports]
                               [Matplotlib Charts]
```

---

## Architecture

### Orchestrator (Main Script)

The main script is the control plane — not just a launcher. It:

- Defines a **single source of truth** for all runtime configuration (ports, paths, credentials, timeouts)
- Initializes shared services before accepting traffic: logging, SQLite database, alert system, threat intelligence client
- Starts each protocol listener as an **independent thread** so a slow attacker on one service never blocks another
- Enforces safety boundaries at the top level so protocol handlers cannot accidentally expose the host

### Concurrency Model

| Service | Threading Model |
|---|---|
| SSH | Per-client handler thread spawned on each accept |
| FTP | pyftpdlib event loop with async I/O |
| HTTP | Handle-request loop with 1s timeout |
| Alerts | Dedicated daemon worker thread (queue-based) |

All threads share one database object protected by `threading.Lock()` — preventing SQLite race conditions during simultaneous attacks.

### Shutdown Pipeline

```
Ctrl+C
  |
  v
graceful_shutdown()
  |- running = False
  |- shutdown_event.set()
  |- desktop_alerts.stop()
  |- generate_comprehensive_report()
       |- Daily JSON report
       |- Matplotlib charts (if available)
       |- HTML combined report
  |- sys.exit(0)
```

Evidence completeness is guaranteed: sessions track `start/end` fields, and shutdown waits for in-progress writes to complete.

---

## Components

### SSH Honeypot (Paramiko)

The most advanced component. Presents as a legitimate SSH server while intercepting everything.

**Dual-path session logic:**

```
Credential attempt
        |
   Match TRIGGER_CREDS?
        |
   YES ─────────────────────────> Proxy to real backend
   |                              - Paramiko client to BACKEND_HOST
   |                              - PTY + interactive shell
   |                              - Bidirectional forwarding loop
   |                              - Every command logged with direction tag
   |
   NO ──────────────────────────> Reject + log + count
                                  - Brute force threshold alert at 3+ attempts
```

**Direction-tagged command logging:**
```
client->backend: whoami
backend->client: root
client->backend: cat /etc/passwd
backend->client: root:x:0:0:root:/root:/bin/bash...
```

This preserves a true transcript-style timeline of attacker activity.

### FTP Honeypot (pyftpdlib)

High-interaction but safely contained. Captures full credential pairs and all file operations.

| Hook | Captures |
|---|---|
| `on_connect()` | IP, port — creates session record |
| `on_login(username)` | Username + desktop alert |
| `ftp_PASS(password)` | Full credential pair to SQLite |
| `ftp_RETR(file)` | Download attempt + counter |
| `ftp_STOR(file)` | Upload attempt + counter |
| `on_disconnect()` | Session end timestamp |

Filesystem containment: all operations restricted to `FTP_ROOT` — no symbolic link traversal, no host filesystem access.

### HTTP Honeypot (HTTPServer)

Low-interaction, reconnaissance-focused. Captures scanning infrastructure signatures.

Every GET request logs:
- Source IP
- Request path (reveals attacker target interest — `/wp-login.php`, `/admin`, `/.env`)
- User-Agent (identifies scanning tools, bots, frameworks)
- Timestamp (reveals scan cadence and automation patterns)

Returns a static HTML response — no dynamic templates, no server-side logic, no reflection of attacker input.

### SQLite Evidence Store

```sql
ssh_sessions     -- auth attempts, trigger events, session lifecycle
ssh_commands     -- full command/response transcript with direction tags
ftp_sessions     -- credential pairs, file transfer counters
ftp_commands     -- every FTP verb and parameter
http_requests    -- IP, method, path, User-Agent, timestamp
```

All inserts use parameterized queries (`?` placeholders) — SQL injection from attacker input is impossible.

Timestamps use `datetime.now().isoformat()` — forensic-friendly, sortable, SIEM-compatible.

### Threat Intelligence (AbuseIPDB)

```
Incoming connection
        |
        v
Check local cache (1hr TTL)
        |
   Cache hit? --> return cached result
        |
   Cache miss --> AbuseIPDB API call
                  abuseConfidenceScore > 25 ?
                        |
                   YES --> HIGH alert + warning log
                   NO  --> log + continue
```

The 1-hour cache prevents redundant API calls when the same scanner hits multiple services — common during automated scan storms.

### Desktop Alert System

Queue-based architecture — alerts never block service threads:

```
SSH/FTP/HTTP thread --> alert_queue.put(alert) --> daemon worker --> display
```

**Alert levels:**

| Level | Trigger | Action |
|---|---|---|
| CRITICAL | Trigger credentials used | Immediate notification + beep |
| HIGH | Brute force (3+ attempts), known threat IP | High-urgency notification |
| MEDIUM | FTP login | Normal notification |
| LOW | File operation, HTTP probe | Low-priority notification |

Anti-spam controls: 100-alert queue cap + 300-second per-IP cooldown. Alerts also persist as JSON: `honeypot_alerts/alerts_YYYYMMDD.json`.

---

## Installation

### Required
```bash
pip install paramiko
```

### Optional (full functionality)
```bash
pip install pyftpdlib pandas matplotlib requests
```

---

## Configuration

```python
# Ports
SSH_PORT = 2222
FTP_PORT = 2121
HTTP_PORT = 8080

# Backend for proxied SSH sessions (triggered credentials only)
BACKEND_HOST = "10.0.2.33"
BACKEND_PORT = 22

# Storage
FTP_ROOT = "/opt/ftp_honeypot"
SQLITE_DB = "honeypot.db"

# Threat intelligence (leave empty to disable)
ABUSEIPDB_API_KEY = ""

# Credentials that grant access + proxy to backend
TRIGGER_CREDS = {
    "admin": "password123",
}
```

---

## Usage

```bash
# Start all services
python3 honeypot.py

# Report generation
python3 honeypot.py --report    # Daily JSON report
python3 honeypot.py --charts    # Matplotlib charts only
python3 honeypot.py --all       # Full report + charts + HTML

# Live monitoring
tail -f honeypot.log
```

Press `Ctrl+C` to stop — reports auto-generate on shutdown.

---

## Output Files

| File / Directory | Contents |
|---|---|
| `honeypot.db` | SQLite evidence database |
| `honeypot.log` | Real-time operational log |
| `honeypot_rsa_key` | Auto-generated SSH host key |
| `daily_reports/report_YYYY-MM-DD.json` | Daily attack summary |
| `honeypot_charts/daily_attacks.png` | Attack frequency trend chart |
| `honeypot_charts/service_comparison.png` | SSH vs FTP vs HTTP bar chart |
| `reports/shutdown_report_TIMESTAMP.html` | Full HTML report with embedded charts |
| `honeypot_alerts/alerts_YYYYMMDD.json` | Desktop alert log |

---

## Sample Report

```json
{
  "date": "2026-03-15",
  "total_attacks": 847,
  "ssh_attacks": 612,
  "ftp_attacks": 183,
  "http_attacks": 52,
  "trigger_events": 3,
  "top_attackers": [
    {"ip": "185.234.x.x", "attacks": 241},
    {"ip": "45.142.x.x",  "attacks": 187},
    {"ip": "103.99.x.x",  "attacks": 94}
  ]
}
```

---

## Security Notes

- Deploy in an **isolated VM or dedicated network segment** — not on production infrastructure
- The `ABUSEIPDB_API_KEY` should be stored as an environment variable in production
- Captured credentials are stored in plaintext SQLite for research analysis
- Backend proxying is intended for controlled research environments only

---

## Skills Demonstrated

`Python` `Multi-threading` `paramiko` `pyftpdlib` `SQLite` `Socket programming` `SSH proxy architecture` `Thread-safe database design` `REST API integration` `Queue-based alert system` `Signal handling` `Graceful shutdown` `Pandas` `Matplotlib` `ML anomaly detection` `Forensic timestamping` `Parameterized SQL`
