# Digital Forensics & Incident Response

> Structured forensic investigations of disk images and memory captures, applying the full IR lifecycle to produce defensible, chain-of-custody investigation reports.

---

## Overview

| Item | Detail |
|---|---|
| **Primary Tools** | Autopsy · Volatility · Wireshark |
| **Evidence Types** | VHD disk images · Raw .img · RAM captures · Registry hives |
| **Methodology** | NIST SP 800-86 forensic process |
| **Semester** | Semester 4 — January 2026 to April 2026 |

---

## Case 2026-AE-099 — Insider Threat Investigation

### Case Summary

| Field | Detail |
|---|---|
| **Case ID** | 2026-AE-099 |
| **Type** | Insider threat — suspected IP exfiltration |
| **Evidence** | 6 forensic disk images (5 VHD + 1 raw .img) |
| **Outcome** | Confirmed exfiltration via USB — defensible chain-of-custody report produced |
| **Investigators** | 2-person team |

### Investigation Methodology

**Phase 1 — Evidence Acquisition and Integrity Verification**
```
Hash verification (MD5 + SHA256) performed on all 6 images before analysis
Write-blocked mounting — no modifications to original evidence
Chain-of-custody documentation initiated
```

**Phase 2 — File System Analysis (Autopsy)**
- Parsed MFT (Master File Table) to identify recently accessed, modified, and created files
- Recovered 14 deleted files including documents, compressed archives, and USB-related artifacts
- Extracted browser cache revealing access to personal cloud storage in the 48 hours preceding the incident
- Identified file MAC times (Modified, Accessed, Created) for timeline construction

**Phase 3 — USB Artifact Recovery**
```
Registry artifacts analysed:
  HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
  → Device: SanDisk Cruzer 32GB
  → Serial: 4C530001170519116283
  → First connected: 2026-02-14 09:23:11 UTC
  → Last connected: 2026-02-14 11:47:33 UTC

Setupapi.dev.log:
  → Confirmed USB device installation at 09:23:11

LNK files recovered:
  → Shortcuts to files on removable drive E:\
  → Target files match recovered deleted documents
```

**Phase 4 — Timeline Construction**

```
09:15 — Subject logged in (Windows Event 4624)
09:23 — USB device connected (Setupapi + USBSTOR registry)
09:24 — File access: Q4_Strategy_CONFIDENTIAL.xlsx (MFT timestamp)
09:31 — File access: Product_Roadmap_2026.pptx (MFT timestamp)
09:44 — File access: Client_Database_Export.csv (MFT timestamp)
10:02 — Browser: Accessed personal Dropbox account (browser cache)
10:15 — File deletion: 14 files removed from Desktop (MFT — unallocated)
11:47 — USB device disconnected (Setupapi log)
11:52 — Subject logged out (Windows Event 4634)
```

**Phase 5 — Findings and Conclusion**

> Three confidential files were accessed and copied to a USB storage device (SanDisk Cruzer 32GB, serial 4C530001170519116283) between 09:23 and 11:47 UTC on 2026-02-14. Files were subsequently deleted from the workstation in an apparent concealment attempt. Browser history confirms access to personal cloud storage during the same session. Evidence supports a conclusion of deliberate, premeditated intellectual property exfiltration.

---

## Memory Forensics — Volatile Evidence Analysis

### Scenario
Analysis of shrapnel RAM captures from a suspected compromised host — producing defensible conclusions from incomplete volatile evidence.

### Volatility Analysis

```bash
# Profile identification
python3 vol.py -f memory.raw imageinfo

# Process tree extraction
python3 vol.py -f memory.raw --profile=Win10x64 pstree

# Identify injected code (process hollowing / DLL injection)
python3 vol.py -f memory.raw --profile=Win10x64 malfind

# Network connections at time of capture
python3 vol.py -f memory.raw --profile=Win10x64 netscan

# Extract command history
python3 vol.py -f memory.raw --profile=Win10x64 cmdline
python3 vol.py -f memory.raw --profile=Win10x64 consoles
```

### Key Findings

```
Suspicious Process:
  svchost.exe (PID 2847)
  Parent: explorer.exe (unusual — legitimate svchost parents: services.exe)
  Memory region: PAGE_EXECUTE_READWRITE at 0x00400000 (injected code indicator)

Network Connection:
  svchost.exe (PID 2847) → 185.234.x.x:443 (ESTABLISHED)
  Known malicious IP — confirmed C2

Command History:
  whoami /all
  net user /domain
  ipconfig /all
  dir C:\Users\administrator\Documents
```

---

## Registry Forensics

Key registry locations analysed for persistence and execution artifacts:

| Hive | Key | Artifact Type |
|---|---|---|
| NTUSER.DAT | `\Software\Microsoft\Windows\CurrentVersion\Run` | Persistence |
| NTUSER.DAT | `\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | MRU — recent files |
| NTUSER.DAT | `\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | Program execution |
| SYSTEM | `\CurrentControlSet\Enum\USBSTOR` | USB device history |
| SYSTEM | `\CurrentControlSet\Services\bam\State\UserSettings` | Background Activity Monitor |
| NTUSER.DAT | `\Software\Microsoft\Windows\Shell\BagMRU` | ShellBags — folder access |

---

## IR Lifecycle Applied

| Phase | Actions Taken |
|---|---|
| **Preparation** | Evidence handling procedures, chain-of-custody documentation, hash verification |
| **Detection** | Alert triage, initial scope assessment |
| **Containment** | Evidence isolation, no write operations on original media |
| **Eradication** | Root cause identified (USB exfiltration + deletion attempt) |
| **Recovery** | File recovery from unallocated space, timeline reconstruction |
| **Lessons Learned** | DLP controls, USB port management recommendations, audit logging gaps identified |

---

## Key Takeaways

- Deleted files are rarely gone — MFT entries and unallocated space are primary recovery sources
- USB artifacts persist across multiple registry hives and log files — cross-correlation is essential
- Memory forensics from partial captures requires careful reasoning about what is and isn't present
- Chain-of-custody documentation is as important as the technical findings — without it, nothing holds up
