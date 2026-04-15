# Network Security & IDS/IPS

> Design, segmentation, and defence of multi-network environments — configuring detection rules, monitoring traffic, validating security controls, and deploying network-based intrusion detection and prevention systems.

---

## Overview

| Item | Detail |
|---|---|
| **Firewall / Router** | pfSense 2.7 |
| **IDS/IPS** | Suricata · Snort |
| **Traffic Analysis** | Wireshark · Zeek |
| **Packet Crafting** | Scapy |
| **Identity** | Active Directory · Kerberos |
| **Semester** | Semesters 2 & 4 — May 2025 to April 2026 |

---

## Lab Environment Design

```
                    ┌─────────────────┐
                    │    Internet     │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   pfSense FW    │  ← IDS/IPS (Suricata)
                    │  192.168.0.1    │  ← DHCP Snooping
                    │                 │  ← ARP Inspection
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
    ┌─────▼──────┐   ┌───────▼──────┐   ┌──────▼──────┐
    │  VLAN 10   │   │   VLAN 20    │   │   VLAN 30   │
    │  LAN/Users │   │  DMZ/Servers │   │  Management │
    │ 10.0.10.x  │   │  10.0.20.x   │   │  10.0.30.x  │
    └────────────┘   └──────────────┘   └─────────────┘
          │
    ┌─────▼──────┐
    │  VLAN 40   │
    │  IoT/Guest │
    │ 10.0.40.x  │
    └────────────┘
```

**Routing:** OSPF between VLANs  
**Access Control:** Inter-VLAN firewall rules — deny-by-default  
**VPN:** Site-to-site IPsec (Phase 1: IKEv2 / Phase 2: AES-256)

---

## Suricata IDS/IPS Rule Development

### ARP Spoofing Detection

```
# Detect ARP replies not matching known MAC-IP pairs
alert arp any any -> any any (
    msg:"POTENTIAL ARP SPOOFING DETECTED";
    arp.opcode:2;
    arp.src_mac:!$KNOWN_MACS;
    classtype:protocol-command-decode;
    sid:9000001;
    rev:1;
)

# Detect gratuitous ARP from unexpected sources
alert arp any any -> any any (
    msg:"GRATUITOUS ARP FROM UNKNOWN HOST";
    arp.opcode:1;
    arp.src_ip:!$TRUSTED_HOSTS;
    threshold:type both, track by_src, count 5, seconds 10;
    classtype:bad-unknown;
    sid:9000002;
    rev:1;
)
```

### DHCP Starvation Detection

```
# Detect DHCP DISCOVER flood (potential starvation attack)
alert udp any any -> any 67 (
    msg:"DHCP STARVATION ATTACK DETECTED";
    content:"|01|";
    offset:0;
    depth:1;
    threshold:type both, track by_src, count 50, seconds 10;
    classtype:denial-of-service;
    sid:9000003;
    rev:1;
)
```

### Port Scan Detection

```
# Detect TCP SYN scan
alert tcp any any -> $HOME_NET any (
    msg:"NMAP TCP SYN SCAN DETECTED";
    flags:S,12;
    threshold:type both, track by_src, count 20, seconds 2;
    classtype:network-scan;
    sid:9000004;
    rev:1;
)
```

---

## Traffic Analysis with Wireshark & Scapy

### Wireshark Filters Used

```python
# Identify all ARP traffic
arp

# Filter by specific source IP
ip.src == 10.0.10.15

# Detect SYN scans (many SYNs, no completions)
tcp.flags.syn == 1 && tcp.flags.ack == 0

# DNS queries only
dns && dns.flags.response == 0

# Identify suspicious large DNS responses (potential DNS tunneling)
dns && dns.resp.len > 512

# Filter Kerberos traffic for analysis
kerberos
```

### Scapy — Custom Packet Crafting for Rule Testing

```python
from scapy.all import *

# Craft ARP spoof packet for rule validation
def test_arp_spoof(target_ip, spoof_ip, iface="eth0"):
    arp_response = ARP(
        op=2,                          # ARP reply
        psrc=spoof_ip,                 # Claim to be this IP
        hwsrc="aa:bb:cc:dd:ee:ff",     # Fake MAC address
        pdst=target_ip,
        hwdst="ff:ff:ff:ff:ff:ff"      # Broadcast
    )
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/arp_response, iface=iface)
    print(f"[*] Sent ARP spoof: {spoof_ip} -> aa:bb:cc:dd:ee:ff")

# Verify Suricata rule triggered
# Expected: Alert in /var/log/suricata/fast.log
# [**] [1:9000001:1] POTENTIAL ARP SPOOFING DETECTED [**]
```

---

## IPsec VPN Configuration

### Phase 1 (IKE)

| Parameter | Value |
|---|---|
| IKE Version | IKEv2 |
| Authentication | Pre-shared key |
| Encryption | AES-256 |
| Hash | SHA-256 |
| DH Group | 14 (2048-bit MODP) |
| Lifetime | 28800 seconds |

### Phase 2 (ESP)

| Parameter | Value |
|---|---|
| Protocol | ESP |
| Encryption | AES-256 |
| Hash | SHA-256 |
| PFS Group | 14 |
| Lifetime | 3600 seconds |

---

## Active Directory Deployment

### Environment

```
Domain:          lab.internal
Forest/Domain:   Windows Server 2022
Workstations:    Windows 11 (3 hosts)
DC:              WIN-DC01 (192.168.1.10)
```

### GPO Security Baseline Applied

| Policy | Setting |
|---|---|
| Account Lockout | 5 failed attempts → 30-minute lockout |
| Password Policy | 12 chars min, complexity required, 90-day expiry |
| Audit Policy | Logon events, object access, privilege use |
| AppLocker | Whitelist only — blocks unsigned executables |
| Windows Firewall | Domain profile — restricted inbound |

---

## Key Takeaways

- IDS/IPS rules require iterative tuning — overly broad rules generate noise that desensitises analysts
- Scapy is invaluable for rule validation — craft the exact packet your rule should catch before deploying
- DHCP snooping and dynamic ARP inspection should be baseline on any managed switch deployment
- IPsec Phase 1 and Phase 2 mismatches are the most common VPN failure point — document parameters on both ends
