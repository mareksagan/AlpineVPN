# Anti-DPI Additions Menu

Choose which features to add by referencing the ID numbers.

---

## Category A: Network Layer (Easy, Low Risk)

| ID | Feature | Description | Alpine | FreeBSD | Effort |
|----|---------|-------------|--------|---------|--------|
| A1 | **DNS over HTTPS (DoH)** | Encrypt DNS queries to prevent DNS-based tracking | ✅ | ✅ | Low |
| A2 | **DNS over TLS (DoT)** | Alternative to DoH, port 853 | ✅ | ✅ | Low |
| A3 | **DSCP Field Zeroing** | Clear QoS markings that could identify traffic type | ✅ | ⚠️ | Low |
| A4 | **TCP ECN Disabling** | Disable Explicit Congestion Notification (fingerprinting vector) | ✅ | ✅ | Low |
| A5 | **ARP Filtering** | Ignore ARP requests from non-local networks | ✅ | ❌ | Low |
| A6 | **ICMP Rate Limiting** | Limit ICMP responses to prevent scanning | ✅ | ✅ | Low |
| A7 | **TCP Fast Open Disable** | Disable TFO cookies (tracking vector) | ✅ | ❌ | Low |

---

## Category B: Traffic Obfuscation (Medium Effort)

| ID | Feature | Description | Alpine | FreeBSD | Effort |
|----|---------|-------------|--------|---------|--------|
| B1 | **Shadowsocks Plugin** | Wrap WireGuard in Shadowsocks tunnel | ✅ | ❌ | Medium |
| B2 | **V2Ray/Xray Integration** | Advanced traffic obfuscation and routing | ✅ | ❌ | Medium |
| B3 | **Stunnel Wrapper** | Wrap WireGuard in TLS (looks like HTTPS) | ✅ | ✅ | Medium |
| B4 | **Simple-obfs Plugin** | Basic obfuscation for WireGuard | ✅ | ❌ | Medium |
| B5 | **WebSocket Tunneling** | Tunnel through WebSocket (CDN-friendly) | ✅ | ❌ | Medium |
| B6 | **Domain Fronting** | Use CDN to hide destination | ✅ | ✅ | High |

---

## Category C: System Hardening (Easy)

| ID | Feature | Description | Alpine | FreeBSD | Effort |
|----|---------|-------------|--------|---------|--------|
| C1 | **SSH Hardening** | Change SSH port, disable root login | ✅ | ✅ | Low |
| C2 | **Fail2Ban** | Block brute force attempts | ✅ | ✅ | Low |
| C3 | **MAC Address Randomization** | Randomize MAC on boot | ✅ | ⚠️ | Low |
| C4 | **Hostname Randomization** | Random hostname to prevent tracking | ✅ | ✅ | Low |
| C5 | **Timezone Randomization** | Set UTC to hide location | ✅ | ✅ | Low |
| C6 | **NTP Privacy** | Use encrypted NTP (NTS) | ✅ | ❌ | Low |
| C7 | **USB Guard** | Block USB devices (physical security) | ✅ | ❌ | Medium |

---

## Category D: Advanced Routing (High Effort)

| ID | Feature | Description | Alpine | FreeBSD | Effort |
|----|---------|-------------|--------|---------|--------|
| D1 | **Multi-hop VPN** | Route through 2+ VPN servers | ✅ | ✅ | High |
| D2 | **Tor Bridge** | Route VPN through Tor network | ✅ | ✅ | High |
| D3 | **I2P Integration** | Route through I2P network | ✅ | ❌ | High |
| D4 | **Dynamic Routing** | Auto-switch endpoints when blocked | ✅ | ✅ | High |
| D5 | **Decoy Traffic** | Generate fake HTTP traffic to mask VPN | ✅ | ✅ | Medium |

---

## Category E: Protocol-level (WireGuard Specific)

| ID | Feature | Description | Alpine | FreeBSD | Effort |
|----|---------|-------------|--------|---------|--------|
| E1 | **Persistent Keepalive Jitter** | Already implemented (20-30s random) | ✅ | ✅ | Done |
| E2 | **MTU Randomization** | Randomize MTU per connection | ✅ | ✅ | Medium |
| E3 | **Handshake Spoofing** | Make handshake look like HTTPS TLS | ✅ | ❌ | High |
| E4 | **Packet Padding** | Add random padding to all packets | ❌ | ❌ | Protocol change |
| E5 | **Chaff Traffic** | Send decoy packets during idle | ✅ | ✅ | Medium |

---

## Category F: Kernel-level (Expert)

| ID | Feature | Description | Alpine | FreeBSD | Effort |
|----|---------|-------------|--------|---------|--------|
| F1 | **Kernel Module Hiding** | Hide WireGuard kernel module | ✅ | ❌ | Expert |
| F2 | **System Call Proxying** | Proxy syscalls to hide origin | ❌ | ❌ | Expert |
| F3 | **Custom Kernel Build** | Remove identifying kernel strings | ✅ | ✅ | Expert |
| F4 | **Memory Encryption** | Encrypt sensitive data in RAM | ❌ | ❌ | Expert |

---

## Quick Recommendations by Use Case

### Basic Privacy (Home/User)
```
A1 (DoH) + A4 (ECN disable) + C1 (SSH hardening)
```

### Corporate Firewall Evasion
```
A1 (DoH) + B1 (Shadowsocks) + C3 (MAC random)
```

### Nation-State Censorship (China/Iran)
```
B2 (V2Ray) + B5 (WebSocket) + B6 (Domain fronting) + D2 (Tor)
```

### Maximum Paranoia
```
All of A + B2 + C + D2 + F3
```

---

## Implementation Status

| Category | Current | Possible | % Complete |
|----------|---------|----------|------------|
| Network Layer | 15 | 22 | 68% |
| Traffic Obfuscation | 2 | 6 | 33% |
| System Hardening | 8 | 15 | 53% |
| Advanced Routing | 0 | 5 | 0% |
| Protocol-level | 2 | 5 | 40% |
| Kernel-level | 0 | 4 | 0% |

**Overall: ~45% of possible features implemented**

---

## How to Choose

**Tell me the IDs you want, for example:**
- "Add A1, A3, and B1"
- "Add all of category A"
- "Add everything except F (kernel)"
- "Make it maximum paranoia - add everything possible"

**Or tell me your threat model:**
- "Just basic home privacy"
- "Corporate firewall at work"
- "Nation-state censorship"
- "I'm Edward Snowden"

And I'll recommend the right combination.
