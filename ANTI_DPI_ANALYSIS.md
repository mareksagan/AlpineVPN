# Anti-DPI Measures Analysis

## Executive Summary

This document analyzes potential anti-DPI (Deep Packet Inspection) measures for VPN implementations, organized by category and OS-specific capabilities.

---

## 1. General Anti-DPI Techniques (Protocol Agnostic)

### 1.1 Traffic Obfuscation

| Technique | Description | Effectiveness | Implementation Complexity |
|-----------|-------------|---------------|---------------------------|
| **Junk Packet Injection** | Insert random-sized padding packets between real data | High | Medium (requires protocol support like AmneziaWG) |
| **Packet Size Randomization** | Vary payload sizes to avoid signature detection | Medium | Low |
| **Timing Jitter** | Randomize inter-packet timing to avoid clock-skew detection | Medium | Medium |
| **Payload Obfuscation** | XOR or encrypt packet headers/metadata | High | High |

### 1.2 Port and Endpoint Camouflage

| Technique | Description | Risk/Reward |
|-----------|-------------|-------------|
| **Port 443 (HTTPS)** | Blend with HTTPS traffic | Low risk, basic obfuscation |
| **Port 53 (DNS)** | Appear as DNS queries | Medium risk, may trigger DNS inspection |
| **Port 80 (HTTP)** | Appear as web traffic | High risk, often inspected/shaped |
| **Random High Ports** | Unusual ports may avoid basic filters | Variable |

### 1.3 TLS/Handshake Camouflage

| Technique | Description |
|-----------|-------------|
| **SNI Spoofing** | Send fake Server Name Indication |
| **Certificate Forgery** | Mimic legitimate certificate patterns |
| **JA3 Fingerprint Randomization** | Vary TLS handshake parameters |

---

## 2. Linux-Specific Anti-DPI Measures

### 2.1 Sysctl/kernel Parameters

```bash
# Already implemented in scripts:
net.ipv4.tcp_timestamps = 0          # Disable TCP timestamp fingerprinting
net.ipv4.ip_default_ttl = 64         # Common TTL to blend in
net.ipv4.tcp_no_metrics_save = 1     # Don't save TCP metrics (prevents history-based detection)
net.ipv4.ip_local_port_range = 1024 65535  # Wide port range

# Additional options:
net.ipv4.tcp_tw_reuse = 1            # Reuse TIME_WAIT sockets (confuses connection tracking)
net.ipv4.tcp_rfc1337 = 1             # Drop RST packets for TIME_WAIT sockets
net.ipv4.tcp_window_scaling = 1      # Enable window scaling (normalized behavior)
net.ipv4.tcp_sack = 1                # Enable SACK (normalized behavior)
```

### 2.2 Iptables/Nftables Packet Mangling

```bash
# TTL manipulation (hide hop count)
iptables -t mangle -A POSTROUTING -o eth0 -j TTL --ttl-set 64

# TCP MSS clamping (normalize packet sizes)
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300

# Randomize source ports more aggressively
iptables -t nat -A POSTROUTING -p udp --dport 443 -j MASQUERADE --random

# Add jitter to packet timing (advanced)
iptables -t mangle -A POSTROUTING -m statistic --mode random --probability 0.01 -j DROP
```

### 2.3 Traffic Control (tc) Shaping

```bash
# Mimic HTTPS traffic patterns
tc qdisc add dev eth0 root cake \
    bandwidth 100mbit \
    diffserv4 \
    dual-srchost \
    nat \
    wash \
    ack-filter-aggressive \
    split-gso \
    rtt 100ms \
    noatm \
    overhead 44 mpu 84

# Add latency to confuse timing analysis
tc qdisc add dev eth0 root netem delay 10ms 2ms distribution normal
```

### 2.4 Advanced Kernel Modules

| Module | Purpose | Availability |
|--------|---------|--------------|
| `xt_TPROXY` | Transparent proxy (hide origin) | Most kernels |
| `xt_DELUDE` | Deflect TCP reset packets | Rare |
| `xt_pknock` | Port knocking | Common |
| `sch_obfuscate` | Traffic pattern obfuscation | Custom build |

---

## 3. FreeBSD-Specific Anti-DPI Measures

### 3.1 Sysctl Parameters

```bash
# Currently implemented:
net.inet.tcp.rfc1323=0          # Disable TCP timestamps
net.inet.ip.ttl=64              # Common TTL
net.inet.ip.portrange.randomized=1  # Randomize ports

# Additional options:
net.inet.tcp.blackhole=2        # Drop packets to closed ports silently
net.inet.udp.blackhole=1        # Drop UDP to closed ports silently
net.inet.tcp.drop_synfin=1      # Drop SYN+FIN packets (some DPI uses these)
net.inet.ip.check_interface=0   # Don't verify incoming interface
net.inet.ip.redirect=0          # Disable ICMP redirects
net.inet.icmp.drop_redirect=1   # Drop ICMP redirect attacks
```

### 3.2 PF (Packet Filter) Rules

```bash
# /etc/pf.conf additions for anti-DPI

# Normalize TTL
scrub in all fragment reassemble max-mss 1300
scrub out all random-id min-ttl 64

# Block fingerprinting scans
block in quick on $ext_if proto tcp flags FPU/FSRPAU
block in quick on $ext_if proto tcp flags /SFRAU

# Randomize outbound source ports (NAT)
nat on $ext_if from 10.7.0.0/24 to any -> ($ext_if) port 1024:65535 static-port

# TCP normalization (prevent OS fingerprinting)
match in on $ext_if proto tcp all scrub (reassemble tcp max-mss 1300)

# Block evil bit packets (joke, but some filters check)
block in quick on $ext_if from any to any ip options lsrr
block in quick on $ext_if from any to any ip options ssrr
```

### 3.3 Dummynet Traffic Shaping

```bash
# Add delay/jitter to confuse timing analysis
ipfw pipe 1 config bw 100Mbit/s delay 10ms
ipfw queue 1 config pipe 1 weight 100
ipfw add 1000 queue 1 ip from any to any out via em0

# Random packet loss to mimic congested networks (1%)
ipfw pipe 2 config bw 100Mbit/s plr 0.01
```

### 3.4 Kernel-Level Defenses

| Feature | Command | Purpose |
|---------|---------|---------|
| MAC Randomization | `ifconfig em0 link random` | Change MAC address |
| SYN Cache | `net.inet.tcp.syncookies=1` | Prevent SYN flood detection |
| Path MTU Blackhole Detection | `net.inet.tcp.path_mtu_discovery=0` | Disable PMTUD (prevents probing) |

---

## 4. Application-Level Measures

### 4.1 WireGuard-Specific

```bash
# Config options in wg0.conf:

# Randomized persistent keepalive (already implemented)
PersistentKeepalive = 25  # Randomized 20-30s

# MTU clamping to avoid fragmentation patterns
MTU = 1280  # Lower than standard 1420

# Use pre-shared keys (adds encryption layer)
PresharedKey = ...
```

### 4.2 AmneziaWG-Specific (Most Advanced)

```bash
# AmneziaWG obfuscation parameters (already implemented):
Jc = 42          # Junk packet count (3-128)
Jmin = 65        # Min junk size (20-100)
Jmax = 512       # Max junk size (50-1000)
S1 = 123         # Obfuscation param 1
S2 = 234         # Obfuscation param 2
H1 = 1234567890  # Header obfuscation 1
H2 = 9876543210  # Header obfuscation 2
H3 = 1111111111  # Header obfuscation 3
H4 = 2222222222  # Header obfuscation 4
```

### 4.3 Stunnel/Shadowsocks Wrappers

```bash
# Wrap WireGuard in TLS (looks like HTTPS)
stunnel /etc/stunnel/wg.conf

# Shadowsocks obfuscation
ss-server -c /etc/shadowsocks.json
```

---

## 5. Network Architecture Defenses

### 5.1 Multi-Hop Routing

```
Client -> Entry Node (Obfuscation Layer) -> Middle Node -> Exit Node -> Internet
         (Shadowsocks/Obfs4)              (WireGuard)    (Clean exit)
```

### 5.2 Domain Fronting

| Service | Method | Status |
|---------|--------|--------|
| Cloudflare | CDN fronting | Detected by most DPI |
| AWS API Gateway | Host header spoofing | Partially blocked |
| Azure Front Door | Custom domain | Still viable |

### 5.3 Decoy Traffic

```bash
# Generate fake HTTP traffic to mask VPN
curl -s https://example.com/fake > /dev/null &
wget -q -O - https://google.com > /dev/null &
```

---

## 6. Detection Evasion Techniques

### 6.1 Active Probing Countermeasures

| Attack | Defense |
|--------|---------|
| RST injection | `net.ipv4.tcp_rfc1337=1` (Linux) |
| SYN flood | SYN cookies, rate limiting |
| Timing analysis | Add jitter via tc/dummynet |
| Payload analysis | Encryption + obfuscation |

### 6.2 Statistical Analysis Evasion

```bash
# Mimic web browsing patterns:
# - Burst traffic (page loads)
# - Idle periods (reading)
# - Variable packet sizes

# Use tc to shape traffic like HTTP
tc qdisc add dev eth0 root tbf \
    rate 10mbit burst 32kbit latency 400ms
```

---

## 7. Recommendations by Threat Model

### 7.1 Basic Corporate Firewall
**Threat**: Port blocking, simple inspection
**Solution**: Port 443 + basic sysctl hardening

### 7.2 Nation-State DPI (China/Iran)
**Threat**: Protocol identification, active probing, traffic analysis
**Solution**: AmneziaWG + domain fronting + multi-hop + tc shaping

### 7.3 Corporate Deep Inspection
**Threat**: TLS interception, SNI filtering, fingerprinting
**Solution**: Stunnel wrapping + JA3 randomization + SNI spoofing

---

## 8. Currently Implemented vs Possible

| Feature | WireGuard Scripts | AmneziaWG | Possible Addition |
|---------|------------------|-----------|-------------------|
| Port 443 | ✅ | ✅ | - |
| TCP timestamps off | ✅ | ✅ | - |
| TTL normalization | ✅ | ✅ | - |
| Randomized keepalive | ✅ | ✅ | - |
| Junk packets | ❌ | ✅ | ❌ (requires protocol) |
| Header obfuscation | ❌ | ✅ | ❌ (requires protocol) |
| TC shaping | ✅ (CAKE) | ✅ (CAKE) | Advanced mimicking |
| TTL mangling | ❌ | ❌ | iptables/PF scrub |
| SYN normalization | ❌ | ❌ | sysctl/PF |
| Traffic padding | ❌ | ❌ | Additional wrapper |

---

## 9. Implementation Priority

### High Impact / Low Effort
1. ✅ Port 443 (done)
2. ✅ Anti-fingerprint sysctls (done)
3. ✅ Randomized keepalive (done)
4. 🔄 TTL mangling via iptables/PF

### High Impact / Medium Effort
5. 🔄 Traffic shaping with tc/dummynet
6. 🔄 TCP normalization in firewall
7. 🔄 MTU/MSS clamping

### High Impact / High Effort
8. ❌ Multi-hop architecture
9. ❌ Protocol-level obfuscation (AmneziaWG only)
10. ❌ Domain fronting integration

---

## 10. References

- [AmneziaWG Protocol](https://github.com/amnezia-vpn/amneziawg-go)
- [WireGuard Whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
- [GoodbyeDPI Techniques](https://github.com/ValdikSS/GoodbyeDPI)
- [Tor Pluggable Transports](https://2019.www.torproject.org/docs/pluggable-transports.html)
- [PT Spec](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/blob/main/doc/spec.md)

---

*Document Version: 1.0*
*Last Updated: 2026-02-17*
