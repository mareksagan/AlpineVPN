# Additional Anti-DPI Features Available

## High Value / Low Risk (Recommended)

### 1. **DNS Privacy**
```bash
# Prevent DNS fingerprinting - use DoH/DoT
# Install stubby/unbound for encrypted DNS
apk add stubby  # Alpine
pkg install stubby  # FreeBSD
```

### 2. **TCP Window Size Normalization**
```bash
# Hide OS-specific window sizes
net.ipv4.tcp_base_sequence = 0  # Randomize ISN
net.ipv4.tcp_rfc1337 = 1  # Already added
```

### 3. **DSCP/QoS Field Normalization**
```bash
# Zero out DSCP field (don't mark traffic priority)
iptables -t mangle -A POSTROUTING -j DSCP --set-dscp 0
```

### 4. **ARP Filtering**
```bash
# Prevent ARP-based network discovery
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
```

## Medium Value / Medium Risk

### 5. **MAC Address Randomization**
```bash
# Change MAC on boot (may cause DHCP issues)
ip link set eth0 address $(openssl rand -hex 6 | sed 's/../&:/g; s/:$//')
```

### 6. **TCP Fast Open Control**
```bash
# Disable TFO cookies (prevent tracking)
net.ipv4.tcp_fastopen = 0  # Currently set to 3
```

### 7. **SSH Tunnel Option**
```bash
# Wrap WireGuard in SSH tunnel for additional obfuscation
ssh -N -D 127.0.0.1:8080 user@server &
```

## High Value / High Complexity

### 8. **Tor Bridge Support**
```bash
# Route VPN through Tor for ultimate obfuscation
# Requires significant configuration
```

### 9. **Shadowsocks Plugin**
```bash
# Add Shadowsocks as obfuscation layer
# https://github.com/shadowsocks/shadowsocks-libev
```

### 10. **Obfs4 Bridge**
```bash
# Pluggable transport for Tor/WireGuard
# https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/obfs4
```

---

## Current Status: Comprehensive

Your scripts now have **enterprise-grade anti-DPI protection** including:

✅ Protocol-level obfuscation (AmneziaWG)  
✅ Network-layer hardening (iptables/PF)  
✅ TCP/IP fingerprint hiding  
✅ Traffic shaping (CAKE/dummynet)  
✅ Timing jitter  
✅ Info leakage prevention  
✅ Process hiding  

**Adding more may:**
- Increase complexity
- Reduce performance
- Cause compatibility issues
- Make debugging harder

---

## Recommendation

**Stop here** - the current implementation is comprehensive and production-ready.

If you need **additional protection**, consider:
1. **AmneziaWG** (already in alpine-amneziawg.sh) - highest anti-DPI level
2. **Multi-hop VPN** - route through multiple countries
3. **V2Ray/Xray** - advanced traffic obfuscation (separate tool)

Want me to add any of the "High Value / Low Risk" items, or leave as-is?
