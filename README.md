# AlpineVPN

**High-Performance WireGuard VPN installer for Alpine Linux and FreeBSD with Anti-DPI Hardening.**

AlpineVPN is a POSIX sh implementation of the popular WireGuard installer, aggressively optimized for **Alpine Linux** (busybox/ash) and **FreeBSD**. Features advanced kernel tuning, multi-core network processing, and anti-DPI hardening. No bash required.

[![Alpine Linux](https://img.shields.io/badge/Alpine%20Linux-ready-blue?logo=alpine-linux)](https://alpinelinux.org/)
[![FreeBSD](https://img.shields.io/badge/FreeBSD-supported-red?logo=freebsd)](https://www.freebsd.org/)
[![POSIX sh](https://img.shields.io/badge/POSIX%20sh-compatible-green)](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Why AlpineVPN?

### Performance Optimizations
- **Alpine Linux**: TCP BBR congestion control, 128MB socket buffers, RPS/XPS multi-core packet processing, NIC ring buffer tuning
- **FreeBSD**: CUBIC congestion control, 128MB maxsockbuf, mbuf cluster tuning, driver-specific NIC optimizations (Intel/Realtek), PF state table (500K states)
- **Both**: Automatic MTU calculation, jumbo frames support, aggressive TCP/UDP buffer tuning, CPU governor performance mode

### Anti-DPI Hardening
- **Port 443 by default** (HTTPS) - blends in with normal web traffic
- **Randomized keepalive intervals** (20-30 seconds) - prevents pattern detection
- **Disabled TCP timestamps** - prevents OS fingerprinting
- **Standardized TTL (64)** - masks hop count fingerprinting
- **Disabled TCP metrics cache** - prevents history-based fingerprinting
- **Aggressive source port randomization** - harder to track flows

### POSIX Compliance
- Zero bash dependencies - runs on `ash`, `dash`, `busybox sh`
- No GNU extensions - uses POSIX-compliant `sed`, `mktemp`, etc.
- Python QR code fallback when native `qrencode` unavailable

## Performance

Real-world speed testing on minimal hardware (1 vCPU, 1GB RAM):

| Platform | Throughput | Notes |
|----------|-----------|-------|
| **FreeBSD 14.x** | **~240 Mbps** | CUBIC + mbuf tuning + PF optimization |
| **Alpine Linux** | **~170 Mbps** | TCP BBR + RPS/XPS + aggressive buffers |

*Test conditions: Cloud VPS (1 vCPU/1GB RAM), WireGuard mobile client, iperf3 over 100ms latency link*

> **Note**: FreeBSD's CUBIC congestion control and mbuf subsystem optimizations now outperform Alpine Linux on equivalent hardware. Alpine remains excellent for containerized deployments.

## Quick Start

### Alpine Linux
```bash
wget https://raw.githubusercontent.com/mareksagan/AlpineVPN/main/alpine-wireguard.sh
sudo sh alpine-wireguard.sh
```

### FreeBSD
```bash
wget https://raw.githubusercontent.com/mareksagan/AlpineVPN/main/freebsd-wireguard.sh
sudo sh freebsd-wireguard.sh
```

### One-liner (Alpine)
```bash
curl -O https://raw.githubusercontent.com/mareksagan/AlpineVPN/main/alpine-wireguard.sh && sudo sh alpine-wireguard.sh
```

## OS-Specific Features

### Alpine Linux
- **Init System**: OpenRC with parallel service startup (`rc_parallel=YES`)
- **Firewall**: iptables with custom init.d service
- **Multi-Core**: RPS/XPS (Receive/Transmit Packet Steering) across all CPUs
- **Memory**: Transparent hugepages, musl libc optimizations (`vm.max_map_count`)
- **Network**: TCP BBR (if kernel ≥4.20), 128MB socket buffers
- **Hardware**: ethtool ring buffer tuning (RX/TX 4096)

### FreeBSD
- **Init System**: Native rc.d with `sysrc` configuration
- **Firewall**: PF (Packet Filter) with MSS clamping (1420), 500K state limit
- **Multi-Core**: netisr queue tuning, device polling support
- **Memory**: mbuf cluster tuning (262K clusters), jumbo frame buffers
- **Network**: CUBIC congestion control, 128MB maxsockbuf
- **Hardware**: Driver-specific optimizations (Intel em/igb/ix/ixl, Realtek re, VirtIO, E1000)
- **Boot**: loader.conf tunables for persistent optimization

## Anti-DPI Features

Both scripts implement multiple layers of DPI resistance:

1. **Port Camouflage**
   - Default port 443 (HTTPS) - most firewalls allow this
   - Suggests ports 53 (DNS) or 8080 (HTTP-alt) as alternatives

2. **Traffic Pattern Obfuscation**
   - Randomized PersistentKeepalive (20-30s per client)
   - Disables TCP timestamps (`tcp_timestamps=0` / `tcp.rfc1323=0`)
   - Standardized TTL=64 (masks router hop count)

3. **Fingerprint Randomization**
   - Disables TCP metrics cache (`tcp_no_metrics_save=1`)
   - Aggressive source port randomization (1024-65535)
   - Disables ICMP redirects

## Command Line Options

```
--addclient [name]      Add a new client
--listclients           List existing clients
--removeclient [name]   Remove a client
--showclientqr [name]   Show QR code for client
--uninstall             Remove WireGuard completely
--auto                  Auto-install with defaults
--serveraddr [host]     Set server endpoint address
--port [number]         Set port (default: 443)
--clientname [name]     Set first client name
--dns1 [IP]             Primary DNS server
--dns2 [IP]             Secondary DNS server
-y, --yes               Auto-confirm prompts
-h, --help              Show help
```

## Technical Details

### Kernel Tunables Applied

**Alpine Linux (`/etc/sysctl.d/99-wireguard-optimize.conf`):**
```
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_timestamps = 0        # Anti-DPI
net.ipv4.ip_default_ttl = 64       # Anti-DPI
vm.max_map_count = 262144          # musl libc
```

**FreeBSD (`/etc/sysctl.d/99-wireguard.conf`):**
```
kern.ipc.maxsockbuf=134217728
net.inet.tcp.cc.algorithm=cubic
net.inet.tcp.rfc1323=0             # Anti-DPI (no timestamps)
net.inet.ip.ttl=64                 # Anti-DPI
net.inet.udp.recvspace=2097152
kern.ipc.nmbclusters=262144
```

### Loader Tunables (FreeBSD only)
```
hw.em.rxd="4096"
hw.em.txd="4096"
hw.em.msix="1"
kern.ipc.nmbclusters="262144"
```

## Compatibility

| OS | Version | Status | Notes |
|----|---------|--------|-------|
| Alpine Linux | 3.15+ | ✅ Supported | Primary target platform |
| FreeBSD | 14.0+ | ✅ Supported | Maximum performance |
| Ubuntu | 20.04+ | ✅ Supported | Uses systemd |
| Debian | 11+ | ✅ Supported | Uses systemd |
| Rocky/Alma/CentOS | 8+ | ✅ Supported | Uses systemd |
| Fedora | 35+ | ✅ Supported | Uses systemd |
| openSUSE | 15+ | ✅ Supported | Uses systemd |

## Security Considerations

- **ptrace_scope**: Disabled for non-parent (Alpine)
- **ICMP redirects**: Disabled (FreeBSD)
- **Port randomization**: Enabled on both platforms
- **Preshared keys**: Generated per client (PSK)
- **File permissions**: 600 on all config files
- **Firewall**: Blocks RFC1918 spoofing attempts

## Troubleshooting

**"Cannot parse IP address" error:**
- Fixed in latest version - IPv6 format corrected to `0.0.0.0/0, ::/0`

**QR code not displaying:**
- Alpine: `apk add qrencode` or `apk add py3-qrcode`
- FreeBSD: `pkg install libqrencode` or `pkg install py311-qrcode`

**Low throughput:**
- Verify BBR (Alpine) or CUBIC (FreeBSD) is loaded
- Check CPU governor is set to "performance"
- Verify NIC ring buffers are increased

**Connection blocked by DPI:**
- Ensure port 443 is used (default)
- Check `tcp_timestamps=0` is applied
- Verify keepalive is randomized

## Credits

Based on the wireguard-install script by hwdsl2 and Nyr, with extensive modifications for:
- POSIX sh compliance
- Alpine Linux optimizations
- FreeBSD support
- Anti-DPI hardening
- Performance tuning

## License

MIT License - See [LICENSE](LICENSE) for details.
