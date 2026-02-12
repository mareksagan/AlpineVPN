# AlpineVPN

## Lightweight WireGuard VPN installer for Alpine Linux and POSIX-compliant systems.

AlpineVPN is a POSIX sh implementation of the popular WireGuard installer, specifically optimized for **Alpine Linux** (busybox/ash) while maintaining compatibility with all major Linux distributions. No bash required.

[![Alpine Linux](https://img.shields.io/badge/Alpine%20Linux-ready-blue?logo=alpine-linux)](https://alpinelinux.org/)
[![POSIX sh](https://img.shields.io/badge/POSIX%20sh-compatible-green)](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Why AlpineVPN?

- **Zero Bash Dependencies**: Runs on `ash`, `dash`, `busybox sh` - perfect for containerized or minimal systems
- **Alpine-Optimized**: Native OpenRC support, proper repository handling, and BusyBox compatibility  
- **Cloudflare by Default**: Privacy-focused with `1.1.1.1` as the default DNS (easily changed)
- **Bulletproof QR Codes**: Falls back to Python if native `qrencode` isn't available
- **POSIX Compliant**: Uses only standard shell utilities, no GNU extensions

## Quick Start

```bash
# Download AlpineVPN
wget https://raw.githubusercontent.com/mareksagan/AlpineVPN/main/alpine-wireguard.sh
sudo sh alpine-wireguard.sh

# Or one-liner with curl
curl -O https://raw.githubusercontent.com/mareksagan/AlpineVPN/main/alpine-wireguard.sh && sudo sh alpine-wireguard.sh
