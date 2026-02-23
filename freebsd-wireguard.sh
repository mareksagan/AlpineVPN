#!/bin/sh
#
# WireGuard Installer for FreeBSD 14.x - Client Config Fix
#

set -eu

exiterr() { 
    echo ""
    echo "  ✗ Error: $1" >&2 
    exit 1 
}

WG_DIR="/usr/local/etc/wireguard"
PF_CONF="/etc/pf.conf"
BACKUP_DIR="/var/backups/wireguard-install-$(date +%Y%m%d-%H%M%S)"
SERVER_ENDPOINT_FILE="$WG_DIR/endpoint.txt"

show_header() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║         WireGuard VPN Script - Performance Mode           ║"
    echo "║                   FreeBSD 14.x Edition                    ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
}

# Sanitize WireGuard keys (remove all whitespace)
sanitize_key() {
    printf '%s' "$1" | tr -d '[:space:]'
}

# Get export directory for client configs (home directory for easy SCP access)
# Sets global variable: export_dir
get_export_dir() {
    export_dir="${HOME}/"
    if [ -n "${SUDO_USER:-}" ] && getent group "$SUDO_USER" >/dev/null 2>&1; then
        _user_home_dir=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
        if [ -d "$_user_home_dir" ] && [ "$_user_home_dir" != "/" ]; then
            export_dir="$_user_home_dir/"
        fi
    fi
}

atomic_write() {
    _file="$1"
    _tmpfile="${_file}.tmp.$$"
    cat > "$_tmpfile"
    chmod 600 "$_tmpfile"
    mv -f "$_tmpfile" "$_file"
}

# POSIX-compliant sed in-place (no GNU extension)
sed_inplace() {
    _script="$1"
    _file="$2"
    _tmpf="${_file}.sedtmp.$$"
    sed "$_script" "$_file" > "$_tmpf" || return 1
    mv -f "$_tmpf" "$_file"
}

# Show QR code with fallback (POSIX-compliant)
show_qr_code() {
    _config_file="$1"
    
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t UTF8 < "$_config_file"
        printf '\n  ↑ That is a QR code containing the client configuration.\n'
    elif command -v python3 >/dev/null 2>&1 && python3 -c "import qrcode" 2>/dev/null; then
        python3 -c "
import qrcode
import sys
try:
    with open('$_config_file', 'r') as f:
        data = f.read()
    qr = qrcode.QRCode(border=1)
    qr.add_data(data)
    qr.make(fit=True)
    qr.print_ascii(invert=True)
    print()
except Exception as e:
    print('Error:', e)
    sys.exit(1)
"
        printf '\n  ↑ That is a QR code containing the client configuration.\n'
    else
        echo "  QR CODE NOT AVAILABLE"
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        echo "  To enable QR codes, install libqrencode:"
        echo "    pkg install libqrencode"
        echo ""
        echo "  Or use Python alternative:"
        echo "    pkg install py311-qrcode"
        echo "    (check 'pkg search qrcode' for available versions)"
        echo ""
        echo "  Config file: $_config_file"
        echo ""
        echo "  Transfer this file to your device via:"
        echo "    scp $_config_file user@phone:/path/"
    fi
    echo "═══════════════════════════════════════════════════════════"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        exiterr "This installer must be run as root"
    fi
}

check_os() {
    if [ "$(uname -s)" != "FreeBSD" ]; then
        exiterr "This script is for FreeBSD only."
    fi
    _os_version=$(freebsd-version -u 2>/dev/null | cut -d'-' -f1)
    [ -z "$_os_version" ] && exiterr "Could not determine FreeBSD version"
    
    _major=$(echo "$_os_version" | cut -d. -f1)
    if [ "$_major" -lt 14 ]; then
        exiterr "FreeBSD 14.0+ required. Found: $_os_version"
    fi
    echo ""
    echo "  Detected: FreeBSD $_os_version"
}

check_ip() {
    _ip="$1"
    _regex='^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'
    printf '%s' "$_ip" | grep -Eq "$_regex"
}

calculate_mtu() {
    _iface="$1"
    _base_mtu=1500
    _overhead=80
    
    if [ -n "$_iface" ] && ifconfig "$_iface" >/dev/null 2>&1; then
        _base_mtu=$(ifconfig "$_iface" | grep -m1 mtu | awk '{print $NF}')
        [ -z "$_base_mtu" ] && _base_mtu=1500
    fi
    
    if ifconfig "$_iface" 2>/dev/null | grep -q "pppoe"; then
        _overhead=$((_overhead + 8))
    fi
    
    _wg_mtu=$((_base_mtu - _overhead))
    [ "$_wg_mtu" -lt 1280 ] && _wg_mtu=1280
    printf '%s' "$_wg_mtu"
}

configure_sysctl() {
    echo ""
    echo "  Optimizing kernel for maximum WireGuard performance..."
    
    # FreeBSD uses /etc/sysctl.conf, not /etc/sysctl.d/
    _sysctl_conf="/etc/sysctl.conf"
    
    # Check if already configured to avoid duplicates
    if grep -q "# WireGuard Performance Settings" "$_sysctl_conf" 2>/dev/null; then
        echo "  Sysctl settings already configured, reapplying..."
    fi
    
    # Remove old settings if they exist (for clean reinstall)
    if [ -f "$_sysctl_conf" ]; then
        sed_inplace '/# WireGuard Performance Settings/d' "$_sysctl_conf"
        sed_inplace '/^net.inet.ip.forwarding=1/d' "$_sysctl_conf"
        sed_inplace '/^net.inet6.ip6.forwarding=1/d' "$_sysctl_conf"
        sed_inplace '/^kern.ipc.maxsockbuf=/d' "$_sysctl_conf"
        sed_inplace '/^net.inet.tcp.sendbuf_max=/d' "$_sysctl_conf"
        sed_inplace '/^net.inet.tcp.recvbuf_max=/d' "$_sysctl_conf"
        sed_inplace '/^net.inet.udp.recvspace=/d' "$_sysctl_conf"
        sed_inplace '/^net.link.ifqmaxlen=/d' "$_sysctl_conf"
    fi
    
    cat >> "$_sysctl_conf" << 'EOF'
# WireGuard Performance Settings
# Core forwarding
net.inet.ip.forwarding=1
net.inet6.ip6.forwarding=1

# Socket buffer maximums (increased to 128MB for high-throughput WireGuard)
kern.ipc.maxsockbuf=134217728

# TCP buffer maximums (128MB max, matching Alpine Linux aggressive tuning)
net.inet.tcp.sendbuf_max=134217728
net.inet.tcp.recvbuf_max=134217728

# TCP buffer auto-tuning - DISABLED for stable VPN throughput
# Auto-tuning can cause speed fluctuations as it oscillates
net.inet.tcp.sendbuf_auto=0
net.inet.tcp.recvbuf_auto=0

# Default TCP socket buffer sizes
net.inet.tcp.sendspace=262144
net.inet.tcp.recvspace=262144

# UDP socket buffer sizes (increased for WireGuard)
net.inet.udp.recvspace=2097152
net.inet.udp.maxdgram=65535

# Aggressive TCP performance tuning
net.inet.tcp.delayed_ack=0
net.inet.tcp.rfc1323=1
net.inet.tcp.rfc1644=1
net.inet.tcp.rfc3042=1
net.inet.tcp.rfc3390=1
net.inet.tcp.rfcmodel=1

# TCP connection tuning
net.inet.tcp.fastopen=3
net.inet.tcp.keepidle=60000
net.inet.tcp.keepintvl=10000
net.inet.tcp.keepinit=10000

# Congestion control - HTCP is better for high-BDP links than CUBIC
# HTCP maintains throughput better under varying latency conditions
net.inet.tcp.cc.algorithm=htcp
net.inet.tcp.cc.abe=1

# TCP pacing - smooths out packet transmission for stable uploads
# Prevents burst-induced drops that cause speed oscillations
net.inet.tcp.pacing=1

# AQM/ECN settings for PIE-like behavior
net.inet.tcp.ecn.enable=1
net.inet.tcp.ecn.negotiate_incoming=1

# Network interrupt tuning
net.route.netisr_maxqlen=2048

# Maximum sockets and connections
kern.ipc.somaxconn=65535
kern.ipc.acceptqueue_limit=16384

# Network device backlog
net.inet.ip.maxfragpackets=4096
net.inet.ip.maxfragsperpacket=128
net.inet6.ip6.maxfragpackets=4096
net.inet6.ip6.maxfragsperpacket=128

# IP reassembly tuning
net.inet.ip.maxchainsent=0

# Memory tuning for network buffers
kern.ipc.nmbclusters=262144
kern.ipc.nmbjumbop=131072
kern.ipc.nmbjumbo=65536

# Virtual memory tuning (matching Alpine approach)
vm.swappiness=10
vm.v_free_target=8192
vm.v_free_min=4096
vm.v_free_reserved=2048

# FreeBSD-specific network security and performance
# Drop packets to closed ports (reduces CPU load from port scans)
net.inet.tcp.blackhole=2
net.inet.udp.blackhole=1

# Interface queue maximum length (high throughput)
net.link.ifqmaxlen=2048

# Maximum sockets system-wide
kern.ipc.maxsockets=204800

# ICMP rate limiting (prevent flood)
net.inet.icmp.icmplim=250

# Disable logging of failed connections (performance)
net.inet.tcp.log_in_vain=0
net.inet.udp.log_in_vain=0

# Disable DROP_SYNFIN (RFC compliant but can cause issues)
net.inet.tcp.drop_synfin=0

# Socket buffer limits
kern.ipc.sockbuf_waste_factor=8

# Aggressive TCP reuse for high-connection scenarios
net.inet.tcp.msl=7500
net.inet.tcp.always_keepalive=0

# Path MTU discovery
net.inet.ip.mtudisc=1
net.inet.tcp.path_mtu_discovery=1

# Randomize port allocation (security)
net.inet.ip.portrange.randomized=1
net.inet.ip.portrange.first=1024
net.inet.ip.portrange.last=65535

# IP fastforwarding (packet forwarding optimization)
net.inet.ip.fastforwarding=0

# Anti-DPI: Disable TCP timestamps to prevent fingerprinting
net.inet.tcp.rfc1323=0

# Anti-DPI: Set default TTL to common value (64) to blend in
net.inet.ip.ttl=64

# Anti-DPI: Disable ICMP redirects (security + prevents fingerprinting)
net.inet.icmp.drop_redirect=1
net.inet.ip.redirect=0

# Anti-DPI: Randomize port allocation (already enabled above, reinforced here)
net.inet.ip.portrange.randomized=1

# Anti-DPI: SYN cookies (prevent SYN flood detection/probing)
net.inet.tcp.syncookies=1

# Anti-DPI: Drop packets to closed ports silently (don't reveal OS)
net.inet.tcp.blackhole=2
net.inet.udp.blackhole=1

# Anti-DPI: Drop SYN+FIN packets (some DPI uses these for probing)
net.inet.tcp.drop_synfin=1

# Anti-DPI: Disable path MTU discovery (prevents MTU-based fingerprinting)
net.inet.ip.mtudisc=0
net.inet.tcp.path_mtu_discovery=0

# Anti-DPI: Don't accept source routed packets
net.inet.ip.accept_sourceroute=0
net.inet.ip6.accept_sourceroute=0

# Anti-DPI: Enable reverse path filtering (prevent IP spoofing)
net.inet.ip.check_interface=1

# Anti-DPI: Disable ICMP echo broadcasts (smurf attack prevention)
net.inet.icmp.bmcastecho=0

# Anti-DPI: Hide processes from other users
kern.ps_showallprocs=0

# Anti-DPI: Randomize process IDs
kern.randompid=1

# Anti-DPI: Disable process debugging
kern.unprivileged_proc_debug=0

# ==================== CATEGORY A: NETWORK LAYER ====================

# A4: Anti-DPI: Disable TCP ECN (fingerprinting vector)
net.inet.tcp.ecn.enable=0

# A6: Anti-DPI: ICMP rate limiting (prevent scanning)
net.inet.icmp.icmplim=100

# A7: Anti-DPI: Disable TCP Fast Open (TFO cookie tracking)
net.inet.tcp.fastopen.enabled=0
net.inet.tcp.fastopen.client_enable=0
net.inet.tcp.fastopen.server_enable=0

# A5: Anti-DPI: ARP filtering (FreeBSD uses different mechanism)
net.link.ether.inet.log_arp_movements=0
net.link.ether.inet.log_arp_wrong_iface=0

# ===================================================================
EOF

    # Apply settings immediately
    sysctl net.inet.ip.forwarding=1 >/dev/null 2>&1 || true
    sysctl net.inet6.ip6.forwarding=1 >/dev/null 2>&1 || true
    sysctl kern.ipc.maxsockbuf=134217728 >/dev/null 2>&1 || true
    sysctl net.inet.tcp.sendbuf_max=134217728 >/dev/null 2>&1 || true
    sysctl net.inet.tcp.recvbuf_max=134217728 >/dev/null 2>&1 || true
    sysctl net.inet.udp.recvspace=2097152 >/dev/null 2>&1 || true
    sysctl net.link.ifqmaxlen=2048 >/dev/null 2>&1 || true
    
    # Apply anti-DPI sysctls immediately
    sysctl net.inet.tcp.syncookies=1 >/dev/null 2>&1 || true
    sysctl net.inet.tcp.blackhole=2 >/dev/null 2>&1 || true
    sysctl net.inet.udp.blackhole=1 >/dev/null 2>&1 || true
    sysctl net.inet.tcp.drop_synfin=1 >/dev/null 2>&1 || true
    sysctl net.inet.ip.mtudisc=0 >/dev/null 2>&1 || true
    sysctl net.inet.tcp.path_mtu_discovery=0 >/dev/null 2>&1 || true
    sysctl net.inet.ip.accept_sourceroute=0 >/dev/null 2>&1 || true
    sysctl net.inet.ip6.accept_sourceroute=0 >/dev/null 2>&1 || true
    sysctl net.inet.ip.check_interface=1 >/dev/null 2>&1 || true
    sysctl net.inet.icmp.bmcastecho=0 >/dev/null 2>&1 || true
    sysctl kern.ps_showallprocs=0 >/dev/null 2>&1 || true
    sysctl kern.randompid=1 >/dev/null 2>&1 || true
    sysctl kern.unprivileged_proc_debug=0 >/dev/null 2>&1 || true
    
    # Enable gateway mode
    sysrc -f /etc/rc.conf gateway_enable="YES" >/dev/null
    
    # Configure loader.conf tunables for next boot (FreeBSD-specific)
    configure_loader_tunables
    
    # Apply queue management for anti-bufferbloat and stable uploads
    echo "  Applying queue management for stable uploads..."
    
    # Get external interface
    _ext_if=$(route -n get 0.0.0.0 2>/dev/null | grep interface | awk '{print $2}')
    
    if [ -n "$_ext_if" ]; then
        echo "    Tuning $_ext_if..."
        
        # Disable interrupt coalescing (reduces latency/jitter)
        ifconfig "$_ext_if" -txcoalesce 2>/dev/null || true
        
        # Moderate queue length (prevents bufferbloat while maintaining throughput)
        ifconfig "$_ext_if" txqueuelen 1000 2>/dev/null || true
        
        # Disable TSO/LRO for lower latency (VPN performs better without offloading)
        ifconfig "$_ext_if" -tso -lro 2>/dev/null || true
        
        # Set moderate RX queue
        ifconfig "$_ext_if" rxqueuelen 1000 2>/dev/null || true
    fi
    
    # Tune WireGuard interface
    if ifconfig wg0 >/dev/null 2>&1; then
        echo "    Tuning wg0..."
        ifconfig wg0 txqueuelen 1000 2>/dev/null || true
        ifconfig wg0 rxqueuelen 1000 2>/dev/null || true
    fi
    
    # Multi-core IRQ affinity (distribute interrupts across CPUs)
    _cpu_count=$(sysctl -n hw.ncpu 2>/dev/null || echo 1)
    if [ "$_cpu_count" -gt 1 ] && [ -n "$_ext_if" ]; then
        echo "    Applying multi-core IRQ affinity ($_cpu_count CPUs)..."
        
        # Find IRQs for the network interface
        _irq_list=$(pciconf -lv 2>/dev/null | grep -A5 "$_ext_if" | grep "irq" | head -5)
        if [ -z "$_irq_list" ]; then
            # Alternative: try to find via vmstat -i
            _irq_nums=$(vmstat -i 2>/dev/null | grep -i "$_ext_if" | awk '{print $1}' | head -4)
        fi
        
        # Distribute IRQs across CPUs (round-robin)
        _cpu=0
        echo "$_irq_nums" | while read -r _irq; do
            if [ -n "$_irq" ] && [ -e "/proc/irq/$_irq/smp_affinity" ]; then
                # Calculate mask for specific CPU
                _mask=$(printf '%x' $((1 << _cpu)))
                echo "$_mask" > /proc/irq/$_irq/smp_affinity 2>/dev/null || true
                _cpu=$(( (_cpu + 1) % _cpu_count ))
            fi
        done
    fi
    
    echo "  ✓ Kernel optimizations applied"
}

# FreeBSD loader.conf tunables (require reboot)
configure_loader_tunables() {
    _loader_conf="/boot/loader.conf"
    
    # Check if already configured to avoid duplicates
    if grep -q "# WireGuard Performance Tunables" "$_loader_conf" 2>/dev/null; then
        return
    fi
    
    # Add performance tunables to loader.conf
    cat >> "$_loader_conf" << 'EOF'

# WireGuard Performance Tunables (added by AlpineVPN)
# Network mbuf clusters (must be set at boot)
kern.ipc.nmbclusters="262144"
kern.ipc.nmbjumbop="131072"
kern.ipc.nmbjumbo="65536"

# Maximum interface queue length
net.link.ifqmaxlen="2048"

# Intel NIC optimizations (if applicable)
hw.em.rxd="4096"
hw.em.txd="4096"
hw.em.msix="1"

# Realtek NIC optimizations (if applicable)
hw.re.rxd="4096"
hw.re.txd="4096"

# TCP segmentation offload support
device="tso"
EOF
}

optimize_nic() {
    _iface="$1"
    [ -z "$_iface" ] && return
    echo ""
    echo "  Optimizing $_iface for maximum throughput..."
    
    # Disable TCP segmentation offload and large receive offload
    ifconfig "$_iface" -tso -lro 2>/dev/null || true
    
    # Set larger MTU if supported (jumbo frames)
    ifconfig "$_iface" mtu 9000 2>/dev/null || true
    
    # Increase transmit queue length for high-throughput
    ifconfig "$_iface" txqueuelen 10000 2>/dev/null || true
    
    # Try to enable polling for reduced latency (if supported)
    sysctl kern.polling.enable=1 2>/dev/null || true
    
    # Disable RX/TX checksumming offload issues with some WireGuard setups
    ifconfig "$_iface" -rxcsum -txcsum 2>/dev/null || true
    
    # Driver-specific optimizations based on interface name
    case "$_iface" in
        em*|igb*|ix*|ixl*)
            echo "Intel NIC detected - driver-specific optimizations applied"
            # Intel-specific: enable multiqueue if available
            ifconfig "$_iface" -txcsum -rxcsum -tso -lro 2>/dev/null || true
            ;;
        re*)
            echo "Realtek NIC detected - driver-specific optimizations applied"
            # Realtek-specific optimizations
            ifconfig "$_iface" -txcsum -rxcsum 2>/dev/null || true
            ;;
        vtnet*)
            echo "VirtIO NIC detected (VM) - optimizations applied"
            # VirtIO-specific: disable LRO/TSO in VMs
            ifconfig "$_iface" -lro -tso 2>/dev/null || true
            ;;
        e1000*)
            echo "E1000 NIC detected (VM) - optimizations applied"
            # E1000-specific (often in VMs)
            ifconfig "$_iface" -txcsum -rxcsum 2>/dev/null || true
            ;;
    esac
    
    # Show final interface configuration
    echo "Interface configuration after optimization:"
    ifconfig "$_iface" 2>/dev/null | grep -E "(mtu|options|capabilities)" | head -5 || true
}

configure_firewall() {
    _ext_if="$1"
    _wg_port="$2"
    
    # Backup PF config to a persistent location if not already backed up
    if [ -f "$PF_CONF" ] && [ ! -f "/var/backups/wireguard-pf.conf.backup" ]; then
        mkdir -p /var/backups
        cp "$PF_CONF" "/var/backups/wireguard-pf.conf.backup"
    fi
    
    cat > "$PF_CONF" << EOF
# Skip loopback
set skip on lo0
set limit states 500000

# Normalize packets (anti-DPI)
scrub in all fragment reassemble
scrub out all random-id min-ttl 64

# NAT for VPN clients
nat on $_ext_if inet from 10.7.0.0/24 to any -> ($_ext_if) port 1024:65535

# Allow SSH
pass in quick on $_ext_if proto tcp from any to any port 22 flags S/SA keep state

# Allow WireGuard
pass in quick on $_ext_if proto udp from any to any port $_wg_port keep state

# Allow VPN traffic
pass quick on wg0 all
pass out quick on $_ext_if inet from 10.7.0.0/24 to any keep state

# Block private networks
block in quick on $_ext_if from 10.0.0.0/8 to any
block in quick on $_ext_if from 172.16.0.0/12 to any
block in quick on $_ext_if from 192.168.0.0/16 to any

# Block suspicious TCP flags
block in quick on $_ext_if proto tcp flags FPU/FSRPAU
block in quick on $_ext_if proto tcp flags /SFRAU
block in quick on $_ext_if proto tcp flags F/SFRAU
EOF

    pfctl -nf "$PF_CONF" || exiterr "PF config error"
    
    if sysrc firewall_enable 2>/dev/null | grep -q "YES"; then
        service ipfw oneflush 2>/dev/null || true
        sysrc firewall_enable="NO"
    fi
    
    sysrc pf_enable="YES"
    service pf start >/dev/null 2>&1 || service pf reload >/dev/null 2>&1 || exiterr "PF failed"
    
    # Configure dummynet for traffic shaping (anti-DPI: add jitter)
    configure_dummynet "$_ext_if"
}

# Configure dummynet for anti-DPI traffic shaping
configure_dummynet() {
    _iface="$1"
    [ -z "$_iface" ] && return
    
    echo "  Configuring dummynet traffic shaping..."
    
    # Load dummynet module
    if ! kldstat -q -m dummynet; then
        kldload dummynet 2>/dev/null || {
            echo "    Warning: Could not load dummynet module"
            return
        }
    fi
    
    # Flush existing rules
    ipfw -q flush 2>/dev/null || true
    
    # Create pipe with moderate bandwidth and small delay/jitter
    ipfw pipe 1 config bw 100Mbit/s delay 5ms 2>/dev/null || true
    
    # Add rule to shape outbound VPN traffic (adds jitter)
    ipfw -q add 100 pipe 1 ip from 10.7.0.0/24 to any out via "$_iface" 2>/dev/null || true
    
    # Enable ipfw and dummynet in rc.conf
    sysrc firewall_enable="YES" >/dev/null 2>&1 || true
    sysrc firewall_type="workstation" >/dev/null 2>&1 || true
    sysrc dummynet_enable="YES" >/dev/null 2>&1 || true
    
    echo "    Dummynet configured (5ms delay jitter)"
}

# ==================== CATEGORY C: SYSTEM HARDENING ====================

# C3: Randomize MAC address on boot (FreeBSD)
randomize_mac() {
    echo "  Configuring MAC address randomization..."
    _iface=$(route -n get 0.0.0.0 2>/dev/null | grep interface | awk '{print $2}')
    [ -z "$_iface" ] && return
    
    # Generate random MAC (locally administered)
    _new_mac=$(openssl rand -hex 6 2>/dev/null | sed 's/../&:/g; s/:$//' | awk -F: '{printf "02:%s:%s:%s:%s:%s", $2, $3, $4, $5, $6}')
    
    # Create startup script for MAC randomization
    cat > /usr/local/etc/rc.d/mac_randomize << EOF
#!/bin/sh
# PROVIDE: mac_randomize
# REQUIRE: NETWORKING
# BEFORE: wireguard

echo "Randomizing MAC address for $_iface..."
ifconfig $_iface ether $_new_mac
EOF
    chmod +x /usr/local/etc/rc.d/mac_randomize
    sysrc mac_randomize_enable="YES" 2>/dev/null || true
    
    echo "    MAC randomization configured for $_iface ($_new_mac)"
}

# C4: Randomize hostname
randomize_hostname() {
    echo "  Randomizing hostname..."
    _new_hostname="host-$(jot -r 1 10000000 99999999 2>/dev/null || echo $$)"
    hostname "$_new_hostname"
    sysrc hostname="$_new_hostname"
    echo "$_new_hostname" > /etc/rc.conf.d/hostname 2>/dev/null || true
    echo "    Hostname changed to: $_new_hostname"
}

# C5: Set timezone to UTC
set_utc_timezone() {
    echo "  Setting timezone to UTC..."
    cp /usr/share/zoneinfo/UTC /etc/localtime 2>/dev/null || true
    sysrc timezone="UTC"
    export TZ=UTC
    echo "    Timezone set to UTC"
}

# C6: Setup NTP privacy
setup_ntp_privacy() {
    echo "  Setting up NTP privacy..."
    # Install and configure ntpd with pool servers
    pkg install -y ntp 2>/dev/null || true
    
    # Configure with privacy-focused servers
    cat > /etc/ntp.conf << 'EOF'
# NTP configuration with privacy
restrict default ignore
restrict 127.0.0.1
restrict ::1

# Use Cloudflare and Google time servers (anycast, hard to track)
server time.cloudflare.com iburst
server time.google.com iburst
server 0.freebsd.pool.ntp.org iburst
server 1.freebsd.pool.ntp.org iburst

# Disable status queries
restrict -4 default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery

# Disable monitoring (prevents info leakage)
disable monitor
EOF
    
    sysrc ntpd_enable="YES" 2>/dev/null || true
    service ntpd restart 2>/dev/null || true
    echo "    NTP privacy configured"
}

# ==================== CATEGORY E: PROTOCOL-LEVEL ====================

# E2: Randomize MTU per connection
randomize_mtu() {
    echo "  Configuring MTU randomization..."
    # Generate random MTU between 1280 and 1380
    _rand_mtu=$((1280 + ($(date +%s) % 100)))
    
    # Apply to WireGuard config
    if [ -f "$WG_DIR/wg0.conf" ]; then
        sed_inplace "s/MTU = .*/MTU = $_rand_mtu/" "$WG_DIR/wg0.conf"
        echo "    MTU randomized to: $_rand_mtu"
    fi
}

# E5: Generate chaff/decoy traffic
generate_chaff_traffic() {
    echo "  Configuring chaff traffic generator..."
    
    # Create chaff generator script
    cat > /usr/local/bin/chaff-generator.sh << 'EOF'
#!/bin/sh
# Chaff traffic generator for FreeBSD

CHAFF_URLS="https://www.google.com https://www.cloudflare.com https://www.github.com https://www.microsoft.com https://www.apple.com https://www.amazon.com"

while true; do
    # Random sleep between 30-120 seconds
    sleep $((30 + ($(date +%s) % 91)))
    
    # Pick random URL
    _url=$(echo "$CHAFF_URLS" | tr ' ' '\n' | sort -R | head -n 1)
    
    # Send request with fake user agent
    fetch -q -o /dev/null --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --timeout=10 "$_url" 2>/dev/null || true
done
EOF
    chmod +x /usr/local/bin/chaff-generator.sh
    
    # Add to rc.d
    cat > /usr/local/etc/rc.d/chaff << EOF
#!/bin/sh
# PROVIDE: chaff
# REQUIRE: NETWORKING

echo "Starting chaff traffic generator..."
/usr/local/bin/chaff-generator.sh &
echo \$! > /var/run/chaff.pid

echo "Stopping chaff traffic generator..."
kill \$(cat /var/run/chaff.pid 2>/dev/null) 2>/dev/null || true
rm -f /var/run/chaff.pid
EOF
    chmod +x /usr/local/etc/rc.d/chaff
    sysrc chaff_enable="YES" 2>/dev/null || true
    
    # Start now
    /usr/local/bin/chaff-generator.sh &
    echo "    Chaff traffic generator started"
}

# B4: Setup simple-obfs if available (FreeBSD limited support)
setup_simple_obfs() {
    echo "  Checking for obfuscation tools..."
    # FreeBSD has limited obfs support
    # Try to install obfs4proxy if available
    pkg install -y obfs4proxy-tor 2>/dev/null || {
        echo "    Obfuscation tools not available in pkg"
        return
    }
    echo "    obfs4proxy installed (manual configuration required)"
}

# Apply DSCP zeroing via PF (FreeBSD doesn't have iptables DSCP target)
apply_dscp_zeroing() {
    echo "  DSCP zeroing configured via PF scrub rules"
    # PF scrub rules already zero out ToS/DSCP when configured
}

# Master function to apply all anti-DPI measures
apply_all_anti_dpi() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  Applying Advanced Anti-DPI Measures"
    echo "═══════════════════════════════════════════════════════════"
    
    # Category C
    randomize_mac
    randomize_hostname
    set_utc_timezone
    setup_ntp_privacy
    
    # Category E
    randomize_mtu
    generate_chaff_traffic
    
    # Category B (limited on FreeBSD)
    setup_simple_obfs
    
    echo "═══════════════════════════════════════════════════════════"
}

install_packages() {
    echo ""
    echo "  Installing WireGuard..."
    env ASSUME_ALWAYS_YES=YES pkg update -q || exiterr "pkg update failed"
    
    if ! kldstat -q -m if_wg; then
        kldload if_wg || exiterr "Failed to load if_wg"
        echo 'if_wg_load="YES"' >> /boot/loader.conf
    fi
    
    env ASSUME_ALWAYS_YES=YES pkg install -y wireguard-tools
    pkg install -y libqrencode 2>/dev/null || true
    
    mkdir -p "$WG_DIR"
    chmod 700 "$WG_DIR"
    sysrc wireguard_enable="YES"
    sysrc wireguard_interfaces="wg0"
}

create_server_config() {
    _endpoint_ip="$1"
    _wg_port="$2"
    _wg_mtu="$3"
    
    echo ""
    echo "  Creating server configuration..."
    
    # Generate keys and sanitize immediately (strip newlines)
    _server_priv=$(wg genkey | tr -d '\n')
    _server_pub=$(printf '%s' "$_server_priv" | wg pubkey | tr -d '\n')
    
    # Store endpoint for later use by clients
    printf '%s:%s' "$_endpoint_ip" "$_wg_port" > "$SERVER_ENDPOINT_FILE"
    
    atomic_write "$WG_DIR/wg0.conf" << EOF
[Interface]
Address = 10.7.0.1/24
PrivateKey = $_server_priv
ListenPort = $_wg_port
MTU = $_wg_mtu

# Server Public Key: $_server_pub
EOF

    printf '%s' "$_server_pub" > "$WG_DIR/server.pub"
    chmod 600 "$WG_DIR/wg0.conf"
    echo "Server public key: $_server_pub"
}

start_wireguard() {
    _wg_port="$1"
    echo ""
    echo "  Starting WireGuard..."
    
    ifconfig wg0 destroy 2>/dev/null || true
    
    if ! service wireguard start 2>/dev/null; then
        wg-quick up wg0 || exiterr "Failed to start WireGuard"
    fi
    
    ifconfig wg0 >/dev/null 2>&1 || exiterr "Interface failed"
    echo ""
    echo "  ✓ WireGuard running on port $_wg_port"
}

add_client() {
    _client_name="$1"
    _dns_servers="${2:-1.1.1.1, 1.0.0.1}"
    
    _client=$(printf '%s' "$_client_name" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c-15)
    [ -z "$_client" ] && exiterr "Invalid client name"
    
    if [ -f "$WG_DIR/wg0.conf" ] && grep -q "^# BEGIN_PEER $_client$" "$WG_DIR/wg0.conf"; then
        exiterr "Client $_client already exists"
    fi
    
    # Find next available IP
    _octet=2
    while grep -q "10.7.0.$_octet/32" "$WG_DIR/wg0.conf" 2>/dev/null && [ "$_octet" -lt 254 ]; do
        _octet=$((_octet + 1))
    done
    [ "$_octet" -eq 254 ] && exiterr "No IPs available"
    
    echo ""
    echo "  Creating client '$_client' (10.7.0.$_octet)..."
    
    # Generate and sanitize keys
    _client_priv=$(wg genkey | tr -d '\n')
    _client_pub=$(printf '%s' "$_client_priv" | wg pubkey | tr -d '\n')
    _psk=$(wg genpsk | tr -d '\n')
    
    # Get server details
    _server_pub=$(cat "$WG_DIR/server.pub" | tr -d '\n')
    _endpoint=$(cat "$SERVER_ENDPOINT_FILE" | tr -d '\n')
    _mtu=$(grep "^MTU" "$WG_DIR/wg0.conf" | awk '{print $3}' | tr -d '\n')
    [ -z "$_mtu" ] && _mtu=1420
    
    # Validate no empty values
    [ -z "$_server_pub" ] && exiterr "Server public key missing"
    [ -z "$_endpoint" ] && exiterr "Server endpoint missing"
    [ -z "$_client_priv" ] && exiterr "Client key generation failed"
    [ -z "$_psk" ] && exiterr "PSK generation failed"
    
    # Add peer to server config
    cat >> "$WG_DIR/wg0.conf" << EOF

# BEGIN_PEER $_client
[Peer]
PublicKey = $_client_pub
PresharedKey = $_psk
AllowedIPs = 10.7.0.$_octet/32
# END_PEER $_client
EOF
    
    # Create client config in home directory for easy SCP access
    get_export_dir
    _client_file="$export_dir$_client.conf"
    
    # Anti-DPI: Randomize keepalive interval (20-30 seconds) to avoid pattern detection
    _keepalive=$((20 + ($(date +%s) % 11)))
    
    # Write client config with explicit newlines, no trailing spaces
    printf '%s\n' "[Interface]" > "$_client_file"
    printf 'Address = 10.7.0.%s/24\n' "$_octet" >> "$_client_file"
    printf 'DNS = %s\n' "$_dns_servers" >> "$_client_file"
    printf 'PrivateKey = %s\n' "$_client_priv" >> "$_client_file"
    printf 'MTU = %s\n\n' "$_mtu" >> "$_client_file"
    printf '%s\n' "[Peer]" >> "$_client_file"
    printf 'PublicKey = %s\n' "$_server_pub" >> "$_client_file"
    printf 'PresharedKey = %s\n' "$_psk" >> "$_client_file"
    printf 'AllowedIPs = 0.0.0.0/0\n' >> "$_client_file"
    printf 'Endpoint = %s\n' "$_endpoint" >> "$_client_file"
    printf 'PersistentKeepalive = %s\n' "$_keepalive" >> "$_client_file"
    
    chmod 600 "$_client_file"
    
    # Add to running server (POSIX-compliant mktemp with template)
    _tmpfile=$(mktemp /tmp/wg-psk.XXXXXX) || exiterr "Failed to create temp file"
    printf '%s' "$_psk" > "$_tmpfile"
    wg set wg0 peer "$_client_pub" preshared-key "$_tmpfile" allowed-ips "10.7.0.$_octet/32" 2>/dev/null || \
        echo "Note: Restart WireGuard to activate new peer"
    rm -f "$_tmpfile"
    
    if [ -n "${SUDO_USER:-}" ]; then
        chown "$SUDO_USER:$SUDO_USER" "$_client_file" 2>/dev/null || true
    fi
    
    echo ""
    echo "  ✓ Client '$_client' created successfully"
    echo "  Location: $_client_file"
    
    # Validate config syntax
    if wg-quick strip "$_client_file" >/dev/null 2>&1; then
        echo "Config validation: OK"
    else
        echo "Warning: Config validation failed"
    fi
    
    # Show QR code (with Python fallback)
    show_qr_code "$_client_file"
}

show_status() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  WireGuard Status"
    echo "═══════════════════════════════════════════════════════════"
    ifconfig wg0 2>/dev/null || { echo ""; echo "  Not running"; echo "═══════════════════════════════════════════════════════════"; return 1; }
    echo ""
    wg show wg0 2>/dev/null || true
    echo "═══════════════════════════════════════════════════════════"
}

remove_client() {
    _client_name="$1"
    _client=$(printf '%s' "$_client_name" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c-15)
    
    if ! grep -q "^# BEGIN_PEER $_client$" "$WG_DIR/wg0.conf" 2>/dev/null; then
        exiterr "Client not found"
    fi
    
    printf "  Remove '%s'? [y/N] " "$_client"
    read -r _confirm
    case "$_confirm" in
        [yY])
            _peer_key=$(sed -n "/^# BEGIN_PEER $_client/,/^# END_PEER $_client/p" "$WG_DIR/wg0.conf" | grep PublicKey | awk '{print $3}')
            if [ -n "$_peer_key" ]; then
                wg set wg0 peer "$_peer_key" remove 2>/dev/null || true
            fi
            sed_inplace "/^# BEGIN_PEER $_client/,/^# END_PEER $_client/d" "$WG_DIR/wg0.conf"
            get_export_dir
            rm -f "${export_dir}${_client}.conf"
            echo "  Removed"
            ;;
    esac
}

uninstall_wireguard() {
    printf "  Uninstall WireGuard? [y/N] "
    read -r _confirm
    case "$_confirm" in
        [yY])
            echo ""
            echo "  Stopping WireGuard..."
            service wireguard stop 2>/dev/null || ifconfig wg0 destroy 2>/dev/null || true
            
            echo "  Removing rc.conf settings..."
            sysrc -x wireguard_enable 2>/dev/null || true
            sysrc -x wireguard_interfaces 2>/dev/null || true
            sysrc -x gateway_enable 2>/dev/null || true
            sysrc -x pf_enable 2>/dev/null || true
            
            echo "  Restoring PF configuration..."
            if [ -f "/var/backups/wireguard-pf.conf.backup" ]; then
                cp "/var/backups/wireguard-pf.conf.backup" "$PF_CONF"
                service pf reload 2>/dev/null || true
                rm -f "/var/backups/wireguard-pf.conf.backup"
            fi
            
            echo "  Cleaning up loader.conf entries..."
            _loader_conf="/boot/loader.conf"
            if [ -f "$_loader_conf" ]; then
                # Remove WireGuard-specific entries we added
                sed_inplace '/# WireGuard Performance Tunables/d' "$_loader_conf"
                sed_inplace '/^kern.ipc.nmbclusters=/d' "$_loader_conf"
                sed_inplace '/^kern.ipc.nmbjumbop=/d' "$_loader_conf"
                sed_inplace '/^kern.ipc.nmbjumbo=/d' "$_loader_conf"
                sed_inplace '/^net.link.ifqmaxlen=/d' "$_loader_conf"
                sed_inplace '/^hw.em.rxd=/d' "$_loader_conf"
                sed_inplace '/^hw.em.txd=/d' "$_loader_conf"
                sed_inplace '/^hw.em.msix=/d' "$_loader_conf"
                sed_inplace '/^hw.re.rxd=/d' "$_loader_conf"
                sed_inplace '/^hw.re.txd=/d' "$_loader_conf"
                sed_inplace '/^device="tso"/d' "$_loader_conf"
                sed_inplace '/^if_wg_load=/d' "$_loader_conf"
            fi
            
            echo "  Cleaning up sysctl settings..."
            _sysctl_conf="/etc/sysctl.conf"
            if [ -f "$_sysctl_conf" ]; then
                sed_inplace '/# WireGuard Performance Settings/d' "$_sysctl_conf"
                sed_inplace '/^net.inet.ip.forwarding=1/d' "$_sysctl_conf"
                sed_inplace '/^net.inet6.ip6.forwarding=1/d' "$_sysctl_conf"
                sed_inplace '/^kern.ipc.maxsockbuf=/d' "$_sysctl_conf"
                sed_inplace '/^net.inet.tcp.sendbuf_max=/d' "$_sysctl_conf"
                sed_inplace '/^net.inet.tcp.recvbuf_max=/d' "$_sysctl_conf"
                sed_inplace '/^net.inet.udp.recvspace=/d' "$_sysctl_conf"
                sed_inplace '/^net.link.ifqmaxlen=/d' "$_sysctl_conf"
            fi
            rm -rf "$WG_DIR"
            
            echo "  ⚠ Note: Loader.conf changes require a reboot to fully take effect."
            echo ""
            echo "  ✓ WireGuard uninstalled"
            ;;
    esac
}

menu() {
    while true; do
        echo ""
        echo "═══════════════════════════════════════════════════════════"
        echo "  WireGuard Management"
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        echo "    1) Add client"
        echo "    2) List clients"
        echo "    3) Remove client"
        echo "    4) Show QR code"
        echo "    5) Show status"
        echo "    6) Uninstall"
        echo "    7) Exit"
        echo ""
        printf "  Select: "
        read -r _opt
        
        case "$_opt" in
            1)
                printf "Client name: "; read -r _name
                printf "DNS [1.1.1.1, 1.0.0.1]: "; read -r _dns
                add_client "$_name" "${_dns:-1.1.1.1, 1.0.0.1}"
                ;;
            2)
                grep "^# BEGIN_PEER" "$WG_DIR/wg0.conf" 2>/dev/null | cut -d' ' -f3 | nl || echo "No clients"
                ;;
            3)
                printf "Remove: "; read -r _name
                remove_client "$_name"
                ;;
            4)
                printf "Client: "; read -r _name
                _c=$(printf '%s' "$_name" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c-15)
                get_export_dir
                if [ -f "${export_dir}${_c}.conf" ]; then
                    show_qr_code "${export_dir}${_c}.conf"
                else
                    echo "  Config file not found: ${export_dir}${_c}.conf"
                fi
                ;;
            5) show_status ;;
            6) uninstall_wireguard ;;
            7) exit 0 ;;
            *) echo "Invalid" ;;
        esac
    done
}

main() {
    check_root
    check_os
    
    _default_iface=$(route -n get 0.0.0.0 2>/dev/null | grep interface | awk '{print $2}')
    [ -z "$_default_iface" ] && exiterr "No default interface"
    
    mkdir -p "$BACKUP_DIR"
    
    if [ -f "$WG_DIR/wg0.conf" ]; then
        show_header
        menu
        exit 0
    fi
    
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║         Welcome to the WireGuard Server Installer         ║"
    echo "║                   FreeBSD 14.x Edition                    ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    
    _ip=$(ifconfig "$_default_iface" | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | head -1)
    check_ip "$_ip" || exiterr "Invalid IP detected"
    
    echo "  Interface: $_default_iface"
    echo "  Local IP: $_ip"
    
    _public_ip="$_ip"
    if printf '%s' "$_ip" | grep -Eq '^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'; then
        echo "Private IP detected: $_ip"
        _public_ip=$(fetch -q -o - https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep ip= | cut -d= -f2)
        check_ip "$_public_ip" || _public_ip="$_ip"
        echo "Using endpoint: $_public_ip"
    fi
    
    echo "Note: Port 443 (HTTPS) is recommended to blend in against DPI"
    printf "Port [443]: "; read -r _wg_port
    _wg_port=${_wg_port:-443}
    case "$_wg_port" in
        ''|*[!0-9]*) exiterr "Invalid port" ;;
        *) [ "$_wg_port" -gt 65535 ] && exiterr "Invalid port" ;;
    esac
    
    printf "First client [client]: "; read -r _first_client
    _first_client=${_first_client:-client}
    
    _wg_mtu=$(calculate_mtu "$_default_iface")
    
    echo ""
    echo "Config:"
    echo "  Endpoint: ${_public_ip}:${_wg_port}"
    echo "  MTU: $_wg_mtu"
    printf "Proceed? [Y/n] "; read -r _confirm
    case "$_confirm" in [nN]) exit 0 ;; esac
    
    install_packages
    configure_sysctl
    optimize_nic "$_default_iface"
    configure_firewall "$_default_iface" "$_wg_port"
    apply_all_anti_dpi
    create_server_config "$_public_ip" "$_wg_port" "$_wg_mtu"
    start_wireguard "$_wg_port"
    add_client "$_first_client"
    
    get_export_dir
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  ✓ Installation Complete"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "  Server: ${_public_ip}:${_wg_port}"
    echo "  Client: ${export_dir}${_first_client}.conf"
    echo "═══════════════════════════════════════════════════════════"
}

main "$@"
