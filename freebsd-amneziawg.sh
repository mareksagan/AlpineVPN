#!/bin/sh
#
# AmneziaWG Installer for FreeBSD 14.x
# Based on WireGuard Installer with DPI evasion and performance optimizations
#

set -eu

exiterr() { 
    echo "Error: $1" >&2 
    exit 1 
}

AWG_DIR="/usr/local/etc/amneziawg"
PF_CONF="/etc/pf.conf"
BACKUP_DIR="/var/backups/amneziawg-install-$(date +%Y%m%d-%H%M%S)"
SERVER_ENDPOINT_FILE="$AWG_DIR/endpoint.txt"

# Sanitize keys (remove all whitespace)
sanitize_key() {
    printf '%s' "$1" | tr -d '[:space:]'
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

# Helper function to find awg binary
get_awg_bin() {
    if hash awg 2>/dev/null; then
        echo "awg"
    elif [ -x /usr/local/bin/awg ]; then
        echo "/usr/local/bin/awg"
    elif [ -x /usr/bin/awg ]; then
        echo "/usr/bin/awg"
    else
        echo ""
    fi
}

# Helper function to find awg-quick binary
get_awg_quick_bin() {
    if hash awg-quick 2>/dev/null; then
        echo "awg-quick"
    elif [ -x /usr/local/bin/awg-quick ]; then
        echo "/usr/local/bin/awg-quick"
    elif [ -x /usr/bin/awg-quick ]; then
        echo "/usr/bin/awg-quick"
    else
        echo ""
    fi
}

# Generate AmneziaWG obfuscation parameters
generate_amnezia_params() {
    # Jc = 3 to 128 (junk packet count)
    awg_jc=$((3 + ($(date +%s) * 17 + $$) % 126))
    
    # Jmin = 20 to 100 (junk packet minimum size)
    awg_jmin=$((20 + ($(date +%s) * 31 + $$) % 81))
    
    # Jmax = 50 to 1000 (junk packet maximum size)
    awg_jmax=$((50 + ($(date +%s) * 47 + $$) % 951))
    
    # Ensure Jmax > Jmin
    if [ "$awg_jmax" -le "$awg_jmin" ]; then
        awg_jmax=$((awg_jmin + 50))
    fi
    
    # S1 = 50 to 200 (junk packet s1 parameter)
    awg_s1=$((50 + ($(date +%s) * 53 + $$) % 151))
    
    # S2 = 50 to 400 (junk packet s2 parameter)
    awg_s2=$((50 + ($(date +%s) * 61 + $$) % 351))
    
    # H1-H4 = 1000000000 to 2147483647 (header parameters)
    _min_h=1000000000
    _max_h=2147483647
    _range_h=$((_max_h - _min_h + 1))
    
    awg_h1=$((_min_h + ($(date +%s) * 37 + $$ * 2) % _range_h))
    awg_h2=$((_min_h + ($(date +%s) * 73 + $$ * 3) % _range_h))
    awg_h3=$((_min_h + ($(date +%s) * 91 + $$ * 5) % _range_h))
    awg_h4=$((_min_h + ($(date +%s) * 123 + $$ * 7) % _range_h))
}

# Show QR code with fallback (POSIX-compliant)
show_qr_code() {
    _config_file="$1"
    
    if command -v qrencode >/dev/null 2>&1; then
        echo "Scan QR code:"
        qrencode -t UTF8 < "$_config_file"
        printf '\n↑ That is a QR code containing the client configuration.\n'
    elif command -v python3 >/dev/null 2>&1 && python3 -c "import qrcode" 2>/dev/null; then
        echo ""
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
        printf '↑ That is a QR code containing the client configuration.\n'
    else
        echo ""
        echo "═══════════════════════════════════════════════════════════"
        echo "  QR CODE NOT AVAILABLE"
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        echo "To enable QR codes, install libqrencode:"
        echo "  pkg install libqrencode"
        echo ""
        echo "Or use Python alternative:"
        echo "  pkg install py311-qrcode (check 'pkg search qrcode' for available versions)"
        echo ""
        echo "Config file location: $_config_file"
        echo ""
        echo "You can transfer this file to your device via:"
        echo "  scp $_config_file user@phone:/path/"
        echo "═══════════════════════════════════════════════════════════"
    fi
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
    echo "Detected FreeBSD $_os_version"
}

check_ip() {
    _ip="$1"
    _regex='^(([0-9]|[1-9][0-9]|1[0-9][2]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    printf '%s' "$_ip" | grep -Eq "$_regex"
}

calculate_mtu() {
    _iface="$1"
    _base_mtu=1500
    _overhead=100  # AmneziaWG overhead: 80 bytes + obfuscation overhead
    
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
    echo "Optimizing kernel for maximum AmneziaWG performance..."
    mkdir -p /etc/sysctl.d
    
    cat > /etc/sysctl.d/99-amneziawg.conf << 'EOF'
# Core forwarding
net.inet.ip.forwarding=1
net.inet6.ip6.forwarding=1

# Socket buffer maximums (increased to 128MB for high-throughput AmneziaWG)
kern.ipc.maxsockbuf=134217728

# TCP buffer maximums (128MB max, matching Alpine Linux aggressive tuning)
net.inet.tcp.sendbuf_max=134217728
net.inet.tcp.recvbuf_max=134217728

# TCP buffer auto-tuning ranges (min/default/max in bytes)
net.inet.tcp.sendbuf_auto=1
net.inet.tcp.recvbuf_auto=1
net.inet.tcp.sendbuf_inc=32768
net.inet.tcp.recvbuf_inc=65536

# Default TCP socket buffer sizes
net.inet.tcp.sendspace=262144
net.inet.tcp.recvspace=262144

# UDP socket buffer sizes (increased for AmneziaWG)
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

# Congestion control - use CUBIC (FreeBSD equivalent to BBR)
# Note: FreeBSD does not have BBR, CUBIC is the best available alternative
net.inet.tcp.cc.algorithm=cubic
net.inet.tcp.cc.abe=1

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
EOF

    sysctl -f /etc/sysctl.d/99-amneziawg.conf >/dev/null 2>&1 || true
    sysrc -f /etc/rc.conf gateway_enable="YES" >/dev/null
    sysctl net.inet.ip.forwarding=1 >/dev/null
    
    # Configure loader.conf tunables for next boot (FreeBSD-specific)
    configure_loader_tunables
}

# FreeBSD loader.conf tunables (require reboot)
configure_loader_tunables() {
    _loader_conf="/boot/loader.conf"
    
    # Backup original if not already backed up
    if [ ! -f "$BACKUP_DIR/loader.conf.backup" ] && [ -f "$_loader_conf" ]; then
        cp "$_loader_conf" "$BACKUP_DIR/loader.conf.backup" 2>/dev/null || true
    fi
    
    # Add performance tunables to loader.conf
    cat >> "$_loader_conf" << 'EOF'

# AmneziaWG Performance Tunables (added by AlpineVPN)
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

# Disable Spectre/Meltdown mitigations for performance (optional, security risk)
# hw.ibrs_disable="1"

# TCP segmentation offload support
device="tso"
EOF
}

optimize_nic() {
    _iface="$1"
    [ -z "$_iface" ] && return
    echo "Optimizing $_iface for maximum throughput..."
    
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
    
    [ -f "$PF_CONF" ] && cp "$PF_CONF" "$BACKUP_DIR/pf.conf.backup" 2>/dev/null || mkdir -p "$BACKUP_DIR"
    
    cat > "$PF_CONF" << EOF
set skip on lo0
set limit states 500000
scrub in on $_ext_if all fragment reassemble max-mss 1380
nat on $_ext_if inet from 10.7.0.0/24 to any -> ($_ext_if) static-port
pass in quick on $_ext_if proto tcp from any to any port 22 keep state
pass in quick on $_ext_if proto udp from any to any port $_wg_port keep state
pass quick on awg0 all
pass out quick on $_ext_if inet from 10.7.0.0/24 to any keep state
block in quick on $_ext_if from 10.0.0.0/8 to any
block in quick on $_ext_if from 172.16.0.0/12 to any
block in quick on $_ext_if from 192.168.0.0/16 to any
EOF

    pfctl -nf "$PF_CONF" || exiterr "PF config error"
    
    if sysrc firewall_enable 2>/dev/null | grep -q "YES"; then
        service ipfw oneflush 2>/dev/null || true
        sysrc firewall_enable="NO"
    fi
    
    sysrc pf_enable="YES"
    service pf start >/dev/null 2>&1 || service pf reload >/dev/null 2>&1 || exiterr "PF failed"
}

install_packages() {
    echo "Installing AmneziaWG..."
    env ASSUME_ALWAYS_YES=YES pkg update -q || exiterr "pkg update failed"
    
    # Load WireGuard kernel module (AmneziaWG uses standard if_wg module)
    if ! kldstat -q -m if_wg; then
        kldload if_wg || exiterr "Failed to load if_wg kernel module"
        echo 'if_wg_load="YES"' >> /boot/loader.conf
    fi
    
    # Install dependencies for building from source
    env ASSUME_ALWAYS_YES=YES pkg install -y go git gmake
    
    # Build and install AmneziaWG from source
    install_amneziawg_from_source
    
    mkdir -p "$AWG_DIR"
    chmod 700 "$AWG_DIR"
    sysrc amneziawg_enable="YES"
    sysrc amneziawg_interfaces="awg0"
}

install_amneziawg_from_source() {
    # Build and install AmneziaWG from source
    _tmp_dir=$(mktemp -d /tmp/amneziawg-build.XXXXXX)
    cd "$_tmp_dir" || exiterr "Failed to create temp directory"
    
    # Clone and build amneziawg-go
    git clone https://github.com/amnezia-vpn/amneziawg-go.git 2>/dev/null || exiterr "Failed to clone amneziawg-go"
    cd amneziawg-go || exiterr "Failed to enter amneziawg-go directory"
    gmake 2>/dev/null || go build -o amneziawg-go .
    cp amneziawg-go /usr/local/bin/ 2>/dev/null || exiterr "Failed to install amneziawg-go"
    ln -sf /usr/local/bin/amneziawg-go /usr/local/bin/awg-go 2>/dev/null || true
    
    # Clone and build amneziawg-tools
    cd "$_tmp_dir" || exiterr "Failed to return to temp directory"
    git clone https://github.com/amnezia-vpn/amneziawg-tools.git 2>/dev/null || exiterr "Failed to clone amneziawg-tools"
    cd amneziawg-tools || exiterr "Failed to enter amneziawg-tools directory"
    
    # Show directory structure for debugging
    echo "AmneziaWG tools directory structure:"
    ls -la 2>/dev/null || echo "Cannot list directory"
    
    # Build the tools
    echo "Building amneziawg-tools in src directory..."
    gmake -C src || exiterr "Failed to build amneziawg-tools (src)"
    
    # Check what was built
    echo "Checking built binaries in src/:"
    ls -la src/wg src/awg* 2>/dev/null || echo "Built binaries:"
    find src -type f -executable 2>/dev/null
    
    # Install
    echo "Installing amneziawg-tools..."
    if ! gmake install PREFIX=/usr/local 2>/dev/null; then
        # Manual installation
        echo "Manual installation of binaries..."
        # The binary is named 'wg' but we need 'awg'
        if [ -f "src/wg" ]; then
            cp src/wg /usr/local/bin/awg || exiterr "Failed to install awg binary"
            chmod +x /usr/local/bin/awg
            echo "Installed src/wg as /usr/local/bin/awg"
        else
            exiterr "wg binary not found after build in src/"
        fi
        # awg-quick is the wg-quick script with 'awg' instead of 'wg'
        if [ -f "wg-quick/freebsd.bash" ]; then
            sed 's/wg /awg /g; s/wg$/awg/g' wg-quick/freebsd.bash > /usr/local/bin/awg-quick
            chmod +x /usr/local/bin/awg-quick
            echo "Created awg-quick from wg-quick/freebsd.bash"
        elif [ -f "src/wg-quick/freebsd.bash" ]; then
            sed 's/wg /awg /g; s/wg$/awg/g' src/wg-quick/freebsd.bash > /usr/local/bin/awg-quick
            chmod +x /usr/local/bin/awg-quick
            echo "Created awg-quick from src/wg-quick/freebsd.bash"
        elif [ -f "wg-quick.bash" ]; then
            sed 's/wg /awg /g; s/wg$/awg/g' wg-quick.bash > /usr/local/bin/awg-quick
            chmod +x /usr/local/bin/awg-quick
            echo "Created awg-quick from wg-quick.bash"
        else
            _wg_quick_path=$(find . -name "*.bash" -type f 2>/dev/null | grep -E "(wg-quick|awg-quick|freebsd)" | head -1)
            if [ -n "$_wg_quick_path" ]; then
                sed 's/wg /awg /g; s/wg$/awg/g' "$_wg_quick_path" > /usr/local/bin/awg-quick
                chmod +x /usr/local/bin/awg-quick
                echo "Created awg-quick from $_wg_quick_path"
            else
                exiterr "wg-quick bash script not found in repository"
            fi
        fi
    fi
    
    # Cleanup
    cd / || exiterr "Failed to return to root"
    rm -rf "$_tmp_dir"
    
    # Verify installation
    echo "Verifying AmneziaWG installation..."
    if hash awg-quick 2>/dev/null; then
        echo "awg-quick: $(which awg-quick)"
    else
        echo "Warning: awg-quick not found in PATH"
        ls -la /usr/local/bin/awg* 2>/dev/null || echo "No awg binaries in /usr/local/bin"
    fi
    
    echo "AmneziaWG installed successfully from source"
}

create_server_config() {
    _endpoint_ip="$1"
    _wg_port="$2"
    _wg_mtu="$3"
    
    echo "Creating server config..."
    
    # Ensure awg is in PATH
    if ! hash awg 2>/dev/null; then
        if [ -x /usr/local/bin/awg ]; then
            export PATH="$PATH:/usr/local/bin"
            hash -r
        fi
    fi
    
    # Generate keys and sanitize immediately (strip newlines)
    _awg_bin=$(get_awg_bin)
    [ -z "$_awg_bin" ] && exiterr "awg binary not found"
    _server_priv=$($_awg_bin genkey | tr -d '\n') || exiterr "Failed to generate server private key"
    _server_pub=$(printf '%s' "$_server_priv" | $_awg_bin pubkey | tr -d '\n') || exiterr "Failed to generate server public key"
    
    # Generate AmneziaWG obfuscation parameters
    generate_amnezia_params
    
    # Store endpoint for later use by clients
    printf '%s:%s' "$_endpoint_ip" "$_wg_port" > "$SERVER_ENDPOINT_FILE"
    
    # Store obfuscation parameters for clients
    printf '%s %s %s %s %s %s %s %s' "$awg_jc" "$awg_jmin" "$awg_jmax" "$awg_s1" "$awg_s2" "$awg_h1" "$awg_h2" "$awg_h3" "$awg_h4" > "$AWG_DIR/awg_params.txt"
    
    atomic_write "$AWG_DIR/awg0.conf" << EOF
[Interface]
Address = 10.7.0.1/24
PrivateKey = $_server_priv
ListenPort = $_wg_port
MTU = $_wg_mtu
Jc = $awg_jc
Jmin = $awg_jmin
Jmax = $awg_jmax
S1 = $awg_s1
S2 = $awg_s2
H1 = $awg_h1
H2 = $awg_h2
H3 = $awg_h3
H4 = $awg_h4

# Server Public Key: $_server_pub
EOF

    printf '%s' "$_server_pub" > "$AWG_DIR/server.pub"
    chmod 600 "$AWG_DIR/awg0.conf"
    echo "Server public key: $_server_pub"
}

start_wireguard() {
    _wg_port="$1"
    echo "Starting AmneziaWG..."
    
    # Ensure awg-quick is in PATH
    if ! hash awg-quick 2>/dev/null; then
        if [ -x /usr/local/bin/awg-quick ]; then
            export PATH="$PATH:/usr/local/bin"
            hash -r
        fi
    fi
    
    ifconfig awg0 destroy 2>/dev/null || true
    
    if ! service amneziawg start 2>/dev/null; then
        _awg_quick_bin=$(get_awg_quick_bin)
        [ -z "$_awg_quick_bin" ] && exiterr "awg-quick binary not found"
        
        if ! "$_awg_quick_bin" up awg0 2>&1; then
            echo "Error: Failed to start AmneziaWG"
            echo "Debug: Checking configuration..."
            cat "$AWG_DIR/awg0.conf" 2>/dev/null || echo "Config file not found"
            exit 1
        fi
    fi
    
    ifconfig awg0 >/dev/null 2>&1 || exiterr "Interface failed"
    echo "AmneziaWG running on port $_wg_port"
}

add_client() {
    _client_name="$1"
    _dns_servers="${2:-1.1.1.1, 1.0.0.1}"
    
    # Ensure awg is in PATH
    if ! hash awg 2>/dev/null; then
        if [ -x /usr/local/bin/awg ]; then
            export PATH="$PATH:/usr/local/bin"
            hash -r
        fi
    fi
    
    _client=$(printf '%s' "$_client_name" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c-15)
    [ -z "$_client" ] && exiterr "Invalid client name"
    
    if [ -f "$AWG_DIR/awg0.conf" ] && grep -q "^# BEGIN_PEER $_client$" "$AWG_DIR/awg0.conf"; then
        exiterr "Client $_client already exists"
    fi
    
    # Find next available IP
    _octet=2
    while grep -q "10.7.0.$_octet/32" "$AWG_DIR/awg0.conf" 2>/dev/null && [ "$_octet" -lt 254 ]; do
        _octet=$((_octet + 1))
    done
    [ "$_octet" -eq 254 ] && exiterr "No IPs available"
    
    echo "Creating client $_client (10.7.0.$_octet)..."
    
    # Generate and sanitize keys
    _awg_bin=$(get_awg_bin)
    [ -z "$_awg_bin" ] && exiterr "awg binary not found"
    
    _client_priv=$($_awg_bin genkey | tr -d '\n') || exiterr "Failed to generate client private key"
    _client_pub=$(printf '%s' "$_client_priv" | $_awg_bin pubkey | tr -d '\n') || exiterr "Failed to generate client public key"
    _psk=$($_awg_bin genpsk | tr -d '\n') || exiterr "Failed to generate PSK"
    
    # Get server details
    _server_pub=$(cat "$AWG_DIR/server.pub" | tr -d '\n')
    _endpoint=$(cat "$SERVER_ENDPOINT_FILE" | tr -d '\n')
    _mtu=$(grep "^MTU" "$AWG_DIR/awg0.conf" | awk '{print $3}' | tr -d '\n')
    [ -z "$_mtu" ] && _mtu=1400
    
    # Get obfuscation parameters from server config
    _awg_jc=$(grep "^Jc" "$AWG_DIR/awg0.conf" | awk '{print $3}' | tr -d '\n')
    _awg_jmin=$(grep "^Jmin" "$AWG_DIR/awg0.conf" | awk '{print $3}' | tr -d '\n')
    _awg_jmax=$(grep "^Jmax" "$AWG_DIR/awg0.conf" | awk '{print $3}' | tr -d '\n')
    _awg_s1=$(grep "^S1" "$AWG_DIR/awg0.conf" | awk '{print $3}' | tr -d '\n')
    _awg_s2=$(grep "^S2" "$AWG_DIR/awg0.conf" | awk '{print $3}' | tr -d '\n')
    _awg_h1=$(grep "^H1" "$AWG_DIR/awg0.conf" | awk '{print $3}' | tr -d '\n')
    _awg_h2=$(grep "^H2" "$AWG_DIR/awg0.conf" | awk '{print $3}' | tr -d '\n')
    _awg_h3=$(grep "^H3" "$AWG_DIR/awg0.conf" | awk '{print $3}' | tr -d '\n')
    _awg_h4=$(grep "^H4" "$AWG_DIR/awg0.conf" | awk '{print $3}' | tr -d '\n')
    
    # Validate no empty values
    [ -z "$_server_pub" ] && exiterr "Server public key missing"
    [ -z "$_endpoint" ] && exiterr "Server endpoint missing"
    [ -z "$_client_priv" ] && exiterr "Client key generation failed"
    [ -z "$_psk" ] && exiterr "PSK generation failed"
    
    # Add peer to server config
    cat >> "$AWG_DIR/awg0.conf" << EOF

# BEGIN_PEER $_client
[Peer]
PublicKey = $_client_pub
PresharedKey = $_psk
AllowedIPs = 10.7.0.$_octet/32
# END_PEER $_client
EOF
    
    # Create client config directory
    _export_dir="${AWG_DIR}/clients"
    mkdir -p "$_export_dir"
    chmod 700 "$_export_dir"
    _client_file="$_export_dir/$_client.conf"
    
    # Anti-DPI: Randomize keepalive interval (20-30 seconds) to avoid pattern detection
    _keepalive=$((20 + ($(date +%s) % 11)))
    
    # Write client config with explicit newlines, no trailing spaces
    printf '%s\n' "[Interface]" > "$_client_file"
    printf 'Address = 10.7.0.%s/24\n' "$_octet" >> "$_client_file"
    printf 'DNS = %s\n' "$_dns_servers" >> "$_client_file"
    printf 'PrivateKey = %s\n' "$_client_priv" >> "$_client_file"
    printf 'MTU = %s\n' "$_mtu" >> "$_client_file"
    printf 'Jc = %s\n' "$_awg_jc" >> "$_client_file"
    printf 'Jmin = %s\n' "$_awg_jmin" >> "$_client_file"
    printf 'Jmax = %s\n' "$_awg_jmax" >> "$_client_file"
    printf 'S1 = %s\n' "$_awg_s1" >> "$_client_file"
    printf 'S2 = %s\n' "$_awg_s2" >> "$_client_file"
    printf 'H1 = %s\n' "$_awg_h1" >> "$_client_file"
    printf 'H2 = %s\n' "$_awg_h2" >> "$_client_file"
    printf 'H3 = %s\n' "$_awg_h3" >> "$_client_file"
    printf 'H4 = %s\n\n' "$_awg_h4" >> "$_client_file"
    printf '%s\n' "[Peer]" >> "$_client_file"
    printf 'PublicKey = %s\n' "$_server_pub" >> "$_client_file"
    printf 'PresharedKey = %s\n' "$_psk" >> "$_client_file"
    printf 'AllowedIPs = 0.0.0.0/0\n' >> "$_client_file"
    printf 'Endpoint = %s\n' "$_endpoint" >> "$_client_file"
    printf 'PersistentKeepalive = %s\n' "$_keepalive" >> "$_client_file"
    
    chmod 600 "$_client_file"
    
    # Ensure awg is in PATH for set command
    if ! hash awg 2>/dev/null; then
        if [ -x /usr/local/bin/awg ]; then
            export PATH="$PATH:/usr/local/bin"
            hash -r
        fi
    fi
    
    # Add to running server (POSIX-compliant mktemp with template)
    _tmpfile=$(mktemp /tmp/awg-psk.XXXXXX) || exiterr "Failed to create temp file"
    printf '%s' "$_psk" > "$_tmpfile"
    $_awg_bin set awg0 peer "$_client_pub" preshared-key "$_tmpfile" allowed-ips "10.7.0.$_octet/32" 2>/dev/null || \
        echo "Note: Restart AmneziaWG to activate new peer"
    rm -f "$_tmpfile"
    
    if [ -n "${SUDO_USER:-}" ]; then
        chown "$SUDO_USER:$SUDO_USER" "$_client_file" 2>/dev/null || true
    fi
    
    echo "Client '$_client' created successfully"
    echo "Location: $_client_file"
    echo ""
    
    # Validate config syntax
    if awg-quick strip "$_client_file" >/dev/null 2>&1; then
        echo "Config validation: OK"
    else
        echo "Warning: Config validation failed"
    fi
    
    # Show QR code (with Python fallback)
    show_qr_code "$_client_file"
}

show_status() {
    echo "=== AmneziaWG Status ==="
    ifconfig awg0 2>/dev/null || { echo "Not running"; return 1; }
    echo ""
    awg show awg0 2>/dev/null || true
}

remove_client() {
    _client_name="$1"
    _client=$(printf '%s' "$_client_name" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c-15)
    
    if ! grep -q "^# BEGIN_PEER $_client$" "$AWG_DIR/awg0.conf" 2>/dev/null; then
        exiterr "Client not found"
    fi
    
    printf "Remove '%s'? [y/N] " "$_client"
    read -r _confirm
    case "$_confirm" in
        [yY])
            _peer_key=$(sed -n "/^# BEGIN_PEER $_client/,/^# END_PEER $_client/p" "$AWG_DIR/awg0.conf" | grep PublicKey | awk '{print $3}')
            if [ -n "$_peer_key" ]; then
                awg set awg0 peer "$_peer_key" remove 2>/dev/null || true
            fi
            sed_inplace "/^# BEGIN_PEER $_client/,/^# END_PEER $_client/d" "$AWG_DIR/awg0.conf"
            rm -f "$AWG_DIR/clients/$_client.conf"
            echo "Removed"
            ;;
    esac
}

uninstall_wireguard() {
    printf "Uninstall AmneziaWG? [y/N] "
    read -r _confirm
    case "$_confirm" in
        [yY])
            service amneziawg stop 2>/dev/null || ifconfig awg0 destroy 2>/dev/null || true
            sysrc -x amneziawg_enable 2>/dev/null || true
            sysrc -x amneziawg_interfaces 2>/dev/null || true
            
            if [ -f "$BACKUP_DIR/pf.conf.backup" ]; then
                mv "$BACKUP_DIR/pf.conf.backup" "$PF_CONF"
                service pf reload 2>/dev/null || true
            fi
            
            # Remove AmneziaWG binaries
            rm -f /usr/local/bin/amneziawg-go /usr/local/bin/awg-go
            rm -f /usr/local/bin/awg /usr/local/bin/awg-quick
            
            rm -rf "$AWG_DIR" /etc/sysctl.d/99-amneziawg.conf
            echo "Uninstalled"
            ;;
    esac
}

menu() {
    while true; do
        echo ""
        echo "AmneziaWG Management"
        echo "1) Add client"
        echo "2) List clients"
        echo "3) Remove client"
        echo "4) Show QR"
        echo "5) Status"
        echo "6) Uninstall"
        echo "7) Exit"
        printf "Select: "
        read -r _opt
        
        case "$_opt" in
            1)
                printf "Client name: "; read -r _name
                printf "DNS [1.1.1.1, 1.0.0.1]: "; read -r _dns
                add_client "$_name" "${_dns:-1.1.1.1, 1.0.0.1}"
                ;;
            2)
                grep "^# BEGIN_PEER" "$AWG_DIR/awg0.conf" 2>/dev/null | cut -d' ' -f3 | nl || echo "No clients"
                ;;
            3)
                printf "Remove: "; read -r _name
                remove_client "$_name"
                ;;
            4)
                printf "Client: "; read -r _name
                _c=$(printf '%s' "$_name" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c-15)
                if [ -f "$AWG_DIR/clients/$_c.conf" ]; then
                    show_qr_code "$AWG_DIR/clients/$_c.conf"
                else
                    echo "Not found"
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
    
    if [ -f "$AWG_DIR/awg0.conf" ]; then
        menu
        exit 0
    fi
    
    echo "=== AmneziaWG Installer ==="
    echo "Performance Mode: Enabled with DPI evasion"
    echo ""
    
    _ip=$(ifconfig "$_default_iface" | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | head -1)
    check_ip "$_ip" || exiterr "Invalid IP"
    
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
    echo "  MTU: $_wg_mtu (optimized for AmneziaWG with obfuscation)"
    echo "  DPI Evasion: Junk packets, header obfuscation, randomized keepalive"
    printf "Proceed? [Y/n] "; read -r _confirm
    case "$_confirm" in [nN]) exit 0 ;; esac
    
    install_packages
    configure_sysctl
    optimize_nic "$_default_iface"
    configure_firewall "$_default_iface" "$_wg_port"
    create_server_config "$_public_ip" "$_wg_port" "$_wg_mtu"
    start_wireguard "$_wg_port"
    add_client "$_first_client"
    
    echo ""
    echo "==================================="
    echo "Server: ${_public_ip}:${_wg_port}"
    echo "Client: $AWG_DIR/clients/$_first_client.conf"
    echo "DPI evasion and performance optimizations applied"
    echo "==================================="
}

main "$@"
