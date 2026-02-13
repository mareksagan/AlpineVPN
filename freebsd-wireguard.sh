#!/bin/sh
#
# WireGuard Installer for FreeBSD 14.x - Client Config Fix
#

set -eu

exiterr() { 
    echo "Error: $1" >&2 
    exit 1 
}

WG_DIR="/usr/local/etc/wireguard"
PF_CONF="/etc/pf.conf"
BACKUP_DIR="/var/backups/wireguard-install-$(date +%Y%m%d-%H%M%S)"
SERVER_ENDPOINT_FILE="$WG_DIR/endpoint.txt"

# Sanitize WireGuard keys (remove all whitespace)
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
    echo "Optimizing kernel..."
    mkdir -p /etc/sysctl.d
    
    cat > /etc/sysctl.d/99-wireguard.conf << 'EOF'
net.inet.ip.forwarding=1
net.inet6.ip6.forwarding=1
kern.ipc.maxsockbuf=16777216
net.inet.tcp.sendbuf_max=16777216
net.inet.tcp.recvbuf_max=16777216
net.inet.tcp.sendspace=262144
net.inet.tcp.recvspace=262144
net.inet.udp.recvspace=262144
net.inet.tcp.delayed_ack=0
net.route.netisr_maxqlen=2048
EOF

    sysctl -f /etc/sysctl.d/99-wireguard.conf >/dev/null 2>&1 || true
    sysrc -f /etc/rc.conf gateway_enable="YES" >/dev/null
    sysctl net.inet.ip.forwarding=1 >/dev/null
}

optimize_nic() {
    _iface="$1"
    [ -z "$_iface" ] && return
    echo "Optimizing $_iface..."
    ifconfig "$_iface" -tso -lro 2>/dev/null || true
}

configure_firewall() {
    _ext_if="$1"
    _wg_port="$2"
    
    [ -f "$PF_CONF" ] && cp "$PF_CONF" "$BACKUP_DIR/pf.conf.backup" 2>/dev/null || mkdir -p "$BACKUP_DIR"
    
    cat > "$PF_CONF" << EOF
set skip on lo0
set limit states 500000
scrub in on $_ext_if all fragment reassemble max-mss 1420
nat on $_ext_if inet from 10.7.0.0/24 to any -> ($_ext_if) static-port
pass in quick on $_ext_if proto tcp from any to any port 22 keep state
pass in quick on $_ext_if proto udp from any to any port $_wg_port keep state
pass quick on wg0 all
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
    echo "Installing WireGuard..."
    env ASSUME_ALWAYS_YES=YES pkg update -q || exiterr "pkg update failed"
    
    if ! kldstat -q -m if_wg; then
        kldload if_wg || exiterr "Failed to load if_wg"
        echo 'if_wg_load="YES"' >> /boot/loader.conf
    fi
    
    env ASSUME_ALWAYS_YES=YES pkg install -y wireguard-tools
    pkg install -y qrencode 2>/dev/null || true
    
    mkdir -p "$WG_DIR"
    chmod 700 "$WG_DIR"
    sysrc wireguard_enable="YES"
    sysrc wireguard_interfaces="wg0"
}

create_server_config() {
    _endpoint_ip="$1"
    _wg_port="$2"
    _wg_mtu="$3"
    
    echo "Creating server config..."
    
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
    echo "Starting WireGuard..."
    
    ifconfig wg0 destroy 2>/dev/null || true
    
    if ! service wireguard start 2>/dev/null; then
        wg-quick up wg0 || exiterr "Failed to start WireGuard"
    fi
    
    ifconfig wg0 >/dev/null 2>&1 || exiterr "Interface failed"
    echo "WireGuard running on port $_wg_port"
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
    
    echo "Creating client $_client (10.7.0.$_octet)..."
    
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
    
    # Create client config directory
    _export_dir="${WG_DIR}/clients"
    mkdir -p "$_export_dir"
    chmod 700 "$_export_dir"
    _client_file="$_export_dir/$_client.conf"
    
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
    printf 'PersistentKeepalive = 25\n' >> "$_client_file"
    
    chmod 600 "$_client_file"
    
    # Add to running server
    _tmpfile=$(mktemp)
    printf '%s' "$_psk" > "$_tmpfile"
    wg set wg0 peer "$_client_pub" preshared-key "$_tmpfile" allowed-ips "10.7.0.$_octet/32" 2>/dev/null || \
        echo "Note: Restart WireGuard to activate new peer"
    rm -f "$_tmpfile"
    
    if [ -n "${SUDO_USER:-}" ]; then
        chown "$SUDO_USER:$SUDO_USER" "$_client_file" 2>/dev/null || true
    fi
    
    echo "Client '$_client' created successfully"
    echo "Location: $_client_file"
    echo ""
    
    # Validate config syntax
    if wg-quick strip "$_client_file" >/dev/null 2>&1; then
        echo "Config validation: OK"
    else
        echo "Warning: Config validation failed"
    fi
    
    # Show QR
    if command -v qrencode >/dev/null 2>&1; then
        echo "Scan QR code:"
        qrencode -t UTF8 < "$_client_file"
    fi
}

show_status() {
    echo "=== WireGuard Status ==="
    ifconfig wg0 2>/dev/null || { echo "Not running"; return 1; }
    echo ""
    wg show wg0 2>/dev/null || true
}

remove_client() {
    _client_name="$1"
    _client=$(printf '%s' "$_client_name" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c-15)
    
    if ! grep -q "^# BEGIN_PEER $_client$" "$WG_DIR/wg0.conf" 2>/dev/null; then
        exiterr "Client not found"
    fi
    
    printf "Remove '%s'? [y/N] " "$_client"
    read -r _confirm
    case "$_confirm" in
        [yY])
            _peer_key=$(sed -n "/^# BEGIN_PEER $_client/,/^# END_PEER $_client/p" "$WG_DIR/wg0.conf" | grep PublicKey | awk '{print $3}')
            if [ -n "$_peer_key" ]; then
                wg set wg0 peer "$_peer_key" remove 2>/dev/null || true
            fi
            sed -i '' "/^# BEGIN_PEER $_client/,/^# END_PEER $_client/d" "$WG_DIR/wg0.conf"
            rm -f "$WG_DIR/clients/$_client.conf"
            echo "Removed"
            ;;
    esac
}

uninstall_wireguard() {
    printf "Uninstall WireGuard? [y/N] "
    read -r _confirm
    case "$_confirm" in
        [yY])
            service wireguard stop 2>/dev/null || ifconfig wg0 destroy 2>/dev/null || true
            sysrc -x wireguard_enable 2>/dev/null || true
            sysrc -x wireguard_interfaces 2>/dev/null || true
            
            if [ -f "$BACKUP_DIR/pf.conf.backup" ]; then
                mv "$BACKUP_DIR/pf.conf.backup" "$PF_CONF"
                service pf reload 2>/dev/null || true
            fi
            
            rm -rf "$WG_DIR" /etc/sysctl.d/99-wireguard.conf
            echo "Uninstalled"
            ;;
    esac
}

menu() {
    while true; do
        echo ""
        echo "WireGuard Management"
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
                grep "^# BEGIN_PEER" "$WG_DIR/wg0.conf" 2>/dev/null | cut -d' ' -f3 | nl || echo "No clients"
                ;;
            3)
                printf "Remove: "; read -r _name
                remove_client "$_name"
                ;;
            4)
                printf "Client: "; read -r _name
                _c=$(printf '%s' "$_name" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c-15)
                [ -f "$WG_DIR/clients/$_c.conf" ] && qrencode -t UTF8 < "$WG_DIR/clients/$_c.conf" 2>/dev/null || echo "Not found"
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
        menu
        exit 0
    fi
    
    echo "=== WireGuard Installer ==="
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
    
    printf "Port [51820]: "; read -r _wg_port
    _wg_port=${_wg_port:-51820}
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
    create_server_config "$_public_ip" "$_wg_port" "$_wg_mtu"
    start_wireguard "$_wg_port"
    add_client "$_first_client"
    
    echo ""
    echo "==================================="
    echo "Server: ${_public_ip}:${_wg_port}"
    echo "Client: $WG_DIR/clients/$_first_client.conf"
    echo "==================================="
}

main "$@"
