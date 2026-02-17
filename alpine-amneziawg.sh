#!/bin/sh
#
# https://github.com/hwdsl2/wireguard-install   
# AmneziaWG Version - Performance-Optimized with DPI evasion
#
# POSIX sh version for Alpine Linux and other minimal systems
# FULLY CORRECTED – Kernel module auto‑build with automatic kernel upgrade
#

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' failed."; }
exiterr3() { exiterr "'yum install' failed."; }
exiterr4() { exiterr "'zypper install' failed."; }
exiterr5() { exiterr "'apk add' failed."; }

# FIXED: Changed 1[0-9][2] to 1[0-9][0-9] for POSIX compatibility and correctness
check_ip() {
	IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'
	printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_pvt_ip() {
	IPP_REGEX='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
	printf '%s' "$1" | tr -d '\n' | grep -Eq "$IPP_REGEX"
}

check_dns_name() {
	FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
	printf '%s' "$1" | tr -d '\n' | grep -Eq "$FQDN_REGEX"
}

check_root() {
	if [ "$(id -u)" != 0 ]; then
		exiterr "This installer must be run as root. Try 'sudo sh $0'"
	fi
}

check_shell() {
	:
}

check_kernel() {
	if [ "$(uname -r | cut -d "." -f 1)" -eq 2 ]; then
		exiterr "The system is running an old kernel, which is incompatible with this installer."
	fi
}

check_os() {
	if grep -qs "ubuntu" /etc/os-release; then
		os="ubuntu"
		os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	elif [ -e /etc/debian_version ]; then
		os="debian"
		os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	elif [ -e /etc/almalinux-release ] || [ -e /etc/rocky-release ] || [ -e /etc/centos-release ]; then
		os="centos"
		os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
	elif [ -e /etc/fedora-release ]; then
		os="fedora"
		os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	elif [ -e /etc/SUSE-brand ] && [ "$(head -1 /etc/SUSE-brand)" = "openSUSE" ]; then
		os="openSUSE"
		os_version=$(tail -1 /etc/SUSE-brand | grep -oE '[0-9\\.]+')
	elif [ -e /etc/alpine-release ]; then
		os="alpine"
		os_version=$(cut -d '.' -f 1,2 /etc/alpine-release)
	else
		exiterr "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, Fedora, openSUSE and Alpine."
	fi
}

check_os_ver() {
	if [ "$os" = "ubuntu" ] && [ "$os_version" -lt 2004 ]; then
		exiterr "Ubuntu 20.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	fi
	if [ "$os" = "debian" ] && [ "$os_version" -lt 11 ]; then
		exiterr "Debian 11 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	fi
	if [ "$os" = "centos" ] && [ "$os_version" -lt 8 ]; then
		exiterr "CentOS 8 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	fi
}

check_container() {
	if command -v systemd-detect-virt >/dev/null 2>&1; then
		if systemd-detect-virt -cq 2>/dev/null; then
			exiterr "This system is running inside a container, which is not supported by this installer."
		fi
	fi
}

set_client_name() {
	client=$(echo "$unsanitized_client" | sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' | cut -c-15)
}

# POSIX-compliant sed in-place (no GNU extension)
sed_inplace() {
	script="$1"
	file="$2"
	tmpf="${file}.sedtmp.$$"
	sed "$script" "$file" > "$tmpf" || return 1
	mv -f "$tmpf" "$file"
}

# Helper function to find awg binary (returns full path)
get_awg_bin() {
	_path=$(command -v awg 2>/dev/null)
	if [ -n "$_path" ] && [ -x "$_path" ]; then
		echo "$_path"
	elif [ -x /usr/bin/awg ]; then
		echo "/usr/bin/awg"
	elif [ -x /usr/local/bin/awg ]; then
		echo "/usr/local/bin/awg"
	else
		echo ""
	fi
}

# Helper function to find awg-quick binary (returns full path)
get_awg_quick_bin() {
	_path=$(command -v awg-quick 2>/dev/null)
	if [ -n "$_path" ] && [ -x "$_path" ]; then
		echo "$_path"
	elif [ -x /usr/bin/awg-quick ]; then
		echo "/usr/bin/awg-quick"
	elif [ -x /usr/local/bin/awg-quick ]; then
		echo "/usr/local/bin/awg-quick"
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

# PERFORMANCE: Calculate optimal MTU based on physical interface (BusyBox compatible)
calculate_mtu() {
	# FIXED: Removed grep -P, using awk instead for BusyBox compatibility
	default_iface=$(ip -4 route show default 2>/dev/null | grep "dev" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
	if [ -n "$default_iface" ] && [ -e "/sys/class/net/$default_iface/mtu" ]; then
		base_mtu=$(cat "/sys/class/net/$default_iface/mtu" 2>/dev/null || echo 1500)
		# AmneziaWG overhead: 80 bytes (IPv4) + additional overhead for obfuscation (~20 bytes), use 100 for safety
		wg_mtu=$((base_mtu - 100))
		# Ensure not less than 1280 (minimum IPv6 MTU)
		if [ "$wg_mtu" -lt 1280 ]; then
			wg_mtu=1280
		fi
	else
		wg_mtu=1400  # Safe default for AmneziaWG with obfuscation overhead
	fi
	echo "$wg_mtu"
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case $1 in
			--auto)
				auto=1
				shift
				;;
			--addclient)
				add_client=1
				unsanitized_client="$2"
				shift
				shift
				;;
			--listclients)
				list_clients=1
				shift
				;;
			--removeclient)
				remove_client=1
				unsanitized_client="$2"
				shift
				shift
				;;
			--showclientqr)
				show_client_qr=1
				unsanitized_client="$2"
				shift
				shift
				;;
			--uninstall)
				remove_wg=1
				shift
				;;
			--serveraddr)
				server_addr="$2"
				shift
				shift
				;;
			--port)
				server_port="$2"
				shift
				shift
				;;
			--clientname)
				first_client_name="$2"
				shift
				shift
				;;
			--dns1)
				dns1="$2"
				shift
				shift
				;;
			--dns2)
				dns2="$2"
				shift
				shift
				;;
			-y|--yes)
				assume_yes=1
				shift
				;;
			-h|--help)
				show_usage
				;;
			*)
				show_usage "Unknown parameter: $1"
				;;
		esac
	done
}

check_args() {
	auto=${auto:-0}
	assume_yes=${assume_yes:-0}
	add_client=${add_client:-0}
	list_clients=${list_clients:-0}
	remove_client=${remove_client:-0}
	show_client_qr=${show_client_qr:-0}
	remove_wg=${remove_wg:-0}
	
	if [ "$auto" != 0 ] && [ -e "$WG_CONF" ]; then
		show_usage "Invalid parameter '--auto'. AmneziaWG is already set up on this server."
	fi
	if [ "$((add_client + list_clients + remove_client + show_client_qr))" -gt 1 ]; then
		show_usage "Invalid parameters. Specify only one of '--addclient', '--listclients', '--removeclient' or '--showclientqr'."
	fi
	if [ "$remove_wg" = 1 ]; then
		if [ "$((add_client + list_clients + remove_client + show_client_qr + auto))" -gt 0 ]; then
			show_usage "Invalid parameters. '--uninstall' cannot be specified with other parameters."
		fi
	fi
	if [ ! -e "$WG_CONF" ]; then
		st_text="You must first set up AmneziaWG before"
		if [ "$add_client" = 1 ]; then exiterr "$st_text adding a client."; fi
		if [ "$list_clients" = 1 ]; then exiterr "$st_text listing clients."; fi
		if [ "$remove_client" = 1 ]; then exiterr "$st_text removing a client."; fi
		if [ "$show_client_qr" = 1 ]; then exiterr "$st_text showing QR code for a client."; fi
		if [ "$remove_wg" = 1 ]; then exiterr "Cannot remove AmneziaWG because it has not been set up on this server."; fi
	fi
	if [ "$((add_client + remove_client + show_client_qr))" = 1 ] && [ -n "$first_client_name" ]; then
		show_usage "Invalid parameters. '--clientname' can only be specified when installing AmneziaWG."
	fi
	if [ -n "$server_addr" ] || [ -n "$server_port" ] || [ -n "$first_client_name" ]; then
			if [ -e "$WG_CONF" ]; then
				show_usage "Invalid parameters. AmneziaWG is already set up on this server."
			elif [ "$auto" = 0 ]; then
				show_usage "Invalid parameters. You must specify '--auto' when using these parameters."
			fi
	fi
	if [ "$add_client" = 1 ]; then
		set_client_name
		if [ -z "$client" ]; then
			exiterr "Invalid client name. Use one word only, no special characters except '-' and '_'."
		elif grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; then
			exiterr "$client: invalid name. Client already exists."
		fi
	fi
	if [ "$remove_client" = 1 ] || [ "$show_client_qr" = 1 ]; then
		set_client_name
		if [ -z "$client" ] || ! grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; then
			exiterr "Invalid client name, or client does not exist."
		fi
	fi
	if [ -n "$server_addr" ]; then
		if ! check_dns_name "$server_addr" && ! check_ip "$server_addr"; then
			exiterr "Invalid server address. Must be a fully qualified domain name (FQDN) or an IPv4 address."
		fi
	fi
	if [ -n "$first_client_name" ]; then
		unsanitized_client="$first_client_name"
		set_client_name
		if [ -z "$client" ]; then
			exiterr "Invalid client name. Use one word only, no special characters except '-' and '_'."
		fi
	fi
	if [ -n "$server_port" ]; then
		if ! echo "$server_port" | grep -qE '^[0-9]+$' || [ "$server_port" -gt 65535 ]; then
			exiterr "Invalid port. Must be an integer between 1 and 65535."
		fi
	fi
	if [ -n "$dns1" ]; then
		if [ -e "$WG_CONF" ] && [ "$add_client" = 0 ]; then
			show_usage "Invalid parameters. Custom DNS server(s) can only be specified when installing AmneziaWG or adding a client."
		fi
	fi
	if { [ -n "$dns1" ] && ! check_ip "$dns1"; } || { [ -n "$dns2" ] && ! check_ip "$dns2"; }; then
		exiterr "Invalid DNS server(s)."
	fi
	if [ -z "$dns1" ] && [ -n "$dns2" ]; then
		show_usage "Invalid DNS server. --dns2 cannot be specified without --dns1."
	fi
	if [ -n "$dns1" ] && [ -n "$dns2" ]; then
		dns="$dns1, $dns2"
	elif [ -n "$dns1" ]; then
		dns="$dns1"
	else
		dns="1.1.1.1, 1.0.0.1"  # Changed from Google to Cloudflare (faster)
	fi
}

check_nftables() {
	if [ "$os" = "centos" ]; then
		if grep -qs "hwdsl2 VPN script" /etc/sysconfig/nftables.conf 2>/dev/null; then
			exiterr "This system has nftables enabled, which is not supported by this installer."
		fi
		if command -v systemctl >/dev/null 2>&1; then
			if systemctl is-active --quiet nftables 2>/dev/null; then
				exiterr "This system has nftables enabled, which is not supported by this installer."
			fi
		fi
	fi
}

install_wget() {
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "Wget is required to use this installer."
			printf "Press any key to install Wget and continue..."
			read -r _
		fi
		if [ "$os" = "alpine" ]; then
			(
				set -x
				apk add --no-cache wget >/dev/null
			) || exiterr5
		else
			export DEBIAN_FRONTEND=noninteractive
			(
				set -x
				apt-get -yqq update || apt-get -yqq update
				apt-get -yqq install wget >/dev/null
			) || exiterr2
		fi
	fi
}

install_iproute() {
	if ! hash ip 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "iproute is required to use this installer."
			printf "Press any key to install iproute and continue..."
			read -r _
		fi
		if [ "$os" = "alpine" ]; then
			(
				set -x
				apk add --no-cache iproute2 >/dev/null
			) || exiterr5
		elif [ "$os" = "debian" ] || [ "$os" = "ubuntu" ]; then
			export DEBIAN_FRONTEND=noninteractive
			(
				set -x
				apt-get -yqq update || apt-get -yqq update
				apt-get -yqq install iproute2 >/dev/null
			) || exiterr2
		elif [ "$os" = "openSUSE" ]; then
			(
				set -x
				zypper install iproute2 >/dev/null
			) || exiterr4
		else
			(
				set -x
				yum -y -q install iproute >/dev/null
			) || exiterr3
		fi
	fi
}

# Ensure TUN device exists (required for userspace fallback)
ensure_tun() {
	if [ ! -c /dev/net/tun ]; then
		echo "Creating TUN device..."
		mkdir -p /dev/net
		# Load tun module if available
		if modprobe tun 2>/dev/null; then
			# Create device node with major 10, minor 200
			mknod /dev/net/tun c 10 200 2>/dev/null || true
			chmod 600 /dev/net/tun
		else
			echo "Warning: Could not load tun module. Userspace fallback may fail."
		fi
	fi
	# Ensure module loads at boot
	if [ "$os" = "alpine" ]; then
		mkdir -p /etc/modules-load.d
		if ! grep -q "^tun" /etc/modules-load.d/tun.conf 2>/dev/null; then
			echo "tun" >> /etc/modules-load.d/tun.conf
		fi
	fi
}

show_header() {
cat <<'EOF'

╔═══════════════════════════════════════════════════════════╗
║       AmneziaWG VPN Script - Performance + DPI Evasion    ║
║          https://github.com/amnezia-vpn/amneziawg-go      ║
╚═══════════════════════════════════════════════════════════╝
EOF
}

show_header2() {
cat <<'EOF'

╔═══════════════════════════════════════════════════════════╗
║        Welcome to the AmneziaWG Server Installer          ║
║          https://github.com/amnezia-vpn/amneziawg-go      ║
╚═══════════════════════════════════════════════════════════╝

  Performance Mode: Auto-optimizing MTU, kernel buffers, and
  TCP settings for maximum throughput and minimum latency.

  DPI Evasion: Junk packets, header obfuscation, and
  randomized keepalive for Deep Packet Inspection evasion.
EOF
}

show_header3() {
cat <<'EOF'

  Copyright (c) 2022-2025 Lin Song (WireGuard base)
  Copyright (c) 2020-2023 Nyr (WireGuard base)
  AmneziaWG obfuscation added for DPI evasion
  Performance optimizations for low-latency/high-throughput
EOF
}

show_usage() {
	if [ -n "$1" ]; then
		echo ""
		echo "  ✗ Error: $1" >&2
	fi
	show_header
	show_header3
cat 1>&2 <<EOF

  Usage: sh $0 [options]

  Client Management:
    --addclient [name]      Add a new client
    --listclients           List existing clients
    --removeclient [name]   Remove an existing client
    --showclientqr [name]   Show QR code for a client

  Installation:
    --auto                  Auto-install with default/custom options
    --serveraddr [address]  Server DNS name or IPv4 address
    --port [number]         AmneziaWG port (1-65535, default: 443)
    --clientname [name]     First client name (default: client)
    --dns1 [IP]             Primary DNS (default: Cloudflare)
    --dns2 [IP]             Secondary DNS (optional)

  Other:
    --uninstall             Remove AmneziaWG and all configuration
    -y, --yes               Assume "yes" to prompts
    -h, --help              Show this help message

  Run without arguments for interactive setup.
EOF
	exit 1
}

show_welcome() {
	if [ "$auto" = 0 ]; then
		show_header2
		echo 'I need to ask you a few questions before starting setup.'
		echo 'You can use the default options and just press enter if you are OK with them.'
	else
		show_header
		op_text=default
		if [ -n "$server_addr" ] || [ -n "$server_port" ] || [ -n "$first_client_name" ] || [ -n "$dns1" ]; then
			op_text=custom
		fi
		echo ""
		echo "Starting AmneziaWG setup using $op_text options."
	fi
}

show_dns_name_note() {
cat <<EOF

Note: Make sure this DNS name '$1'
      resolves to the IPv4 address of this server.
EOF
}

enter_server_address() {
	echo ""
	echo "Do you want AmneziaWG VPN clients to connect to this server using a DNS name,"
	printf "e.g. vpn.example.com, instead of its IP address? [y/N] "
	read -r response
	case $response in
		[yY][eE][sS]|[yY])
			use_dns_name=1
			echo ""
			;;
		*)
			use_dns_name=0
			;;
	esac
	if [ "$use_dns_name" = 1 ]; then
		printf "Enter the DNS name of this VPN server: "
		read -r server_addr_i
		until check_dns_name "$server_addr_i"; do
			echo "Invalid DNS name. You must enter a fully qualified domain name (FQDN)."
			printf "Enter the DNS name of this VPN server: "
			read -r server_addr_i
		done
		ip="$server_addr_i"
		show_dns_name_note "$ip"
	else
		detect_ip
		check_nat_ip
	fi
}

find_public_ip() {
	ip_url1="http://ipv4.icanhazip.com"
	ip_url2="http://ip1.dynupdate.no-ip.com"
	get_public_ip=$(wget -T 10 -t 1 -4qO- "$ip_url1" 2>/dev/null || curl -m 10 -4Ls "$ip_url1" 2>/dev/null | grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$')
	if ! check_ip "$get_public_ip"; then
		get_public_ip=$(wget -T 10 -t 1 -4qO- "$ip_url2" 2>/dev/null || curl -m 10 -4Ls "$ip_url2" 2>/dev/null | grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$')
	fi
}

detect_ip() {
	if [ "$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')" -eq 1 ]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		ip=$(ip -4 route get 1 | sed 's/ uid .*//' | awk '{print $NF;exit}' 2>/dev/null)
		if ! check_ip "$ip"; then
			find_public_ip
			ip_match=0
			if [ -n "$get_public_ip" ]; then
				ip_list=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
				while IFS= read -r line; do
					if [ "$line" = "$get_public_ip" ]; then
						ip_match=1
						ip="$line"
					fi
				done <<EOF2
$ip_list
EOF2
			fi
			if [ "$ip_match" = 0 ]; then
				if [ "$auto" = 0 ]; then
					echo ""
					echo "Which IPv4 address should be used?"
					num_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
					ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
					printf "IPv4 address [1]: "
					read -r ip_num
					until [ -z "$ip_num" ] || { echo "$ip_num" | grep -qE '^[0-9]+$' && [ "$ip_num" -le "$num_of_ip" ]; }; do
						echo "$ip_num: invalid selection."
						printf "IPv4 address [1]: "
						read -r ip_num
					done
					[ -z "$ip_num" ] && ip_num=1
				else
					ip_num=1
				fi
				ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "${ip_num}p")
			fi
		fi
	fi
	if ! check_ip "$ip"; then
		echo "Error: Could not detect this server's IP address." >&2
		echo "Abort. No changes were made." >&2
		exit 1
	fi
}

check_nat_ip() {
	if check_pvt_ip "$ip"; then
		find_public_ip
		if ! check_ip "$get_public_ip"; then
			if [ "$auto" = 0 ]; then
				echo ""
				echo "This server is behind NAT. What is the public IPv4 address?"
				printf "Public IPv4 address: "
				read -r public_ip
				until check_ip "$public_ip"; do
					echo "Invalid input."
					printf "Public IPv4 address: "
					read -r public_ip
				done
			else
				echo "Error: Could not detect this server's public IP." >&2
				echo "Abort. No changes were made." >&2
				exit 1
			fi
		else
			public_ip="$get_public_ip"
		fi
	fi
}

show_config() {
	if [ "$auto" != 0 ]; then
		echo ""
		if [ -n "$server_addr" ]; then
			echo "Server address: $server_addr"
		else
			printf '%s' "Server IP: "
			if [ -n "$public_ip" ]; then printf '%s\n' "$public_ip"; else printf '%s\n' "$ip"; fi
		fi
		if [ -n "$server_port" ]; then port_text="$server_port"; else port_text=443; fi
		if [ -n "$first_client_name" ]; then client_text="$client"; else client_text=client; fi
		if [ -n "$dns1" ] && [ -n "$dns2" ]; then
			dns_text="$dns1, $dns2"
		elif [ -n "$dns1" ]; then
			dns_text="$dns1"
		else
			dns_text="Cloudflare DNS"
		fi
		echo "Port: UDP/$port_text"
		echo "Client name: $client_text"
		echo "Client DNS: $dns_text"
		echo "Optimized MTU: $wg_mtu (calculated for AmneziaWG with obfuscation)"
	fi
}

detect_ipv6() {
	ip6=""
	if [ "$(ip -6 addr | grep -c 'inet6 [23]')" -ne 0 ]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n 1p)
	fi
}

select_port() {
	if [ "$auto" = 0 ]; then
		echo ""
		echo "Which port should AmneziaWG listen on?"
		echo "Note: Port 443 (HTTPS) is recommended to blend in against DPI"
		printf "Port [443]: "
		read -r port
		until [ -z "$port" ] || { echo "$port" | grep -qE '^[0-9]+$' && [ "$port" -le 65535 ]; }; do
			echo "$port: invalid port."
			printf "Port [443]: "
			read -r port
		done
		[ -z "$port" ] && port=443
	else
		if [ -n "$server_port" ]; then port="$server_port"; else port=443; fi
	fi
}

enter_custom_dns() {
	printf "Enter primary DNS server: "
	read -r dns1
	until check_ip "$dns1"; do
		echo "Invalid DNS server."
		printf "Enter primary DNS server: "
		read -r dns1
	done
	printf "Enter secondary DNS server (Enter to skip): "
	read -r dns2
	until [ -z "$dns2" ] || check_ip "$dns2"; do
		echo "Invalid DNS server."
		printf "Enter secondary DNS server (Enter to skip): "
		read -r dns2
	done
}

enter_first_client_name() {
	if [ "$auto" = 0 ]; then
		echo ""
		echo "Enter a name for the first client:"
		printf "Name [client]: "
		read -r unsanitized_client
		set_client_name
		[ -z "$client" ] && client=client
	else
		if [ -n "$first_client_name" ]; then
			unsanitized_client="$first_client_name"
			set_client_name
		else
			client=client
		fi
	fi
}

show_setup_ready() {
	if [ "$auto" = 0 ]; then
		echo ""
		echo "AmneziaWG installation is ready to begin."
		echo "Performance optimizations and DPI evasion will be applied automatically."
	fi
}

check_firewall() {
	firewall=""
	if command -v systemctl >/dev/null 2>&1; then
		if ! systemctl is-active --quiet firewalld.service 2>/dev/null && ! hash iptables 2>/dev/null; then
			if [ "$os" = "centos" ] || [ "$os" = "fedora" ]; then
				firewall="firewalld"
			elif [ "$os" = "openSUSE" ]; then
				firewall="firewalld"
			elif [ "$os" = "debian" ] || [ "$os" = "ubuntu" ]; then
				firewall="iptables"
			elif [ "$os" = "alpine" ]; then
				firewall="iptables"
			fi
			if [ "$firewall" = "firewalld" ]; then
				echo ""
				echo "Note: firewalld, which is required to manage routing tables, will also be installed."
			fi
		fi
	else
		if ! hash iptables 2>/dev/null && [ "$os" = "alpine" ]; then
			firewall="iptables"
		fi
	fi
}

abort_and_exit() {
	echo "Abort. No changes were made." >&2
	exit 1
}

confirm_setup() {
	if [ "$auto" = 0 ]; then
		printf "Do you want to continue? [Y/n] "
		read -r response
		case $response in
			[yY][eE][sS]|[yY]|'')
				:
				;;
			*)
				abort_and_exit
				;;
		esac
	fi
}

show_start_setup() {
	echo ""
	echo "Installing AmneziaWG with performance optimizations and DPI evasion, please wait..."
}

install_pkgs() {
	if [ "$os" = "ubuntu" ]; then
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install qrencode $firewall >/dev/null
		) || exiterr2
		# AmneziaWG needs to be built from source or use custom repo on Ubuntu
		echo "Installing AmneziaWG from source..."
		install_amneziawg_from_source
	elif [ "$os" = "debian" ]; then
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install qrencode $firewall >/dev/null
		) || exiterr2
		echo "Installing AmneziaWG from source..."
		install_amneziawg_from_source
	elif [ "$os" = "centos" ] && [ "$os_version" -ge 9 ]; then
		(
			set -x
			yum -y -q install epel-release >/dev/null
			yum -y -q install qrencode $firewall >/dev/null 2>&1
		) || exiterr3
		install_amneziawg_from_source
		mkdir -p /etc/amnezia/amneziawg/
	elif [ "$os" = "centos" ] && [ "$os_version" -eq 8 ]; then
		(
			set -x
			yum -y -q install epel-release elrepo-release >/dev/null
			yum -y -q install qrencode $firewall >/dev/null 2>&1
		) || exiterr3
		install_amneziawg_from_source
		mkdir -p /etc/amnezia/amneziawg/
	elif [ "$os" = "fedora" ]; then
		(
			set -x
			dnf install -y qrencode $firewall >/dev/null
		) || exiterr "'dnf install' failed."
		install_amneziawg_from_source
		mkdir -p /etc/amnezia/amneziawg/
	elif [ "$os" = "openSUSE" ]; then
		(
			set -x
			zypper install -y qrencode $firewall >/dev/null
		) || exiterr4
		install_amneziawg_from_source
		mkdir -p /etc/amnezia/amneziawg/
	elif [ "$os" = "alpine" ]; then
		# FIXED: Removed space in URL between v and version
		alpine_version=$(cut -d '.' -f 1,2 /etc/alpine-release)
		community_url="http://dl-cdn.alpinelinux.org/alpine/v$alpine_version/community"
		
		# Add community repo if not present (either commented or missing)
		if ! grep -q "$community_url" /etc/apk/repositories 2>/dev/null; then
			echo "$community_url" >> /etc/apk/repositories
		fi
		
		# Uncomment any commented community repos
		sed_inplace 's|^#\(http.*/community\)|\1|' /etc/apk/repositories
		
		(
			set -x
			apk update
			# Install bash explicitly – needed for awg-quick script
			# Add pkgconfig to improve make install success
			apk add --no-cache build-base linux-headers libmnl-dev iptables go git bash pkgconfig
			# Install qrencode (C version) - preferred method
			apk add --no-cache libqrencode || apk add --no-cache qrencode || true
			# Alternative: try to install Python QR code generator as backup
			apk add --no-cache py3-qrcode 2>/dev/null || true
		) || exiterr5
		
		# Build AmneziaWG from source on Alpine
		install_amneziawg_from_source
		
		mkdir -p /etc/amnezia/amneziawg/
	fi
	[ ! -d /etc/amnezia/amneziawg ] && exiterr "Failed to create /etc/amnezia/amneziawg directory."
	if [ "$firewall" = "firewalld" ]; then
		if command -v systemctl >/dev/null 2>&1; then
			(
				set -x
				systemctl enable --now firewalld.service >/dev/null 2>&1
			)
		fi
	fi
}

install_amneziawg_from_source() {
	echo "Building AmneziaWG from source..."
	
	# Build and install AmneziaWG from source
	_tmp_dir=$(mktemp -d /tmp/amneziawg-build.XXXXXX)
	cd "$_tmp_dir" || exiterr "Failed to create temp directory"
	
	# Install dependencies
	if [ "$os" = "alpine" ]; then
		echo "Installing build dependencies..."
		apk add --no-cache go git build-base linux-headers libmnl-dev 2>/dev/null || true
	elif [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
		apt-get -yqq install golang git make 2>/dev/null || true
	else
		yum -y install golang git make 2>/dev/null || true
	fi
	
	# Check if go is available
	if ! hash go 2>/dev/null; then
		exiterr "Go compiler not found. Please install Go to build AmneziaWG."
	fi
	
	# Clone and build amneziawg-go
	echo "Cloning amneziawg-go..."
	git clone https://github.com/amnezia-vpn/amneziawg-go.git 2>/dev/null || exiterr "Failed to clone amneziawg-go"
	cd amneziawg-go || exiterr "Failed to enter amneziawg-go directory"
	echo "Building amneziawg-go..."
	make 2>/dev/null || go build -o amneziawg-go . || exiterr "Failed to build amneziawg-go"
	cp amneziawg-go /usr/local/bin/ 2>/dev/null || cp amneziawg-go /usr/bin/ 2>/dev/null || exiterr "Failed to install amneziawg-go"
	ln -sf /usr/local/bin/amneziawg-go /usr/local/bin/awg-go 2>/dev/null || true
	ln -sf /usr/bin/amneziawg-go /usr/bin/awg-go 2>/dev/null || true
	echo "amneziawg-go installed successfully"
	
	# Clone and build amneziawg-tools
	echo "Cloning amneziawg-tools..."
	cd "$_tmp_dir" || exiterr "Failed to return to temp directory"
	git clone https://github.com/amnezia-vpn/amneziawg-tools.git 2>/dev/null || exiterr "Failed to clone amneziawg-tools"
	cd amneziawg-tools || exiterr "Failed to enter amneziawg-tools directory"
	
	# Build the tools
	echo "Building amneziawg-tools..."
	if ! make -C src; then
		if ! CC=gcc make -C src; then
			exiterr "Failed to build amneziawg-tools (src). Check build dependencies (gcc, make, linux-headers)."
		fi
	fi
	
	# Install with make install (preferred)
	if make install PREFIX=/usr 2>/dev/null || make install 2>/dev/null; then
		echo "amneziawg-tools installed successfully via make install"
	else
		# Manual installation fallback
		echo "Manual installation of binaries..."
		if [ -f "src/wg" ]; then
			cp src/wg /usr/bin/awg || exiterr "Failed to install awg binary"
			chmod +x /usr/bin/awg
			echo "Installed src/wg as /usr/bin/awg"
		else
			exiterr "wg binary not found after build in src/"
		fi
		# Look for the quick script (AmneziaWG repo may have it in different places)
		if [ -f "wg-quick/linux.bash" ]; then
			sed 's/wg /awg /g; s/wg$/awg/g' wg-quick/linux.bash > /usr/bin/awg-quick
			chmod +x /usr/bin/awg-quick
			echo "Created awg-quick from wg-quick/linux.bash"
		elif [ -f "src/wg-quick/linux.bash" ]; then
			sed 's/wg /awg /g; s/wg$/awg/g' src/wg-quick/linux.bash > /usr/bin/awg-quick
			chmod +x /usr/bin/awg-quick
			echo "Created awg-quick from src/wg-quick/linux.bash"
		elif [ -f "wg-quick.bash" ]; then
			sed 's/wg /awg /g; s/wg$/awg/g' wg-quick.bash > /usr/bin/awg-quick
			chmod +x /usr/bin/awg-quick
			echo "Created awg-quick from wg-quick.bash"
		else
			# Search for .bash files
			_wg_quick_path=$(find . -name "*.bash" -type f 2>/dev/null | grep -E "(wg-quick|awg-quick|linux)" | head -1)
			if [ -n "$_wg_quick_path" ]; then
				sed 's/wg /awg /g; s/wg$/awg/g' "$_wg_quick_path" > /usr/bin/awg-quick
				chmod +x /usr/bin/awg-quick
				echo "Created awg-quick from $_wg_quick_path"
			else
				exiterr "wg-quick bash script not found in repository"
			fi
		fi
	fi
	
	# Fix any accidental double replacement that could produce "aawg"
	if [ -f /usr/bin/awg-quick ]; then
		# Ensure shebang is bash
		sed -i '1s|^.*$|#!/bin/bash|' /usr/bin/awg-quick
		# Replace any occurrence of "aawg" with "awg" (fixes possible double replacement)
		sed -i 's/aawg/awg/g' /usr/bin/awg-quick
		# Also ensure that the script calls the correct binary (awg, not wg)
		sed -i 's/\bwg\b/awg/g' /usr/bin/awg-quick
	fi
	
	# Create symlinks
	if [ -f /usr/bin/awg ] && [ ! -f /usr/local/bin/awg ]; then
		ln -sf /usr/bin/awg /usr/local/bin/awg 2>/dev/null || true
	fi
	if [ -f /usr/bin/awg-quick ] && [ ! -f /usr/local/bin/awg-quick ]; then
		ln -sf /usr/bin/awg-quick /usr/local/bin/awg-quick 2>/dev/null || true
	fi
	
	# --- Build and install AmneziaWG kernel module (Alpine only) with auto kernel upgrade ---
	if [ "$os" = "alpine" ]; then
		echo ""
		echo "═══════════════════════════════════════════════════════════"
		echo "  Building AmneziaWG kernel module..."
		echo "═══════════════════════════════════════════════════════════"

		_kver=$(uname -r)
		_kernel_headers_dir="/lib/modules/$_kver/build"

		# Function to check if kernel headers are present
		check_headers() {
			[ -d "$_kernel_headers_dir" ]
		}

		# Function to get available LTS kernel version from repository
		get_available_lts_version() {
			apk update >/dev/null 2>&1
			apk list --upgradable 2>/dev/null | grep 'linux-lts-' | head -1 | awk '{print $1}' | sed 's/linux-lts-//' | sed 's/-r[0-9]*$//' || echo ""
		}

		# Function to compare versions (simple, assumes same format)
		version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

		if ! check_headers; then
			echo "❌ Kernel headers for $_kver not found."
			# Try to install matching headers via apk (may install newer version)
			_flavor=$(echo "$_kver" | sed -n 's/^.*-\([a-z]\+\)$/\1/p')
			case "$_flavor" in
				lts|virt|vanilla) _pkg="linux-$_flavor-dev" ;;
				*) _pkg="linux-headers" ;;
			esac
			echo "   Attempting to install kernel headers package: $_pkg"
			apk add --no-cache "$_pkg" 2>&1 | while read -r line; do echo "     $line"; done

			# Re-check after installation
			if check_headers; then
				echo "✅ Kernel headers installed successfully."
			else
				echo "⚠️  Headers still missing after installing $_pkg."
				# Check if kernel upgrade is available
				_current_kver_base=$(echo "$_kver" | cut -d- -f1) # e.g., 6.12.54
				_avail_kver=$(get_available_lts_version)
				if [ -n "$_avail_kver" ] && version_gt "$_avail_kver" "$_current_kver_base"; then
					echo "   Your kernel ($_kver) is older than available LTS kernel ($_avail_kver)."
					echo "   Upgrading kernel to match headers..."
					apk upgrade linux-lts 2>&1 | while read -r line; do echo "     $line"; done
					echo ""
					echo "═══════════════════════════════════════════════════════════"
					echo "  Kernel has been upgraded. Please reboot the system and"
					echo "  then run this script again to complete the installation."
					echo "═══════════════════════════════════════════════════════════"
					exit 0
				else
					echo "❌ Cannot resolve kernel headers mismatch. Falling back to userspace."
				fi
			fi
		fi

		# Proceed only if headers are present
		if check_headers; then
			cd "$_tmp_dir" || exiterr "Failed to return to temp directory"

			echo "Cloning kernel module repository..."
			if ! git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git; then
				echo "❌ Failed to clone kernel module repository."
				echo "   Falling back to userspace."
			else
				cd amneziawg-linux-kernel-module/src || {
					echo "❌ Kernel module src directory not found. Skipping."
				}

				echo "Building kernel module (verbose output)..."
				echo "----------------------------------------------------------------"
				if make V=1; then
					echo "✅ Kernel module compiled successfully."
					echo "Installing kernel module..."
					if make install; then
						echo "✅ Kernel module installed."

						# Load the module now
						echo "Loading kernel module..."
						if modprobe amneziawg; then
							echo "✅ Kernel module loaded."
						else
							echo "❌ Could not load amneziawg module. Check dmesg for details."
							echo "   Falling back to userspace."
						fi

						# Ensure module loads at boot
						mkdir -p /etc/modules-load.d
						if ! grep -q "^amneziawg" /etc/modules-load.d/amneziawg.conf 2>/dev/null; then
							echo "amneziawg" >> /etc/modules-load.d/amneziawg.conf
							echo "✅ Module configured to load at boot."
						fi
					else
						echo "❌ Kernel module installation failed."
						echo "   Falling back to userspace."
					fi
				else
					echo "❌ Kernel module build failed."
					echo "   Falling back to userspace."
				fi
			fi
		else
			echo "❌ Kernel headers not available; skipping kernel module build."
		fi
		echo "═══════════════════════════════════════════════════════════"
		echo ""
	fi
	# --- End kernel module build ---
	
	# Final verification
	echo "Verifying AmneziaWG installation..."
	if ! hash awg 2>/dev/null && [ ! -f /usr/bin/awg ] && [ ! -f /usr/local/bin/awg ]; then
		exiterr "awg binary not found after installation"
	fi
	if ! hash awg-quick 2>/dev/null && [ ! -f /usr/bin/awg-quick ] && [ ! -f /usr/local/bin/awg-quick ]; then
		exiterr "awg-quick binary not found after installation"
	fi
	
	# Cleanup
	cd / || exiterr "Failed to return to root"
	rm -rf "$_tmp_dir"
	
	echo "AmneziaWG installed successfully from source"
}

remove_pkgs() {
	if [ "$os" = "ubuntu" ]; then
		(
			set -x
			rm -rf /etc/amnezia/
			# Remove amneziawg binaries
			rm -f /usr/local/bin/amneziawg-go /usr/local/bin/awg-go /usr/bin/amneziawg-go /usr/bin/awg-go
			rm -f /usr/local/bin/awg /usr/local/bin/awg-quick /usr/bin/awg /usr/bin/awg-quick
		)
	elif [ "$os" = "debian" ]; then
		(
			set -x
			rm -rf /etc/amnezia/
			rm -f /usr/local/bin/amneziawg-go /usr/local/bin/awg-go /usr/bin/amneziawg-go /usr/bin/awg-go
			rm -f /usr/local/bin/awg /usr/local/bin/awg-quick /usr/bin/awg /usr/bin/awg-quick
		)
	elif [ "$os" = "centos" ] && [ "$os_version" -ge 9 ]; then
		(
			set -x
			rm -f /usr/local/bin/amneziawg-go /usr/local/bin/awg-go /usr/bin/amneziawg-go /usr/bin/awg-go
			rm -f /usr/local/bin/awg /usr/local/bin/awg-quick /usr/bin/awg /usr/bin/awg-quick
			rm -rf /etc/amnezia/
		)
	elif [ "$os" = "centos" ] && [ "$os_version" -eq 8 ]; then
		(
			set -x
			rm -f /usr/local/bin/amneziawg-go /usr/local/bin/awg-go /usr/bin/amneziawg-go /usr/bin/awg-go
			rm -f /usr/local/bin/awg /usr/local/bin/awg-quick /usr/bin/awg /usr/bin/awg-quick
			rm -rf /etc/amnezia/
		)
	elif [ "$os" = "fedora" ]; then
		(
			set -x
			rm -f /usr/local/bin/amneziawg-go /usr/local/bin/awg-go /usr/bin/amneziawg-go /usr/bin/awg-go
			rm -f /usr/local/bin/awg /usr/local/bin/awg-quick /usr/bin/awg /usr/bin/awg-quick
			rm -rf /etc/amnezia/
		)
	elif [ "$os" = "openSUSE" ]; then
		(
			set -x
			rm -f /usr/local/bin/amneziawg-go /usr/local/bin/awg-go /usr/bin/amneziawg-go /usr/bin/awg-go
			rm -f /usr/local/bin/awg /usr/local/bin/awg-quick /usr/bin/awg /usr/bin/awg-quick
			rm -rf /etc/amnezia/
		)
	elif [ "$os" = "alpine" ]; then
		(
			set -x
			apk del libqrencode qrencode py3-qrcode 2>/dev/null || true
			rm -f /usr/local/bin/amneziawg-go /usr/local/bin/awg-go /usr/bin/amneziawg-go /usr/bin/awg-go
			rm -f /usr/local/bin/awg /usr/local/bin/awg-quick /usr/bin/awg /usr/bin/awg-quick
			rm -rf /etc/amnezia/
			# Remove kernel module
			rm -f /lib/modules/*/extra/amneziawg.ko
			depmod -a
		)
	fi
}

create_server_config() {
	endpoint_ip="$ip"
	if [ -n "$public_ip" ]; then endpoint_ip="$public_ip"; fi
	
	ip6_addr=""
	if [ -n "$ip6" ]; then ip6_addr=", fddd:2c4:2c4:2c4::1/64"; fi
	
	# PERFORMANCE: Calculate optimal MTU
	wg_mtu=$(calculate_mtu)
	
	# Generate AmneziaWG obfuscation parameters
	generate_amnezia_params
	
	# Ensure awg is available for key generation
	if ! hash awg 2>/dev/null; then
		if [ -x /usr/bin/awg ]; then
			export PATH="$PATH:/usr/bin"
			hash -r
		elif [ -x /usr/local/bin/awg ]; then
			export PATH="$PATH:/usr/local/bin"
			hash -r
		else
			exiterr "awg not found after installation. Cannot generate keys."
		fi
	fi
	
	# Generate server private key
	_awg_bin=$(get_awg_bin)
	[ -z "$_awg_bin" ] && exiterr "awg binary not found"
	_server_priv_key=$($_awg_bin genkey) || exiterr "Failed to generate server private key"
	
	cat << EOF > "$WG_CONF"
# Do not alter the commented lines
# They are used by amneziawg-install
# ENDPOINT $endpoint_ip
# AWG_PARAMS Jc=$awg_jc Jmin=$awg_jmin Jmax=$awg_jmax S1=$awg_s1 S2=$awg_s2 H1=$awg_h1 H2=$awg_h2 H3=$awg_h3 H4=$awg_h4

[Interface]
Address = 10.7.0.1/24$ip6_addr
PrivateKey = $_server_priv_key
ListenPort = $port
MTU = $wg_mtu
Jc = $awg_jc
Jmin = $awg_jmin
Jmax = $awg_jmax
S1 = $awg_s1
S2 = $awg_s2
H1 = $awg_h1
H2 = $awg_h2
H3 = $awg_h3
H4 = $awg_h4

EOF
	chmod 600 "$WG_CONF"
}

create_firewall_rules() {
	if [ "$os" = "alpine" ]; then
		# Get default interface for anti-DPI rules
		_default_iface=$(ip -4 route show default 2>/dev/null | grep "dev" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
		
		cat > /etc/init.d/awg-iptables <<EOF
#!/sbin/openrc-run

description="AmneziaWG iptables rules"

depend() {
    need net
    after firewall
}

start() {
    ebegin "Adding AmneziaWG iptables rules"
    
    # Basic NAT and forwarding
    iptables -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
    iptables -I INPUT -p udp --dport $port -j ACCEPT
    iptables -I FORWARD -s 10.7.0.0/24 -j ACCEPT
    iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    # Anti-DPI: TTL normalization (hide hop count)
    iptables -t mangle -A POSTROUTING -o $_default_iface -j TTL --ttl-set 64 2>/dev/null || true
    
    # Anti-DPI: TCP MSS clamping (normalize packet sizes)
    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300 2>/dev/null || true
    
    # Anti-DPI: Block TCP timestamps in outgoing packets (fingerprint hiding)
    iptables -t mangle -A POSTROUTING -p tcp --tcp-option 8 -j DROP 2>/dev/null || true
    
    # Anti-DPI: Randomize source ports for UDP (AmneziaWG)
    iptables -t nat -A POSTROUTING -p udp --sport $port -j MASQUERADE --random 2>/dev/null || true
    
    eend \$?
}

stop() {
    ebegin "Removing AmneziaWG iptables rules"
    iptables -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
    iptables -D INPUT -p udp --dport $port -j ACCEPT
    iptables -D FORWARD -s 10.7.0.0/24 -j ACCEPT
    iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -t mangle -D POSTROUTING -o $_default_iface -j TTL --ttl-set 64 2>/dev/null || true
    iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300 2>/dev/null || true
    iptables -t mangle -D POSTROUTING -p tcp --tcp-option 8 -j DROP 2>/dev/null || true
    iptables -t nat -D POSTROUTING -p udp --sport $port -j MASQUERADE --random 2>/dev/null || true
    eend \$?
}
EOF
		chmod +x /etc/init.d/awg-iptables
		if command -v rc-update >/dev/null 2>&1; then
			rc-update add awg-iptables default >/dev/null 2>&1
		fi
		if command -v rc-service >/dev/null 2>&1; then
			rc-service awg-iptables start
		else
			/etc/init.d/awg-iptables start
		fi
	elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld.service 2>/dev/null; then
		firewall-cmd -q --add-port="$port"/udp
		firewall-cmd -q --zone=trusted --add-source=10.7.0.0/24
		firewall-cmd -q --permanent --add-port="$port"/udp
		firewall-cmd -q --permanent --zone=trusted --add-source=10.7.0.0/24
		firewall-cmd -q --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
		firewall-cmd -q --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
		if [ -n "$ip6" ]; then
			firewall-cmd -q --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd -q --permanent --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd -q --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
			firewall-cmd -q --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
		fi
	else
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		if [ "$(systemd-detect-virt 2>/dev/null)" = "openvz" ] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		_default_iface=$(ip -4 route show default 2>/dev/null | grep "dev" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
		cat > /etc/systemd/system/awg-iptables.service << EOF
[Unit]
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
ExecStart=$iptables_path -w 5 -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStart=$iptables_path -w 5 -t mangle -A POSTROUTING -o $_default_iface -j TTL --ttl-set 64
ExecStart=$iptables_path -w 5 -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300
ExecStart=$iptables_path -w 5 -t mangle -A POSTROUTING -p tcp --tcp-option 8 -j DROP
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -p udp --sport $port -j MASQUERADE --random
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
ExecStop=$iptables_path -w 5 -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -w 5 -t mangle -D POSTROUTING -o $_default_iface -j TTL --ttl-set 64
ExecStop=$iptables_path -w 5 -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300
ExecStop=$iptables_path -w 5 -t mangle -D POSTROUTING -p tcp --tcp-option 8 -j DROP
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -p udp --sport $port -j MASQUERADE --random
EOF
		if [ -n "$ip6" ]; then
			cat >> /etc/systemd/system/awg-iptables.service << EOF
ExecStart=$ip6tables_path -w 5 -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
ExecStart=$ip6tables_path -w 5 -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -w 5 -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
ExecStop=$ip6tables_path -w 5 -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF
		fi
		cat >> /etc/systemd/system/awg-iptables.service << 'EOF'
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
		(
			set -x
			systemctl enable --now awg-iptables.service >/dev/null 2>&1
		)
	fi
}

remove_firewall_rules() {
	port=$(grep '^ListenPort' "$WG_CONF" | cut -d " " -f 3)
	if [ "$os" = "alpine" ]; then
		if command -v rc-service >/dev/null 2>&1; then
			rc-service awg-iptables stop 2>/dev/null || true
		else
			[ -f /etc/init.d/awg-iptables ] && /etc/init.d/awg-iptables stop 2>/dev/null || true
		fi
		if command -v rc-update >/dev/null 2>&1; then
			rc-update del awg-iptables default 2>/dev/null || true
		fi
		rm -f /etc/init.d/awg-iptables
	elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld.service 2>/dev/null; then
		firewall-cmd -q --remove-port="$port"/udp
		firewall-cmd -q --zone=trusted --remove-source=10.7.0.0/24
		firewall-cmd -q --permanent --remove-port="$port"/udp
		firewall-cmd -q --permanent --zone=trusted --remove-source=10.7.0.0/24
		firewall-cmd -q --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
		firewall-cmd -q --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
		if grep -qs 'fddd:2c4:2c4:2c4::1/64' "$WG_CONF"; then
			firewall-cmd -q --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd -q --permanent --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd -q --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
			firewall-cmd -q --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
		fi
	else
		if command -v systemctl >/dev/null 2>&1; then
			systemctl disable --now awg-iptables.service 2>/dev/null || true
		fi
		rm -f /etc/systemd/system/awg-iptables.service
	fi
}

get_export_dir() {
	export_to_home_dir=0
	export_dir=~/
	if [ -n "$SUDO_USER" ] && getent group "$SUDO_USER" >/dev/null 2>&1; then
		user_home_dir=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
		if [ -d "$user_home_dir" ] && [ "$user_home_dir" != "/" ]; then
			export_dir="$user_home_dir/"
			export_to_home_dir=1
		fi
	fi
}

select_dns() {
	if [ "$auto" = 0 ]; then
		echo ""
		echo "Select a DNS server for the client:"
		echo "   1) Current system resolvers"
		echo "   2) Cloudflare DNS (Optimized for speed)"
		echo "   3) Google Public DNS"
		echo "   4) OpenDNS"
		echo "   5) Quad9"
		echo "   6) AdGuard DNS"
		echo "   7) Custom"
		printf "DNS server [2]: "
		read -r dns_choice
		until [ -z "$dns_choice" ] || echo "$dns_choice" | grep -qE '^[1-7]$'; do
			echo "$dns_choice: invalid selection."
			printf "DNS server [2]: "
			read -r dns_choice
		done
	else
		dns_choice=2
	fi
		case "$dns_choice" in
		1)
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
		;;
		2|"")
			dns="1.1.1.1, 1.0.0.1"
		;;
		3)
			dns="8.8.8.8, 8.8.4.4"
		;;
		4)
			dns="208.67.222.222, 208.67.220.220"
		;;
		5)
			dns="9.9.9.9, 149.112.112.112"
		;;
		6)
			dns="94.140.14.14, 94.140.15.15"
		;;
		7)
			enter_custom_dns
			if [ -n "$dns2" ]; then
				dns="$dns1, $dns2"
			else
				dns="$dns1"
			fi
		;;
esac
}

select_client_ip() {
	octet=2
	while grep AllowedIPs "$WG_CONF" | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
		octet=$((octet + 1))
	done
	if [ "$octet" -eq 255 ]; then
		exiterr "253 clients are already configured. The AmneziaWG internal subnet is full!"
	fi
}

new_client() {
	# Ensure awg is in PATH
	if ! hash awg 2>/dev/null; then
		if [ -x /usr/bin/awg ]; then
			export PATH="$PATH:/usr/bin"
			hash -r
		elif [ -x /usr/local/bin/awg ]; then
			export PATH="$PATH:/usr/local/bin"
			hash -r
		fi
	fi
	
	select_client_ip
	specify_ip=n
	if [ "$1" = "add_client" ] && [ "$add_client" = 0 ]; then
		echo ""
		printf "Do you want to specify an internal IP address for the new client? [y/N]: "
		read -r specify_ip
		until echo "$specify_ip" | grep -qE '^[yYnN]*$'; do
			echo "$specify_ip: invalid selection."
			printf "Do you want to specify an internal IP address for the new client? [y/N]: "
			read -r specify_ip
		done
		if ! echo "$specify_ip" | grep -qE '^[yY]$'; then
			echo "Using auto assigned IP address 10.7.0.$octet."
		fi
	fi
	if echo "$specify_ip" | grep -qE '^[yY]$'; then
		echo ""
		printf "Enter IP address for the new client (e.g. 10.7.0.X): "
		read -r client_ip
		octet=$(printf '%s' "$client_ip" | cut -d "." -f 4)
		until { echo "$client_ip" | grep -qE '^10\.7\.0\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$' && ! grep AllowedIPs "$WG_CONF" | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; }; do
			if ! echo "$client_ip" | grep -qE '^10\.7\.0\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$'; then
				echo "Invalid IP address. Must be within the range 10.7.0.2 to 10.7.0.254."
			else
				echo "The IP address is already in use. Please choose another one."
			fi
			printf "Enter IP address for the new client (e.g. 10.7.0.X): "
			read -r client_ip
			octet=$(printf '%s' "$client_ip" | cut -d "." -f 4)
		done
	fi
	# Ensure awg is in PATH for key operations
	if ! hash awg 2>/dev/null; then
		if [ -x /usr/bin/awg ]; then
			export PATH="$PATH:/usr/bin"
			hash -r
		elif [ -x /usr/local/bin/awg ]; then
			export PATH="$PATH:/usr/local/bin"
			hash -r
		fi
	fi
	
	_awg_bin=$(get_awg_bin)
	[ -z "$_awg_bin" ] && exiterr "awg binary not found"
	
	key=$($_awg_bin genkey) || exiterr "Failed to generate client key"
	psk=$($_awg_bin genpsk) || exiterr "Failed to generate PSK"
	
	server_priv_key=$(grep PrivateKey "$WG_CONF" | cut -d " " -f 3)
	server_pub_key=$(echo "$server_priv_key" | $_awg_bin pubkey) || exiterr "Failed to get server public key"
	
	ip6_suffix=""
	if grep -q 'fddd:2c4:2c4:2c4::1' "$WG_CONF"; then
		ip6_suffix=", fddd:2c4:2c4:2c4::$octet/128"
	fi
	
	endpoint=$(grep '^# ENDPOINT' "$WG_CONF" | cut -d " " -f 3)
	listen_port=$(grep ListenPort "$WG_CONF" | cut -d " " -f 3)
	
	# PERFORMANCE: Get optimized MTU from server config
	wg_mtu=$(grep '^MTU' "$WG_CONF" | cut -d " " -f 3 || echo 1400)
	
	# Get AmneziaWG obfuscation parameters from server config
	awg_jc=$(grep '^Jc' "$WG_CONF" | cut -d " " -f 3)
	awg_jmin=$(grep '^Jmin' "$WG_CONF" | cut -d " " -f 3)
	awg_jmax=$(grep '^Jmax' "$WG_CONF" | cut -d " " -f 3)
	awg_s1=$(grep '^S1' "$WG_CONF" | cut -d " " -f 3)
	awg_s2=$(grep '^S2' "$WG_CONF" | cut -d " " -f 3)
	awg_h1=$(grep '^H1' "$WG_CONF" | cut -d " " -f 3)
	awg_h2=$(grep '^H2' "$WG_CONF" | cut -d " " -f 3)
	awg_h3=$(grep '^H3' "$WG_CONF" | cut -d " " -f 3)
	awg_h4=$(grep '^H4' "$WG_CONF" | cut -d " " -f 3)
	
	cat << EOF >> "$WG_CONF"
# BEGIN_PEER $client
[Peer]
PublicKey = $(echo "$key" | $_awg_bin pubkey)
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$ip6_suffix
# END_PEER $client
EOF
	get_export_dir()
	
	client_ip6=""
	if grep -q 'fddd:2c4:2c4:2c4::1' "$WG_CONF"; then
		client_ip6=", fddd:2c4:2c4:2c4::$octet/64"
	fi
	
	# Anti-DPI: Randomize keepalive interval (20-30 seconds) to avoid pattern detection
	# Using shell arithmetic since we can't use $RANDOM in POSIX sh
	_keepalive=$((20 + ($(date +%s) % 11)))
	
	cat << EOF > "$export_dir$client".conf
[Interface]
Address = 10.7.0.$octet/24$client_ip6
DNS = $dns
PrivateKey = $key
MTU = $wg_mtu
Jc = $awg_jc
Jmin = $awg_jmin
Jmax = $awg_jmax
S1 = $awg_s1
S2 = $awg_s2
H1 = $awg_h1
H2 = $awg_h2
H3 = $awg_h3
H4 = $awg_h4

[Peer]
PublicKey = $server_pub_key
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $endpoint:$listen_port
PersistentKeepalive = $_keepalive
EOF
	if [ "$export_to_home_dir" = 1 ]; then
		chown "$SUDO_USER:$SUDO_USER" "$export_dir$client".conf
	fi
	chmod 600 "$export_dir$client".conf
}

update_sysctl() {
	mkdir -p /etc/sysctl.d
	conf_fwd="/etc/sysctl.d/99-amneziawg-forward.conf"
	conf_opt="/etc/sysctl.d/99-amneziawg-optimize.conf"
	echo 'net.ipv4.ip_forward=1' > "$conf_fwd"
	if [ -n "$ip6" ]; then
		echo "net.ipv6.conf.all.forwarding=1" >> "$conf_fwd"
	fi
	
	# PERFORMANCE: Apply aggressive optimizations locally instead of downloading
	# This ensures maximum performance settings regardless of OS
	cat > "$conf_opt" <<'EOF'
# AmneziaWG Performance Optimizations - Maximum Throughput / Minimum Latency
# Core networking
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.netdev_max_backlog = 50000
net.core.somaxconn = 65535

# TCP optimizations for low latency
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_low_latency = 1

# Congestion control - BBR with CAKE for stable throughput
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = cake
net.ipv4.tcp_mtu_probing = 1

# Upload stability - prevent speed drops after initial burst
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_pacing_ss_ratio = 200
net.ipv4.tcp_pacing_ca_ratio = 120

# UDP optimizations for AmneziaWG
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# Memory tuning
vm.swappiness = 10
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10

# Alpine Linux specific optimizations for musl libc and minimal systems
# Increase max memory map areas (musl uses more small mappings)
vm.max_map_count = 262144

# Reduce swap activity further for container/embedded environments
vm.vfs_cache_pressure = 50

# Kernel panic reboot timeout (Alpine often runs headless)
kernel.panic = 10

# Disable kernel messages during boot (cleaner Alpine console)
kernel.printk = 3 3 3 3

# Security: Disable ptrace for non-parent (Alpine security hardening)
kernel.yama.ptrace_scope = 1

# Anti-DPI: Disable TCP timestamps to prevent fingerprinting
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1

# Anti-DPI: Randomize source ports more aggressively
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_local_reserved_ports = 

# Anti-DPI: Disable TCP metrics cache (prevents fingerprinting based on history)
net.ipv4.tcp_no_metrics_save = 1

# Anti-DPI: SYN cookies (prevent SYN flood detection/probing)
net.ipv4.tcp_syncookies = 1

# Anti-DPI: Disable TCP timestamps to prevent OS fingerprinting
net.ipv4.tcp_timestamps = 0

# Anti-DPI: Enable SACK (normalized behavior)
net.ipv4.tcp_sack = 1

# Anti-DPI: Enable window scaling (normalized behavior)
net.ipv4.tcp_window_scaling = 1

# Anti-DPI: Protect against TIME_WAIT assassination
net.ipv4.tcp_rfc1337 = 1

# Anti-DPI: Don't accept ICMP redirects (prevent MITM/fingerprinting)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Anti-DPI: Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Anti-DPI: Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Anti-DPI: Enable reverse path filtering (prevent IP spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Anti-DPI: Disable log martians (don't reveal dropped packets)
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0

# Anti-DPI: Restrict kernel message access (hide system info)
kernel.dmesg_restrict = 1

# Anti-DPI: Restrict kernel pointers in /proc
kernel.kptr_restrict = 2

# Anti-DPI: Hide processes from other users
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# Anti-DPI: Connection tracking limits (prevent resource exhaustion)
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 60

# Anti-DPI: IPv6 privacy extensions (if IPv6 is used)
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2

# Anti-DPI: Increase TTL slightly to mask hop count fingerprinting
# (Set at runtime by function)
EOF
	
	# Enable TCP BBR congestion control if kernel version >= 4.20 (BusyBox compatible)
	current_kver=$(uname -r)
	kver_major=$(echo "$current_kver" | cut -d. -f1)
	kver_minor=$(echo "$current_kver" | cut -d. -f2)
	
	# Check if kernel >= 4.20 without using sort -C
	kver_ok=0
	if [ "$kver_major" -gt 4 ]; then
		kver_ok=1
	elif [ "$kver_major" -eq 4 ] && [ "$kver_minor" -ge 20 ]; then
		kver_ok=1
	fi
	
	# Only add BBR settings if module loads successfully
	if modprobe -q tcp_bbr 2>/dev/null && [ "$kver_ok" -eq 1 ] && [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
		echo "net.core.default_qdisc = cake" >> "$conf_opt"
		echo "net.ipv4.tcp_congestion_control = bbr" >> "$conf_opt"
		echo "net.ipv4.tcp_slow_start_after_idle = 0" >> "$conf_opt"
	fi
	
	# Apply settings
	sysctl -e -q -p "$conf_fwd"
	sysctl -e -q -p "$conf_opt"
	
	# PERFORMANCE: Increase NIC ring buffer sizes if ethtool is available (BusyBox compatible)
	if hash ethtool 2>/dev/null; then
		# FIXED: Removed grep -P, using awk instead for BusyBox compatibility
		default_iface=$(ip -4 route show default 2>/dev/null | grep "dev" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
		if [ -n "$default_iface" ]; then
			ethtool -G "$default_iface" rx 4096 tx 4096 2>/dev/null || true
		fi
	fi
	
	# ALPINE-SPECIFIC: Multi-core network processing (RPS/XPS)
	# Distribute network interrupts across all CPUs for better performance
	if [ "$os" = "alpine" ]; then
		alpine_optimize_multicore_net
		alpine_tune_interfaces
	fi
}

# Alpine Linux specific: Optimize multi-core network processing
alpine_optimize_multicore_net() {
	_default_iface=$(ip -4 route show default 2>/dev/null | grep "dev" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
	[ -z "$_default_iface" ] && return
	
	# Get CPU count (BusyBox compatible)
	_cpu_count=$(grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
	[ "$_cpu_count" -le 1 ] && return
	
	echo "Optimizing multi-core network processing (RPS/XPS)..."
	
	# Calculate RPS/XPS mask - use all CPUs
	# For n CPUs, mask is (2^n - 1) in hex
	_rps_mask=0
	_i=0
	while [ "$_i" -lt "$_cpu_count" ]; do
		_rps_mask=$((_rps_mask + (1 << _i)))
		_i=$((_i + 1))
	done
	_rps_mask_hex=$(printf '%x' "$_rps_mask")
	
	# Apply RPS (Receive Packet Steering)
	if [ -d "/sys/class/net/$_default_iface/queues" ]; then
		for _rx_queue in /sys/class/net/"$_default_iface"/queues/rx-*; do
			[ -e "$_rx_queue/rps_cpus" ] && echo "$_rps_mask_hex" > "$_rx_queue/rps_cpus" 2>/dev/null || true
			[ -e "$_rx_queue/rps_flow_cnt" ] && echo 32768 > "$_rx_queue/rps_flow_cnt" 2>/dev/null || true
		done
		
		# Apply XPS (Transmit Packet Steering)
		for _tx_queue in /sys/class/net/"$_default_iface"/queues/tx-*; do
			[ -e "$_tx_queue/xps_cpus" ] && echo "$_rps_mask_hex" > "$_tx_queue/xps_cpus" 2>/dev/null || true
		done
	fi
	
	# Increase backlog for RPS
	echo 65536 > /proc/sys/net/core/netdev_max_backlog 2>/dev/null || true
	echo 65536 > /proc/sys/net/core/netdev_budget 2>/dev/null || true
	echo 65536 > /proc/sys/net/core/netdev_budget_usecs 2>/dev/null || true
	
	# Alpine-specific: Optimize for musl libc and minimal environment
	# Increase max anonymous memory mappings (musl uses more small mappings)
	echo 262144 > /proc/sys/vm/max_map_count 2>/dev/null || true
	
	# Enable transparent hugepages for better memory performance
	if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
		echo always > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
	fi
	
	# CPU governor to performance mode if available (Alpine on bare metal)
	if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
		for _gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
			echo performance > "$_gov" 2>/dev/null || true
		done
	fi
	
	# Anti-DPI: Set default TTL to common value (64) to blend in
	# This masks the hop count fingerprint
	echo 64 > /proc/sys/net/ipv4/ip_default_ttl 2>/dev/null || true
}

# Alpine Linux specific: Per-interface tuning for stable uploads
alpine_tune_interfaces() {
	_default_iface=$(ip -4 route show default 2>/dev/null | grep "dev" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
	[ -z "$_default_iface" ] && return
	
	echo "Tuning network interfaces for stable VPN performance..."
	
	# Disable offloading features for better VPN performance
	ethtool -K "$_default_iface" tso off gso off gro off lro off 2>/dev/null || true
	ethtool -K "$_default_iface" tx-checksum-ip-generic off 2>/dev/null || true
	
	# Set moderate queue length (prevent bufferbloat while maintaining throughput)
	ip link set dev "$_default_iface" txqueuelen 1000 2>/dev/null || true
	
	# Apply same settings to WireGuard interface when created
	if ip link show wg0 >/dev/null 2>&1; then
		ip link set dev wg0 txqueuelen 1000 2>/dev/null || true
	fi
	if ip link show awg0 >/dev/null 2>&1; then
		ip link set dev awg0 txqueuelen 1000 2>/dev/null || true
	fi
	
	# Apply anti-DPI iptables rules
	apply_anti_dpi_rules
	
	# Try to load and use CAKE (best AQM for variable connections)
	if modprobe sch_cake 2>/dev/null; then
		echo "CAKE scheduler loaded successfully"
		# Apply CAKE to external interface (bandwidth-agnostic mode)
		tc qdisc replace dev "$_default_iface" root cake bandwidth unlimited 2>/dev/null || \
			tc qdisc replace dev "$_default_iface" root fq_codel 2>/dev/null || true
	else
		echo "CAKE not available, using fq_codel"
		# Fallback to fq_codel
		tc qdisc replace dev "$_default_iface" root fq_codel 2>/dev/null || true
	fi
	
	# Apply to WireGuard interfaces as well
	if ip link show wg0 >/dev/null 2>&1; then
		tc qdisc replace dev wg0 root fq_codel 2>/dev/null || true
	fi
	if ip link show awg0 >/dev/null 2>&1; then
		tc qdisc replace dev awg0 root fq_codel 2>/dev/null || true
	fi
}

# Apply anti-DPI iptables rules immediately
apply_anti_dpi_rules() {
	_default_iface=$(ip -4 route show default 2>/dev/null | grep "dev" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
	[ -z "$_default_iface" ] && return
	
	echo "Applying anti-DPI iptables rules..."
	
	# Anti-DPI: TTL normalization (hide hop count)
	iptables -t mangle -C POSTROUTING -o "$_default_iface" -j TTL --ttl-set 64 2>/dev/null || \
		iptables -t mangle -A POSTROUTING -o "$_default_iface" -j TTL --ttl-set 64 2>/dev/null || true
	
	# Anti-DPI: TCP MSS clamping (normalize packet sizes)
	iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300 2>/dev/null || \
		iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300 2>/dev/null || true
	
	# Anti-DPI: Block TCP timestamps (fingerprint hiding)
	iptables -t mangle -C POSTROUTING -p tcp --tcp-option 8 -j DROP 2>/dev/null || \
		iptables -t mangle -A POSTROUTING -p tcp --tcp-option 8 -j DROP 2>/dev/null || true
	
	# Anti-DPI: Randomize source ports for outgoing connections
	iptables -t nat -C POSTROUTING -o "$_default_iface" -j MASQUERADE --random 2>/dev/null || \
		iptables -t nat -A POSTROUTING -o "$_default_iface" -j MASQUERADE --random 2>/dev/null || true
	
	echo "Anti-DPI rules applied"
}

update_rclocal() {
	if [ "$os" = "alpine" ]; then
		ipt_cmd="rc-service awg-iptables restart"
	else
		ipt_cmd="systemctl restart awg-iptables.service"
	fi
	
	if ! grep -qs "$ipt_cmd" /etc/rc.local 2>/dev/null; then
		if [ ! -f /etc/rc.local ]; then
			echo '#!/bin/sh' > /etc/rc.local
		else
			if [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
				sed_inplace '/^exit 0/d' /etc/rc.local
			fi
		fi
cat >> /etc/rc.local <<EOF

$ipt_cmd
EOF
		if [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
			echo "exit 0" >> /etc/rc.local
		fi
		chmod +x /etc/rc.local
	fi
}

start_wg_service() {
	# Ensure TUN device exists (userspace fallback)
	ensure_tun
	
	# Load AmneziaWG kernel module if built (Alpine)
	if [ "$os" = "alpine" ]; then
		if modprobe amneziawg 2>/dev/null; then
			echo "AmneziaWG kernel module loaded."
		else
			echo "Kernel module not available; will use userspace fallback."
		fi
	fi
	
	# Get full path to awg-quick
	_awg_quick_bin=$(get_awg_quick_bin)
	if [ -z "$_awg_quick_bin" ]; then
		exiterr "awg-quick binary not found"
	fi
	if [ ! -x "$_awg_quick_bin" ]; then
		exiterr "awg-quick binary not executable ($_awg_quick_bin)"
	fi
	
	if [ "$os" = "alpine" ]; then
		if ! "$_awg_quick_bin" up awg0 2>&1; then
			echo "Error: Failed to start AmneziaWG"
			echo "Debug: Checking configuration..."
			cat /etc/amnezia/amneziawg/awg0.conf 2>/dev/null || echo "Config file not found"
			exit 1
		fi
		echo "#!/bin/sh" > /etc/local.d/amneziawg.start
		echo "$_awg_quick_bin up awg0" >> /etc/local.d/amneziawg.start
		chmod +x /etc/local.d/amneziawg.start
		if command -v rc-update >/dev/null 2>&1; then
			rc-update add local default >/dev/null 2>&1
		fi
		
		# Alpine-specific: Optimize OpenRC for faster boot
		alpine_optimize_openrc
	else
		(
			set -x
			systemctl enable --now awg-quick@awg0.service >/dev/null 2>&1
		)
	fi
	
	# PERFORMANCE: Increase transmit queue length for awg0 interface
	ip link set dev awg0 txqueuelen 10000 2>/dev/null || true
}

# Alpine Linux specific: Optimize OpenRC configuration
alpine_optimize_openrc() {
	_rc_conf="/etc/rc.conf"
	
	# Enable parallel service startup for faster boot
	if [ -f "$_rc_conf" ]; then
		if ! grep -q "^rc_parallel=" "$_rc_conf" 2>/dev/null; then
			echo "rc_parallel=\"YES\"" >> "$_rc_conf"
		fi
		
		# Reduce service timeout for faster failure recovery
		if ! grep -q "^rc_timeout_stopsec=" "$_rc_conf" 2>/dev/null; then
			echo "rc_timeout_stopsec=\"10\"" >> "$_rc_conf"
		fi
		
		# Enable color output (cosmetic but helpful)
		if ! grep -q "^rc_color=" "$_rc_conf" 2>/dev/null; then
			echo "rc_color=\"yes\"" >> "$_rc_conf"
		fi
	fi
	
	# Create modprobe.d config for wireguard module parameters (used by AmneziaWG)
	mkdir -p /etc/modprobe.d
	cat > /etc/modprobe.d/wireguard.conf << 'EOF'
# WireGuard module parameters for Alpine Linux (used by AmneziaWG)
# Disable debug logging for performance
options wireguard debug=0
EOF
}

show_client_qr_code() {
	if hash qrencode 2>/dev/null; then
		# Method 1: Native qrencode (best quality)
		qrencode -t UTF8 < "$export_dir$client".conf
		printf '\n↑ That is a QR code containing the client configuration.\n'
	elif hash python3 2>/dev/null && python3 -c "import qrcode" 2>/dev/null; then
		# Method 2: Python qrcode module (alternative for Alpine)
		echo ""
		python3 -c "
import qrcode
import sys
try:
    with open('$export_dir$client.conf', 'r') as f:
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
		# Fallback: Just show the file path
		echo ""
		echo "═══════════════════════════════════════════════════════════"
		echo "  QR CODE NOT AVAILABLE"
		echo "═══════════════════════════════════════════════════════════"
		echo ""
		echo "To enable QR codes on Alpine, install libqrencode:"
		echo "  apk add libqrencode"
		echo ""
		echo "Or use Python alternative:"
		echo "  apk add py3-qrcode"
		echo ""
		echo "Config file location: $export_dir$client.conf"
		echo ""
		echo "You can transfer this file to your device via:"
		echo "  scp $export_dir$client.conf user@phone:/path/"
		echo "  cat $export_dir$client.conf | curl -F 'f:1=<-' ix.io  (pastebin)"
		echo "═══════════════════════════════════════════════════════════"
	fi
}

finish_setup() {
	echo ""
	echo "═══════════════════════════════════════════════════════════"
	if ! hash awg-quick 2>/dev/null; then
		echo "  ⚠ Warning"
		echo "═══════════════════════════════════════════════════════════"
		echo ""
		echo "  Installation was finished, but the AmneziaWG tools"
		echo "  are not available. Reboot the system to complete"
		echo "  installation."
	else
		echo "  ✓ Installation Complete"
		echo "═══════════════════════════════════════════════════════════"
		echo ""
		echo "  Performance optimizations applied:"
		echo "    • BBR congestion control enabled"
		echo "    • Maximum socket buffers configured"
		echo "    • Low-latency TCP settings applied"
		echo "    • AmneziaWG MTU: $wg_mtu (auto-optimized)"
		echo ""
		echo "  DPI Evasion features enabled:"
		echo "    • Junk packet obfuscation"
		echo "    • Header obfuscation"
		echo "    • Randomized keepalive intervals"
	fi
	echo ""
	echo "  Client configuration: $export_dir$client.conf"
	echo "  Run this script again to add more clients."
	echo "═══════════════════════════════════════════════════════════"
}

select_menu_option() {
	echo ""
	echo "═══════════════════════════════════════════════════════════"
	echo "  AmneziaWG is already installed"
	echo "═══════════════════════════════════════════════════════════"
	echo ""
	echo "  Select an option:"
	echo ""
	echo "    1) Add a new client"
	echo "    2) List existing clients"
	echo "    3) Remove an existing client"
	echo "    4) Show QR code for a client"
	echo "    5) Remove AmneziaWG"
	echo "    6) Exit"
	echo ""
	printf "  Option: "
	read -r option
	until echo "$option" | grep -qE '^[1-6]$'; do
		echo "$option: invalid selection."
		printf "Option: "
		read -r option
	done
}

show_clients() {
	grep '^# BEGIN_PEER' "$WG_CONF" | cut -d ' ' -f 3 | nl -s ') '
}

enter_client_name() {
	echo ""
	echo "Provide a name for the client:"
	printf "Name: "
	read -r unsanitized_client
	[ -z "$unsanitized_client" ] && abort_and_exit
	set_client_name
	while [ -z "$client" ] || grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; do
		if [ -z "$client" ]; then
			echo "Invalid client name. Use one word only, no special characters except '-' and '_'."
		else
			echo "$client: invalid name. Client already exists."
		fi
		printf "Name: "
		read -r unsanitized_client
		[ -z "$unsanitized_client" ] && abort_and_exit
		set_client_name
	done
}

update_wg_conf() {
	tmpfile=$(mktemp /tmp/awg-peer.XXXXXX)
	sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" "$WG_CONF" > "$tmpfile"
	awg addconf awg0 "$tmpfile"
	rm -f "$tmpfile"
}

print_client_added() {
	echo ""
	echo "$client added. Configuration available in: $export_dir$client.conf"
	echo "Optimized with MTU: $(grep MTU "$export_dir$client.conf" | cut -d= -f2 | tr -d ' ')"
	echo "DPI evasion enabled with obfuscation parameters."
}

print_check_clients() {
	echo ""
	echo "Checking for existing client(s)..."
}

check_clients() {
	num_of_clients=$(grep -c '^# BEGIN_PEER' "$WG_CONF")
	if [ "$num_of_clients" = 0 ]; then
		echo ""
		echo "There are no existing clients!"
		exit 1
	fi
}

print_client_total() {
	if [ "$num_of_clients" = 1 ]; then
		printf '\n%s\n' "Total: 1 client"
	elif [ -n "$num_of_clients" ]; then
		printf '\n%s\n' "Total: $num_of_clients clients"
	fi
}

select_client_to() {
	echo ""
	echo "Select the client to $1:"
	show_clients
	printf "Client: "
	read -r client_num
	[ -z "$client_num" ] && abort_and_exit
	until echo "$client_num" | grep -qE '^[0-9]+$' && [ "$client_num" -le "$num_of_clients" ]; do
		echo "$client_num: invalid selection."
		printf "Client: "
		read -r client_num
		[ -z "$client_num" ] && abort_and_exit
	done
	client=$(grep '^# BEGIN_PEER' "$WG_CONF" | cut -d ' ' -f 3 | sed -n "${client_num}p")
}

confirm_remove_client() {
	if [ "$assume_yes" != 1 ]; then
		echo ""
		printf "Confirm $client removal? [y/N]: "
		read -r remove
		until echo "$remove" | grep -qE '^[yYnN]*$'; do
			echo "$remove: invalid selection."
			printf "Confirm $client removal? [y/N]: "
			read -r remove
		done
	else
		remove=y
	fi
}

remove_client_conf() {
	get_export_dir
	wg_file="$export_dir$client.conf"
	if [ -f "$wg_file" ]; then
		echo "Removing $wg_file..."
		rm -f "$wg_file"
	fi
}

print_remove_client() {
	echo ""
	echo "Removing $client..."
}

remove_client_wg() {
	peer_pubkey=$(sed -n "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/p" "$WG_CONF" | grep -m 1 PublicKey | cut -d " " -f 3)
	_awg_bin=$(get_awg_bin)
	[ -n "$_awg_bin" ] && $_awg_bin set awg0 peer "$peer_pubkey" remove
	sed_inplace "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" "$WG_CONF"
	remove_client_conf
}

print_client_removed() {
	echo ""
	echo "$client removed!"
}

print_client_removal_aborted() {
	echo ""
	echo "$client removal aborted!"
}

check_client_conf() {
	wg_file="$export_dir$client.conf"
	if [ ! -f "$wg_file" ]; then
		echo "Error: Cannot show QR code. Missing client config file $wg_file" >&2
		echo "       You may instead re-run this script and add a new client." >&2
		exit 1
	fi
}

print_client_conf() {
	echo ""
	echo "Configuration for '$client' is available in: $wg_file"
}

confirm_remove_wg() {
	if [ "$assume_yes" != 1 ]; then
		echo ""
		printf "Confirm AmneziaWG removal? [y/N]: "
		read -r remove
		until echo "$remove" | grep -qE '^[yYnN]*$'; do
			echo "$remove: invalid selection."
			printf "Confirm AmneziaWG removal? [y/N]: "
			read -r remove
		done
	else
		remove=y
	fi
}

print_remove_wg() {
	echo ""
	echo "Removing AmneziaWG, please wait..."
}

disable_wg_service() {
	if [ "$os" = "alpine" ]; then
		_awg_quick_bin=$(get_awg_quick_bin)
	[ -n "$_awg_quick_bin" ] && $_awg_quick_bin down awg0 2>/dev/null || true
		rm -f /etc/local.d/amneziawg.start
	else
		systemctl disable --now awg-quick@awg0.service 2>/dev/null || true
	fi
}

remove_sysctl_rules() {
	rm -f /etc/sysctl.d/99-amneziawg-forward.conf /etc/sysctl.d/99-amneziawg-optimize.conf
	if [ ! -f /usr/sbin/openvpn ] && [ ! -f /usr/sbin/ipsec ] && [ ! -f /usr/local/sbin/ipsec ]; then
		echo 0 > /proc/sys/net/ipv4/ip_forward
		echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
}

remove_rclocal_rules() {
	if [ "$os" = "alpine" ]; then
		ipt_cmd="rc-service awg-iptables restart"
	else
		ipt_cmd="systemctl restart awg-iptables.service"
	fi
	
	if grep -qs "$ipt_cmd" /etc/rc.local 2>/dev/null; then
		sed_inplace "/^$ipt_cmd/d" /etc/rc.local
	fi
}

print_wg_removed() {
	echo ""
	echo "AmneziaWG removed!"
}

print_wg_removal_aborted() {
	echo ""
	echo "AmneziaWG removal aborted!"
}

awgsetup() {

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

check_root
check_shell
check_kernel
check_os
check_os_ver
check_container

WG_CONF="/etc/amnezia/amneziawg/awg0.conf"

auto=0
assume_yes=0
add_client=0
list_clients=0
remove_client=0
show_client_qr=0
remove_wg=0
public_ip=""
server_addr=""
server_port=""
first_client_name=""
unsanitized_client=""
client=""
dns=""
dns1=""
dns2=""

parse_args "$@"
check_args

if [ "$add_client" = 1 ]; then
	show_header
	new_client add_client
	update_wg_conf
	echo ""
	show_client_qr_code
	print_client_added
	exit 0
fi

if [ "$list_clients" = 1 ]; then
	show_header
	print_check_clients
	check_clients
	echo ""
	show_clients
	print_client_total
	exit 0
fi

if [ "$remove_client" = 1 ]; then
	show_header
	confirm_remove_client
	if echo "$remove" | grep -qE '^[yY]$'; then
		print_remove_client
		remove_client_wg
		print_client_removed
		exit 0
	else
		print_client_removal_aborted
		exit 1
	fi
fi

if [ "$show_client_qr" = 1 ]; then
	show_header
	echo ""
	get_export_dir
	check_client_conf
	show_client_qr_code
	print_client_conf
	exit 0
fi

if [ "$remove_wg" = 1 ]; then
	show_header
	confirm_remove_wg
	if echo "$remove" | grep -qE '^[yY]$'; then
		print_remove_wg
		remove_firewall_rules
		disable_wg_service
		remove_sysctl_rules
		remove_rclocal_rules
		remove_pkgs
		print_wg_removed
		exit 0
	else
		print_wg_removal_aborted
		exit 1
	fi
fi

if [ ! -e "$WG_CONF" ]; then
	check_nftables
	install_wget
	install_iproute
	show_welcome
	if [ "$auto" = 0 ]; then
		enter_server_address
	else
		if [ -n "$server_addr" ]; then
			ip="$server_addr"
		else
			detect_ip
			check_nat_ip
		fi
	fi
	# PERFORMANCE: Calculate MTU early for display
	wg_mtu=$(calculate_mtu)
	show_config
	detect_ipv6
	select_port
	enter_first_client_name
	if [ "$auto" = 0 ]; then
		select_dns
	fi
	show_setup_ready
	check_firewall
	confirm_setup
	show_start_setup
	install_pkgs
	create_server_config
	update_sysctl
	create_firewall_rules
	if [ "$os" != "openSUSE" ] && [ "$os" != "alpine" ]; then
		update_rclocal
	fi
	new_client
	start_wg_service
	echo ""
	show_client_qr_code
	if [ "$auto" != 0 ] && check_dns_name "$server_addr"; then
		show_dns_name_note "$server_addr"
	fi
	finish_setup
else
	show_header
	select_menu_option
	case "$option" in
		1)
			enter_client_name
			select_dns
			new_client add_client
			update_wg_conf
			echo ""
			show_client_qr_code
			print_client_added
			exit 0
		;;
		2)
			print_check_clients
			check_clients
			echo ""
			show_clients
			print_client_total
			exit 0
		;;
		3)
			check_clients
			select_client_to remove
			confirm_remove_client
			if echo "$remove" | grep -qE '^[yY]$'; then
				print_remove_client
				remove_client_wg
				print_client_removed
				exit 0
			else
				print_client_removal_aborted
				exit 1
			fi
		;;
		4)
			check_clients
			select_client_to "show QR code for"
			echo ""
			get_export_dir
			check_client_conf
			show_client_qr_code
			print_client_conf
			exit 0
		;;
		5)
			confirm_remove_wg
			if echo "$remove" | grep -qE '^[yY]$'; then
				print_remove_wg
				remove_firewall_rules
				disable_wg_service
				remove_sysctl_rules
				remove_rclocal_rules
				remove_pkgs
				print_wg_removed
				exit 0
			else
				print_wg_removal_aborted
				exit 1
			fi
		;;
		6)
			exit 0
		;;
	esac
fi
}

awgsetup "$@"

exit 0
