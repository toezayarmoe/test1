#!/bin/sh
#
# Script for automatic setup of an IPsec VPN server on Ubuntu, Debian, CentOS/RHEL,
# Rocky Linux, AlmaLinux, Oracle Linux, Amazon Linux 2 and Alpine Linux
#
# DO NOT RUN THIS SCRIPT ON YOUR PC OR MAC!
#
# The latest version of this script is available at:
# https://github.com/hwdsl2/setup-ipsec-vpn
#
# Copyright (C) 2021-2024 Lin Song <linsongui@gmail.com>
#
# This work is licensed under the Creative Commons Attribution-ShareAlike 3.0
# Unported License: http://creativecommons.org/licenses/by-sa/3.0/
#
# Attribution required: please include my name in any derivative and let me
# know how you have improved it!

# =====================================================

# Define your own values for these variables
# - IPsec pre-shared key, VPN username and password
# - All values MUST be placed inside 'single quotes'
# - DO NOT use these special characters within values: \ " '

YOUR_IPSEC_PSK='your_ipsec_psk'
YOUR_USERNAME='your_vpn_username'
YOUR_PASSWORD='your_vpn_password'

# =====================================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

exiterr() { echo "Error: $1" >&2; exit 1; }

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_dns_name() {
  FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$FQDN_REGEX"
}

check_root() {
  if [ "$(id -u)" != 0 ]; then
    exiterr "Script must be run as root. Try 'sudo sh $0'"
  fi
}

check_vz() {
  if [ -f /proc/user_beancounters ]; then
    exiterr "OpenVZ VPS is not supported."
  fi
}

check_lxc() {
  # shellcheck disable=SC2154
  if [ "$container" = "lxc" ] && [ ! -e /dev/ppp ]; then
cat 1>&2 <<'EOF'
Error: /dev/ppp is missing. LXC containers require configuration.
       See: https://github.com/hwdsl2/setup-ipsec-vpn/issues/1014
EOF
  exit 1
  fi
}

check_os() {
  rh_file="/etc/redhat-release"
  if [ -f "$rh_file" ]; then
    os_type=centos
    if grep -q "Red Hat" "$rh_file"; then
      os_type=rhel
    fi
    [ -f /etc/oracle-release ] && os_type=ol
    grep -qi rocky "$rh_file" && os_type=rocky
    grep -qi alma "$rh_file" && os_type=alma
    if grep -q "release 7" "$rh_file"; then
      os_ver=7
    elif grep -q "release 8" "$rh_file"; then
      os_ver=8
      grep -qi stream "$rh_file" && os_ver=8s
      if [ "$os_type$os_ver" = "centos8" ]; then
        exiterr "CentOS Linux 8 is EOL and not supported."
      fi
    elif grep -q "release 9" "$rh_file"; then
      os_ver=9
      grep -qi stream "$rh_file" && os_ver=9s
    else
      exiterr "This script only supports CentOS/RHEL 7-9."
    fi
  elif grep -qs "Amazon Linux release 2 " /etc/system-release; then
    os_type=amzn
    os_ver=2
  elif grep -qs "Amazon Linux release 2023" /etc/system-release; then
    exiterr "Amazon Linux 2023 is not supported."
  else
    os_type=$(lsb_release -si 2>/dev/null)
    [ -z "$os_type" ] && [ -f /etc/os-release ] && os_type=$(. /etc/os-release && printf '%s' "$ID")
    case $os_type in
      [Uu]buntu)
        os_type=ubuntu
        ;;
      [Dd]ebian|[Kk]ali)
        os_type=debian
        ;;
      [Rr]aspbian)
        os_type=raspbian
        ;;
      [Aa]lpine)
        os_type=alpine
        ;;
      *)
cat 1>&2 <<'EOF'
Error: This script only supports one of the following OS:
       Ubuntu, Debian, CentOS/RHEL, Rocky Linux, AlmaLinux,
       Oracle Linux, Amazon Linux 2 or Alpine Linux
EOF
        exit 1
        ;;
    esac
    if [ "$os_type" = "alpine" ]; then
      os_ver=$(. /etc/os-release && printf '%s' "$VERSION_ID" | cut -d '.' -f 1,2)
      if [ "$os_ver" != "3.18" ] && [ "$os_ver" != "3.19" ]; then
        exiterr "This script only supports Alpine Linux 3.18/3.19."
      fi
    else
      os_ver=$(sed 's/\..*//' /etc/debian_version | tr -dc 'A-Za-z0-9')
      if [ "$os_ver" = 8 ] || [ "$os_ver" = 9 ] || [ "$os_ver" = "jessiesid" ] \
        || [ "$os_ver" = "bustersid" ]; then
cat 1>&2 <<EOF
Error: This script requires Debian >= 10 or Ubuntu >= 20.04.
       This version of Ubuntu/Debian is too old and not supported.
EOF
        exit 1
      fi
    fi
  fi
}

check_iface() {
  def_iface=$(route 2>/dev/null | grep -m 1 '^default' | grep -o '[^ ]*$')
  if [ "$os_type" != "alpine" ]; then
    [ -z "$def_iface" ] && def_iface=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -Po '(?<=dev )(\S+)')
  fi
  def_state=$(cat "/sys/class/net/$def_iface/operstate" 2>/dev/null)
  check_wl=0
  if [ -n "$def_state" ] && [ "$def_state" != "down" ]; then
    if [ "$os_type" = "ubuntu" ] || [ "$os_type" = "debian" ] || [ "$os_type" = "raspbian" ]; then
      if ! uname -m | grep -qi -e '^arm' -e '^aarch64'; then
        check_wl=1
      fi
    else
      check_wl=1
    fi
  fi
  if [ "$check_wl" = 1 ]; then
    case $def_iface in
      wl*)
        exiterr "Wireless interface '$def_iface' detected. DO NOT run this script on your PC or Mac!"
        ;;
    esac
  fi
}

check_creds() {
  [ -n "$YOUR_IPSEC_PSK" ] && VPN_IPSEC_PSK="$YOUR_IPSEC_PSK"
  [ -n "$YOUR_USERNAME" ] && VPN_USER="$YOUR_USERNAME"
  [ -n "$YOUR_PASSWORD" ] && VPN_PASSWORD="$YOUR_PASSWORD"
  if [ -z "$VPN_IPSEC_PSK" ] && [ -z "$VPN_USER" ] && [ -z "$VPN_PASSWORD" ]; then
    return 0
  fi
  if [ -z "$VPN_IPSEC_PSK" ] || [ -z "$VPN_USER" ] || [ -z "$VPN_PASSWORD" ]; then
    exiterr "All VPN credentials must be specified. Edit the script and re-enter them."
  fi
  if printf '%s' "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" | LC_ALL=C grep -q '[^ -~]\+'; then
    exiterr "VPN credentials must not contain non-ASCII characters."
  fi
  case "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" in
    *[\\\"\']*)
      exiterr "VPN credentials must not contain these special characters: \\ \" '"
      ;;
  esac
}

check_dns() {
  if { [ -n "$VPN_DNS_SRV1" ] && ! check_ip "$VPN_DNS_SRV1"; } \
    || { [ -n "$VPN_DNS_SRV2" ] && ! check_ip "$VPN_DNS_SRV2"; }; then
    exiterr "The DNS server specified is invalid."
  fi
}

check_server_dns() {
  if [ -n "$VPN_DNS_NAME" ]; then
    if ! check_ip "$VPN_DNS_NAME" && ! check_dns_name "$VPN_DNS_NAME"; then
      exiterr "The DNS name specified is invalid."
    fi
    public_ip=$(dig +short TXT o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null | tr -d '"')
    [ -z "$public_ip" ] && public_ip=$(curl -s ifconfig.co 2>/dev/null)
    [ -z "$public_ip" ] && public_ip=$(curl -s ifconfig.me 2>/dev/null)
    [ -z "$public_ip" ] && public_ip=$(wget -qO- ifconfig.co 2>/dev/null)
    [ -z "$public_ip" ] && public_ip=$(wget -qO- ifconfig.me 2>/dev/null)
    if [ -n "$public_ip" ]; then
      [ "$public_ip" != "$VPN_DNS_NAME" ] && echo "Warning: The server's actual public IP is $public_ip"
    fi
  fi
}

check_client_name() {
  if [ -z "$VPN_CLIENT_NAME" ]; then
    return 0
  fi
  if [ "$os_type" = "alpine" ]; then
    if printf '%s' "$VPN_CLIENT_NAME" | LC_ALL=C grep -q '[^ -~]\+'; then
      exiterr "VPN client name must not contain non-ASCII characters."
    fi
    case "$VPN_CLIENT_NAME" in
      *[\\\"\']*)
        exiterr "VPN client name must not contain these special characters: \\ \" '"
        ;;
    esac
  fi
}

show_start() {
  if [ "$in_container" = 0 ]; then
cat <<'EOF'
VPN setup in progress... Please be patient.
EOF
  fi
}

wait_for_apt() {
  if [ "$os_type" != "alpine" ]; then
    while fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
      echo "Waiting for other package managers to finish..."
      sleep 5
    done
  fi
}

install_pkgs() {
  if [ "$os_type" = "debian" ] || [ "$os_type" = "ubuntu" ] || [ "$os_type" = "raspbian" ]; then
    wait_for_apt
    export DEBIAN_FRONTEND=noninteractive
    (
      apt-get -yqq update
      apt-get -yqq --no-install-recommends install wget dnsutils openssl \
        iptables iproute2 gawk grep sed net-tools patch
    ) || exiterr "'apt-get install' failed."
  elif [ "$os_type" = "alpine" ]; then
    apk add -U -q bash bind-tools coreutils openssl wget
  fi
}

detect_ip() {
  # Try to detect server IPs. Turn off 'set -e' temporarily
  set +e
  public_ip=$(dig +short TXT o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null | tr -d '"')
  [ -z "$public_ip" ] && public_ip=$(curl -s ifconfig.co 2>/dev/null)
  [ -z "$public_ip" ] && public_ip=$(curl -s ifconfig.me 2>/dev/null)
  [ -z "$public_ip" ] && public_ip=$(wget -qO- ifconfig.co 2>/dev/null)
  [ -z "$public_ip" ] && public_ip=$(wget -qO- ifconfig.me 2>/dev/null)
  client_ip=$(ip -4 route get 1 2>/dev/null | awk '{print $NF;exit}')
  [ -z "$client_ip" ] && client_ip=$(ifconfig 2>/dev/null | grep -o 'inet addr:[^ ]*' | grep -o '[^:]*$' | grep -m 1 -v '127.0')
  set -e
}

install_vpn_pkgs() {
  if [ "$os_type" = "debian" ] || [ "$os_type" = "ubuntu" ] || [ "$os_type" = "raspbian" ]; then
    (
      apt-get -yqq update
      apt-get -yqq --no-install-recommends install libcharon-extauth-plugins strongswan xl2tpd
    ) || exiterr "'apt-get install' failed."
  elif [ "$os_type" = "alpine" ]; then
    apk add -U -q strongswan xl2tpd
  fi
}

update_ike_port() {
  echo "Updating IPsec configuration to use port 124..."
  # Example for strongSwan, adjust the file path and configuration as needed
  if grep -q "leftikeport=23" /etc/ipsec.conf; then
    sed -i 's/leftikeport=23/leftikeport=124/' /etc/ipsec.conf
  else
    echo "leftikeport=124" >> /etc/ipsec.conf
  fi
  if grep -q "rightikeport=23" /etc/ipsec.conf; then
    sed -i 's/rightikeport=23/rightikeport=124/' /etc/ipsec.conf
  else
    echo "rightikeport=124" >> /etc/ipsec.conf
  fi

  # Add similar changes to any connection-specific configuration files if necessary
  # For example, /etc/ipsec.d/your-connection.conf
  # sed -i 's/ikeport=23/ikeport=124/' /etc/ipsec.d/your-connection.conf

  # Restart the IPsec service to apply changes
  systemctl restart strongswan
}

update_config() {
  bigecho "Creating VPN configuration..."

  L2TP_NET=${L2TP_NET:-'192.168.42.0/24'}
  L2TP_LOCAL=${L2TP_LOCAL:-'192.168.42.1'}
  L2TP_POOL=${L2TP_POOL:-'192.168.42.10-192.168.42.250'}
  XAUTH_NET=${XAUTH_NET:-'192.168.43.0/24'}
  XAUTH_POOL=${XAUTH_POOL:-'192.168.43.10-192.168.43.250'}
  DNS_SRV1=${DNS_SRV1:-'1.1.1.1'}
  DNS_SRV2=${DNS_SRV2:-'1.0.0.1'}

  bigecho2 "Updating sysctl settings..."

  /sbin/sysctl -q -p

  bigecho2 "Updating IPTables rules..."

  iptables -I INPUT -p udp --dport 124 -j ACCEPT
  iptables -I INPUT -p udp --dport 21 -j ACCEPT
  iptables -I INPUT -p 50 -j ACCEPT
  iptables -I INPUT -p udp --dport 1701 -j ACCEPT
  iptables-save > /etc/iptables.rules
}

restart_services() {
  bigecho2 "Restarting services..."

  systemctl restart strongswan
  systemctl restart xl2tpd
}

# Script start
vpnsetup() {
  check_root
  check_vz
  check_lxc
  check_os
  check_iface
  check_creds
  check_dns
  check_server_dns
  check_client_name
  show_start

  install_pkgs
  install_vpn_pkgs
  update_ike_port
  update_config
  restart_services
}

vpnsetup "$@"

exit 0
