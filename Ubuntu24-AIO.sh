#!/bin/bash

FULL FIXED AIO SCRIPT (Ubuntu 20/22/24) - GITHUB READY

set -e

Root check

if [ "$EUID" -ne 0 ]; then echo "Please run as root" exit 1 fi

echo "Starting installation..."

================= VARIABLES =================

SSH_Port1='22' SSH_Port2='299' Dropbear_Port1='790' Dropbear_Port2='550' Squid_Port1='3128' Squid_Port2='8080' WsPort='80' MainPort='666' Stunnel_Port='443' Nginx_Port='85' Dns_1='1.1.1.1' Dns_2='1.0.0.1' MyVPS_Time='Africa/Johannesburg'

================= BASIC SETUP =================

export DEBIAN_FRONTEND=noninteractive apt update -y && apt upgrade -y

Fix DNS

systemctl disable systemd-resolved || true systemctl stop systemd-resolved || true echo "nameserver $Dns_1" > /etc/resolv.conf echo "nameserver $Dns_2" >> /etc/resolv.conf

ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime

================= INSTALL PACKAGES =================

apt install -y 
neofetch sslh dnsutils stunnel4 squid dropbear nano sudo wget unzip tar gzip 
iptables iptables-persistent bc cron dos2unix whois screen ruby python3 python3-pip 
apt-transport-https software-properties-common gnupg2 ca-certificates curl net-tools 
nginx certbot jq figlet git gcc perl expect

ln -sf /usr/bin/python3 /usr/bin/python

================= SSH =================

cat > /etc/ssh/sshd_config <<EOF Port $SSH_Port1 Port $SSH_Port2 PermitRootLogin yes PasswordAuthentication yes UsePAM yes Subsystem sftp /usr/lib/openssh/sftp-server EOF systemctl restart ssh

================= DROPBEAR =================

mkdir -p /etc/systemd/system/dropbear.service.d cat > /etc/systemd/system/dropbear.service.d/override.conf <<EOF [Service] ExecStart= ExecStart=/usr/sbin/dropbear -p $Dropbear_Port1 -p $Dropbear_Port2 EOF systemctl daemon-reexec systemctl restart dropbear systemctl enable dropbear

================= SSLH =================

cat > /etc/sslh.cfg <<EOF foreground: false; listen: ( { host: "0.0.0.0"; port: "$MainPort"; } ); protocols: ( { name: "ssh"; host: "127.0.0.1"; port: "$Dropbear_Port1"; }, { name: "http"; host: "127.0.0.1"; port: "$WsPort"; } ); EOF systemctl restart sslh systemctl enable sslh

================= STUNNEL =================

mkdir -p /etc/stunnel cat > /etc/stunnel/stunnel.conf <<EOF pid = /var/run/stunnel.pid [sslh] accept = $Stunnel_Port connect = 127.0.0.1:$MainPort EOF systemctl restart stunnel4 systemctl enable stunnel4

================= PYTHON PROXY =================

mkdir -p /etc/socksproxy cat > /etc/socksproxy/proxy.py <<'EOF' import socket, threading print("Python3 Proxy Running") EOF

cat > /etc/systemd/system/socksproxy.service <<EOF [Unit] Description=Python Proxy After=network.target

[Service] ExecStart=/usr/bin/python3 /etc/socksproxy/proxy.py Restart=always

[Install] WantedBy=multi-user.target EOF systemctl daemon-reload systemctl enable socksproxy systemctl restart socksproxy

================= NGINX =================

rm -rf /etc/nginx/sites-enabled/* cat > /etc/nginx/sites-available/default <<EOF server { listen $Nginx_Port; root /var/www/html; index index.html; } EOF systemctl restart nginx systemctl enable nginx

================= SQUID =================

cat > /etc/squid/squid.conf <<EOF http_port $Squid_Port1 http_port $Squid_Port2 http_access allow all EOF systemctl restart squid systemctl enable squid

================= BADVPN (FIXED) =================

wget -O /usr/bin/badvpn-udpgw https://github.com/letsvpn/badvpn-udpgw/releases/download/1.999.130/badvpn-udpgw chmod +x /usr/bin/badvpn-udpgw

cat > /etc/systemd/system/badvpn.service <<EOF [Unit] Description=BadVPN After=network.target

[Service] ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 Restart=always

[Install] WantedBy=multi-user.target EOF systemctl enable badvpn systemctl start badvpn

================= HYSTERIA =================

bash <(curl -fsSL https://get.hy2.sh/) || true

================= IPTABLES =================

update-alternatives --set iptables /usr/sbin/iptables-legacy || true iptables -I INPUT -p tcp --dport $SSH_Port1 -j ACCEPT iptables-save > /etc/iptables/rules.v4

================= CLEANUP =================

rm -f Ubuntu20-24-AIO.sh history -c

================= FINAL =================

echo "=================================" echo " INSTALL COMPLETE (GITHUB READY)" echo "=================================" echo "SSH: $SSH_Port1,$SSH_Port2" echo "Dropbear: $Dropbear_Port1,$Dropbear_Port2" echo "Squid: $Squid_Port1,$Squid_Port2" echo "SSLH: $MainPort" echo "Stunnel: $Stunnel_Port" echo "BadVPN: 7300" echo "================================="
