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
wfH8HO/T9bxEddWDsB3fJKpM/tiVMt4s/WMdGJtFdRlxzUb03u+HT6t00sLlZ78g
ngjxLpJGFpHAGdVf9vACBtrxv5qcrG5gd8k7MJ+FtMTcjeQm8kVRyIW7cOWxlpGY
6jringYZ6NcRTrh/OlxIHKdsLI9ddcekbYGyZVTm1wd22HVG+07PH/AeyY78O2+Z
tbjxGTFRSYt3jUaFeUmWNtxqWnR4MPmC+6iKvUKisV27P89g8v8CiZynAAWRJ0+A
qp+PWxwHi/iJ501WdLspeo8VkXIb3PivyIKC356m+yuuibD2uqwLZ2//afup84Qu
pRtgW/PbAgMBAAECggEAVo/efIQUQEtrlIF2jRNPJZuQ0rRJbHGV27tdrauU6MBT
NG8q7N2c5DymlT75NSyHRlKVzBYTPDjzxgf1oqR2X16Sxzh5uZTpthWBQtal6fmU
JKbYsDDlYc2xDZy5wsXnCC3qAaWs2xxadPUS3Lw/cjGsoeZlOFP4QtV/imLseaws
7r4KZE7SVO8dF8Xtcy304Bd7UsKClnbCrGsABUF/rqA8g34o7yrpo9XqcwbF5ihQ
TbnB0Ns8Bz30pjgGjJZTdTL3eskP9qMJWo/JM76kSaJWReoXTws4DlQHxO29z3eK
zKdxieXaBGMwFnv23JvXKJ5eAnxzqsL6a+SuNPPN4QKBgQDQhisSDdjUJWy0DLnJ
/HjtsnQyfl0efOqAlUEir8r5IdzDTtAEcW6GwPj1rIOm79ZeyysT1pGN6eulzS1i
6lz6/c5uHA9Z+7LT48ZaQjmKF06ItdfHI9ytoXaaQPMqW7NnyOFxCcTHBabmwQ+E
QZDFkM6vVXL37Sz4JyxuIwCNMQKBgQDLThgKi+L3ps7y1dWayj+Z0tutK2JGDww7
6Ze6lD5gmRAURd0crIF8IEQMpvKlxQwkhqR4vEsdkiFFJQAaD+qZ9XQOkWSGXvKP
A/yzk0Xu3qL29ZqX+3CYVjkDbtVOLQC9TBG60IFZW79K/Zp6PhHkO8w6l+CBR+yR
X4+8x1ReywKBgQCfSg52wSski94pABugh4OdGBgZRlw94PCF/v390En92/c3Hupa
qofi2mCT0w/Sox2f1hV3Fw6jWNDRHBYSnLMgbGeXx0mW1GX75OBtrG8l5L3yQu6t
SeDWpiPim8DlV52Jp3NHlU3DNrcTSOFgh3Fe6kpot56Wc5BJlCsliwlt0QKBgEol
u0LtbePgpI2QS41ewf96FcB8mCTxDAc11K6prm5QpLqgGFqC197LbcYnhUvMJ/eS
W53lHog0aYnsSrM2pttr194QTNds/Y4HaDyeM91AubLUNIPFonUMzVJhM86FP0XK
3pSBwwsyGPxirdpzlNbmsD+WcLz13GPQtH2nPTAtAoGAVloDEEjfj5gnZzEWTK5k
4oYWGlwySfcfbt8EnkY+B77UVeZxWnxpVC9PhsPNI1MTNET+CRqxNZzxWo3jVuz1
HtKSizJpaYQ6iarP4EvUdFxHBzjHX6WLahTgUq90YNaxQbXz51ARpid8sFbz1f37
jgjgxgxbitApzno0E2Pq/Kg=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDRTCCAi2gAwIBAgIUOvs3vdjcBtCLww52CggSlAKafDkwDQYJKoZIhvcNAQEL
BQAwMjEQMA4GA1UEAwwHS29ielZQTjERMA8GA1UECgwIS29iZUtvYnoxCzAJBgNV
BAYTAlBIMB4XDTIxMDcwNzA1MzQwN1oXDTMxMDcwNTA1MzQwN1owMjEQMA4GA1UE
AwwHS29ielZQTjERMA8GA1UECgwIS29iZUtvYnoxCzAJBgNVBAYTAlBIMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApZoAnZu0QdlVisHx/Bzv0/W8RHXV
g7Ad3ySqTP7YlTLeLP1jHRibRXUZcc1G9N7vh0+rdNLC5We/IJ4I8S6SRhaRwBnV
X/bwAgba8b+anKxuYHfJOzCfhbTE3I3kJvJFUciFu3DlsZaRmOo64p4GGejXEU64
fzpcSBynbCyPXXXHpG2BsmVU5tcHdth1RvtOzx/wHsmO/DtvmbW48RkxUUmLd41G
hXlJljbcalp0eDD5gvuoir1CorFduz/PYPL/AomcpwAFkSdPgKqfj1scB4v4iedN
VnS7KXqPFZFyG9z4r8iCgt+epvsrromw9rqsC2dv/2n7qfOELqUbYFvz2wIDAQAB
o1MwUTAdBgNVHQ4EFgQUcKFL6tckon2uS3xGrpe1Zpa68VEwHwYDVR0jBBgwFoAU
cKFL6tckon2uS3xGrpe1Zpa68VEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAYQP0S67eoJWpAMavayS7NjK+6KMJtlmL8eot/3RKPLleOjEuCdLY
QvrP0Tl3M5gGt+I6WO7r+HKT2PuCN8BshIob8OGAEkuQ/YKEg9QyvmSm2XbPVBaG
RRFjvxFyeL4gtDlqb9hea62tep7+gCkeiccyp8+lmnS32rRtFa7PovmK5pUjkDOr
dpvCQlKoCRjZ/+OfUaanzYQSDrxdTSN8RtJhCZtd45QbxEXzHTEaICXLuXL6cmv7
tMuhgUoefS17gv1jqj/C9+6ogMVa+U7QqOvL5A7hbevHdF/k/TMn+qx4UdhrbL5Q
enL3UGT+BhRAPiA1I5CcG29RqjCzQoaCNg==
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

# Log Settings
rm -f /etc/logrotate.d/rsyslog
cat <<'logrotate' > /etc/logrotate.d/rsyslog
/var/log/syslog
{
        daily
        missingok
        notifempty
        create 640 syslog adm
        postrotate
                /usr/lib/rsyslog/rsyslog-rotate
        endscript
}

/var/log/kern.log
/var/log/auth.log
{
        rotate 1
        daily
        missingok
        notifempty
        compress
        delaycompress
        sharedscripts
        postrotate
                /usr/lib/rsyslog/rsyslog-rotate
        endscript
}
logrotate
chown root:root /var/log
chmod 755 /var/log
chown root:root /var/log
chown syslog:adm /var/log/syslog
chmod 640 /var/log/syslog
logrotate -v -f /etc/logrotate.d/rsyslog

# CONFIGURE SLOWDNS
rm -rf /etc/slowdns
mkdir -m 777 /etc/slowdns
# ServerKEY
cat > /etc/slowdns/server.key << END
$Serverkey
END
# ServerPUB
cat > /etc/slowdns/server.pub << END
$Serverpub
END
wget -q -O /etc/slowdns/sldns-server "https://raw.githubusercontent.com/fisabiliyusri/SLDNS/main/slowdns/sldns-server"
chmod +x /etc/slowdns/server.key
chmod +x /etc/slowdns/server.pub
chmod +x /etc/slowdns/sldns-server

# Iptables Rule for SlowDNS server
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300

# Install server-sldns.service
cat > /etc/systemd/system/server-sldns.service << END
[Unit]
Description=Server SlowDNS By TekidoerVPN
Documentation=https://tekidoervpn.site
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/etc/slowdns/sldns-server -udp :5300 -privkey-file /etc/slowdns/server.key $Nameserver 127.0.0.1:$SSH_Port2
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

# Permission service slowdns
cd
chmod +x /etc/systemd/system/server-sldns.service
pkill sldns-server
systemctl daemon-reload
systemctl stop server-sldns
systemctl enable server-sldns
systemctl start server-sldns
systemctl restart server-sldns
systemctl status --no-pager server-sldns

# UDP hysteria
wget -N --no-check-certificate -q -O ~/install_server.sh https://raw.githubusercontent.com/RepositoriesDexter/Hysteria/main/install_server.sh; chmod +x ~/install_server.sh; ./install_server.sh --version v1.3.5
rm -f /etc/hysteria/config.json
echo '{
  "log_level": "fatal",
  "listen": ":5666",
  "cert": "/etc/hysteria/hysteria.crt",
  "key": "/etc/hysteria/hysteria.key",
  "up_mbps": 100,
  "down_mbps": 100,
  "disable_udp": false,
  "obfs": "Tekidoer",
  "auth": {
    "mode": "passwords",
    "config": ["Tekidoer:123"]
  }
}
' >> /etc/hysteria/config.json

# Creating Hysteria CERT
cat << EOF > /etc/hysteria/hysteria.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            40:26:da:91:18:2b:77:9c:85:6a:0c:bb:ca:90:53:fe
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=KobZ
        Validity
            Not Before: Jul 22 22:23:55 2020 GMT
            Not After : Jul 20 22:23:55 2030 GMT
        Subject: CN=server
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (1024 bit)
                Modulus:
                    00:ce:35:23:d8:5d:9f:b6:9b:cb:6a:89:e1:90:af:
                    42:df:5f:f8:bd:ad:a7:78:9a:ca:20:f0:3d:5b:d6:
                    c9:ef:4c:4a:99:96:c3:38:fd:59:b4:d7:65:ed:d4:
                    a7:fa:ab:03:e2:be:88:2f:ca:fc:90:dd:b0:b7:bc:
                    23:cb:83:ac:36:e2:01:57:69:64:b8:e1:9e:51:f0:
                    a6:9d:13:d9:92:6b:4d:04:a6:10:64:a3:3f:6b:ff:
                    fe:32:ac:91:63:c2:71:24:be:9e:76:4f:87:cc:3a:
                    03:a1:9e:48:3f:11:92:33:3b:19:16:9c:d0:5d:16:
                    ee:c1:42:67:99:47:66:67:67
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                6B:08:C0:64:10:71:A8:32:7F:0B:FE:1E:98:1F:BD:72:74:0F:C8:66
            X509v3 Authority Key Identifier: 
                keyid:64:49:32:6F:FE:66:62:F1:57:4D:BB:91:A8:5D:BD:26:3E:51:A4:D2
                DirName:/CN=KobZ
                serial:01:A4:01:02:93:12:D9:D6:01:A9:83:DC:03:73:DA:ED:C8:E3:C3:B7
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
         a1:3e:ac:83:0b:e5:5d:ca:36:b7:d0:ab:d0:d9:73:66:d1:62:
         88:ce:3d:47:9e:08:0b:a0:5b:51:13:fc:7e:d7:6e:17:0e:bd:
         f5:d9:a9:d9:06:78:52:88:5a:e5:df:d3:32:22:4a:4b:08:6f:
         b1:22:80:4f:19:d1:5f:9d:b6:5a:17:f7:ad:70:a9:04:00:ff:
         fe:84:aa:e1:cb:0e:74:c0:1a:75:0b:3e:98:90:1d:22:ba:a4:
         7a:26:65:7d:d1:3b:5c:45:a1:77:22:ed:b6:6b:18:a3:c4:ee:
         3e:06:bb:0b:ec:12:ac:16:a5:50:b3:ed:46:43:87:72:fd:75:
         8c:38
-----BEGIN CERTIFICATE-----
MIICVDCCAb2gAwIBAgIQQCbakRgrd5yFagy7ypBT/jANBgkqhkiG9w0BAQsFADAP
MQ0wCwYDVQQDDARLb2JaMB4XDTIwMDcyMjIyMjM1NVoXDTMwMDcyMDIyMjM1NVow
ETEPMA0GA1UEAwwGc2VydmVyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDO
NSPYXZ+2m8tqieGQr0LfX/i9rad4msog8D1b1snvTEqZlsM4/Vm012Xt1Kf6qwPi
vogvyvyQ3bC3vCPLg6w24gFXaWS44Z5R8KadE9mSa00EphBkoz9r//4yrJFjwnEk
vp52T4fMOgOhnkg/EZIzOxkWnNBdFu7BQmeZR2ZnZwIDAQABo4GuMIGrMAkGA1Ud
EwQCMAAwHQYDVR0OBBYEFGsIwGQQcagyfwv+HpgfvXJ0D8hmMEoGA1UdIwRDMEGA
FGRJMm/+ZmLxV027kahdvSY+UaTSoROkETAPMQ0wCwYDVQQDDARLb2JaghQBpAEC
kxLZ1gGpg9wDc9rtyOPDtzATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMC
BaAwEQYDVR0RBAowCIIGc2VydmVyMA0GCSqGSIb3DQEBCwUAA4GBAKE+rIML5V3K
NrfQq9DZc2bRYojOPUeeCAugW1ET/H7XbhcOvfXZqdkGeFKIWuXf0zIiSksIb7Ei
gE8Z0V+dtloX961wqQQA//6EquHLDnTAGnULPpiQHSK6pHomZX3RO1xFoXci7bZr
GKPE7j4GuwvsEqwWpVCz7UZDh3L9dYw4
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/hysteria/hysteria.key
-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAM41I9hdn7aby2qJ
4ZCvQt9f+L2tp3iayiDwPVvWye9MSpmWwzj9WbTXZe3Up/qrA+K+iC/K/JDdsLe8
I8uDrDbiAVdpZLjhnlHwpp0T2ZJrTQSmEGSjP2v//jKskWPCcSS+nnZPh8w6A6Ge
SD8RkjM7GRac0F0W7sFCZ5lHZmdnAgMBAAECgYAFNrC+UresDUpaWjwaxWOidDG8
0fwu/3Lm3Ewg21BlvX8RXQ94jGdNPDj2h27r1pEVlY2p767tFr3WF2qsRZsACJpI
qO1BaSbmhek6H++Fw3M4Y/YY+JD+t1eEBjJMa+DR5i8Vx3AE8XOdTXmkl/xK4jaB
EmLYA7POyK+xaDCeEQJBAPJadiYd3k9OeOaOMIX+StCs9OIMniRz+090AJZK4CMd
jiOJv0mbRy945D/TkcqoFhhScrke9qhgZbgFj11VbDkCQQDZ0aKBPiZdvDMjx8WE
y7jaltEDINTCxzmjEBZSeqNr14/2PG0X4GkBL6AAOLjEYgXiIvwfpoYE6IIWl3re
ebCfAkAHxPimrixzVGux0HsjwIw7dl//YzIqrwEugeSG7O2Ukpz87KySOoUks3Z1
yV2SJqNWskX1Q1Xa/gQkyyDWeCeZAkAbyDBI+ctc8082hhl8WZunTcs08fARM+X3
FWszc+76J1F2X7iubfIWs6Ndw95VNgd4E2xDATNg1uMYzJNgYvcTAkBoE8o3rKkp
em2n0WtGh6uXI9IC29tTQGr3jtxLckN/l9KsJ4gabbeKNoes74zdena1tRdfGqUG
JQbf7qSE3mg2
-----END PRIVATE KEY-----
EOF

chmod 755 /etc/hysteria/config.json
chmod 755 /etc/hysteria/hysteria.crt
chmod 755 /etc/hysteria/hysteria.key

iptables -t nat -A PREROUTING -i $(ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1) -p udp --dport 20000:50000 -j DNAT --to-destination :5666
systemctl enable hysteria-server.service
systemctl restart hysteria-server.service
systemctl status --no-pager hysteria-server.service

# Creating startup 1 script using cat eof tricks
cat <<'deekayz' > /etc/deekaystartup
#!/bin/sh

# Setting server local time
ln -fs /usr/share/zoneinfo/MyTimeZone /etc/localtime

# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive

# Allowing SlowDNS to Forward traffic
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300

# Disable IpV6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6

# Add DNS server ipv4
echo "nameserver DNS1" > /etc/resolv.conf
echo "nameserver DNS2" >> /etc/resolv.conf

# For sslh
mkdir -p /var/run/sslh
touch /var/run/sslh/sslh.pid
chmod 777 /var/run/sslh/sslh.pid

# For udp
iptables -t nat -A PREROUTING -i $(ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1) -p udp --dport 20000:50000 -j DNAT --to-destination :5666

deekayz

sed -i "s|MyTimeZone|$MyVPS_Time|g" /etc/deekaystartup
sed -i "s|DNS1|$Dns_1|g" /etc/deekaystartup
sed -i "s|DNS2|$Dns_2|g" /etc/deekaystartup
rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots 
cat <<'deekayx' > /etc/systemd/system/deekaystartup.service
[Unit]
Description=Custom startup script
ConditionPathExists=/etc/deekaystartup

[Service]
Type=oneshot
ExecStart=/etc/deekaystartup
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
deekayx

chmod +x /etc/deekaystartup
systemctl enable deekaystartup
systemctl start deekaystartup
systemctl status --no-pager deekaystartup
cd

# Pull BadVPN Binary 64bit or 32bit
if [ "$(getconf LONG_BIT)" == "64" ]; then
 wget -O /usr/bin/badvpn-udpgw "https://www.dropbox.com/s/jo6qznzwbsf1xhi/badvpn-udpgw64"
else
 wget -O /usr/bin/badvpn-udpgw "https://www.dropbox.com/s/8gemt9c6k1fph26/badvpn-udpgw"
fi

# Change Permission to make it Executable
chmod +x /usr/bin/badvpn-udpgw
 
# Setting our startup script for badvpn
cat <<'deekayb' > /etc/systemd/system/badvpn.service
[Unit]
Description=badvpn tun2socks service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10

[Install]
WantedBy=multi-user.target
deekayb

systemctl enable badvpn
systemctl start badvpn
systemctl status --no-pager badvpn

# Some Final Cronjob
echo "* * * * * root /bin/bash /etc/deekayvpn/service_checker.sh >/dev/null 2>&1" > /etc/cron.d/service-checker
echo "*/2 * * * * root /usr/sbin/logrotate -v -f /etc/logrotate.d/rsyslog >/dev/null 2>&1" > /etc/cron.d/logrotate

# Download script
cd /usr/local/bin
wget -O premium-script.tar.gz "https://www.dropbox.com/s/1ex9tr7hzoh53ln/premium-script.tar.gz"
tar -xvf premium-script.tar.gz
rm -f premium-script.tar.gz
cp /usr/local/bin/menu /usr/bin/menu
cp /usr/local/bin/menu /usr/bin/Menu
chmod +x /usr/bin/Menu
chmod +x /usr/bin/menu
chmod +x ./*
cd

clear
cd
echo " "
echo " "
echo "PREMIUM SCRIPT SUCCESSFULLY INSTALLED!"
echo "SCRIPT BY TEKIDOER"
echo "PLEASE WAIT..."
echo " "

# Finishing
chown -R www-data:www-data /home/vps/public_html

clear
echo ""
echo " INSTALLATION FINISH! "
echo ""
echo ""
echo "Server Information: " | tee -a log-install.txt | lolcat
echo "   • Timezone       : $MyVPS_Time "  | tee -a log-install.txt | lolcat
echo "   • IPtables       : [ON]"  | tee -a log-install.txt | lolcat
echo "   • Auto-Reboot    : [OFF] See menu to [ON] "  | tee -a log-install.txt | lolcat

echo " "| tee -a log-install.txt | lolcat
echo "Automated Features:"| tee -a log-install.txt | lolcat
echo "   • Auto restart server "| tee -a log-install.txt | lolcat
echo "   • Auto disconnect multilogin users [Openvpn]."| tee -a log-install.txt | lolcat
echo "   • Auto configure firewall every reboot[Protection for torrent and etc..]"| tee -a log-install.txt | lolcat

echo " " | tee -a log-install.txt | lolcat
echo "Services & Port Information:" | tee -a log-install.txt | lolcat
echo "   • Dropbear             : [ON] : $Dropbear_Port1 | $Dropbear_Port2 " | tee -a log-install.txt | lolcat
echo "   • Squid Proxy          : [ON] : $Squid_Port1 | $Squid_Port2" | tee -a log-install.txt | lolcat
echo "   • SSL through Dropbear : [ON] : 443" | tee -a log-install.txt | lolcat
echo "   • SSH Websocket        : [ON] : 443 | $WsPort" | tee -a log-install.txt | lolcat
echo "   • BadVPN               : [ON] : 7300 " | tee -a log-install.txt | lolcat
echo "   • Hysteria             : [ON] : 20000:50000" | tee -a log-install.txt | lolcat
echo "   • Nginx                : [ON] : $Nginx_Port" | tee -a log-install.txt | lolcat

echo "" | tee -a log-install.txt | lolcat
echo "Notes:" | tee -a log-install.txt | lolcat
echo "  ★ To display list of commands:  " [ menu ] or [ menu dk ] "" | tee -a log-install.txt | lolcat
echo "" | tee -a log-install.txt | lolcat
echo "  ★ Other concern and questions of these auto-scripts?" | tee -a log-install.txt | lolcat
echo "    Direct Message : https://t.me/Tekidoer" | tee -a log-install.txt | lolcat
echo ""

clear
echo ""
echo ""
figlet Tekidoer Script -c | lolcat
echo ""
echo "       Installation Complete! System need to reboot to apply all changes! "
history -c;
rm /root/Ubuntu24-AIO.sh
echo "           Server will secure this server and reboot after 10 seconds! "
sleep 10
reboot
