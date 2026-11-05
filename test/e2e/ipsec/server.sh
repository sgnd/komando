#!/bin/sh
# The e2e IPsec server: strongSwan (IKEv1 L2TP/IPsec, IKEv1 XAUTH, IKEv2)
# and xl2tpd behind it. Throwaway keys and passwords, for tests only.
set -e
apk add -q --no-cache strongswan xl2tpd ppp socat openssl >/dev/null
LIFE="${IPSEC_LIFE:-1h}"
# the client sits on the server's own LAN here: do not let that traffic skip IPsec
sed -i 's/load = yes/load = no/' /etc/strongswan.d/charon/bypass-lan.conf
cat > /etc/strongswan.d/zz-e2e.conf <<CONF
charon {
  # Cisco-style clients use aggressive mode with a group password
  i_dont_care_about_security_and_use_aggressive_mode_psk = yes
  filelog {
    e2e {
      path = /tmp/charon.log
      default = 1
      ike = 2
      cfg = 2
      enc = 1
    }
  }
}
CONF

cat > /etc/ipsec.conf <<CONF
config setup
  charondebug="ike 1, knl 1, cfg 1, net 0"
  uniqueids=never

conn %default
  ikelifetime=8h
  lifetime=$LIFE
  margintime=20s
  rekeyfuzz=0%
  dpddelay=10s
  dpdtimeout=60s
  dpdaction=clear

conn l2tp
  keyexchange=ikev1
  authby=secret
  type=transport
  left=%any
  leftprotoport=17/1701
  right=%any
  rightprotoport=17/%any
  ike=aes256-sha256-modp2048,aes128-sha1-modp1024,3des-sha1-modp1024!
  esp=aes256-sha256,aes128-sha1!
  # the server rekeys ESP first (a quick mode komando answers), like a
  # MikroTik with a 30-minute proposal lifetime
  lifetime=60s
  margintime=20s
  auto=add

# Cisco-style: aggressive mode with a group name, XAUTH, mode config
conn xauth
  keyexchange=ikev1
  aggressive=yes
  authby=xauthpsk
  xauth=server
  left=%any
  leftsubnet=10.40.0.0/24
  right=%any
  rightid=keyid:staff
  rightsourceip=10.40.1.0/24
  rightdns=10.40.0.53
  modeconfig=pull
  ike=aes256-sha256-modp2048,aes128-sha1-modp1024!
  esp=aes256-sha256,aes128-sha1!
  rekey=no
  auto=add

conn ikev2-psk
  keyexchange=ikev2
  authby=secret
  left=%any
  leftid=@ipsecsrv
  leftsubnet=10.50.0.0/24
  right=%any
  rightid=@psk-client
  rightsourceip=10.50.1.0/24
  rightdns=10.50.0.53
  # short lifetimes: the server rekeys the CHILD SA and the IKE SA during the test
  lifetime=60s
  ikelifetime=100s
  margintime=20s
  reauth=no
  auto=add

conn ikev2-eap
  keyexchange=ikev2
  left=%any
  leftid=@ipsecsrv
  leftcert=server.pem
  leftsendcert=always
  leftsubnet=10.50.0.0/24
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  eap_identity=%identity
  rightsourceip=10.50.2.0/24
  rightdns=10.50.0.53
  # the server asks the client to log in again (AUTH_LIFETIME) during the test
  ikelifetime=100s
  margintime=20s
  auto=add
CONF

# a throwaway CA and server certificate for the EAP connection; the client
# gets the CA through /pki
mkdir -p /pki
cd /tmp
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out /pki/ca.pem -days 2 -subj "/CN=komando e2e CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout /etc/ipsec.d/private/server.key -out s.csr -subj "/CN=ipsecsrv" 2>/dev/null
printf 'subjectAltName=DNS:ipsecsrv\nextendedKeyUsage=serverAuth\n' > ext.cnf
openssl x509 -req -in s.csr -CA /pki/ca.pem -CAkey ca.key -CAcreateserial -out /etc/ipsec.d/certs/server.pem -days 2 -extfile ext.cnf 2>/dev/null
cp /pki/ca.pem /etc/ipsec.d/cacerts/ca.pem
# a second CA the client must not trust
openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out /pki/other-ca.pem -days 2 -subj "/CN=someone else" 2>/dev/null
chmod 644 /pki/*.pem
cd /

cat > /etc/ipsec.secrets <<CONF
%any %any : PSK "l2tp-psk"
keyid:staff : PSK "group-secret"
xauth-user : XAUTH "xauth-pass"
@psk-client : PSK "ikev2-psk"
: RSA server.key
eap-user : EAP "eap-pass"
CONF
ip addr add 10.40.0.1/32 dev lo
ip addr add 10.50.0.1/32 dev lo

mkdir -p /etc/xl2tpd /var/run/xl2tpd
cat > /etc/xl2tpd/xl2tpd.conf <<CONF
[global]
port = 1701
[lns default]
ip range = 10.30.0.10-10.30.0.50
local ip = 10.30.0.1
require chap = no
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
CONF
cat > /etc/ppp/options.xl2tpd <<CONF
ipcp-accept-local
ipcp-accept-remote
require-mschap-v2
ms-dns 10.30.0.53
noccp
auth
mtu 1400
mru 1400
nodefaultroute
lcp-echo-interval 10
lcp-echo-failure 4
logfile /tmp/ppp.log
CONF
printf '"l2tp-user" * "l2tp-pass" *\n' > /etc/ppp/chap-secrets

# something to reach only through the VPN
socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:'echo through-the-vpn' &
ipsec start --nofork > /tmp/starter.log 2>&1 &
xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf > /tmp/xl2tpd.log 2>&1 &
sleep infinity
