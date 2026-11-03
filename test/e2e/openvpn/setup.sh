#!/bin/sh
# Makes throwaway OpenVPN servers for the e2e test, in $1: a CA, server and
# client certificates (EC, valid two days), a tls-auth and a tls-crypt key,
# four server configs and the client profiles komando connects with:
#   tcp     TCP, new keys every 15 seconds          (10.8.0.0/24, port 1194)
#   crypt   UDP, tls-crypt, ChaCha20-Poly1305        (10.9.0.0/24, port 1195)
#   auth    UDP, tls-auth with key-direction, AES-256-CBC + SHA256 (10.10.0.0/24, port 1196)
#   login   TCP, user name and password, no client certificate (10.11.0.0/24, port 1197)
# Run inside alpine (it installs openssl and openvpn).
set -e
apk add --no-cache openssl openvpn >/dev/null
cd "$1"
openssl ecparam -genkey -name prime256v1 -out ca.key 2>/dev/null
openssl req -x509 -new -key ca.key -subj /CN=komando-e2e-ca -days 2 -out ca.crt
for n in server client; do
  openssl ecparam -genkey -name prime256v1 -out $n.key 2>/dev/null
  openssl req -new -key $n.key -subj /CN=$n -out $n.csr
  ext=""
  [ $n = server ] && printf 'extendedKeyUsage=serverAuth\n' > ext.cnf && ext="-extfile ext.cnf"
  openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 $ext -out $n.crt 2>/dev/null
done
openvpn --genkey secret ta.key
openvpn --genkey secret tc.key
printf '#!/bin/sh\n[ "$(head -1 "$1")" = e2e-user ] && [ "$(tail -1 "$1")" = e2e-pass ]\n' > check.sh
chmod 755 check.sh

common='dev tun
ca /pki/ca.crt
cert /pki/server.crt
key /pki/server.key
dh none
topology subnet
keepalive 10 60
verb 3'
printf '%s\nport 1194\nproto tcp-server\nserver 10.8.0.0 255.255.255.0\nreneg-sec 15\n' "$common" > tcp.conf
printf '%s\nport 1195\nproto udp\nserver 10.9.0.0 255.255.255.0\ntls-crypt /pki/tc.key\ndata-ciphers CHACHA20-POLY1305\n' "$common" > crypt.conf
printf '%s\nport 1196\nproto udp\nserver 10.10.0.0 255.255.255.0\ntls-auth /pki/ta.key 0\nauth SHA256\ndata-ciphers AES-256-CBC\n' "$common" > auth.conf
printf '%s\nport 1197\nproto tcp-server\nserver 10.11.0.0 255.255.255.0\nverify-client-cert none\nusername-as-common-name\nscript-security 2\nauth-user-pass-verify /pki/check.sh via-file\n' "$common" > login.conf

inline() { printf '<%s>\n' "$1"; cat "$2"; printf '</%s>\n' "$1"; }
{ printf 'client\ndev tun\nproto tcp-client\nremote ovpnsrv 1194\nnobind\nremote-cert-tls server\nverb 3\n'
  inline ca ca.crt; inline cert client.crt; inline key client.key; } > tcp.ovpn
{ printf 'client\ndev tun\nproto udp\nremote ovpnsrv 1195\nnobind\nremote-cert-tls server\ndata-ciphers CHACHA20-POLY1305\n'
  inline ca ca.crt; inline cert client.crt; inline key client.key; inline tls-crypt tc.key; } > crypt.ovpn
{ printf 'client\ndev tun\nproto udp\nremote ovpnsrv 1196\nnobind\nremote-cert-tls server\nauth SHA256\ndata-ciphers AES-256-CBC\nkey-direction 1\n'
  inline ca ca.crt; inline cert client.crt; inline key client.key; inline tls-auth ta.key; } > auth.ovpn
{ printf 'client\ndev tun\nproto tcp-client\nremote ovpnsrv 1197\nnobind\nremote-cert-tls server\nauth-user-pass\n'
  inline ca ca.crt; } > login.ovpn
cp tcp.ovpn client.ovpn
chmod 644 ./*
chmod 755 check.sh
