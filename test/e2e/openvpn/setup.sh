#!/bin/sh
# Makes a throwaway OpenVPN server for the e2e test: a CA, server and
# client certificates (EC, valid two days) and a client config, in $1.
# Run inside alpine (it installs openssl).
set -e
apk add --no-cache openssl >/dev/null
cd "$1"
openssl ecparam -genkey -name prime256v1 -out ca.key 2>/dev/null
openssl req -x509 -new -key ca.key -subj /CN=komando-e2e-ca -days 2 -out ca.crt
for n in server client; do
  openssl ecparam -genkey -name prime256v1 -out $n.key 2>/dev/null
  openssl req -new -key $n.key -subj /CN=$n -out $n.csr
  openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -out $n.crt 2>/dev/null
done
cat > server.conf <<CONF
port 1194
proto tcp-server
dev tun
ca /pki/ca.crt
cert /pki/server.crt
key /pki/server.key
dh none
topology subnet
server 10.8.0.0 255.255.255.0
verb 3
CONF
{
  printf 'client\ndev tun\nproto tcp-client\nremote host.docker.internal 11194\nnobind\nverb 3\n'
  printf '<ca>\n'; cat ca.crt; printf '</ca>\n<cert>\n'; cat client.crt; printf '</cert>\n<key>\n'; cat client.key; printf '</key>\n'
} > client.ovpn
chmod 644 ./*
