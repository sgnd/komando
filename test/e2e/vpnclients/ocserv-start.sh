#!/bin/sh
# Make a CA and server certificate (shared with the client through /certs),
# a user e2e/ocpass, a TCP listener the client checks through the VPN, and
# start ocserv in the foreground.
set -e
cd /certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=e2e-ca 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout server.key -out server.csr -subj /CN=ocserv 2>/dev/null
printf 'subjectAltName=DNS:ocserv\n' > san.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile san.ext -out server.crt 2>/dev/null
chmod 644 ca.crt
printf 'ocpass\nocpass\n' | ocpasswd -c /etc/ocserv/passwd e2e
mkdir -p /dev/net && [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
(while true; do nc -l -p 7000 >/dev/null 2>&1; done) &
exec ocserv -f -c /etc/ocserv/ocserv.conf
