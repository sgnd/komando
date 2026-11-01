#!/bin/sh
# Start OpenVPN with the config komando mounted at /vpn, wait for the
# tunnel, then serve SOCKS5 on eth0:1080 through it. Only komando may use
# the SOCKS port: it logs in with the user and password komando passes in
# KOMANDO_SOCKS_USER / KOMANDO_SOCKS_PASS (random for each connection).
set -e
adduser -D -H -s /sbin/nologin "$KOMANDO_SOCKS_USER"
echo "$KOMANDO_SOCKS_USER:$KOMANDO_SOCKS_PASS" | chpasswd >/dev/null
unset KOMANDO_SOCKS_PASS
AUTH=""
# OpenVPN keeps the login in memory; komando deletes the file once connected
if [ -s /vpn/auth ]; then AUTH="--auth-user-pass /vpn/auth"; fi
openvpn --config /vpn/config.ovpn $AUTH --script-security 2 --up /etc/komando/up.sh \
  --log /tmp/openvpn.log --daemon --writepid /tmp/openvpn.pid
i=0
while ! ip link show tun0 >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 90 ] || ! kill -0 "$(cat /tmp/openvpn.pid 2>/dev/null)" 2>/dev/null; then
    echo "OPENVPN_FAILED"
    tail -n 20 /tmp/openvpn.log
    exit 1
  fi
  sleep 1
done
echo "OPENVPN_READY"
exec sockd -f /etc/komando/sockd.conf
