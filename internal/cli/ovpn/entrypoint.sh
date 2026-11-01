#!/bin/sh
# Start OpenVPN with the config komando mounted at /vpn, wait for the
# tunnel, then serve SOCKS5 on :1080 through it.
set -e
AUTH=""
if [ -s /vpn/auth ]; then AUTH="--auth-user-pass /vpn/auth --auth-nocache"; fi
openvpn --config /vpn/config.ovpn $AUTH --script-security 2 --up /etc/komando/up.sh \
  --log /tmp/openvpn.log --daemon --writepid /tmp/openvpn.pid
i=0
while ! ip link show tun0 >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 90 ] || ! kill -0 "$(cat /tmp/openvpn.pid 2>/dev/null)" 2>/dev/null; then
    echo "OPENVPN_FAILED"; tail -n 20 /tmp/openvpn.log; exit 1
  fi
  sleep 1
done
echo "OPENVPN_READY"
exec sockd -f /etc/komando/sockd.conf
