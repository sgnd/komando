#!/bin/sh
# Use the DNS servers the VPN pushes, inside this container only.
env | sed -n 's/^foreign_option_[0-9]*=dhcp-option DNS //p' | sed 's/^/nameserver /' > /tmp/resolv
if [ -s /tmp/resolv ]; then cat /tmp/resolv > /etc/resolv.conf; fi
exit 0
