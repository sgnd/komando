# shellcheck shell=bash
# VPNs: a SOCKS proxy (komando's own, through the bastion) and an OS VPN check.
echo "==> VPNs"
q $K tunnel start bastion -D "127.0.0.1:$E2E_SOCKS"
q $K vpn add lab socks --address "127.0.0.1:$E2E_SOCKS" --check pg:5432
check "status lists the running tunnel" True "$($K status | jget '"127.0.0.1:'"$E2E_SOCKS"'" in [t["spec"] for t in d["data"]["tunnels"]]')"
check "status in text names it" 1 "$($K -o text status | grep -c '^tunnel ' || true)"
check "status --short counts the tunnel" 1 "$($K status --short | grep -c 'tun:[1-9]' || true)"
q $K conn add pg-lab 'postgres://app@pg:5432/app?sslmode=disable' --via lab --password-ref secret:pg-pass
check "db through a SOCKS VPN" 1 "$($K db query pg-lab 'select 1' | jget 'd["data"]["results"][0]["rows"][0][0]')"
q $K host add target-lab agent@target --via lab --password-ref secret:agent-pass
# target-lab is the protected target under a second name, so it is protected too
check "shell names the VPN on the way" 1 "$(ptyrun 'exit\n' env NO_COLOR=1 "$K" shell target-lab --yes | tr -d '\r' | grep -c '^komando: shell on target-lab (agent@target) via vpn lab · PROTECTED$' || true)"
check "ssh through a SOCKS VPN" target "$($K exec target-lab --read-only -- hostname | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "vpn test" 1 "$($K test kind:vpn | jget 'd["data"]["summary"]["ok"]')"
q $K vpn add corp system --check 127.0.0.1:1
check "system VPN down says so" VPN_DOWN "$($K db query pg-lab 'select 1' >/dev/null; $K test corp | jget 'd["data"]["results"][0]["error"]["code"]' || true)"
set +e; $K vpn rm lab >/dev/null; check "VPN in use cannot be removed" 8 $?; set -e
q $K tunnel stop --all
check "status after tunnel stop" 0 "$($K status | jget 'len(d["data"]["tunnels"])')"
check "status --short is empty when nothing runs" "" "$($K status --short)"
