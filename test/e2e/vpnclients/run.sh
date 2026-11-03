#!/usr/bin/env bash
# komando's openconnect and Tailscale VPN kinds against real servers, all
# in Docker: ocserv (the AnyConnect protocol) and Headscale with one
# Tailscale node. komando runs in a Linux client container with no VPN
# programs at all: both are built in.
#
#   test/e2e/vpnclients/run.sh      (make e2e-vpnclients)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PROJECT=${E2E_VPNC_PROJECT:-komando-vpnc}
BIN_DIR="$(mktemp -d "$HOME/.komando-vpnc.XXXX")"
export KOMANDO_BIN="$BIN_DIR/komando"
DC=(docker compose -p "$PROJECT" -f "$HERE/compose.yml")
cleanup() { [ "${KEEP:-0}" = 1 ] && return; "${DC[@]}" down -v >/dev/null 2>&1 || true; rm -rf "$BIN_DIR"; }
trap cleanup EXIT
PASS=0
ok() { PASS=$((PASS + 1)); echo "  ok   $1"; }
fail() { echo "  FAIL $1"; "${DC[@]}" logs --tail 30 "${2:-client}" || true; exit 1; }
in_client() { "${DC[@]}" exec -T -e KOMANDO_HOME=/tmp/k -e KOMANDO_VAULT_PASS=e2e -e KOMANDO_OUTPUT=json client "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# gone NAME: wait until no program with that name runs in the client (slim images have no ps)
gone() { in_client sh -c "for i in 1 2 3 4 5 6 7 8 9 10; do cat /proc/[0-9]*/comm 2>/dev/null | grep -qx $1 || exit 0; sleep 1; done; exit 1"; }

echo "==> build komando for Linux and start the servers"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)" go build -o "$KOMANDO_BIN" ./cmd/komando)
"${DC[@]}" up -d --build >/dev/null 2>&1
sleep 5

echo "==> openconnect family (ocserv, AnyConnect protocol)"
in_client sh -c 'cp /certs/ca.crt /usr/local/share/ca-certificates/e2e.crt && update-ca-certificates >/dev/null 2>&1'
in_client sh -c 'printf ocpass | komando secret set oc-pass' >/dev/null
in_client komando vpn add oc anyconnect --portal https://ocserv --user e2e --password-ref secret:oc-pass --check 192.168.99.1:7000 >/dev/null
[ "$(in_client komando test oc | jget 'd["data"]["summary"]["ok"]')" = 1 ] || fail "anyconnect connects" ocserv
ok "anyconnect connects on demand and reaches the VPN side"
[ "$(in_client komando vpn status | jget '[v for v in d["data"]["vpns"] if v["name"]=="oc"][0]["up"]')" = True ] || fail "status up"
ok "vpn status shows the session"
in_client komando vpn add oc-mfa anyconnect --portal https://ocserv --user e2e --mfa >/dev/null
[ "$(in_client komando test oc-mfa | jget 'd["data"]["results"][0]["error"]["code"]' || true)" = VPN_LOGIN_REQUIRED ] || fail "mfa"
ok "an --mfa VPN asks for a person (VPN_LOGIN_REQUIRED), never connects by itself"
in_client sh -c 'command -v openconnect ocproxy' >/dev/null 2>&1 && fail "the client image has openconnect"
ok "no openconnect or ocproxy on the client (AnyConnect is built in)"
[ "$(in_client komando status | jget '[v["name"] for v in d["data"]["vpns"]]')" = "['oc']" ] || fail "status lists the AnyConnect session"
ok "komando status lists the session"
in_client komando vpn down oc >/dev/null
gone komando || fail "the AnyConnect session process left running"
ok "vpn down ends the session"
in_client sh -c 'printf wrong | komando secret set oc-wrong' >/dev/null
in_client komando vpn add oc-bad anyconnect --portal https://ocserv --user e2e --password-ref secret:oc-wrong --check 192.168.99.1:7000 >/dev/null
out=$(in_client komando test oc-bad || true)
grep -qi 'refused' <<<"$out" || { echo "$out"; fail "a wrong password is named"; }
ok "a wrong AnyConnect password says so"

echo "==> Tailscale (Headscale)"
for _ in $(seq 1 30); do "${DC[@]}" exec -T headscale headscale users list >/dev/null 2>&1 && break; sleep 1; done
"${DC[@]}" exec -T headscale headscale users create e2e >/dev/null
UID_=$("${DC[@]}" exec -T headscale headscale users list -o json | jget '[u for u in d if u["name"]=="e2e"][0]["id"]')
KEY=$("${DC[@]}" exec -T headscale headscale preauthkeys create --user "$UID_" --reusable -o json | jget 'd["key"]')
"${DC[@]}" exec -T -d peer sh -c 'tailscaled --tun=userspace-networking --statedir=/tmp/ts >/tmp/tsd.log 2>&1'
sleep 2
"${DC[@]}" exec -T peer tailscale up --login-server=http://headscale:8080 --authkey="$KEY" --hostname=peer >/dev/null
"${DC[@]}" exec -T -d peer sh -c 'while true; do nc -l -p 7000 >/dev/null 2>&1; done'
PEER_IP=$("${DC[@]}" exec -T peer tailscale ip -4 | tr -d '\r')
in_client sh -c "printf %s '$KEY' | komando secret set ts-key" >/dev/null
in_client komando vpn add tailnet tailscale --server http://headscale:8080 --password-ref secret:ts-key --check "$PEER_IP:7000" >/dev/null
[ "$(in_client komando test tailnet | jget 'd["data"]["summary"]["ok"]')" = 1 ] || fail "tailscale connects"
ok "tailscale connects on demand and reaches a tailnet node ($PEER_IP)"
in_client sh -c 'command -v tailscaled tailscale' >/dev/null 2>&1 && fail "the client image has tailscale programs"
ok "no tailscale or tailscaled program on the client"
# the key comes in through the environment and grep reads it from a file, so this check's own
# command lines (including grep's, which cat may read) never hold it
"${DC[@]}" exec -T -e "K=$KEY" client sh -c 'f=$(mktemp) && printf %s "$K" > "$f" || exit 1; cat /proc/[0-9]*/cmdline 2>/dev/null | tr "\\0" " " | grep -qFf "$f"; r=$?; rm -f "$f"; [ "$r" = 1 ]' || fail "auth key visible in a command line"
ok "the auth key is not on any command line"
[ "$(in_client komando status | jget '[v["name"] for v in d["data"]["vpns"]]')" = "['tailnet']" ] || fail "status lists the tailnet"
ok "komando status lists the tailnet session"
in_client komando vpn down tailnet >/dev/null
gone komando || fail "the Tailscale session process left running"
ok "vpn down stops the session"
[ "$(in_client komando test tailnet | jget 'd["data"]["summary"]["ok"]')" = 1 ] || fail "tailscale reconnects"
ok "a second session reuses the node (no new login)"
in_client komando vpn down tailnet >/dev/null

echo
echo "passed: $PASS  failed: 0"
