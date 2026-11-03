#!/usr/bin/env bash
# OpenVPN in a container, end to end: a throwaway OpenVPN server, then
# komando connects through its own container and checks that the laptop's
# network is untouched, the SOCKS port needs komando's login, and no
# config or password is left on disk.
#
#   test/e2e/openvpn/run.sh        (needs docker, go, python3, curl)
#
# The work folder is under $HOME because Docker Desktop shares it by default.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
W="$(mktemp -d "$HOME/.komando-ovpn-e2e.XXXX")"
export KOMANDO_HOME="$W/home" KOMANDO_VAULT_PASS=e2e
# a script, even when an AI agent starts it (the status line checks need that)
unset CLAUDECODE GEMINI_CLI CODEX_SANDBOX CODEX_THREAD_ID CURSOR_AGENT KOMANDO_AGENT AI_AGENT
K="$W/komando"
SERVER=komando-e2e-ovpn-server
cleanup() { "$K" vpn down --all >/dev/null 2>&1 || true; docker rm -f "$SERVER" >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT
fail() { echo "FAIL $*"; exit 1; }
. "$ROOT/test/e2e/pty.sh"

(cd "$ROOT" && go build -o "$K" ./cmd/komando)
mkdir -p "$W/pki"
docker run --rm -v "$ROOT/test/e2e/openvpn:/s:ro" -v "$W/pki:/pki" alpine:3.22 /s/setup.sh /pki
docker run -d --rm --name "$SERVER" --cap-add NET_ADMIN --device /dev/net/tun -p 127.0.0.1:11194:1194 \
  -v "$W/pki:/pki:ro" --entrypoint sh alpine:3.22 -c 'apk add -q --no-cache openvpn && exec openvpn --config /pki/server.conf' >/dev/null
sleep 8

"$K" vpn add office openvpn --config "$W/pki/client.ovpn" --check 10.8.0.1:1194 >/dev/null
[ "$("$K" test office 2>"$W/err" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["summary"]["ok"])')" = 1 ] || fail "connect"
echo "ok   connects through the container"
grep -q '^komando:' "$W/err" && fail "a script got a status line"
echo "ok   no status line for scripts"
[ "$("$K" status | python3 -c 'import json,sys; print([v["name"] for v in json.load(sys.stdin)["data"]["vpns"]])')" = "['office']" ] || fail "status does not list the session"
echo "ok   komando status lists the VPN session"
[ "$("$K" prompt)" = "vpn:office" ] || fail "prompt does not show the VPN"
echo "ok   komando prompt shows the VPN"
S=$("$K" vpn status | python3 -c 'import json,sys; print([v for v in json.load(sys.stdin)["data"]["vpns"] if v["up"]][0]["socks"])')
if curl -s -m 5 --socks5 "$S" telnet://10.8.0.1:1194 </dev/null >/dev/null 2>&1; then fail "SOCKS without login"; fi
echo "ok   SOCKS port refuses anyone without komando's login"
[ -z "$(ls "$KOMANDO_HOME/vpn/office-openvpn" 2>/dev/null)" ] || fail "config or password left on disk"
echo "ok   no config or password left on disk"
if command -v ip >/dev/null; then ip route get 10.8.0.1 | grep -q tun && fail "laptop route changed"
else route -n get 10.8.0.1 2>/dev/null | grep -q utun && fail "laptop route changed"; fi
echo "ok   laptop network untouched"
"$K" vpn down office >/dev/null
ptyrun '' "$K" test office | tr -d '\r' | grep -q '^komando: vpn office connected; it stays up until unused for 30m' || fail "no notice when a command starts the VPN"
echo "ok   a person is told the VPN stays up"
"$K" vpn down office >/dev/null
docker ps --format '{{.Names}}' | grep -q komando-vpn-office && fail "container left running"
echo "ok   vpn down removes the container"
