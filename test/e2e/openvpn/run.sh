#!/usr/bin/env bash
# komando's own OpenVPN client, end to end, against real OpenVPN 2.6 servers
# in one container: TCP; UDP with tls-crypt and ChaCha20-Poly1305; UDP with
# tls-auth, AES-256-CBC and HMAC-SHA256 (also through the PRF of servers
# without TLS key export); and a user-name-and-password login. komando runs
# in a Linux client container on the same Docker network (Docker Desktop
# does not forward UDP from the host), with no openvpn program, no Docker
# and no admin rights, and the client's routes do not change.
#
#   test/e2e/openvpn/run.sh        (needs docker and go)
#
# The work folder is under $HOME because Docker Desktop shares it by default.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
W="$(mktemp -d "$HOME/.komando-ovpn-e2e.XXXX")"
NET=komando-ovpn-e2e SERVER=komando-ovpn-e2e-server CLIENT=komando-ovpn-e2e-client
cleanup() { docker rm -f "$SERVER" "$CLIENT" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT
fail() { echo "FAIL $*"; docker exec "$SERVER" sh -c 'tail -n 6 /tmp/*.log' 2>&1 | sed 's/^/  server: /'; exit 1; }
in_client() { docker exec -i -e KOMANDO_HOME=/tmp/k -e KOMANDO_VAULT_PASS=e2e -e KOMANDO_OUTPUT=json -e "KOMANDO_OVPN_DEBUG=${KOMANDO_OVPN_DEBUG:-}" "$CLIENT" "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# ptyrun INPUT CMD...: CMD in a pseudo-terminal inside the client (test/e2e/pty.sh's helper)
# only the first Python block (ptyrun): pty.sh holds ptykeys after it
sed -n "/<<'PY'/,/^PY\$/{p;/^PY\$/q;}" "$ROOT/test/e2e/pty.sh" | sed '1d;$d' > "$W/pty.py"
ptyrun() { docker exec -i -e KOMANDO_HOME=/tmp/k -e KOMANDO_VAULT_PASS=e2e "$CLIENT" python3 -I - "$@" < "$W/pty.py"; }

(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)" go build -o "$W/komando" ./cmd/komando)
mkdir -p "$W/pki"
docker run --rm -v "$ROOT/test/e2e/openvpn:/s:ro" -v "$W/pki:/pki" alpine:3.22 /s/setup.sh /pki
docker network create "$NET" >/dev/null
docker run -d --rm --name "$SERVER" --network "$NET" --network-alias ovpnsrv --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$W/pki:/pki:ro" --entrypoint sh alpine:3.22 -c \
  'apk add -q --no-cache openvpn && for c in tcp crypt auth login; do openvpn --config /pki/$c.conf --daemon ovpn-$c --log /tmp/$c.log; done; sleep infinity' >/dev/null
docker run -d --rm --name "$CLIENT" --network "$NET" -v "$W/komando:/usr/local/bin/komando:ro" -v "$W/pki:/pki:ro" \
  python:3.13-alpine sleep infinity >/dev/null
# the server installs openvpn first, which can take a minute on a slow mirror
ready=0
for _ in $(seq 1 180); do [ "$(docker exec "$SERVER" sh -c 'grep -l "Initialization Sequence Completed" /tmp/*.log 2>/dev/null | wc -l')" = 4 ] && ready=1 && break; sleep 1; done
[ "$ready" = 1 ] || fail "the OpenVPN servers did not start within 180 s (apk add openvpn, or a server config)"

routes_before=$(docker exec "$CLIENT" sh -c 'ip route; ip addr' | md5sum)
in_client sh -c 'printf e2e-pass | komando secret set ovpn-pass' >/dev/null
# name profile check-address [extra vpn add flags]
for spec in "office tcp 10.8.0.1:1194" "crypt crypt 10.9.0.1:1194" "oldstyle auth 10.10.0.1:1194" "login login 10.11.0.1:1194 --user e2e-user --password-ref secret:ovpn-pass"; do
  set -- $spec
  name=$1 profile=$2 check=$3; shift 3
  in_client komando vpn add "$name" openvpn --config "/pki/$profile.ovpn" --check "$check" "$@" >/dev/null || fail "vpn add $name"
  [ "$(in_client komando test "$name" | jget 'd["data"]["summary"]["ok"]')" = 1 ] || {
    in_client komando test "$name" || true; in_client tail -20 "/tmp/k/vpn/$name.log" || true; fail "$name ($profile) connects"; }
  echo "ok   $name: $profile profile connects and reaches the VPN side"
done

# the tcp server renegotiates the keys every 15 seconds: the session must carry on
sleep 20
[ "$(in_client komando test office | jget 'd["data"]["summary"]["ok"]')" = 1 ] || { in_client tail -20 /tmp/k/vpn/office.log || true; fail "office after a key renegotiation"; }
docker exec "$SERVER" grep -q 'TLS: soft reset' /tmp/tcp.log || fail "the server did not renegotiate"
echo "ok   the session carries on through a key renegotiation"
[ "$(in_client komando status | python3 -c 'import json,sys; print(sorted(v["name"] for v in json.load(sys.stdin)["data"]["vpns"]))')" = "['crypt', 'login', 'office', 'oldstyle']" ] || fail "status lists the sessions"
echo "ok   komando status lists the four sessions"
# the prompt note counts them: it reads only runtime.pids, never the sealed store
[ "$(in_client komando status --short)" = "vpn:4" ] || fail "status --short counts the VPNs: got [$(in_client komando status --short)]"
echo "ok   komando status --short counts them"
in_client sh -c 'command -v openvpn || cat /proc/[0-9]*/comm 2>/dev/null | grep -x openvpn' >/dev/null 2>&1 && fail "an openvpn program on the client"
echo "ok   no openvpn program on the client"
[ "$(docker exec "$CLIENT" sh -c 'ip route; ip addr' | md5sum)" = "$routes_before" ] || fail "the client's routes or addresses changed"
echo "ok   the client's routes and addresses are unchanged"
S=$(in_client komando vpn status | python3 -c 'import json,sys; print([v for v in json.load(sys.stdin)["data"]["vpns"] if v["name"] == "office"][0]["socks"])')
# a SOCKS5 greeting offering only "no login" must be refused (0xFF)
reply=$(docker exec "$CLIENT" python3 -c "
import socket; h, p = '$S'.split(':'); s = socket.create_connection((h, int(p)), 3); s.sendall(b'\x05\x01\x00'); print(s.recv(2).hex())")
[ "$reply" = 05ff ] || fail "the session's SOCKS port takes clients without its login ($reply)"
echo "ok   the session's SOCKS port refuses anyone without its login"
left=$(in_client sh -c 'ls /tmp/k/vpn/ | grep -Ev "[.](log|lock)$"' || true)
[ -z "$left" ] || fail "config or password left on disk: $left"
echo "ok   no config or password left on disk"
in_client komando vpn down --all >/dev/null
[ "$(in_client komando status | jget 'len(d["data"]["vpns"])')" = 0 ] || fail "vpn down ends the sessions"
echo "ok   vpn down ends the sessions"

# the PRF of servers without TLS key export (OpenVPN before 2.6)
docker exec "$SERVER" sh -c ': > /tmp/auth.log.mark; wc -l < /tmp/auth.log > /tmp/auth.lines'
[ "$(docker exec -i -e KOMANDO_HOME=/tmp/k -e KOMANDO_VAULT_PASS=e2e -e KOMANDO_OUTPUT=json -e KOMANDO_OVPN_NO_EKM=1 "$CLIENT" komando test oldstyle | jget 'd["data"]["summary"]["ok"]')" = 1 ] || fail "keys from the OpenVPN PRF"
docker exec "$SERVER" sh -c 'tail -n +$(( $(cat /tmp/auth.lines) + 1 )) /tmp/auth.log | grep -q "protocol-flags.*tls-ekm"' && fail "the PRF run still used TLS key export"
echo "ok   keys from the OpenVPN PRF (no TLS key export)"
in_client komando vpn down --all >/dev/null

# a wrong password is named
in_client sh -c 'printf nope | komando secret set ovpn-wrong' >/dev/null
in_client komando vpn add badlogin openvpn --config /pki/login.ovpn --check 10.11.0.1:1194 --user e2e-user --password-ref secret:ovpn-wrong >/dev/null
out=$(in_client komando test badlogin || true)
grep -q 'refused the login' <<<"$out" || { echo "$out"; in_client tail -5 /tmp/k/vpn/badlogin.log || true; fail "a wrong password says so"; }
echo "ok   a refused login says so"

# a VPN that started by itself says so, for a person
ptyrun '' komando test office | tr -d '\r' | grep -q '^komando: vpn office connected; it stays up until unused for 30m' || fail "no notice when a command starts the VPN"
echo "ok   a person is told the VPN stays up"
in_client komando vpn down --all >/dev/null

# when the server goes away, the session ends instead of looking up
[ "$(in_client komando test office | jget 'd["data"]["summary"]["ok"]')" = 1 ] || fail "office again"
docker exec "$SERVER" pkill -f tcp.conf
for _ in $(seq 1 20); do [ "$(in_client komando status | jget '[v["name"] for v in d["data"]["vpns"]]')" = "[]" ] && break; sleep 1; done
[ "$(in_client komando status | jget '[v["name"] for v in d["data"]["vpns"]]')" = "[]" ] || fail "a dead VPN still shows as up"
echo "ok   a session whose server went away ends (status no longer lists it)"

# profiles komando cannot run faithfully are refused when added
in_client sh -c 'printf "comp-lzo yes\n" | cat /pki/tcp.ovpn - > /tmp/lzo.ovpn'
[ "$(in_client komando vpn add lzo openvpn --config /tmp/lzo.ovpn --check 10.8.0.1:1194 | jget 'd["error"]["code"]' || true)" = OVPN_UNSUPPORTED ] || fail "compression is refused"
echo "ok   a compressing profile is refused at vpn add (VORACLE)"
