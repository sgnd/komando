#!/usr/bin/env bash
# komando's own IPsec clients, end to end, against a real strongSwan 5.9
# server with xl2tpd: L2TP/IPsec (IKEv1 main mode, PSK, PPP MS-CHAPv2),
# Cisco-style IPsec (IKEv1 aggressive mode, group name, XAUTH, mode
# config) and IKEv2 (PSK; EAP-MSCHAPv2 with the server's certificate).
# komando runs in a Linux client container on the same Docker network
# (Docker Desktop does not forward UDP from the host), with no admin
# rights, and the client's routes do not change. The SAs are short-lived
# here, so rekeys by both sides happen during the run.
#
#   test/e2e/ipsec/run.sh      (needs docker and go; KEEP=1 keeps the lab)
#
# The work folder is under $HOME because Docker Desktop shares it by default.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
W="$(mktemp -d "$HOME/.komando-ipsec-e2e.XXXX")"
NET=komando-ipsec-e2e SERVER=komando-ipsec-e2e-server CLIENT=komando-ipsec-e2e-client
cleanup() {
  [ -n "${KEEP:-}" ] && { echo "kept: docker exec -it $CLIENT sh; work folder $W"; return; }
  docker rm -f "$SERVER" "$CLIENT" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$W"
}
trap cleanup EXIT
fail() {
  echo "FAIL $*"
  docker exec "$SERVER" sh -c 'grep -E "IKE\]|ENC\]|CFG\] (selected|no )" /tmp/charon.log | tail -n 12; tail -n 4 /tmp/xl2tpd.log' 2>&1 | sed 's/^/  server: /'
  exit 1
}
in_client() { docker exec -i -e KOMANDO_HOME=/tmp/k -e KOMANDO_VAULT_PASS=e2e -e KOMANDO_OUTPUT=json -e "KOMANDO_IPSEC_LIFETIME=${LIFETIME:-}" "$CLIENT" "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
ok_test() { [ "$(in_client komando test "$1" | jget 'd["data"]["summary"]["ok"]')" = 1 ]; }
show_log() { in_client sh -c "tail -n 15 /tmp/k/vpn/$1.log" 2>&1 | sed 's/^/  client: /' || true; }

(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)" go build -o "$W/komando" ./cmd/komando)
mkdir -p "$W/pki"
docker network create "$NET" >/dev/null
docker run -d --name "$SERVER" --network "$NET" --network-alias ipsecsrv --privileged \
  -v "$ROOT/test/e2e/ipsec:/s:ro" -v "$W/pki:/pki" alpine:3.22 /s/server.sh >/dev/null
docker run -d --name "$CLIENT" --network "$NET" -v "$W/komando:/usr/local/bin/komando:ro" -v "$W/pki:/pki:ro" \
  python:3.13-alpine sleep infinity >/dev/null
for _ in $(seq 1 240); do
  docker exec "$SERVER" sh -c 'test -s /pki/other-ca.pem && ipsec statusall 2>/dev/null | grep -q "ikev2-eap:" && grep -q Listening /tmp/xl2tpd.log' 2>/dev/null && break
  sleep 1
done
docker exec "$SERVER" sh -c 'ipsec statusall 2>/dev/null | grep -q "ikev2-eap:"' || fail "the strongSwan server did not start"

routes_before=$(docker exec "$CLIENT" sh -c 'ip route; ip addr' | md5sum)
for s in "l2tp-psk l2tp-psk" "l2tp-pass l2tp-pass" "group group-secret" "xauth xauth-pass" "v2psk ikev2-psk" "eap eap-pass" "wrong nope"; do
  set -- $s
  printf '%s' "$2" | in_client komando secret set "$1" >/dev/null
done

LIFETIME=40s
add() { in_client komando vpn add "$@" >/dev/null || fail "vpn add $1"; }
add l2tp l2tp --server ipsecsrv --psk-ref secret:l2tp-psk --user l2tp-user --password-ref secret:l2tp-pass --check 10.30.0.1:8080
add cisco ipsec --server ipsecsrv --id staff --psk-ref secret:group --user xauth-user --password-ref secret:xauth --check 10.40.0.1:8080
add v2psk ikev2 --server ipsecsrv --id psk-client --psk-ref secret:v2psk --check 10.50.0.1:8080
add v2eap ikev2 --server ipsecsrv --user eap-user --password-ref secret:eap --ca /pki/ca.pem --check 10.50.0.1:8080
for spec in "l2tp L2TP/IPsec (IKEv1 main mode, PPP MS-CHAPv2)" "cisco Cisco-style IPsec (aggressive mode, XAUTH, mode config)" \
  "v2psk IKEv2 with a pre-shared key" "v2eap IKEv2 with EAP-MSCHAPv2 and the server's certificate"; do
  name=${spec%% *}
  # l2tp and v2psk keep komando's normal lifetimes, so the server's rekeys come first
  LIFETIME=40s; case $name in l2tp|v2psk) LIFETIME= ;; esac
  ok_test "$name" || { in_client komando test "$name" || true; show_log "$name"; fail "$name connects"; }
  echo "ok   $name: ${spec#* } connects and reaches the VPN side"
done

[ "$(in_client komando status | python3 -c 'import json,sys; print(sorted(v["name"] for v in json.load(sys.stdin)["data"]["vpns"]))')" = "['cisco', 'l2tp', 'v2eap', 'v2psk']" ] || fail "status lists the sessions"
echo "ok   komando status lists the four sessions"
[ "$(in_client komando vpn up l2tp | jget 'd["data"]["session"].get("socks_pass", "") + d["data"]["session"].get("socks_user", "")')" = "" ] || fail "vpn up shows the session's SOCKS login"
echo "ok   vpn up hides the session's SOCKS password"

# 200 seconds of use (longer than five missed dead peer checks): komando
# rekeys cisco's ESP every ~32s and its IKE SA at ~96s; the server rekeys
# l2tp's ESP (~40s) and v2psk's CHILD SA (~40s) and IKE SA (~80s), and asks
# v2eap to log in again (~72s)
end=$((SECONDS + 200))
while [ $SECONDS -lt $end ]; do
  for name in l2tp cisco v2psk v2eap; do
    ok_test "$name" || { in_client komando test "$name" | head -c 800 || true; echo; show_log "$name"; fail "$name still works at $((200 - end + SECONDS))s"; }
  done
  sleep 8
done
for want in "l2tp:IKEv1: the server rekeyed ESP" "cisco:IKEv1: new IKE SA" "v2psk:IKEv2: the server rekeyed ESP" \
  "v2psk:IKEv2: the server rekeyed the IKE SA" "v2eap:IKEv2: new CHILD SA" "v2eap:IKEv2: logged in again"; do
  name=${want%%:*}
  in_client grep -q "${want#*:}" "/tmp/k/vpn/$name.log" || { show_log "$name"; fail "$name: no '${want#*:}' in its log"; }
done
[ "$(in_client grep -c "IKEv1: ESP up" /tmp/k/vpn/cisco.log)" -ge 3 ] || { show_log cisco; fail "cisco rekeyed ESP fewer than twice"; }
[ "$(in_client grep -c "IKEv1: the server rekeyed ESP" /tmp/k/vpn/l2tp.log)" -ge 2 ] || { show_log l2tp; fail "the server rekeyed l2tp's ESP fewer than twice"; }
echo "ok   all four stay up for 200s through rekeys (komando's and the server's, ESP and IKE)"

# the server drops the ESP SA in use (its lifetime ran out): komando makes a new one
child=$(docker exec "$SERVER" sh -c 'ipsec status | grep -o "l2tp{[0-9]*}" | tail -1')
docker exec "$SERVER" ipsec down "$child" >/dev/null
sleep 4
ok_test l2tp || { show_log l2tp; fail "l2tp after the server deleted its ESP SA"; }
in_client grep -q "the server deleted the ESP SA in use" /tmp/k/vpn/l2tp.log || { show_log l2tp; fail "no new ESP SA after the server's delete"; }
echo "ok   l2tp carries on when the server deletes the ESP SA in use"

in_client sh -c 'cat /proc/[0-9]*/comm 2>/dev/null | grep -Ex "charon|pluto|racoon|xl2tpd|pppd|openvpn"' >/dev/null 2>&1 && fail "a VPN program on the client"
echo "ok   no strongSwan, xl2tpd or pppd on the client"
[ "$(docker exec "$CLIENT" sh -c 'ip route; ip addr' | md5sum)" = "$routes_before" ] || fail "the client's routes or addresses changed"
echo "ok   the client's routes and addresses are unchanged"
left=$(in_client sh -c 'ls /tmp/k/vpn/ | grep -Ev "[.](log|lock)$"' || true)
[ -z "$left" ] || fail "config or password left on disk: $left"
echo "ok   no keys or passwords left on disk"
for name in l2tp cisco v2psk v2eap; do
  in_client grep -Eq "l2tp-psk|l2tp-pass|group-secret|xauth-pass|ikev2-psk|eap-pass" "/tmp/k/vpn/$name.log" && fail "a secret in $name's log"
done
echo "ok   no secret in the session logs"
in_client komando vpn down --all >/dev/null
[ "$(in_client komando status | jget 'len(d["data"]["vpns"])')" = 0 ] || fail "vpn down ends the sessions"
sleep 2
docker exec "$SERVER" sh -c 'ipsec status' | grep -q ESTABLISHED && fail "the server still has SAs after vpn down (no delete sent)"
echo "ok   vpn down ends the sessions and tells the server"
LIFETIME=

# refusals say what is wrong
refused() { # name want-in-message add-args...
  local name=$1 want=$2; shift 2
  in_client komando vpn add "$name" "$@" --overwrite >/dev/null || fail "vpn add $name"
  out=$(in_client komando test "$name" || true)
  grep -qi -- "$want" <<<"$out" || { echo "$out" | head -c 600; echo; show_log "$name"; fail "$name: want '$want'"; }
  echo "ok   $name is refused: $want"
}
refused bad-psk "pre-shared key" l2tp --server ipsecsrv --psk-ref secret:wrong --user l2tp-user --password-ref secret:l2tp-pass --check 10.30.0.1:8080
refused bad-ppp "wrong user name or password" l2tp --server ipsecsrv --psk-ref secret:l2tp-psk --user l2tp-user --password-ref secret:wrong --check 10.30.0.1:8080
refused bad-xauth "XAUTH" ipsec --server ipsecsrv --id staff --psk-ref secret:group --user xauth-user --password-ref secret:wrong --check 10.40.0.1:8080
refused bad-group "pre-shared key" ipsec --server ipsecsrv --id staff --psk-ref secret:wrong --user xauth-user --password-ref secret:xauth --check 10.40.0.1:8080
refused bad-v2psk "AUTHENTICATION_FAILED" ikev2 --server ipsecsrv --id psk-client --psk-ref secret:wrong --check 10.50.0.1:8080
refused bad-eap "wrong user name or password" ikev2 --server ipsecsrv --user eap-user --password-ref secret:wrong --ca /pki/ca.pem --check 10.50.0.1:8080
refused bad-ca "not trusted" ikev2 --server ipsecsrv --user eap-user --password-ref secret:eap --ca /pki/other-ca.pem --check 10.50.0.1:8080
# the certificate is made out to ipsecsrv, not to the server's address
SRV_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SERVER")
refused bad-name "is not for" ikev2 --server "$SRV_IP" --user eap-user --password-ref secret:eap --ca /pki/ca.pem --check 10.50.0.1:8080
refused no-server "does not answer" l2tp --server 10.255.255.1 --psk-ref secret:l2tp-psk --user l2tp-user --password-ref secret:l2tp-pass --check 10.30.0.1:8080

# mistakes are caught when the VPN is added
usage() { # want-in-message add-args...
  local want=$1; shift
  out=$(in_client komando vpn add bad "$@" 2>&1 || true)
  grep -q -- "$want" <<<"$out" || { echo "$out"; fail "vpn add $*: want '$want'"; }
}
usage "needs --server" l2tp --psk-ref secret:l2tp-psk --user u
usage "l2tp needs --psk-ref" l2tp --server ipsecsrv --user u
usage "ikev2 needs --psk-ref" ikev2 --server ipsecsrv
usage "--config is not used" ipsec --server ipsecsrv --psk-ref secret:group --config /etc/hosts
usage "--ca must be a PEM" ikev2 --server ipsecsrv --user u --ca /etc/hosts
out=$(in_client komando vpn edit v2psk --remote-id x --id y --dry-run 2>&1); grep -q would_change <<<"$out" || fail "vpn edit --remote-id on ikev2"
out=$(in_client komando vpn edit l2tp --remote-id x 2>&1 || true); grep -q "not used by l2tp" <<<"$out" || fail "vpn edit --remote-id on l2tp is refused"
echo "ok   vpn add and vpn edit refuse settings that cannot work"

# a session whose server goes away ends instead of looking up
ok_test v2psk || fail "v2psk again"
docker exec "$SERVER" sh -c 'ipsec stop' >/dev/null 2>&1
for _ in $(seq 1 90); do [ "$(in_client komando status | jget '[v["name"] for v in d["data"]["vpns"]]')" = "[]" ] && break; sleep 2; done
[ "$(in_client komando status | jget '[v["name"] for v in d["data"]["vpns"]]')" = "[]" ] || fail "a dead IPsec VPN still shows as up"
echo "ok   a session whose server went away ends (status no longer lists it)"
why=$(in_client komando vpn status | python3 -c 'import json,sys; r=[v for v in json.load(sys.stdin)["data"]["vpns"] if v["name"]=="v2psk"][0]; print(r.get("last_end",""), len(r.get("last_log",[])))')
case $why in *"stopped answering"*|*"ended"*) ;; *) fail "vpn status does not say why v2psk ended: $why";; esac
echo "ok   vpn status says why the session ended ($why lines of log)"
