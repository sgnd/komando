# WireGuard end to end: wgpeer (test/e2e/wgpeer) is a user-space WireGuard
# server on this computer with a TCP echo at 10.77.0.1:7 inside the tunnel.
# komando connects with the .conf it prints, reaches the echo only through
# the tunnel, and says VPN_DOWN when the far end does not answer.
R="${ROOT:-$(pwd)}"
(cd "$R" && go build -o "$TMP/wgpeer" ./test/e2e/wgpeer)
"$TMP/wgpeer" >"$TMP/wg.conf" 2>"$TMP/wg.log" &
WGPID=$!
for _ in $(seq 1 50); do grep -q '^AllowedIPs' "$TMP/wg.conf" 2>/dev/null && break; sleep 0.2; done
W="t-wg-$$"
q $K vpn add "$W" wireguard --config "$TMP/wg.conf" --check 10.77.0.1:7
check "WireGuard keys go to the vault, not the inventory" False "$($K vpn show "$W" | jget '"PrivateKey" in json.dumps(d)')"
check "vpn test reaches 10.77.0.1:7 through WireGuard" True "$($K vpn test "$W" | jget 'd["ok"]')"
q $K vpn up "$W"
check "vpn status: up" True "$($K vpn status | jget 'any(v["name"] == "'"$W"'" and v["up"] for v in (d["data"]["vpns"] if isinstance(d["data"], dict) and "vpns" in d["data"] else d["data"]))')"
q $K vpn down "$W"

# the same keys, but the far end is gone: up must not claim success
sed 's/^Endpoint = 127.0.0.1:[0-9]*/Endpoint = 127.0.0.1:9/' "$TMP/wg.conf" >"$TMP/wg-dead.conf"
q $K vpn add "$W-dead" wireguard --config "$TMP/wg-dead.conf" --check 10.77.0.1:7
check "vpn up with no answer from the far end is VPN_DOWN" VPN_DOWN "$($K vpn up "$W-dead" --timeout 20s | jget 'd["error"]["code"]' || true)"

kill "$WGPID" 2>/dev/null || true
q $K vpn rm "$W" "$W-dead"
