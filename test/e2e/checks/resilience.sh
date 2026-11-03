# Long waits outlive SSH connections: when the server (or a NAT on the way)
# drops komando's connection, `job wait` connects again and keeps waiting
# until the job ends, as kubectl wait does. (Found in real use: a 25-minute
# install whose wait ended after ~10 minutes with the job still running.)
P="${PROJECT:-komando-e2e}"
JID=$($K job start direct -- 'sleep 15; echo done' | jget 'd["data"]["jobs"][0]["id"]')
( rc=0; $K job wait "$JID" --timeout 2m --interval 2s >"$TMP/wait.out" 2>&1 || rc=$?; echo "$rc" >"$TMP/wait.rc" ) &
WPID=$!
# cut its sessions again and again at random moments: during the
# handshake, while a channel opens, halfway through reading the status
for _ in $(seq 1 12); do
  sleep "0.$((RANDOM % 5 + 3))"
  docker exec "$P-direct-1" pkill -f 'sshd-session: agent|sshd: agent' 2>/dev/null || true
done
wait "$WPID"
[ "$(cat "$TMP/wait.rc")" = 0 ] || { echo "  job wait said:"; head -c 800 "$TMP/wait.out"; echo; }
check "job wait survives dropped connections" "0 exited" "$(cat "$TMP/wait.rc") $(jget 'd.get("data", {}).get("state")' <"$TMP/wait.out" || true)"
check "the job really ran to its end" done "$($K job logs "$JID" | jget 'd["data"]["content"].strip()' || true)"
