# shellcheck shell=bash
# A run in a session outlives SSH connections: when the server (or a NAT on
# the way) drops komando's connection, the run goes on there, and
# `exec --attach` reads its output and its exit code afterwards.
P="${PROJECT:-komando-e2e}"
( rc=0; $K exec direct --wait 2m -- 'sleep 15; echo done' >"$TMP/wait.out" 2>"$TMP/wait.err" || rc=$?; echo "$rc" >"$TMP/wait.rc" ) &
WPID=$!
# cut its sessions again and again at random moments: during the
# handshake, while a channel opens, halfway through reading the status
for _ in $(seq 1 12); do
  sleep "0.$((RANDOM % 5 + 3))"
  docker exec "$P-direct-1" pkill -f 'sshd-session: agent|sshd: agent' 2>/dev/null || true
done
wait "$WPID"
JID=$(sess_id <"$TMP/wait.out")
# the exec itself may have lost its connection (exit 4): the session went on
# there, and --attach reads it to its end
O=$($K exec direct --attach "$JID" --wait 2m || true)
check "a run in a session survives dropped connections" "done 0" "$(echo "$O" | jget 'd["data"]["results"][0]["stdout"].strip() + " " + str(d["data"]["results"][0]["exit_code"])' || true)"
