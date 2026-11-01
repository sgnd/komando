#!/usr/bin/env bash
# End-to-end test: starts disposable SSH containers (bastion -> private target,
# plus a directly reachable box), then drives the real komando binary.
#
#   make e2e            (or)   test/e2e/run.sh
#
# Needs: docker (with compose), go, python3. Set KEEP=1 to keep containers.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
E2E="$ROOT/test/e2e"
K="$ROOT/bin/komando"
export KOMANDO_HOME="$(mktemp -d)"
export KOMANDO_ACTOR="e2e"
PROJECT=komando-e2e
PASS=0
FAIL=0

cleanup() {
  [ "${KEEP:-0}" = 1 ] || docker compose -p "$PROJECT" -f "$E2E/compose.yml" down -v >/dev/null 2>&1 || true
  pkill -f "komando tunnel serve" >/dev/null 2>&1 || true
  rm -rf "$KOMANDO_HOME"
}
trap cleanup EXIT

# jget '<python expression on d>' : evaluate against JSON on stdin
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

check() { # check "name" expected actual
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  ok   $1"
  else FAIL=$((FAIL+1)); echo "  FAIL $1: expected [$2] got [$3]"; fi
}

echo "==> build"
(cd "$ROOT" && go build -o bin/komando ./cmd/komando)

echo "==> start containers"
docker compose -p "$PROJECT" -f "$E2E/compose.yml" up -d --build --wait >/dev/null 2>&1 \
  || docker compose -p "$PROJECT" -f "$E2E/compose.yml" up -d --build >/dev/null
for i in $(seq 1 30); do nc -z 127.0.0.1 2222 2>/dev/null && nc -z 127.0.0.1 2223 2>/dev/null && break; sleep 1; done
sleep 1

echo "==> inventory & vault"
echo -n agentpass | $K secret set agent-pass >/dev/null
$K host add bastion agent@127.0.0.1:2222 --password-ref secret:agent-pass -g lab >/dev/null
$K host add direct agent@127.0.0.1:2223 --password-ref secret:agent-pass -g lab -t test >/dev/null
$K host add target agent@target --jump bastion --password-ref secret:agent-pass -g lab --protected >/dev/null
check "host list count" 3 "$($K host list | jget 'd["data"]["count"]')"
check "secret never printed" False "$($K secret get agent-pass | jget '"value" in d["data"]')"

echo "==> connectivity (incl. jump host)"
check "host test all ok" 3 "$($K host test @lab | jget 'd["data"]["summary"]["ok"]')"

echo "==> exec"
check "exec stdout via jump" "target" "$($K exec target --read-only -- hostname | jget 'd["data"]["results"][0]["stdout"].strip()')"
set +e
$K exec direct -- 'exit 3' >/dev/null; check "non-zero exit -> 5" 5 $?
$K exec direct -- 'rm -rf /' >/dev/null; check "policy blocks rm -rf /" 6 $?
$K exec target -- 'touch /tmp/x' >/dev/null; check "protected host needs --yes" 6 $?
$K exec direct --timeout 1s -- 'sleep 5' >/dev/null; check "timeout -> 7" 7 $?
$K exec nope -- true >/dev/null; check "unknown host -> 3" 3 $?
set -e
check "sudo works" root "$($K exec direct --sudo -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "dry-run reports block" PROTECTED_HOST "$($K exec @lab --dry-run -- 'touch x' | jget 'd["data"]["would_be_blocked"]["code"]')"

echo "==> fs"
$K fs replace direct /etc/app/app.conf --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup >/dev/null
check "fs replace applied" "worker_connections 4096;" "$($K fs cat direct /etc/app/app.conf | jget 'd["data"]["content"].strip()')"
set +e; $K fs replace direct /etc/app/app.conf --old 'missing' --new 'x' --sudo >/dev/null; check "fs replace no match -> 8" 8 $?; set -e
$K fs write direct /home/agent/t/x.txt --content hello -p >/dev/null
check "fs write idempotent" False "$($K fs write direct /home/agent/t/x.txt --content hello --if-changed | jget 'd["data"]["changed"]')"

echo "==> cp"
TMP="$(mktemp -d)"; echo payload > "$TMP/f"
check "upload to group" 3 "$($K cp "$TMP/f" @lab:/tmp/f --yes | jget 'd["data"]["summary"]["ok"]')"
$K cp '@lab:/tmp/f' "$TMP/down" >/dev/null
check "download per host" payload "$(cat "$TMP/down/target/f")"

echo "==> jobs"
JID=$($K job start direct -- 'echo a; sleep 1; echo b' | jget 'd["data"]["jobs"][0]["id"]')
check "job wait ok" exited "$($K job wait "$JID" --interval 1s | jget 'd["data"]["state"]')"
check "job logs" "a b" "$($K job logs "$JID" | jget '" ".join(d["data"]["content"].split())')"

echo "==> keys"
$K key gen deploy >/dev/null
check "key deploy" 3 "$($K key deploy deploy @lab --set-default --yes | jget 'd["data"]["summary"]["ok"]')"
$K host edit direct --unset password-ref >/dev/null
check "key-only login" ok "$($K exec direct -- 'echo ok' | jget 'd["data"]["results"][0]["stdout"].strip()')"

echo "==> tunnel"
LISTEN=$($K tunnel start target -L 0:localhost:22 | jget 'd["data"]["listen"]')
check "tunnel reaches private ssh" SSH-2.0 "$(nc -w 2 127.0.0.1 "${LISTEN##*:}" </dev/null | head -1 | cut -c1-7)"
$K tunnel stop --all >/dev/null

echo "==> modules"
check "facts os" debian "$($K facts direct | jget 'd["data"]["results"][0]["data"]["os"]')"
check "net check private" False "$($K net check direct target:22 | jget 'd["data"]["results"][0]["data"][0]["open"]')"
$K cron set direct t1 'true' --schedule '@daily' >/dev/null
check "cron set idempotent" 1 "$($K cron set direct t1 'true' --schedule '@daily' >/dev/null; $K cron list direct | jget 'len(d["data"]["results"][0]["data"])')"
check "audit recorded" True "$($K audit -n 200 | jget 'd["data"]["count"] > 10')"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
