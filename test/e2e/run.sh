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
KOMANDO_HOME="$(mktemp -d)"
export KOMANDO_HOME
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
for _ in $(seq 1 30); do nc -z 127.0.0.1 2222 2>/dev/null && nc -z 127.0.0.1 2223 2>/dev/null && break; sleep 1; done
sleep 1

echo "==> inventory & vault"
echo -n agentpass | $K secret set agent-pass >/dev/null
$K host add bastion agent@127.0.0.1:2222 --password-ref secret:agent-pass -g lab >/dev/null
$K host add direct agent@127.0.0.1:2223 --password-ref secret:agent-pass -g lab -t test >/dev/null
$K host add target agent@target --via bastion --password-ref secret:agent-pass -g lab --protected >/dev/null
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

echo "==> conns through bastion (db, cache, storage)"
q() { local o; o=$("$@") || { echo "  step failed: ${*:2}"; echo "$o" | head -c 600; echo; return 1; }; }
for _ in $(seq 1 60); do docker compose -p "$PROJECT" -f "$E2E/compose.yml" ps --format '{{.Health}}' pg maria 2>/dev/null | grep -qv healthy || break; sleep 1; done
G() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T s3 /garage "$@" 2>/dev/null; }
NODE=$(G status | awk '/^[0-9a-f]{16}/{print $1; exit}')
G layout assign -z dc1 -c 1G "$NODE" >/dev/null && G layout apply --version 1 >/dev/null
G bucket create backups >/dev/null && G key create komando > "$TMP/s3key" && G bucket allow --read --write --owner backups --key komando >/dev/null
S3ID=$(awk '/Key ID/{print $3}' "$TMP/s3key")
echo -n apppass | $K secret set pg-pass >/dev/null
echo -n shoppass | $K secret set maria-pass >/dev/null
echo -n redispass | $K secret set redis-pass >/dev/null
awk '/Secret key/{printf "%s", $3}' "$TMP/s3key" | $K secret set s3-secret >/dev/null
q $K conn add pg 'postgres://app@pg:5432/app?sslmode=disable' --via bastion --password-ref secret:pg-pass
q $K conn add maria 'mysql://shop@maria:3306/shop' --via bastion --password-ref secret:maria-pass --protected
q $K conn add cache 'redis://redis:6379/0' --via bastion --password-ref secret:redis-pass
q $K conn add bucket "s3://$S3ID@backups/e2e?endpoint=http://s3:3900&region=garage" --via bastion --password-ref secret:s3-secret
check "conn test via bastion" 4 "$($K conn test all | jget 'd["data"]["summary"]["ok"]')"

# postgres: write, read-only enforcement, dump, destroy, restore
q $K db query pg --write "create table t(id int primary key, name text); create sequence s; insert into t values (1, 'a'), (2, 'b')"
check "pg read via bastion" 2 "$($K db query pg 'select count(*) from t' | jget 'd["data"]["results"][0]["rows"][0][0]')"
set +e
$K db query pg "insert into t values (3, 'c')" >/dev/null; check "pg write needs --write" 6 $?
$K db query pg "select nextval('s')" >/dev/null; check "pg read-only enforced by server" 6 $?
$K db query pg --write "drop table t" >/dev/null; check "pg drop needs --allow-dangerous" 6 $?
set -e
check "pg dry run rolls back" 2 "$($K db query pg --write --dry-run 'delete from t where id > 0' >/dev/null; $K db query pg 'select count(*) from t' | jget 'd["data"]["results"][0]["rows"][0][0]')"
q $K db dump pg --to "$TMP/pg.sql.gz"
check "pg dump is private" 600 "$(stat -c %a "$TMP/pg.sql.gz" 2>/dev/null || stat -f %Lp "$TMP/pg.sql.gz")"
q $K db query pg --write --allow-dangerous "drop table t; drop sequence s"
q $K db restore pg --from "$TMP/pg.sql.gz" --allow-dangerous
check "pg restore brings rows back" 2 "$($K db query pg 'select count(*) from t' | jget 'd["data"]["results"][0]["rows"][0][0]')"

# mariadb (protected): --yes, dump and restore through bastion
set +e; $K db query maria --write "create table p(id int primary key)" >/dev/null; check "protected conn needs --yes" 6 $?; set -e
q $K db query maria --write --yes "create table p(id int primary key, name varchar(10))"
q $K db query maria --write --yes "insert into p values (1, 'kopi'), (2, 'teh')"
check "maria typed ints" 1 "$($K db query maria 'select id from p order by id' | jget 'd["data"]["results"][0]["rows"][0][0]')"
q $K db dump maria --to "$TMP/maria.sql"
q $K db query maria --write --yes --allow-dangerous "drop table p"
q $K db restore maria --from "$TMP/maria.sql" --yes --allow-dangerous
check "maria restore brings rows back" 2 "$($K db query maria 'select count(*) from p' | jget 'd["data"]["results"][0]["rows"][0][0]')"

# redis
q $K cache set cache greeting halo --ttl 1h
check "cache get via bastion" halo "$($K cache get cache greeting | jget 'd["data"]["value"]')"
set +e
$K cache run cache -- FLUSHALL >/dev/null; check "cache flushall blocked" 6 $?
$K cache rm cache greeting >/dev/null; check "cache rm needs --allow-dangerous" 6 $?
set -e

# storage
echo backup-data > "$TMP/obj.txt"
q $K storage upload bucket "$TMP/obj.txt" 2026/obj.txt
check "storage ls via bastion" 2026/obj.txt "$($K storage ls bucket --recursive | jget 'd["data"]["objects"][0]["key"]')"
q $K storage download bucket 2026/obj.txt --to "$TMP/obj-back.txt"
check "storage round trip" backup-data "$(cat "$TMP/obj-back.txt")"

# one inventory: targets pick servers and conns together
echo "==> servers and conns together"
q $K group add stack 'bastion,pg,cache'
check "list @stack has both" "bastion,cache,pg" "$($K list @stack | jget '",".join(t["name"] for t in d["data"]["targets"])')"
check "test @stack checks both" 3 "$($K test @stack | jget 'd["data"]["summary"]["ok"]')"
check "exec @stack skips conns" "cache,pg" "$($K exec @stack --read-only -- true | jget '",".join(s["name"] for s in d["meta"]["skipped"])')"
check "db query @stack finds pg" 1 "$($K db query @stack 'select 1 as n' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "cache on a database says use db" NO_MATCHING_TARGETS "$($K cache info pg | jget 'd["error"]["code"]' || true)"

# one verb pair for files, and tunnels to conns by name
echo hello-upload > "$TMP/up.txt"
q $K upload direct "$TMP/up.txt" /tmp/up.txt
q $K download direct /tmp/up.txt --to "$TMP/down/"
check "upload/download to a server" hello-upload "$(cat "$TMP/down/up.txt")"
TUN=$($K tunnel start pg | jget 'd["data"]["listen"]')
check "tunnel to a conn by name" 0 "$(nc -z "${TUN%:*}" "${TUN##*:}"; echo $?)"
q $K tunnel stop --all

# VPNs: a SOCKS proxy (komando's own, through the bastion) and an OS VPN check
echo "==> VPNs"
q $K tunnel start bastion -D 127.0.0.1:18080
q $K vpn add lab socks --address 127.0.0.1:18080 --check pg:5432
q $K conn add pg-lab 'postgres://app@pg:5432/app?sslmode=disable' --via lab --password-ref secret:pg-pass
check "db through a SOCKS VPN" 1 "$($K db query pg-lab 'select 1' | jget 'd["data"]["results"][0]["rows"][0][0]')"
q $K host add target-lab agent@target --via lab --password-ref secret:agent-pass
check "ssh through a SOCKS VPN" target "$($K exec target-lab --read-only -- hostname | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "vpn test" 1 "$($K test kind:vpn | jget 'd["data"]["summary"]["ok"]')"
q $K vpn add corp system --check 127.0.0.1:1
check "system VPN down says so" VPN_DOWN "$($K db query pg-lab 'select 1' >/dev/null; $K test corp | jget 'd["data"]["results"][0]["error"]["code"]' || true)"
set +e; $K vpn rm lab >/dev/null; check "VPN in use cannot be removed" 8 $?; set -e
q $K tunnel stop --all

# no way around protection
q $K snippet add touch-it 'touch /tmp/komando-e2e'
check "recipe list has built-ins and saved" True "$($K recipe list | jget 'any(r["builtin"] for r in d["data"]["recipes"]) and any(not r["builtin"] for r in d["data"]["recipes"])')"
set +e; $K snippet run touch-it target >/dev/null; check "snippet on protected host needs --yes" 6 $?; set -e
set +e; $K host rm target >/dev/null; check "removing a protected host needs --yes" 6 $?; set -e
set +e; $K config set audit off >/dev/null; check "turning off audit needs --yes" 6 $?; set -e
set +e; $K secret set leaked hunter2 >/dev/null; check "secret value as argument refused" 2 $?; set -e

# no secret value may reach the state file or the audit log
LEAKS=$(cat "$KOMANDO_HOME/state.json" "$KOMANDO_HOME/audit.jsonl" | { grep -c -E 'apppass|shoppass|redispass' || true; })
check "no passwords in state or audit" 0 "$LEAKS"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
