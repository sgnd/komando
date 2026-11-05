#!/usr/bin/env bash
# End-to-end test: starts disposable SSH containers (bastion -> private target,
# plus a directly reachable box), then drives the real komando binary.
#
#   make e2e            (or)   test/e2e/run.sh
#
# Needs: docker (with compose), go, python3. Set KEEP=1 to keep containers.
#
# Several runs can share one machine (e.g. one per git worktree) when each
# sets its own project name and host ports:
#   E2E_PROJECT=komando-e2e-b E2E_SSH_BASTION=3222 E2E_SSH_DIRECT=3223 \
#   E2E_SSH_SWARM=3224 E2E_REGISTRY=6005 E2E_SOCKS=19080 E2E_BAO=8211 E2E_MOTO=5026 E2E_VW=8091 \
#   E2E_K3S_OLD=16454 make e2e
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
E2E="$ROOT/test/e2e"
K="$ROOT/bin/komando"
# E2E_HOME keeps the inventory after the run (with KEEP=1 for the
# containers), to try commands by hand against the same lab
KOMANDO_HOME="${E2E_HOME:-$(mktemp -d)}"
mkdir -p "$KOMANDO_HOME" && chmod 700 "$KOMANDO_HOME"
export KOMANDO_HOME
export KOMANDO_ACTOR="e2e"
# this script is a script, even when an AI agent starts it; the agent
# checks below say so on purpose (and never open an approval window)
unset CLAUDECODE CLAUDE_CODE_ENTRYPOINT GEMINI_CLI CODEX_SANDBOX CODEX_THREAD_ID CURSOR_AGENT KOMANDO_AGENT AI_AGENT
A() { CLAUDECODE=1 KOMANDO_NO_DIALOG=1 "$K" "$@"; }
PROJECT=${E2E_PROJECT:-komando-e2e}
export E2E_SSH_BASTION=${E2E_SSH_BASTION:-2222} E2E_SSH_DIRECT=${E2E_SSH_DIRECT:-2223}
export E2E_SSH_SWARM=${E2E_SSH_SWARM:-2224} E2E_REGISTRY=${E2E_REGISTRY:-5005}
export E2E_BAO=${E2E_BAO:-8201} E2E_MOTO=${E2E_MOTO:-5016} E2E_VW=${E2E_VW:-8090} E2E_K3S_OLD=${E2E_K3S_OLD:-16444}
E2E_SOCKS=${E2E_SOCKS:-18080}
PASS=0
FAIL=0

cleanup() {
  [ "${KEEP:-0}" = 1 ] || docker compose -p "$PROJECT" -f "$E2E/compose.yml" down -v >/dev/null 2>&1 || true
  "$K" tunnel stop --all >/dev/null 2>&1 || true # only this run's tunnels
  [ -n "${E2E_HOME:-}" ] || rm -rf "$KOMANDO_HOME"
}
trap cleanup EXIT

# jget '<python expression on d>' : evaluate against JSON on stdin
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

check() { # check "name" expected actual
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  ok   $1"
  else FAIL=$((FAIL+1)); echo "  FAIL $1: expected [$2] got [$3]"; fi
}

. "$E2E/pty.sh"

echo "==> build"
(cd "$ROOT" && go build -o bin/komando ./cmd/komando)

echo "==> start containers"
docker compose -p "$PROJECT" -f "$E2E/compose.yml" up -d --build --wait >/dev/null 2>&1 \
  || docker compose -p "$PROJECT" -f "$E2E/compose.yml" up -d --build >/dev/null
for _ in $(seq 1 30); do nc -z 127.0.0.1 "$E2E_SSH_BASTION" 2>/dev/null && nc -z 127.0.0.1 "$E2E_SSH_DIRECT" 2>/dev/null && break; sleep 1; done
sleep 1

echo "==> inventory & vault"
echo -n agentpass | $K secret set agent-pass >/dev/null
$K host add bastion "agent@127.0.0.1:$E2E_SSH_BASTION" --password-ref secret:agent-pass -g lab >/dev/null
$K host add direct "agent@127.0.0.1:$E2E_SSH_DIRECT" --password-ref secret:agent-pass -g lab -t test >/dev/null
$K host add target agent@target --via bastion --password-ref secret:agent-pass -g lab --protected >/dev/null
check "host list count" 3 "$($K host list | jget 'd["data"]["count"]')"
check "secret never printed" False "$($K secret get agent-pass | jget '"value" in d["data"]')"
check "reveal needs a person" REVEAL_NEEDS_HUMAN "$($K secret get agent-pass --reveal </dev/null | jget 'd["error"]["code"]' || true)"
check "secret in use cannot be removed" SECRET_IN_USE "$($K secret rm agent-pass | jget 'd["error"]["code"]' || true)"
check "plain password refused as a ref" USAGE "$($K host add bad "agent@127.0.0.1:$E2E_SSH_DIRECT" --password-ref agentpass | jget 'd["error"]["code"]' || true)"

check "completion lists the inventory" True "$($K __complete exec '' 2>/dev/null | grep -qx direct && echo True || echo False)"
check "schema knows kind: selectors" True "$($K schema | jget '"kind:KIND" in d["data"]["target_selectors"]')"
chmod 400 "$KOMANDO_HOME/audit.jsonl"
check "no audit, no change" AUDIT_UNAVAILABLE "$($K host add nope "agent@127.0.0.1:$E2E_SSH_DIRECT" | jget 'd["error"]["code"]' || true)"
chmod 600 "$KOMANDO_HOME/audit.jsonl"

echo "==> connectivity (incl. jump host)"
check "host test all ok" 3 "$($K host test @lab | jget 'd["data"]["summary"]["ok"]')"

echo "==> exec"
check "exec stdout via jump" "target" "$($K exec target --read-only -- hostname | jget 'd["data"]["results"][0]["stdout"].strip()')"
# six servers behind one bastion: one login to the bastion, not six
for i in 1 2 3 4 5 6; do $K host add "fan$i" agent@target --via bastion --password-ref secret:agent-pass -g fan >/dev/null; done
logins() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" logs bastion 2>/dev/null | grep -c 'Accepted password' || true; }
before=$(logins)
check "exec -P 6 through one bastion" 6 "$($K exec @fan -P 6 --read-only -- hostname | jget 'd["data"]["summary"]["ok"]')"
sleep 1
check "the bastion saw one login for six servers" 1 "$(( $(logins) - before ))"
$K host rm fan1 fan2 fan3 fan4 fan5 fan6 --yes >/dev/null
set +e
$K exec direct -- 'exit 3' >/dev/null; check "non-zero exit -> 5" 5 $?
$K exec direct -- 'rm -rf /' >/dev/null; check "policy blocks rm -rf /" 6 $?
$K exec target -- 'touch /tmp/x' >/dev/null; check "protected host needs --yes" 6 $?
$K exec direct --timeout 1s -- 'sleep 5' >/dev/null; check "timeout -> 7" 7 $?
$K exec nope -- true >/dev/null; check "unknown host -> 3" 3 $?
$K shell direct </dev/null >/dev/null 2>&1; check "shell needs a terminal -> 2" 2 $?
check "shell refuses agents" NEEDS_TERMINAL "$(A shell direct --dry-run </dev/null | jget 'd["error"]["code"]' || true)"
O=$(ptyrun 'exit 3\n' env NO_COLOR=1 "$K" shell direct | tr -d '\r'); check "shell passes the remote exit code" 3 $?
check "shell says where it logs in" 1 "$(grep -c '^komando: shell on direct (agent@127.0.0.1)$' <<<"$O")"
check "shell says how it ended" 1 "$(grep -c '^komando: left direct (exit 3, [0-9]*s)$' <<<"$O")"
ptyrun 'n\n' "$K" shell target >/dev/null; check "shell on a protected host: no -> 6" 6 $?
O=$(ptyrun 'exit 0\n' env NO_COLOR=1 "$K" shell target --yes | tr -d '\r'); check "shell on a protected host with --yes" 0 $?
check "shell names the bastion and protection" 1 "$(grep -c '^komando: shell on target (agent@target) via bastion · PROTECTED$' <<<"$O")"
check "PROTECTED is red in colour terminals" 1 "$(ptyrun 'exit 0\n' env TERM=xterm NO_COLOR= "$K" shell target --yes | grep -c $'\e\\[1;31mPROTECTED')"
check "shell --dry-run reports the protected stop" PROTECTED_HOST "$(ptyrun '' "$K" -o json shell target --dry-run | tr -d '\r' | grep '^{' | jget 'd["meta"]["would_be_blocked"]["code"]')"
set -e
echo "==> secret managers, built in (no vault or aws CLI)"
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$E2E_BAO/v1/sys/health" >/dev/null && curl -s "http://127.0.0.1:$E2E_MOTO/" >/dev/null && break; sleep 1; done
curl -sf -H "X-Vault-Token: e2e-root" -d '{"data":{"agentpass":"agentpass"}}' "http://127.0.0.1:$E2E_BAO/v1/secret/data/e2e" >/dev/null
curl -sf -H 'X-Amz-Target: secretsmanager.CreateSecret' -H 'Content-Type: application/x-amz-json-1.1' \
  -H 'Authorization: AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/secretsmanager/aws4_request, SignedHeaders=host, Signature=0' \
  -d '{"Name":"e2e/agent","SecretString":"{\"password\":\"agentpass\"}"}' "http://127.0.0.1:$E2E_MOTO/" >/dev/null
BAOENV=(env PATH=/usr/bin:/bin VAULT_ADDR="http://127.0.0.1:$E2E_BAO" VAULT_TOKEN=e2e-root)
SMENV=(env PATH=/usr/bin:/bin AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 AWS_ENDPOINT_URL="http://127.0.0.1:$E2E_MOTO" AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true)
$K host add direct-bao "agent@127.0.0.1:$E2E_SSH_DIRECT" --password-ref 'vault:secret/e2e#agentpass' >/dev/null
$K host add direct-sm "agent@127.0.0.1:$E2E_SSH_DIRECT" --password-ref 'aws-sm:e2e/agent#password' >/dev/null
check "password from OpenBao" agent "$("${BAOENV[@]}" $K exec direct-bao --read-only -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()' || true)"
check "password from AWS Secrets Manager" agent "$("${SMENV[@]}" $K exec direct-sm --read-only -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()' || true)"
$K host rm direct-bao direct-sm >/dev/null
(cd "$ROOT" && KOMANDO_E2E_MOTO="http://127.0.0.1:$E2E_MOTO" go test -count=1 -v -run '^TestSSMKMSMoto$' ./internal/cloud/ >"$KOMANDO_HOME/ssm-kms.log" 2>&1) || true
check "SSM session key from KMS (moto)" ok "$(grep -q -- '--- PASS: TestSSMKMSMoto' "$KOMANDO_HOME/ssm-kms.log" && echo ok)"
(cd "$ROOT" && KOMANDO_E2E_MOTO="http://127.0.0.1:$E2E_MOTO" go test -count=1 -v -run '^TestImportAWS$' ./internal/cli/ >"$KOMANDO_HOME/import-aws.log" 2>&1) || true
check "import aws: a conn per bucket of each profile (moto S3)" ok "$(grep -q -- '--- PASS: TestImportAWS' "$KOMANDO_HOME/import-aws.log" && echo ok)"
check "sudo works" root "$($K exec direct --sudo -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "dry-run reports block" PROTECTED_HOST "$($K exec @lab --dry-run -- 'touch x' | jget 'd["data"]["would_be_blocked"]["code"]')"

echo "==> fs"
$K fs replace direct /etc/app/app.conf --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup >/dev/null
check "fs replace applied" "worker_connections 4096;" "$($K fs cat direct /etc/app/app.conf | jget 'd["data"]["content"].strip()')"
set +e; $K fs replace direct /etc/app/app.conf --old 'missing' --new 'x' --sudo >/dev/null; check "fs replace no match -> 8" 8 $?; set -e
$K fs write direct /home/agent/t/x.txt --content hello -p >/dev/null
check "fs write idempotent" False "$($K fs write direct /home/agent/t/x.txt --content hello --if-changed | jget 'd["data"]["changed"]')"
check "fs write dry-run shows the diff" True "$($K fs write direct /home/agent/t/x.txt --content hello2 --dry-run | jget '"+hello2" in d["data"]["diff"]')"
check "fs write --validate refuses bad content" VALIDATION_FAILED "$($K fs write direct /home/agent/t/v.txt --content bad --validate 'grep -q good %s' | jget 'd["error"]["code"]' || true)"
check "refused file was not written" False "$($K fs stat direct /home/agent/t/v.txt | jget 'd["data"]["exists"]')"
check "fs write --sudo --validate (visudo)" VALIDATION_FAILED "$($K fs write direct /etc/sudoers.d/e2e --content 'not a sudoers line' --sudo --validate 'visudo -cf %s' | jget 'd["error"]["code"]' || true)"
check "sudo still works after refused edit" root "$($K exec direct --sudo -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()')"

echo "==> cp"
TMP="$(mktemp -d)"; echo payload > "$TMP/f"

echo "==> sudo password"
echo -n opspass | $K secret set ops-pass >/dev/null
$K host add ops "ops@127.0.0.1:$E2E_SSH_DIRECT" --password-ref secret:ops-pass --sudo-ref secret:ops-pass >/dev/null
printf '#!/bin/sh\nwhoami\n' > "$TMP/who.sh"
check "sudo with password" root "$($K exec ops --sudo -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "sudo password then stdin" payload "$($K exec ops --sudo --stdin-file "$TMP/f" -- cat | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "script with sudo password" root "$($K script ops "$TMP/who.sh" --sudo | jget 'd["data"]["results"][0]["stdout"].strip()')"
# sudo never asks on a NOPASSWD host, so the password must not reach the command
$K host edit direct --sudo-ref secret:agent-pass >/dev/null
check "unasked sudo password not leaked" False "$($K script direct "$TMP/who.sh" --sudo | jget '"agentpass" in json.dumps(d)')"
check "unasked sudo password not in stdin" payload "$($K exec direct --sudo --stdin-file "$TMP/f" -- cat | jget 'd["data"]["results"][0]["stdout"].strip()')"
$K host edit direct --unset sudo-ref >/dev/null
$K host rm ops >/dev/null
$K exec direct --sudo -- 'mkdir -m 700 /etc/private && install -m 600 /dev/null /etc/private/token' >/dev/null
$K fs write direct /etc/private/token --content s3cret --sudo >/dev/null
check "fs write --sudo keeps a mode the user cannot see" 600 "$($K exec direct --sudo -- stat -c %a /etc/private/token | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "upload to group" 3 "$($K cp "$TMP/f" @lab:/tmp/f --yes | jget 'd["data"]["summary"]["ok"]')"
$K cp '@lab:/tmp/f' "$TMP/down" >/dev/null
check "download per host" payload "$(cat "$TMP/down/target/f")"

echo "==> jobs"
JID=$($K job start direct -- 'echo a; sleep 1; echo b' | jget 'd["data"]["jobs"][0]["id"]')
check "job wait ok" exited "$($K job wait "$JID" --interval 1s | jget 'd["data"]["state"]')"
check "job logs" "a b" "$($K job logs "$JID" | jget '" ".join(d["data"]["content"].split())')"
check "exec gets a vault secret as env" match "$($K exec direct -e P=secret:agent-pass -- 'test "$P" = agentpass && echo match' | jget 'd["data"]["results"][0]["stdout"].strip()')"
JID=$($K job start direct -e P=secret:agent-pass -- 'test "$P" = agentpass && echo job-match' | jget 'd["data"]["jobs"][0]["id"]')
$K job wait "$JID" --interval 1s >/dev/null
check "job gets a vault secret as env" True "$($K job logs "$JID" | jget '"job-match" in d["data"]["content"]')"
check "job env file is deleted" False "$($K fs stat direct ".komando/jobs/$JID/env" | jget 'd["data"]["exists"]')"
$K fs write direct /home/agent/t/app.env --content 'DB_PASSWORD=agentpass' >/dev/null
check "secret values hidden in output" "DB_PASSWORD=[secret:agent-pass]" "$($K fs cat direct /home/agent/t/app.env | jget 'd["data"]["content"].strip()')"

echo "==> keys"
$K key gen deploy >/dev/null
check "key deploy" 3 "$($K key deploy deploy @lab --set-default --yes | jget 'd["data"]["summary"]["ok"]')"
$K host edit direct --unset password-ref >/dev/null
check "key-only login" ok "$($K exec direct -- 'echo ok' | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "revoking the login key needs --allow-dangerous" POLICY_BLOCKED "$($K key revoke deploy direct | jget 'd["error"]["code"]' || true)"
$K key gen leaver >/dev/null
$K key deploy leaver direct >/dev/null
check "key revoke --dry-run counts" 1 "$($K key revoke leaver direct --dry-run | jget 'd["data"]["results"][0]["would_remove"]')"
check "key revoke removes it" 1 "$($K key revoke leaver direct | jget 'd["data"]["results"][0]["removed"]')"
check "other keys stay" ok "$($K exec direct -- 'echo ok' | jget 'd["data"]["results"][0]["stdout"].strip()')"
$K host add pc "agent@127.0.0.1" --port "$E2E_SSH_DIRECT" --key deploy --proxy-command 'nc %h %p' >/dev/null
check "proxy command carries ssh" ok "$($K exec pc -- 'echo ok' | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "ssh-command shows the proxy" True "$($K host ssh-command pc | jget '"ProxyCommand=nc %h %p" in d["data"]["argv"]')"
check "proxy and --via do not mix" USAGE "$($K host add pc2 agent@127.0.0.1 --via bastion --proxy-command 'nc %h %p' | jget 'd["error"]["code"]' || true)"
$K host add ssm1 ec2-user@i-0abc123 --ssm >/dev/null
check "--ssm sets the AWS proxy" True "$($K host show ssm1 | jget '"AWS-StartSSHSession" in d["data"]["proxy_command"]')"
$K host rm pc ssm1 >/dev/null
check "revoke a public key line" 0 "$($K key revoke "$(cat "$KOMANDO_HOME/keys/leaver.pub")" direct | jget 'd["data"]["results"][0]["removed"]')"

echo "==> tunnel"
LISTEN=$($K tunnel start target -L 0:localhost:22 | jget 'd["data"]["listen"]')
check "tunnel reaches private ssh" SSH-2.0 "$(nc -w 2 127.0.0.1 "${LISTEN##*:}" </dev/null | head -1 | cut -c1-7)"
$K tunnel stop --all >/dev/null
check "open bind needs --yes" OPEN_BIND "$($K tunnel start target -L 0.0.0.0:0:localhost:22 | jget 'd["error"]["code"]' || true)"

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
# a database always needs its password, so the secret manager's answer counts
curl -sf -H "X-Vault-Token: e2e-root" -d '{"data":{"pgpass":"apppass"}}' "http://127.0.0.1:$E2E_BAO/v1/secret/data/pg" >/dev/null
q $K conn add pg-bao 'postgres://app@pg:5432/app?sslmode=disable' --via bastion --password-ref 'vault:secret/pg#pgpass'
check "db password from OpenBao" 1 "$("${BAOENV[@]}" $K db query pg-bao 'select 1' | jget 'd["data"]["results"][0]["rows"][0][0]' || true)"
check "wrong OpenBao token is named" True "$(env PATH=/usr/bin:/bin VAULT_ADDR="http://127.0.0.1:$E2E_BAO" VAULT_TOKEN=bad $K db query pg-bao 'select 1' | jget '"permission denied" in json.dumps(d)' || true)"
q $K conn rm pg-bao
# Bitwarden (Vaultwarden): an account made the way a Bitwarden client makes it, read by komando
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$E2E_VW/alive" >/dev/null && break; sleep 1; done
(cd "$ROOT" && go run ./test/e2e/bwseed "http://127.0.0.1:$E2E_VW" e2e@example.com 'e2e master pw' shop-pg apppass) >/dev/null
BWENV=(env PATH=/usr/bin:/bin KOMANDO_BW_SERVER="http://127.0.0.1:$E2E_VW" KOMANDO_BW_EMAIL=e2e@example.com KOMANDO_BW_PASSWORD='e2e master pw')
q $K conn add pg-bw 'postgres://app@pg:5432/app?sslmode=disable' --via bastion --password-ref 'bw://shop-pg/password'
check "db password from Vaultwarden (bw://)" 1 "$("${BWENV[@]}" $K db query pg-bw 'select 1' | jget 'd["data"]["results"][0]["rows"][0][0]' || true)"
check "wrong Bitwarden master password is named" True "$(env PATH=/usr/bin:/bin KOMANDO_BW_SERVER="http://127.0.0.1:$E2E_VW" KOMANDO_BW_EMAIL=e2e@example.com KOMANDO_BW_PASSWORD=nope $K db query pg-bw 'select 1' | jget '"bitwarden" in json.dumps(d)' || true)"
q $K conn rm pg-bw
# db shell is komando's own SQL shell: no psql or mysql on PATH
check "db shell on PostgreSQL" 42 "$(ptyrun 'select 41 + 1 as answer;\n\q\n' env PATH=/usr/bin:/bin "$K" db shell pg | tr -d '\r' | grep -E '^ *42 *$' | tr -d ' ' | head -1 || true)"
check "db shell is read-only" True "$(ptyrun 'create table nope(x int);\n\q\n' env PATH=/usr/bin:/bin "$K" db shell pg | grep -q 'the shell is read-only' && echo True)"
check "db shell \\d lists tables" True "$(ptyrun '\d\n\q\n' env PATH=/usr/bin:/bin "$K" db shell pg | grep -q 'table\|relation' && echo True)"
q $K conn add maria 'mysql://shop@maria:3306/shop' --via bastion --password-ref secret:maria-pass --protected
q $K conn add cache 'redis://redis:6379/0' --via bastion --password-ref secret:redis-pass
q $K conn add bucket "s3://$S3ID@backups/e2e?endpoint=http://s3:3900&region=garage" --via bastion --password-ref secret:s3-secret
check "conn test via bastion" 4 "$($K conn test all | jget 'd["data"]["summary"]["ok"]')"
check "conn test logs in" login "$($K conn test pg | jget 'd["data"]["results"][0]["detail"]["check"]')"
echo -n wrongpass | $K secret set pg-wrong >/dev/null
q $K conn add pg-wrong 'postgres://app@pg:5432/app?sslmode=disable' --via bastion --password-ref secret:pg-wrong
check "conn test catches a wrong password" False "$($K conn test pg-wrong | jget 'd["data"]["results"][0]["ok"]' || true)"
q $K conn rm pg-wrong
q $K conn edit pg --option statement_timeout=1s
check "conn statement_timeout option is used" TIMEOUT "$($K db query pg 'select pg_sleep(3)' | jget 'd["error"]["code"]' || true)"
q $K conn edit pg --option statement_timeout=

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
check "db info" primary "$($K db info pg | jget 'd["data"]["role"]')"
check "db sizes lists the table" True "$($K db sizes pg | jget 'any(r["name"]=="t" for r in d["data"]["tables"])')"
check "db locks answers" 0 "$($K db locks pg | jget 'd["data"]["count"]')"
q $K db query pg --write "create table t2(id int primary key, t_id int references t(id) on delete cascade); insert into t2 values (1, 1)"
check "db schema shows foreign keys" "foreign key" "$($K db schema pg t2 | jget 'd["data"]["tables"][0]["constraints"][0]["type"]')"
($K db query pg 'select pg_sleep(30)' --timeout 60s > "$TMP/slow.json" 2>&1 &)
for _ in $(seq 1 20); do PID=$($K db activity pg | jget '[s["pid"] for s in d["data"]["sessions"] if "pg_sleep" in (s.get("query") or "")][0]' 2>/dev/null) && break; sleep 1; done
check "db activity sees the slow query" True "$([ -n "$PID" ] && echo True || echo False)"
check "db kill --dry-run names the query" True "$($K db kill pg "$PID" --dry-run | jget '"pg_sleep" in d["data"]["session"]["query"]')"
check "db kill --session needs --allow-dangerous" POLICY_BLOCKED "$($K db kill pg "$PID" --session | jget 'd["error"]["code"]' || true)"
check "db kill cancels it" "cancel query" "$($K db kill pg "$PID" | jget 'd["data"]["done"]')"
for _ in $(seq 1 10); do grep -q '"ok"' "$TMP/slow.json" 2>/dev/null && break; sleep 1; done
check "the cancelled query stopped" False "$(jget 'd["ok"]' < "$TMP/slow.json")"
q $K db dump pg --to "$TMP/t2.dump" --format custom --table public.t2
check "custom dump is a pg archive" PGDMP "$(head -c 5 "$TMP/t2.dump")"
q $K db query pg --write --allow-dangerous "drop table t2"
q $K db restore pg --from "$TMP/t2.dump" --allow-dangerous
check "pg_restore brings the table back" 1 "$($K db query pg 'select count(*) from t2' | jget 'd["data"]["results"][0]["rows"][0][0]')"
q $K db dump pg --to "$TMP/schema.sql" --schema-only
check "schema-only dump has no rows" 0 "$(grep -c "COPY public.t " "$TMP/schema.sql" || true)"

# mariadb (protected): --yes, dump and restore through bastion
set +e; $K db query maria --write "create table p(id int primary key)" >/dev/null; check "protected conn needs --yes" 6 $?; set -e
q $K db query maria --write --yes "create table p(id int primary key, name varchar(10))"
q $K db query maria --write --yes "insert into p values (1, 'kopi'), (2, 'teh')"
check "maria typed ints" 1 "$($K db query maria 'select id from p order by id' | jget 'd["data"]["results"][0]["rows"][0][0]')"
q $K db dump maria --to "$TMP/maria.sql"
q $K db query maria --write --yes --allow-dangerous "drop table p"
q $K db restore maria --from "$TMP/maria.sql" --yes --allow-dangerous
check "maria restore brings rows back" 2 "$($K db query maria 'select count(*) from p' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "maria db info" primary "$($K db info maria | jget 'd["data"]["role"]')"
check "maria db sizes" True "$($K db sizes maria | jget 'any(r["name"]=="p" for r in d["data"]["tables"])')"
check "maria db activity answers" True "$($K db activity maria --all | jget '"sessions" in d["data"]')"
check "maria db locks names the missing privilege" DB_PRIVILEGE "$($K db locks maria | jget 'd["error"]["code"]' || true)"

# redis
q $K cache set cache greeting halo --ttl 1h
check "cache get via bastion" halo "$($K cache get cache greeting | jget 'd["data"]["value"]')"
set +e
$K cache run cache -- FLUSHALL >/dev/null; check "cache flushall blocked" 6 $?
$K cache rm cache greeting >/dev/null; check "cache rm needs --allow-dangerous" 6 $?
$K cache run cache --write -- GETDEL greeting >/dev/null; check "cache GETDEL needs --allow-dangerous" 6 $?
set -e

# memcached (with a login), through the bastion
printf mcpass | $K secret set mc-pass >/dev/null
q $K conn add mc 'memcached://e2e@memcached:11211' --password-ref secret:mc-pass --via bastion
q $K cache set mc greeting halo --ttl 1h
check "memcached get via bastion, with its time to live" "halo True" "$($K cache get mc greeting | jget 'd["data"]["value"] + " " + str(d["data"]["ttl_seconds"] > 3500)')"
check "memcached keys" "['greeting']" "$($K cache keys mc 'greet*' | jget 'd["data"]["keys"]')"
check "memcached info summary" True "$($K cache info mc | jget 'd["data"]["summary"]["version"].endswith("(memcached)")')"
check "memcached run reads" True "$($K cache run mc -- stats | jget 'any("curr_items" in l for l in d["data"]["reply"])')"
set +e
$K cache run mc -- flush_all >/dev/null; check "memcached flush_all blocked" 6 $?
$K cache rm mc greeting >/dev/null; check "memcached rm needs --allow-dangerous" 6 $?
set -e
check "memcached rm --dry-run names the key" "['greeting']" "$($K cache rm mc greeting --dry-run | jget 'd["data"]["would_delete"]')"
q $K cache rm mc greeting --allow-dangerous
check "memcached key gone" KEY_NOT_FOUND "$($K cache get mc greeting | jget 'd["error"]["code"]' || true)"
printf wrong | $K secret set mc-pass >/dev/null
check "memcached wrong password is named" CACHE_AUTH "$($K cache info mc | jget 'd["error"]["code"]' || true)"
q $K conn rm mc

# storage
echo backup-data > "$TMP/obj.txt"
q $K storage upload bucket "$TMP/obj.txt" 2026/obj.txt
check "storage ls via bastion" 2026/obj.txt "$($K storage ls bucket --recursive | jget 'd["data"]["objects"][0]["key"]')"
q $K storage download bucket 2026/obj.txt --to "$TMP/obj-back.txt"
check "storage round trip" backup-data "$(cat "$TMP/obj-back.txt")"
# aws_profile: komando reads ~/.aws itself; no aws CLI on PATH
printf '[e2e]\naws_access_key_id = %s\naws_secret_access_key = %s\n' "$S3ID" "$(awk '/Secret key/{printf "%s", $3}' "$TMP/s3key")" > "$TMP/aws-credentials"
AWSENV=(env PATH=/usr/bin:/bin AWS_SHARED_CREDENTIALS_FILE="$TMP/aws-credentials" AWS_CONFIG_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true)
q $K conn add bucket-aws "s3://backups/e2e?endpoint=http://s3:3900&region=garage" --via bastion --option aws_profile=e2e
check "s3 with aws_profile, no aws CLI" 2026/obj.txt "$("${AWSENV[@]}" $K storage ls bucket-aws --recursive | jget 'd["data"]["objects"][0]["key"]')"
q $K conn edit bucket-aws --option aws_profile=nope
check "unknown aws_profile is named" AWS_PROFILE_NOT_FOUND "$("${AWSENV[@]}" $K storage ls bucket-aws | jget 'd["error"]["code"]' || true)"
q $K conn rm bucket-aws
mkdir -p "$TMP/tree/sub" && echo one > "$TMP/tree/a.txt" && echo two > "$TMP/tree/sub/b.txt" && echo skip > "$TMP/tree/c.tmp"
check "upload -r to storage" 3 "$($K upload bucket "$TMP/tree" tree -r | jget 'd["data"]["copied"]')"
check "sync to storage sends nothing new" 0 "$($K sync "$TMP/tree" bucket:tree --exclude '*.tmp' | jget 'd["data"]["copied"] + d["data"]["updated"]')"
check "storage cat --tail" two "$($K storage cat bucket tree/sub/b.txt --tail 1 | jget 'd["data"]["content"].strip()')"
q $K download bucket tree -r --to "$TMP/tree-back"
check "download -r from storage" two "$(cat "$TMP/tree-back/sub/b.txt")"
check "download -r keeps local files" True "$(echo changed > "$TMP/tree-back/a.txt"; $K download bucket tree -r --to "$TMP/tree-back" | jget 'd["data"]["kept"] >= 1')"
check "rm --prefix --dry-run lists" True "$($K storage rm bucket --prefix tree/ --dry-run | jget 'd["data"]["count"] >= 2')"
check "rm --prefix needs --allow-dangerous" POLICY_BLOCKED "$($K storage rm bucket --prefix tree/ | jget 'd["error"]["code"]' || true)"
check "rm --older-than leaves new objects" 0 "$($K storage rm bucket --prefix tree/ --older-than 30d --allow-dangerous | jget 'd["data"]["count"]')"
check "rm --prefix removes them" True "$($K storage rm bucket --prefix tree/ --allow-dangerous | jget 'd["data"]["count"] >= 2')"

# file servers through the bastion: SFTP (shell-less account) and FTPS (TLS required)
echo -n deploypass | $K secret set files-pass >/dev/null
q $K conn add files-sftp 'sftp://deploy@sftp/uploads' --via bastion --password-ref secret:files-pass
q $K conn add files-ftps 'ftps://deploy@ftps/www?tls=skip-verify' --via bastion --password-ref secret:files-pass
for c in files-sftp files-ftps; do
  q $K storage upload "$c" "$TMP/obj.txt" 2026/11/obj.txt
  check "$c upload creates folders" 2026/11/obj.txt "$($K storage ls "$c" --recursive | jget '[o["key"] for o in d["data"]["objects"] if not o.get("dir")][0]')"
  check "$c upload replaces" True "$($K storage upload "$c" "$TMP/obj.txt" 2026/11/obj.txt | jget 'd["data"]["replaced"]')"
  q $K storage download "$c" 2026/11/obj.txt --to "$TMP/$c.txt"
  check "$c round trip" backup-data "$(cat "$TMP/$c.txt")"
  set +e; $K storage rm "$c" 2026/11/obj.txt >/dev/null; check "$c rm needs --allow-dangerous" 6 $?; set -e
done

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
check "download never replaces a local file" FILE_EXISTS "$($K download direct /tmp/up.txt --to "$TMP/down/" | jget 'd["data"]["results"][0]["error"]["code"]' || true)"
q $K download direct /tmp/up.txt --to "$TMP/down/" --overwrite
check "no temporary files left" 0 "$(ls -A "$TMP/down" | grep -c komando-download || true)"
dd if=/dev/urandom of="$TMP/big.bin" bs=1048576 count=40 2>/dev/null
check "large upload is streamed intact" "$(shasum -a 256 "$TMP/big.bin" | cut -c1-64)" "$($K upload direct "$TMP/big.bin" /tmp/big.bin | jget 'd["data"]["results"][0]["sha256"]')"
check "sync to a server" 2 "$($K sync "$TMP/tree" direct:/home/agent/site --exclude '*.tmp' | jget 'd["data"]["results"][0]["copied"]')"
check "sync again sends nothing" 0 "$($K sync "$TMP/tree" direct:/home/agent/site --exclude '*.tmp' | jget 'd["data"]["results"][0]["copied"] + d["data"]["results"][0]["updated"]')"
rm "$TMP/tree/sub/b.txt"
check "sync --delete needs --allow-dangerous" POLICY_BLOCKED "$($K sync "$TMP/tree" direct:/home/agent/site --delete | jget 'd["error"]["code"]' || true)"
check "sync --delete --dry-run lists it" sub/b.txt "$($K sync "$TMP/tree" direct:/home/agent/site --exclude '*.tmp' --delete --dry-run | jget '[a["path"] for a in d["data"]["results"][0]["actions"] if a["op"]=="delete"][0]')"
check "sync --delete removes it" 1 "$($K sync "$TMP/tree" direct:/home/agent/site --exclude '*.tmp' --delete --allow-dangerous | jget 'd["data"]["results"][0]["deleted"]')"
check "sync from a server" one "$($K sync direct:/home/agent/site "$TMP/site-back" >/dev/null; cat "$TMP/site-back/a.txt")"
TUN=$($K tunnel start pg | jget 'd["data"]["listen"]')
check "tunnel to a conn by name" 0 "$(nc -z "${TUN%:*}" "${TUN##*:}"; echo $?)"
q $K tunnel stop --all

# Kubernetes (k3s on the private network, reached through the bastion)
echo "==> cluster (k3s through the bastion)"
for _ in $(seq 1 60); do docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s kubectl get nodes 2>/dev/null | grep -q " Ready" && break; sleep 2; done
docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s cat /etc/rancher/k3s/k3s.yaml | sed 's#https://127.0.0.1:6443#https://k3s:6443#; s#: default$#: lab-k3s#' > "$TMP/kubeconfig"
q $K import kubeconfig "$TMP/kubeconfig"
q $K conn edit lab-k3s --via bastion
check "cluster status through bastion" 1 "$($K cluster status lab-k3s | jget 'd["data"]["nodes_ready"]')"
cat > "$TMP/app.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: web, namespace: default }
spec:
  replicas: 1
  selector: { matchLabels: { app: web } }
  template:
    metadata: { labels: { app: web } }
    spec: { containers: [ { name: web, image: "rancher/mirrored-pause:3.6" } ] }
YAML
check "apply --dry-run changes nothing" "K8S_NOT_FOUND" "$($K cluster apply lab-k3s --file "$TMP/app.yaml" --dry-run >/dev/null; $K cluster get lab-k3s deploy web | jget 'd["error"]["code"]' || true)"
check "apply --dry-run shows the change" create "$($K cluster apply lab-k3s --file "$TMP/app.yaml" --dry-run | jget 'd["data"]["changes"][0]["action"]')"
q $K cluster apply lab-k3s --file "$TMP/app.yaml"
check "apply then list" web "$($K cluster ls lab-k3s deployments | jget 'd["data"]["items"][0]["name"]')"
check "ls -l picks by label" "True 0" "$($K cluster ls lab-k3s pods -l app=web | jget 'd["data"]["count"] >= 1') $($K cluster ls lab-k3s pods -l app=nope | jget 'd["data"]["count"]')"
check "events for an object" True "$($K cluster events lab-k3s --for deployment/web | jget 'd["data"]["count"] > 0')"
check "describe lists the pods" True "$($K cluster describe lab-k3s deployment web | jget 'len(d["data"]["pods"]) > 0')"
cat > "$TMP/broken.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: broken, namespace: default }
spec:
  replicas: 1
  selector: { matchLabels: { app: broken } }
  template:
    metadata: { labels: { app: broken } }
    spec: { containers: [ { name: app, image: "komando.invalid/none:0" } ] }
YAML
q $K cluster apply lab-k3s --file "$TMP/broken.yaml"
for _ in $(seq 1 45); do $K cluster status lab-k3s | jget 'any("ImagePull" in p["problem"] or "ErrImage" in p["problem"] for p in d["data"]["problems"])' | grep -q True && break; sleep 2; done
check "status names a bad image" True "$($K cluster status lab-k3s | jget 'any(("ImagePull" in p["problem"] or "ErrImage" in p["problem"]) and "broken" in p["object"] for p in d["data"]["problems"])')"
check "status counts the deployment short" True "$($K cluster status lab-k3s | jget 'any(p["object"]=="deployment/default/broken" for p in d["data"]["problems"])')"
check "describe shows the container reason" True "$($K cluster describe lab-k3s pod "$($K cluster ls lab-k3s pods -l app=broken | jget 'd["data"]["items"][0]["name"]')" | jget '"Err" in str(d["data"]["containers"][0].get("reason")) or "ImagePull" in str(d["data"]["containers"][0].get("reason"))')"
q $K cluster rm lab-k3s deployment broken --allow-dangerous
q $K cluster scale lab-k3s deployment/web 2
check "scale" 2 "$($K cluster get lab-k3s deploy web | jget 'd["data"]["spec"]["replicas"]')"
set +e; $K cluster scale lab-k3s deployment/web 0 >/dev/null; check "scale to 0 needs --allow-dangerous" 6 $?; set -e
q $K cluster restart lab-k3s deployment/web
set +e; $K cluster run lab-k3s -- delete deploy web >/dev/null; check "cluster run delete needs --write" 6 $?; set -e
check "cluster run secret values need --allow-dangerous" POLICY_BLOCKED "$($K cluster run lab-k3s --write -- get secrets -A -o yaml | jget 'd["error"]["code"]' || true)"
check "cluster run reads through bastion" True "$(env PATH=/usr/bin:/bin $K cluster run lab-k3s -- get deploy web -o name | jget '"deployment.apps/web" in d["data"]["stdout"]')"
check "rollout status --wait" True "$($K cluster status lab-k3s deployment/web --wait --timeout 90s | jget 'd["data"]["rolled_out"]')"
check "deploy a bad image times out" ROLLOUT_TIMEOUT "$($K cluster deploy lab-k3s deployment/web --image komando.invalid/none:1 --wait --timeout 20s | jget 'd["error"]["code"]' || true)"
check "history keeps the revisions" True "$($K cluster history lab-k3s deployment/web | jget 'len(d["data"]["revisions"]) >= 2 and d["data"]["revisions"][0]["images"] == ["komando.invalid/none:1"]')"
check "rollback brings the old image back" "rancher/mirrored-pause:3.6" "$($K cluster rollback lab-k3s deployment/web --wait --timeout 90s | jget 'd["data"]["images"][0]')"
check "rolled back and healthy" True "$($K cluster status lab-k3s deployment/web | jget 'd["data"]["rolled_out"]')"
check "logs of a workload" True "$($K cluster logs lab-k3s deploy/web | jget '"object" in d["data"]')"
check "logs by label" True "$($K cluster logs lab-k3s -l app=web | jget '"logs" in d["data"]')"
check "logs -f stops at --timeout" True "$($K cluster logs lab-k3s deploy/web -f --timeout 3s | tail -1 | jget 'd["data"]["followed"]')"
check "exec in a pod needs --read-only or a change" True "$($K cluster exec lab-k3s deploy/web --read-only --dry-run -- cat /etc/hostname | jget '"exec deploy/web" in d["data"]["would_run"]')"
check "exec checks the policy" POLICY_BLOCKED "$($K cluster exec lab-k3s deploy/web -- rm -rf / | jget 'd["error"]["code"]' || true)"
check "forward runs on 127.0.0.1" True "$($K cluster forward lab-k3s deploy/web 18099:80 --dry-run | jget '"--address 127.0.0.1" in d["data"]["would_run"]')"
# exec and port-forward for real, with no kubectl on PATH
cat > "$TMP/tools.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: tools, namespace: default }
spec:
  replicas: 1
  selector: { matchLabels: { app: tools } }
  template:
    metadata: { labels: { app: tools } }
    spec:
      containers:
        - name: tools
          image: busybox:1.37
          command: ["sh", "-c", "mkdir -p /www && echo hello-from-pod > /www/index.html && exec httpd -f -p 8080 -h /www"]
          ports: [{ name: http, containerPort: 8080 }]
---
apiVersion: v1
kind: Service
metadata: { name: tools, namespace: default }
spec:
  selector: { app: tools }
  ports: [{ port: 80, targetPort: http }]
YAML
q $K cluster apply lab-k3s --file "$TMP/tools.yaml"
$K cluster status lab-k3s deployment/tools --wait --timeout 120s >/dev/null || true
NOKUBE=(env PATH=/usr/bin:/bin)
check "exec without kubectl" hello-from-pod "$("${NOKUBE[@]}" $K cluster exec lab-k3s deploy/tools --read-only -- cat /www/index.html | jget 'd["data"]["stdout"].strip()' || true)"
check "exec keeps stdout, stderr and the exit code" "3 out err" "$("${NOKUBE[@]}" $K cluster exec lab-k3s deploy/tools --read-only -- sh -c 'echo out; echo err >&2; exit 3' | jget 'str(d["data"]["exit_code"]) + " " + d["data"]["stdout"].strip() + " " + d["data"]["stderr"].strip()' || true)"
"${NOKUBE[@]}" $K cluster forward lab-k3s deploy/tools 18099:8080 --timeout 20s >/dev/null 2>&1 &
"${NOKUBE[@]}" $K cluster forward lab-k3s svc/tools 18098:80 --timeout 20s >/dev/null 2>&1 &
for _ in $(seq 1 20); do curl -sf http://127.0.0.1:18099/ >/dev/null && curl -sf http://127.0.0.1:18098/ >/dev/null && break; sleep 1; done
check "forward a pod port without kubectl" hello-from-pod "$(curl -sf http://127.0.0.1:18099/ || true)"
check "forward a service port to its named target port" hello-from-pod "$(curl -sf http://127.0.0.1:18098/ || true)"
check "two connections through one forward" "hello-from-pod hello-from-pod" "$(curl -sf http://127.0.0.1:18099/ || true) $(curl -sf http://127.0.0.1:18099/ || true)"
wait
echo "copied in" > "$TMP/cp-in.txt"
# Kubernetes 1.29 has no WebSocket exec (v5): the same commands go over SPDY
echo "==> cluster on Kubernetes 1.29 (SPDY)"
for _ in $(seq 1 60); do docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s-old kubectl get nodes 2>/dev/null | grep -q " Ready" && break; sleep 2; done
docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s-old cat /etc/rancher/k3s/k3s.yaml | sed 's#https://127.0.0.1:6443#https://k3s-old:6443#; s#: default$#: lab-old#' > "$TMP/kubeconfig-old"
q $K import kubeconfig "$TMP/kubeconfig-old"
q $K conn edit lab-old --via bastion
q $K cluster apply lab-old --file "$TMP/tools.yaml"
$K cluster status lab-old deployment/tools --wait --timeout 180s >/dev/null || true
check "1.29: exec over SPDY" hello-from-pod "$("${NOKUBE[@]}" $K cluster exec lab-old deploy/tools --read-only -- cat /www/index.html | jget 'd["data"]["stdout"].strip()' || true)"
check "1.29: exec keeps stdout, stderr and the exit code" "3 out err" "$("${NOKUBE[@]}" $K cluster exec lab-old deploy/tools --read-only -- sh -c 'echo out; echo err >&2; exit 3' | jget 'str(d["data"]["exit_code"]) + " " + d["data"]["stdout"].strip() + " " + d["data"]["stderr"].strip()' || true)"
"${NOKUBE[@]}" $K cluster forward lab-old deploy/tools 18097:8080 --timeout 20s >/dev/null 2>&1 &
for _ in $(seq 1 20); do curl -sf http://127.0.0.1:18097/ >/dev/null && break; sleep 1; done
check "1.29: forward a pod port" "hello-from-pod hello-from-pod" "$(curl -sf http://127.0.0.1:18097/ || true) $(curl -sf http://127.0.0.1:18097/ || true)"
wait
POD_OLD=$("${NOKUBE[@]}" $K cluster run lab-old -- get pods -l app=tools -o 'jsonpath={.items[0].metadata.name}' | jget 'd["data"]["stdout"]' || true)
q "${NOKUBE[@]}" $K cluster run lab-old --write --allow-dangerous -- cp "$TMP/cp-in.txt" "$POD_OLD:/tmp/cp-in.txt"
q "${NOKUBE[@]}" $K cluster run lab-old --write --allow-dangerous -- cp "$POD_OLD:/tmp/cp-in.txt" "$TMP/cp-back-old.txt"
check "1.29: cp there and back (stdin ends over SPDY)" "copied in" "$(cat "$TMP/cp-back-old.txt" 2>/dev/null)"
check "1.29: cluster shell for a person" hello-from-pod "$(ptyrun 'cat /www/index.html; exit\n' env NO_COLOR=1 "$K" cluster shell lab-old deploy/tools | tr -d '\r' | grep -x hello-from-pod | head -1 || true)"
docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s-old cat /etc/rancher/k3s/k3s.yaml | sed "s#https://127.0.0.1:6443#https://127.0.0.1:$E2E_K3S_OLD#" > "$TMP/kubeconfig-old-direct"
(cd "$ROOT" && KOMANDO_E2E_OLD_KUBECONFIG="$TMP/kubeconfig-old-direct" go test -count=1 -v -run '^TestSPDYCluster$' ./internal/kube/ >"$TMP/spdy.log" 2>&1) || true
check "1.29: every SPDY path (exec, stdin end, terminal, port-forward)" ok "$(grep -q -- '--- PASS: TestSPDYCluster' "$TMP/spdy.log" && echo ok)"
docker compose -p "$PROJECT" -f "$E2E/compose.yml" stop k3s-old >/dev/null 2>&1 || true
check "cluster shell needs a person" NEEDS_TERMINAL "$($K cluster shell lab-k3s deploy/tools </dev/null | jget 'd["error"]["code"]' || true)"
check "cluster shell for a person" hello-from-pod "$(ptyrun 'cat /www/index.html; exit\n' env NO_COLOR=1 "$K" cluster shell lab-k3s deploy/tools | tr -d '\r' | grep -x hello-from-pod | head -1 || true)"
# cluster run is komando's own kubectl: every verb here runs with no kubectl on PATH
KR() { "${NOKUBE[@]}" $K cluster run lab-k3s "$@"; }
KS() { KR "$@" | jget 'd["data"]["stdout"]' || true; }
check "run: get prints the server's table" True "$(KS -- get pods -l app=tools | python3 -c 'import sys; s=sys.stdin.read(); print(s.startswith("NAME") and "READY" in s and "STATUS" in s and "tools-" in s)')"
check "run: get -o jsonpath" tools "$(KS -- get deploy tools -o 'jsonpath={.metadata.name}')"
check "run: get -o custom-columns" True "$(KS -- get svc tools -o 'custom-columns=PORT:.spec.ports[0].port' | grep -qx 80 && echo True)"
check "run: describe" True "$(KS -- describe deploy tools | grep -q 'deployment/tools' && echo True)"
check "run: api-resources" True "$(KS -- api-resources | grep -q '^deployments ' && echo True)"
check "run: version" True "$(KS -- version | grep -q 'Server Version: v1\.' && echo True)"
check "run: auth can-i" yes "$(KS -- auth can-i get pods | tr -d '\n')"
check "run: explain a field" True "$(KS -- explain deployment.spec.replicas | grep -q 'FIELD: replicas <integer>' && echo True)"
check "run: wait for a condition" True "$(KS -- wait deploy/tools --for=condition=Available --timeout=60s | grep -q 'condition met' && echo True)"
check "run: rollout status" True "$(KS -- rollout status deploy/tools | grep -q 'rolled out' && echo True)"
check "run: exec" hello-from-pod "$(KS --write --allow-dangerous -- exec deploy/tools -- cat /www/index.html | tr -d '\n')"
q KR --write -- create configmap e2e-cfg --from-literal=color=blue
check "run: create configmap, read it back" blue "$(KS -- get cm e2e-cfg -o 'jsonpath={.data.color}')"
q KR --write -- label cm e2e-cfg tier=test
check "run: label" test "$(KS -- get cm e2e-cfg -o 'jsonpath={.metadata.labels.tier}')"
check "run: label refuses to overwrite" 5 "$(KR --write -- label cm e2e-cfg tier=other >/dev/null; echo $?)"
q KR --write --allow-dangerous -- patch cm e2e-cfg --type merge -p '{"data":{"color":"green"}}'
check "run: patch" green "$(KS -- get cm e2e-cfg -o 'jsonpath={.data.color}')"
check "run: delete needs --allow-dangerous" 6 "$(KR --write -- delete cm e2e-cfg >/dev/null; echo $?)"
q KR --write --allow-dangerous -- delete cm e2e-cfg
check "run: deleted is not found" K8S_NOT_FOUND "$(KR -- get cm e2e-cfg | jget 'd["error"]["code"]' || true)"
POD=$(KS -- get pods -l app=tools -o 'jsonpath={.items[0].metadata.name}')
q KR --write --allow-dangerous -- cp "$TMP/cp-in.txt" "$POD:/tmp/cp-in.txt"
q KR --write --allow-dangerous -- cp "$POD:/tmp/cp-in.txt" "$TMP/cp-back.txt"
check "run: cp there and back" "copied in" "$(cat "$TMP/cp-back.txt" 2>/dev/null)"
check "run: diff a change exits 1" 5 "$(sed 's/replicas: 1/replicas: 2/' "$TMP/tools.yaml" > "$TMP/tools2.yaml"; KR -- diff -f "$TMP/tools2.yaml" >/dev/null; echo $?)"
check "run: scale" 2 "$(KR --write -- scale deploy/tools --replicas=2 >/dev/null; KS -- get deploy tools -o 'jsonpath={.spec.replicas}')"
q $K cluster rm lab-k3s deployment tools --allow-dangerous
q $K cluster rm lab-k3s service tools --allow-dangerous
q $K cluster rm lab-k3s deployment web --allow-dangerous

# Docker Swarm (a one-node manager, Docker-in-Docker, over SSH)
echo "==> cluster (Docker Swarm)"
q $K host add swarm1 "agent@127.0.0.1:$E2E_SSH_SWARM" --password-ref secret:agent-pass
for _ in $(seq 1 60); do $K exec swarm1 --read-only -- docker node ls >/dev/null 2>&1 && break; sleep 2; done
check "swarm status" True "$($K cluster status swarm1 | jget 'd["data"]["healthy"]')"
cat > "$TMP/stack.yml" <<'YAML'
services:
  web:
    image: busybox:1.37
    command: ["sleep", "86400"]
YAML
q $K cluster apply swarm1 --file "$TMP/stack.yml" --stack e2e
check "swarm services" True "$($K cluster ls swarm1 services | jget 'any(r["name"]=="e2e_web" for r in d["data"]["items"])')"
q $K cluster scale swarm1 service/e2e_web 2
check "swarm scale" True "$($K cluster ls swarm1 services | jget 'any(r["ready"].endswith("/2") for r in d["data"]["items"])')"
check "swarm status --wait" True "$($K cluster status swarm1 service/e2e_web --wait --timeout 90s | jget 'd["data"]["rolled_out"]')"
check "swarm rollback --wait" 1/1 "$($K cluster rollback swarm1 service/e2e_web --wait --timeout 90s | jget 'd["data"]["replicas"]')"
check "swarm logs -f stops at --timeout" True "$($K cluster logs swarm1 e2e_web -f --timeout 3s >/dev/null; echo True)"
check "swarm run reads" True "$($K cluster run swarm1 -- service ls | jget 'd["data"]["results"][0]["ok"]')"
set +e; $K cluster run swarm1 --write -- service rm e2e_web >/dev/null; check "swarm run rm needs --allow-dangerous" 6 $?; set -e
check "docker raw volume rm needs --allow-dangerous" POLICY_BLOCKED "$($K docker raw swarm1 -- volume rm nothing | jget 'd["error"]["code"]' || true)"
check "docker raw reads stay reads" True "$($K docker raw swarm1 -- volume ls | jget 'd["data"]["results"][0]["ok"]')"
q $K cluster rm swarm1 stack e2e --allow-dangerous

# container registry (registry:2 on the private network, through the bastion)
echo "==> registry"
docker pull -q busybox:1.37 >/dev/null && docker tag busybox:1.37 "127.0.0.1:$E2E_REGISTRY"/tools/busybox:1.37 && docker push -q "127.0.0.1:$E2E_REGISTRY"/tools/busybox:1.37 >/dev/null
q $K conn add reg 'registry://e2e@registry:5000?tls=false' --via bastion
check "registry catalog" True "$($K registry ls reg | jget '"tools/busybox" in d["data"]["repositories"]')"
check "registry tags" 1.37 "$($K registry ls reg tools/busybox | jget 'd["data"]["tags"][0]')"
check "registry inspect digest" True "$($K registry inspect reg tools/busybox:1.37 | jget 'd["data"]["digest"].startswith("sha256:")')"
q $K registry copy reg:tools/busybox:1.37 reg:mirror/busybox:stable
check "registry copy keeps the digest" "$($K registry inspect reg tools/busybox:1.37 | jget 'd["data"]["digest"]')" "$($K registry inspect reg mirror/busybox:stable | jget 'd["data"]["digest"]')"
set +e; $K registry rm reg tools/busybox:1.37 >/dev/null; check "registry rm needs --allow-dangerous" 6 $?; set -e
check "registry rm names the tags it takes" True "$($K registry rm reg tools/busybox:1.37 --allow-dangerous --dry-run | jget '"1.37" in d["data"]["tags"]')"
q $K registry rm reg tools/busybox:1.37 --allow-dangerous
check "registry rm removed it" REGISTRY_NOT_FOUND "$($K registry inspect reg tools/busybox:1.37 | jget 'd["error"]["code"]' || true)"
# prune: three images built one after the other; keepme is the same image as v1
for v in 1 2 3; do
  printf 'FROM busybox:1.37\nRUN echo %s > /build\n' "$v" | docker build -q -t "127.0.0.1:$E2E_REGISTRY/prune/app:v$v" - >/dev/null
  docker push -q "127.0.0.1:$E2E_REGISTRY/prune/app:v$v" >/dev/null; sleep 1
done
docker tag "127.0.0.1:$E2E_REGISTRY/prune/app:v1" "127.0.0.1:$E2E_REGISTRY/prune/app:keepme" && docker push -q "127.0.0.1:$E2E_REGISTRY/prune/app:keepme" >/dev/null
check "registry prune needs --allow-dangerous" 6 "$($K registry prune reg prune/app --keep 1 >/dev/null 2>&1; echo $?)"
check "registry prune --dry-run: only v2 goes (v1 is keepme's image)" "['v2'] False" \
  "$($K registry prune reg prune/app --keep 1 --match '^v' --dry-run | jget '[t for d_ in d["data"]["delete"] for t in d_["tags"]], "deleted" in d["data"]')"
q $K registry prune reg prune/app --keep 1 --match '^v' --allow-dangerous
check "registry prune deleted v2 and kept the rest" "['keepme', 'v1', 'v3']" "$($K registry ls reg prune/app | jget 'sorted(d["data"]["tags"])')"
# registry TLS: HTTPS with a private CA, at a name only bastion can look up
q $K conn add regtls 'registry://e2e@registry.lab.test' --via bastion
check "registry: a private CA is refused by default" REGISTRY_TLS "$($K registry ls regtls | jget 'd["error"]["code"]' || true)"
check "registry: the refusal points at ca= first" True "$($K registry ls regtls | jget '"?ca=secret:NAME" in d["error"]["hint"]' || true)"
docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T regtls cat /certs/ca.crt | $K secret set regtls-ca >/dev/null
q $K conn edit regtls --url 'registry://e2e@registry.lab.test?ca=secret:regtls-ca'
check "registry: ?ca=secret:NAME trusts the private CA (name looked up on bastion)" True "$($K registry ls regtls | jget 'd["ok"]')"
check "registry: conn test logs in with ca=" login "$($K conn test regtls | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "registry: ca= is not a doctor warning" False "$($K doctor | jget 'any(c["name"] == "security:conn:regtls" for c in d["data"]["security"])')"
q $K conn edit regtls --url 'registry://e2e@registry.lab.test?tls=skip-verify'
check "registry: ?tls=skip-verify works without the CA" True "$($K registry ls regtls | jget 'd["ok"]')"
check "registry: doctor warns about tls=skip-verify, --via too" True "$($K doctor | jget 'any(c["name"] == "security:conn:regtls" and c["warning"] for c in d["data"]["security"])')"
check "registry: an unknown tls value is refused" USAGE "$($K conn edit regtls --url 'registry://e2e@registry.lab.test?tls=insecure' | jget 'd["error"]["code"]' || true)"
q $K conn rm regtls

# VPNs: a SOCKS proxy (komando's own, through the bastion) and an OS VPN check
echo "==> VPNs"
q $K tunnel start bastion -D "127.0.0.1:$E2E_SOCKS"
q $K vpn add lab socks --address "127.0.0.1:$E2E_SOCKS" --check pg:5432
check "status lists the running tunnel" True "$($K status | jget '"127.0.0.1:'"$E2E_SOCKS"'" in [t["spec"] for t in d["data"]["tunnels"]]')"
check "status in text names it" 1 "$($K -o text status | grep -c '^tunnel ' || true)"
check "prompt counts the tunnel" 1 "$($K prompt | grep -c 'tun:[1-9]' || true)"
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
check "prompt is empty when nothing runs" "" "$($K prompt)"

# logs --follow streams until stopped (here by --timeout)
check "logs --follow streams" True "$($K logs direct --file /etc/hostname --follow --timeout 3s | head -1 | jget '"direct" in d["data"]')"
check "logs --follow: no status line for scripts" 0 "$($K logs direct --file /etc/hostname --follow --timeout 3s 2>&1 >/dev/null | grep -c '^komando:' || true)"
check "logs --follow says where for a person" 1 "$(ptyrun '' "$K" logs direct --file /etc/hostname --follow --timeout 3s | tr -d '\r' | grep -c '^komando: following logs on direct (Ctrl-C stops)$' || true)"
set +e; $K fs rm direct /tmp/somedir --recursive >/dev/null; check "fs rm -r needs --allow-dangerous" 6 $?; set -e

# no way around protection
q $K snippet add touch-it 'touch /tmp/komando-e2e'
check "recipe list has built-ins and saved" True "$($K recipe list | jget 'any(r["builtin"] for r in d["data"]["recipes"]) and any(not r["builtin"] for r in d["data"]["recipes"])')"
set +e; $K snippet run touch-it target >/dev/null; check "snippet on protected host needs --yes" 6 $?; set -e
set +e; $K host rm target >/dev/null; check "removing a protected host needs --yes" 6 $?; set -e
set +e; $K config set audit off >/dev/null; check "turning off audit needs --yes" 6 $?; set -e
set +e; $K secret set leaked hunter2 >/dev/null; check "secret value as argument refused" 2 $?; set -e

echo "==> AI agents"
set +e; A exec target --yes -- 'touch /tmp/x' >/dev/null; check "agent --yes needs a person (no screen)" 6 $?; set -e
check "agent is told to ask the user" True "$(A exec target --yes -- 'touch /tmp/x' | jget '"own terminal" in d["error"]["hint"]' || true)"
check "agent --allow-dangerous needs a person" POLICY_BLOCKED "$(A fs rm direct /tmp/somedir --recursive --allow-dangerous | jget 'd["error"]["code"]' || true)"
q $K fs write direct /home/agent/app/.env -p --content "$(printf 'DB_HOST=db\nDB_PASSWORD=hunter22\nAPI_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n')"
echo 'hello' | $K fs write direct /home/agent/app/readme.txt >/dev/null
check "a script sees the file as it is" True "$($K fs cat direct /home/agent/app/.env | jget '"hunter22" in d["data"]["content"]')"
check "an agent sees [hidden]" "True False False" "$(A fs cat direct /home/agent/app/.env | jget '"DB_PASSWORD=[hidden]" in d["data"]["content"], "hunter22" in json.dumps(d), "ghp_" in json.dumps(d)')"
check "agent exec output is masked" False "$(A exec direct --read-only -- cat /home/agent/app/.env | jget '"hunter22" in json.dumps(d)')"
check "agent text output is masked" 0 "$(A exec direct --read-only -o text -- cat /home/agent/app/.env | { grep -c hunter22 || true; })"
check "agent --reveal without a person stays masked" False "$(A fs cat direct /home/agent/app/.env --reveal | jget '"hunter22" in json.dumps(d)')"
check "masked text is never written back" HIDDEN_VALUE "$(A fs write direct /home/agent/app/.env --content 'DB_PASSWORD=[hidden]' | jget 'd["error"]["code"]' || true)"
q A fs replace direct /home/agent/app/.env --old 'DB_PASSWORD=[hidden]' --new 'DB_PASSWORD={{secret:ops-pass}}'
check "agent sets a hidden value from the vault" True "$($K fs cat direct /home/agent/app/.env | jget '"DB_PASSWORD=[secret:ops-pass]" in d["data"]["content"] and "DB_HOST=db" in d["data"]["content"]')"
check "agent cannot copy .env here" SENSITIVE_FILE "$(A download direct /home/agent/app/.env --to "$TMP/" | jget 'd["error"]["code"]' || true)"
q A download direct /home/agent/app --to "$TMP/agentcopy" -r
check "agent folder copy leaves .env behind" "False True" "$(python3 -c "import os; print(os.path.exists('$TMP/agentcopy/.env'), os.path.exists('$TMP/agentcopy/readme.txt'))")"
check "agent secret get --reveal refused" REVEAL_NEEDS_HUMAN "$(A secret get ops-pass --reveal | jget 'd["error"]["code"]' || true)"
check "guard stops reading the vault" deny "$(printf '{"tool_name":"Read","tool_input":{"file_path":"%s/.komando/vault.key"}}' "$HOME" | $K guide guard | jget 'd["hookSpecificOutput"]["permissionDecision"]')"
check "guard stops ssh around komando" deny "$(echo '{"tool_name":"Bash","tool_input":{"command":"ssh web1 cat .env"}}' | $K guide guard | jget 'd["hookSpecificOutput"]["permissionDecision"]')"
check "guard lets komando through" "" "$(echo '{"tool_name":"Bash","tool_input":{"command":"komando fs cat web1 /srv/.env"}}' | $K guide guard)"
mkdir -p "$TMP/home"
q env HOME="$TMP/home" "$K" guide install
check "guide install adds the Claude Code guard" True "$(jget '"guide guard" in json.dumps(d["hooks"]["PreToolUse"])' < "$TMP/home/.claude/settings.json")"

echo "==> audit chain and doctor"
check "audit chain intact" True "$($K audit verify | jget 'd["data"]["ok"]')"
check "audit names the agent" True "$($K audit -n 200 | jget 'any(e.get("agent") == "Claude Code" for e in d["data"]["entries"])')"
cp "$KOMANDO_HOME/audit.jsonl" "$TMP/audit.bak"
python3 - "$KOMANDO_HOME/audit.jsonl" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().splitlines()
lines[len(lines) // 2] = lines[len(lines) // 2].replace('{', '{"edited":1,', 1)
open(p, "w").write("\n".join(lines) + "\n")
PY
check "edited audit record found" AUDIT_TAMPERED "$($K audit verify | jget 'd["error"]["code"]' || true)"
cp "$TMP/audit.bak" "$KOMANDO_HOME/audit.jsonl"
check "doctor checks security" True "$($K doctor | jget 'any(c["name"] == "security:audit_chain" and c["ok"] for c in d["data"]["security"])')"

# checks per area (test/e2e/checks/*.sh) run here, against the same lab and
# inventory; they use $K, A, check, jget, q and $TMP like the ones above
for f in "$E2E"/checks/*.sh; do
  [ -e "$f" ] || continue
  echo "==> $(basename "$f" .sh)"
  # shellcheck source=/dev/null
  . "$f"
done

# no secret value may reach the state file or the audit log
LEAKS=$(cat "$KOMANDO_HOME/state.json" "$KOMANDO_HOME/audit.jsonl" | { grep -c -E 'apppass|shoppass|redispass' || true; })
check "no passwords in state or audit" 0 "$LEAKS"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
