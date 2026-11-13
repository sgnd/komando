# shellcheck shell=bash
# Sourced by run.sh for one area of the e2e lab: the home komando uses, the
# helpers every check uses (check, jget, q, A, $TMP, ptyrun), starting and
# stopping the area's containers, and the setup steps (+name in run.sh's
# area table: setup_name here) that make the inventory a check needs.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E="$ROOT/test/e2e"
K="$ROOT/bin/komando"
# E2E_HOME keeps the inventory after the run (with KEEP=1 for the
# containers), to try commands by hand against the same lab: one folder per
# area, E2E_HOME/AREA
KOMANDO_HOME="${E2E_HOME:+$E2E_HOME/$AREA}"
KOMANDO_HOME="${KOMANDO_HOME:-$(mktemp -d)}"
mkdir -p "$KOMANDO_HOME" && chmod 700 "$KOMANDO_HOME"
export KOMANDO_HOME
export KOMANDO_ACTOR="e2e"
# a new vault would put its key in this computer's keychain (the login
# keychain on a Mac): every run would leave one there. The unit tests cover
# the keychain with stand-ins (internal/vault/newkey_test.go).
export KOMANDO_KEYCHAIN=off
# the audit log and the inventory as text, from the sealed store
audit_text() { "$K" audit -n 0 -o json 2>/dev/null; }
inventory_text() { "$K" export -o json 2>/dev/null; }
# this script is a script, even when an AI agent starts it; the agent
# checks say so on purpose (and never open an approval window)
unset CLAUDECODE CLAUDE_CODE_ENTRYPOINT GEMINI_CLI CODEX_SANDBOX CODEX_THREAD_ID CURSOR_AGENT KOMANDO_AGENT AI_AGENT
# an agent's komando keeps the usual data folder (~/.komando): A runs with a
# home whose .komando is this run's folder
AGENT_HOME="$(mktemp -d)"
ln -s "$KOMANDO_HOME" "$AGENT_HOME/.komando"
A() { CLAUDECODE=1 KOMANDO_NO_DIALOG=1 HOME="$AGENT_HOME" "$K" "$@"; }
TMP="$(mktemp -d)"
PROJECT=${E2E_PROJECT:-komando-e2e}
export E2E_SSH_BASTION=${E2E_SSH_BASTION:-2222} E2E_SSH_DIRECT=${E2E_SSH_DIRECT:-2223}
export E2E_SSH_SWARM=${E2E_SSH_SWARM:-2224} E2E_REGISTRY=${E2E_REGISTRY:-5005}
export E2E_BAO=${E2E_BAO:-8201} E2E_MOTO=${E2E_MOTO:-5016} E2E_VW=${E2E_VW:-8090} E2E_K3S_OLD=${E2E_K3S_OLD:-16444}
export E2E_AZURITE=${E2E_AZURITE:-10010}
E2E_SOCKS=${E2E_SOCKS:-18080}
BAOENV=(env PATH=/usr/bin:/bin VAULT_ADDR="http://127.0.0.1:$E2E_BAO" VAULT_TOKEN=e2e-root)
PASS=0
FAIL=0

# DC ARGS...: docker compose on this lab
DC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }

# in_area NAME: this run is the area NAME. A check file that several areas
# source puts each part under the one area whose containers it needs, so
# every part runs once in a full run.
in_area() { [ "$AREA" = "$1" ]; }
# skipped REASON: a check could not run here (its server does not start on
# this machine); the results name the area SKIPPED with REASON, never ok
skipped() { echo "  SKIPPED: $1"; [ -z "${E2E_RESULTS:-}" ] || echo "$AREA $1" >>"$E2E_RESULTS.skipped"; }
# has_service NAME: the area started that compose service
has_service() { case " ${SERVICES[*]} " in *" $1 "*) return 0 ;; esac; return 1; }

# jget '<python expression on d>' : evaluate against JSON on stdin
# When the output is not the JSON the check expects (an error instead of data),
# it prints that output, so a failure in CI says why.
jget() { python3 -c "
import json,sys
raw=sys.stdin.read()
try:
    d=json.loads(raw); print($1)
except Exception as e:
    sys.stderr.write('jget: %s: %s; komando printed: %s\n' % (type(e).__name__, e, raw.strip()[:1500] or '(nothing)')); sys.exit(1)
"; }

check() { # check "name" expected actual
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  ok   $1"
  else FAIL=$((FAIL+1)); echo "  FAIL $1: expected [$2] got [$3]"; fi
}

# q CMD...: a step that must work; when it does not, say which and what it printed
q() { local o; o=$("$@") || { echo "  step failed: ${*:2}"; echo "$o" | head -c 600; echo; return 1; }; }

. "$E2E/pty.sh"

# wait_port PORT: until something listens on 127.0.0.1:PORT (at most 30s)
wait_port() { for _ in $(seq 1 30); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 1; done; }

lab_up() {
  [ "${#SERVICES[@]}" -gt 0 ] || return 0
  echo "==> start containers: ${SERVICES[*]}"
  DC up -d --build --wait "${SERVICES[@]}" >/dev/null 2>&1 || DC up -d --build "${SERVICES[@]}" >/dev/null
}

lab_down() {
  [ "${#SERVICES[@]}" -gt 0 ] || return 0
  [ "${KEEP:-0}" = 1 ] || DC down -v >/dev/null 2>&1 || true
}

# ---- setup steps (+name in run.sh) ----

# +hosts: the vault secret agent-pass and the lab servers this area started:
# bastion, direct, and target (protected, only reachable through bastion)
setup_hosts() {
  echo "==> inventory & vault"
  echo -n agentpass | $K secret set agent-pass >/dev/null
  if has_service bastion; then
    wait_port "$E2E_SSH_BASTION"
    $K host add bastion "agent@127.0.0.1:$E2E_SSH_BASTION" --password-ref secret:agent-pass -g lab >/dev/null
  fi
  if has_service direct; then
    wait_port "$E2E_SSH_DIRECT"
    $K host add direct "agent@127.0.0.1:$E2E_SSH_DIRECT" --password-ref secret:agent-pass -g lab -t test >/dev/null
  fi
  if has_service target; then
    $K host add target agent@target --via bastion --password-ref secret:agent-pass -g lab --protected >/dev/null
  fi
  sleep 1
}

# +data: a Garage bucket and the conns pg, maria (protected), cache and
# bucket, all through the bastion, with their passwords in the vault
setup_data() {
  echo "==> conns through bastion (db, cache, storage)"
  for _ in $(seq 1 60); do DC ps --format '{{.Health}}' pg maria 2>/dev/null | grep -qv healthy || break; sleep 1; done
  G() { DC exec -T s3 /garage "$@" 2>/dev/null; }
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
}

# +maria_conn: the protected conn maria, for checks that only edit the
# inventory (no MariaDB runs)
setup_maria_conn() {
  echo -n shoppass | $K secret set maria-pass >/dev/null
  q $K conn add maria 'mysql://shop@maria:3306/shop' --via bastion --password-ref secret:maria-pass --protected
}

# +vpns: the SOCKS VPN lab (through the bastion, in use by target-lab) and
# the system VPN corp, which is down
setup_vpns() {
  q $K vpn add lab socks --proxy-address "127.0.0.1:$E2E_SOCKS" --check pg:5432
  q $K vpn add corp system --check 127.0.0.1:1
  q $K host add target-lab agent@target --via lab --password-ref secret:agent-pass
}

# +swarm: swarm1, a one-node Docker Swarm manager over SSH
setup_swarm() {
  wait_port "$E2E_SSH_SWARM"
  q $K host add swarm1 "agent@127.0.0.1:$E2E_SSH_SWARM" --password-ref secret:agent-pass
  for _ in $(seq 1 60); do $K exec swarm1 --read-only -- docker node ls >/dev/null 2>&1 && break; sleep 2; done
}

# +files_pass: the vault secret of the lab's file servers (user deploy)
setup_files_pass() { echo -n deploypass | $K secret set files-pass >/dev/null; }

# write_tools_yaml FILE: a busybox web server and its Service, for exec and
# port-forward in Kubernetes
write_tools_yaml() {
  cat > "$1" <<'YAML'
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
}
