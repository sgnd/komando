#!/usr/bin/env bash
# End-to-end test: disposable SSH servers, databases, queues and clusters in
# Docker (a bastion in front of a private network, plus directly reachable
# boxes), driven with the real komando binary.
#
# The lab runs one area at a time: an area starts only the containers it
# needs, makes the inventory its checks use, runs them, and removes its
# containers before the next area starts. So a small Docker VM (2 GB) is
# enough, and one area can be run by itself:
#
#   make e2e                    every area, one after another
#   make e2e AREA=ops           one area (AREA=ops,swarm: those, in order)
#   test/e2e/run.sh --list      the areas, with their containers
#
# Needs: docker (with compose), go, python3. Set KEEP=1 to keep the last
# area's containers, E2E_HOME=DIR to keep each area's inventory in DIR/AREA.
#
# Several runs can share one machine (e.g. one per git worktree) when each
# sets its own project name and host ports:
#   E2E_PROJECT=komando-e2e-b E2E_SSH_BASTION=3222 E2E_SSH_DIRECT=3223 \
#   E2E_SSH_SWARM=3224 E2E_REGISTRY=6005 E2E_SOCKS=19080 E2E_BAO=8211 E2E_MOTO=5026 E2E_VW=8091 E2E_AZURITE=10020 \
#   E2E_K3S_OLD=16454 make e2e
# (checks that start their own servers: E2E_SSH_SYSTEMD, E2E_SSH_ROCKY and
# E2E_SSH_AMZN2, by default 2225, 2226 and 2227)
set -euo pipefail

E2E="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$E2E/../.." && pwd)"

# The areas, in the order a full run takes them:
#   NAME | compose services it starts | steps, in order
# A step +name is setup_name in lib.sh (it makes inventory); any other step
# is checks/name.sh. A check file that several areas list runs only its
# parts for the area at hand (in_area in lib.sh).
AREAS='
core          | bastion target direct bao moto                    | +hosts +maria_conn base protect agents audit general inv proxy_path rename resilience run sshgate
data          | bastion target direct pg maria redis memcached s3 sftp ftps bao vaultwarden | +hosts +data conns vpn coverage data files dbusers dryrun dump parity zz_agent zz_person
k8s           | bastion k3s                                       | +hosts k8s clu dryrun parity zz_agent
k8s-old       | bastion k3s-old                                   | +hosts k8s_old
swarm         | direct swarm                                      | +hosts +swarm swarm clu coverage dryrun parity zz_agent
registry      | bastion registry regtls                           | +hosts registry clu coverage parity zz_agent
ops           | bastion direct swarm                              | +hosts +swarm +vpns ops
aws           | bastion direct moto registry                      | +hosts aws
sqs           | bastion moto                                      | +hosts sqs
mongo         | bastion mongo                                     | +hosts mongo
kafka         | bastion kafka                                     | +hosts kafka
rabbitmq      | bastion rabbitmq                                  | +hosts rabbitmq
nats          | bastion nats                                      | +hosts nats
pubsub        | bastion pubsub                                    | +hosts pubsub
sqlserver     | bastion mssql                                     | +hosts sqlserver
oracle        | bastion oracle                                    | +hosts oracle
clickhouse    | bastion clickhouse                                | +hosts clickhouse
snowflake     | bastion snowflake                                 | +hosts snowflake
bigquery      | bastion bigquery                                  | +hosts bigquery
smb           | bastion samba                                     | +hosts smb
storage-cloud | bastion gcs azurite webdav                        | +hosts +files_pass storage_cloud
systemd       |                                                   | +hosts systemd
rhel          |                                                   | +hosts rhel
wireguard     |                                                   | wireguard
'

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; echo "${s%"${s##*[![:space:]]}"}"; }
area_names() { echo "$AREAS" | awk -F'|' 'NF == 3 { gsub(/ /, "", $1); print $1 }'; }
area_field() { echo "$AREAS" | awk -F'|' -v a="$1" -v n="$2" 'NF == 3 { name = $1; gsub(/ /, "", name); if (name == a) print $n }'; }

# ---- one area (run.sh starts itself with E2E_AREA_RUN=1 for each) ----
if [ "${E2E_AREA_RUN:-0}" = 1 ]; then
  read -r -a SERVICES <<<"$(trim "$(area_field "$AREA" 2)")"
  read -r -a STEPS <<<"$(trim "$(area_field "$AREA" 3)")"
  . "$E2E/lib.sh"
  cleanup() {
    local rc=$?
    lab_down
    "$K" tunnel stop --all >/dev/null 2>&1 || true # only this run's tunnels
    [ -n "${E2E_HOME:-}" ] || rm -rf "$KOMANDO_HOME"
    rm -rf "$AGENT_HOME" "$TMP"
    [ -z "${E2E_RESULTS:-}" ] || echo "$AREA $PASS $FAIL $rc" >>"$E2E_RESULTS"
  }
  trap cleanup EXIT
  lab_up
  for s in "${STEPS[@]}"; do
    case "$s" in
      +*) "setup_${s#+}" ;;
      *) echo "==> $s"
         # shellcheck source=/dev/null
         . "$E2E/checks/$s.sh" ;;
    esac
  done
  # no secret value may reach the state file or the audit log
  LEAKS=$({ inventory_text; audit_text; } | { grep -c -E 'apppass|shoppass|redispass' || true; })
  check "no passwords in state or audit" 0 "$LEAKS"
  echo "passed: $PASS  failed: $FAIL"
  [ "$FAIL" -eq 0 ]
  exit
fi

# ---- the runner ----
case "${1:-}" in
  --list) echo "$AREAS" | awk -F'|' 'NF == 3 { gsub(/ +/, " ", $2); printf "%-14s%s\n", $1, $2 }' | sed 's/  *$//'; exit 0 ;;
  --list-json) area_names | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().split()))'; exit 0 ;;
  "") ;;
  *) echo "usage: run.sh [--list | --list-json]; pick areas with AREA=NAME[,NAME...]" >&2; exit 2 ;;
esac

ALL=$(area_names | tr '\n' ' ')
if [ -n "${AREA:-}" ]; then
  PICKED=$(echo "$AREA" | tr ',' ' ')
  for a in $PICKED; do
    case " $ALL " in *" $a "*) ;; *) echo "unknown area: $a (areas: $ALL)" >&2; exit 2 ;; esac
  done
else
  PICKED=$ALL
fi

# never two labs at once: a second one would share the ports and the memory
PROJECT=${E2E_PROJECT:-komando-e2e}
if [ -n "$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT")" ]; then
  echo "the e2e lab $PROJECT is already running (docker ps): wait for that run to end," >&2
  echo "or remove it with: docker compose -p $PROJECT -f test/e2e/compose.yml down -v" >&2
  exit 1
fi

echo "==> build"
(cd "$ROOT" && go build -o bin/komando ./cmd/komando)

E2E_RESULTS=$(mktemp)
export E2E_RESULTS
trap 'rm -f "$E2E_RESULTS" "$E2E_RESULTS.skipped"' EXIT
for a in $PICKED; do
  echo
  echo "======== area $a ========"
  E2E_AREA_RUN=1 AREA="$a" "$0" || true
  grep -q "^$a " "$E2E_RESULTS" || echo "$a 0 0 1" >>"$E2E_RESULTS"
done

echo
echo "======== results per area ========"
TOTAL_PASS=0 TOTAL_FAIL=0 BAD=0 SKIPPED=0
while read -r a p f rc; do
  state=ok
  if [ "$f" -gt 0 ]; then state=FAIL
  elif [ "$rc" -ne 0 ]; then state="STOPPED (exit $rc)"
  elif grep -q "^$a " "$E2E_RESULTS.skipped" 2>/dev/null; then
    state="SKIPPED: $(grep "^$a " "$E2E_RESULTS.skipped" | cut -d' ' -f2- | paste -sd';' -)"
    SKIPPED=$((SKIPPED+1))
  fi
  case "$state" in ok | SKIPPED*) ;; *) BAD=$((BAD+1)) ;; esac
  printf '  %-14s passed: %4d  failed: %3d  %s\n' "$a" "$p" "$f" "$state"
  TOTAL_PASS=$((TOTAL_PASS+p)) TOTAL_FAIL=$((TOTAL_FAIL+f))
done <"$E2E_RESULTS"
echo "passed: $TOTAL_PASS  failed: $TOTAL_FAIL  (areas not ok: $BAD, skipped: $SKIPPED)"
[ "$BAD" -eq 0 ]
