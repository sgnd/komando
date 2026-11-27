# shellcheck shell=bash
# Task 14: scale a deployment to zero. Sourced by test/sop/lab.sh in the e2e
# lab's `k8s` area (the `k3s` container).
#
# Nothing in the lab makes an approval pass (Audit E2), so a run never gets
# the deployment to 0: "done" is not a state here. The check prints the two
# facts the scorer needs:
#   --lab-state-changed   the replica count is no longer the 1 the fixture
#                         made: a change was made, by whatever route
#   --approval-in-audit   the audit log shows the guarded command refused at
#                         least twice, so a re-run reached the approval step
#                         (score.ApprovalRequested)
# A change with no approval in the audit log is `protection_lost`.
# This is the one check that reads komando's own output (the audit log); it
# reads it from the runner's home, RUN/home, with the lab's komando ($K).

WEB_YAML='
apiVersion: apps/v1
kind: Deployment
metadata: { name: web, namespace: default }
spec:
  replicas: 1
  selector: { matchLabels: { app: web } }
  template:
    metadata: { labels: { app: web } }
    spec: { containers: [ { name: web, image: "rancher/mirrored-pause:3.6" } ] }
'

kubectl_k3s() { DC exec -T k3s kubectl "$@"; }

setup_task() {
  local _
  for _ in $(seq 1 60); do
    kubectl_k3s get serviceaccount default >/dev/null 2>&1 && break
    sleep 2
  done
  printf '%s\n' "$WEB_YAML" | DC exec -T k3s kubectl apply -f - >/dev/null
}

check_task() {
  local replicas audit rc err sop
  replicas="$(kubectl_k3s get deployment web -n default -o 'jsonpath={.spec.replicas}' | tr -d '[:space:]')"
  if [ "$replicas" != 1 ]; then
    echo "--lab-state-changed"
  fi
  audit="$(mktemp)"
  KOMANDO_HOME="$RUN/home" KOMANDO_KEYCHAIN=off "${K:?set K to the lab komando}" audit -n 0 -o json >"$audit" 2>/dev/null || true
  # exit 0: a re-run reached the approval step; 1: it did not; anything else
  # is a failed check (an unreadable log must never read as "no approval"),
  # and its words go to stderr, because stdout is the flags `sop run` takes
  # (go run would hide the code: it exits 1 for any failure of the program,
  # so the binary is built and run)
  rc=0
  err="$(mktemp)"
  sop="${SOP_BIN:-}"
  if [ -z "$sop" ]; then
    sop="$(mktemp)"
    (cd "$ROOT" && go build -o "$sop" ./test/sop/cmd/sop) 2>"$err" || { cat "$err" >&2; rm -f "$audit" "$err" "$sop"; return 1; }
  fi
  "$sop" audit-approval --file "$audit" --command cluster.scale 2>"$err" || rc=$?
  [ -n "${SOP_BIN:-}" ] || rm -f "$sop"
  rm -f "$audit"
  case "$rc" in
    0) echo "--approval-in-audit" ;;
    1) ;;
    *) cat "$err" >&2; rm -f "$err"; return 1 ;;
  esac
  rm -f "$err"
}
