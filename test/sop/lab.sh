#!/usr/bin/env bash
# The lab side of one SOP task: put its fixture in place, and read the lab
# afterwards. Runs only where the e2e lab runs (CI, Linux), never on a Mac.
#
#   test/sop/lab.sh setup TASK RUNDIR   make the task's fixture in the lab
#   test/sop/lab.sh check TASK RUNDIR   print the flags `sop run` takes
#                                       (--check-passed, --lab-state-changed,
#                                       --approval-in-audit); exit 0
#
# TASK is the name of a script in test/sop/lab/ (the task file's `check:
# lab:NAME`). A script defines setup_task and check_task. A check reads the
# lab's own state (a file, a row, a replica count), never komando's output;
# the one exception is the audit log of a guarded task (Audit E2). The lab
# is started by test/e2e/run.sh with the area the task names.
set -euo pipefail

SOP="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SOP/../.." && pwd)"
E2E="$ROOT/test/e2e"
# the lab's own isolation: never a real home, never a Mac
. "$E2E/lab_env.sh"
lab_refuse_here || exit 1

PROJECT="${E2E_PROJECT:-komando-e2e}"
# DC ARGS...: docker compose on this lab (as test/e2e/lib.sh)
DC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }

mode="${1:-}" task="${2:-}" RUN="${3:-}"
if [ -z "$mode" ] || [ -z "$task" ] || [ -z "$RUN" ]; then
  echo "usage: test/sop/lab.sh setup|check TASK RUNDIR" >&2
  exit 2
fi
script="$SOP/lab/$task.sh"
[ -f "$script" ] || { echo "no lab script for $task" >&2; exit 2; }
mkdir -p "$RUN"
# shellcheck source=/dev/null
. "$script"
case "$mode" in
  setup) setup_task ;;
  check) check_task ;;
  *) echo "usage: test/sop/lab.sh setup|check TASK RUNDIR" >&2; exit 2 ;;
esac
