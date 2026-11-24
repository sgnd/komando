#!/usr/bin/env bash
# Runs the test SOP in the e2e lab (vault note
# 2026-11-24-komando-v2-7-test-sop-design). Never on a Mac, never against a
# real home: lab_env.sh gives every run its own empty HOME, no keyring and
# no ssh-agent, and lab_refuse_here stops on macOS.
#
#   test/sop/run.sh smoke                  the scripted model on task 01: no key, no cost
#   test/sop/run.sh score FILE...          check result files for secrets and unknown fields
#   test/sop/run.sh agent --yes-cost ...   a model run: only after the owner's yes to the cost
#
# A model run needs SOP_MODEL and SOP_API_KEY in the environment of the CI
# job or the lab shell. This script never reads a key from a file.
set -euo pipefail

SOP="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SOP/../.." && pwd)"
. "$ROOT/test/e2e/lab_env.sh"
lab_refuse_here || exit 1
lab_env || exit 1

cmd="${1:-}"
[ -n "$cmd" ] && shift
case "$cmd" in
  smoke)
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    printf 'run komando list\nsay done\n' >"$work/script.txt"
    (cd "$ROOT" && go run ./test/sop/cmd/sop run scripted \
      --task test/sop/tasks/01-add-server-uptime.md --script "$work/script.txt" \
      --tree "${SOP_TREE:-new}" --out "$work/result.json")
    test -s "$work/result.json" && echo "sop smoke: ok"
    ;;
  score)
    for f in "$@"; do
      (cd "$ROOT" && go run ./test/sop/cmd/sop check "$f")
    done
    ;;
  agent)
    : "${SOP_MODEL:?set SOP_MODEL in the environment}"
    : "${SOP_API_KEY:?set SOP_API_KEY in the environment (never in a file)}"
    (cd "$ROOT" && go run ./test/sop/cmd/sop run agent --model "$SOP_MODEL" "$@")
    ;;
  *)
    echo "usage: test/sop/run.sh smoke | score FILE... | agent --yes-cost --task FILE --tree old|new --out FILE" >&2
    exit 2
    ;;
esac
