#!/bin/sh
# start-time.sh NEW OLD: how long the komando binaries NEW and OLD take to
# start, for `komando version`, `komando list` (empty list) and
# `komando guide guard` (the agent hook that runs before every tool call).
# Each command runs once to warm up, then 5 times per binary, the two
# binaries taking turns so both see the same noise; the median counts.
# Fails when NEW is more than 10% slower than OLD for any command. Runs in
# CI on Linux (date +%s%N is GNU date).
set -eu
new=$1 old=$2
runs=5

# a throwaway home per binary: nothing of a person's is read or written,
# and no keychain is used (as in the e2e lab)
unset DBUS_SESSION_BUS_ADDRESS SSH_AUTH_SOCK CLAUDECODE CLAUDE_CODE_ENTRYPOINT GEMINI_CLI CODEX_SANDBOX CODEX_THREAD_ID CURSOR_AGENT KOMANDO_AGENT AI_AGENT
export KOMANDO_KEYCHAIN=off KOMANDO_ACTOR=start-time
newhome=$(mktemp -d) oldhome=$(mktemp -d)
trap 'rm -rf "$newhome" "$oldhome"' EXIT

# one tool call as Claude Code hands it to the hook: a komando line, which
# the guard rates
hook='{"tool_name":"Bash","tool_input":{"command":"komando exec web1 --read-only -- uptime"},"cwd":"/tmp"}'

# ms BIN HOME CMD: one run's wall time in milliseconds
ms() {
  start=$(date +%s%N)
  case $3 in
  version) HOME=$2 KOMANDO_HOME=$2/.komando "$1" version >/dev/null ;;
  list) HOME=$2 KOMANDO_HOME=$2/.komando "$1" list -o json >/dev/null ;;
  guard) printf '%s' "$hook" | HOME=$2 KOMANDO_HOME=$2/.komando "$1" guide guard >/dev/null ;;
  esac
  echo $(( ($(date +%s%N) - start) / 1000000 ))
}

median() { sort -n | sed -n "$(( (runs + 1) / 2 ))p"; }

fail=0
printf '%-8s %10s %10s %8s\n' command new_ms old_ms change
for cmd in version list guard; do
  ms "$new" "$newhome" "$cmd" >/dev/null # warm up: the first list makes the store
  ms "$old" "$oldhome" "$cmd" >/dev/null
  n="" o=""
  i=0
  while [ $i -lt $runs ]; do
    n="$n $(ms "$new" "$newhome" "$cmd")"
    o="$o $(ms "$old" "$oldhome" "$cmd")"
    i=$((i + 1))
  done
  nm=$(echo "$n" | tr ' ' '\n' | sed '/^$/d' | median)
  om=$(echo "$o" | tr ' ' '\n' | sed '/^$/d' | median)
  change=$(( om > 0 ? (nm - om) * 100 / om : 0 ))
  printf '%-8s %10s %10s %7s%%\n' "$cmd" "$nm" "$om" "$change"
  if [ $((nm * 100)) -gt $((om * 110)) ]; then
    echo "$cmd: the branch starts more than 10% slower than main ($nm ms against $om ms)" >&2
    fail=1
  fi
done
exit $fail
