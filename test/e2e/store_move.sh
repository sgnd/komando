#!/usr/bin/env bash
# The store moves to format 3 only from `komando doctor` answered y (cut
# step E1). The BUILT komando runs at a pseudo-terminal, as a person types,
# on a store made by the last format-2 release:
#
#   test/e2e/store_move.sh NEW OLD
#
# NEW is the komando under test, OLD the release LastFormat2Release names
# (internal/store/migrate3_fix.go). After a dry run, completion (run from
# .zshrc), help, version, schema, komando alone, the completion helper, a
# mistyped line, a usage error, another command and doctor answered n, the
# store is still format 2, byte-equal, with no backup; doctor answered y
# moves it once.
# Every run gets `env -i` with HOME and KOMANDO_HOME in a temp folder: it
# never reads or writes ~/.komando. komando refuses an AI agent here
# (NEEDS_PERSON), so a person or CI runs it.
set -euo pipefail

E2E="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=pty.sh
. "$E2E/pty.sh"
[ $# -eq 2 ] || { echo "usage: $0 NEW OLD" >&2; exit 2; }
NEW=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
OLD=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")

T=$(mktemp -d "${TMPDIR:-/tmp}/store-move.XXXXXX")
trap 'rm -rf "$T"' EXIT
chmod 700 "$T"
H=$T/home
mkdir -m 700 "$H"
DB=$H/.komando/store.db

# ENV: komando gets nothing from this shell but the temp home
ENV=(env -i PATH=/usr/bin:/bin HOME="$H" KOMANDO_HOME="$H/.komando" KOMANDO_KEYCHAIN=off
  TMPDIR="$T" LANG=C.UTF-8 TERM=xterm)
format() {
  python3 -I -c 'import sqlite3, sys
c = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
print(c.execute("SELECT v FROM meta WHERE k = ?", ("format",)).fetchone()[0])' "$DB"
}
sum() { python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$DB"; }
backups() { find "$H/.komando" -maxdepth 1 -name 'store-v0-17-backup-*' | wc -l | tr -d ' '; }

# flat: the screen as one line; the terminal wraps long lines anywhere
flat() { tr -s '\r\n\t ' ' '; }

fail=0
pass() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }

echo "== a format-2 store made by $("$OLD" --version 2>&1 | head -1)"
printf 'FAKE-demo-pass-not-real' | "${ENV[@]}" "$OLD" -o text secret set demo-pass
"${ENV[@]}" "$OLD" -o text host add demo-1 demo@192.0.2.10 --password-ref secret:demo-pass </dev/null
"${ENV[@]}" "$OLD" -o text host add demo-2 demo@192.0.2.11 </dev/null
[ "$(format)" = 2 ] || { echo "FAIL the old release made format $(format), not 2"; exit 1; }
SUM=$(sum)

# still2 LABEL INPUT [WANT] ARGS...: the line at the pty, INPUT typed at a
# question; the store stays format 2, byte-equal, no backup; the screen
# shows WANT (a word, or - for nothing)
still2() {
  local label=$1 input=$2 want=$3 shown
  shift 3
  shown=$(ptyrun "$input" "${ENV[@]}" "$NEW" "$@" | flat || true)
  if [ "$(format)" != 2 ] || [ "$(sum)" != "$SUM" ] || [ "$(backups)" != 0 ]; then
    bad "$label: format $(format), $(backups) backup(s), store.db changed: $(printf %s "$shown" | tail -c 400)"
  elif [ "$want" != - ] && ! printf %s "$shown" | grep -qF -- "$want"; then
    bad "$label: the screen lacks '$want': $(printf %s "$shown" | tail -c 400)"
  else
    pass "$label"
  fi
}

echo "== $NEW, at a terminal"
still2 "doctor --dry-run" 'n\n' "would" doctor --dry-run
still2 "-o text doctor --dry-run" 'n\n' "nothing was written" -o text doctor --dry-run
still2 "completion zsh" 'n\n' - completion zsh
still2 "help" 'n\n' - help
still2 "version" 'n\n' - version
still2 "schema" 'n\n' - schema
still2 "komando alone" 'n\n' -
still2 "the completion helper by hand" 'n\n' - __complete host show ""
still2 "a mistyped line" 'n\n' - lsit
still2 "a usage error" 'n\n' - list --no-such-flag
still2 "another command" 'n\n' "komando doctor" list
still2 "doctor answered n" 'n\n' "nothing was changed" doctor
still2 "doctor answered with Enter" '\n' "nothing was changed" doctor

shown=$(ptyrun 'y\n' "${ENV[@]}" "$NEW" doctor | flat || true)
if [ "$(format)" = 3 ] && [ "$(backups)" = 1 ] && printf %s "$shown" | grep -qF "[y/N]" && printf %s "$shown" | grep -qF -- "--accept-old-copy"; then
  pass "doctor answered y: the plan, then format 3 and one backup"
else
  bad "doctor answered y: format $(format), $(backups) backup(s): $(printf %s "$shown" | tail -c 600)"
fi
ptyrun 'y\n' "${ENV[@]}" "$NEW" doctor >/dev/null || true
if [ "$(format)" = 3 ] && [ "$(backups)" = 1 ]; then pass "doctor again: no second move"; else bad "doctor again: $(backups) backup(s)"; fi

[ "$fail" = 0 ] && echo "RESULT: only doctor answered y moved the store" || echo "RESULT: FAILED"
exit "$fail"
