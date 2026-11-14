#!/usr/bin/env bash
# Unit tests with coverage, and a floor per package: a package's coverage
# may go up, never below its line in test/coverage-floor.txt. After raising
# it, write the new number there (a floor only moves up).
#
#   test/coverage.sh        (make cover)
set -euo pipefail
cd "$(dirname "$0")/.."
FLOORS=test/coverage-floor.txt
mod=$(go list -m)
# -timeout: internal/cli takes minutes, near Go's default 10m limit on a
# slow runner
report=$(go test -timeout 30m -cover ./... 2>&1) || { echo "$report"; exit 1; }
echo "$report"
fail=0
while read -r pkg floor; do
  case "$pkg" in "" | \#*) continue ;; esac
  got=$(echo "$report" | awk -v p="$mod/$pkg" '$2 == p { for (i = 1; i <= NF; i++) if ($i == "coverage:") { sub("%", "", $(i+1)); print $(i+1) } }')
  if [ -z "$got" ]; then
    echo "FAIL $pkg: no coverage reported (renamed or moved? update $FLOORS)"
    fail=1
  elif awk -v g="$got" -v f="$floor" 'BEGIN { exit !(g < f) }'; then
    echo "FAIL $pkg: coverage $got% is below its floor of $floor%: add tests for the new code"
    fail=1
  fi
done <"$FLOORS"
[ "$fail" = 0 ] && echo "coverage floors: ok"
exit "$fail"
