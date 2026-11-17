#!/bin/sh
# no-lab-build.sh FILE: fail when the komando binary FILE was built with
# the e2elab tag (internal/store/home_lab.go), which lets a variable name
# the account's home folder. Only the e2e lab's own komando may have it.
set -eu
if LC_ALL=C grep -q KOMANDO_E2E_ACCOUNT_HOME "$1"; then
  echo "$1 was built with the e2elab tag (check GOFLAGS): not a release binary" >&2
  exit 1
fi
