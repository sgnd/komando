# General CLI behaviour: usage errors, typos, dry-run never blocked.
check "missing args name the usage line" True "$($K fs cat direct | jget '"usage: komando fs cat TARGET PATH" in d["error"]["message"]' || true)"
check "-o text applies to usage errors" True "$($K fs cat direct -o text 2>&1 >/dev/null | grep -q '^error \[USAGE\]' && echo True || echo False)"
set +e; $K host lst >/dev/null 2>&1; check "unknown subcommand fails" 2 $?; set -e
check "unknown subcommand suggests" True "$($K svc restat direct x | jget '"did you mean restart" in d["error"]["message"]' || true)"
check "dry-run shows a protected change" PROTECTED_HOST "$($K exec target --dry-run -- touch /tmp/x | jget 'd["meta"]["would_be_blocked"]["code"]')"
check "dry-run banner in text" True "$($K exec target --dry-run -o text -- touch /tmp/x 2>&1 >/dev/null | grep -q '^dry run: nothing was changed' && echo True || echo False)"
