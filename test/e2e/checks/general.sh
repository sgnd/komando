# General CLI behaviour: usage errors, typos, dry-run never blocked.
check "missing args name the usage line" True "$($K fs cat direct | jget '"usage: komando fs cat TARGET PATH" in d["error"]["message"]' || true)"
check "-o text applies to usage errors" True "$($K fs cat direct -o text 2>&1 >/dev/null | grep -q '^error \[USAGE\]' && echo True || echo False)"
set +e; $K host lst >/dev/null 2>&1; check "unknown subcommand fails" 2 $?; set -e
check "unknown subcommand suggests" True "$($K svc restat direct x | jget '"did you mean restart" in d["error"]["message"]' || true)"
check "dry-run shows a protected change" PROTECTED_HOST "$($K exec target --dry-run -- touch /tmp/x | jget 'd["meta"]["would_be_blocked"]["code"]')"
check "dry-run banner in text" True "$($K exec target --dry-run -o text -- touch /tmp/x 2>&1 >/dev/null | grep -q '^dry run: nothing was changed' && echo True || echo False)"
q $K host add t-e2egen-alias agent@TARGET. --via bastion --password-ref secret:agent-pass
check "same server under another spelling is protected" PROTECTED_HOST "$($K exec t-e2egen-alias --dry-run -- touch /tmp/x | jget 'd["meta"]["would_be_blocked"]["code"]')"
q $K host rm t-e2egen-alias
check "bad KOMANDO_OUTPUT names the variable" True "$(KOMANDO_OUTPUT=bogus $K list 2>&1 | grep -q 'KOMANDO_OUTPUT=bogus' && echo True || echo False)"
set +e; $K exec direct -P -1 -- true >/dev/null 2>&1; check "negative -P refused" 2 $?; set -e
check "many skipped targets: one line" 1 "$($K list all -o text >/dev/null 2>&1; $K exec all --read-only -o text -- true 2>&1 >/dev/null | grep -c '^skipped')"
