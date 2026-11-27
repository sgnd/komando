# shellcheck shell=bash
# General CLI behaviour: usage errors, typos, dry-run never blocked.
# stderr_of CMD...: what CMD wrote on stderr, whatever its exit code (run.sh
# uses pipefail, so `CMD | grep` would fail when CMD does)
# shellcheck disable=SC2069 # on purpose: stderr to the pipe, stdout dropped
stderr_of() { "$@" 2>&1 >/dev/null || true; }
said() { case "$1" in *"$2"*) echo True ;; *) echo False ;; esac; }
check "missing args name the usage line" True "$($K fs cat direct | jget '"usage: komando fs cat SERVER PATH" in d["error"]["message"]' || true)"
check "-o text applies to usage errors" True "$(said "$(stderr_of $K fs cat direct -o text)" '(code USAGE')"
set +e; $K host lst >/dev/null 2>&1; check "unknown subcommand fails" 2 $?; set -e
check "unknown subcommand suggests" True "$($K pkg instal direct x | jget '"did you mean install" in d["error"]["message"]' || true)"
check "dry-run shows a protected change" PROTECTED_TARGET "$($K host ssh exec target --dry-run -- touch /tmp/x | jget 'd["meta"]["would_be_blocked"]["code"]')"
check "dry-run banner in text" True "$(said "$(stderr_of $K host ssh exec target --dry-run -o text -- touch /tmp/x)" 'Dry run: nothing was changed')"
q $K host ssh add t-e2egen-alias agent@TARGET. --via bastion --credential agent-pass
check "same server under another spelling is protected" PROTECTED_TARGET "$($K host ssh exec t-e2egen-alias --dry-run -- touch /tmp/x | jget 'd["meta"]["would_be_blocked"]["code"]')"
q $K host ssh remove t-e2egen-alias --yes # an alias of a protected server is protected too
check "bad KOMANDO_OUTPUT names the variable" True "$(said "$(KOMANDO_OUTPUT=bogus $K list 2>&1 || true)" 'KOMANDO_OUTPUT=bogus')"
set +e; $K host ssh exec direct -P -1 -- true >/dev/null 2>&1; check "negative -P refused" 2 $?; set -e
check "many skipped targets: one line" 1 "$(stderr_of $K host ssh exec all --read-only -o text -- true | grep -c '^Skipped' || true)"

# test --wait: a server that is up passes at once; one that never comes up
# fails with its real reason when the time is up, not before
check "test --wait on a server that is up" True "$($K test direct --wait 30s | jget 'd["ok"] and d["data"]["waited_ms"] < 10000')"
q $K host ssh add t-never "agent@127.0.0.1:1" --credential agent-pass
check "test --wait gives up with the real reason" "CONNECTION_REFUSED True" \
  "$($K test t-never --wait 3s | jget 'd["data"]["results"][0]["error"]["code"] + " " + str(d["data"]["waited_ms"] >= 3000)' || true)"
q $K host ssh remove t-never
