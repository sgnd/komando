# shellcheck shell=bash
# logs --follow, and no way around protection.
# logs --follow streams until stopped (here by --timeout)
check "logs --follow streams" True "$($K logs direct --file /etc/hostname --follow --timeout 3s | head -1 | jget '"direct" in d["data"]')"
check "logs --follow: no status line for scripts" 0 "$($K logs direct --file /etc/hostname --follow --timeout 3s 2>&1 >/dev/null | grep -c '^komando:' || true)"
check "logs --follow says where for a person" 1 "$(ptyrun '' "$K" logs direct --file /etc/hostname --follow --timeout 3s | tr -d '\r' | grep -c '^komando: following logs on direct (Ctrl-C stops)$' || true)"
set +e; $K fs rm direct /tmp/somedir --recursive >/dev/null; check "fs rm -r needs --allow-dangerous" 6 $?; set -e

# no way around protection
q $K recipe add touch-it 'touch /tmp/komando-e2e'
check "recipe list has built-ins and saved" True "$($K recipe list | jget 'any(r["builtin"] for r in d["data"]["recipes"]) and any(not r["builtin"] for r in d["data"]["recipes"])')"
set +e; $K recipe run touch-it target >/dev/null; check "recipe on protected host needs --yes" 6 $?; set -e
set +e; $K host rm target >/dev/null; check "removing a protected host needs --yes" 6 $?; set -e
set +e; $K config set audit off >/dev/null; check "turning off audit needs --yes" 6 $?; set -e
set +e; $K secret set leaked hunter2 >/dev/null; check "secret value as argument refused" 2 $?; set -e
