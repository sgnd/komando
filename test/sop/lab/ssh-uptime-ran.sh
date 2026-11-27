# shellcheck shell=bash
# Task 01: add the server `direct` and run `uptime` on it. Sourced by
# test/sop/lab.sh in the e2e lab's `core` area (the `direct` container).
#
# The fixture: `uptime` on `direct` is a wrapper that notes each run in
# /tmp/sop-uptime-ran and then runs the real one. The check reads that file,
# so "uptime ran on the server" is the lab's own fact, not komando's account
# of it, and it holds on both trees whatever command the runner used.
# `direct`'s own details go to lab.txt in the run folder, as the task says.

MARK=/tmp/sop-uptime-ran

setup_task() {
  local port="${E2E_SSH_DIRECT:-2223}"
  # the real uptime moves aside once; the wrapper replaces it (not a PATH
  # entry: sshd's PATH is not ours to rely on)
  DC exec -T direct sh -c '
    set -e
    [ -e /usr/bin/uptime.real ] || mv /usr/bin/uptime /usr/bin/uptime.real
    printf "%s\n" "#!/bin/sh" "echo ran >> '"$MARK"'" "exec /usr/bin/uptime.real \"\$@\"" >/usr/bin/uptime
    chmod 755 /usr/bin/uptime
    rm -f '"$MARK"'
  '
  # the details the task text points to; the password is in its own file
  printf '%s\n' agentpass >"$RUN/direct.pw"
  chmod 600 "$RUN/direct.pw"
  cat >"$RUN/lab.txt" <<TXT
direct
  address: 127.0.0.1
  port: $port
  user: agent
  password file: direct.pw
TXT
}

check_task() {
  local n
  n="$(DC exec -T direct sh -c "wc -l < $MARK 2>/dev/null || echo 0" | tr -d '[:space:]')"
  if [ "${n:-0}" -ge 1 ]; then
    echo "--check-passed"
  fi
}
