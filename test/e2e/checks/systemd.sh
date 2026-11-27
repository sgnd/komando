# shellcheck shell=bash
# logs against the real journalctl, on a server with
# systemd as PID 1 (test/e2e/systemd). The checks start that container
# themselves; where a machine cannot run it they say so and are skipped.
SYSD_PORT=${E2E_SSH_SYSTEMD:-2225}
SYSD="komando-e2e-systemd-$$"
R="${ROOT:-$(pwd)}"
sys() { docker exec "$SYSD" "$@"; } # sys CMD...: the native command on that server
docker build -q -t komando-e2e-systemd "$R/test/e2e/systemd" >/dev/null
docker run -d --name "$SYSD" --restart unless-stopped --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -p "127.0.0.1:$SYSD_PORT:22" komando-e2e-systemd >/dev/null
up=no
for _ in $(seq 1 30); do
  sys systemctl is-active ssh >/dev/null 2>&1 && up=yes && break
  sleep 1
done
if [ "$up" != yes ]; then
  echo "  skipped: systemd cannot run as PID 1 in a container on this machine"
else
  q $K host ssh add t-sysd "agent@127.0.0.1:$SYSD_PORT" --credential agent-pass
  q $K host ssh trust t-sysd

  # like journalctl: a plain user may not read the system journal; komando says so
  # (journald answers "No entries" or "insufficient permissions"; either way komando names --sudo)
  check "logs --unit as a plain user = journalctl's refusal, said clearly" "No entries True" \
    "$(sys su agent -s /bin/sh -c 'journalctl -u t-svc --no-pager' 2>/dev/null | grep -o 'No entries') $($K logs t-sysd --unit t-svc | jget '"--sudo" in json.dumps(d) and "hello from t-svc" not in json.dumps(d)' || true)"
  check "logs --unit = journalctl -u" True "$(sys journalctl -u t-svc --no-pager | grep -q 'hello from t-svc' && $K logs t-sysd --unit t-svc --sudo | jget '"hello from t-svc" in json.dumps(d)')"
  q $K host ssh remove t-sysd
fi
docker rm -f "$SYSD" >/dev/null 2>&1 || true
