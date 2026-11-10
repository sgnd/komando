# shellcheck shell=bash
# svc and logs against the real systemctl and journalctl, on a server with
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
  q $K host add t-sysd "agent@127.0.0.1:$SYSD_PORT" --password-ref secret:agent-pass
  q $K host trust t-sysd
  state() { $K svc status t-sysd t-svc | jget 'd["data"]["results"][0]["data"][0]["active_state"]'; }
  pid() { sys systemctl show -p MainPID --value t-svc; }

  check "svc status = systemctl show" "$(sys systemctl show -p ActiveState --value t-svc)" "$(state)"
  check "svc status MainPID = systemctl" "$(pid)" "$($K svc status t-sysd t-svc | jget 'str(d["data"]["results"][0]["data"][0].get("main_pid") or d["data"]["results"][0]["data"][0].get("pid"))')"
  q $K svc stop t-sysd t-svc
  check "svc stop = systemctl is-active" "inactive inactive" "$(sys systemctl is-active t-svc || true) $(state)"
  q $K svc start t-sysd t-svc --wait 10
  check "svc start --wait = systemctl is-active" "active active" "$(sys systemctl is-active t-svc) $(state)"
  before=$(pid)
  q $K svc restart t-sysd t-svc --wait 10
  check "svc restart gives a new process (systemctl MainPID)" True "$([ "$(pid)" != "$before" ] && [ "$(pid)" != 0 ] && echo True || echo False)"
  before=$(pid)
  q $K svc reload t-sysd t-svc
  check "svc reload keeps the process (systemctl MainPID)" "$before active" "$(pid) $(state)"
  q $K svc disable t-sysd t-svc
  check "svc disable = systemctl is-enabled" disabled "$(sys systemctl is-enabled t-svc || true)"
  q $K svc enable t-sysd t-svc
  check "svc enable = systemctl is-enabled" enabled "$(sys systemctl is-enabled t-svc)"
  check "svc list has what systemctl lists" True "$($K svc list t-sysd | jget '"t-svc.service" in json.dumps(d["data"])')"
  # like journalctl: a plain user may not read the system journal; komando says so
  # (journald answers "No entries" or "insufficient permissions"; either way komando names --sudo)
  check "svc logs as a plain user = journalctl's refusal, said clearly" "No entries True" \
    "$(sys su agent -s /bin/sh -c 'journalctl -u t-svc --no-pager' 2>/dev/null | grep -o 'No entries') $($K svc logs t-sysd t-svc | jget '"--sudo" in json.dumps(d) and "hello from t-svc" not in json.dumps(d)' || true)"
  check "svc logs --sudo = journalctl -u" True "$(sys journalctl -u t-svc --no-pager | grep -q 'hello from t-svc' && $K svc logs t-sysd t-svc --sudo | jget '"hello from t-svc" in json.dumps(d)')"
  check "logs --unit = journalctl -u" True "$($K logs t-sysd --unit t-svc --sudo | jget '"hello from t-svc" in json.dumps(d)')"
  check "an unknown unit is not found (systemctl: no such unit)" "4 3" \
    "$(sys systemctl status t-nosuch >/dev/null 2>&1; echo $?) $($K svc status t-sysd t-nosuch >/dev/null 2>&1; echo $?)"
  # daemon-reload: a changed unit file is read again
  sys sed -i 's/^Description=.*/Description=komando test service v2/' /etc/systemd/system/t-svc.service
  check "svc daemon-reload = systemctl daemon-reload" "komando test service v2 komando test service v2" \
    "$($K svc daemon-reload t-sysd >/dev/null; sys systemctl show -p Description --value t-svc) $($K svc status t-sysd t-svc | jget 'd["data"]["results"][0]["data"][0]["description"]')"
  # reboot: destructive, so blocked without --allow-dangerous; then it waits for the server
  check "reboot needs --allow-dangerous" 6 "$($K reboot t-sysd >/dev/null 2>&1; echo $?)"
  pid1=$(sys cut -d' ' -f22 /proc/1/stat)
  check "reboot waits for the server and checks it restarted" "True True" \
    "$($K reboot t-sysd --allow-dangerous --wait 120s | jget 'str(d["data"]["results"][0]["rebooted"]) + " " + str(d["data"]["results"][0]["back_after_s"] > 0)' || true)"
  check "after reboot: a new PID 1 and the service is back" "True active" \
    "$([ "$(sys cut -d' ' -f22 /proc/1/stat)" != "$pid1" ] && echo True || echo False) $(sys systemctl is-active t-svc || true)"
  q $K host rm t-sysd
fi
docker rm -f "$SYSD" >/dev/null 2>&1 || true
