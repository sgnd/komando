# shellcheck shell=bash
# Server operations: svc, logs, pkg, net, user, cron, vpn. The lab's
# servers are containers without systemd. Self-cleaning: everything made
# here is named t-fixops*.
r0='d["data"]["results"][0]'

# svc / logs on a server without systemd say so, with exit 3
set +e
$K svc status direct ssh >/dev/null; check "svc status without systemd exits 3" 3 $?
$K logs direct --unit ssh >/dev/null; check "logs --unit without a journal exits 3" 3 $?
$K logs direct --file /t-fixops-nope >/dev/null; check "logs of a missing file exits 3" 3 $?
$K logs direct --file /etc/hostname --unit ssh >/dev/null; check "logs with two sources is a usage error" 2 $?
$K logs direct -p loud >/dev/null; check "logs with a bad priority is a usage error" 2 $?
$K logs direct --file /etc/hostname --since -1h >/dev/null; check "logs --file --since is a usage error" 2 $?
$K logs direct -n -1 >/dev/null; check "logs -n -1 is a usage error" 2 $?
$K logs direct --file /t-fixops-nope --follow --timeout 3s >/dev/null; check "logs -f of a missing file exits 3" 3 $?
set -e
check "svc status names NO_SYSTEMD" NO_SYSTEMD "$($K svc status direct ssh | jget "${r0}[\"error\"][\"code\"]" || true)"
check "svc restart names NO_SYSTEMD" NO_SYSTEMD "$($K svc restart direct ssh --wait 3 | jget "${r0}[\"error\"][\"code\"]" || true)"
check "logs --unit names NO_JOURNAL or NO_SYSTEMD" True "$($K logs direct --unit ssh | jget "${r0}[\"error\"][\"code\"] in ('NO_JOURNAL', 'NO_SYSTEMD')" || true)"
check "logs --file reads the file" direct "$($K logs direct --file /etc/hostname -n 1 | jget "${r0}[\"stdout\"].strip()")"
check "svc dry-run shows the short command" "svc enable --now t-fixops" "$($K svc enable direct t-fixops --now --dry-run | jget 'd["data"]["would_run"][0]["remote_command"]')"

# cron: IDs, one line, schedule, % escaping, list rows, rm
set +e
$K cron set direct 't-fixops.x' true --schedule @daily >/dev/null; check "cron ID with a dot is refused" 2 $?
$K cron set direct t-fixops-c "$(printf 'a\nb')" --schedule @daily >/dev/null; check "cron COMMAND with a newline is refused" 2 $?
$K cron set direct t-fixops-c true --schedule '61 * * * *' >/dev/null; check "cron schedule is checked" 2 $?
$K cron list direct --user t-fixops-nouser >/dev/null; check "cron list of an unknown user fails" True "$([ $? -ne 0 ] && echo True || echo False)"
set -e
q $K cron set direct t-fixops-c 'date +%F >/dev/null' --schedule '*/5 * * * *'
check "cron % is escaped" True "$($K cron list direct | jget "any(r.get('id') == 't-fixops-c' and r['command'] == 'date +\\\\%F >/dev/null' and r['schedule'] == '*/5 * * * *' for r in ${r0}['data'])")"
check "cron rm says how many" 1 "$($K cron rm direct t-fixops-c | jget "${r0}[\"data\"][\"removed\"]")"
check "cron rm of an unknown ID removes 0" 0 "$($K cron rm direct t-fixops-c | jget "${r0}[\"data\"][\"removed\"]")"

# user: list on Debian and Alpine, lock state, unknown user
check "user list on Debian" True "$($K user list direct | jget "${r0}['ok'] and any(u['name'] == 'agent' for u in ${r0}['data'])")"
check "user list on Alpine" True "$($K user list swarm1 | jget "${r0}['ok'] and any(u['name'] == 'agent' for u in ${r0}['data'])")"
check "user list has admin_group" True "$($K user list direct | jget "all('admin_group' in u for u in ${r0}['data'])")"
q $K user add direct t-fixopsu --shell /bin/sh
q $K user lock direct t-fixopsu
check "user list shows a locked account" True "$($K user list direct | jget "[u.get('locked') for u in ${r0}['data'] if u['name'] == 't-fixopsu'][0]")"
q $K user unlock direct t-fixopsu
check "user list shows an unlocked account" False "$($K user list direct | jget "[u.get('locked') for u in ${r0}['data'] if u['name'] == 't-fixopsu'][0]")"
$K user rm direct t-fixopsu --remove-home --allow-dangerous >/dev/null 2>&1 || true
# a login user without sudo rights: the error names the cause and the next command
q $K key gen t-fixops-k
q $K user add direct t-fixopsns --key t-fixops-k --shell /bin/sh
q $K host add t-fixops-ns "t-fixopsns@127.0.0.1:$E2E_SSH_DIRECT" --key t-fixops-k
q $K host trust t-fixops-ns
check "svc restart without sudo rights names PERMISSION_DENIED" PERMISSION_DENIED "$($K svc restart t-fixops-ns ssh | jget "${r0}['error']['code']" || true)"
check "pkg install without sudo rights names the next command" True "$($K pkg install t-fixops-ns tree | jget "'--sudo-ref secret:t-fixops-ns-sudo' in ${r0}['error']['hint'] or '--user OTHER' in ${r0}['error']['hint']" || true)"
check "user add without sudo rights names PERMISSION_DENIED" PERMISSION_DENIED "$($K user add t-fixops-ns t-fixopsx | jget "${r0}['error']['code']" || true)"
q $K host rm t-fixops-ns
$K user rm direct t-fixopsns --remove-home --allow-dangerous >/dev/null 2>&1 || true
q $K key rm t-fixops-k
set +e
$K user lock direct t-fixops-nouser >/dev/null; check "user lock of an unknown user exits 3" 3 $?
$K user add direct t-fixopsk --pubkey 'not a key' >/dev/null; check "user add checks --pubkey" 2 $?
$K user add swarm1 t-fixopsu >/dev/null 2>&1; check "user add without useradd exits 3" 3 $?
$K user rm swarm1 t-fixopsu --allow-dangerous >/dev/null 2>&1; check "user rm without userdel exits 3" 3 $?
set -e
check "user add on Alpine without shadow names TOOL_MISSING" TOOL_MISSING "$($K user add swarm1 t-fixopsu 2>/dev/null | jget "${r0}['error']['code']" || true)"
check "user rm on Alpine without shadow names TOOL_MISSING" TOOL_MISSING "$($K user rm swarm1 t-fixopsu --allow-dangerous 2>/dev/null | jget "${r0}['error']['code']" || true)"

# pkg: option injection, essential packages, installed rows, changed, unknown
set +e
$K pkg install direct -- --allow-unauthenticated >/dev/null; check "pkg refuses an option as a package" 2 $?
$K pkg install direct 'tr*' >/dev/null; check "pkg refuses a pattern" 2 $?
$K pkg rm direct openssh-server >/dev/null; check "removing an essential package is blocked" 6 $?
$K pkg install direct t-fixops-nopkg >/dev/null; check "pkg install of an unknown package exits 3" 3 $?
set -e
check "pkg installed rows" True "$($K pkg installed direct bash t-fixops-nopkg | jget "[r['installed'] for r in ${r0}['data']] == [True, False]")"
check "pkg install reports a change" True "$($K pkg install direct tree | jget "${r0}['data']['changed']")"
check "pkg install again changes nothing" False "$($K pkg install direct tree | jget "${r0}['data']['changed']")"
check "pkg rm reports a change" removed "$($K pkg rm direct tree | jget "${r0}['data']['packages'][0]['state']")"
check "pkg install on Alpine" installed "$($K pkg install swarm1 tree | jget "${r0}['data']['packages'][0]['state']")"
q $K pkg rm swarm1 tree
check "pkg upgradable lists rows" True "$($K pkg upgradable direct | jget "isinstance(${r0}['data']['packages'], list)")"
check "pkg upgrade --dry-run lists what would change" True "$($K pkg upgrade direct --dry-run | jget "d['meta'].get('dry_run') and isinstance(${r0}['data']['would_upgrade'], list)")"
check "pkg security lists rows and the state" True "$($K pkg security direct | jget "isinstance(d['data']['results'][0]['security_updates'], list) and 'pending_updates' in d['data']['results'][0]['state']")"
check "pkg security --apply --dry-run changes nothing" True "$($K pkg security direct --apply --dry-run | jget "d['meta'].get('dry_run') and not d['data']['applied']")"
set +e
$K pkg security swarm1 >/dev/null; check "pkg security on Alpine is unsupported" 3 $?
$K pkg security direct --keep-going >/dev/null; check "pkg security --keep-going needs --apply" 2 $?
set -e
check "pkg output shows the short command" "pkg install tree" "$($K pkg install direct tree --dry-run | jget 'd["data"]["would_run"][0]["remote_command"]')"

# net: dns, check, http, ports
set +e
$K net dns direct t-fixops.invalid >/dev/null; check "net dns NXDOMAIN exits 3" 3 $?
$K net check direct 127.0.0.1:1 >/dev/null; check "net check of a closed port fails" 5 $?
$K net check direct 127.0.0.1:99999 >/dev/null; check "net check checks the port" 2 $?
$K net http direct http://127.0.0.1:1/ >/dev/null; check "net http without an answer exits 4" 4 $?
$K net dns direct localhost --type BOGUS >/dev/null; check "net dns checks --type" 2 $?
$K net dns direct --type MX -- -f/etc/passwd >/dev/null; check "net dns refuses a name that is a dig option" 2 $?
$K docker exec swarm1 -- --privileged -u root t-fixops id >/dev/null; check "docker exec refuses a container that is a docker option" 2 $?
set -e
check "net check says why" refused "$($K net check direct 127.0.0.1:1 | jget "${r0}['data'][0]['reason']" || true)"
check "net dns --type A" True "$($K net dns direct localhost --type A | jget "'127.0.0.1' in ${r0}['data']['records']")"
check "net ports has pid with sudo" True "$($K net ports direct --sudo | jget "any(r.get('process') == 'sshd' and r.get('pid', 0) > 0 for r in ${r0}['data'])")"
check "net ports on busybox (netstat)" True "$($K net ports swarm1 | jget "any(r['port'] == 22 for r in ${r0}['data'])")"

# vpn: status sees a working SOCKS proxy, dry-run makes the real checks
set +e
$K vpn rm lab --dry-run >/dev/null; check "vpn rm --dry-run sees VPN_IN_USE" 8 $?
$K vpn add lab socks --address 127.0.0.1:1 --dry-run >/dev/null; check "vpn add --dry-run sees VPN_EXISTS" 8 $?
$K vpn add direct socks --address 127.0.0.1:1 --dry-run >/dev/null; check "vpn add --dry-run sees NAME_TAKEN" 8 $?
set -e
check "vpn status: stopped SOCKS proxy is down" False "$($K vpn status | jget '[v["up"] for v in d["data"]["vpns"] if v["name"] == "lab"][0]')"
q $K tunnel start bastion -D "127.0.0.1:$E2E_SOCKS"
check "vpn status: running SOCKS proxy is up" True "$($K vpn status | jget '[v["up"] for v in d["data"]["vpns"] if v["name"] == "lab"][0]')"
check "vpn down of a SOCKS VPN names the tunnel" True "$($K vpn down lab | jget '"tunnel stop" in d["data"]["notes"][0]')"
q $K tunnel stop --all
check "vpn down --all with nothing up" True "$($K vpn down --all | jget 'd["ok"] and d["data"]["disconnected"] == []')"
check "vpn test hint is not itself" True "$($K vpn test lab | jget '"tunnel start" in d["data"]["results"][0]["error"]["hint"]' || true)"
check "vpn edit changes notes" t-fixops "$($K vpn edit corp --notes t-fixops | jget 'd["data"]["vpn"]["notes"]')"
q $K vpn edit corp --notes ''

# a person at a terminal: deletes ask for the server's name, a protected
# server asks [y/N], "no" changes nothing (komando's own questions, no flags)
tty() { ptyrun "$1" env NO_COLOR=1 TERM=dumb "$K" -o text "${@:2}" | tr -d '\r'; } # tty ANSWER ARGS...
set +e
O=$(tty 'wrong\n' docker prune swarm1); RC=$?
check "person: docker prune asks for the server's name" 1 "$(grep -c 'Type the name swarm1 to continue' <<<"$O")"
check "person: docker prune never asks a bare yes" 0 "$(grep -c 'Type yes' <<<"$O")"
check "person: a wrong name stops docker prune (6)" 6 "$RC"
O=$(tty 'wrong\n' pkg rm direct openssh-server); RC=$?
check "person: removing an essential package asks for the name" 1 "$(grep -c 'Type the name direct to continue' <<<"$O")"
check "person: a wrong name keeps the package (6)" "6 True" "$RC $($K pkg installed direct openssh-server | jget "${r0}['data'][0]['installed']")"
q $K host add t-fixops-p "agent@127.0.0.1:$E2E_SSH_DIRECT" --password-ref secret:agent-pass --protected
q $K host trust t-fixops-p
O=$(tty 'n\n' svc restart t-fixops-p ssh); RC=$?
check "person: svc restart on a protected server asks [y/N]" 1 "$(grep -c 't-fixops-p (protected): this command changes it. Continue? \[y/N\]' <<<"$O")"
check "person: no to svc restart stops (6)" 6 "$RC"
O=$(tty 'wrong\n' reboot t-fixops-p); RC=$?
check "person: reboot asks for the server's name" 1 "$(grep -c 'Type the name t-fixops-p to continue' <<<"$O")"
check "person: a wrong name stops the reboot (6)" 6 "$RC"
q $K host rm t-fixops-p --yes # a protected server: a script removes it with --yes (no agent here)
# logs --follow ends with Ctrl-C: a clean stop, not an error
O=$(ptyrun $'\x03' env NO_COLOR=1 TERM=dumb "$K" -o text logs direct --file /etc/hostname --follow | tr -d '\r'); RC=$?
check "person: logs --follow shows the lines before Ctrl-C" 1 "$(grep -c '^direct' <<<"$O")"
check "person: Ctrl-C ends logs --follow cleanly (0)" "0 0" "$RC $(grep -ci 'error' <<<"$O")"
set -e

# a group: one result per server, each with its own error
check "svc status @lab gives one result per server" "bastion direct" "$($K svc status @lab ssh | jget "' '.join(sorted(r['host'] for r in d['data']['results']))" || true)"
check "pkg installed @lab: each server answers" "True True" "$($K pkg installed @lab bash | jget "' '.join(str(r['ok']) for r in d['data']['results'])")"
