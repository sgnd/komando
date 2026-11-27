# shellcheck shell=bash
# Server operations: logs, pkg, docker, vpn. The lab's
# servers are containers without systemd. Self-cleaning: everything made
# here is named t-fixops*.
r0='d["data"]["results"][0]'

# logs on a server without systemd say so, with exit 3
set +e
$K logs direct --unit ssh >/dev/null; check "logs --unit without a journal exits 3" 3 $?
$K logs direct --file /t-fixops-nope >/dev/null; check "logs of a missing file exits 3" 3 $?
$K logs direct --file /etc/hostname --unit ssh >/dev/null; check "logs with two sources is a usage error" 2 $?
$K logs direct -p loud >/dev/null; check "logs with a bad priority is a usage error" 2 $?
$K logs direct --file /etc/hostname --since -1h >/dev/null; check "logs --file --since is a usage error" 2 $?
$K logs direct -n -1 >/dev/null; check "logs -n -1 is a usage error" 2 $?
$K logs direct --file /t-fixops-nope --follow --timeout 3s >/dev/null; check "logs -f of a missing file exits 3" 3 $?
set -e
check "logs --unit names NO_JOURNAL or NO_SYSTEMD" True "$($K logs direct --unit ssh | jget "${r0}[\"error\"][\"code\"] in ('NO_JOURNAL', 'NO_SYSTEMD')" || true)"
check "logs --file reads the file" direct "$($K logs direct --file /etc/hostname -n 1 | jget "${r0}[\"stdout\"].strip()")"

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
check "pkg upgrade --security --dry-run changes nothing" True "$($K pkg upgrade direct --security --dry-run | jget "d['meta'].get('dry_run') and not d['data']['applied']")"
check "pkg security on Alpine says apk has no security notices" "False True" "$($K pkg security swarm1 | jget "d['data']['results'][0]['security_notices'], 'unclassified_updates' in json.dumps(d['data']['results'][0]['warnings'])" | tr -d "(),")"
set +e
$K pkg upgrade direct --keep-going >/dev/null; check "pkg upgrade --keep-going needs --security" 2 $?
set -e
check "pkg output shows the short command" "pkg install tree" "$($K pkg install direct tree --dry-run | jget 'd["data"]["would_run"][0]["remote_command"]')"

# docker: a container name is never an option of docker
set +e
$K docker exec swarm1 -- --privileged -u root t-fixops id >/dev/null; check "docker exec refuses a container that is a docker option" 2 $?
set -e

# vpn: status sees a working SOCKS proxy, dry-run makes the real checks
set +e
$K vpn rm lab --dry-run >/dev/null; check "vpn rm --dry-run sees VPN_IN_USE" 8 $?
$K vpn add lab socks --proxy-address 127.0.0.1:1 --dry-run >/dev/null; check "vpn add --dry-run sees VPN_EXISTS" 8 $?
$K vpn add direct socks --proxy-address 127.0.0.1:1 --dry-run >/dev/null; check "vpn add --dry-run sees NAME_TAKEN" 8 $?
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

# a person at a terminal: deletes ask for the name of what goes, a wrong
# name changes nothing (komando's own questions, no flags)
tty() { ptyrun "$1" env NO_COLOR=1 TERM=dumb "$K" -o text "${@:2}" | tr -d '\r'; } # tty ANSWER ARGS...
set +e
O=$(tty 'wrong\n' docker prune swarm1); RC=$?
check "person: docker prune asks for the server's name" 1 "$(grep -c 'Type the name swarm1 to continue' <<<"$O")"
check "person: docker prune never asks a bare yes" 0 "$(grep -c 'Type yes' <<<"$O")"
check "person: a wrong name stops docker prune (6)" 6 "$RC"
O=$(tty 'wrong\n' pkg rm direct openssh-server); RC=$?
check "person: removing an essential package asks for its name" 1 "$(grep -c 'Type the name openssh-server to continue' <<<"$O")"
check "person: a wrong name keeps the package (6)" "6 True" "$RC $($K pkg installed direct openssh-server | jget "${r0}['data'][0]['installed']")"
# logs --follow ends with Ctrl-C: a clean stop, not an error
O=$(ptyrun $'\x03' env NO_COLOR=1 TERM=dumb "$K" -o text logs direct --file /etc/hostname --follow | tr -d '\r'); RC=$?
check "person: logs --follow shows the lines before Ctrl-C" 1 "$(grep -c '^direct' <<<"$O")"
check "person: Ctrl-C ends logs --follow cleanly (0)" "0 0" "$RC $(grep -ci 'error' <<<"$O")"
set -e

# a group: one result per server, each with its own error
check "pkg installed @lab: each server answers" "True True" "$($K pkg installed @lab bash | jget "' '.join(str(r['ok']) for r in d['data']['results'])")"
