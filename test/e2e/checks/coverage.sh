# shellcheck shell=bash
# Every command runs at least once in e2e. These are the ones no other check
# reaches: the plain, everyday path of each, against the lab (hosts direct,
# bastion, target (protected), swarm1; conns pg, maria, cache, bucket).
#
# Two commands are the exceptions, as they need the computer komando runs on,
# not the lab:
# - `secret keychain` moves the vault key into this computer's keychain: the
#   login keychain on a Mac (a person's own), the Secret Service on Linux
#   (which a CI runner does not have).
# - `config approval-code` is turned on by a person at a terminal, who types
#   the code from an authenticator app on their phone.
# Their unit tests cover them instead (internal/cli/secret_keychain_test.go,
# internal/cli/approval_code_cmd_test.go), without touching a real keychain.
ok() { jget 'd["ok"]'; }
has() { jget "'$1' in json.dumps(d)"; } # has TEXT: the JSON answer mentions TEXT
C="t-cov-$$"                            # unique per run, so a rerun never meets leftovers

# each part runs in the area that has its containers (run.sh)
if in_area data; then
# inventory and settings
check "version" True "$($K version | ok)"
# a go build is a source build, which update refuses; a release build checks GitHub
check "update (dry run)" True "$($K update --dry-run | jget 'd["ok"] or d["error"]["code"] in ("SOURCE_BUILD", "RELEASES_UNREACHABLE")')"
check "config show" True "$($K config show | ok)"
check "conn kinds" True "$($K conn kinds | has postgres)"
check "conn list" True "$($K conn list | has maria)"
check "conn show" True "$($K conn show pg | jget 'd["data"]["name"] == "pg"')"
check "secret list" True "$($K secret list | has agent-pass)"
check "secret check of the stored value" True "$(echo agentpass | $K secret check agent-pass | jget 'd["data"]["match"]')"
check "secret check says how a value differs, never the value" "SECRET_MISMATCH True False" "$(echo ' agentpass' | $K secret check agent-pass | jget 'd["error"]["code"] + " " + str("only in spaces" in d["data"]["difference"]) + " " + str("agentpass" in json.dumps(d))' || true)"
check "an agent cannot check a secret" NEEDS_PERSON "$(echo agentpass | A secret check agent-pass | jget 'd["error"]["code"]' || true)"
check "group list" True "$($K group list | has lab)"
q $K group add "$C-g" direct
check "group rm" True "$($K group rm "$C-g" direct | ok)"
check "host trust" True "$($K host trust direct | ok)"
check "export" True "$($K export kind:host | has direct)"
$K export kind:host >"$TMP/hosts.json"
check "import komando (dry run)" True "$($K import komando "$TMP/hosts.json" --dry-run | ok)"
check "export" True "$($K export --to "$TMP/$C-export.json" | ok)"
ssh-keygen -q -t ed25519 -N '' -C "$C" -f "$TMP/$C-key"
q $K key add "$C-key" "$TMP/$C-key"
check "key list" True "$($K key list | has "$C-key")"
check "key show" True "$($K key show "$C-key" | ok)"
check "key edit" True "$($K key edit "$C-key" --passphrase-ref '' | ok)"
q $K key rm "$C-key"
check "policy list" True "$($K policy list | has rm-root)"
check "policy check blocks rm -rf /" True "$($K policy check 'rm -rf /' | has rm-root || true)"
q $K policy deny "curl .*$C"
check "policy deny applies" True "$($K policy check "curl https://$C" | has custom || true)"
q $K policy rm "curl .*$C" --yes

# files and jobs
q $K fs mkdir direct "/tmp/$C/sub"
q $K fs write direct "/tmp/$C/a.txt" --content one
check "fs ls" True "$($K fs ls direct "/tmp/$C" | has a.txt)"
q $K fs chmod direct 640 "/tmp/$C/a.txt"
check "fs chmod" 640 "$($K exec direct --read-only -- stat -c %a "/tmp/$C/a.txt" | jget 'd["data"]["results"][0]["stdout"].strip()')"
q $K fs mv direct "/tmp/$C/a.txt" "/tmp/$C/sub/b.txt"
check "fs mv" True "$($K fs stat direct "/tmp/$C/sub/b.txt" | jget 'd["data"]["exists"]')"
JID=$($K job start direct -- 'sleep 30' | jget 'd["data"]["jobs"][0]["id"]')
check "job list" True "$($K job list | has "$JID")"
check "job status" True "$($K job status "$JID" | ok)"
q $K job kill "$JID"
q $K job rm "$JID"
q $K recipe add "$C-hello" 'echo hello {{who}}' --read-only
check "recipe run" "hello lab" "$($K recipe run "$C-hello" direct --var who=lab | jget 'd["data"]["results"][0]["stdout"].strip()')"
q $K recipe rm "$C-hello"
check "tunnel list" True "$($K tunnel list | ok)"

# data
check "db explain" True "$($K db explain pg 'select 1' | ok)"
q $K cache set cache "$C:k" v
check "cache keys" True "$($K cache keys cache "$C:*" | has "$C:k")"
q $K storage upload bucket "$TMP/hosts.json" "$C/hosts.json"
check "storage link" True "$($K storage link bucket "$C/hosts.json" | jget 'd["data"]["url"].startswith("http")')"
check "storage link --endpoint signs for that address" True "$($K storage link bucket "$C/hosts.json" --endpoint https://files.example.com | jget 'd["data"]["url"].startswith("https://files.example.com/") and "warning" not in d["data"]')"
U=$($K storage link bucket "$C/hosts.json" --endpoint http://s3:3900 | jget 'd["data"]["url"]')
check "a link signed for an address works there" True "$($K exec bastion --read-only -- "curl -sf '$U'" | has direct)"

# system modules (the lab containers run without systemd: svc must say so)
check "svc list fails clearly without systemd" False "$($K svc list direct | ok || true)"
check "svc status fails clearly without systemd" False "$($K svc status direct ssh | ok || true)"
check "svc logs fails clearly without systemd" NO_SYSTEMD "$($K svc logs direct ssh | jget 'd["data"]["results"][0]["error"]["code"]' || true)"
for a in start stop restart reload enable disable; do
  check "svc $a on a protected host previews" PROTECTED_HOST "$($K svc $a target nginx --dry-run | jget 'd["meta"]["would_be_blocked"]["code"]')"
done
check "pkg installed" True "$($K pkg installed direct curl | jget 'd["data"]["results"][0]["data"][0]["installed"]')"
check "pkg upgradable" True "$($K pkg upgradable direct | ok)"
check "pkg update (dry run)" True "$($K pkg update direct --dry-run | ok)"
check "pkg upgrade (dry run)" True "$($K pkg upgrade direct --dry-run | ok)"
q $K pkg install direct tree
check "pkg install" True "$($K pkg installed direct tree | jget 'd["data"]["results"][0]["data"][0]["installed"]')"
q $K pkg rm direct tree
check "pkg rm" False "$($K pkg installed direct tree | jget 'd["data"]["results"][0]["data"][0]["installed"]')"
q $K user add direct "$C-u"
check "user list" True "$($K user list direct | has "$C-u")"
q $K user lock direct "$C-u"
q $K user unlock direct "$C-u"
q $K user rm direct "$C-u" --remove-home --allow-dangerous
check "user rm" False "$($K user list direct | has "$C-u")"
q $K cron set direct "$C-c" true --schedule @daily
check "cron rm" 1 "$($K cron rm direct "$C-c" | jget 'd["data"]["results"][0]["data"]["removed"]')"
check "net dns" True "$($K net dns direct localhost | ok)"
check "net ports" True "$($K net ports direct | jget 'any(r["port"] == 22 for r in d["data"]["results"][0]["data"])')"

# VPNs
check "vpn list" True "$($K vpn list | has corp)"
check "vpn show" corp "$($K vpn show corp | jget 'd["data"]["vpn"]["name"]')"
check "vpn test of a VPN that is down" VPN_DOWN "$($K vpn test corp | jget 'd["data"]["results"][0]["error"]["code"]' || true)"
# renames: a conn reached through a SOCKS VPN keeps working when both get new names
TUN=$($K tunnel start bastion -D "127.0.0.1:$E2E_SOCKS" | jget 'd["data"]["id"]')
q $K vpn add "$C-vpn" socks --address "127.0.0.1:$E2E_SOCKS"
q $K conn add "$C-db" 'postgres://app@pg:5432/app?sslmode=disable' --via "$C-vpn" --password-ref secret:pg-pass
check "vpn mv takes the conn's --via along" "conn $C-db --via" "$($K vpn mv "$C-vpn" "$C-vpn2" | jget '" ".join(d["data"]["updated"])')"
check "conn mv" "renamed $C-db2" "$($K conn mv "$C-db" "$C-db2" | jget 'd["data"]["action"] + " " + d["data"]["to"]')"
check "the conn has both new names" "$C-db2 $C-vpn2" "$($K conn show "$C-db2" | jget 'd["data"]["name"] + " " + d["data"]["via"]')"
check "the old conn name is gone" CONN_NOT_FOUND "$($K conn show "$C-db" | jget 'd["error"]["code"]' || true)"
check "db query through the renamed conn and VPN" 1 "$($K db query "$C-db2" 'select 1' | jget 'd["data"]["results"][0]["rows"][0][0]')"
q $K conn rm "$C-db2"
q $K vpn rm "$C-vpn2"
q $K tunnel stop "$TUN"
fi

if in_area registry; then
check "net http" True "$($K net http bastion http://registry:5000/v2/ | jget 'd["data"]["results"][0]["data"]["code"] in (200, 401)')"
fi

if in_area swarm; then
# docker on swarm1
q $K docker raw swarm1 --allow-dangerous -- run -d --name "$C-c" busybox sleep 300
check "docker ps" True "$($K docker ps swarm1 | has "$C-c")"
check "docker images" True "$($K docker images swarm1 | has busybox)"
check "docker inspect" True "$($K docker inspect swarm1 "$C-c" | ok)"
check "docker exec" hi "$($K docker exec swarm1 "$C-c" -- echo hi | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "docker logs" True "$($K docker logs swarm1 "$C-c" | ok)"
check "docker stats" True "$($K docker stats swarm1 | ok)"
q $K docker restart swarm1 "$C-c"
q $K docker stop swarm1 "$C-c"
q $K docker start swarm1 "$C-c"
q $K docker stop swarm1 "$C-c"
check "docker pull (dry run)" True "$($K docker pull swarm1 busybox --dry-run | ok)"
check "docker compose (dry run)" True "$($K docker compose swarm1 --dry-run -- ps | ok)"
# prune only as a dry run: a real one would also remove other checks' stopped containers
PRUNE=$($K docker prune swarm1 --dry-run)
check "docker prune (dry run) lists the stopped container" True "$(echo "$PRUNE" | jget "'$C-c' in [c['name'] for c in d['data']['results'][0]['containers']]")"
check "docker prune (dry run) says the real run needs --allow-dangerous" POLICY_BLOCKED "$(echo "$PRUNE" | jget 'd["data"]["would_be_blocked"]["code"]')"
check "docker prune --older-than keeps what is new" False "$($K docker prune swarm1 --older-than 30d --dry-run | jget "'$C-c' in [c['name'] for c in d['data']['results'][0]['containers']]")"
q $K docker rm swarm1 "$C-c" --allow-dangerous
fi
