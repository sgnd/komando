# shellcheck shell=bash
# Inventory, keys, secrets, settings, policy and selectors.
# Uses the lab inventory: direct, bastion, target (protected, via bastion),
# maria (protected conn), VPN lab (socks). Everything made here is t-e2einv*.

code() { jget 'd["error"]["code"] if d.get("error") else "ok"' || true; }

# audit -n
set +e; $K audit -n -1 >/dev/null; check "audit -n -1 is a usage error" 2 $?; set -e
check "audit text is one line per entry" True "$($K audit -n 3 -o text | head -1 | grep -q '^TIME *ACTOR *COMMAND *TARGETS *OK' && echo True || echo False)"

# host add/edit validation
check "port out of range" USAGE "$($K host add t-e2einv1 'agent@127.0.0.1:99999' | code)"
check "empty user" USAGE "$($K host add t-e2einv1 '@127.0.0.1' | code)"
check "unknown --via" VIA_NOT_FOUND "$($K host add t-e2einv1 agent@10.9.9.9 --via nosuch | code)"
check "--via itself" VIA_CYCLE "$($K host add t-e2einv1 agent@10.9.9.9 --via t-e2einv1 | code)"
check "missing identity file" FILE_NOT_FOUND "$($K host add t-e2einv1 agent@10.9.9.9 --identity "$TMP/no-such-key" | code)"
check "bad group name" USAGE "$($K host add t-e2einv1 agent@10.9.9.9 -g 'a b' | code)"
check "dry-run says would_add" would_add "$($K host add t-e2einv1 agent@10.9.9.9 --dry-run | jget 'd["data"]["action"]')"

# the same server under another spelling is protected too
check "trailing dot alias is protected" True "$($K host add t-e2einv1 agent@TARGET. --via bastion | jget 'd["data"]["protected"]')"
q $K host rm t-e2einv1 --yes
check "conn alias is protected" True "$($K conn add t-e2einv2 'mysql://shop@maria.:3306/shop' --via bastion | jget 'd["data"]["protected"]')"
q $K conn rm t-e2einv2 --yes

# protected entries cannot be re-pointed without --yes
check "re-point protected host" PROTECTED_HOST "$($K host edit target --via direct | code)"
check "re-point protected conn" PROTECTED_TARGET "$($K conn edit maria --via direct | code)"
check "dry-run shows that stop" PROTECTED_HOST "$($K host edit target --via direct --dry-run | jget 'd["meta"]["would_be_blocked"]["code"]')"
check "edit without changes" USAGE "$($K host edit direct | code)"
check "conflicting edit" USAGE "$($K host edit direct --add-tag x --rm-tag x | code)"

# rm of a host and the host behind it, together
q $K host add t-e2einv3 agent@10.9.9.1
q $K host add t-e2einv4 agent@10.9.9.2 --via t-e2einv3
check "rm a via host alone" HOST_IN_USE "$($K host rm t-e2einv3 | code)"
check "rm both together" ok "$($K host rm t-e2einv3 t-e2einv4 | code)"
q $K host add t-e2einv6 agent@10.9.9.6
q $K host add t-e2einv7 agent@10.9.9.7
check "rm a selector --dry-run lists it" 2 "$($K host rm 't-e2einv*' --dry-run | jget 'len(d["data"]["removed"])')"
check "rm a selector" ok "$($K host rm 't-e2einv*' | code)"
# @lab holds bastion (the --via host of the conns) and target (protected)
check "rm @group still in use removes nothing" HOST_IN_USE "$($K host rm @lab | code)"
check "rm @group protected stop in dry-run" PROTECTED_HOST "$($K host rm target --dry-run | jget 'd["meta"]["would_be_blocked"]["code"]')"

# host trust --reset --dry-run changes nothing
N1=$($K host trust direct --reset --dry-run | jget 'd["data"]["would_remove_entries"]')
N2=$($K host trust direct --reset --dry-run | jget 'd["data"]["would_remove_entries"]')
check "trust --reset --dry-run removes nothing" "$N1" "$N2"
check "trust --reset --dry-run counts the pinned key" True "$([ "$N1" -ge 1 ] && echo True || echo False)"

# ssh-command: a hop per ProxyCommand, VPN as nc -X 5
# bastion logs in with a key komando made, sealed in the store: OpenSSH
# gets it from a running ssh-agent only
check "ssh-command without an ssh-agent" SSH_AGENT_NEEDED "$(env -u SSH_AUTH_SOCK $K host ssh-command target | jget 'd["error"]["code"]' || true)"

# import: a proxy command never comes from a file; protected names
printf '%s\n' '{"hosts":[{"name":"t-e2einv5","address":"10.9.9.5","proxy_command":"nc %h %p"}]}' >"$TMP/inv-hosts.json"
check "import komando drops a proxy command" True "$(A import komando "$TMP/inv-hosts.json" --dry-run | jget '"proxy_command" in str(d["data"]["not_imported"])')"
$K export target >"$TMP/inv-target.json"
check "overwrite of a protected host is skipped" target "$($K import komando "$TMP/inv-target.json" --overwrite | jget 'd["data"]["skipped"][0]["name"]')"
check "old name host import still works" target "$($K host import --json "$TMP/inv-target.json" --dry-run 2>/dev/null | jget 'd["data"]["skipped"][0]["name"]')"

# groups
q $K group add t-e2einvg direct
check "group rm of a non-member" '[]' "$($K group rm t-e2einvg bastion | jget 'json.dumps(d["data"]["removed"])')"
check "unknown group" GROUP_NOT_FOUND "$($K group rm t-e2einvnone direct | code)"
check "group list GROUP" '["direct"]' "$($K group list t-e2einvg | jget 'json.dumps(d["data"]["members"])')"
q $K group rm t-e2einvg

# keys
check "weak RSA refused" USAGE "$($K key gen t-e2einvk --type rsa --bits 1024 | code)"
check "comment with a newline refused" USAGE "$($K key gen t-e2einvk -C "$(printf 'a\nb')" | code)"
check "key gen --dry-run has no fingerprint" None "$($K key gen t-e2einvk --dry-run | jget 'd["data"].get("fingerprint")')"
q $K key gen t-e2einvk
PUB="$TMP/t-e2einvk.pub"
$K key show t-e2einvk | jget 'd["data"]["public_key"]' >"$PUB"
check "public key given to key add" KEY_INVALID "$($K key add t-e2einvk2 "$PUB" | code)"
check "plain passphrase in key edit" USAGE "$($K key edit t-e2einvk --passphrase-ref pw123 | code)"
check "key list text is a table" True "$($K key list -o text | head -1 | grep -q '^NAME *TYPE *FINGERPRINT *USED BY' && echo True || echo False)"
q $K key rm t-e2einvk --delete-file --allow-dangerous

# secrets
check "secret get shows no length" False "$($K secret get agent-pass | jget '"length" in d["data"]')"
check "replacing a protected host's secret" PROTECTED_TARGET "$(echo -n x | $K secret set agent-pass | code)"
printf 'a' | $K secret set t-e2einvs1 >/dev/null
printf 'b' | $K secret set t-e2einvs2 >/dev/null
check "secret set says replaced" True "$(printf 'c' | $K secret set t-e2einvs2 | jget 'd["data"]["replaced"]')"
check "secret rm takes many" ok "$($K secret rm t-e2einvs1 t-e2einvs2 --allow-dangerous | code)"

# settings
check "config get" 10 "$($K config get parallel | jget 'd["data"]["default"]')"
check "tiny max_output_bytes" USAGE "$($K config set max_output_bytes 1 | code)"
check "negative value names the fix" True "$($K config set parallel -3 | jget '"--" in d["error"]["hint"]')"
check "config set is audited" True "$($K config set connect_timeout 15s >/dev/null; $K audit -n 1 --command config.set | jget 'd["data"]["entries"][0]["new"] == "15s"')"

# policy
check "built-in rule cannot be removed" BUILTIN_RULE "$($K policy rm rm-root | code)"
check "empty deny pattern" USAGE "$($K policy deny '' | code)"
set +e; $K policy check 'rm -rf //' >/dev/null; check "policy check exits 6 when blocked" 6 $?; set -e
check "grep mkfs is allowed" False "$($K policy check 'grep mkfs notes.txt' | jget 'd["data"]["blocked"]')"

# selectors and lookups
check "selector starting with !" False "$($K list '!direct' | jget 'any(t["name"] == "direct" for t in d["data"]["targets"])')"
check "names in any case" direct "$($K host show DIRECT | jget 'd["data"]["name"]')"
check "did you mean on host show" True "$($K host show dirct | jget '"direct" in d["error"]["hint"]')"
check "schema host.add" "komando host add" "$($K schema host.add | jget 'd["data"]["commands"][0]["path"]')"
check "test text has USER and SUDO" True "$($K test direct -o text | head -1 | grep -q 'USER *SUDO' && echo True || echo False)"
$K doctor -o text 2>&1 | grep -E '^✗' | sed 's/^/    doctor says: /' || true
check "doctor text is a checklist" True "$($K doctor -o text 2>/dev/null | grep -q '^✓ komando folder' && echo True || echo False)"

# a rebuilt server (new host keys, same address) inside a group: host trust
# @lab refuses only that one; a script's --reset gets NEEDS_PERSON; a person
# at a terminal answers y and it is re-pinned, the others stay
DC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }
oldfp=$($K host trust direct | jget 'd["data"]["fingerprint"]')
DC exec -T direct sh -c 'rm -f /etc/ssh/ssh_host_*; ssh-keygen -q -A; kill -HUP 1' >/dev/null
sleep 1
check "host trust @lab refuses only the rebuilt server" "PARTIAL_FAILURE HOSTKEY_MISMATCH True" \
  "$($K host trust @lab | jget 'd["error"]["code"] + " " + [r for r in d["data"]["results"] if r["host"] == "direct"][0]["error"]["code"] + " " + str(all(r["ok"] for r in d["data"]["results"] if r["host"] != "direct"))' || true)"
check "a script cannot replace a pinned key" NEEDS_PERSON "$($K host trust @lab --reset | jget 'd["error"]["code"]' || true)"
o=$(ptyrun 'y\n' env NO_COLOR=1 TERM=dumb "$K" -o json host trust @lab --reset 2>/dev/null | tr -d '\r' | grep '^{')
check "host trust @lab --reset by a person re-pins it, with the old key named" "True True" \
  "$(jget '[str(r["fingerprint"] != r["old_fingerprints"][0]) + " " + str(r["old_fingerprints"][0] == "'"$oldfp"'") for r in d["data"]["results"] if r["host"] == "direct"][0]' <<<"$o")"
check "the rebuilt server works again" direct "$($K exec direct --read-only -- hostname | jget 'd["data"]["results"][0]["stdout"].strip()')"

# command journeys (audit-core 2026-11-12)
# host rm names every user of a --via server at once
q $K host add t-e2einv8 agent@10.9.9.8
q $K host add t-e2einv9 agent@10.9.9.9 --via t-e2einv8
q $K conn add t-e2einva redis://10.9.9.10:6379/0 --via t-e2einv8
check "rm a via host names every user" "True True" \
  "$($K host rm t-e2einv8 | jget 'str("t-e2einv9" in d["error"]["message"]) + " " + str("conn edit t-e2einva --unset via" in d["error"]["hint"])' || true)"
# group add/rm take several names
check "group add takes several names" ok "$($K group add t-e2einvg t-e2einv8 t-e2einv9 | code)"
check "group rm takes several names" ok "$($K group rm t-e2einvg t-e2einv8 t-e2einv9 | code)"
q $K conn rm t-e2einva
q $K host rm t-e2einv8 t-e2einv9
# import: the TLS default of conn add, a next step, a protected conn skipped in the dry run too
printf 'REDIS_URL=redis://:pw@t-e2einv.example:6379/0\nDATABASE_URL=postgres://app:pw@t-e2einv.example:5432/shop\n' >"$TMP/inv.env"
o=$($K import env "$TMP/inv.env" --group t-e2einvi)
check "import skips a clear-text login over the network" True "$(jget 'any(s["name"] == "redis" and "without TLS" in s["reason"] for s in d["data"]["skipped"])' <<<"$o")"
check "import gives a database verified TLS" True "$($K conn show database | jget '"sslmode=verify-full" in d["data"]["url"]')"
check "import says what to run next" "komando test @t-e2einvi" "$(jget 'd["data"]["next"]' <<<"$o")"
q $K conn rm database
q $K secret rm database-pass --allow-dangerous
printf '{"format":"komando-export/1","conns":[{"name":"maria","kind":"mysql","url":"mysql://x@10.9.9.9:3306/x?tls=true"}]}' >"$TMP/inv-maria.json"
check "import --overwrite --dry-run skips a protected conn" "maria []" \
  "$($K import komando "$TMP/inv-maria.json" --overwrite --dry-run | jget 'd["data"]["skipped"][0]["name"] + " " + str(d["data"]["conns"])')"
