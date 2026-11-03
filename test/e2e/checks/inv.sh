# Inventory, keys, secrets, settings, policy and selectors (fix/inv).
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
check "rm @group with a protected host" PROTECTED_HOST "$($K host rm @lab | code)"

# host trust --reset --dry-run changes nothing
N1=$($K host trust direct --reset --dry-run | jget 'd["data"]["would_remove_entries"]')
N2=$($K host trust direct --reset --dry-run | jget 'd["data"]["would_remove_entries"]')
check "trust --reset --dry-run removes nothing" "$N1" "$N2"
check "trust --reset --dry-run counts the pinned key" True "$([ "$N1" -ge 1 ] && echo True || echo False)"

# ssh-command: a hop per ProxyCommand, VPN as nc -X 5
check "ssh-command via bastion carries the key" True "$($K host ssh-command target | jget '"-W target:22" in d["data"]["command"] and d["data"]["command"].count("UserKnownHostsFile") == 2')"

# import: agents need a person for proxy commands; protected names
cat >"$TMP/inv-hosts.json" <<EOF
{"hosts":[{"name":"t-e2einv5","address":"10.9.9.5","proxy_command":"nc %h %p"}]}
EOF
check "agent import with proxy command" SAFETY_SETTING "$(A host import --json "$TMP/inv-hosts.json" | code)"
$K host rm t-e2einv5 >/dev/null 2>&1 || true
$K host export target >"$TMP/inv-target.json"
check "overwrite of a protected host is skipped_protected" '["target"]' "$($K host import --json "$TMP/inv-target.json" --overwrite | jget 'json.dumps(d["data"]["skipped_protected"])')"
check "import komando reads host export" target "$($K import komando "$TMP/inv-target.json" --dry-run | jget 'd["data"]["skipped"][0]["name"]')"

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
PUB="$($K key show t-e2einvk | jget 'd["data"]["path"]').pub"
check "public key given to key add" KEY_INVALID "$($K key add t-e2einvk2 "$PUB" | code)"
check "plain passphrase in key edit" USAGE "$($K key edit t-e2einvk --passphrase-ref pw123 | code)"
check "key list text is a table" True "$($K key list -o text | head -1 | grep -q '^NAME *TYPE *FINGERPRINT *USED_BY' && echo True || echo False)"
q $K key rm t-e2einvk --delete-file

# secrets
check "secret get shows no length" False "$($K secret get agent-pass | jget '"length" in d["data"]')"
check "replacing a protected host's secret" PROTECTED_TARGET "$(echo -n x | $K secret set agent-pass | code)"
printf 'a' | $K secret set t-e2einvs1 >/dev/null
printf 'b' | $K secret set t-e2einvs2 >/dev/null
check "secret set says replaced" True "$(printf 'c' | $K secret set t-e2einvs2 | jget 'd["data"]["replaced"]')"
check "secret rm takes many" ok "$($K secret rm t-e2einvs1 t-e2einvs2 | code)"

# settings
check "config get" 10 "$($K config get parallel | jget 'd["data"]["default"]')"
check "tiny max_output_bytes" USAGE "$($K config set max_output_bytes 1 | code)"
check "negative value names the fix" True "$($K config set parallel -3 | jget '"--" in d["error"]["hint"]')"
check "config set is audited" True "$($K config set connect_timeout 15s >/dev/null; $K audit -n 1 --command config.set | jget 'd["data"]["entries"][0]["new"] == "15s"')"

# policy
check "built-in rule cannot be allowed" BUILTIN_RULE "$($K policy allow rm-root | code)"
check "empty deny pattern" USAGE "$($K policy deny '' | code)"
set +e; $K policy check 'rm -rf //' >/dev/null; check "policy check exits 6 when blocked" 6 $?; set -e
check "grep mkfs is allowed" False "$($K policy check 'grep mkfs notes.txt' | jget 'd["data"]["blocked"]')"

# selectors and lookups
check "selector starting with !" False "$($K list '!direct' | jget 'any(t["name"] == "direct" for t in d["data"]["targets"])')"
check "names in any case" direct "$($K host show DIRECT | jget 'd["data"]["name"]')"
check "did you mean on host show" True "$($K host show dirct | jget '"direct" in d["error"]["hint"]')"
check "schema host.add" "komando host add" "$($K schema host.add | jget 'd["data"]["commands"][0]["path"]')"
check "test text has USER and SUDO" True "$($K test direct -o text | head -1 | grep -q 'USER *SUDO' && echo True || echo False)"
check "doctor text is a checklist" True "$($K doctor -o text 2>/dev/null | grep -q '^✓ state' && echo True || echo False)"
