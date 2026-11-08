# shellcheck shell=bash
# rename --prefix, key mv and group mv against the lab: a small project
# under its own prefix (a secret, a jump server, a protected server behind
# it, a group, a managed key) is renamed in one step, and the renamed
# server still answers through the renamed path and secret.
# Everything made here is t-ren<pid>-* (renamed to t-new<pid>-*).

code() { jget 'd["error"]["code"] if d.get("error") else "ok"' || true; }
R="t-ren$$"
N="t-new$$"

echo -n agentpass | $K secret set "$R-pass" >/dev/null
q $K host add "$R-jump" "agent@127.0.0.1:$E2E_SSH_BASTION" --password-ref "secret:$R-pass" -g "$R" -g "$R-edge"
q $K host add "$R-target" agent@target --via "$R-jump" --password-ref "secret:$R-pass" -g "$R" --protected
q $K key gen "$R-key"
q $K conn add "$R-db" "postgres://shop@10.9.9.9/shop?sslmode=disable" --via "$R-jump" --password-ref "secret:$R-pass"
check "rename: the project answers before" True "$($K test "$R-target" | jget 'd["ok"]')"

# the dry run lists everything and changes nothing
DRY=$($K rename --prefix "$R-" "$N-" --dry-run)
check "rename dry run: count" 7 "$(echo "$DRY" | jget 'd["data"]["count"]')"
check "rename dry run: OLD without - counts" "$N" "$(echo "$DRY" | jget '[p["to"] for p in d["data"]["renamed"]["group"] if p["from"] == "'"$R"'"][0]')"
check "rename dry run: a protected stop" PROTECTED_HOST "$(echo "$DRY" | jget 'd["meta"]["would_be_blocked"]["code"]')"
check "rename dry run: via follows" "$N-jump" "$(echo "$DRY" | jget '[u["to"] for u in d["data"]["updated"] if u["entry"] == "host '"$N"'-target" and u["field"] == "via"][0]')"
check "rename dry run: changes nothing" True "$($K host show "$R-target" | jget 'd["data"]["via"] == "'"$R"'-jump"')"

# an agent with no screen to ask on is refused; a person's --yes covers all
check "rename: agent without a window" PROTECTED_HOST "$(A rename --prefix "$R-" "$N-" --yes | code)"
check "rename: without --yes" PROTECTED_HOST "$($K rename --prefix "$R-" "$N-" | code)"
check "rename: one --yes" 7 "$($K rename --prefix "$R-" "$N-" --yes | jget 'd["data"]["count"]')"
check "rename: still protected" True "$($K host show "$N-target" | jget 'd["data"]["protected"]')"
check "rename: refs follow" True "$($K host show "$N-target" | jget 'd["data"]["via"] == "'"$N"'-jump" and d["data"]["password_ref"] == "secret:'"$N"'-pass" and "'"$N"'" in d["data"]["groups"]')"
check "rename: the key file moved" True "$([ -f "$KOMANDO_HOME/keys/$N-key" ] && [ ! -e "$KOMANDO_HOME/keys/$R-key" ] && echo True || echo False)"
check "rename: the secret moved" True "$($K secret list | jget '"'"$N"'-pass" in [s["name"] for s in d["data"]["secrets"]] and "'"$R"'-pass" not in [s["name"] for s in d["data"]["secrets"]]')"
check "rename: answers through the renamed path" True "$($K test "$N-target" | jget 'd["ok"]')"
check "rename: nothing left to rename" NOTHING_TO_RENAME "$($K rename --prefix "$R-" "$N-" | code)"

# a clash stops it and changes nothing
q $K host add "$R-solo" agent@10.9.9.8
q $K host add "$N-solo" agent@10.9.9.9
check "rename: clash" NAME_TAKEN "$($K rename --prefix "$R-" "$N-" | code)"
check "rename: clash changes nothing" True "$($K host show "$R-solo" | jget 'd["ok"]')"
q $K host rm "$N-solo"

# key mv and group mv
q $K host edit "$R-solo" --key "$N-key"
check "key mv" True "$($K key mv "$N-key" "$N-key2" | jget 'd["data"]["action"] == "renamed"')"
check "key mv: the server follows" "$N-key2" "$($K host show "$R-solo" | jget 'd["data"]["key"]')"
check "key mv: files moved" True "$([ -f "$KOMANDO_HOME/keys/$N-key2" ] && [ -f "$KOMANDO_HOME/keys/$N-key2.pub" ] && echo True || echo False)"
check "group mv: protected member" PROTECTED_HOST "$($K group mv "$N" "$N-all" | code)"
check "group mv --yes" True "$($K group mv "$N" "$N-all" --yes | jget 'd["data"]["action"] == "renamed"')"
check "group mv: members follow" 2 "$($K group list "$N-all" | jget 'len(d["data"]["members"])')"

q $K host rm "$N-target" "$R-solo" --yes
q $K conn rm "$N-db"
q $K host rm "$N-jump"
q $K key rm "$N-key2" --delete-file
q $K secret rm "$N-pass"
