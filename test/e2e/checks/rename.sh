# shellcheck shell=bash
# host, secret, key and group rename against the lab: a small project under
# its own prefix (a secret, a jump server, a protected server behind it, a
# group, a managed key) is renamed one entry at a time, and the renamed
# server still answers through the renamed path and secret.
# Everything made here is t-ren<pid>-* (renamed to t-new<pid>-*).

code() { jget 'd["error"]["code"] if d.get("error") else "ok"' || true; }
R="t-ren$$"
N="t-new$$"

echo -n agentpass | $K credential password add "$R-pass" >/dev/null
q $K host ssh add "$R-jump" "agent@127.0.0.1:$E2E_SSH_BASTION" --credential "$R-pass" -g "$R" -g "$R-edge"
q $K host ssh add "$R-target" agent@target --via "$R-jump" --credential "$R-pass" -g "$R" --protected
q $K credential key create "$R-key"
check "rename: the project answers before" True "$($K test "$R-target" | jget 'd["ok"]')"

# the dry run lists the references and changes nothing
DRY=$($K host ssh rename "$R-jump" "$N-jump" --dry-run)
check "rename dry run: the action" would_rename "$(echo "$DRY" | jget 'd["data"]["action"]')"
check "rename dry run: changes nothing" True "$($K host ssh show "$R-target" | jget 'd["data"]["via"] == "'"$R"'-jump"')"

# a server in the middle of a path: the --via of the server behind it follows
check "host rename" True "$($K host ssh rename "$R-jump" "$N-jump" | jget 'd["data"]["action"] == "renamed"')"
check "host rename: via follows" "$N-jump" "$($K host ssh show "$R-target" | jget 'd["data"]["via"]')"
check "host rename: still protected" True "$($K host ssh show "$R-target" | jget 'd["data"]["protected"]')"

# a secret: every reference follows, the value stays
check "secret rename: the two servers follow" 2 "$($K credential password rename "$R-pass" "$N-pass" | jget 'len(d["data"]["updated"])')"
check "secret rename: refs follow" True "$($K host ssh show "$R-target" | jget 'd["data"]["password_ref"] == "credential:'"$N"'-pass"')"
check "secret rename: the secret moved" True "$($K credential list | jget '"'"$N"'-pass" in [s["name"] for s in d["data"]["secrets"]] and "'"$R"'-pass" not in [s["name"] for s in d["data"]["secrets"]]')"
check "rename: answers through the renamed path" True "$($K test "$R-target" | jget 'd["ok"]')"

# a clash stops it and changes nothing
q $K host ssh add "$R-solo" agent@10.9.9.8
q $K host ssh add "$N-solo" agent@10.9.9.9
check "rename: clash" NAME_TAKEN "$($K host ssh rename "$R-solo" "$N-solo" | code)"
check "rename: clash changes nothing" True "$($K host ssh show "$R-solo" | jget 'd["ok"]')"
q $K host ssh remove "$N-solo"

# key mv and group mv
q $K host ssh edit "$R-solo" --key "$R-key"
check "key mv" True "$($K credential key rename "$R-key" "$N-key2" | jget 'd["data"]["action"] == "renamed"')"
check "key mv: the server follows" "$N-key2" "$($K host ssh show "$R-solo" | jget 'd["data"]["key"]')"
check "key mv: the key keeps working" True "$($K credential key show "$N-key2" | jget 'd["data"]["path"].startswith("sealed:")')"
check "group mv: protected member" PROTECTED_TARGET "$($K group mv "$R" "$N-all" | code)"
check "group mv --yes" True "$($K group mv "$R" "$N-all" --yes | jget 'd["data"]["action"] == "renamed"')"
check "group mv: members follow" 2 "$($K group list "$N-all" | jget 'len(d["data"]["members"])')"

q $K host ssh remove "$R-target" "$R-solo" --yes
q $K host ssh remove "$N-jump"
q $K credential key remove "$N-key2" --delete-file --allow-dangerous
q $K credential password remove "$N-pass" --allow-dangerous
