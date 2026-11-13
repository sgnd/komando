# shellcheck shell=bash
# AI agents: what an agent may not do alone, masked output, the guard hook.
set +e; A exec target --yes -- 'touch /tmp/x' >/dev/null; check "agent --yes needs a person (no screen)" 6 $?; set -e
check "agent is told to ask the user" True "$(A exec target --yes -- 'touch /tmp/x' | jget '"own terminal" in d["error"]["hint"]' || true)"
check "agent --allow-dangerous needs a person" POLICY_BLOCKED "$(A fs rm direct /tmp/somedir --recursive --allow-dangerous | jget 'd["error"]["code"]' || true)"
q $K fs write direct /home/agent/app/.env -p --content "$(printf 'DB_HOST=db\nDB_PASSWORD=hunter22\nAPI_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n')"
echo 'hello' | $K fs write direct /home/agent/app/readme.txt >/dev/null
check "a script sees the file as it is" True "$($K fs cat direct /home/agent/app/.env | jget '"hunter22" in d["data"]["content"]')"
check "an agent sees [hidden]" "True False False" "$(A fs cat direct /home/agent/app/.env | jget '"DB_PASSWORD=[hidden]" in d["data"]["content"], "hunter22" in json.dumps(d), "ghp_" in json.dumps(d)')"
check "agent exec output is masked" False "$(A exec direct --read-only -- cat /home/agent/app/.env | jget '"hunter22" in json.dumps(d)')"
check "agent text output is masked" 0 "$(A exec direct --read-only -o text -- cat /home/agent/app/.env | { grep -c hunter22 || true; })"
check "agent --reveal without a person stays masked" False "$(A fs cat direct /home/agent/app/.env --reveal | jget '"hunter22" in json.dumps(d)')"
check "masked text is never written back" HIDDEN_VALUE "$(A fs write direct /home/agent/app/.env --content 'DB_PASSWORD=[hidden]' | jget 'd["error"]["code"]' || true)"
check "an agent needs a person to send a vault secret" SECRET_DESTINATION "$(A fs replace direct /home/agent/app/.env --old 'DB_PASSWORD=[hidden]' --new 'DB_PASSWORD={{secret:ops-pass}}' | jget 'd["error"]["code"]' || true)"
check "an agent's preview of it reads no secret" "True SECRET_DESTINATION" "$(A fs replace direct /home/agent/app/.env --old 'DB_PASSWORD=[hidden]' --new 'DB_PASSWORD={{secret:ops-pass}}' --dry-run | jget 'd["data"]["would_change"], d["meta"]["would_be_blocked"]["code"]')"
check "an agent with another KOMANDO_HOME needs a person" SAFETY_SETTING "$(CLAUDECODE=1 KOMANDO_NO_DIALOG=1 "$K" list | jget 'd["error"]["code"]' || true)"
q $K fs replace direct /home/agent/app/.env --old 'DB_PASSWORD=[hidden]' --new 'DB_PASSWORD={{secret:ops-pass}}'
check "a hidden value set from the vault" True "$($K fs cat direct /home/agent/app/.env | jget '"DB_PASSWORD=[secret:ops-pass]" in d["data"]["content"] and "DB_HOST=db" in d["data"]["content"]')"
check "an agent's guess of a vault value is refused" SECRET_INPUT_INVALID "$(A exec direct --read-only -- echo opspass | jget 'd["error"]["code"]' || true)"
check "the guess is in the audit log" True "$($K audit --limit 5 | jget '"SECRET_INPUT_INVALID" in json.dumps(d) and "opspass" not in json.dumps(d)')"
check "agent cannot copy .env here" SENSITIVE_FILE "$(A download direct /home/agent/app/.env --to "$TMP/" | jget 'd["error"]["code"]' || true)"
q A download direct /home/agent/app --to "$TMP/agentcopy" -r
check "agent folder copy leaves .env behind" "False True" "$(python3 -c "import os; print(os.path.exists('$TMP/agentcopy/.env'), os.path.exists('$TMP/agentcopy/readme.txt'))")"
check "agent secret get --reveal refused" REVEAL_NEEDS_HUMAN "$(A secret get ops-pass --reveal | jget 'd["error"]["code"]' || true)"
check "guard stops reading the vault" deny "$(printf '{"tool_name":"Read","tool_input":{"file_path":"%s/.komando/vault.key"}}' "$HOME" | $K guide guard | jget 'd["hookSpecificOutput"]["permissionDecision"]')"
check "guard stops ssh around komando" deny "$(echo '{"tool_name":"Bash","tool_input":{"command":"ssh web1 cat .env"}}' | $K guide guard | jget 'd["hookSpecificOutput"]["permissionDecision"]')"
check "guard lets komando through" "" "$(echo '{"tool_name":"Bash","tool_input":{"command":"komando fs cat web1 /srv/.env"}}' | $K guide guard)"
mkdir -p "$TMP/home"
q env HOME="$TMP/home" "$K" guide install
check "guide install adds the Claude Code guard" True "$(jget '"guide guard" in json.dumps(d["hooks"]["PreToolUse"])' < "$TMP/home/.claude/settings.json")"
check "guide uninstall takes the guard out only with a yes" SAFETY_SETTING "$(env HOME="$TMP/home" "$K" guide uninstall | jget 'd["error"]["code"]' || true)"
q env HOME="$TMP/home" "$K" guide uninstall --yes
check "guide uninstall takes the guard out" False "$(jget '"guide guard" in json.dumps(d.get("hooks", {}))' < "$TMP/home/.claude/settings.json")"
check "guide uninstall takes the skill out" False "$([ -e "$TMP/home/.claude/skills/komando" ] && echo True || echo False)"
