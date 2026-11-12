# shellcheck shell=bash
# A person at a terminal: every question komando asks, answered no and yes
# in a real pseudo-terminal, plus typed commands that ask for what is missing.
# A "no" must change nothing; a "yes" must do what was asked, once.
# Uses names that start with t-person; everything is removed at the end.
P1="t-person-$$"
set +e
tty() { ptyrun "$1" env NO_COLOR=1 TERM=dumb "$K" -o text "${@:2}" | tr -d '\r'; } # tty ANSWER ARGS...

# a change to a protected server: [y/N]
O=$(tty 'n\n' exec target -- touch "/tmp/$P1"); RC=$?
check "person: a protected server asks first" 1 "$(grep -c 'target is protected. Change it anyway? \[y/N\]' <<<"$O")"
check "person: no to a protected server stops (6)" 6 "$RC"
check "person: no changed nothing" False "$($K fs stat target "/tmp/$P1" | jget 'd["data"]["exists"]')"
tty 'y\n' exec target -- touch "/tmp/$P1" >/dev/null
check "person: yes to a protected server runs it" True "$($K fs stat target "/tmp/$P1" | jget 'd["data"]["exists"]')"
q $K fs rm target "/tmp/$P1" --yes

# a destructive command: type the name to go on
q $K db query pg --write "create table if not exists t_person(x int)"
O=$(tty 'wrong\n' db query pg --write "drop table t_person"); RC=$?
check "person: a destructive query asks for the name" 1 "$(grep -c 'Type the name pg to continue' <<<"$O")"
check "person: a wrong name stops it (6)" 6 "$RC"
check "person: the table is still there" 1 "$($K db query pg "select count(*) from information_schema.tables where table_name='t_person'" | jget 'd["data"]["results"][0]["rows"][0][0]')"
tty 'pg\n' db query pg --write "drop table t_person" >/dev/null
check "person: the right name runs it" 0 "$($K db query pg "select count(*) from information_schema.tables where table_name='t_person'" | jget 'd["data"]["results"][0]["rows"][0][0]')"

# `komando db` alone: examples and the conn journey, exit 0
O=$(tty '' db); RC=$?
check "person: komando db shows how to list databases" 1 "$(grep -c 'komando list kind:db' <<<"$O")"
check "person: komando db shows examples" 1 "$(grep -c '^  komando db dump prod-db --to prod.sql.gz' <<<"$O")"
check "person: komando db alone exits 0" 0 "$RC"

# a change that weakens komando's own safety: [y/N]
q $K policy deny "t-person-word"
tty 'n\n' policy rm "t-person-word" >/dev/null
check "person: no keeps the deny rule" True "$($K policy check "echo t-person-word" | jget '"custom" in json.dumps(d)' || true)"
tty 'y\n' policy rm "t-person-word" >/dev/null
check "person: yes removes the deny rule" False "$($K policy check "echo t-person-word" | jget '"custom" in json.dumps(d)' || true)"

# removing a group with many members: [y/N]
for i in 1 2 3 4; do q $K host add "$P1-$i" agent@10.9.9.9 -g "$P1"; done
tty 'n\n' group rm "$P1" >/dev/null
check "person: no keeps the group" 4 "$($K list "@$P1" | jget 'd["data"]["count"]' || true)"
tty 'y\n' group rm "$P1" >/dev/null
check "person: yes deletes the group" TARGET_EMPTY "$($K list "@$P1" | jget 'd["error"]["code"]' || true)"
q $K host rm "$P1-1" "$P1-2" "$P1-3" "$P1-4"

# a secret typed hidden: never shown on the screen
O=$(tty 'personpass\n' secret set "$P1-pass"); RC=$?
check "person: secret set asks for the value" 0 "$RC"
check "person: the typed value is not echoed" 0 "$(grep -c personpass <<<"$O")"
check "person: the typed value was stored" True "$(echo personpass | $K secret check "$P1-pass" | jget 'd["data"]["match"]')"
q $K secret rm "$P1-pass"

# komando login HOST: a person logs in once, then an AI agent can use it
q $K host add "$P1-login" "agent@127.0.0.1:$E2E_SSH_DIRECT"
check "person: without a login an agent cannot reach it" False "$(A exec "$P1-login" --read-only -- true </dev/null | jget 'd["ok"]')"
O=$(tty 'agentpass\n' login "$P1-login"); RC=$?
check "person: login asks what the server asks" 1 "$(grep -c 'Password' <<<"$O")"
check "person: login succeeds" 0 "$RC"
check "person: an agent uses the kept login" via-login "$(A exec "$P1-login" --read-only -- echo via-login </dev/null | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "person: status lists the login" True "$($K status | jget "'$P1-login' in json.dumps(d)")"
q $K logout "$P1-login"
check "person: after logout the agent is out again" False "$(A exec "$P1-login" --read-only -- true </dev/null | jget 'd["ok"]')"
q $K host rm "$P1-login"

# typed commands at a terminal: what is missing is asked, the line shown
O=$(ptykeys -- env TERM=xterm "$K" | tr -d '\r')
check "person: komando alone shows the commands by group" True "$(grep -q 'START' <<<"$O" && grep -q 'SERVERS' <<<"$O" && echo True || echo False)"
O=$(ptykeys 'target\r' -- env TERM=xterm "$K" host show | tr -d '\r')
check "person: a missing NAME is asked, then the line runs" True "$(grep -q 'NAME' <<<"$O" && grep -q '\$ komando host show target' <<<"$O" && echo True || echo False)"
# a change on a protected server: the server's own [y/N] is the question, and no changes nothing
O=$(ptykeys "/tmp/$P1-dir\r" 'n\r' -- env TERM=xterm "$K" fs mkdir target | tr -d '\r')
check "person: a filled-in change on a protected server asks [y/N]" 1 "$(grep -c 'Change it anyway? \[y/N\]' <<<"$O")"
check "person: no to it made nothing" False "$($K fs stat target "/tmp/$P1-dir" | jget 'd["data"]["exists"]')"
check "person: an agent at a terminal is never asked" 0 "$(ptykeys -- env TERM=xterm KOMANDO_AGENT=1 "$K" host show </dev/null | grep -c 'NAME:' || true)"
set -e
