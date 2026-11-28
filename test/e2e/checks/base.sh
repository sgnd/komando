# shellcheck shell=bash
# The lab's servers: inventory and vault, logins through the bastion, exec,
# shell, secret managers (OpenBao, AWS Secrets Manager), fs, sudo, cp, exec sessions,
# keys, tunnels and modules. Moved here from run.sh; runs first in the core area.
check "host ssh list count" 3 "$($K host ssh list | jget 'd["data"]["count"]')"
# every --via bastion connection starts with a login there: sshd's default
# MaxStartups (10:30:100) drops new logins once ten are half-open, which a
# loaded CI runner reaches (C88, 2026-11-17)
check "the bastion takes many logins at once" "maxstartups 200:30:400" "$(DC exec -T bastion /usr/sbin/sshd -T 2>/dev/null | grep -i '^maxstartups ' || true)"
check "secret never printed" False "$($K credential password show agent-pass | jget '"value" in d["data"]')"
check "reveal needs a person" REVEAL_NEEDS_TERMINAL "$($K credential password show agent-pass --reveal </dev/null | jget 'd["error"]["code"]' || true)"
check "secret in use cannot be removed" SECRET_IN_USE "$($K credential password remove agent-pass | jget 'd["error"]["code"]' || true)"
check "plain password refused as a ref" USAGE "$($K host ssh add bad "agent@127.0.0.1:$E2E_SSH_DIRECT" --credential agentpass | jget 'd["error"]["code"]' || true)"
# renaming a secret moves every reference with it; the logins below prove the value survived the round trip
check "secret mv updates the 3 servers" 3 "$($K credential password rename agent-pass agent-pass-renamed | jget 'len(d["data"]["updated"])')"
check "the server follows the rename" credential:agent-pass-renamed "$($K host ssh show direct | jget 'd["data"]["password_ref"]')"
check "secret mv back" 3 "$($K credential password rename agent-pass-renamed agent-pass | jget 'len(d["data"]["updated"])')"
echo -n copypass | $K credential password add agent-pass-copy >/dev/null
check "secret rename onto a taken name needs --overwrite" SECRET_EXISTS "$($K credential password rename agent-pass agent-pass-copy | jget 'd["error"]["code"]' || true)"
$K credential password remove agent-pass-copy --allow-dangerous >/dev/null

check "completion lists the inventory" True "$($K __complete host ssh exec '' 2>/dev/null | grep -qx direct && echo True || echo False)"
# a run prepares only the commands of its line: a group's commands in
# completion and a sub-command's help each come out prepared;
# the help is read in full: after grep -q quits, its writes die of SIGPIPE
check "completion lists a group's commands" True "$($K __complete host ssh '' 2>/dev/null | grep -q '^remove' && echo True || echo False)"
check "a sub-command's help shows the safety line" 1 "$(grep -c 'Safety: ' <<<"$($K host ssh remove --help -o text 2>/dev/null)")"
check "schema knows kind: selectors" True "$($K schema | jget '"kind:KIND" in d["data"]["target_selectors"]')"

echo "==> connectivity (incl. jump host)"
check "host ssh test all ok" 3 "$($K host ssh test @lab | jget 'd["data"]["summary"]["ok"]')"

echo "==> exec"
check "exec stdout via jump" "target" "$($K host ssh exec target --read-only -- hostname | jget 'd["data"]["results"][0]["stdout"].strip()')"
# six servers behind one bastion: one login to the bastion, not six
for i in 1 2 3 4 5 6; do $K host ssh add "fan$i" agent@target --via bastion --credential agent-pass -g fan >/dev/null; done
logins() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" logs bastion 2>/dev/null | grep -c 'Accepted password' || true; }
before=$(logins)
check "exec -P 6 through one bastion" 6 "$($K host ssh exec @fan -P 6 --read-only -- hostname | jget 'd["data"]["summary"]["ok"]')"
sleep 1
check "the bastion saw one login for six servers" 1 "$(( $(logins) - before ))"
$K host ssh remove fan1 fan2 fan3 fan4 fan5 fan6 --yes >/dev/null
# many servers at once: import a CSV, edit a group in one go, rename one
CSV=$(mktemp)
printf 'name,address,user,via,password-ref,groups,protected\nbulk1,target,agent,bastion,credential:agent-pass,bulk,no\nbulk2,target,agent,bastion,credential:agent-pass,bulk,yes\n' >"$CSV"
check "import csv --dry-run adds nothing" 2 "$($K import csv "$CSV" --dry-run | jget 'len(d["data"]["hosts"])')"
check "import csv" 2 "$($K import csv "$CSV" | jget 'len(d["data"]["hosts"])')"
rm -f "$CSV"
check "host ssh edit @group stops at a protected server" PROTECTED_TARGET "$($K host ssh edit @bulk --user agent2 | jget 'd["error"]["code"]' || true)"
check "host ssh edit @group --yes changes both" 2 "$($K host ssh edit @bulk --add-tag bulked --user agent --yes | jget 'len(d["data"]["changed"])')"
$K host ssh rename bulk1 bulk-one --yes >/dev/null # same address as the protected target
check "host ssh rename keeps the server working" target "$($K host ssh exec bulk-one --read-only -- hostname | jget 'd["data"]["results"][0]["stdout"].strip()')"
$K host ssh remove bulk-one bulk2 --yes >/dev/null
set +e
$K host ssh exec direct -- 'exit 3' >/dev/null; check "non-zero exit -> 5" 5 $?
$K host ssh exec direct -- 'rm -rf /' >/dev/null; check "policy blocks rm -rf /" 6 $?
$K host ssh exec target -- 'touch /tmp/x' >/dev/null; check "protected host needs --yes" 6 $?
$K host ssh exec direct --timeout 1s -- 'sleep 5' >/dev/null; check "timeout -> 7" 7 $?
$K host ssh exec nope -- true >/dev/null; check "unknown host -> 3" 3 $?
$K host ssh shell direct </dev/null >/dev/null 2>&1; check "shell needs a terminal -> 2" 2 $?
check "shell refuses agents" NEEDS_TERMINAL "$(A host ssh shell direct --dry-run </dev/null | jget 'd["error"]["code"]' || true)"
O=$(ptyrun 'exit 3\n' env NO_COLOR=1 "$K" host ssh shell direct | tr -d '\r'); check "shell passes the remote exit code" 3 $?
check "shell says where it logs in" 1 "$(grep -c '^komando: shell on direct (agent@127.0.0.1)$' <<<"$O")"
check "shell says how it ended" 1 "$(grep -c '^komando: left direct (exit 3, [0-9]*s)$' <<<"$O")"
ptyrun 'n\n' "$K" host ssh shell target >/dev/null; check "shell on a protected host: no -> 6" 6 $?
O=$(ptyrun 'exit 0\n' env NO_COLOR=1 "$K" host ssh shell target --yes | tr -d '\r'); check "shell on a protected host with --yes" 0 $?
check "shell names the bastion and protection" 1 "$(grep -c '^komando: shell on target (agent@target) via bastion · PROTECTED$' <<<"$O")"
check "PROTECTED is red in colour terminals" 1 "$(ptyrun 'exit 0\n' env TERM=xterm NO_COLOR= "$K" host ssh shell target --yes | grep -c $'\e\\[1;31mPROTECTED')"
check "shell --dry-run reports the protected stop" PROTECTED_TARGET "$(ptyrun '' "$K" -o json host ssh shell target --dry-run | tr -d '\r' | grep '^{' | jget 'd["meta"]["would_be_blocked"]["code"]')"
# a login with no stored password: a person types it, as with ssh; an agent is never asked
$K host ssh add nopass "agent@127.0.0.1:$E2E_SSH_DIRECT" >/dev/null
O=$(ptyrun 'agentpass\n' env NO_COLOR=1 "$K" -o text host ssh exec nopass --read-only -- echo typed-ok | tr -d '\r'); check "a person types the password when none is stored" 0 $?
check "the question names the server" 1 "$(grep -c 'nopass: Password: ' <<<"$O")"
check "the typed password logs in" 1 "$(grep -cx 'typed-ok' <<<"$O")"
check "an agent is not asked for a password" False "$(A host ssh exec nopass --read-only -- true </dev/null | jget 'd["ok"]')"
check "an agent with no value is sent to the user" NEEDS_PERSON "$(A credential token add some-pass </dev/null | jget 'd["error"]["code"]' || true)"
check "the agent playbook reaches an agent whole" 0 "$(A guide -o text | grep -c 'password: \[hidden\]' || true)"
$K host ssh remove nopass >/dev/null
# --ask-password: a person types it once while adding the server; later logins use the vault
# Next: is said on stderr to a person at a terminal that is not dumb (not CI)
O=$(ptyrun 'agentpass\n' env NO_COLOR=1 TERM=xterm CI= "$K" -o text host ssh add askpw "agent@127.0.0.1:$E2E_SSH_DIRECT" --ask-password | tr -d '\r'); check "host ssh add --ask-password" 0 $?
check "host ssh add says what to run next" 1 "$(grep -c '^Next: komando test askpw' <<<"$O")"
check "the stored password logs in without a question" "stored-ok" "$($K host ssh exec askpw --read-only -- echo stored-ok | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "an agent cannot use --ask-password" NEEDS_PERSON "$(A host ssh add askpw2 "agent@127.0.0.1:$E2E_SSH_DIRECT" --ask-password </dev/null | jget 'd["error"]["code"]' || true)"
check "rm names the secret left behind" "['askpw-pass']" "$($K host ssh remove askpw | jget 'd["data"]["secrets_unused"]')"
$K credential password remove askpw-pass --allow-dangerous >/dev/null
# a whole export carries your deny rules, and import adds them in another home
$K policy create 'e2e-forbidden-word' >/dev/null
EXP="$(mktemp -d)/backup.json"
$K export --to "$EXP" >/dev/null
OTHER="$(mktemp -d)"; chmod 700 "$OTHER"
check "import adds the exported deny rule" "['e2e-forbidden-word']" "$(KOMANDO_HOME="$OTHER" "$K" import komando "$EXP" | jget 'd["data"]["deny_rules_added"]')"
rm -rf "$OTHER" "$(dirname "$EXP")"
$K policy remove 'e2e-forbidden-word' --yes >/dev/null
check "audit list --actor finds the e2e actor" True "$($K audit list --actor e2e -n 5 | jget 'd["data"]["count"] > 0')"
set -e
echo "==> secret managers, built in (no vault or aws CLI)"
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$E2E_BAO/v1/sys/health" >/dev/null && curl -s "http://127.0.0.1:$E2E_MOTO/" >/dev/null && break; sleep 1; done
curl -sf -H "X-Vault-Token: e2e-root" -d '{"data":{"agentpass":"agentpass"}}' "http://127.0.0.1:$E2E_BAO/v1/secret/data/e2e" >/dev/null
curl -sf -H 'X-Amz-Target: secretsmanager.CreateSecret' -H 'Content-Type: application/x-amz-json-1.1' \
  -H 'Authorization: AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/secretsmanager/aws4_request, SignedHeaders=host, Signature=0' \
  -d '{"Name":"e2e/agent","SecretString":"{\"password\":\"agentpass\"}"}' "http://127.0.0.1:$E2E_MOTO/" >/dev/null
# E1 (format 3): a server keeps its password as credential:NAME only; an outside
# store on the field is refused. The logins through OpenBao and AWS Secrets
# Manager come back with C485 (`komando credential`), which adds store items.
check "a server's password in OpenBao is refused" USAGE "$($K host ssh add direct-bao "agent@127.0.0.1:$E2E_SSH_DIRECT" --credential 'vault:secret/e2e#agentpass' 2>&1 | jget 'd["error"]["code"]' || true)"
check "a server's password in AWS Secrets Manager is refused" USAGE "$($K host ssh add direct-sm "agent@127.0.0.1:$E2E_SSH_DIRECT" --credential 'aws-sm:e2e/agent#password' 2>&1 | jget 'd["error"]["code"]' || true)"
check "the refusals wrote no server" False "$($K host ssh list | jget '"direct-bao" in json.dumps(d) or "direct-sm" in json.dumps(d)')"
(cd "$ROOT" && KOMANDO_E2E_MOTO="http://127.0.0.1:$E2E_MOTO" go test -count=1 -v -run '^TestSSMKMSMoto$' ./internal/cloud/ >"$KOMANDO_HOME/ssm-kms.log" 2>&1) || true
check "SSM session key from KMS (moto)" ok "$(grep -q -- '--- PASS: TestSSMKMSMoto' "$KOMANDO_HOME/ssm-kms.log" && echo ok)"
(cd "$ROOT" && KOMANDO_E2E_MOTO="http://127.0.0.1:$E2E_MOTO" go test -count=1 -v -run '^TestImportAWS$' ./internal/cli/ >"$KOMANDO_HOME/import-aws.log" 2>&1) || true
check "import aws: a conn per bucket of each profile (moto S3)" ok "$(grep -q -- '--- PASS: TestImportAWS' "$KOMANDO_HOME/import-aws.log" && echo ok)"
check "sudo works" root "$($K host ssh exec direct --sudo -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "dry-run reports block" PROTECTED_TARGET "$($K host ssh exec @lab --dry-run -- 'touch x' | jget 'd["data"]["would_be_blocked"]["code"]')"

echo "==> fs"
$K fs replace direct /etc/app/app.conf --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup >/dev/null
check "fs replace applied" "worker_connections 4096;" "$($K fs cat direct /etc/app/app.conf | jget 'd["data"]["content"].strip()')"
set +e; $K fs replace direct /etc/app/app.conf --old 'missing' --new 'x' --sudo >/dev/null; check "fs replace no match -> 8" 8 $?; set -e
# fs replace and fs restore on a group: each server has its own result
q $K group create t-fsg bastion direct
q $K host ssh exec @t-fsg -- 'printf "a=1\n" > /tmp/e2efsg.conf'
check "fs replace @group dry run shows each server" "2 True" "$($K fs replace @t-fsg /tmp/e2efsg.conf --old a=1 --new a=2 --dry-run | jget 'str(len(d["data"]["results"]))+" "+str(all(r["would_change"] for r in d["data"]["results"]))')"
check "fs replace @group changes every server" "2 0" "$($K fs replace @t-fsg /tmp/e2efsg.conf --old a=1 --new a=2 --backup | jget 'str(d["data"]["summary"]["ok"])+" "+str(d["data"]["summary"]["failed"])')"
check "fs replace @group wrote both files" "a=2 a=2" "$($K host ssh exec @t-fsg --read-only -o text -- cat /tmp/e2efsg.conf | grep -o 'a=2' | tr '\n' ' ' | sed 's/ $//')"
check "fs restore @group puts both back" "a=1 a=1" "$($K fs restore @t-fsg /tmp/e2efsg.conf >/dev/null; $K host ssh exec @t-fsg --read-only -o text -- cat /tmp/e2efsg.conf | grep -o 'a=1' | tr '\n' ' ' | sed 's/ $//')"
q $K host ssh exec bastion -- 'printf "b=1\n" > /tmp/e2efsg.conf'
set +e
out=$($K fs replace @t-fsg /tmp/e2efsg.conf --old a=1 --new a=3); rc=$?
set -e
check "fs replace @group: a server without the text fails alone (8)" "8 PARTIAL_FAILURE NO_MATCH" "$rc $(echo "$out" | jget 'd["error"]["code"]+" "+[r for r in d["data"]["results"] if r["host"]=="bastion"][0]["error"]["code"]')"
check "fs replace @group: the other server was changed" a=3 "$($K fs cat direct /tmp/e2efsg.conf | jget 'd["data"]["content"].strip()')"
q $K host ssh exec @t-fsg --allow-dangerous -- 'rm -f /tmp/e2efsg.conf*'
q $K group remove t-fsg
$K fs write direct /home/agent/t/x.txt --content hello -p >/dev/null
check "fs write idempotent" False "$($K fs write direct /home/agent/t/x.txt --content hello --if-changed | jget 'd["data"]["changed"]')"
check "fs write dry-run shows the diff" True "$($K fs write direct /home/agent/t/x.txt --content hello2 --dry-run | jget '"+hello2" in d["data"]["diff"]')"
check "fs write --validate refuses bad content" VALIDATION_FAILED "$($K fs write direct /home/agent/t/v.txt --content bad --validate 'grep -q good %s' | jget 'd["error"]["code"]' || true)"
check "refused file was not written" False "$($K fs stat direct /home/agent/t/v.txt | jget 'd["data"]["exists"]')"
check "fs write --sudo --validate (visudo)" VALIDATION_FAILED "$($K fs write direct /etc/sudoers.d/e2e --content 'not a sudoers line' --sudo --validate 'visudo -cf %s' | jget 'd["error"]["code"]' || true)"
check "sudo still works after refused edit" root "$($K host ssh exec direct --sudo -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()')"

echo "==> cp"
echo payload > "$TMP/f"

echo "==> sudo password"
echo -n opspass | $K credential password add ops-pass >/dev/null
$K host ssh add ops "ops@127.0.0.1:$E2E_SSH_DIRECT" --credential ops-pass --sudo-credential ops-pass >/dev/null
printf '#!/bin/sh\nwhoami\n' > "$TMP/who.sh"
check "sudo with password" root "$($K host ssh exec ops --sudo -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "sudo password then stdin" payload "$($K host ssh exec ops --sudo --stdin-file "$TMP/f" -- cat | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "script with sudo password" root "$($K host ssh exec ops --script "$TMP/who.sh" --sudo | jget 'd["data"]["results"][0]["stdout"].strip()')"
O=$($K host ssh exec ops --sudo -- 'whoami; cat; echo end'); SJ=$(echo "$O" | sess_id)
check "session with sudo password runs as root" "root end" "$(echo "$O" | jget '" ".join(d["data"]["results"][0]["stdout"].split())')"
check "session sudo password file is deleted" False "$($K fs stat ops "$(SDIR "$SJ")/pw" | jget 'd["data"]["exists"]')"
# a long script from this computer in a session: exec --script
O=$($K host ssh exec ops --sudo --script "$TMP/who.sh"); SJ=$(echo "$O" | sess_id)
check "exec --script runs in a session as root" root "$(echo "$O" | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "exec --script leaves no copy on the server" False "$($K fs stat ops "$(SDIR "$SJ")/script" | jget 'd["data"]["exists"]')"
# exec --sudo-user and --stdin-file, with a sudo password: the env and
# the input reach a command that runs as another user
O=$($K host ssh exec ops --sudo-user agent -e GREETING=hi --stdin-file "$TMP/f" -- 'echo "$(whoami) $GREETING $(cat)"'); SJ=$(echo "$O" | sess_id)
check "exec --sudo-user gets the env and the input" "agent hi payload" "$(echo "$O" | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "exec --stdin-file leaves no copy on the server" False "$($K fs stat ops "$(SDIR "$SJ")/in" | jget 'd["data"]["exists"]')"
check "exec --sudo-user deletes the sudo password" False "$($K fs stat ops "$(SDIR "$SJ")/pw" | jget 'd["data"]["exists"]')"
printf '#!/usr/bin/env bash\necho "got:$1:$2"\n' > "$TMP/args.sh"
check "exec --script --arg" "got:a b:c" "$($K host ssh exec direct --script "$TMP/args.sh" --arg 'a b' --arg c | jget 'd["data"]["results"][0]["stdout"].strip()')"
# sudo never asks on a NOPASSWD host, so the password must not reach the command
$K host ssh edit direct --sudo-credential agent-pass >/dev/null
check "unasked sudo password not leaked" False "$($K host ssh exec direct --script "$TMP/who.sh" --sudo | jget '"agentpass" in json.dumps(d)')"
check "unasked sudo password not in stdin" payload "$($K host ssh exec direct --sudo --stdin-file "$TMP/f" -- cat | jget 'd["data"]["results"][0]["stdout"].strip()')"
O=$($K host ssh exec direct --sudo --stdin-file "$TMP/f" -- 'cat'); SJ=$(echo "$O" | sess_id)
check "session: unasked sudo password not in its input" payload "$(echo "$O" | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "session: unasked sudo password is deleted unread" False "$($K fs stat direct "$(SDIR "$SJ")/pw" | jget 'd["data"]["exists"]')"
$K host ssh edit direct --unset sudo-credential >/dev/null
$K host ssh remove ops >/dev/null
$K host ssh exec direct --sudo -- 'mkdir -m 700 /etc/private && install -m 600 /dev/null /etc/private/token' >/dev/null
$K fs write direct /etc/private/token --content s3cret --sudo >/dev/null
check "fs write --sudo keeps a mode the user cannot see" 600 "$($K host ssh exec direct --sudo -- stat -c %a /etc/private/token | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "upload to group" 3 "$($K copy "$TMP/f" @lab:/tmp/f --yes | jget 'd["data"]["summary"]["ok"]')"
$K copy '@lab:/tmp/f' "$TMP/down" >/dev/null
check "download per host" payload "$(cat "$TMP/down/target/f")"

echo "==> exec sessions"
O=$($K host ssh exec direct --wait 0 -- 'echo a; sleep 2; echo b' || true); JID=$(echo "$O" | sess_id)
check "exec --wait 0 returns at once, the run goes on" SESSION_WAIT_TIMEOUT "$(echo "$O" | jget 'd["error"]["code"]')"
check "status lists the running session" True "$($K status | jget 'any(e["id"] == "'"$JID"'" for e in d["data"]["exec_sessions"])')"
O=$($K host ssh exec direct --attach "$JID" --wait 1m)
check "--attach reads the output and the exit code" "a b 0" "$(echo "$O" | jget '" ".join(d["data"]["results"][0]["stdout"].split()) + " " + str(d["data"]["results"][0]["exit_code"])')"
O=$($K host ssh exec direct --wait 0 -- 'echo a; sleep 31; echo late' || true); JT=$(echo "$O" | sess_id)
q $K host ssh exec direct --attach "$JT" --stop
check "--stop ends the run" 0 "$($K host ssh exec direct --read-only -o text -- 'pgrep -fxc "sleep 31" || true')"
check "a stopped session does not run on" "a" "$($K host ssh exec direct --attach "$JT" --wait 1m | jget 'd["data"]["results"][0]["stdout"].strip()' || true)"
check "the starter's read to its end removes the session's folder" False "$($K fs stat direct "$(SDIR "$JT")" | jget 'd["data"]["exists"]')"
O=$($K host ssh exec direct -- 'exit 3' || true)
check "a failed run in a session says its exit code" 3 "$(echo "$O" | jget 'd["data"]["results"][0]["exit_code"]')"
check "exec gets a vault secret as env" match "$($K host ssh exec direct -e P=credential:agent-pass -- 'test "$P" = agentpass && echo match' | jget 'd["data"]["results"][0]["stdout"].strip()')"
O=$($K host ssh exec direct --wait 0 -e P=credential:agent-pass -- 'sleep 1; test "$P" = agentpass && echo session-match' || true); JID=$(echo "$O" | sess_id)
check "a session gets a vault secret as env" True "$($K host ssh exec direct --attach "$JID" --wait 1m | jget '"session-match" in d["data"]["results"][0]["stdout"]')"
check "the session's env file is deleted" False "$($K fs stat direct "$(SDIR "$JID")/env" | jget 'd["data"]["exists"]')"
$K fs write direct /home/agent/t/app.env --content 'DB_PASSWORD=agentpass' >/dev/null
check "secret values hidden in output" "DB_PASSWORD=[credential:agent-pass]" "$($K fs cat direct /home/agent/t/app.env | jget 'd["data"]["content"].strip()')"

echo "==> keys"
$K credential key create deploy >/dev/null
check "key deploy" 3 "$($K credential key install deploy @lab --set-default --yes | jget 'd["data"]["summary"]["ok"]')"
$K host ssh edit direct --unset credential >/dev/null
check "key-only login" ok "$($K host ssh exec direct -- 'echo ok' | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "revoking the login key needs --allow-dangerous" POLICY_BLOCKED "$($K credential key uninstall deploy direct | jget 'd["error"]["code"]' || true)"
$K credential key create leaver >/dev/null
$K credential key install leaver direct >/dev/null
check "key revoke --dry-run counts" 1 "$($K credential key uninstall leaver direct --dry-run | jget 'd["data"]["results"][0]["would_remove"]')"
check "key revoke removes it" 1 "$($K credential key uninstall leaver direct | jget 'd["data"]["results"][0]["removed"]')"
check "other keys stay" ok "$($K host ssh exec direct -- 'echo ok' | jget 'd["data"]["results"][0]["stdout"].strip()')"
# --all-users: the key in two accounts (agent and ops), each file changed as its user
LEAVER=$($K credential key show leaver | jget 'd["data"]["public_key"]')
q $K host ssh exec direct --sudo -- "for u in agent ops; do h=\$(getent passwd \$u | cut -d: -f6); mkdir -p \$h/.ssh; echo '$LEAVER' >> \$h/.ssh/authorized_keys; chown -R \$u \$h/.ssh; done"
check "key revoke --all-users --dry-run names each user" "agent:1 ops:1" "$($K credential key uninstall leaver direct --all-users --dry-run | jget '" ".join(u["user"]+":"+str(u["removed"]) for u in d["data"]["results"][0]["users"])')"
check "key revoke --all-users removes it everywhere" 2 "$($K credential key uninstall leaver direct --all-users | jget 'd["data"]["results"][0]["removed"]')"
check "ops's file keeps its owner" ops "$($K host ssh exec direct --sudo -- 'stat -c %U ~ops/.ssh/authorized_keys' | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "login still works after --all-users" ok "$($K host ssh exec direct -- 'echo ok' | jget 'd["data"]["results"][0]["stdout"].strip()')"
$K host ssh add pc "agent@127.0.0.1" --port "$E2E_SSH_DIRECT" --key deploy --proxy-command 'nc %h %p' >/dev/null
check "proxy command carries ssh" ok "$($K host ssh exec pc -- 'echo ok' | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "proxy and --via do not mix" USAGE "$($K host ssh add pc2 agent@127.0.0.1 --via bastion --proxy-command 'nc %h %p' | jget 'd["error"]["code"]' || true)"
$K host ssh add ssm1 ec2-user@i-0abc123 --ssm >/dev/null
check "--ssm sets the AWS proxy" True "$($K host ssh show ssm1 | jget '"AWS-StartSSHSession" in d["data"]["proxy_command"]')"
$K host ssh remove pc ssm1 >/dev/null
check "revoke a public key line" 0 "$($K credential key uninstall "$($K credential key show leaver | jget 'd["data"]["public_key"]')" direct | jget 'd["data"]["results"][0]["removed"]')"

echo "==> tunnel"
LISTEN=$($K host ssh tunnel start target -L 0:localhost:22 | jget 'd["data"]["listen"]')
check "tunnel reaches private ssh" SSH-2.0 "$(nc -w 2 127.0.0.1 "${LISTEN##*:}" </dev/null | head -1 | cut -c1-7)"
$K host ssh tunnel stop --all >/dev/null
check "open bind needs --yes" OPEN_BIND "$($K host ssh tunnel start target -L 0.0.0.0:0:localhost:22 | jget 'd["error"]["code"]' || true)"

echo "==> modules"
check "test results carry host" direct "$($K test direct | jget 'd["data"]["results"][0]["host"]')"
check "audit recorded" True "$($K audit list -n 200 | jget 'd["data"]["count"] > 10')"
