# shellcheck shell=bash
# The lab's servers: inventory and vault, logins through the bastion, exec,
# shell, secret managers (OpenBao, AWS Secrets Manager), fs, sudo, cp, jobs,
# keys, tunnels and modules. Moved here from run.sh; runs first in the core area.
check "host list count" 3 "$($K host list | jget 'd["data"]["count"]')"
check "secret never printed" False "$($K secret get agent-pass | jget '"value" in d["data"]')"
check "reveal needs a person" REVEAL_NEEDS_HUMAN "$($K secret get agent-pass --reveal </dev/null | jget 'd["error"]["code"]' || true)"
check "secret in use cannot be removed" SECRET_IN_USE "$($K secret rm agent-pass | jget 'd["error"]["code"]' || true)"
check "plain password refused as a ref" USAGE "$($K host add bad "agent@127.0.0.1:$E2E_SSH_DIRECT" --password-ref agentpass | jget 'd["error"]["code"]' || true)"
# renaming a secret moves every reference with it; the logins below prove the value survived the round trip
check "secret mv updates the 3 servers" 3 "$($K secret mv agent-pass agent-pass-renamed | jget 'len(d["data"]["updated"])')"
check "the server follows the rename" secret:agent-pass-renamed "$($K host show direct | jget 'd["data"]["password_ref"]')"
check "secret mv back" 3 "$($K secret mv agent-pass-renamed agent-pass | jget 'len(d["data"]["updated"])')"
$K secret cp agent-pass agent-pass-copy >/dev/null
check "secret cp to a taken name needs --overwrite" SECRET_EXISTS "$($K secret cp agent-pass agent-pass-copy | jget 'd["error"]["code"]' || true)"
$K secret rm agent-pass-copy >/dev/null

check "completion lists the inventory" True "$($K __complete exec '' 2>/dev/null | grep -qx direct && echo True || echo False)"
check "schema knows kind: selectors" True "$($K schema | jget '"kind:KIND" in d["data"]["target_selectors"]')"

echo "==> connectivity (incl. jump host)"
check "host test all ok" 3 "$($K host test @lab | jget 'd["data"]["summary"]["ok"]')"

echo "==> exec"
check "exec stdout via jump" "target" "$($K exec target --read-only -- hostname | jget 'd["data"]["results"][0]["stdout"].strip()')"
# six servers behind one bastion: one login to the bastion, not six
for i in 1 2 3 4 5 6; do $K host add "fan$i" agent@target --via bastion --password-ref secret:agent-pass -g fan >/dev/null; done
logins() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" logs bastion 2>/dev/null | grep -c 'Accepted password' || true; }
before=$(logins)
check "exec -P 6 through one bastion" 6 "$($K exec @fan -P 6 --read-only -- hostname | jget 'd["data"]["summary"]["ok"]')"
sleep 1
check "the bastion saw one login for six servers" 1 "$(( $(logins) - before ))"
$K host rm fan1 fan2 fan3 fan4 fan5 fan6 --yes >/dev/null
# many servers at once: import a CSV, edit a group in one go, rename one
CSV=$(mktemp)
printf 'name,address,user,via,password-ref,groups,protected\nbulk1,target,agent,bastion,secret:agent-pass,bulk,no\nbulk2,target,agent,bastion,secret:agent-pass,bulk,yes\n' >"$CSV"
check "import csv --dry-run adds nothing" 2 "$($K import csv "$CSV" --dry-run | jget 'len(d["data"]["hosts"])')"
check "import csv" 2 "$($K import csv "$CSV" | jget 'len(d["data"]["hosts"])')"
rm -f "$CSV"
check "host edit @group stops at a protected server" PROTECTED_HOST "$($K host edit @bulk --user agent2 | jget 'd["error"]["code"]' || true)"
check "host edit @group --yes changes both" 2 "$($K host edit @bulk -t bulked --user agent --yes | jget 'len(d["data"]["changed"])')"
$K host mv bulk1 bulk-one --yes >/dev/null # same address as the protected target
check "host mv keeps the server working" target "$($K exec bulk-one --read-only -- hostname | jget 'd["data"]["results"][0]["stdout"].strip()')"
$K host rm bulk-one bulk2 --yes >/dev/null
set +e
$K exec direct -- 'exit 3' >/dev/null; check "non-zero exit -> 5" 5 $?
$K exec direct -- 'rm -rf /' >/dev/null; check "policy blocks rm -rf /" 6 $?
$K exec target -- 'touch /tmp/x' >/dev/null; check "protected host needs --yes" 6 $?
$K exec direct --timeout 1s -- 'sleep 5' >/dev/null; check "timeout -> 7" 7 $?
$K exec nope -- true >/dev/null; check "unknown host -> 3" 3 $?
$K shell direct </dev/null >/dev/null 2>&1; check "shell needs a terminal -> 2" 2 $?
check "shell refuses agents" NEEDS_TERMINAL "$(A shell direct --dry-run </dev/null | jget 'd["error"]["code"]' || true)"
O=$(ptyrun 'exit 3\n' env NO_COLOR=1 "$K" shell direct | tr -d '\r'); check "shell passes the remote exit code" 3 $?
check "shell says where it logs in" 1 "$(grep -c '^komando: shell on direct (agent@127.0.0.1)$' <<<"$O")"
check "shell says how it ended" 1 "$(grep -c '^komando: left direct (exit 3, [0-9]*s)$' <<<"$O")"
ptyrun 'n\n' "$K" shell target >/dev/null; check "shell on a protected host: no -> 6" 6 $?
O=$(ptyrun 'exit 0\n' env NO_COLOR=1 "$K" shell target --yes | tr -d '\r'); check "shell on a protected host with --yes" 0 $?
check "shell names the bastion and protection" 1 "$(grep -c '^komando: shell on target (agent@target) via bastion · PROTECTED$' <<<"$O")"
check "PROTECTED is red in colour terminals" 1 "$(ptyrun 'exit 0\n' env TERM=xterm NO_COLOR= "$K" shell target --yes | grep -c $'\e\\[1;31mPROTECTED')"
check "shell --dry-run reports the protected stop" PROTECTED_HOST "$(ptyrun '' "$K" -o json shell target --dry-run | tr -d '\r' | grep '^{' | jget 'd["meta"]["would_be_blocked"]["code"]')"
# a login with no stored password: a person types it, as with ssh; an agent is never asked
$K host add nopass "agent@127.0.0.1:$E2E_SSH_DIRECT" >/dev/null
O=$(ptyrun 'agentpass\n' env NO_COLOR=1 "$K" -o text exec nopass --read-only -- echo typed-ok | tr -d '\r'); check "a person types the password when none is stored" 0 $?
check "the question names the server" 1 "$(grep -c 'nopass: Password: ' <<<"$O")"
check "the typed password logs in" 1 "$(grep -cx 'typed-ok' <<<"$O")"
check "an agent is not asked for a password" False "$(A exec nopass --read-only -- true </dev/null | jget 'd["ok"]')"
check "an agent with no value is sent to the user" NEEDS_PERSON "$(A secret set some-pass </dev/null | jget 'd["error"]["code"]' || true)"
check "the agent playbook reaches an agent whole" 0 "$(A guide -o text | grep -c 'password: \[hidden\]' || true)"
$K host rm nopass >/dev/null
# --ask-password: a person types it once while adding the server; later logins use the vault
O=$(ptyrun 'agentpass\n' env NO_COLOR=1 "$K" -o text host add askpw "agent@127.0.0.1:$E2E_SSH_DIRECT" --ask-password | tr -d '\r'); check "host add --ask-password" 0 $?
check "host add says what to run next" 1 "$(grep -c '^next: komando test askpw' <<<"$O")"
check "the stored password logs in without a question" "stored-ok" "$($K exec askpw --read-only -- echo stored-ok | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "an agent cannot use --ask-password" NEEDS_PERSON "$(A host add askpw2 "agent@127.0.0.1:$E2E_SSH_DIRECT" --ask-password </dev/null | jget 'd["error"]["code"]' || true)"
check "rm names the secret left behind" "['askpw-pass']" "$($K host rm askpw | jget 'd["data"]["secrets_unused"]')"
$K secret rm askpw-pass >/dev/null
# a whole export carries your deny rules, and import adds them in another home
$K policy deny 'e2e-forbidden-word' >/dev/null
EXP="$(mktemp -d)/backup.json"
$K export --to "$EXP" >/dev/null
OTHER="$(mktemp -d)"; chmod 700 "$OTHER"
check "import adds the exported deny rule" "['e2e-forbidden-word']" "$(KOMANDO_HOME="$OTHER" "$K" import komando "$EXP" | jget 'd["data"]["deny_rules_added"]')"
rm -rf "$OTHER" "$(dirname "$EXP")"
$K policy rm 'e2e-forbidden-word' --yes >/dev/null
check "audit --actor finds the e2e actor" True "$($K audit --actor e2e -n 5 | jget 'd["data"]["count"] > 0')"
set -e
echo "==> secret managers, built in (no vault or aws CLI)"
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$E2E_BAO/v1/sys/health" >/dev/null && curl -s "http://127.0.0.1:$E2E_MOTO/" >/dev/null && break; sleep 1; done
curl -sf -H "X-Vault-Token: e2e-root" -d '{"data":{"agentpass":"agentpass"}}' "http://127.0.0.1:$E2E_BAO/v1/secret/data/e2e" >/dev/null
curl -sf -H 'X-Amz-Target: secretsmanager.CreateSecret' -H 'Content-Type: application/x-amz-json-1.1' \
  -H 'Authorization: AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/secretsmanager/aws4_request, SignedHeaders=host, Signature=0' \
  -d '{"Name":"e2e/agent","SecretString":"{\"password\":\"agentpass\"}"}' "http://127.0.0.1:$E2E_MOTO/" >/dev/null
SMENV=(env PATH=/usr/bin:/bin AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 AWS_ENDPOINT_URL="http://127.0.0.1:$E2E_MOTO" AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true)
$K host add direct-bao "agent@127.0.0.1:$E2E_SSH_DIRECT" --password-ref 'vault:secret/e2e#agentpass' >/dev/null
$K host add direct-sm "agent@127.0.0.1:$E2E_SSH_DIRECT" --password-ref 'aws-sm:e2e/agent#password' >/dev/null
check "password from OpenBao" agent "$("${BAOENV[@]}" $K exec direct-bao --read-only -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()' || true)"
check "password from AWS Secrets Manager" agent "$("${SMENV[@]}" $K exec direct-sm --read-only -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()' || true)"
$K host rm direct-bao direct-sm >/dev/null
(cd "$ROOT" && KOMANDO_E2E_MOTO="http://127.0.0.1:$E2E_MOTO" go test -count=1 -v -run '^TestSSMKMSMoto$' ./internal/cloud/ >"$KOMANDO_HOME/ssm-kms.log" 2>&1) || true
check "SSM session key from KMS (moto)" ok "$(grep -q -- '--- PASS: TestSSMKMSMoto' "$KOMANDO_HOME/ssm-kms.log" && echo ok)"
(cd "$ROOT" && KOMANDO_E2E_MOTO="http://127.0.0.1:$E2E_MOTO" go test -count=1 -v -run '^TestImportAWS$' ./internal/cli/ >"$KOMANDO_HOME/import-aws.log" 2>&1) || true
check "import aws: a conn per bucket of each profile (moto S3)" ok "$(grep -q -- '--- PASS: TestImportAWS' "$KOMANDO_HOME/import-aws.log" && echo ok)"
check "sudo works" root "$($K exec direct --sudo -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "dry-run reports block" PROTECTED_HOST "$($K exec @lab --dry-run -- 'touch x' | jget 'd["data"]["would_be_blocked"]["code"]')"

echo "==> fs"
$K fs replace direct /etc/app/app.conf --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup >/dev/null
check "fs replace applied" "worker_connections 4096;" "$($K fs cat direct /etc/app/app.conf | jget 'd["data"]["content"].strip()')"
set +e; $K fs replace direct /etc/app/app.conf --old 'missing' --new 'x' --sudo >/dev/null; check "fs replace no match -> 8" 8 $?; set -e
$K fs write direct /home/agent/t/x.txt --content hello -p >/dev/null
check "fs write idempotent" False "$($K fs write direct /home/agent/t/x.txt --content hello --if-changed | jget 'd["data"]["changed"]')"
check "fs write dry-run shows the diff" True "$($K fs write direct /home/agent/t/x.txt --content hello2 --dry-run | jget '"+hello2" in d["data"]["diff"]')"
check "fs write --validate refuses bad content" VALIDATION_FAILED "$($K fs write direct /home/agent/t/v.txt --content bad --validate 'grep -q good %s' | jget 'd["error"]["code"]' || true)"
check "refused file was not written" False "$($K fs stat direct /home/agent/t/v.txt | jget 'd["data"]["exists"]')"
check "fs write --sudo --validate (visudo)" VALIDATION_FAILED "$($K fs write direct /etc/sudoers.d/e2e --content 'not a sudoers line' --sudo --validate 'visudo -cf %s' | jget 'd["error"]["code"]' || true)"
check "sudo still works after refused edit" root "$($K exec direct --sudo -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()')"

echo "==> cp"
echo payload > "$TMP/f"

echo "==> sudo password"
echo -n opspass | $K secret set ops-pass >/dev/null
$K host add ops "ops@127.0.0.1:$E2E_SSH_DIRECT" --password-ref secret:ops-pass --sudo-ref secret:ops-pass >/dev/null
printf '#!/bin/sh\nwhoami\n' > "$TMP/who.sh"
check "sudo with password" root "$($K exec ops --sudo -- whoami | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "sudo password then stdin" payload "$($K exec ops --sudo --stdin-file "$TMP/f" -- cat | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "script with sudo password" root "$($K exec ops --script "$TMP/who.sh" --sudo | jget 'd["data"]["results"][0]["stdout"].strip()')"
SJ=$($K job start ops --sudo -- 'whoami; cat; echo end' | jget 'd["data"]["jobs"][0]["id"]')
check "job with sudo password" exited "$($K job wait "$SJ" --interval 1s | jget 'd["data"]["state"]')"
check "job with sudo password runs as root" "root end" "$($K job logs "$SJ" | jget '" ".join(d["data"]["content"].split())')"
check "job sudo password file is deleted" False "$($K fs stat ops ".komando/jobs/$SJ/pw" | jget 'd["data"]["exists"]')"
# a long script from this computer as a job: exec --script's twin
SJ=$($K job start ops --sudo --script "$TMP/who.sh" | jget 'd["data"]["jobs"][0]["id"]')
check "job start --script with sudo password" exited "$($K job wait "$SJ" --interval 1s | jget 'd["data"]["state"]')"
check "job start --script runs the script as root" root "$($K job logs "$SJ" | jget 'd["data"]["content"].strip()')"
check "job start --script leaves no copy on the server" False "$($K fs stat ops ".komando/jobs/$SJ/script" | jget 'd["data"]["exists"]')"
printf '#!/usr/bin/env bash\necho "got:$1:$2"\n' > "$TMP/args.sh"
SJ=$($K job start direct --script "$TMP/args.sh" --arg 'a b' --arg c | jget 'd["data"]["jobs"][0]["id"]')
$K job wait "$SJ" --interval 1s >/dev/null
check "job start --script --arg" "got:a b:c" "$($K job logs "$SJ" | jget 'd["data"]["content"].strip()')"
check "job list shows the script, not its text" True "$($K job list | jget 'any(j["command"].startswith("--script") for j in d["data"]["jobs"])')"
# sudo never asks on a NOPASSWD host, so the password must not reach the command
$K host edit direct --sudo-ref secret:agent-pass >/dev/null
check "unasked sudo password not leaked" False "$($K exec direct --script "$TMP/who.sh" --sudo | jget '"agentpass" in json.dumps(d)')"
check "unasked sudo password not in stdin" payload "$($K exec direct --sudo --stdin-file "$TMP/f" -- cat | jget 'd["data"]["results"][0]["stdout"].strip()')"
$K host edit direct --unset sudo-ref >/dev/null
$K host rm ops >/dev/null
$K exec direct --sudo -- 'mkdir -m 700 /etc/private && install -m 600 /dev/null /etc/private/token' >/dev/null
$K fs write direct /etc/private/token --content s3cret --sudo >/dev/null
check "fs write --sudo keeps a mode the user cannot see" 600 "$($K exec direct --sudo -- stat -c %a /etc/private/token | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "upload to group" 3 "$($K cp "$TMP/f" @lab:/tmp/f --yes | jget 'd["data"]["summary"]["ok"]')"
$K cp '@lab:/tmp/f' "$TMP/down" >/dev/null
check "download per host" payload "$(cat "$TMP/down/target/f")"

echo "==> jobs"
JID=$($K job start direct -- 'echo a; sleep 1; echo b' | jget 'd["data"]["jobs"][0]["id"]')
check "job wait ok" exited "$($K job wait "$JID" --interval 1s | jget 'd["data"]["state"]')"
check "job logs" "a b" "$($K job logs "$JID" | jget '" ".join(d["data"]["content"].split())')"
J2=$($K job start direct -- 'exit 3' | jget 'd["data"]["jobs"][0]["id"]')
set +e; $K job wait "$JID" "$J2" --interval 1s >/dev/null; check "job wait several: worst exit" 5 $?; set -e
check "job wait several" 1 "$($K job wait "$JID" "$J2" --interval 1s | jget 'd["data"]["summary"]["ok"]' || true)"
check "exec gets a vault secret as env" match "$($K exec direct -e P=secret:agent-pass -- 'test "$P" = agentpass && echo match' | jget 'd["data"]["results"][0]["stdout"].strip()')"
JID=$($K job start direct -e P=secret:agent-pass -- 'test "$P" = agentpass && echo job-match' | jget 'd["data"]["jobs"][0]["id"]')
$K job wait "$JID" --interval 1s >/dev/null
check "job gets a vault secret as env" True "$($K job logs "$JID" | jget '"job-match" in d["data"]["content"]')"
check "job env file is deleted" False "$($K fs stat direct ".komando/jobs/$JID/env" | jget 'd["data"]["exists"]')"
$K fs write direct /home/agent/t/app.env --content 'DB_PASSWORD=agentpass' >/dev/null
check "secret values hidden in output" "DB_PASSWORD=[secret:agent-pass]" "$($K fs cat direct /home/agent/t/app.env | jget 'd["data"]["content"].strip()')"

echo "==> keys"
$K key gen deploy >/dev/null
check "key deploy" 3 "$($K key deploy deploy @lab --set-default --yes | jget 'd["data"]["summary"]["ok"]')"
$K host edit direct --unset password-ref >/dev/null
check "key-only login" ok "$($K exec direct -- 'echo ok' | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "revoking the login key needs --allow-dangerous" POLICY_BLOCKED "$($K key revoke deploy direct | jget 'd["error"]["code"]' || true)"
$K key gen leaver >/dev/null
$K key deploy leaver direct >/dev/null
check "key revoke --dry-run counts" 1 "$($K key revoke leaver direct --dry-run | jget 'd["data"]["results"][0]["would_remove"]')"
check "key revoke removes it" 1 "$($K key revoke leaver direct | jget 'd["data"]["results"][0]["removed"]')"
check "other keys stay" ok "$($K exec direct -- 'echo ok' | jget 'd["data"]["results"][0]["stdout"].strip()')"
$K host add pc "agent@127.0.0.1" --port "$E2E_SSH_DIRECT" --key deploy --proxy-command 'nc %h %p' >/dev/null
check "proxy command carries ssh" ok "$($K exec pc -- 'echo ok' | jget 'd["data"]["results"][0]["stdout"].strip()')"
# pc logs in with a key komando made, sealed in the store: OpenSSH gets it
# from a running ssh-agent, never from a file
check "ssh-command without an ssh-agent" SSH_AGENT_NEEDED "$(env -u SSH_AUTH_SOCK $K host ssh-command pc | jget 'd["error"]["code"]' || true)"
if command -v ssh-agent >/dev/null && command -v ssh >/dev/null; then
  AGENT_ENV=$(ssh-agent -s)
  eval "$AGENT_ENV" >/dev/null
  LINE=$($K host ssh-command pc -o text)
  check "ssh-command gives the ssh-agent the key" True "$(ssh-add -l | grep -q 'komando:deploy' && echo True || echo False)"
  check "ssh-command line has no private key file" False "$(grep -l 'PRIVATE KEY' $(dirname "$(echo "$LINE" | sed 's/.* -i \([^ ]*\).*/\1/')")/* >/dev/null 2>&1 && echo True || echo False)"
  check "OpenSSH logs in through the ssh-agent" ok "$(timeout 30 sh -c "$LINE echo ok" </dev/null 2>/dev/null | tr -d '\r')"
  ssh-agent -k >/dev/null
  unset SSH_AUTH_SOCK SSH_AGENT_PID
fi
check "proxy and --via do not mix" USAGE "$($K host add pc2 agent@127.0.0.1 --via bastion --proxy-command 'nc %h %p' | jget 'd["error"]["code"]' || true)"
$K host add ssm1 ec2-user@i-0abc123 --ssm >/dev/null
check "--ssm sets the AWS proxy" True "$($K host show ssm1 | jget '"AWS-StartSSHSession" in d["data"]["proxy_command"]')"
$K host rm pc ssm1 >/dev/null
check "revoke a public key line" 0 "$($K key revoke "$($K key show leaver | jget 'd["data"]["public_key"]')" direct | jget 'd["data"]["results"][0]["removed"]')"

echo "==> tunnel"
LISTEN=$($K tunnel start target -L 0:localhost:22 | jget 'd["data"]["listen"]')
check "tunnel reaches private ssh" SSH-2.0 "$(nc -w 2 127.0.0.1 "${LISTEN##*:}" </dev/null | head -1 | cut -c1-7)"
$K tunnel stop --all >/dev/null
check "open bind needs --yes" OPEN_BIND "$($K tunnel start target -L 0.0.0.0:0:localhost:22 | jget 'd["error"]["code"]' || true)"

echo "==> modules"
FACTS=$($K facts direct)
check "facts os" debian "$(echo "$FACTS" | jget 'd["data"]["results"][0]["data"]["os"]')"
check "facts os support status" True "$(echo "$FACTS" | jget 'd["data"]["results"][0]["data"]["os_support"]["status"] in ("supported", "extended", "unsupported", "unknown")')"
check "facts sudo_nopasswd known" True "$(echo "$FACTS" | jget 'd["data"]["results"][0]["data"]["sudo_nopasswd"] in (True, False)')"
check "facts sees sshd listening" True "$(echo "$FACTS" | jget '22 in [p["port"] for p in d["data"]["results"][0]["data"]["listening"]["ports"]]')"
check "test results carry host" direct "$($K test direct | jget 'd["data"]["results"][0]["host"]')"
check "net check private" False "$($K net check direct target:22 | jget 'd["data"]["results"][0]["data"][0]["open"]')"
$K cron set direct t1 'true' --schedule '@daily' >/dev/null
check "cron set idempotent" 1 "$($K cron set direct t1 'true' --schedule '@daily' >/dev/null; $K cron list direct | jget 'len(d["data"]["results"][0]["data"])')"
check "audit recorded" True "$($K audit -n 200 | jget 'd["data"]["count"] > 10')"
