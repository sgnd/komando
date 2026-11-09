# shellcheck shell=bash
# ssh-gate: an SSH key that runs komando and nothing else (a forced command
# in authorized_keys), as the iPhone app's key will. The direct container
# plays the komando computer: it gets a Linux komando, two keys are added
# with the lines `komando ssh-gate line` prints, and OpenSSH logs in with
# them as a phone would. That komando keeps its vault key in vault.key: the
# container has no keychain (no Secret Service), like a Linux CI runner.
GATE="${PROJECT:-komando-e2e}-direct-1"
GARCH=$(docker version -f '{{.Server.Arch}}')
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$GARCH" go build -o "$TMP/komando-linux" ./cmd/komando)
docker cp "$TMP/komando-linux" "$GATE:/usr/local/bin/komando" >/dev/null
docker exec "$GATE" chmod 755 /usr/local/bin/komando
gx() { docker exec -i -u agent -e HOME=/home/agent "$GATE" "$@"; } # on the komando computer, as its user
for k in gate-rw gate-ro; do rm -f "$TMP/$k" "$TMP/$k.pub"; ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$TMP/$k"; done
L1=$(gx komando ssh-gate line --name phone "$(cat "$TMP/gate-rw.pub")" -o json | jget 'd["data"]["line"]')
L2=$(gx komando ssh-gate line --name phone-read --read-only "$(cat "$TMP/gate-ro.pub")" -o json | jget 'd["data"]["line"]')
check "ssh-gate line: restrict, the full path, the key" True "$(case "$L1" in 'restrict,command="/usr/local/bin/komando ssh-gate --name phone" ssh-ed25519 '*' gate-rw') echo True ;; *) echo "False: $L1" ;; esac)"
printf '%s\n%s\n' "$L1" "$L2" | gx sh -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
# kssh KEY [COMMAND]: log in with that key only, as the phone does
kssh() {
  local key=$1
  shift
  ssh -T -p "$E2E_SSH_DIRECT" -i "$TMP/$key" -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR agent@127.0.0.1 "$@" </dev/null
}
code() { jget 'd["error"]["code"]'; }
mentions() { jget "'$1' in json.dumps(d)"; } # mentions TEXT: the JSON answer holds TEXT

check "a gate key runs komando" True "$(kssh gate-rw 'KOMANDO_AGENT=Komando komando version -o json' | jget 'd["ok"]')"
check "a gate key may change things" True "$(kssh gate-rw komando host add gx agent@10.9.9.9 -o json | jget 'd["ok"]')"
check "a read-only key reads" True "$(kssh gate-ro komando list -o json | mentions gx)"
check "a read-only key changes nothing" SSH_GATE_READ_ONLY "$(kssh gate-ro komando host rm gx -o json | code || true)"
check "exec without --read-only is not a read" SSH_GATE_READ_ONLY "$(kssh gate-ro komando exec gx -o json -- uptime | code || true)"
check "no shell: another program" SSH_GATE_REFUSED "$(kssh gate-rw id | code || true)"
check "no shell: a second command" SSH_GATE_SYNTAX "$(kssh gate-rw 'komando list; id' | code || true)"
check "no shell: a login" SSH_GATE_REFUSED "$(kssh gate-rw | code || true)"
# sftp gets ssh-gate's refusal instead of its protocol and gives up (exit 255 or 1)
check "no file copy (sftp)" True "$(if echo ls | sftp -b - -P "$E2E_SSH_DIRECT" -i "$TMP/gate-rw" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR agent@127.0.0.1 >/dev/null 2>&1; then echo False; else echo True; fi)"
check "--reveal is refused" SSH_GATE_REFUSED "$(kssh gate-rw komando secret get gx-pass --reveal -o json | code || true)"
check "a person's command is refused" SSH_GATE_REFUSED "$(kssh gate-rw komando secret passphrase -o json | code || true)"
# a secret from the key's stdin, never shown back; the vault keeps its key in vault.key here
check "a gate key sets a secret from stdin" True "$(echo -n gx-s3cret | ssh -T -p "$E2E_SSH_DIRECT" -i "$TMP/gate-rw" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR agent@127.0.0.1 komando secret set gx-pass -o json | jget 'd["ok"]')"
check "the value never comes back" False "$(kssh gate-ro komando secret get gx-pass -o json | mentions gx-s3cret)"
check "no keychain here: the vault uses vault.key" keyfile "$(gx cat /home/agent/.komando/vault.json | jget 'd["mode"]')"
# the komando a key runs is an agent: --yes on a protected server needs a person, who is not at this screen
kssh gate-rw komando host edit gx --protected --yes -o json >/dev/null || true
check "--yes from a key needs a person" False "$(kssh gate-rw komando host rm gx --yes -o json | jget 'd["ok"]' || true)"
check "the server is still there" True "$(gx komando host show gx -o json | jget 'd["ok"]')"
A1=$(gx komando audit -n 200 -o json)
check "audit: every key command, with the key's name" True "$(jget 'sum(1 for e in d["data"]["entries"] if e["command"] == "ssh-gate" and e.get("ssh_gate") in ("phone", "phone-read")) >= 12' <<<"$A1")"
check "audit: the refusals and why" True "$(jget 'any(e.get("blocked") == "SSH_GATE_READ_ONLY" and e["ok"] is False and e.get("reason") for e in d["data"]["entries"])' <<<"$A1")"
check "audit: the change names the key" True "$(jget 'any(e["command"] == "host.add" and e.get("agent") == "ssh-gate key phone" for e in d["data"]["entries"])' <<<"$A1")"
check "audit: the client's own name is kept apart" True "$(jget 'any(e.get("client_agent") == "Komando" for e in d["data"]["entries"])' <<<"$A1")"
gx sh -c "sed -i '/ssh-gate --name phone/d' ~/.ssh/authorized_keys; rm -rf ~/.komando"
docker exec "$GATE" rm -f /usr/local/bin/komando
