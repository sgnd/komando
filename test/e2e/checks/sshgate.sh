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
for k in gate-rw gate-ro gate-net gate-sh; do rm -f "$TMP/$k" "$TMP/$k.pub"; ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$TMP/$k"; done
L1=$(gx komando ssh-gate line --name phone "$(cat "$TMP/gate-rw.pub")" -o json | jget 'd["data"]["line"]')
L2=$(gx komando ssh-gate line --name phone-read --read-only "$(cat "$TMP/gate-ro.pub")" -o json | jget 'd["data"]["line"]')
check "ssh-gate line: restrict, the full path, the key" True "$(case "$L1" in 'restrict,command="/usr/local/bin/komando ssh-gate --name phone" ssh-ed25519 '*' gate-rw') echo True ;; *) echo "False: $L1" ;; esac)"
L3=$(gx komando ssh-gate line --name phone-net --read-only --network "$(cat "$TMP/gate-net.pub")" -o json | jget 'd["data"]["line"]')
L4=$(gx komando ssh-gate line --name ops --shell-access "$(cat "$TMP/gate-sh.pub")" -o json | jget 'd["data"]["line"]')
check "ssh-gate line --shell-access: restrict,pty and --shell-access" True "$(case "$L4" in 'restrict,pty,command="/usr/local/bin/komando ssh-gate --name ops --shell-access" ssh-ed25519 '*' gate-sh') echo True ;; *) echo "False: $L4" ;; esac)"
printf '%s\n%s\n%s\n%s\n' "$L1" "$L2" "$L3" "$L4" | gx sh -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
# kssh KEY [COMMAND]: log in with that key only, as the phone does
kssh() {
  local key=$1
  shift
  ssh -T -p "$E2E_SSH_DIRECT" -i "$TMP/$key" -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR agent@127.0.0.1 "$@" </dev/null
}
# ktty KEY COMMAND: the same with a terminal (ssh -tt), as a terminal app asks for.
# Its answer is the text on that terminal. ssh's own exit code (the gate's, or
# 255 when sshd gives no terminal) is dropped: run.sh has pipefail, and a refusal
# is a non-zero exit that must not fail the grep it is piped into.
ktty() {
  local key=$1
  shift
  ssh -tt -p "$E2E_SSH_DIRECT" -i "$TMP/$key" -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR agent@127.0.0.1 "$@" </dev/null 2>&1 || true
}
code() { jget 'd["error"]["code"]'; }
refusedq() { grep -Eq 'code SSH_GATE_REFUSED|"code":"SSH_GATE_REFUSED"'; } # text (a terminal) or JSON
mentions() { jget "'$1' in json.dumps(d)"; } # mentions TEXT: the JSON answer holds TEXT

check "a gate key runs komando" True "$(kssh gate-rw 'KOMANDO_AGENT=Komando komando version -o json' | jget 'd["ok"]')"
gx komando host add gx agent@10.9.9.9 -o json >/dev/null # a person sets komando up here
check "no key changes komando's servers" SSH_GATE_REFUSED "$(kssh gate-rw komando host add gy agent@10.9.9.8 -o json | code || true)"
# no key writes on this computer: a file saved over authorized_keys would give it a shell
AK0=$(gx sha256sum /home/agent/.ssh/authorized_keys)
check "no download to this computer" SSH_GATE_REFUSED "$(kssh gate-rw komando download gx /etc/hostname --to .ssh/authorized_keys --overwrite -o json | code || true)"
check "no cp to this computer" SSH_GATE_REFUSED "$(kssh gate-rw komando cp gx:/etc/hostname .bashrc -o json | code || true)"
# nor through a target that is this computer: a sqlite file, or a server at 127.0.0.1
gx komando conn add gxdb sqlite:///home/agent/gx.db -o json >/dev/null
gx komando host add gme agent@127.0.0.1 -o json >/dev/null
check "no VACUUM INTO a file here" SSH_GATE_REFUSED "$(kssh gate-rw "komando db query gxdb --write \"VACUUM INTO '/home/agent/.ssh/authorized_keys2'\" -o json" | code || true)"
check "no change on a server at 127.0.0.1" SSH_GATE_REFUSED "$(kssh gate-rw komando exec gme -o json -- id | code || true)"
# --read-only checks the words of a command, it is not a sandbox: no key, read-only or not, runs exec here
check "no read-only exec on a server at 127.0.0.1" SSH_GATE_REFUSED "$(kssh gate-ro komando exec gme --read-only -o json -- id | code || true)"
# nor a read there: logs --file and fs cat would read any file here, a private key too
check "no logs --file on a server at 127.0.0.1" SSH_GATE_REFUSED "$(kssh gate-ro "komando logs gme --file .ssh/authorized_keys --grep '^ssh' -o json" | code || true)"
check "no fs cat on a server at 127.0.0.1" SSH_GATE_REFUSED "$(kssh gate-ro komando fs cat gme /etc/hostname -o json | code || true)"
gx komando conn add gxpg 'postgres://agent@db.example.com/app?host=127.0.0.1' -o json >/dev/null
check "no change on a conn whose ?host= is 127.0.0.1" SSH_GATE_REFUSED "$(kssh gate-rw "komando db query gxpg --write 'SELECT 1' -o json" | code || true)"
check "no authorized_keys2" False "$(gx sh -c 'test -e /home/agent/.ssh/authorized_keys2 && echo True || echo False')"
check "authorized_keys is as it was" "$AK0" "$(gx sha256sum /home/agent/.ssh/authorized_keys)"
check "a read-only key reads" True "$(kssh gate-ro komando list -o json | mentions gx)"
check "a read-only key changes nothing" SSH_GATE_READ_ONLY "$(kssh gate-ro komando pkg install gx htop -o json | code || true)"
check "exec without --read-only is not a read" SSH_GATE_READ_ONLY "$(kssh gate-ro komando exec gx -o json -- uptime | code || true)"
# a read key stays off the network unless its line has --network
check "ssh-gate status: a read key without network" "True False" "$(kssh gate-ro komando ssh-gate status -o json | jget 'str(d["data"]["read_only"]) + " " + str(d["data"]["network"])')"
check "ssh-gate status: a read key with --network" "True True" "$(kssh gate-net komando ssh-gate status -o json | jget 'str(d["data"]["read_only"]) + " " + str(d["data"]["network"])')"
check "a read key runs no program" SSH_GATE_NETWORK_REQUIRED "$(kssh gate-ro komando exec gx --read-only -o json -- curl -s https://example.com | code || true)"
check "a read key does not dial a website" SSH_GATE_NETWORK_REQUIRED "$(kssh gate-ro komando cert check https://example.com -o json | code || true)"
check "ssh-gate status: a shell key" "False True" "$(kssh gate-sh komando ssh-gate status -o json | jget 'str(d["data"]["read_only"]) + " " + str(d["data"]["shell_access"])')"
check "a shell key opens no shell without a terminal" SSH_GATE_REFUSED "$(kssh gate-sh komando shell gx | code || true)"
check "a shell key opens no shell on this computer" True "$(ktty gate-sh komando shell gme | refusedq && echo True || echo False)"
check "a shell key sends komando shell SERVER only" True "$(ktty gate-sh komando shell gx -o json | refusedq && echo True || echo False)"
# a line without pty (every key but a --shell-access one): sshd gives no terminal, so the call never starts
check "a key without --shell-access gets no terminal" True "$(ktty gate-rw komando shell gx | grep -q 'PTY allocation request failed' && echo True || echo False)"
check "a key without --shell-access opens no shell" SSH_GATE_REFUSED "$(kssh gate-rw komando shell gx | code || true)"
# a server the gate's komando reaches (the bastion, on the same network), its host key pinned by a person here
echo -n agentpass | gx komando secret set gsh-pass -o json >/dev/null
gx komando host add gsh agent@bastion --password-ref secret:gsh-pass -o json >/dev/null
gx komando test gsh -o json >/dev/null
# kshell KEY SERVER: komando shell SERVER through the gate, in a 24x80 terminal that
# grows to 33x111 once the shell is up; then it types a line and exit. Prints the screen.
kshell() {
  python3 -I - "$TMP/$1" "$E2E_SSH_DIRECT" "$2" <<'PY' || true
import fcntl, os, pty, select, struct, sys, termios, time
key, port, server = sys.argv[1:4]
pid, fd = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    os.execvp("ssh", ["ssh", "-tt", "-p", port, "-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                      "-o", "PreferredAuthentications=publickey", "-o", "StrictHostKeyChecking=no",
                      "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "agent@127.0.0.1", "komando shell " + server])
out, start, typed = b"", time.time(), False
while time.time() - start < 60:
    if not typed and (b"$ " in out or time.time() - start > 20):
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 33, 111, 0, 0))  # the key's terminal grows
        time.sleep(1)
        os.write(fd, b"stty size; echo gate-$((6*7)); exit\r")
        typed = True
    if select.select([fd], [], [], 0.2)[0]:
        try:
            b = os.read(fd, 4096)
        except OSError:
            break
        if not b:
            break
        out += b
os.waitpid(pid, 0)
sys.stdout.write(out.decode(errors="replace"))
PY
}
SH=$(kshell gate-sh gsh)
check "a shell key opens the shell through the gate" True "$(grep -q 'gate-42' <<<"$SH" && echo True || echo False)"
check "the key's new terminal size reaches the server" True "$(grep -q '33 111' <<<"$SH" && echo True || echo False)"
gx komando policy create 'gate-e2e-never' -o json >/dev/null
check "no shell while a deny rule of your own is set" True "$(ktty gate-sh komando shell gsh | refusedq && echo True || echo False)"
gx komando policy remove 'gate-e2e-never' --yes -o json >/dev/null
check "a read key with --network may" True "$(kssh gate-net komando exec gx --read-only -o json -- uptime | jget '(d.get("error") or {}).get("code") != "SSH_GATE_NETWORK_REQUIRED"')"
check "no shell: another program" SSH_GATE_REFUSED "$(kssh gate-rw id | code || true)"
check "no shell: a second command" SSH_GATE_SYNTAX "$(kssh gate-rw 'komando list; id' | code || true)"
check "no shell: a login" SSH_GATE_REFUSED "$(kssh gate-rw | code || true)"
# sftp gets ssh-gate's refusal instead of its protocol and gives up (exit 255 or 1)
check "no file copy (sftp)" True "$(if echo ls | sftp -b - -P "$E2E_SSH_DIRECT" -i "$TMP/gate-rw" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR agent@127.0.0.1 >/dev/null 2>&1; then echo False; else echo True; fi)"
check "--reveal is refused" SSH_GATE_REFUSED "$(kssh gate-rw komando secret get gx-pass --reveal -o json | code || true)"
check "a person's command is refused" SSH_GATE_REFUSED "$(kssh gate-rw komando secret passphrase -o json | code || true)"
check "no key sets a secret" SSH_GATE_REFUSED "$(kssh gate-rw komando secret set gx-other -o json | code || true)"
# a secret a person stored, never shown to a key; the vault keeps its key in vault.key here
check "a person sets a secret here" True "$(echo -n gx-s3cret | gx komando secret set gx-pass -o json | jget 'd["ok"]')"
check "the value never comes back" False "$(kssh gate-ro komando secret get gx-pass -o json | mentions gx-s3cret)"
check "no keychain here: the store's key is a file" True "$(gx test -f /home/agent/.komando/store.key && echo True || echo False)"
# the komando a key runs is an agent: --yes on a protected server needs a person, who is not at this screen
gx komando host edit gx --protected -o json >/dev/null
check "--yes from a key needs a person" PROTECTED_TARGET "$(kssh gate-rw komando exec gx --yes -o json -- touch /tmp/gx | code || true)"
check "a shell key opens no shell on a protected server" True "$(ktty gate-sh komando shell gx | refusedq && echo True || echo False)"
A1=$(gx komando audit list -n 200 -o json)
check "audit: every key command, with the key's name" True "$(jget 'sum(1 for e in d["data"]["entries"] if e["command"] == "ssh-gate" and e.get("ssh_gate") in ("phone", "phone-read", "phone-net")) >= 14' <<<"$A1")"
check "audit: what no key may write here" True "$(jget 'any(e.get("blocked") == "SSH_GATE_REFUSED" and e.get("runs") == "download" for e in d["data"]["entries"])' <<<"$A1")"
check "audit: the refusals and why" True "$(jget 'any(e.get("blocked") == "SSH_GATE_READ_ONLY" and e["ok"] is False and e.get("reason") for e in d["data"]["entries"])' <<<"$A1")"
check "audit: what the key's komando did names the key" True "$(jget 'any(e["command"] != "ssh-gate" and e.get("agent") == "ssh-gate key phone" for e in d["data"]["entries"])' <<<"$A1")"
check "audit: the shell went through the gate, with sshd's terminal" True "$(jget 'any(e.get("ssh_gate") == "ops" and e.get("runs") == "shell" and e["ok"] is True and e.get("shell_access") is True for e in d["data"]["entries"])' <<<"$A1")"
check "audit: a key's shell session starts, with the key and the server" True "$(jget 'any(e.get("session") == "start" and e.get("ssh_gate") == "ops" and e.get("hosts") == ["gsh"] for e in d["data"]["entries"])' <<<"$A1")"
check "audit: and ends, with how long and why" True "$(jget 'any(e.get("session") == "end" and e.get("ssh_gate") == "ops" and e.get("hosts") == ["gsh"] and e.get("end") == "exit" and isinstance(e.get("duration_ms"), int) for e in d["data"]["entries"])' <<<"$A1")"
check "audit: the client's own name is kept apart" True "$(jget 'any(e.get("client_agent") == "Komando" for e in d["data"]["entries"])' <<<"$A1")"
gx sh -c "sed -i '/ssh-gate --name phone/d; /ssh-gate --name ops/d' ~/.ssh/authorized_keys; rm -rf ~/.komando"
docker exec "$GATE" rm -f /usr/local/bin/komando
