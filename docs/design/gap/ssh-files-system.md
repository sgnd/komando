# komando feature gap analysis: SSH, fleet, files, jobs, tunnels, keys, hosts, system modules

> **Snapshot of `feat/v0.3` (commit 4784fc9), 2026-11-02.** Many MISSING and
> PARTIAL rows below were done in Phases 1–5 and the built-in work, and no
> feature needs kubectl, psql, the aws CLI, openvpn or openconnect any more.
> Current status: [README.md](README.md#still-open).

Written 2026-11-02 on branch `feat/v0.3` (commit `4784fc9`). Sources: `bin/komando --help`
(all commands), code in `internal/cli` and `internal/sshx`, `docs/design/{vision,ux,network}.md`,
`docs/features/*.md`. No server was contacted.

**How to read the status**

- **PRESENT**: a command/flag handles it in a structured and safe way.
- **PARTIAL**: part of it exists; what is missing is named in the notes column.
- **MISSING**: no first-class support. "possible via exec" means it can still be done
  through `komando exec` (the raw, audited path, treated as *write*, subject to policy), but
  without structured output, idempotency, or a meaningful dry-run.
- **NON-GOAL**: excluded by `docs/design/vision.md` (the quoted reason is included).

**Priority** (for gaps only): **P1** = daily need / security / blocks agent workflows;
**P2** = useful; **P3** = niche. PRESENT rows are marked "–".

Non-goal quotes used repeatedly (vision.md, "Non-goals" and "Technical rules"):

- NG-TUI: "GUI, TUI, plugin system, or daemon/server. komando stays a pure CLI."
- NG-IaC: "Infrastructure as Code, cloud provisioning, or GitOps."
- NG-POOL: "No pool and no daemon. One connection per command."
- NG-MON: "Continuously running monitoring or alerting."
- NG-FULL: "Replacing full tools (...). komando handles 80% of daily work safely."
- NG-NET (network.md, Security): "komando never changes the laptop's routes, DNS, or firewall."

---

## 1. SSH connection and authentication (OpenSSH `ssh`, `ssh_config`)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Login with a private key file | ssh `-i`, `IdentityFile` | PRESENT | `host add/edit --identity PATH`, `--key NAME` (keychain) | – |
| Use ssh-agent (including 1Password/Secretive agent via `SSH_AUTH_SOCK`) | ssh-agent, `IdentityAgent` | PRESENT | `internal/sshx/client.go` reads `SSH_AUTH_SOCK`; `doctor` checks ssh-agent | – |
| Automatic fallback to `~/.ssh/id_ed25519/id_ecdsa/id_rsa` | ssh default identities | PRESENT | `client.go` (only when there is no `--key/--identity`) | – |
| Encrypted key (passphrase from the vault) | ssh + ssh-agent | PRESENT | `key add/edit --passphrase-ref secret:NAME`; without one, the agent's copy of an encrypted `--key`/`--identity` is used, found by its public key | – |
| Password login (stored safely) | ssh + sshpass | PARTIAL | password login works via refs `secret:/env:/file:/op:///vault:/aws-sm:/gcp-sm:` (password + keyboard-interactive). But `host add/edit` does not validate the ref format: `--password-ref hunter2` (also `--sudo-ref`) is accepted, stored in plain text in `state.json` and printed in the output. `conn add` and `vpn add` already reject it via `vault.ValidRef`; host does not yet | P1 |
| Keyboard-interactive / SSH 2FA (Google Authenticator OTP, Duo) | ssh, Teleport | PRESENT | a person at a terminal is asked the password and the code (sshx/auth.go `passwordLogin`); for an AI agent `komando login HOST` keeps a person's login for `login_for` (8h) and its commands use it (sshx/held.go, cli/login_ssh.go); without one the login stops with `AUTH_FAILED` quoting the question, so no wrong code counts against the account | — |
| `IdentitiesOnly` (limit the keys tried, avoid "Too many authentication failures") | ssh_config | PARTIAL | when `--key/--identity` is set, default keys are not tried; the explicit key is tried first, then all ssh-agent keys are still tried after it (no option to turn off the agent per host) | P2 |
| Per-host `IdentityAgent` (a different agent per host) | ssh_config | MISSING | only the global `SSH_AUTH_SOCK` | P3 |
| Jump host / bastion (`-J`, `ProxyJump`), chains of many hops | ssh, Teleport | PRESENT | `--via bastion,db1` for host and conn; `--jump` alias; imported from `ProxyJump` | – |
| `ProxyCommand` (e.g. `aws ssm start-session`, `cloudflared access ssh`, `gcloud compute start-iap-tunnel`) | ssh_config, Teleport | MISSING | `parseSSHConfig` ignores `ProxyCommand` (without reporting it); no SSM/IAP/Cloudflare Access transport. Common in clouds without public IPs | P2 |
| Access via VPN per connection (many VPNs at once) | tsh, Tailscale SSH, VPN clients | PRESENT | `vpn add` (wireguard, tailscale, openconnect family, openvpn, socks, system) + `--via vpn,bastion` | – |
| Tailscale SSH (auth based on tailnet identity, no key) | Tailscale SSH | PARTIAL | `vpn add ... tailscale` provides the path, but komando still needs an auth method (`NO_AUTH` when there is no key/agent/password) | P3 |
| SSH certificate login (user cert signed by a CA, `CertificateFile`) | OpenSSH CA, Teleport, Vault SSH, step-ca | PARTIAL | a user cert already loaded in ssh-agent is used (the agent's signer carries its cert); there is no `CertificateFile`/cert flag per host or per key, so file-based certs cannot be used. Important for teams that use short-lived certs | P2 |
| Agent forwarding (`-A`, `ForwardAgent`) — e.g. `git pull` from the server using the laptop's key | ssh | MISSING | no `agent.ForwardToAgent` in the code. If added, it must be opt-in per host + audited (risky) | P2 |
| X11 forwarding (`-X/-Y`) | ssh | MISSING | not in the code; remote GUI is outside the 80% daily focus | P3 |
| Keepalive (`ServerAliveInterval`) | ssh_config, autossh | PRESENT | `keepalive@komando` automatic in `client.go`; the interval cannot be set per host | – |
| Connect timeout | ssh `ConnectTimeout` | PRESENT | `--connect-timeout`, `config set connect_timeout` (applies to the whole via/VPN chain) | – |
| Per-host cipher/KEX/HostKeyAlgorithms choice (old servers) | ssh_config | MISSING | no option; legacy servers (RSA-SHA1, DH group1) can fail with no way out | P3 |
| Compression (`-C`) for slow links | ssh | MISSING | none | P3 |
| Connection multiplexing (`ControlMaster/ControlPersist`) across commands | ssh_config | NON-GOAL | NG-POOL: "No pool and no daemon. One connection per command." One command uses one connection per host | – |
| Automatic retry on temporary connection failure | Ansible `retries`, pssh | MISSING | `exec`/modules do not retry; only tunnels reconnect | P2 |
| IPv6, non-standard port | ssh | PRESENT | `user@[addr]:port`, `--port`; IPv6 edge cases noted in ux.md | – |
| Ad-hoc host without registering it | ssh `user@host` | PRESENT | target `user@addr:port` | – |
| `Match` blocks in ssh_config (Match host/user/exec) | ssh_config | PARTIAL | `host import` reads `Include`, wildcard `Host` as defaults, but `Match` is silently ignored (`cur = nil`) — this breaks ux.md §9 "Unsupported fields are reported, not silently dropped" | P2 |
| Report unsupported ssh_config directives (`ProxyCommand`, `LocalForward`, `ForwardAgent`, `CertificateFile`, ...) on import | ssh_config | MISSING | `host import` only reads Host/HostName/User/Port/IdentityFile/ProxyJump/Include; the rest is dropped without a warning | P2 |
| Print the equivalent OpenSSH command (interop) | — | PRESENT | `host ssh-command NAME` | – |
| Export the inventory to `ssh_config` (so ssh/scp/VS Code Remote use the komando inventory) | Termius, Teleport `tsh config` | MISSING | only per host (`host ssh-command`) and JSON (`host export`) | P3 |
| Windows hosts (OpenSSH on Windows / WinRM / PowerShell) | Ansible winrm, Salt | MISSING | host model = "SSH (Linux)" (vision.md); `exec` to Windows OpenSSH may work, system modules do not | P3 |

## 2. SSH keys and certificates (`ssh-keygen`, `ssh-agent`, `ssh-copy-id`, SSH CA)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Create an ed25519 / RSA key pair | ssh-keygen | PRESENT | `key gen NAME --type ed25519\|rsa --bits --comment` | – |
| Create an ECDSA key | ssh-keygen `-t ecdsa` | MISSING | `--type` is only ed25519/rsa (an existing ECDSA key can be added with `key add`) | P3 |
| FIDO2 hardware key (`ed25519-sk`, YubiKey) | ssh-keygen `-t ed25519-sk` | PARTIAL | only when the sk key is in ssh-agent; `key gen` cannot create one | P3 |
| Passphrase when creating a key | ssh-keygen `-N` | MISSING | `key gen` writes the private key unencrypted (0600, `ssh.MarshalPrivateKey`). Secure-by-default suggests a `--passphrase-ref` option | P2 |
| Register an existing key | ssh-add / ssh_config | PRESENT | `key add NAME PATH [--passphrase-ref]` (the file is not copied) | – |
| Show public key and fingerprint | ssh-keygen `-y`, `-l` | PRESENT | `key show`, `key list` (SHA256 fingerprint stored in state) | – |
| Install a public key on a server (idempotent) | ssh-copy-id, Ansible `authorized_key` | PRESENT | `key deploy KEY TARGET [--set-default]`, many hosts in parallel | – |
| Revoke / remove a public key from `authorized_keys` on many servers (offboarding, rotation) | Ansible `authorized_key state=absent`, Teleport | MISSING | `key deploy` and `user add --key` only add. When a team member leaves or a key leaks, there is no command for many servers at once; per host you can run `fs replace HOST ~/.ssh/authorized_keys --old '<key line>' --new '' --backup` (one host per command, the line must be copied exactly, no lookup from the keychain) | P1 |
| List `authorized_keys` per server/user (audit who can log in) | Ansible, Teleport | MISSING | possible via `fs cat ~/.ssh/authorized_keys`, without parsing/fingerprints and without matching against the keychain | P2 |
| End-to-end key rotation (deploy new → switch → revoke old) | Teleport, Vault SSH | PARTIAL | the first two steps exist (`key deploy --set-default`), the revoke step does not (see the row above) | P2 |
| Add a key to ssh-agent | ssh-add | MISSING | komando reads the agent but does not add to it; not needed because komando loads keys itself | P3 |
| `authorized_keys` options (`from=`, `command=`, `no-port-forwarding`) | Ansible `authorized_key key_options` | MISSING | keys are installed without restrictions; useful for restricted automation/agent keys | P3 |
| SSH CA: sign user/host certs | ssh-keygen `-s`, step-ca, Vault SSH | MISSING | komando cannot act as a CA; you can use ssh-keygen on the laptop | P3 |
| Automatic short-lived cert per session | Teleport `tsh login`, Vault SSH | MISSING | needs a CA server; close to the NG-TUI list ("daemon/server") if komando had to be the CA | P3 |

## 3. Host keys and server trust (`known_hosts`, `ssh-keyscan`)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Host key policy accept-new / strict / off | ssh `StrictHostKeyChecking` | PRESENT | `--host-key-policy`, `config set host_key_policy` (`off` needs `--yes`, `SAFETY_SETTING`) | – |
| Reject a changed host key | ssh | PRESENT | `HOSTKEY_MISMATCH`, never skipped automatically | – |
| Fetch & pin the host key (keyscan), also behind a bastion | ssh-keyscan | PRESENT | `host trust NAME` (fetched the way komando reaches the server: directly, `--via`, VPN or proxy command; jump hosts are checked under `host_key_policy`, the target is only scanned, never logged in to) | – |
| Forget / replace the key after a server is rebuilt | ssh-keygen `-R` | PRESENT | `host trust NAME --reset` | – |
| Import the existing `~/.ssh/known_hosts` (avoid repeating TOFU) | — | MISSING | komando uses its own `~/.komando/known_hosts`; hosts already trusted by OpenSSH are trusted again via TOFU | P2 |
| Host certificate / `@cert-authority` in known_hosts | OpenSSH, Teleport | PARTIAL | the known_hosts parser (x/crypto) reads `@cert-authority` lines when written by hand into `~/.komando/known_hosts`, but there is no command to add a CA. Without that line, a host that presents a host cert fails (`CONNECT_FAILED`: "no authorities for hostname"), instead of TOFU | P2 |
| Verify the fingerprint from another source (DNS SSHFP, out-of-band) | ssh `VerifyHostKeyDNS` | MISSING | `host trust` does not accept `--fingerprint SHA256:...` to compare before pinning | P2 |
| List pinned host keys | `ssh-keygen -F`, Termius known hosts | PARTIAL | the fingerprint appears in the `host trust` output; there is no list command (the `known_hosts` file can be read by hand) | P3 |

## 4. Inventory and host management (Termius, Warp, Ansible inventory, Salt, ClusterSSH)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Add/edit/remove/show hosts | Termius, Ansible inventory | PRESENT | `host add/edit/rm/show`, `--rename` updates references | – |
| Groups, tags, key=value labels, notes | Termius tags, Ansible groups/vars | PRESENT | `--group/--tag/--label/--notes`; `group add/rm/list` | – |
| Nested groups (group of groups / `children`) | Ansible | MISSING | the selector `@a,@b` can combine, but there is no parent group definition | P3 |
| Selectors: name, glob, `@group`, `tag:`, `label:`, `kind:`, `all`, combinations, `!` | Ansible patterns, Salt targeting, pssh `-h` | PRESENT | ux.md §2; "did you mean" for typos | – |
| Target by facts (os=ubuntu, arch, version) | Salt grains targeting (`-G`), Ansible `group_by` | MISSING | labels must be filled in by hand | P3 |
| Per-host variables (env, default user, sudo) | Ansible host_vars | PRESENT | `--env KEY=VALUE` exported to every command, `--user`, `--sudo-ref`, `config set default_user` | – |
| Per-host variables for recipes/templates (`{{app}}` per host) | Ansible host_vars | MISSING | `recipe run --var` is the same for all hosts; labels cannot be used as `{{var}}` values | P3 |
| Mark production hosts (need confirmation) | Teleport labels+RBAC, Termius — | PRESENT | `--protected`; protected follows the address | – |
| Import `~/.ssh/config` | Termius, Warp | PRESENT | `import ssh-config` / `host import` (Include, ProxyJump, wildcard) — see the `Match` gap in §1 | – |
| Import an Ansible inventory (INI/YAML) | — | MISSING | not among the `import` sources; many teams already have an Ansible inventory | P2 |
| Import from Termius / Royal TSX / MobaXterm / PuTTY | Termius export | MISSING | vision.md lists `termius` in the migration table but it is not implemented yet | P2 |
| Dynamic inventory from the cloud (EC2/DO/Hetzner tags) | Ansible dynamic inventory, Salt cloud | MISSING | vision.md: "Cloud VMs (DigitalOcean, Hetzner, AWS EC2)" candidate after v1.0; provisioning = NG-IaC, but *reading* the VM list is not provisioning | P2 |
| Export / move to another computer | Termius sync | PRESENT | `export`, `import komando`, `host export --target` | – |
| Sync the inventory across devices/teams (cloud) | Termius cloud sync, Teleport | NON-GOAL | NG-TUI "... daemon/server"; the existing path: `export`/`import` files | – |
| Check that login works on all hosts | `ansible -m ping`, Termius | PRESENT | `test TARGET` (host, conn, VPN) | – |
| Check that sudo works during `test` | `ansible -b -m ping` | PARTIAL | `test` already reports `sudo_nopasswd` (`sudo -n true`); the password from `--sudo-ref` is not tested, so a wrong sudo-ref is only noticed on the first command | P2 |
| Connection history / "recent hosts" | Termius, Warp | PARTIAL | `audit --target` gives history per host; no "last used" list in `list` | P3 |

## 5. Remote execution and fleet (pssh, ClusterSSH, Fabric, pyinfra, Ansible ad-hoc, Salt)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Run a command on one / many hosts in parallel | pssh, `ansible -m shell`, `salt cmd.run`, Fabric | PRESENT | `exec TARGET -- CMD`, `-P/--parallel`, results per host in order | – |
| Structured output per host (stdout, stderr, exit, duration) + worst exit code | Ansible JSON callback, Salt `--out json` | PRESENT | JSON envelope, `data.results[]`, `summary`, exit 5 if any is non-zero | – |
| Stream output while running | pssh `-P`, Fabric | PRESENT | `--stream` (NDJSON) | – |
| Stop after the first failure | Ansible `any_errors_fatal` | PRESENT | `--fail-fast` | – |
| Rolling / staged batches (`serial: 2` / `25%`), pause & health check between batches | Ansible `serial`, Fabric, Salt `--batch-size` | PARTIAL | `-P 1 --fail-fast` = one at a time; no percentage batch size, pause, or health check between batches (important for restarting a fleet without downtime) | P2 |
| Group identical output (500 hosts → "480 hosts: OK") | clush `-b`, `ansible -o`, dshbak | MISSING | output per host is always full; expensive for an agent on a large fleet | P2 |
| Save output per host to a folder | pssh `-o/-e` | MISSING | JSON stdout can be processed; `--max-output` limits it | P3 |
| Non-interactive sudo, sudo with a password from the vault, sudo -u | Ansible `become`, Fabric `sudo` | PRESENT | `--sudo`, `--sudo-user`, host `--sudo-ref` | – |
| `su`/`doas`/`pbrun` as become method | Ansible `become_method` | MISSING | sudo only | P3 |
| Env vars and working dir | Fabric `cd`, `env` | PRESENT | `-e KEY=VAL`, `-C DIR`, host `--env` | – |
| stdin from a local file | pssh `-I`, ssh `< file` | PRESENT | `--stdin-file FILE\|-` | – |
| Run a local script on the remote without copying it | Ansible `script`, pyinfra, `ssh 'bash -s' < x` | PRESENT | `script TARGET FILE --arg --interpreter` | – |
| PTY for tools that ask for one | ssh `-t` | PRESENT | `--pty` (non-interactive) | – |
| Dry-run / check mode | `ansible --check`, pyinfra `--dry` | PRESENT | global `--dry-run` (shows the command + whether policy blocks it) | – |
| Guardrails for dangerous commands | — (Teleport only has RBAC) | PRESENT | `policy list/check/deny/allow`, `--allow-dangerous` | – |
| Read-only declaration for protected hosts | — | PRESENT | `--read-only` | – |
| Per-host time limit and output limit | pssh `-t`, Ansible `timeout` | PRESENT | `--timeout`, `--max-output` | – |
| Async execution limit (`async`/`poll`) | Ansible async | PRESENT | via `job start` (see §7) | – |
| Interactive to many terminals at once (type once, all hosts) | ClusterSSH, tmux synchronize-panes, Termius multi-exec | NON-GOAL | NG-TUI: "GUI, TUI ... komando stays a pure CLI." Parallel `exec` already covers the non-interactive need | – |
| Playbook / declarative state (multi-step orchestration, handlers) | Ansible playbook, Salt state, pyinfra deploy | NON-GOAL | NG-IaC: "Infrastructure as Code, cloud provisioning, or GitOps." | – |
| Local commands on the laptop as part of the flow | Fabric `local` | MISSING | not explicitly excluded by vision.md ("Non-goals" does not mention local commands); low value because humans/agents already have a local shell | P3 |

## 6. Interactive shell and sessions (ssh, mosh, Teleport, Termius)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Interactive login shell (PTY, resize) | ssh, Termius, tsh ssh | PRESENT | `shell TARGET` (alias `ssh`, `connect`), `WindowChange` handled, via `--via`/VPN | – |
| Run an interactive command with a TTY (`ssh -t host htop`, `docker exec -it`, `sudo -i`) | ssh `-t host CMD` | MISSING | `shell` only opens a login shell; `exec --pty` is not interactive | P2 |
| Confirmation/marker when opening a shell to a protected host | Teleport | PARTIAL | `shell` is audited (only "opened"); no warning/confirmation for protected hosts | P2 |
| Session recording / replay | Teleport, `script`, asciinema | MISSING | the audit only records that the session started, not its content | P3 |
| Roaming / connection that survives drops (Wi-Fi change, laptop sleep) | mosh, Eternal Terminal | MISSING | `job` exists for long work; nothing for a human shell | P3 |
| Escape sequence (`~.`), switch to port-forward mid-session | ssh | MISSING | niche | P3 |
| Share a session / join someone else's session | Teleport, tmate | NON-GOAL | NG-TUI ("daemon/server") | – |

## 7. Long-running jobs (tmux/screen/nohup, Ansible async)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Start a detached process that survives an SSH drop | nohup, setsid, tmux, screen | PRESENT | `job start TARGET -- CMD` (setsid nohup, log in `~/.komando/jobs/<id>`), many hosts | – |
| Status, exit code, runtime, log tail | `jobs`, tmux | PRESENT | `job status`, `job list --refresh --target` | – |
| Read logs incrementally | `tail -f` | PRESENT | `job logs --offset/next_offset`, `--tail`, `--max-bytes` | – |
| Wait for completion with a time limit | Ansible `async_status`, `wait` | PRESENT | `job wait --wait-timeout --interval` | – |
| Stop (signal to the process group) | kill | PRESENT | `job kill --signal TERM\|KILL\|INT\|HUP` | – |
| Clean up jobs | — | PRESENT | `job rm [--keep-remote]` | – |
| Run a local script as a job | Ansible `script` + async | MISSING | `job start` only accepts a command; long scripts (`deploy.sh`) must be uploaded first (`upload` + `job start`) | P2 |
| Maximum job duration (kill automatically after X) | `timeout`, Ansible `async: N` | MISSING | possible via the command `timeout 2h ...` inside the job | P3 |
| Attach interactively to a job / send input | tmux attach, screen -r | MISSING | jobs have no stdin/TTY | P3 |
| Notification when a job finishes | — | NON-GOAL | NG-MON ("continuously running monitoring or alerting"); `job wait` is enough | – |
| Slow modules automatically become jobs (`pkg upgrade`, `db dump` on the server) | Ansible async per task | MISSING | `pkg upgrade` runs synchronously with a default `--timeout` of 5m; the agent must remember to use `job start` + a raw command | P2 |

## 8. Tunnels and forwarding (ssh `-L/-R/-D`, autossh, sshuttle)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Local forward `-L` | ssh | PRESENT | `tunnel start HOST -L [bind:]LPORT:RHOST:RPORT` | – |
| Remote forward `-R` | ssh | PRESENT | `tunnel start HOST -R ...` | – |
| SOCKS5 `-D` | ssh | PRESENT | `tunnel start HOST -D [bind:]PORT` | – |
| Tunnel to a conn by name (free local port) | Teleport `tsh proxy db`, Termius | PRESENT | `tunnel start app-db [--port 15432]` via `--via`/VPN | – |
| Background tunnel, list, stop | autossh `-f`, Termius | PRESENT | `tunnel list` (liveness, prune), `tunnel stop [--all]` | – |
| Automatic reconnect when SSH drops | autossh | PARTIAL | `connMgr` reconnects local/dynamic forwards; a code comment says only local/dynamic, not remote forward (`-R`) | P2 |
| Default bind to 127.0.0.1; binding to another address needs `--yes` | ssh `GatewayPorts` | PARTIAL | the default 127.0.0.1 is already correct, but `-L 0.0.0.0:8080:...` is accepted without `--yes` — network.md: "Tunnels and proxies only listen on 127.0.0.1, unless given `--bind` (needs `--yes`)". This exposes an internal DB to the LAN without confirmation | P1 |
| Tunnel survives a laptop reboot (launchd/systemd service) | autossh + systemd | NON-GOAL | NG-POOL/NG-TUI ("daemon"); a tunnel is only a temporary background process | – |
| Tunnel lifetime limit (stop automatically after X / when idle) | Teleport TTL | MISSING | VPN has `vpn_idle`, tunnels do not; a tunnel someone forgot to stop keeps access open | P3 |
| Transparent "VPN over SSH" (changes laptop routes) | sshuttle | NON-GOAL | NG-NET: "komando never changes the laptop's routes, DNS, or firewall." Alternative: `tunnel -D` + `vpn add ... socks` | – |
| Forward a Unix socket (`-L /tmp/x.sock:/var/run/docker.sock`) | ssh | MISSING | the spec is host:port only | P3 |

## 9. Files and transfer (scp, sftp, rsync, Ansible copy/fetch/synchronize/get_url/unarchive)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Upload a file to many servers in parallel | scp, pssh `pscp`, Ansible `copy` | PRESENT | `upload TARGET FILE [DEST]`, `cp SRC TARGET:PATH`, sha256 reported | – |
| Upload with mode, create parent folders, install via sudo | Ansible `copy mode/become` | PARTIAL | `--mode`, `-p`, `--sudo` only for a single file (folder + sudo is rejected), no `--owner` on upload (it exists on `fs write`) | P2 |
| Download from many servers (a folder per server) | scp, Ansible `fetch` | PRESENT | `download @web PATH --to DIR` → `DIR/<host>/...` | – |
| Download root-owned files (`/var/log/...`, `/etc/shadow`-like) | Ansible `fetch become` | MISSING | `download` has no `--sudo`; `fs cat --sudo` is only for text (binary content is dropped) with a default limit of 1 MiB (`--max-bytes`) | P2 |
| Recursive folders | scp `-r`, sftp | PRESENT | `-r` on upload/download | – |
| Do not overwrite without `--overwrite` | scp `-n`, rsync `--ignore-existing` | MISSING | upload to a server overwrites silently; download from a server opens the local file with `O_TRUNC` (only storage is "never overwrite"). This contradicts the ux.md edge case: "Destination file already exists: not overwritten without `--overwrite`" | P1 |
| Atomic download (tmp then rename; no half-written files) | rsync | MISSING | `fetchFile` writes straight to the destination. ux.md: "Interrupted download: write to a temporary file then rename" | P1 |
| Large files without loading them into memory (stream) | scp, rsync | PARTIAL | download and `upload -r` already stream (`io.Copy`), but single-file upload uses `os.ReadFile` (the whole file into RAM) then `writeRemote`; a single GB-sized DB dump/ISO/backup file can run out of memory | P1 |
| Progress on stderr for large files | scp, rsync `--progress` | MISSING | ux.md edge case: "very large file (progress on stderr)" | P2 |
| Resume an interrupted transfer | rsync `--partial`, sftp `reget` | MISSING | not available for host SFTP; FTP storage has no resume either | P3 |
| Delta sync (only what changed), `--delete`, `--exclude` | rsync, Ansible `synchronize` | MISSING | `upload -r` copies all files again, does not delete old files, no exclude. Deploying a site/folder is daily work; the vision lists the verb `sync` | P1 |
| Transfer dry-run that shows which files will change | rsync `-n -i` | PARTIAL | `--dry-run` exists on `cp`, but it does not compare content (no changed/unchanged list) | P2 |
| Skip the upload when the content is the same (idempotent) | Ansible `copy` (checksum) | PARTIAL | `fs write --from FILE --if-changed` for a single file; `upload`/`cp` do not | P2 |
| Keep symlinks | rsync `-l`, scp | MISSING | recursive upload/download skips non-regular files (symlinks) without reporting | P2 |
| Keep modification times (`-p`) | scp `-p`, rsync `-t` | MISSING | mode is kept, mtime is not | P3 |
| Compression during transfer | rsync `-z`, scp `-C` | MISSING | SFTP without compression; compress by hand (`tar czf`) via exec | P3 |
| Copy server → server (remote to remote) | scp `host1:a host2:b`, rsync | MISSING | you must download then upload | P3 |
| Copy a file within one server | Ansible `copy remote_src` | MISSING | `fs mv` exists, `fs cp` does not; possible via exec `cp` | P3 |
| Download a URL directly on the server (with checksum) | Ansible `get_url`, `curl -o` | MISSING | possible via exec `curl -o`; the curl-pipe-sh pattern is blocked by policy (good) | P2 |
| Extract an archive on the server | Ansible `unarchive` | MISSING | possible via exec `tar xzf` | P3 |
| Interactive sftp-shell-style browsing | sftp, Cyberduck | NON-GOAL | NG-TUI; `fs ls/stat/cat` covers the non-interactive version | – |

## 10. File and config editing (Ansible lineinfile/blockinfile/template/file)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Read a file (head/tail/line numbers, byte limit, sudo) | cat, Ansible `slurp` | PRESENT | `fs cat --head --tail --line-numbers --max-bytes --sudo` | – |
| Replace exact text / regex, fail when missing/ambiguous, with diff & backup | Ansible `replace`, `sed -i` | PRESENT | `fs replace --old --new [--regex --all --backup]`; `--dry-run` shows a diff | – |
| Ensure a line exists (add it if missing, replace it if it matches a regex) | Ansible `lineinfile` | PARTIAL | `fs replace --regex` fails when nothing is found; `fs write --append` is not idempotent. Needs two steps and logic in the agent (e.g. `PasswordAuthentication no` in sshd_config) | P2 |
| Delete matching lines | Ansible `lineinfile state=absent` | PARTIAL | `fs replace --regex` with a pattern that also captures `\n` can delete whole lines (`--new ''` without it leaves a blank line), but it fails with `NO_MATCH` when the line is already gone (not idempotent) | P3 |
| Managed block with markers (`# BEGIN komando x` / `# END`) | Ansible `blockinfile` | MISSING | the marker pattern is already used by `cron` (`# komando:<id>`), not yet for files | P2 |
| Write a file atomically, mode/owner, backup, idempotent | Ansible `copy content=` | PRESENT | `fs write --content/--from/stdin --mode --owner --backup --if-changed --parents` | – |
| Diff during `fs write` dry-run | `ansible --check --diff` | MISSING | `fs write` dry-run only reports the byte count and does not compare with the old content (even though `fs replace` already has `unifiedDiff`). Agent rule no. 4 requires `--dry-run` first, but for `fs write` you cannot see what changes | P1 |
| Render a template with variables | Ansible `template` (Jinja2), pyinfra `files.template` | MISSING | `{{var}}` only for recipe commands | P2 |
| Validate a file before installing it (`validate: nginx -t -c %s`, `visudo -cf`) | Ansible `validate` | MISSING | a wrong edit to `sudoers`/`sshd_config` via `fs write/replace` can lock you out of the server (the agent loses its way back); the `nginx-test` recipe only checks after writing | P1 |
| mkdir -p, mv, chmod (recursive), rm (recursive) | Ansible `file` | PRESENT | `fs mkdir/mv/chmod/rm` (+`--sudo`) | – |
| Standalone chown / chgrp | Ansible `file owner=` | MISSING | only via `fs write/replace --owner`; no `fs chown` (recursive) | P2 |
| Create a symlink | Ansible `file state=link`, `ln -s` | MISSING | `fs stat/ls` recognize symlinks but cannot create them | P2 |
| touch / change mtime | Ansible `file state=touch` | MISSING | `fs write --content ''` overwrites the content | P3 |
| stat (exists, size, mode, sha256) | Ansible `stat` | PRESENT | `fs stat [--sha256]` (`exists:false` is not an error) | – |
| ls (recursive, dotfiles, limit) | ls, sftp | PRESENT | `fs ls -a -r --max` | – |
| Find files (name/size/age) | find, Ansible `find` | PARTIAL | recipes `big-files`, `big-dirs`; no structured `fs find` | P3 |
| Search content (grep in a file/folder) | grep -r | PARTIAL | `logs --file --grep` for a single file; possible via exec `grep -r` | P3 |
| Restore from `.bak` | — | MISSING | `--backup` creates `PATH.bak`, then `PATH.bak.<UTC time>` (never overwritten, they add up); no `fs restore`/rollback; you must `fs mv` by hand | P2 |
| Edit in a local editor ($EDITOR) then save back | `vim scp://`, VS Code Remote | MISSING | useful for humans; possible via download→edit→`fs write --if-changed` | P3 |

## 11. Services (systemctl/service, Ansible `service`/`systemd`)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Structured status | systemctl show | PRESENT | `svc status TARGET UNIT...` (active_state, sub_state, main_pid, n_restarts, memory) | – |
| start/stop/restart/reload + state report + journal on failure | systemctl, Ansible `systemd` | PRESENT | `svc start/stop/restart/reload` (20 journal lines on failure) | – |
| enable/disable | systemctl | PRESENT | `svc enable/disable` | – |
| enable `--now` in one step | Ansible `enabled+state` | MISSING | two commands | P3 |
| List units + filter failed/state | systemctl list-units | PRESENT | `svc list --failed --state` | – |
| `daemon-reload` after changing a unit file | systemctl, Ansible `daemon_reload` | MISSING | not in `svc`; the agent flow "write unit → reload → restart" must use `exec` | P1 |
| mask/unmask | systemctl | MISSING | possible via exec | P3 |
| View unit file & drop-ins (`systemctl cat`) | systemctl cat | MISSING | possible via `fs cat` if you know the path; possible via exec | P2 |
| Create/edit an override drop-in (`systemctl edit`) | systemctl edit | MISSING | possible via `fs write` to `/etc/systemd/system/X.d/override.conf` + daemon-reload (which is missing) | P2 |
| List & manage systemd timers | systemctl list-timers | PARTIAL | the `cron-all` recipe shows `list-timers`; not structured, cannot create | P3 |
| User units (`systemctl --user`) | systemctl --user | MISSING | `--no-sudo` only drops sudo (its help mentions "--user units"), but `systemctl` is never called with `--user`; must use exec | P3 |
| Non-systemd init (OpenRC/Alpine, sysvinit) | Ansible `service` | MISSING | `svc` is systemd only (even though `pkg` supports apk) | P3 |
| Validate config before reload (nginx -t, apachectl configtest) | Ansible handlers | PARTIAL | recipes `nginx-test`, `apache-test`; `svc reload` does not validate | P3 |

## 12. Packages (apt/dnf/yum/apk/zypper/pacman, Ansible `package`)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Install / remove / update index / upgrade (all managers, auto-detect) | apt, dnf, Ansible `package` | PRESENT | `pkg install/rm/update/upgrade`, `DEBIAN_FRONTEND=noninteractive` | – |
| List pending upgrades | apt list --upgradable | PARTIAL | `pkg upgradable` exists, but the output is raw text per manager (not structured name/current/candidate rows) | P2 |
| Security updates only | unattended-upgrades, `dnf upgrade --security` | PARTIAL | the `security-updates` recipe only reads; `pkg upgrade` has no `--security` | P2 |
| Installed versions | dpkg-query, rpm -q | PRESENT | `pkg installed [PKG...]` (tab-separated) | – |
| Search packages / package info | apt search, dnf info | MISSING | possible via exec | P3 |
| Install a specific version | `apt install x=1.2` | PARTIAL | apt `nginx=1.24*` passes name validation; no cross-manager syntax | P3 |
| Hold/pin a version (prevent upgrade) | apt-mark hold, dnf versionlock | MISSING | important for kernel/DB in production | P2 |
| Add a repo/PPA + GPG key | Ansible `apt_repository`, `yum_repository` | MISSING | possible via `fs write` + exec | P2 |
| Autoremove / clean the cache | apt autoremove | PARTIAL | the `apt-clean` recipe (apt only) | P3 |
| dist-upgrade / full-upgrade | apt full-upgrade | MISSING | `pkg upgrade` = `apt-get upgrade` (packages that need new dependencies are held back) | P3 |
| Detect a needed reboot after an upgrade | needrestart, `/var/run/reboot-required` | PRESENT | `facts` → `reboot_required` | – |
| Install from a local .deb/.rpm file | apt install ./x.deb | MISSING | `upload` + exec | P3 |
| Non-OS packages (snap, flatpak, pip, global npm) | Ansible `snap`, `pip` | MISSING | NG-FULL — possible via exec | P3 |

## 13. Users and access (useradd, Ansible `user`/`group`/`authorized_key`, sudoers)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| List users (human / all) + sudo members | getent, Ansible | PRESENT | `user list [--all]` | – |
| Create a user idempotently + SSH key + sudo | Ansible `user` + `authorized_key` | PRESENT | `user add TARGET NAME --key/--pubkey --admin --shell` | – |
| Lock an account | usermod -L | PRESENT | `user lock` | – |
| Unlock an account | usermod -U, chage -E -1 | MISSING | `lock` is reversible in concept but there is no `user unlock`; must use exec | P2 |
| Delete a user (dangerous) | userdel | PRESENT | `user rm [--remove-home]` (needs `--allow-dangerous`) | – |
| Revoke a user's SSH key | Ansible `authorized_key state=absent` | MISSING | see §2 (offboarding) | P1 |
| Manage groups (groupadd, add/remove members of any group, e.g. `docker`) | Ansible `group`, usermod -aG | MISSING | `--admin` is only sudo/wheel | P2 |
| Limited sudoers rules (NOPASSWD for specific commands) + visudo validation | Ansible `community.general.sudoers` | MISSING | the `sudoers` recipe only reads; writing sudoers without validation can lock you out | P2 |
| Set/expire a user's password | passwd, chage, Ansible `user password` | MISSING | deliberately missing is safer; if added, it must go through a vault ref | P3 |
| Change shell/home/UID of an existing user | usermod | MISSING | `user add` does not change an existing user | P3 |
| Last login / failed logins | last, lastlog, auth.log | PRESENT | recipes `last-logins`, `auth-failures` (text) | – |
| sshd hardening (view effective settings) | sshd -T | PRESENT | the `sshd-config` recipe (read); change via `fs replace --backup` | – |

## 14. Cron and scheduling (crontab, Ansible `cron`, systemd timer)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Idempotent crontab entries by ID | Ansible `cron name=` | PRESENT | `cron set TARGET ID CMD --schedule`, marker `# komando:<id>` | – |
| List entries (with ID) | crontab -l | PRESENT | `cron list` (line + id) | – |
| Remove entries | Ansible `cron state=absent` | PRESENT | `cron rm` | – |
| Another user's crontab | crontab -u | PRESENT | `--user NAME --sudo` | – |
| All system cron (/etc/crontab, /etc/cron.d, all users) | — | PRESENT | the `cron-all` recipe (text) | – |
| Schedule validation | — | PARTIAL | only checks 5 fields or `@daily`; values are not validated (e.g. `61 * * * *`) | P3 |
| Cron env (MAILTO, PATH, SHELL) | Ansible `cronvar` | MISSING | `cron set` only writes the schedule line; env can be written inside the command | P3 |
| Disable temporarily without deleting | Ansible `cron disabled=yes` | MISSING | only `cron rm` then `cron set` again | P3 |
| Files in `/etc/cron.d` | Ansible `cron cron_file=` | MISSING | possible via `fs write` | P3 |
| Create a systemd timer | systemd | MISSING | possible via `fs write` unit + exec | P3 |
| One-off schedule (`at`) | at | MISSING | `job start -- 'sleep 3600; ...'` instead | P3 |

## 15. Logs (journalctl, log files, logrotate)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| journald per unit, since/until, priority, grep, limit | journalctl | PRESENT | `logs --unit --since --until --priority --grep -n` | – |
| Log files (tail/grep, sudo) | tail, grep | PRESENT | `logs --file PATH --grep -n --sudo` | – |
| Follow (`-f`), including many hosts | journalctl -f, tail -F, multitail | PRESENT | `logs --follow` (NDJSON stream per host) | – |
| Container logs | docker logs | PRESENT | `logs --container` | – |
| Kernel log / a specific boot (`-k`, `-b -1`) | journalctl -k/-b, dmesg | PARTIAL | recipes `oom` and `journal-errors`; `logs` has no `--kernel`/`--boot` | P2 |
| Structured logs (journald fields as JSON) | journalctl -o json | MISSING | output is `short-iso` text lines | P3 |
| Compressed/rotated log files (`.gz`, `.1`) | zgrep, lnav | MISSING | `--file` takes one path; possible via exec `zgrep` | P3 |
| Several units at once | journalctl -u a -u b | MISSING | `--unit` takes one value | P3 |
| Configure logrotate / force a rotate | logrotate | MISSING | `fs write` to `/etc/logrotate.d` + exec | P3 |
| Shrink the journal | journalctl --vacuum | PRESENT | the `journal-vacuum` recipe | – |

## 16. Facts, processes, disk (facts/grains, htop, iotop, ncdu, lsof)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Structured facts (OS, kernel, arch, CPU, RAM, swap, load, uptime, IP, virt, init, pkg manager, tools, reboot_required, failed_units, timezone) | Ansible setup, Salt grains | PRESENT | `facts TARGET` | – |
| Facts for all mounts/disks, NICs, hardware (DMI), tool versions | Ansible setup | PARTIAL | facts only cover the root disk; recipes `disk`/`inodes` give text | P3 |
| Health summary | — | PRESENT | recipes `health`, `memory`, `failed-units`, `time-sync` | – |
| Top CPU/memory processes, find a process | ps, htop | PRESENT | recipes `top-cpu`, `top-mem`, `process` (text) | – |
| Structured process list (JSON) | ps, Salt `ps` | MISSING | only text via recipes | P2 |
| Kill a process safely (PID/name, signal, confirmation) | kill, pkill, Ansible | MISSING | possible via exec `kill`; no report of which processes were hit | P2 |
| Interactive monitors (htop, top, iotop, ncdu) | htop, iotop, ncdu | NON-GOAL | NG-TUI ("TUI ... komando stays a pure CLI"); one-shot versions: recipes `top-*`, `big-dirs` | – |
| Per-process disk I/O / iostat | iotop, iostat | MISSING | the `memory` recipe uses vmstat; no I/O | P3 |
| Disk usage & largest folders/files | df, du, ncdu | PRESENT | recipes `disk`, `inodes`, `big-dirs`, `big-files` | – |
| Open files / who holds a file/port | lsof, fuser | PARTIAL | `net ports --sudo` gives the process per port; no open files | P3 |
| Recent OOM kills | dmesg | PRESENT | the `oom` recipe | – |

## 17. Networking from the server (ss, dig, curl, mtr, traceroute, nmap)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Check destination TCP ports from the server (many at once) | nc -z, Ansible `wait_for` | PRESENT | `net check TARGET HOST:PORT...` (structured) | – |
| HTTP from the server (status, timing, IP) | curl -w | PRESENT | `net http TARGET URL` | – |
| DNS resolution from the server | getent, dig | PARTIAL | `net dns` uses `getent ahosts` (A/AAAA only); cannot choose the record type (MX/TXT/CNAME), a specific resolver, or TTL | P2 |
| Listening ports + processes | ss -tulpn, netstat | PRESENT | `net ports [--sudo]` | – |
| Connection statistics | ss -s | PRESENT | the `connections` recipe | – |
| Ping / ICMP latency | ping | MISSING | possible via exec | P2 |
| Traceroute / mtr | traceroute, mtr | MISSING | possible via exec if installed | P2 |
| Structured TLS certificate check (days to expiry, issuer, SAN) | openssl s_client, certbot certificates | PARTIAL | recipes `cert-expiry`, `certbot-certs` (text); no "days left" for the agent. vision: "certificates/ACME" candidate after v1.0 | P2 |
| Wait until a port/URL is ready (`wait_for`) | Ansible `wait_for`, `wait-for-it` | MISSING | `net check` runs once, without `--wait`/retry | P2 |
| Routes, interfaces, ARP | ip route/addr | PARTIAL | `facts` → `ips`; no routes | P3 |
| Scan another host's ports | nmap | MISSING | security-sensitive; possible via exec | P3 |
| Bandwidth between servers | iperf3 | MISSING | possible via exec if iperf3 is installed | P3 |
| Server's public/egress IP | `curl ifconfig.me` | MISSING | `net http` discards the body (`-o /dev/null`), so it cannot read the egress IP; possible via exec `curl ifconfig.me` | P3 |
| Packet capture | tcpdump | MISSING | possible via `job start` + `download` | P3 |
| Check from the laptop to the server (not from the server) | nc, ssh -v | PRESENT | `test TARGET` | – |

## 18. System configuration (sysctl, mount/fstab, firewall, hostname/timedatectl, reboot, wait_for, certbot, git)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Controlled reboot + wait for the server to come back + verify | Ansible `reboot`, pyinfra `server.reboot` | MISSING | `reboot` is blocked by policy (correct); with `--allow-dangerous` the connection drops without waiting/verifying. The patch flow (`pkg upgrade` → `facts.reboot_required` → reboot → wait → `test`) cannot be finished safely by an agent | P1 |
| Firewall status | ufw status, firewall-cmd | PRESENT | the `firewall` recipe (ufw/firewalld/nftables/iptables, text) | – |
| Manage firewall rules (allow/deny port, source) with an anti-lockout guard (SSH port) | ufw, firewalld, Ansible `ufw`/`firewalld` | MISSING | policy blocks flush; adding rules needs exec. No anti-lockout | P2 |
| sysctl get/set (+ persist to `/etc/sysctl.d`) | sysctl, Ansible `sysctl` | MISSING | possible via exec + `fs write` | P3 |
| mount / fstab (add, mount, unmount) | mount, Ansible `mount` | MISSING | risky (a wrong fstab = failed boot); possible via exec | P3 |
| Swap file | mkswap, Ansible | MISSING | possible via exec; `facts` reads swap | P3 |
| Set hostname | hostnamectl, Ansible `hostname` | MISSING | `facts` reads the hostname | P3 |
| Set timezone / NTP | timedatectl, Ansible `timezone` | PARTIAL | the `time-sync` recipe and `facts.timezone` read it; no set | P3 |
| Locale | localectl | MISSING | possible via exec | P3 |
| Let's Encrypt certificates (issue/renew) | certbot, acme.sh | PARTIAL | the `certbot-certs` recipe reads; renew/issue via exec. vision: ACME candidate after v1.0 | P3 |
| Git checkout/pull on the server (deploy) | Ansible `git` | MISSING | the example recipe `deploy-app` uses `git pull` via exec | P3 |
| SELinux/AppArmor status & mode | Ansible `selinux` | MISSING | possible via exec | P3 |
| Kernel modules / limits.conf | Ansible `modprobe`, `pam_limits` | MISSING | possible via exec / `fs write` | P3 |
| Clear page cache, docker prune, apt clean | — | PRESENT | recipes `drop-caches`, `docker-prune`, `apt-clean` | – |

## 19. Recipes / snippets (Termius snippets, Fabric tasks, Salt modules)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| 39 built-in recipes (health, disk, certs, security, network, db, web) | Termius snippets, Salt modules | PRESENT | `recipe list [--category]`, `recipe run NAME TARGET` | – |
| Your own recipes with `{{var}}` blanks and `{{var=x}}` defaults | Termius snippets, Fabric | PRESENT | `recipe add --desc --sudo --read-only --overwrite`, `--var` | – |
| Recipes are treated as write unless `--read-only` | — | PRESENT | ux.md §3 polarity | – |
| Share recipes with the team / other machines | Termius team vault | PRESENT | included in `export`/`import komando` | – |
| Multi-step recipes / recipes with files (scripts) | Fabric tasks, Ansible roles | MISSING | a recipe = one command line; long scripts go through `script` | P3 |
| Structured recipe output (parser) | Salt modules | MISSING | built-in recipes return text; the important ones already have structured commands (`svc`, `net`, `facts`) | P3 |
| Community recipe catalog / plugins | Ansible Galaxy, Salt formulas | NON-GOAL | NG-TUI: "... plugin system ..." | – |

## 20. Security, access, and audit (Teleport tsh, Tailscale SSH)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Audit every action (who, what, where, result) | Teleport audit log | PRESENT | `audit --command --failed --limit --target`; `KOMANDO_ACTOR`. Note: the audit is written after the action and failures to write the file are silently ignored (it does not fail closed); turning off the audit via `config set audit off` needs `--yes` | – |
| Filter the audit by time / export | Teleport | PARTIAL | no `--since/--until`; the `audit.jsonl` file can be read | P3 |
| Send the audit to a central place (syslog/SIEM/webhook) | Teleport, auditd | MISSING | the audit is only local per laptop; the team cannot see agent actions on other machines | P2 |
| Human confirmation for production targets & dangerous commands | Teleport access requests | PRESENT | protected → `--yes`/prompt `[y/N]`; dangerous → retype the name; an agent cannot answer the prompt | – |
| Remote approval (ask someone else for permission, just-in-time access) | Teleport access requests | NON-GOAL | needs a server; NG-TUI "daemon/server" | – |
| Central multi-user RBAC | Teleport roles | NON-GOAL | NG-TUI "daemon/server"; replacement: SSH users with minimum rights (docs/features/safety.md) | – |
| Session recording | Teleport | MISSING | see §6 | P3 |
| Secrets never in arguments/output/audit | — | PARTIAL | AES-256-GCM vault, `secret set` rejects values in arguments (`SECRET_IN_ARGS`), external refs (1Password, Vault, AWS SM, GCP SM); but `host add/edit --password-ref/--sudo-ref` accepts plain values, then stores and prints them (see §1) | P1 |
| Extendable dangerous-command policy | — | PRESENT | `policy deny REGEX`, `policy check` | – |
| Allowlist (only certain commands allowed for the agent) | Teleport `command` restrictions, `authorized_keys command=` | MISSING | policy is only a deny-list; there is no global "agent may only do read-only" mode | P2 |

---

## Count summary

273 capabilities rated in total (updated after per-row verification; the first count "270, PRESENT 103"
was miscounted, and 8 statuses and 3 priorities were corrected, see the last section).

| Status | Count |
|---|---|
| PRESENT | 104 |
| PARTIAL | 41 |
| MISSING | 115 |
| NON-GOAL | 13 |

| Gap priority (PARTIAL + MISSING) | Count |
|---|---|
| P1 | 13 (the "revoke key" gap appears in §2 and §13; the unvalidated `--password-ref` gap appears in §1 and §20) |
| P2 | 57 |
| P3 | 86 |

## Top P1 gaps

1. **Revoke SSH keys from `authorized_keys`** (offboarding/rotation; `key deploy`/`user add` only add) — §2, §13.
2. **Folder sync (delta, `--delete`, `--exclude`, dry-run list of changes)** for deploys — §9.
3. **Transfers do not overwrite without `--overwrite`** (server upload and download overwrite silently; breaks ux.md) — §9.
4. **Atomic download (tmp + rename)** — §9.
5. **Streaming upload of large files** (single-file upload still uses `os.ReadFile` to load the whole file into RAM) — §9.
6. **Controlled reboot + wait to come back + verify** for the patch flow — §18.
7. **`svc daemon-reload`** for the "write unit → reload → restart" flow — §11.
8. **Tunnel binds to non-loopback without `--yes`** (contradicts network.md) — §8.
9. **Diff on `fs write --dry-run`** (dry-run is required for agents but does not show the change) — §10.
10. **Validate files before installing them** (`visudo -cf`, `sshd -t`, `nginx -t`) so an edit does not lock you out — §10.
11. **`host add/edit` accepts plain passwords in `--password-ref`/`--sudo-ref`** (stored in `state.json` and printed; `conn`/`vpn` already use `vault.ValidRef`) — §1, §20.

The next strongest P2 candidates: `ProxyCommand`/AWS SSM, GCP IAP, Cloudflare Access transport (§1), `serial` rolling batches (§5), `download --sudo` (§9), idempotent `lineinfile` (§10), and SSH certificates (§1, §3).

## Per-row verification

Rechecked 2026-11-02 against the code on `feat/v0.3` (commit `4784fc9`): every row was reread from
`internal/cli`, `internal/sshx`, `internal/store`, `internal/vault`, `internal/policy`, `bin/komando schema`
and `--help` (with a temporary `KOMANDO_HOME`), plus the `golang.org/x/crypto` v0.58.0 code for
agent/known_hosts behavior. One local test without a server: `host add ... --password-ref hunter2` in a temporary
`KOMANDO_HOME`. NON-GOAL rows were matched against vision.md "Non-goals" (lines 221-228) or "Technical rules".
The `#` number is the row order in the tables above.

| # | Capability (short) | Final status | Check result | Evidence in code |
|---|---|---|---|---|
| 1 | Login with a private key file | PRESENT | Correct | host.go:51 `--key`, host.go:39/52 `--identity`; client.go:301-317 |
| 2 | Use ssh-agent (including 1Password/Secretive… | PRESENT | Correct | sshx/client.go:320-327 (SSH_AUTH_SOCK); meta.go:565 doctor |
| 3 | Automatic fallback to ~/.ssh/id_ed25519/id_ecds… | PRESENT | Correct | sshx/client.go:328-333 (only when there is no explicit key) |
| 4 | Encrypted key (passphrase from the vault) | PRESENT | Correct | key.go:163, key.go:171-190 `--passphrase-ref`; client.go:278-290 |
| 5 | Password login (stored safely) | PARTIAL | Corrected: PRESENT→PARTIAL, –→P1 | host.go:95-96 stores `--password-ref`/`--sudo-ref` without `vault.ValidRef` (used in conn.go:100, vpn.go:167); local test `host add t1 a@192.0.2.1 --password-ref hunter2` → exit 0, value stored & printed |
| 6 | Keyboard-interactive / SSH 2FA (OTP Google Aut… | PARTIAL | Correct | sshx/auth.go `passwordLogin` (the password once, only to a hidden password question; a code question stops the login); shell.go:37 uses the same Dial |
| 7 | IdentitiesOnly (limit the keys tried, avoid… | PARTIAL | Corrected: evidence (status unchanged) | sshx/client.go:301-335: the explicit key goes into `signers` first, then all agent keys are added after it (not before) |
| 8 | Per-host IdentityAgent (a different agent per host) | MISSING | Correct | grep IdentityAgent: 0 results; store.go:17-36 has no agent field |
| 9 | Jump host / bastion (-J, ProxyJump), chains of ma… | PRESENT | Correct | host.go:55 `--via`, host.go:56 alias `--jump`; host.go:547 ProxyJump; client.go:119-162 |
| 10 | ProxyCommand (e.g. aws ssm start-session, clou… | MISSING | Correct | grep ProxyCommand: 0 results; host.go:512-517 other options are only stored in a map, not used |
| 11 | Access via VPN per connection (many VPNs at on… | PRESENT | Correct | vpn.go:25-44 list of kinds (netx.Kinds); client.go:63-69 VPN at the start of --via |
| 12 | Tailscale SSH (auth based on tailnet identity… | PARTIAL | Correct | client.go:353-355 NO_AUTH when there is no key/agent/password |
| 13 | SSH certificate login (user cert signed… | PARTIAL | Corrected: MISSING→PARTIAL | client.go:322-325 `ag.Signers()` (x/crypto agent client.go:819-829) also carries the user cert from the agent; grep CertificateFile/NewCertSigner: 0 results |
| 14 | Agent forwarding (-A, ForwardAgent) — e.g. git… | MISSING | Correct | grep ForwardToAgent/RequestAgentForwarding: 0 results |
| 15 | X11 forwarding (-X/-Y) | MISSING | Correct | grep X11: 0 results |
| 16 | Keepalive (ServerAliveInterval) | PRESENT | Correct | sshx/client.go:103-115 (keepalive@komando every 30 sec, fixed) |
| 17 | Connect timeout | PRESENT | Correct | root.go:165 `--connect-timeout`; meta.go:358 `connect_timeout`; client.go:64,89-91 |
| 18 | Per-host cipher/KEX/HostKeyAlgorithms choice… | MISSING | Correct | grep Ciphers/KeyExchanges/HostKeyAlgorithms: 0 results; client.go:256-261 |
| 19 | Compression (-C) for slow links | MISSING | Correct | grep Compression: 0 results |
| 20 | Connection multiplexing (ControlMaster/ControlPer… | NON-GOAL | Correct (note: the basis is "Technical rules", not "Non-goals") | vision.md:189-190; common.go:135-158 one Dial per host per command |
| 21 | Automatic retry on temporary connection failure | MISSING | Correct | common.go:135-158 fanout without retry; the only reconnect is in tunnel.go:440-491 |
| 22 | IPv6, non-standard port | PRESENT | Correct | sshx/client.go:165-183 ParseAdhoc (SplitHostPort); host.go:49 `--port`; ux.md:294 |
| 23 | Ad-hoc host without registering it | PRESENT | Correct | client.go:139-147 ad-hoc user@host:port; select.go (ad-hoc target) |
| 24 | Match blocks in ssh_config (Match host/user/exec) | PARTIAL | Correct | host.go:509-510 `case "match": cur = nil`; ux.md:211 |
| 25 | Report unsupported ssh_config directives… | MISSING | Correct | host.go:465-564 only hostname/user/port/identityfile/proxyjump/include are used; grep unsupported in the importer: 0 results |
| 26 | Print the equivalent OpenSSH command (interop) | PRESENT | Correct | host.go:709-759 `host ssh-command` |
| 27 | Export the inventory to ssh_config (so ssh/sc… | MISSING | Correct | host.go:596-619 JSON only; grep ssh_config writer: 0 results |
| 28 | Windows hosts (OpenSSH on Windows / WinRM / Pow… | MISSING | Correct | vision.md:91 "SSH (Linux)"; factsScript ops.go:19-38 Linux only |
| 29 | Create an ed25519 / RSA key pair | PRESENT | Correct | key.go:53-75, key.go:107 `--type ed25519\|rsa` |
| 30 | Create an ECDSA key | MISSING | Correct | key.go:75 "--type must be ed25519 or rsa" |
| 31 | FIDO2 hardware key (ed25519-sk, YubiKey) | PARTIAL | Correct | x/crypto common.go:208-225 supports sk-* via the agent; key.go:53-75 does not create sk |
| 32 | Passphrase when creating a key | MISSING | Correct | key.go:58,70 `ssh.MarshalPrivateKey` without a passphrase; key.go:88 0600 |
| 33 | Register an existing key | PRESENT | Correct | key.go:118-163 `key add` (path is referenced) |
| 34 | Show public key and fingerprint | PRESENT | Correct | key.go:95 SHA256 fingerprint; key.go:196 list, key.go:227 show |
| 35 | Install a public key on a server (idempotent) | PRESENT | Correct | key.go:280-360 (grep -qF then append; fanout; `--set-default`) |
| 36 | Revoke / remove a public key from authorized_keys… | MISSING | Corrected: evidence (status unchanged) | key.go:308-309 & modules.go:673-675 only append; grep revoke/absent: 0 results. Per host, `fs replace` works (fs.go:563-672, one host) |
| 37 | List authorized_keys per server/user (audit… | MISSING | Correct | grep authorized_keys parser: 0 results; only fs.go:260 `fs cat` |
| 38 | End-to-end key rotation (deploy new → switch →… | PARTIAL | Correct | key.go:360 `--set-default`; the revoke step is missing (see #36) |
| 39 | Add a key to ssh-agent | MISSING | Correct | grep agent.Add: 0 results |
| 40 | authorized_keys options (from=, command=, no-port… | MISSING | Correct | key.go:309 writes the key line as is, without options |
| 41 | SSH CA: sign user/host certs | MISSING | Correct | grep CertSigner/ssh-keygen -s: 0 results |
| 42 | Automatic short-lived cert per session | MISSING | Correct | grep cert/CA: 0 results |
| 43 | Host key policy accept-new / strict / off | PRESENT | Correct | root.go:148-149 `off` → guardSafety (SAFETY_SETTING, common.go:328); meta.go:366-369 |
| 44 | Reject a changed host key | PRESENT | Correct | client.go:396-397, 218-221 HOSTKEY_MISMATCH |
| 45 | Fetch & pin the host key (keyscan), also behind… | PRESENT | Correct | host.go (sshx.FetchHostKey: the usual route, jump hosts under host_key_policy; the target is scanned, not logged in to) |
| 46 | Forget / replace the key after a server is rebu… | PRESENT | Correct | host.go:669-673 `--reset` → ForgetHost (client.go:414) |
| 47 | Import the existing ~/.ssh/known_hosts (avoi… | MISSING | Correct | client.go:369,375 only ~/.komando/known_hosts; grep import known_hosts: 0 results |
| 48 | Host certificate / @cert-authority in known_ho… | PARTIAL | Corrected: MISSING→PARTIAL | client.go:384 `knownhosts.New` (x/crypto knownhosts.go:439-444 CertChecker) accepts hand-written @cert-authority lines; without them CheckHostKey (certs.go:372-373) fails → CONNECT_FAILED, not TOFU; grep cert-authority: 0 results |
| 49 | Verify the fingerprint from another source (DNS S… | MISSING | Correct | host.go:705 only `--reset`; grep fingerprint flag: 0 results |
| 50 | List pinned host keys | PARTIAL | Correct | host.go:695-699 fingerprint in the output; no list subcommand |
| 51 | Add/edit/remove/show hosts | PRESENT | Correct | host.go:84 add, 154 edit (--rename 157), 317 rm, 297 show |
| 52 | Groups, tags, key=value labels, notes | PRESENT | Correct | host.go:58-68 --group/--tag/--label/--notes; host.go:770-852 group |
| 53 | Nested groups (group of groups / children) | MISSING | Correct | grep children/parent group: 0 results; store.go:28 flat Groups |
| 54 | Selectors: name, glob, @group, tag:, label:, ki… | PRESENT | Correct | select.go:125 kind:, 208 all, 210 @, 212 tag:, 214 label:, 224 glob; did-you-mean select.go:77,251 |
| 55 | Target by facts (os=ubuntu, arch, ver… | MISSING | Correct | select.go:205-230 inventory attributes only |
| 56 | Per-host variables (env, default user, sudo) | PRESENT | Correct | host.go:65 --env, 54 --sudo-ref; meta.go:358 default_user; sshx/run.go:102-108 |
| 57 | Per-host variables for recipes/templates ({{app… | MISSING | Correct | ops.go:355-359 renders once before runFleet (one value for all hosts) |
| 58 | Mark production hosts (need confirmation) | PRESENT | Correct | host.go:58 --protected; common.go:184-196, 233 |
| 59 | Import ~/.ssh/config | PRESENT | Correct | importer.go:49,370 ssh-config; host.go:365 host import |
| 60 | Import an Ansible inventory (INI/YAML) | MISSING | Correct | importer.go sources (help `import`): no ansible; grep ansible: 0 results |
| 61 | Import from Termius / Royal TSX / MobaXterm /… | MISSING | Correct | vision.md:170 termius; grep termius in the importer: 0 results |
| 62 | Dynamic inventory from the cloud (EC2/DO/Hetzner… | MISSING | Correct | vision.md:208-209 candidate after v1.0; grep ec2/hetzner in cli: 0 results |
| 63 | Export / move to another computer | PRESENT | Correct | importer.go:612 export; importer.go:49 `komando` source; host.go:596 host export --target |
| 64 | Sync the inventory across devices/teams (c… | NON-GOAL | Correct | vision.md:227 "daemon/server" |
| 65 | Check that login works on all hosts | PRESENT | Correct | everything.go:151,174 test (host/conn/VPN) |
| 66 | Check that sudo works during test | PARTIAL | Corrected: MISSING→PARTIAL | host.go:637-647 `test` runs `sudo -n true` → `sudo_nopasswd`; sudo-ref (run.go:102-108) is not tested |
| 67 | Connection history / "recent hosts" | PARTIAL | Correct | meta.go:276 audit --target; everything.go:61 list without last-used |
| 68 | Run a command on one / many hosts in parallel | PRESENT | Correct | exec.go:191-314 runFleet + fanout; root.go:166 -P |
| 69 | Structured output per host (stdout, stderr, e… | PRESENT | Correct | exec.go:275-313 results/summary; worst → exit 5 (exec.go:289) |
| 70 | Stream output while running | PRESENT | Correct | exec.go:80 --stream, 241-265 NDJSON |
| 71 | Stop after the first failure | PRESENT | Correct | exec.go:81, 232-238 --fail-fast |
| 72 | Rolling / staged batches (serial: 2 / 25%), pa… | PARTIAL | Correct | exec.go:81 + root.go:166; grep serial/batch: 0 results |
| 73 | Group identical output (500 hosts → "480 ho… | MISSING | Correct | exec.go:275-299 results per host without grouping |
| 74 | Save output per host to a folder | MISSING | Correct | grep output-dir: 0 results |
| 75 | Non-interactive sudo, sudo with a password from… | PRESENT | Correct | exec.go:74-75 --sudo/--sudo-user; host.go:54 --sudo-ref; run.go:102-108 |
| 76 | su/doas/pbrun as become method | MISSING | Correct | grep doas/pbrun in sshx: 0 results (doas only in policy.go:26) |
| 77 | Env vars and working dir | PRESENT | Correct | exec.go:76-77 -e/-C; host.go:65 --env |
| 78 | stdin from a local file | PRESENT | Correct | exec.go:78, 113-118 --stdin-file |
| 79 | Run a local script on the remote without copying it | PRESENT | Correct | exec.go:129-177 script --arg --interpreter |
| 80 | PTY for tools that ask for one | PRESENT | Correct | exec.go:79 --pty |
| 81 | Dry-run / check mode | PRESENT | Correct | root.go:161; exec.go:212-226 would_run + would_be_blocked |
| 82 | Guardrails for dangerous commands | PRESENT | Correct | meta.go:441-530 policy list/check/deny/allow; root.go:163 |
| 83 | Read-only declaration for protected hosts | PRESENT | Correct | exec.go:125 --read-only; common.go:184 |
| 84 | Per-host time limit and output limit | PRESENT | Correct | root.go:164 --timeout, 168 --max-output |
| 85 | Async execution limit (async/poll) | PRESENT | Correct | job.go:52-148 job start |
| 86 | Interactive to many terminals at once (type… | NON-GOAL | Correct | vision.md:227 "GUI, TUI ... pure CLI" |
| 87 | Playbook / declarative state (multi-step orchestr… | NON-GOAL | Correct | vision.md:226 "Infrastructure as Code ... GitOps" |
| 88 | Local commands on the laptop as part of the flow | MISSING | Corrected: NON-GOAL→MISSING, –→P3 | vision.md:221-228 does not exclude local commands; grep local exec for flows: 0 results |
| 89 | Interactive login shell (PTY, resize) | PRESENT | Correct | shell.go:18-74 (alias ssh/connect, WindowChange shell.go:59-66) |
| 90 | Run an interactive command with a TTY (ssh -… | MISSING | Correct | shell.go:23 ExactArgs(1), sess.Shell(); exec --pty without terminal stdin |
| 91 | Confirmation/marker when opening a shell to a protected host | PARTIAL | Correct | shell.go:36 audit only; does not call guard/protectedHost |
| 92 | Session recording / replay | MISSING | Correct | shell.go:36 audits once; grep record: 0 results |
| 93 | Roaming / connection that survives drops (Wi-Fi change, la… | MISSING | Correct | grep mosh/roam: 0 results |
| 94 | Escape sequence (~.), switch to port-forward m… | MISSING | Correct | shell.go:57 raw stdin to the session; no escape |
| 95 | Share a session / join someone else's session | NON-GOAL | Correct | vision.md:227 "daemon/server" |
| 96 | Start a detached process that survives an SSH d… | PRESENT | Correct | job.go:29 $HOME/.komando/jobs, job.go:104-106 setsid nohup |
| 97 | Status, exit code, runtime, log tail | PRESENT | Correct | job.go:225 status, 417/463-465 list --refresh --target |
| 98 | Read logs incrementally | PRESENT | Correct | job.go:266, 308-311 --offset/--max-bytes/--tail |
| 99 | Wait for completion with a time limit | PRESENT | Correct | job.go:320, 367-368 --interval/--wait-timeout |
| 100 | Stop (signal to the process group) | PRESENT | Correct | job.go:376-409 kill -SIG -- -PGID |
| 101 | Clean up jobs | PRESENT | Correct | job.go:472, 497 --keep-remote |
| 102 | Run a local script as a job | MISSING | Correct | job.go:52 start accepts only a command (flags job.go:144-148) |
| 103 | Maximum job duration (kill automatically af… | MISSING | Correct | job.go:144-148 no time-limit flag |
| 104 | Attach interactively to a job / send input | MISSING | Correct | job.go:105 stdin </dev/null |
| 105 | Notification when a job finishes | NON-GOAL | Correct | vision.md:228 "Continuously running ... monitoring or alerting" (and :227 daemon) |
| 106 | Slow modules automatically become jobs (pkg upgrade, d… | MISSING | Correct | modules.go:427,472-492 pkg upgrade via runOne (normal timeout) |
| 107 | Local forward -L | PRESENT | Correct | tunnel.go:57-71, 222 -L |
| 108 | Remote forward -R | PRESENT | Correct | tunnel.go:223 -R; tunnel.go:391-393 c.Listen |
| 109 | SOCKS5 -D | PRESENT | Correct | tunnel.go:224 -D; tunnel.go:73-81 |
| 110 | Tunnel to a conn by name (free local po… | PRESENT | Correct | tunnel.go:101-117 conn + --port (tunnel.go:225) |
| 111 | Background tunnel, list, stop | PRESENT | Correct | tunnel.go:261 list (alive/prune), 306 stop --all |
| 112 | Automatic reconnect when SSH drops | PARTIAL | Correct | tunnel.go:440 connMgr (local/dynamic); tunnel.go:408-409 -R stops when the listener drops |
| 113 | Default bind to 127.0.0.1; binding to another address… | PARTIAL | Correct | tunnel.go:65-70 bind from the spec is accepted without checking g.yes; network.md:163-164 |
| 114 | Tunnel survives a laptop reboot (service… | NON-GOAL | Correct | vision.md:227 daemon; vision.md:189-190 "no daemon" |
| 115 | Tunnel lifetime limit (stop automatically after X / w… | MISSING | Correct | meta.go:358 vpn_idle only for VPN; grep idle in tunnel.go: 0 results |
| 116 | Transparent "VPN over SSH" (changes laptop routes) | NON-GOAL | Correct (note: sources network.md:169 and vision.md:200) | network.md:169; vision.md:200 "the laptop's network does not change" |
| 117 | Forward a Unix socket (-L /tmp/x.sock:/var/run/d… | MISSING | Correct | tunnel.go:57-83 spec split on ":" → host:port only |
| 118 | Upload a file to many servers in parallel | PRESENT | Correct | transfer.go:42-76; cp.go:55-84; cp.go:184 sha256 (single file) |
| 119 | Upload with mode, create parent folders, install… | PARTIAL | Correct | cp.go:49-52 --mode/-p/--sudo; cp.go:189-191 folder+sudo rejected; no --owner |
| 120 | Download from many servers (a folder per server) | PRESENT | Correct | cp.go:127-133 DIR/<host>/ |
| 121 | Download root-owned files (/var/log/..., /etc/s… | MISSING | Corrected: evidence (status unchanged) | transfer.go:109-110 only --to/-r; fs.go:311-312 `fs cat --sudo` default 1 MiB (`--max-bytes`), fs.go:278-281 binary dropped |
| 122 | Recursive folders | PRESENT | Correct | cp.go:49 -r; transfer.go:110 |
| 123 | Do not overwrite without --overwrite | MISSING | Correct | cp.go:180 writeRemote overwrites; cp.go:210,284 O_TRUNC; storage.go:316 only storage FILE_EXISTS; ux.md:318 |
| 124 | Atomic download (tmp then rename; no half-written fi… | MISSING | Correct | cp.go:278-292 fetchFile O_TRUNC straight to the destination; ux.md:319 |
| 125 | Large files without loading them into memory (stream) | PARTIAL | Corrected: MISSING→PARTIAL | cp.go:173 `os.ReadFile` for single-file upload; cp.go:205-214 (upload -r) and cp.go:290 (download) already stream with io.Copy |
| 126 | Progress on stderr for large files | MISSING | Correct | grep progress: 0 results; ux.md:321 |
| 127 | Resume an interrupted transfer | MISSING | Corrected: evidence (status unchanged) | grep resume/offset in cp.go & storex: 0 results (ftp.go:41 is only a control-connection comment) — FTP storage has no resume either |
| 128 | Delta sync (only what changed), --del… | MISSING | Correct | cp.go:193-223 copies everything again, no delete/exclude; grep exclude in cp.go: 0 results |
| 129 | Transfer dry-run that shows which files wi… | PARTIAL | Correct | cp.go:114-117 dry-run only src/dst/hosts/direction |
| 130 | Skip the upload when the content is the same (idempotent) | PARTIAL | Correct | fs.go:517-531 --if-changed; cp.go:172-185 upload without comparison |
| 131 | Keep symlinks | MISSING | Correct | cp.go:202-204 & 265-267 non-regular (symlink) skipped without reporting |
| 132 | Keep modification times (-p) | MISSING | Correct | cp.go:219 & 284 mode only; grep Chtimes: 0 results |
| 133 | Compression during transfer | MISSING | Correct | grep compress in sftp/cp: 0 results |
| 134 | Copy server → server (remote to remote) | MISSING | Correct | cp.go:72-73 remote-to-remote rejected |
| 135 | Copy a file within one server | MISSING | Correct | fs.go:36 no `fs cp`; fs.go:771 mv |
| 136 | Download a URL directly on the server (with checksum) | MISSING | Correct | grep get_url/download URL: 0 results; policy.go:37 curl-pipe-sh |
| 137 | Extract an archive on the server | MISSING | Correct | grep unarchive/tar x: 0 results |
| 138 | Interactive sftp-shell-style browsing | NON-GOAL | Correct | vision.md:227 TUI/pure CLI; fs.go:110-317 ls/stat/cat |
| 139 | Read a file (head/tail/line numbers, byte limit,… | PRESENT | Correct | fs.go:260-317 --head/--tail/--line-numbers/--max-bytes/--sudo |
| 140 | Replace exact text / regex, fail when miss… | PRESENT | Correct | fs.go:563-672; diff in dry-run fs.go:645-648 |
| 141 | Ensure a line exists (add it if miss… | PARTIAL | Correct | fs.go:617-623 NO_MATCH (plain text: changed:false when --new is already there); fs.go:549 --append |
| 142 | Delete matching lines | PARTIAL | Corrected: evidence (status unchanged) | fs.go:612-640: `--regex` with `\n` in the pattern can delete whole lines, but fails with NO_MATCH when the line is already gone (not idempotent) |
| 143 | Managed block with markers (# BEGIN komando… | MISSING | Correct | grep BEGIN komando/blockinfile: 0 results; modules.go:757 marker only for cron |
| 144 | Write a file atomically, mode/owner, backup, idempotent | PRESENT | Correct | fs.go:327-447 tmp+rename; fs.go:547-560 flags |
| 145 | Diff during fs write dry-run | MISSING | Correct | fs.go:506-508 dry-run only host/path/bytes; unifiedDiff fs.go:675 used by replace only |
| 146 | Render a template with variables | MISSING | Correct | ops.go:151 render only for recipes |
| 147 | Validate a file before installing it (validate: ngin… | MISSING | Correct | grep validate/visudo: 0 results; ops.go:130 nginx-test is separate |
| 148 | mkdir -p, mv, chmod (recursive), rm (recursive) | PRESENT | Correct | fs.go:755-785 rm/mkdir/mv/chmod (+--sudo, -r) |
| 149 | Standalone chown / chgrp | MISSING | Correct | fs.go:560 --owner only on write/replace; fs.go:36 no chown |
| 150 | Create a symlink | MISSING | Correct | fs.go:98-99,190-191 only recognize; no symlink creator |
| 151 | touch / change mtime | MISSING | Correct | grep touch/Chtimes: 0 results |
| 152 | stat (exists, size, mode, sha256) | PRESENT | Correct | fs.go:174-217 (--sha256, exists:false) |
| 153 | ls (recursive, dotfiles, limit) | PRESENT | Correct | fs.go:110-172 -a/-r/--max |
| 154 | Find files (name/size/age) | PARTIAL | Correct | ops.go:109-110 big-dirs/big-files; no fs find |
| 155 | Search content (grep in a file/folder) | PARTIAL | Correct | modules.go:203-205,232-236 logs --file --grep (one file) |
| 156 | Restore from .bak | MISSING | Correct | fs.go backupName: PATH.bak, then PATH.bak.<UTC time>; grep restore: 0 results |
| 157 | Edit in a local editor ($EDITOR) then save back | MISSING | Correct | grep EDITOR: 0 results |
| 158 | Structured status | PRESENT | Correct | modules.go:32,77-86 svc status |
| 159 | start/stop/restart/reload + state report + jo… | PRESENT | Correct | modules.go:91-111 (20 journal lines when start/restart/reload fails) |
| 160 | enable/disable | PRESENT | Correct | modules.go:91 svcActionCmd for enable/disable |
| 161 | enable --now in one step | MISSING | Correct | modules.go:100 `systemctl enable` without --now |
| 162 | List units + filter failed/state | PRESENT | Correct | modules.go:117-143 --failed/--state |
| 163 | daemon-reload after changing a unit file | MISSING | Correct | grep daemon-reload: 0 results |
| 164 | mask/unmask | MISSING | Correct | grep mask in modules: 0 results (only policy.go:32) |
| 165 | View unit file & drop-ins (systemctl cat) | MISSING | Correct | grep 'systemctl cat': 0 results |
| 166 | Create/edit an override drop-in (systemctl edit) | MISSING | Correct | grep 'systemctl edit'/override: 0 results |
| 167 | List & manage systemd timers | PARTIAL | Correct | ops.go:137 cron-all (list-timers, text) |
| 168 | User units (systemctl --user) | MISSING | Corrected: PARTIAL→MISSING | modules.go:109 `--no-sudo` only drops sudo; the commands at modules.go:82,100,121 never use `--user`; grep 'systemctl --user': 0 results |
| 169 | Non-systemd init (OpenRC/Alpine, sysvinit) | MISSING | Correct | modules.go:82-121 systemctl only; modules.go:418 apk in pkg |
| 170 | Validate config before reload (nginx -t, apac… | PARTIAL | Correct | ops.go:130,132 nginx-test/apache-test; modules.go:100 reload without validation |
| 171 | Install / remove / update index / upgrade (al… | PRESENT | Correct | modules.go:413-503 pkgShell + DEBIAN_FRONTEND |
| 172 | List pending upgrades | PARTIAL | Correct | modules.go:428-452 upgradable raw text per manager |
| 173 | Security updates only | PARTIAL | Correct | ops.go:127 security-updates (read); grep --security: 0 results |
| 174 | Installed versions | PRESENT | Correct | modules.go:429,435 dpkg-query/rpm tab-separated |
| 175 | Search packages / package info | MISSING | Correct | modules.go:423-453 no search/info |
| 176 | Install a specific version | PARTIAL | Correct | modules.go:485 name validation does not reject = and * |
| 177 | Hold/pin a version (prevent upgrade) | MISSING | Correct | grep apt-mark/versionlock: 0 results |
| 178 | Add a repo/PPA + GPG key | MISSING | Correct | grep add-apt-repository/yum_repository: 0 results |
| 179 | Autoremove / clean the cache | PARTIAL | Correct | ops.go:144 apt-clean (apt only) |
| 180 | dist-upgrade / full-upgrade | MISSING | Correct | modules.go:427 `apt-get upgrade`; grep full-upgrade: 0 results |
| 181 | Detect a needed reboot after an upgrade | PRESENT | Correct | ops.go:33 reboot_required |
| 182 | Install from a local .deb/.rpm file | MISSING | Correct | modules.go:485 PKGS are package names only; no local files |
| 183 | Non-OS packages (snap, flatpak, pip, global npm) | MISSING | Correct | modules.go:414-419 OS managers only |
| 184 | List users (human / all) + sudo members | PRESENT | Correct | modules.go:611-642 user list --all + sudo/wheel/admin groups |
| 185 | Create a user idempotently + SSH key + sudo | PRESENT | Correct | modules.go:646-684 --key/--pubkey/--admin/--shell |
| 186 | Lock an account | PRESENT | Correct | modules.go:686-692 usermod -L -e 1 |
| 187 | Unlock an account | MISSING | Correct | grep 'usermod -U'/unlock in modules: 0 results |
| 188 | Delete a user (dangerous) | PRESENT | Correct | modules.go:696-707; policy.go:39 userdel |
| 189 | Revoke a user's SSH key | MISSING | Correct | see #36; modules.go:673-675 only append |
| 190 | Manage groups (groupadd, add/remove members of… | MISSING | Correct | modules.go:670 only sudo/wheel; grep groupadd/gpasswd: 0 results |
| 191 | Limited sudoers rules (NOPASSWD for specific comm… | MISSING | Correct | ops.go:124 sudoers (read); grep visudo: 0 results |
| 192 | Set/expire a user's password | MISSING | Correct | grep chpasswd/chage/passwd: 0 results |
| 193 | Change shell/home/UID of an existing user | MISSING | Correct | modules.go:668 `id \|\| useradd` (existing user is not changed) |
| 194 | Last login / failed logins | PRESENT | Correct | ops.go:122-123 auth-failures/last-logins |
| 195 | sshd hardening (view effective settings) | PRESENT | Correct | ops.go:125 sshd-config |
| 196 | Idempotent crontab entries by ID | PRESENT | Correct | modules.go:754-770 cron set --schedule, marker # komando:<id> |
| 197 | List entries (with ID) | PRESENT | Correct | modules.go:731-752 cron list (line + id) |
| 198 | Remove entries | PRESENT | Correct | modules.go:772-779 cron rm |
| 199 | Another user's crontab | PRESENT | Correct | modules.go:722-723 --user/--sudo |
| 200 | All system cron (/etc/crontab, /etc/cron.d,… | PRESENT | Correct | ops.go:137 cron-all |
| 201 | Schedule validation | PARTIAL | Correct | modules.go:759-761 only checks the field count / @ prefix |
| 202 | Cron env (MAILTO, PATH, SHELL) | MISSING | Correct | modules.go:765 schedule line only |
| 203 | Disable temporarily without deleting | MISSING | Correct | modules.go:716-781 only list/set/rm |
| 204 | Files in /etc/cron.d | MISSING | Correct | grep cron.d in modules: 0 results |
| 205 | Create a systemd timer | MISSING | Correct | grep timer in modules: 0 results |
| 206 | One-off schedule (at) | MISSING | Correct | grep '\bat\b' scheduler: 0 results |
| 207 | journald per unit, since/until, priority, grep… | PRESENT | Correct | modules.go:176-183 flags; 237-255 journalctl |
| 208 | Log files (tail/grep, sudo) | PRESENT | Correct | modules.go:232-236 --file; modules.go:186 --sudo |
| 209 | Follow (-f), including many hosts | PRESENT | Correct | modules.go:272-273,785-790 followLogs → runFleet stream |
| 210 | Container logs | PRESENT | Correct | modules.go:201,216-230 --container |
| 211 | Kernel log / a specific boot (-k, -b -1) | PARTIAL | Correct | ops.go:115 oom (journalctl -k), ops.go:121 journal-errors; no --kernel/--boot flag |
| 212 | Structured logs (journald fields as JSON) | MISSING | Correct | modules.go:206,238 `-o short-iso` |
| 213 | Compressed/rotated log files (.gz, .1) | MISSING | Correct | modules.go:232-236 one path, no zgrep |
| 214 | Several units at once | MISSING | Correct | modules.go:176 --unit single string |
| 215 | Configure logrotate / force a rotate | MISSING | Correct | grep logrotate: 0 results |
| 216 | Shrink the journal | PRESENT | Correct | ops.go:142 journal-vacuum |
| 217 | Structured facts (OS, kernel, arch, CPU, RAM,… | PRESENT | Correct | ops.go:19-38 factsScript |
| 218 | Facts for all mounts/disks, NICs, hardware (DMI), v… | PARTIAL | Correct | ops.go:27 root disk only |
| 219 | Health summary | PRESENT | Correct | ops.go:106,111,120,136 |
| 220 | Top CPU/memory processes, find a process | PRESENT | Correct | ops.go:112-114 top-cpu/top-mem/process |
| 221 | Structured process list (JSON) | MISSING | Correct | ops.go:112-114 text; grep structured ps: 0 results |
| 222 | Kill a process safely (PID/name, signal, con… | MISSING | Correct | grep pkill/process kill in modules: 0 results (kill only in job.go:388) |
| 223 | Interactive monitors (htop, top, iotop, ncdu) | NON-GOAL | Correct | vision.md:227 TUI |
| 224 | Per-process disk I/O / iostat | MISSING | Correct | ops.go:111 vmstat; grep iostat/iotop: 0 results |
| 225 | Disk usage & largest folders/files | PRESENT | Correct | ops.go:107-110 |
| 226 | Open files / who holds a file/port | PARTIAL | Correct | modules.go:549-573 net ports --sudo; grep lsof/fuser: 0 results |
| 227 | Recent OOM kills | PRESENT | Correct | ops.go:115 oom |
| 228 | Check destination TCP ports from the server (many at o… | PRESENT | Correct | modules.go:512-546 net check |
| 229 | HTTP from the server (status, timing, IP) | PRESENT | Correct | modules.go:575-588 net http |
| 230 | DNS resolution from the server | PARTIAL | Correct | modules.go:590-598 getent ahosts |
| 231 | Listening ports + processes | PRESENT | Correct | modules.go:549-573 ss -tulpnH |
| 232 | Connection statistics | PRESENT | Correct | ops.go:117 connections |
| 233 | Ping / ICMP latency | MISSING | Correct | grep ping in cli: 0 results |
| 234 | Traceroute / mtr | MISSING | Correct | grep traceroute/mtr: 0 results |
| 235 | Structured TLS certificate check (days to expiry, i… | PARTIAL | Correct | ops.go:128-129 cert-expiry/certbot-certs (text); vision.md:208 |
| 236 | Wait until a port/URL is ready (wait_for) | MISSING | Correct | modules.go:512-546 runs once |
| 237 | Routes, interfaces, ARP | PARTIAL | Correct | ops.go:28 ips; grep 'ip route': 0 results |
| 238 | Scan another host's ports | MISSING | Correct | grep nmap: 0 results |
| 239 | Bandwidth between servers | MISSING | Correct | grep iperf: 0 results |
| 240 | Server's public/egress IP | MISSING | Corrected: evidence (status unchanged) | modules.go:579 `net http` uses `-o /dev/null` (body discarded), so it cannot read the egress IP; only via exec |
| 241 | Packet capture | MISSING | Correct | grep tcpdump: 0 results |
| 242 | Check from the laptop to the server (not from the server) | PRESENT | Correct | everything.go:151 test |
| 243 | Controlled reboot + wait for the server to come back + ve… | MISSING | Correct | policy.go:26 power (reboot); grep wait-for-reboot: 0 results |
| 244 | Firewall status | PRESENT | Correct | ops.go:118 firewall |
| 245 | Manage firewall rules (allow/deny port, sour… | MISSING | Correct | policy.go:31 firewall-flush; grep ufw allow: 0 results |
| 246 | sysctl get/set (+ persist to /etc/sysctl.d) | MISSING | Correct | grep sysctl: 0 results |
| 247 | mount / fstab (add, mount, unmount) | MISSING | Correct | grep fstab/mount: 0 results |
| 248 | Swap file | MISSING | Correct | grep mkswap: 0 results; ops.go:24 swap facts |
| 249 | Set hostname | MISSING | Correct | grep hostnamectl: 0 results; ops.go:20 |
| 250 | Set timezone / NTP | PARTIAL | Correct | ops.go:136 time-sync, ops.go:37 timezone; no set |
| 251 | Locale | MISSING | Correct | grep localectl: 0 results |
| 252 | Let's Encrypt certificates (issue/renew) | PARTIAL | Correct | ops.go:129 certbot-certs; vision.md:208 |
| 253 | Git checkout/pull on the server (deploy) | MISSING | Correct | ops.go:265 only a `recipe add` example; grep git in modules: 0 results |
| 254 | SELinux/AppArmor status & mode | MISSING | Correct | grep selinux/getenforce: 0 results |
| 255 | Kernel modules / limits.conf | MISSING | Correct | grep modprobe/limits.conf: 0 results |
| 256 | Clear page cache, docker prune, apt clean | PRESENT | Correct | ops.go:141,143,144 |
| 257 | 39 built-in recipes (health, disk, certs, securit… | PRESENT | Correct | `recipe list` = 39 entries (ops.go:106-144); ops.go:334 run |
| 258 | Your own recipes with {{var}} blanks and defaul… | PRESENT | Correct | ops.go:263-275 add (--desc/--sudo/--read-only/--overwrite); ops.go:151 render |
| 259 | Recipes are treated as write unless --read-only | PRESENT | Correct | ops.go:275 ReadOnly only with --read-only; ux.md:121-126 |
| 260 | Share recipes with the team / other machines | PRESENT | Correct | importer.go:612 export includes recipes; importer.go:196 |
| 261 | Multi-step recipes / recipes with files (scripts) | MISSING | Correct | ops.go:275 Snippet with one Command |
| 262 | Structured recipe output (parser) | MISSING | Correct | ops.go:359 runFleet → text stdout |
| 263 | Community recipe catalog / plugins | NON-GOAL | Correct | vision.md:227 "plugin system" |
| 264 | Audit every action (who, what, where, result) | PRESENT | Corrected: evidence (status unchanged) | common.go:369-396 the audit is written after the action and OpenFile errors are ignored (`return`) — it does not fail closed; meta.go:276 flags --command/--failed/--limit/--target |
| 265 | Filter the audit by time / export | PARTIAL | Correct | meta.go:276 no --since/--until |
| 266 | Send the audit to a central place (syslog/SIEM/webhook) | MISSING | Correct | common.go:391 local file only |
| 267 | Human confirmation for production targets & dangerous… | PRESENT | Correct | common.go:307-347 [y/N] and type the name; non-interactive → reject |
| 268 | Remote approval (ask someone else for permission, ju… | NON-GOAL | Correct | vision.md:227 daemon/server |
| 269 | Central multi-user RBAC | NON-GOAL | Correct | vision.md:227; safety.md:24 |
| 270 | Session recording | MISSING | Correct | see #92 |
| 271 | Secrets never in arguments/output/audit | PARTIAL | Corrected: PRESENT→PARTIAL, –→P1 | vault.go:142 AES-GCM, key.go:385 SECRET_IN_ARGS (secret set); but host.go:95-96 does not validate --password-ref/--sudo-ref (see #5) |
| 272 | Extendable dangerous-command policy | PRESENT | Correct | meta.go:496 deny, meta.go:464 check |
| 273 | Allowlist (only certain commands allowed… | MISSING | Correct | policy.go deny-list only; grep allowlist: 0 results |
