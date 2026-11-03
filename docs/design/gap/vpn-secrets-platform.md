# Feature gap analysis: VPN & networking, secrets & identity, cross-cutting UX & platform

> **Snapshot of `feat/v0.3` (commit 4784fc9), 2026-11-02.** Many MISSING and
> PARTIAL rows below were done in Phases 1–5 and the built-in work, and no
> feature needs kubectl, psql, the aws CLI or openvpn any more (only Pulse
> VPNs still use openconnect).
> Current status: [README.md](README.md#still-open).

Repo: `komando` branch `feat/v0.3`, commit `4784fc9` (binary `bin/komando` version `v0.1.1-0.20261102014502-4784fc9fe746`).
Method: read `inventory.txt`, `extras.txt`, `roothelp.txt`, `docs/design/{vision,ux,network}.md`,
`docs/features/*`, `skills/komando/SKILL.md`, `README.md`, `install.sh`, `Makefile`, `.github/workflows/*`,
and the `internal/cli` code (`vpn.go`, `vpnsession.go`, `tunnel.go`, `key.go`, `root.go`, `meta.go`, `common.go`,
`host.go`, `importer.go`, `everything.go`), `internal/vault/vault.go`, `internal/netx`, `internal/out/out.go`,
`internal/sshx/client.go`. The binary was only run with `--help`/`schema`/`config show`/`__complete`
in a scratch `KOMANDO_HOME`; no connection to any server.

Status legend: **PRESENT** (exists, with evidence) · **PARTIAL** (exists, but something is missing) ·
**MISSING** (checked in code/docs, not found) · **NON-GOAL** (excluded by `vision.md`).
Priority applies only to gaps: **P1** (daily need / security / blocks agents), **P2**, **P3**.
Non-goal quotes from the `vision.md` section "Non-goals":
- N1: "GUI, TUI, plugin system, or daemon/server. komando stays a pure CLI."
- N2: "Infrastructure as Code, cloud provisioning, or GitOps."
- N3: "Monitoring or alerting that runs continuously."
- N4: "Replacing full tools (`psql`, `kubectl`, `terraform`, `helm`)."

---

## A. VPN & network access

### A1. General VPN model and paths (`--via`)

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Path chain VPN → bastion → target for all targets | `ssh -J`, Termius | PRESENT | `--via a,b` in `host add/edit`, `conn add/edit`; `docs/design/network.md` "One concept: `--via`" | — |
| Many VPNs active at once, safe with clashing subnets | — (OS VPN is usually one) | PRESENT | userspace/netstack per command; `network.md` "Main idea"; `docs/features/vpn.md` | — |
| Connect automatically when a target needs a VPN | — | PRESENT | `vpn.go` Long help: "A command that needs it connects it" | — |
| Background session per VPN, reused + disconnected when idle | `tailscale up`, `nmcli` | PRESENT | `vpn up/down/status`, `vpn serve` (hidden), `config set vpn_idle` (default 30m); `netx.ReapIdle()` in `root.go` | — |
| MFA always done by a human, agent gets `VPN_LOGIN_REQUIRED` | — | PRESENT | `--mfa`, `vpnsession.go` (VPN_LOGIN_REQUIRED), owner decision in `network.md` | — |
| VPN status: connected since when, used by whom | `wg show`, `tailscale status` | PARTIAL | `vpn status` shows sessions; no statistics yet (last handshake, rx/tx bytes, latency, assigned IP) | P3 — light diagnostics, not a daily need |
| Test connectivity through VPN | `tailscale ping`, `ping` | PRESENT | `komando test kind:vpn` uses `--check host:port`; alias `test`/`ping` | — |
| Change a VPN without remove-and-add | `nmcli con modify` | PARTIAL | no `vpn edit` (inventory has only add/down/list/rm/show/status/test/up); change via `vpn add --overwrite`. Changing `--password-ref`/`--check`/group means repeating all flags | P2 — consistency with `host edit`/`conn edit` (ux.md §1 verb `edit`) |
| Route clash detection for OS-mode VPN | — | PRESENT | `internal/netx/routes.go`, commit 7149b1c; `network.md` phase 4 | — |
| Audit of VPN connect/disconnect | — | PRESENT | `audit(st, "vpn.up", ...)` in `vpnsession.go` | — |
| `doctor` checks the needed VPN clients | — | PRESENT | `meta.go` doctor: `vpnClients(v)` + `installHint` | — |
| DNS inside the VPN (split DNS) without changing laptop DNS | `wg-quick` DNS=, Tailscale MagicDNS | PARTIAL | WireGuard: userspace resolver from `DNS=` (`netx/wireguard.go` line 93; search domain is ignored). Search domain and MagicDNS for openconnect/ocproxy are not guaranteed | P3 |
| Kill switch / change the laptop's default route | WARP, Mullvad | MISSING | not excluded by `vision.md` "Non-goals" (N1–N4 do not mention it), so not a NON-GOAL; but deliberately not built: `network.md:169` "komando never changes the laptop's routes, DNS, or firewall" | P3 — do not build while the `network.md` decision holds |
| VPN in menu bar / status GUI | Tunnelblick, Viscosity | NON-GOAL | N1 "GUI, TUI ... komando stays a pure CLI" | — |
| Corporate HTTP(S) proxy (`HTTPS_PROXY`, CONNECT proxy) | `aws`, `kubectl`, `gh` honor `HTTPS_PROXY` | PARTIAL | `storage` (S3) already honors `HTTPS_PROXY`: `internal/storex/storex.go:72` clones `http.DefaultTransport` (which has `ProxyFromEnvironment`; turned off only when `--via` is set). Cluster and registry do not yet: `internal/kube/kube.go:236`, `internal/registry/registry.go:43` build `http.Transport{}` without `Proxy`. SSH/db/cache do not go through an HTTP proxy; VPN kind is only `socks`, there is no `http-proxy`. `ux.md:295` edge case mentions "corporate proxy" | P2 — offices with a mandatory proxy cannot use cluster/registry |

### A2. WireGuard (wg / wg-quick)

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Import wg-quick config, keys move to vault | `wg-quick up` | PRESENT | `vpn add NAME wireguard --config`; `netx.StripWGKeys` → `secret:NAME-key`, `-psk` | — |
| Runs in-process without root | wireguard-go, `wg-quick` (root) | PRESENT | `netstack.CreateNetTUN` in `netx/wireguard.go:225` | — |
| MTU, multiple addresses, PSK | `wg-quick` | PRESENT | `WGConfig.MTU`, PSK ref | — |
| `PostUp`/`Table`/`ListenPort` | `wg-quick` | MISSING | deliberately ignored (`netx/wireguard.go:119`): does not touch the laptop's network. Decision in `network.md:169`, not `vision.md` "Non-goals", so not a NON-GOAL | P3 — do not build (runs scripts/changes laptop routes) |
| Create a WG key pair / new peer | `wg genkey`, `wg pubkey` | MISSING | no `vpn key`/gen; `key gen` is SSH only | P3 — usually the VPN admin creates the config |
| Handshake/transfer statistics | `wg show` | MISSING | `vpn status` does not show them | P3 |
| Warning that the original `.conf` file still holds keys | — | PRESENT | note in `vpn add` output ("still holds the keys") | — |

### A3. OpenVPN / Pritunl

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| `.ovpn` profile (also Pritunl) | `openvpn`, Pritunl client | PRESENT | kind `openvpn`, alias `pritunl` (`vpn.go`) | — |
| Without changing the laptop's network (Docker container) | — | PRESENT | `openvpnContainer` in `vpnsession.go`; needs Docker | — |
| OS mode with sudo | `sudo openvpn` | PRESENT | `--os-mode`; pid in `/var/run`, log to syslog | — |
| Filtering of dangerous directives (`up`, `script-security`, file paths) | — | PRESENT | `ovpnAllowed`, `checkOVPN` (inline-only for ca/cert/key) | — |
| OpenVPN static challenge / OTP | `openvpn --static-challenge` | MISSING | the directive passes the filter (`vpn.go:61`), but there is no way to type the OTP: container mode `docker run -d` + `--daemon` (`ovpn/entrypoint.sh:13`), OS mode `openvpn --daemon` with an `--auth-user-pass` file (`vpnsession.go:258-264`); both have no stdin, including during interactive `vpn up` | P3 |
| OpenVPN 3 / DCO / Access Server SAML | `openvpn3` | MISSING | OpenVPN 2 only | P3 |
| OpenVPN without Docker and without sudo (userspace) | `ooni/minivpn` | MISSING | `network.md` mentions evaluating minivpn; not built | P3 |

### A4. openconnect family

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| GlobalProtect, Fortinet, AnyConnect/ocserv, Pulse/Ivanti, F5 | `openconnect --protocol=` | PRESENT | `netx.Kinds` protocol `gp`, `fortinet`, `anyconnect`, `pulse`, `f5`; via `ocproxy` (local SOCKS) | — |
| Juniper Network Connect (`nc`) and Array (`array`) protocols | `openconnect --protocol=nc/array` | MISSING | not in `netx.Kinds` | P3 — rare |
| SAML/SSO login via browser (GP/AnyConnect/Fortinet SSO) | `openconnect --external-browser`, `gp-saml-gui` | MISSING | `vpnsession.go:205` only `--user`, `--passwd-on-stdin`; no SSO option. Many corporate VPNs are now SAML-only | P2 — corporate SAML VPNs cannot be used |
| Server certificate pinning (`--servercert`) | `openconnect --servercert` | MISSING | no flag; relies on system CA | P2 — secure by default for self-signed portals |
| Auth group / realm (`--authgroup`, `--usergroup`) | `openconnect --authgroup` | MISSING | no flag | P2 — many AnyConnect portals need a group |
| Client certificate (`-c`, `-k`, PKCS#12) | `openconnect -c` | MISSING | no flag | P3 |
| GlobalProtect HIP report (`--csd-wrapper`) | `openconnect --csd-wrapper` | MISSING | — | P3 |
| `tunsocks` as an alternative to `ocproxy` | `tunsocks` | MISSING | only `ocproxy` | P3 |

### A5. Tailscale / Headscale

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Join a tailnet in userspace with auth key / browser login | `tailscale up` | PRESENT | kind `tailscale`; auth key via `--password-ref`, no key → `MFA` (browser login) | — |
| Headscale (own login server) | `tailscale up --login-server` | PRESENT | `--server` | — |
| `tailscale status` / peer list | `tailscale status` | PARTIAL | only `vpn status`/`test`; no list of tailnet nodes | P3 |
| `tailscale ping` (direct/DERP) | `tailscale ping` | MISSING | — | P3 |
| Exit node | `tailscale up --exit-node` | MISSING | not relevant for target access (an exit node changes egress) | P3 |
| Tailscale SSH | `tailscale ssh` | PARTIAL | hosts in the tailnet can be reached via `--via tailnet` with normal SSH; Tailscale SSH (auth by the tailnet, no keys) is not supported | P3 |
| `serve` / `funnel` | `tailscale serve/funnel` | NON-GOAL | publishes local services; outside a devops "client"; close to N1 (server) | — |
| Send files (`tailscale file cp`) | Taildrop | MISSING | `upload`/`download` via SFTP already meet the need | P3 |
| ACL tags / ephemeral node | `--advertise-tags`, ephemeral auth key | PARTIAL | depends on the auth key type; no flag | P3 |

### A6. Other mesh/VPNs

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| ZeroTier | `zerotier-cli join` | PARTIAL | only via kind `system` + `--check` (VPN managed by the OS); no `zerotier` kind (userspace libzt exists) | P3 |
| Nebula, NetBird | `nebula`, `netbird up` | PARTIAL | only via `system` | P3 |
| Built-in OS L2TP/IPsec/IKEv2 | `scutil --nc`, `nmcli` | PRESENT | alias `l2tp/ipsec/ikev2 = system`, `--service` | — |
| Cloudflare WARP (Zero Trust client) | `warp-cli connect` | PARTIAL | via `system --check`; `vpn up` does not run `warp-cli` | P3 |

### A7. Zero-trust / just-in-time access

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| AWS SSM Session Manager: shell/exec to EC2 without open SSH | `aws ssm start-session`, ProxyCommand `AWS-StartSSHSession` | MISSING | no kind/`--via` step for SSM; `ProxyCommand` is not in the host model | **P1** — standard way to reach private EC2; universal devops client |
| AWS SSM port forwarding (to RDS/ElastiCache) | `AWS-StartPortForwardingSessionToRemoteHost` | MISSING | same | **P1** — same, for `db`/`cache` on AWS |
| Generic `ProxyCommand` (escape hatch for SSM/IAP/cloudflared/tsh) | OpenSSH `ProxyCommand` | MISSING | `host.go` `import ssh-config` reads only `HostName/User/Port/IdentityFile/ProxyJump`; `ProxyCommand` is dropped **silently**, which breaks `ux.md` §9 "Unsupported fields are reported" | **P1** — imported hosts fail to connect with no explanation |
| GCP IAP TCP tunnel | `gcloud compute start-iap-tunnel`, `gcloud compute ssh --tunnel-through-iap` | MISSING | — | P2 |
| Azure Bastion | `az network bastion ssh/tunnel` | MISSING | — | P3 |
| Cloudflare Access (SSH/TCP) | `cloudflared access ssh/tcp` | MISSING | — | P2 — common at startups |
| Cloudflare Tunnel (exposes services) | `cloudflared tunnel` | NON-GOAL | running a connector = server/daemon (N1) | — |
| Teleport (`tsh ssh`, `tsh db`, `tsh kube`), short-lived certificates | `tsh` | MISSING | no integration; SSH certificates from files are also not loaded (see B3) | P2 |
| HashiCorp Boundary | `boundary connect` | MISSING | — | P3 |
| StrongDM | `sdm connect` | MISSING | — | P3 |

### A8. Proxies and forwarding for other apps

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Local / remote forward / SOCKS5 over SSH in the background | `ssh -L/-R/-D` | PRESENT | `tunnel start -L/-R/-D`, `tunnel list/stop` | — |
| Tunnel to a conn by name (via `--via`/VPN) | — | PRESENT | `tunnel start app-db [--port]` | — |
| SOCKS "inside" a VPN for the browser | — | PRESENT | `tunnel start office -D 1080` (`docs/features/vpn.md`) | — |
| Binding a tunnel on non-loopback needs confirmation | — | PARTIAL | default `127.0.0.1` (`tunnel.go:66,77`), but `-L 0.0.0.0:8080:...` is accepted without `--yes`. `network.md` "Security": "unless given `--bind` (needs `--yes`)" — not enforced (`guardSafety` is not called in `tunnel.go`) | **P1** — opens DB/SSH ports to the local/cafe network; secure by default |
| Use an existing (corporate) SOCKS proxy | proxychains | PRESENT | kind `socks` (`--address`, `--user` + `--password-ref`) | — |
| Force other apps through a proxy | `proxychains`, `tsocks` | PARTIAL | komando provides SOCKS (`tunnel -D`), but does not wrap other programs | P3 — native tools via `tunnel` are enough (ux.md §12) |
| VPN-over-SSH for whole subnets | `sshuttle` | PARTIAL | `tunnel -D` + `--via` covers komando's own needs; no "route subnet" mode | P3 — changing laptop routes conflicts with `network.md` |
| Expose local services to the internet | `ngrok` | NON-GOAL | becomes a public server (N1); `tunnel -R` to your own server already exists | — |
| Forward to a Kubernetes pod / service | `kubectl port-forward` | PARTIAL | `cluster run` classifies `port-forward` as destructive (`cluster.go:863`); no `tunnel start` to a k8s service | P2 — daily dev need (outside this domain, noted) |

---

## B. Secrets & identity

### B1. Local vault

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Encrypted vault (AES-256-GCM, scrypt), list of secret names without values | `pass`/`pass ls`, `gopass ls`, ansible-vault, `vault kv list` | PRESENT | `internal/vault/vault.go`; mode `keyfile` or `passphrase` (`KOMANDO_VAULT_PASS`); `secret list` shows only names and `updated_at` | — |
| Secret input without arguments (hidden prompt, `--from-env`, stdin) | `gh secret set` | PRESENT | `secret set`; `SECRET_IN_ARGS` rejects positional values | — |
| `--reveal` only for humans | 1Password (biometrics), `op read` needs a session | PARTIAL | `secret get --reveal` runs from a pipe without TTY/confirmation (`key.go:447-452`; only logged as `secret.reveal` in audit); only a rule in SKILL/AGENTS.md. Vision: "passwords are never seen by AI" | **P1** — an agent can read all passwords; secure by default |
| Safe `secret rm` | `vault kv delete` (versions remain) | PARTIAL | `key.go` `rm`: no `IN_USE` check (hosts/conns/vpns that refer to it), no confirmation/`--yes`, **no audit line**, permanent delete. `ux.md` §8 asks for `IN_USE` when deleting something still in use | **P1** — one command can cut access to prod without a trace |
| `secret set` does not overwrite silently | `gh secret set` (overwrites), `pass insert` (asks) | PARTIAL | `vault.Set` always overwrites; no `--overwrite` (ux.md §3 standard flag name) | P2 |
| Store `vault.key` in the OS keyring (macOS Keychain, libsecret, Windows Credential Manager) | `aws-vault`, `gh auth` (keyring), `docker-credential-*` | MISSING | `vault.key` is stored next to `vault.json` (0600). Possible via the `security`/`secret-tool` CLI without cgo | P2 — secure by default; stealing one folder = all secrets |
| Change passphrase / re-key vault | `ansible-vault rekey`, `gopass` | MISSING | no command | P2 |
| Lock/unlock vault temporarily (session) | `op signin`, `bw unlock` | MISSING | keyfile is always open; passphrase per process via env | P3 |
| Secret version history / restore | Vault KV v2, gopass (git) | MISSING | one value per name, only `UpdatedAt` | P3 |
| Generate a random password | `pass generate`, `op item create --generate-password` | MISSING | — | P3 |
| Rename/copy a secret | `gopass mv/cp` | MISSING | — | P3 |
| See who uses a secret | — | MISSING | `secret list` only `name`,`updated_at`; `host show`/`conn show` show the ref from the target side | P2 — before rotation/deletion |
| Secret rotation (change on server + vault at once) | Vault dynamic, AWS SM rotation | MISSING | no `secret rotate`; manual: `user`/`db query ALTER USER` + `secret set` | P2 |
| File permission check for `file:` refs | `ssh` (rejects 0644 keys) | MISSING | `vault.Resolve` reads `file:` without a mode check, even though `ux.md` §7 says "file permissions too loose → error" | P2 |

### B2. References to external secret managers

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| `env:`, `file:` | — | PRESENT | `vault.Resolve` | — |
| 1Password (`op read`) | `op read` | PRESENT | `op://VAULT/ITEM/FIELD` → `op read --no-newline` | — |
| 1Password `op run` / `op inject` (env/template) | `op run --env-file`, `op inject` | MISSING | only one value per ref; no env injection (see B4) | P2 |
| HashiCorp Vault KV | `vault kv get -field` | PRESENT | `vault:PATH#FIELD` | — |
| Vault dynamic DB credentials + lease renew/revoke | `vault read database/creds/role` | MISSING | refs are KV only; no leases | P2 — short-lived credentials = best practice |
| Vault SSH CA (sign public key) | `vault ssh -mode=ca`, `vault write ssh/sign/...` | MISSING | see B3 (SSH certificates from files) | P2 |
| AWS Secrets Manager | `aws secretsmanager` | PRESENT | `aws-sm:NAME[#KEY]` | — |
| AWS SSM Parameter Store (SecureString) | `aws ssm get-parameter --with-decryption` | MISSING | only Secrets Manager | P2 — very common on AWS |
| Google Secret Manager | `gcloud secrets versions access` | PRESENT | `gcp-sm:NAME[@PROJECT]` (always `latest`, no version choice) | — |
| Azure Key Vault | `az keyvault secret show` | MISSING | aws-sm and gcp-sm exist, Azure not yet; not equal for a "universal client" | P2 |
| Bitwarden / Vaultwarden | `bw get password` | MISSING | — | P2 — popular in small teams |
| `pass` / `gopass` | `pass show` | MISSING | — | P2 — cheap to add (`external()` pattern) |
| sops (encrypted files in git) | `sops -d --extract` | MISSING | — | P2 — common in GitOps repos |
| age | `age -d` | MISSING | — | P3 |
| Doppler, Infisical | `doppler secrets get`, `infisical secrets get` | MISSING | — | P3 |
| aws-vault / AWS profiles | `aws-vault exec` | PARTIAL | `aws-sm:` uses the `aws` CLI, so `AWS_PROFILE`/SSO apply; no profile choice per ref | P3 |
| Kubernetes Secret as a source | `kubectl get secret` | MISSING | `cluster get` hides Secret values (correct), no `k8s:` ref | P3 |
| External MFA/login stays with the human | — | PRESENT | `external()` runs the native CLI, message "(is it signed in?)" | — |
| Cache external ref results within one command | `op` session cache | PARTIAL | `external()` is called on every resolve, 60s timeout; many hosts with the same ref = many calls | P3 |

### B3. SSH identity & keys

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Generate/register/deploy SSH keys | `ssh-keygen`, `ssh-copy-id` | PRESENT | `key gen/add/deploy/list/show/rm/edit` | — |
| Key passphrase from the vault | — | PRESENT | `key add --passphrase-ref` | — |
| ssh-agent (including 1Password/Secretive/FIDO agents) | `ssh-agent` | PRESENT | `sshx/client.go:322` `agent.NewClient`; `IdentityAgent` from ssh_config is not read (only `SSH_AUTH_SOCK`) | — |
| SSH certificate from file (`id_ed25519-cert.pub`) | OpenSSH `CertificateFile` | MISSING | `sshx` loads only the private key; certificates work only if they are in the agent | P2 — needed by Vault SSH CA/Teleport/step-ca |
| Per-host `IdentityAgent` | OpenSSH | MISSING | — | P3 |
| SSH key rotation across many servers | `ssh-copy-id` + remove old | PARTIAL | `key deploy` (idempotent) exists; no "remove old key from authorized_keys" | P2 |

### B4. Injecting secrets into commands/processes

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Secret as an env var in a remote command without the agent seeing it (`--env DB_PASS=secret:x`) | `op run`, `doppler run`, Ansible `no_log` | MISSING | `exec/job/script --env` and `host --env` accept literal values (`common.go:475` `parseEnv`, without `vault.Resolve`). An agent that needs a password in a script must use `--reveal` (breaks the vision) | **P1** — blocks agents; core of "passwords are never seen by AI" |
| Run local tools with vault secrets in env | `op run -- cmd`, `aws-vault exec` | PARTIAL | only for specific tools: `db shell` (psql/mysql) and tunnel; no general wrapper | P2 |
| Load `.env` (direnv) | `direnv`, `dotenv` | PARTIAL | `import env` reads `.env` to create a conn; does not export `.env` to commands | P3 |
| Upload a file with secrets (template) to a server | `op inject`, Ansible template + vault | MISSING | `fs write --content/--from` is literal; no `{{secret:x}}` | P2 — e.g. write an app's `.env` without exposing the password |
| `host --env` stored in plain text in `state.json` | — | PARTIAL | host `--env` values are stored as plain text; no warning if they contain secrets | P2 |

### B5. Team sharing & central identity

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Share the vault between team members | 1Password shared vault, gopass multi-recipient, sops+age | PARTIAL | local vault per person; the team path = external refs (`op://`, `vault:`). No multi-recipient vault | P2 — document the "team uses external refs" pattern first |
| Encrypted export including secrets | `ansible-vault`, `gopass export` | MISSING | `export` "no passwords"; `vision.md` Migration: "without secrets (or encrypted)" not built yet | P2 |
| SSO/OIDC login to komando | `gcloud auth login`, `az login` | NON-GOAL | there is no komando server (N1) | — |

---

## C. Cross-cutting UX & platform

### C1. Configuration, profiles, env

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| One config file + `config show/set` | `aws configure`, `gh config` | PRESENT | `config show/set` (host_key_policy, default_user, timeouts, parallel, max_output_bytes, audit, audit_sql, vpn_idle) | — |
| Guard for security settings | — | PRESENT | `guardSafety` (`SAFETY_SETTING`) | — |
| Profiles/contexts (several inventories: work vs client) | `aws --profile`, `kubectl config use-context`, `az account set` | PARTIAL | only `KOMANDO_HOME=...`; no `--home`/`context use`. Groups/tags cover part of the need | P3 — groups + selectors are enough (KISS) |
| Override settings via env (`KOMANDO_TIMEOUT`, `KOMANDO_PARALLEL`) | `AWS_*`, `KUBECONFIG` | PARTIAL | only `KOMANDO_HOME`, `KOMANDO_OUTPUT`, `KOMANDO_ACTOR`, `KOMANDO_VAULT_PASS` | P3 |
| Per-project configuration (file in the repo) | `.terraform`, `ansible.cfg` | MISSING | — | P3 |

### C2. Output

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Stable JSON envelope + exit code | `gh --json`, `kubectl -o json` | PRESENT | `internal/out`, `meta.contract=1`, `docs/features/output.md` | — |
| Automatic text on TTY, JSON in a pipe | `gh` | PRESENT | `-o auto` (`root.go` `outputFormat`), `KOMANDO_OUTPUT` | — |
| `--pretty` JSON | `jq .` | PRESENT | `--pretty` | — |
| NDJSON streaming | `kubectl get -w -o json` | PRESENT | `exec --stream`, `logs --follow` | — |
| YAML | `kubectl -o yaml`, `az -o yaml` | MISSING | `out.go:89` "yaml-ish not supported, keep it simple" — KISS decision | P3 |
| CSV/TSV (e.g. `db query`, `list` results) | `az -o tsv`, `psql --csv` | MISSING | json/text only | P2 — exporting query results to a spreadsheet is often requested |
| Built-in filter/query (JMESPath/jq) | `aws --query`, `gh --jq`, `az --query` | MISSING | users must use `jq` | P3 — `jq` is enough; KISS |
| Output template (Go template) | `gh --template`, `docker --format` | MISSING | — | P3 |
| Choose columns/fields | `gh --json f1,f2`, `kubectl -o custom-columns` | MISSING | — | P3 |
| `--no-headers` | `kubectl --no-headers` | MISSING | text tables always have headers | P3 |
| Color & `NO_COLOR` | `gh`, `kubectl` | PRESENT | no color at all (grep finds no ANSI codes), so `NO_COLOR` is met automatically; `ux.md` §4 | — |
| Truncated output with `truncated` + hint | `kubectl logs --limit-bytes` | PRESENT | `--max-output`, `--limit`, `ux.md` §4 | — |
| Pagination (cursor/continue) | `aws --starting-token`, `gh --paginate` | PARTIAL | `--limit` + `truncated`; no continuation token (`storage ls`, `registry ls`, `cache keys`) | P3 |
| `--quiet` (exit code only) | `grep -q`, `gh -q` | MISSING | — | P3 |
| `--watch`/refresh | `kubectl get -w`, `watch` | MISSING | `job wait`, `logs --follow` exist; repeated status refresh is close to N3 | P3 |

### C3. Help, completion, documentation

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| `--help` with real examples | `gh`, `kubectl` | PRESENT | `Example:` in 66 of ±155 commands (`grep -c 'Example:' internal/cli/*.go`); `TestConventions` does not check examples, so commands like `vpn up`, `secret get` have no example | — |
| "Did you mean" for commands/selectors | `git`, `kubectl` | PRESENT | `komando lst` → suggestion; `ux.md` §2.4 | — |
| `komando` without arguments: first three steps | `gh` | PARTIAL | shows the full long help, not "three steps" (`ux.md` §10) | P3 |
| Static completion bash/zsh/fish/powershell | all CLIs | PRESENT | `completion` (cobra) | — |
| Dynamic completion of host/conn/group/tag/VPN/secret names | `kubectl` (resource names), `gh` | MISSING | 0 `ValidArgsFunction`/`RegisterFlagCompletionFunc`; `__complete exec ""` is empty. `ux.md` §10 promises it | **P1** — daily need, beginner-friendly, promised in ux.md |
| Man page | `git`, `gh` (man) | MISSING | cobra/doc can generate it in `make dist` | P3 |
| Offline docs | `gh help`, `az find` | PRESENT | `guide`, `schema`, `--help`, `docs/features/` | — |
| i18n | — | NOT PLANNED | decided English-only; Indonesian translations (`README.id.md`, `docs/features/id/`) removed | — |
| Positioning in root help | — | PARTIAL | `root.go` Short/Long still says "servers (SSH), databases, caches and storage", not yet cluster/registry/VPN/secret (`vision.md` gap 1) | P3 |

### C4. Logging, debug, diagnostics

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| `--verbose`/`--debug`/trace (SSH handshake, HTTP, `--via` path) | `ssh -vvv`, `kubectl -v=8`, `aws --debug` | MISSING | no flag; `-v` is used for `--version` | P2 — diagnosing failed VPN/bastion connections |
| `doctor` (local checks) | `flyctl doctor`, `brew doctor` | PRESENT | state, keys, ssh-agent, VPN clients, platform | — |
| `doctor` checks the external secret CLIs (`op`, `vault`, `aws`, `gcloud`) that are referenced | — | MISSING | doctor does not check external refs | P3 |
| VPN log per session | — | PRESENT | log file per session (`vpnsession.go` `logFile`) | — |

### C5. Distribution, releases, platform

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Install script + checksum | `flyctl`, `doctl` | PRESENT | `install.sh` (verifies `checksums.txt`) | — |
| `go install` | — | PRESENT | README | — |
| Homebrew | `brew install gh` | MISSING | no tap/formula | P2 — most common install path on macOS; beginner-friendly |
| apt/rpm (deb/rpm, repo) | `gh`, `doctl` | MISSING | `make dist` produces only tar.gz | P3 |
| Scoop/winget | `gh`, `az` | MISSING | Windows is not supported | P3 |
| Docker image (for CI) | `amazon/aws-cli`, `bitnami/kubectl` | MISSING | — | P3 |
| Nix | nixpkgs | MISSING | — | P3 |
| Native Windows | all comparable CLIs | MISSING | `Makefile` `PLATFORMS` only linux/darwin; `install.sh` refuses; `syscall.SysProcAttr{Setsid}` in `vpnsession.go` | P2 — universal client; WSL as a temporary path is already documented |
| Signed releases / provenance / SBOM | `cosign`, GitHub attestations, `gh` (signed) | PARTIAL | only `checksums.txt` from the same source (`release.yml`); no signature/SBOM | P2 — a tool that holds SSH keys; secure by default |
| Version check / self-update | `gh` (notification), `flyctl version upgrade` | MISSING | `version` only prints the version; rerun `install.sh` | P2 — security patches arrive fast (SECURITY.md: only the latest release is supported) |
| Telemetry policy | `gh` (opt-out), `az` | PARTIAL | no telemetry (no outbound network code), but not stated in README/SECURITY | P3 — write "no telemetry" |
| Single pure Go binary (no size limit) | — | PRESENT | `CGO_ENABLED=0` + `-trimpath -s -w` in `Makefile` `dist`; release builds measured at 35 MB (darwin/arm64) and 37 MB (linux/amd64). Local `bin/komando` is 51 MB because it is a normal build; rule `vision.md:185` | — |

### C6. Inventory, moving machines, teams

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Universal selectors (glob, `@group`, `tag:`, `label:`, `kind:`, `!`) | Ansible patterns, `kubectl -l` | PRESENT | `select.go`, `docs/features/targets.md` | — |
| Import from other tools | — | PRESENT | `import` with sources `ssh-config`, `pgpass`, `mycnf`, `env`, `kubeconfig`, `docker`, `filezilla`, `rclone`, `dbeaver`, `komando` (`importer.go:49`) | — |
| Import `~/.aws` (storage conn), Termius, TablePlus | — | PARTIAL | the `vision.md` Migration table lists `aws`, `termius`, `tableplus`; not present yet (`importer.go`) | P3 |
| Export/import to move machines | `gh` (none), Termius sync | PRESENT | `export [TARGET] --to`, `import komando` | — |
| Automatic sync between machines | Termius cloud sync | NON-GOAL | needs a server/daemon (N1); export file + git is enough | — |
| Central team inventory | Ansible inventory in git, Teleport | PARTIAL | the export file can be committed; `import komando FILE` skips names that already exist (reported as `skipped`), and `--overwrite` replaces the whole entry; no per-field merge / diff report | P2 — the "team inventory in git" pattern needs documenting |
| Dynamic inventory from cloud APIs (EC2, GCP, DO, Hetzner) | Ansible dynamic inventory, `doctl compute droplet list` | MISSING | `vision.md`: "cloud VMs" is a candidate after v1.0 | P2 — cloud servers change often |
| One-shot health summary | `flyctl status`, `kubectl get` | PARTIAL | `test all`, `recipe run health`, `cluster status`, `facts`; no single "status @prod" that combines them | P3 |
| Cost/usage | `aws ce`, `doctl balance` | MISSING | `vision.md` "Non-goals" N2 mentions only IaC, cloud provisioning, and GitOps; viewing costs is not excluded, so not a NON-GOAL. There is no cost command | P3 — not a daily need; judge with the "criteria for adding a family" |

### C7. Process safety, governance, audit

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Global `--dry-run` | `terraform plan`, `kubectl --dry-run=server` | PRESENT | global flag; `dryrun_test.go` | — |
| Protected + `--yes`, human confirmation `[y/N]`/type the name | `terraform apply` approval | PRESENT | `ux.md` §6, `confirmProtected` | — |
| Policy for destructive commands + `--allow-dangerous` | — | PRESENT | `policy list/check/deny/allow` | — |
| Two-person approval / RBAC | Teleport access request, Boundary | NON-GOAL | needs a server (N1); protected + human prompt is the replacement | — |
| Local audit log (actor, target) | CloudTrail, `ansible` log | PRESENT | `audit.jsonl` (`common.go:370`: ts, command, ok, dry_run, actor, hosts, remote), `KOMANDO_ACTOR`, filter `--target/--command/--failed/--limit`. The `--via` path is not recorded (only `tunnel.start` records the spec) | — |
| Audit **fails closed** | — | PARTIAL | `common.go` `audit()`: if the file cannot be opened → silent `return`, the result of `f.Write` is ignored. Conflicts with `ux.md` §6 "Fail closed: if the audit cannot be written, the change is refused" | **P1** — a security promise not kept |
| Filter audit by time (`--since/--until`) and actor | `aws cloudtrail lookup-events` | MISSING | only limit/target/command/failed | P2 |
| Send audit to syslog/SIEM/HTTP | auditd, Vector | MISSING | local JSONL file (can be tailed by other tools) | P2 — teams/companies need a central trail |
| Audit file rotation | logrotate | MISSING | `audit.jsonl` keeps growing; `audit` reads the whole file | P3 |
| Notifications (Slack/webhook) after an action/job | Ansible callback, `gh` notifications | MISSING | continuous notifications are a NON-GOAL (N3); a one-time notification when `job wait` finishes does not exist | P3 |
| Scheduling | cron, `gh workflow` | PRESENT | `cron set/list/rm` manage the **remote** crontab (`modules.go:716`); scheduling on the laptop = daemon (N1), so the missing part is a NON-GOAL, not a gap | — |

### C8. AI agent integration

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Skill for Claude Code, Codex, Cursor, Gemini CLI | `claude mcp add`, `npx skills add`, Cursor rules (`.cursor/rules`) | PRESENT | `guide install [--project]` → `.claude/skills`, `.agents/skills`; `skills/komando/SKILL.md`, `AGENTS.md` | — |
| Agent playbook | — | PRESENT | `komando guide` (`internal/cli/guide.md`) | — |
| Machine schema of all commands/flags/exit codes | `gh api`-style, OpenAPI | PARTIAL | `schema [--compact]` exists, but its fixed part is stale: `meta.go:243-253` `target_selectors` mentions only "hosts" and has no `kind:`; `secret_refs` only `secret:` / `env:` / `file:` (no `op://`, `vault:`, `aws-sm:`, `gcp-sm:`). Agents are told to use `schema` as the source of truth | **P1** — agents get wrong info; cheap to fix |
| Schema of the `data` shape per command (output JSON Schema) | — | MISSING | envelope only; the `data` field is not described | P2 — stronger v1.0 contract |
| MCP server (stdio) | many devops CLIs now have MCP | MISSING | none; skill + CLI already work. A stdio MCP is run by the agent (not a daemon), but adds surface | P2 — non-shell clients (Claude Desktop, IDEs) cannot use komando |
| Automatic actor name for agents | — | PARTIAL | `KOMANDO_ACTOR` is manual; default `$USER` (agent and human look the same in audit) | P2 — audit cannot tell agents apart if it is not set |
| Agent cannot answer prompts | — | PRESENT | prompts appear only when stdin **and** stderr are terminals (`common.go:295` `interactive()`); from a pipe/agent the answer is always "no" (`confirmYes`, `common.go:314`). The answer is read from the TTY stdin, not `/dev/tty` (`ux.md` §6) | — |

### C9. Reliability

| Capability | Comparable tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Idempotency | Ansible | PRESENT | `cron set`, `user add`, `key deploy`, `import`, `fs write --if-changed` | — |
| Limited parallelism | Ansible forks | PRESENT | `-P/--parallel`, `--fail-fast` | — |
| Connection retry/backoff | `aws` (retry mode), Ansible `retries` | MISSING | only `minio.MaxRetry=2` and registry token retry; the guide forbids blind retries | P3 — hint + agent decides is already in line with the design |
| Rate limit (Docker Hub, APIs) | `crane` | MISSING | only `--parallel` | P3 |
| Clean Ctrl-C (exit 130, rollback) | — | PARTIAL | `signal.NotifyContext` in `root.go:64` cancels the context; but `context.Canceled` is mapped to `CANCELLED` with exit **1** (`common.go:122-123`, `out.ExitError`), not 130, and audit does not record `interrupted` as promised in `ux.md:183` (§6) | P3 — agents cannot tell Ctrl-C from a normal error |
| Detached long jobs | `nohup`, Ansible async | PRESENT | `job start/status/logs/wait/kill/rm` | — |
| State safe for concurrent processes | — | PRESENT | `store.Update` with a file lock (`ux.md` §8) | — |
| Fuzzy picker / interactive host picker | `fzf`, `gcloud` interactive | NON-GOAL | close to a TUI (N1: "GUI, TUI ... komando stays a pure CLI"); dynamic completion is the replacement | — |
| User aliases/custom commands | `gh alias set`, `git alias` | PARTIAL | `recipe add` (saved remote command with `{{blank}}`); no aliases for komando's own commands | P3 |

---

## P1 priority summary (ordered by impact)

1. **Secrets into env/remote commands without `--reveal`** (`exec/job/script --env K=secret:x`, `fs write` template) — B4. Without this, agents are forced to read passwords.
2. **`secret get --reveal` without a human gate** — B1. Agents can read all secrets; it should need a TTY/confirmation like `--yes`.
3. **`secret rm` without `IN_USE`, confirmation, and audit** — B1.
4. **Audit fail-open** (`common.go` `audit()` ignores errors) — C7, breaks `ux.md` §6.
5. **Tunnel non-loopback bind without `--yes`** — A8, breaks `network.md` "Security".
6. **AWS SSM Session Manager (shell + port forwarding) as a `--via` step** — A7.
7. **`ProxyCommand` silently dropped on `import ssh-config`** (and no generic ProxyCommand path) — A7, breaks `ux.md` §9.
8. **Dynamic completion of target names** — C3, promised in `ux.md` §10.
9. **Stale `komando schema`** (selectors & secret refs) — C8; agents use the schema as the source of truth.

(Only nine items deserve P1; the next top P2 candidates: openconnect SAML/SSO, `HTTPS_PROXY`, OS keyring for `vault.key`, `--debug`, Homebrew, signed releases, MCP server, Azure Key Vault/Bitwarden/pass/sops.)

## Status counts

Total of 197 capabilities rated (after per-row verification; see the next section):

| Status | Count |
|---|---|
| PRESENT | 68 |
| PARTIAL | 39 |
| MISSING | 81 |
| NON-GOAL | 8 |
| NOT PLANNED | 1 |

Gap priorities (120 PARTIAL/MISSING rows, all now prioritized): P1 = 10 rows (9 themes; SSM shell and SSM port forwarding are counted separately), P2 = 43, P3 = 67 (i18n moved to NOT PLANNED).

Changes from the previous version (PRESENT 68, PARTIAL 40, MISSING 78, NON-GOAL 11; P3 = 64): three NON-GOAL rows
that `vision.md` does not exclude (kill switch, `PostUp`/`Table`/`ListenPort`, cost) became MISSING P3; HTTP(S) proxy
became PARTIAL (storage already honors `HTTPS_PROXY`); OpenVPN static challenge became MISSING; scheduling
became PRESENT (local side is NON-GOAL); Ctrl-C became PARTIAL P3 (exit 1, not 130).

## Per-row verification

Rechecked 2026-11-02 at commit `4784fc9`: each row was checked directly against the code (grep/read file) and the binary
(`KOMANDO_HOME=$(mktemp -d) bin/komando ... --help`), not from the old "Evidence" text. NON-GOAL is only accepted when
the `docs/design/vision.md` section "Non-goals" (lines 221–228) really excludes it; decisions in `network.md`
do not count as NON-GOAL. Paths are relative to `internal/cli/` unless stated otherwise.

| # | Capability (short) | Final status | Check result | Evidence in code |
|---|---|---|---|---|
| 1 | `--via` path chain | PRESENT | Correct | `host.go:55` `--via` (+alias `--jump`), `conn.go:65` `--via`; edit: `host.go:183`, `conn.go:203` |
| 2 | Many VPNs at once | PRESENT | Correct | `netx/netx.go:47` wireguard "many at once"; session per VPN `vpnsession.go:144` |
| 3 | Automatic connect | PRESENT | Correct | `vpn.go:32` Long "A command that needs it connects it" |
| 4 | Session reuse + idle | PRESENT | Correct | `vpnsession.go:540` `serve` `Hidden: true`; `root.go:146` `netx.ReapIdle()`; `meta.go:408` `vpn_idle` (default 30m in `config show`) |
| 5 | MFA by a human | PRESENT | Correct | `netx/netx.go:75` and `vpnsession.go:273` `VPN_LOGIN_REQUIRED`; `vpn.go:322` `--mfa` |
| 6 | VPN status | PARTIAL | Correct | `vpnsession.go:501-510` `vpnStatusRow`: name, kind, up, since, last_used, socks, used_by; no handshake/bytes/IP |
| 7 | Connectivity test through VPN | PRESENT | Correct | `netx/netx.go:361` dial `v.Check`; `everything.go:156` alias `ping` |
| 8 | Change VPN (`vpn edit`) | PARTIAL | Correct | `grep 'Use: *"edit' internal/cli`: only conn/host/key; `vpn.go:327` `--overwrite` |
| 9 | OS-mode route clash | PRESENT | Correct | `netx/routes.go:108` `Clashes`; used in `vpnsession.go:402` |
| 10 | Connect/disconnect audit | PRESENT | Correct | `vpnsession.go:295` `vpn.up`, `vpnsession.go:492` `vpn.down` |
| 11 | `doctor` VPN clients | PRESENT | Correct | `meta.go:581-584` `vpnClients` + `installHint` (`vpnsession.go:83,100`) |
| 12 | Split DNS | PARTIAL | Correct | `netx/wireguard.go:93` "search domains are ignored"; `CreateNetTUN(..., c.DNS, ...)` `wireguard.go:225` |
| 13 | Kill switch | MISSING | Corrected: NON-GOAL→MISSING (P3) | `vision.md:221-228` does not mention it; the decision is in `network.md:169` |
| 14 | VPN menu bar / GUI | NON-GOAL | Correct | `vision.md:227` N1 "GUI, TUI ... pure CLI" |
| 15 | Corporate HTTP(S) proxy | PARTIAL | Corrected: MISSING→PARTIAL | `storex/storex.go:72` clones `http.DefaultTransport` (proxy env active); `kube/kube.go:236`, `registry/registry.go:43` without `Proxy`; `grep ProxyFromEnvironment internal`: 0 results |
| 16 | wg-quick import, keys to vault | PRESENT | Correct | `vpn.go:199-207` `netx.StripWGKeys` → `secret:NAME-key`, `-psk` |
| 17 | WG without root | PRESENT | Correct | `netx/wireguard.go:225` `netstack.CreateNetTUN` |
| 18 | MTU, addresses, PSK | PRESENT | Correct | `netx/wireguard.go:26-33` `DNS`, `MTU`, `PresharedKey`; `Addresses` slice |
| 19 | `PostUp`/`Table`/`ListenPort` | MISSING | Corrected: NON-GOAL→MISSING (P3) | `netx/wireguard.go:119` ignored; `vision.md:221-228` does not exclude it |
| 20 | Create WG keys | MISSING | Correct | `grep -i 'genkey\|wgtypes' internal`: 0 results; `key gen` SSH only (`key.go:54,66`) |
| 21 | WG handshake statistics | MISSING | Correct | `grep -i 'IpcGet\|rx_bytes' internal`: 0 results |
| 22 | Warning `.conf` holds keys | PRESENT | Correct | `vpn.go:298` "still holds the keys" |
| 23 | `.ovpn` / Pritunl profile | PRESENT | Correct | `vpn.go:149-150` `pritunl` → `openvpn` |
| 24 | OpenVPN in a container | PRESENT | Correct | `vpnsession.go:238` `openvpnContainer`; `vpnsession.go:104` Docker hint |
| 25 | OpenVPN OS mode sudo | PRESENT | Correct | `vpn.go:321` `--os-mode`; `vpnsession.go:251,258` `/var/run/komando-openvpn-*.pid`, `--syslog` |
| 26 | `.ovpn` directive filter | PRESENT | Correct | `vpn.go:55` `ovpnAllowed`, `vpn.go:77` `checkOVPN`, `vpn.go:115` inline-only |
| 27 | OpenVPN static challenge | MISSING | Corrected: PARTIAL→MISSING | `vpn.go:61` allowed; `ovpn/entrypoint.sh:13` `--daemon`; `vpnsession.go:258-264` `--daemon` + auth file; no stdin |
| 28 | OpenVPN 3 / DCO / SAML | MISSING | Correct | `grep -i 'openvpn3\|dco' internal`: 0 results |
| 29 | Userspace OpenVPN (minivpn) | MISSING | Correct | `grep -i minivpn internal`: 0 results; only `network.md:105` |
| 30 | openconnect family | PRESENT | Correct | `netx/netx.go:51-55` protocol `gp`, `fortinet`, `anyconnect`, `pulse`, `f5`; `vpnsession.go:206` `ocproxy -D` |
| 31 | `nc`/`array` protocols | MISSING | Correct | `netx/netx.go:46-56` without `nc`/`array` |
| 32 | openconnect SAML/SSO | MISSING | Correct | `vpnsession.go:205-211` only `--user`, `--non-inter`, `--passwd-on-stdin`; `grep -i 'external-browser\|saml' internal`: 0 results |
| 33 | `--servercert` | MISSING | Correct | `grep -i servercert internal`: 0 results |
| 34 | `--authgroup`/`--usergroup` | MISSING | Correct | `grep -i 'authgroup\|usergroup' internal`: 0 results |
| 35 | openconnect client certificate | MISSING | Correct | `vpnsession.go:205-211` without `-c`/`-k`; `vpn add` flags have no cert |
| 36 | HIP report `--csd-wrapper` | MISSING | Correct | `grep -i csd internal`: 0 results (other than `nproc`) |
| 37 | `tunsocks` | MISSING | Correct | `grep -i tunsocks internal`: 0 results |
| 38 | Tailscale userspace | PRESENT | Correct | `vpnsession.go:167` `--tun=userspace-networking`; `vpn.go:229-231` no key → `MFA` |
| 39 | Headscale | PRESENT | Correct | `vpnsession.go:188` `--login-server`; `vpn.go:318` `--server` |
| 40 | Tailnet peer list | PARTIAL | Correct | `grep 'tailscale.*status' internal`: 0 results; only `vpn status` |
| 41 | `tailscale ping` | MISSING | Correct | `grep '"ping"' internal/cli`: only the `test` alias and an ovpn directive |
| 42 | Exit node | MISSING | Correct | `grep -i exit-node internal`: 0 results |
| 43 | Tailscale SSH | PARTIAL | Correct | tailnet SOCKS `vpnsession.go:168`; no `tailscale ssh` |
| 44 | `serve`/`funnel` | NON-GOAL | Correct | `vision.md:227` N1 daemon/server (must keep running to expose) |
| 45 | Taildrop | MISSING | Correct | `grep -i 'taildrop\|file cp' internal`: 0 results |
| 46 | ACL tags / ephemeral | PARTIAL | Correct | `vpnsession.go:178-189` only `--auth-key`, `--login-server`, `--hostname`; `grep advertise-tags`: 0 results |
| 47 | ZeroTier | PARTIAL | Correct | `netx/netx.go:46-56` without `zerotier`; `system` `netx.go:49` |
| 48 | Nebula, NetBird | PARTIAL | Correct | `grep -i 'nebula\|netbird' internal`: 0 results; only `system` |
| 49 | L2TP/IPsec/IKEv2 | PRESENT | Correct | `vpn.go:151-152` alias → `system`; `vpnsession.go:351,353` `scutil --nc` / `nmcli` |
| 50 | Cloudflare WARP | PARTIAL | Correct | `grep -i warp internal`: 0 results; `system` + `--check` |
| 51 | AWS SSM shell | MISSING | Correct | `grep -i ssm internal`: 0 results |
| 52 | AWS SSM port forward | MISSING | Correct | `grep -i ssm internal`: 0 results |
| 53 | `ProxyCommand` | MISSING | Correct | `host.go:547-559` only hostname/user/proxyjump/port/identityfile; `grep -i proxycommand internal`: 0 results; no note in `Skipped` |
| 54 | GCP IAP | MISSING | Correct | `grep -i 'iap\|gcloud compute' internal`: 0 results |
| 55 | Azure Bastion | MISSING | Correct | `grep -i azure internal`: 0 results |
| 56 | Cloudflare Access | MISSING | Correct | `grep -i cloudflared internal`: 0 results |
| 57 | Cloudflare Tunnel | NON-GOAL | Correct | `vision.md:227` N1 daemon/server |
| 58 | Teleport | MISSING | Corrected: evidence "see B5"→"see B3" | `grep -i 'teleport\|tsh' internal`: 0 results |
| 59 | Boundary | MISSING | Correct | `grep -i boundary internal`: 0 results |
| 60 | StrongDM | MISSING | Correct | `grep -i 'strongdm\|sdm' internal`: 0 results |
| 61 | `tunnel -L/-R/-D` | PRESENT | Correct | `tunnel.go:222-224` flags; `tunnel.go:260,305` list/stop |
| 62 | Tunnel to conn | PRESENT | Correct | `tunnel.go:95-96` example `app-db --port`; `tunnel.go:225` |
| 63 | SOCKS inside VPN | PRESENT | Correct | `tunnel.go:136-137` the VPN name becomes `--via`; `docs/features/vpn.md:34` |
| 64 | Non-loopback bind without `--yes` | PARTIAL | Correct | `tunnel.go:66,77` default `127.0.0.1`; `tunnel.go:68-69,78-79` free bind; `grep 'guardSafety\|g.yes' internal/cli/tunnel.go`: 0 results |
| 65 | Use existing SOCKS | PRESENT | Correct | `vpn.go:210-221` kind `socks` (`--address`, `--user` + `--password-ref`) |
| 66 | Wrap apps through a proxy | PARTIAL | Correct | `tunnel -D` exists; `grep -i 'proxychains\|tsocks' internal`: 0 results |
| 67 | VPN-over-SSH subnet | PARTIAL | Correct | `grep -i sshuttle internal`: 0 results |
| 68 | Expose to the internet (ngrok) | NON-GOAL | Correct | `vision.md:227` N1 server |
| 69 | k8s port-forward | PARTIAL | Correct | `cluster.go:863` port-forward = destructive; `cluster.go:1025` cannot dry-run; `tunnel.go` without k8s |
| 70 | Vault AES-GCM + scrypt | PRESENT | Correct | `vault/vault.go:134` scrypt, `:138-142` AES-GCM; keyfile/passphrase mode `:114-131` |
| 71 | Secret input without arguments | PRESENT | Correct | `key.go:385` `SECRET_IN_ARGS`, `:390` `--from-env`, `:407` TTY prompt |
| 72 | `--reveal` only for humans | PARTIAL | Correct | `key.go:447-452` no TTY/confirmation check (only `secret.reveal` audit) |
| 73 | Safe `secret rm` | PARTIAL | Correct | `key.go:471-494` no `IN_USE`, no confirmation, no `audit(`; `vault.go:185` permanent delete |
| 74 | `secret set` overwrites | PARTIAL | Correct | `vault.go:159` overwrites the entry; `key.go:434` only the `--from-env` flag |
| 75 | `vault.key` in OS keyring | MISSING | Correct | `vault.go:121-127` `vault.key` file 0600; `grep -i 'keyring\|secret-tool' internal`: 0 results |
| 76 | Re-key vault | MISSING | Correct | `secret --help`: get/list/rm/set only; `grep -i rekey internal`: 0 results |
| 77 | Lock/unlock vault | MISSING | Correct | `grep -i unlock internal`: 0 results |
| 78 | Secret version history | MISSING | Correct | `vault.go:159` one entry per name + `UpdatedAt` |
| 79 | Generate password | MISSING | Correct | `secret --help`: no `generate` |
| 80 | Rename/copy secret | MISSING | Correct | `secret --help`: no `mv`/`cp` |
| 81 | Who uses a secret | MISSING | Correct | `vault.go:40-43` `Info{name, updated_at}` |
| 82 | Secret rotation | MISSING | Correct | `grep -i rotate internal`: 0 results |
| 83 | `file:` file permissions | MISSING | Correct | `vault.go:263-265` `os.ReadFile` without `Stat`/mode |
| 84 | `env:`, `file:` | PRESENT | Correct | `vault.go:256-265` |
| 85 | 1Password `op read` | PRESENT | Correct | `vault.go:265-266` |
| 86 | `op run`/`op inject` | MISSING | Correct | `grep '"op", "run"\|inject' internal`: 0 results |
| 87 | Vault KV | PRESENT | Correct | `vault.go:267-272` `vault kv get -field` |
| 88 | Vault dynamic creds | MISSING | Correct | `vault.go:267-272` only `kv get`; `grep -i lease internal`: 0 results |
| 89 | Vault SSH CA | MISSING | Corrected: evidence "see B5"→"see B3" | `grep -i 'ssh/sign' internal`: 0 results |
| 90 | AWS Secrets Manager | PRESENT | Correct | `vault.go:273-279` |
| 91 | SSM Parameter Store | MISSING | Correct | `vault.go:227` prefixes: secret/env/file/op/vault/aws-sm/gcp-sm; `grep get-parameter internal`: 0 results |
| 92 | Google Secret Manager | PRESENT | Correct | `vault.go:280-286` always `latest` |
| 93 | Azure Key Vault | MISSING | Correct | `grep -i 'keyvault\|azure' internal`: 0 results |
| 94 | Bitwarden | MISSING | Correct | `grep -i 'bitwarden\|"bw"' internal`: 0 results |
| 95 | `pass`/`gopass` | MISSING | Correct | `vault.go:227` without a `pass:` prefix |
| 96 | sops | MISSING | Correct | `grep -i sops internal`: 0 results |
| 97 | age | MISSING | Correct | `vault.go:227` without an `age:` prefix |
| 98 | Doppler, Infisical | MISSING | Correct | `grep -i 'doppler\|infisical' internal`: 0 results |
| 99 | AWS profiles | PARTIAL | Correct | `vault.go:299` `exec.CommandContext` inherits env (`AWS_PROFILE`); no profile per ref |
| 100 | K8s Secret as a source | MISSING | Correct | `cluster.go:325-328` `redact`; `vault.go:227` without `k8s:` |
| 101 | External MFA stays with the human | PRESENT | Correct | `vault.go:293-308` `external()`, "(is it signed in?)" |
| 102 | External ref cache | PARTIAL | Correct | `vault.go:297` 60s timeout per call; `grep -i cache internal/vault`: 0 results |
| 103 | SSH key gen/add/deploy | PRESENT | Correct | `key.go:37,116,170,196,227,248,283` gen/add/edit/list/show/rm/deploy |
| 104 | Passphrase from vault | PRESENT | Correct | `key.go:163` `--passphrase-ref`; `sshx/client.go:285` |
| 105 | ssh-agent | PRESENT | Correct | `sshx/client.go:320-322` `SSH_AUTH_SOCK` + `agent.NewClient` |
| 106 | SSH certificate from file | MISSING | Correct | `sshx/client.go:276,289` only `ParsePrivateKey`; `grep NewCertSigner internal`: 0 results |
| 107 | Per-host `IdentityAgent` | MISSING | Correct | `grep -i identityagent internal`: 0 results |
| 108 | SSH key rotation | PARTIAL | Correct | `key.go:308-309` only adds to `authorized_keys`; no removal |
| 109 | Secret in remote `--env` | MISSING | Correct | `common.go:475-481` `parseEnv` without `vault.Resolve`; `exec.go:76,205`, `job.go:76,146`, `host.go:65,71` |
| 110 | Local tools with secrets | PARTIAL | Correct | `dbshell.go:151` `PGPASSWORD`, `:193` `MYSQL_PWD`; no general wrapper |
| 111 | Load `.env` | PARTIAL | Correct | `importer.go:499` `importEnv` only creates a conn |
| 112 | Secret template in `fs write` | MISSING | Correct | `fs.go:547-548` `--content`/`--from` literal; `grep '{{secret' internal`: 0 results |
| 113 | Plain `host --env` | PARTIAL | Correct | `store/store.go:31` `Env map[string]string` in `state.json` |
| 114 | Team vault sharing | PARTIAL | Correct | `vault.go:30` local vault with one key; external refs `vault.go:219-222` |
| 115 | Encrypted export + secrets | MISSING | Correct | `importer.go:616` `export` "(no passwords)"; `vision.md:158` |
| 116 | SSO/OIDC to komando | NON-GOAL | Correct | `vision.md:227` N1 (needs a server) |
| 117 | `config show/set` | PRESENT | Correct | `meta.go:341-343,358` (host_key_policy, default_user, timeouts, parallel, max_output_bytes, audit, audit_sql, vpn_idle) |
| 118 | Security settings guard | PRESENT | Correct | `common.go:324-328` `guardSafety` → `SAFETY_SETTING`; `meta.go:371,403` |
| 119 | Profiles/contexts | PARTIAL | Correct | `root.go` has no `--home` flag; only the `KOMANDO_HOME` env |
| 120 | Override settings via env | PARTIAL | Correct | `grep KOMANDO_ internal`: HOME, OUTPUT, ACTOR, VAULT_PASS (+SOCKS_* internal) |
| 121 | Per-project configuration | MISSING | Correct | no project config file is read in `root.go`/`store` |
| 122 | JSON envelope + exit code | PRESENT | Correct | `out/out.go:16-26` exit codes, `:65-72` `contract` |
| 123 | Auto text/JSON | PRESENT | Correct | `root.go:60,134,159` `outputFormat`, `KOMANDO_OUTPUT` |
| 124 | `--pretty` | PRESENT | Correct | `root.go:160` |
| 125 | NDJSON streaming | PRESENT | Correct | `exec.go:80` `--stream`; `modules.go:785-789` `followLogs` uses `stream: true`; `out.go:167` `Event` |
| 126 | YAML | MISSING | Correct | `out/out.go:89` "yaml-ish not supported" |
| 127 | CSV/TSV | MISSING | Correct | `grep -i 'csv\|tsv' internal/out`: 0 results |
| 128 | jq/JMESPath filter | MISSING | Correct | `grep '"query"\|"jq"' internal/cli/root.go`: 0 results |
| 129 | Output template | MISSING | Correct | no global `--template`/`--format` flag (`root.go:159-168`) |
| 130 | Choose columns | MISSING | Correct | `grep '"fields"\|"columns"' internal/cli`: 0 results |
| 131 | `--no-headers` | MISSING | Correct | `grep no-headers internal`: 0 results |
| 132 | Color / `NO_COLOR` | PRESENT | Correct | `grep '\x1b\[\|NO_COLOR' internal`: 0 results (no color) |
| 133 | Truncated output | PRESENT | Correct | `root.go:168` `--max-output`; `sshx/run.go:38-39` `*_truncated` |
| 134 | Pagination | PARTIAL | Correct | `storage ls --help` only `-n/--limit`; no continuation token |
| 135 | `--quiet` | MISSING | Correct | `grep '"quiet"' internal`: 0 results |
| 136 | `--watch` | MISSING | Correct | `grep '"watch"' internal/cli`: 0 results; `job wait`, `logs -f` exist |
| 137 | `--help` with examples | PRESENT | Corrected: evidence (`TestConventions` does not check examples) | 66 `Example:` of ±155 `Use:` in `internal/cli`; `conventions_test.go:13-43` has no Example check |
| 138 | Did you mean | PRESENT | Correct | cobra (`komando lst` → suggests `list`); `select.go:76-77,250-251` for selectors |
| 139 | No arguments: three steps | PARTIAL | Correct | `komando` without arguments prints the Long help `root.go:111` |
| 140 | Static completion | PRESENT | Correct | `completion --help`: bash, fish, powershell, zsh |
| 141 | Dynamic completion | MISSING | Correct | `grep 'ValidArgsFunction\|RegisterFlagCompletionFunc' internal`: 0 results; `__complete exec ""` is empty |
| 142 | Man page | MISSING | Correct | `grep 'GenMan\|cobra/doc' internal Makefile`: 0 results |
| 143 | Offline docs | PRESENT | Correct | `meta.go:37` `guide`, `meta.go:179` `schema`; `docs/features/` |
| 144 | i18n | NOT PLANNED | Decided English-only | Indonesian translations (`README.id.md`, `docs/features/id/`) removed; CLI messages are English |
| 145 | Root help positioning | PARTIAL | Correct | `root.go:110-112` "servers (SSH), databases, caches and storage" |
| 146 | `--verbose`/`--debug` | MISSING | Correct | `grep '"verbose"\|"debug"' internal/cli/root.go`: 0 results; `-v` = `--version` |
| 147 | `doctor` | PRESENT | Correct | `meta.go:547-587` state, hosts, keys, ssh_agent, VPN clients, platform |
| 148 | `doctor` checks external refs | MISSING | Correct | `meta.go:547-587` no check of `op`/`vault`/`aws`/`gcloud` |
| 149 | VPN log per session | PRESENT | Correct | `vpnsession.go:137` `logFile` |
| 150 | Install + checksum | PRESENT | Correct | `install.sh:31-36` downloads and checks `checksums.txt` |
| 151 | `go install` | PRESENT | Correct | `README.md:47` |
| 152 | Homebrew | MISSING | Correct | `git ls-files \| grep -i 'brew\|formula'`: 0 results |
| 153 | apt/rpm | MISSING | Correct | `Makefile:35-44` only tar.gz |
| 154 | Scoop/winget | MISSING | Correct | `git ls-files \| grep -i 'scoop\|winget'`: 0 results |
| 155 | komando Docker image | MISSING | Correct | Dockerfiles only in `internal/cli/ovpn/` and `test/e2e/` |
| 156 | Nix | MISSING | Correct | `git ls-files \| grep -i nix`: 0 results |
| 157 | Native Windows | MISSING | Correct | `Makefile:6` PLATFORMS linux/darwin; `install.sh:15` refuses; `vpnsession.go:308` `Setsid` |
| 158 | Signed releases | PARTIAL | Correct | `.github/workflows/release.yml` only `make dist` + `gh release create`; `grep -i 'cosign\|attest\|sbom' .github`: 0 results |
| 159 | Version check / self-update | MISSING | Correct | `root.go:200-206` `version` only prints; `grep api.github.com internal`: 0 results |
| 160 | Telemetry | PARTIAL | Correct | `grep -ri telemetr README* SECURITY.md docs` (outside gap): 0 results |
| 161 | Pure Go binary (no size limit) | PRESENT | Correct (evidence extended with measured size) | `Makefile:40` `CGO_ENABLED=0 ... -trimpath`; build `-s -w`: 35 MB darwin/arm64, 37 MB linux/amd64 |
| 162 | Universal selectors | PRESENT | Correct | `select.go:98-99` `!`, `:125` `kind:`, `:210-214` `@`, `tag:`, `label:`, `:224` glob |
| 163 | Import from other tools | PRESENT | Corrected: evidence (pipe inside backticks broke the table) | `importer.go:49` source list; `import --help` 10 sources |
| 164 | Import aws/Termius/TablePlus | PARTIAL | Correct | `import --help` without aws/termius/tableplus; `vision.md:166,170` |
| 165 | Export/import to move machines | PRESENT | Correct | `importer.go:616` `export [TARGET] --to`; source `komando` |
| 166 | Automatic sync | NON-GOAL | Correct | `vision.md:227` N1 daemon/server |
| 167 | Team inventory | PARTIAL | Corrected: evidence (`--overwrite` applies changes) | `importer.go:142-196` skips existing names unless `--overwrite` |
| 168 | Dynamic cloud inventory | MISSING | Correct | `grep -i 'ec2\|droplet\|hetzner' internal`: 0 results; `vision.md:206-208` |
| 169 | Health summary | PARTIAL | Correct | `ops.go:106` recipe `health`, `ops.go:80` `facts`, `cluster.go:207` `status` |
| 170 | Cost/usage | MISSING | Corrected: NON-GOAL→MISSING (P3) | `vision.md:226` N2 only IaC/provisioning/GitOps |
| 171 | Global `--dry-run` | PRESENT | Correct | `root.go:161`; `internal/cli/dryrun_test.go` |
| 172 | Protected + confirmation | PRESENT | Correct | `common.go:307` `confirmProtected`, `:346` "Type ... to continue" |
| 173 | Policy + `--allow-dangerous` | PRESENT | Correct | `meta.go:442` `policy` (allow/check/deny/list); `root.go:163` |
| 174 | Two-person approval / RBAC | NON-GOAL | Correct | `vision.md:227` N1 (needs a server) |
| 175 | Local audit log | PRESENT | Corrected: evidence (`via` not recorded) | `common.go:374-389` record fields; `meta.go:331-334` filters |
| 176 | Audit fails closed | PARTIAL | Correct | `common.go:391-396` `return` when open fails, result of `f.Write` ignored |
| 177 | Audit filter by time/actor | MISSING | Correct | `meta.go:331-334` only target/command/failed (+limit) |
| 178 | Audit to SIEM | MISSING | Correct | `common.go:391` only `audit.jsonl` |
| 179 | Audit file rotation | MISSING | Correct | `meta.go:295` `bufio.Scanner` reads the whole file; no rotation |
| 180 | Notifications | MISSING | Correct | `grep -i 'webhook\|slack' internal`: 0 results |
| 181 | Scheduling | PRESENT | Corrected: PARTIAL→PRESENT | `modules.go:716,754` `cron set/list/rm`; local side N1 `vision.md:227` |
| 182 | Agent skill | PRESENT | Correct | `meta.go:61` `.claude/skills`, `.agents/skills`; `meta.go:105` `--project` |
| 183 | Agent playbook | PRESENT | Correct | `meta.go:37` `guide`; `internal/cli/guide.md` |
| 184 | Machine schema | PARTIAL | Corrected: evidence (lines `meta.go:244-254`→`243-253`) | `meta.go:243-253` selectors "hosts" without `kind:`; `secret_refs` without op/vault/aws-sm/gcp-sm |
| 185 | `data` shape schema | MISSING | Correct | `meta.go:179` `schema` only commands/flags/envelope |
| 186 | MCP server | MISSING | Correct | `grep -i mcp internal cmd`: 0 results |
| 187 | Automatic agent actor | PARTIAL | Correct | `common.go:399-404` `KOMANDO_ACTOR`, if empty `$USER` |
| 188 | Agent cannot answer prompts | PRESENT | Corrected: evidence (TTY stdin, not /dev/tty) | `common.go:295` `interactive()`, `:301` reads `os.Stdin`, `:314` `confirmYes` |
| 189 | Idempotency | PRESENT | Correct | `fs.go:550` `--if-changed`; `key.go:308-309` deploy; `modules.go:754` cron set |
| 190 | Limited parallelism | PRESENT | Correct | `root.go:166` `-P/--parallel`; `exec.go:81` `--fail-fast` |
| 191 | Retry/backoff | MISSING | Correct | `storex/storex.go:67` `MaxRetry = 2`; `registry/registry.go:105` token retry; no backoff |
| 192 | Rate limit | MISSING | Correct | `grep -i 'rate.Limit\|ratelimit' internal`: 0 results |
| 193 | Clean Ctrl-C | PARTIAL | Corrected: PRESENT→PARTIAL (P3) | `root.go:64` `NotifyContext`; `common.go:122-123` `CANCELLED` exit 1; `grep 130 internal/cli`: 0 results |
| 194 | Detached jobs | PRESENT | Correct | `job.go:35` job start/status/logs/wait/kill/rm/list |
| 195 | Concurrency-safe state | PRESENT | Correct | `store/store.go:297-316` `Update` + `syscall.Flock` |
| 196 | Fuzzy picker | NON-GOAL | Correct | `vision.md:227` N1 "TUI" |
| 197 | User command aliases | PARTIAL | Correct | `ops.go:214,263` `recipe add NAME COMMAND`; no aliases for komando commands |
