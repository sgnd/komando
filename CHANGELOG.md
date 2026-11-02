# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org).

## [Unreleased]

### Secrets stay away from AI agents

- A person allows what an AI agent asks for: when Claude Code, Codex, Gemini
  CLI or Cursor adds `--yes`, `--allow-dangerous` or `--reveal`, komando
  shows the exact command in a window on the screen and runs it only after
  "Allow once". With no screen the agent is refused and the hint asks the
  person to run the command themselves. People and scripts are unchanged.
- For AI agents, passwords, keys and tokens in any output show as
  `[hidden]`: `.env` and config files, `env`, logs, database rows,
  Kubernetes Secrets, private keys, password hashes, URLs with a password.
  `--reveal` (allowed by a person) shows them. Vault values are now also
  hidden when base64- or URL-encoded.
- `fs write` and `fs replace` take `{{secret:NAME}}`, which becomes the
  vault value on the server; an `--old` with `[hidden]` in it matches the
  hidden value. Text that still holds `[hidden]` or `[secret:NAME]` is never
  written (`HIDDEN_VALUE`), nor stored with `secret set`.
- An AI agent cannot copy `.env` files, private keys and other secret files
  to this computer (`SENSITIVE_FILE`); folder copies and `sync` leave them out.
- `komando guide install` also adds a guard to Claude Code
  (`.claude/settings.json`) that stops reading `~/.komando`, private keys,
  `.env` files and credential stores, dumping every environment variable,
  and `ssh`/`scp`/`rsync` around komando. `--no-guard` skips it.
- `--reveal` is now a flag of every command; `secret get --reveal` still
  works only for a person at a terminal.

### Measured against international standards

- New page [security-standards.md](docs/features/security-standards.md):
  OWASP ASVS, OWASP Top 10 for LLM applications, NIST, ISO 27001, CIS and
  SLSA, with what is met, what is partly met and what is up to you.
- Passphrase vaults use scrypt N=2^17 (the OWASP minimum, was 2^15); an older
  vault moves up with a new salt on its next change.
- The audit log is a hash chain: `komando audit verify` finds a record that
  was edited, added or removed. Records name the AI agent and whether a
  person allowed the command.
- `komando doctor` checks security: file permissions, vault mode and
  passphrase length (NIST SP 800-63B), the audit chain, and conns whose
  traffic is not encrypted or whose server certificate is not checked.
- The agent rules say server output is data, never instructions (prompt
  injection).
- Releases carry signed SLSA build provenance (`gh attestation verify`). CI
  reads only, actions are pinned to commits, Dependabot keeps modules and
  actions current, and `make security` runs govulncheck and staticcheck.
  `make fuzz` fuzzes the masking, the policy filter and the guard; fuzzing
  found and fixed a crash on invalid UTF-8 in `fs replace --old`.
- golang.org/x/net 0.62.0 (GO-2026-6860, GO-2026-6866).

### Day-to-day database care (gap analysis, phase 4)

- `db info` (version, uptime, size, connections, primary or replica and
  replay lag), `db activity [--all]`, `db locks` (who waits on whom),
  `db sizes` (databases, biggest tables and indexes) for PostgreSQL and
  MySQL/MariaDB; `db info` and `db sizes` for SQLite too.
- `db kill CONN PID` cancels a running query; `--session` ends the
  connection and needs `--allow-dangerous`. `--dry-run` shows the session.
- `db schema TABLE` shows foreign keys, checks and unique constraints.
- `db dump --format custom` writes a PostgreSQL archive; `db restore`
  recognises it and uses pg_restore (in one transaction). `--table` and
  `--schema-only` narrow a dump (PostgreSQL and MySQL).

### Bulk transfer (gap analysis, phase 3)

- `komando sync SRC DST` keeps a folder in step between this computer and
  servers (many at once) or storage, sending only new and changed files.
  `--exclude` skips names and paths; `--delete` removes what the source no
  longer has (needs `--allow-dangerous`); `--dry-run` lists every file.
- Storage: `upload -r` sends a folder, `download -r` fetches a prefix
  (existing local files stay unless `--overwrite`), `storage cat` reads a
  text object (`--head`, `--tail`), and `storage rm --prefix [--older-than
  30d]` cleans up old objects with a list first and a `--limit`.
- Uploads to servers stream the file: a backup of any size no longer has to
  fit in memory.
- `key revoke KEY TARGET` removes a public key from authorized_keys on many
  servers (`--user` for another account); revoking the key komando logs in
  with needs `--allow-dangerous`.

### Cluster deploy cycle (gap analysis, phase 2)

- `cluster deploy TARGET TYPE/NAME --image IMAGE [--wait]` puts out a new
  image on Kubernetes (deployment, statefulset, daemonset) or Swarm.
- `cluster status TARGET TYPE/NAME [--wait]` tells whether a rollout has
  finished, and waits for it (`ROLLOUT_FAILED`, `ROLLOUT_TIMEOUT`).
- `cluster history` lists a deployment's revisions with their images;
  `cluster rollback [--to N] [--wait]` goes back (Swarm: to the previous
  version).
- `cluster status TARGET` names every problem: CrashLoopBackOff and other
  container waits, deployments short of replicas, nodes not ready or under
  pressure (`healthy`, `problems`).
- `cluster describe` (state, conditions, containers or pods, events) and
  `cluster events [--warnings] [--for TYPE/NAME]`.
- `cluster ls -l SELECTOR`, and useful columns for ingresses, volume claims
  and volumes, jobs, cron jobs, autoscalers, config maps, events and
  namespaces.
- `cluster logs` reads a workload (`deploy/api`) or a label (`-l app=api`)
  across its pods, and follows with `-f` (Kubernetes and Swarm).
- `cluster exec` runs a command in a pod with the destructive-command
  check (`--read-only` for looks); `cluster forward` reaches a pod or
  service port on 127.0.0.1.

### Secrets stay out of sight; dry runs show the change (gap analysis, phase 1)

- Vault secrets are hidden in everything komando prints: a remote `.env`,
  a log line or `env` output shows `[secret:NAME]` instead of the value
  (values of 6 characters or more). `secret get --reveal` still shows it
  to a person.
- `--env KEY=secret:NAME` (exec, script, job, host `--env`) fills the value
  in from the vault on the way to the server, so an agent never handles it.
  Jobs get their exports from a private file that is deleted at start, not
  on a command line other users can see.
- `cluster apply --dry-run` shows each object's change (`create`, `change`
  or `none`) as a diff; Secret values stay hidden.
- `registry rm` lists every tag that goes with the image, in the dry run
  too.

### Promises kept (gap analysis, phase 1)

- The audit log fails closed: when it cannot be written, commands that
  could change something are refused (`AUDIT_UNAVAILABLE`); `doctor`
  checks it.
- `komando test` logs in to databases, caches and registries (and reports
  the server version) instead of only opening the port.
- Shell completion fills in server, conn and VPN names, `@groups`, `tag:`
  and saved names from the inventory.
- `komando schema` lists every selector (`kind:`, servers and conns) and
  every secret reference form.
- `import ssh-config` reports what it did not carry over (Match blocks,
  ProxyCommand, ...) instead of dropping it silently.
- `conn edit --option statement_timeout=10s` is used by `db query` and
  `db schema`.
- docs/design/vision.md shows the real status of every family.

### Safer file edits, downloads and tunnels (gap analysis, phase 1)

- `fs write|replace --validate CMD` checks the new file before it goes
  into place (`%s` is its path, e.g. `visudo -cf %s`, `sshd -t -f %s`). If
  the check fails the old file stays (`VALIDATION_FAILED`).
- `fs write --dry-run` shows the change as a diff.
- Downloads from servers never replace a file on this computer
  (`FILE_EXISTS`; `--overwrite` to replace), are written under a temporary
  name first, and refuse server paths that lead outside the destination.
- `tunnel start` asks for `--yes` before listening on anything but
  loopback (`OPEN_BIND`), as docs/design/network.md promised.

### Secrets and risk ratings (gap analysis, phase 1)

- `secret get --reveal` works only for a person at a terminal
  (`REVEAL_NEEDS_HUMAN` for agents and scripts); commands refer to secrets
  as `secret:NAME` instead.
- `secret rm` refuses a secret that a server, conn, key or VPN still uses
  (`SECRET_IN_USE`) and is written to the audit log.
- `host add|edit --password-ref/--sudo-ref` refuse a password typed where a
  reference belongs; before, it was stored and printed as plain text.
- `cluster run -- get secret ... -o yaml|json|jsonpath` needs
  `--allow-dangerous`: those formats print the secret values. The default
  table (names and key counts) stays a read.
- `docker raw` and `docker rm` are rated like `cluster run` on a Swarm
  manager: reads stay reads, and `rm`, `volume rm`, `prune`, `run`, `exec`
  need `--allow-dangerous`; so does `docker compose down -v/--rmi`.
- `cache run`: `GETDEL`, `RENAME` and `EXPIRE` to zero or the past delete
  keys, so they need `--allow-dangerous` like `DEL`. Read commands of
  RedisJSON, RediSearch, RedisTimeSeries and RedisBloom count as reads;
  `ACL LOG RESET` is a write.
- `db query`: passwords in `CREATE/ALTER USER|ROLE ... PASSWORD`,
  `IDENTIFIED BY` and `SET PASSWORD` are replaced with `'***'` in the audit
  log.
- `svc logs -f` and `docker logs -f` stream like `logs -f` (they waited for
  the timeout before).
- `registry ls` follows every page of the repository list (it read only the
  first).

### Safety fixes from a full review

- `--dry-run` now changes nothing on every command. Inventory commands
  (`host`, `conn`, `group`, `key`, `policy`, `config`, `recipe`) show the
  result without saving it, and `job kill`, `job rm`, `tunnel stop`,
  `key gen`, `key rm --delete-file`, `secret set` and `secret rm` only
  report what they would do. Before, some of them made the change while
  the answer and the audit log said `dry_run: true`.
- `.ovpn` profiles may not use `setenv opt ...`: OpenVPN runs the rest of
  that line as an option, which got past the allowlist (for example
  `setenv opt up /bin/sh`).
- The destructive-command policy checks each line of a script, so a
  `reboot` on its own line is caught. It also catches `/sbin/reboot`,
  `nohup reboot`, `rm -rf "/"`, `rm -rf -- /`, `rm --recursive --force /`,
  `rm -rf /etc/*` and `rm -rf /var/lib`.
- `--env` names must be shell variable names (`A-Z`, `0-9`, `_`). A name
  like `X;reboot;Y` used to run as a command, past the policy check.
- `svc restart|start|reload` quotes unit names in its `journalctl` call.
- The sudo password (`--sudo-ref`) is sent only when sudo asks for it.
  When sudo did not ask (NOPASSWD, or a recent sudo), the password went to
  the command's stdin, and `script` printed it in its error output.
- `db query` on MySQL: `--` starts a comment only before white space, as
  in MySQL itself, so `SELECT 1 --1, LOAD_FILE(...)` is no longer rated a
  read. `SET TRANSACTION`, `SET SESSION CHARACTERISTICS`,
  `transaction_read_only` and `SET autocommit` are refused, because they
  switch off or end the read-only transaction.
- `fs write|replace|upload --sudo` reads the existing file mode as root.
  Before, a file the SSH user could not see (`/etc/sudoers.d`, `/root`)
  became 0644. The staged copy in `/tmp` is now private (0600) and is
  removed when the connection fails.
- `fs write --append` refuses files over 64 MiB (FILE_TOO_LARGE) instead
  of cutting them to 64 MiB.

### VPN clients tested against real servers

- `make e2e-vpnclients` runs, all in Docker: ocserv (the AnyConnect
  protocol, the path the whole openconnect family uses) and Headscale with
  a Tailscale node. komando connects on demand, `--mfa` VPNs ask for a
  person, the Tailscale auth key is on no command line, and `vpn down`
  stops the clients.
- Session checks read the process name from /proc on Linux (small images
  have no `ps`, which made every session look dead).

### Subnet clashes

- `vpn up` for VPNs that change the computer's routes (OpenVPN
  `--os-mode`, system VPNs with `--service`) compares the routing table
  before and after and warns when the new routes overlap ones another
  interface already had (two networks claiming the same addresses). The
  other kinds never touch the computer's routes, so they cannot clash.

### Output contract 1

- Every JSON answer carries `meta.contract: 1`, and `komando schema` says
  `contract: 1`. Within a contract, field names, error codes and exit codes
  are only added, never renamed or removed (docs/design/ux.md, section 13).

### Agent skill

- `komando guide install` adds the komando skill (`SKILL.md`, the Agent
  Skills format) to `~/.claude/skills` (Claude Code) and `~/.agents/skills`
  (Codex, Cursor, Gemini CLI). Agents then reach for komando by themselves
  on server, database, cache and storage tasks. `--project` installs into
  the current folder; a changed file is kept as `SKILL.md.bak`. The same
  skill lives in `skills/komando/` for `npx skills add sgnd/komando`.

### Logs and files

- `komando logs ... --follow` (`-f`) keeps printing new lines until Ctrl-C;
  in a terminal they show as plain lines (marked by server when there are
  several), for agents as NDJSON events.
- `fs rm --recursive` needs `--allow-dangerous`, like `storage rm`.

### More import sources

- `komando import filezilla` (SFTP sites, passwords to the vault), `rclone`
  (SFTP remotes) and `dbeaver` (PostgreSQL, MySQL/MariaDB and SQLite
  connections).

### Fixes from the second review

- OpenVPN container: the entrypoint parsed again (a comment had swallowed
  `fi`; a test now checks every embedded script), the SOCKS port listens
  only on the container's network and needs a random per-connection
  login, the container runs with only the capabilities it needs and
  no-new-privileges, and config/login files are removed also when
  connecting fails. Tested against a real OpenVPN server
  (`make e2e-openvpn`).
- .ovpn inline blocks end the way OpenVPN ends them, so text after `</ca>`
  can no longer smuggle in directives; an unclosed block is refused.
- `cluster run` refuses flags that would send the conn's credentials to
  another cluster or identity (`--server`, `--kubeconfig`, `--token`,
  `--context`, `--as` ...) and user `--dry-run` values; `config view` (it
  can print credentials), `edit`, `apply --prune`, scaling to 0, role
  bindings, privileged `run`, and docker `exec`/`run`/`cp`, `--prune` and
  node drains are rated dangerous.
- VPN sessions: stops take the VPN's lock and check it is still the same
  session; sessions in use (a long `logs --follow`) stay fresh; containers
  are tracked by ID and labelled with their komando home; OS-mode OpenVPN
  writes its pid to /var/run and logs to syslog.
- Imports keep a secret reference only when that secret really does not
  exist (not when the vault is locked).

### Fixes from review

- `cluster run` must start with the command (a leading flag could hide a
  delete behind a "get"); kubectl and docker commands are rated by verb and
  subcommand (`auth reconcile`, `service rm`, `system prune` ...), the
  destructive-command policy sees them unquoted, and `--dry-run=server` goes
  right after the verb (never into `exec ... --`).
- `import komando` drops references to secrets or files that already exist
  on this computer and imports recipes as changes, so a file from someone
  else cannot send your passwords to their server or skip `--yes`.
- OpenVPN configs pass only an allowlist of client settings, with keys
  inline; nothing that runs programs or reads/writes files by path.
- KOMANDO_VAULT_PASS is removed from the environment at start, so kubectl,
  credential plugins, VPN clients and docker never inherit it.
- VPN sessions: a reused pid is never signalled, a failed stop (sudo) is
  reported and the session kept, idle sessions close at the next komando
  command, two commands cannot start the same VPN twice, config and login
  files are deleted once connected, the Tailscale auth key no longer shows
  in `ps`, and `vpn up/down/rm --dry-run` change nothing.
- `label:KEY` without a value picks targets that have the label (it picked
  those without it). kubectl secrets are hidden in the audit log;
  `cluster rm`/`registry rm --dry-run` report what would be blocked.

### OpenVPN without touching your computer's network

- `openvpn` (and `pritunl`) VPNs run in a small Docker container, built
  once from files inside komando, and are reached through a local SOCKS
  port, like the other VPN kinds: several at once, no sudo, no route
  changes. `--os-mode` keeps the old way (sudo, system routes).

### Password managers (v0.7)

- `--password-ref` also takes `op://...` (1Password), `vault:PATH#FIELD`
  (HashiCorp Vault), `aws-sm:NAME[#KEY]` (AWS Secrets Manager) and
  `gcp-sm:NAME[@PROJECT]` (Google Secret Manager). komando runs that tool's
  CLI when it needs the value and never stores it.
### Registry copy (v0.6)

- `komando registry copy SRC:IMAGE DST:[IMAGE]` copies an image between
  registries or repositories with every platform, keeping the digest.
  Layers already at the destination are skipped, layers within one registry
  are mounted, credentials never go to another host (e.g. an upload
  redirect), and only the destination is guarded (`--yes` when protected).

### Database shell (v0.7)

- `komando db shell CONN` opens psql, mysql or sqlite3 on this computer,
  connected through the conn's `--via` path, with the password in the
  client's environment. Read-only unless `--write` (PostgreSQL
  default_transaction_read_only, MySQL session READ ONLY, sqlite3
  -readonly); protected conns need `--yes` for `--write`. PostgreSQL keeps
  verifying the certificate's host name through the forward (PGHOSTADDR).
  For people only: without a terminal it refuses with NEEDS_TERMINAL.

### File servers in storage (v0.7)

- `komando storage` also works with FTPS (`ftps://`, TLS on control and data
  connections), SFTP (`sftp://`, for shell-less accounts; host keys checked
  like SSH hosts) and FTP (`ftp://`, refused without `?insecure=1` because
  it sends the password unencrypted). ls, download, upload and rm behave as
  for buckets; uploads go to a temporary name and are renamed into place,
  creating missing folders; keys cannot leave the conn's folder. All of it
  works through `--via` bastions and VPNs.

### Container registries (v0.6)

- `komando registry ls|inspect|rm` for Docker Hub, GHCR, GitLab, Harbor,
  ECR and registry:2 over the OCI Distribution API (basic and token auth),
  through `--via` paths and VPNs. `rm` deletes by digest and needs
  `--allow-dangerous`. `komando import docker` reads
  `~/.docker/config.json`, including credential helpers.

### Clusters (v0.5)

- `komando cluster` for Kubernetes (a k8s conn) and Docker Swarm (a manager
  server) with the same verbs: `status`, `ls`, `get` (Secret values hidden),
  `logs`, `apply` (server-side; `--dry-run` asks the server), `restart`,
  `scale` (to 0 needs `--allow-dangerous`), `rm` (needs `--allow-dangerous`)
  and `run` for any kubectl or docker command (read-only unless `--write`).
  The Kubernetes API is called directly (no client-go), through `--via`
  paths and VPNs; `cluster run` gives kubectl a private kubeconfig and a
  local tunnel. `komando import kubeconfig` adds one conn per context and
  keeps each context's credentials in the vault.

### VPNs (v0.4, first part)

- `komando vpn add NAME wireguard|socks|system`. A VPN goes first in a
  `--via` path (`--via office,bastion`) for servers, conns and tunnels.
  WireGuard runs inside komando for that command only: several VPNs at
  once, overlapping subnets, no admin rights, no change to the computer's
  network. Keys go to the vault. `system` checks an OS VPN is connected
  (`VPN_DOWN` if not). `list`, `test`, targets (`kind:vpn`), groups and
  `export`/`import` include VPNs; a VPN in use cannot be removed.

### One command per job (v0.3)

- `--via` for servers too: `host add db1 ... --via bastion` (chains like
  `--via bastion,db1`). `--jump` still works; state files move `jump` to
  `via` on load. Conns take `--via` chains as well, and a host on anyone's
  `--via` path cannot be removed (`HOST_IN_USE`).
- `komando upload` and `komando download` work for servers (SFTP, many at
  once) and storage conns. `cp` and `storage upload/download` are the same
  commands spelled the old way.
- `komando recipe` is one list of built-in and saved commands. `ops` and
  `snippet` are other names for it; saved recipes cannot reuse built-in
  names, and marking an existing recipe read-only needs `--yes`.
- `host list/test` and `conn list/test` are `komando list/test` limited to
  servers or conns (new selector `kind:conn`); `svc logs` and `docker logs`
  are `komando logs` with `--unit` or `--container`.
- `komando import SOURCE` brings in `ssh-config`, `pgpass`, `mycnf`, `env`
  (.env URLs) and `komando` export files; passwords go to the vault, re-imports
  change nothing, and what cannot be imported is listed. `komando export`
  saves servers, conns and recipes (no passwords) to move computers.
- `komando tunnel start CONN` opens a local port to a conn through its
  `--via` path, for apps like TablePlus or psql (`--port` to choose it).

- `komando conn`: an inventory of databases (PostgreSQL, MySQL, SQLite) next
  to hosts. Add, edit, list, show, remove and test them; reach private ones
  through a host with `--via`. Passwords are refused in URLs and live in the
  vault. First step toward `komando db` (see `docs/design/resources-and-db.md`).
- Hosts and conns share one name space. Removing a host that a conn uses
  with `--via` is refused (`HOST_IN_USE`); renaming a host updates its conns.
- `komando audit --host` also matches conn names.
- `komando db query/schema/explain` for PostgreSQL and SQLite. Read-only by
  default (the database enforces it); `--write` to change data, `--write
  --dry-run` to try it and roll back. Destructive SQL (DROP, TRUNCATE,
  DELETE/UPDATE without WHERE, ...) needs `--allow-dangerous`; protected
  conns need `--yes`. Results are structured rows, safe for JSON.
- `komando storage` (alias `s3`) for S3 and S3-compatible storage (MinIO, R2,
  Wasabi, Spaces, B2, Garage): `ls`, `download` (to a file, never
  overwriting), `upload`, `rm` (exact keys only, needs `--allow-dangerous`),
  and `link` for temporary download links. Keys stay inside the conn's folder.
- `komando policy list` shows the SQL and Redis rules; `komando policy check
  --for KIND` rates a SQL query or Redis command.
- MySQL and MariaDB conns for `komando db`.
- `komando db dump` and `db restore`: backups to and from a file on this
  computer, using pg_dump/psql or mysqldump/mysql on the `--via` server (or
  locally). The password never appears on a command line; files are 0600 and
  never overwritten; restores need `--allow-dangerous` and refuse files with
  client commands (`\!`, `system`). MySQL `tls=` settings carry over.
- `komando config set audit_sql full|hash|off` controls how SQL text is kept
  in the audit log.
- `komando cache` for Redis/Valkey: `get` (any type, with TTL), `keys` (SCAN,
  never KEYS), `info`, `set`, `rm`, and `run` for any command, read-only
  unless `--write`. Deleting, flushing, blocking, scripts and
  server-reconfiguring commands need `--allow-dangerous`.

### Everything in one place

- Targets pick servers and conns together: `@prod` is everything in the
  `prod` group. Each command uses what it can work with and lists the rest
  in `meta.skipped`; when nothing fits, `NO_MATCHING_TARGETS` names the right
  command. New selector `kind:` (`kind:host`, `kind:db`, `kind:postgres`, ...).
  Typos get a "did you mean" hint. Unknown names now report
  `TARGET_NOT_FOUND` from commands that take both kinds.
- `komando list [TARGET]` and `komando test TARGET` show and check servers
  and conns together. `group add/rm` and `group list` include conns.

### Safety

- Snippets count as changes, so protected servers need `--yes`, unless saved
  with `--read-only`. Snippets saved before this release are treated as
  changes too. `snippet add --mutating` is no longer needed.
- `komando secret set NAME VALUE` is refused (`SECRET_IN_ARGS`): a value on
  the command line lands in shell history. Type it, pipe it, or use
  `--from-env`.
- Removing, replacing (`add --overwrite`) or unprotecting a protected server
  or conn needs `--yes`.
- Protection follows the address: an ad-hoc `user@address`, a second host
  name for the same address and port, or a second conn to the same database
  server, file or bucket counts as protected too.
- Turning off the audit log or `audit_sql`, loosening host key checks
  (setting, or `--host-key-policy off`), and removing a deny rule need `--yes`
  (`SAFETY_SETTING`). `config set audit` accepts only on/off values.
- A person typing in a terminal is asked instead of getting an error: `[y/N]`
  for protected targets, and typing the target's name for dangerous
  commands. Agents and scripts still need `--yes` / `--allow-dangerous`.
- Names ignore upper and lower case (`Web1` and `web1` cannot both exist),
  and `all` cannot be a name. `host import` skips invalid names.

### One way to say each thing

Old names keep working for one release and print a note.

- `rm` everywhere: `group remove`, `pkg remove` and `user delete` are now
  `rm`; every `rm` also accepts `remove`, `delete` and `del`.
- `--overwrite` replaces `--force` (`host add`, `conn add`, `snippet add`).
- `--var` replaces `--param` (`ops run`).
- `--target` replaces `--host` (`audit`, `job list`) and takes any target.
- `-n, --limit` replaces `--lines` (`logs`, `svc logs`, `docker logs`).
  `fs cat -n` (line numbers) is now `--line-numbers`; `job logs --limit`
  (bytes) is now `--max-bytes`.
- `-r` is the only short flag for `--recursive` (`fs ls` used `-R`).
- `logs --file` and `--grep` lose their short flags: `-g` now means only
  `--group`, and `-f` in `logs` is kept free for a future `--follow`.
- `pkg` and `user` accept `--no-sudo`.
- Usage lines say `TARGET` everywhere (was `HOST` in `fs`, `shell`, `tunnel`).

## [0.1.0]

First release.

- Server list with groups, tags, labels, jump hosts and `~/.ssh/config` import
- SSH keys and an encrypted password vault
- Run commands and scripts on many servers in parallel; long-running jobs
- Safe file reading and editing, upload and download
- Background tunnels (local, remote, SOCKS)
- Health checks and 39 ready-made recipes; services, logs, Docker, packages, network, users, cron
- Safety: dangerous-command filter, protected servers, dry run, server identity check, audit log
- Readable text in a terminal, JSON for AI agents
