# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org).

## [Unreleased]

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
