# Changelog

All notable changes are listed here, newest first. Each version starts with
its highlights; the sections below them give the details. Versions follow
[Semantic Versioning](https://semver.org), and the format follows
[Keep a Changelog](https://keepachangelog.com).

## [Unreleased]

### Added

- Release archives include `THIRD_PARTY_LICENSES`: the license texts and
  NOTICE files of the Go modules and the Go standard library built into
  komando (`make licenses` writes it alone).
- `install.sh` installs one version with `KOMANDO_VERSION=vX.Y.Z`.
- The README has Update, Uninstall and "Something wrong?" sections, and
  says how to protect the vault key (`komando secret keychain`).
- The docs say how to get the AI agent seatbelts (secrets hidden in output,
  a person allows `--yes`) for agents komando does not know by name: set
  `KOMANDO_AGENT=1` in the agent's environment.

### Changed

- Exit codes: `NO_AUTH` (a server with no key, identity or password) now
  exits 4 like `AUTH_FAILED`, not 2. `SECRET_UNRESOLVED` (a password
  reference that cannot be read) exits 3 everywhere; it was 2 for servers
  and 1 for conns and registry CAs. The agent guide's error table now says
  `PARTIAL_FAILURE` exits with the worst code among the failed servers.

### Fixed

- `install.sh` no longer installs into `~/.local/bin` when
  `KOMANDO_INSTALL_DIR` is set but cannot be written: it creates the
  folder, or stops with a message.

### Security

- Downloads by an AI agent (`download`, `sync`, `storage download`, also
  to stdout) save text files the way `fs cat` shows them, with secret
  values as `[hidden]`. Before, they gave the agent the real file.
- `upload` and `sync` refuse a file that still holds `[hidden]` or
  `[secret:NAME]`, as `fs write` does, so a masked copy never replaces the
  real values.
- `fs cat` and `fs replace` now hide Redis passwords (`requirepass`,
  `masterauth`, ACL rules) as other output does. Before, `fs replace`
  could confirm a guessed password and `fs cat` returned the file's hash.
- `exec --read-only` checks the SQL in `psql -c`, `mysql -e` and SQL fed in
  with `--stdin-file` (the same rules as `db query`), and the commands in
  `redis-cli`, `valkey-cli` and `keydb-cli` (the same as `cache run`). It
  also catches `sort -o`, `uniq IN OUT`, `split`, `openssl -out`, `date -s`,
  `hostname NAME`, `dmesg -C` and `less +CMD`.
- The danger check now stops `bash --rcfile FILE -c ...`, `ufw --force
  reset`, `iptables -P INPUT DROP`, `cp`, `mv`, `tee`, `truncate` or `dd`
  onto `/etc/passwd`, `/etc/shadow` or `/etc/sudoers`, `echo '...' | sh`
  (the text is checked like `sh -c`) and `base64 -d | sh`.
- `secret set` checks that `KOMANDO_VAULT_PASS` opens the secrets already
  stored; a mistyped passphrase no longer saves a secret under a second key.
  A missing `vault.key` is no longer replaced by a new one while secrets
  need it: komando asks you to restore it.

## [0.3.1] - 2026-11-07

### Highlights

- **Rebuilt a group of servers?** `komando host trust @group --reset --yes`
  accepts all their new keys after one yes, instead of one per server.
- **New servers that are still starting:** `komando test @new --wait 5m`
  waits until they answer, instead of a sleep loop.
- **AI agents read output more simply:** the guide tells them to use `-o
  text` when they only want to read what a command printed.

### Added

- `komando host trust TARGET` takes many servers (`@group`, `tag:`,
  `'web*'`, `a,b`): after a rebuild of a whole group, `--reset` replaces
  every changed key after ONE yes that names each server with its new
  fingerprint, instead of one yes per server. `data.results` has each
  server's `fingerprint` and `old_fingerprints`. A changed key is still
  refused without `--reset`; `host trust NAME` answers as before.

- `komando test TARGET --wait 5m` waits for new servers: it tests again
  every few seconds until every target passes or the time is up (right
  after creating or rebuilding cloud servers, instead of a sleep loop).
  It does not wait out a changed host key or a refused login: those fail at
  once. `data.waited_ms` says how long it waited.

### Changed

- `komando host rm` says which servers' pinned host keys it keeps
  (`host_keys_kept`, `note`): a server added again at the same address must
  show the same key, so `rm` plus `add` is no way around
  `HOSTKEY_MISMATCH`.

- The agent guide (`komando guide`), the skill and the output docs say
  when to use `-o text`: to read a command's output, instead of pulling
  `stdout` out of the JSON. JSON stays the default for branching on each
  server's exit code or error.

### Fixed

- `--help` examples for `cluster` commands now use `--namespace`; `-n` is
  `--limit` in komando, so the old examples failed when copied. `import
  --help` no longer shows "(default -)", and `komando --help` and `conn
  --help` now say that clusters and registries are conns too.

## [0.3.0] - 2026-11-07

### Highlights

- **New license.** komando is now under the AGPL-3.0, with a commercial
  license for closed-source use. It stays free to use for any purpose.
- **More VPNs built in.** L2TP/IPsec, Cisco-style IPsec (XAUTH) and IKEv2
  work without strongSwan, OS VPN settings or admin rights.
- **Patch rounds.** `pkg security` installs only security updates, one
  server at a time, and checks each server before and after. `cert check`
  shows when certificates expire, `docker prune` previews what it would
  delete, and `reboot` restarts servers one at a time and waits for them.
- **Safer for AI agents.** A full security review brought fixes for SQL,
  database restores, Redis passwords, clusters and `--read-only`.
- **Easier inventory.** Rename servers, conns, VPNs and secrets (`mv`),
  import servers from a spreadsheet (`import csv`) and edit many at once.

### Changed

- **License: komando is now under the GNU Affero General Public License
  v3.0 (AGPL-3.0)** instead of MIT. You can still use it for free, for any
  purpose. If you change komando and give it to others, or let them use it
  over a network, you must share your version's source code under the same
  license. A [commercial license](COMMERCIAL-LICENSE.md) is available for
  closed-source use. Contributors now sign a short
  [Contributor License Agreement](CLA.md) once. v0.1.0 and v0.2.0 stay
  under MIT.

- The built-in recipes `cert-expiry`, `certbot-certs` and `docker-prune`
  are gone: `komando cert check` and `komando docker prune` do the same
  better (`docker-prune` skipped the preview and the `--allow-dangerous`
  question). Running one of those names says which command to use; a
  saved recipe of the same name still works.

- `komando facts` and `komando pkg security` read the server's state with
  the same check, so they agree: `facts` now also sees a newer kernel that
  needrestart reports (`reboot_required`, `reboot_packages: ["kernel"]`)
  and, on dnf/yum servers, the services that need a restart (from
  `needs-restarting -s`). `pkg security` now has `os_support` and warns on
  an OS past end of life, where an empty list does not mean the server is
  safe.

- `komando vpn status`: `last_end` now says when the session ended and how
  long it ran. When an L2TP server ends the session, it also says how long
  the link had no traffic (a server idle timeout?), and the log shows the
  server's own reason (StopCCN/CDN result, LCP Terminate text).

- Servers behind the same jump hosts share one connection to them within a
  command: `exec -P 10` through a bastion logs in to it once (OpenSSH's
  ControlMaster), staying under its `MaxStartups`. A broken shared path is
  opened again once.

- A protected server stays protected under another name: before any
  change, komando also compares the IP addresses names resolve to on this
  computer, so `db.internal` is the protected `10.0.0.5` (hosts and conns,
  same port). Names only a jump host knows are compared as text.

- A person is asked about a safety change (for example a recipe replaced by
  a read-only one) before komando locks its state file, so other komando
  commands do not wait for the answer.

- `cache run` text output shows map entries as `name: value` (was `name =>
  value`). For agents, a RESP2 `HGETALL` reply is shown as a map, so
  secret-named fields are hidden as over RESP3.

- When a script command times out, the hint no longer says to raise
  `--timeout`; it says the script may still be running and names `SCRIPT
  KILL` or `FUNCTION KILL`.

- Approval window: line breaks, tabs, control characters, long runs of
  spaces, blank-drawing letters (U+3164 ...) and combining marks show as
  $'...' escapes, so multi-line `fs replace` edits on protected hosts can be
  approved; bidi and zero-width characters are still refused.

- Error and hint lines show colour/conceal escapes and carriage returns as
  \e and \r.

- A saved read-only recipe that no longer passes the read-only check runs as
  a change (protected servers ask for --yes) instead of being blocked.

- `--backup` copies add up next to the file; clean them up with `fs rm`.

- An SSH connection that stops answering (for example a VPN that dropped
  silently) is closed after about a minute without an answer, so commands
  report the loss instead of waiting until `--timeout`.

- `host edit --rename` and `conn edit --rename` are deprecated in favour of
  `host mv` / `conn mv`.

- The approval window for protected changes says which protected entries the
  command touches.

- Imports refuse a server whose `key` is not in komando's keychain.

- The hidden `secret set` prompt drops text typed or pasted before it
  appeared, and says so; it strips bracketed-paste marks.

- `komando facts` reports values it cannot read as `null` instead of
  `0`/`false`: `reboot_required` is `null` where it cannot be checked, and
  an unsupported OS shows `updates.security: null` with a warning.

### Added

- `komando schema` says what each command does: `kind` is `read`,
  `change` or `depends`, and `kind_note` says on what for `depends`
  (`exec` changes things unless `--read-only`, `db query` only reads
  unless `--write`). Agents can see it before they run a command.

- `make e2e` also runs `facts`, `pkg security` (with a real `--apply`) and
  `pkg` against Rocky Linux 9 (dnf) and Amazon Linux 2 (yum) servers, and
  compares every answer with the native `dnf`/`yum`/`rpm` on the same
  server (`test/e2e/rhel`, `test/e2e/checks/rhel.sh`).

- Registry conns (`registry://`, `oci://`) take TLS options:
  `?ca=secret:NAME` trusts a private CA (PEM in the vault), or pins the
  registry's own certificate when the CA is not at hand, and keeps the
  certificate check on; `?tls=skip-verify` uses HTTPS without the check
  (like Docker's `insecure-registries`; `komando doctor` warns about it,
  also with `--via`). A refused certificate is now `REGISTRY_TLS` (not
  `REGISTRY_UNREACHABLE`), with a hint that names `ca=` first. Unknown
  registry URL options and `tls=` values are refused instead of ignored.
  With `--via`, the last server looks the registry's name up (its
  `/etc/hosts` applies); the certificate check and `Host` stay on the name.

- L2TP/IPsec (`l2tp`), Cisco-style IPsec with a group name and XAUTH login
  (`ipsec`, also `cisco`) and IKEv2 (`ikev2`, pre-shared key or EAP-MSCHAPv2
  login with the server's certificate checked) are built into komando:
  komando's own IKEv1, IKEv2, ESP-in-UDP, L2TP and PPP, so they need no
  strongSwan, no OS VPN settings and no admin rights, and the computer's
  network stays as it is. New `vpn add`/`vpn edit` flags: `--server`,
  `--psk-ref`, `--id`, `--remote-id`, `--ca`. Tested against strongSwan 5.9
  and xl2tpd, rekeys included (`make e2e-ipsec`). Before, these kinds were
  only a name for `system`.

- `komando vpn status` shows why a VPN's last session ended (`last_end`),
  and for `l2tp`, `ipsec` and `ikev2` the last lines of its log
  (`last_log`), so an agent can tell why without reading `~/.komando`.

- `db dump --on HOST` runs pg_dump or mysqldump on a server you choose,
  whatever the conn's own path (for example a conn through a VPN), so
  `--format custom` works there too. It runs at low priority (nice, ionice),
  keeps the password in the tool's environment and streams the backup back
  over SSH; `runs_on` and `low_priority` in the answer and the audit say
  where and how. `db restore --on HOST` loads a PostgreSQL archive with
  pg_restore there, behind the same `--allow-dangerous` gate.

- New errors with hints: `TOOL_TOO_OLD` (pg_dump older than the database
  server, or pg_restore older than the archive) and `CONN_UNREACHABLE` (the
  tool cannot reach the database from that server, with how to add a
  127.0.0.1 conn through it).

- `komando reboot TARGET`: reboots servers one at a time, waits for each to
  answer again and checks it really started anew (boot id). A server that
  does not come back stops the rest. Destructive: needs `--allow-dangerous`.

- `komando registry prune CONN REPO --keep N [--older-than 30d] [--match RE]`:
  deletes old images, never one a kept tag points at (`latest` always
  stays). `registry inspect` now gives a multi-platform image's build date.

- `komando import aws`: one S3 storage conn per bucket of each profile in
  `~/.aws/config` (and the credentials file). The conns use the profile, so
  no key is copied and SSO or roles keep working.

- memcached conns (`memcached://`, `memcacheds://` for TLS, the text
  protocol's login): `cache get`, `set`, `rm`, `keys`, `info` and `run` work
  like they do for Redis, with the same safety rules (`flush_all` needs
  `--allow-dangerous`). komando speaks the protocol itself.

- `komando db user ls|add|passwd|rm`, `db grant`, `db revoke` and `db grants`
  for PostgreSQL and MySQL/MariaDB. Passwords come from a secret reference
  and are never shown or audited; PostgreSQL gets a SCRAM-SHA-256 verifier
  computed by komando, so the password never reaches the server.

- `komando config set audit_syslog tls://HOST:6514` (or `udp://`, `tcp://`):
  each audit record also goes to a log server or SIEM, as RFC 5424 syslog.
  Changing it needs `--yes`.

- `komando secret keychain`: the vault key moves from `vault.key` into the
  OS keychain (macOS keychain, Linux Secret Service), so a backup of
  `~/.komando` no longer opens the vault. `--off --yes` moves it back.
  `doctor` names it.

- `komando config approval-code`: komando's "Allow once" window then also
  asks for the 6-digit code from your authenticator app (TOTP), a second
  factor for an AI agent's `--yes`, `--allow-dangerous` and `--reveal`. Only a
  person at a terminal can turn it on; turning it off needs that code too.

- The guard that keeps AI agents away from secret files on this computer now
  also works for Cursor, Gemini CLI and Codex: `komando guide install` adds
  it to `.cursor/hooks.json`, `.gemini/settings.json` and `.codex/hooks.json`
  when those folders exist (Codex asks you to approve it once in `/hooks`).

- `komando svc daemon-reload TARGET`: reloads unit files after you write
  one, and names units that still need a reload.

- `komando job wait` takes several job IDs and waits for all of them, with
  one result per job and a summary; the exit code is the worst one.

- `komando job start --sudo` works on servers whose sudo needs a password
  (`--sudo-ref`). The password is sent as input, never on a command line,
  and the job deletes it as soon as it starts.

- `komando host mv OLD NEW`, `conn mv` and `vpn mv` rename an entry and
  update every reference to it (`--via` paths, jobs, tunnels) in one step;
  renaming a protected entry needs `--yes`.

- `komando host edit` takes several names and targets (`host edit @ubuntu
  --sudo-ref secret:ubuntu-sudo`); one `--yes` and one approval window,
  which lists every server and which are protected, cover the whole command.

- `komando import csv FILE` adds servers from a spreadsheet; every row is
  checked before anything is written.

- `komando secret mv OLD NEW` renames a secret and every server, conn, key
  and VPN reference to it, without showing the value. `secret cp OLD NEW`
  copies one inside the vault.

- `komando secret check NAME`: a person compares a value with the stored one
  without seeing either; refused for AI agents (`NEEDS_PERSON`).

- `secret set` and `secret get` warn when a value starts or ends with a
  space or tab, ends with a line break, or holds control characters.

- `komando facts` reports whether the OS still gets security updates
  (`os_support`: supported, extended through Ubuntu Pro ESM or Debian LTS,
  unsupported, unknown), pending and security updates with the package index
  age, reboot-required packages, services needing a restart, passwordless
  sudo, Docker version, Swarm role and running containers, PM2 daemons and
  apps, listening ports with their programs, hand-made systemd units, and
  `warnings`. It also has a short text view.

- `komando pkg security TARGET` lists pending security updates with each
  server's state (running containers, failed units, pending updates, reboot
  required, services needing a restart). `--apply` installs only security
  updates, one server at a time, compares each server before and after and
  stops the round on an unexpected change (`UNEXPECTED_CHANGE`;
  `--keep-going` to continue). It never reboots.

- `komando cert check TARGET...` shows when TLS certificates expire: on
  servers (certbot, nginx, haproxy, apache, `--path`; only the certificate
  part of a file is read) and for websites and TLS conns (directly or
  through `--via`, with a trust check), plus certbot renewal state. `--warn`
  (default 30d) flags certificates expiring soon; problems exit 1 with
  `CERT_PROBLEMS`.

- `komando docker prune TARGET` with `--older-than`, `--all` and
  `--volumes`. `--dry-run` lists the stopped containers, images, volumes and
  build cache that would be removed, with sizes and a total. The real run
  needs `--allow-dangerous`.

- komando's own restore of plain SQL skips pg_dump 17's `SET
  transaction_timeout` on PostgreSQL servers older than 17, so such backups
  restore there.

### Security

- Updated `github.com/klauspost/compress` to v1.20.2 (GO-2026-6865: a
  crafted compressed frame could crash komando during a VPN session).

Fixes from the full security review of 2026-11-04.

- komando db refuses SET NAMES, SET CHARACTER SET, client_encoding and
  character_set_client changes (SQL_STRING_RULES), and refuses a connection
  whose client character set can hide a backslash (SJIS, GBK, BIG5, GB18030,
  UHC, JOHAB, cp932).

- MySQL `--` before 0x7f is read as a comment the way the server reads it;
  `--` before a non-ASCII byte is refused (SQL_HIDDEN_CODE).

- In MySQL only known transactional statements (SELECT, INSERT, UPDATE,
  DELETE, REPLACE, WITH, VALUES, TABLE, SHOW, DESCRIBE, EXPLAIN, HELP, USE,
  DO, HANDLER, SET) run inside komando's transaction; everything else,
  including CHECK TABLE, CACHE INDEX, replication START/STOP/CHANGE, IMPORT
  TABLE, CLONE, BACKUP STAGE and XA, must be sent alone, needs --write, and
  a dry run reports it without running it.

- A dry run no longer executes statements a rollback does not undo (ending
  sessions, COPY ... PROGRAM, server files, dblink, server config,
  set_config with a computed name, DO, CALL, EXECUTE, setval); they are
  reported as skipped.

- `db query --write --dry-run` runs nothing when the real run would be
  blocked (destructive SQL without --allow-dangerous, or a protected conn
  without --yes); it shows the plan and meta.would_be_blocked.

- Postgres COMMIT AND CHAIN hidden from the classifier is now caught
  (SQL_TX_CONTROL) before the next statement runs.

- `db dump --table` refuses values that start with `-`; mysqldump read them
  as options on the --via server (e.g. --result-file could overwrite files).

- `db restore` names SQL that runs programs, touches server files, changes
  server config or privileges, or cannot be inspected (sql-program,
  sql-server-file, sql-server-config, sql-privileges, sql-opaque,
  sql-remote, sql-kill) next to db-restore in the approval and
  POLICY_BLOCKED, with the line where each first appears.

- `cache run` now needs `--write --allow-dangerous` for read-only scripts
  (`EVAL_RO`, `EVALSHA_RO`, `FCALL_RO`) and for module code (`TFCALL`,
  `TFCALLASYNC`, `RG.PYEXECUTE`, `RG.TRIGGER`, `RG.TRIGGERONKEY`), because
  each can block the server or run code komando cannot inspect.

- `FUNCTION LOAD REPLACE`, `TFUNCTION LOAD REPLACE`, `TFUNCTION DELETE` and
  `RG.UNREGISTER` count as `redis-scripts` (destructive).

- AI agents no longer see Redis passwords: `CONFIG GET` and `SENTINEL CONFIG
  GET` values of requirepass, masterauth, primaryauth, tls-*-pass and
  sentinel-pass, and the password hashes in `ACL LIST` and `ACL GETUSER`,
  show as `[hidden]`, also when the password is a word like `yes`.

- Output masking now also hides Redis passwords written the Redis way
  (`requirepass pw`, `sentinel auth-pass mymaster pw`, ACL `>pw` and
  `#hash`), as seen through `fs read` of redis.conf or users.acl, grep, or
  redis-cli `CONFIG GET` over `exec`.

- Cluster run: an AI agent's `get secret -o yaml|json` is a read, since the
  values show as hidden; it no longer asks the person for --allow-dangerous.

- Cluster run / cluster apply: a file that still holds a value komando hid
  ([hidden], (hidden)) is refused with HIDDEN_VALUE before anything is sent,
  so a get-edit-apply round trip cannot overwrite a password with the
  marker.

- Cluster run: an AI agent cannot send komando's own folder, or files that
  are secrets by name (unless --reveal), to the cluster through -f,
  --from-file or cp (SENSITIVE_FILE).

- Cluster run: an empty object name (delete pod/, delete pod "",
  metadata.name: "") is refused instead of deleting the whole collection.

- Cluster run cp: never writes into a .git folder; copied files keep their
  exec bit like kubectl cp, never setuid, setgid or world-write.

- Swarm: --mount read as CSV, host-folder volumes (volume-opt device, volume
  create --opt device=), --volumes-from, --network/--net host, --cgroupns
  host, --pid container:, --device-cgroup-rule, credential folders even
  read-only (/root, /home/USER, .ssh, /etc/kubernetes, /var/lib/kubelet,
  shadow, etcd, rancher), /opt and /var/spool, and plugin create|enable|set
  now need --allow-dangerous.

- Kubeconfig login programs: a kubeconfig a person imported (or allowed) is
  trusted for its program and server, so agents no longer get a window on
  every read; a change in the vault asks again.

- Approval window: names the program a kubeconfig login runs, and a yes
  given for something else does not cover it.

- Cluster exec/shell/forward --dry-run report the login-program stop the
  real run would meet.

- komando counts an AI agent's variable as present even when it is empty,
  and the agent guard now also stops env flag clusters, GNU long-option
  prefixes and env -S, exec -c, read/printf -v/mapfile/for loops that set
  the variables, brace/glob/$-computed names, statements that start with a
  keyword, more wrappers (timeout, setsid, stdbuf, chrt, busybox, ...),
  `sudo komando` without -E, `bash -lc`/`sh -ec` scripts and quoted heredocs
  fed to a shell.

- An AI agent's local reads, file: references and the guard catch
  ~/.KOMANDO-style case variants on macOS and Windows, hard links to
  komando's data or private keys, and any /proc/.../environ path (refused
  even with --reveal).

- `komando sync` of a folder checks each file for an AI agent, as `cp -r`
  does; komando's own data is never uploaded, even with --reveal.

- The agent guard stops recursive reads and archives of a folder that holds
  komando's data (grep -r ~, rg, tar -C ~, zip -r, cp -r, find -exec, the
  Grep tool in the home folder), follows tar/git -C, sees through $(echo
  ...) substitutions and expands ~user.

- `--read-only` now reads shell scripts the way bash does: options after
  `-c` (`bash -c -- '...'`), arguments a script gets (`sh -c '...' "$0"`),
  comments, here-documents, `case` inside `$( )` and brace expansion
  (`{rm,-rf,/x}`). A command it cannot read (an unclosed quote) is refused.

- Under `--read-only`, an argument that is only known when the command runs
  (`find /data $X`, `xargs find`) is refused for commands whose arguments
  decide what they do. `-e` values are filled in first.

- Under `--read-only`, setting a variable that runs code (BASH_ENV, PS4,
  PROMPT_COMMAND, LD_PRELOAD, PAGER, GIT_SSH_COMMAND, BASH_FUNC_*) is
  refused, whether inline, through env or sudo, through export, or with -e.

- `--read-only` now catches more commands that write or run commands: git
  -c, sed e/w, gawk --source and @f(), tar --checkpoint-action and extract,
  psql \! and \o, mysql system and tee, vim, script, sg, hash -p,
  gzip/xz/unzip/patch on files, curl -o/-O/-d/-X POST, wget saving a file,
  sqlite3, crontab FILE, docker/kubectl exec, and git branch/tag/config
  changes. Subcommands are now found after global options (`kubectl -n prod
  delete`, `iptables -t nat -A`). New wrappers: chrt, taskset, numactl,
  prlimit, fakeroot, faketime.

- `pkg rm` now treats openssh-server.x86_64, sudo.noarch and other name.arch
  spellings (also after a version) as essential, and apt patterns such as
  `openssh.server` that would pick an essential package. All need
  --allow-dangerous.

- Package names may no longer end in '-' (apt reads it as 'remove this
  package', even for `pkg install` and `pkg upgrade`) or '.'; a local
  package file gets a message pointing to `komando upload` + `komando exec`.

- On apt servers, `pkg rm` of a package whose removal would take an
  essential package with it (libssl3 takes openssh-server) now stops with
  POLICY_BLOCKED before anything is removed. Other package managers are not
  checked this way yet (known gap).

- An AI agent's `--dry-run --reveal` no longer shows hidden values; a dry
  run always keeps masking on and reports `REVEAL_NEEDS_PERSON` in
  `meta.would_be_blocked`.

- `fs replace` refuses (HIDDEN_VALUE) an agent's edit that would uncover a
  hidden value, such as renaming `DB_PASSWORD=` or cutting off `postgres://`
  or `Bearer `.

- For AI agents, `fs replace`, `fs write --if-changed` and `would_change` no
  longer reveal whether new text equals a hidden value, and `fs cat`/`fs
  replace`/`fs write` leave out the sha256 of a file with hidden values.

- `fs cat --head/--tail` masks the whole file before cutting it; the end of
  a private key without its BEGIN line is hidden too.

- VPN (OpenVPN): verify-x509-name now compares the server certificate's
  subject attribute by attribute. A crafted value such as O="Corp, CN=vpn"
  or CN="vpn " can no longer pass as the pinned server.

- VPN (OpenVPN): remote-cert-ku accepts the 0x prefix, as OpenVPN does.
  remote-cert-eku accepts the IPsec usage names (IPSec End System, IPSec
  Tunnel, IPSec User).

- VPN (OpenVPN): a client-side rekey no longer cuts off a renegotiation the
  server already started, which could drop the session.

- VPN: only SOCKS clients that log in keep a VPN session from going idle.
  Running out of file descriptors no longer ends the session.

### Removed

- `op://` no longer falls back to the closed-source `op` CLI, as announced
  in 0.2.0: it reads 1Password Connect only. Without Connect it says so and
  names the alternatives (`bw://`, `kdbx:`, a komando secret).

### Fixed

- `komando vpn up` printed the session's local SOCKS password; it now shows
  `[hidden]`.

- `komando db dump` works again on PostgreSQL 12 and 13: it no longer reads
  catalog columns that only newer servers have (`prosqlbody`, `tgparentid`).

- The Bitwarden device id file (`bitwarden-device`) is kept in
  `KOMANDO_HOME`, like every other state file, instead of always in
  `~/.komando`.

- The Postgres read-only session setting falls back for any pooler that
  rejects the startup parameter (SQLSTATE 08P01), not only PgBouncer's
  wording.

- `db restore` no longer hangs (PostgreSQL) or fails with 'Query was empty'
  (MySQL) when the last statement has no trailing `;`.

- `db restore` no longer refuses backups whose data or comments mention
  NO_BACKSLASH_ESCAPES or standard_conforming_strings, MySQL routines with a
  line starting with a column such as `source`, names ending in a backslash
  in backticks, or non-Latin PostgreSQL dollar-quote tags.

- `db restore` refuses computed changes to standard_conforming_strings
  (set_config) and sql_mode (CONCAT, variables), and DELIMITER lines it
  cannot follow; the check and the restore now read DELIMITER the same way.

- MySQL restore no longer sends a comment-only chunk in front of the next
  statement on the same line.

- Dry-run and result `runs_on` say `local` when komando itself runs the dump
  or restore through the --via path.

- The agent guard no longer treats quoted regexes and sed scripts as file
  globs (`grep -o '.*' f`, `sed 's/.*//' f`), no longer checks find's -name
  patterns, and allows `du -sh ~/*/*`.

- `komando import kubeconfig|pgpass|mycnf|env|docker` works for AI agents
  again (the secrets go into the vault, which agents never see).

- `--dry-run --host-key-policy off` keeps the policy for people and scripts;
  only an AI agent's preview connects with identity checks on.

- Read-only shell scripts with a `#!` line now work with `script
  --read-only` and `exec --read-only --stdin-file ... -- 'bash -s'`. Script
  arguments (`--arg`, `bash -s -- ARGS`) are refused under --read-only.

- `exec --read-only --stdin-file` treats input as data unless the command is
  a shell reading its input (`bash -s`). SQL sent to `psql` with `n > 5`
  works again; `\!` and `system` in that SQL are refused.

- `awk '/systemd/'`, `awk '/a|b/'`, `node -v`, `php -v`, `perl -v`, `bash
  --version` and `exec 2>&1` are read-only again.

- A streamed line that only mentions a private key header no longer holds
  `logs --follow` or `exec --stream` output for 256 KiB. After 16 KiB the
  output is released with the header hidden.

- Connecting through a jump host that never answers the channel open (or
  waits for a firewalled target) now fails with CONNECT_TIMEOUT after
  --connect-timeout, where it used to hang.

- A slow SSM or proxy-command start no longer makes the ssh-agent's
  signature time out into a false AUTH_FAILED.

- `host import` and `komando import` resolve each name once, in parallel and
  outside the inventory lock, when checking imported hosts against protected
  servers.

- `host trust --dry-run` says how the key would be fetched (directly,
  through a VPN, a proxy command or jump hosts).

- Re-running a secret rotation (`--old 'NAME=[hidden]' --new
  'NAME={{secret:VAULT}}'`) on a host where it is already done returns
  changed:false again, not NO_MATCH.

- Writes work again on SFTP servers that do not allow setting file modes,
  when their new files are no more open than requested; the result reports
  the mode the file got.

- A broken or empty state file now fails with `STATE_CORRUPT` and a hint on
  how to recover.

- Moving the vault key to or from the keychain waits for other komando
  processes changing the vault.

- `komando exec` (and `script`, `logs`, module commands) no longer reports a
  bare exit -1 when the connection breaks mid-command: the server's result
  has error code `CONNECTION_LOST` (exit 4), keeps the output received so
  far, and says the command may still be running or may have finished.

- Renaming a protected host or conn with `--rename` no longer skips the
  `--yes` check, and renaming a conn updates the tunnels that point to it.

- `secret rm` and `used_by` count `secret:` references in a server's
  environment variables.

- The approval code's key can no longer be set, moved, copied or removed
  with `komando secret` (`RESERVED_SECRET`).

- `komando test` results carry `host`, like `facts` and `exec`. `name` stays
  for existing scripts; use `host`.

## [0.2.0] - 2026-11-04

### Highlights

- **More than servers.** One list now holds databases (PostgreSQL, MySQL,
  SQLite), caches (Redis, Valkey), storage (S3, FTPS, SFTP),
  Kubernetes and Docker Swarm clusters and container registries, each with
  its own safe command: `db`, `cache`, `storage`, `cluster`, `registry`.
- **VPNs built in.** WireGuard, OpenVPN, AnyConnect and Tailscale connect by
  themselves when a target needs them, several at once, with nothing else
  to install.
- **Passwords from where you keep them.** komando's own vault, or HashiCorp
  Vault, AWS and Google secret managers, Bitwarden, KeePass and 1Password.
- **Secrets stay away from AI agents.** Passwords, keys and tokens show as
  `[hidden]`, and changes that need a person open a window on their screen.
- **Know what is running.** `komando status` and `komando prompt` show the
  VPNs, tunnels and jobs that are still up.

### Built in: secret managers and AWS logins (no vault, aws or gcloud CLI)

- `vault:` references read HashiCorp Vault or OpenBao themselves (KV v1 and
  v2, namespaces, `VAULT_CACERT`, `~/.vault-token`).
- `aws-sm:` reads AWS Secrets Manager, and `gcp-sm:` Google Secret Manager,
  with the credentials already on the computer.
- Conns with `aws_profile` (S3, ECR) read `~/.aws` themselves: SSO,
  assumed roles, temporary keys. New `komando login aws [--profile]` does
  the SSO sign-in that `aws sso login` did, into the same cache.
- New error codes `AWS_PROFILE_NOT_FOUND` and `AWS_FAILED`;
  `AWS_CLI_MISSING` no longer happens.

### Built in: OpenVPN and AnyConnect (no Docker, openvpn or openconnect)

- `openvpn` VPNs (and Pritunl profiles) run on komando's own OpenVPN client
  in user space: UDP and TCP, tls-auth and tls-crypt, AES-128/256-GCM,
  ChaCha20-Poly1305 and AES-CBC with HMAC, TLS key export or the older PRF,
  pushed options, keepalive and key renegotiation. No Docker container,
  no openvpn program, no admin rights; the computer's routes stay as they
  are. Profiles with options it does not support, or with compression
  (VORACLE), are refused at `vpn add` (`OVPN_UNSUPPORTED`). `--os-mode` is
  deprecated.
- `anyconnect` VPNs (Cisco AnyConnect, ocserv) run on komando's own client:
  the XML login (with one-time codes asked at `vpn up`) and the CSTP tunnel.
  The login happens at the terminal; the session's process gets only the
  session cookie.
- Experimental: komando's own Fortinet (form login with token codes, PPP
  over TLS), GlobalProtect (gateway login with challenges, GPST tunnel) and
  F5 BIG-IP (APM login, PPP over TLS) clients. They are used when
  openconnect is not installed, or with
  `KOMANDO_EXPERIMENTAL_VPN=fortinet,globalprotect,f5`; they have not yet
  been tried against the vendors' own servers.
- Experimental: komando's own Pulse Secure / Ivanti Connect Secure client
  (IF-T/TLS with EAP: realm choice, password, one-time codes asked at
  `vpn up`, the DSID session cookie, packets over TLS). Same rule: used
  when openconnect is not installed, or with `KOMANDO_EXPERIMENTAL_VPN=pulse`.
  Client certificates (EAP-TTLS) and Host Checker are refused with a clear
  error.
- AnyConnect uses DTLS (UDP) when the server offers it, with the key taken
  from the TLS connection (ocserv's PSK-NEGOTIATE); packets move back to
  TLS when UDP stops answering. Tested against ocserv.
- Hosts added with `--ssm` reach EC2 through komando's own AWS Session
  Manager client when the aws CLI or its session-manager-plugin is missing
  (or with `KOMANDO_EXPERIMENTAL=ssm`). KMS-encrypted sessions work: komando
  asks KMS for the session's data key and encrypts the stream with it.
- Every VPN session's local SOCKS port now needs a random per-session login
  (WireGuard and Tailscale too), so other users of the computer cannot use
  it.

### Built in: komando's own dump and restore

- `db dump` and `db restore` work without pg_dump, psql, mysqldump or mysql
  for direct conns, VPN conns and servers without those tools: komando
  writes and reads plain SQL itself (PostgreSQL: extensions, schemas, types,
  functions, sequences, tables with identity, generated columns and
  partitions, data via COPY, constraints, indexes, views, materialized
  views, triggers, row-level security, comments; MySQL: tables, data,
  views, triggers, routines). Objects it cannot write stop the dump by name
  (`DUMP_UNSUPPORTED`). Through a server that has the tools, they are still
  used. `tool` in the answer says which ran.

### Built in: komando's own kubectl and SQL shell

- `cluster run` no longer needs kubectl: komando understands the kubectl
  commands itself and prints what kubectl prints (server-side tables, wide,
  name, json, yaml, jsonpath, custom-columns, watch) for get, describe,
  logs, events, top, explain, version, api-resources, api-versions,
  cluster-info, auth, wait, rollout, apply, diff, create, replace, delete,
  patch, label, annotate, scale, set image, cordon, uncordon, drain, taint,
  run, exec, cp, debug, certificate and config. The read-only default and
  the risk checks are unchanged; port-forward and `exec -it` point at
  `cluster forward` and `cluster shell`.
- `db shell` is komando's own SQL shell for PostgreSQL, MySQL/MariaDB and
  SQLite (no psql, mysql or sqlite3): each statement gets db query's checks
  and is audited; `\d`, `\l`, `\dn`, `\du`, `\x`, `\G`, `\timing`, `\i`.
  `TOOL_MISSING` and `TLS_THROUGH_FORWARD` no longer happen for it.

### Built in: Kubernetes exec, shell and port-forward (no kubectl)

- `cluster exec` and `cluster forward` speak Kubernetes' streaming
  protocols over WebSocket themselves, and over SPDY on clusters before
  Kubernetes 1.30 (tried when the WebSocket is refused, as kubectl does;
  tested against Kubernetes 1.29). `cluster forward svc/NAME` maps the
  service port to the pod's target port (by number or name), like kubectl.
- New `cluster shell TARGET POD|TYPE/NAME [-- COMMAND]`: an interactive
  terminal in a pod for people, with the status lines and the protected
  question of `komando shell`.
- EKS and GKE tokens (`aws eks get-token`, `aws-iam-authenticator`,
  `gke-gcloud-auth-plugin` in a kubeconfig) are made by komando.
- `cluster exec --dry-run` and `cluster forward --dry-run` describe the
  call without "kubectl" in `would_run`, and add `pod`, `command`, `local`.

### Built in: Bitwarden, KeePass, 1Password Connect

- New `bw://ITEM/FIELD` for Bitwarden and Vaultwarden: komando logs in,
  syncs once per run and decrypts on this computer (personal, item-key and
  organization items), like Bitwarden's own clients.
- New `kdbx:FILE#GROUP/ENTRY[#FIELD]` for KeePass and KeePassXC files.
- `op://` reads a 1Password Connect server (`OP_CONNECT_HOST`,
  `OP_CONNECT_TOKEN`). Without Connect it still calls the `op` CLI, which is
  deprecated: komando ships only open-source parts, and the 1Password SDK's
  core is a prebuilt WebAssembly module.

### Built in: Tailscale and Headscale (no tailscaled)

- `tailscale` VPNs run inside komando with Tailscale's own Go library
  (`tsnet`), in user-space: no `tailscale` or `tailscaled` to install, no
  admin rights, the computer's network unchanged. Without an auth key,
  `komando vpn up` opens the login page once; the node then stays logged in.

### `komando prompt`: VPNs and tunnels in your shell prompt

- `komando prompt` prints `vpn:office tun:2`, or nothing, for zsh (also
  oh-my-zsh), bash or starship; the docs have the line to add. It only
  reads the state file: no network, no writes, no other programs, never an
  error, and it does not keep an idle VPN alive.

### `komando status`: what is still running

- One command lists what komando left running: VPN sessions (with when
  they close if unused), tunnels and jobs. It contacts nothing, so it is
  quick and works offline; `job list --refresh` still asks the servers
  whether a job runs.

### Where am I? Status lines for people

- `shell`, `db shell`, `cluster forward` and `logs --follow` (servers,
  Kubernetes, Swarm) print one line before they connect: what, where, as
  whom, the way there (`via vpn office → bastion1`) and `PROTECTED`
  (red; `NO_COLOR` turns colour off). `shell` and `db shell` also say how
  the session ended: `left web1 (exit 0, 12m)` or `connection to web1 lost`.
- A command that connects a VPN by itself says the VPN stays up, for how
  long, and how to stop it.
- Only for a person at a terminal, on stderr: agents, scripts, pipes and
  JSON output are unchanged. Names and addresses are printed without
  control characters, so they cannot rewrite the terminal.
- `db shell`'s line moved before connecting and uses the same format
  (was `komando: psql session on app-db (read-only)`).

### Safer `komando shell` (`ssh`, `connect`)

- `--dry-run` no longer opens a real shell: it shows the host, address,
  user, `--via` path and whether it is protected, and connects nothing.
- A protected server asks `[y/N]` before the shell opens, like `db shell`
  on a protected conn; `--yes` skips the question.
- AI agents are refused even when they run in a pseudo-terminal, and the
  error code is now `NEEDS_TERMINAL` (was `NOT_A_TTY`), the same as
  `db shell`. Like `db shell`, it also needs stderr to be a terminal.
### Clearer errors

- Every error now has a hint with the next step; a test keeps it that way.
- A file missing on this computer reads "./x does not exist on this
  computer" instead of Go's "stat ./x: no such file or directory".
- `cp ./missing web1:/tmp/` no longer suggests renaming the destination; that
  hint is only for a target komando does not know.
- A failure on one server no longer names it twice ("web1: … for web1").
- In text, an error from many servers shows its code too
  (`error [PARTIAL_FAILURE]: …`), like any other error.
- An unexpected file error is `FILE_ERROR`, not `REMOTE_ERROR`.

### Feels like the native tools (an end-to-end round over every command)

- `--dry-run` is never stopped by a safety rule: it shows the plan, and
  `meta.would_be_blocked` (in text: "without --dry-run this stops here")
  names the stop the real run would hit. Text dry runs start with
  "dry run: nothing was changed".
- A typo in a subcommand (`komando host lst`) fails with exit 2 and "did you
  mean list?" instead of printing help and exiting 0. Missing or extra
  arguments show the usage line and an example, and `-o text` now applies
  to these errors too.
- A person who answers no at a `[y/N]` prompt sees "cancelled … nothing was
  changed" instead of advice to re-run with `--yes`.
- A protected server or conn stays protected under another spelling of its
  address (upper case, a trailing dot).
- Text output shows server and database content safely: colours stay, but
  other terminal escape sequences (window title, clipboard writes) and
  control characters are shown as `\e` and `\xNN`.
- Many skipped targets print as one line; `KOMANDO_OUTPUT` with a wrong
  value names the variable; negative `-P`, `--timeout`, `--max-output` are
  refused.
- Masking for AI agents no longer hides settings and plain values
  (`max_tokens: 4096`, `password_min_length=12`, URLs, paths, YAML
  structure such as `secretKeyRef: {...}`), and a token never runs into the
  next line.
- cron: IDs are matched exactly (an ID with a dot could delete other
  entries), a newline in COMMAND is refused, schedules are checked here,
  `%` is escaped, crontab read errors are reported instead of shown as an
  empty list, `--user` uses sudo, `cron rm` says how many it removed.
- pkg: package names that start with `-` or hold patterns are refused
  (option injection), removing essential packages (openssh-server, sudo,
  systemd, libc ...) needs `--allow-dangerous`, `pkg installed` returns
  rows with installed true/false, `upgradable --refresh`, dnf/yum
  `upgradable` no longer fails when nothing is pending, and output and the
  audit log show `pkg install tree` instead of a long script.
- user: `user list` works on Debian and Alpine, `user unlock`, `--pubkey` is
  checked, `--shell` applies to existing users.
- net: `net check` fails (exit 5) on a closed port like `nc -z`, accepts
  `[IPv6]:port` and checks the port range; `net http` reports no answer as
  NO_RESPONSE and takes `--expect 200` or `2xx`; `net dns` fails with
  NXDOMAIN (exit 3) when a name does not resolve.
- The agent guard no longer blocks setting komando's variables, quoted
  heredocs, or `|` inside quotes; reading through them still is.
- Servers and files: `fs write`/`replace` follow symlinks and write the
  target (`--no-follow` refuses); `fs mv` never overwrites without
  `--overwrite`; diffs are real unified diffs; `--read-only` is checked
  (a command that writes is READ_ONLY_VIOLATION); remote `~` and `host:`
  mean the home folder like scp; `SRC/` copies the contents and re-runs
  never nest; symlinks that are skipped are listed; sync keeps modes and
  times, refuses a missing source, and never deletes when the source is
  empty; recursive downloads go on past unreadable files and report them;
  `download --sudo`; `script --arg` works for perl, python, ruby and node.
- Text output for people: each failed server shows `[FAILED exit=3]` with
  its own error and hint, stderr stays inside its server's block,
  truncated output says so, streamed output is not printed twice, and a
  `--timeout` that ends a follow (`logs -f`, `cluster logs -f`,
  `cluster run -- get -w`, `cluster forward`) is a normal end. Tables for
  `fs ls`, jobs, recipes, tunnels, keys, secrets, audit, config, db
  activity/locks/sizes, cache info, cluster ls and docker ps.
- Jobs: `job kill` records the kill and is safe to repeat, `job rm` refuses
  a running job (`--kill` first), `job wait --timeout`.
- Inventory: protected entries need `--yes` for any change, an alias of a
  protected server is protected too, hosts are validated when saved (port,
  user, --via, identity file), `host rm @group` / `conn rm 'tmp-*'` take
  selectors, `group rm GROUP` deletes a group, `config get`, `doctor`
  checks the inventory, audit records every inventory and settings change,
  `host ssh-command` prints commands that work through jump hosts, `import`
  vets proxy commands, an empty inventory says how to start, and "did you
  mean" everywhere.
- Policy: `rm -rf //`, `find / -delete`, `chmod -R ... /`, `iptables
  --flush` are caught; `grep mkfs notes` is not; `policy check` exits 6
  when blocked; `policy allow` explains built-in rules.
- Databases, caches, storage: dates and times print as psql/mysql do (no
  invented `Z`, MySQL zero dates kept); MariaDB `explain --analyze`;
  placeholder count checked before sending; `db query --csv/--tsv`; cache
  output reads like redis-cli and `cache info` gives a summary; downloads
  never write in a dry run; a key ending in `/` means into that folder;
  `--to DIR/` and `--to -`; folder markers are skipped; missing databases
  and folders exit 3; `db shell` explains how to install the client on
  this computer.
- Clusters and docker: Swarm output has the same shape as Kubernetes
  (`items`, `healthy`, `problems`); TYPE NAME and TYPE/NAME work in every
  verb; `-A`; rollouts that time out name the stuck pods and why; rollback
  skips the revision that failed; `apply` diffs Secrets without showing
  them and says created/configured/unchanged; `docker exec` passes words as
  given and keeps the exit code; `docker raw`/`compose` can no longer slip
  past the policy with a leading flag; a missing container exits 3.
- System modules and VPNs: hosts without systemd say NO_SYSTEMD, unknown
  units UNIT_NOT_FOUND; `svc restart --wait`; pkg install/rm report what
  changed and PACKAGE_NOT_FOUND; `pkg upgrade --dry-run` lists what would
  change; `net dns --type MX`; `net ports` with process and pid; `vpn
  status` dials SOCKS and system VPNs; `vpn up` checks a WireGuard tunnel
  really answers; `vpn edit`; VPN errors keep their own code through SSH.
- `facts` knows containers (init, virt, IPs without /len).
- `job wait` survives a dropped SSH connection (a NAT or firewall closing
  an idle one): it connects again and keeps waiting until the job ends or
  the timeout passes. Before, a 25-minute install's wait could stop after
  ~10 minutes with the job still running.
- The agent guard no longer mistakes `.../environments` for a process
  environment or a jq filter `.key` for a key file, and reads `\"` the way
  the shell does (fuzzing found a way around it).
- `cluster forward TARGET svc/x :80` picks any free local port, like kubectl.
- `vpn rm` takes several names, like `host rm`; `svc logs` as a user who may
  not read the system journal says to add `--sudo`.
- e2e: WireGuard end to end (a user-space peer), and svc/logs against the
  real systemctl and journalctl on a server with systemd as PID 1.
- e2e: AWS SSM end to end with a stand-in `aws` CLI (login, commands and
  files through `aws ssm start-session`), and an expired SSO login.
- `storage link --endpoint https://PUBLIC-NAME` signs a link for the address
  people use when komando reaches the storage through `--via`.
- `docker logs` shows times only with `--timestamps`, like docker and
  kubectl; a failing command on one server states its error once.
- e2e: every one of the 195 commands now runs at least once
  (`test/e2e/checks/`), and `E2E_HOME` keeps a lab inventory to try
  commands by hand.

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
  actions current, and `make security` runs govulncheck.
  `make fuzz` fuzzes the masking, the policy filter and the guard; fuzzing
  found and fixed a crash on invalid UTF-8 in `fs replace --old`.
- golang.org/x/net 0.62.0 (GO-2026-6860, GO-2026-6866).
- `--proxy-command` runs a program on this computer on every connection, so
  it passes the policy filter, and an AI agent needs a person's yes to set it.

### Project

- Added a code of conduct, Dependabot updates, CODEOWNERS and `.editorconfig`.
  `make lint` now also runs staticcheck.
- Issues use forms (bug report, feature suggestion); security reports go to
  GitHub's private form. Simpler SECURITY.md, CONTRIBUTING.md and pull
  request checklist.
- A release runs every check (lint, unit and end-to-end tests) first, and
  takes its notes from this file.
- Docs are English only: removed `README.id.md` and `docs/features/id/`, and
  translated the design notes in `docs/design/`.

### Cloud access

- `host add|edit --proxy-command CMD` reaches a server through a program on
  this computer, like OpenSSH's ProxyCommand (`%h %p %r %n`): AWS SSM, GCP
  IAP, Cloudflare Access, Teleport. `--ssm` sets the AWS Systems Manager
  command (the address is the instance ID). Conns can use such a host as
  `--via` (RDS behind SSM). `import ssh-config` keeps ProxyCommand; imports
  of export files drop it.
- S3 conns can log in with an AWS CLI profile (`--option aws_profile=NAME`):
  SSO, assumed roles and temporary keys work as configured in the aws CLI.
  An expired SSO login answers `AWS_LOGIN_REQUIRED`.
- Amazon ECR registries get a fresh login from the aws CLI each time
  (logins last 12 hours), with the same `aws_profile` option.

### Day-to-day database care

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

### Bulk transfer

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

### Cluster deploy cycle

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

### Secrets stay out of sight; dry runs show the change

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

### Promises kept

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

### Safer file edits, downloads and tunnels

- `fs write|replace --validate CMD` checks the new file before it goes
  into place (`%s` is its path, e.g. `visudo -cf %s`, `sshd -t -f %s`). If
  the check fails the old file stays (`VALIDATION_FAILED`).
- `fs write --dry-run` shows the change as a diff.
- Downloads from servers never replace a file on this computer
  (`FILE_EXISTS`; `--overwrite` to replace), are written under a temporary
  name first, and refuse server paths that lead outside the destination.
- `tunnel start` asks for `--yes` before listening on anything but
  loopback (`OPEN_BIND`), as docs/design/network.md promised.

### Secrets and risk ratings

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

### Password managers

- `--password-ref` also takes `op://...` (1Password), `vault:PATH#FIELD`
  (HashiCorp Vault), `aws-sm:NAME[#KEY]` (AWS Secrets Manager) and
  `gcp-sm:NAME[@PROJECT]` (Google Secret Manager). komando runs that tool's
  CLI when it needs the value and never stores it.
### Registry copy

- `komando registry copy SRC:IMAGE DST:[IMAGE]` copies an image between
  registries or repositories with every platform, keeping the digest.
  Layers already at the destination are skipped, layers within one registry
  are mounted, credentials never go to another host (e.g. an upload
  redirect), and only the destination is guarded (`--yes` when protected).

### Database shell

- `komando db shell CONN` opens psql, mysql or sqlite3 on this computer,
  connected through the conn's `--via` path, with the password in the
  client's environment. Read-only unless `--write` (PostgreSQL
  default_transaction_read_only, MySQL session READ ONLY, sqlite3
  -readonly); protected conns need `--yes` for `--write`. PostgreSQL keeps
  verifying the certificate's host name through the forward (PGHOSTADDR).
  For people only: without a terminal it refuses with NEEDS_TERMINAL.

### File servers in storage

- `komando storage` also works with FTPS (`ftps://`, TLS on control and data
  connections), SFTP (`sftp://`, for shell-less accounts; host keys checked
  like SSH hosts) and FTP (`ftp://`, refused without `?insecure=1` because
  it sends the password unencrypted). ls, download, upload and rm behave as
  for buckets; uploads go to a temporary name and are renamed into place,
  creating missing folders; keys cannot leave the conn's folder. All of it
  works through `--via` bastions and VPNs.

### Container registries

- `komando registry ls|inspect|rm` for Docker Hub, GHCR, GitLab, Harbor,
  ECR and registry:2 over the OCI Distribution API (basic and token auth),
  through `--via` paths and VPNs. `rm` deletes by digest and needs
  `--allow-dangerous`. `komando import docker` reads
  `~/.docker/config.json`, including credential helpers.

### Clusters

- `komando cluster` for Kubernetes (a k8s conn) and Docker Swarm (a manager
  server) with the same verbs: `status`, `ls`, `get` (Secret values hidden),
  `logs`, `apply` (server-side; `--dry-run` asks the server), `restart`,
  `scale` (to 0 needs `--allow-dangerous`), `rm` (needs `--allow-dangerous`)
  and `run` for any kubectl or docker command (read-only unless `--write`).
  The Kubernetes API is called directly (no client-go), through `--via`
  paths and VPNs; `cluster run` gives kubectl a private kubeconfig and a
  local tunnel. `komando import kubeconfig` adds one conn per context and
  keeps each context's credentials in the vault.

### VPNs

- `komando vpn add NAME wireguard|socks|system`. A VPN goes first in a
  `--via` path (`--via office,bastion`) for servers, conns and tunnels.
  WireGuard runs inside komando for that command only: several VPNs at
  once, overlapping subnets, no admin rights, no change to the computer's
  network. Keys go to the vault. `system` checks an OS VPN is connected
  (`VPN_DOWN` if not). `list`, `test`, targets (`kind:vpn`), groups and
  `export`/`import` include VPNs; a VPN in use cannot be removed.

### One command per job

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

## [0.1.0] - 2026-11-02

First release.

- Server list with groups, tags, labels, jump hosts and `~/.ssh/config` import
- SSH keys and an encrypted password vault
- Run commands and scripts on many servers in parallel; long-running jobs
- Safe file reading and editing, upload and download
- Background tunnels (local, remote, SOCKS)
- Health checks and 39 ready-made recipes; services, logs, Docker, packages, network, users, cron
- Safety: dangerous-command filter, protected servers, dry run, server identity check, audit log
- Readable text in a terminal, JSON for AI agents

[Unreleased]: https://github.com/sgnd/komando/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/sgnd/komando/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/sgnd/komando/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/sgnd/komando/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sgnd/komando/releases/tag/v0.1.0
