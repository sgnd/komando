# komando — playbook for AI agents

You manage real servers, databases, caches and storage. Be precise, observe before you act, and prefer the
smallest change that works. When its output is piped (as when you run it),
every komando command prints exactly one JSON object on stdout; pass `-o json`
to be explicit. Branch on `ok`, `error.code` and the process exit code. `meta.contract` (now 1)
only changes when a field or code is renamed or removed; new ones may appear.

## 1. Orient yourself

```bash
komando list                          # servers and conns: name, kind, where, groups, protected
komando group list                    # groups/tags -> members (servers and conns)
komando test all                      # what is reachable; which user, passwordless sudo?
komando import ssh-config --dry-run   # (with the human) bring in existing servers and databases
komando facts <target>                # OS, package manager, tools, CPU/mem/disk, load
komando schema --compact              # every command (use `komando schema <cmd>` for flags)
```

Run `facts` before your first change on an unfamiliar host: it tells you
whether to use apt or dnf, whether systemd/docker exist, and how full the disk is.

## 2. Targets

`web1` · `web-*` · `@group` · `tag:prod` · `label:dc=jkt` · `kind:host|db|cache|storage|postgres|...` ·
`all` · `user@1.2.3.4:22` (ad-hoc server) · combine with commas, exclude with `!`:
`@web,!web-3`. A target picks servers and conns together. Each command uses
what it can work with and lists the rest in `meta.skipped`; if nothing fits,
`NO_MATCHING_TARGETS` says which command to use. Check what a target picks
with `komando list '<expr>'`.

VPNs: `komando list kind:vpn`. A target behind a VPN has it first in its
`--via`; komando connects it by itself. `VPN_DOWN` means a VPN the computer
runs itself is not connected: ask the human to connect it.

## 3. Read before you write

| Need                         | Command |
|------------------------------|---------|
| Quick health                 | `komando recipe run health <t>` |
| Any read-only shell command  | `komando exec <t> --read-only -- '<cmd>'` |
| Logs                         | `komando logs <t> --unit nginx --since -30m --grep 'error'` |
| Service state (structured)   | `komando svc status <t> nginx` |
| File content                 | `komando fs cat <t> /etc/nginx/nginx.conf --line-numbers` |
| Ports / connectivity         | `komando net ports <t>` · `komando net check <t> db:5432` |
| Containers                   | `komando docker ps <t>` · `komando logs <t> --container api --since 10m` |
| More diagnostics             | `komando recipe list` then `komando recipe run <name> <t>` |

## 4. Change things safely

1. Preview: add `--dry-run` to see the exact remote command and whether it would be blocked.
2. Edit config with `fs replace` (exact match, fails on 0 or >1 matches) and `--backup`:
   `komando fs replace web1 /etc/nginx/nginx.conf --old '...' --new '...' --sudo --backup`
3. Validate before reload: `komando recipe run nginx-test web1` (or `sshd -t`, `apachectl configtest`).
4. Apply: `komando svc reload web1 nginx` → re-check `svc status`.
5. Roll back from `PATH.bak` if validation fails.
6. Roll out to fleets gradually: one host first, then `--parallel` small batches, `--fail-fast`.

Writes are atomic (temp file + rename). `fs write --if-changed` and `cron set`
are idempotent, so retries are safe.

## 5. Databases

```bash
komando list kind:conn                                   # known databases
komando db schema <conn> [table...]                 # tables, then columns/indexes
komando db query <conn> "select ..."                # read-only transaction: data cannot change
komando db query <conn> "... where id = $1" --arg 42   # values as arguments, not pasted
komando db query <conn> --write --dry-run "update ..."  # runs, reports rows_affected, rolls back
komando db query <conn> --write "update ..."            # commits
```

Caches work the same way: `komando cache get|keys|info <conn>` read,
`cache set` changes, `cache rm` deletes (needs `--allow-dangerous`), and
`komando cache run <conn> -- CMD ...` only reads unless `--write`. Never use
`KEYS` (use `cache keys`, it SCANs).

Buckets: `komando storage ls <conn>` and `komando download <conn> KEY` read, `komando upload <conn> FILE` and `storage link`
change or share, `storage rm` deletes (needs `--allow-dangerous`). Keys are
relative to the conn's folder.

`--dry-run` never changes anything. In `db` it runs the SQL inside a
transaction and rolls it back (sequences still advance); in `cache` and
`storage` nothing is sent.

Without `--write` the database itself refuses changes. `WRITE_REQUIRES_FLAG`
(exit 6) means the SQL writes: dry-run it, then ask the human before
`--write` on anything that matters. Never `BEGIN`/`COMMIT` yourself. Do not
run `psql`/`mysql` through `exec`: you lose the read-only guarantee,
structured rows, and the password leaks into the server's process list.

Clusters: `komando cluster status|ls|get|logs <conn>` read; `apply` (try
`--dry-run`, the server checks it), `restart` and `scale` change; `rm` and
scaling to 0 need `--allow-dangerous`. `komando cluster run <conn> -- <kubectl
args>` for anything else (needs `--write` to change). Namespaces are
`--namespace`.

## 6. Long-running work

Anything that may exceed ~2 minutes (upgrades, backups, builds, migrations):

```bash
komando job start db1 -- 'pg_dump app | gzip > /backup/app.sql.gz'   # returns job id at once
komando job logs <id> --offset <next_offset>     # read only new output
komando job wait <id> --wait-timeout 10m         # blocks; exit code mirrors the job
```

## 7. Guardrails (do not fight them)

- `POLICY_BLOCKED` (exit 6): the command looks destructive (rm -rf /, mkfs, reboot,
  DROP DATABASE, curl|sh, firewall flush, stopping sshd ...). Stop and ask the human.
  Only re-run with `--allow-dangerous` after explicit human approval.
- `PROTECTED_HOST` / `PROTECTED_TARGET` (exit 6): host or conn is marked production. Get confirmation, then `--yes`.
  Read-only work needs no confirmation: declare it with `--read-only`. Removing,
  replacing or unprotecting a protected target also needs confirmation.
- `SAFETY_SETTING` (exit 6): the change turns a seatbelt off (audit log, host
  key checks, a deny rule). Ask the human; never do it to get around a block.
- Snippets count as changes unless saved with `--read-only`.
- Never put a secret value in a command line: `komando secret set NAME` reads it
  from `--from-env VAR` or stdin.
- `HOSTKEY_MISMATCH` (exit 4): possible man-in-the-middle. Never auto-fix; report to the human.
- Never print secrets. Credentials are references (`secret:NAME`, `env:VAR`), not values.
- Everything is recorded in `komando audit`. Set `KOMANDO_ACTOR=<your-name>`.

## 8. Error codes → what to do

| exit | code examples                     | action |
|------|-----------------------------------|--------|
| 2    | USAGE                             | fix flags; see `komando schema <cmd>` |
| 3    | TARGET_NOT_FOUND, TARGET_EMPTY, PATH_NOT_FOUND | `komando list`; the hint suggests the closest name |
| 3    | NO_MATCHING_TARGETS               | use the command the hint names (e.g. `db` for a database) |
| 4    | AUTH_FAILED, CONNECTION_REFUSED, HOSTKEY_* | follow `error.hint`; do not retry blindly |
| 5    | FAILED / PARTIAL_FAILURE          | read `data.results[].stderr` and `exit_code` per host |
| 5    | DB_ERROR                          | fix the SQL; check `db schema` |
| 6    | POLICY_BLOCKED, PROTECTED_HOST/TARGET, SAFETY_SETTING, WRITE_REQUIRES_FLAG | ask the human |
| 7    | TIMEOUT, CONNECT_TIMEOUT          | raise `--timeout` or use `job start` |
| 8    | NO_MATCH, AMBIGUOUS_MATCH         | re-read the file, use exact unique `--old` text |

Every error carries `error.hint` with the next step. Read it.

## 9. Output size

Per-stream output is capped (default 256 KiB, `--max-output`); truncation is
flagged with `stdout_truncated`. Prefer filtering on the server (`--grep`,
`-n`, `| head`, `| tail`) over pulling large outputs.
