# komando — playbook for AI agents

You manage real servers. Be precise, observe before you act, and prefer the
smallest change that works. When its output is piped (as when you run it),
every komando command prints exactly one JSON object on stdout; pass `-o json`
to be explicit. Branch on `ok`, `error.code` and the process exit code.

## 1. Orient yourself

```bash
komando host list                     # what servers exist (names, groups, tags, protected)
komando group list                    # groups/tags -> member hosts
komando host test all                 # who is reachable, which user, passwordless sudo?
komando facts <target>                # OS, package manager, tools, CPU/mem/disk, load
komando schema --compact              # every command (use `komando schema <cmd>` for flags)
```

Run `facts` before your first change on an unfamiliar host: it tells you
whether to use apt or dnf, whether systemd/docker exist, and how full the disk is.

## 2. Targets

`web1` · `web-*` · `@group` · `tag:prod` · `label:dc=jkt` · `all` ·
`user@1.2.3.4:22` (ad-hoc) · combine with commas, exclude with `!`:
`@web,!web-3`. Check what a selector matches with `komando host list --target '<expr>'`.

## 3. Read before you write

| Need                         | Command |
|------------------------------|---------|
| Quick health                 | `komando ops run health <t>` |
| Any read-only shell command  | `komando exec <t> --read-only -- '<cmd>'` |
| Logs                         | `komando logs <t> --unit nginx --since -30m --grep 'error'` |
| Service state (structured)   | `komando svc status <t> nginx` |
| File content                 | `komando fs cat <t> /etc/nginx/nginx.conf -n` |
| Ports / connectivity         | `komando net ports <t>` · `komando net check <t> db:5432` |
| Containers                   | `komando docker ps <t>` · `komando docker logs <t> api --since 10m` |
| More diagnostics             | `komando ops list` then `komando ops run <recipe> <t>` |

## 4. Change things safely

1. Preview: add `--dry-run` to see the exact remote command and whether it would be blocked.
2. Edit config with `fs replace` (exact match, fails on 0 or >1 matches) and `--backup`:
   `komando fs replace web1 /etc/nginx/nginx.conf --old '...' --new '...' --sudo --backup`
3. Validate before reload: `komando ops run nginx-test web1` (or `sshd -t`, `apachectl configtest`).
4. Apply: `komando svc reload web1 nginx` → re-check `svc status`.
5. Roll back from `PATH.bak` if validation fails.
6. Roll out to fleets gradually: one host first, then `--parallel` small batches, `--fail-fast`.

Writes are atomic (temp file + rename). `fs write --if-changed` and `cron set`
are idempotent, so retries are safe.

## 5. Long-running work

Anything that may exceed ~2 minutes (upgrades, backups, builds, migrations):

```bash
komando job start db1 -- 'pg_dump app | gzip > /backup/app.sql.gz'   # returns job id at once
komando job logs <id> --offset <next_offset>     # read only new output
komando job wait <id> --wait-timeout 10m         # blocks; exit code mirrors the job
```

## 6. Guardrails (do not fight them)

- `POLICY_BLOCKED` (exit 6): the command looks destructive (rm -rf /, mkfs, reboot,
  DROP DATABASE, curl|sh, firewall flush, stopping sshd ...). Stop and ask the human.
  Only re-run with `--allow-dangerous` after explicit human approval.
- `PROTECTED_HOST` (exit 6): host is marked production. Get confirmation, then `--yes`.
  Read-only work needs no confirmation: declare it with `--read-only`.
- `HOSTKEY_MISMATCH` (exit 4): possible man-in-the-middle. Never auto-fix; report to the human.
- Never print secrets. Credentials are references (`secret:NAME`, `env:VAR`), not values.
- Everything is recorded in `komando audit`. Set `KOMANDO_ACTOR=<your-name>`.

## 7. Error codes → what to do

| exit | code examples                     | action |
|------|-----------------------------------|--------|
| 2    | USAGE                             | fix flags; see `komando schema <cmd>` |
| 3    | HOST_NOT_FOUND, TARGET_EMPTY, PATH_NOT_FOUND | list inventory / check path |
| 4    | AUTH_FAILED, CONNECTION_REFUSED, HOSTKEY_* | follow `error.hint`; do not retry blindly |
| 5    | FAILED / PARTIAL_FAILURE          | read `data.results[].stderr` and `exit_code` per host |
| 6    | POLICY_BLOCKED, PROTECTED_HOST    | ask the human |
| 7    | TIMEOUT, CONNECT_TIMEOUT          | raise `--timeout` or use `job start` |
| 8    | NO_MATCH, AMBIGUOUS_MATCH         | re-read the file, use exact unique `--old` text |

Every error carries `error.hint` with the next step. Read it.

## 8. Output size

Per-stream output is capped (default 256 KiB, `--max-output`); truncation is
flagged with `stdout_truncated`. Prefer filtering on the server (`--grep`,
`-n`, `| head`, `| tail`) over pulling large outputs.
