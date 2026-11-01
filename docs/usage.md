# Using komando

A task-by-task guide. New here? Start with the [README](../README.md).

- [Add servers](#add-servers)
- [Log in without typing passwords](#log-in-without-typing-passwords)
- [Pick which servers to use](#pick-which-servers-to-use)
- [Run commands](#run-commands)
- [Check server health](#check-server-health)
- [Read and edit files](#read-and-edit-files)
- [Copy files](#copy-files)
- [Long tasks](#long-tasks)
- [Services, logs, Docker, packages](#services-logs-docker-packages)
- [Reach private servers (tunnels)](#reach-private-servers-tunnels)
- [Databases (conns)](#databases-conns)
- [Query a database](#query-a-database)
- [Network checks](#network-checks)
- [Users and scheduled jobs](#users-and-scheduled-jobs)
- [Saved commands (snippets)](#saved-commands-snippets)
- [Safety](#safety)
- [Reading the results](#reading-the-results)
- [Troubleshooting](#troubleshooting)
- [Settings and files](#settings-and-files)
- [Glossary](#glossary)

---

## Add servers

```bash
komando host add web1 ubuntu@203.0.113.10                 # name + user@address
komando host add web2 ubuntu@203.0.113.11 --group web --tag prod
komando host add db1 admin@10.0.0.5 --jump bastion         # reached through "bastion"
komando host import --ssh-config ~/.ssh/config             # import what you already have
komando host list                                          # see them all
komando host test all                                      # can we log in everywhere?
```

Change or remove later:

```bash
komando host edit web1 --add-tag canary --port 2222
komando host edit web1 --protected        # production: changes need --yes
komando host rm web2
```

## Log in without typing passwords

If you can already log in with `ssh` on this computer, komando usually just
works: it uses the same keys (files like `~/.ssh/id_ed25519`, and the
ssh-agent program that holds unlocked keys). Otherwise it uses a stored password.

**Store a password safely.** You type it, nothing is shown, it is saved encrypted:

```bash
komando secret set web1-pass
komando host edit web1 --password-ref secret:web1-pass
```

**Better: use a key.** Create one and install it on your servers:

```bash
komando key gen deploy
komando key deploy deploy @web --set-default
```

**sudo needs a password?**

```bash
komando secret set web1-sudo
komando host edit web1 --sudo-ref secret:web1-sudo
```

References can also point to an environment variable (`env:MY_VAR`) or a
file (`file:/path`).

## Pick which servers to use

Most commands take a *target*:

| Write | Meaning |
|-------|---------|
| `web1` | one server |
| `web-*` | names starting with `web-` |
| `@web` | everyone in group `web` |
| `tag:prod` | everyone tagged `prod` |
| `label:dc=jkt` | everyone with label `dc=jkt` |
| `all` | every server |
| `@web,!web3` | combine with `,` and leave out with `!` |
| `root@1.2.3.4:22` | a one-off server not in your list |

Groups, tags and labels are set when adding or editing a server:
`komando host edit web1 --add-group web --add-tag prod --label dc=jkt`.

Preview what a target matches: `komando host list --target '@web,!web3'`.

## Run commands

```bash
komando exec web1 -- uptime
komando exec @web -- 'df -h /'                    # all web servers at once
komando exec @web --sudo -- systemctl is-active nginx
komando exec web1 --dry-run -- 'apt-get -y upgrade'  # show, don't run
komando script @web ./deploy.sh --arg v1.2.3     # run a local script remotely
```

Useful options: `--timeout 10m`, `--parallel 20`, `--fail-fast`,
`-e KEY=VALUE`, `-C /some/dir`, `--stream` (live output).

## Check server health

```bash
komando facts web1               # OS, CPU, memory, disk, IPs, installed tools
komando ops list                 # 39 ready-made checks
komando ops run health @web
komando ops run disk all
komando ops run top-mem web1
komando ops run cert-expiry web1 --param name=example.com
komando ops run updates all
```

## Read and edit files

```bash
komando fs cat web1 /etc/nginx/nginx.conf --tail 50
komando fs ls web1 /var/www
komando fs stat web1 /etc/hosts --sha256
```

Edit one piece of text safely. It only changes the file if the old text is
found **exactly once**, and `--backup` keeps the previous version:

```bash
komando fs replace web1 /etc/nginx/nginx.conf \
  --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup
```

Write a whole file (atomic; `--if-changed` skips identical content):

```bash
komando fs write web1 /etc/app/.env --from ./app.env --sudo --mode 0640 --if-changed
```

Also: `fs mkdir`, `fs mv`, `fs chmod`, `fs rm`.

## Copy files

Remote paths are written `TARGET:PATH`.

```bash
komando cp ./release.tar.gz @web:/tmp/            # upload to many servers
komando cp -r ./site web1:/var/www/site
komando cp web1:/var/log/nginx/error.log ./logs/  # download
komando cp @web:/etc/nginx/nginx.conf ./configs/  # → ./configs/<server>/nginx.conf
```

## Long tasks

Anything slow (backups, upgrades, builds) runs as a *job* that keeps going
on the server even if you disconnect:

```bash
komando job start db1 -- 'pg_dump app | gzip > /backup/app.sql.gz'
komando job status <id>
komando job logs <id>
komando job wait <id>
komando job kill <id>
komando job list
```

## Services, logs, Docker, packages

```bash
komando svc status @web nginx
komando svc restart web1 nginx
komando svc list web1 --failed

komando logs web1 --unit nginx --since -30m --grep 'error|crit'
komando logs web1 --file /var/log/syslog -n 100 --sudo

komando docker ps web1
komando docker logs web1 api --since 10m
komando docker compose web1 --dir /srv/shop -- up -d

komando pkg install @web htop
komando pkg upgradable all
```

`pkg` works with apt, dnf, yum, apk, zypper and pacman automatically.

## Reach private servers (tunnels)

A tunnel makes a service on a server appear on your own computer. Tunnels
run in the background until you stop them.

`-L 15432:localhost:5432` means: "port 15432 on *my* computer leads to port
5432 (PostgreSQL) on the server". Then point your database app at
`localhost:15432`.

```bash
komando tunnel start db1 -L 15432:localhost:5432
komando tunnel start bastion -D 1080   # a SOCKS proxy: set your browser to localhost:1080 to browse "from" the server
komando tunnel list
komando tunnel stop --all
```

## Databases (conns)

A **conn** is a database, cache or storage bucket komando knows about, the
way a host is a server you know about. The kind comes from the start of the
URL:

| Kind       | URL example |
|------------|-------------|
| PostgreSQL | `postgres://app@10.0.0.5:5432/app?sslmode=require` |
| MySQL / MariaDB | `mysql://shop@db.internal:3306/shop?tls=true` |
| SQLite     | `sqlite:///var/lib/app.db` (a file on this computer) |
| Redis / Valkey | `redis://default@cache.internal:6379/0` (`rediss://` for TLS) |
| S3 and compatible (MinIO, R2, Wasabi, ...) | `s3://ACCESS_KEY_ID@my-bucket/backups?endpoint=https://minio.internal:9000&region=us-east-1` |

For S3 the user part is the access key ID; the secret key goes in the vault
like a password (`--password-ref secret:NAME`). Leave out `endpoint` for AWS.

Run `komando conn kinds` to see them all.

Never put the password in the URL; komando refuses it. Store it in the vault
instead:

```bash
komando secret set prod-db-pass
komando conn add prod-db postgres://app@10.0.0.5:5432/app \
  --via web1 --password-ref secret:prod-db-pass --protected
```

`--via web1` means "the database is only reachable from web1". komando
connects through web1 over SSH by itself: no tunnel to start, no port opened
on your computer.

```bash
komando conn list                     # all conns
komando conn test all                 # reachable? does the password reference work?
komando conn edit prod-db --add-tag critical
komando conn rm old-db                # only forgets it; the database is untouched
```

Conns use the same selectors as hosts (`@group`, `tag:prod`, `*-db`, `all`)
and share their names: a host and a conn cannot both be called `db1`. A host
that a conn uses with `--via` cannot be removed until the conn is changed.

## Query a database

`komando db` runs SQL on a conn. **It cannot change anything unless you add
`--write`**: without it, the query runs in a read-only transaction and the
database itself refuses changes.

```bash
komando db schema prod-db                     # what tables are there?
komando db schema prod-db users               # columns, types, indexes of one table
komando db query prod-db "select id, email from users order by id desc limit 10"
komando db explain prod-db "select * from orders where user_id = 42"
```

Use `--arg` for values instead of pasting them into the SQL (`$1`, `$2` in
PostgreSQL; `?` in MySQL and SQLite):

```bash
komando db query prod-db "select * from users where email = $1" --arg bob@example.com
```

**Changing data** takes two steps. First a dry run: the SQL really runs, you
see how many rows it touches, then everything is rolled back.

```bash
komando db query prod-db --write --dry-run "update users set plan = 'pro' where id = 42"
komando db query prod-db --write "update users set plan = 'pro' where id = 42"
```

Seatbelts:

- A protected conn also needs `--yes` for `--write`.
- Destructive SQL needs `--allow-dangerous`: `DROP`, `TRUNCATE`, `DELETE` or
  `UPDATE` without `WHERE`, privilege changes, and a few more
  (`komando policy list` shows them; `komando policy check --sql postgres "..."`
  tests a query).
- `BEGIN`/`COMMIT` are refused: komando runs everything in one transaction.
- A few statements cannot be rolled back (`VACUUM`, `CREATE INDEX
  CONCURRENTLY`, MySQL DDL). They must be sent alone, and a dry run only
  reports them.
- Queries stop after 30 seconds (`--timeout 2m` for more) and return at most
  500 rows (`--limit`).

SQL from a file: `komando db query prod-db --file report.sql` (`--file -`
reads stdin).

### Backups

```bash
komando db dump prod-db --to prod-2026-11-02.sql.gz      # backup to a file on this computer
komando db restore staging-db --from prod-2026-11-02.sql.gz --write --allow-dangerous
```

- The backup file always lands on **this computer**, readable only by you.
  An existing file is never overwritten.
- komando uses the database's own tools: `pg_dump`/`psql` (package
  `postgresql-client`) or `mysqldump`/`mysql` (`mysql-client`). They run on
  the conn's `--via` server when it has one, otherwise here. If they are
  missing, the error tells you what to install
  (`komando pkg install web1 postgresql-client`).
- The password goes to the tool through its environment, never on its
  command line, so other users of the server cannot see it.
- A restore can overwrite data, so it needs `--write` and `--allow-dangerous`
  (and `--yes` on a protected conn). PostgreSQL restores run in one
  transaction: if anything fails, nothing changes.
- SQLite: `dump` copies the database file (`--to backup.db`). To restore,
  stop the app and copy the file back.
- Big databases take time: there is no timeout unless you pass `--timeout`.

## Network checks

Run *from* your servers:

```bash
komando net check @web db.internal:5432 redis.internal:6379
komando net http web1 https://example.com
komando net ports web1 --sudo
komando net dns web1 api.example.com
```

## Users and scheduled jobs

```bash
komando user list web1
komando user add @web deploy --key deploy --admin
komando cron set db1 nightly-backup '/usr/local/bin/backup.sh' --schedule '0 2 * * *'
komando cron list db1
komando cron rm db1 nightly-backup
```

## Saved commands (snippets)

Save a command once and reuse it. `{{app}}` is a blank you fill in with
`--var app=...`. `--mutating` marks it as one that changes things, so
protected servers will ask for `--yes`.

```bash
komando snippet add restart-app 'systemctl restart {{app}}' --sudo --mutating
komando snippet run restart-app @web --var app=shop
```

## Safety

| Seatbelt | What it does |
|----------|--------------|
| Dangerous-command filter | Blocks `rm -rf /`, `mkfs`, `reboot`, `DROP DATABASE`, `curl … \| sh` *on your servers*, firewall flush, stopping SSH and more. See `komando policy list`. |
| Protected servers | Changes need `--yes`. Commands that only look (not change) can say so with `--read-only` and run without `--yes`. |
| Dry run | `--dry-run` shows what would run and whether it would be blocked. |
| Safe edits | Atomic writes, exact-match replace, optional `.bak` backups. |
| Encrypted vault | Passwords are AES-256-GCM encrypted. Only names are ever shown. |
| Server identity | A changed server fingerprint stops the connection (`HOSTKEY_MISMATCH`). |
| History | Every action is in `komando audit`. |

Overriding a block needs `--allow-dangerous` — a human decision.
Add your own rules with `komando policy deny 'REGEX'`.

> The filter catches common accidents; it is not a complete security
> boundary. Give automation an SSH user with only the permissions it needs.

## Reading the results

In a terminal you get readable text. When another program (like an AI agent)
runs komando, it gets one JSON object instead. Force either with `-o text` or
`-o json`.

```json
{
  "ok": false,
  "command": "exec",
  "data": { "results": [ { "host": "web1", "ok": false, "exit_code": 3, "stdout": "", "stderr": "…" } ] },
  "error": { "code": "FAILED", "message": "host web1 failed", "hint": "…" },
  "meta": { "version": "0.1.0", "duration_ms": 211 }
}
```

`error.hint` always says what to try next.

| Exit code | Meaning |
|-----------|---------|
| 0 | success |
| 1 | general error |
| 2 | wrong command or flag |
| 3 | not found (server, file, key…) |
| 4 | cannot connect or log in |
| 5 | the command failed on the server |
| 6 | blocked for safety |
| 7 | timed out |
| 8 | edit precondition failed (text not found / not unique) |

The full machine-readable reference is `komando schema`.

## Troubleshooting

| Error | Usually means | Try |
|-------|---------------|-----|
| `AUTH_FAILED` | wrong user, key or password | `komando host show NAME`, `komando key deploy` |
| `CONNECTION_REFUSED` / `CONNECT_TIMEOUT` | server down, wrong port, firewall | check address and port, `--connect-timeout 30s` |
| `HOSTKEY_MISMATCH` | server rebuilt — or someone intercepting | confirm with your provider, then `komando host trust NAME --reset` |
| `SECRET_UNRESOLVED` | stored password or env var missing | `komando secret list` |
| `sudo: a password is required` | sudo needs a password | `komando host edit NAME --sudo-ref secret:NAME` |
| `POLICY_BLOCKED` | looks destructive | double-check; a human may add `--allow-dangerous` |
| `TIMEOUT` | took too long | `--timeout 30m` or use `komando job start` |

`komando doctor` checks your local setup.

## Settings and files

```bash
komando config show
komando config set parallel 20
komando config set default_timeout 10m
komando config set host_key_policy strict    # accept-new (default) | strict | off
komando config set audit_sql hash            # full (default) | hash | off: keep SQL text out of the history
```

Everything is stored in `~/.komando/` (change with `KOMANDO_HOME`):

| File | Contains |
|------|----------|
| `state.json` | servers, conns, keys, settings |
| `vault.json`, `vault.key` | encrypted secrets and their key |
| `keys/` | SSH keys made by `komando key gen` |
| `known_hosts` | remembered server fingerprints |
| `audit.jsonl` | history of every action |

Back this folder up and keep it private. Set `KOMANDO_VAULT_PASS` before
the first secret if you prefer a passphrase over the `vault.key` file.

## Glossary

| Word | Meaning |
|------|---------|
| Server | A computer (often in the cloud) that runs your apps. |
| SSH | The secure way to log in to and control a Linux server remotely. |
| CLI | Command-line interface: typing commands instead of clicking. |
| AI agent | An AI that runs tools by itself to finish a task. |
| SSH key | A pair of files that proves who you are; safer than a password. |
| Vault / secret | Encrypted storage for passwords. |
| sudo | Running a command as the administrator (root). |
| Jump host / bastion | A gateway server used to reach private servers. |
| Tunnel | Makes a remote service (like a database) appear on your computer. |
| Fingerprint | A server's ID card; an unexpected change is a warning sign. |
| Service | A background program like nginx or a database, managed by systemd. |
| Job | A long task left running on the server. |
| Exit code | A program's result number: 0 = success, anything else = problem. |
| JSON | Structured text that programs read easily. |
