# Running commands

Run commands and scripts on one or many servers, start long tasks, and save
commands you use often. [All features](README.md)

## Quick start

```bash
komando exec web1 -- uptime                          # one server
komando exec @web -- 'df -h /'                       # every web server at once
komando exec web1 --dry-run -- 'apt-get -y upgrade'  # show what would run, run nothing
komando script @web ./deploy.sh --arg v1.2.3         # run a local script remotely
komando job start db1 -- 'pg_dump app | gzip > /backup/app.sql.gz'   # a long task
```

## Run a command

Everything after `--` is the command. It runs through the server's login
shell, on all picked servers in parallel (`run` and `x` are other names for
`exec`).

```bash
komando exec web1 -- uptime
komando exec @web -P 20 -- 'df -h / | tail -1'           # up to 20 servers at once
komando exec tag:prod --sudo -- systemctl is-active nginx
komando exec db1 --read-only -- 'psql -c "select 1"'
```

| Option | What it does |
|--------|--------------|
| `-s`, `--sudo` / `--sudo-user NAME` | Run as root, or as another user (uses the server's `--sudo-ref` password if set). |
| `-C`, `--dir PATH` | Run in this folder on the server. |
| `-e`, `--env KEY=VALUE` | Export a variable first (repeatable). |
| `--timeout 10m` | Time limit per server (default 5m). |
| `-P`, `--parallel 20` | How many servers at once (default 10). |
| `--fail-fast` | Start no more servers after the first failure. |
| `--stream` | Print output live, as it comes (NDJSON events). |
| `--stdin-file FILE` | Send a local file as the command's input (`-` = komando's own input). |
| `--pty` | Give the command a terminal (some tools need one). |
| `--read-only` | Say the command only looks (see below). |

### Results and exit codes

Each server gets its own output, errors, exit code and run time. If the
command fails on any server, komando exits 5; if it cannot connect, it
exits 4.

With `-o text`, one server prints like `ssh`: its output, its errors, and a
closing `error: host web1 failed (exit 3)` when it fails. Several servers
get a block each:

```text
=== web1 [ok exit=0]
active
=== web2 [FAILED exit=3]
[stderr] inactive
error [PARTIAL_FAILURE]: 1 of 2 failed: web2 (exit 3)
```

With `--fail-fast`, servers that never started are reported as skipped, not
failed. With `--parallel 1`, servers run one by one, in name order. Output
longer than `--max-output` (256 KiB per stream) is cut, and komando says so.

### Protected servers and `--read-only`

On a protected server, a command needs `--yes`, unless you add
`--read-only` to say it only looks. komando checks that promise: a command
that clearly changes something (`rm`, `mv`, `tee`, `> file`, `sed -i`,
`systemctl restart`, `apt install`, ...) is refused with
`READ_ONLY_VIOLATION`. In that case drop `--read-only` and confirm with
`--yes` instead.

Destructive commands (`rm -rf /`, `mkfs`, `reboot`, `DROP DATABASE`, ...)
are blocked everywhere unless a person allows them. See [Safety](safety.md).

### Pass a password to a command

A password for the remote command can come from the vault, so it is never
typed or shown: `-e DB_PASS=secret:prod-db`. komando fills in the value on
the way to the server.

## Run a local script

`komando script` sends a script file from this computer to the servers and
runs it. Nothing is left on the server's disk.

```bash
komando script @web ./deploy.sh --arg v1.2.3 --sudo
komando script db1 ./backup.py --interpreter python3
```

The interpreter comes from the script's `#!` line, or from `--interpreter`
(otherwise `sh`). `--arg` values reach the script as `$1`, `sys.argv[1]`,
`$ARGV[0]` and so on, for sh, bash, python, perl, ruby and node alike.
`script` takes the same options as `exec`.

## Long tasks (jobs)

Anything slow (backups, upgrades, builds) should run as a *job*. A job keeps
running on the server even if you disconnect, and `job start` returns at
once with a job ID per server.

```bash
komando job start db1 -- 'pg_dump app | gzip > /backup/app.sql.gz'
komando job start @web --sudo -- 'apt-get update && apt-get -y upgrade'
komando job status <id>                 # running, exited or lost; exit code; last lines
komando job logs <id>                   # output so far
komando job wait <id> --timeout 30m     # wait until it ends
komando job kill <id>                   # stop it (TERM; --signal KILL for a hard stop)
komando job list                        # every job; --refresh asks the servers
komando job rm <id>                     # forget it and delete its remote logs
```

Good to know:

- `job logs --offset N` reads only what is new: pass back the `next_offset`
  from the previous call. `--tail N` gives the last lines instead.
- `job wait` waits up to `--timeout` (default 10m). When the time is up, the
  job keeps running and komando exits 7 (`WAIT_TIMEOUT`). Otherwise the exit
  code follows the job's.
- `job kill` on a job that already ended does nothing. A job started with
  `--sudo` needs `job kill --sudo`.
- `job rm` refuses a running job: kill it first, or add `--kill`.
  `--keep-remote` keeps the log folder on the server.
- `job list --target @web` shows only jobs on those servers.

## Recipes (ready-made and saved commands)

A recipe is a saved command. komando comes with 39 ready-made ones
(`health`, `disk`, `cert-expiry`, ...; see [Health](health.md)), and you
can save your own next to them. `ops` and `snippet` are other names for
`recipe`.

```bash
komando recipe list                                   # built-in and saved
komando recipe list --category saved                  # only your own
komando recipe add restart-app 'systemctl restart {{app}}' --sudo
komando recipe add disk-of 'df -h {{path=/}}' --read-only --desc 'Disk use of a path'
komando recipe run restart-app @web --var app=shop
komando recipe run disk-of web1 --var path=/srv
komando recipe rm disk-of
```

- `{{app}}` is a blank you fill in with `--var app=...`. `{{path=/}}` has a
  default.
- komando treats a recipe as a change, so protected servers ask for `--yes`,
  unless you saved it with `--read-only` because it only looks.
- A built-in name (`disk`, `health`, ...) cannot be reused. Replace one of
  your own with `--overwrite`.
- A `--var` the recipe has no blank for is refused (`UNKNOWN_VAR`), so a typo
  never runs the recipe with its default.
- `recipe run --no-sudo` skips sudo even when the recipe asks for it.

## Interactive shell (for people)

```bash
komando shell web1             # also: komando ssh web1, komando connect web1
komando shell prod-web1        # protected: asks [y/N] first (--yes skips the question)
komando shell web1 --dry-run   # shows the host, address, user and --via path; connects nothing
```

`shell` logs you in to the server, through its `--via` path (VPN and
bastions) when it has one. One line says where you are going, and one more
says how it ended:

```text
komando: shell on prod-web1 (root@10.0.0.5) via vpn office → bastion1 · PROTECTED
...
komando: left prod-web1 (exit 0, 12m)
```

Inside a shell you can type anything, so on a protected server komando asks
first, as `db shell` does on a protected conn. A shell needs a person at a
terminal: agents and scripts get `NEEDS_TERMINAL` and use `exec` or `job`
instead.
