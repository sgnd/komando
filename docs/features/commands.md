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

| Flag | What it does |
|------|--------------|
| `-c`, `--cmd 'COMMAND'` | Give the command as one string instead of after `--`. |
| `-s`, `--sudo` / `--sudo-user NAME` | Run as root, or as another user (uses the server's `--sudo-ref` password if set). |
| `-C`, `--dir PATH` | Run in this folder on the server. |
| `-e`, `--env KEY=VALUE` | Export a variable first (repeatable). |
| `--timeout 10m` | Time limit per server (default 5m). |
| `-P`, `--parallel 20` | How many servers at once (default 10). |
| `--fail-fast` | Start no more servers after the first failure. |
| `--stream` | Print output live, as it comes, a whole line at a time (in JSON: one event per line). |
| `--stdin-file FILE` | Send a local file as the command's input (`-` = komando's own input). |
| `--pty` | Give the command a terminal (some tools need one). |
| `--read-only` | Say the command only looks (see below). |

### Results and exit codes

Each server gets its own output, errors, exit code and run time. If the
command fails on any server, komando exits 5; if it cannot connect, it
exits 4.

With `-o text`, one server prints like `ssh`: its output, its errors, and a
closing `error [FAILED]: host web1 failed (exit 3)` when it fails. Several servers
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

### When the connection drops

Sometimes the link to a server breaks while a command is running: the VPN
drops, the Wi-Fi changes, a firewall cuts the connection. komando then
cannot know how the command ended. That server's result says so:

- error code `CONNECTION_LOST`, exit code 4 (other servers keep their own
  results; the worst exit code wins, as usual);
- the output that arrived before the break, with `exit_code` -1 (unknown);
- in text mode: `=== web2 [FAILED connection lost, outcome unknown]`.

The command may **still be running** on the server, or it may **already
have finished**. Do not simply run it again (an upgrade or a migration
twice can hurt). First look, with a read-only command: its log file, `ps`,
or the change it should have made:

```bash
komando exec web2 --read-only -- 'tail -20 /var/log/unattended-upgrades/unattended-upgrades.log'
komando exec web2 --read-only -- 'ps -ef | grep -v grep | grep apt'
```

If the server simply stops answering (a VPN that went away without a word),
komando notices within about a minute instead of waiting for `--timeout`.

This is different from:

| What happened | Error code | Exit |
|---------------|-----------|------|
| could not connect at all (the command never started) | `CONNECT_FAILED`, `CONNECTION_REFUSED`, `AUTH_FAILED`, ... | 4 |
| the link broke before the command started (it did not run) | `CONNECTION_LOST`, message says "it did not run" | 4 |
| the link broke while the command ran (outcome unknown) | `CONNECTION_LOST` | 4 |
| the command ran and failed | `FAILED` (per server: its `exit_code`) | 5 |
| the command ran longer than `--timeout` (komando stopped it) | `TIMEOUT` | 7 |

For long tasks, or any task over a shaky link, use a [job](#long-tasks-jobs)
instead: it keeps running on the server, keeps its output and exit code
there, and `job wait` connects again by itself after a drop.

### Protected servers and `--read-only`

On a protected server, a command needs `--yes`, unless you add
`--read-only` to say it only looks. komando checks that promise: a command
that clearly changes something (`rm`, `mv`, `tee`, `> file`, `sed -i`,
`systemctl restart`, `apt install`, ...) is refused with
`READ_ONLY_VIOLATION`. In that case drop `--read-only` and confirm with
`--yes` instead.

A command komando cannot follow is refused the same way: `eval`, `source`,
a command name in a variable (`$X file`), a shell or python reading a
script it cannot see (`... | sh`, `python3 -c`). Text after `sh -c` or
`bash -lc` is checked like the command. With `--stdin-file`, the input is
checked too, so `--read-only --stdin-file check.sh -- 'bash -s'` works when
the script only looks. `script --read-only` needs a shell as the
interpreter (`sh`, `bash -eu`). Script arguments (`--arg`, or words after
`bash -s --`) are refused under `--read-only`: put the values in the
script. An argument the check cannot see (`find /data $X`) is refused for
commands whose arguments decide what they do (`find`, `sed`, `git`,
`kubectl` ...); `-e` values are filled in first. Other input (a CSV for
`wc`, SQL for `psql`) is data and is not read as commands, except that
`psql` and `mysql` input may not use `\!`, `\o`, `system` or `tee`.

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
`script` takes the same flags as `exec` (except `-c`), plus `--arg` and
`--interpreter`.

## Long tasks (jobs)

Anything slow (backups, upgrades, builds) should run as a *job*. A job keeps
running on the server even if you disconnect, and `job start` returns at
once with a job ID per server.

```bash
komando job start db1 -- 'pg_dump app | gzip > /backup/app.sql.gz'
komando job start @web --sudo -- 'apt-get update && apt-get -y upgrade'
komando job status JOB_ID               # running, exited or lost; exit code; last lines
komando job logs JOB_ID                 # output so far
komando job wait JOB_ID --timeout 30m   # wait until it ends
komando job wait JOB_ID1 JOB_ID2        # wait for several (one per server)
komando job kill JOB_ID                 # stop it (TERM; --signal KILL for a hard stop)
komando job list                        # every job; --refresh asks the servers
komando job rm JOB_ID                   # forget it and delete its remote logs
```

Good to know:

- `job logs --offset N` reads only what is new: pass back the `next_offset`
  from the previous call. `--tail N` gives the last lines instead.
- `job wait` waits up to `--timeout` (default 10m). When the time is up, the
  job keeps running and komando exits 7 (`WAIT_TIMEOUT`). Otherwise the exit
  code follows the job's. If the connection drops while it waits, it
  connects again and keeps waiting.
- `job wait` with several IDs waits for all of them and gives one result per
  job (`data.jobs`) and a summary; the exit code is the worst one.
- `job start --sudo` uses the server's `--sudo-ref` password when it has
  one. The password is sent as input (never on a command line), waits in a
  private file only the job's user can read, and the job deletes it the
  moment it starts. The command itself gets no input, so it cannot read it.
- `job kill` on a job that already ended does nothing. A job started with
  `--sudo` needs `job kill --sudo`.
- `job rm` refuses a running job: kill it first, or add `--kill`.
  `--keep-remote` keeps the log folder on the server.
- `job list --target @web` shows only jobs on those servers.

## Recipes (ready-made and saved commands)

A recipe is a saved command. komando comes with 36 ready-made ones
(`health`, `disk`, `updates`, ...; see [Health](health.md)), and you
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
  unless you saved it with `--read-only` because it only looks. A read-only
  recipe is checked like `exec --read-only` when you save it. If, with its
  blanks filled in, it no longer passes that check, it runs as a change.
- A `--var` value may not start with `-`, because a program would read it
  as an option (`OPTION_LIKE_VAR`). Write a path like that as `./-name`. A
  number or a relative time (`-5`, `-2h`) is fine.
- A built-in name (`disk`, `health`, ...) cannot be reused. Replace one of
  your own with `--overwrite`.
- A `--var` the recipe has no blank for is refused (`UNKNOWN_VAR`), so a typo
  never runs the recipe with its default.
- `recipe run --no-sudo` skips sudo even when the recipe asks for it.

## The menu (for people)

Type `komando` alone in a terminal and a menu opens: choose what to do with
the arrow keys (or `j`/`k`) and Enter, or press its number to choose it at
once. `?` shows every command (`komando --help`).

```text
komando · v0.6.0 · 12 servers, 3 conns, 1 VPN

> 1. Shell     Open a login shell on a server
  2. Test      Check that servers, conns and VPNs answer
  3. Facts     OS, updates, Docker and open ports of a server
  4. Database  Open a SQL shell on a database
  5. VPN       Connect a VPN and log in
  ...

↑↓ move · Enter or 1-8 choose · ? help · q quit
```

The menu shows only what has something to act on: Shell and Facts need a
server, Database a PostgreSQL, MySQL or SQLite conn, and VPN a VPN. While
komando knows no server yet, the menu starts with Import (when there is a
`~/.ssh/config` to bring in) and Add: type a name and `user@address`, as
in `komando host add web1 deploy@10.0.0.5`.

After an action that needs one, the list to choose from comes next: servers
for Shell and Facts, database conns for Database, VPNs for VPN, and all of
them (or `all`) for Test. Type part of a name, address, group or tag to
filter it. `protected` comes first in a row's details, so it is the last of
them a narrow window cuts off. A line too long for the window ends in `…`,
and a long filter or Add line shows its end, where you type. The menu
remembers your last action and the last name you chose while it is open,
and puts the cursor on them.

The menu runs the same command you could type, and shows it first
(`$ komando shell web1`), so every question and safety check works as it
does on the command line. When the command ends, Enter goes back to the
menu and `q` quits; the scrollback keeps the command, its output and how it
ended (`exit 1`). On a list, Esc clears the filter, then goes back to the
menu, and so does Left; on the menu, Esc (like `q`) quits. Ctrl-C stops the
command that is running, not the menu.

The menu is only for a person at a terminal. AI agents, scripts, pipes and
`komando` with any flag get the first steps (or, when piped, a `USAGE`
error) as before. `komando --help` lists every command.

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
