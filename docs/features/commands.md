# Running commands

Run commands and scripts on one or many servers, start long tasks, and save
commands you use often. [All docs](README.md)

## Quick start

```bash
komando exec web1 -- uptime                          # one server
komando exec @web -- 'df -h /'                       # every web server at once
komando exec web1 --dry-run -- 'apt-get -y upgrade'  # show what would run, run nothing
komando exec @web --script ./deploy.sh --arg v1.2.3  # run a local script remotely
komando job start web1 -- 'tar czf /backup/www.tgz /var/www'   # a long task
```

## Run a command

Everything after `--` is the command. It runs through the server's login
shell, on all picked servers in parallel (`run` and `x` are other names for
`exec`). komando's own flags go before `--`: `exec web1 -- uptime --dry-run`
is refused, because `--dry-run` there would be part of the command and the
command would really run. When the command on the server takes such a flag
itself (`apt-get upgrade --dry-run`), give it as one string with `-c`.

The `--` is required: `komando exec web1 apt-get install -y nginx` is a
usage error (exit 2) and runs nothing, because komando would read `-y` as
its own `--yes`. The same holds for every command that hands words to
another program: `job start`, `docker exec`, `docker compose`, `docker raw`,
`cluster exec`, `cluster shell`, `cluster run` and `cache run`.

```bash
komando exec web1 -- uptime
komando exec @web -P 20 -- 'df -h / | tail -1'           # up to 20 servers at once
komando exec tag:prod --sudo -- systemctl is-active nginx
komando exec db1 --read-only -- 'df -h /var/lib/postgresql'   # SQL itself: komando db query
```

| Flag | What it does |
|------|--------------|
| `-c`, `--cmd 'COMMAND'` | Give the command as one string instead of after `--`. |
| `-s`, `--sudo` / `--sudo-user NAME` | Run as root, or as another user (uses the server's `--sudo-ref` password if set). |
| `-C`, `--dir PATH` | Run in this folder on the server. |
| `-e`, `--env KEY=VALUE` | Export a variable first (repeatable; a comma stays in the value). |
| `--timeout 10m` | Time limit per server (default 5m). |
| `-P`, `--parallel 20` | How many servers at once (default 10). |
| `--fail-fast` | Start no more servers after the first failure. |
| `--stream` | Print output live, as it comes, a whole line at a time (in JSON: one event per line). |
| `--stdin-file FILE` | Send a local file as the command's input (`-` = komando's own input). |
| `--pty` | Give the command a terminal (some tools need one). |
| `--read-only` | Say the command only looks (see below). |

### Results and exit codes

Each server gets its own output, errors, exit code and run time. If the
command fails on any server, komando exits 5. If komando cannot connect or
log in, it exits 4, except when the server does not answer within
`--connect-timeout` (`CONNECT_TIMEOUT`): that exits 7, like other
timeouts.

With `-o text`, one server prints like `ssh`: its output, its errors, and a
closing `error [FAILED]: server web1 failed (exit 3)` when it fails. Several servers
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

The command may still be running on the server, or it may already have
finished. Do not run it again yet (an upgrade or a migration twice can
hurt). First look, with a read-only command: its log file, `ps`,
or the change it should have made:

```bash
komando exec web2 --read-only -- 'tail -20 /var/log/unattended-upgrades/unattended-upgrades.log'
komando exec web2 --read-only -- 'ps -ef | grep -v grep | grep apt'
```

If the server stops answering (a VPN that went away without a word),
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

On a protected server or conn, `--read-only` is an allowlist: it skips
`--yes` only for commands komando knows read: `cat`, `tail`, `head`, `ls`,
`stat`, `df`, `du`, `free`, `uptime`, `ps`, `grep`, `ss`, `journalctl` and
`systemctl status`/`is-active`, `docker ps`/`logs`/`inspect`,
`kubectl get`/`describe`/`logs`, `find` without `-delete`/`-exec`, and the
like, including a shell script built only from them. A command komando does
not recognise (a program of your own, say) is treated as a change on a
protected target, so it needs `--yes` with a person's approval like any
other. On an unprotected server `--read-only` only has to pass the
`READ_ONLY_VIOLATION` check above. `docker exec` and `cluster exec` check
their `--read-only` the same way.

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

komando blocks destructive commands (`rm -rf /`, `mkfs`, `reboot`,
`DROP DATABASE`, ...) everywhere unless a person allows them. See [Safety](safety.md).

### Pass a password to a command

A password for the remote command can come from the vault, so it is never
typed or shown: `-e DB_PASS=secret:prod-db`. komando fills in the value on
the way to the server. It goes to the command on its input, not on its
command line, so other users of the server do not see it in `ps` and it is
not written to sudo's log. Values that are not from the vault are on the
command line as usual.

### Times, sizes and KEY=VALUE flags

Every flag that takes a time reads it the same way: a number and a unit,
such as `30s`, `10m`, `2h`, `1h30m` or `7d`. A number without a unit is
refused (`--older-than 30` could mean seconds or days), except `0`.

Every size flag (`--max-bytes`, `--max-output`) takes bytes (`1048576`)
or a size with a unit: `256KiB`, `10MB`, `1GB`. KB and KiB both mean
1024 bytes, MB and MiB both 1024 KiB.

A KEY=VALUE flag (`--env`, `--label`, `--option`) takes one pair each
time; repeat it for more: `--label team=ops --label env=prod`. A value
keeps its commas (`--option hosts=a,b`), and a second `KEY=` after a
comma is refused, so `--option a=on,b=x` is never read as one value.

## Run a local script

`komando exec TARGET --script FILE` sends a script file from this computer
to the servers and runs it. Nothing is left on the server's disk.

```bash
komando exec @web --script ./deploy.sh --arg v1.2.3 --sudo
komando exec db1 --script ./backup.py --interpreter python3
```

The interpreter comes from the script's `#!` line, or from `--interpreter`
(otherwise `sh`). `--arg` values reach the script as `$1`, `sys.argv[1]`,
`$ARGV[0]` and so on, for sh, bash, python, perl, ruby and node alike.
The script is sent as the interpreter's input, so `--stdin-file` and
`--pty` do not go with `--script`. `komando script TARGET FILE` is the old
name: it still works in this release and says to use `exec --script`.
Through `env` (`#!/usr/bin/env -S bash -e`), the program after env's own
options is the interpreter, with its arguments. A script that holds a value
komando hid (`[hidden]`) is refused (`HIDDEN_VALUE`), as is such a file
given to `exec --stdin-file`.

## Long tasks (jobs)

Anything slow (backups, upgrades, builds) should run as a *job*. A job keeps
running on the server even if you disconnect, and `job start` returns at
once with a job ID per server.

```bash
komando job start web1 -- 'tar czf /backup/www.tgz /var/www'
komando job start @web --sudo -- 'apt-get update && apt-get -y upgrade'
komando job start @web --script ./migrate.sh --arg v2   # a script from this computer
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
- `job start --script FILE` runs a script from this computer as the job,
  with `--arg` and `--interpreter` as in `exec --script`. Its copy waits in
  the job's private folder and is removed the moment the job opens it.
- When `exec` times out or loses its connection, its hint is the
  `komando job start ...` line that runs the same thing as a job.
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
can save your own next to them.

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

## At your terminal: komando asks for what is missing

There is one way to use komando: `komando <thing> <verb> [target] [flags]`.
At your own terminal, leave something out and komando asks for it, one line
at a time, in the normal screen (your scrollback keeps it):

```text
$ komando logs
   1  web1  ubuntu@10.0.0.5
   2  web2  ubuntu@10.0.0.6
TARGET: 1
$ komando logs web1
...
Next time: komando logs web1
```

- It asks only what the command needs: missing arguments, required flags,
  and the few values a command is useless without (the SQL of `db query`,
  the command of `exec`). Labels are the real names: `CONN (database):`,
  `TARGET:`, `--old:`. `?` explains the question; Enter takes the default
  in brackets.
- Lists come from what komando knows: a number picks a row, part of a name
  narrows the list, and a selector (`@web`, `tag:db`) or a new name is
  taken as typed. With one item that is not protected komando uses it and
  says so (`Using app-db (the only one of your databases)`); a protected
  one is never picked for you. With none it says how to add one.
- It then shows the whole line (`$ komando ...`). A read runs at once. A
  change asks `Run it? [y/N, d = --dry-run first]` (Enter is No; `d` shows
  what it would do and asks again). One that deletes for good asks you to
  type the target's name. A protected target asks its usual
  `Change it anyway? [y/N]` instead.
- `komando host add` (or `conn add`, `vpn add`, `db add`, `cache add`,
  `queue add`, `storage add`, `cluster add`, `registry add`) typed alone
  asks that kind's own questions: which kind, a name, the address or the
  parts of the URL, the user, the port, how you log in, and whether it is
  production. A password is never asked here: the command asks for it
  itself, hidden (`--ask-password`). A password pasted with the address
  (`root:secret@10.0.0.5`) is taken out before it is drawn. After the add,
  `komando test` shows that it answers; if it does not, komando says the
  commands to change, test again or remove it.
- Ctrl-C at a question stops it and nothing runs. komando never adds
  `--yes`, `--allow-dangerous`, `--reveal` or `--write` for you.
- After a command you ran ends well, komando may say what usually comes
  next (`Next: komando db info app-db`). `komando host show web1` (`conn
  show`, `vpn show`, `group list GROUP`, `key show`, `job status`,
  `secret get`, `config get`) ends with the commands for that item.

`komando` alone shows the commands by group, START first. A command typed
in full runs as it always did. Nothing is ever asked of an AI agent, a
script, a pipe, a CI job (`CI` set), a dumb terminal (`TERM=dumb`) or JSON
output: they get the usual `USAGE` error that names what is missing.

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
