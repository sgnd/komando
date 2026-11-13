# Running commands

Run commands and scripts on one or many servers, start long tasks, and save
commands you use often. [All docs](README.md)

## Run a command

```bash
komando exec web1 -- uptime
```

```text
 10:42:01 up 34 days,  2:11,  1 user,  load average: 0.12, 0.08, 0.05
```

Typed alone at your terminal, `komando exec` asks for the server (from your
list), then the command.

Everything after `--` is the command. It runs through the server's login
shell, on all picked servers in parallel. komando's own flags go before `--`: `exec web1 -- uptime --dry-run`
is refused, because `--dry-run` there would be part of the command and the
command would really run. When the command on the server takes such a flag
itself (`apt-get upgrade --dry-run`), give it as one string with `-c`.

The `--` is required: `komando exec web1 apt-get install -y nginx` is a
usage error (exit 2) and runs nothing, because komando would read `-y` as
its own `--yes`. The same holds for every command that hands words to
another program: `job start`, `docker exec`, `docker compose`, `docker raw`,
`cluster exec`, `cluster shell`, `cluster run` and `cache run`.

```bash
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
closing `Error: server web1 failed (exit 3)` when it fails. Several servers
get a block each:

```text
=== web1 [ok, exit 0]
active
=== web2 [failed: exit 3]
[stderr] inactive
Error: 1 of 2 failed: web2 (exit 3)
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

On a protected server, a command asks first (at your terminal komando asks
you; an AI agent or a script adds `--yes` after a person agrees; see
[Safety](safety.md)), unless you add `--read-only` to say it only looks. komando checks that promise: a command
that clearly changes something (`rm`, `mv`, `tee`, `> file`, `sed -i`,
`systemctl restart`, `apt install`, ...) is refused with
`READ_ONLY_VIOLATION`. In that case drop `--read-only` and confirm the change instead.

On a protected server or conn, `--read-only` is an allowlist: it skips
the question only for commands komando knows read: `cat`, `tail`, `head`, `ls`,
`stat`, `df`, `du`, `free`, `uptime`, `ps`, `grep`, `ss`, `journalctl` and
`systemctl status`/`is-active`, `docker ps`/`logs`/`inspect`,
`kubectl get`/`describe`/`logs`, `find` without `-delete`/`-exec`, and the
like, including a shell script built only from them. A command komando does
not recognise (a program of your own, say) is treated as a change on a
protected target, so it asks first like any other. On an unprotected server `--read-only` only has to pass the
`READ_ONLY_VIOLATION` check above. `docker exec` and `cluster exec` check
their `--read-only` the same way.

A command komando cannot follow is refused the same way: `eval`, `source`,
a command name in a variable (`$X file`), a shell or python reading a
script it cannot see (`... | sh`, `python3 -c`). Text after `sh -c` or
`bash -lc` is checked like the command. With `--stdin-file`, the input is
checked too, so `--read-only --stdin-file check.sh -- 'bash -s'` works when
the script only looks. `exec --script --read-only` needs a shell as the
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

### How many: `--limit`

Every list command takes `-n/--limit N`, the most items to show (in
`cluster` commands `--limit` only, since `-n` is the namespace there).
Log readers show the last N lines.
A command that runs on several servers counts per server. Without
`--limit` a list shows what it always did: everything, or the default
its help names (`fs list` 1000, `logs` 200). `--limit 0` shows all where
the help says so. When a list stops at its limit, the JSON has
`meta.truncated: true` and `-o text` says on stderr
`showing N of more; use --limit 0 for all`.

### Other names

Help shows one name per command. Plurals and the words people often type
(`servers`, `databases`, `ls` for `list`) find the same command, and
`komando schema NAME` says which command a name runs.

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
`--pty` do not go with `--script`. Through `env` (`#!/usr/bin/env -S bash -e`), the program after env's own
options is the interpreter, with its arguments. A script that holds a value
komando hid (`[hidden]`) is refused (`HIDDEN_VALUE`), as is such a file
given to `exec --stdin-file`.

## Long tasks (jobs)

Anything slow (backups, upgrades, builds) should run as a *job*. A job keeps
running on the server even if you disconnect, and `job start` returns at
once with a job ID per server.

```bash
komando job start web1 -- 'tar czf /backup/www.tgz /var/www'
```

```text
ID                     HOST  PID    STATE
j1108-193010-9f8e7d6c  web1  48213  started
```

Typed alone, `komando job start` asks for the server, then the command.

```bash
komando job start @web --sudo -- 'apt-get update && apt-get -y upgrade'
komando job start @web --script ./migrate.sh --arg v2   # a script from this computer
komando job status JOB               # running, exited or lost; exit code; last lines
komando job logs JOB                 # output so far
komando job wait JOB --timeout 30m   # wait until it ends
komando job wait JOB1 JOB2        # wait for several (one per server)
komando job kill JOB                 # stop it (TERM; --signal KILL for a hard stop)
komando job list                        # every job; --refresh asks the servers
komando job rm JOB                   # forget it and delete its remote logs
```

Good to know:

- `job logs --offset N` reads only what is new: pass back the `next_offset`
  from the previous call. `-n/--limit N` gives the last lines instead.
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

A recipe is a saved command. komando comes with ready-made ones
(`health`, `disk`, `memory` and more; see [Health](health.md)), and you
can save your own next to them.

```bash
komando recipe list                                   # built-in and saved
komando recipe list --category saved                  # only your own
komando recipe add restart-app 'systemctl restart {{app}}' --needs-sudo
komando recipe add disk-of 'df -h {{path=/}}' --read-only --desc 'Disk use of a path'
komando recipe run restart-app @web --var app=shop
komando recipe run disk-of web1 --var path=/srv
komando recipe rm disk-of
```

- `{{app}}` is a blank you fill in with `--var app=...`. `{{path=/}}` has a
  default.
- komando treats a recipe as a change, so a protected server asks first,
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

There is one way to use komando: `komando NOUN VERB [TARGET] [FLAGS]`.
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
  says so (`Using prod-db (the only one of your databases)`); a protected
  one is never picked for you. With none it says how to add one.
- It then shows the whole line (`$ komando ...`). A read runs at once. A
  change asks `Run it? [y/N, d = --dry-run first]` (Enter is No; `d` shows
  what it would do and asks again). One that deletes for good asks you to
  type the name of what goes (or how many). A protected target asks its
  usual `web1 is protected. Change it anyway? [y/N]` instead.
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
  next, on one line on stderr with at most three commands (`Next: komando
  db info prod-db`). Every add, edit, rename and rm has one. Nothing "next"
  is printed on stdout; scripts and agents read `data.next`. `komando host
  show web1` (`conn show`, `vpn show`, `group list GROUP`, `key show`,
  `job status`, `secret show`, `config get`) ends with the commands for
  that item.

`komando` alone shows the commands by group, START first. A command typed
in full runs as it always did. Nothing is ever asked of an AI agent, a
script, a pipe, a CI job (`CI` set), a dumb terminal (`TERM=dumb`) or JSON
output: they get the usual `USAGE` error that names what is missing.

## Interactive shell (for people)

```bash
komando shell web1             # log in, with a status line first
komando shell web1 --dry-run   # shows the server, address, user and --via path; connects nothing
```

`shell` logs you in to the server, through its `--via` path (VPN and
bastions) when it has one. Inside a shell you can type anything, so on a
protected server komando asks `[y/N]` first, as `db shell` does on a
protected conn. A shell needs a person at a terminal: agents and scripts
get `NEEDS_TERMINAL` and use `exec` or `job` instead.

### Where am I? (status lines)

When you type a command yourself, komando prints one line saying where you
are working, before it connects. It does this for the commands you stay
inside: `shell`, `db shell`, `cluster shell`, `cluster forward`,
`logs --follow` and `cluster logs -f`.

```text
komando: shell on web1 (deploy@10.0.1.5) via vpn office → bastion
komando: shell on db1 (root@10.0.0.5) · PROTECTED
komando: psql on prod-db (read-only) via bastion
komando: forwarding 127.0.0.1:8080 → svc/api:80 on prod-k8s (Ctrl-C stops)
komando: following logs on web1, web2 (Ctrl-C stops)
```

- `via` is the way there: the VPN first, then the bastions.
- A protected server or database says `PROTECTED`, in red unless `NO_COLOR`
  is set.
- On a terminal that cannot show them (`TERM=dumb`, or a locale such as
  `LANG=C` that is not UTF-8), komando writes the marks in its own lines
  (errors, hints, warnings) in ASCII: `+` for ✓, `x` for ✗, `*` for ●, `->`
  for →, `-` for ·. A result (a file, a row, a log line) is always shown as
  it is.
- When a `shell` or `db shell` ends, one more line says how:
  `komando: left web1 (exit 0, 12m)` or
  `komando: connection to web1 lost after 3m`.
- When a command connects a VPN by itself, komando says that the VPN stays
  up and how to stop it.

These lines go to stderr, and only to a person at a terminal. Agents,
scripts and pipes never get them, and the JSON output does not change.

## See what is still running

Some things keep running after the command that started them: a VPN (from
`vpn up`, or connected by a command), a server login kept by
`komando login`, a tunnel, or a job on a server. `komando status` lists
them all:

```bash
komando status
```

```text
KIND    NAME                   DETAIL                                             SINCE
vpn     office                 used 3m ago, closes in 26m if unused               42m
login   web1                   kept for 7h more (`komando logout web1` ends it)   1h
tunnel  t1108-195255-ab12cd34  127.0.0.1:5433 → prod-db                            2h
job     j1108-193010-9f8e7d6c  web1: tar czf /backup/www.tgz /var/www             15m
jobs run on their servers: `komando job list --refresh` shows which still run
```

With nothing running it says
`nothing running: no VPN sessions, server logins, tunnels or jobs`.

- It contacts nothing, so it is quick and works offline.
- A job stays on the list until `komando job rm`. Whether it still runs is
  known only on its server, which `komando job list --refresh` asks.
- Agents get the same as JSON (`vpns`, `logins`, `tunnels`, `jobs`).
- An idle VPN closes after `vpn_idle` (see [Settings](settings.md)).

### Show it in your shell prompt

`komando status --short` prints a short note such as `vpn:2 tun:1` (how
many VPNs and tunnels are up), or nothing when nothing is running, so your
prompt can show it all the time. Add it yourself; komando never changes your
shell files.

zsh (also with oh-my-zsh), in `~/.zshrc`:

```zsh
setopt PROMPT_SUBST
RPROMPT='$(komando status --short)'
```

bash, in `~/.bashrc`:

```bash
PS1='$(p=$(komando status --short); [ -n "$p" ] && echo "[$p] ")'"$PS1"
```

starship, in `~/.config/starship.toml`:

```toml
[custom.komando]
command = "komando status --short"
when = true
```

It reads only the process numbers komando keeps beside its store (no
names, no key, no network, nothing written), prints no JSON and never
fails, so it is safe to run on every prompt. It is a quick hint: a VPN that
crashed a moment ago can still show until the next komando command.
`komando status` is the full check.

## Limits

- The `--` before a command's words is required for every command that
  hands words to another program; komando's own flags go before it.
- Output longer than `--max-output` (256 KiB per stream) is cut.
- `--timeout` is per server (default 5m); a job is the way past it.
- `--read-only` on a protected target skips the question only for commands
  komando knows read; script arguments (`--arg`, words after `bash -s --`)
  are refused under it.
- `exec --script` cannot be combined with `--stdin-file` or `--pty`.
- A recipe `--var` value may not start with `-` (except a number or a time
  back from now).
- A built-in recipe name cannot be reused for your own.
- `shell` and the questions for missing arguments need a person at a
  terminal: nothing is asked of an AI agent, a script, a pipe, a CI job
  (`CI` set), a dumb terminal (`TERM=dumb`) or JSON output.
- `komando status` lists jobs from komando's own records; only
  `job list --refresh` asks the servers.

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `USAGE` | an argument is missing, or the command's words were not after `--` (exit 2) | read the example in the error; put the command after `--` |
| `FAILED` | the command ran and failed on a server (exit 5) | read that server's output and `exit_code` |
| `CONNECTION_LOST` | the link broke; the command may still run, or may have finished (exit 4) | look first with a read-only command; use a job over a shaky link |
| `CONNECT_TIMEOUT` | the server did not answer within `--connect-timeout` (exit 7) | check the address and the `--via` path |
| `TIMEOUT` | the command ran longer than `--timeout`; komando stopped it (exit 7) | raise `--timeout`, or run it as a job |
| `READ_ONLY_VIOLATION` | `--read-only`, but the command changes something or komando cannot follow it (exit 6) | drop `--read-only`; a protected server then asks first |
| `HIDDEN_VALUE` | a script or `--stdin-file` holds a value komando hid (`[hidden]`) | put `secret:NAME` in `-e` instead |
| `WAIT_TIMEOUT` | `job wait` ran out of time; the job still runs (exit 7) | `komando job wait JOB` again, or `komando job logs JOB --limit 50` |
| `JOB_RUNNING` | `job rm` on a running job | `komando job kill JOB` first, or add `--kill` |
| `JOB_NOT_FOUND` | no job with that ID | see them with `komando job list` |
| `OPTION_LIKE_VAR` | a recipe `--var` value starts with `-` | write a path like that as `./-name` |
| `UNKNOWN_VAR` | the recipe has no blank of that name | check its blanks with `komando recipe list` |
| `NEEDS_TERMINAL` | `shell` without a person at a terminal | use `komando exec` or `komando job start` |
