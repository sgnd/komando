# Running commands

Run commands and scripts on one or many servers, start long tasks, and save
commands you use often. [All docs](README.md)

## Quick start

```bash
komando exec web1 -- uptime                          # one server
komando exec @web -- 'df -h /'                       # every web server at once
komando exec web1 --dry-run -- 'apt-get -y upgrade'  # show what would run, run nothing
komando script @web ./deploy.sh --arg v1.2.3         # run a local script remotely
komando job start web1 -- 'tar czf /backup/www.tgz /var/www'   # a long task
```

## Run a command

Everything after `--` is the command. It runs through the server's login
shell, on all picked servers in parallel (`run` and `x` are other names for
`exec`). komando's own flags go before `--`: `exec web1 -- uptime --dry-run`
is refused, because `--dry-run` there would be part of the command and the
command would really run. When the command on the server takes such a flag
itself (`apt-get upgrade --dry-run`), give it as one string with `-c`.

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
Through `env` (`#!/usr/bin/env -S bash -e`), the program after env's own
options is the interpreter, with its arguments. `script` takes the same
flags as `exec` except `-c`, `--stdin-file` and `--pty` (the script itself
is the input), plus `--arg` and `--interpreter`. A script that holds a value
komando hid (`[hidden]`) is refused (`HIDDEN_VALUE`), as is such a file
given to `exec --stdin-file`.

## Long tasks (jobs)

Anything slow (backups, upgrades, builds) should run as a *job*. A job keeps
running on the server even if you disconnect, and `job start` returns at
once with a job ID per server.

```bash
komando job start web1 -- 'tar czf /backup/www.tgz /var/www'
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

Type `komando` alone in a terminal and a menu opens. Pick a thing first
(a server, a database, a VPN), then what to do with it. Move with the arrow
keys (or `j`/`k`) and choose with Enter or a number. In a list of servers
or services, type to filter it.

```text
komando  3 servers · 1 database · 2 services · 2 VPNs (office connected)

> 1. Servers                 db1, web1, web2
  2. Databases and services  cache1, orders-queue, shop-db
  3. VPNs                    lab not connected · office connected
  4. Running now (1)         Jobs, tunnels, VPNs and logins komando left running
  5. Add something           A server, a database, a VPN or another service
  6. Check everything        See if every server and service answers
  7. History and undo        What komando and your AI agent changed, and how to put it back
  8. Settings and help       AI agent, passwords, production servers, SSH keys

↑↓ move · Enter or 1-8 choose · ? help · q quit
```

The first time, with nothing added yet, the menu offers Add a server, Bring
in my SSH servers (when `~/.ssh/config` names some), Set up my AI agent and
Settings and help. While something is still running (a job, a tunnel, a VPN,
a kept login), a Running now row shows it, with a way to stop each one.

Pick a server and komando asks what you want to do with it: open a shell,
check its health, read logs, start or stop services, run a command, work
with files, Docker, updates, reboot, change it or remove it. More… holds the
rest (cron, users, network checks, tunnels, certificates, SSH keys, saved
commands). Databases, caches, queues, file storage, clusters, registries and
VPNs each have their own list of tasks the same way.

A line too long for the window ends in `…`; the help and problems under a
question wrap instead. A long filter shows its end, where you type.

The menu runs the same command you could type, and shows it first
(`$ komando shell web1`), so every question and safety check works as it
does on the command line. When the command ends, Enter goes back to the
menu and `q` quits. Esc goes back one step (on the main menu, it leaves). Ctrl-C stops the command
that is running, not the menu. `?` explains the screen you are on.

The menu is only for a person at a terminal. AI agents, scripts, pipes and
`komando` with any flag get the first steps (or, when piped, a `USAGE`
error). `komando --help` lists every command.

### Add, one question at a time

Add asks what you are adding (a Linux or Windows server, a database, a
cache, a message queue, file storage, Kubernetes, a container registry or a
VPN), then one question at a time, in the order you think of it: a name,
the address, the user, what the server runs, the port, how you log in, and
whether it is production. Each question says what it is
and where to find it, shows an example, and offers a default that Enter
takes (`Port [22]:`). An answer is checked before the next question: a name
that is taken, an address with a typo or a file that is not there is said
under it, marked `!`, and the answer stays to be fixed.

```text
Add a server · 3 of 7
  Name     web1
  Address  203.0.113.20

Which user do you log in as?
User: root_
The login name on the server. Many VPS use root; Ubuntu cloud servers use ubuntu; Windows uses Administrator, or user@domain for a domain user.
```

The last screen shows every answer and the commands they make, before
anything runs:

```text
Add a server: check and run
This runs:
  $ komando host add web1 root@203.0.113.20 --ask-password --protected
  $ komando test web1

> 1. Run it          run the commands above
  2. Try it first    show what it would do, changing nothing (--dry-run)
  3. Name            web1
  ...
  10. More options   jump host, one-time code, group, notes
```

Enter on an answer asks it again; More options asks the rare ones (a jump
host or VPN, a one-time code, a group, notes). A password is never typed into the menu:
the command asks for it itself, hidden (`--ask-password`), and keeps it as
a saved password. A password pasted with the address (`root:secret@10.0.0.5`) is
taken out before it is shown, and nothing keeps it. After the add, `komando
test` shows that it answers (for a server with a one-time code, `komando
login` instead).

`komando host add`, `komando db add` (and `cache add`, `queue add`,
`storage add`, `cluster add`, `registry add`, `vpn add`) typed alone at a
terminal ask the same questions. With any argument or flag, or for an AI
agent or a script, they ask nothing.

### Every task asks what it needs

A task picked in the menu asks only what it needs: the server, database or
VPN you picked is already filled in, then the few things that matter.
Everything else waits under More options on the review screen. For a
command that changes something, the review also offers *Try it first*,
which runs it with `--dry-run` and comes back to the review. The menu never
adds `--yes`, `--allow-dangerous` or `--reveal`: a change that needs your
yes asks you when it runs.

Keys in a form: Enter takes the answer (or the default), Esc clears what
you typed and then goes back one question, numbers choose on a list, and
Ctrl-C cancels before anything runs: the menu then says "Nothing was added."
or "Nothing was run."

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
