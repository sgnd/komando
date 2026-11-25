# Running commands

Run commands and scripts on one or many servers, keep long runs alive, and
save commands you use often. [All docs](README.md)

## Run a command

```bash
komando host ssh exec web1 -- uptime
```

```text
 10:42:01 up 34 days,  2:11,  1 user,  load average: 0.12, 0.08, 0.05
```

Typed alone at your terminal, `komando host ssh exec` asks for the server
(from your list), then the command.

Everything after `--` is the command. It runs through the server's login
shell, on all picked servers in parallel. komando's own flags go before `--`: `exec web1 -- uptime --dry-run`
is refused, because `--dry-run` there would be part of the command and the
command would really run. When the command on the server takes such a flag
itself (`apt-get upgrade --dry-run`), give it as one string with `-c`.

The `--` is required: `komando host ssh exec web1 apt-get install -y nginx`
is a usage error (exit 2) and runs nothing, because komando would read `-y`
as its own `--yes`. The same holds for every command that hands words to
another program: `host winrm exec`, `cluster kubernetes exec`,
`cluster PROVIDER raw`, `cache PROVIDER raw` and `credential run`.

```bash
komando host ssh exec @web -P 20 -- 'df -h / | tail -1'           # up to 20 servers at once
komando host ssh exec tag:prod --sudo -- systemctl is-active nginx
komando host ssh exec db1 --read-only -- 'df -h /var/lib/postgresql'   # SQL itself: komando database postgres query
```

| Flag | What it does |
|------|--------------|
| `-c`, `--cmd 'COMMAND'` | Give the command as one string instead of after `--`. |
| `-s`, `--sudo` / `--sudo-user NAME` | Run as root, or as another user (uses the server's `--sudo-credential` password if set). |
| `-C`, `--dir PATH` | Run in this folder on the server. |
| `-e`, `--env KEY=VALUE` | Export a variable first (repeatable; a comma stays in the value). |
| `--timeout 10m` | Time limit per server (default 5m). |
| `-P`, `--parallel 20` | How many servers at once (default 10). |
| `--fail-fast` | Start no more servers after the first failure. |
| `--stream` | Print output live, as it comes, a whole line at a time (in JSON: one event per line). |
| `--stdin-file FILE` | Send a local file as the command's input (`-` = komando's own input). |
| `--pty` | Give the command a terminal (some tools need one). |
| `--read-only` | Say the command only looks (see below). |
| `--attach ID` | Come back to a run that is still going (see [Long runs](#long-runs-sessions)). |

<!-- TODO(cut): the flags `--stream`, `--pty`, `--connect-timeout`, `--max-output` and `--script` with `--arg` and `--interpreter` wait on the leaf Options of the table (PR B). -->

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
inactive
Error: 1 of 2 failed: web2 (exit 3)
```

A run in a session merges what the command prints and what it reports as
errors into one output (`out.log`).

<!-- TODO(cut): the merged output and the end of the separate stderr wait on the switch of step D2 (C324). -->

With `--fail-fast`, servers that never started are reported as skipped, not
failed. With `--parallel 1`, servers run one by one, in name order. Output
longer than `--max-output` (256 KiB per stream) is cut, and komando says so.

### When the connection drops

Every `exec` runs in a session on the server. When the link to a server
breaks while a command is running (the VPN drops, the Wi-Fi changes, a
firewall cuts the connection), the command keeps going there. That server's
result says the link was lost:

- error code `CONNECTION_LOST`, exit code 4 (other servers keep their own
  results; the worst exit code wins, as usual);
- the output that arrived before the break;
- in text mode: `=== web2 [failed: connection lost]`.

Do not run the command again yet (an upgrade or a migration twice can
hurt). Come back to the same run:

```bash
komando host ssh exec web2 --attach 3f7k2m9q8x1c5v4b6n0h2j4pw8
```

If the server stops answering (a VPN that went away without a word),
komando notices within about a minute instead of waiting for `--timeout`.

This is different from:

| What happened | Error code | Exit |
|---------------|-----------|------|
| could not connect at all (the command never started) | `CONN_UNREACHABLE`, `CONNECTION_REFUSED`, `AUTH_FAILED`, ... | 4 |
| the link broke before the command started (it did not run) | `CONNECTION_LOST`, message says "it did not run" | 4 |
| the link broke while the command ran | `CONNECTION_LOST` | 4 |
| the command ran and failed | `COMMAND_FAILED` (per server: its `exit_code`) | 5 |
| the command ran longer than `--timeout` (komando stopped it) | `TIMEOUT` | 7 |

### Protected servers and `--read-only`

On a protected server, a command asks first (at your terminal komando asks
you; an AI agent or a script adds `--yes` after a person agrees; see
[Safety](safety.md)), unless you add `--read-only` to say it only looks.

`--read-only` is a strict allowlist, on every server: the command runs only
when komando knows every part of it only reads. Anything else is refused
with `READ_ONLY_VIOLATION`; drop `--read-only` and confirm the change
instead. What passes:

- Plain read tools: `cat`, `tail`, `head`, `ls`, `stat`, `df`, `du`, `free`,
  `uptime`, `ps`, `grep`, `wc`, `id`, `jq` and the like, also in a pipe, a
  `for` loop or after `sh -c`.
- Tools whose options decide, with the options komando knows read: `find`
  without `-delete`/`-exec`, `sed -n`, `sort`, `awk` that only prints,
  `journalctl`, `dmesg`, `ss`, `tar -t`, `openssl x509`. A long option is written in full
  (`--quiet`, not `--qui`): a tool reads a shortened name as any option
  that starts with it, `sed --in` as `--in-place`.
- Commands with subcommands, in the forms that read: `systemctl status`,
  `is-active`, `list-units`, `show`; `docker ps`, `logs`, `inspect`,
  `stats`; `kubectl get`, `describe`, `logs`, `top`; `ip addr`, `ip route`;
  `iptables -L`/`-S`; `apt list`, `dpkg -l`, `rpm -q`; `nginx -t`,
  `sshd -T`. A subcommand komando does not know is refused, not waved
  through.
- `sudo -n`, `sudo -u USER`, `timeout 10`, `nice`, `env NAME=VALUE`, `time`
  and `xargs` (with a plain read tool) in front of such a command, and
  `set -e`, `-u` and `-o pipefail`.

What does not pass, besides clear changes (`rm`, `tee`, `> file`,
`sed -i`, `systemctl restart`, `apt install`): a program komando does not
know (your own tool, `curl`, `wget`, `nc`), `git` (a repository's own
config can run a program on `git status` or `git diff`), an option or
subcommand it has not heard of, `kubectl --kubeconfig` and other client
settings, `sudo -E`, unquoted braces (`{a,b}`), `${x@P}` and other
expansions bash evaluates, `let`, `printf -v`, `test -v`, `set -x`,
`psql` and `mysql` (nothing holds them to a read-only transaction; use
`komando database postgres query`, which is), and setting a variable with an upper-case
name (`PATH`, `PS4`, `TAR_OPTIONS`, `KUBECONFIG` ...: programs read such
names as settings or code) by `NAME=`, `export`, `read`, `for` or `-e`.
Use a name with a lower-case letter (`-e dir=/var/log -- 'du -sh $dir'`);
`LANG`, `LC_*`, `TZ`, `TERM` and `COLUMNS` are fine. A command that uses an
`-e` value has no double quotes: in `"$dir"` the value is one word komando
cannot check. A value with `*`, `?`, `[`, `{`, `~` or a backslash is refused:
bash would expand it into names komando cannot see. `kubectl config view --raw` is refused too: it prints the
kubeconfig's credentials. komando has no separate command for reading a
server's state: use `--read-only` with the tool's own command
(`systemctl status nginx`, `docker ps`, `cat /etc/os-release`).
`cluster kubernetes exec` checks its `--read-only` the same way.

A command komando cannot follow is refused the same way: `eval`, `source`,
a command name in a variable (`$X file`), a shell or python reading a
script it cannot see (`... | sh`, `python3 -c`). Text after `sh -c` or
`bash -lc` is checked like the command. With `--stdin-file`, the input is
checked too, so `--read-only --stdin-file check.sh -- 'bash -s'` works when
the script only looks. `exec --script --read-only` needs a shell as the
interpreter (`sh`, `bash -eu`). Script arguments (`--arg`, or words after
`bash -s --`) are refused under `--read-only`: put the values in the
script. An argument the check cannot see (`find /data $X`) is refused for
commands whose arguments decide what they do (`find`, `sed`, `sort`,
`kubectl` ...); `-e` values are filled in first. Other input (a CSV for
`wc`) is data and is not read as commands.

komando blocks destructive commands (`rm -rf /`, `mkfs`, `reboot`,
`DROP DATABASE`, ...) everywhere unless a person allows them. A rule on the
command text also stops the dangerous forms of deleting files, removing
containers, pruning Docker data, removing an essential package, stopping
sshd, deleting a user and rebooting. See [Safety](safety.md).

### Pass a password to a command

A password for the remote command can come from the vault, so it is never
typed or shown: `-e DB_PASS=credential:prod-db`. komando fills in the value on
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
its help names. `--limit 0` shows all where
the help says so. When a list stops at its limit, the JSON has
`meta.truncated: true` and `-o text` prints on stderr
`Note: showing the first N; --limit 0 shows all` (some commands put their
own cut note in their output instead).

### Other names

Help shows one name per command. A few plain synonyms (`ls` for `list`)
find the same command, and `komando schema NAME` says which command a name
runs.

## Run a local script

`komando host ssh exec TARGET --script FILE` sends a script file from this
computer to the servers and runs it. Nothing is left on the server's disk.

```bash
komando host ssh exec @web --script ./deploy.sh --arg v1.2.3 --sudo
komando host ssh exec db1 --script ./backup.py --interpreter python3
```

The interpreter comes from the script's `#!` line, or from `--interpreter`
(otherwise `sh`). `--arg` values reach the script as `$1`, `sys.argv[1]`,
`$ARGV[0]` and so on, for sh, bash, python, perl, ruby and node alike.
The script is sent as the interpreter's input, so `--stdin-file` and
`--pty` do not go with `--script`. Through `env` (`#!/usr/bin/env -S bash -e`), the program after env's own
options is the interpreter, with its arguments. A script that holds a value
komando hid (`[hidden]`) is refused (`HIDDEN_VALUE`), as is such a file
given to `exec --stdin-file`.

## Long runs (sessions)

Every `exec` runs in a session on the server and prints its session ID
first. A session keeps running if you disconnect, and keeps the output and
the exit code there. Anything slow (backups, upgrades, builds) is safe to
start this way:

```bash
komando host ssh exec web1 -- 'tar czf /backup/www.tgz /var/www'
```

```text
session 3f7k2m9q8x1c5v4b6n0h2j4pw8 on web1
```

```bash
komando host ssh exec @web --sudo -- 'apt-get update && apt-get -y upgrade'
komando host ssh exec web1 --timeout 2h -- ./reindex.sh        # stopped if it runs longer than 2 hours
komando host ssh exec web1 --attach ID                         # stream the output, return the exit code
komando host ssh exec web1 --attach ID --offset 4096           # read only what is new
komando host ssh exec web1 --attach ID --stop                  # stop it (TERM; --signal KILL for a hard stop)
komando host ssh exec web1 --attach ID --remove                # remove its log on the server
komando status                                                 # sessions that are still running
```

Good to know:

- `--attach ID` only reads. It streams the output from the start, or from
  `--offset N`, and returns the run's exit code when the run ends. An
  attach has no command and no `--`.
- The first call's approval covers a re-attach.
- The ID is 26 characters from `a` to `z` and `0` to `9`, made by komando
  from 128 random bits.
- The log lives in `~/.komando/sessions/` of the login user on the server
  (folder mode 0700, files 0600, never `/tmp`). It is removed after a
  finished `--attach` read, with `--remove`, or after 7 days.
- Output in the log may hold secrets. komando masks it only on this
  computer.
- `--timeout 2h` stops the run after 2 hours, as `--stop` does.
- `--sudo` uses the server's `--sudo-credential` password when it has one.
  The password is sent as input (never on a command line) and waits in a
  private file only the session's user can read. The run first asks sudo
  whether it needs a password: when it does not, the file is deleted
  unread; when it does, sudo reads it before the command starts. Either
  way the command can never read it.
- `--script FILE`, `--stdin-file FILE` and `--sudo-user USER` work as in a
  plain `exec`.
- A session of `host winrm exec` is not shipped yet.

<!-- TODO(cut): the wait limit and the exit code for a run that outlasts an agent's tool timeout wait on C324; the Windows session waits on C359. -->

## Saved and ready-made commands (snippets)

A snippet is a saved command. komando comes with ready-made ones
(`health`, `disk`, `memory` and more; see [Health](health.md)), and you
can save your own next to them.

```bash
komando snippet list                                   # built-in and saved
komando snippet list --category saved                  # only your own
komando snippet create restart-app 'systemctl restart {{app}}' --needs-sudo
komando snippet create disk-of 'df -h {{path=/}}' --read-only --desc 'Disk use of a path'
komando snippet exec restart-app @web --var app=shop
komando snippet exec disk-of web1 --var path=/srv
komando snippet remove disk-of
```

- `{{app}}` is a blank you fill in with `--var app=...`. `{{path=/}}` has a
  default.
- komando treats a snippet as a change, so a protected server asks first,
  unless you saved it with `--read-only` because it only looks. A read-only
  snippet is checked like `exec --read-only` when you save it. If, with its
  blanks filled in, it no longer passes that check, it runs as a change.
- A `--var` value may not start with `-`, because a program would read it
  as an option (`OPTION_LIKE_VAR`). Write a path like that as `./-name`. A
  number or a relative time (`-5`, `-2h`) is fine.
- A built-in name (`disk`, `health`, ...) cannot be reused. Replace one of
  your own with `--overwrite`.
- A `--var` the snippet has no blank for is refused (`UNKNOWN_VAR`), so a typo
  never runs the snippet with its default.
- `snippet exec --no-sudo` skips sudo even when the snippet asks for it.
- A snippet can sit in a group, and it travels in `komando export`.

## At your terminal: komando asks for what is missing

There is one way to use komando: `komando TYPE PROVIDER VERB NAME`, or
`komando NOUN [KIND] VERB [NAME]` for komando's own things.
At your own terminal, leave something out and komando asks for it, one line
at a time, in the normal screen (your scrollback keeps it):

```text
$ komando host ssh exec
   1  web1  203.0.113.10
   2  web2  203.0.113.11
TARGET (servers): 1
COMMAND: uptime
$ komando host ssh exec web1 -- uptime
...
Next time: komando host ssh exec web1 -- uptime
```

- It asks only what the command needs: missing arguments, required flags,
  and the few values a command is useless without (the SQL of
  `database postgres query`, the command of `exec`). Labels are the real
  names: `TARGET (servers):`, `NAME:`, `--old:`. `?` explains the question;
  Enter takes the default in brackets.
- Lists come from what komando knows: a number picks a row, part of a name
  narrows the list, and a selector (`@web`, `tag:db`) or a new name is
  taken as typed. With one item that is not protected komando uses it and
  says so (`Using prod-db (the only one of your databases)`); a protected
  one is never picked for you. With none it says how to add one.
- It then shows the whole line (`$ komando ...`). A read runs at once. A
  change asks `Run it? [y/N, d = --dry-run first]` (Enter is No; `d` shows
  what it would do and asks again). One that deletes for good asks you to
  type the name of what goes (or how many). A protected target asks its
  usual `web1 (protected): this command changes it. Continue? [y/N]` instead.
- `komando host ssh add` (or `database postgres add`, `vpn wireguard add`,
  `cache redis add`, `queue kafka add`, `storage s3 add`,
  `cluster kubernetes add`, `registry oci add`) typed alone asks that
  entry's own questions: a name, the address or the parts of the URL, the
  port, which credential logs in, and whether it is production. A password
  is never asked here: save it with `komando credential password add`,
  which asks for it hidden. After the add, `komando test` shows that it
  answers; if it does not, komando says the commands to change, test again
  or remove it.
- Ctrl-C at a question stops it and nothing runs. komando never adds
  `--yes`, `--allow-dangerous`, `--reveal` or `--write` for you.
- After a command you ran ends well, komando may say what usually comes
  next, on one line on stderr with at most three commands (`Next: komando
  database postgres show prod-db`). Every add, edit, rename and remove has
  one. Nothing "next" is printed on stdout; scripts and agents read
  `data.next`. `komando host ssh show web1` (and `show` on every type,
  `group show`, `credential password show`, `config get`) ends with the
  commands for that item.

`komando` alone shows the commands by group. A command typed in full runs
as it always did. Nothing is ever asked of an AI agent, a script, a pipe, a
CI job (`CI` set), a dumb terminal (`TERM=dumb`) or JSON output: they get
the usual `USAGE` error that names what is missing.

## Interactive shell (for people)

```bash
komando host ssh shell web1             # log in, with a status line first
komando host ssh shell web1 --dry-run   # shows the server, address, user and --via path; connects nothing
```

`shell` logs you in to the server, through its `--via` path (VPN and
bastions) when it has one. Inside a shell you can type anything, so on a
protected server komando asks `[y/N]` first, as `database postgres shell`
does on a protected database. A shell needs a person at a terminal: agents
and scripts get `NEEDS_TERMINAL` and use `exec` instead.

### Where am I? (status lines)

When you type a command yourself, komando prints one line saying where you
are working, before it connects. It does this for the commands you stay
inside: `host ssh shell`, `database PROVIDER shell`,
`cluster kubernetes shell` and `cluster kubernetes tunnel start`.

```text
komando: shell on web1 (deploy@10.0.1.5) via vpn office → bastion
komando: shell on db1 (root@10.0.0.5) · PROTECTED
komando: psql on prod-db (read-only) via bastion
komando: forwarding 127.0.0.1:8080 → svc/api:80 on prod-k8s (Ctrl-C stops)
```

- `via` is the way there: the VPN first, then the bastions.
- A protected server or database says `PROTECTED`, in red unless `NO_COLOR`
  is set.
- On a terminal that cannot show them (`TERM=dumb`, or a locale such as
  `LANG=C` that is not UTF-8), komando writes the marks in its own lines
  (errors, hints, warnings) in ASCII: `+` for ✓, `x` for ✗, `*` for ●, `->`
  for →, `-` for ·. A result (a file, a row, a log line) is always shown as
  it is.
- When a `shell` ends, one more line says how:
  `komando: left web1 (exit 0, 12m)` or
  `komando: connection to web1 lost after 3m`.
- When a command connects a VPN by itself, komando says that the VPN stays
  up and how to stop it.

These lines go to stderr, and only to a person at a terminal. Agents,
scripts and pipes never get them, and the JSON output does not change.

## See what is still running

Some things keep running after the command that started them: a VPN (from
`vpn wireguard start`, or connected by a command), a server login kept by
`komando test`, a tunnel, or an exec session on a server. `komando status`
lists them all:

```bash
komando status
```

```text
KIND    NAME                        DETAIL                                                        SINCE
vpn     office                      used 3m ago, closes in 26m if unused                          42m
login   web1                        kept for 7h more (`komando test web1 --end` ends it)          1h
tunnel  t1108-195255-ab12cd34       127.0.0.1:5433 → prod-db                                      2h
exec    3f7k2m9q8x1c5v4b6n0h2j4pw8  web1: tar czf /backup/www.tgz /var/www                        15m
```

With nothing running it says
`nothing running: no VPN sessions, server logins, tunnels or exec sessions`.

- It contacts nothing, so it is quick and works offline.
- It lists the exec sessions that are still running.
- Agents get the same as JSON.
- An idle VPN closes after `vpn_idle` (see [Settings](settings.md)).
- A kept login ends after 8 hours (the `login_for` setting), or sooner with
  `komando test web1 --end`. `komando test --end` ends all of them.

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
- `--timeout` is per server (default 5m); a run in a session goes on
  there, and `--attach ID` comes back to it.
- `--read-only` runs only commands komando knows only read, on every
  target; script arguments (`--arg`, words after `bash -s --`)
  are refused under it.
- `exec --script` cannot be combined with `--stdin-file` or `--pty`.
- A snippet `--var` value may not start with `-` (except a number or a time
  back from now).
- A built-in snippet name cannot be reused for your own.
- `shell` and the questions for missing arguments need a person at a
  terminal: nothing is asked of an AI agent, a script, a pipe, a CI job
  (`CI` set), a dumb terminal (`TERM=dumb`) or JSON output.
- `komando status` lists exec sessions from komando's own records.
- `reboot` has no command of its own. It runs through `exec` behind the
  power rules and needs a person's yes. komando no longer reboots one
  server at a time with a boot-ID check, and no longer returns
  `back_after`: reboot servers one by one and call `komando test` until
  each answers.

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `USAGE` | an argument is missing, or the command's words were not after `--` (exit 2) | read the example in the error; put the command after `--` |
| `COMMAND_FAILED` | the command ran and failed on a server (exit 5) | read that server's output and `exit_code` |
| `CONNECTION_LOST` | the link broke; the command may still run, or may have finished (exit 4) | `komando host ssh exec SERVER --attach ID` before you run it again |
| `CONNECT_TIMEOUT` | the server did not answer within `--connect-timeout` (exit 7) | check the address and the `--via` path |
| `TIMEOUT` | the command ran longer than `--timeout`; komando stopped it (exit 7) | raise `--timeout` |
| `READ_ONLY_VIOLATION` | `--read-only`, but the command changes something or komando cannot follow it (exit 6) | drop `--read-only`; a protected server then asks first |
| `HIDDEN_VALUE` | a script or `--stdin-file` holds a value komando hid (`[hidden]`) | put `credential:NAME` in `-e` instead |
| `OPTION_LIKE_VAR` | a snippet `--var` value starts with `-` | write a path like that as `./-name` |
| `UNKNOWN_VAR` | the snippet has no blank of that name | check its blanks with `komando snippet list` |
| `NEEDS_TERMINAL` | `shell` without a person at a terminal | use `komando host ssh exec` |
