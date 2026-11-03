# Running commands

Run commands and scripts on one or many servers, long tasks, and saved commands. [All features](README.md)

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

With `-o text`, one server prints like ssh: its output, its errors, and a
closing `error: host web1 failed (exit 3)` when it fails. Several servers
get a block each, with their errors inside:

```text
=== web1 [ok exit=0]
active
=== web2 [FAILED exit=3]
[stderr] inactive
error [PARTIAL_FAILURE]: 1 of 2 failed: web2 (exit 3)
```

`--fail-fast` stops starting servers after the first failure; the ones it
never started are reported as skipped, not failed. With `--parallel 1` the
servers run one by one, in name order. When output is longer than
`--max-output` (256 KiB), it is cut and komando says so.

`--read-only` tells komando the command only looks, so protected servers
do not ask for `--yes`. komando checks that promise: a command that clearly
changes something (`rm`, `mv`, `tee`, `> file`, `sed -i`,
`systemctl restart`, `apt install`, ...) is refused with
`READ_ONLY_VIOLATION`. Drop `--read-only` and confirm with `--yes` instead.

`komando script` runs a local file with the interpreter from its `#!` line
(or `--interpreter`); `--arg` values reach it as `$1`, `sys.argv[1]`,
`$ARGV[0]` ... for sh, bash, python, perl, ruby and node alike.

A password for the remote command comes from the vault, so it is never
typed or shown: `-e DB_PASS=secret:prod-db`. komando fills in the value on
the way to the server.

## Interactive shell (for people)

```bash
komando shell web1          # also: komando ssh web1, komando connect web1
komando shell prod-web1     # protected: asks [y/N] first (--yes skips the question)
komando shell web1 --dry-run   # shows the host, address, user and --via path; connects nothing
```

`shell` logs you in to the server, through its `--via` path (VPN and
bastions) when it has one. A line first says where you are going, and one
more says how it ended:

```
komando: shell on prod-web1 (root@10.0.0.5) via vpn office → bastion1 · PROTECTED
...
komando: left prod-web1 (exit 0, 12m)
```
 Inside it you can type anything, so on a
protected server it asks first, like `db shell` on a protected conn. It
needs a person at a terminal: agents and scripts get `NEEDS_TERMINAL` and
use `exec` or `job` instead.

## Long tasks

Anything slow (backups, upgrades, builds) runs as a *job* that keeps going
on the server even if you disconnect:

```bash
komando job start db1 -- 'pg_dump app | gzip > /backup/app.sql.gz'
komando job status <id>
komando job logs <id>                 # --offset N reads only what is new
komando job wait <id> --timeout 30m   # the job keeps running after the wait ends
komando job kill <id>                 # state becomes "killed"; on an ended job it does nothing
komando job list                      # --refresh asks the servers for the live state
komando job rm <id>                   # a running job: kill it first, or add --kill
```

## Recipes (ready-made and saved commands)

Save a command once and reuse it. `{{app}}` is a blank you fill in with
`--var app=...`. Your recipes sit next to the built-in ones (`health`,
`disk`, `cert-expiry`, ...) in `komando recipe list`. komando treats a recipe
as a change, so protected servers ask for `--yes`, unless you save it with
`--read-only` because it only looks. (`ops` and `snippet` are other names for
`recipe`.)

```bash
komando recipe add restart-app 'systemctl restart {{app}}' --sudo
komando recipe add disk-of 'df -h {{path=/}}' --read-only
komando recipe run restart-app @web --var app=shop
komando recipe run disk-of web1 --var path=/srv
```

A built-in name (`disk`, `health`, ...) cannot be reused, and a `--var` the
recipe has no blank for is refused (`UNKNOWN_VAR`), so a typo never runs the
recipe with its default.
