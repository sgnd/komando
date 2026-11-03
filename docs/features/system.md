# Services, logs, Docker, packages, users

Day-to-day server administration, with structured results instead of raw
terminal output. [All features](README.md)

## Quick start

```bash
komando svc status @web nginx                                 # is nginx running?
komando svc restart @web nginx --wait 10                      # restart, and check it came back
komando logs web1 --unit nginx --since -30m --grep 'error|crit'
komando docker ps web1                                        # running containers
komando pkg upgradable all --refresh                          # pending updates
komando user list web1                                        # who can log in
```

## Services (systemd)

```bash
komando svc status @web nginx php8.2-fpm      # state, main PID, restarts, memory
komando svc restart @web nginx --wait 10      # fails unless nginx is active within 10s
komando svc enable web1 nginx --now           # enable and start
komando svc stop web1 old-worker
komando svc list web1 --failed                # or --state running
komando svc logs web1 nginx                   # same as komando logs web1 --unit nginx
```

`start`, `stop`, `restart`, `reload`, `enable` and `disable` use sudo and
report the state afterwards. Add `--no-sudo` for user units or when you log
in as root.

- A unit that does not exist exits 3 with `UNIT_NOT_FOUND`.
- A server without systemd (most containers) exits 3 with `NO_SYSTEMD`.
  Read its logs with `--file` or `komando docker logs` instead.

## Logs

`logs` reads one source: the systemd journal (`--unit`), a file (`--file`)
or a Docker container (`--container`).

```bash
komando logs web1 --unit nginx --since -30m --grep 'error|crit'
komando logs web1 --unit nginx --follow                 # keep watching; Ctrl-C to stop
komando logs web1 --unit nginx -p err --since today     # errors and worse
komando logs @web --file /var/log/nginx/error.log -n 50 --sudo
komando logs web1 --container api --since 10m --timestamps
```

| Option | What it does |
|--------|--------------|
| `-n`, `--limit N` | The last N lines (default 200). |
| `--grep REGEX` | Only lines that match (extended regex, any case). |
| `--since` / `--until` | A time range: `-1h`, `10m`, `today`, `'2026-01-02 10:00'` (journal and containers). |
| `-p`, `--priority` | Journal priority and worse: `emerg` ... `debug`, or 0-7. |
| `-f`, `--follow` | Keep printing new lines until Ctrl-C. |
| `-s`, `--sudo` | Read the whole journal or a protected file. |
| `--timestamps` | Show when each container log line was written. |

Without `--sudo`, the journal shows only your own entries, and komando warns
you. A log file that does not exist exits 3.

## Docker

```bash
komando docker ps web1                         # running containers (--all for stopped ones too)
komando docker stats web1                      # CPU, memory, network and disk use
komando docker images web1
komando docker logs web1 api -n 100            # same as komando logs web1 --container api
komando docker restart web1 api
komando docker exec web1 api -- php artisan migrate:status
komando docker compose web1 --dir /srv/shop -- up -d --pull always
```

- Reading (`ps`, `stats`, `images`, `inspect`, `logs`) needs nothing extra.
- `start`, `stop`, `restart`, `pull`, `run` and `compose up` change things,
  so protected servers need `--yes`.
- `rm`, `prune`, `compose down -v` and other deletes need
  `--allow-dangerous`.
- `docker exec` passes the command's words as written, with no shell, so
  the image needs no `sh`. For pipes or `&&`, write the shell yourself:
  `-- sh -c 'ls /data | wc -l'`. Add `--read-only` when it only looks.
- `docker raw TARGET -- ARGS...` runs any other docker subcommand, under the
  same rules.
- `--sudo` runs docker through sudo, when your user is not in the `docker`
  group.

## Packages

`pkg` works with apt, dnf, yum, apk, zypper and pacman; komando finds out
which one each server uses.

```bash
komando pkg install @web htop
komando pkg rm web1 htop
komando pkg installed web1 nginx openssl        # installed versions (all without names)
komando pkg upgradable all --refresh            # refresh the package index first
komando pkg upgrade web1 --dry-run              # what would be upgraded
komando pkg upgrade web1                        # everything, or name the packages
komando pkg update web1                         # only refresh the package index
```

- `install` and `rm` report what changed (`changed: false` when there was
  nothing to do). An unknown package exits 3 (`PACKAGE_NOT_FOUND`).
- `upgradable` says how old the package index is, and suggests `--refresh`
  when it is more than a day old.
- Removing packages a server needs (openssh-server, sudo, systemd, libc
  ...) needs `--allow-dangerous`.
- `--no-sudo` skips sudo when you log in as root.

## Users

```bash
komando user list web1                       # NAME UID HOME SHELL ADMIN-GROUP LOCKED
komando user list web1 --all                 # include system accounts
komando user add @web deploy --key deploy --admin
komando user add web1 ci --pubkey 'ssh-ed25519 AAAA... ci@example.com' --shell /bin/sh
komando user lock web1 leaver                # SSH keys stop working too
komando user unlock web1 leaver
komando user rm web1 leaver --remove-home --allow-dangerous
```

- `user add` can run again safely: an existing user is not created twice,
  but its shell, key and admin group are brought in line. `--key`
  authorizes a key from komando's keychain, `--pubkey` a key line, and
  `--admin` adds the user to the `sudo` group (Debian) or `wheel` (RHEL,
  Alpine).
- `user lock` locks the password and expires the account, so SSH keys stop
  working too, without deleting anything.
- `user list` reads the lock state through sudo (`--no-sudo` leaves it
  out). `admin_group` means "in the sudo, wheel or admin group"; rules in
  `sudoers.d` are not read.
- `user rm` needs `--allow-dangerous`.

## Scheduled jobs (cron)

komando manages crontab entries by an ID you choose. `cron set` with the
same ID replaces the entry instead of adding a second one, and other lines
in the crontab are kept as they are.

```bash
komando cron set db1 nightly-backup '/usr/local/bin/backup.sh >> /var/log/backup.log 2>&1' --schedule '0 2 * * *'
komando cron set @web clean-tmp 'find /tmp -mtime +7 -delete' --schedule @daily
komando cron list db1
komando cron rm db1 nightly-backup           # data: {"removed": 1}
komando cron list db1 --user www-data        # another user's crontab (uses sudo)
```

- IDs use letters, digits, `-` and `_`.
- `--schedule` takes five fields (`'*/5 * * * *'`) or `@hourly`, `@daily`,
  `@weekly`, `@monthly`, `@yearly`, `@reboot`. It is checked before anything
  is written.
- `%` in the command is escaped for you.
- `--sudo` edits root's crontab.
