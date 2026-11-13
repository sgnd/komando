# Services, logs, Docker, packages, users

Day-to-day server administration, with structured results instead of raw
terminal output. [All docs](README.md)

## Quick start

```bash
komando svc status @web nginx                                 # is nginx running?
komando svc restart @web nginx --wait 10s                     # restart, and check it came back
komando logs web1 --unit nginx --since 30m --grep 'error|crit'
komando docker ps web1                                        # running containers
komando pkg upgradable all --refresh                          # pending updates
komando user list web1                                        # who can log in
```

## Common tasks from start to end

Every step is a command; a person and an AI agent type the same ones. A
person who leaves out an argument at a terminal is asked for it (the
server from a list); an agent gets a usage error with an example.

```bash
# a service misbehaves
komando svc list web1 --failed                       # what is broken?
komando logs web1 --unit nginx --since 30m --grep error
komando fs replace web1 /etc/nginx/nginx.conf --old A --new B --backup --dry-run
komando svc restart web1 nginx --wait 10s --dry-run
komando svc restart web1 nginx --wait 10s            # fails unless it is active within 10s

# a patch round
komando pkg security @web --refresh                  # what is pending, and each server's state
komando pkg upgrade @web --security --dry-run
komando pkg upgrade @web --security                  # one server at a time
komando reboot web1 --dry-run                        # when reboot_required says so

# a person joins, then leaves
komando user add web1 alice --key alice --admin
komando user lock web1 alice                         # stops logins, keeps the files
komando user rm web1 alice --remove-home --dry-run

# a nightly job
komando cron set db1 nightly-backup '/usr/local/bin/backup.sh' --schedule '0 2 * * *'
komando cron list db1
komando cron rm db1 nightly-backup

# a full disk on a Docker server
komando recipe run disk web1
komando docker prune web1 --older-than 30d --dry-run # what would go, and how much
```

Changes on a protected server ask a person (`[y/N]` at a terminal, the
approval window for an agent's `--yes`); deletes such as `user rm`,
`docker prune` and `reboot` ask the person to type the server's name, or
need `--allow-dangerous`.

## Services (systemd)

Most Linux servers start and watch their services with systemd. systemd
calls each service a unit (`nginx`, `php8.2-fpm`).

```bash
komando svc status @web nginx php8.2-fpm      # state, main PID, restarts, memory
komando svc restart @web nginx --wait 10s     # fails unless nginx is active within 10s
komando svc enable web1 nginx --now           # enable and start
komando svc stop web1 old-worker
komando svc start web1 worker
komando svc disable web1 old-worker --now      # do not start it at boot, and stop it now
komando svc list web1 --failed                # or --state running
komando svc logs web1 nginx                   # same as komando logs web1 --unit nginx
```

`start`, `stop`, `restart`, `reload`, `enable` and `disable` use sudo and
report the state afterwards. Add `--no-sudo` when you log in as root. When
sudo wants a password komando does not have, or the login user may not use
sudo, the command stops with `PERMISSION_DENIED` and a hint that names the
fix (`komando host edit web1 --sudo-ref secret:web1-sudo`, see
[Sudo passwords](servers.md#sudo-passwords-and-the-vault)); a server with no
sudo at all gives `TOOL_MISSING` (add `--no-sudo` as root). The same holds
for `pkg`, `user`, `cron --user root`, `docker --sudo` and recipes that use
sudo. They
work on system services only: komando does not manage a user's own units
(`systemctl --user`); use `komando exec` for those.

- `--wait` takes a time (`10s`, `2m`); a bare number counts as seconds.
- Stopping, disabling or masking the SSH server (`ssh`, `sshd`,
  `ssh.socket`) needs `--allow-dangerous`: it locks you out.
- A unit that does not exist exits 3 with `UNIT_NOT_FOUND`.
- A server without systemd (most containers) exits 3 with `NO_SYSTEMD`.
  Read its logs with `--file` or `komando docker logs` instead.

After you write or change a unit file, reload systemd so it reads it:

```bash
komando svc daemon-reload web1                # names any unit that still needs a reload
```

## Logs

`logs` reads one source: the systemd journal (`--unit`), a file (`--file`)
or a Docker container (`--container`).

```bash
komando logs web1 --unit nginx --since 30m --grep 'error|crit'
komando logs web1 --unit nginx --follow                 # keep watching; Ctrl-C to stop
komando logs web1 --unit nginx -p err --since today     # errors and worse
komando logs @web --file /var/log/nginx/error.log -n 50 --sudo
komando logs web1 --container api --since 10m --timestamps
```

| Flag | What it does |
|------|--------------|
| `-u`, `--unit UNIT` | Read the systemd journal of this service. |
| `--file PATH` | Read this log file. |
| `--container NAME` | Read this Docker container's log. |
| `-n`, `--limit N` | The last N lines (default 200). |
| `--grep REGEX` | Only lines that match (extended regex, any case). |
| `--since` / `--until` | A time range: a time back from now (`30m`, `2h`, `7d`), `today`, `yesterday`, or a date (`'2026-01-02 10:00'`). Containers take no `today` or `yesterday`. |
| `-p`, `--priority` | Journal priority and worse: `emerg` ... `debug`, or 0-7. |
| `-f`, `--follow` | Keep printing new lines until Ctrl-C. |
| `-s`, `--sudo` | Read the whole journal or a protected file. As root, komando does not read a file through a link another server user made (IS_A_SYMLINK), and `--follow` keeps reading the file it opened. |
| `--timestamps` | Show when each container log line was written (with `--container` only; journal lines have their time already). |

`komando svc logs TARGET UNIT` and `komando docker logs TARGET CONTAINER`
are other names for `logs --unit` and `logs --container`, with all the flags
above.

Without `--sudo`, the journal shows only your own entries, and komando warns
you. A log file that does not exist exits 3.

## Docker

```bash
komando docker ps web1                         # running containers (--all for stopped ones too)
komando docker stats web1                      # CPU, memory, network and disk use
komando docker images web1
komando docker logs web1 api -n 100            # same as komando logs web1 --container api
komando docker inspect web1 api                # a container, image or other object in full
komando docker pull web1 nginx:1.27            # fetch an image
komando docker stop web1 api                   # also: start, restart
komando docker restart web1 api
komando docker rm web1 old-api --dry-run       # remove a container (needs --allow-dangerous)
komando docker exec web1 api -- php artisan migrate:status
komando docker compose web1 --dir /srv/shop -- up -d --pull always
komando docker prune web1 --older-than 30d --dry-run   # what would be removed, and how much space
```

- Reading (`ps`, `stats`, `images`, `inspect`, `logs`) needs nothing extra.
- `start`, `stop`, `restart`, `pull`, `compose up` and a `docker run`
  through `docker raw` change things, so protected servers need `--yes`.
- `rm`, `prune`, `compose down -v` and other deletes need
  `--allow-dangerous`.
- `docker exec` passes the command's words as written, with no shell, so
  the image needs no `sh`. For pipes or `&&`, write the shell yourself:
  `-- sh -c 'ls /data | wc -l'`. Add `--read-only` when it only looks; it
  is checked as for `exec`, so on a protected server only commands komando
  knows read skip `--yes`.
- `docker raw TARGET -- ARGS...` runs any other docker subcommand, under the
  same rules.
- `--sudo` runs docker through sudo, when your user is not in the `docker`
  group.

### Free disk space (docker prune)

```bash
komando docker prune web1 --dry-run                          # what would go, with sizes and a total
komando docker prune web1 --older-than 30d --all --dry-run   # also unused tagged images, older than 30 days
komando docker prune web1 --older-than 30d --allow-dangerous # do it
```

`docker prune` runs `docker system prune`: it removes stopped containers,
dangling images, unused networks and build cache.

- `--dry-run` changes nothing. It asks docker on the server (only commands
  that list) and shows each container, image and volume that would go, the
  build cache docker can free, and a total. Image sizes count shared layers
  in every image, so the space really freed can be less.
- `--older-than 30d` keeps everything created in the last 30 days (docker's
  `until` filter).
- `--all` removes every image no container uses, not only dangling ones;
  the next deploy pulls them again.
- `--volumes` also removes unused anonymous volumes. That is data: look at
  the dry run first. It cannot be combined with `--older-than` (docker has
  no age filter for volumes).
- The real run deletes, so it needs `--allow-dangerous` (and `--yes` on a
  protected server).

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
komando pkg upgrade @web --security             # only security updates, one server at a time
```

- `install` and `rm` report what changed (`changed: false` when there was
  nothing to do). An unknown package exits 3 (`PACKAGE_NOT_FOUND`).
- `upgradable` says how old the package index is, and suggests `--refresh`
  when it is more than a day old.
- Removing packages a server needs (openssh-server, sudo, systemd, libc
  ...) needs `--allow-dangerous`, however the name is written
  (`openssh-server:amd64`, `sudo.x86_64`, `openssh.server`). On apt
  servers, removing a package that would take one of them with it
  (`libssl3` takes openssh-server) stops with `POLICY_BLOCKED` before
  anything is removed; other package managers are not checked this way.
- Package names are exact names: no options, patterns or a trailing `-`.
  For a local `.deb` or `.rpm`, use `komando upload` and `komando exec`.
- `--no-sudo` skips sudo when you log in as root.

### Security updates

`pkg security` and `pkg upgrade --security` handle a patch round: only security updates, one server at
a time, with a look at each server before and after.

```bash
komando pkg security @swarm --refresh            # what is pending, and each server's state
komando pkg upgrade @swarm --security --dry-run  # the plan, and any stop it would hit
komando pkg upgrade @swarm --security            # patch, one server at a time
komando pkg upgrade @swarm --security --keep-going # do not stop at a server that changed
```

- `pkg security` only looks. It lists the security updates (apt:
  packages from the `-security` pocket; dnf and yum: updates with a
  security notice) and the server's state: running containers, failed
  units, pending updates, whether a reboot is required, and services that
  still run old code (from `needrestart` or `needs-restarting`). These
  come from the same check as `komando facts`, so both say the same.
- It also judges the OS (`os_support`, as in `komando facts`). On an OS past
  end of life the list can be empty while the server is not safe: the
  repositories publish no new fixes for it. komando then says so in
  `warnings`.
- `pkg upgrade --security` installs only those updates. On apt servers komando uses
  `unattended-upgrade` when it is installed (it picks security origins and
  follows the server's own settings), otherwise `apt-get install
  --only-upgrade` of the listed packages; changed config files are kept.
  If the server's unattended-upgrades is set to reboot by itself, komando
  uses apt-get instead. dnf and yum run `upgrade --security`.
- needrestart does not restart services during the run. The result lists
  the services that need a restart (`services_need_restart`): restart them
  with `komando svc restart` when it suits you.
- After each server komando compares its state with the one before. Fewer
  running containers, a newly failed unit or a removed essential package
  stop the round with `UNEXPECTED_CHANGE` (exit 8); the other servers stay
  as they are and are listed in `not_run`. komando waits up to a minute for
  containers to come back first. `--keep-going` goes on after a failure or
  a change.
- komando never reboots. `reboot_required` says when a server needs one;
  use `komando reboot` ([Reboot](#reboot)).
- The upgrade runs detached on the server, so a dropped connection does not
  break it halfway. `--security` waits up to 30 minutes per server; `--timeout`
  changes that. After a `TIMEOUT` the upgrade goes on: run `pkg security`
  again later to see what is left.
- It is a change like `pkg upgrade`: protected servers need `--yes`. An
  update that would remove an essential package stops with
  `POLICY_BLOCKED` before anything changes (apt servers).
- A stale package index hides new fixes: komando warns when it is more than
  a day old; add `--refresh`. Repositories without security notices (for
  example CentOS) list nothing on dnf/yum. apk, zypper and pacman servers
  are listed in `meta.skipped`: use `pkg upgrade` there.

## Reboot

```bash
komando reboot web1 --dry-run                 # what would run, and whether it would be blocked
komando reboot @web --allow-dangerous         # one server at a time
komando reboot @web --allow-dangerous --wait 10m
```

`komando reboot` restarts one server at a time. For each server it asks
for a reboot (`systemctl reboot`, through sudo), waits until SSH answers
again, and checks that the server really started anew (a new boot ID).
Only then does it go on to the next server.

- `--wait` is how long each server may take to come back (default 5m).
- A server that does not come back in time stops the rest with
  `REBOOT_TIMEOUT` (exit 7). Any other failure stops the rest too. The
  servers after it are listed in `not_rebooted`.
- A reboot is destructive, so it needs `--allow-dangerous`, and `--yes` on
  protected servers.
- `--no-sudo` skips sudo when you log in as root.

## Users

```bash
komando user list web1                       # NAME UID HOME SHELL ADMIN GROUP LOCKED
komando user list web1 --all                 # include system accounts
komando user add @web deploy --key deploy --admin
komando user add web1 ci --pubkey 'ssh-ed25519 AAAA... ci@example.com' --shell /bin/sh
komando user lock web1 leaver                # SSH keys stop working too
komando user unlock web1 leaver
komando user rm web1 leaver --remove-home --allow-dangerous
```

- `user add` can run again safely: an existing user is not created twice,
  but its shell, key and admin group are brought in line. `--key`
  authorizes a key from komando's key list, `--pubkey` a key line, and
  `--admin` adds the user to the `sudo` group (Debian) or `wheel` (RHEL,
  Alpine). Give `--key` or `--pubkey`, not both.
- `user lock` locks the password and expires the account, so SSH keys stop
  working too, without deleting anything. Locking or deleting `root` or the
  user komando logs in as needs `--allow-dangerous`: komando could not log
  in afterwards to undo it, and root is the account that repairs a server.
  The same goes for `user add --shell` with a shell nobody can log in with
  (`/usr/sbin/nologin`, `/bin/false`) for those two accounts.
- On Alpine, `user add`, `lock`, `unlock` and `rm` need the `shadow`
  package (`useradd`, `usermod`, `userdel`). Without it they stop with
  `TOOL_MISSING` (exit 3) and the hint `komando pkg install TARGET shadow`.
- `user list` reads the lock state through sudo (`--no-sudo` leaves it
  out). `admin_group` means "in the sudo, wheel or admin group"; rules in
  `sudoers.d` are not read.
- `user rm` needs `--allow-dangerous`; a person at a terminal types the
  server's name instead. Try `--dry-run` first.

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
- `--user root` edits root's crontab.
