# Services, logs, Docker, packages, users

Day-to-day server administration, with structured results instead of raw
terminal output. [All docs](README.md)

## Check and restart a service

Most Linux servers start and watch their services with systemd. systemd
calls each service a unit (`nginx`, `php8.2-fpm`).

```bash
komando svc status @web nginx                 # state, main PID, restarts, memory
komando svc restart @web nginx --wait 10s     # fails unless nginx is active within 10s
```

Typed alone at your terminal, `komando svc restart` asks for the server
(from your list), then the services, then how long to wait.

```bash
komando svc list web1 --failed                # or --state running
komando svc enable web1 nginx --now           # enable and start
komando svc stop web1 old-worker
komando svc start web1 worker
komando svc disable web1 old-worker --now     # do not start it at boot, and stop it now
komando svc logs web1 nginx                   # the unit's journal (see Logs)
```

`start`, `stop`, `restart`, `reload`, `enable` and `disable` use sudo and
report the state afterwards (see [Sudo](#sudo)).

- `--wait` takes a time (`10s`, `2m`); a bare number counts as seconds.
- Stopping, disabling or masking the SSH server (`ssh`, `sshd`,
  `ssh.socket`) needs `--allow-dangerous`: it locks you out.

After you write or change a unit file, reload systemd so it reads it:

```bash
komando svc daemon-reload web1                # names any unit that still needs a reload
```

## Logs

`logs` reads one source: the systemd journal (`--unit`), a file (`--file`)
or a Docker container (`--container`).

```bash
komando logs web1 --unit nginx --since 30m --grep 'error|crit'
```

Typed alone, `komando logs` asks for the server, then which log and from
how long ago.

```bash
komando logs web1 --unit nginx --follow                 # keep watching; Ctrl-C to stop
komando logs web1 --unit nginx -p err --since today     # errors and worse
komando logs @web --file /var/log/nginx/error.log -n 50 --sudo
komando logs web1 --container api --since 10m --timestamps
```

`komando svc logs TARGET UNIT` and `komando docker logs TARGET CONTAINER`
read the same as `logs --unit` and `logs --container`. The flags are under
[Reference](#reference).

Without `--sudo`, the journal shows only your own entries, and komando warns
you. A log file that does not exist exits 3.

## Docker

```bash
komando docker ps web1                         # running containers (--all for stopped ones too)
komando docker logs web1 api -n 100
komando docker restart web1 api
```

```bash
komando docker stats web1                      # CPU, memory, network and disk use
komando docker images web1
komando docker inspect web1 api                # a container, image or other object in full
komando docker pull web1 nginx:1.27            # fetch an image
komando docker stop web1 api                   # also: start
komando docker rm web1 old-api --dry-run       # remove a container
komando docker exec web1 api -- php artisan migrate:status
komando docker compose web1 --dir /srv/shop -- up -d --pull always
```

- Reading (`ps`, `stats`, `images`, `inspect`, `logs`) needs nothing extra.
- `start`, `stop`, `restart`, `pull`, `compose up` and a `docker run`
  through `docker raw` change things, so a protected server asks first.
- `rm`, `prune`, `compose down -v` and other deletes delete for good: at
  your terminal komando asks you to type the server's name; an AI agent or
  a script adds `--allow-dangerous` after a person agrees
  ([Safety](safety.md)).
- `docker exec` passes the command's words as written, with no shell, so
  the image needs no `sh`. For pipes or `&&`, write the shell yourself:
  `-- sh -c 'ls /data | wc -l'`. Add `--read-only` when it only looks; it
  is checked as for `exec`, so on a protected server only commands komando
  knows read skip the question.
- `docker raw TARGET -- ARGS...` runs any other docker subcommand, under the
  same rules.
- `--sudo` runs docker through sudo, when your user is not in the `docker`
  group.

### Free disk space (docker prune)

```bash
komando docker prune web1 --dry-run                          # what would go, with sizes and a total
komando docker prune web1 --older-than 30d --all --dry-run   # also unused tagged images, older than 30 days
komando docker prune web1 --older-than 30d                   # do it (asks you to type web1)
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
- The real run deletes, so it is confirmed like `docker rm`.

## Packages

`pkg` works with apt, dnf, yum, apk, zypper and pacman; komando finds out
which one each server uses.

```bash
komando pkg upgradable all --refresh            # refresh the package index first
komando pkg install @web htop
```

Typed alone, `komando pkg install` asks for the server, then the packages.

```bash
komando pkg rm web1 htop
komando pkg installed web1 nginx openssl        # installed versions (all without names)
komando pkg upgrade web1 --dry-run              # what would be upgraded
komando pkg upgrade web1                        # everything, or name the packages
komando pkg update web1                         # only refresh the package index
```

- `install` and `rm` report what changed (`changed: false` when there was
  nothing to do). An unknown package exits 3 (`PACKAGE_NOT_FOUND`).
- `upgradable` says how old the package index is, and suggests `--refresh`
  when it is more than a day old.
- Removing packages a server needs (openssh-server, sudo, systemd, libc
  and the like) needs `--allow-dangerous`, however the name is written
  (`openssh-server:amd64`, `sudo.x86_64`, `openssh.server`). On apt
  servers, removing a package that would take one of them with it
  (`libssl3` takes openssh-server) stops with `POLICY_BLOCKED` before
  anything is removed.
- Package names are exact names: no options, patterns or a trailing `-`.
  For a local `.deb` or `.rpm`, use `komando upload` and `komando exec`.

### Security updates

`pkg security` and `pkg upgrade --security` handle a patch round: only
security updates, one server at a time, with a look at each server before
and after.

```bash
komando pkg security @web --refresh              # what is pending, and each server's state
komando pkg upgrade @web --security --dry-run    # the plan, and any stop it would hit
komando pkg upgrade @web --security              # patch, one server at a time
komando pkg upgrade @web --security --keep-going # do not stop at a server that changed
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
- It is a change like `pkg upgrade`: a protected server asks first. An
  update that would remove an essential package stops with
  `POLICY_BLOCKED` before anything changes (apt servers).
- A stale package index hides new fixes: komando warns when it is more than
  a day old; add `--refresh`.

## Reboot

```bash
komando reboot web1 --dry-run                 # what would run, and whether it would be blocked
komando reboot @web                           # one server at a time; asks you to type how many
komando reboot @web --wait 10m
```

`komando reboot` restarts one server at a time. For each server it asks
for a reboot (`systemctl reboot`, through sudo), waits until SSH answers
again, and checks that the server really started anew (a new boot ID).
Only then does it go on to the next server.

- `--wait` is how long each server may take to come back (default 5m).
- A server that does not come back in time stops the rest with
  `REBOOT_TIMEOUT` (exit 7). Any other failure stops the rest too. The
  servers after it are listed in `not_rebooted`.
- A reboot is destructive: at your terminal komando asks you to type the
  server's name (several: how many); an AI agent or a script adds
  `--allow-dangerous` after a person agrees.

## Users

```bash
komando user list web1                       # NAME UID HOME SHELL ADMIN GROUP LOCKED
komando user add web1 alice --key alice --admin
```

Typed alone, `komando user add` asks for the server, then the user name.

```bash
komando user list web1 --all                 # include system accounts
komando user add @web app --pubkey 'ssh-ed25519 AAAA... app@example.com' --shell /bin/sh
komando user lock web1 alice                 # SSH keys stop working too
komando user unlock web1 alice
komando user rm web1 alice --remove-home --dry-run
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
- `user list` reads the lock state through sudo (`--no-sudo` leaves it
  out). `admin_group` means "in the sudo, wheel or admin group"; rules in
  `sudoers.d` are not read.
- `user rm` deletes for good: at your terminal komando asks you to type the
  server's name; an AI agent or a script adds `--allow-dangerous` after a
  person agrees. Try `--dry-run` first.

## Scheduled jobs (cron)

komando manages crontab entries by an ID you choose. `cron set` with the
same ID replaces the entry instead of adding a second one, and other lines
in the crontab are kept as they are.

```bash
komando cron set db1 nightly-backup '/usr/local/bin/backup.sh >> /var/log/backup.log 2>&1' --schedule '0 2 * * *'
komando cron list db1
```

Typed alone, `komando cron set` asks for the server, the ID, the command
and the schedule.

```bash
komando cron set @web clean-tmp 'find /tmp -mtime +7 -delete' --schedule @daily
komando cron rm db1 nightly-backup           # data: {"removed": 1}
komando cron list db1 --user www-data        # another user's crontab (uses sudo)
komando cron list db1 --user root            # root's crontab
```

- IDs use letters, digits, `-` and `_`.
- `--schedule` takes five fields (`'*/5 * * * *'`) or `@hourly`, `@daily`,
  `@weekly`, `@monthly`, `@yearly`, `@reboot`. It is checked before anything
  is written.
- `%` in the command is escaped for you.

## Sudo

Commands that change something use sudo unless you add `--no-sudo` (`svc`,
`pkg`, `user`, `reboot`, `recipe run`): add it when you log in as root.
Commands that read use sudo only when you ask: `--sudo` for `logs`,
`docker` and `net ports`, `--user` for another user's crontab.

When sudo wants a password komando does not have, or the login user may not
use sudo, the command stops with `PERMISSION_DENIED` and a hint that names
the fix (`komando host edit web1 --sudo-ref secret:web1-sudo`, see
[Sudo passwords](servers.md#sudo-passwords-and-the-vault)). A server with
no sudo at all gives `TOOL_MISSING` (add `--no-sudo` as root). The same
holds for `pkg`, `user`, `cron --user`, the `docker` commands that change
something with `--sudo`, and recipes that use sudo.

## Whole jobs, step by step

Every step is a command; a person and an AI agent type the same ones.

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

## Limits

- `svc` works on system services only: komando does not manage a user's
  own units (`systemctl --user`); use `komando exec` for those.
- `svc` and `logs --unit` need systemd; a server without it (most
  containers) stops with `NO_SYSTEMD`.
- `--since today` and `--since yesterday` do not work for containers.
- On apt servers only, `pkg rm` and `pkg upgrade --security` check whether
  an essential package would go with another one; other package managers
  are not checked this way.
- `pkg security` lists nothing on dnf/yum for repositories without security
  notices (for example CentOS). apk, zypper and pacman servers are listed
  in `meta.skipped`: use `pkg upgrade` there.
- `pkg` takes exact package names only; for a local `.deb` or `.rpm`, use
  `upload` and `exec`.
- `docker prune --volumes` cannot be combined with `--older-than`.
- komando never reboots as part of a patch round.
- On Alpine, `user add`, `lock`, `unlock` and `rm` need the `shadow`
  package (`useradd`, `usermod`, `userdel`).
- `user list` does not read rules in `sudoers.d`.
- `svc logs` does not take `--file` or `--container`; use `logs`.

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `UNIT_NOT_FOUND` | no service of that name (exit 3) | check the name with `komando svc list TARGET` |
| `NO_SYSTEMD` | the server runs without systemd (exit 3) | read its logs with `--file` or `komando docker logs` |
| `PERMISSION_DENIED` | sudo wants a password komando does not have, or the user may not use sudo | store the sudo password: `komando host edit SERVER --sudo-ref secret:NAME` |
| `TOOL_MISSING` | sudo, or a tool the command needs, is not installed (exit 3) | as root add `--no-sudo`; on Alpine, `komando pkg install TARGET shadow` for `user` |
| `PACKAGE_NOT_FOUND` | no such package in the server's package index | check the name; `komando pkg update TARGET` if the package is new |
| `UNEXPECTED_CHANGE` | a server changed after patching (exit 8); the rest were not patched | check it with `komando docker ps` and `komando svc list --failed`, then run again or add `--keep-going` |
| `REBOOT_TIMEOUT` | a server did not come back within `--wait` (exit 7) | check the server's console; the servers after it were not rebooted |
| `TIMEOUT` | a `--security` upgrade ran longer than `--timeout`; it goes on | run `komando pkg security` later to see what is left |
| `POLICY_BLOCKED` | a delete, a reboot or removing an essential package without `--allow-dangerous` | check with `--dry-run`, ask a person, then add `--allow-dangerous` |

## Reference

`logs` flags (also for `svc logs` and `docker logs`, where they fit):

| Flag | What it does |
|------|--------------|
| `-u`, `--unit UNIT` | Read the systemd journal of this service. |
| `--file PATH` | Read this log file. |
| `-c`, `--container NAME` | Read this Docker container's log. |
| `-n`, `--limit N` | The last N lines (default 200). |
| `--grep REGEX` | Only lines that match (extended regex, any case). |
| `--since` / `--until` | A time range: a time back from now (`30m`, `2h`, `7d`), `today`, `yesterday`, or a date (`'2026-01-02 10:00'`). Containers take no `today` or `yesterday`. |
| `-p`, `--priority` | Journal priority and worse: `emerg` to `debug`, or 0-7. |
| `-f`, `--follow` | Keep printing new lines until Ctrl-C. |
| `-s`, `--sudo` | Read the whole journal or a protected file. |
| `--timestamps` | Show when each container log line was written (with `--container` only; journal lines have their time already). |
