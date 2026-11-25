# Services, logs, Docker, packages, users

Day-to-day server administration through `komando host ssh exec`. There is
one command for it: you write the server's own tool (`systemctl`,
`journalctl`, `docker`, `apt-get`, `useradd`, `crontab`), and komando runs
it, checks it against its safety rules and records it. [All docs](README.md)

```bash
komando host ssh exec TARGET [--read-only] [--sudo] -- COMMAND
```

- The command's words go after `--`; komando's own flags go before it.
  Without `--` the run stops with `USAGE`. Write `-- apt-get install -y
  nginx`, not `apt-get install -y nginx`.
- `--read-only` declares a command that only reads. komando checks that it
  does and refuses anything else with `READ_ONLY_VIOLATION`. Without it, a
  command counts as a change.
- `exec` always runs in a session on the server and prints its session ID.
  If the connection drops, the run goes on: come back with
  `komando host ssh exec TARGET --attach ID` (see [Long
  runs](#long-runs)).
- Add `--dry-run` first to see the plan and any stop the real run would
  hit. A dry run never changes anything.
- A rule on the command's text stops the dangerous forms, whichever tool
  you use: deleting files, removing or pruning Docker data, killing a
  container, removing an essential package, stopping sshd, deleting a
  user and rebooting. Each needs `--allow-dangerous` after a person agrees
  ([Safety](safety.md)).

## Check and restart a service

Most Linux servers start and watch their services with systemd. systemd
calls each service a unit (`nginx`, `php8.2-fpm`).

```bash
komando host ssh exec @web --read-only -- systemctl status nginx      # state, main PID, restarts, memory
komando host ssh exec @web --sudo -- systemctl restart nginx          # then check that it is active
```

Typed alone at your terminal, `komando host ssh exec` asks for the server
(from your list), then the command.

```bash
komando host ssh exec web1 --read-only -- systemctl list-units --type=service --failed
komando host ssh exec web1 --sudo -- systemctl enable --now nginx     # enable and start
komando host ssh exec web1 --sudo -- systemctl stop old-worker
komando host ssh exec web1 --sudo -- systemctl start worker
komando host ssh exec web1 --sudo -- systemctl disable --now old-worker   # not at boot, and stop it now
komando host ssh exec web1 --read-only -- journalctl -u nginx -n 100 --no-pager   # the unit's journal (see Logs)
```

`start`, `stop`, `restart`, `reload`, `enable` and `disable` change the
server, so they need `--sudo` and a protected server asks first. To check
that a restart worked, run `systemctl is-active nginx` afterwards: it exits
non-zero unless the unit is active.

Stopping, disabling or masking the SSH server (`ssh`, `sshd`,
`ssh.socket`) needs `--allow-dangerous`: it locks you out.

After you write or change a unit file, reload systemd so it reads it:

```bash
komando host ssh exec web1 --sudo -- systemctl daemon-reload
```

A user's own units (`systemctl --user`) run as the login user, without
sudo:

```bash
komando host ssh exec web1 --read-only -- systemctl --user list-units
komando host ssh exec web1 -- systemctl --user restart syncthing
```

A user's manager runs only while they are logged in, unless lingering is
on. A person with sudo turns lingering on once: `loginctl enable-linger
USER` on the server.

Lost: the structured service results (state, PID, restarts, memory as
fields) and the wait that failed unless the unit was active in time.
`exec` returns the tool's own text and exit code.

## Logs

Read one source: the systemd journal, a file or a Docker container.

```bash
komando host ssh exec web1 --read-only --sudo -- journalctl -u nginx --since -30m --no-pager -g 'error|crit'
```

```bash
komando host ssh exec web1 --read-only --sudo -- journalctl -u nginx -f             # keep watching; Ctrl-C to stop
komando host ssh exec web1 --read-only --sudo -- journalctl -u nginx -p err --since today --no-pager
komando host ssh exec @web --read-only --sudo -- tail -n 50 /var/log/nginx/error.log
komando host ssh exec web1 --read-only -- docker logs --since 10m --timestamps api
```

Without `--sudo`, the journal shows only your own entries. A log file that
does not exist makes the tool fail with its own exit code.

TODO(cut): whether `journalctl -f`, `tail -f` and `docker logs -f` run
under `--read-only` waits on the read-only allowlist (`readonly.go`).

## Docker

```bash
komando host ssh exec web1 --read-only -- docker ps                  # running containers (-a for stopped ones too)
komando host ssh exec web1 --read-only -- docker logs --tail 100 api
komando host ssh exec web1 -- docker restart api
```

```bash
komando host ssh exec web1 --read-only -- docker stats --no-stream   # CPU, memory, network and disk use
komando host ssh exec web1 --read-only -- docker images
komando host ssh exec web1 --read-only -- docker inspect api         # a container, image or other object in full
komando host ssh exec web1 -- docker pull nginx:1.27                 # fetch an image
komando host ssh exec web1 -- docker stop api                        # also: start
komando host ssh exec web1 --dry-run -- docker rm old-api            # remove a container
komando host ssh exec web1 -- docker exec api php artisan migrate:status
komando host ssh exec web1 -C /srv/shop -- docker compose up -d --pull always
```

- Reading (`ps`, `stats`, `images`, `inspect`, `logs`) needs nothing extra
  when you add `--read-only`.
- `start`, `stop`, `restart`, `pull`, `compose up` and `docker run` change
  things, so a protected server asks first.
- `docker rm`, `docker prune`, `docker kill` and `docker compose down -v`
  delete or kill for good: at your terminal komando asks you to type the
  server's name; an AI agent or a script adds `--allow-dangerous` after a
  person agrees ([Safety](safety.md)). A `docker run` that gives the
  container the server (privileged, the host's network or processes, a
  bind of `/` or the docker socket) is stopped too.
- `docker exec` passes the command's words as written, with no shell, so
  the image needs no `sh`. For pipes or `&&`, write the shell yourself:
  `docker exec api sh -c 'ls /data | wc -l'`. A shell in a container
  (`docker exec ... sh`) is stopped by its own rule.
- `--sudo` runs docker through sudo, when your user is not in the `docker`
  group.
- `--dir` (`-C`) is the working folder, for `docker compose` in the
  project's folder.

TODO(cut): whether komando still reads the compose file on the server
before `compose up` (the compose-file reader, `execComposeReason`) and what
it stops waits on the exec rules pull request (#464).

### Free disk space (docker prune)

```bash
komando host ssh exec web1 --read-only -- docker system df              # what Docker uses, and what can be freed
komando host ssh exec web1 --dry-run -- docker system prune --filter until=720h --all
komando host ssh exec web1 -- docker system prune --filter until=720h --all   # asks you to type web1
```

`docker system prune` removes stopped containers, dangling images, unused
networks and build cache.

- `--dry-run` shows the plan and the stop the real run would hit. It does
  not ask docker what would go.
- `--filter until=720h` keeps everything created in the last 30 days.
- `--all` removes every image no container uses, not only dangling ones;
  the next deploy pulls them again.
- `--volumes` also removes unused anonymous volumes. That is data: look at
  `docker system df -v` first.
- The real run deletes, so a prune is confirmed like `docker rm`.

Lost: the dry run that listed every container, image and volume with sizes
and a total, the per-volume age filter and the `volumes_removed` list.

## Packages

Use the server's own package tool (apt, dnf, yum, apk, zypper or pacman).
`command -v apt-get dnf yum apk zypper pacman` shows which one a server has.

```bash
komando host ssh exec @web --sudo -- apt-get update                    # refresh the package index
komando host ssh exec @web --read-only -- apt list --upgradable
komando host ssh exec @web --sudo -- apt-get install -y htop
```

Typed alone, `komando host ssh exec` asks for the server, then the command.

```bash
komando host ssh exec web1 --read-only -- dpkg -l nginx openssl         # installed versions
komando host ssh exec web1 --sudo -- apt-get -s upgrade                 # what would be upgraded (a simulation)
komando host ssh exec web1 --sudo -- apt-get upgrade -y                 # everything
komando host ssh exec web1 --sudo -- apt-get remove -y htop
```

- Write the tool's own non-interactive flag (`-y`) after `--`. It is
  never read as komando's `--yes`.
- Removing packages a server needs (openssh-server, sudo, systemd, libc
  and the like) needs `--allow-dangerous`, however the name is written
  (`openssh-server:amd64`, `sudo.x86_64`). Removing an ordinary package
  is a change, and a protected server asks first.
- Package names are exact names: no options, patterns or a trailing `-`.
  For a local `.deb` or `.rpm`, use `komando copy` and `exec`.
- `apt-get update` rewrites the server's package index as root, so it is a
  change. A dry run never runs it.
- A stale package index hides new fixes: run `apt-get update` first.
- Lost: `pkg installed`, `pkg upgradable` and its index age and refresh
  advice, `pkg install` and `pkg rm` with their `changed` result. Read the
  tool's text instead.

### Security updates

A patch round is: look at what is pending, simulate, patch one server at a
time, check each server before and after.

```bash
komando host ssh exec @web --sudo -- apt-get update
komando host ssh exec @web --read-only -- apt list --upgradable         # what is pending
komando host ssh exec web1 --sudo -- apt-get -s upgrade                 # simulate: stop if it would remove an essential package
komando host ssh exec web1 --sudo -- unattended-upgrade -v              # only security updates, when it is installed
komando host ssh exec web1 --read-only -- sh -c 'test -f /var/run/reboot-required && echo reboot required'
```

- Simulate first (`apt-get -s upgrade`) and stop when the simulation would
  remove an essential package. The essential-package rule reads a `remove`
  command; it cannot see what an upgrade would remove, so the simulation
  is how you see it coming.
- Patch one server at a time, not `@web` at once, and check each server
  (`docker ps`, `systemctl --failed`) before the next one.
- On dnf and yum, `dnf upgrade --security`; on zypper, `zypper patch
  --category security`. apk and pacman have no way to pick only security
  updates: pacman supports no partial upgrades.
- The upgrade runs in a session on the server, so a dropped connection
  does not break it halfway. Come back with `--attach ID`.
- komando never reboots as part of a patch round. Reboot after the round
  ([Reboot](#reboot)).
- A ready-made snippet is planned for the whole round (simulate, stop on
  an essential package, upgrade). `pkg-upgrade-all` upgrades every package
  and reports `changed`.

TODO(cut): the snippet for a security upgrade (C335) and the rule for
`dist-upgrade`, `full-upgrade` and `autoremove` (C362) wait on their rows;
write the snippet's name here when they land.

## Reboot

```bash
komando host ssh exec web1 --dry-run --sudo -- systemctl reboot   # what would run, and whether it would be blocked
komando host ssh exec web1 --sudo -- systemctl reboot             # asks you to type web1
```

A reboot is destructive. The power rules stop it: at your terminal komando asks you
to type the server's name; an AI agent or a script adds `--allow-dangerous`
after a person agrees. Reboot only with a person's yes.

Lost: rebooting a group one server at a time and checking the boot ID of
each before the next. Reboot servers one by one, and check that each
came back:

```bash
komando test web1                                  # logs in again once the server is up
komando host ssh exec web1 --read-only -- cat /proc/sys/kernel/random/boot_id   # a new value means a new boot
```

The result no longer has `back_after`: an app measures it by calling
`test` until the server answers.

## Users

```bash
komando host ssh exec web1 --read-only -- getent passwd              # accounts
komando host ssh exec web1 --sudo -- useradd -m -s /bin/bash -G sudo alice
```

Typed alone, `komando host ssh exec` asks for the server, then the command.

```bash
komando host ssh exec web1 --read-only --sudo -- passwd -S alice     # lock state
komando host ssh exec web1 --sudo -- usermod -L -e 1 alice           # lock the password and expire the account
komando host ssh exec web1 --sudo -- usermod -U -e '' alice          # unlock
komando host ssh exec web1 --dry-run --sudo -- userdel -r alice
```

- Put a key on a user with `komando credential key install web1 --user
  alice --public-key-file FILE`; that is a person's step, never an agent's.
- `usermod -L -e 1` locks the password and expires the account, so SSH keys
  stop working too, without deleting anything. On Debian, the admin group
  is `sudo`; on RHEL and Alpine it is `wheel`.
- `userdel` deletes for good: it is stopped by the `userdel` rule, so at
  your terminal komando asks you to type the server's name; an AI agent or
  a script adds `--allow-dangerous` after a person agrees. Try `--dry-run`
  first.
- Lost: `user add` as one idempotent step, and the list with the ADMIN and
  LOCKED columns. `user list` does not read rules in `sudoers.d`.

## Scheduled jobs (cron)

Use `crontab` on the server. komando no longer keeps entries by an ID.

```bash
komando host ssh exec db1 --read-only -- crontab -l
komando host ssh exec db1 -- sh -c '(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1") | crontab -'
komando host ssh exec db1 --read-only --sudo -- crontab -l -u www-data    # another user's crontab
```

- Change a crontab as a whole: read it, change the text, write it back.
  `crontab -r` removes every entry and is stopped by a rule
  (`--allow-dangerous`); removing one line is a change.
- Escape `%` in the command as `\%`.
- Lost: setting and removing one entry by an ID, and the check of the
  schedule before it is written. A ready-made snippet for cron entries is
  planned.

TODO(cut): the name of the ready-made cron snippet waits on the row that
adds it.

## Sudo

`exec` runs as the login user. Add `--sudo` to run as root, or
`--sudo-user NAME` to run as that user with `sudo -u`. A command that
changes the system usually needs it; a command that reads needs it only for
files and logs the login user cannot read.

When sudo wants a password komando does not have, or the login user may not
use sudo, the command stops with `PERMISSION_DENIED` and a hint that names
the fix (`komando host ssh edit web1 --sudo-credential web1-sudo`, see
[Sudo passwords](servers.md#sudo-passwords-and-the-vault)). A server with
no sudo at all gives `TOOL_MISSING`: log in as root and leave out `--sudo`.

## Long runs

Every `exec` runs in a session on the server, so a long package upgrade or
a large copy survives a dropped connection. The first call prints the
session ID.

```bash
komando host ssh exec web1 --sudo -- apt-get upgrade -y        # prints the session ID first
komando host ssh exec web1 --attach ID                         # stream the output and get the exit code
komando host ssh exec web1 --attach ID --offset 4096           # read from an offset
komando host ssh exec web1 --attach ID --stop                  # end the run
komando host ssh exec web1 --attach ID --remove                # remove its log on the server
```

- `--attach` only reads: the approval of the first call covers it.
- A run that outlasts an agent's tool timeout comes back as "still
  running" with its ID. TODO(cut): the wait limit and the exit code for it
  wait on C324.
- `CONNECTION_LOST` (exit 4) means the link broke while the command ran:
  attach before you run it again.
- A single-host result has no separate stderr: a session merges stdout and
  stderr into one output.

## Whole jobs, step by step

Every step is a command; a person and an AI agent type the same ones.

```bash
# a service misbehaves
komando host ssh exec web1 --read-only -- systemctl list-units --failed         # what is broken?
komando host ssh exec web1 --read-only --sudo -- journalctl -u nginx --since -30m --no-pager -g error
komando host ssh exec web1 --sudo -- cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
komando host ssh exec web1 --sudo -- sed -i 's/worker_connections 768;/worker_connections 4096;/' /etc/nginx/nginx.conf
komando host ssh exec web1 --read-only --sudo -- grep worker_connections /etc/nginx/nginx.conf
komando host ssh exec web1 --dry-run --sudo -- systemctl restart nginx
komando host ssh exec web1 --sudo -- systemctl restart nginx

# a patch round
komando host ssh exec @web --read-only -- apt list --upgradable
komando host ssh exec web1 --sudo -- apt-get -s upgrade                         # simulate
komando host ssh exec web1 --sudo -- apt-get upgrade -y                         # one server at a time
komando host ssh exec web1 --dry-run --sudo -- systemctl reboot                 # when it says reboot required

# a person joins, then leaves
komando host ssh exec web1 --sudo -- useradd -m alice
komando host ssh exec web1 --sudo -- usermod -L -e 1 alice                      # stops logins, keeps the files
komando host ssh exec web1 --dry-run --sudo -- userdel -r alice

# a nightly job
komando host ssh exec db1 -- sh -c '(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/backup.sh") | crontab -'
komando host ssh exec db1 --read-only -- crontab -l

# a full disk on a Docker server
komando snippet exec disk web1
komando host ssh exec web1 --dry-run -- docker system prune --filter until=720h
```

## Limits

- Lost: editing a config file with validation, a backup and an undo. Copy
  the file first (`cp FILE FILE.bak`), change it with one targeted command,
  read it back. Never use `sed -i` without that copy. A ready-made change
  snippet is planned.
- `systemctl` and `journalctl` need systemd; a server without it (most
  containers) answers with the tool's own error.
- The essential-package rule reads the text of a remove command. It does
  not see what an upgrade would remove: simulate first.
- `exec` takes exact names; there is no pattern matching of package names.
- komando never reboots as part of a patch round.
- On Alpine, user management needs the `shadow` package (`useradd`,
  `usermod`, `userdel`).
- The structured results, the `--wait` of a restart and the per-server
  `not_run` lists are gone; every result is the tool's text and exit code.

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `USAGE` | words after the target without `--` | put `--` before the command: `komando host ssh exec web1 -- apt-get install -y nginx` |
| `PERMISSION_DENIED` | sudo wants a password komando does not have, or the user may not use sudo | store the sudo password: `komando host ssh edit SERVER --sudo-credential NAME` |
| `TOOL_MISSING` | sudo, or a tool the command needs, is not installed (exit 3) | as root leave out `--sudo`; on Alpine, `komando host ssh exec TARGET --sudo -- apk add shadow` for users |
| `READ_ONLY_VIOLATION` | `--read-only` does not know that the command only reads | check the command, then run it without `--read-only`; a protected server asks first |
| `CONNECTION_LOST` | the link broke while the command ran (exit 4) | attach before you run it again: `komando host ssh exec TARGET --attach ID` |
| `POLICY_BLOCKED` | a delete, a reboot, stopping sshd or removing an essential package without `--allow-dangerous` | check with `--dry-run`, ask a person, then add `--allow-dangerous` |
| `PROTECTED_TARGET` | a change on a protected server | at your terminal komando asks first; a script adds `--yes` |

## Reference

Flags of `komando host ssh exec` used on this page:

| Flag | What it does |
|------|--------------|
| `--read-only` | The command only reads. komando checks it and refuses anything else. |
| `-s`, `--sudo` | Run it as root through sudo. |
| `--sudo-user USER` | Run it as this user with `sudo -u`. |
| `-C`, `--dir PATH` | The working folder. |
| `-e`, `--env KEY=VALUE` | An environment variable, repeatable. |
| `--attach ID` | Come back to a session: stream its output and get its exit code. |
| `--offset N` | With `--attach`: read the output from this offset. |
| `--stop`, `--signal` | With `--attach`: end the run; `--signal` names the signal (default `TERM`). |
| `--remove` | With `--attach`: remove the session's log on the server. |
| `-P`, `--parallel` | How many servers at once (global). |
| `--fail-fast` | Stop at the first server that fails. |
| `--dry-run` | Show the plan and the stop the real run would hit; change nothing. |
