# Services, logs, Docker, packages, users

Day-to-day server administration. [All features](README.md)

## Services, logs, Docker, packages

```bash
komando svc status @web nginx
komando svc restart @web nginx --wait 10     # fails unless nginx is active within 10s
komando svc enable web1 nginx --now          # enable and start
komando svc list web1 --failed

komando logs web1 --unit nginx --since -30m --grep 'error|crit'
komando logs web1 --file /var/log/syslog -n 100 --sudo
komando logs web1 --unit nginx --follow       # keep watching; Ctrl-C to stop

komando docker ps web1
komando logs web1 --container api --since 10m
komando docker compose web1 --dir /srv/shop -- up -d

komando pkg install @web htop
komando pkg upgradable all --refresh         # refresh the package index first
komando pkg upgrade web1 --dry-run           # what would be upgraded
```

- `svc status` exits 3 with `UNIT_NOT_FOUND` for a unit that does not exist,
  and with `NO_SYSTEMD` on a server without systemd (most containers); read
  those servers' logs with `--file` or `komando docker logs`.
- `logs` takes one source: `--unit` (journal), `--file` or `--container`.
  `--since`/`--until` work with the journal and containers; a missing file
  exits 3. Without `--sudo` the journal shows only your own entries, and
  komando warns about it.
- `pkg` works with apt, dnf, yum, apk, zypper and pacman automatically.
  `install` and `rm` report what changed (`changed: false` when there was
  nothing to do); an unknown package exits 3 (`PACKAGE_NOT_FOUND`).
  `upgradable` says how old the package index is and suggests `--refresh`
  when it is more than a day old. Removing packages a server needs
  (openssh-server, sudo, systemd, libc ...) needs `--allow-dangerous`.

## Users and scheduled jobs

```bash
komando user list web1                       # NAME UID HOME SHELL ADMIN-GROUP LOCKED
komando user add @web deploy --key deploy --admin
komando user lock web1 leaver                # SSH keys stop working too; user unlock undoes it
komando cron set db1 nightly-backup '/usr/local/bin/backup.sh' --schedule '0 2 * * *'
komando cron list db1
komando cron rm db1 nightly-backup           # data: {"removed": 1}
```

`user list` reads the lock state through sudo (`--no-sudo` leaves it out);
`admin_group` means "in the sudo, wheel or admin group" (rules in
sudoers.d are not read). Cron IDs are letters, digits, `-` and `_`; the
schedule is checked before anything is written, and `%` is escaped for you.
