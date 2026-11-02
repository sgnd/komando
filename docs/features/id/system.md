# Service, log, Docker, paket, user

Administrasi server sehari-hari. [Semua fitur](README.md)

## Service, log, Docker, paket

```bash
komando svc status @web nginx
komando svc restart web1 nginx
komando svc list web1 --failed

komando logs web1 --unit nginx --since -30m --grep 'error|crit'
komando logs web1 --file /var/log/syslog -n 100 --sudo
komando logs web1 --unit nginx --follow       # terus pantau; Ctrl-C untuk berhenti

komando docker ps web1
komando logs web1 --container api --since 10m
komando docker compose web1 --dir /srv/shop -- up -d

komando pkg install @web htop
komando pkg upgradable all
```

`pkg` otomatis bekerja dengan apt, dnf, yum, apk, zypper, dan pacman.

## User dan jadwal

```bash
komando user list web1
komando user add @web deploy --key deploy --admin
komando cron set db1 nightly-backup '/usr/local/bin/backup.sh' --schedule '0 2 * * *'
komando cron list db1
komando cron rm db1 nightly-backup
```
