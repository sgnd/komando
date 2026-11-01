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

## Long tasks

Anything slow (backups, upgrades, builds) runs as a *job* that keeps going
on the server even if you disconnect:

```bash
komando job start db1 -- 'pg_dump app | gzip > /backup/app.sql.gz'
komando job status <id>
komando job logs <id>
komando job wait <id>
komando job kill <id>
komando job list
```

## Saved commands (snippets)

Save a command once and reuse it. `{{app}}` is a blank you fill in with
`--var app=...`. komando treats a snippet as a change, so protected servers
ask for `--yes`, unless you save it with `--read-only` because it only looks.

```bash
komando snippet add restart-app 'systemctl restart {{app}}' --sudo
komando snippet add disk 'df -h {{path=/}}' --read-only
komando snippet run restart-app @web --var app=shop
```
