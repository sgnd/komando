# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org).

## [Unreleased]

- `komando conn`: an inventory of databases (PostgreSQL, MySQL, SQLite) next
  to hosts. Add, edit, list, show, remove and test them; reach private ones
  through a host with `--via`. Passwords are refused in URLs and live in the
  vault. First step toward `komando db` (see `docs/design/resources-and-db.md`).
- Hosts and conns share one name space. Removing a host that a conn uses
  with `--via` is refused (`HOST_IN_USE`); renaming a host updates its conns.
- `komando audit --host` also matches conn names.
- `komando db query/schema/explain` for PostgreSQL and SQLite. Read-only by
  default (the database enforces it); `--write` to change data, `--write
  --dry-run` to try it and roll back. Destructive SQL (DROP, TRUNCATE,
  DELETE/UPDATE without WHERE, ...) needs `--allow-dangerous`; protected
  conns need `--yes`. Results are structured rows, safe for JSON.
- `komando policy list` shows the SQL rules; `komando policy check --sql KIND`
  classifies a query.

## [0.1.0]

First release.

- Server list with groups, tags, labels, jump hosts and `~/.ssh/config` import
- SSH keys and an encrypted password vault
- Run commands and scripts on many servers in parallel; long-running jobs
- Safe file reading and editing, upload and download
- Background tunnels (local, remote, SOCKS)
- Health checks and 39 ready-made recipes; services, logs, Docker, packages, network, users, cron
- Safety: dangerous-command filter, protected servers, dry run, server identity check, audit log
- Readable text in a terminal, JSON for AI agents
