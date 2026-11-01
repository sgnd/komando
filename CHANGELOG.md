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
- `komando storage` (alias `s3`) for S3 and S3-compatible storage (MinIO, R2,
  Wasabi, Spaces, B2, Garage): `ls`, `get` (to a file, never overwriting),
  `put`, `rm` (exact keys only), and `link` for temporary download links.
  Keys stay inside the conn's folder.
- `komando policy list` shows the SQL and Redis rules; `komando policy check
  --for KIND` rates a SQL query or Redis command.
- MySQL and MariaDB conns for `komando db`.
- `komando db dump` and `db restore`: backups to and from a file on this
  computer, using pg_dump/psql or mysqldump/mysql on the `--via` server (or
  locally). The password never appears on a command line; files are 0600 and
  never overwritten; restores need `--write --allow-dangerous`.
- `komando config set audit_sql full|hash|off` controls how SQL text is kept
  in the audit log.
- `komando cache` for Redis/Valkey: `get` (any type, with TTL), `keys` (SCAN,
  never KEYS), `info`, `set`, `del`, and `run` for any command, read-only
  unless `--write`. Flushing, blocking and server-reconfiguring commands
  need `--allow-dangerous`.

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
