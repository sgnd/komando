# Databases

Add databases and query, back up and restore them safely. [All features](README.md)

## Databases (conns)

A **conn** is a database, cache or storage bucket komando knows about, the
way a host is a server you know about. The kind comes from the start of the
URL:

| Kind       | URL example |
|------------|-------------|
| PostgreSQL | `postgres://app@10.0.0.5:5432/app?sslmode=require` |
| MySQL / MariaDB | `mysql://shop@db.internal:3306/shop?tls=true` |
| SQLite     | `sqlite:///var/lib/app.db` (a file on this computer) |
| Redis / Valkey | `redis://default@cache.internal:6379/0` (`rediss://` for TLS) |
| S3 and compatible (MinIO, R2, Wasabi, ...) | `s3://ACCESS_KEY_ID@my-bucket/backups?endpoint=https://minio.internal:9000&region=us-east-1` |

For S3 the user part is the access key ID; the secret key goes in the vault
like a password (`--password-ref secret:NAME`). Leave out `endpoint` for AWS.

Run `komando conn kinds` to see them all.

Never put the password in the URL; komando refuses it. Store it in the vault
instead:

```bash
komando secret set prod-db-pass
komando conn add prod-db postgres://app@10.0.0.5:5432/app \
  --via web1 --password-ref secret:prod-db-pass --protected
```

`--via web1` means "the database is only reachable from web1". komando
connects through web1 over SSH by itself: no tunnel to start, no port opened
on your computer.

```bash
komando list kind:conn                     # all conns
komando test kind:conn                 # reachable? does the password reference work?
komando conn edit prod-db --add-tag critical
komando conn rm old-db                # only forgets it; the database is untouched
```

Conns use the same targets as servers (`@group`, `tag:prod`, `*-db`, `all`)
and share their names: a host and a conn cannot both be called `db1` (or
`DB1`: names ignore upper and lower case). A host
that a conn uses with `--via` cannot be removed until the conn is changed.

## Query a database

`komando db` runs SQL on a conn. **It does not change your data unless you
add `--write`**: without it, the query runs in a read-only transaction and
the database itself refuses changes. A few admin functions that a read-only
transaction does not stop (ending sessions, reading server files, `dblink`)
are blocked by komando's own checks. These checks catch mistakes; for real
limits, give komando a database user with only the rights it needs.

```bash
komando db schema prod-db                     # what tables are there?
komando db schema prod-db users               # columns, types, indexes of one table
komando db query prod-db "select id, email from users order by id desc limit 10"
komando db explain prod-db "select * from orders where user_id = 42"
```

Use `--arg` for values instead of pasting them into the SQL (`$1`, `$2` in
PostgreSQL; `?` in MySQL and SQLite):

```bash
komando db query prod-db "select * from users where email = $1" --arg bob@example.com
```

**Changing data** takes two steps. First a dry run: the SQL really runs, you
see how many rows it touches, then everything is rolled back.

```bash
komando db query prod-db --write --dry-run "update users set plan = 'pro' where id = 42"
komando db query prod-db --write "update users set plan = 'pro' where id = 42"
```

Seatbelts:

- A protected conn also needs `--yes` for `--write`.
- Destructive SQL needs `--allow-dangerous`: `DROP`, `TRUNCATE`, `DELETE` or
  `UPDATE` without `WHERE`, privilege changes, and a few more
  (`komando policy list` shows them; `komando policy check --for postgres "..."`
  tests a query).
- `BEGIN`/`COMMIT` are refused: komando runs everything in one transaction.
- A few statements cannot be rolled back (`VACUUM`, `CREATE INDEX
  CONCURRENTLY`, MySQL DDL). They must be sent alone, and a dry run only
  reports them.
- Queries stop after 30 seconds (`--timeout 2m` for more) and return at most
  500 rows (`--limit`).

SQL from a file: `komando db query prod-db --file report.sql` (`--file -`
reads stdin).

### Backups

```bash
komando db dump prod-db --to prod-2026-11-02.sql.gz      # backup to a file on this computer
komando db restore staging-db --from prod-2026-11-02.sql.gz --allow-dangerous
```

- The backup file always lands on **this computer**, readable only by you.
  An existing file is never overwritten.
- komando uses the database's own tools: `pg_dump`/`psql` (package
  `postgresql-client`) or `mysqldump`/`mysql` (`mysql-client`). They run on
  the conn's `--via` server when it has one, otherwise here. If they are
  missing, the error tells you what to install
  (`komando pkg install web1 postgresql-client`).
- The password goes to the tool through its environment, never on its
  command line, so other users of the server cannot see it.
- A restore can overwrite data, so it needs `--allow-dangerous` (and `--yes`
  on a protected conn). PostgreSQL restores run in one transaction: if
  anything fails, nothing changes.
- Before sending anything, komando reads the whole file. A file with client
  commands that could run programs or read files (`\!`, `system`, `\i`) is
  refused; real dumps never contain them.
- For MySQL conns with `?tls=...`, the same TLS setting is passed to
  `mysqldump`/`mysql` (MySQL and MariaDB clients both work).
- SQLite: `dump` copies the database file (`--to backup.db`). To restore,
  stop the app and copy the file back.
- Big databases take time: there is no timeout unless you pass `--timeout`.
