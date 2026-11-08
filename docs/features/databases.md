# Databases

Add PostgreSQL, MySQL/MariaDB and SQLite databases, then query, inspect,
back up and restore them safely. [All features](README.md)

## Quick start

```bash
komando secret set app-db-pass                              # type the password once
komando conn add app-db postgres://app@10.0.0.5:5432/app \
  --via web1 --password-ref secret:app-db-pass --protected
komando db schema app-db                                    # what tables are there?
komando db query app-db "select id, email from users order by id desc limit 10"
komando db dump app-db --to app-2026-11-02.sql.gz           # back up to this computer
```

Queries only read unless you add `--write`.

## Add a database

A **conn** is a database, cache or storage bucket that komando knows about,
the way a host entry is a server it knows about. The kind comes from the start of
the URL:

| Kind | URL example |
|------|-------------|
| PostgreSQL | `postgres://app@10.0.0.5:5432/app?sslmode=require` |
| MySQL / MariaDB | `mysql://shop@db.internal:3306/shop?tls=true` |
| SQLite | `sqlite:///var/lib/app.db` (a file on this computer) |

`komando conn kinds` lists every kind, including caches, storage, clusters
and registries.

**Never put the password in the URL**; komando refuses it. Store it in the
vault, or point at your password manager (see [Servers](servers.md)):

```bash
komando secret set app-db-pass
komando conn add app-db postgres://app@10.0.0.5:5432/app \
  --via web1 --password-ref secret:app-db-pass --protected
```

`--via web1` means "the database is only reachable from web1". komando
connects through web1 over SSH by itself: there is no tunnel to start and no
port opens on your computer. `--via` can also be a chain or a VPN (see
[Tunnels](tunnels.md) and [VPNs](vpn.md)).

```bash
komando list kind:conn                       # all conns
komando test kind:conn                       # reachable? does the password work?
komando conn show app-db                     # its settings (passwords stay references)
komando conn edit app-db --add-tag critical
komando conn rm old-db                       # only forgets it; the database is untouched
```

- Conns use the same targets as servers (`@group`, `tag:prod`, `*-db`,
  `all`). See [Targets](targets.md).
- Hosts and conns share one set of names: a host and a conn cannot both be
  called `db1`. Names ignore upper and lower case, so `DB1` is the same name.
- A host that a conn uses in `--via` cannot be removed until the conn is
  changed.

### Encryption (TLS)

A conn that goes straight over the network (no `--via`, not to this
computer) should use TLS that checks the server's certificate. Otherwise
anyone on the network path can read the data, and can trick the login into
giving them the password:

| Kind | Checked TLS | Encrypted, certificate not checked | No encryption |
|------|-------------|------------------------------------|---------------|
| PostgreSQL | `?sslmode=verify-full` | `?sslmode=require` | `?sslmode=disable` |
| MySQL / MariaDB | `?tls=true` | `?tls=skip-verify` | `?tls=false` |

- Without a setting, a Postgres conn uses TLS when the server offers it,
  but does not check the certificate and goes on without TLS when told to.
  A MySQL conn without `tls=` is not encrypted, and the MySQL 8 login then
  encrypts the password with a key the server sends over that same plain
  connection, which someone in between can swap.
- Saved conns keep working as they are. `komando doctor` warns about every
  conn without checked TLS and prints the `komando conn edit NAME --url ...`
  line that fixes it.
- A server whose certificate comes from your own CA: add
  `?sslrootcert=/path/to/ca.pem` (Postgres).
- When TLS stops a connection (the certificate does not check out, or the
  server has no TLS), the hint says what to do and names the weaker setting
  with what it costs.
- Through `--via`, the traffic is inside SSH up to the `--via` server.

## Run a query

```bash
komando db schema app-db                     # list tables
komando db schema app-db users orders        # columns, types, indexes, foreign keys, checks
komando db query app-db "select id, email from users order by id desc limit 10"
komando db explain app-db "select * from orders where user_id = 42"
komando db query app-db --file report.sql    # SQL from a file (--file - reads stdin)
```

**Use `--arg` for values** instead of pasting them into the SQL. The
placeholders are `$1`, `$2` in PostgreSQL, and `?` in MySQL and SQLite:

```bash
komando db query app-db "select * from users where email = $1" --arg bob@example.com
```

The number of `--arg` values must match the placeholders (`USAGE`, exit 2).

**For spreadsheets and scripts**, `--csv` or `--tsv` prints the rows
instead of JSON or a table. NULL is an empty field, binary is `\x` hex:

```bash
komando db query app-db --csv "select id, email from users" > users.csv
```

**Limits.** A query returns at most 500 rows (`--limit`, `0` for no limit)
and `--max-output` bytes. A cut result says which cap it hit:
`"truncated": "rows"` (raise `--limit`) or `"truncated": "bytes"` (raise
`--max-output`). A query stops after 30 seconds; use `--timeout 2m` for
more, or give one conn its own limit:

```bash
komando conn edit app-db --option statement_timeout=10s
```

`--timeout` on the command line always wins.

On a protected conn, an AI agent sees email addresses, phone numbers, card
numbers and IBANs in the rows as `[hidden: email]` and so on. Name the
columns that hold other personal data (names, addresses) to hide them
whole, for the agent: see [Personal data](safety.md#personal-data).

```bash
komando conn edit app-db --option 'mask_columns=full_name address birth_date'
```

**SQL that starts with a `-- comment`** looks like a flag to the command
line. Put `--` before it, or use `--file -`.

### How values come back (JSON)

| Column type | Value |
|-------------|-------|
| date | `"2024-02-29"` |
| timestamp / datetime (no time zone) | `"2024-02-29 10:11:12.5"`, no `Z` |
| timestamptz | `"2024-02-29T08:00:00Z"` (an instant, in UTC) |
| MySQL zero dates | `"0000-00-00 00:00:00"`, as stored |
| binary (bytea, blob) | `{"base64": "..."}`, also when empty; text output shows `\x` hex like psql |
| integers too big for JSON (over 2^53) | strings; the whole column is then strings |
| money, xml and other types | text, with the type named in `columns` |

In text output, tables line up, also with CJK characters and emoji.

## Change data

`komando db query` **does not change your data unless you add `--write`**.
Without it, the query runs in a read-only transaction and the database
itself refuses changes.

Changing data takes two steps. First a dry run: the SQL really runs, you
see how many rows it touches, and then everything is rolled back.

```bash
komando db query app-db --write --dry-run "update users set plan = 'pro' where id = 42"
komando db query app-db --write "update users set plan = 'pro' where id = 42"
```

The seatbelts:

- A protected conn also needs `--yes` with `--write`, whatever the SQL is.
- Destructive SQL needs `--allow-dangerous`: `DROP`, `TRUNCATE`, `DELETE` or
  `UPDATE` without `WHERE`, privilege changes, and a few more.
  `komando policy list` shows them all; `komando policy check --for postgres "..."`
  tests a query.
- A few admin functions that a read-only transaction does not stop (ending
  sessions, reading server files, `dblink`) are blocked by komando's own
  checks.
- `BEGIN` and `COMMIT` are refused: komando runs everything in one
  transaction. Each statement is sent to the server on its own, and if one
  still ends that transaction, komando stops before the next one.
- Without `--write` the session is read-only too (on Postgres, unless a
  pooler such as PgBouncer refuses the setting; then only the transaction
  is).
- SQL that komando cannot read the way the server does is refused
  (`SQL_HIDDEN_CODE`): MySQL `/*! ... */` comments, Postgres `U&"..."`
  names, a number written right before `$` (`1abc$$`), a MySQL `--`
  followed by a non-ASCII byte. Changing the client character set
  (`SET NAMES`, `client_encoding`) is refused, and so is a connection whose
  character set can hide a backslash (SJIS, GBK, BIG5 and similar).
- A few statements cannot be rolled back (`VACUUM`,
  `CREATE INDEX CONCURRENTLY`, `SET PASSWORD`, and in MySQL every statement
  other than `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `REPLACE`, `SHOW`,
  `SET` and a few more reads). They must be sent alone, and a dry run only
  reports them.
- A dry run also skips what a rollback does not undo: `setval()`, ending
  sessions, `COPY ... PROGRAM`, server files, `dblink`, and code komando
  cannot see into (`DO`, `CALL`, `EXECUTE`). If the real run would be
  blocked (no `--allow-dangerous`, or a protected conn without `--yes`), a
  dry run runs nothing and only shows the plan. A function you call by name
  (`SELECT reset_ids()`) runs, and what it does outside the transaction
  (a sequence, a file) stays.
- `db explain --analyze` really runs the query, so a query that changes data
  needs `--write` there too.

These checks catch mistakes. For real limits, give komando a database user
with only the rights it needs.

## Check on a database

```bash
komando db info app-db                   # version, uptime, size, connections, primary or replica
komando db activity app-db               # what runs now: pid, user, how long, the query (--all adds idle ones)
komando db locks app-db                  # who waits, and the session holding the lock
komando db sizes app-db -n 10            # databases, biggest tables and indexes
komando db explain app-db --analyze "select ..."   # real timings (MariaDB: ANALYZE)
```

Stop a slow query:

```bash
komando db kill app-db 4821 --dry-run    # which query it would stop
komando db kill app-db 4821              # cancel the query; the client stays connected
komando db kill app-db 4821 --session --allow-dangerous   # end the whole connection
```

- Text output shows sizes (`7.5 MiB`) and durations (`3h`). JSON keeps the
  raw numbers (`size_bytes`, `running_seconds`).
- `db schema` shows tables in the order you name them, and marks
  `auto_increment` and `generated always as identity` columns.
- SQLite has no server sessions, so `activity`, `locks` and `kill` do not
  apply to it.

## Users and grants

```bash
komando secret set app-ro-pass                              # the password goes to the vault first
komando db user add app-db app_ro --password-ref secret:app-ro-pass
komando db grant app-db app_ro --privileges SELECT --on all-tables:public
komando db grants app-db app_ro                             # what it may do now
komando db user ls app-db                                   # all users and roles
komando db user passwd app-db app_ro --password-ref secret:app-ro-pass-2   # rotate
komando db revoke app-db app_ro --privileges SELECT --on all-tables:public
komando db user rm app-db app_ro --allow-dangerous
komando db grant shop-db app --privileges SELECT,INSERT --on 'shop.*' --from '10.0.%'   # MySQL
```

- Passwords come only from a secret reference. They are never typed on a
  command line, shown, or written to the audit log (`--dry-run` and the
  answer show `[hidden]`). PostgreSQL gets a SCRAM-SHA-256 verifier that
  komando computes, so the password never reaches the server or its logs.
  For an AI agent, the password needs a person's yes (`--yes`, then the
  window, `SECRET_DESTINATION`): the conn could be a server the agent set up.
- `--on` takes `database:NAME`, `schema:NAME`, `table:[SCHEMA.]TABLE` or
  `all-tables:SCHEMA` on PostgreSQL (`--role ROLE` grants a role instead),
  and `DB.*`, `DB.TABLE` or `*.*` on MySQL (`--from` sets the account host).
- Adding users and grants are changes (`--yes` on protected conns).
  Removing a user also needs `--allow-dangerous`.

## Back up and restore

```bash
komando db dump app-db --to app-2026-11-02.sql.gz      # plain SQL, compressed (.gz)
komando db dump app-db --to app.dump --format custom   # PostgreSQL archive, for pg_restore
komando db dump app-db --to orders.sql --table public.orders   # one table (repeatable)
komando db dump app-db --to schema.sql --schema-only   # no rows
komando db restore staging-db --from app-2026-11-02.sql.gz --allow-dangerous
komando db restore staging-db --from app.dump --allow-dangerous   # an archive goes to pg_restore
komando db dump app-db --to app.dump --format custom --on db1      # pg_dump runs on the server db1
komando db restore staging-db --from app.dump --on db1 --allow-dangerous   # pg_restore runs on db1
```

**Where the backup goes.** Always to a file on **this computer**, readable
only by you. An existing file is never overwritten.

**Who does the work.** `pg_dump` or `mysqldump` runs on a server that has
it: the one you name with `--on HOST`, else the last server of the conn's
`--via` path. Otherwise (a direct conn or a VPN, or a `--via` server without
the tool) komando dumps by itself, and nothing has to be installed. `runs_on`
in the answer (and in `komando audit`) names where the tool ran. A plain
SQL restore is always run by komando itself,
through the same `--via` path, never by `psql` or `mysql`: those would obey
client commands hidden in the file on that server. Only a PostgreSQL
archive goes to `pg_restore` on the server. `tool` in the answer says which
was used. The password goes to a server's tool through its environment,
never on its command line, so other users of that server cannot see it. For
MySQL conns with `?tls=...`, the same TLS setting is passed to the server's
tools (MySQL and MariaDB clients both work).

**Running the dump on a server you choose (`--on HOST`).** Useful when the
conn goes through a VPN (komando then can only write plain SQL itself) but a
server you manage has `pg_dump` and can reach the database, often the
database server itself:

```bash
komando db dump prod-db --to prod.dump --format custom --on db1 --dry-run   # where and what would run
komando db dump prod-db --to prod.dump --format custom --on db1
```

- `HOST` is a server from your inventory (a name or a selector that picks
  exactly one); komando reaches it the usual way, through its own `--via`.
  The conn's password goes to it, so a `user@address` that is not in the
  inventory is refused.
- The tool there connects to the conn URL's address **as that server sees
  it**. When the database only listens on `127.0.0.1` on that server, add a
  second conn for that address reached through it
  (`komando conn add prod-db-local postgres://app@127.0.0.1:5432/app --via db1 --password-ref ...`)
  and dump that one; `CONN_UNREACHABLE` says this when it happens.
- A dump runs at low priority (`nice -n 10`, plus `ionice -c3` where the
  server has it), so the server keeps serving its users. `low_priority` in
  the answer says so.
- The backup streams back over SSH into `--to` on this computer (compressed
  here when it ends in `.gz`); nothing is written on the server.
- `pg_dump` refuses a server newer than itself. komando reports that as
  `TOOL_TOO_OLD` with both versions and the package to install
  (`postgresql-client-NN`). A server named with `--on` is never skipped: a
  missing or old tool there is an error, while a `--via` server without a
  usable tool falls back to komando's own plain SQL dump.
- `db restore --on HOST` runs `pg_restore` there for an archive, streaming
  the file to it over SSH. It has the same gate as any restore
  (`--allow-dangerous`, plus `--yes` on a protected conn). Plain SQL is
  always restored by komando itself, so `--on` with a SQL file is refused.
- PostgreSQL 17 tools write `SET transaction_timeout`, which servers before
  17 do not know. komando's own restore of plain SQL skips that line on such
  servers. `pg_restore` 17 cannot load an archive into them, and an older
  `pg_restore` cannot read a newer archive: for an old server, dump with
  `--format custom` only from a `pg_dump` of its own major version, or use
  plain SQL.

**What komando's own dump contains.** Plain SQL that psql and mysql can
also read:

- PostgreSQL: extensions, schemas, enum/domain/composite types, functions,
  sequences, tables (identity and generated columns, partitions), data,
  constraints, indexes, views, materialized views, triggers, row-level
  security and comments.
- MySQL: tables, data (generated columns are computed again on restore),
  views (after the routines, with stand-ins first, so a view may read
  another view or call a function), triggers and routines.
- PostgreSQL `--table` dumps those tables and the sequences they own or use in a
  `DEFAULT`, but not schemas, types or functions they need (like
  `pg_dump --table`). A name with a dot in it goes in double quotes:
  `--table 'public."app.events"'`.
- Owners and privileges are left out (like `--no-owner --no-acl`).
- An object it cannot write (an aggregate, an operator, a foreign table,
  ...) stops the dump with its name (`DUMP_UNSUPPORTED`) instead of being
  left out silently.
- `--format custom` needs `pg_dump` on a server (`--on HOST`, or the conn's
  `--via` server).

**Restoring safely.**

- A restore can overwrite data, so it needs `--allow-dangerous` (and `--yes`
  on a protected conn).
- PostgreSQL restores run in one transaction: if anything fails, nothing
  changes. MySQL runs the statements in order and stops at the first error;
  what ran before it stays.
- komando reads the whole file before sending anything, the way psql and
  mysql would read it. A file with client commands that could run programs
  or read files (`\!`, `system`, `\i`) is refused (`UNSAFE_BACKUP`), and so
  is a file komando cannot follow: one that ends inside a quote or
  comment, or a `SET` or `set_config` that changes
  `standard_conforming_strings` or adds `NO_BACKSLASH_ESCAPES`. A file that
  switches databases (`\connect`, from
  `pg_dump --create` or `pg_dumpall`) is refused too
  (`RESTORE_UNSUPPORTED`): dump the one database without `--create`. Real
  single-database dumps pass. `db restore --dry-run` runs this check too and
  says what would stop the real run.
- SQL in the file that does more than write data is named next to
  `db-restore` in the approval and in `POLICY_BLOCKED`, with the line where
  it first appears: `sql-program` (`COPY ... PROGRAM`), `sql-server-file`
  (`INTO OUTFILE`, `pg_read_file`), `sql-server-config` (`ALTER SYSTEM`),
  `sql-privileges` (`GRANT`, `CREATE ROLE`), `sql-opaque` (`DO`,
  `PREPARE`), `sql-remote` and `sql-kill`. A pg_dump with privileges names
  `sql-privileges`.
- `--table` takes table names only; a value that starts with `-` is
  refused.

**SQLite.** `dump` copies the database file (`--to backup.db`). To restore,
stop the app and copy the file back.

**Big databases** take time: `dump` and `restore` have no timeout unless you
pass `--timeout`.

## Interactive SQL shell (for people)

```bash
komando db shell staging-db           # komando's own SQL shell; starts read-only
komando db shell staging-db --write   # allow changes
komando db shell app-db --yes         # any shell on a protected conn needs --yes
```

`db shell` is komando's own SQL shell for PostgreSQL, MySQL/MariaDB and
SQLite, so nothing else needs to be installed. It connects through the
conn's `--via` path, and every statement gets the same checks as
`db query`: read-only unless you started it with `--write`, destructive
statements only with `--allow-dangerous`, and each one is written to the
audit log. A statement ends with `;` and runs in its own transaction.

```text
app-db> select id, name
     -> from users limit 2;
 id | name
----+------
  1 | ana
  2 | budi
(2 rows)
app-db> \q
```

| Command | What it does |
|---------|--------------|
| `\q` | quit |
| `\?` | list the commands |
| `\d [TABLE]` | list tables, or show one table |
| `\l` / `\dn` / `\du` | databases / schemas / roles |
| `\x` | expanded rows (or end a statement with `\G`) |
| `\timing` | show how long each statement takes |
| `\i FILE` | run SQL from a file |

Up and down arrows recall earlier lines. The shell is for people at a
terminal: agents and scripts get `NEEDS_TERMINAL` and use `db query`, which
returns JSON.

## Troubleshooting

| Error | Exit | Meaning |
|-------|------|---------|
| `DB_AUTH` | 4 | wrong user name or password |
| `DB_NOT_FOUND` | 3 | the database does not exist |
| `DB_PRIVILEGE` | 4 or 5 | the conn's user lacks a right (for example to see lock waits in `db locks`, or to manage users) |
| `DUMP_UNSUPPORTED` | 2 | komando's own dump cannot write an object; the message names it |
| `TOOL_MISSING` | 3 | `pg_dump`, `mysqldump` or `pg_restore` is not installed where it should run |
| `TOOL_TOO_OLD` | 5 | `pg_dump` is older than the database server, or `pg_restore` older than the archive |
| `CONN_UNREACHABLE` | 4 | the tool cannot reach the database from the server it runs on |
| `NEEDS_TERMINAL` | 2 | `db shell` was run without a terminal; use `db query` |

`db dump` and `db restore` report the same connection errors as `db query`.
