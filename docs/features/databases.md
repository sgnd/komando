# Databases

Add PostgreSQL, MySQL/MariaDB, SQL Server, Oracle, ClickHouse, Snowflake,
BigQuery, SQLite and MongoDB databases, then query, inspect, back up and
restore them safely. [All docs](README.md)

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

A conn is a database, cache, queue, storage bucket, cluster or registry
that komando knows about, the way a host entry is a server it knows about. The kind comes from the
start of the URL:

| Kind | URL example |
|------|-------------|
| PostgreSQL | `postgres://app@10.0.0.5:5432/app?sslmode=require` |
| MySQL / MariaDB | `mysql://shop@db.internal:3306/shop?tls=true` |
| SQL Server | `sqlserver://app@db.internal:1433/sales?encrypt=true` (also `mssql://`). See [SQL Server](#sql-server). |
| Oracle | `oracle://app@db.internal:1521/ORCLPDB1?tls=true` (the path is the service name). See [Oracle](#oracle). |
| ClickHouse | `clickhouse://app@ch.internal:8443/analytics?tls=true` (the HTTP interface). See [ClickHouse](#clickhouse). |
| Snowflake | `snowflake://APP_RO@myorg-myaccount/ANALYTICS/PUBLIC?warehouse=REPORTING&role=ANALYST_RO` (the account in place of a host). See [Snowflake](#snowflake). |
| BigQuery | `bigquery://my-project/analytics?location=EU` (the project, and a default dataset). See [BigQuery](#bigquery). |
| SQLite | `sqlite:///var/lib/app.db` (a file on this computer) |
| MongoDB | `mongodb://app@db1.internal:27017,db2.internal/shop?replicaSet=rs0&authSource=admin` (Atlas: `mongodb+srv://app@cluster0.abcde.mongodb.net/shop`). See [MongoDB](#mongodb). |

`komando conn kinds` lists every kind, including caches, queues, storage,
clusters and registries.

Never put the password in the URL; komando refuses it. Store it in the
vault, or point at your password manager (see [Servers](servers.md)):

```bash
komando secret set app-db-pass
komando conn add app-db postgres://app@10.0.0.5:5432/app \
  --via web1 --password-ref secret:app-db-pass --protected
```

Or in one step at your terminal: `--ask-password` asks for it (hidden) and
stores it as `secret:app-db-pass`:

```bash
komando conn add app-db postgres://app@10.0.0.5:5432/app --via web1 --ask-password --protected
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
| SQL Server | `?encrypt=true` (or `strict`) | `?encrypt=true&tls=skip-verify` | `?encrypt=disable` |
| Oracle | `?tls=true` (TCPS) | `?tls=skip-verify` | `?tls=false` |
| ClickHouse | `?tls=true` (HTTPS, port 8443) | `?tls=skip-verify` | `?tls=false` (port 8123) |
| Snowflake | always (HTTPS) | not offered | not offered |
| BigQuery | always (HTTPS) | not offered | an `http://` endpoint (an emulator) |

- Without a setting, a Postgres conn uses TLS when the server offers it,
  but does not check the certificate and goes on without TLS when told to.
  A MySQL conn without `tls=` is not encrypted, and the MySQL 8 login then
  encrypts the password with a key the server sends over that same plain
  connection, which someone in between can swap. A SQL Server conn without
  `encrypt=` (or with `encrypt=false`) encrypts only the login, and
  without `encrypt=` does not check the certificate either. An Oracle conn
  without `tls=true` uses no TLS; Oracle's own network encryption, when the
  server turns it on, encrypts but does not prove who the server is. A
  ClickHouse conn without `tls=true` is plain HTTP.
- New conns check by default. When `conn add` (or `conn edit --url`)
  saves such a conn and its URL does not say how to use TLS, komando adds
  `sslmode=verify-full` (Postgres), `tls=true` (MySQL, Oracle, ClickHouse,
  whose port 8123 becomes 8443) or `encrypt=true` (SQL Server) and says so in
  `warnings`. A URL that names a setting keeps it, and a conn through
  `--via` or to this computer is left as written. If the server has no TLS
  or a certificate from its own CA, the first connection's hint says what
  to do (the rows below).
- Conns saved before keep working as they are. `komando doctor` warns
  about every conn without checked TLS and prints the
  `komando conn edit NAME --url ...` line that fixes it.
- A server whose certificate comes from a private CA (your company's, or a
  cloud's own, such as Amazon RDS or Azure Database): store the CA and name
  it with `?ca=`, for Postgres, MySQL, SQL Server, Oracle, ClickHouse,
  Snowflake and BigQuery (a proxy that inspects TLS). The certificate is
  then fully checked: signed by that CA and naming the server, also with
  `sslmode=require`, and never without TLS:

  ```bash
  komando secret set rds-ca < global-bundle.pem
  komando conn add orders 'postgres://app@orders.abc123.eu-west-1.rds.amazonaws.com/orders?ca=secret:rds-ca' --password-ref secret:orders-pass
  ```

  For Postgres a file on this computer works too:
  `?sslrootcert=/path/to/ca.pem`.
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

Use `--arg` for values instead of pasting them into the SQL. The
placeholders are `$1`, `$2` in PostgreSQL, `?` in MySQL and SQLite,
`@p1`, `@p2` in SQL Server, `:1`, `:2` in Oracle, `?` in Snowflake and
BigQuery (where the values go as `STRING`), and `{p1:String}`,
`{p2:UInt64}` in ClickHouse (named `p1`, `p2`, with a type):

```bash
komando db query app-db "select * from users where email = $1" --arg bob@example.com
```

The number of `--arg` values must match the placeholders (`USAGE`, exit 2).
In Oracle SQL each placeholder takes its own `--arg`, also a name used
twice (`where a = :1 or b = :1` takes two); in a PL/SQL block a name used
twice takes one.

For spreadsheets and scripts, `-o csv` or `-o tsv` prints the rows
instead of JSON or a table. NULL is an empty field, binary is `\x` hex:

```bash
komando db query app-db -o csv "select id, email from users" > users.csv
```

A CSV or TSV export has every row, unless you give `--limit` (komando
then says on stderr when it stopped there). If the rows are more than
`--max-output` bytes, komando prints nothing and fails with
`OUTPUT_TRUNCATED` (exit 1), so a file is never cut without you knowing:
raise `--max-output`, or for a whole database use `komando db dump`.
Errors go to stderr, so the file holds only rows. `--csv` and `--tsv`
are the old names; they still work in this release and say to use `-o`.

Otherwise a query returns at most 500 rows (`--limit`, `0` for no limit)
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

SQL that starts with a `-- comment` looks like a flag to the command
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
| SQL Server decimal, money | text with every digit (`"12.50"`) |
| SQL Server uniqueidentifier | `"6F9619FF-8B86-D011-B42D-00C04FC964FF"` |
| Oracle DATE (it holds a time of day too) | `"2026-11-09 13:04:05"` |
| ClickHouse Decimal, Int128 and wider | text with every digit (`"12.50"`) |
| ClickHouse Array, Map, Tuple | JSON arrays and objects |
| Snowflake NUMBER with a scale | text with every digit (`"12.50"`) |
| Snowflake VARIANT, OBJECT, ARRAY | JSON values, arrays and objects |
| BigQuery NUMERIC, BIGNUMERIC | text with every digit |
| BigQuery TIMESTAMP | `"2026-11-09T13:04:05.123456Z"` (UTC) |
| BigQuery STRUCT, ARRAY, JSON | JSON objects, arrays and values |

In text output, tables line up, also with CJK characters and emoji.

## Change data

`komando db query` does not change your data unless you add `--write`.
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
  `UPDATE` without `WHERE`, privilege changes, code that reaches the
  server's operating system (`CREATE EXTENSION`, a function in C or
  `plpython3u`, `LOAD`, MySQL `INSTALL PLUGIN` and `SONAME`, SQL Server
  `CREATE ASSEMBLY`), and a few more.
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
- SQL Server can only end a whole session (`KILL`), so `db kill` needs
  `--session` there.
- On Oracle the PID is the session's SID (`db activity` shows it, with
  its serial#).
- On ClickHouse the PID is a number `db activity` makes from the query's
  `query_id`; `db kill` stops that query, and there is no `--session` or
  `db locks`.
- On Snowflake, too, the PID is a number `db activity` makes from the query
  ID; `db kill` cancels the query (`SYSTEM$CANCEL_QUERY`), and `--session`
  ends its session. There is no `db locks`.
- On BigQuery the PID is a number `db activity` makes from the job ID;
  `db kill` cancels the job. There is no `--session` or `db locks`.

## Users and grants

```bash
komando secret set app-ro-pass                              # the password goes to the vault first
komando db user add app-db app_ro --password-ref secret:app-ro-pass
komando db grant app-db app_ro --privileges SELECT --on all-tables:public
komando db grants app-db app_ro                             # what it may do now
komando db user ls app-db                                   # all users and roles
komando db user passwd app-db app_ro --password-ref secret:app-ro-pass-2   # rotate (the conn's own user: also conn edit, see rotate.md)
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
  For SQL Server see [SQL Server](#sql-server), for Oracle [Oracle](#oracle),
  for ClickHouse [ClickHouse](#clickhouse). On Snowflake, `db user ls` and
  `db grants` read; adding, changing and granting are not available. On
  BigQuery, users and rights are Google Cloud IAM, so these commands are
  not available.
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

### Where the backup goes, and who makes it

The backup always goes to a file on this computer, readable only by you.
An existing file is never overwritten.

`pg_dump` or `mysqldump` runs on a server that has it: the one you name with
`--on HOST`, else the last server of the conn's `--via` path. Otherwise (a
direct conn or a VPN, or a `--via` server without the tool) komando dumps by
itself, and nothing has to be installed. `runs_on` in the answer (and in
`komando audit`) names where the tool ran. A plain SQL restore is always run
by komando itself, through the same `--via` path, never by `psql` or
`mysql`: those would obey client commands hidden in the file on that server.
Only a PostgreSQL archive goes to `pg_restore` on the server. `tool` in the
answer says which was used.

The password goes to a server's tool through its environment, never on its
command line, so other users of that server cannot see it. For MySQL conns
with `?tls=...`, the same TLS setting is passed to the server's tools (MySQL
and MariaDB clients both work). For Postgres, `pg_dump` and `pg_restore`
read the conn URL themselves: with `sslmode=verify-full` (or `verify-ca`)
they check the database's certificate against `~/.postgresql/root.crt` on
the server they run on, not against the system's CAs as komando does. With
`pg_dump` 16 or newer, komando adds `sslrootcert=system`, so they use the
system's CAs too. An older one needs the CA in that file there; without it
the dump stops with `DB_CONNECT` and a hint (install `postgresql-client` 16
or newer, put the CA in `~/.postgresql/root.crt`, or reach the database
`--via` that server without TLS).

### A private CA (`?ca=secret:NAME`)

The tools on the server check the database's certificate against the conn's
CA too, the same full check komando makes: signed by that CA and naming the
server. komando sends the CA after the password, on the tool's input, never
on its command line. It lands in a new folder in `/tmp` that only the login
user can open, and goes once the tool ends. `pg_dump` and `pg_restore` of
any version get it as `sslrootcert=` with `sslmode=verify-full` (in place of
`ca=`, which libpq does not know), so `~/.postgresql/root.crt` is not
needed. `mysqldump` gets `--ssl-ca` and a checked TLS connection, also when
the URL has no `tls=`.

### Run the dump on a server you choose (`--on HOST`)

This helps when the conn goes through a VPN (komando then can only write
plain SQL itself) but a server you manage has `pg_dump` and can reach the
database, often the database server itself:

```bash
komando db dump prod-db --to prod.dump --format custom --on db1 --dry-run   # where and what would run
komando db dump prod-db --to prod.dump --format custom --on db1
```

- `HOST` is a server from your inventory (a name or a selector that picks
  exactly one); komando reaches it the usual way, through its own `--via`.
  The conn's password goes to it, so a `user@address` that is not in the
  inventory is refused.
- The tool there connects to the conn URL's address as that server sees
  it. When the database only listens on `127.0.0.1` on that server, add a
  second conn for that address reached through it
  (`komando conn add prod-db-local postgres://app@127.0.0.1:5432/app --via db1 --password-ref ...`)
  and dump that one; `CONN_UNREACHABLE` says this when it happens.
- A dump runs at low priority (`nice -n 10`, plus `ionice -c3` where the
  server has it), so the server keeps serving its users. `low_priority` in
  the answer says so.
- The backup streams back over SSH into `--to` on this computer (compressed
  here when it ends in `.gz`); nothing is written on the server, except a
  private CA's certificate while the tool runs.
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

### What komando's own dump contains

Plain SQL that psql and mysql can also read:

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

### Restore safely

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
  it first appears: `sql-program` (`COPY ... PROGRAM`, `CREATE EXTENSION`), `sql-server-file`
  (`INTO OUTFILE`, `pg_read_file`), `sql-server-config` (`ALTER SYSTEM`),
  `sql-privileges` (`GRANT`, `CREATE ROLE`), `sql-opaque` (`DO`,
  `PREPARE`), `sql-remote` and `sql-kill`. A pg_dump with privileges names
  `sql-privileges`.
- `--table` takes table names only; a value that starts with `-` is
  refused.

### SQLite and big databases

For SQLite, `dump` copies the database file (`--to backup.db`). To restore,
stop the app and copy the file back.

Big databases take time: `dump` and `restore` have no timeout unless you
pass `--timeout`.

## MongoDB

A MongoDB conn takes the same `db query`, with a command document in
JSON instead of SQL: its first key names the command, as in `runCommand`.
`db schema` and `db info` work too.

```bash
komando secret set shop-mongo-pass
komando conn add shop-mongo 'mongodb://app@db1.internal,db2.internal/shop?replicaSet=rs0&authSource=admin' --via bastion --password-ref secret:shop-mongo-pass
komando db query shop-mongo '{"find": "orders", "filter": {"status": "open"}, "sort": {"_id": -1}, "limit": 10}'
komando db query shop-mongo '{"aggregate": "orders", "pipeline": [{"$group": {"_id": "$status", "n": {"$sum": 1}}}], "cursor": {}}'
komando db query shop-mongo --write '{"update": "orders", "updates": [{"q": {"_id": {"$oid": "5f1d7f1b2c3a4b5c6d7e8f90"}}, "u": {"$set": {"status": "paid"}}}]}'
komando db schema shop-mongo                      # collections, sizes, indexes
komando db schema shop-mongo orders               # fields and their types, from a sample
komando db info shop-mongo                        # version, primary or secondary, sizes
```

- komando rates each command before it sends it, as it does SQL: `find`,
  `aggregate`, `count`, `distinct` and the other reads run as they are. A
  command that changes data, or one komando does not know as a read, needs
  `--write`; a protected conn also needs `--yes`. A `delete` or a multi-document
  `update` with an empty filter, `drop`, `dropDatabase`, user and role
  changes and `shutdown` also need `--allow-dangerous`. An `aggregate` with
  `$out` or `$merge` writes.
- MongoDB has no read-only transaction, so the rating is what keeps a read
  a read. For a hard guarantee, give the conn a user with only the `read`
  role.
- `--write --dry-run` sends nothing (MongoDB cannot roll a write back) and
  says how the command was rated.
- Values are MongoDB Extended JSON: `{"$oid": "..."}`, `{"$date":
  "2026-11-08T10:00:00Z"}`. `"$db": "other"` runs one command on another
  database than the URL's (without one in the URL: `admin`).
- Results: `data.documents` for commands that return a cursor (at most
  `--limit`, default 500, and `--max-output` bytes), `data.reply` for the
  others. `-o text` prints one document per line.
- Every member of a replica set is reached through `--via`. A private CA
  works with `?tls=true&ca=secret:NAME`.
- For SQL databases only: `db dump`, `restore`, `activity`, `locks`,
  `sizes`, `kill`, users and grants, and `db shell`. On MongoDB they say so
  (`NOT_SUPPORTED`); run `mongodump` on a server with `komando exec`.

## SQL Server

SQL Server (and Azure SQL Managed Instance) conns take the same `db`
commands as PostgreSQL and MySQL, in T-SQL:

```bash
komando secret set sales-pass
komando conn add sales 'sqlserver://app@db.internal:1433/sales?encrypt=true' --password-ref secret:sales-pass
komando db query sales "select top (10) id, email from dbo.users order by id desc"
komando db query sales "select * from dbo.users where email = @p1" --arg bob@example.com
komando db query sales --write --dry-run "update dbo.users set plan = 'pro' where id = 42"
komando db schema sales dbo.orders                  # columns, identity, indexes, foreign keys, checks
komando db explain sales "select * from dbo.orders where user_id = 42"   # the plan; nothing runs
komando db info sales
komando db kill sales 57 --session --allow-dangerous
```

- **The URL.** The path is the database. A named instance
  (`db\SQLEXPRESS`) is reached by its port: `sqlserver://app@db:49172/sales`.
  The options are `encrypt=` (`true`, `strict`, `false`, `disable`; see
  [Encryption](#encryption-tls)), `tls=skip-verify`, `ca=secret:NAME`,
  `applicationintent=readonly` (a readable replica of an availability
  group) and `database=NAME` in place of the path. Logins are SQL Server
  logins (user and password); Windows and Entra ID logins are not
  supported.
- **Without `--write` nothing stays.** SQL Server has no read-only
  transaction, so komando runs the SQL in a transaction that it always
  rolls back, and checks after each statement that this transaction is
  still open. komando's checks come first, stricter than for the other
  databases, because T-SQL needs no `;` between statements:
  - a change anywhere in the text counts, so `select 1 delete from t` is a
    `DELETE` without `WHERE`;
  - a first word that is not a T-SQL statement is the name of a procedure
    that SQL Server runs (`sp_who`), so it needs `--write` and
    `--allow-dangerous`, like `EXEC`;
  - `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVE TRANSACTION` and
    `SET IMPLICIT_TRANSACTIONS` are refused anywhere, so `BEGIN ... END`
    blocks and `TRY ... CATCH` belong in a stored procedure;
  - names and text with letters outside ASCII must be quoted (`[naïve]`,
    `N'café'`).

  A procedure or function you call can still act outside the transaction
  (`xp_cmdshell`, a linked server, mail). For a hard limit, give the conn a
  login with only `db_datareader`.
- **`CREATE PROCEDURE`, `FUNCTION` and `TRIGGER`** take the rest of the
  text as their body, as SQL Server does, also after a `;`. Creating one is
  a change; what the body does counts when it runs.
- `BACKUP`, `RESTORE`, `CREATE DATABASE` and `ALTER DATABASE` cannot run in a
  transaction: send them alone, with `--write`; a dry run only reports them.
- `db explain` shows the plan with `SET SHOWPLAN_TEXT`: nothing runs, so it
  needs no `--write` for a change either. `--analyze` runs the query with
  `SET STATISTICS PROFILE` and shows the real row counts.
- `db activity`, `locks` and the sessions in `db info` need the
  `VIEW SERVER STATE` permission; without it a login sees only its own
  session.
- **Users.** `db user add` creates a login (with the password) and a user
  for it in the conn's database; `db user rm` removes both. `--no-login`
  creates a database role instead. `db grant` takes `--on database` (the
  conn's), `schema:NAME`, `all-tables:SCHEMA` (the same) or
  `table:[SCHEMA.]TABLE`, and `--role db_datareader` (any database role)
  adds the user to a role.
- **Backups.** `db dump` and `db restore` are not available for SQL Server
  yet (`NOT_SUPPORTED`). SQL Server's own `BACKUP DATABASE ... TO DISK`
  writes a `.bak` file on the database server (with `--write` and
  `--allow-dangerous`); `komando download` then fetches it from that server.

## Oracle

Oracle Database conns (19c and later, and Oracle Database Free) take the
same `db` commands, in Oracle SQL:

```bash
komando secret set erp-pass
komando conn add erp 'oracle://app@db.internal:1521/ERPPDB?tls=true' --password-ref secret:erp-pass
komando db query erp "select id, email from app.users order by id desc fetch first 10 rows only"
komando db query erp "select * from app.users where email = :1" --arg bob@example.com
komando db query erp --write --dry-run "update app.users set plan = 'pro' where id = 42"
komando db schema erp app.orders                   # columns, identity, indexes, foreign keys, checks
komando db explain erp "select * from app.orders where user_id = 42"   # EXPLAIN PLAN; nothing runs
komando db info erp
komando db kill erp 371 --session --allow-dangerous   # 371 is the SID
```

- **The URL.** The path is the service name, often a pluggable database
  (`ORCLPDB1`, `FREEPDB1`); `lsnrctl status` on the server lists them. An
  old database without services: `oracle://app@db:1521?sid=ORCL`. The
  options are `tls=` (`true`, `skip-verify`, `false`; TCPS listens on its
  own port, often 2484) and `ca=secret:NAME` for a private CA (with
  `tls=true`). Logins are user and password; wallets and Kerberos are not
  supported.
- **Without `--write` nothing changes.** komando starts every run with
  `SET TRANSACTION READ ONLY`, and checks after each statement that this
  transaction is still open.
- **DDL commits on its own** in Oracle (`CREATE`, `ALTER`, `DROP`, `GRANT`,
  `TRUNCATE`, `COMMENT`, ...). So it always needs `--write`, must be sent on
  its own, and a dry run only reports it. `ALTER SESSION` is not DDL.
- **PL/SQL.** A block (`BEGIN ... END;`, `DECLARE ...`) and `WITH FUNCTION`
  run code komando cannot follow: they need `--write` and
  `--allow-dangerous`, and a dry run skips them. A block runs to the end of
  the text or to a line with only `/`, as in SQL*Plus:

  ```bash
  komando db query erp --write --allow-dangerous -f - <<'SQL'
  begin
    app.close_month(date '2026-10-31');
  end;
  /
  SQL
  ```

  `CREATE PROCEDURE`, `FUNCTION`, `PACKAGE`, `TRIGGER` and `TYPE` work the
  same way; creating one is a change, and what the body does counts when
  it runs.
- `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `SET TRANSACTION` and
  `PRAGMA AUTONOMOUS_TRANSACTION` are refused anywhere, also inside a
  block. Names and text with letters outside ASCII must be quoted
  (`"Straße"`, `'café'`). `q'[...]'` quotes work.
- Calls to packages that reach other servers or files (`UTL_HTTP`,
  `UTL_FILE`, `DBMS_PIPE`, `DBMS_SCHEDULER`, ...) need `--write` and
  `--allow-dangerous`, and so does a call to any function that is not one
  of Oracle's own (`app.close_month(1)`, `pkg.f(x)`): it can commit on its
  own (an autonomous transaction), even in a `SELECT`. A name across a
  database link (`orders@prodlink`) and an inline external table
  (`FROM EXTERNAL (...)`, which reads files on the database server and with
  a `PREPROCESSOR` runs a program there) need the same. A function called
  without `()` looks like a column, so komando cannot see it: for a hard
  limit, give the conn a user with only `SELECT` (or `READ`) grants.
- `db explain` uses `EXPLAIN PLAN` and `DBMS_XPLAN`: nothing runs, so it
  needs no `--write` for a change either, nor for the DDL that `EXPLAIN
  PLAN` takes (`CREATE TABLE`, `CREATE INDEX`, `ALTER INDEX`). Other DDL
  cannot be planned. `--analyze` is not available on
  Oracle (`NOT_SUPPORTED`); the plan shows Oracle's estimated rows.
- `db activity`, `locks`, `kill`, and the size and uptime in `db info`,
  read Oracle's `V$` and `DBA_` views: the conn's user needs
  `SELECT_CATALOG_ROLE`. Without it `db sizes` shows the user's own tables
  and the others say what to grant. A table's `CLOB` and `BLOB` data
  counts in its `total_bytes` (not in `table_bytes`, as with PostgreSQL's
  TOAST). `db kill` without `--session` stops
  only the running call (`ALTER SYSTEM CANCEL SQL`, Oracle 18c and later).
- **Users.** In Oracle a user is also a schema. `db user add` creates the
  user and lets it log in (`CREATE SESSION`); `--no-login` creates a role.
  `db user rm` refuses a user that still owns tables (`DB_USER_IN_USE`).
  Names are upper case, as Oracle stores them. `db grant` takes
  `--on table:[SCHEMA.]TABLE` (`SELECT`, `INSERT`, `UPDATE`, `DELETE`,
  `EXECUTE`, ...), `--on database` (system privileges such as
  `CREATE TABLE` or `SELECT ANY TABLE`), `--on schema:NAME` (Oracle 23ai:
  `SELECT` becomes `SELECT ANY TABLE ON SCHEMA`), and `--role NAME`.
- **Backups.** `db dump` and `db restore` are not available for Oracle
  (`NOT_SUPPORTED`): Data Pump (`expdp`, `impdp`) and RMAN run on the
  database server and write there. Run them with `komando exec` (or a
  `komando job` for a big one), then fetch the file with `komando download`.

## ClickHouse

ClickHouse conns (23.3 and later) take the same `db` commands, in
ClickHouse SQL. komando speaks ClickHouse's HTTP interface (port 8443 with TLS, 8123 without) with its own client, so
nothing else needs to be installed:

```bash
komando secret set events-pass
komando conn add events 'clickhouse://app@ch.internal:8443/analytics?tls=true' --password-ref secret:events-pass
komando db query events "select event, count() from hits where day = today() group by event order by 2 desc limit 10"
komando db query events "select * from hits where user_id = {p1:UInt64} limit 10" --arg 42
komando db query events --write "insert into notes (id, text) values (1, 'hello')"
komando db schema events analytics.hits             # columns, engine, ORDER BY, skipping indexes
komando db explain events "select count() from hits where user_id = 42"   # the plan, with the indexes used
komando db sizes events                              # from system.parts
komando db activity events                           # running queries
komando db kill events 8078617214407497              # the pid db activity shows
```

- **The URL.** The path is the database (the user's default when left
  out). The options are `tls=` (`true`, `skip-verify`, `false`) and
  `ca=secret:NAME` for a private CA (with `tls=true`). Without a port it is
  8443 with TLS and 8123 without. Ports 9000 and 9440 are ClickHouse's
  native protocol, which komando does not speak: it says so.
- **Without `--write` nothing changes.** ClickHouse has no transactions,
  but it has its own read-only mode: every request komando sends without
  `--write`, and every query that returns rows, carries the setting
  `readonly=1`, and the server refuses writes, DDL and setting changes.
  `SETTINGS` and `SET` in a read are refused for the same reason.
- **A write cannot be rolled back.** `INSERT`, `ALTER`, `CREATE`,
  `OPTIMIZE` and every other statement that is not a read need `--write`,
  must be sent on their own, and a dry run only reports them. Destructive
  ones need `--allow-dangerous` as usual: `DROP`, `TRUNCATE`, `DETACH`,
  `ALTER ... DROP` or `CLEAR`, `SYSTEM`, `KILL QUERY`, users, roles,
  quotas and grants, `BACKUP` and `FREEZE`.
- **Reading from elsewhere.** `readonly=1` lets reads through, also reads
  that reach other servers or the server's files. So the table functions
  and engines that do (`url()`, `s3()`, `remote()`, `mysql()`,
  `postgresql()`, `file()`, `executable()`, `Kafka`, ...) need `--write`
  and `--allow-dangerous`, also inside `DESCRIBE` or `EXPLAIN`.
- **A read-only user.** A user whose settings profile has `readonly = 1`
  may not send any setting, so komando sends none (its `--timeout` then
  only stops the waiting, not the query). For a hard limit, give the conn
  such a user with only `SELECT` grants.
- Text in `$$...$$` and names or text with letters outside ASCII outside
  quotes are refused (`SQL_HIDDEN_CODE`): use `'...'` (with `\'` for a quote) and
  `` `...` ``. `FORMAT` and `INTO OUTFILE` are refused too: komando reads
  the rows itself (`-o csv`, `-o tsv`).
- `db explain` is `EXPLAIN indexes = 1`; ClickHouse has no
  `EXPLAIN ANALYZE` (`NOT_SUPPORTED`).
- **Users.** `db user add` creates a SQL user with a SHA-256 hash of the
  password and a random salt that komando computes, so the password never
  reaches the server or its query log; `--no-login` creates a role. The
  conn's user needs access management (or `CREATE USER` and `GRANT`).
  `db grant` takes `--on DB.*`, `DB.TABLE`, `*.*`, `database:DB` or
  `table:DB.TABLE` (`SELECT`, `INSERT`, `ALTER`, `CREATE`, `DROP`,
  `TRUNCATE`, `OPTIMIZE`, `SHOW`, `KILL QUERY`, ...), and `--role NAME`.
  Users defined in the server's `users.xml` cannot be changed with SQL.
- **Backups.** `db dump` and `db restore` are not available for
  ClickHouse (`NOT_SUPPORTED`). Its own `BACKUP TABLE ... TO Disk('backups',
  'name.zip')` (or `S3(...)`) writes the backup on the server, with
  `--write` and `--allow-dangerous`.

## Snowflake

Snowflake conns take the same `db` commands, in Snowflake SQL. komando
speaks Snowflake's SQL API (HTTPS) with its own client, so nothing else
needs to be installed:

```bash
komando secret set analytics-key < rsa_key.p8      # the user's private key (key-pair login)
komando conn add analytics 'snowflake://APP_RO@myorg-myaccount/ANALYTICS/PUBLIC?warehouse=REPORTING&role=ANALYST_RO' \
  --password-ref secret:analytics-key
komando db query analytics "select region, sum(total) from orders where placed > ? group by 1" --arg 2026-01-01
komando db schema analytics public.orders          # columns, primary key, clustering key
komando db explain analytics "select * from orders where id = 42"
komando db activity analytics                      # running and queued queries
komando db kill analytics 4387013457812345         # the pid db activity shows
komando db grants analytics APP_RO                 # its roles, and what each role may do
```

- **The URL.** The account goes where other kinds have a host: the
  account identifier Snowflake shows (`myorg-myaccount`, or a locator with
  its region such as `xy12345.eu-central-1`; `...snowflakecomputing.com`
  works too). The path is `/DATABASE/SCHEMA`, both optional; the options
  are `warehouse=`, `role=` and `ca=secret:NAME` (a proxy that inspects
  TLS). It is always HTTPS on port 443 with the certificate checked.
- **Login.** Snowflake's SQL API takes no passwords, so `--password-ref`
  holds one of two things:
  - **A private key** (PEM, `-----BEGIN PRIVATE KEY-----`) for key-pair
    login. komando signs a short-lived token with it for each hour of use.
    Snowflake must know the public half: `ALTER USER APP_RO SET
    RSA_PUBLIC_KEY = '...'`. Store the key without a passphrase (the vault
    encrypts it): `openssl pkcs8 -topk8 -nocrypt -in rsa_key.p8 | komando
    secret set analytics-key`.
  - **A programmatic access token** (`ALTER USER APP_RO ADD PROGRAMMATIC
    ACCESS TOKEN ...`), which Snowflake lets stand where a password goes.

  Browser sign-in (SSO) and OAuth are not supported in this version.
- **Read-only is komando's check, not Snowflake's.** Snowflake has no
  read-only mode komando can switch on, and each statement is a session of
  its own, so nothing can be rolled back. Without `--write` komando sends
  only statements it rates as reads, one per request, and asks Snowflake to
  run exactly one statement. A statement that is not a read (`INSERT`,
  `CREATE`, `COPY`, `CALL`, ...) needs `--write`, goes on its own, and a
  dry run only reports it. Give the conn a role that may only read, so
  a mistake in komando's checks cannot change anything either:

  ```sql
  CREATE ROLE ANALYST_RO;
  GRANT USAGE ON WAREHOUSE REPORTING TO ROLE ANALYST_RO;
  GRANT USAGE ON DATABASE ANALYTICS TO ROLE ANALYST_RO;
  GRANT USAGE ON ALL SCHEMAS IN DATABASE ANALYTICS TO ROLE ANALYST_RO;
  GRANT SELECT ON ALL TABLES IN DATABASE ANALYTICS TO ROLE ANALYST_RO;
  GRANT SELECT ON FUTURE TABLES IN DATABASE ANALYTICS TO ROLE ANALYST_RO;
  GRANT ROLE ANALYST_RO TO USER APP_RO;
  ALTER USER APP_RO SET DEFAULT_ROLE = ANALYST_RO;
  ```

  and name it in the URL (`?role=ANALYST_RO`).
- **Destructive** (`--allow-dangerous`): `DROP`, `TRUNCATE`,
  `CREATE OR REPLACE` (it drops what had the name), users, roles, grants
  and policies, warehouses, integrations, shares and `ALTER ACCOUNT`,
  stage files (`PUT`, `GET`, `REMOVE`, `COPY INTO @stage`), URLs and
  credentials in a statement, `CALL` and `EXECUTE IMMEDIATE`, and
  `SYSTEM$` functions other than those that only read
  (`SYSTEM$CANCEL_QUERY` among them).
- A Snowflake Scripting block (`BEGIN ... END`, `DECLARE`) goes as one
  statement: `EXECUTE IMMEDIATE $$ ... $$`. `BEGIN` and `COMMIT` are
  refused. A `/*` inside a comment, `$$` right after a name, and names or
  text with letters outside ASCII outside quotes are refused
  (`SQL_HIDDEN_CODE`).
- **A warehouse.** Most queries need one: give it with `?warehouse=`.
  `SELECT 1` and `SHOW` do not, so `conn test` works without one.
- `db schema`, `db sizes` and `db activity` read the URL's database
  (`INFORMATION_SCHEMA`); activity shows the queries the conn's role may
  see. `db explain` is `EXPLAIN` (not run); `--analyze` is not available.
  Unquoted names are upper case, so `db schema analytics orders` finds
  `ORDERS`.
- **Not available** (`NOT_SUPPORTED`): `db dump` and `db restore`
  (Snowflake unloads with `COPY INTO @stage`, and keeps copies with Time
  Travel and `CLONE`), `db user add`, `passwd` and `rm`, `db grant` and
  `revoke` (send the SQL with `db query --write`), and `db locks`.

## BigQuery

BigQuery conns take the same `db` commands, in GoogleSQL. komando speaks
BigQuery's REST API with its own client (not the Google Cloud SDK), so
nothing else needs to be installed:

```bash
komando conn add warehouse 'bigquery://my-project/analytics?location=EU'   # gcloud's login
komando db query warehouse --dry-run "select * from orders where placed > '2026-01-01'"  # what it would read
komando db query warehouse "select region, sum(total) from orders where placed > ? group by 1" --arg 2026-01-01
komando db query warehouse "select * from logs.events" --max-bytes 200GB   # allow a bigger read
komando db schema warehouse analytics.orders        # columns, primary key, partitioning, clustering
komando db explain warehouse "select * from orders where id = 42"
komando db activity warehouse                       # jobs that are not done
komando db kill warehouse 4387013457812345          # the pid db activity shows
```

- **The URL.** `bigquery://PROJECT[/DATASET]?location=EU`: the project the
  jobs run in (and are billed to), a default dataset for names without one,
  and where the jobs run (`EU`, `US`, `europe-west1`, ...; without it
  BigQuery picks from the tables, and `db activity` and `db sizes` use the
  dataset's location, or `US`). Other options: `ca=secret:NAME` (a proxy
  that inspects TLS) and `endpoint=URL` (an emulator, or a Private Service
  Connect address such as `https://bigquery-NAME.p.googleapis.com`). It is
  HTTPS with the certificate checked; `tls=` is refused.
- **Login.** The same as for `gs://` conns: gcloud's login (`gcloud auth
  application-default login`, `GOOGLE_APPLICATION_CREDENTIALS`, or the
  metadata server on Google Cloud), or a service account key (the JSON
  file) in `--password-ref`:

  ```bash
  komando secret set warehouse-key < key.json
  komando conn add warehouse 'bigquery://my-project/analytics' --password-ref secret:warehouse-key
  ```

  gcloud's login is only sent to Google's own hosts
  (`https://*.googleapis.com`); an emulator gets a key the conn names, or
  no login at all. The login needs `roles/bigquery.jobUser` on the project
  and `roles/bigquery.dataViewer` on the datasets it reads; give a conn
  that only reads no more than that.
- **Every statement is checked by BigQuery first.** komando sends each
  statement as a dry run (it runs nothing and costs nothing), which says
  what kind of statement BigQuery sees and how many bytes it would read.
  Without `--write` only what BigQuery calls a `SELECT` runs, after
  komando's own check. A write (`INSERT`, `CREATE`, `MERGE`, ...) needs
  `--write` and goes on its own (each statement is a job of its own, so
  nothing can be rolled back).
- **Cost.** BigQuery bills by the bytes a query reads. A query that would
  read more than `--max-bytes` (default `10GB`; `0` is no cap) does not run
  (`DB_BYTES_LIMIT`), and every job carries that cap
  (`maximumBytesBilled`), so BigQuery stops it as well. Each result says
  `bytes_processed`. `--dry-run` (with or without `--write`) is BigQuery's
  own dry run for every statement, also a `SELECT`: it shows what each
  would read and runs nothing. A run that times out cancels its job.
- **Placeholders** are `?`, and the `--arg` values go as `STRING`: BigQuery
  does not turn text into numbers by itself, so write `CAST(? AS INT64)`.
- **Destructive** (`--allow-dangerous`): `DROP`, `TRUNCATE`,
  `CREATE OR REPLACE` (it drops what had the name), `LOAD DATA OVERWRITE`,
  `GRANT` and `REVOKE`, row access policies, reservations, capacity
  commitments and project or organization options, `EXPORT DATA` (it writes
  outside BigQuery), `EXTERNAL_QUERY` and remote functions (they reach
  other services), `CALL` and `EXECUTE IMMEDIATE`.
- **Scripts** (`DECLARE`, `SET`, `IF`, `BEGIN ... END`) are refused: komando
  sends each statement as a job of its own, so variables would not carry
  over. `BEGIN` and `COMMIT TRANSACTION` are refused too. A `/*` inside a
  comment, a raw string with a backslash before a quote, and names or text
  with letters outside ASCII outside quotes are refused
  (`SQL_HIDDEN_CODE`); `#` comments, triple-quoted text and `` `names` ``
  are read as BigQuery reads them.
- `db schema` reads the API (no query, no cost): the URL's dataset, or
  every dataset in the project, and a table asked for as `TABLE`,
  `DATASET.TABLE` or `PROJECT.DATASET.TABLE`. `db explain` is the dry run
  (statement type, bytes, tables read, result columns); `--analyze` is not
  available. `db activity` reads `region-LOCATION.INFORMATION_SCHEMA.JOBS`
  (seeing other people's jobs needs `bigquery.jobs.listAll`) and `db
  sizes` reads `INFORMATION_SCHEMA.TABLE_STORAGE`.
- **Not available** (`NOT_SUPPORTED`): `db dump` and `db restore`
  (`EXPORT DATA` writes tables to Cloud Storage, and table snapshots keep
  copies inside BigQuery), `db user`, `db grant`, `revoke` and `grants`
  (Google Cloud IAM), and `db locks`.

## Interactive SQL shell (for people)

```bash
komando db shell staging-db           # komando's own SQL shell; starts read-only
komando db shell staging-db --write   # allow changes
komando db shell app-db --yes         # any shell on a protected conn needs --yes
```

`db shell` is komando's own SQL shell for PostgreSQL, MySQL/MariaDB,
SQL Server, Oracle, ClickHouse, Snowflake, BigQuery and SQLite, so nothing
else needs to be installed. It connects through the conn's `--via` path,
and every statement gets the same checks as
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
| `\write` | allow changes for the rest of the shell (it asks first, also on a protected conn); `\write` again goes back to read-only |
| `\?` | list the commands |
| `\d [TABLE]` | list tables, or show one table |
| `\l` / `\dn` / `\du` | databases / schemas / roles |
| `\x` | expanded rows (or end a statement with `\G`) |
| `\timing` | show how long each statement takes |
| `\i FILE` | run SQL from a file |

Up and down arrows recall earlier lines. The read-only mode is the
database's own (a read-only transaction): `\write` connects again with
changes allowed. A destructive statement (`DROP`, `TRUNCATE`, a `DELETE`
without `WHERE`) asks you to type the conn's name first, as `db query` does
at the command line; anything else is `Not run.`. The shell is for people at
a terminal: agents and scripts get `NEEDS_TERMINAL` and use `db query`,
which returns JSON.

## Troubleshooting

| Error | Exit | Meaning |
|-------|------|---------|
| `DB_AUTH` | 4 | wrong user name or password |
| `DB_NOT_FOUND` | 3 | the database does not exist |
| `DB_PRIVILEGE` | 5 | the conn's user lacks a right (for example to see lock waits in `db locks`, or to manage users) |
| `DB_BYTES_LIMIT` | 6 | a BigQuery query would read more than `--max-bytes` (default 10GB), so it did not run |
| `DUMP_UNSUPPORTED` | 2 | komando's own dump cannot write an object; the message names it |
| `TOOL_MISSING` | 3 | `pg_dump`, `mysqldump` or `pg_restore` is not installed where it should run |
| `TOOL_TOO_OLD` | 5 | `pg_dump` is older than the database server, or `pg_restore` older than the archive |
| `CONN_UNREACHABLE` | 4 | the tool cannot reach the database from the server it runs on |
| `NEEDS_TERMINAL` | 2 | `db shell` was run without a terminal; use `db query` |

`db dump` and `db restore` report the same connection errors as `db query`.
