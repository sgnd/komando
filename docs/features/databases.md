# Databases

Query, inspect, back up and restore PostgreSQL, MySQL/MariaDB, SQL Server,
Oracle, ClickHouse, Snowflake, BigQuery, SQLite and MongoDB databases
safely. [All docs](README.md)

A database command is `komando database PROVIDER VERB NAME`: the provider
is the engine (`postgres`, `mysql`, `sqlserver`, `oracle`, `clickhouse`,
`snowflake`, `bigquery`, `sqlite`, `mongodb`), the verb is `add`, `query`,
`backup` and so on, and NAME is the database's name in komando's list.

## Add a database

```bash
komando credential password add prod-db-pass --user app --ask   # a person types the password, hidden
komando database postgres add prod-db postgres://10.0.0.5:5432/app --via web1 --credential prod-db-pass --protected
komando test prod-db                         # can komando reach it and log in?
```

Typed alone, `komando database postgres add` asks for each part step by
step.

komando calls a database an **entry** (see the [glossary](glossary.md)).
The provider is the engine, and it is also the start of the URL:

| Provider | URL example |
|----------|-------------|
| `postgres` | `postgres://10.0.0.5:5432/app?sslmode=require` |
| `mysql` (also MariaDB) | `mysql://db.internal:3306/shop?tls=true` |
| `sqlserver` | `sqlserver://db.internal:1433/sales?encrypt=true` (also `mssql://`). See [SQL Server](#sql-server). |
| `oracle` | `oracle://db.internal:1521/ORCLPDB1?tls=true` (the path is the service name). See [Oracle](#oracle). |
| `clickhouse` | `clickhouse://ch.internal:8443/analytics?tls=true` (the HTTP interface). See [ClickHouse](#clickhouse). |
| `snowflake` | `snowflake://myorg-myaccount/ANALYTICS/PUBLIC?warehouse=REPORTING&role=ANALYST_RO` (the account in place of a host). See [Snowflake](#snowflake). |
| `bigquery` | `bigquery://my-project/analytics?location=EU` (the project, and a default dataset). See [BigQuery](#bigquery). |
| `sqlite` | `sqlite:///var/lib/app.db` (a file on this computer; on Windows `sqlite://C:\data\app.db`) |
| `mongodb` | `mongodb://db1.internal:27017,db2.internal/shop?replicaSet=rs0&authSource=admin` (Atlas: `mongodb+srv://cluster0.abcde.mongodb.net/shop`). See [MongoDB](#mongodb). |

`komando database --help` lists the providers, and `komando schema` lists
every database command.

TODO(cut): the typed flags of each provider's `add` (host, port, database,
options) that replace the URL wait on the `Options` of each leaf in the
table (PR B).

The user name is part of the credential, not of the URL. Never put the
password in the URL; komando refuses it. A credential holds it, sealed
(see [Credentials](credentials.md)):

```bash
komando credential password add prod-db-pass --user app      # asks for the password, hidden
komando database postgres add prod-db postgres://10.0.0.5:5432/app --via web1 --credential prod-db-pass --protected
```

Or point the credential at your password manager with
`komando credential password add prod-db-pass --user app --store my-vault --item prod-db`.

A URL says more than its address: Postgres reads `host=`, `port=`,
`hostaddr=` and `service=`, Redis `sentinels=`, MongoDB more seed hosts,
RabbitMQ `management=`, and most kinds a CA or TLS mode. So for an entry
with a stored password, every setting of its URL counts as part of where
the password goes, except the few that move nothing (`connect_timeout`,
`application_name` and other timeouts): an AI agent's change of any other
needs your yes (`SECRET_DESTINATION`). komando reads a Postgres entry from
its URL only: never from `PG*` environment variables, and never with a
password from `~/.pgpass` unless the URL names a `passfile=`.

A SQLite entry never opens komando's own folder. For an AI agent it also
never opens a file in a folder where logins are kept (`~/.ssh`, `~/.aws`,
`~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker`) or any other file
komando keeps from agents, links followed, and `database PROVIDER backup --to`
and `database PROVIDER restore --from` refuse the same paths
(`SENSITIVE_FILE`).

A password that should never be kept on this computer is typed each time
instead. Make the credential with `--ask`, and it keeps no password:

```bash
komando credential password add prod-db-pass --user app --ask
komando database postgres add prod-db postgres://10.0.0.5:5432/app --via web1 --credential prod-db-pass
komando database postgres edit prod-db --credential prod-db-pass   # point an existing entry at it
```

An entry that uses an `--ask` credential asks as a
[server that uses one](servers.md) does: at your terminal (hidden), in an
app's window, or, for an AI agent's command, in komando's own window,
which names the entry, its user, address, the way there (`--via`) and the
command; the agent never sees the password. A cancel stops the command
with `DECLINED`, and the window stays shut for that entry for a minute. A
script, or an agent with no screen, gets `NEEDS_PERSON`. Only you set
where the password goes: an AI agent that adds an entry with an `--ask`
credential, changes its URL (its user too) or `--via`, points it at such a
credential, changes a server or VPN on its way, or replaces a credential
its URL names (`ca=credential:`) gets `NEEDS_PERSON`; as for a stored
password (above), every setting of the URL except the few that move
nothing counts as where it goes. An agent's `database PROVIDER backup` and
`restore` of such an entry stop too: the dump tool would get the password
in its environment, where the agent's own programs could read it; run those
yourself. A file (SQLite) or a cluster has no password to type: an `--ask`
credential is refused there. An entry has no separate login command, so
every command asks; use TLS (`sslmode=verify-full`, `tls=true`) so the
server is checked before the password goes out.

`--via web1` means "the database is only reachable from web1". komando
connects through web1 over SSH by itself: there is no tunnel to start and no
port opens on your computer. `--via` can also be a chain or a VPN (see
[Tunnels](tunnels.md) and [VPNs](vpn.md)). An entry that goes straight over
the network should use TLS: see [Encryption (TLS)](#encryption-tls).

At a terminal, a command with the database or the SQL left out asks for
it, with a list of your databases, then prints the full command. Typed
alone, `komando database postgres query` asks which database, then the
SQL. An AI agent or a script gets `USAGE` (exit 2) with an example in the
hint. Every error ends with a hint that names the next command to run,
with your entry in it.

### Check, change, rename or remove a database entry

```bash
komando database postgres list               # your PostgreSQL databases
komando list                                 # every entry, whatever its type
komando test prod-db                         # reachable? does the password work?
komando database postgres show prod-db       # its settings (passwords stay credential names)
komando database postgres edit prod-db --label tier=critical
komando database postgres edit prod-db --protected   # every change then needs a person's yes
komando database postgres rename prod-db shop-db     # every reference follows
komando database postgres remove staging-db  # komando forgets it; the database is untouched
```

- Entries use the same targets as servers (`@group`, `tag:prod`, `*-db`,
  `all`). See [Targets](targets.md).
- Entries share one set of names: a server and a database cannot both be
  called `db1`. Names ignore upper and lower case, so `DB1` is the same
  name.
- A server that an entry uses in `--via` cannot be removed until the entry
  is changed.

## Look at tables

Tables, columns and indexes are SQL. Send it with `query`; the catalog
views are the same ones psql, mysql and the other clients read.

```bash
komando database postgres query prod-db "select table_name, table_type from information_schema.tables where table_schema = 'public' order by table_name"
komando database postgres query prod-db "select column_name, data_type, is_nullable from information_schema.columns where table_name = 'users' order by ordinal_position"
komando database postgres query prod-db "select indexname, indexdef from pg_indexes where tablename = 'users'"
```

```text
table_name  table_type
orders      BASE TABLE
users       BASE TABLE
(2 rows)
```

- Tables in the `public` schema are the ones named without a schema;
  others are `schema.table`.
- The other engines have their own catalogs: `information_schema` on
  MySQL, SQL Server, Snowflake and BigQuery, `all_tables` on Oracle,
  `system.tables` on ClickHouse, `sqlite_master` on SQLite. MongoDB has
  `listCollections` and `listIndexes` (see [MongoDB](#mongodb)).

## Run a query

```bash
komando database postgres query prod-db "select id, email from users order by id desc limit 2"
```

```text
id    email
1204  ana@example.com
1203  budi@example.com
(2 rows)
```

Queries only read unless you add `--write` (see [Change data](#change-data)).

```bash
komando database postgres query prod-db "explain select * from orders where user_id = 42"
komando database postgres query prod-db --file report.sql   # SQL from a file (--file - reads stdin)
```

Use `--arg` for values instead of pasting them into the SQL. The
placeholders are `$1`, `$2` in PostgreSQL, `?` in MySQL and SQLite,
`@p1`, `@p2` in SQL Server, `:1`, `:2` in Oracle, `?` in Snowflake and
BigQuery (where the values go as `STRING`), and `{p1:String}`,
`{p2:UInt64}` in ClickHouse (named `p1`, `p2`, with a type):

```bash
komando database postgres query prod-db "select * from users where email = $1" --arg bob@example.com
```

The number of `--arg` values must match the placeholders (`USAGE`, exit 2).
In Oracle SQL each placeholder takes its own `--arg`, also a name used
twice (`where a = :1 or b = :1` takes two); in a PL/SQL block a name used
twice takes one.

### Export rows to CSV or TSV

For spreadsheets and scripts, `-o csv` or `-o tsv` prints the rows
instead of JSON or a table. NULL is an empty field, binary is `\x` hex:

```bash
komando database postgres query prod-db -o csv "select id, email from users" > users.csv
```

A CSV or TSV export has every row, unless you give `--limit` (komando
then says on stderr when it stopped there). If the rows are more than
`--max-output` bytes, komando prints nothing and fails with
`OUTPUT_TRUNCATED` (exit 1), so a file is never cut without you knowing:
raise `--max-output`, or for a whole database use `komando database postgres backup`.
Errors go to stderr, so the file holds only rows.

### How much comes back, and how long it may run

Otherwise a query returns at most 500 rows (`--limit`, `0` for no limit)
and `--max-output` bytes. A cut result says which cap it hit:
`"truncated": "rows"` (raise `--limit`) or `"truncated": "bytes"` (raise
`--max-output`). A query stops after 30 seconds; use `--timeout 2m` for
more, or give one entry its own limit:

```bash
komando database postgres edit prod-db --option statement_timeout=10s
```

`--timeout` on the command line always wins.

On a protected entry, an AI agent sees email addresses, phone numbers, card
numbers and IBANs in the rows as `[hidden: email]` and so on. Name the
columns that hold other personal data (names, addresses) to hide them
whole, for the agent: see [Personal data](safety.md#personal-data).

```bash
komando database postgres edit prod-db --option 'mask_columns=full_name address birth_date'
```

An AI agent's query that names such a column (to rename it, compute from
it or filter on it) stops with `REVEAL_NEEDS_PERSON`; `SELECT *` shows it as
`[hidden: column]`. An agent's `backup` stops with `NEEDS_PERSON` on every
database: the file holds every row as it is, passwords, tokens and personal
data included, and the agent would read it next. No flag lifts it, and
`--reveal` opens no window for it. A person runs the backup in their own
terminal.

SQL that starts with a `-- comment` looks like a flag to the command
line. Put `--` before it, or use `--file -`.

In text output, tables line up, also with CJK characters and emoji. How
each column type looks in JSON is in [Reference](#how-values-come-back-json).

## Change data

`komando database postgres query` does not change your data unless you add `--write`.
Without it, the query runs in a read-only transaction and the database
itself refuses changes.

Changing data takes two steps. First a dry run: the SQL really runs, you
see how many rows it touches, and then everything is rolled back.

```bash
komando database postgres query prod-db --write --dry-run "update users set plan = 'pro' where id = 42"
komando database postgres query prod-db --write "update users set plan = 'pro' where id = 42"
```

```text
1 row affected
dry run: rolled back, nothing changed
```

The seatbelts:

- A protected entry asks before every `--write`, whatever the SQL is.
- Destructive SQL is stopped: `DROP`, `TRUNCATE`, `DELETE` or `UPDATE`
  without `WHERE`, privilege changes, code that reaches the server's
  operating system (`CREATE EXTENSION`, a function in C or `plpython3u`,
  `LOAD`, MySQL `INSTALL PLUGIN` and `SONAME`, SQL Server
  `CREATE ASSEMBLY`), and a few more. `komando policy list` shows them
  all; `komando policy check "komando database postgres query prod-db 'drop table users'"`
  tests a query.
- At your terminal komando asks you first (a protected entry: a yes;
  destructive SQL: `--allow-dangerous`); an AI agent or a script adds
  `--yes` (or `--allow-dangerous`) after a person agrees. Without it, it
  gets `PROTECTED_TARGET` or `POLICY_BLOCKED` (exit 6). See
  [Safety](safety.md#what-needs-a-yes).
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
  blocked (no `--allow-dangerous`, or a protected entry without `--yes`), a
  dry run runs nothing and only shows the plan. A function you call by name
  (`SELECT reset_ids()`) runs, and what it does outside the transaction
  (a sequence, a file) stays.
- `explain analyze` really runs the query, so a query that changes data
  needs `--write` there too.

These checks catch mistakes. For real limits, give komando a database user
with only the rights it needs.

## Back up and restore

```bash
komando database postgres backup prod-db --to backups/
```

```text
prod-db: backups/prod-db-2026-11-13.sql.gz (48.2 MiB)
```

Typed alone, `komando database postgres backup` asks which database to back up, then
which file to save it to.

Which kinds komando can back up itself:

| Provider | `backup` / `restore` | Instead |
|------|--------------------------|---------|
| PostgreSQL | yes | |
| MySQL / MariaDB | yes | |
| SQLite | `backup` copies the database file; no `restore` | stop the app, then copy the file back |
| MongoDB | no | `mongodump` on a server, with `komando host ssh exec` |
| SQL Server | no | `BACKUP DATABASE ... TO DISK` with `database sqlserver query --write`, then `komando copy` the `.bak` file |
| Oracle | no | Data Pump (`expdp`, `impdp`) or RMAN with `komando host ssh exec`, then `komando copy` |
| ClickHouse | no | `BACKUP TABLE ... TO Disk('backups', 'name.zip')` (or `S3(...)`) with `database clickhouse query --write` |
| Snowflake | no | `COPY INTO @stage`, Time Travel or `CLONE` |
| BigQuery | no | `EXPORT DATA` to Cloud Storage, or table snapshots |

A "no" kind answers `NOT_SUPPORTED`, with this hint. The backup SQL in
the "Instead" column needs `--allow-dangerous` too. For a big job, `komando host ssh exec` keeps running if the link drops
(come back with `--attach ID`). For a few rows,
`komando database postgres query NAME -o csv` is a copy on this computer.

```bash
komando database postgres backup prod-db                                   # prod-db-<date>.sql.gz in this folder
komando database postgres backup prod-db --to prod-2026-11-02.sql.gz       # plain SQL, compressed (.gz)
komando database postgres backup prod-db --to prod.dump --format custom    # PostgreSQL archive, for pg_restore
komando database postgres backup prod-db --to orders.sql --table public.orders   # one table (repeatable)
komando database postgres backup prod-db --to schema.sql --schema-only     # no rows
komando database postgres restore staging-db --from prod-2026-11-02.sql.gz --dry-run   # checks the file, changes nothing
komando database postgres restore staging-db --from prod-2026-11-02.sql.gz
komando database postgres restore staging-db --from prod.dump            # an archive: pg_restore on the entry's --via server
komando database postgres backup prod-db --to prod.dump --format custom --run-on db1     # pg_dump runs on the server db1
komando database postgres restore staging-db --from prod.dump --run-on db1             # pg_restore runs on db1
```

A restore can overwrite data. At your terminal komando asks you first;
an AI agent or a script adds `--allow-dangerous` (and `--yes` on a
protected entry) after a person agrees. See [Restore safely](#restore-safely).

### Where the backup goes, and who makes it

The backup always goes to a file on this computer, readable only by you.
An existing file is never overwritten. Without `--to` it is
`NAME-<date>.sql.gz` in this folder (`--format custom`:
`NAME-<date>.dump`; SQLite: `NAME-<date>.db`); `--to` a folder puts that
name inside it.

`pg_dump` or `mysqldump` runs on a server that has it: the one you name with
`--run-on HOST`, else the last server of the entry's `--via` path. Otherwise (a
direct entry or a VPN, or a `--via` server without the tool) komando dumps by
itself, and nothing has to be installed. `runs_on` in the answer (and in
`komando audit`) names where the tool ran. A plain SQL restore is always run
by komando itself, through the same `--via` path, never by `psql` or
`mysql`: those would obey client commands hidden in the file on that server.
Only a PostgreSQL archive goes to `pg_restore` on the server. `tool` in the
answer says which was used.

The password goes to a server's tool through its environment, never on its
command line, so other users of that server cannot see it. For MySQL entries
with `?tls=...`, the same TLS setting is passed to the server's tools (MySQL
and MariaDB clients both work). For Postgres, `pg_dump` and `pg_restore`
read the entry URL themselves: with `sslmode=verify-full` (or `verify-ca`)
they check the database's certificate against `~/.postgresql/root.crt` on
the server they run on, not against the system's CAs as komando does. With
`pg_dump` 16 or newer, komando adds `sslrootcert=system`, so they use the
system's CAs too. An older one needs the CA in that file there; without it
the dump stops with `DB_CONNECT` and a hint (install `postgresql-client` 16
or newer, put the CA in `~/.postgresql/root.crt`, or reach the database
`--via` that server without TLS).

### A private CA (`?ca=credential:NAME`)

The tools on the server check the database's certificate against the entry's
CA too, the same full check komando makes: signed by that CA and naming the
server. komando sends the CA after the password, on the tool's input, never
on its command line. It lands in a new folder in `/tmp` that only the login
user can open, and goes once the tool ends. `pg_dump` and `pg_restore` of
any version get it as `sslrootcert=` with `sslmode=verify-full` (in place of
`ca=`, which libpq does not know), so `~/.postgresql/root.crt` is not
needed. `mysqldump` gets `--ssl-ca` and a checked TLS connection, also when
the URL has no `tls=`.

### Run the dump on a server you choose (`--run-on HOST`)

This helps when the entry goes through a VPN (komando then can only write
plain SQL itself) but a server you manage has `pg_dump` and can reach the
database, often the database server itself:

```bash
komando database postgres backup prod-db --to prod.dump --format custom --run-on db1 --dry-run
komando database postgres backup prod-db --to prod.dump --format custom --run-on db1
```

- `HOST` is a server from your list (a name or a selector that picks
  exactly one); komando reaches it the usual way, through its own `--via`.
  The entry's password goes to it, so a `user@address` that is not in your
  list is refused, and for an AI agent a server other than the entry's
  own `--via` server needs your yes (`SECRET_DESTINATION`).
- The tool there connects to the entry URL's address as that server sees
  it. When the database only listens on `127.0.0.1` on that server, add a
  second entry for that address reached through it
  (`komando database postgres add prod-db-local postgres://127.0.0.1:5432/app --via db1 --credential prod-db-pass`)
  and dump that one; `CONN_UNREACHABLE` says this when it happens.
- A dump runs at low priority (`nice -n 10`, plus `ionice -c3` where the
  server has it), so the server keeps serving its users. `low_priority` in
  the answer says so.
- The backup streams back over SSH into `--to` on this computer (compressed
  here when it ends in `.gz`); nothing is written on the server, except a
  private CA's certificate while the tool runs.
- `pg_dump` refuses a server newer than itself. komando reports that as
  `TOOL_TOO_OLD` with both versions and the package to install
  (`postgresql-client-NN`). A server named with `--run-on` is never skipped: a
  missing or old tool there is an error, while a `--via` server without a
  usable tool falls back to komando's own plain SQL dump.
- `restore --run-on HOST` runs `pg_restore` there for an archive, streaming
  the file to it over SSH. It asks the same as any restore. Plain SQL is
  always restored by komando itself, so `--run-on` with a SQL file is refused.
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
- `--format custom` needs `pg_dump` on a server (`--run-on HOST`, or the entry's
  `--via` server).
- For SQLite, `backup` copies the database file (`--to backup.db`); a `.gz`
  name, `--format`, `--schema-only`, `--table` and `--run-on` are refused.

### Restore safely

- A restore can overwrite data. At your terminal komando first offers to
  save the database as it is now (`Save a copy of staging-db as it is now
  first, so you can go back? [Y/n]`), then asks you to type the entry's
  name instead of `--allow-dangerous`. Scripts and AI agents get no
  question: run `komando database postgres backup NAME` first yourself, then add
  `--allow-dangerous` (and `--yes` on a protected entry) after a person
  agrees.
- The file that was checked is the file that is restored. komando keeps
  a fingerprint of every part of the file from the check; a file that is
  changed, replaced or made longer afterwards stops with `FILE_CHANGED`
  (exit 8) before the database is opened. The restore reads a private
  copy that matched the check whole, so it is never cut in two: a change
  anywhere in the file leaves the database untouched. Run the restore
  again: komando checks the file as it is now.
- That copy goes to komando's own run folder (Linux: `$XDG_RUNTIME_DIR/komando`
  or `~/.local/state/komando/run`; macOS: `~/Library/Application Support/komando/run`;
  Windows: `%LOCALAPPDATA%\komando\run`), mode 0600, and is removed when
  the restore ends, whatever the end. Too little free space there stops
  the restore before it starts (`RESTORE_SPACE_MISSING`).
- A MySQL `DELIMITER` after a statement on the same line is refused
  (`UNSAFE_BACKUP`); mysqldump writes it on a line of its own.
- A PostgreSQL archive (`--format custom`) is read too: komando checks the
  SQL in its table of contents (pg_dump 9.5 to 17 archives) and names what
  it does beyond writing data, as for plain SQL (`COPY ... PROGRAM`,
  `GRANT`, ...). The line numbers count in that SQL, as `pg_restore -f -`
  prints it. An archive komando cannot read (another version, cut short,
  damaged) is refused (`BAD_FILE`). One whose table of contents holds
  more than 256 MiB of SQL is refused with `FILE_TOO_LARGE`: dump fewer objects (`pg_dump -Fc -n
  SCHEMA` or `-t TABLE`) and restore each part, or run `pg_restore` by
  hand. One that keeps table data as SQL
  (`pg_dump --inserts`) is named in the approval as SQL komando did not
  read. A gzipped archive (`.dump.gz`) is refused: unpack it first.
- A pg_dump tar archive (`-Ft`) or directory archive (`-Fd`) is refused
  (`USAGE`) with its format named: komando does not check those formats.
  Any other tar file is refused the same way.
  Dump again with `--format custom` (`pg_dump -Fc`) or as plain SQL
  (`pg_dump -Fp`).
- PostgreSQL restores run in one transaction: if anything fails, nothing
  changes. MySQL runs the statements in order and stops at the first error;
  what ran before it stays (`RESTORE_FAILED`).
- komando reads the whole file before sending anything, the way psql and
  mysql would read it. A file with client commands that could run programs
  or read files (`\!`, `system`, `\i`) is refused (`UNSAFE_BACKUP`), and so
  is a file komando cannot follow: one that ends inside a quote or
  comment, or a `SET` or `set_config` that changes
  `standard_conforming_strings` or adds `NO_BACKSLASH_ESCAPES`. A file that
  switches databases (`\connect`, from
  `pg_dump --create` or `pg_dumpall`) is refused too
  (`RESTORE_UNSUPPORTED`): dump the one database without `--create`. Real
  single-database dumps pass. `restore --dry-run` runs this check too and
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
- `restore` does not take a SQLite file: stop the programs that use the
  database, then copy the backup over the database file.
- Big databases take time: `backup` and `restore` have no timeout unless you
  pass `--timeout`.

## Check on a database

What runs, what waits and how big things are come from the database's own
views, through `query`. They are reads, so they need no `--write`:

```bash
komando database postgres query prod-db "select version(), now() - pg_postmaster_start_time() as uptime, pg_size_pretty(pg_database_size(current_database())) as size"
komando database postgres query prod-db "select pid, usename, now() - query_start as running, query from pg_stat_activity where state = 'active'"
komando database postgres query prod-db "select pid, pg_blocking_pids(pid) as blocked_by, query from pg_stat_activity where cardinality(pg_blocking_pids(pid)) > 0"
komando database postgres query prod-db "select relname, pg_size_pretty(pg_total_relation_size(oid)) as total from pg_class where relkind = 'r' order by pg_total_relation_size(oid) desc limit 10"
komando database postgres query prod-db "explain (analyze, buffers) select * from orders where user_id = 42"
```

```text
version                    uptime   size
PostgreSQL 16.4 on x86_64  12 days  7.5 GB
(1 row)
```

Stop a slow query. This changes the server, so it needs `--write`; a dry
run shows what would be rated first:

```bash
komando database postgres query prod-db --write --dry-run "select pg_cancel_backend(4821)"
komando database postgres query prod-db --write "select pg_cancel_backend(4821)"      # cancel the query; the client stays connected
komando database postgres query prod-db --write "select pg_terminate_backend(4821)"   # end the whole connection
```

Ending a whole connection is destructive: at your terminal komando asks
you first; an AI agent or a script adds `--allow-dangerous` after a person
agrees.

- Each engine keeps these facts in its own place: `pg_stat_activity` on
  PostgreSQL, `information_schema.processlist` and `sys.innodb_lock_waits`
  on MySQL, `sys.dm_exec_requests` on SQL Server (`KILL`), `v$session` on
  Oracle (`ALTER SYSTEM CANCEL SQL`), `system.processes` and
  `system.parts` on ClickHouse (`KILL QUERY`), `information_schema.query_history`
  on Snowflake (`SYSTEM$CANCEL_QUERY`), `INFORMATION_SCHEMA.JOBS` on
  BigQuery.
- SQLite has no server sessions, so there is nothing to list or stop.
- On MongoDB use `currentOp` and `killOp` (see [MongoDB](#mongodb)).
- The sizes and the sessions of other users need rights on those views
  (`VIEW SERVER STATE` on SQL Server, `SELECT_CATALOG_ROLE` on Oracle).

## Users and grants

Database users and rights are SQL. Send `create user`, `grant`, `revoke`
and `drop user` with `query --write`:

```bash
komando database postgres query prod-db --write --dry-run "create user app_ro login"
komando database postgres query prod-db --write "grant select on all tables in schema public to app_ro"
komando database postgres query prod-db "select grantee, table_name, privilege_type from information_schema.role_table_grants where grantee = 'app_ro'"   # what it may do now
komando database postgres query prod-db "select rolname, rolsuper, rolcanlogin from pg_roles"   # all users and roles
komando database postgres query prod-db --write "revoke select on all tables in schema public from app_ro"
komando database postgres query prod-db --write "drop user app_ro"
```

TODO(cut): a way to give a new user's password without typing it into the
SQL waits on the ready-made snippets planned after v0.18.0.

- `create user`, `alter user`, `grant` and `revoke` change who may do
  what. `query --write` rates them as destructive: at your terminal komando
  asks you for `--allow-dangerous`, and scripts and AI agents add it after
  a person agrees (`POLICY_BLOCKED` without it). A rule of the built-in
  policy (`db-drop-user`) stops `drop user` the same way.
- Never type a password into the SQL: it would show in the audit log and
  in the server's query log. Keep it in a credential (see
  [Credentials](credentials.md)).
- On MySQL the account host is part of the name (`'app'@'10.0.%'`). On
  SQL Server see [SQL Server](#sql-server), on Oracle [Oracle](#oracle),
  on ClickHouse [ClickHouse](#clickhouse). On Snowflake the users are in
  `SHOW USERS` and `SHOW GRANTS TO USER`. On BigQuery users and rights are
  Google Cloud IAM, so there is no SQL for them. On MongoDB send
  `usersInfo`, `createUser` or `grantRolesToUser` with `query --write`
  (see [MongoDB](#mongodb)).
- A user that still owns objects or has sessions is not dropped by the
  server (an error like `2BP01`, "role cannot be dropped"). End its
  sessions first.

## Interactive SQL shell (for people)

```bash
komando database postgres shell staging-db           # komando's own SQL shell; starts read-only
komando database postgres shell staging-db --write   # allow changes
komando database postgres shell prod-db              # a protected entry asks first
```

`shell` is komando's own SQL shell for PostgreSQL, MySQL/MariaDB,
SQL Server, Oracle, ClickHouse, Snowflake, BigQuery and SQLite, so nothing
else needs to be installed. It connects through the entry's `--via` path,
and every statement gets the same checks as
`query`: read-only unless you started it with `--write`, destructive
statements only after you type the entry's name, and each one is written
to the audit log. A statement ends with `;` (an Oracle PL/SQL block: a
line with only `/`) and runs in its own transaction.

```text
staging-db> select id, name
         -> from users limit 2;
 id | name
----+------
  1 | ana
  2 | budi
(2 rows)
staging-db> \q
```

| Command | What it does |
|---------|--------------|
| `\q` | quit |
| `\write` | allow changes for the rest of the shell (it asks first, also on a protected entry); `\write` again goes back to read-only |
| `\?` | list the commands |
| `\d [TABLE]` | list tables, or show one table |
| `\l` / `\dn` / `\du` | databases / schemas / roles |
| `\x` | expanded rows (or end a statement with `\G`) |
| `\timing` | show how long each statement takes |
| `\i FILE` | run SQL from a file |

Up and down arrows recall earlier lines. The read-only mode is the
database's own (a read-only transaction): `\write` connects again with
changes allowed. A destructive statement (`DROP`, `TRUNCATE`, a `DELETE`
without `WHERE`) asks you to type the entry's name first, as `query` does
at the command line; anything else is `Not run.`. The shell is for people at
a terminal: agents and scripts get `NEEDS_TERMINAL` and use `query`,
which returns JSON. MongoDB has no `shell`.

## Encryption (TLS)

An entry that goes straight over the network (no `--via`, not to this
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

- Without a setting, a Postgres entry uses TLS when the server offers it,
  but does not check the certificate and goes on without TLS when told to.
  A MySQL entry without `tls=` is not encrypted, and the MySQL 8 login then
  encrypts the password with a key the server sends over that same plain
  connection, which someone in between can swap. A SQL Server entry without
  `encrypt=` (or with `encrypt=false`) encrypts only the login, and
  without `encrypt=` does not check the certificate either. An Oracle entry
  without `tls=true` uses no TLS; Oracle's own network encryption, when the
  server turns it on, encrypts but does not prove who the server is. A
  ClickHouse entry without `tls=true` is plain HTTP.
- komando checks by default. When `database PROVIDER add` (or `database PROVIDER edit --url`) saves
  such an entry and its URL does not say how to use TLS, komando adds
  `sslmode=verify-full` (Postgres), `tls=true` (MySQL, Oracle, ClickHouse,
  whose port 8123 becomes 8443) or `encrypt=true` (SQL Server) and says so in
  `warnings`. A URL that names a setting keeps it, and an entry through
  `--via` or to this computer is left as written. If the server has no TLS
  or a certificate from its own CA, the first connection's hint says what
  to do (the rows below).
- An entry whose URL turns the check off keeps working. `komando doctor`
  warns about every entry without checked TLS and prints the
  `komando database PROVIDER edit NAME --url ...` line that fixes it.
- A server whose certificate comes from a private CA (your company's, or a
  cloud's own, such as Amazon RDS or Azure Database): store the CA and name
  it with `?ca=`, for Postgres, MySQL, SQL Server, Oracle, ClickHouse,
  Snowflake and BigQuery (a proxy that inspects TLS). The certificate is
  then fully checked: signed by that CA and naming the server, also with
  `sslmode=require`, and never without TLS:

  ```bash
  komando credential certificate add rds-ca          # the CA bundle, global-bundle.pem
  komando database postgres add prod-db 'postgres://orders.abc123.eu-west-1.rds.amazonaws.com/orders?ca=credential:rds-ca' --credential prod-db-pass
  ```

  For Postgres a file on this computer works too:
  `?sslrootcert=/path/to/ca.pem`.

  TODO(cut): how a certificate file is given to `credential certificate add` waits on the `Options` of that leaf (PR B).
- When TLS stops a connection (the certificate does not check out, or the
  server has no TLS), the hint says what to do and names the weaker setting
  with what it costs.
- Through `--via`, the traffic is inside SSH up to the `--via` server.

## MongoDB

A MongoDB entry takes `query` with a command document in JSON instead of
SQL: its first key names the command, as in `runCommand`. Collections,
indexes, the server's version, the plan and the running operations are
commands too (`listCollections`, `listIndexes`, `buildInfo`, `explain`,
`currentOp`).

```bash
komando credential password add shop-mongo-pass --user app
komando database mongodb add prod-db 'mongodb://db1.internal,db2.internal/shop?replicaSet=rs0&authSource=admin' --via web1 --credential shop-mongo-pass
komando database mongodb query prod-db '{"find": "orders", "filter": {"status": "open"}, "sort": {"_id": -1}, "limit": 10}'
komando database mongodb query prod-db '{"aggregate": "orders", "pipeline": [{"$group": {"_id": "$status", "n": {"$sum": 1}}}], "cursor": {}}'
komando database mongodb query prod-db --write '{"update": "orders", "updates": [{"q": {"_id": {"$oid": "5f1d7f1b2c3a4b5c6d7e8f90"}}, "u": {"$set": {"status": "paid"}}}]}'
komando database mongodb query prod-db '{"listCollections": 1}'                  # collections
komando database mongodb query prod-db '{"listIndexes": "orders"}'               # indexes of one collection
komando database mongodb query prod-db '{"buildInfo": 1}'                        # version
komando database mongodb query prod-db '{"explain": {"find": "orders", "filter": {"status": "open"}}, "verbosity": "queryPlanner"}'   # the plan
komando database mongodb query prod-db '{"currentOp": 1, "$db": "admin"}'        # what runs now
komando database mongodb query prod-db --write --dry-run '{"killOp": 1, "op": 12345, "$db": "admin"}'   # the operation it would stop
komando database mongodb query prod-db '{"usersInfo": {"forAllDBs": true}}'      # users of every database, and their roles
```

- komando rates each command before it sends it, as it does SQL: `find`,
  `aggregate`, `count`, `distinct` and the other reads run as they are. A
  command that changes data, or one komando does not know as a read, needs
  `--write`; a protected entry also asks first. A `delete` or a
  multi-document `update` with an empty filter, `drop`, `dropDatabase`,
  user and role changes and `shutdown` are destructive. An `aggregate` with
  `$out` or `$merge` writes.
- MongoDB has no read-only transaction, so the rating is what keeps a read
  a read. For a hard guarantee, give the entry a user with only the `read`
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
  works with `?tls=true&ca=credential:NAME`.
- An `explain` of a read (`find`, `aggregate`, `count`, `distinct`) gives
  `queryPlanner`, or with `"verbosity": "executionStats"` the numbers, which
  runs the read. An `explain` of a command that writes is refused.
- `killOp` stops one operation; the client stays connected. User
  changes and grants (`createUser`, `grantRolesToUser`) go through `query
  --write`.
- For SQL databases only: `backup`, `restore` and `shell`. On MongoDB they
  say so (`NOT_SUPPORTED`). For a backup, see
  [Back up and restore](#back-up-and-restore).

## SQL Server

SQL Server (and Azure SQL Managed Instance) entries take the same
commands as PostgreSQL and MySQL, in T-SQL:

```bash
komando credential password add sales-pass --user app
komando database sqlserver add prod-db 'sqlserver://db.internal:1433/sales?encrypt=true' --credential sales-pass
komando database sqlserver query prod-db "select top (10) id, email from dbo.users order by id desc"
komando database sqlserver query prod-db "select * from dbo.users where email = @p1" --arg bob@example.com
komando database sqlserver query prod-db --write --dry-run "update dbo.users set plan = 'pro' where id = 42"
komando database sqlserver query prod-db "select column_name, data_type, is_nullable from information_schema.columns where table_name = 'orders'"   # columns
komando database sqlserver query prod-db "select session_id, status, command, wait_type from sys.dm_exec_requests"   # what runs now
komando database sqlserver query prod-db --write "kill 57"   # end session 57
```

- **The URL.** The path is the database. A named instance
  (`db\SQLEXPRESS`) is reached by its port, not by its name:
  `sqlserver://db:49172/sales`. The name needs the SQL Server Browser,
  which answers over UDP, and `--via` carries only TCP.
  The options are `encrypt=` (`true`, `strict`, `false`, `disable`; see
  [Encryption](#encryption-tls)), `tls=skip-verify`, `ca=credential:NAME`,
  `applicationintent=readonly` (a readable replica of an availability
  group) and `database=NAME` in place of the path. Logins are SQL Server
  logins (user and password); Windows and Entra ID logins are not
  supported.
- **Its own certificate.** A certificate SQL Server made for itself may
  have a negative serial number, which komando accepts; the chain and the
  host name are still checked, so `encrypt=true` needs `ca=` or
  `tls=skip-verify` for it as for any self-signed certificate.
- **Without `--write` nothing stays.** SQL Server has no read-only
  transaction, so komando runs the SQL in a transaction that it always
  rolls back, and checks after each statement that this transaction is
  still open. komando's checks come first, stricter than for the other
  databases, because T-SQL needs no `;` between statements:
  - a change anywhere in the text counts, so `select 1 delete from t` is a
    `DELETE` without `WHERE`;
  - a first word that is not a T-SQL statement is the name of a procedure
    that SQL Server runs (`sp_who`), so it needs `--write` and is
    destructive, like `EXEC`;
  - `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVE TRANSACTION` and
    `SET IMPLICIT_TRANSACTIONS` are refused anywhere, so `BEGIN ... END`
    blocks and `TRY ... CATCH` belong in a stored procedure;
  - names and text with letters outside ASCII must be quoted (`[naïve]`,
    `N'café'`).

  A procedure or function you call can still act outside the transaction
  (`xp_cmdshell`, a linked server, mail). For a hard limit, give the entry a
  login with only `db_datareader`.
- **`CREATE PROCEDURE`, `FUNCTION` and `TRIGGER`** take the rest of the
  text as their body, as SQL Server does, also after a `;`. Creating one is
  a change; what the body does counts when it runs.
- `BACKUP`, `RESTORE`, `CREATE DATABASE` and `ALTER DATABASE` cannot run in a
  transaction: send them alone, with `--write`; a dry run only reports them.
- The `sys.dm_exec_*` views and the sessions of other logins need the
  `VIEW SERVER STATE` permission; without it a login sees only its own
  session.
- **Users.** Create a login (with its password) and a user for it with
  `create login` and `create user`, both through `query --write`; a
  database role is `create role`. Rights are `grant`, and adding the user
  to a role such as `db_datareader` is `alter role db_datareader add
  member app_ro`.
- **Backups:** see [Back up and restore](#back-up-and-restore).

## Oracle

Oracle Database entries (19c and later, and Oracle Database Free) take the
same commands, in Oracle SQL:

```bash
komando credential password add erp-pass --user app
komando database oracle add prod-db 'oracle://db.internal:1521/ERPPDB?tls=true' --credential erp-pass
komando database oracle query prod-db "select id, email from app.users order by id desc fetch first 10 rows only"
komando database oracle query prod-db "select * from app.users where email = :1" --arg bob@example.com
komando database oracle query prod-db --write --dry-run "update app.users set plan = 'pro' where id = 42"
komando database oracle query prod-db "select column_name, data_type, nullable from all_tab_columns where owner = 'APP' and table_name = 'ORDERS'"   # columns
komando database oracle query prod-db "select sid, serial#, username, status, sql_id from v\$session where username is not null"   # what runs now
komando database oracle query prod-db --write "alter system kill session '371,4172' immediate"   # 371 is the SID
```

- **The URL.** The path is the service name, often a pluggable database
  (`ORCLPDB1`, `FREEPDB1`); `lsnrctl status` on the server lists them. An
  old database without services: `oracle://db:1521?sid=ORCL`. The
  options are `tls=` (`true`, `skip-verify`, `false`; TCPS listens on its
  own port, often 2484) and `ca=credential:NAME` for a private CA (with
  `tls=true`). Logins are user and password; Oracle wallets, Kerberos and
  operating-system logins are not supported.
- **Without `--write` nothing changes.** komando starts every run with
  `SET TRANSACTION READ ONLY`, and checks after each statement that this
  transaction is still open.
- **DDL commits on its own** in Oracle (`CREATE`, `ALTER`, `DROP`, `GRANT`,
  `TRUNCATE`, `COMMENT`, ...). So it always needs `--write`, must be sent on
  its own, and a dry run only reports it. `ALTER SESSION` is not DDL.
- **PL/SQL.** A block (`BEGIN ... END;`, `DECLARE ...`) and `WITH FUNCTION`
  run code komando cannot follow: they need `--write`, are destructive, and
  a dry run skips them. A block runs to the end of the text or to a line
  with only `/`, as in SQL*Plus:

  ```bash
  komando database oracle query prod-db --write -f - <<'SQL'
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
  (`"Straße"`, `'café'`). `q'[...]'` quotes work. A `--` comment that
  holds a control character or an unusual line break is refused, because
  komando cannot be sure where Oracle ends it.
- Calls to packages that reach other servers or files (`UTL_HTTP`,
  `UTL_FILE`, `DBMS_PIPE`, `DBMS_SCHEDULER`, ...) need `--write` and are
  destructive, and so is a call to any function that is not one of
  Oracle's own (`app.close_month(1)`, `pkg.f(x)`): it can commit on its
  own (an autonomous transaction), even in a `SELECT`. A name across a
  database link (`orders@prodlink`) and an inline external table
  (`FROM EXTERNAL (...)`, which reads files on the database server and with
  a `PREPROCESSOR` runs a program there) count the same. A function called
  without `()` looks like a column, so komando cannot see it: for a hard
  limit, give the entry a user with only `SELECT` (or `READ`) grants.
- Oracle's own views give what a client would show: `v$session` for
  what runs now, `v$lock` for locks, `dba_segments` for sizes and
  `v$instance` for the version and uptime. They need
  `SELECT_CATALOG_ROLE` for the entry's user; without it only the user's own
  objects show. A table's `CLOB` and `BLOB` data is not in `dba_segments`
  for the table itself (it has its own segments). To stop a call send
  `ALTER SYSTEM CANCEL SQL` (Oracle 18c and later) with `query --write`.
- **Users.** In Oracle a user is also a schema. `create user` and
  `grant create session to` make a user that can log in; `create role`
  makes a role. A user that still owns tables is not dropped without
  `cascade`. Names are upper case, as Oracle stores them. `grant` takes
  object rights (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `EXECUTE`, ...)
  and system privileges such as `CREATE TABLE` or `SELECT ANY TABLE`. All
  of it goes through `query --write`.
- **Backups:** see [Back up and restore](#back-up-and-restore).

## ClickHouse

ClickHouse entries (23.3 and later) take the same commands, in
ClickHouse SQL. komando speaks ClickHouse's HTTP interface (port 8443 with
TLS, 8123 without) with its own client, so nothing else needs to be
installed:

```bash
komando credential password add events-pass --user app
komando database clickhouse add prod-db 'clickhouse://ch.internal:8443/analytics?tls=true' --credential events-pass
komando database clickhouse query prod-db "select event, count() from hits where day = today() group by event order by 2 desc limit 10"
komando database clickhouse query prod-db "select * from hits where user_id = {p1:UInt64} limit 10" --arg 42
komando database clickhouse query prod-db --write "insert into notes (id, text) values (1, 'hello')"
komando database clickhouse query prod-db "select name, type, is_in_primary_key from system.columns where table = 'hits'"   # columns
komando database clickhouse query prod-db "explain indexes = 1 select count() from hits where user_id = 42"   # the plan, with the indexes used
komando database clickhouse query prod-db "select table, formatReadableSize(sum(bytes_on_disk)) from system.parts where active group by table"   # sizes
komando database clickhouse query prod-db "select query_id, user, elapsed, query from system.processes"   # running queries
komando database clickhouse query prod-db --write "kill query where query_id = '2b8e0a4f'"
```

- **The URL.** The path is the database (the user's default when left
  out). The options are `tls=` (`true`, `skip-verify`, `false`) and
  `ca=credential:NAME` for a private CA (with `tls=true`). Without a port it is
  8443 with TLS and 8123 without. Ports 9000 and 9440 are ClickHouse's
  native protocol, which komando does not speak: it says so. A server
  that opens only the native port can still be reached: add `--via` a
  server that can reach its port 8123 or 8443.
- **Without `--write` nothing changes.** ClickHouse has no transactions,
  but it has its own read-only mode: every request komando sends without
  `--write`, and every query that returns rows, carries the setting
  `readonly=1`, and the server refuses writes, DDL and setting changes.
  `SETTINGS` and `SET` in a read are refused for the same reason. Each
  request is a session of its own, so a `SET` would not last anyway.
  ClickHouse sessions and its experimental transactions are not used.
- **A write cannot be rolled back.** `INSERT`, `ALTER`, `CREATE`,
  `OPTIMIZE` and every other statement that is not a read need `--write`,
  must be sent on their own, and a dry run only reports them. Destructive
  ones, as usual: `DROP`, `TRUNCATE`, `DETACH`, `ALTER ... DROP` or
  `CLEAR`, `SYSTEM`, `KILL QUERY`, users, roles, quotas and grants,
  `BACKUP` and `FREEZE`.
- **Reading from elsewhere.** `readonly=1` lets reads through, also reads
  that reach other servers or the server's files. So the table functions
  and engines that do (`url()`, `s3()`, `remote()`, `mysql()`,
  `postgresql()`, `file()`, `executable()`, `Kafka`, ...) need `--write`
  and are destructive, also inside `DESCRIBE` or `EXPLAIN`. Functions
  the server's admin added as programs (executable user-defined functions)
  run under `readonly=1` like any function: komando cannot tell them from
  ClickHouse's own functions by name.
- **A read-only user.** A user whose settings profile has `readonly = 1`
  may not send any setting, so komando sends none (its `--timeout` then
  only stops the waiting, not the query). A profile with `readonly = 2`
  gets the timeout and the other settings, but komando does not send
  `readonly` for it. For a hard limit, give the entry such a user with only
  `SELECT` grants. A user whose settings profile reads queries as another
  language (`dialect = 'kusto'` or `'prql'`) is refused
  (`SQL_SAFE_SETTINGS_REQUIRED`): komando checks ClickHouse SQL only.
- Text in `$$...$$` and names or text with letters outside ASCII outside
  quotes are refused (`SQL_HIDDEN_CODE`): use `'...'` (with `\'` for a quote) and
  `` `...` ``. `FORMAT` and `INTO OUTFILE` are refused too: komando reads
  the rows itself (`-o csv`, `-o tsv`).
- ClickHouse has no `EXPLAIN ANALYZE`; `explain indexes = 1` shows the
  plan and the indexes used.
- **Users.** `create user`, `create role` and `grant` go through
  `query --write`. The entry's user needs access management (or
  `CREATE USER` and `GRANT`). A grant names `DB.*`, `DB.TABLE` or `*.*`
  and rights such as `SELECT`, `INSERT`, `ALTER`, `CREATE`, `DROP`,
  `TRUNCATE`, `OPTIMIZE`, `SHOW` and `KILL QUERY`. Users defined in the
  server's `users.xml` cannot be changed with SQL.
- **Backups:** see [Back up and restore](#back-up-and-restore).

## Snowflake

Snowflake entries take the same commands, in Snowflake SQL. komando
speaks Snowflake's SQL API (HTTPS) with its own client, so nothing else
needs to be installed:

```bash
komando credential key add analytics-key --user APP_RO   # the user's private key (key-pair login)
komando database snowflake add prod-db 'snowflake://myorg-myaccount/ANALYTICS/PUBLIC?warehouse=REPORTING&role=ANALYST_RO' --credential analytics-key
komando database snowflake query prod-db "select region, sum(total) from orders where placed > ? group by 1" --arg 2026-01-01
komando database snowflake query prod-db "select column_name, data_type from information_schema.columns where table_name = 'ORDERS'"   # columns
komando database snowflake query prod-db "explain select * from orders where id = 42"   # the plan, not run
komando database snowflake query prod-db "select query_id, user_name, execution_status from table(information_schema.query_history()) where end_time is null"   # running queries
komando database snowflake query prod-db --write "select system\$cancel_query('01b2c3d4-0000-0000-0000-000000000000')"
komando database snowflake query prod-db "show grants to user APP_RO"   # its roles and rights
```

- **The URL.** The account goes where other kinds have a host: the
  account identifier Snowflake shows (`myorg-myaccount`, or a locator with
  its region such as `xy12345.eu-central-1`; `...snowflakecomputing.com`
  works too). The path is `/DATABASE/SCHEMA`, both optional; the options
  are `warehouse=`, `role=` and `ca=credential:NAME` (a proxy that inspects
  TLS). It is always HTTPS on port 443 with the certificate checked.
- **Login.** Snowflake's SQL API takes no passwords, so `--credential`
  names one of two things:
  - **A private key** (a `credential key`, PEM, `-----BEGIN PRIVATE KEY-----`) for key-pair
    login. komando signs a short-lived token with it for each hour of use.
    Snowflake must know the public half: `ALTER USER APP_RO SET
    RSA_PUBLIC_KEY = '...'`. Store the key without a passphrase (the vault
    encrypts it): `openssl pkcs8 -topk8 -nocrypt -in rsa_key.p8` makes
    one. The key is an RSA key, PKCS#8
    (`BEGIN PRIVATE KEY`) or PKCS#1 (`BEGIN RSA PRIVATE KEY`). A key with a
    passphrase is refused; the error shows the `openssl` line that removes
    it. When Snowflake refuses the key (`DB_AUTH`), the hint shows the
    key's fingerprint: compare it with `RSA_PUBLIC_KEY_FP` in
    `DESC USER APP_RO`.
  - **A programmatic access token** (a `credential token`; `ALTER USER APP_RO ADD PROGRAMMATIC
    ACCESS TOKEN ...`), which Snowflake lets stand where a password goes.

  Browser sign-in (SSO) and OAuth are not supported.

  TODO(cut): how a PEM file is given to `credential key add` waits on the `Options` of that leaf (PR B).
- **Read-only is komando's check, not Snowflake's.** Snowflake has no
  read-only mode komando can switch on, and each statement is a session of
  its own, so nothing can be rolled back. Without `--write` komando sends
  only statements it rates as reads, one per request, and asks Snowflake to
  run exactly one statement. A statement that is not a read (`INSERT`,
  `CREATE`, `COPY`, `CALL`, ...) needs `--write`, goes on its own, and a
  dry run only reports it. A function that calls out of Snowflake (an
  external function) is caught when it is created, not when it is called
  by name. Give the entry a role that may only read, so
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
- **Destructive:** `DROP`, `TRUNCATE`,
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
  `SELECT 1` and `SHOW` do not, so `komando test` works without one.
- Schema, sizes and activity come from the URL's database
  (`INFORMATION_SCHEMA`); activity shows the queries the entry's role may
  see. `explain` shows the plan and does not run the query. Unquoted
  names are upper case, so `where table_name = 'ORDERS'` finds `orders`.
- **Not available** (`NOT_SUPPORTED`): `backup` and `restore` (see
  [Back up and restore](#back-up-and-restore)). Users and grants are SQL:
  `create user` and `grant` through `query --write`, `show grants` to
  read.

## BigQuery

BigQuery entries take the same commands, in GoogleSQL. komando speaks
BigQuery's REST API with its own client (not the Google Cloud SDK), so
nothing else needs to be installed:

```bash
komando database bigquery add prod-db 'bigquery://my-project/analytics?location=EU'   # gcloud's login
komando database bigquery query prod-db --dry-run "select * from orders where placed > '2026-01-01'"  # what it would read
komando database bigquery query prod-db "select region, sum(total) from orders where placed > ? group by 1" --arg 2026-01-01
komando database bigquery query prod-db "select * from logs.events" --max-bytes 200GB   # allow a bigger read
komando database bigquery query prod-db "select column_name, data_type from analytics.INFORMATION_SCHEMA.COLUMNS where table_name = 'orders'"   # columns
komando database bigquery query prod-db "select job_id, user_email, state from region-eu.INFORMATION_SCHEMA.JOBS where state != 'DONE'"   # jobs that are not done
```

- **The URL.** `bigquery://PROJECT[/DATASET]?location=EU`: the project the
  jobs run in (and are billed to), a default dataset for names without one,
  and where the jobs run (`EU`, `US`, `europe-west1`, ...; without it
  BigQuery picks from the tables; a query on `INFORMATION_SCHEMA` uses the
  dataset's location, or `US`). Other options: `ca=credential:NAME` (a proxy
  that inspects TLS) and `endpoint=URL` (an emulator, or a Private Service
  Connect address such as `https://bigquery-NAME.p.googleapis.com`). It is
  HTTPS with the certificate checked; `tls=` is refused. An `http://`
  endpoint (an emulator) is allowed; `komando doctor` warns when it crosses
  the network.
- **Login.** The same as for `gs://` entries: gcloud's login (`gcloud auth
  application-default login`, `GOOGLE_APPLICATION_CREDENTIALS`, or the
  metadata server on Google Cloud), or a service account key (the JSON
  file) in a credential:

  ```bash
  komando credential token add warehouse-key    # the service account key, key.json
  komando database bigquery add prod-db 'bigquery://my-project/analytics' --credential warehouse-key
  ```

  TODO(cut): how a key file is given to `credential token add` waits on the `Options` of that leaf (PR B).

  gcloud's login is only sent to Google's own hosts
  (`https://*.googleapis.com`); an emulator gets a key the entry names, or
  no login at all. The login needs `roles/bigquery.jobUser` on the project
  and `roles/bigquery.dataViewer` on the datasets it reads; give an entry
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
  `bytes_processed` (text: `(BigQuery read 1.2 GiB)`). `--dry-run` (with
  or without `--write`) is BigQuery's own dry run for every statement, also
  a `SELECT`: it shows what each would read and runs nothing. A run that
  times out cancels its job. Sizes count in powers of 1024: `10GB` is
  10 GiB, `200GB` is 200 GiB. Every job komando starts is named `komando_`
  plus a random ID and has the label `komando=<who ran it>`, so you can
  find komando's jobs and their cost in BigQuery's job history.
- **Placeholders** are `?`, and the `--arg` values go as `STRING`: BigQuery
  does not turn text into numbers by itself, so write `CAST(? AS INT64)`.
- **Destructive:** `DROP`, `TRUNCATE`,
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
- The plan is the dry run: `--dry-run` shows the statement type and the
  bytes it would read, and runs nothing. Jobs are in
  `region-LOCATION.INFORMATION_SCHEMA.JOBS` (seeing other people's jobs
  needs `bigquery.jobs.listAll`) and sizes in
  `INFORMATION_SCHEMA.TABLE_STORAGE`.
- **Not available** (`NOT_SUPPORTED`): `backup` and `restore` (see
  [Back up and restore](#back-up-and-restore)). Users and rights are
  Google Cloud IAM, so there is no SQL for them.

## Limits

- An `--ask` credential relies on komando telling an AI agent from a person, by
  the agent's environment only. Any program of your user can fake
  komando's window, replace its binary or read its memory; see
  [Servers](servers.md#limits). Files under `~/.postgresql` (a
  `root.crt` there) are read as Postgres does.

**SQL Server**

- Always Encrypted columns are not supported.
- komando refuses a URL option it does not know. `TrustServerCertificate`
  is refused too: write `tls=skip-verify` (with `encrypt=true`) instead.

**Oracle**

- komando refuses a URL option it does not know, and a service name with
  characters other than letters, digits and `_ $ # . -`.
- A trigger `ON DATABASE` (a logon trigger can lock everyone out) is
  destructive.

**ClickHouse**

- `tls=true` on port 8123 is refused: 8123 is plain HTTP, 8443 is HTTPS.
- A backslash inside a quoted name (`` `\x75rl` ``) is refused, because
  ClickHouse turns it into another letter.
- `cluster()` and `Distributed` tables use clusters the admin set up, so
  they count as reads.
- komando does not use a proxy from `HTTPS_PROXY` and does not follow
  redirects. To go through a server, use `--via`.

**Snowflake**

- komando's Snowflake client is built from Snowflake's documentation and
  tested against a stand-in server, not against a real Snowflake account.
  Please report anything that does not work.
- `PUT` and `GET` (stage files to and from this computer) do not run:
  Snowflake's SQL API does not take them. Use `COPY INTO` with a stage, or
  Snowflake's own tools.
- `SET` and `USE` count as reads: they change only the session of that one
  request, which ends with it.
- A size query needs a warehouse in the URL.
- komando does not use a proxy from `HTTPS_PROXY` and does not follow
  redirects. For a company proxy that inspects TLS, use `ca=credential:NAME`
  and reach it through `--via` or a `proxy` VPN.

**BigQuery**

- komando's BigQuery client is built from Google's REST reference and
  tested against a stand-in server, not against a real Google Cloud
  project. Please report anything that does not work.
- `shell` always uses the default `--max-bytes` cap.
- A query on `INFORMATION_SCHEMA.JOBS` shows the jobs from the last two days.
- A `MERGE` with `WHEN NOT MATCHED BY SOURCE` can change every row, so it
  is destructive. A plain `MERGE ... WHEN MATCHED THEN UPDATE` is a normal
  change.
- A `--dry-run` of a change needs no `--write`, but a statement that
  reaches outside BigQuery (`EXTERNAL_QUERY`) keeps its rating.

## Troubleshooting

| Error | Exit | What it means | What to do |
|-------|------|---------------|------------|
| `DB_AUTH` | 4 | wrong user name or password | check them with `komando database postgres show prod-db`; fix with `komando database postgres edit prod-db --credential NAME` |
| `DB_NOT_FOUND` | 3 | the database does not exist | check the path in the entry URL |
| `DB_PRIVILEGE` | 5 | the entry's user lacks a right (for example to read the lock views, or to manage users) | ask the database admin for the right |
| `DB_BYTES_LIMIT` | 6 | a BigQuery query would read more than `--max-bytes` (default 10GB), so it did not run | narrow the query, or raise `--max-bytes` after a person agrees |
| `NOT_SUPPORTED` | 2 | the command does not work for this kind: `backup` and `restore` on SQL Server, Oracle, ClickHouse, Snowflake, BigQuery and MongoDB; `shell` on MongoDB | the hint says what to use instead |
| `OUTPUT_TRUNCATED` | 1 | a CSV or TSV export is bigger than `--max-output`; nothing was printed | raise `--max-output`, narrow the SQL, or use `komando database postgres backup` |
| `SQL_HIDDEN_CODE` | 2 | SQL komando cannot read the way the server does | rewrite it as the hint says |
| `DUMP_UNSUPPORTED` | 2 | komando's own dump cannot write an object; the message names it | dump with `--run-on HOST` (pg_dump), or dump the other tables with `--table` |
| `TOOL_MISSING` | 3 | `pg_dump`, `mysqldump` or `pg_restore` is not installed where it should run | install it there, or pick another server with `--run-on` |
| `TOOL_TOO_OLD` | 5 | `pg_dump` is older than the database server, or `pg_restore` older than the archive | install the package the hint names |
| `CONN_UNREACHABLE` | 4 | the tool cannot reach the database from the server it runs on | add an entry for the address that server sees (see [`--run-on`](#run-the-dump-on-a-server-you-choose---run-on-host)) |
| `UNSAFE_BACKUP` | 6 | the backup file has client commands (`\!`, `system`, `\i`) or SQL komando cannot follow | remove that line if the file is not from a trusted dump |
| `RESTORE_UNSUPPORTED` | 2 | the file switches databases (`\connect`) | dump the one database without `--create` |
| `RESTORE_FAILED` | 5 | the restore stopped at a line; PostgreSQL changed nothing, MySQL kept what ran before | fix the file, then restore it again |
| `RESTORE_SPACE_MISSING` | 3 | too little free space in komando's run folder for the checked copy of the backup; the database was not touched | free the bytes the hint names in that folder, then restore again |
| `NEEDS_TERMINAL` | 2 | `shell` was run without a terminal | use `query` |

`backup` and `restore` report the same connection errors as `query`.
Every code is in [Error codes](error-codes.md).

## Reference

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
| Snowflake DATE, TIME, TIMESTAMP | text in the column's form: `TIMESTAMP_NTZ` without a zone, `TIMESTAMP_LTZ` in UTC, `TIMESTAMP_TZ` with its offset |
| Snowflake BINARY | `{"base64": "..."}` |
| BigQuery INT64 | a number |
| BigQuery BYTES | `{"base64": "..."}` |
| BigQuery DATE, TIME, DATETIME, GEOGRAPHY, INTERVAL | text, as BigQuery writes it |
| BigQuery NUMERIC, BIGNUMERIC | text with every digit |
| BigQuery TIMESTAMP | `"2026-11-09T13:04:05.123456Z"` (UTC) |
| BigQuery STRUCT, ARRAY, JSON | JSON objects, arrays and values |
