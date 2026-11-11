# ClickHouse conns

Status: **built, 2026-11-10** (dump and restore: not done, ClickHouse's
own BACKUP writes on the server).

## The question

ClickHouse holds logs, events and analytics for many teams, and the
questions are the usual ones: what tables are there, how big are they,
what is running, stop that query, add a read-only user. Three things
about ClickHouse touch komando's promise that a query without `--write`
cannot change anything:

1. **There are no transactions** (only an experimental kind). Nothing can
   be rolled back, so a dry run cannot run a write and undo it.
2. **The server has its own read-only mode**, the setting `readonly=1`,
   which may come with each query. It refuses writes, DDL and setting
   changes, but lets every read through, also reads from elsewhere:
   `url()`, `s3()`, `remote()`, `mysql()` reach other servers, `file()`
   reads files on the server, `executable()` runs a program there.
3. **Two protocols.** The native protocol (9000, 9440 with TLS) and the
   HTTP interface (8123, 8443 with TLS).

## Decisions

- **HTTP, komando's own client.** komando speaks the HTTP interface with
  a small database/sql driver of its own (`internal/dbx/clickhouse.go`),
  not `clickhouse-go`, which brings `ch-go`, compression libraries and
  OpenTelemetry for a protocol komando does not need. The HTTP interface
  takes one statement per request, sends errors with a code, streams rows
  as `JSONCompactEachRowWithNamesAndTypes`, and goes through `--via` and
  VPNs like any TCP connection (the dialer gets the host name, so the SSH
  server resolves it). DBeaver and most BI tools use it too.
- **The URL:** `clickhouse://user@host:8443/DB?tls=true`. The path is the
  database (the user's default when left out). Options: `tls=true|
  skip-verify|false` (HTTPS) and `ca=secret:NAME` (with `tls=true`). The
  port defaults to 8443 with TLS and 8123 without. Ports 9000 and 9440 are
  refused with a hint (the native protocol), and so is `tls=true` on 8123.
  New conns that cross the network get `tls=true`, and port 8123 becomes
  8443. No proxy from the environment, no redirects.
- **The password** goes in the `X-ClickHouse-Key` header, never in the URL
  komando builds (ClickHouse would log it with the query).
- **Read-only.** Without `--write` every request carries `readonly=1`.
  With `--write`, every query that returns rows still does. A statement
  that is not a read (`SELECT`, `WITH`, `SHOW`, `DESCRIBE`, `EXISTS`,
  `EXPLAIN`) is rated `NoTx`: it needs `--write`, is sent alone, and a dry
  run only reports it. A first word komando does not know needs `--write`
  too. `BEGIN`, `COMMIT` and `ROLLBACK` are refused.
- **A read-only user.** A settings profile with `readonly = 1` refuses any
  setting in a request, even the same value; `readonly = 2` refuses a
  change of `readonly`. komando reads the user's `readonly` and `dialect`
  from `system.settings` first (with no settings), then sends only what
  that user may: nothing (1), or its timeout and the rest but not
  `readonly` (2). A write on such a user says the user may only read,
  rather than asking for `--write`. A `dialect` other than `clickhouse`
  (`kusto`, `prql`) is refused (`SQL_STRING_RULES`): komando checks
  ClickHouse SQL.
- **Settings sent** (when allowed): `max_execution_time` from `--timeout`,
  `cancel_http_readonly_queries_on_client_close=1` (a cut-off read stops on
  the server), `http_write_exception_in_output_format=0` (an error after the
  first rows comes as text, not as a row that looks like data), and
  `output_format_decimal_trailing_zeros=1` (`1.50` stays `1.50`). The
  query gets `FORMAT JSONCompactEachRowWithNamesAndTypes` at its end, so
  SQL with its own `FORMAT` fails with a hint. `SET` and `SETTINGS` in a
  read are refused by the server (`readonly=1`); each request is its own
  session, so a `SET` would not last anyway.
- **What `readonly=1` lets through is rated.** Table functions, table and
  database engines and dictionary sources that reach other servers (`url`,
  `s3*`, `azure*`, `hdfs*`, `remote`, `mysql`, `postgresql`, `mongodb`,
  `redis`, `jdbc`, `odbc`, `kafka`, `iceberg*`, `deltaLake*`, `HTTP`,
  `CLICKHOUSE`, ...) are `sql-remote`; `file`, `fileCluster`, `sqlite`,
  `FileLog`, the `Filesystem` database engine and the `YAMLRegExpTree`
  dictionary source are `sql-server-file`; `executable` is `sql-program`.
  All are destructive (`--write` and `--allow-dangerous`), also inside
  `DESCRIBE` and `EXPLAIN`, and an engine counts without arguments too
  (`ENGINE = Filesystem`, `ENGINE = S3`). `cluster()` and `Distributed` use clusters the server's
  admin set up, and stay reads.
- **ClickHouse's own statements.** `SYSTEM` is `sql-server-config`
  (`SYSTEM SHUTDOWN`, `SYSTEM KILL`: `sql-kill`); `DETACH`, `ALTER ...
  CLEAR`, `DETACH PARTITION`, `REPLACE PARTITION`, `MOVE PARTITION ... TO
  TABLE`, a TTL in `ALTER` (`MODIFY TTL`, `MATERIALIZE TTL`, a column
  TTL; not `REMOVE TTL`), `CREATE OR REPLACE TABLE` and `REPLACE TABLE`
  are `sql-drop`; `FREEZE`, `BACKUP` and
  `RESTORE` are `sql-server-file`; users, roles, quotas, row policies,
  settings profiles and `MOVE USER` are `sql-privileges`; a named
  collection (connection settings, often passwords) is `sql-server-config`.
  `merge(...)` is a table function here, not `MERGE`.
- **The lexer.** Backslash escapes in `'...'`, `"..."` and `` `...` ``,
  `--` and `#` comments that end at a line break, nested `/* */`
  comments (all tested against ClickHouse 24.8). A backslash inside a
  quoted name is refused: ClickHouse decodes it (`` `\x75rl` `` is `url`).
  `$` outside quotes (a
  `$$...$$` heredoc) and letters outside ASCII outside quotes are refused
  (`SQL_HIDDEN_CODE`).
- **Placeholders** are ClickHouse's query parameters `{p1:String}`,
  `{p2:UInt64}`: `--arg` values go as `param_p1`, `param_p2`, and the
  server parses them by the type.
- **Values.** 64-bit integers come as text and become JSON numbers where
  JSON holds them exactly (as for the other kinds, a bigger one makes its
  column text); 128- and 256-bit integers and `Decimal` stay text with
  every digit; arrays, maps and tuples keep their shape. Type names keep
  their case (`DateTime64(3, 'UTC')`).
- **`db explain`** is `EXPLAIN indexes = 1`: the plan and the parts and
  granules the indexes leave. ClickHouse has no `EXPLAIN ANALYZE`
  (`NOT_SUPPORTED`; `system.query_log` has a finished query's numbers).
- **Info, activity, sizes, kill.** `db info` reads `version()`,
  `uptime()` and, when the user may, `system.parts`, `system.metrics`,
  `system.processes`. `db activity` lists `system.processes`. A query has a
  `query_id` (text) and no session number, so its `pid` is 53 bits of
  `cityHash64(query_id)`, which `db kill` takes (`KILL QUERY WHERE ...
  ASYNC`). An HTTP request is one query, so `--session` is
  `NOT_SUPPORTED`, and so is `db locks` (no row locks to wait for).
  `db sizes` sums `system.parts`.
- **Users** are ClickHouse SQL users (access management). komando sends
  `IDENTIFIED WITH sha256_hash BY '<hash>' SALT '<salt>'`, a SHA-256 of
  the password and a random salt it computes itself, so the password never
  reaches the server or its query log. `--no-login` creates a role; `db
  user rm` drops a role when the name is one. `db grant` takes `DB.*`,
  `DB.TABLE`, `*.*`, `database:DB` or `table:DB.TABLE`, and `--role`.
  `db grants` reads `system.grants` and `system.role_grants`, for a user or
  a role. Users from `users.xml` cannot be changed with SQL (the error
  says so).

## Not done

- **`db dump` and `db restore`** (`NOT_SUPPORTED`). ClickHouse's own
  `BACKUP ... TO Disk(...)` or `S3(...)` writes on the server (with
  `--write` and `--allow-dangerous`); a faithful dump of MergeTree tables
  with their engines, partitions and TTLs is a feature of its own.
- The native protocol. Everything here works over HTTP; a server that
  only opens 9000 is reached by `--via` to a host that can reach 8123.
- **Executable user-defined functions** that the server's admin configured
  run under `readonly=1` like any function; komando cannot tell them from
  ClickHouse's own functions by name. For a hard limit, give the conn a
  user with only `SELECT` grants (and a `readonly = 1` profile).
- The experimental transactions, sessions (`session_id`), and
  `INTO OUTFILE` (the server answers with an error; `-o csv` gives a file
  on this computer).
