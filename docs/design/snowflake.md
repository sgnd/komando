# Snowflake conns

Status: **built, 2026-11-10, not yet run against a real account**
(dump and restore: not done; users and grants: read only).

## The question

Snowflake holds the analytics of many teams, and the questions are the
usual ones: what tables are there, how big, what is running, stop that
query, who may see what. Three things about Snowflake touch komando's
promise that a query without `--write` cannot change anything:

1. **There is no read-only mode** a client can switch on for a session or
   a statement, as Postgres, MySQL, Oracle and ClickHouse have.
2. **Each request to the SQL API is a session of its own.** A transaction
   cannot span two requests, so nothing komando sends can be rolled back,
   and a dry run cannot run a write and undo it.
3. **No passwords on the SQL API.** It takes key-pair tokens (a JWT the
   client signs), OAuth tokens and programmatic access tokens.

## Decisions

- **The SQL REST API, komando's own client.** `POST /api/v2/statements`
  and its status and cancel calls, in `internal/dbx/snowflake.go`, as a
  small database/sql driver. Not `gosnowflake`: it is Apache-2.0 (so it
  could be used), but brings the AWS and Azure SDKs, Apache Arrow
  and a browser login for a protocol komando needs four calls of. The SQL
  API is documented and stable; gosnowflake's own protocol is not
  documented. No new dependency: the JWT is signed with Go's
  `crypto/rsa`.
- **The URL:** `snowflake://USER@ACCOUNT/DATABASE/SCHEMA?warehouse=W&role=R`.
  The account identifier stands where other kinds have a host
  (`myorg-myaccount`, `xy12345.eu-central-1`, or with
  `.snowflakecomputing.com`); the host is that plus
  `.snowflakecomputing.com`, with `_` as `-`. Options: `warehouse`, `role`,
  `ca=secret:NAME`. `tls=` is refused: it is always HTTPS on 443 with the
  certificate checked, so `conn add` adds nothing and `doctor` has nothing
  to warn about. `ca=` is for a company proxy that inspects TLS. No proxy
  from the environment, no redirects. `--via` and VPNs dial the account's
  name, so the SSH server resolves it.
- **Login.** The conn's secret (`--password-ref`) is a private key (PEM,
  PKCS#8 or PKCS#1, RSA, unencrypted: the vault encrypts it) or a
  programmatic access token, told apart by `-----BEGIN`. With a key,
  komando signs an RS256 JWT: `iss` = `ACCOUNT.USER.SHA256:<fingerprint
  of the public key>`, `sub` = `ACCOUNT.USER` (upper case; the account
  without its region), valid 59 minutes, made again five minutes before it
  ends. A refused login (401, or 403 with a 390xxx code) is `DB_AUTH`; its
  hint names the key's fingerprint to compare with `DESC USER`'s
  `RSA_PUBLIC_KEY_FP`, or says the API takes no passwords. An encrypted key
  is refused with the `openssl pkcs8 -nocrypt` line. No browser SSO and no
  OAuth in this version.
- **Read-only is the classifier's.** Without `--write` (and inside a
  read-only "transaction", which only marks the requests) the driver rates
  each statement again before sending it and refuses anything that is not
  a read: a second check for code paths that skip `db query`'s own. Every
  request carries `MULTI_STATEMENT_COUNT=1`, so if komando split SQL where
  Snowflake does not, Snowflake refuses the request rather than running a
  second statement. A statement that is not a read is `NoTx`: it needs
  `--write`, goes alone, and a dry run only reports it. The docs give the
  SQL for a role that may only read and tell people to use it.
- **Reads:** `SELECT`, `WITH`, `SHOW`, `DESCRIBE`, `EXPLAIN`, `LIST`, and
  `SET` and `USE` (they change the request's own session, which ends with
  it). Everything else needs `--write`, also a first word komando does not
  know. `BEGIN`, `COMMIT` and `ROLLBACK` are refused; a Snowflake
  Scripting block (`BEGIN ... END`, `DECLARE`) is refused with a hint to
  send it as `EXECUTE IMMEDIATE $$ ... $$`, which is opaque.
- **Destructive:** besides the general rules (`DROP`, `TRUNCATE`, a
  `DELETE` or `UPDATE` without `WHERE`, `GRANT`), `CREATE OR REPLACE`
  (`sql-drop`: it drops what had the name), users, roles, database roles
  and policies (`sql-privileges`), the account, warehouses, integrations,
  shares, resource monitors, network rules and replication groups
  (`sql-server-config`), `PUT`, `GET`, `REMOVE` and `COPY INTO @stage` or
  `'s3://...'` (`sql-server-file`), `URL =`, `CREDENTIALS =`, external
  functions and external access integrations (`sql-remote`), `CALL`,
  `EXECUTE`, an anonymous procedure (`WITH p AS PROCEDURE ... CALL p()`)
  and a call inside `TABLE(...)` other than `FLATTEN`, `GENERATOR`,
  `RESULT_SCAN`, `SPLIT_TO_TABLE`, `STRTOK_SPLIT_TO_TABLE`, `INFER_SCHEMA`
  and `INFORMATION_SCHEMA`'s functions, since a procedure that returns a
  table runs that way (`sql-opaque`), `SYSTEM$CANCEL_QUERY`, `SYSTEM$ABORT_SESSION`
  and the like (`sql-kill`), and every other `SYSTEM$` function not on a
  short list of ones that only read (`sql-server-config`; some show
  secrets). The pipe operator `->>` splits a statement into parts, each
  rated. `MERGE ... WHEN MATCHED THEN UPDATE` is a write, not an update
  without `WHERE`.
- **The lexer.** `snowflakeMask` turns Snowflake's quoting into text the
  shared lexer reads the same way, at the same length: `//` comments
  become `--`, `\'` inside `'...'` becomes `''`, `$$...$$` becomes a plain
  `'...'` with its text hidden. Backslash escapes count in `'...'` only,
  not in `"..."`. Refused (`SQL_HIDDEN_CODE`): a `/*` inside a comment
  (Snowflake does not document whether comments nest), `$$` right after a
  name or number, a line comment with a control character or an unusual
  line break, letters outside ASCII outside quotes. `$` inside a name
  (`SYSTEM$WAIT`) is part of it.
- **Requests are asynchronous** (`async=true`): the POST answers with the
  statement's handle, then komando asks for the result (50 ms, doubling to
  2 s). So when the run is cancelled (`--timeout`, Ctrl-C) komando can
  always cancel the statement on the server. `timeout` in the request is
  the run's `--timeout`. 429, 503 and 504 are tried again up to three
  times with `retry=true` and the same request ID, which Snowflake runs
  once. Results larger than one partition are fetched a partition at a
  time as they are read.
- **Placeholders** are `?`; `--arg` values go as `TEXT` bindings, and
  Snowflake converts them.
- **Values.** The SQL API sends every value as text. `NUMBER` without a
  scale becomes a number where JSON holds it exactly; with a scale it
  stays text with every digit. Dates, times and timestamps (sent as days
  or seconds since 1970) become text in the column's form: `DATE`
  `2024-01-01`, `TIMESTAMP_NTZ` without a zone, `TIMESTAMP_LTZ` in UTC,
  `TIMESTAMP_TZ` with its offset. `BINARY` is `{"base64": ...}`;
  `VARIANT`, `OBJECT` and `ARRAY` keep their JSON shape.
- **Info, activity, sizes, kill.** `db info` reads `CURRENT_VERSION()`,
  the account, region, user, role, warehouse, database and schema, and
  (with a warehouse) the database's size. `db activity` reads the URL
  database's `INFORMATION_SCHEMA.QUERY_HISTORY` for queries that are
  running, queued, blocked or waiting for their warehouse, leaving out
  komando's own session. A query has a text ID, so its `pid` is 53 bits of
  the FNV-1a hash of that ID, computed by komando. `db kill` finds the
  query by it and calls `SYSTEM$CANCEL_QUERY`; `--session` calls
  `SYSTEM$ABORT_SESSION` with its session ID. `db sizes` reads
  `INFORMATION_SCHEMA.TABLES`. `db locks` is `NOT_SUPPORTED` (activity
  shows `BLOCKED`).
- **Schema** from `INFORMATION_SCHEMA.TABLES` and `COLUMNS` of the URL's
  database, the primary key from `SHOW PRIMARY KEYS`, the clustering key
  as an index. Unquoted names are upper-cased, as Snowflake does.
- **Users and grants: read only.** `db user ls` is `SHOW USERS` (some
  columns) and `SHOW ROLES`; `db grants NAME` is `SHOW GRANTS TO USER` and
  `SHOW GRANTS TO ROLE` for each of its roles, one level (or for NAME as a
  role). Adding users, passwords (Snowflake's own way is key pairs) and
  grants are `NOT_SUPPORTED`, before connecting; the hint says to send the
  SQL with `db query --write`.

## Not verified

No Snowflake account was available. The client was built from
Snowflake's documentation and tested against a fake SQL API (unit tests
in `internal/dbx/snowflake_test.go`, and the e2e fake in
`test/e2e/snowflake`). Not checked against the real service:

- that the JWT claims, the token-type headers and a programmatic access
  token are accepted exactly as sent;
- the error codes komando maps (`000606` no warehouse, `002003` not
  found, `003001` privileges, `000630` timeout, `000604` cancelled,
  `390xxx` login) and the text of their messages;
- the exact forms of `TIME`, `TIMESTAMP_TZ` and `DATE` values in
  `jsonv2`, and how partitions beyond the first come back;
- that `SELECT 1` runs without a warehouse (conn test relies on it),
  that each request is a session of its own, and that
  `INFORMATION_SCHEMA.QUERY_HISTORY` lists other sessions' running queries
  for a role with `MONITOR` on the warehouse;
- the column names of `SHOW USERS`, `SHOW GRANTS` and `SHOW PRIMARY KEYS`;
- whether Snowflake nests `/* */` comments (komando refuses the case).

`internal/dbx/snowflake_live_test.go` runs against an account when
`KOMANDO_SFTEST` (the conn URL) and `KOMANDO_SFTEST_SECRET` (a token or
PEM key) are set; run it before calling this done.

## Not done

- **`db dump` and `db restore`** (`NOT_SUPPORTED`): Snowflake unloads
  with `COPY INTO @stage` and keeps copies with Time Travel and `CLONE`;
  a faithful dump of tables, stages, pipes and policies is a feature of
  its own.
- **`db user add`, `passwd`, `rm`, `db grant` and `revoke`.**
- Browser SSO (`externalbrowser`), OAuth, encrypted private keys, and
  `PUT`/`GET` (the SQL API does not run them).
- User-defined functions that call out (external functions) are rated
  only when created; a call to one by name runs like any function. The
  read-only role is the hard limit.
