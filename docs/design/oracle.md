# Oracle conns

Status: **built, 2026-11-10** (dump and restore: not done, Data Pump runs on
the server).

## The question

Oracle Database runs a large share of company systems (ERP, banking,
government), and the people who look after them ask the same things as on
PostgreSQL: what tables are there, what does this row say, who is blocking
whom, add a read-only user. Three things about Oracle touch komando's
promise that a query without `--write` cannot change anything:

1. **DDL commits on its own.** `CREATE`, `ALTER`, `DROP`, `GRANT`,
   `TRUNCATE` and the rest commit before and after they run, so a DDL
   statement ends any transaction komando opened, read-only or not, and a
   dry run cannot roll it back.
2. **PL/SQL.** A block (`BEGIN ... END;`, `DECLARE ...`) holds many
   statements and can run SQL komando never sees (`EXECUTE IMMEDIATE`).
   A function can declare `PRAGMA AUTONOMOUS_TRANSACTION` and commit on
   its own, even when called from a `SELECT` inside a read-only
   transaction; since 12c such a function can sit in the query itself
   (`WITH FUNCTION`).
3. **Quoting.** `q'[...]'` quotes take any delimiter and may hold `'`, and
   a line with only `/` ends a PL/SQL block (SQL*Plus).

## Decisions

- **Driver:** `github.com/sijms/go-ora/v2` (MIT, pure Go, no Oracle
  client). Its runtime needs nothing outside the Go standard library.
  komando builds the driver's settings itself (`ParseConfig` with a
  stand-in password, then the real one), and opens connections through its
  own connector, so the password never sits in a connection string, each
  connection gets its own copy of the TLS settings, and `--via` dials by
  host name so the SSH server resolves it.
- **The URL:** `oracle://user@host:1521/SERVICE`. The path is the service
  name (a pluggable database such as `ORCLPDB1`); `?sid=NAME` reaches an
  old database by SID. Options: `tls=true|skip-verify|false` (TCPS),
  `ca=secret:NAME` (needs `tls=true`). Unknown options are refused, and so
  is a service name with characters outside `A-Z 0-9 _ $ # . -`: the name
  goes into a connect descriptor, where `)(` would add settings. New conns
  that cross the network get `tls=true`, like MySQL.
- **Read-only.** go-ora refuses `ReadOnly` in `BeginTx`, so komando opens a
  plain transaction and sends `SET TRANSACTION READ ONLY` first (`READ
  WRITE` with `--write`). After every statement it sends the same `SET
  TRANSACTION` again: Oracle refuses it inside an open transaction
  (ORA-01453), which shows komando's is still the open one. If it
  succeeds, something committed, the new transaction is read-only again,
  and komando stops (`SQL_TX_CONTROL`).
- **DDL is always a write, on its own.** The classifier marks every DDL
  statement `NoTx`: it needs `--write`, is sent alone, and a dry run only
  reports it. `ALTER SESSION` does not commit and stays in the transaction.
- **One statement per call.** Oracle runs one SQL statement per call, so
  a statement is rated by its first word, as for PostgreSQL. A word komando
  does not know needs `--write` and is handled as DDL: sent on its own, and
  a dry run only reports it (Oracle could take it for DDL, which commits).
- **PL/SQL is opaque.** An anonymous block and `WITH FUNCTION` are rated
  `sql-opaque` (destructive: `--write` and `--allow-dangerous`, never in a
  dry run). `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `SET TRANSACTION` and
  `AUTONOMOUS_TRANSACTION` are refused anywhere in the text, except in a
  `CREATE PROCEDURE`, `FUNCTION`, `PACKAGE`, `TRIGGER` or `TYPE`, whose
  body is stored, not run (that is a write). A trigger `ON DATABASE` (a
  logon trigger can lock everyone out) is `sql-server-config`.
- **Packages that reach out.** `UTL_HTTP`, `UTL_TCP`, `UTL_SMTP`,
  `UTL_MAIL`, `UTL_INADDR`, `HTTPURITYPE`, `DBMS_LDAP` and `DBMS_CLOUD`
  are `sql-remote`; `UTL_FILE`, `BFILENAME` and `DBMS_DATAPUMP`
  `sql-server-file`; any other `DBMS_` or `UTL_` package `sql-opaque`,
  except a short list that only reads or computes (`DBMS_XPLAN`,
  `DBMS_METADATA`, `DBMS_RANDOM`, `DBMS_LOB`, ...).
- **Stored functions.** A call to any function that is not one of Oracle's
  own SQL functions (`app.f()`, `pkg.f()`, `f()`) is `sql-opaque`, in a
  query or a DML statement: it may be autonomous and commit, which neither
  the read-only transaction nor a dry run's rollback stops. Oracle's own
  functions, and the keywords and type names a `(` follows (`IN (`,
  `NUMBER(10)`), are listed; a `(` after `INTO` or before `) AS` holds
  column names. A function without arguments can be called without `()`,
  like a column; komando cannot see that call. Any `@` (a database link)
  is `sql-remote`.
- **External tables.** `FROM EXTERNAL (...)` (18c) and `EXTERNAL MODIFY`
  read files on the database server (`sql-server-file`); with a
  `PREPROCESSOR`, or access parameters from a query (`USING CLOB`), they
  run a program there (`sql-program`).
- **The lexer.** `q'X...X'` and `nq'...'` quotes are turned into plain
  quotes of the same length before the usual splitter runs, so positions
  stay right. A line with only `/` ends a statement. A PL/SQL block or
  stored unit runs to the end of the text or to such a line, not to the
  next `;`. Letters outside ASCII must be quoted, and a `--` comment with a
  control character or a Unicode line break is refused: komando cannot be
  sure where Oracle ends it.
- **Explain:** `EXPLAIN PLAN SET STATEMENT_ID = 'komando' FOR ...` (nothing
  runs; the plan rows go to `PLAN_TABLE` in a transaction that is rolled
  back: a read-only one refuses the write to `PLAN_TABLE`) and
  `DBMS_XPLAN.DISPLAY`. `CREATE TABLE`, `CREATE INDEX` and `ALTER INDEX`,
  the DDL `EXPLAIN PLAN` takes, are planned in that transaction too, with
  no `--write`; other DDL cannot be planned. `EXPLAIN PLAN` typed into
  `db query` is refused with a pointer to `db explain`.
- **DBA views.** `info`, `activity`, `locks`, `sizes` and `kill` read
  `V$SESSION`, `V$SQL`, `V$INSTANCE` and `DBA_` views, which need
  `SELECT_CATALOG_ROLE`. Without it `info` shows less, `sizes` falls back
  to the user's own segments, and the others say what to grant. `db kill`
  takes the SID and reads the serial# itself; without `--session` it sends
  `ALTER SYSTEM CANCEL SQL` (18c and later).
- **Users** are schemas. `db user add` runs one PL/SQL block that creates
  the user, grants `CREATE SESSION`, and drops the user again if the grant
  fails. `db user rm` does not use `CASCADE`: a user that owns objects
  stays, with `DB_USER_IN_USE`. Names are upper case, as Oracle stores
  names written without quotes; a password with `"` is refused (Oracle
  cannot quote it).

## Not done

- **`db dump` and `db restore`.** Oracle's own tools (Data Pump `expdp`,
  `impdp`, RMAN) run on the database server and write files there; komando
  cannot reach them through the SQL connection. Both say `NOT_SUPPORTED`,
  with a hint to run them with `komando exec` and fetch the file with
  `komando download`.
- `db explain --analyze` (`NOT_SUPPORTED`). `DBMS_XPLAN.DISPLAY_CURSOR`
  needs the cursor of the statement that just ran, and in tests it did not
  find the cursors of statements sent through go-ora; showing the real row
  counts needs another way to find them.
- Oracle wallets, Kerberos and OS logins; native network encryption as a
  setting of its own (go-ora accepts it when the server asks for it).
