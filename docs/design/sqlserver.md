# SQL Server conns

Status: **built, 2026-11-10** (dump and restore: not yet).

## The question

SQL Server is the third big SQL database people run, and most of what
`komando db` does for PostgreSQL and MySQL is the same work there: look at
tables, read rows, change a few with a dry run first, see who is running
what, manage logins. Two things make it different, and both touch
komando's promise that a query without `--write` cannot change anything:

1. **There is no read-only transaction.** PostgreSQL and MySQL refuse a
   write inside `START TRANSACTION READ ONLY`. SQL Server has no such
   mode (`ApplicationIntent=ReadOnly` only picks a replica).
2. **T-SQL needs no `;`.** `SELECT 1 DELETE FROM t` is two statements, and
   a bare name as the first word runs that stored procedure (`sp_who`).
   Rating a statement by its first word, as komando does elsewhere, would
   call both of those reads.

## Decisions

- **Driver:** `github.com/microsoft/go-mssqldb` (BSD-3-Clause, pure Go,
  Microsoft's own). It brings `golang-sql/civil` (Apache-2.0),
  `golang-sql/sqlexp` (BSD-3-Clause), `shopspring/decimal` (MIT), and a
  copy of `swisscom/mssql-always-encrypted` inside it (MIT).
  komando builds the driver's settings itself (`msdsn.Config`), so the
  password never goes through a connection string that could end up in an
  error, and `--via` goes through the driver's `HostDialer`, which hands
  the host name to the SSH server to resolve.
- **The URL** follows the other SQL kinds: `sqlserver://user@host:port/db`.
  komando's own option names where they exist (`tls=skip-verify`,
  `ca=secret:NAME`), SQL Server's where they do not (`encrypt=`,
  `applicationintent=`), read without regard to case. Unknown options are
  refused, and so is `TrustServerCertificate` (it says `tls=skip-verify`).
  New conns that cross the network get `encrypt=true`, as Postgres gets
  `sslmode=verify-full`.
- **Read-only without a read-only transaction.** Without `--write`, the
  SQL runs inside a transaction that is always rolled back. SQL Server's
  DDL is transactional, so a `CREATE` or `DROP` is undone as well. After
  every statement komando reads `@@TRANCOUNT`: if it is not 1, something
  ended or nested the transaction, and komando stops (the same check the
  savepoint does on the other kinds).
- **What a rollback cannot undo is refused before it is sent.** The T-SQL
  rules (`internal/driver/sql_tsql.go`) look at every keyword, not only the
  first: T-SQL reserves its keywords, so `DELETE` outside quotes is the
  statement. `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVE`, `TRAN` and the settings
  that open transactions on their own (`IMPLICIT_TRANSACTIONS`,
  `ANSI_DEFAULTS`) are refused anywhere. `EXEC`, a bare procedure name,
  `KILL`, `SHUTDOWN`, `BACKUP`, `RESTORE`, `BULK`, `OPENROWSET`,
  `OPENQUERY`, `DBCC`, `RECONFIGURE` and login or role changes are rated
  destructive, which also keeps them out of a dry run.
- **The lexer errs towards seeing more.** `]]` inside `[names]`, nested
  `/* */` comments, `1DELETE` read as `1 DELETE` (SQL Server does), a
  `--` comment ending at any control character or Unicode line break.
  Letters outside ASCII must be quoted, since komando cannot know every
  character SQL Server takes for a space.
- **A procedure body is one statement.** `CREATE PROCEDURE`, `FUNCTION`
  and `TRIGGER` take the rest of the batch as their body, so komando does
  not split it at `;`, and rates the definition a write: the body runs
  later.
- **Explain:** `SET SHOWPLAN_TEXT ON` plans without running, so a planned
  `DELETE` needs no `--write` (`driver.PlanOnly`), while a procedure still
  does. The SQL may not touch the SHOWPLAN settings itself.
- **`db kill`** needs `--session`: SQL Server cannot cancel another
  session's query without ending the session.
- **Users** are a login plus a database user, made in one transaction, so
  a failed `CREATE USER` leaves no login behind.

## Not done

- **`db dump` and `db restore`.** komando writes its own SQL dumps for
  PostgreSQL and MySQL. A faithful T-SQL dump (identity values, computed
  columns, schemas, procedures, triggers, types) and a T-SQL restore with
  the same checks are a feature of their own. Until then both say
  `NOT_SUPPORTED`, and the hint points at `BACKUP DATABASE` and
  `komando download`.
- Windows (NTLM, Kerberos) and Entra ID logins; named instances by name
  (the SQL Server Browser answers over UDP, which `--via` cannot carry);
  Always Encrypted columns.
