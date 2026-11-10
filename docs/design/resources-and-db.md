# Design: non-SSH resources and `komando db`

The big goal and the roadmap for all families are in [vision.md](vision.md).

Status: **Phases 1–5 done**: `komando conn`; `komando db` for PostgreSQL,
MySQL and SQLite (query, schema, explain, dump, restore, `audit_sql`);
`komando cache` (Redis/Valkey); `komando storage` (S3, the command name is
`storage`, not `s3`). Extra safety from review: the `sql-opaque` rule
(DO/CALL/PREPARE/EXECUTE), `sql-remote` (dblink), refusing MySQL comments
`/*! */` and servers with non-default string rules, and checking restore
files for client commands. The next plans are in [vision.md](vision.md).

Decisions made during Phase 2:

- `db query` output is always `data.results[]`, one entry per statement, so
  the shape is the same for one or many statements. Statements that return
  rows have `columns`, `rows` (may be empty) and `row_count`; those that change
  rows have `rows_affected`; DDL has neither.
- Parameters use positional `--arg VALUE` (`$1`/`?`), not `--param k=v`,
  because that is what the drivers understand. The audit only records how many there are.
- Unknown statements (often typos) are still sent without `--write`:
  the read-only transaction refuses them if they turn out to write, and the database
  error message is clearer for typos.
- Statements that cannot be rolled back (`VACUUM`, `CREATE INDEX CONCURRENTLY`,
  MySQL DDL) must be sent alone; dry-run only reports them.
- `--dry-run` without `--write` still runs read queries (nothing changes).
- SQLite: `--write` may create a new file; without `--write` the file is opened
  `mode=ro` + `query_only`.
- Timestamps are always UTC; integers > 2^53, NaN and Infinity become strings.

Decisions made during Phase 1:

- The command name is `conn`. The kind is taken from the URL scheme, so the form is
  `conn add NAME URL` (no KIND argument). See `komando conn kinds`.
- `PROTECTED_HOST` stays for hosts; conns use `PROTECTED_TARGET`.
  No breaking change.
- Names are unique across hosts and conns (`NAME_TAKEN`). Their selectors stay
  separate: `@db` in `exec` only picks hosts.
- `conn test` in Phase 1 only checks TCP (or that the file exists for
  SQLite) and that `--password-ref` can be read. Logging in to the DB comes in Phase 2.
- A host used as `--via` cannot be removed (`HOST_IN_USE`);
  renaming a host also updates `Via` in conns.
