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

## Background

Right now komando knows only one kind of target: the **SSH host**. All
its safety layers are tied to the host:

| Layer | Where it is now |
|---|---|
| Inventory | `store.Host` in `state.json` |
| Credentials | `PasswordRef` → `vault.Resolve` (`secret:`, `env:`, `file:`) |
| Seatbelt | `guard()` in `internal/cli/common.go`: `policy.Check` (regex over shell commands) + `Protected` needs `--yes` |
| Dry-run | global flag `--dry-run` |
| Output | JSON envelope + stable exit codes (`internal/out`) |
| Audit | `audit()` → `audit.jsonl` |

Agents also need to talk to databases, caches, and object storage. Today
the way to do it is `komando exec web1 -- psql -c "..."`. That way has three problems:

1. **The output is not structured.** The agent has to parse text tables from `psql`.
2. **The seatbelt is weak.** The `db-drop` regex only catches `DROP DATABASE`.
   `DELETE FROM users;` (without `WHERE`) gets through.
3. **The DB password leaks.** The password goes into the command line or env on the server,
   and then into `audit.jsonl`.

The goal of this design: bring **the same safety layer** to non-SSH resources,
starting with databases.

## Non-goals

- Becoming a full DB client (REPL, migrations, ORM). For that there is already
  `psql`/`usql`.
- Changing the existing `host`. There is no breaking `state.json`
  migration.
- In this phase: redis, s3, and cloud APIs. Only their abstraction is
  prepared.

## Part 1: resource abstraction (`conn`)

### Data model

Add one new map to `store.State`, next to `Hosts`:

```go
type Conn struct {
    Name        string            `json:"name"`
    Kind        string            `json:"kind"`               // postgres | mysql | sqlite | (later: redis, s3)
    URL         string            `json:"url"`                // WITHOUT a password, e.g. postgres://app@db.internal:5432/app?sslmode=require
    PasswordRef string            `json:"password_ref,omitempty"` // secret:/env:/file:, same as Host
    Via         string            `json:"via,omitempty"`      // name of the SSH host used to reach this resource
    Groups      []string          `json:"groups,omitempty"`
    Tags        []string          `json:"tags,omitempty"`
    Labels      map[string]string `json:"labels,omitempty"`
    Protected   bool              `json:"protected,omitempty"`
    Options     map[string]string `json:"options,omitempty"`  // per kind: statement_timeout, row_limit, ...
    Notes       string            `json:"notes,omitempty"`
    CreatedAt   time.Time         `json:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at"`
}

// State
Conns map[string]*Conn `json:"conns"`
```

Rules:

- **Names are unique across hosts and conns.** That way, later one selector
  (`@prod`, `tag:x`) can be used for both without ambiguity.
- **The URL must not contain a password.** If `conn add` receives
  `postgres://u:pass@...`, refuse it with `USAGE` and the hint
  `komando secret set NAME` then `--password-ref secret:NAME`. Do not save it
  silently.
- `Via` uses the existing `Jump` chain. `sshx.Dial(via)` then
  `client.Dial("tcp", addr)` inside the process. **No background tunnel is
  needed and no local port is opened.**

### Commands

```
komando conn add NAME URL [--via HOST] [--password-ref REF] [--group G] [--tag T] [--protected]
komando conn list [SELECTOR]
komando conn edit NAME ...           # same flags as add, plus --add-tag/--rm-tag
komando conn rm NAME
komando conn test SELECTOR           # connect + ping + server version
```

The shape matches `host`, so an agent that already knows `host` understands it
right away.

### Drivers and risk classification

New package `internal/driver`:

```go
type Risk int

const (
    RiskRead        Risk = iota // changes nothing
    RiskWrite                   // changes data
    RiskDestructive             // hard or impossible to undo
)

type Verdict struct {
    Risk   Risk
    Rules  []policy.Rule // matching rules (for error messages)
    Reason string
}
```

Every kind implements:

- `Classify(op) Verdict`: called **before** anything is sent to the server.
- `Dial(ctx, conn, dialer)`: opens the connection, optionally through SSH.

Then `guard()` is generalized into one decision point for all kinds:

| Risk | Normal conn | `--protected` conn |
|---|---|---|
| read | runs | runs |
| write | runs | needs `--yes` (`PROTECTED_HOST` → made general: `PROTECTED_TARGET`) |
| destructive | needs `--allow-dangerous` (`POLICY_BLOCKED`) | needs `--allow-dangerous` **and** `--yes` |

Exit codes and error codes reuse the existing ones (6 for policy). Agents do not
need to learn a new contract.

> Compatibility note: renaming `PROTECTED_HOST` → `PROTECTED_TARGET`
> is a contract change. Proposal: keep `PROTECTED_HOST` for hosts,
> use `PROTECTED_TARGET` only for conns. Needs a decision (see
> [Open questions](#open-questions)).

## Part 2: `komando db`

### Commands

```
komando db query  CONN [SQL | -f FILE | -] [--write] [--limit N] [--param k=v ...]
komando db schema CONN [TABLE...]          # tables, columns, types, indexes, estimated row counts
komando db explain CONN SQL                # EXPLAIN (no ANALYZE unless --analyze --write)
komando db dump   CONN --to PATH           # phase 3, through job
```

Examples:

```bash
komando conn add prod-db postgres://app@10.0.0.5:5432/app \
  --via web1 --password-ref secret:prod-db-pass --protected

komando db schema prod-db users
komando db query prod-db "select id, email from users where created_at > now() - interval '1 day'"
komando db query prod-db --write --dry-run "update users set plan='pro' where id=42"
komando db query prod-db --write --yes "update users set plan='pro' where id=42"
```

### Read-only by default, enforced by the DB itself

This is the most important decision: **`db query` without `--write` runs in a
read-only transaction on the server side.**

- Postgres: `BEGIN READ ONLY` … `ROLLBACK`
- MySQL: `START TRANSACTION READ ONLY` … `ROLLBACK`
- SQLite: open with `mode=ro`

So even if the SQL classification is wrong, the server still refuses writes. The regex
and parser are only a **second layer** for clear error messages,
not the only safeguard. This also matches the note in
`komando policy`: guardrails are not a security boundary.

If a read-only query is refused by the server (e.g. Postgres `25006
read_only_sql_transaction`), return:

```json
{"code":"WRITE_REQUIRES_FLAG","hint":"this statement modifies data; re-run with --write (try --dry-run first)"}
```

with exit 6.

### SQL classification (for `--write`)

Classification is done per statement, after comments and string literals
are removed:

| Class | Examples |
|---|---|
| read | `SELECT`, `WITH … SELECT`, `SHOW`, `EXPLAIN` (without ANALYZE), `DESCRIBE` |
| write | `INSERT`, `UPDATE … WHERE`, `DELETE … WHERE`, `CREATE TABLE/INDEX`, `ALTER … ADD` |
| destructive | `DROP`, `TRUNCATE`, `UPDATE`/`DELETE` **without `WHERE`**, `ALTER … DROP`, `GRANT`, `REVOKE`, `ALTER ROLE/USER`, `VACUUM FULL`, `COPY … TO PROGRAM` |
| unknown | treated as **write** |

- **Multi-statement** (`a; b`): the risk is taken from the highest one. In MySQL,
  multi-statement is turned off in the driver (`multiStatements=false`), except
  through `-f FILE --write`.
- These rules are registered as `policy.Rule` with IDs such as
  `sql-drop`, `sql-delete-no-where`, and so on, so they show up in
  `komando policy` and can be referred to in error messages.

Parser: start with a small home-made tokenizer (first keyword + a check for
top-level `WHERE`). Do not pull in a full SQL parser right away. If
it turns out not to be enough later, consider `pg_query_go` (cgo, heavy) or
`vitess/sqlparser` (MySQL only).

### Dry-run

- `--write --dry-run` in Postgres: run inside `BEGIN`, report
  `rows_affected` (and `RETURNING` if present), then `ROLLBACK`. A real
  dry-run, not just showing a plan.
- In MySQL, DDL auto-commits. So for DDL, dry-run only
  returns the classification and executes nothing. DML is still
  rolled back like in Postgres.
- The output always includes `"dry_run": true` and `"rolled_back": true`.

### Output shape

```json
{
  "ok": true,
  "command": "db.query",
  "data": {
    "conn": "prod-db",
    "risk": "read",
    "write": false,
    "results": [{
      "sql": "select id, email from users limit 2",
      "keyword": "SELECT",
      "risk": "read",
      "columns": [{"name": "id", "type": "int8"}, {"name": "email", "type": "text"}],
      "rows": [[1, "a@x.io"], [2, "b@x.io"]],
      "row_count": 2
    }],
    "committed": false
  },
  "meta": {"version": "…", "duration_ms": 41}
}
```

- `rows` is an array of arrays, which uses fewer tokens than an array of objects.
- `--limit` defaults to 500. The byte limit uses the existing `max_output_bytes`.
  If cut, `truncated: true` and the hint suggests `LIMIT`/`WHERE`.
- Data types: timestamp → RFC3339, `bytea`/BLOB → `{"base64": "…"}`, large
  numeric → string (so precision is not lost in JSON).
- `-o text` shows a plain table through `Texter`.

### Timeouts and load

- `statement_timeout` (Postgres) / `max_execution_time` (MySQL) is set from
  `--timeout`, default 30 seconds for `db query` (not 5 minutes like
  `exec`).
- One connection per command, no pool. komando is a short-lived
  CLI.
- `application_name = komando/<actor>` so it is visible in
  `pg_stat_activity`.

### Audit

One line per command, using the existing `audit()`:

```json
{"command":"db.query","conns":["prod-db"],"risk":"write","sql":"update users set plan='pro' where id=42","rows_affected":1,"ok":true,"dry_run":false,"actor":"claude"}
```

- The password never goes in (the URL is stored without a password).
- SQL can contain sensitive data. Add the setting
  `audit_sql: full | hash | off`, default `full`.
- `--param` parameters are stored as names only, without their values.

### Errors

| Situation | Code | Exit |
|---|---|---|
| Conn does not exist | `CONN_NOT_FOUND` | 3 |
| DB connect / auth failed | `DB_CONNECT` / `DB_AUTH` | 4 |
| `--via` host failed | the existing SSH errors (`HOSTKEY_MISMATCH`, …) | 4 |
| SQL error (syntax, constraint) | `DB_ERROR` + `sqlstate` in `data` | 5 |
| Blocked by policy | `POLICY_BLOCKED` / `WRITE_REQUIRES_FLAG` / `PROTECTED_TARGET` | 6 |
| Timeout | `TIMEOUT` | 7 |

Every error carries a `hint`, following the existing rules.

### Dependencies

| Kind | Library | Notes |
|---|---|---|
| postgres | `github.com/jackc/pgx/v5` | pure Go, `DialFunc` can be pointed at SSH |
| mysql | `github.com/go-sql-driver/mysql` | `RegisterDialContext` for SSH |
| sqlite | `modernc.org/sqlite` | pure Go, no cgo; useful for tests and local files |

The binary will grow by a few MB. If this becomes a problem, the drivers can be
split out with a build tag (`-tags nodb`).

**Rejected alternative:** running `psql`/`mysql` on the server through
`exec`. This way has no dependencies, but it needs the client installed on the server,
the output is text, and the password has to be sent to the server. It can still be offered
as a `--via-cli` fallback if someone asks for it.

## Part 3: changes elsewhere

- `komando guide`: add a section "database: look at the schema first, query
  read-only, `--write --dry-run`, only then `--write`".
- `komando schema`: included automatically because it uses cobra.
- `komando policy`: show the SQL rules, grouped by kind.
- `AGENTS.md`: add the rule "do not use `exec … psql`, use `komando db`".
- `docs/usage.md`: a new "Databases" section.
- Tests: unit tests for the SQL tokenizer (case table: comments, strings containing
  `;`, CTEs, `DELETE` without `WHERE`). Integration tests use SQLite, then
  Postgres and MySQL in CI through service containers.

## Phased plan

| Phase | Contents | Result |
|---|---|---|
| 1 | `store.Conn`, `conn add/list/edit/rm/test`, `internal/driver`, generalized `guard()` | foundation; no queries yet |
| 2 | `db query/schema/explain` for postgres + sqlite, read-only, `--write`, dry-run rollback, `--via` | main feature |
| 3 | mysql, `db dump`/`restore` via `job`, `audit_sql` | complete for DBs |
| 4 | `redis` kind (`cache get/keys/ttl/info`; block `FLUSHALL`, `KEYS *` on protected) | proves the abstraction for a second kind |
| 5 | `s3` kind | — |

Phase 4 is placed before S3 on purpose. Redis also needs `--via` and per-command
classification, so it is a good test of whether the `driver`
abstraction is right.

## Open questions

1. **Command name:** `conn`, `resource`, or `db add` directly (with no general
   abstraction)? This design picks `conn` because it is short and generic.
2. **Protected error code:** keep `PROTECTED_HOST` for hosts and
   add `PROTECTED_TARGET` for conns, or make them all the same (breaking)?
3. **Shared selectors:** should `komando conn test @prod` and
   `komando exec @prod` share the same groups? This design
   prepares for it (unique names), but does not turn it on yet.
4. **`audit_sql` default:** `full` (easy to debug) or `hash` (safer
   for personal data)?
5. **Binary size:** is an increase of roughly 5–8 MB acceptable, or do the DB
   drivers need to be a separate build?
