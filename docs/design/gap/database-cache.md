# Gap analysis: databases and caches (komando `feat/v0.3`, commit 4784fc9)

> **Snapshot of `feat/v0.3` (commit 4784fc9), 2026-11-02.** Many MISSING and
> PARTIAL rows below were done in Phases 1–5 and the built-in work, and no
> feature needs kubectl, psql, the aws CLI, openvpn or openconnect any more.
> Current status: [README.md](README.md#still-open).

Scope: `komando db` (postgres, mysql/mariadb, sqlite), `komando cache` (redis/valkey/keydb/dragonfly),
and data engines that are not supported yet. Compared with psql, pgcli, mysql, mycli, sqlite3, usql,
DBeaver/DataGrip, pg_dump/pg_restore/pg_dumpall, mysqldump/mydumper, pg_activity/pg_top, pgbench,
golang-migrate/dbmate/Flyway/Atlas/sqitch, PgBouncer admin, redis-cli, RedisInsight, memcached tools,
mongosh, sqlcmd, sqlplus, clickhouse-client, cqlsh, curl to Elasticsearch/OpenSearch, influx, cockroach,
aws dynamodb, kcat/kafka-topics, rabbitmqadmin, nats, etcdctl, consul.

Method: read `internal/cli/db.go`, `dbdump.go`, `dbshell.go`, `cache.go`, `conn.go`, `everything.go`,
`meta.go`, `ops.go`, `internal/dbx/*`, `internal/cachex/cachex.go`, `internal/driver/*`, docs
(`vision.md`, `resources-and-db.md`, `ux.md`, `features/databases.md`, `features/caches.md`), plus
`bin/komando ... --help` and `komando policy check --for ...` (offline, with no connection to any server).

## Legend

- **PRESENT**: there is a safe, structured, first-class command/flag.
- **PARTIAL**: possible, but through a raw path (`db query`, `cache run`, `exec`, `db shell`, `tunnel`) or the feature is incomplete. The notes column says what is missing.
- **MISSING**: no reasonable path in komando (a workaround outside komando is named if there is one).
- **NON-GOAL**: deliberately not built; the reason is quoted from the design documents.
- Priority: **P1** daily need / security / agent blocker; **P2** useful; **P3** niche. PRESENT and NON-GOAL rows get `-`.

Non-goal quotes used repeatedly:

- **NG-1** (vision.md, Non-goals): "Replacing full tools (`psql`, `kubectl`, `terraform`, `helm`). komando handles 80% of daily work safely. The rest can still be done through `exec` on the host or the original tool."
- **NG-2** (resources-and-db.md, Non-goals): "Being a full DB client (REPL, migrations, ORM). `psql`/`usql` already exist for that."
- **NG-3** (vision.md): "GUI, TUI, plugin system, or daemon/server. komando stays a pure CLI."
- **NG-4** (vision.md): "Monitoring or alerting that runs continuously."
- **NG-5** (vision.md, Technical rules): "No pool and no daemon. One connection per command."
- **NG-6** (vision.md): "Infrastructure as Code, cloud provisioning, or GitOps."

Technical facts that affect priority:

- Binary size: the release build (`-s -w -trimpath`, CGO_ENABLED=0) is **34.7 MB** (`bin/komando` at 51 MB in the repo is an unstripped dev build). Binary size is no longer capped (owner decision), so new drivers (Mongo, MSSQL, ClickHouse, Cassandra) are judged by daily need, not size.
- `db dump/restore` uses external `pg_dump`/`psql`/`mysqldump`/`mysql` (on the laptop or on the `--via` host), not pure Go.

---

## 1. Database connections and inventory

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Register a DB with a URL, password in the vault | psql (`PG*` env, `.pgpass`), mysql (`.my.cnf`), usql, DBeaver | PRESENT | `conn add NAME URL --password-ref secret:X`; a URL with a password is rejected (`URL_HAS_PASSWORD`, `driver.Parse`) | - |
| PostgreSQL | psql, pgcli | PRESENT | kind `postgres`/`postgresql` (pgx v5, pure Go) | - |
| MySQL / MariaDB | mysql, mycli, mariadb | PRESENT | kind `mysql`/`mariadb`; MariaDB `max_statement_time` fallback (`dbx.setTimeout`) | - |
| SQLite (local file) | sqlite3 | PRESENT | `sqlite:///path` (modernc, no cgo); `mode=ro` + `query_only` without `--write` | - |
| SQLite on a remote server (file on an SSH host) | sqlite3 via ssh | MISSING | `conn.go:94` "conns are local files; --via is not supported". Workaround: `exec host -- sqlite3 ...` (no SQL classification) or `download` and then query locally | P2 (SQLite on small VPSes is common: Rails/Django/PocketBase apps) |
| Reach a DB through a bastion (`--via`), with no local port | ssh -L + psql, DBeaver SSH tunnel | PRESENT | `conn add --via HOST`; dial inside the process (pgx `DialFunc`, mysql `RegisterDialContext`) | - |
| Reach a DB through a VPN | DBeaver + OS VPN | PRESENT | `--via office,bastion` (VPN kinds) | - |
| Postgres TLS (sslmode, sslrootcert, client cert) | psql `sslmode`/`sslrootcert`/`sslcert` | PARTIAL | pgx reads all `ssl*` parameters from the URL. But `db shell` only passes `PGSSLMODE` (`dbshell.go`), not `sslrootcert`/`sslcert`; `db dump` passes the full URL to `pg_dump` (ok). Cert paths are local files, not from the vault | P2 |
| MySQL TLS with own CA / client cert | mysql `--ssl-ca`, `--ssl-cert` | PARTIAL | Only `tls=` true, false, skip-verify, preferred (`dbx/mysql.go`); a custom CA needs `mysql.RegisterTLSConfig`, which is not used. ux.md edge case: "TLS with self-signed certificates: explicit option per conn" | P2 (RDS/Azure/self-hosted with a private CA) |
| Local Unix socket (`/var/run/postgresql`, `mysql.sock`) | psql, mysql | MISSING | `driver.Parse` requires a hostname. Workaround: TCP to 127.0.0.1 through `--via` that server | P3 |
| IAM login / cloud token (RDS IAM, Cloud SQL IAM, Azure AD) | aws rds generate-db-auth-token + psql, cloud-sql-proxy | MISSING | Static secret refs only (`secret:`/`env:`/`file:`/`aws-sm:`...). A 15-minute token must be made per connection | P2 (more and more common on AWS/GCP; fits the ref model as `aws-rds-iam:`) |
| `pg_service.conf` / `~/.pgpass` / `~/.my.cnf` | psql, mysql | PRESENT | `komando import pgpass`, `import mycnf`, `import env`, `import dbeaver` (importer.go). `pg_service.conf` is not imported | - (pg_service: P3) |
| Check connection **and login** + server version | `pg_isready`, `psql -c 'select 1'`, `redis-cli ping` | PARTIAL | **Bug/gap**: `komando test` for a conn only opens TCP (`conn.go testConn`, `Check: "tcp"`) and checks that the password ref can be read. Login, auth, wrong DB name, TLS and server version are not checked, even though `--help` says "reached and logged in to" and resources-and-db.md promises "connect + ping + server version" | **P1** (agents rely on `test` before working; auth errors only show up later) |
| Query many DBs at once (`db query @prod`) | usql (no), loop scripts, DataGrip "run on multiple" | MISSING | Rejected with a clear message (`singleConn`; ux.md "Next") | P2 (check version/size on 20 tenant DBs; the universal selector already exists) |
| Pick another DB on the same server without a new conn | psql `\c dbname`, mysql `USE` | PARTIAL | `USE` in mysql only lasts for one command; there is no `--database` override. Workaround: a new conn per DB | P3 |
| Read replica / read-only routing to a replica | pgcli? (no), application | MISSING | Workaround: a separate conn for the replica (`--tag replica`) | P3 |
| Other Postgres-wire: CockroachDB, YugabyteDB, Neon, Supabase, Timescale, Redshift, AlloyDB | cockroach sql, psql | PARTIAL | Queries through `postgres://` probably work (pgx, `SHOW standard_conforming_strings`, `BEGIN READ ONLY`). Not tested yet; `db schema` uses `pg_class` (CockroachDB supports part of it), `db dump` with `pg_dump` is not supported by CockroachDB; Redshift does not support all catalogs | P2 (needs tests + compatibility notes) |
| Other MySQL-wire: TiDB, Vitess/PlanetScale, Aurora, SingleStore | mysql | PARTIAL | Through `mysql://`; not tested yet (PlanetScale: `START TRANSACTION READ ONLY` is supported; `mysqldump` to Vitess is limited) | P3 |

## 2. Running queries

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Run any SQL | psql `-c`, mysql `-e`, sqlite3, usql | PRESENT | `db query CONN "SQL"` | - |
| Read-only by default, enforced by the server | (not in psql; DBeaver "read-only connection") | PRESENT | `BEGIN READ ONLY` / `START TRANSACTION READ ONLY` / sqlite `mode=ro` (`dbx.Run`) | - |
| Risk classification before sending | (none) | PRESENT | `driver.ClassifySQL`; rules `sql-drop`, `sql-delete-no-where`, `sql-kill`, etc.; `policy check --for postgres "..."` | - |
| Write dry-run with rollback | (manual BEGIN/ROLLBACK) | PRESENT | `--write --dry-run` → `rows_affected` + `rolled_back` | - |
| SQL from a file / stdin | psql `-f`, `\i`, mysql `< file` | PRESENT | `--file FILE`, `--file -` | - |
| Parameter binding | psql `\bind` (16+), `-v` | PRESENT | positional `--arg` (`$1`/`?`), only for 1 statement | - |
| Named variables / substitution (`:var`, `\set`) | psql `-v`, `\set`, `\gset` | MISSING | Only positional `--arg`; `\gset` (result → variable) does not exist | P3 |
| Multiple statements in one atomic transaction | psql `--single-transaction` | PRESENT | One `db query` = one transaction; `BEGIN/COMMIT` is rejected (`SQL_TX_CONTROL`) | - |
| Interactive transaction across commands (BEGIN … inspect … COMMIT) | psql, mysql REPL | NON-GOAL | NG-5 "One connection per command"; deliberate design (resources-and-db.md). Replacement: `--write --dry-run` then `--write` | - |
| Savepoint | psql | NON-GOAL | `SAVEPOINT` is rejected (`txControl`); a consequence of the one-transaction model | - |
| Non-transactional statements (VACUUM, CREATE INDEX CONCURRENTLY, MySQL DDL) | psql | PRESENT | Must be sent alone; dry-run only reports (`Statement.NoTx`) | - |
| Query timeout | psql `statement_timeout`, mysql `max_execution_time` | PRESENT | `--timeout` (default 30 seconds), set on the server | - |
| `lock_timeout` (do not wait long for a lock) | psql `SET lock_timeout` | PARTIAL | Not set; only `statement_timeout`. ux.md edge case "db: long lock (`lock_timeout`)" is not closed yet. You can run `SET lock_timeout` manually in the same query | P2 (DDL in production can queue behind a lock and block all other queries for 30 seconds) |
| `idle_in_transaction_session_timeout`, `application_name` | psql | PRESENT | `application_name = komando/<actor>` (visible in `pg_stat_activity`); the transaction is always closed per command | - |
| Cancel a query (Ctrl-C) | psql Ctrl-C | PRESENT | context cancel + server timeout | - |
| EXPLAIN / EXPLAIN ANALYZE | psql, pgcli, DataGrip | PRESENT | `db explain [--analyze]` (Postgres `ANALYZE, BUFFERS`; MySQL `EXPLAIN ANALYZE`; SQLite `QUERY PLAN`) | - |
| EXPLAIN in JSON format / visualization (explain.dalibo, pev2) | psql, DataGrip | PARTIAL | Possible with `db query "explain (format json) ..."`; no `--format json` flag or summary of slowest nodes | P3 |
| `\gexec` (run query results as SQL) | psql | MISSING | Deliberately absent (dangerous for agents); can be done in two manual steps | P3 |
| `\watch` (repeat a query every N seconds) | psql `\watch`, `watch` | MISSING | No `--repeat/--interval`. A continuous mode conflicts with NG-4; a limited version (`--repeat 5 --interval 2s`) still fits | P3 |
| `\timing` | psql, mysql | PRESENT | `meta.duration_ms` in every answer (total, not per statement) | - |
| MySQL `--safe-updates` safeguard | mysql `--safe-updates` | PRESENT | Equal/stronger: `sql-update-no-where`, `sql-delete-no-where` | - |
| Structured result per statement | (not in psql) | PRESENT | `data.results[]` with `columns`, `rows`, `row_count`, `rows_affected` | - |
| JSON-safe data types (bigint, numeric, bytea, timestamp UTC) | none | PRESENT | `driver.JSONValue`; > 2^53 becomes a string, binary → `{"base64":...}` | - |

## 3. Output, paging, data export and import

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Text table output | psql aligned, mysql table | PRESENT | `-o text` (tabwriter, cuts cells > 80 characters) | - |
| JSON output | usql `-J`, psql `\pset format json` (17+) | PRESENT | `-o json` (stable envelope) | - |
| Expanded / vertical mode (`\x`, `\G`) | psql `\x`, mysql `\G`, pgcli | MISSING | Wide tables are cut off in the terminal; there is no `-o vertical` | P3 |
| CSV/TSV/Markdown export | psql `\copy ... csv`, `--csv`, sqlite3 `.mode csv`, DBeaver export, mycli `--csv` | MISSING | `-o` only has `auto`, `json`, `text`. Workaround: `-o json` then jq `@csv` | P2 (the request "send this data as CSV" is very common) |
| Export large results to a file (streaming, without the 500 rows / 256 KiB limit) | psql `\copy (query) TO file`, `\o file`, DBeaver export | PARTIAL | `--limit 0` + a large `--max-output`; everything is held in memory and printed at once. `COPY ... TO STDOUT` is not supported through `database/sql` | P2 |
| Result paging (offset/cursor, "next page") | pgcli pager, DataGrip, psql `FETCH` | PARTIAL | `truncated: true` + hint; no `--offset`/cursor; the agent must write `LIMIT/OFFSET` itself | P3 |
| Pager for humans (`less`) | psql/pgcli pager | PARTIAL | Piping to `less` is safe (SIGPIPE is handled, ux.md); not automatic | P3 |
| Import CSV into a table | psql `\copy FROM`, mysql `LOAD DATA LOCAL INFILE`, sqlite3 `.import`, DBeaver import | MISSING | `COPY FROM STDIN` does not work through `db query`; `LOAD DATA LOCAL` is not enabled in the driver. Workaround: generate INSERTs then `--file --write` | P2 |
| Copy data between DBs (table A in prod → staging) | DBeaver data transfer, pg_dump `-t` \| psql | MISSING | Workaround: `db dump` (whole DB) then `db restore` | P3 |
| Save output to a file | psql `\o`, `-o file` | PRESENT | Shell redirect; stable JSON | - |

## 4. Schema introspection (equivalent to psql / sqlite3 / mysql meta-commands)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| List tables/views + estimated rows (`\dt`, `.tables`, `SHOW TABLES`) | psql, sqlite3, mysql | PRESENT | `db schema CONN` (table, view, matview, foreign table; `row_estimate`) | - |
| Columns, types, null, default, PK (`\d table`, `.schema`, `DESCRIBE`) | psql, sqlite3, mysql | PRESENT | `db schema CONN TABLE...` | - |
| Indexes (definition) | psql `\d`, `\di` | PRESENT | `indexes[].definition` | - |
| Foreign keys / relations | psql `\d`, DataGrip diagram | PARTIAL | `dbx.Table` has no FK (`dbx/schema.go:14-21`). Only through the raw path: `db query` to `information_schema.table_constraints`/`pg_constraint` (read) | **P1** (agents need relations to write correct JOINs and to judge the impact of DELETE/ON DELETE CASCADE) |
| Unique/check constraints, exclusion | psql `\d` | PARTIAL | Unique is only implied by the index definition; CHECK/exclusion is not in `db schema`, only through `db query` to `pg_constraint` / `information_schema.check_constraints` | P2 |
| Triggers | psql `\d`, `SHOW TRIGGERS` | PARTIAL | Not in `db schema`; only through `db query` (`information_schema.triggers`, `SHOW TRIGGERS`, classified read). Important when judging side effects of UPDATE/DELETE | P2 |
| List schemas/namespaces (`\dn`) | psql | PARTIAL | The schema name shows per table; there is no schema list (empty ones are not visible) | P3 |
| List databases on the server (`\l`, `SHOW DATABASES`) | psql, mysql | PARTIAL | Through `db query "select datname from pg_database"`; MySQL `db schema` only shows the current `DATABASE()` | P2 |
| Functions/procedures (`\df`, `SHOW PROCEDURE STATUS`) | psql, mysql | PARTIAL | Through `db query` to the catalog | P3 |
| Sequences (`\ds`), types/enums (`\dT`), extensions (`\dx`) | psql | PARTIAL | Through `db query`; enums matter for writing valid INSERTs | P3 |
| View definition (`\d+ view`, `SHOW CREATE VIEW`) | psql, mysql | PARTIAL | Through `db query "select pg_get_viewdef(...)"` / `SHOW CREATE VIEW` | P3 |
| Full DDL of one table (`SHOW CREATE TABLE`, `pg_dump -s -t`) | mysql, pg_dump | PARTIAL | MySQL: `db query "show create table x"` (read). Postgres: no built-in function; `db dump` has no `--schema-only -t` | P2 |
| Table/index size (`\dt+`, `\di+`) | psql | PARTIAL | Through `db query` (`pg_total_relation_size`, `information_schema.tables.data_length`). No size column in `db schema` | P2 |
| Table/column comments (`\d+`, `COMMENT`) | psql, DataGrip | PARTIAL | Not in `db schema`; through `db query` (`obj_description`/`col_description`, `information_schema.columns.column_comment`). Comments often explain what a column means: useful for agents | P3 |
| Partitions | psql `\d+` | PARTIAL | Partitioned tables (`relkind p`) show as `table`; the parent/child relation does not | P3 |
| Per-table privileges (`\dp`, `SHOW GRANTS`) | psql, mysql | PARTIAL | Through `db query` | P3 |
| Search tables/columns by name across all schemas | DataGrip search, pgcli completion | PARTIAL | `db schema` then filter with jq; columns only for named tables | P3 |
| ER diagram | DBeaver, DataGrip | NON-GOAL | NG-3 (not a GUI) | - |

## 5. Interactive client comfort

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Interactive REPL | psql, mysql, sqlite3, pgcli, mycli, usql | PRESENT (through the original tool) | `db shell CONN` opens psql/mysql/sqlite3 with the password from the vault and the `--via` path, read-only by default (`PGOPTIONS=-c default_transaction_read_only=on`, `--init-command=SET SESSION TRANSACTION READ ONLY`, `-readonly`). A home-made REPL = NG-2 | - |
| REPL with pgcli/mycli/usql/litecli | pgcli, mycli, usql | PARTIAL | `db shell` only calls psql/mysql/sqlite3. Workaround: `tunnel start CONN` then pgcli to the local port (the password must be typed manually) | P3 (`--client pgcli`) |
| SQL autocomplete | pgcli, mycli, DataGrip | NON-GOAL | NG-2/NG-3; available via `db shell` + pgcli | - |
| Query history | psql `~/.psql_history`, pgcli history, DataGrip | PARTIAL | `komando audit --command db.query` records the SQL (if `audit_sql=full`), actor and result. There is no "rerun entry N" | P3 |
| Saved / favorite queries (named queries) | pgcli `\ns`/`\n`, mycli favorites, DBeaver scripts, usql | MISSING | `recipe` is only for shell on a host (ops.go), not SQL to a conn. Workaround: a `.sql` file + `--file` | P2 (agents and teams need safe, reusable "check the queue", "latest users"; `recipe` already exists as a concept) |
| Edit a query in `$EDITOR` (`\e`) | psql, pgcli | NON-GOAL | NG-2 (available via `db shell`) | - |
| `\!` shell escape | psql | NON-GOAL | Deliberately blocked in restore; in `db shell` it is noted as a risk (docs) | - |
| Syntax help (`\h`) | psql, mysql `help` | NON-GOAL | Original tool via `db shell` | - |

## 6. Backup and restore

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Dump one DB to a local file (plain SQL, gzip) | pg_dump, mysqldump | PRESENT | `db dump CONN --to FILE[.gz]`; file 0600, does not overwrite, atomic | - |
| Consistent SQLite dump | sqlite3 `.backup`, `.dump` | PRESENT | `VACUUM INTO` (a DB file, not SQL text). Text `.dump`: not available | - |
| Custom/directory/tar format (`pg_dump -Fc/-Fd/-Ft`) | pg_dump, pg_restore | MISSING | Only plain SQL (`toolsFor`). The custom format is standard Postgres practice (selective restore, parallel, compression) | **P1** (production Postgres backups are almost always `-Fc`; files from other teams cannot be restored) |
| Restore custom format (`pg_restore`) | pg_restore | MISSING | `db restore` only runs SQL through `psql` | **P1** (the pair of the row above) |
| Parallel dump (`-j`), mydumper/myloader | pg_dump `-Fd -j`, mydumper | MISSING | | P3 |
| Schema only / data only (`-s`, `-a`, `--no-data`) | pg_dump, mysqldump | MISSING | | P2 (a schema dump for review/diff is very common) |
| Include/exclude tables or schemas (`-t`, `-T`, `-n`, `--ignore-table`) | pg_dump, mysqldump | MISSING | | P2 (exclude giant log tables) |
| Globals/roles (`pg_dumpall --globals-only`), all DBs | pg_dumpall, mysqldump `--all-databases` | MISSING | | P3 |
| Restore options: `--clean`, `--create`, `--no-owner`, `--no-acl` | pg_restore, psql | MISSING | Restoring from prod to staging often fails because owners/roles differ; there is no `--no-owner` | P2 |
| Single-transaction restore + dangerous file check | psql `--single-transaction` | PRESENT | `--single-transaction ON_ERROR_STOP=1` (Postgres only, `dbdump.go:64`; MySQL restore is not atomic because DDL auto-commits); files with `\!`, `\i`, `system` are rejected (`driver/restore.go`) | - |
| Restore safeguards (destructive + protected) | none | PRESENT | `--allow-dangerous`, `--yes` on a protected conn | - |
| zstd/lz4 compression, level | pg_dump `-Z zstd`, gzip | PARTIAL | Only `.gz` | P3 |
| Dump straight to storage (S3) or keep it on the server | pg_dump \| aws s3 cp | PARTIAL | The file always goes to the laptop; two steps `db dump` then `storage upload` (a large DB through the laptop = slow). Workaround: `job start host -- 'pg_dump ...'` (you must handle the password yourself) | P2 |
| Dump/restore a large DB as a background job (progress, resume after disconnect) | `nohup pg_dump`, `komando job` | MISSING | `db dump` runs in the foreground, with no progress and no detach; AGENTS.md rule 6 says to use `job` for > 2 minutes, but `job` cannot run `db dump` | P2 |
| Dump with a pure Go client (no pg_dump installed) | none | MISSING | Needs `postgresql-client`/`mysql-client` on the laptop or the `--via` host; pg_dump version < server → fails (there is a hint) | P3 |
| Scheduled backup + retention | pgBackRest, cron | NON-GOAL | NG-5 (no daemon); can use `cron set` on the host | - |
| PITR / WAL archiving / base backup (pgBackRest, Barman, wal-g, xtrabackup) | pgBackRest, wal-g | NON-GOAL | NG-1 | - |
| Backup verification (list contents, `pg_restore -l`) | pg_restore `-l` | MISSING | | P3 |

## 7. Operations and diagnosis (daily DBA)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Server summary: version, uptime, DB size, connections/max_connections, primary/replica role | `\conninfo`, `SELECT version()`, `mysqladmin status`, pg_activity header | PARTIAL | There is no `db info`/`db status` (even though `cache info` exists and ux.md lists the verbs `status`/`info`). The `postgres-status`/`mysql-status` recipes run on the host via `sudo -u postgres psql`, not on the conn. Workaround: `db query` | **P1** (first step of every incident; verb consistency across families) |
| Activity / running queries | pg_activity, pg_top, `SHOW PROCESSLIST`, mytop | PARTIAL | `db query "select ... from pg_stat_activity"` (read). No first-class command that filters long-running/idle in transaction queries | **P1** |
| Locks and who blocks whom | pg_activity (blocking), `pg_blocking_pids`, `sys.innodb_lock_waits` | PARTIAL | Through `db query`; the lock tree query is complex to rewrite every time | **P1** |
| Stop a query / session | `pg_cancel_backend`, `pg_terminate_backend`, MySQL `KILL` | PARTIAL | `db query --write --allow-dangerous "select pg_terminate_backend(123)"` (rule `sql-kill`). No `db kill PID` with a dry-run that shows the query to be stopped and the difference between cancel and terminate | **P1** |
| Slow queries / query statistics (`pg_stat_statements`, slow log, `performance_schema`) | pg_stat_statements, pt-query-digest, PMM | PARTIAL | Through `db query` if the extension is installed | P2 |
| Biggest DBs / tables / indexes | psql `\l+`, `\dt+`, pg_activity | PARTIAL | Through `db query` | **P1** (a full disk is a daily incident; `db schema` already shows rows but not size) |
| Bloat, dead tuples, last autovacuum | pgstattuple, check_postgres, pg_activity | PARTIAL | Through `db query` (`pg_stat_user_tables`) | P3 |
| Unused indexes / missing indexes | pg_stat_user_indexes, pghero | PARTIAL | Through `db query` | P3 |
| Cache hit ratio, IO statistics | pghero, pg_activity | PARTIAL | Through `db query` | P3 |
| Replication status and lag | `pg_stat_replication`, `SHOW REPLICA STATUS`, orchestrator | PARTIAL | Through `db query` (`SHOW REPLICA STATUS` is classified read) | P2 |
| Replication slots (logical/physical) | psql | PARTIAL | Read through `db query`; drop/create is blocked by `sql-server-config` (needs `--allow-dangerous`) | P3 |
| Server configuration (`SHOW ALL`, `pg_settings`, `SHOW VARIABLES`) | psql, mysql | PARTIAL | Read through `db query`; changing globals = `sql-server-config` (destructive). No summary of "settings that differ from the default" | P3 |
| VACUUM / ANALYZE / REINDEX / OPTIMIZE TABLE | psql, mysqlcheck | PRESENT (through the raw path) | `db query --write "vacuum analyze t"` (noTx, must be alone); `VACUUM FULL` is blocked by `sql-vacuum-full` | - |
| Wraparound / XID age | check_postgres | PARTIAL | Through `db query` | P3 |
| Benchmark (pgbench, sysbench, mysqlslap) | pgbench | MISSING | Not part of the daily 80%; can use `exec host -- pgbench` | P3 |
| Continuous monitoring / dashboard (pg_activity live, PMM) | pg_activity, pg_top | NON-GOAL | NG-4 and NG-3 (TUI) | - |
| DB health check with advice (pghero-style "checks") | pghero, pg_doctor | MISSING | Could become a built-in SQL `recipe` (see section 5) | P2 |

## 8. Users, roles and privileges

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| List users/roles and their attributes (`\du`, `mysql.user`) | psql, mysql | PARTIAL | Through `db query` | P2 |
| Create user / change password / grant / revoke | psql, mysql, DataGrip | PARTIAL | `db query --write --allow-dangerous "create user ..."` (rule `sql-privileges`). **Security gap**: the password in `CREATE USER ... PASSWORD '...'` / `ALTER ROLE ... PASSWORD` is recorded in full in `audit.jsonl` when `audit_sql=full` (the default), and `--arg` cannot be used in Postgres DDL. There is no redaction of password literals and no way to take the password from the vault (`secret:`) | **P1** (security: secret leaks into the audit log; "create a read-only user for the app/komando" is a common task, and the docs themselves suggest a dedicated least-privilege user) |
| Template "read-only user for komando/agent" | none | MISSING | docs/features/databases.md: "give komando a database user with only the rights it needs", but there is no help to create one | P2 |
| See effective grants of one user (`SHOW GRANTS FOR`, `\dp`) | mysql, psql | PARTIAL | Through `db query` | P3 |
| Row-level security, policies | psql | PARTIAL | Through `db query`; `CREATE POLICY` is classified write (not privileges) | P3 |

## 9. Schema migrations and schema diff

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Versioned migration tool (up/down, version table) | golang-migrate, dbmate, Flyway, Liquibase, Atlas, sqitch, goose | NON-GOAL | NG-2 "Being a full DB client (REPL, migrations, ORM)". Replacement: `db query --file m.sql --write --dry-run` then `--write` (atomic in Postgres) | - |
| Run existing migration files safely (dry-run per file, order) | dbmate `--dry-run`?, Atlas `migrate apply --dry-run` | PARTIAL | One file per command with `--file`; MySQL DDL cannot be dry-run. No "run a folder" | P3 |
| Migration status (installed version) | migrate `version`, Flyway `info` | PARTIAL | Through `db query "select * from schema_migrations"` | P3 |
| Schema diff of two DBs (prod vs staging) | Atlas `schema diff`, migra, pgquarrel, mysqldiff, DataGrip compare | MISSING | Workaround: `db schema -o json` on two conns then `diff`/jq (only columns/indexes of named tables) | P2 (detect drift before deploy; `db schema` JSON is already 70% of the way) |
| Generate migrations from a diff | Atlas, migra | NON-GOAL | NG-2/NG-6 | - |
| Migration lint (operations that lock tables) | squawk, Atlas lint | PARTIAL | Risk classification catches DROP/TRUNCATE/ALTER DROP, but not `ALTER TABLE ... ADD COLUMN ... DEFAULT volatile`, indexes without CONCURRENTLY, etc. | P3 |

## 10. Connection poolers and proxies

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| PgBouncer admin console (`SHOW POOLS`, `SHOW STATS`, `PAUSE`, `RELOAD`) | psql to db `pgbouncer` | MISSING | The PgBouncer console does not accept `BEGIN READ ONLY` or the `SHOW standard_conforming_strings` check during `dbx.Open`, so `db query` will almost certainly fail. Workaround: `exec host -- psql -p 6432 pgbouncer -c 'show pools'` | P3 |
| Query through PgBouncer in transaction mode (normal app DB) | psql | PARTIAL | Probably works (one transaction per command fits); pgx stdlib uses prepared statements, which are a problem in PgBouncer < 1.21 transaction mode. Not tested/documented yet | P2 |
| ProxySQL admin, pgpool, Odyssey | mysql to the admin port | MISSING | | P3 |
| Connection pool on the komando side | none | NON-GOAL | NG-5 "No pool and no daemon" | - |

## 11. DB-specific security and audit

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Audit every query (who, what, result) | pgaudit (server side), DataGrip log | PRESENT | `audit_sql`: full, hash, off; for `--arg` only the count is recorded | - |
| Redaction of sensitive data in audit SQL (password literals, PII) | none | MISSING | Only the choice of all/hash/nothing. See section 8 | **P1** (merge with the CREATE USER row) |
| Block dangerous functions in read-only (dblink, pg_read_file, COPY PROGRAM, lo_export) | none | PRESENT | `sql-remote`, `sql-server-file`, `sql-program` | - |
| Reject non-default string-parsing settings (classification bypass) | none | PRESENT | `checkStringRules`, `SQL_STRING_RULES` | - |
| Type-the-name confirmation on restore/drop at a terminal | DataGrip "production" warning | PRESENT | `confirmDangerous` (`common.go:334`): at a terminal without `--allow-dangerous` you are asked to type the conn name; a protected conn asks `[y/N]` (`confirmProtected`) | - |
| Limit on the number of changed rows (`--max-rows-affected`) | (not common; Atlas/ pt-archiver) | MISSING | `--dry-run` shows the count, but `--write` without a dry-run has no safety limit (e.g. an UPDATE with a wrong WHERE touches 1 million rows) | P2 (a cheap safety layer for agents) |
| Masking sensitive columns in output | DataGrip, Satori, pg_anonymizer | MISSING | `conn --option` already exists but is not used by db kinds | P3 |
| Promised per-conn options (`statement_timeout`, `row_limit`) | none | MISSING | resources-and-db.md: "Options ... per-kind: statement_timeout, row_limit"; `conn --option` is only used by `cluster` (namespace, `cluster.go:78`). The example in `conn edit --help` (`--option statement_timeout=10s`, `conn.go:186`) is misleading: it is accepted but ignored | P3 |

---

## 12. Cache: connections and topology

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Redis/Valkey/KeyDB/Dragonfly standalone | redis-cli, valkey-cli | PRESENT | kind `redis` (`redis://`, `rediss://`), go-redis v9 | - |
| Garnet, Upstash, ElastiCache/Memorystore non-cluster | redis-cli | PRESENT (probably) | Same protocol; not tested yet | - |
| Redis Cluster (MOVED/ASK, ElastiCache cluster mode, `redis-cli -c`) | redis-cli `-c` | MISSING | A single `redis.NewClient`; commands for another slot get `MOVED` (ux.md edge case "Redis cluster (`MOVED`)"). `cache keys` only scans one node | P2 (common on large ElastiCache/Azure) |
| Sentinel (find the master) | redis-cli `-p 26379`, `SENTINEL get-master-addr-by-name` | PARTIAL | Only the raw path: a conn to the sentinel port then `cache run --write -- SENTINEL get-master-addr-by-name X` (`SENTINEL` is not known to `cachex.Classify`, so it is classified write). There is no sentinel-aware conn (find the master automatically, follow failover); ux.md edge case "sentinel" is not closed yet | P2 |
| ACL user + password | redis-cli `--user`, `--pass` | PRESENT | user in the URL, password via ref | - |
| TLS by default (rediss) | redis-cli `--tls` | PRESENT | `MinVersion TLS1.2`, SNI | - |
| TLS with own CA / skip-verify / client cert (`--cacert`, `--insecure`, `--cert`) | redis-cli | MISSING | `cachex.Open` only sets `ServerName`; no URL options. Self-hosted Redis with a private certificate cannot be used | P2 |
| Pick a DB (`-n`, `SELECT`) | redis-cli `-n` | PARTIAL | DB number from the URL path; `SELECT` through `cache run` is classified write and is useless (one command per connection). No per-command `--db N` | P3 |
| Through a bastion/VPN (`--via`) | ssh -L + redis-cli | PRESENT | `a.Dial` | - |
| Unix socket | redis-cli `-s` | MISSING | | P3 |
| Login check (not just TCP) | `redis-cli ping` | PARTIAL | Same as section 1: `komando test` only checks TCP; `cache info` does PING+AUTH | **P1** (merge with the test row in section 1) |
| Interactive REPL | redis-cli | MISSING | `db shell` has no `cache shell` counterpart. Workaround: `tunnel start CONN` + `redis-cli` (password typed manually). ux.md section 12 path 3 ("original tool on the laptop through the komando path") does not exist for cache yet | P3 |

## 13. Cache: reading and browsing

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Read a key of any type + TTL + size | redis-cli `GET/HGETALL/...`, RedisInsight browser | PRESENT | `cache get` (string/hash/list/set/zset/stream, `--limit` cap, binary → base64) | - |
| Module types (RedisJSON, TimeSeries, Bloom) | RedisInsight | PARTIAL | `cache get` returns `value: null`; `cache run -- JSON.GET k` **is classified write** (unknown command), so it needs `--write` just to read | P2 (read rules for common modules: `JSON.GET/MGET`, `FT.SEARCH/INFO`, `TS.RANGE/GET`, `BF.EXISTS`) |
| List keys by pattern (SCAN, safe) | redis-cli `--scan --pattern` | PRESENT | `cache keys CONN 'pat*' --limit` (SCAN, never KEYS) | - |
| Filter keys by type (`SCAN TYPE`) | redis-cli `--scan --type` (7+) | PARTIAL | `cache keys` has no `--type` (`cachex.Keys`); through the raw path `cache run -- SCAN 0 MATCH 'x:*' TYPE hash COUNT 1000` (read), cursor repeated manually | P3 |
| Count keys matching a pattern / per prefix | RedisInsight "tree view", redis-rdb-tools | MISSING | `cache keys` stops at `--limit`; the total count is unknown | P3 |
| Number of keys per DB | redis-cli `INFO keyspace`, `DBSIZE` | PRESENT | `cache info` (keyspace section) / `cache run -- DBSIZE` | - |
| Structured INFO per section | redis-cli `INFO` | PRESENT | `cache info CONN [SECTION]` → map per section | - |
| TTL / PTTL / OBJECT / MEMORY USAGE | redis-cli | PRESENT | TTL in `cache get`; the rest through `cache run` (classified read) | - |
| Read streams (XRANGE, XINFO, XPENDING) | redis-cli | PRESENT | `cache get` (stream) and `cache run` (read) | - |
| Non-blocking `XREAD` | redis-cli | PARTIAL | Classified write (not in the read list) because it can `BLOCK`; `XREAD` without BLOCK should be read | P3 |

## 14. Cache: writing per data type

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Set string + TTL | redis-cli `SET ... EX` | PRESENT | `cache set CONN KEY VALUE --ttl` | - |
| Set with NX/XX/KEEPTTL/GET | redis-cli | PARTIAL | Through `cache run --write -- SET k v NX` | P3 |
| Value from a file/stdin (binary, large JSON) | redis-cli `-x` | MISSING | `cache set` only takes arguments; no `--file`/stdin | P3 |
| Change TTL / persist (`EXPIRE`, `PERSIST`) | redis-cli | PARTIAL | `cache run --write -- EXPIRE k 3600`; no `cache expire`/`cache set --ttl` for an existing key | P3 |
| Hash/list/set/zset/stream (HSET, LPUSH, SADD, ZADD, XADD, HDEL, SREM ...) | redis-cli, RedisInsight editor | PARTIAL | All through `cache run --write`; only strings are first-class | P3 |
| Rename/copy a key | redis-cli `RENAME`, `COPY` | PARTIAL | `cache run --write`. `RENAME` silently overwrites the target key but is only classified write (see section 17) | P3 |
| Delete exact keys | redis-cli `DEL/UNLINK` | PRESENT | `cache rm` (`--allow-dangerous`) | - |
| Delete by pattern (prefix invalidation: `--scan --pattern 'x:*' \| xargs DEL`) | redis-cli pipeline | MISSING | `cache rm` deliberately has no pattern. Workaround: `cache keys` then `cache rm k1 k2 ...` (limited by `--limit` and argv length). Can be made safe: `--dry-run` shows the count + examples, `--allow-dangerous`, UNLINK in batches | P2 (invalidating the cache per prefix is daily work after a deploy) |
| Flush DB | redis-cli `FLUSHDB` | PRESENT (through the raw path) | `cache run --write --allow-dangerous -- FLUSHDB` (rule `redis-flush`) | - |
| Write dry-run | none | PARTIAL | Reported honestly: Redis cannot roll back, `--dry-run` only checks permission (`withCache`). It does not show the old value / whether the key exists | P3 |

## 15. Cache: diagnosis and server operations

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Biggest keys (`--bigkeys`) | redis-cli `--bigkeys` | MISSING | Workaround: `cache keys` + `cache run -- MEMORY USAGE` per key (slow, limited). Makes sense as `cache keys --sort size` / `cache big` with SCAN | P2 (memory-full/eviction incidents are common) |
| Memory per key (`--memkeys`, `--memkeys-samples`) | redis-cli | MISSING | Same as above | P2 |
| Hot keys (`--hotkeys`, LFU) | redis-cli `--hotkeys` | MISSING | `OBJECT FREQ` per key through `cache run` | P3 |
| Latency (`--latency`, `--latency-history`, `--intrinsic-latency`) | redis-cli | PARTIAL | `LATENCY LATEST/HISTORY/DOCTOR` through `cache run` (read). Client-side latency is missing (`test` only checks TCP) | P3 |
| Rolling statistics (`--stat`) | redis-cli `--stat` | NON-GOAL | NG-4 (continuous monitoring); a snapshot is in `cache info` | - |
| Slowlog | redis-cli `SLOWLOG GET` | PRESENT (through the raw path) | `cache run -- SLOWLOG GET 20` (read); `SLOWLOG RESET` = write | - |
| MONITOR (see all commands) | redis-cli `MONITOR` | MISSING | `cache run -- MONITOR` is classified write and `Do()` only reads one reply. A time-limited version (`--duration 5s`) is useful for debugging; a continuous version = NG-4. Warning: MONITOR leaks values (PII/secrets) | P3 |
| List clients | redis-cli `CLIENT LIST` | PRESENT (through the raw path) | `cache run -- CLIENT LIST` (read; raw text, not parsed into a table) | - |
| Kill clients | redis-cli `CLIENT KILL` | PRESENT (through the raw path) | `cache run --write --allow-dangerous -- CLIENT KILL ...` (`redis-kill`) | - |
| See config (`CONFIG GET`) | redis-cli | PRESENT (through the raw path) | read; for agents, password settings (requirepass, masterauth, ...) show as `[hidden]` (`cachex.HideSecrets`) | - |
| Change config (`CONFIG SET maxmemory`) | redis-cli | PRESENT (through the raw path) | `redis-server-config` (destructive) | - |
| Replication (role, lag, `INFO replication`) | redis-cli | PRESENT | `cache info CONN replication` | - |
| Memory doctor / stats | redis-cli `MEMORY DOCTOR` | PRESENT (through the raw path) | read | - |
| Persistence: BGSAVE, LASTSAVE, BGREWRITEAOF | redis-cli | PRESENT (through the raw path) | `BGSAVE` is classified write; `SAVE` is blocked (`redis-blocking`) | - |
| `DEBUG` (sleep, object, reload) | redis-cli | PRESENT (through the raw path) | `redis-blocking`, needs `--allow-dangerous` | - |
| Repeat a command (`-r N -i S`) | redis-cli `-r`, `-i` | MISSING | | P3 |
| Health check with advice (eviction, fragmentation, maxmemory not set, persistence off) | RedisInsight "Database analysis" | MISSING | `cache info` only gives raw numbers; there is no `warnings[]` summary | P2 (agents need interpretation; cheap to derive from INFO) |

## 16. Cache: pub/sub, scripting, cluster admin

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| PUBLISH | redis-cli | PRESENT (through the raw path) | `cache run --write -- PUBLISH ch msg` | - |
| SUBSCRIBE / PSUBSCRIBE (listen for N messages or N seconds) | redis-cli `SUBSCRIBE` | MISSING | Needs a streaming mode; a limited version (`--count`, `--duration`) fits a CLI, a continuous version = NG-4 | P3 |
| `PUBSUB CHANNELS/NUMSUB` | redis-cli | PRESENT (through the raw path) | read | - |
| EVAL / EVALSHA / FCALL | redis-cli `--eval` | PRESENT (through the raw path) | `redis-script-run` (destructive: cannot be inspected, can block the server), `_RO` forms, `TFCALL` and `RG.PYEXECUTE` too; `FUNCTION`/`TFUNCTION LOAD REPLACE` = `redis-scripts` | - |
| `--eval file.lua` | redis-cli | MISSING | The script must be inline in argv | P3 |
| Cluster admin (`CLUSTER NODES/INFO`, `--cluster check/fix/rebalance/reshard`) | redis-cli `--cluster` | PARTIAL | `CLUSTER INFO/NODES` read through `cache run` to one node; `--cluster fix/reshard` is not available (NG-1) | P3 |
| Sentinel admin (`SENTINEL masters`, failover) | redis-cli | PARTIAL | Through `cache run --write -- SENTINEL ...` to a conn on the sentinel port. Even reading needs `--write`, and `SENTINEL FAILOVER/REMOVE/SET` is only classified write (does not need `--allow-dangerous`) | P3 |

## 17. Cache: backup, bulk, data migration

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| RDB backup to the laptop (`redis-cli --rdb`) | redis-cli `--rdb` | MISSING | vision.md goal 2: every family has "backup, and restore"; `cache` has no `dump`/`restore` | P2 |
| Export/import keys (DUMP/RESTORE, JSON) by pattern | redis-dump, RIOT, RedisInsight bulk | MISSING | `DUMP` read & `RESTORE` write exist through `cache run`, one by one | P3 |
| Mass insert (`--pipe`) | redis-cli `--pipe` | MISSING | | P3 |
| Copy between instances (`MIGRATE`, RIOT, redis-shake) | redis-cli, redis-shake | PARTIAL | `MIGRATE` is blocked as `redis-flush` (destructive) through `cache run` | P3 |

## 18. Security/consistency findings in cache classification

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Commands that delete data are treated the same as `DEL` | none | PARTIAL | `GETDEL`, `HDEL`, `SREM`, `ZREMRANGEBY*`, `LTRIM`, `EXPIRE k 0`, `RESTORE ... REPLACE`, `RENAME` (overwrites the target), `SET` over a key of another type are classified **write**, while `DEL/UNLINK` and `cache rm` need `--allow-dangerous` (`cachex.Classify`). At least `GETDEL`, `RENAME` to an existing key, and `EXPIRE/PEXPIRE` ≤ 0 should equal `data-delete` | P2 |
| `policy check --for redis "CLIENT LIST"` (one quoted argument) | none | PARTIAL | Small bug: without splitting into words it is classified `write`; `-- CLIENT LIST` is classified `read` (`meta.go` passes raw `args` to `cachex.Classify`). For SQL the arguments are joined, so the two paths differ | P3 |
| Module reads and plain reads that are not registered yet (`XREAD`, `JSON.GET`, `FT.SEARCH`, `TS.RANGE`, `HELLO`, `CLIENT NO-TOUCH`) | none | PARTIAL | Classified write, so agents must use `--write` to read; this weakens the meaning of `--write` in the audit | P2 |

## 19. Memcached

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| get/set/delete, stats, stats items/slabs, flush_all | telnet, memcached-tool, memcdump, mcrouter | MISSING | vision.md family table: `cache` "later: memcached". Simple text protocol, small pure Go client (`gomemcache`), fits `cache get/set/rm/info`; no SCAN (`keys` limited through `lru_crawler metadump`) | P2 (still common in WordPress/PHP/legacy; small binary cost) |

---

## 20. Data engines not supported yet

The assessment uses the vision.md criteria "Criteria for adding a family" (fits the conn+kind+verb model, honest read-only default, pure Go, daily need, has a maintainer). Binary size is no longer capped.

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| MongoDB (find, aggregate, count, indexes, stats, currentOp, killOp, mongodump/restore) | mongosh, mongodump, Compass | MISSING | vision.md: candidate after v1.0 ("and mongodb"). The official driver is pure Go but large (+~6-8 MB); read-only is possible through `readPreference` + a read user, there is no equivalent read-only transaction, so classification (`find`/`aggregate` without `$out/$merge`) becomes the main layer. Workaround: `exec host -- mongosh --eval` | P2 (the most popular non-SQL DB) |
| Microsoft SQL Server / Azure SQL | sqlcmd, Azure Data Studio | MISSING | vision.md: `db` "later: mssql". `go-mssqldb` is pure Go; read-only: `SET TRANSACTION ISOLATION ... ` does not block writes, needs `ApplicationIntent=ReadOnly`/a read user + T-SQL classification (dialect `[ ]`, `GO`) | P2 |
| Oracle | sqlplus, SQLcl | MISSING | `go-ora` is pure Go; `SET TRANSACTION READ ONLY` exists. Rare among komando's target users (small/medium devops) | P3 |
| ClickHouse | clickhouse-client | MISSING | vision.md: `db` "later: clickhouse". `clickhouse-go` is pure Go; read-only through the `readonly=1` setting (enforced by the server, fits the contract) | P2 |
| Cassandra / ScyllaDB | cqlsh, nodetool | MISSING | `gocql` is pure Go; no read-only transactions; must rely on CQL classification + a read role | P3 |
| Elasticsearch / OpenSearch (health, indices, search, mapping, snapshot, delete index) | curl, elasticsearch-cli, opensearch-cli, Kibana Dev Tools | MISSING | vision.md: candidate after v1.0 "search (Elasticsearch, OpenSearch)". REST API (no SDK) fits the technical rules; risk per method+path is clear (GET read, DELETE index destructive) | P2 (very common for logs/search; cheap in binary size) |
| InfluxDB / TimescaleDB / Prometheus | influx CLI, promtool | PARTIAL | Timescale = postgres (PRESENT through `db`). Influx: MISSING. Prometheus is named as a "query metrics" candidate in vision.md (another domain) | P3 |
| CockroachDB | cockroach sql | PARTIAL | See section 1 (postgres-wire, not tested yet; `db dump` does not fit, CRDB uses `BACKUP`) | P3 |
| MariaDB-specific (Galera status `wsrep_%`, `mariadb-dump`, `max_statement_time`, sequences, system-versioned tables) | mariadb, mariadb-dump | PARTIAL | The `mariadb://` scheme, MariaDB timeout and MariaDB TLS flags for dump exist. Galera/wsrep through `db query "show status like 'wsrep%'"`. `mariadb-dump` (the new binary name in 11.x; `mysqldump` becomes a symlink and may disappear) is not detected yet | P3 |
| DynamoDB | aws dynamodb, NoSQL Workbench | MISSING | Own SigV4 already exists for S3 (can be reused); read = GetItem/Query/Scan. Daily need among self-hosted devops users is low | P3 |
| Kafka (topics, consumer groups + lag, produce/consume N messages, reset offsets) | kcat, kafka-topics, kafka-consumer-groups, kafkactl | MISSING | vision.md: candidate after v1.0 "message queue (RabbitMQ, Kafka, NATS)". `franz-go` is pure Go. Consumer lag is a daily incident need in teams that use Kafka | P2 |
| RabbitMQ (queues, depth, consumers, purge, publish, shovel) | rabbitmqadmin, rabbitmqctl | MISSING | vision.md candidate. Management HTTP API (no SDK); purge/delete queue = destructive | P2 |
| NATS / JetStream (streams, consumers, pub/sub, KV) | nats CLI | MISSING | vision.md candidate; `nats.go` is pure Go | P3 |
| etcd (get/put/del prefix, member list, endpoint health, snapshot) | etcdctl | MISSING | `go.etcd.io/etcd/client` pulls in gRPC (large). Used in self-managed k8s; an etcd snapshot is a critical backup | P3 |
| Consul KV / catalog / health | consul CLI | MISSING | Simple HTTP API; KV is similar to `cache` | P3 |
| DuckDB / local Parquet files | duckdb CLI | MISSING | Needs cgo (breaks "Pure Go, no cgo") | P3 |
| Cloud data warehouses (BigQuery, Snowflake, Redshift, Databricks) | bq, snowsql | MISSING | Redshift through postgres-wire (not tested yet); BigQuery/Snowflake need large SDKs | P3 |
| Neo4j / graph DBs | cypher-shell | MISSING | | P3 |
| Valkey/KeyDB/Dragonfly | valkey-cli | PRESENT | kind `redis` (docs/features/caches.md) | - |
| Managed DB provisioning (create RDS/Cloud SQL, resize) | aws rds, gcloud sql | NON-GOAL | NG-6 "Infrastructure as Code, cloud provisioning" | - |

---

## Count summary

Counted from all table rows above (sections 1-20):

| Status | Count |
|---|---|
| PRESENT (including "PRESENT (through the raw path)", "PRESENT (through the original tool)", "PRESENT (probably)") | 66 |
| PARTIAL | 71 |
| MISSING | 67 |
| NON-GOAL | 15 |
| **Total capabilities** | **219** |

Prioritized gaps (PARTIAL + MISSING): P1 = 12 rows (10 unique gaps: db and cache login checks merged, audit redaction and CREATE USER merged), P2 = 47, P3 = 79.
Breakdown: PARTIAL = 9 P1 + 19 P2 + 43 P3; MISSING = 3 P1 + 28 P2 + 36 P3.
These counts already use the per-row verification results in the final section (7 rows moved from MISSING to PARTIAL; priorities did not change).

## Top P1 (by impact)

1. **`komando test` for db/cache only checks TCP**, not login/version, even though the help and the design promise login (`conn.go testConn`). Agents cannot verify credentials, DB name and TLS before working.
2. **The password in `CREATE USER/ALTER ROLE ... PASSWORD` is recorded in full in `audit.jsonl`** (default `audit_sql=full`), and there is no way to use `secret:` in SQL. Needs password literal redaction + a `db` user helper.
3. **`db info`/`db status`**: version, uptime, DB size, connections vs max, primary/replica. `cache info` already exists; `db` does not yet (verbs `status/info` in ux.md).
4. **Session activity** (pg_stat_activity / PROCESSLIST) as first-class, with filters for long-running queries and idle-in-transaction.
5. **Locks and blocking chains** (`pg_blocking_pids`, `innodb_lock_waits`).
6. **`db kill PID`** (cancel vs terminate) with a dry-run that shows the query to be stopped; today it only works through `select pg_terminate_backend()` + `--allow-dangerous`.
7. **Biggest DBs/tables/indexes** (full-disk incidents); `db schema` has no size column.
8. **Foreign keys (and relations) in `db schema`**: important so agents write correct JOINs and judge cascade effects.
9. **`pg_dump -Fc` (custom format)** in `db dump`: the standard for production Postgres backups.
10. **`pg_restore`** for custom/directory files in `db restore`.

Extra note outside the priority table: binary size is no longer capped, so new engines (Mongo, MSSQL, ClickHouse, Kafka) are chosen by daily need; HTTP-based families (Elasticsearch/OpenSearch, RabbitMQ, Consul) are still the simplest to build.

## Per-row verification

Every row above was checked again against the code (`internal/cli`, `internal/dbx`, `internal/cachex`, `internal/driver`), `bin/komando ... --help` (offline) and the design documents. The rule used is consistent: a capability that can be run through komando's own `db query`/`cache run` = PARTIAL; a capability that needs another tool on the host (`exec host -- pgbench`, `tunnel` + external client) stays MISSING, as in the other rows of this report. Code line numbers refer to commit 4784fc9.

| # | Capability (short) | Final status | Check result | Evidence in code |
|---|---|---|---|---|
| 1 | Register DB, password in vault | PRESENT | Correct | `conn.go:66` `--password-ref`; `driver/driver.go:159` `URL_HAS_PASSWORD` |
| 2 | PostgreSQL | PRESENT | Correct | `driver.go:63` postgres/postgresql scheme; `dbx/dbx.go:37-53` pgx stdlib |
| 3 | MySQL / MariaDB | PRESENT | Correct | `driver.go:65` mysql/mariadb scheme; `dbx/dbx.go:282-283` `max_statement_time` fallback |
| 4 | Local SQLite | PRESENT | Correct | `dbx/dbx.go:59-67` `mode=ro` + `query_only(1)`; modernc (`dbx.go:23`) |
| 5 | SQLite on remote host | MISSING | Correct | `conn.go:93-94` "--via is not supported" |
| 6 | DB through bastion `--via` | PRESENT | Correct | `dbx/dbx.go:45-48` `DialFunc`; `dbx/mysql.go:43-46` `RegisterDialContext` |
| 7 | DB through VPN | PRESENT | Correct | `conn.go:387-393` `netx.Open` for VPN in `--via` |
| 8 | Postgres TLS | PARTIAL | Correct | `dbshell.go:157-160` only `PGSSLMODE`; `dbdump.go:63` full URL to pg_dump |
| 9 | MySQL TLS own CA | PARTIAL | Correct | `dbx/mysql.go:37-38` `tls=` as is; grep `RegisterTLSConfig`: 0 results |
| 10 | DB Unix socket | MISSING | Correct | `driver.go:181-182` URL requires host |
| 11 | IAM login / cloud token | MISSING | Correct | `conn.go:66` static ref list; grep `rds-iam`/`generate-db-auth`: 0 results |
| 12 | pgpass / my.cnf / pg_service | PRESENT | Correct | `komando import --help`: pgpass, mycnf, env, dbeaver; grep `pg_service`: 0 results |
| 13 | Connection + login check | PARTIAL | Correct | `conn.go:490-502` only TCP dial; `everything.go:157` help "logged in to" |
| 14 | Query many DBs | MISSING | Correct | `select.go:504-510` `singleConn` rejects >1 conn |
| 15 | Pick another DB | PARTIAL | Correct | `driver/sql.go:336` `USE` read; no `--database` flag in `db.go:83-87` |
| 16 | Read replica | MISSING | Correct | grep `replica` in dbx/cli db: 0 results |
| 17 | Other Postgres-wire | PARTIAL | Correct | `dbx/dbx.go:101` `SHOW standard_conforming_strings`; `test/e2e/compose.yml` only postgres/mariadb/redis |
| 18 | Other MySQL-wire | PARTIAL | Correct | `test/e2e/compose.yml:23` only mariadb; no TiDB/Vitess tests |
| 19 | Run SQL | PRESENT | Correct | `db.go:50-81` `db query` |
| 20 | Read-only default | PRESENT | Correct | `dbx/dbx.go:231` `ReadOnly: !o.Write`; sqlite `mode=ro` |
| 21 | Risk classification | PRESENT | Correct | `driver/sql.go:234` `ClassifySQL`; `meta.go:481` `policy check --for` |
| 22 | Dry-run rollback | PRESENT | Correct | `dbx/dbx.go:246-256` rollback + `rolled_back` |
| 23 | SQL from file/stdin | PRESENT | Correct | `db.go:79` `--file`, `-` = stdin |
| 24 | Parameter binding | PRESENT | Correct | `db.go:86` `--arg`; `dbx/dbx.go:194-195` one statement |
| 25 | Named variables | MISSING | Correct | `db.go:83-87` only `--arg`; grep `\set`/`gset`: 0 results |
| 26 | Atomic multi-statement | PRESENT | Correct | `dbx/dbx.go:231-251` one tx; `driver/sql.go:418-421` `SQL_TX_CONTROL` |
| 27 | Interactive transaction | NON-GOAL | Correct | vision.md:189 "One connection per command" + Non-goals vision.md:223 (original tool); resources-and-db.md:72 |
| 28 | Savepoint | NON-GOAL | Correct | `driver/sql.go:339-342` `SAVEPOINT` in `txControl`; based on vision.md:189 + :223 |
| 29 | Non-transactional statement | PRESENT | Correct | `driver/sql.go:298-323` `noTx`; `dbx/dbx.go:200-212` |
| 30 | Query timeout | PRESENT | Correct | `db.go:29` default 30 s; `dbx/dbx.go:267-288` `statement_timeout`/`max_execution_time` |
| 31 | lock_timeout | PARTIAL | Correct | grep `lock_timeout` in Go: 0 results; ux.md:329 |
| 32 | application_name | PRESENT | Correct | `dbx/dbx.go:50-51`; `db.go:245` `komando/<actor>` |
| 33 | Cancel query | PRESENT | Correct | `root.go:64` `signal.NotifyContext`; `dbx/dbx.go:189-192` |
| 34 | EXPLAIN | PRESENT | Correct | `db.go:89-133` `db explain --analyze` |
| 35 | EXPLAIN JSON | PARTIAL | Correct | `db.go:107-126` only a fixed prefix; no `--format` |
| 36 | \gexec | MISSING | Correct | grep `gexec`: 0 results |
| 37 | \watch | MISSING | Correct | `db.go:83-87` no `--repeat/--interval` |
| 38 | \timing | PRESENT | Correct | `out/out.go:74` `duration_ms` in meta |
| 39 | --safe-updates | PRESENT | Correct | `driver/sql.go:525-526` `sql-update-no-where`/`sql-delete-no-where` |
| 40 | Result per statement | PRESENT | Correct | `dbx/dbx.go:145-172` `StatementResult` |
| 41 | JSON-safe types | PRESENT | Correct | `driver/value.go:15-45` `JSONValue` |
| 42 | Text table output | PRESENT | Correct | `db.go:302-311` tabwriter, cut >80 |
| 43 | JSON output | PRESENT | Correct | `root.go:159` `-o auto|json|text` |
| 44 | Vertical mode | MISSING | Correct | `root.go:136` only auto/json/text; grep `vertical`: 0 results |
| 45 | CSV export | MISSING | Correct | `root.go:136`; grep `csv` in Go: 0 results |
| 46 | Large result export | PARTIAL | Correct | `dbx/dbx.go:322-343` all rows in memory; `root.go:168` `--max-output` |
| 47 | Result paging | PARTIAL | Correct | `dbx/dbx.go:323-325` `truncated`; no `--offset` |
| 48 | less pager | PARTIAL | Correct | ux.md:314; no automatic pager |
| 49 | CSV import | MISSING | Correct | `dbx/mysql.go:39-40` other params become session variables (LOAD DATA LOCAL not enabled); grep `CopyFrom`: 0 results |
| 50 | Copy data between DBs | MISSING | Correct | `dbdump.go:63,77` whole-DB dump only |
| 51 | Save output to file | PRESENT | Correct | shell redirect; stable `out` envelope |
| 52 | List tables + row estimate | PRESENT | Correct | `dbx/schema.go:93-101` relkind r,p,v,m,f + `reltuples` |
| 53 | Columns/types/null/default/PK | PRESENT | Correct | `dbx/schema.go:122-130`, `mysql.go:131-133`, `schema.go:182` |
| 54 | Indexes | PRESENT | Correct | `dbx/schema.go:143`, `mysql.go:146-149` |
| 55 | Foreign keys | PARTIAL | Corrected: MISSING→PARTIAL | `dbx/schema.go:14-21` no FK; raw path `db query` to `pg_constraint` (SELECT = read, `driver/sql.go:335`) |
| 56 | Check/exclusion constraints | PARTIAL | Corrected: MISSING→PARTIAL | grep `pg_constraint`/`check_constraints`: 0 results; possible through `db query` (read) |
| 57 | Triggers | PARTIAL | Corrected: MISSING→PARTIAL | grep `trigger` in dbx: 0 results; `SHOW TRIGGERS` read (`driver/sql.go:335`) |
| 58 | List schemas | PARTIAL | Correct | `dbx/schema.go:15` schema per table; no separate `pg_namespace` query |
| 59 | List databases | PARTIAL | Correct | `dbx/mysql.go:103` `DATABASE()` only |
| 60 | Functions/procedures | PARTIAL | Correct | not in `dbx/schema.go`; `db query` read |
| 61 | Sequences/enums/extensions | PARTIAL | Correct | not in `dbx/schema.go`; `db query` read |
| 62 | View definition | PARTIAL | Correct | not in `dbx/schema.go`; `db query` read |
| 63 | Full DDL of one table | PARTIAL | Correct | `dbdump.go:63` pg_dump without `-s -t`; grep `schema-only`: 0 results |
| 64 | Table/index size | PARTIAL | Correct | `dbx/schema.go:14-21` no size column |
| 65 | Table/column comments | PARTIAL | Corrected: MISSING→PARTIAL | grep `col_description`/`column_comment`: 0 results; possible through `db query` (read) |
| 66 | Partitions | PARTIAL | Correct | `dbx/schema.go:96,99` relkind `p` becomes `table` |
| 67 | Per-table privileges | PARTIAL | Correct | not in `dbx`; `SHOW GRANTS` read |
| 68 | Search tables/columns | PARTIAL | Correct | `dbx/schema.go:120-121` columns only for named tables |
| 69 | ER diagram | NON-GOAL | Correct | vision.md:227 "GUI, TUI ..." (Non-goals) |
| 70 | Interactive REPL | PRESENT (through the original tool) | Correct | `dbshell.go:137-196` psql/mysql/sqlite3 read-only |
| 71 | pgcli/mycli REPL | PARTIAL | Correct | `dbshell.go:76` only psql/mysql/sqlite3; `tunnel start --help` conn |
| 72 | SQL autocomplete | NON-GOAL | Correct | resources-and-db.md:72 (REPL); vision.md:227 |
| 73 | Query history | PARTIAL | Correct | `db.go:340-346` SQL in audit; `audit --command` |
| 74 | Saved queries | MISSING | Correct | `recipe run` only "on servers" (`recipe --help`); `ops.go:106-144` shell |
| 75 | $EDITOR | NON-GOAL | Correct | resources-and-db.md:72; vision.md:223 |
| 76 | \! shell escape | NON-GOAL | Correct | `driver/restore.go:83-88`; docs/features/databases.md:109; vision.md:223 |
| 77 | \h help | NON-GOAL | Correct | vision.md:223 (original tool); resources-and-db.md:72 |
| 78 | Dump to file + gzip | PRESENT | Correct | `dbdump.go:222-243`, `writeAtomic` `dbdump.go:334-359` 0600, no overwrite |
| 79 | SQLite dump | PRESENT | Correct | `dbdump.go:185-210` `VACUUM INTO` |
| 80 | pg_dump -Fc/-Fd/-Ft | MISSING | Correct | `dbdump.go:63` without `-F`; grep `"-F`: 0 results |
| 81 | pg_restore | MISSING | Correct | `dbdump.go:64` psql; grep `pg_restore` in Go: 0 results |
| 82 | Parallel dump | MISSING | Correct | `dbdump.go:63,77` without `-j`; grep `mydumper`: 0 results |
| 83 | Schema/data only | MISSING | Correct | `dbdump.go:105` only `--to`; grep `schema-only`: 0 results |
| 84 | Include/exclude tables | MISSING | Correct | `dbdump.go:105` only `--to` |
| 85 | Globals/all DBs | MISSING | Correct | grep `pg_dumpall`/`all-databases`: 0 results |
| 86 | Restore options | MISSING | Correct | `dbdump.go:129` only `--from`; grep `no-owner`: 0 results |
| 87 | Single-transaction restore + file check | PRESENT | Corrected: evidence (added: Postgres only) | `dbdump.go:64` (psql), `dbdump.go:78` mysql without a transaction; `driver/restore.go:26-96` |
| 88 | Restore safeguards | PRESENT | Correct | `dbdump.go:271-274` destructive `db-restore`; `common.go:203-227` |
| 89 | zstd/lz4 compression | PARTIAL | Correct | `dbdump.go:230,301` only `.gz` |
| 90 | Dump straight to S3/server | PARTIAL | Correct | `dbdump.go:24-27` always to this computer |
| 91 | Dump as a job | MISSING | Correct | `job start --help`: shell command on the host, not `db dump` |
| 92 | Pure Go dump | MISSING | Correct | `dbdump.go:390-395` `TOOL_MISSING` |
| 93 | Scheduled backup | NON-GOAL | Correct | vision.md:189, :227 (daemon); `cron set` exists |
| 94 | PITR/WAL | NON-GOAL | Correct | vision.md:223 (full tools) |
| 95 | Backup verification | MISSING | Correct | grep `pg_restore`: 0 results |
| 96 | DB server summary | PARTIAL | Correct | `db.go:40` no info/status; `ops.go:138-139` recipe on the host; ux.md:38 |
| 97 | Session activity | PARTIAL | Correct | `db.go:40` no activity command |
| 98 | Locks/blocking | PARTIAL | Correct | grep `pg_blocking_pids`/`lock_waits`: 0 results |
| 99 | Stop query/session | PARTIAL | Correct | `driver/sql.go:346,491-492` `sql-kill`; no `db kill` |
| 100 | Slow queries | PARTIAL | Correct | no command; `db query` read |
| 101 | Biggest DBs | PARTIAL | Correct | `dbx/schema.go:14-21` no size |
| 102 | Bloat/autovacuum | PARTIAL | Correct | `db query` read; no command |
| 103 | Unused indexes | PARTIAL | Correct | `db query` read; no command |
| 104 | Cache hit ratio | PARTIAL | Correct | `db query` read; no command |
| 105 | Replication/lag | PARTIAL | Correct | `driver/sql.go:335` `SHOW` read |
| 106 | Replication slots | PARTIAL | Correct | `driver/sql.go:349-350` slot -> `sql-server-config` |
| 107 | Server configuration | PARTIAL | Correct | `driver/sql.go:480-481,473-474` SET GLOBAL/ALTER SYSTEM destructive |
| 108 | VACUUM/ANALYZE | PRESENT (through the raw path) | Correct | `driver/sql.go:306-307` noTx; `:493-495` `sql-vacuum-full` |
| 109 | XID wraparound | PARTIAL | Correct | `db query` read; no command |
| 110 | Benchmark | MISSING | Correct | grep `pgbench`/`sysbench`: 0 results |
| 111 | Continuous monitoring | NON-GOAL | Correct | vision.md:228 and :227 (TUI) |
| 112 | DB health check | MISSING | Correct | `db.go:40` no checks |
| 113 | List users/roles | PARTIAL | Correct | `db query` read; no command |
| 114 | Create user / password in audit | PARTIAL | Correct | `driver/sql.go:470-471` `sql-privileges`; `db.go:346` full SQL; `store.go:131` default `full`; `common.go:387-396` no redaction |
| 115 | Read-only user template | MISSING | Correct | docs/features/databases.md:56; no command |
| 116 | Effective grants | PARTIAL | Correct | `SHOW GRANTS` read; no command |
| 117 | RLS / policy | PARTIAL | Correct | `driver/sql.go:469-472` `CREATE POLICY` only write |
| 118 | Migration tool | NON-GOAL | Correct | resources-and-db.md:72 "migrations" |
| 119 | Run migration files | PARTIAL | Correct | `db.go:79` one `--file`; `driver/sql.go:316` MySQL DDL noTx |
| 120 | Migration status | PARTIAL | Correct | `db query` read |
| 121 | Schema diff | MISSING | Correct | grep `diff` in dbx/cli db: 0 results |
| 122 | Generate migrations | NON-GOAL | Correct | resources-and-db.md:72; vision.md:226 |
| 123 | Migration lint | PARTIAL | Correct | `driver/sql.go:462-546` no lock/CONCURRENTLY rules |
| 124 | PgBouncer admin | MISSING | Correct | `dbx/dbx.go:86-89,101` string rules check during Open |
| 125 | Through PgBouncer transaction mode | PARTIAL | Correct | `dbx/dbx.go:53` pgx stdlib default; no tests |
| 126 | ProxySQL/pgpool | MISSING | Correct | grep `proxysql`/`pgpool`: 0 results |
| 127 | Connection pool | NON-GOAL | Correct | vision.md:189 "No pool"; `dbx/dbx.go:81` 1 connection |
| 128 | Query audit | PRESENT | Correct | `db.go:340-350`; `meta.go:417-422` audit_sql |
| 129 | Audit SQL redaction | MISSING | Correct | `db.go:340-347` full/hash/off only; grep `redact` in db: 0 results |
| 130 | Block dangerous functions | PRESENT | Correct | `driver/sql.go:345-370` `sql-remote`, `sql-server-file`, `sql-program` |
| 131 | Reject string rules | PRESENT | Correct | `dbx/dbx.go:96-124` `SQL_STRING_RULES` |
| 132 | Type-the-name confirmation | PRESENT | Corrected: evidence ux.md backlog→code | `common.go:208,334-347` `confirmDangerous` |
| 133 | --max-rows-affected | MISSING | Correct | grep `max-rows-affected`: 0 results |
| 134 | Column masking | MISSING | Correct | grep `mask` in dbx/cli db: 0 results |
| 135 | Per-conn options | MISSING | Corrected: evidence (added misleading help example) | `cluster.go:78` the only user of `Options`; `conn.go:186` `statement_timeout` example |
| 136 | Redis/Valkey standalone | PRESENT | Correct | `driver.go:69-70`; `cachex.go:27-47` go-redis |
| 137 | Garnet/Upstash/ElastiCache | PRESENT (probably) | Correct | same protocol; no tests (`test/e2e/compose.yml:28` redis only) |
| 138 | Redis Cluster | MISSING | Correct | `cachex.go:41` `redis.NewClient`; grep `ClusterClient`: 0 results |
| 139 | Sentinel find master | PARTIAL | Corrected: MISSING→PARTIAL | `cachex.go:123-148` `SENTINEL` classified write, `cache run --write` sends it; grep `sentinel` in Go: 0 results |
| 140 | ACL user + password | PRESENT | Correct | `cachex.go:30` `Username`, `Password` |
| 141 | TLS rediss | PRESENT | Correct | `cachex.go:34-36` TLS1.2 + `ServerName` |
| 142 | TLS own CA | MISSING | Correct | `cachex.go:36` only `ServerName` |
| 143 | Pick redis DB | PARTIAL | Correct | `cachex.go:28` DB from URL; `SELECT` unknown = write |
| 144 | Redis through --via | PRESENT | Correct | `cachex.go:38-40` `o.Dialer` |
| 145 | Redis Unix socket | MISSING | Correct | `driver.go:181-182` host required |
| 146 | Cache login check | PARTIAL | Correct | `conn.go:490-502` TCP; `cachex.go:42` PING in `cache info` |
| 147 | Cache REPL | MISSING | Correct | `cache.go:36` no `shell` |
| 148 | cache get all types | PRESENT | Correct | `cachex.go:162-246` |
| 149 | Module types | PARTIAL | Correct | `cachex.go:242-243` `value: nil`; `JSON.GET` not in `readCmds` (`cachex.go:72-78`) |
| 150 | cache keys SCAN | PRESENT | Correct | `cachex.go:249-271` SCAN |
| 151 | SCAN TYPE | PARTIAL | Corrected: MISSING→PARTIAL | `cachex.go:256` no TYPE; `SCAN` read (`cachex.go:72`) through `cache run` |
| 152 | Count keys per pattern | MISSING | Correct | `cachex.go:261-263` stops at limit |
| 153 | Number of keys per DB | PRESENT | Correct | `cachex.go:77` `DBSIZE`, `INFO` read |
| 154 | Structured INFO | PRESENT | Correct | `cachex.go:274-303` |
| 155 | TTL/OBJECT/MEMORY | PRESENT | Correct | `cachex.go:72,84-85` read |
| 156 | Read streams | PRESENT | Correct | `cachex.go:76,89` XRANGE/XPENDING/XINFO read; `:231-241` |
| 157 | XREAD | PARTIAL | Correct | `XREAD` not in `readCmds` (`cachex.go:72-78`) |
| 158 | Set string + TTL | PRESENT | Correct | `cache.go:182-202` |
| 159 | SET NX/XX | PARTIAL | Correct | `cache.go:224-262` `cache run --write` |
| 160 | Value from file | MISSING | Correct | `cache.go:189` `ExactArgs(3)`, no `--file` |
| 161 | EXPIRE/PERSIST | PARTIAL | Correct | `cache.go:231` `EXPIRE` example via `cache run --write` |
| 162 | Write hash/list/set | PARTIAL | Correct | `cache.go:36` only string `set` |
| 163 | Rename/copy | PARTIAL | Correct | `RENAME` not in `destructive` (`cachex.go:97-103`) = write |
| 164 | Delete exact keys | PRESENT | Correct | `cache.go:204-222` `DataDelete` |
| 165 | Delete by pattern | MISSING | Correct | `cache.go:207` "no patterns" |
| 166 | Flush DB | PRESENT (through the raw path) | Correct | `cachex.go:98` `redis-flush` |
| 167 | Cache write dry-run | PARTIAL | Correct | `cache.go:63-66` "nothing sent" |
| 168 | bigkeys | MISSING | Correct | grep `bigkeys`: 0 results |
| 169 | memkeys | MISSING | Correct | grep `memkeys`: 0 results |
| 170 | hotkeys | MISSING | Correct | grep `hotkeys`: 0 results; `OBJECT FREQ` read (`cachex.go:85`) |
| 171 | Latency | PARTIAL | Correct | `cachex.go:87` LATENCY read; `conn.go:491` test TCP |
| 172 | --stat | NON-GOAL | Correct | vision.md:228 |
| 173 | Slowlog | PRESENT (through the raw path) | Correct | `cachex.go:86` GET read; RESET = write |
| 174 | MONITOR | MISSING | Correct | `MONITOR` not registered = write; `cachex.go:311` one `Do()` |
| 175 | CLIENT LIST | PRESENT (through the raw path) | Correct | `cachex.go:83` read |
| 176 | CLIENT KILL | PRESENT (through the raw path) | Correct | `cachex.go:107` `redis-kill` |
| 177 | CONFIG GET | PRESENT (through the raw path) | Correct | `readSub` CONFIG GET read; passwords hidden for agents (`HideSecrets`) |
| 178 | CONFIG SET | PRESENT (through the raw path) | Correct | `cachex.go:106` `redis-server-config` |
| 179 | Replication INFO | PRESENT | Correct | `cache.go:158-180` `cache info CONN replication` |
| 180 | MEMORY DOCTOR | PRESENT (through the raw path) | Correct | `cachex.go:84` read |
| 181 | BGSAVE/SAVE | PRESENT (through the raw path) | Correct | `cachex.go:99` SAVE `redis-blocking`; BGSAVE not registered = write |
| 182 | DEBUG | PRESENT (through the raw path) | Correct | `cachex.go:99` `redis-blocking` |
| 183 | Repeat command | MISSING | Correct | `cache.go:224-262` no `-r/-i` |
| 184 | Cache health check | MISSING | Correct | `cachex.go:274-303` only raw numbers |
| 185 | PUBLISH | PRESENT (through the raw path) | Correct | not registered = write, `cache run --write` |
| 186 | SUBSCRIBE | MISSING | Correct | `cachex.go:311` `Do()` one reply |
| 187 | PUBSUB CHANNELS | PRESENT (through the raw path) | Correct | `cachex.go:93` read |
| 188 | EVAL/FCALL | PRESENT (through the raw path) | Correct | `destructive` map: `redis-script-run` for EVAL/EVALSHA/FCALL and their `_RO` forms |
| 189 | --eval file | MISSING | Correct | `cache.go:224-262` no `--file` |
| 190 | Cluster admin | PARTIAL | Correct | `cachex.go:88` CLUSTER INFO/NODES read; no `--cluster` |
| 191 | Sentinel admin | PARTIAL | Corrected: MISSING→PARTIAL | `SENTINEL` not in `destructive`/`readCmds` (`cachex.go:72-113`) = write |
| 192 | RDB backup | MISSING | Correct | `cache.go:36` no dump/restore; vision.md:23 |
| 193 | Export/import by pattern | MISSING | Correct | `cachex.go:78` DUMP read; RESTORE = write; no bulk |
| 194 | Mass insert | MISSING | Correct | grep `pipe` in cachex/cache.go: 0 results |
| 195 | MIGRATE | PARTIAL | Correct | `cachex.go:101` `MIGRATE`→`redis-flush` |
| 196 | Data delete = write | PARTIAL | Correct | `cachex.go:139-148` only DEL/UNLINK `DataDelete` |
| 197 | Quoted redis policy check | PARTIAL | Correct | `meta.go:478` `cachex.Classify(args)` vs `:481` `strings.Join` |
| 198 | Unregistered module reads | PARTIAL | Correct | `cachex.go:72-95` no XREAD/JSON.GET/HELLO/NO-TOUCH |
| 199 | Memcached | MISSING | Correct | grep `memcache`: 0 results; vision.md:93 |
| 200 | MongoDB | MISSING | Correct | grep `mongo` in Go: only `ops.go:32` tool detection; vision.md:209 |
| 201 | MSSQL | MISSING | Correct | grep `mssql`: 0 results; vision.md:92 |
| 202 | Oracle | MISSING | Correct | grep `go-ora`/`oracle`: 0 results |
| 203 | ClickHouse | MISSING | Correct | grep `clickhouse`: 0 results; vision.md:92 |
| 204 | Cassandra | MISSING | Correct | grep `cassandra`/`gocql`: 0 results |
| 205 | Elasticsearch | MISSING | Correct | grep `elastic`/`opensearch`: 0 results; vision.md:207-208 |
| 206 | Influx/Timescale/Prometheus | PARTIAL | Correct | grep `influx`: 0 results; Timescale = kind postgres |
| 207 | CockroachDB | PARTIAL | Correct | see row 17; grep `cockroach`: 0 results |
| 208 | MariaDB-specific | PARTIAL | Correct | `dbdump.go:42-48` MariaDB TLS flags; `:77` `mysqldump`; grep `mariadb-dump`: 0 results |
| 209 | DynamoDB | MISSING | Correct | grep `dynamodb`: 0 results |
| 210 | Kafka | MISSING | Correct | grep `kafka`: 0 results; vision.md:207 |
| 211 | RabbitMQ | MISSING | Correct | grep `rabbit`: 0 results; vision.md:207 |
| 212 | NATS | MISSING | Correct | grep `nats`: 0 results |
| 213 | etcd | MISSING | Correct | grep `etcd`: 0 results |
| 214 | Consul | MISSING | Correct | grep `consul`: 0 results |
| 215 | DuckDB | MISSING | Correct | grep `duckdb`: 0 results; vision.md:180 no cgo |
| 216 | Cloud warehouse | MISSING | Correct | grep `bigquery`/`snowflake`: 0 results |
| 217 | Neo4j | MISSING | Correct | grep `neo4j`: 0 results |
| 218 | Valkey/KeyDB/Dragonfly | PRESENT | Correct | `driver.go:69`; docs/features/caches.md:5-6 |
| 219 | DB provisioning | NON-GOAL | Correct | vision.md:226 "cloud provisioning" |
