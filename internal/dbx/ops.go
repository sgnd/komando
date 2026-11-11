package dbx

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/sgnd/komando/internal/out"
)

// Day-to-day DBA views: what the server is, what runs now, who waits on
// whom, what is big, and stopping a query. Everything but Kill only reads.

// rowsOf runs a query and returns its rows as column -> value maps, with
// bytes turned into text.
func rowsOf(ctx context.Context, q querier, query string, args ...any) ([]map[string]any, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	res := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			switch v := vals[i].(type) {
			case []byte:
				s := string(v)
				if n, err := strconv.ParseInt(s, 10, 64); err == nil { // MySQL numbers come as text
					m[c] = n
				} else {
					m[c] = s
				}
			case time.Time:
				m[c] = v.UTC().Format(time.RFC3339)
			default:
				m[c] = v
			}
		}
		res = append(res, m)
	}
	return res, rows.Err()
}

func oneRow(ctx context.Context, q querier, query string, args ...any) (map[string]any, error) {
	rows, err := rowsOf(ctx, q, query, args...)
	if err != nil || len(rows) == 0 {
		return map[string]any{}, err
	}
	return rows[0], nil
}

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

// NotSupported is the stop for a db command that kind has no use for:
// SQLite, a file with no server, has no sessions and no users.
func NotSupported(kind, what string) error {
	hint := "SQLite is a file, not a server: it has no sessions, so there is nothing to show or stop"
	if strings.HasPrefix(what, "db user") || strings.HasPrefix(what, "db grant") {
		hint = "SQLite is a file, not a server: it has no users; who may read or change it is set by the file's permissions"
	}
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED", hint, "%s is not available for %s", what, kind)
}

// Info is the server at a glance: version, uptime, size, connections, and
// whether it is a primary or a read-only replica.
func Info(ctx context.Context, db *sql.DB, kind string, timeout time.Duration) (map[string]any, error) {
	ctx, cancel := withTimeout(ctx, timeout)
	defer cancel()
	var res map[string]any
	var err error
	switch kind {
	case "postgres":
		res, err = oneRow(ctx, db, `
SELECT current_setting('server_version') AS version, current_database() AS database, current_user AS "user",
       pg_postmaster_start_time() AS started,
       extract(epoch FROM now() - pg_postmaster_start_time())::bigint AS uptime_seconds,
       pg_database_size(current_database()) AS size_bytes,
       (SELECT count(*) FROM pg_stat_activity) AS connections,
       current_setting('max_connections')::int AS max_connections,
       CASE WHEN pg_is_in_recovery() THEN 'replica' ELSE 'primary' END AS role`)
		if err == nil && res["role"] == "replica" {
			if lag, lerr := oneRow(ctx, db, `SELECT extract(epoch FROM now() - pg_last_xact_replay_timestamp())::bigint AS replay_lag_seconds`); lerr == nil {
				res["replay_lag_seconds"] = lag["replay_lag_seconds"]
			}
		}
	case "mysql":
		res, err = oneRow(ctx, db, `
SELECT VERSION() AS version, DATABASE() AS `+"`database`"+`, CURRENT_USER() AS user,
       @@max_connections AS max_connections,
       IF(@@read_only = 1 OR @@super_read_only = 1, 'replica', 'primary') AS role,
       (SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = DATABASE()) AS size_bytes`)
		if err != nil {
			// MariaDB has no super_read_only
			res, err = oneRow(ctx, db, `
SELECT VERSION() AS version, DATABASE() AS `+"`database`"+`, CURRENT_USER() AS user,
       @@max_connections AS max_connections, IF(@@read_only = 1, 'replica', 'primary') AS role,
       (SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = DATABASE()) AS size_bytes`)
		}
		if err == nil {
			for _, v := range []struct{ name, key string }{{"Uptime", "uptime_seconds"}, {"Threads_connected", "connections"}} {
				if r, serr := oneRow(ctx, db, "SHOW GLOBAL STATUS LIKE '"+v.name+"'"); serr == nil {
					if n, perr := strconv.ParseInt(fmt.Sprint(r["Value"]), 10, 64); perr == nil {
						res[v.key] = n
					} else if n, ok := r["Value"].(int64); ok {
						res[v.key] = n
					}
				}
			}
		}
	case "sqlserver":
		res, err = mssqlInfo(ctx, db)
	case "oracle":
		res, err = oracleInfo(ctx, db)
	case "clickhouse":
		res, err = clickhouseInfo(ctx, db)
	case "snowflake":
		res, err = snowflakeInfo(ctx, db)
	case "bigquery":
		res, err = bigqueryInfo(ctx, db)
	case "sqlite":
		res, err = oneRow(ctx, db, `
SELECT sqlite_version() AS version, (SELECT page_count FROM pragma_page_count()) * (SELECT page_size FROM pragma_page_size()) AS size_bytes,
       (SELECT journal_mode FROM pragma_journal_mode()) AS journal_mode`)
	}
	if err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	return res, nil
}

// Activity lists sessions: by default only those running something.
func Activity(ctx context.Context, db *sql.DB, kind string, all bool, timeout time.Duration) ([]map[string]any, error) {
	ctx, cancel := withTimeout(ctx, timeout)
	defer cancel()
	var rows []map[string]any
	var err error
	switch kind {
	case "postgres":
		rows, err = rowsOf(ctx, db, `
SELECT pid, usename AS "user", datname AS database, application_name AS app, client_addr::text AS client, state,
       extract(epoch FROM now() - query_start)::bigint AS running_seconds,
       wait_event_type AS waiting_on, left(query, 500) AS query
FROM pg_stat_activity
WHERE pid <> pg_backend_pid() AND backend_type = 'client backend' AND ($1 OR state <> 'idle')
ORDER BY query_start NULLS LAST`, all)
	case "mysql":
		rows, err = rowsOf(ctx, db, `
SELECT id AS pid, user, host AS client, db AS `+"`database`"+`, command, time AS running_seconds, state, LEFT(info, 500) AS query
FROM information_schema.processlist
WHERE id <> CONNECTION_ID() AND (? OR command <> 'Sleep')
ORDER BY time DESC`, all)
	case "sqlserver":
		rows, err = mssqlActivity(ctx, db, all)
	case "oracle":
		rows, err = oracleActivity(ctx, db, all)
	case "clickhouse": // system.processes holds only running queries
		rows, err = clickhouseActivity(ctx, db)
	case "snowflake": // running and queued queries
		rows, err = snowflakeActivity(ctx, db)
	case "bigquery": // jobs that are not done
		rows, err = bigqueryActivity(ctx, db)
	default:
		return nil, NotSupported(kind, "db activity")
	}
	if err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	return rows, nil
}

// Locks lists sessions that wait for a lock, with the session holding it.
func Locks(ctx context.Context, db *sql.DB, kind string, timeout time.Duration) ([]map[string]any, error) {
	ctx, cancel := withTimeout(ctx, timeout)
	defer cancel()
	var rows []map[string]any
	var err error
	switch kind {
	case "postgres":
		rows, err = rowsOf(ctx, db, `
SELECT w.pid AS waiting_pid, w.usename AS waiting_user, extract(epoch FROM now() - w.query_start)::bigint AS waiting_seconds,
       left(w.query, 300) AS waiting_query,
       b.pid AS blocking_pid, b.usename AS blocking_user, b.state AS blocking_state, left(b.query, 300) AS blocking_query
FROM pg_stat_activity w
CROSS JOIN LATERAL unnest(pg_blocking_pids(w.pid)) AS bp(pid)
JOIN pg_stat_activity b ON b.pid = bp.pid
ORDER BY waiting_seconds DESC`)
	case "mysql":
		rows, err = rowsOf(ctx, db, `
SELECT waiting_pid, wait_age_secs AS waiting_seconds, LEFT(waiting_query, 300) AS waiting_query,
       blocking_pid, LEFT(blocking_query, 300) AS blocking_query
FROM sys.innodb_lock_waits ORDER BY wait_age_secs DESC`)
		if err != nil { // MariaDB and servers without the sys schema
			rows, err = rowsOf(ctx, db, `
SELECT r.trx_mysql_thread_id AS waiting_pid, TIMESTAMPDIFF(SECOND, r.trx_wait_started, NOW()) AS waiting_seconds,
       LEFT(r.trx_query, 300) AS waiting_query, b.trx_mysql_thread_id AS blocking_pid, LEFT(b.trx_query, 300) AS blocking_query
FROM information_schema.innodb_lock_waits w
JOIN information_schema.innodb_trx r ON r.trx_id = w.requesting_trx_id
JOIN information_schema.innodb_trx b ON b.trx_id = w.blocking_trx_id`)
		}
		var me *mysql.MySQLError
		if errors.As(err, &me) && (me.Number == 1227 || me.Number == 1142) {
			return nil, out.Errf(out.ExitConnect, "DB_PRIVILEGE", "grant it with `GRANT PROCESS ON *.* TO user` (as an admin), or use a conn with an admin user",
				"lock waits need the PROCESS privilege, which this user lacks")
		}
	case "sqlserver":
		rows, err = mssqlLocks(ctx, db)
	case "oracle":
		rows, err = oracleLocks(ctx, db)
	case "clickhouse":
		return nil, chNoLocks()
	case "snowflake":
		return nil, sfNoLocks()
	case "bigquery":
		return nil, bqNoLocks()
	default:
		return nil, NotSupported(kind, "db locks")
	}
	if err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	return rows, nil
}

// Sizes lists databases, the biggest tables and the biggest indexes.
func Sizes(ctx context.Context, db *sql.DB, kind string, limit int, timeout time.Duration) (map[string]any, error) {
	ctx, cancel := withTimeout(ctx, timeout)
	defer cancel()
	res := map[string]any{}
	var err error
	switch kind {
	case "postgres":
		if res["databases"], err = rowsOf(ctx, db, `
SELECT datname AS name, pg_database_size(datname) AS bytes FROM pg_database WHERE NOT datistemplate ORDER BY 2 DESC`); err != nil {
			break
		}
		if res["tables"], err = rowsOf(ctx, db, `
SELECT schemaname AS schema, relname AS name, pg_total_relation_size(relid) AS total_bytes, pg_relation_size(relid) AS table_bytes,
       pg_indexes_size(relid) AS index_bytes, n_live_tup AS rows
FROM pg_stat_user_tables ORDER BY 3 DESC LIMIT $1`, limit); err != nil {
			break
		}
		res["indexes"], err = rowsOf(ctx, db, `
SELECT schemaname AS schema, relname AS "table", indexrelname AS name, pg_relation_size(indexrelid) AS bytes, idx_scan AS scans
FROM pg_stat_user_indexes ORDER BY 4 DESC LIMIT $1`, limit)
	case "mysql":
		if res["databases"], err = rowsOf(ctx, db, `
SELECT table_schema AS name, SUM(data_length + index_length) AS bytes FROM information_schema.tables
GROUP BY table_schema ORDER BY 2 DESC`); err != nil {
			break
		}
		res["tables"], err = rowsOf(ctx, db, `
SELECT table_schema AS `+"`schema`"+`, table_name AS name, data_length + index_length AS total_bytes, data_length AS table_bytes,
       index_length AS index_bytes, table_rows AS `+"`rows`"+`
FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema = DATABASE() ORDER BY 3 DESC LIMIT ?`, limit)
	case "sqlserver":
		err = mssqlSizes(ctx, db, limit, res)
	case "oracle":
		err = oracleSizes(ctx, db, limit, res)
	case "clickhouse":
		err = clickhouseSizes(ctx, db, limit, res)
	case "snowflake":
		err = snowflakeSizes(ctx, db, limit, res)
	case "bigquery":
		err = bigquerySizes(ctx, db, limit, res)
	case "sqlite":
		res["databases"], err = rowsOf(ctx, db, `
SELECT 'main' AS name, (SELECT page_count FROM pragma_page_count()) * (SELECT page_size FROM pragma_page_size()) AS bytes`)
	}
	if err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	return res, nil
}

// Session reads one session by its id, so a kill can say what it stops.
func Session(ctx context.Context, db *sql.DB, kind string, pid int64) (map[string]any, error) {
	rows, err := Activity(ctx, db, kind, true, 10*time.Second)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if fmt.Sprint(r["pid"]) == strconv.FormatInt(pid, 10) {
			return r, nil
		}
	}
	return nil, out.Errf(out.ExitNotFound, "SESSION_NOT_FOUND", "list sessions with `komando db activity CONN --all`", "no session %d", pid)
}

// Kill cancels the session's running query, or with session ends the
// connection.
func Kill(ctx context.Context, db *sql.DB, kind string, pid int64, session bool) error {
	var err error
	switch kind {
	case "postgres":
		fn := "pg_cancel_backend"
		if session {
			fn = "pg_terminate_backend"
		}
		var ok bool
		if err = db.QueryRowContext(ctx, "SELECT "+fn+"($1)", pid).Scan(&ok); err == nil && !ok {
			return out.Errf(out.ExitRemote, "KILL_FAILED", "you may lack the right to stop another user's session", "the server did not stop session %d", pid)
		}
	case "mysql":
		what := "KILL QUERY "
		if session {
			what = "KILL "
		}
		_, err = db.ExecContext(ctx, what+strconv.FormatInt(pid, 10))
	case "sqlserver":
		if !session {
			return KillNeedsSession()
		}
		_, err = db.ExecContext(ctx, "KILL "+strconv.FormatInt(pid, 10))
	case "oracle":
		err = oracleKill(ctx, db, pid, session)
	case "clickhouse":
		if session {
			return KillNoSession()
		}
		err = clickhouseKill(ctx, db, pid)
	case "snowflake":
		err = snowflakeKill(ctx, db, pid, session)
	case "bigquery":
		err = bigqueryKill(ctx, db, pid, session)
	default:
		return NotSupported(kind, "db kill")
	}
	if err != nil {
		return queryErr(kind, ctx, err)
	}
	return nil
}
