package dbx

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// Oracle's views for db info, activity, locks, sizes and kill. Sessions,
// instances and data files live in V$ and DBA_ views, which need
// SELECT_CATALOG_ROLE (or SELECT ANY DICTIONARY); without it info shows
// less, sizes only the user's own schema, and activity says what to grant.

func oracleInfo(ctx context.Context, db *sql.DB) (map[string]any, error) {
	res, err := oneRow(ctx, db, `
SELECT (SELECT MAX(version_full) FROM product_component_version) AS version,
       (SELECT MAX(product) FROM product_component_version) AS edition,
       SYS_CONTEXT('USERENV', 'CON_NAME') AS "database", SYS_CONTEXT('USERENV', 'SERVICE_NAME') AS service,
       SYS_CONTEXT('USERENV', 'SESSION_USER') AS "user",
       CASE WHEN SYS_CONTEXT('USERENV', 'DATABASE_ROLE') = 'PRIMARY' THEN 'primary' ELSE 'replica' END AS role
FROM dual`)
	if err != nil {
		return nil, err
	}
	// with SELECT_CATALOG_ROLE: uptime, sessions, size
	for _, q := range []string{
		`SELECT startup_time AS started, ROUND((SYSDATE - startup_time) * 86400) AS uptime_seconds, host_name AS host FROM v$instance`,
		`SELECT (SELECT COUNT(*) FROM v$session WHERE type = 'USER') AS connections,
       (SELECT TO_NUMBER(value) FROM v$parameter WHERE name = 'sessions') AS max_connections FROM dual`,
		`SELECT SUM(bytes) AS size_bytes FROM dba_data_files`,
	} {
		if r, err := oneRow(ctx, db, q); err == nil {
			for k, v := range r {
				res[strings.ToLower(k)] = v
			}
		}
	}
	return lowerKeys(res), nil
}

// lowerKeys: Oracle names unquoted columns in upper case.
func lowerKeys(m map[string]any) map[string]any {
	res := make(map[string]any, len(m))
	for k, v := range m {
		res[strings.ToLower(k)] = v
	}
	return res
}

func lowerRows(rows []map[string]any, err error) ([]map[string]any, error) {
	for i := range rows {
		rows[i] = lowerKeys(rows[i])
	}
	return rows, err
}

// catalogErr says what to grant when a V$ or DBA_ view is out of reach.
func catalogErr(err error, what string) error {
	if n := oraNumber(err); n == 942 || n == 1031 {
		return out.Errf(out.ExitRemote, "DB_PRIVILEGE", "grant the conn's user SELECT_CATALOG_ROLE (as an admin: `komando db grant CONN USER --role SELECT_CATALOG_ROLE`), or use a conn with an admin user",
			"%s needs the V$ views, which this user cannot read", what)
	}
	return err
}

func oracleActivity(ctx context.Context, db *sql.DB, all bool) ([]map[string]any, error) {
	rows, err := lowerRows(rowsOf(ctx, db, `
SELECT s.sid AS pid, s.serial# AS serial, s.username AS "user", s.machine AS client, s.program AS app,
       LOWER(s.status) AS state, s.last_call_et AS running_seconds,
       CASE WHEN s.wait_class <> 'Idle' THEN s.event END AS waiting_on, SUBSTR(q.sql_text, 1, 500) AS query
FROM v$session s LEFT JOIN v$sql q ON q.sql_id = s.sql_id AND q.child_number = s.sql_child_number
WHERE s.type = 'USER' AND s.sid <> SYS_CONTEXT('USERENV', 'SID') AND (:1 = 1 OR s.status = 'ACTIVE')
ORDER BY s.last_call_et DESC`, map[bool]int{false: 0, true: 1}[all]))
	return rows, catalogErr(err, "db activity")
}

func oracleLocks(ctx context.Context, db *sql.DB) ([]map[string]any, error) {
	rows, err := lowerRows(rowsOf(ctx, db, `
SELECT w.sid AS waiting_pid, w.username AS waiting_user, w.seconds_in_wait AS waiting_seconds,
       SUBSTR(wq.sql_text, 1, 300) AS waiting_query,
       b.sid AS blocking_pid, b.username AS blocking_user, LOWER(b.status) AS blocking_state,
       SUBSTR(bq.sql_text, 1, 300) AS blocking_query
FROM v$session w
JOIN v$session b ON b.sid = w.blocking_session
LEFT JOIN v$sql wq ON wq.sql_id = w.sql_id AND wq.child_number = w.sql_child_number
LEFT JOIN v$sql bq ON bq.sql_id = NVL(b.sql_id, b.prev_sql_id) AND bq.child_number = NVL(b.sql_child_number, b.prev_child_number)
WHERE w.blocking_session IS NOT NULL
ORDER BY w.seconds_in_wait DESC`))
	return rows, catalogErr(err, "db locks")
}

func oracleSizes(ctx context.Context, db *sql.DB, limit int, res map[string]any) error {
	var err error
	// the DBA_ views show every schema; a user without them sees its own
	if res["databases"], err = lowerRows(rowsOf(ctx, db, `
SELECT tablespace_name AS name, SUM(bytes) AS bytes FROM dba_data_files GROUP BY tablespace_name ORDER BY 2 DESC`)); err != nil {
		if res["databases"], err = lowerRows(rowsOf(ctx, db, `
SELECT tablespace_name AS name, SUM(bytes) AS bytes FROM user_segments GROUP BY tablespace_name ORDER BY 2 DESC`)); err != nil {
			return err
		}
	}
	segments := `(SELECT s.owner, s.segment_name, s.segment_type, s.bytes FROM dba_segments s
  JOIN dba_users u ON u.username = s.owner AND u.oracle_maintained = 'N')`
	var one int
	if err := db.QueryRowContext(ctx, "SELECT 1 FROM dba_segments WHERE ROWNUM = 1").Scan(&one); err != nil && err != sql.ErrNoRows {
		segments = `(SELECT USER AS owner, segment_name, segment_type, bytes FROM user_segments)`
	}
	if res["tables"], err = lowerRows(rowsOf(ctx, db, oracleTableSizes(segments), limit)); err != nil {
		return err
	}
	res["indexes"], err = lowerRows(rowsOf(ctx, db, fmt.Sprintf(`
SELECT i.table_owner AS "schema", i.table_name AS "table", i.index_name AS name, SUM(s.bytes) AS bytes
FROM %s s JOIN all_indexes i ON i.owner = s.owner AND i.index_name = s.segment_name
WHERE s.segment_type LIKE 'INDEX%%'
GROUP BY i.table_owner, i.table_name, i.index_name ORDER BY 4 DESC FETCH FIRST :1 ROWS ONLY`, segments), limit))
	return err
}

// oracleTableSizes sums each table's segments: the table, its indexes,
// and its LOB data, which lives in segments of its own (SYS_LOB...) that
// all_lobs ties back to the table. Like PostgreSQL's TOAST, LOB data
// counts in total_bytes only.
func oracleTableSizes(segments string) string {
	return fmt.Sprintf(`
SELECT owner AS "schema", name, SUM(bytes) AS total_bytes,
       SUM(CASE WHEN kind = 'table' THEN bytes ELSE 0 END) AS table_bytes,
       SUM(CASE WHEN kind = 'index' THEN bytes ELSE 0 END) AS index_bytes,
       MAX(num_rows) AS "rows"
FROM (SELECT s.owner, s.segment_name AS name, 'table' AS kind, s.bytes, t.num_rows
      FROM %[1]s s LEFT JOIN all_tables t ON t.owner = s.owner AND t.table_name = s.segment_name
      WHERE s.segment_type LIKE 'TABLE%%'
      UNION ALL
      SELECT i.table_owner, i.table_name, 'index', s.bytes, NULL
      FROM %[1]s s JOIN all_indexes i ON i.owner = s.owner AND i.index_name = s.segment_name
      WHERE s.segment_type LIKE 'INDEX%%'
      UNION ALL
      SELECT l.owner, l.table_name, 'lob', s.bytes, NULL
      FROM %[1]s s JOIN all_lobs l ON l.owner = s.owner AND s.segment_name IN (l.segment_name, l.index_name)
      WHERE s.segment_type LIKE 'LOB%%')
GROUP BY owner, name ORDER BY 3 DESC FETCH FIRST :1 ROWS ONLY`, segments)
}

// oracleKill stops session sid: its running call (ALTER SYSTEM CANCEL SQL),
// or with session the whole session (KILL SESSION ... IMMEDIATE). Oracle
// names a session by SID and serial#; komando reads the serial# now.
func oracleKill(ctx context.Context, db *sql.DB, sid int64, session bool) error {
	var serial int64
	if err := db.QueryRowContext(ctx, "SELECT serial# FROM v$session WHERE sid = :1", sid).Scan(&serial); err != nil {
		if err == sql.ErrNoRows {
			return out.Errf(out.ExitNotFound, "SESSION_NOT_FOUND", "list sessions with `komando db activity CONN --all`", "no session %d", sid)
		}
		return catalogErr(err, "db kill")
	}
	stmt := fmt.Sprintf("ALTER SYSTEM CANCEL SQL '%d,%d'", sid, serial)
	if session {
		stmt = fmt.Sprintf("ALTER SYSTEM KILL SESSION '%d,%d' IMMEDIATE", sid, serial)
	}
	_, err := db.ExecContext(ctx, stmt)
	return err
}
