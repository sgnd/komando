package dbx

import (
	"context"
	"database/sql"

	"github.com/sgnd/komando/internal/out"
)

// KillNeedsSession is db kill without --session on SQL Server, which can
// only end another session as a whole (KILL), not just its query.
func KillNeedsSession() error {
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
		"SQL Server cannot stop only the query of another session: KILL ends the whole session and rolls back its transaction; add --session for that",
		"db kill without --session is not available for sqlserver")
}

// SQL Server's views for db info, activity, locks and sizes. The
// sessions and plans live in DMVs that need VIEW SERVER STATE; without
// it a user sees only its own session, and the extras are left out.

func mssqlInfo(ctx context.Context, db *sql.DB) (map[string]any, error) {
	res, err := oneRow(ctx, db, `
SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS version,
       CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS edition,
       DB_NAME() AS [database], SUSER_SNAME() AS [user],
       (SELECT SUM(CAST(size AS bigint)) * 8192 FROM sys.database_files) AS size_bytes,
       @@MAX_CONNECTIONS AS max_connections,
       CASE WHEN DATABASEPROPERTYEX(DB_NAME(), 'Updateability') = 'READ_ONLY' THEN 'replica' ELSE 'primary' END AS role`)
	if err != nil {
		return nil, err
	}
	if r, err := oneRow(ctx, db, `
SELECT sqlserver_start_time AS started, DATEDIFF(SECOND, sqlserver_start_time, SYSDATETIME()) AS uptime_seconds,
       (SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1) AS connections
FROM sys.dm_os_sys_info`); err == nil {
		for k, v := range r {
			res[k] = v
		}
	}
	return res, nil
}

func mssqlActivity(ctx context.Context, db *sql.DB, all bool) ([]map[string]any, error) {
	return rowsOf(ctx, db, `
SELECT s.session_id AS pid, s.login_name AS [user], DB_NAME(s.database_id) AS [database], s.program_name AS app,
       c.client_net_address AS client, COALESCE(r.status, s.status) AS state,
       DATEDIFF(SECOND, r.start_time, SYSDATETIME()) AS running_seconds,
       r.wait_type AS waiting_on, LEFT(t.text, 500) AS query
FROM sys.dm_exec_sessions s
LEFT JOIN sys.dm_exec_requests r ON r.session_id = s.session_id
LEFT JOIN sys.dm_exec_connections c ON c.session_id = s.session_id AND c.parent_connection_id IS NULL
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
WHERE s.is_user_process = 1 AND s.session_id <> @@SPID AND (@p1 = 1 OR r.session_id IS NOT NULL)
ORDER BY r.start_time`, all)
}

func mssqlLocks(ctx context.Context, db *sql.DB) ([]map[string]any, error) {
	return rowsOf(ctx, db, `
SELECT w.session_id AS waiting_pid, ws.login_name AS waiting_user, w.wait_time / 1000 AS waiting_seconds,
       LEFT(wt.text, 300) AS waiting_query,
       w.blocking_session_id AS blocking_pid, bs.login_name AS blocking_user, bs.status AS blocking_state,
       LEFT(bt.text, 300) AS blocking_query
FROM sys.dm_exec_requests w
JOIN sys.dm_exec_sessions ws ON ws.session_id = w.session_id
LEFT JOIN sys.dm_exec_sessions bs ON bs.session_id = w.blocking_session_id
LEFT JOIN sys.dm_exec_connections bc ON bc.session_id = w.blocking_session_id AND bc.parent_connection_id IS NULL
OUTER APPLY sys.dm_exec_sql_text(w.sql_handle) wt
OUTER APPLY sys.dm_exec_sql_text(bc.most_recent_sql_handle) bt
WHERE w.blocking_session_id <> 0
ORDER BY w.wait_time DESC`)
}

func mssqlSizes(ctx context.Context, db *sql.DB, limit int, res map[string]any) error {
	var err error
	// sys.master_files lists every database, but needs VIEW ANY DEFINITION
	// and is missing on Azure SQL Database: fall back to this one
	if res["databases"], err = rowsOf(ctx, db, `
SELECT DB_NAME(database_id) AS name, SUM(CAST(size AS bigint)) * 8192 AS bytes
FROM sys.master_files GROUP BY database_id ORDER BY 2 DESC`); err != nil {
		if res["databases"], err = rowsOf(ctx, db, `
SELECT DB_NAME() AS name, SUM(CAST(size AS bigint)) * 8192 AS bytes FROM sys.database_files`); err != nil {
			return err
		}
	}
	if res["tables"], err = rowsOf(ctx, db, `
SELECT TOP (@p1) s.name AS [schema], t.name AS name,
       SUM(a.total_pages) * 8192 AS total_bytes,
       SUM(CASE WHEN i.index_id IN (0, 1) THEN a.total_pages ELSE 0 END) * 8192 AS table_bytes,
       SUM(CASE WHEN i.index_id > 1 THEN a.total_pages ELSE 0 END) * 8192 AS index_bytes,
       (SELECT SUM(p2.rows) FROM sys.partitions p2 WHERE p2.object_id = t.object_id AND p2.index_id IN (0, 1)) AS [rows]
FROM sys.tables t
JOIN sys.schemas s ON s.schema_id = t.schema_id
JOIN sys.indexes i ON i.object_id = t.object_id
JOIN sys.partitions p ON p.object_id = i.object_id AND p.index_id = i.index_id
JOIN sys.allocation_units a ON a.container_id = p.partition_id
WHERE t.is_ms_shipped = 0
GROUP BY s.name, t.name, t.object_id ORDER BY 3 DESC`, limit); err != nil {
		return err
	}
	res["indexes"], err = rowsOf(ctx, db, `
SELECT TOP (@p1) s.name AS [schema], t.name AS [table], i.name AS name, SUM(a.total_pages) * 8192 AS bytes
FROM sys.indexes i
JOIN sys.tables t ON t.object_id = i.object_id
JOIN sys.schemas s ON s.schema_id = t.schema_id
JOIN sys.partitions p ON p.object_id = i.object_id AND p.index_id = i.index_id
JOIN sys.allocation_units a ON a.container_id = p.partition_id
WHERE i.index_id > 1 AND t.is_ms_shipped = 0
GROUP BY s.name, t.name, i.name ORDER BY 4 DESC`, limit)
	return err
}
