package dbx

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sgnd/komando/internal/out"
)

// ClickHouse's views for db info, activity, sizes and kill: system.parts,
// system.processes, system.metrics. A running query has a query_id (text)
// and no session number, so db activity shows a number made from it
// (chPID), which db kill takes.

// chPID is a query's number for db activity and db kill: 53 bits of the
// hash of its query_id, which JSON holds exactly.
const chPID = "bitAnd(cityHash64(query_id), 9007199254740991)"

func clickhouseInfo(ctx context.Context, db *sql.DB) (map[string]any, error) {
	res, err := oneRow(ctx, db, `
SELECT version() AS version, currentDatabase() AS database, currentUser() AS user, hostName() AS host,
       toString(now() - uptime()) AS started, uptime() AS uptime_seconds`)
	if err != nil {
		return nil, err
	}
	// a user without SELECT on these system tables sees less
	// (system.server_settings came with 23.3)
	for _, q := range []string{
		`SELECT sum(bytes_on_disk) AS size_bytes FROM system.parts WHERE active AND database = currentDatabase()`,
		`SELECT toInt64(sum(value)) AS connections FROM system.metrics WHERE metric IN ('TCPConnection', 'HTTPConnection', 'MySQLConnection', 'PostgreSQLConnection')`,
		`SELECT count() AS running_queries FROM system.processes`,
		`SELECT toInt64(value) AS max_connections FROM system.server_settings WHERE name = 'max_connections'`,
	} {
		if r, err := oneRow(ctx, db, q); err == nil {
			for k, v := range r {
				res[k] = v
			}
		}
	}
	return res, nil
}

func clickhouseActivity(ctx context.Context, db *sql.DB) ([]map[string]any, error) {
	return rowsOf(ctx, db, `
SELECT `+chPID+` AS pid, query_id, user, toString(address) AS client, current_database AS database,
       if(http_user_agent != '', http_user_agent, client_name) AS app, query_kind AS state,
       toUInt64(elapsed) AS running_seconds, read_rows, memory_usage AS memory_bytes, substring(query, 1, 500) AS query
FROM system.processes
WHERE query_id != queryID()
ORDER BY elapsed DESC`)
}

func clickhouseSizes(ctx context.Context, db *sql.DB, limit int, res map[string]any) error {
	var err error
	if res["databases"], err = rowsOf(ctx, db, `
SELECT database AS name, sum(bytes_on_disk) AS bytes FROM system.parts WHERE active GROUP BY database ORDER BY bytes DESC`); err != nil {
		return err
	}
	res["tables"], err = rowsOf(ctx, db, fmt.Sprintf(`
SELECT database AS schema, table AS name, sum(bytes_on_disk) AS total_bytes, sum(data_compressed_bytes) AS compressed_bytes,
       sum(data_uncompressed_bytes) AS uncompressed_bytes, sum(primary_key_bytes_in_memory) AS index_bytes,
       sum(rows) AS rows, count() AS parts
FROM system.parts WHERE active
GROUP BY database, table ORDER BY total_bytes DESC LIMIT %d`, max(limit, 1)))
	return err
}

// clickhouseKill stops a running query. ClickHouse has no sessions to end
// (an HTTP request is one query), so --session is refused before this.
func clickhouseKill(ctx context.Context, db *sql.DB, pid int64) error {
	_, err := db.ExecContext(ctx, fmt.Sprintf("KILL QUERY WHERE %s = %d ASYNC", chPID, pid))
	return err
}

// KillNoSession is db kill --session on ClickHouse.
func KillNoSession() error {
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
		"ClickHouse stops queries (KILL QUERY), not connections: drop --session",
		"db kill --session is not available for clickhouse")
}

// chNoLocks is db locks on ClickHouse, which has no row locks to wait for.
func chNoLocks() error {
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
		"ClickHouse has no locks that queries wait for: `komando db activity CONN` shows what runs, and `komando db query CONN 'SELECT * FROM system.mutations WHERE NOT is_done'` the changes still waiting",
		"db locks is not available for clickhouse")
}
