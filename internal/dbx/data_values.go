package dbx

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// colValue turns one scanned value into its JSON form using the column's
// database type (upper case): a DATE stays a date, a timestamp without a
// time zone gets none, binary columns are always {"base64": ...}.
func colValue(kind, dbType string, v any) any {
	switch kind {
	case "oracle":
		return oracleValue(v, dbType)
	case "clickhouse":
		return chColValue(v)
	case "snowflake", "bigquery":
		return sfColValue(v)
	}
	switch x := v.(type) {
	case time.Time:
		return timeText(kind, dbType, x)
	case []byte:
		if kind == "sqlserver" {
			return mssqlValue(x, dbType)
		}
		if kind == "mysql" {
			v = mysqlValue(x, dbType)
			if b, ok := v.([]byte); ok && len(b) == 0 && mysqlBinary[strings.TrimPrefix(dbType, "UNSIGNED ")] {
				return map[string]string{"base64": ""}
			}
			break
		}
		if kind == "postgres" && dbType == "BYTEA" || len(x) == 0 && kind == "sqlite" {
			// sqlite hands text over as string, so []byte is always a BLOB
			return map[string]string{"base64": base64.StdEncoding.EncodeToString(x)}
		}
	}
	return driver.JSONValue(v)
}

var mysqlBinary = map[string]bool{"BLOB": true, "TINYBLOB": true, "MEDIUMBLOB": true, "LONGBLOB": true, "BINARY": true, "VARBINARY": true, "BIT": true, "GEOMETRY": true}

// colType is a column's type as db query shows it: lower case, except
// ClickHouse's, whose names are case-sensitive (DateTime64, LowCardinality).
func colType(kind, name string) string {
	if kind == "clickhouse" {
		return name
	}
	return strings.ToLower(name)
}

// timeText formats a date or time the way the column stores it.
func timeText(kind, dbType string, t time.Time) string {
	const naive = "2006-01-02 15:04:05.999999999"
	switch dbType {
	case "DATE":
		if kind == "sqlite" && t.Sub(t.Truncate(24*time.Hour)) != 0 {
			return t.Format(naive) // sqlite stores whatever text it was given
		}
		return t.Format("2006-01-02")
	case "TIME":
		if kind == "sqlserver" { // a time of day; the driver puts it on 0001-01-01
			return t.Format("15:04:05.9999999")
		}
	case "TIMESTAMP", "DATETIME", "DATETIME2", "SMALLDATETIME":
		if _, off := t.Zone(); kind == "sqlite" && off != 0 {
			return t.Format(naive + "-07:00")
		}
		return t.Format(naive)
	}
	return t.UTC().Format(time.RFC3339Nano) // with a time zone: an instant
}

// sameTypeColumns makes every column hold one JSON type: when one integer
// of a column is too big for a JSON number (and became a string), all
// integers of that column become strings.
func sameTypeColumns(rows [][]any, raw [][]any) {
	if len(rows) == 0 {
		return
	}
	for c := range rows[0] {
		big := false
		for r := range rows {
			if _, isStr := rows[r][c].(string); isStr && isInt(raw[r][c]) {
				big = true
				break
			}
		}
		if !big {
			continue
		}
		for r := range rows {
			if isInt(raw[r][c]) {
				rows[r][c] = fmt.Sprint(raw[r][c])
			}
		}
	}
}

func isInt(v any) bool {
	switch v.(type) {
	case int64, uint64, int, int32, uint32:
		return true
	}
	return false
}

// pgTypes names PostgreSQL types the driver does not know (it reports
// their OID instead).
var pgTypes = map[string]string{
	"790": "money", "142": "xml", "3614": "tsvector", "3615": "tsquery", "774": "macaddr8",
	"4072": "jsonpath", "3220": "pg_lsn", "1033": "aclitem", "2970": "txid_snapshot", "5038": "pg_snapshot",
	"791": "money[]", "143": "xml[]",
}

// nameTypes replaces OIDs in column types with type names.
func nameTypes(ctx context.Context, q querier, kind string, cols []Column) {
	if kind != "postgres" {
		return
	}
	for i, c := range cols {
		if _, err := strconv.ParseUint(c.Type, 10, 32); err != nil {
			continue
		}
		if n, ok := pgTypes[c.Type]; ok {
			cols[i].Type = n
			continue
		}
		var name string
		if rows, err := q.QueryContext(ctx, "SELECT format_type($1::oid, NULL)", c.Type); err == nil {
			if rows.Next() && rows.Scan(&name) == nil && name != "" {
				cols[i].Type = name
			}
			rows.Close()
		}
	}
}

// timeoutErr says how long the query was allowed to run and how to allow more.
func timeoutErr(err error, d time.Duration) error {
	e, ok := err.(*out.Error)
	if !ok || e.Code != "TIMEOUT" || d <= 0 {
		return err
	}
	return out.Errf(out.ExitTimeout, "TIMEOUT", "narrow the query (WHERE, LIMIT), or allow more time with --timeout "+shortDuration(2*d),
		"query timed out after %s", shortDuration(d))
}

// shortDuration prints 30s, 2m, 1m30s, 1h (no zero units).
func shortDuration(d time.Duration) string {
	s := d.Round(time.Millisecond).String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// checkArgs compares the number of --arg values with the placeholders.
func checkArgs(kind, sql string, n int) error {
	want, ok := driver.Placeholders(kind, sql)
	if !ok || want == n {
		return nil
	}
	mark := map[string]string{"postgres": "$1, $2, ...", "sqlserver": "@p1, @p2, ...", "oracle": ":1, :2, ...", "clickhouse": "{p1:String}, {p2:UInt64}, ..."}[kind]
	if mark == "" {
		mark = "?"
	}
	return out.Errf(out.ExitUsage, "USAGE", fmt.Sprintf("give one --arg per placeholder (%s), in order", mark),
		"the SQL has %d placeholder%s, but --arg was given %d time%s", want, plural(want), n, plural(n))
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// IsMariaDB reports whether a mysql conn is MariaDB, whose syntax differs
// in places (ANALYZE instead of EXPLAIN ANALYZE).
func IsMariaDB(ctx context.Context, q querier) bool {
	rows, err := q.QueryContext(ctx, "SELECT VERSION()")
	if err != nil {
		return false
	}
	defer rows.Close()
	var v string
	return rows.Next() && rows.Scan(&v) == nil && strings.Contains(v, "MariaDB")
}
