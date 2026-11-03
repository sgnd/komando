package dbx

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// viaNet is the network name the MySQL driver uses for connections that go
// through an SSH host. One komando process talks to one conn, so a single
// registration is enough.
const viaNet = "komando-via"

func openMySQL(rawURL string, t driver.Target, password string, dial DialFunc) (*sql.DB, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, out.Usage("invalid mysql URL: %v", err)
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Addr, cfg.DBName = t.User, password, t.Address, t.Database
	cfg.Net = "tcp"
	// dates come back as the server's text, so 0000-00-00 and DATE vs
	// DATETIME stay what they are
	cfg.ParseTime, cfg.Loc = false, time.UTC
	cfg.Params = map[string]string{}
	for k, vs := range u.Query() {
		switch k {
		case "tls":
			cfg.TLSConfig = vs[0] // true | false | skip-verify | preferred
		default:
			cfg.Params[k] = vs[0] // session variables
		}
	}
	if dial != nil {
		mysql.RegisterDialContext(viaNet, func(ctx context.Context, addr string) (net.Conn, error) { return dial(ctx, "tcp", addr) })
		cfg.Net = viaNet
	}
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, out.Usage("invalid mysql settings: %v", err)
	}
	return sql.OpenDB(conn), nil
}

func isUnknownVariable(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && me.Number == 1193
}

func isMySQLNoDatabase(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && me.Number == 1049
}

func isMySQLAuth(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && (me.Number == 1045 || me.Number == 1044 || me.Number == 1698)
}

func mysqlErr(err error) error {
	var me *mysql.MySQLError
	if !errors.As(err, &me) {
		return out.Errf(out.ExitRemote, "DB_ERROR", "fix the SQL; `komando db schema CONN TABLE` shows columns and types", "%v", err)
	}
	switch me.Number {
	case 1792: // ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
		return writeRequired("statement")
	case 3024, 1969: // query timeout: MySQL max_execution_time, MariaDB max_statement_time
		return out.Errf(out.ExitTimeout, "TIMEOUT", "narrow the query (WHERE, LIMIT) or raise --timeout", "%s", me.Message)
	case 1210: // wrong number of placeholder values
		return out.Errf(out.ExitUsage, "USAGE", "give one --arg per placeholder (?), in order", "%s", me.Message)
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "fix the SQL; `komando db schema CONN TABLE` shows columns and types", "%s (error %d)", me.Message, me.Number)
}

// mysqlValue turns the text protocol's raw bytes into typed values.
func mysqlValue(v any, dbType string) any {
	b, ok := v.([]byte)
	if !ok {
		return v
	}
	switch strings.TrimPrefix(dbType, "UNSIGNED ") {
	case "TINYINT", "SMALLINT", "MEDIUMINT", "INT", "BIGINT", "YEAR":
		if n, err := strconv.ParseInt(string(b), 10, 64); err == nil {
			return n
		}
		if n, err := strconv.ParseUint(string(b), 10, 64); err == nil {
			return n
		}
	case "FLOAT", "DOUBLE":
		if f, err := strconv.ParseFloat(string(b), 64); err == nil {
			return f
		}
	}
	return v
}

func mysqlSchema(ctx context.Context, tx *sql.Tx, names []string) ([]Table, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT table_schema, table_name, CASE table_type WHEN 'VIEW' THEN 'view' ELSE 'table' END, table_rows
FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name`)
	if err != nil {
		return nil, err
	}
	var tables []Table
	for rows.Next() {
		var t Table
		var est sql.NullInt64
		if err := rows.Scan(&t.Schema, &t.Name, &t.Type, &est); err != nil {
			rows.Close()
			return nil, err
		}
		if est.Valid {
			t.RowEstimate = &est.Int64
		}
		if wanted(t, names) {
			tables = append(tables, t)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(names) == 0 {
		for i := range tables {
			tables[i].Schema = ""
		}
		return tables, err
	}
	for i := range tables {
		t := &tables[i]
		cols, err := tx.QueryContext(ctx, `
SELECT column_name, column_type, is_nullable = 'YES', column_default, column_key = 'PRI', extra
FROM information_schema.columns WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position`, t.Schema, t.Name)
		if err != nil {
			return nil, err
		}
		for cols.Next() {
			var c TableColumn
			var extra string
			if err := cols.Scan(&c.Name, &c.Type, &c.Nullable, &c.Default, &c.PrimaryKey, &extra); err != nil {
				cols.Close()
				return nil, err
			}
			if c.Default != nil && *c.Default == "NULL" {
				c.Default = nil // MariaDB spells "no default" as the text NULL
			}
			if strings.Contains(strings.ToLower(extra), "auto_increment") {
				c.Identity = "auto_increment"
			}
			t.Columns = append(t.Columns, c)
		}
		cols.Close()
		idx, err := tx.QueryContext(ctx, `
SELECT index_name, MIN(non_unique), GROUP_CONCAT(column_name ORDER BY seq_in_index SEPARATOR ', ')
FROM information_schema.statistics WHERE table_schema = ? AND table_name = ?
GROUP BY index_name ORDER BY index_name`, t.Schema, t.Name)
		if err != nil {
			return nil, err
		}
		for idx.Next() {
			var ix Index
			var nonUnique int
			var cols string
			if err := idx.Scan(&ix.Name, &nonUnique, &cols); err != nil {
				idx.Close()
				return nil, err
			}
			kind := "INDEX"
			if nonUnique == 0 {
				kind = "UNIQUE INDEX"
			}
			ix.Definition = fmt.Sprintf("%s %s (%s)", kind, ix.Name, cols)
			t.Indexes = append(t.Indexes, ix)
		}
		idx.Close()
	}
	for i := range tables {
		tables[i].Schema = "" // in MySQL the schema is the conn's database itself
	}
	return tables, nil
}
