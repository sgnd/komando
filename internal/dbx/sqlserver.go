package dbx

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// SQL Server (go-mssqldb, pure Go). It has no read-only transaction:
// without --write komando's transaction is always rolled back, and after
// each statement komando checks that it is still open (markTx, stillInTx),
// so nothing the SQL does in the database survives. The classifier
// (driver/sql_tsql.go) refuses what a rollback cannot undo.

// viaDialer sends go-mssqldb's connections through komando's dial (an SSH
// --via path or a VPN). HostName makes the driver hand over the name, so
// the --via server's DNS resolves it, not this computer's.
type viaDialer struct {
	dial DialFunc
	host string
}

func (d viaDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr)
}

func (d viaDialer) HostName() string { return d.host }

// sqlserverConfig is the driver's settings for t: the URL's options in
// go-mssqldb's own words, the password, and the conn's ?ca=.
func sqlserverConfig(rawURL string, t driver.Target, password, appName string) (msdsn.Config, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return msdsn.Config{}, out.Usage("komando cannot read the sqlserver URL: %v", err)
	}
	o, err := driver.ParseSQLServerOptions(u.Query())
	if err != nil {
		return msdsn.Config{}, err
	}
	q := url.Values{}
	q.Set("app name", appName)
	if t.Database != "" {
		q.Set("database", t.Database)
	}
	// without encrypt= the driver encrypts only the login and does not
	// check the certificate (its default); `conn add` adds encrypt=true
	// to conns that cross the network on their own
	if o.Encrypt != "" {
		q.Set("encrypt", o.Encrypt)
		q.Set("trustservercertificate", fmt.Sprint(o.SkipVerify))
	}
	if o.ReadOnly {
		q.Set("applicationintent", "ReadOnly")
	}
	host, port, _ := net.SplitHostPort(t.Address)
	dsn := url.URL{Scheme: "sqlserver", User: url.UserPassword(t.User, password), Host: net.JoinHostPort(host, port), RawQuery: q.Encode()}
	cfg, err := msdsn.Parse(dsn.String())
	if err != nil {
		// the DSN holds the password: say what is wrong without it
		msg := err.Error()
		if password != "" {
			msg = strings.ReplaceAll(msg, password, "[hidden]")
		}
		return msdsn.Config{}, out.Usage("komando cannot use the sqlserver settings: %s", msg)
	}
	pool, err := t.RootCAs()
	if err != nil {
		return msdsn.Config{}, err
	}
	if pool != nil && cfg.TLSConfig != nil {
		cfg.TLSConfig.RootCAs, cfg.TLSConfig.InsecureSkipVerify = pool, false
	}
	return cfg, nil
}

func openSQLServer(rawURL string, t driver.Target, password string, dial DialFunc, appName string, _ bool) (*sql.DB, error) {
	cfg, err := sqlserverConfig(rawURL, t, password, appName)
	if err != nil {
		return nil, err
	}
	conn := mssql.NewConnectorConfig(cfg)
	if dial != nil {
		conn.Dialer = viaDialer{dial: dial, host: cfg.Host}
	}
	return sql.OpenDB(conn), nil
}

// readOnlyTx says whether komando asks database/sql for a read-only
// transaction: SQLite's connection is read-only instead, SQL Server has
// none (its transaction is rolled back), and Oracle's is set by markTx.
func readOnlyTx(kind string, write bool) bool {
	return !write && kind != "sqlite" && kind != "sqlserver" && kind != "oracle"
}

// markTx sets the mark stillInTx looks for. SQL Server has savepoints
// but no RELEASE; @@TRANCOUNT serves instead. Oracle starts the
// transaction with SET TRANSACTION, read-only unless write.
func markTx(ctx context.Context, tx *sql.Tx, kind string, write bool) error {
	switch kind {
	case "sqlserver":
		return stillInTx(ctx, tx, kind, write)
	case "oracle":
		_, err := tx.ExecContext(ctx, oracleTxMode(write))
		return err
	case "clickhouse", "snowflake", "bigquery": // no transactions: every statement in one is a read
		return nil
	}
	_, err := tx.ExecContext(ctx, "SAVEPOINT "+txMark)
	return err
}

// stillInTx fails when the transaction komando opened has ended (a COMMIT
// the classifier did not see, or a MySQL statement that commits
// implicitly), so no later statement runs outside it.
func stillInTx(ctx context.Context, tx *sql.Tx, kind string, write bool) error {
	switch kind {
	case "oracle":
		return oracleStillInTx(ctx, tx, write)
	case "clickhouse", "snowflake", "bigquery":
		return nil
	}
	if kind == "sqlserver" {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT @@TRANCOUNT").Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("@@TRANCOUNT is %d, not 1", n)
		}
		return nil
	}
	// RELEASE fails when the savepoint is gone; set it again for the next statement
	if _, err := tx.ExecContext(ctx, "RELEASE SAVEPOINT "+txMark); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "SAVEPOINT "+txMark)
	return err
}

func mssqlNumber(err error) int32 {
	var me mssql.Error
	if errors.As(err, &me) {
		return me.Number
	}
	return 0
}

// isMSAuth: login failed (18456), or the password has expired (18487, 18488).
func isMSAuth(err error) bool {
	n := mssqlNumber(err)
	return n == 18456 || n == 18487 || n == 18488
}

// isMSNoDatabase: the URL's database cannot be opened.
func isMSNoDatabase(err error) bool { return mssqlNumber(err) == 4060 }

func mssqlErr(err error) error {
	var me mssql.Error
	if !errors.As(err, &me) {
		return out.Errf(out.ExitRemote, "DB_ERROR", "fix the SQL; `komando db schema CONN TABLE` shows columns and types", "%v", err)
	}
	switch me.Number {
	case 137, 8178: // a @p placeholder without its --arg
		return out.Errf(out.ExitUsage, "USAGE", "give one --arg per placeholder (@p1, @p2, ...), in order", "%s", me.Message)
	case 229, 230, 262, 297, 300, 15247: // permission denied, VIEW SERVER STATE
		return out.Errf(out.ExitRemote, "DB_PRIVILEGE", "the conn's user lacks this right; ask an admin to grant it, or use a conn with an admin user", "%s (error %d)", me.Message, me.Number)
	case 3906: // a read-only database or replica
		return out.Errf(out.ExitRemote, "DB_ERROR", "this database is read-only (a replica, or set READ_ONLY); change data on the primary", "%s (error %d)", me.Message, me.Number)
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "fix the SQL; `komando db schema CONN TABLE` shows columns and types", "%s (error %d)", me.Message, me.Number)
}

// mssqlBinary are the types whose bytes are data, not text.
var mssqlBinary = map[string]bool{"VARBINARY": true, "BINARY": true, "IMAGE": true, "TIMESTAMP": true, "ROWVERSION": true}

// mssqlValue turns go-mssqldb's bytes into JSON: a uniqueidentifier
// becomes its usual text form, binary columns base64, and DECIMAL and
// MONEY (which come as their digits) stay exact text.
func mssqlValue(b []byte, dbType string) any {
	switch {
	case dbType == "UNIQUEIDENTIFIER" && len(b) == 16:
		// SQL Server stores the first three groups little-endian
		g := []byte{b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6]}
		g = append(g, b[8:]...)
		h := fmt.Sprintf("%X", g)
		return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	case mssqlBinary[dbType]:
		return map[string]string{"base64": base64.StdEncoding.EncodeToString(b)}
	}
	return driver.JSONValue(b)
}

// runShowplan runs one statement under SET SHOWPLAN_TEXT (planned, not
// run) or SET STATISTICS PROFILE (run, with real row counts), and returns
// the plan's lines in place of the statement's rows. The setting is
// turned off again before anything else runs on the connection.
func runShowplan(ctx context.Context, q querier, st driver.Statement, o Options, r *StatementResult) error {
	setting := "SHOWPLAN_TEXT"
	if o.Showplan == "profile" {
		setting = "STATISTICS PROFILE"
	}
	if _, err := q.ExecContext(ctx, "SET "+setting+" ON"); err != nil {
		return err
	}
	defer q.ExecContext(context.WithoutCancel(ctx), "SET "+setting+" OFF")
	rows, err := q.QueryContext(ctx, st.SQL, o.Args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	r.Columns, r.Rows = []Column{{Name: "plan"}}, [][]any{}
	if o.Showplan == "profile" {
		r.Columns = []Column{{Name: "rows"}, {Name: "executes"}, {Name: "plan"}}
	}
	for {
		cols, err := rows.Columns()
		if err != nil {
			return err
		}
		at := map[string]int{}
		for i, c := range cols {
			at[c] = i
		}
		_, isPlan := at["StmtText"]
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		for rows.Next() {
			if err := rows.Scan(ptrs...); err != nil {
				return err
			}
			if !isPlan { // the statement's own rows (profile)
				continue
			}
			row := []any{driver.JSONValue(vals[at["StmtText"]])}
			if o.Showplan == "profile" {
				n, ok := at["Rows"]
				e, ok2 := at["Executes"]
				if !ok || !ok2 { // SHOWPLAN_TEXT's echo of the statement
					continue
				}
				row = []any{driver.JSONValue(vals[n]), driver.JSONValue(vals[e]), row[0]}
			}
			r.Rows = append(r.Rows, row)
			r.RowCount++
		}
		if !rows.NextResultSet() {
			break
		}
	}
	return rows.Err()
}
