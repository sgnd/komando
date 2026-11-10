package dbx

import (
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
	"github.com/sijms/go-ora/v2/configurations"
	"github.com/sijms/go-ora/v2/network"

	kdriver "github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// Oracle (go-ora, pure Go). go-ora has no read-only transaction option,
// so komando starts its transaction with SET TRANSACTION READ ONLY itself
// (markTx), and after each statement checks that this transaction is still
// the open one (stillInTx). DDL commits on its own, so the classifier
// (driver/sql_oracle.go) gives it --write and runs it alone.

// oracleConnector opens go-ora connections from settings komando built,
// so the password never sits in a connection string, and each connection
// gets its own copy of the TLS settings (go-ora writes ServerName in).
type oracleConnector struct {
	cfg  configurations.ConnectionConfig
	tls  *tls.Config
	dial DialFunc
}

type oracleDialer struct{ dial DialFunc }

func (d oracleDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr)
}

func (c *oracleConnector) Connect(ctx context.Context) (driver.Conn, error) {
	cfg := c.cfg
	cfg.Servers = append([]configurations.ServerAddr(nil), c.cfg.Servers...)
	if c.tls != nil {
		cfg.TLSConfig = c.tls.Clone()
	}
	if c.dial != nil {
		cfg.Dialer = oracleDialer{c.dial}
	}
	conn, err := go_ora.NewConnection("", &cfg)
	if err != nil {
		return nil, err
	}
	if err := conn.OpenWithContext(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *oracleConnector) Driver() driver.Driver { return go_ora.NewDriver() }

// oracleConfig is go-ora's settings for t: the address, the service (or
// SID), TCPS and its certificate check, and the password.
func oracleConfig(rawURL string, t kdriver.Target, password, appName string) (configurations.ConnectionConfig, *tls.Config, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return configurations.ConnectionConfig{}, nil, out.Usage("invalid oracle URL: %v", err)
	}
	o, err := kdriver.ParseOracleOptions(u.Query())
	if err != nil {
		return configurations.ConnectionConfig{}, nil, err
	}
	host, port, _ := net.SplitHostPort(t.Address)
	// go-ora wants a password to accept the settings; the real one is set below
	dsn := url.URL{Scheme: "oracle", User: url.UserPassword(t.User, "x"), Host: net.JoinHostPort(host, port), Path: "/" + t.Database}
	if o.SID != "" {
		dsn.Path, dsn.RawQuery = "", url.Values{"SID": {o.SID}}.Encode()
	}
	cfg, err := go_ora.ParseConfig(dsn.String())
	if err != nil {
		return configurations.ConnectionConfig{}, nil, out.Usage("invalid oracle settings: %v", err)
	}
	cfg.Password = password
	cfg.ProgramName = appName
	if !t.Secure {
		return *cfg, nil, nil
	}
	cfg.Protocol = "tcps"
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, InsecureSkipVerify: t.TLS == "skip-verify"}
	pool, err := t.RootCAs()
	if err != nil {
		return configurations.ConnectionConfig{}, nil, err
	}
	tc.RootCAs = pool
	return *cfg, tc, nil
}

// opener opens a kind whose driver komando configures itself. readOnly:
// the connection only reads (ClickHouse sends readonly=1 with everything).
type opener func(rawURL string, t kdriver.Target, password string, dial DialFunc, appName string, readOnly bool) (*sql.DB, error)

var openers = map[string]opener{"sqlserver": openSQLServer, "oracle": openOracle, "clickhouse": openClickHouse, "snowflake": openSnowflake, "bigquery": openBigQuery}

func openOracle(rawURL string, t kdriver.Target, password string, dial DialFunc, appName string, _ bool) (*sql.DB, error) {
	cfg, tc, err := oracleConfig(rawURL, t, password, appName)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(&oracleConnector{cfg: cfg, tls: tc, dial: dial}), nil
}

func oraNumber(err error) int {
	var oe *network.OracleError
	if errors.As(err, &oe) {
		return oe.ErrCode
	}
	return 0
}

// txWrites says whether komando's transaction may write. Oracle's EXPLAIN
// PLAN writes the plan into PLAN_TABLE, which a read-only transaction
// refuses; the planned statement does not run, and the transaction is
// rolled back.
func txWrites(o Options) bool { return o.Write || o.Showplan == "text" }

// oracleTxMode is the SET TRANSACTION that starts komando's transaction.
func oracleTxMode(write bool) string {
	if write {
		return "SET TRANSACTION READ WRITE"
	}
	return "SET TRANSACTION READ ONLY"
}

// A read-only transaction that starts within a few seconds of a table's
// CREATE or ALTER fails with ORA-01466: Oracle cannot tell whether the
// transaction began before the change. Nothing ran, so komando waits and
// tries again in a new transaction.
const oraSnapshotTries = 4

var oraSnapshotWait = time.Second

func oraSnapshotTooOld(kind string, o Options, err error) bool {
	var oe *out.Error
	return kind == "oracle" && !txWrites(o) && errors.As(err, &oe) && strings.Contains(oe.Message, "ORA-01466")
}

// oracleStillInTx: SET TRANSACTION works only as the first statement of a
// transaction (ORA-01453 otherwise), so it failing shows komando's is
// still open. Had it ended (a COMMIT komando did not see), the SET opens a
// new one of the same kind, and komando stops.
func oracleStillInTx(ctx context.Context, tx *sql.Tx, write bool) error {
	_, err := tx.ExecContext(ctx, oracleTxMode(write))
	switch {
	case oraNumber(err) == 1453:
		return nil
	case err == nil:
		return errors.New("the transaction had ended")
	}
	return err
}

// isOraAuth: wrong user or password (ORA-01017), locked (28000) or
// expired (28001) account.
func isOraAuth(err error) bool {
	n := oraNumber(err)
	return n == 1017 || n == 28000 || n == 28001
}

// isOraNoService: the listener does not know the service (ORA-12514) or
// SID (ORA-12505).
func isOraNoService(err error) bool {
	n := oraNumber(err)
	return n == 12514 || n == 12505 || strings.Contains(err.Error(), "ORA-12514") || strings.Contains(err.Error(), "ORA-12505")
}

func oracleErr(err error) error {
	n := oraNumber(err)
	msg := strings.TrimSpace(firstLine(err.Error()))
	switch n {
	case 0:
		return out.Errf(out.ExitRemote, "DB_ERROR", "fix the SQL; `komando db schema CONN TABLE` shows columns and types", "%s", msg)
	case 1008, 1006: // not all variables bound, bind variable does not exist
		return out.Errf(out.ExitUsage, "USAGE", "give one --arg per placeholder (:1, :2, ...), in order", "%s", msg)
	case 1456, 16000: // a write in a read-only transaction, a read-only standby
		return writeRequired("statement")
	case 1031: // insufficient privileges
		return out.Errf(out.ExitRemote, "DB_PRIVILEGE", "the conn's user lacks this right; ask an admin to grant it, or use a conn with an admin user", "%s", msg)
	case 1919: // role does not exist
		return out.Errf(out.ExitRemote, "DB_ERROR", "check the role's name: `komando db user ls CONN` lists users and roles; names without \"quotes\" are upper case in Oracle", "%s", msg)
	case 1749: // GRANT or REVOKE to or from oneself
		return out.Errf(out.ExitRemote, "DB_ERROR", "a user cannot grant to or revoke from itself; name another user, or run it from a conn with another user", "%s", msg)
	case 942: // table or view does not exist (also a missing grant on it)
		return out.Errf(out.ExitRemote, "DB_ERROR", "check the name (`komando db schema CONN`); names without \"quotes\" are upper case in Oracle, and a table you have no grant on looks missing too", "%s", msg)
	case 1466: // the table's definition is newer than the read-only transaction can see
		return out.Errf(out.ExitRemote, "DB_ERROR", "the table was created or altered a moment ago; run the query again in a few seconds", "%s", msg)
	case 1013: // cancelled
		return out.Errf(out.ExitTimeout, "TIMEOUT", "narrow the query (WHERE, FETCH FIRST n ROWS ONLY) or raise --timeout", "%s", msg)
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "fix the SQL; `komando db schema CONN TABLE` shows columns and types", "%s", msg)
}

// runOraclePlan runs one statement for db explain: EXPLAIN PLAN asks
// Oracle for the plan (the statement does not run), and DBMS_XPLAN shows
// it.
func runOraclePlan(ctx context.Context, q querier, st kdriver.Statement, r *StatementResult) error {
	if _, err := q.ExecContext(ctx, "EXPLAIN PLAN SET STATEMENT_ID = 'komando' FOR "+st.SQL); err != nil {
		return err
	}
	rows, err := q.QueryContext(ctx, "SELECT plan_table_output FROM TABLE(DBMS_XPLAN.DISPLAY(NULL, 'komando', 'TYPICAL'))")
	if err != nil {
		return err
	}
	defer rows.Close()
	r.Columns, r.Rows = []Column{{Name: "plan"}}, [][]any{}
	for rows.Next() {
		var line sql.NullString
		if err := rows.Scan(&line); err != nil {
			return err
		}
		r.Rows = append(r.Rows, []any{line.String})
		r.RowCount++
	}
	return rows.Err()
}

// oracleTypes are Oracle's names for go-ora's type codes.
var oracleTypes = map[string]string{
	"NCHAR": "VARCHAR2", "LONGVARCHAR": "CLOB", "LONGVARRAW": "BLOB", "LONGRAW": "LONG RAW",
	"IBFLOAT": "BINARY_FLOAT", "IBDOUBLE": "BINARY_DOUBLE", "BFLOAT": "BINARY_FLOAT", "BDOUBLE": "BINARY_DOUBLE",
	"OCICLOBLOCATOR": "CLOB", "OCIBLOBLOCATOR": "BLOB", "OCIFILELOCATOR": "BFILE",
	"TIMESTAMPDTY": "TIMESTAMP", "TIMESTAMPTZ_DTY": "TIMESTAMP WITH TIME ZONE", "TIMESTAMPTZ": "TIMESTAMP WITH TIME ZONE",
	"TIMESTAMPLTZ_DTY": "TIMESTAMP WITH LOCAL TIME ZONE", "TIMESTAMPELTZ": "TIMESTAMP WITH LOCAL TIME ZONE",
	"INTERVALYM_DTY": "INTERVAL YEAR TO MONTH", "INTERVALDS_DTY": "INTERVAL DAY TO SECOND",
	"INTERVALYM": "INTERVAL YEAR TO MONTH", "INTERVALDS": "INTERVAL DAY TO SECOND", "OCIXMLTYPE": "XMLTYPE",
}

func oracleTypeName(goOra string) string {
	if n, ok := oracleTypes[strings.ToUpper(goOra)]; ok {
		return n
	}
	return strings.ToUpper(goOra)
}

// oracleValue turns go-ora's values into JSON. NUMBER comes as text: a
// whole number JSON holds exactly, or a decimal whose shortest float form
// is the same text, becomes a JSON number; any other stays exact text.
// DATE holds a time of day too; RAW and BLOB become base64.
func oracleValue(v any, dbType string) any {
	switch x := v.(type) {
	case string:
		if dbType != "NUMBER" {
			return x
		}
		if n, err := strconv.ParseInt(x, 10, 64); err == nil && n <= 1<<53 && n >= -(1<<53) {
			return n
		}
		if f, err := strconv.ParseFloat(x, 64); err == nil && strconv.FormatFloat(f, 'f', -1, 64) == x {
			return f
		}
		return x
	case []byte:
		if dbType == "RAW" || dbType == "LONG RAW" || dbType == "BLOB" {
			return map[string]string{"base64": base64.StdEncoding.EncodeToString(x)}
		}
		return kdriver.JSONValue(x)
	case time.Time:
		switch dbType {
		case "DATE", "TIMESTAMP":
			return x.Format("2006-01-02 15:04:05.999999999")
		}
		return x.UTC().Format(time.RFC3339Nano)
	}
	return kdriver.JSONValue(v)
}
