// Package dbx runs classified SQL against a conn and turns the result into
// plain JSON values. Without write it uses a read-only transaction, so the
// database itself refuses changes the classifier may have missed.
package dbx

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// DialFunc opens a TCP connection, possibly through an SSH host.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Open connects to t. dial is nil for a direct connection. readOnly opens
// file databases read-only as well.
func Open(ctx context.Context, rawURL string, t driver.Target, password string, dial DialFunc, readOnly bool, appName string) (*sql.DB, error) {
	var db *sql.DB
	switch t.Kind.Name {
	case "postgres":
		cfg, err := pgx.ParseConfig(driver.WithoutCA(rawURL))
		if err != nil {
			return nil, out.Usage("invalid postgres URL: %v", err)
		}
		pool, err := t.RootCAs()
		if err != nil {
			return nil, err
		}
		if pool != nil {
			pinCA(cfg, pool)
		}
		if password != "" {
			cfg.Password = password
		}
		if dial != nil {
			cfg.DialFunc = pgconn.DialFunc(dial)
			// the host name belongs to the remote network: let the SSH host resolve it
			cfg.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
		}
		if cfg.RuntimeParams["application_name"] == "" {
			cfg.RuntimeParams["application_name"] = appName
		}
		// The simple protocol runs every command in one text, so any
		// place where komando's SQL splitter and the server disagree would
		// let a hidden COMMIT end the read-only transaction. The extended
		// protocol takes one command only (runStatement relies on it).
		if cfg.DefaultQueryExecMode == pgx.QueryExecModeSimpleProtocol {
			cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
		}
		db = stdlib.OpenDB(*cfg)
		if readOnly {
			// a transaction the SQL might start after komando's ends is read-only too
			ro := cfg.Copy()
			ro.RuntimeParams["default_transaction_read_only"] = "on"
			roDB := stdlib.OpenDB(*ro)
			switch err := roDB.PingContext(ctx); {
			case err != nil && startupParamRefused(err):
				roDB.Close() // a pooler (PgBouncer) refuses settings it does not track: go on without it
			case err != nil:
				roDB.Close()
				db.Close()
				return nil, connectErr(t, err)
			default:
				db.Close()
				db = roDB
			}
		}
	case "mysql":
		var err error
		if db, err = openMySQL(rawURL, t, password, dial); err != nil {
			return nil, err
		}
	case "sqlite":
		mode := "rwc" // --write may create the file; reads never do
		if readOnly {
			mode = "ro"
		}
		q := url.Values{"mode": {mode}, "_pragma": {"busy_timeout(5000)"}}
		if readOnly {
			q.Add("_pragma", "query_only(1)")
		}
		var err error
		path := t.Path
		if strings.HasPrefix(path, "~/") { // same as `conn test`
			if home, err := os.UserHomeDir(); err == nil {
				path = filepath.Join(home, path[2:])
			}
		}
		if db, err = sql.Open("sqlite", "file:"+path+"?"+q.Encode()); err != nil {
			return nil, err
		}
	case "sqlserver", "oracle", "clickhouse", "snowflake", "bigquery":
		var err error
		if db, err = openers[t.Kind.Name](rawURL, t, password, dial, appName, readOnly); err != nil {
			return nil, err
		}
	case "mongodb":
		return nil, out.Errf(out.ExitUsage, "NOT_SUPPORTED",
			"on MongoDB use `komando db query CONN '{\"find\": ...}'`, `db schema` and `db info`; for a backup, run mongodump on a server with `komando exec`",
			"this db command is for SQL databases, not MongoDB")
	default:
		return nil, out.Usage("%s conns do not take SQL", t.Kind.Name)
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, connectErr(t, err)
	}
	if err := checkStringRules(ctx, db, t); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// startupParamRefused reports whether a Postgres connect failed because a
// pooler refused default_transaction_read_only as a startup setting.
// PgBouncer says "unsupported startup parameter"; other poolers answer
// with protocol_violation (08P01) or name the setting.
func startupParamRefused(err error) bool {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "08P01" {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "unsupported startup parameter") || strings.Contains(msg, "default_transaction_read_only")
}

// unsafeEncodings are client character sets in which a backslash byte
// (0x5c) can be the second byte of a character. The server converts the
// text from them before reading it, so komando's SQL checks, which read
// bytes, would see a backslash the server never sees.
var unsafeEncodings = map[string]map[string]bool{
	"postgres": {"SJIS": true, "SHIFT_JIS_2004": true, "BIG5": true, "GBK": true, "UHC": true, "GB18030": true, "JOHAB": true},
	"mysql":    {"big5": true, "cp932": true, "gbk": true, "gb18030": true, "sjis": true},
}

// checkStringRules makes sure the server parses quotes the way komando's
// SQL classifier does; otherwise a statement could hide its real effect
// inside what komando takes for a string.
func checkStringRules(ctx context.Context, db *sql.DB, t driver.Target) error {
	kind := t.Kind.Name
	var bad string
	switch kind {
	case "postgres":
		var v string
		if err := db.QueryRowContext(ctx, "SHOW standard_conforming_strings").Scan(&v); err != nil {
			return connectErr(t, err)
		}
		if v != "on" {
			bad = "standard_conforming_strings is off"
		}
		if err := db.QueryRowContext(ctx, "SHOW client_encoding").Scan(&v); err != nil {
			return connectErr(t, err)
		}
		if unsafeEncodings[kind][strings.ToUpper(v)] {
			bad = "client_encoding is " + v
		}
	case "mysql":
		var mode string
		if err := db.QueryRowContext(ctx, "SELECT @@SESSION.sql_mode").Scan(&mode); err != nil {
			return connectErr(t, err)
		}
		for _, m := range []string{"NO_BACKSLASH_ESCAPES", "ANSI_QUOTES", "ANSI"} {
			if strings.Contains(","+mode+",", ","+m+",") {
				bad = "sql_mode contains " + m
			}
		}
		var cs string
		if err := db.QueryRowContext(ctx, "SELECT @@SESSION.character_set_client").Scan(&cs); err != nil {
			return connectErr(t, err)
		}
		if unsafeEncodings[kind][strings.ToLower(cs)] {
			bad = "character_set_client is " + cs
		}
	}
	if bad != "" {
		return out.Errf(out.ExitUsage, "SQL_STRING_RULES",
			"komando checks SQL with the default quoting rules and an ASCII-safe character set (UTF-8); use a database user or connection without this setting",
			"this connection parses strings differently (%s)", bad).NoFlag()
	}
	return nil
}

// Options control one Run.
type Options struct {
	Write    bool
	DryRun   bool
	Limit    int // max rows per statement
	MaxBytes int // rough cap on the JSON size of all rows
	Timeout  time.Duration
	Args     []any
	// Showplan is db explain on SQL Server and Oracle: "text" plans each
	// statement without running it (SET SHOWPLAN_TEXT, EXPLAIN PLAN);
	// "profile" (SQL Server) runs it and returns the plan with real row
	// counts (SET STATISTICS PROFILE). On BigQuery "text" is a dry run.
	Showplan string
	// MaxBilled is the most a BigQuery query may read (--max-bytes): 0 is
	// BQDefaultMaxBytes, below 0 no cap.
	MaxBilled int64
}

// Column describes a result column.
type Column struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

// StatementResult is the outcome of one statement. A statement that returns
// rows has columns, rows and row_count (rows may be empty); one that changes
// rows has rows_affected; other statements (DDL, SET) have neither.
type StatementResult struct {
	SQL          string   `json:"sql"`
	Keyword      string   `json:"keyword"`
	Risk         string   `json:"risk"`
	Columns      []Column `json:"columns,omitempty"`
	Rows         [][]any  `json:"-"`
	RowCount     int      `json:"-"`
	Truncated    string   `json:"truncated,omitempty"` // which cap cut the rows: "rows" (--limit) or "bytes" (--max-output)
	RowsAffected *int64   `json:"rows_affected,omitempty"`
	Skipped      string   `json:"skipped,omitempty"` // why it did not run (dry run of a non-rollbackable statement)
	// BytesProcessed is what a BigQuery statement read, which BigQuery
	// bills by (in a dry run or db explain: what it would read)
	BytesProcessed *int64 `json:"bytes_processed,omitempty"`
}

func (r StatementResult) MarshalJSON() ([]byte, error) {
	type plain StatementResult
	var v any = plain(r)
	if r.Columns != nil {
		v = struct {
			plain
			Rows     [][]any `json:"rows"`
			RowCount int     `json:"row_count"`
		}{plain(r), r.Rows, r.RowCount}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep SQL like "x > 5" readable
	err := enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n"), err
}

// changesRows are statements whose rows-affected count means something.
var changesRows = map[string]bool{"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true, "REPLACE": true, "UPSERT": true, "COPY": true}

// Result is the outcome of a Run.
type Result struct {
	Results    []StatementResult `json:"results"`
	Committed  bool              `json:"committed"`
	RolledBack bool              `json:"rolled_back,omitempty"`
}

// Run executes plan on db in one transaction. Without Write the transaction
// is read-only and always rolled back; with DryRun it is rolled back too.
// Statements that cannot run in a transaction must be alone in the plan;
// in a dry run they are reported but not executed.
func Run(ctx context.Context, db *sql.DB, kind string, plan driver.SQLPlan, o Options) (*Result, error) {
	res, err := runPlan(ctx, db, kind, plan, o)
	for try := 0; try < oraSnapshotTries && oraSnapshotTooOld(kind, o, err); try++ {
		select {
		case <-ctx.Done():
			return nil, timeoutErr(err, o.Timeout)
		case <-time.After(oraSnapshotWait):
		}
		res, err = runPlan(ctx, db, kind, plan, o)
	}
	return res, timeoutErr(err, o.Timeout)
}

func runPlan(ctx context.Context, db *sql.DB, kind string, plan driver.SQLPlan, o Options) (*Result, error) {
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	if len(o.Args) > 0 && len(plan.Statements) != 1 {
		return nil, out.Usage("--arg works with a single statement; split the SQL")
	}
	if len(o.Args) > 0 {
		if err := checkArgs(kind, plan.Statements[0].SQL, len(o.Args)); err != nil {
			return nil, err
		}
	}
	res := &Result{Results: []StatementResult{}}
	budget := o.MaxBytes
	for _, st := range plan.Statements {
		if st.NoTx {
			if len(plan.Statements) != 1 {
				return nil, out.Usage("%s cannot run inside a transaction; send it on its own", st.Keyword)
			}
			return runAlone(ctx, db, kind, st, o, &budget)
		}
	}

	// one connection for the whole run: the session settings and the checks
	// below must see the transaction the statements run in
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	defer conn.Close()
	if kind == "mysql" && !o.Write {
		restore, err := mysqlReadOnlySession(ctx, conn)
		if err != nil {
			return nil, queryErr(kind, ctx, err)
		}
		defer restore()
	}
	// sqlite has no read-only transactions; the connection is read-only instead
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: readOnlyTx(kind, o.Write)})
	if err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	defer tx.Rollback()
	if err := setTimeout(ctx, tx, kind, o.Timeout, true); err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	if err := markTx(ctx, tx, kind, txWrites(o)); err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	for i, st := range plan.Statements {
		r := StatementResult{SQL: st.SQL, Keyword: st.Keyword, Risk: st.Risk.String()}
		if st.NoRollback && !o.Write {
			return nil, writeRequired(st.Keyword) // a read-only transaction does not stop it either
		}
		if o.DryRun && st.NoRollback {
			r.Skipped = "dry run: a rollback may not undo this statement (a killed session, a file or program on the server, setval, code komando cannot see), so it was not executed"
			res.Results = append(res.Results, r)
			continue
		}
		if err := runStatement(ctx, tx, conn, kind, st, o, &budget, &r); err != nil {
			return nil, queryErr(kind, ctx, err)
		}
		if err := stillInTx(ctx, tx, kind, txWrites(o)); err != nil {
			if ctx.Err() != nil {
				return nil, queryErr(kind, ctx, err)
			}
			return nil, txEscaped(i+1, st, err)
		}
		res.Results = append(res.Results, r)
	}
	if o.Write && !o.DryRun {
		if err := tx.Commit(); err != nil {
			return nil, queryErr(kind, ctx, err)
		}
		res.Committed = true
		return res, nil
	}
	if err := tx.Rollback(); err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	res.RolledBack = o.Write // a read-only transaction has nothing to roll back worth reporting
	return res, nil
}

// runAlone runs a statement that cannot run inside a transaction: it
// needs --write, and a dry run only reports it (on BigQuery, BigQuery's
// own dry run checks it and says how much it would read).
func runAlone(ctx context.Context, db *sql.DB, kind string, st driver.Statement, o Options, budget *int) (*Result, error) {
	if !o.Write {
		return nil, writeRequired(st.Keyword)
	}
	res := &Result{Results: []StatementResult{}}
	r := StatementResult{SQL: st.SQL, Keyword: st.Keyword, Risk: st.Risk.String()}
	if o.DryRun && kind != "bigquery" {
		r.Skipped = "dry run: this statement cannot be rolled back, so it was not executed"
		res.Results = append(res.Results, r)
		return res, nil
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	defer conn.Close()
	if err := setTimeout(ctx, conn, kind, o.Timeout, false); err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	if err := runStatement(ctx, conn, conn, kind, st, o, budget, &r); err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	res.Results = append(res.Results, r)
	res.Committed = !o.DryRun
	return res, nil
}

type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// setTimeout makes the server stop a statement after d, so a cancelled
// client does not leave a query running.
func setTimeout(ctx context.Context, q querier, kind string, d time.Duration, inTx bool) error {
	if d <= 0 {
		return nil
	}
	ms := d.Milliseconds()
	switch kind {
	case "postgres":
		scope := "SESSION"
		if inTx {
			scope = "LOCAL"
		}
		_, err := q.ExecContext(ctx, fmt.Sprintf("SET %s statement_timeout = %d", scope, ms))
		return err
	case "mysql":
		_, err := q.ExecContext(ctx, fmt.Sprintf("SET SESSION max_execution_time = %d", ms))
		if isUnknownVariable(err) { // MariaDB names it differently, in seconds
			_, err = q.ExecContext(ctx, fmt.Sprintf("SET SESSION max_statement_time = %.3f", d.Seconds()))
		}
		return err
	}
	return nil
}

// txMark is the savepoint that shows the transaction komando opened is
// still open: any COMMIT, implicit or not, removes it, and so does a
// Postgres COMMIT AND CHAIN, which opens a new transaction at once.
const txMark = "komando_tx"

func txEscaped(n int, st driver.Statement, err error) error {
	return out.Errf(out.ExitUsage, "SQL_TX_CONTROL",
		"leave transactions to komando, and tell the user: what ran before this point may have been committed",
		"statement %d (%s) ended komando's transaction, so komando stopped (%v)", n, st.Keyword, err)
}

// mysqlReadOnlySession makes the whole session read-only, not only
// komando's transaction: if a statement ends the transaction early, what
// follows still cannot write. restore puts the old value back.
func mysqlReadOnlySession(ctx context.Context, conn *sql.Conn) (restore func(), err error) {
	name := "transaction_read_only"
	var old string
	err = conn.QueryRowContext(ctx, "SELECT @@SESSION.transaction_read_only").Scan(&old)
	if isUnknownVariable(err) { // MariaDB before 11.1, MySQL before 5.7.20
		name = "tx_read_only"
		err = conn.QueryRowContext(ctx, "SELECT @@SESSION.tx_read_only").Scan(&old)
	}
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, "SET SESSION "+name+" = 1"); err != nil {
		return nil, err
	}
	return func() {
		if old == "0" {
			conn.ExecContext(context.WithoutCancel(ctx), "SET SESSION "+name+" = 0")
		}
	}, nil
}

// runStatement runs one statement. Postgres statements always go over the
// extended protocol, which refuses text with more than one command: pgx
// would send an Exec without arguments as a simple query, where a COMMIT
// hidden from komando's splitter would end the read-only transaction.
func runStatement(ctx context.Context, q querier, conn *sql.Conn, kind string, st driver.Statement, o Options, budget *int, r *StatementResult) error {
	switch {
	case o.Showplan != "" && kind == "sqlserver":
		return runShowplan(ctx, q, st, o, r)
	case o.Showplan != "" && kind == "oracle":
		return runOraclePlan(ctx, q, st, r)
	case o.Showplan != "" && kind == "bigquery":
		return runBQPlan(ctx, conn, st, o, r)
	case o.DryRun && kind == "bigquery": // BigQuery's own dry run, for reads too: it costs nothing
		return bqDryRunOnly(ctx, conn, st, o, r)
	case kind == "bigquery": // the driver checks the --max-bytes cap and records the bytes read in r
		ctx = withBQRun(ctx, o.MaxBilled, r)
	}
	if !st.Rows && kind == "postgres" && len(o.Args) == 0 {
		var tag pgconn.CommandTag
		err := conn.Raw(func(dc any) error {
			res := dc.(*stdlib.Conn).Conn().PgConn().ExecParams(ctx, st.SQL, nil, nil, nil, nil).Read()
			tag = res.CommandTag
			return res.Err
		})
		if err != nil {
			return err
		}
		if changesRows[st.Keyword] {
			n := tag.RowsAffected()
			r.RowsAffected = &n
		}
		return nil
	}
	if !st.Rows {
		res, err := q.ExecContext(ctx, st.SQL, o.Args...)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err == nil && changesRows[st.Keyword] {
			r.RowsAffected = &n
		}
		return nil
	}
	rows, err := q.QueryContext(ctx, st.SQL, o.Args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	cts, err := rows.ColumnTypes()
	if err != nil {
		return err
	}
	types := make([]string, len(cts))
	for i, ct := range cts {
		name := ct.DatabaseTypeName()
		if kind == "oracle" {
			name = oracleTypeName(name)
		}
		types[i] = strings.ToUpper(name)
		r.Columns = append(r.Columns, Column{Name: ct.Name(), Type: colType(kind, name)})
	}
	r.Rows = [][]any{}
	if r.Columns == nil {
		r.Columns = []Column{}
	}
	var raw [][]any
	vals := make([]any, len(cts))
	ptrs := make([]any, len(cts))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if o.Limit > 0 && r.RowCount >= o.Limit {
			r.Truncated = "rows"
			break
		}
		if o.MaxBytes > 0 && *budget <= 0 {
			r.Truncated = "bytes"
			break
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		row := make([]any, len(vals))
		for i, v := range vals {
			row[i] = colValue(kind, types[i], v)
		}
		if o.MaxBytes > 0 {
			b, _ := json.Marshal(row)
			*budget -= len(b)
		}
		r.Rows = append(r.Rows, row)
		raw = append(raw, append([]any(nil), vals...))
		r.RowCount++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	sameTypeColumns(r.Rows, raw)
	nameTypes(ctx, q, kind, r.Columns)
	return nil
}

func writeRequired(kw string) *out.Error {
	return out.Errf(out.ExitPolicy, "WRITE_REQUIRES_FLAG",
		"this statement changes data; re-run with --write (try --write --dry-run first)",
		"%s needs --write", kw)
}

// connectErr maps a failed connection to an error code.
func connectErr(t driver.Target, err error) error {
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (pe.Code == "28P01" || pe.Code == "28000") || isMySQLAuth(err) || isMSAuth(err) || isOraAuth(err) || isCHAuth(err) {
		return out.Errf(out.ExitConnect, "DB_AUTH", "check the user in the URL and the password reference (`komando conn show NAME`)", "%v", err)
	}
	if errors.As(err, &pe) && pe.Code == "3D000" || isMySQLNoDatabase(err) || isMSNoDatabase(err) || chCode(err) == 81 {
		return out.Errf(out.ExitNotFound, "DB_NOT_FOUND", "check the database name at the end of the conn URL (`komando conn show NAME`)", "%v", err)
	}
	if t.Kind.Name == "oracle" && isOraNoService(err) {
		return out.Errf(out.ExitNotFound, "DB_NOT_FOUND", "check the service name at the end of the conn URL (`komando conn show NAME`); `lsnrctl status` on the server lists them", "%v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "the database did not answer in time; check the address or raise --connect-timeout", "connecting to %s timed out", t.Where())
	}
	if t.Kind.File {
		return out.Errf(out.ExitConnect, "DB_CONNECT", "check the file path in the conn URL", "cannot open %s: %v", t.Path, err)
	}
	if t.Kind.Name == "oracle" && t.Secure && (errors.Is(err, io.EOF) || err.Error() == "EOF") {
		// a listener without TCPS closes the connection on the TLS hello
		err = fmt.Errorf("%w (server refused TLS: the listener closed the connection)", err)
	}
	if h := tlsHint(t.Kind.Name, err); h != "" {
		return out.Errf(out.ExitConnect, "DB_CONNECT", h, "cannot connect to %s: %v", t.Where(), err)
	}
	return out.Errf(out.ExitConnect, "DB_CONNECT", "run `komando conn test NAME` to check reachability", "cannot connect to %s: %v", t.Where(), err)
}

// tlsHint says what to do when TLS stopped the connection: the server's
// certificate did not check out, or the server has no TLS. It names the
// URL settings that weaken it last, with what they cost. "" when TLS was
// not the problem.
func tlsHint(kind string, err error) string {
	msg := err.Error()
	weak := map[string][2]string{ // encrypt without checking, no encryption at all
		"postgres":   {"?sslmode=require", "?sslmode=disable"},
		"mysql":      {"?tls=skip-verify", "?tls=false"},
		"sqlserver":  {"&tls=skip-verify", "?encrypt=disable"},
		"oracle":     {"?tls=skip-verify", "?tls=false"},
		"clickhouse": {"?tls=skip-verify", "?tls=false"},
	}[kind]
	if weak[0] == "" {
		return ""
	}
	// through an SSH tunnel the plain connection is fine; a TLS check of a
	// self-signed certificate would fail there too
	via := "reach the server --via an SSH server and connect without TLS through it (`komando conn edit NAME --via HOST --url '..." + weak[1] + "'`)"
	switch {
	case strings.Contains(msg, "x509:") || strings.Contains(msg, "tls: failed to verify"):
		ca := "give the CA that signed it with ?ca=secret:NAME (`komando secret set NAME < ca.pem`)"
		return "the server's certificate could not be checked: " + ca + ", or " + via +
			"; without --via, " + weak[0] + " encrypts without checking it, so anyone on the network path could pretend to be the server"
	case strings.Contains(msg, "server refused TLS"), errors.Is(err, mysql.ErrNoTLS),
		kind == "oracle" && strings.Contains(msg, "first record does not look like a TLS handshake"),
		kind == "clickhouse" && strings.Contains(msg, "server gave HTTP response to HTTPS client"):
		return "the server has no TLS: " + via + "; without --via, " + weak[1] + " sends the password and the data unencrypted"
	}
	return ""
}

// queryErr maps a failed statement to an error code.
func queryErr(kind string, ctx context.Context, err error) error {
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "narrow the query (WHERE, LIMIT) or raise --timeout", "query timed out")
	}
	if strings.Contains(err.Error(), "expected") && strings.Contains(err.Error(), "arguments, got") { // pgx
		return out.Errf(out.ExitUsage, "USAGE", "give one --arg per placeholder ($1, $2, ...), in order", "%v", err)
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "25006": // read_only_sql_transaction
			return writeRequired("statement")
		case "57014": // query_canceled (statement_timeout)
			return out.Errf(out.ExitTimeout, "TIMEOUT", "narrow the query (WHERE, LIMIT) or raise --timeout", "%s", pe.Message)
		}
		return out.Errf(out.ExitRemote, "DB_ERROR", "fix the SQL; `komando db schema CONN TABLE` shows columns and types", "%s (SQLSTATE %s)", pe.Message, pe.Code)
	}
	switch kind {
	case "mysql":
		return mysqlErr(err)
	case "sqlserver":
		return mssqlErr(err)
	case "oracle":
		return oracleErr(err)
	case "clickhouse":
		return clickhouseErr(err)
	case "snowflake":
		return snowflakeErr(err)
	case "bigquery":
		return bigqueryErr(err)
	}
	msg := err.Error()
	if kind == "sqlite" && (strings.Contains(msg, "readonly database") || strings.Contains(msg, "query_only")) {
		return writeRequired("statement")
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "fix the SQL; `komando db schema CONN TABLE` shows columns and types", "%s", msg)
}

// pinCA makes every TLS attempt check the server's certificate against
// pool (the conn's ?ca=) and its name, and drops the attempts without TLS
// that sslmode=prefer would make.
func pinCA(cfg *pgx.ConnConfig, pool *x509.CertPool) {
	set := func(tc *tls.Config, host string) *tls.Config {
		c := &tls.Config{MinVersion: tls.VersionTLS12}
		if tc != nil {
			c = tc.Clone()
		}
		c.RootCAs, c.InsecureSkipVerify, c.VerifyPeerCertificate, c.VerifyConnection = pool, false, nil, nil
		if c.ServerName == "" {
			c.ServerName = host
		}
		return c
	}
	cfg.TLSConfig = set(cfg.TLSConfig, cfg.Host)
	var keep []*pgconn.FallbackConfig
	for _, fb := range cfg.Fallbacks {
		if fb.TLSConfig != nil {
			fb.TLSConfig = set(fb.TLSConfig, fb.Host)
			keep = append(keep, fb)
		}
	}
	cfg.Fallbacks = keep
}
