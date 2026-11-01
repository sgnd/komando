// Package dbx runs classified SQL against a conn and turns the result into
// plain JSON values. Without write it uses a read-only transaction, so the
// database itself refuses changes the classifier may have missed.
package dbx

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

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
		cfg, err := pgx.ParseConfig(rawURL)
		if err != nil {
			return nil, out.Usage("invalid postgres URL: %v", err)
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
		db = stdlib.OpenDB(*cfg)
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
		if db, err = sql.Open("sqlite", "file:"+t.Path+"?"+q.Encode()); err != nil {
			return nil, err
		}
	default:
		return nil, out.Usage("%s conns do not take SQL", t.Kind.Name)
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, connectErr(t, err)
	}
	return db, nil
}

// Options control one Run.
type Options struct {
	Write    bool
	DryRun   bool
	Limit    int // max rows per statement
	MaxBytes int // rough cap on the JSON size of all rows
	Timeout  time.Duration
	Args     []any
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
	Truncated    bool     `json:"truncated,omitempty"`
	RowsAffected *int64   `json:"rows_affected,omitempty"`
	Skipped      string   `json:"skipped,omitempty"` // why it did not run (dry run of a non-rollbackable statement)
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
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	if len(o.Args) > 0 && len(plan.Statements) != 1 {
		return nil, out.Usage("--arg works with a single statement; split the SQL")
	}
	res := &Result{Results: []StatementResult{}}
	budget := o.MaxBytes
	for _, st := range plan.Statements {
		if st.NoTx {
			if len(plan.Statements) != 1 {
				return nil, out.Usage("%s cannot run inside a transaction; send it on its own", st.Keyword)
			}
			if !o.Write {
				return nil, writeRequired(st.Keyword)
			}
			r := StatementResult{SQL: st.SQL, Keyword: st.Keyword, Risk: st.Risk.String()}
			if o.DryRun {
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
			if err := runStatement(ctx, conn, st, o, &budget, &r); err != nil {
				return nil, queryErr(kind, ctx, err)
			}
			res.Results = append(res.Results, r)
			res.Committed = true
			return res, nil
		}
	}

	// sqlite has no read-only transactions; the connection is read-only instead
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: !o.Write && kind != "sqlite"})
	if err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	defer tx.Rollback()
	if err := setTimeout(ctx, tx, kind, o.Timeout, true); err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	for _, st := range plan.Statements {
		r := StatementResult{SQL: st.SQL, Keyword: st.Keyword, Risk: st.Risk.String()}
		if err := runStatement(ctx, tx, st, o, &budget, &r); err != nil {
			return nil, queryErr(kind, ctx, err)
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
		return err
	}
	return nil
}

func runStatement(ctx context.Context, q querier, st driver.Statement, o Options, budget *int, r *StatementResult) error {
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
	for _, ct := range cts {
		r.Columns = append(r.Columns, Column{Name: ct.Name(), Type: strings.ToLower(ct.DatabaseTypeName())})
	}
	r.Rows = [][]any{}
	if r.Columns == nil {
		r.Columns = []Column{}
	}
	vals := make([]any, len(cts))
	ptrs := make([]any, len(cts))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if o.Limit > 0 && r.RowCount >= o.Limit || o.MaxBytes > 0 && *budget <= 0 {
			r.Truncated = true
			break
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		row := make([]any, len(vals))
		for i, v := range vals {
			row[i] = JSONValue(v)
		}
		if o.MaxBytes > 0 {
			b, _ := json.Marshal(row)
			*budget -= len(b)
		}
		r.Rows = append(r.Rows, row)
		r.RowCount++
	}
	return rows.Err()
}

// JSONValue converts a database value into something JSON keeps exactly:
// text stays text, binary becomes {"base64": ...}, times become RFC 3339,
// and integers too large for a JSON number become strings.
func JSONValue(v any) any {
	switch x := v.(type) {
	case nil, bool, string:
		return x
	case []byte:
		if utf8.Valid(x) && !strings.ContainsRune(string(x), 0) {
			return string(x)
		}
		return map[string]string{"base64": base64.StdEncoding.EncodeToString(x)}
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case int64:
		if x > 1<<53 || x < -(1<<53) {
			return fmt.Sprint(x)
		}
		return x
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Sprint(x)
		}
		return x
	case int, int32, int16, int8, uint8, uint16, uint32, float32:
		return x
	case uint64:
		if x > 1<<53 {
			return fmt.Sprint(x)
		}
		return x
	}
	return fmt.Sprint(v)
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
	if errors.As(err, &pe) && (pe.Code == "28P01" || pe.Code == "28000") || isMySQLAuth(err) {
		return out.Errf(out.ExitConnect, "DB_AUTH", "check the user in the URL and the password reference (`komando conn show NAME`)", "%v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "the database did not answer in time; check the address or raise --connect-timeout", "connecting to %s timed out", t.Where())
	}
	if t.Kind.File {
		return out.Errf(out.ExitNotFound, "DB_CONNECT", "check the file path in the conn URL", "cannot open %s: %v", t.Path, err)
	}
	return out.Errf(out.ExitConnect, "DB_CONNECT", "run `komando conn test NAME` to check reachability", "cannot connect to %s: %v", t.Where(), err)
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
	if kind == "mysql" {
		return mysqlErr(err)
	}
	msg := err.Error()
	if kind == "sqlite" && (strings.Contains(msg, "readonly database") || strings.Contains(msg, "query_only")) {
		return writeRequired("statement")
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "fix the SQL; `komando db schema CONN TABLE` shows columns and types", "%s", msg)
}
