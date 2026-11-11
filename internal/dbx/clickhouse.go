package dbx

import (
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	kdriver "github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// ClickHouse, over its HTTP interface (8123, 8443 with TLS), with
// komando's own small client: a database/sql driver, so db query, schema
// and the rest work as for the other kinds. Each statement is one HTTP
// request; there are no sessions and no transactions.
//
// Read-only is the server's own setting readonly=1, sent with every
// request of a run without --write, with every query that returns rows,
// and with every statement inside a read-only transaction (which here
// only marks the requests). With --write, a statement that is not a read
// is sent alone, outside any transaction (the classifier rates every such
// statement NoTx), and a dry run only reports it.

// chProbe reads the user's own settings before anything else runs: a
// profile with readonly=1 refuses any setting in the request, even one
// it already has, and readonly=2 refuses a change of readonly.
const chProbe = "SELECT name, value FROM system.settings WHERE name IN ('readonly', 'dialect')"

type chConnector struct {
	base     string // http(s)://host:port/
	client   *http.Client
	user     string
	password string
	database string
	agent    string
	readOnly bool // the whole connection only reads (no --write)

	mu        sync.Mutex
	probed    bool
	profileRO int // the user's readonly setting: 0, 1 or 2
	transport *http.Transport
}

type chDriverT struct{}

func (chDriverT) Open(string) (driver.Conn, error) {
	return nil, errors.New("clickhouse conns open through komando's connector")
}

func (c *chConnector) Driver() driver.Driver { return chDriverT{} }

// Close drops the idle HTTP connections (and so the --via channels).
func (c *chConnector) Close() error {
	c.transport.CloseIdleConnections()
	return nil
}

func (c *chConnector) Connect(ctx context.Context) (driver.Conn, error) {
	cn := &chConn{c: c}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.probed {
		return cn, nil
	}
	rows, err := cn.query(ctx, chProbe, nil, false, true)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	vals := make([]driver.Value, 2)
	for {
		if err := rows.Next(vals); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		name, _ := vals[0].(string)
		value, _ := vals[1].(string)
		switch name {
		case "readonly":
			c.profileRO, _ = strconv.Atoi(value)
		case "dialect":
			if value != "clickhouse" {
				return nil, out.Errf(out.ExitUsage, "SQL_STRING_RULES",
					"komando checks ClickHouse SQL; use a user whose settings profile keeps dialect = 'clickhouse'",
					"this user's queries are read as %s, not ClickHouse SQL", value).NoFlag()
			}
		}
	}
	c.probed = true
	return cn, nil
}

type chConn struct {
	c    *chConnector
	inTx bool
	txRO bool
}

func (cn *chConn) Prepare(query string) (driver.Stmt, error) {
	return &chStmt{cn: cn, query: query}, nil
}
func (cn *chConn) Close() error { return nil }
func (cn *chConn) Begin() (driver.Tx, error) {
	return cn.BeginTx(context.Background(), driver.TxOptions{})
}

// BeginTx marks what follows: ClickHouse has no transactions, so a
// read-only one makes every request carry readonly=1, and the classifier
// keeps every statement that is not a read out of it.
func (cn *chConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	cn.inTx, cn.txRO = true, o.ReadOnly
	return chTx{cn}, nil
}

type chTx struct{ cn *chConn }

func (t chTx) Commit() error   { t.cn.inTx, t.cn.txRO = false, false; return nil }
func (t chTx) Rollback() error { t.cn.inTx, t.cn.txRO = false, false; return nil }

func (cn *chConn) Ping(ctx context.Context) error {
	rows, err := cn.query(ctx, "SELECT 1", nil, true, false)
	if err != nil {
		return err
	}
	return rows.Close()
}

func (cn *chConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	resp, err := cn.do(ctx, query, args, cn.c.readOnly || cn.inTx && cn.txRO, false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)); err != nil {
		return nil, err
	}
	var sum struct {
		Written string `json:"written_rows"`
	}
	_ = json.Unmarshal([]byte(resp.Header.Get("X-ClickHouse-Summary")), &sum)
	n, _ := strconv.ParseInt(sum.Written, 10, 64)
	return driver.RowsAffected(n), nil
}

// QueryContext always reads with readonly=1: a statement that returns
// rows is a read (SELECT, SHOW, DESCRIBE, EXPLAIN, EXISTS).
func (cn *chConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return cn.query(ctx, query, args, true, false)
}

// chFormat is how komando asks for rows: one JSON array per line, the
// column names and types first.
const chFormat = "JSONCompactEachRowWithNamesAndTypes"

func (cn *chConn) query(ctx context.Context, query string, args []driver.NamedValue, ro, probe bool) (*chRows, error) {
	resp, err := cn.do(ctx, query+"\nFORMAT "+chFormat, args, ro, probe)
	if err != nil {
		return nil, err
	}
	if f := resp.Header.Get("X-ClickHouse-Format"); f != "" && f != chFormat {
		resp.Body.Close()
		return nil, out.Errf(out.ExitUsage, "USAGE", "leave out FORMAT and INTO OUTFILE: komando reads the rows as JSON and prints them itself (--csv, --tsv, -o text)",
			"the query asks for its own output format (%s)", f)
	}
	// without settings (the probe, a read-only profile) a late failure
	// comes as a row of one string
	return newCHRows(resp.Body, probe || cn.c.profileRO == 1)
}

// do sends one statement. ro asks the server to refuse any change
// (readonly=1). Settings are left out where the user's profile refuses
// them (chProbe), and for the probe itself.
func (cn *chConn) do(ctx context.Context, query string, args []driver.NamedValue, ro, probe bool) (*http.Response, error) {
	c := cn.c
	q := url.Values{}
	for _, a := range args {
		name := a.Name
		if name == "" {
			name = "p" + strconv.Itoa(a.Ordinal)
		}
		q.Set("param_"+name, fmt.Sprint(a.Value))
	}
	if !probe && c.profileRO != 1 {
		if ro && c.profileRO == 0 {
			q.Set("readonly", "1")
		}
		if ro {
			q.Set("cancel_http_readonly_queries_on_client_close", "1")
		}
		if dl, ok := ctx.Deadline(); ok {
			q.Set("max_execution_time", strconv.Itoa(int(math.Max(1, math.Ceil(time.Until(dl).Seconds())))))
		}
		// a failure after the first rows is plain text, not a row
		q.Set("http_write_exception_in_output_format", "0")
		q.Set("output_format_decimal_trailing_zeros", "1") // Decimal(10, 2) 1.50 stays 1.50
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"?"+q.Encode(), strings.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.agent)
	req.Header.Set("X-ClickHouse-User", c.user)
	if c.password != "" {
		req.Header.Set("X-ClickHouse-Key", c.password)
	}
	if c.database != "" {
		req.Header.Set("X-ClickHouse-Database", c.database)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) { // its text holds the URL; the reason is enough
			err = ue.Err
		}
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		err := newCHError(resp.Header.Get("X-ClickHouse-Exception-Code"), string(body), resp.Status)
		if chCode(err) == 164 && !ro && c.profileRO > 0 {
			return nil, out.Errf(out.ExitRemote, "DB_PRIVILEGE", "use a conn with a ClickHouse user that may write; this one reads only, whatever komando asks",
				"this ClickHouse user may only read (readonly = %d in its settings profile)", c.profileRO)
		}
		return nil, err
	}
	return resp, nil
}

// chStmt serves database/sql's prepared form; ClickHouse gets the text.
type chStmt struct {
	cn    *chConn
	query string
}

func (s *chStmt) Close() error  { return nil }
func (s *chStmt) NumInput() int { return -1 }
func (s *chStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.cn.ExecContext(context.Background(), s.query, named(args))
}
func (s *chStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.cn.QueryContext(context.Background(), s.query, named(args))
}
func (s *chStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.cn.ExecContext(ctx, s.query, args)
}
func (s *chStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.cn.QueryContext(ctx, s.query, args)
}

func named(args []driver.Value) []driver.NamedValue {
	res := make([]driver.NamedValue, len(args))
	for i, v := range args {
		res[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return res
}

// chError is a failure ClickHouse reported: "Code: 60. DB::Exception:
// Table x does not exist. (UNKNOWN_TABLE) (version ...)".
type chError struct {
	Code int
	Msg  string
}

func (e *chError) Error() string {
	if e.Code == 0 {
		return e.Msg
	}
	return fmt.Sprintf("%s (ClickHouse error %d)", e.Msg, e.Code)
}

var chCodeText = regexp.MustCompile(`(?s)Code: (\d+)\. (?:DB::Exception: )?(.*?)(?: \(version .*\))?\s*$`)

func newCHError(header, body, status string) error {
	body = strings.TrimSpace(body)
	e := &chError{Msg: body}
	e.Code, _ = strconv.Atoi(header)
	if m := chCodeText.FindStringSubmatch(body); m != nil {
		e.Code, _ = strconv.Atoi(m[1])
		e.Msg = m[2]
	}
	// the server's long help after a failed login is not for komando's users
	if i := strings.Index(e.Msg, "\n"); i >= 0 {
		e.Msg = strings.TrimSpace(e.Msg[:i])
	}
	e.Msg = strings.TrimSuffix(e.Msg, ".")
	if e.Msg == "" {
		e.Msg = "HTTP " + status
	}
	return e
}

func chCode(err error) int {
	var ce *chError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return 0
}

// isCHAuth: wrong password or unknown user (516), a user that needs a
// password (194), or a host the user may not connect from (195).
func isCHAuth(err error) bool {
	n := chCode(err)
	return n == 516 || n == 194 || n == 195
}

func clickhouseErr(err error) error {
	n := chCode(err)
	msg := err.Error()
	var ce *chError
	if errors.As(err, &ce) {
		msg = ce.Msg
	}
	switch n {
	case 164: // READONLY
		if strings.Contains(msg, "setting") {
			return out.Errf(out.ExitUsage, "USAGE", "leave settings out (SET, SETTINGS): komando sends each statement as its own request with readonly=1 for reads, and this user's settings profile may forbid changes too", "%s", msg)
		}
		return writeRequired("statement")
	case 497, 36: // ACCESS_DENIED, and a grant of more than the user has
		return out.Errf(out.ExitRemote, "DB_PRIVILEGE", "the conn's user lacks this right; ask an admin to grant it (`komando db grants CONN USER` shows the user's grants), or use a conn with an admin user", "%s", msg)
	case 456, 457: // UNKNOWN_QUERY_PARAMETER, BAD_QUERY_PARAMETER
		return out.Errf(out.ExitUsage, "USAGE", "write placeholders as {p1:String}, {p2:UInt64}, ... and give one --arg per placeholder, in order", "%s", msg)
	case 159: // TIMEOUT_EXCEEDED (max_execution_time, from --timeout)
		return out.Errf(out.ExitTimeout, "TIMEOUT", "narrow the query (WHERE, LIMIT) or raise --timeout", "%s", msg)
	case 394: // QUERY_WAS_CANCELLED: KILL QUERY
		return out.Errf(out.ExitRemote, "DB_ERROR", "someone stopped this query (`komando db kill`, or KILL QUERY on the server); run it again if it is still needed", "%s", msg)
	case 81:
		return out.Errf(out.ExitNotFound, "DB_NOT_FOUND", "list databases with `komando db query CONN 'SHOW DATABASES'`", "%s", msg)
	case 62: // SYNTAX_ERROR; at komando's own FORMAT when the SQL has one
		if strings.Contains(msg, "FORMAT "+chFormat) {
			return out.Errf(out.ExitUsage, "USAGE", "leave out FORMAT and INTO OUTFILE: komando reads the rows as JSON and prints them itself (--csv, --tsv, -o text)", "%s", msg)
		}
	case 60:
		return out.Errf(out.ExitRemote, "DB_ERROR", "check the name (`komando db schema CONN`); ClickHouse names are case-sensitive", "%s", msg)
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "fix the SQL; `komando db schema CONN TABLE` shows columns and types", "%s", msg)
}

// openClickHouse builds komando's client for t: HTTP or HTTPS with
// the certificate checked against the system's CAs or the conn's ?ca=,
// through dial (--via, a VPN) when there is one, never through a proxy
// from the environment.
func openClickHouse(_ string, t kdriver.Target, password string, dial DialFunc, appName string, readOnly bool) (*sql.DB, error) {
	scheme := "http"
	tr := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if dial != nil {
		tr.DialContext = dial
	} else {
		tr.DialContext = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
	}
	if t.Secure {
		scheme = "https"
		host, _, _ := net.SplitHostPort(t.Address)
		pool, err := t.RootCAs()
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: pool, InsecureSkipVerify: t.TLS == "skip-verify"}
	}
	user := t.User
	if user == "" {
		user = "default"
	}
	c := &chConnector{
		base:      scheme + "://" + t.Address + "/",
		client:    &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		transport: tr,
		user:      user, password: password, database: t.Database, agent: appName, readOnly: readOnly,
	}
	return sql.OpenDB(c), nil
}
