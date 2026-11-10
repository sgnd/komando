package dbx

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	kdriver "github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// Snowflake, over its SQL REST API (POST /api/v2/statements), with
// komando's own small client: a database/sql driver, so db query, schema
// and the rest work as for the other kinds. Each statement is one request
// and a session of its own: there is no transaction across statements.
//
// Snowflake has no read-only setting komando could send. A connection
// without --write (and a read-only transaction, which here only marks the
// requests) checks each statement with the classifier again before it
// goes, and every request asks Snowflake to run exactly one statement
// (MULTI_STATEMENT_COUNT=1), so text komando split wrongly is refused by
// the server. The docs recommend a role that may only read.
//
// Requests are asynchronous: the answer to the POST is the statement's
// handle, then komando asks for the result until it is there. So a
// cancelled run (Ctrl-C, --timeout) can always cancel the statement on
// the server, too.

type sfConnector struct {
	base      string // https://ACCOUNT.snowflakecomputing.com
	client    *http.Client
	transport *http.Transport
	s         kdriver.SnowflakeConn
	auth      *sfAuth
	agent     string
	readOnly  bool // the whole connection only reads (no --write)
}

type sfDriverT struct{}

func (sfDriverT) Open(string) (driver.Conn, error) {
	return nil, errors.New("snowflake conns open through komando's connector")
}

func (c *sfConnector) Driver() driver.Driver { return sfDriverT{} }

// Close drops the idle HTTP connections (and so the --via channels).
func (c *sfConnector) Close() error {
	c.transport.CloseIdleConnections()
	return nil
}

func (c *sfConnector) Connect(context.Context) (driver.Conn, error) { return &sfConn{c: c}, nil }

type sfConn struct {
	c    *sfConnector
	inTx bool
	txRO bool
}

func (cn *sfConn) Prepare(query string) (driver.Stmt, error) {
	return &sfStmt{cn: cn, query: query}, nil
}
func (cn *sfConn) Close() error { return nil }
func (cn *sfConn) Begin() (driver.Tx, error) {
	return cn.BeginTx(context.Background(), driver.TxOptions{})
}

// BeginTx marks what follows: there are no transactions across requests,
// so a read-only one makes every statement in it pass the read check, and
// the classifier keeps every statement that is not a read out of it.
func (cn *sfConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	cn.inTx, cn.txRO = true, o.ReadOnly
	return sfTx{cn}, nil
}

type sfTx struct{ cn *sfConn }

func (t sfTx) Commit() error   { t.cn.inTx, t.cn.txRO = false, false; return nil }
func (t sfTx) Rollback() error { t.cn.inTx, t.cn.txRO = false, false; return nil }

// Ping runs SELECT 1, which needs no warehouse: it checks the login.
func (cn *sfConn) Ping(ctx context.Context) error {
	if _, err := cn.run(ctx, "SELECT 1", nil); err != nil {
		return sfConnectErr(err)
	}
	return nil
}

func (cn *sfConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	res, err := cn.run(ctx, query, args)
	if err != nil {
		return nil, err
	}
	var n int64
	if st := res.Stats; st != nil {
		n = st.Inserted + st.Updated + st.Deleted + st.DuplicatesUpdated
	}
	return driver.RowsAffected(n), nil
}

func (cn *sfConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	res, err := cn.run(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return newSFRows(ctx, cn.c, res), nil
}

// sfStmt serves database/sql's prepared form; Snowflake gets the text.
type sfStmt struct {
	cn    *sfConn
	query string
}

func (s *sfStmt) Close() error  { return nil }
func (s *sfStmt) NumInput() int { return -1 }
func (s *sfStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.cn.ExecContext(context.Background(), s.query, named(args))
}
func (s *sfStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.cn.QueryContext(context.Background(), s.query, named(args))
}
func (s *sfStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.cn.ExecContext(ctx, s.query, args)
}
func (s *sfStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.cn.QueryContext(ctx, s.query, args)
}

// sfResult is the SQL API's answer: a statement's status, or its result
// (the first partition of rows, and where the others are).
type sfResult struct {
	Code               string `json:"code"`
	Message            string `json:"message"`
	StatementHandle    string `json:"statementHandle"`
	StatementStatusURL string `json:"statementStatusUrl"`
	Meta               *struct {
		RowType       []sfColumn `json:"rowType"`
		PartitionInfo []struct {
			RowCount int64 `json:"rowCount"`
		} `json:"partitionInfo"`
	} `json:"resultSetMetaData"`
	Data  [][]any `json:"data"`
	Stats *struct {
		Inserted          int64 `json:"numRowsInserted"`
		Updated           int64 `json:"numRowsUpdated"`
		Deleted           int64 `json:"numRowsDeleted"`
		DuplicatesUpdated int64 `json:"numDuplicateRowsUpdated"`
	} `json:"stats"`
}

// sfPoll is the first wait before asking for a running statement's
// result; it doubles up to sfPollMax.
var sfPoll, sfPollMax = 50 * time.Millisecond, 2 * time.Second

// run sends one statement and waits for its result.
func (cn *sfConn) run(ctx context.Context, query string, args []driver.NamedValue) (*sfResult, error) {
	c := cn.c
	if c.readOnly || cn.inTx && cn.txRO {
		if err := sfReadOnly(query); err != nil {
			return nil, err
		}
	}
	body := map[string]any{
		"statement":  query,
		"parameters": map[string]string{"MULTI_STATEMENT_COUNT": "1", "QUERY_TAG": c.agent},
	}
	for k, v := range map[string]string{"database": c.s.Database, "schema": c.s.Schema, "warehouse": c.s.Warehouse, "role": c.s.Role} {
		if v != "" {
			body[k] = v
		}
	}
	if dl, ok := ctx.Deadline(); ok {
		body["timeout"] = int(math.Max(1, math.Ceil(time.Until(dl).Seconds())))
	}
	if len(args) > 0 {
		b := map[string]any{}
		for i, a := range args {
			b[strconv.Itoa(i+1)] = sfBinding(a.Value)
		}
		body["bindings"] = b
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	rand.Read(id)
	id[6], id[8] = id[6]&0x0f|0x40, id[8]&0x3f|0x80
	h := hex.EncodeToString(id)
	q := url.Values{"requestId": {h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]}, "async": {"true"}}
	var res *sfResult
	status := 0
	for attempt := 0; ; attempt++ {
		status, res, err = c.do(ctx, http.MethodPost, "/api/v2/statements?"+q.Encode(), payload)
		if err != nil || !sfRetry(status) || attempt == 3 {
			break
		}
		q.Set("retry", "true") // the same requestId: Snowflake runs it once
		if err := sleepCtx(ctx, time.Duration(attempt+1)*time.Second); err != nil {
			return nil, err
		}
	}
	return c.wait(ctx, status, res, err)
}

// wait follows a statement until it is done; when ctx ends first, the
// statement is cancelled on the server.
func (c *sfConnector) wait(ctx context.Context, status int, res *sfResult, err error) (*sfResult, error) {
	pause := sfPoll
	handle, path := "", ""
	for err == nil && (status == http.StatusAccepted || sfRetry(status) && handle != "") {
		if status == http.StatusAccepted {
			if handle = res.StatementHandle; handle == "" {
				return nil, errors.New("unexpected answer from Snowflake: a running statement without a handle")
			}
			if path = res.StatementStatusURL; !strings.HasPrefix(path, "/api/v2/statements/") {
				path = "/api/v2/statements/" + url.PathEscape(handle)
			}
		}
		if serr := sleepCtx(ctx, pause); serr != nil {
			c.cancel(ctx, handle)
			return nil, serr
		}
		pause = min(pause*2, sfPollMax)
		if status, res, err = c.do(ctx, http.MethodGet, path, nil); ctx.Err() != nil {
			c.cancel(ctx, handle)
		}
	}
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, sfFailure(status, res)
	}
	if res.StatementHandle == "" {
		res.StatementHandle = handle // the other partitions are fetched by it
	}
	return res, nil
}

// cancel asks Snowflake to stop a statement whose run komando gave up on.
func (c *sfConnector) cancel(ctx context.Context, handle string) {
	if handle == "" {
		return
	}
	cctx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	_, _, _ = c.do(cctx, http.MethodPost, "/api/v2/statements/"+url.PathEscape(handle)+"/cancel", []byte("{}"))
}

// do sends one request. status and res come back for any answer from
// Snowflake; err is for no answer, a failed login, or one that is not
// JSON.
func (c *sfConnector) do(ctx context.Context, method, path string, payload []byte) (int, *sfResult, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return 0, nil, err
	}
	token, kind, err := c.auth.header(c.s)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Snowflake-Authorization-Token-Type", kind)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.agent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) { // its text holds the URL; the reason is enough
			err = ue.Err
		}
		if strings.Contains(err.Error(), "x509:") || strings.Contains(err.Error(), "tls: failed to verify") {
			return 0, nil, out.Errf(out.ExitConnect, "DB_CONNECT",
				"Snowflake's certificate is signed by a public CA, so something on the way answered instead (a proxy that inspects TLS?): if it is your company's, give its CA with ?ca=secret:NAME (`komando secret set NAME < ca.pem`)",
				"cannot connect to %s: %v", c.s.Host, err)
		}
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return 0, nil, err
	}
	res := &sfResult{}
	if jerr := json.Unmarshal(raw, res); jerr != nil {
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
			return 0, nil, fmt.Errorf("unexpected answer from Snowflake (HTTP %d): %v", resp.StatusCode, jerr)
		}
		res = &sfResult{Message: strings.TrimSpace(string(raw))}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden && sfAuthCode(res.Code) {
		return 0, nil, c.auth.failed(c.s, res)
	}
	return resp.StatusCode, res, nil
}

func sfRetry(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// sfBinding is a --arg value as the SQL API binds it.
func sfBinding(v any) map[string]any {
	switch x := v.(type) {
	case nil:
		return map[string]any{"type": "TEXT", "value": nil}
	case int64, int, int32:
		return map[string]any{"type": "FIXED", "value": fmt.Sprint(x)}
	case float64, float32:
		return map[string]any{"type": "REAL", "value": fmt.Sprint(x)}
	case bool:
		return map[string]any{"type": "BOOLEAN", "value": strconv.FormatBool(x)}
	case []byte:
		return map[string]any{"type": "BINARY", "value": hex.EncodeToString(x)}
	case time.Time:
		return map[string]any{"type": "TIMESTAMP_TZ", "value": x.Format("2006-01-02 15:04:05.999999999 -07:00")}
	}
	return map[string]any{"type": "TEXT", "value": fmt.Sprint(v)}
}

// sfReadOnly refuses a statement that is not a read on a connection that
// only reads: Snowflake has no setting that would.
func sfReadOnly(query string) error {
	plan, err := kdriver.ClassifySQL("snowflake", query)
	if err != nil {
		return err
	}
	if len(plan.Statements) != 1 {
		return out.Usage("send one statement at a time")
	}
	if plan.Risk != kdriver.RiskRead {
		return writeRequired(plan.Statements[0].Keyword)
	}
	return nil
}

// openSnowflake builds komando's client for t: HTTPS with the certificate
// checked against the system's CAs or the conn's ?ca=, through dial
// (--via, a VPN) when there is one, never through a proxy from the
// environment. password is the conn's secret: a private key (PEM) for
// key-pair login, or a programmatic access token.
func openSnowflake(rawURL string, t kdriver.Target, password string, dial DialFunc, appName string, readOnly bool) (*sql.DB, error) {
	s, err := kdriver.ParseSnowflakeURL(rawURL)
	if err != nil {
		return nil, err
	}
	auth, err := newSFAuth(password)
	if err != nil {
		return nil, err
	}
	pool, err := t.RootCAs()
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(t.Address)
	tr := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: pool},
	}
	if dial != nil {
		tr.DialContext = dial
	} else {
		tr.DialContext = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
	}
	c := &sfConnector{
		base:      "https://" + t.Address,
		client:    &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		transport: tr,
		s:         s, auth: auth, agent: appName, readOnly: readOnly,
	}
	return sql.OpenDB(c), nil
}
