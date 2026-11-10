package dbx

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2/google"

	kdriver "github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// Google BigQuery, over its REST API with komando's own small client (not
// the Google Cloud SDK): a database/sql driver, so db query, schema and
// the rest work as for the other kinds. Each statement is a job of its
// own; there are no transactions across statements.
//
// Every statement first goes as a dry run (jobs.insert with dryRun),
// which costs nothing and runs nothing. It says what kind of statement
// BigQuery sees and how many bytes the query would read, which is what
// BigQuery bills. A connection without --write (and a read-only
// transaction, which here only marks the statements) refuses anything
// BigQuery does not call a SELECT, after the classifier's own check; a
// query that would read more than --max-bytes is refused before it runs,
// and the job carries the same cap (maximumBytesBilled), so BigQuery
// stops it, too.
//
// The job ID is komando's own, so a run that is cancelled or times out
// cancels the job on the server (jobs.cancel).

// BQDefaultMaxBytes is the most a query may read without --max-bytes:
// 10 GiB, a few cents at on-demand prices.
const BQDefaultMaxBytes int64 = 10 << 30

const bqScope = "https://www.googleapis.com/auth/bigquery"

// bqDefaultCredentials finds application default credentials (gcloud's
// login, GOOGLE_APPLICATION_CREDENTIALS, the metadata server); tests
// replace it.
var bqDefaultCredentials = func(ctx context.Context) (*google.Credentials, error) {
	return google.FindDefaultCredentials(ctx, bqScope)
}

type bqConnector struct {
	b         kdriver.BigQueryConn
	base      string // the endpoint and /bigquery/v2
	client    *http.Client
	transport *http.Transport
	label     string // the komando label on every job: who ran it
	readOnly  bool   // the whole connection only reads (no --write)
	google    bool   // Google's own host (https://*.googleapis.com): gcloud's login goes there, and dry runs always say the statement type
	location  string // where the jobs ran (from the URL, or the first job)
}

type bqDriverT struct{}

func (bqDriverT) Open(string) (driver.Conn, error) {
	return nil, errors.New("bigquery conns open through komando's connector")
}

func (c *bqConnector) Driver() driver.Driver { return bqDriverT{} }

// Close drops the idle HTTP connections (and so the --via channels).
func (c *bqConnector) Close() error {
	c.transport.CloseIdleConnections()
	return nil
}

func (c *bqConnector) Connect(context.Context) (driver.Conn, error) { return &bqConn{c: c}, nil }

type bqConn struct {
	c    *bqConnector
	inTx bool
	txRO bool
}

func (cn *bqConn) Prepare(query string) (driver.Stmt, error) {
	return &bqStmt{cn: cn, query: query}, nil
}
func (cn *bqConn) Close() error { return nil }
func (cn *bqConn) Begin() (driver.Tx, error) {
	return cn.BeginTx(context.Background(), driver.TxOptions{})
}

// BeginTx marks what follows: there are no transactions across jobs, so
// a read-only one makes every statement in it pass the read checks.
func (cn *bqConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	cn.inTx, cn.txRO = true, o.ReadOnly
	return bqTx{cn}, nil
}

type bqTx struct{ cn *bqConn }

func (t bqTx) Commit() error   { t.cn.inTx, t.cn.txRO = false, false; return nil }
func (t bqTx) Rollback() error { t.cn.inTx, t.cn.txRO = false, false; return nil }

// Ping dry-runs SELECT 1: it checks the login and that the project takes
// jobs, and costs nothing.
func (cn *bqConn) Ping(ctx context.Context) error {
	if _, err := cn.c.dryRun(ctx, "SELECT 1", nil); err != nil {
		return bqConnectErr(err)
	}
	return nil
}

func (cn *bqConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	res, err := cn.run(ctx, query, args)
	if err != nil {
		return nil, err
	}
	n, _ := strconv.ParseInt(res.NumDmlAffectedRows, 10, 64)
	return driver.RowsAffected(n), nil
}

func (cn *bqConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	res, err := cn.run(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return &bqRows{ctx: ctx, c: cn.c, res: res, page: res.Rows}, nil
}

// bqStmt serves database/sql's prepared form; BigQuery gets the text.
type bqStmt struct {
	cn    *bqConn
	query string
}

func (s *bqStmt) Close() error  { return nil }
func (s *bqStmt) NumInput() int { return -1 }
func (s *bqStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.cn.ExecContext(context.Background(), s.query, named(args))
}
func (s *bqStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.cn.QueryContext(context.Background(), s.query, named(args))
}
func (s *bqStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.cn.ExecContext(ctx, s.query, args)
}
func (s *bqStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.cn.QueryContext(ctx, s.query, args)
}

// bqRunKey carries one statement's --max-bytes cap and where its bytes go
// (runStatement sets it; db shell and the ops use the default cap).
type bqRunKey struct{}

type bqRun struct {
	maxBytes int64 // 0: BQDefaultMaxBytes; below 0: no cap
	res      *StatementResult
}

func withBQRun(ctx context.Context, maxBytes int64, r *StatementResult) context.Context {
	return context.WithValue(ctx, bqRunKey{}, &bqRun{maxBytes: maxBytes, res: r})
}

// bqCap is the cap for ctx's statement (0 for none), and where its
// bytes go.
func bqCap(ctx context.Context) (int64, *StatementResult) {
	rr, _ := ctx.Value(bqRunKey{}).(*bqRun)
	if rr == nil {
		return BQDefaultMaxBytes, nil
	}
	return bqLimit(rr.maxBytes), rr.res
}

// run checks one statement with a dry run, then runs it as a job and
// waits for its first page of rows.
func (cn *bqConn) run(ctx context.Context, query string, args []driver.NamedValue) (*bqResults, error) {
	c := cn.c
	readOnly := c.readOnly || cn.inTx && cn.txRO
	if readOnly {
		if err := bqReadOnly(query); err != nil {
			return nil, err
		}
	}
	dry, err := c.dryRun(ctx, query, args)
	if err != nil {
		return nil, err
	}
	limit, rec := bqCap(ctx)
	if err := c.checkDry(query, dry, readOnly, limit); err != nil {
		return nil, err
	}
	params := bqParams(args)
	id := make([]byte, 12)
	rand.Read(id)
	ref := bqJobRef{ProjectID: c.b.Project, JobID: "komando_" + hex.EncodeToString(id), Location: c.location}
	conf := c.queryConfig(query, params, limit)
	job := map[string]any{"jobReference": ref, "configuration": map[string]any{"query": conf, "labels": map[string]string{"komando": c.label}}}
	if dl, ok := ctx.Deadline(); ok {
		job["configuration"].(map[string]any)["jobTimeoutMs"] = strconv.FormatInt(int64(math.Max(1000, float64(time.Until(dl).Milliseconds()))), 10)
	}
	var started bqJob
	for attempt := 0; ; attempt++ {
		err = c.call(ctx, http.MethodPost, c.projectPath()+"/jobs", nil, job, &started)
		var e *bqError
		if errors.As(err, &e) && e.Status == http.StatusConflict && attempt > 0 {
			err = nil // the first try made it after all
		}
		if !bqRetry(err) || attempt == 3 {
			break
		}
		if serr := sleepCtx(ctx, time.Duration(attempt+1)*time.Second); serr != nil {
			c.cancel(ctx, ref)
			return nil, serr
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			c.cancel(ctx, ref)
		}
		return nil, err
	}
	if started.JobReference.Location != "" {
		ref.Location = started.JobReference.Location
		c.location = ref.Location
	}
	if started.Status.ErrorResult != nil {
		return nil, started.Status.ErrorResult.err(http.StatusBadRequest)
	}
	res, err := c.wait(ctx, ref)
	if err != nil {
		return nil, err
	}
	if rec != nil {
		if n, perr := strconv.ParseInt(res.TotalBytesProcessed, 10, 64); perr == nil {
			rec.BytesProcessed = &n
		}
	}
	return res, nil
}

// checkDry decides on a dry run's answer: what a read-only connection may
// run, a script where komando saw one statement, and the byte cap.
func (c *bqConnector) checkDry(query string, dry *bqJob, readOnly bool, limit int64) error {
	st := dry.Statistics.Query.StatementType
	switch {
	case st == "" && c.google:
		return errors.New("unexpected answer from BigQuery: the dry run did not say what kind of statement this is")
	case readOnly && st != "SELECT" && st != "":
		return writeRequired(st)
	case st == "SCRIPT" && !bqOpaque(query):
		return out.Errf(out.ExitUsage, "USAGE",
			"BigQuery read this as a script of several statements where komando saw one, so nothing ran: send each statement on its own",
			"BigQuery reads this text as a script")
	}
	if n := dry.bytes(); limit > 0 && n > limit {
		return bqTooBig(n, limit)
	}
	return nil
}

// bqTooBig is a query that would read more than the cap allows.
func bqTooBig(n, limit int64) error {
	return out.Errf(out.ExitPolicy, "DB_BYTES_LIMIT",
		"BigQuery bills by the bytes a query reads: select fewer columns, filter on the partition or cluster columns, or, if that cost is intended (ask the user), raise --max-bytes",
		"the query would read %s, more than --max-bytes %s, so it did not run", humanBytes(n), humanBytes(limit))
}

// bqOpaque reports a CALL or EXECUTE IMMEDIATE, which BigQuery runs as a
// script; the classifier has already rated it (sql-opaque).
func bqOpaque(query string) bool {
	plan, err := kdriver.ClassifySQL("bigquery", query)
	return err == nil && len(plan.Statements) == 1 && (plan.Statements[0].Keyword == "CALL" || plan.Statements[0].Keyword == "EXECUTE")
}

// queryConfig is configuration.query of a job for query.
func (c *bqConnector) queryConfig(query string, params []map[string]any, limit int64) map[string]any {
	conf := map[string]any{"query": query, "useLegacySql": false}
	if c.b.Dataset != "" {
		conf["defaultDataset"] = map[string]string{"projectId": c.b.Project, "datasetId": c.b.Dataset}
	}
	if limit > 0 {
		conf["maximumBytesBilled"] = strconv.FormatInt(limit, 10)
	}
	if len(params) > 0 {
		conf["parameterMode"] = "POSITIONAL"
		conf["queryParameters"] = params
	}
	return conf
}

// dryRun asks BigQuery what query is and how much it would read, without
// running it.
func (c *bqConnector) dryRun(ctx context.Context, query string, args []driver.NamedValue) (*bqJob, error) {
	ref := map[string]string{"projectId": c.b.Project}
	if c.location != "" {
		ref["location"] = c.location
	}
	job := map[string]any{"jobReference": ref, "configuration": map[string]any{"dryRun": true, "query": c.queryConfig(query, bqParams(args), 0)}}
	var res bqJob
	err := c.call(ctx, http.MethodPost, c.projectPath()+"/jobs", nil, job, &res)
	for attempt := 0; bqRetry(err) && attempt < 3; attempt++ {
		if serr := sleepCtx(ctx, time.Duration(attempt+1)*time.Second); serr != nil {
			return nil, serr
		}
		err = c.call(ctx, http.MethodPost, c.projectPath()+"/jobs", nil, job, &res)
	}
	return &res, err
}

// bqPoll is how long one getQueryResults call waits on the server.
var bqPoll = 10 * time.Second

// wait asks for a job's results until it is done; when ctx ends first,
// the job is cancelled on the server.
func (c *bqConnector) wait(ctx context.Context, ref bqJobRef) (*bqResults, error) {
	q := url.Values{"maxResults": {"1000"}, "formatOptions.useInt64Timestamp": {"true"}}
	if ref.Location != "" {
		q.Set("location", ref.Location)
	}
	path := "/projects/" + url.PathEscape(ref.ProjectID) + "/queries/" + url.PathEscape(ref.JobID)
	for tries := 0; ; {
		wait := bqPoll
		if dl, ok := ctx.Deadline(); ok {
			wait = min(wait, max(time.Until(dl), time.Millisecond))
		}
		q.Set("timeoutMs", strconv.FormatInt(max(wait.Milliseconds(), 1), 10))
		var res bqResults
		err := c.call(ctx, http.MethodGet, path, q, nil, &res)
		switch {
		case ctx.Err() != nil:
			c.cancel(ctx, ref)
			return nil, ctx.Err()
		case bqRetry(err) && tries < 5:
			tries++
			if serr := sleepCtx(ctx, time.Duration(tries)*time.Second); serr != nil {
				c.cancel(ctx, ref)
				return nil, serr
			}
		case err != nil:
			return nil, err
		case res.JobComplete:
			res.JobReference = ref
			return &res, nil
		}
	}
}

// cancel asks BigQuery to stop a job komando gave up on.
func (c *bqConnector) cancel(ctx context.Context, ref bqJobRef) {
	cctx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	_ = c.cancelJob(cctx, ref)
}

func (c *bqConnector) cancelJob(ctx context.Context, ref bqJobRef) error {
	var q url.Values
	if ref.Location != "" {
		q = url.Values{"location": {ref.Location}}
	}
	return c.call(ctx, http.MethodPost, "/projects/"+url.PathEscape(ref.ProjectID)+"/jobs/"+url.PathEscape(ref.JobID)+"/cancel", q, nil, &struct{}{})
}

func (c *bqConnector) projectPath() string { return "/projects/" + url.PathEscape(c.b.Project) }

// bqParams are --arg values as positional STRING parameters: BigQuery
// does not turn text into numbers by itself, so a number is written as
// CAST(? AS INT64).
func bqParams(args []driver.NamedValue) []map[string]any {
	var ps []map[string]any
	for _, a := range args {
		v := map[string]any{"value": nil}
		if a.Value != nil {
			v["value"] = fmt.Sprint(a.Value)
		}
		ps = append(ps, map[string]any{"parameterType": map[string]string{"type": "STRING"}, "parameterValue": v})
	}
	return ps
}

// bqReadOnly refuses a statement that is not a read on a connection that
// only reads, before BigQuery sees it.
func bqReadOnly(query string) error {
	plan, err := kdriver.ClassifySQL("bigquery", query)
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

// bqLabel is who runs the job, as a BigQuery label value (lower-case
// letters, digits, _ and -).
func bqLabel(appName string) string {
	b := []byte(strings.ToLower(strings.TrimPrefix(appName, "komando/")))
	for i, ch := range b {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
			b[i] = '_'
		}
	}
	return string(b[:min(len(b), 63)])
}

// openBigQuery builds komando's client for t: HTTPS with the certificate
// checked against the system's CAs or the conn's ?ca=, through dial
// (--via, a VPN) when there is one, never through a proxy from the
// environment. password is the conn's secret: a service account key
// (JSON), or "" for the application default credentials. Tokens are
// fetched the same way as the API is reached.
func openBigQuery(rawURL string, t kdriver.Target, password string, dial DialFunc, appName string, readOnly bool) (*sql.DB, error) {
	b, err := kdriver.ParseBigQueryURL(rawURL)
	if err != nil {
		return nil, err
	}
	pool, err := t.RootCAs()
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		// no ServerName: tokens come from another host (oauth2.googleapis.com)
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
	}
	if dial != nil {
		tr.DialContext = dial
	} else {
		tr.DialContext = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
	}
	plain := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	c := &bqConnector{b: b, base: b.Endpoint + "/bigquery/v2", client: plain, transport: tr,
		label: bqLabel(appName), readOnly: readOnly, google: bqGoogleHost(b.Endpoint), location: b.Location}
	// tokens come over the same dialer and CAs (tr), so --via as well; the
	// token source has no context of its own, so its client has a time limit
	tokens := &http.Client{Transport: tr, Timeout: bqTokenTimeout, CheckRedirect: plain.CheckRedirect}
	creds, err := bqCredentials(password, tokens, c.google)
	if err != nil {
		return nil, err
	}
	if creds != nil {
		c.client = &http.Client{Transport: &bqTokenTransport{src: creds.TokenSource, base: tr}, CheckRedirect: plain.CheckRedirect}
	}
	return sql.OpenDB(c), nil
}

// bqGoogleHost reports an endpoint on Google's own hosts: the API, or a
// Private Service Connect address (bigquery-NAME.p.googleapis.com).
func bqGoogleHost(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && u.Scheme == "https" && (u.Hostname() == "googleapis.com" || strings.HasSuffix(u.Hostname(), ".googleapis.com"))
}
