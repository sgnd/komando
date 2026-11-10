package dbx

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/sgnd/komando/internal/out"
)

// The Google Cloud side of BigQuery conns: the login (a service account
// key, or the application default credentials, as for gs:// conns) and
// what BigQuery's errors mean for komando.

// bqCredentials is the login: the conn's service account key, or the
// application default credentials. gcloud's login goes only to Google's
// own hosts (https://*.googleapis.com): an endpoint elsewhere (an
// emulator) gets a key the conn names, or no login at all.
func bqCredentials(key string, plain *http.Client, onGoogle bool) (*google.Credentials, error) {
	tctx := context.WithValue(context.Background(), oauth2.HTTPClient, plain)
	if key != "" {
		creds, err := google.CredentialsFromJSONWithType(tctx, []byte(key), google.ServiceAccount, bqScope)
		if err != nil {
			return nil, out.Errf(out.ExitUsage, "DB_AUTH", "the --password-ref of a bigquery conn holds a service account key (the JSON file from the console), or leave it out to use gcloud's login",
				"bigquery: the stored key is not a service account key: %v", err)
		}
		return creds, nil
	}
	if !onGoogle {
		return nil, nil // an emulator without a login
	}
	creds, err := bqDefaultCredentials(tctx)
	if err != nil {
		return nil, out.Errf(out.ExitConnect, "DB_AUTH",
			"log in with `gcloud auth application-default login`, or store a service account key with `komando secret set NAME < key.json` and pass --password-ref secret:NAME",
			"bigquery: no Google Cloud login: %v", err)
	}
	return creds, nil
}

// bqConnectErr is bigqueryErr for the first request of a connection: what
// the URL names may not exist.
func bqConnectErr(err error) error {
	var e *bqError
	if !errors.As(err, &e) {
		return err
	}
	if e.Status == http.StatusNotFound || e.Reason == "notFound" {
		return out.Errf(out.ExitNotFound, "DB_NOT_FOUND", "check the project and the dataset in the conn URL (`komando conn show NAME`); a dataset is found only in its own location (?location=)", "%s", e)
	}
	return bigqueryErr(e)
}

// bqTokenTimeout bounds one token fetch: the token source takes no
// context, so neither --timeout nor Ctrl-C reaches its request.
var bqTokenTimeout = 30 * time.Second

// bqTokenTransport adds the login's token to each API request, like
// oauth2.Transport, but waits for the token only as long as the request's
// context lasts, and tells a token endpoint that did not answer apart from
// a login Google refused.
type bqTokenTransport struct {
	src  oauth2.TokenSource
	base http.RoundTripper
}

func (t *bqTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	type got struct {
		tok *oauth2.Token
		err error
	}
	ch := make(chan got, 1)
	go func() {
		tok, err := t.src.Token()
		ch <- got{tok, err}
	}()
	var g got
	select {
	case <-req.Context().Done(): // --timeout or Ctrl-C: the fetch ends with its own time limit
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, req.Context().Err()
	case g = <-ch:
	}
	if g.err == nil && g.tok == nil {
		g.err = errors.New("oauth2: the token source returned no token")
	}
	if g.err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, bqTokenErr(g.err)
	}
	r := req.Clone(req.Context())
	g.tok.SetAuthHeader(r)
	return t.base.RoundTrip(r)
}

// bqTokenErr keeps a refused login (Google answered) and an untrusted
// certificate as they are, for connectErr; a token endpoint that could not
// be reached is a connection problem, not a login to renew.
func bqTokenErr(err error) error {
	var re *oauth2.RetrieveError
	msg := err.Error()
	if errors.As(err, &re) || strings.Contains(msg, "x509:") || strings.Contains(msg, "tls: failed to verify") {
		return err
	}
	var ue *url.Error
	if errors.As(err, &ue) || strings.Contains(msg, "cannot fetch token") {
		return out.Errf(out.ExitConnect, "DB_CONNECT",
			"Google's token endpoint (oauth2.googleapis.com) did not answer: check DNS and the network from this computer, or from the --via host if the conn has one",
			"bigquery: cannot fetch a Google token: %s", strings.Join(strings.Fields(msg), " "))
	}
	return err
}

// connectErr explains a request that got no answer: no login, a
// certificate that did not check out, or the network.
func (c *bqConnector) connectErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) { // its text holds the URL; the reason is enough
		err = ue.Err
	}
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "x509:") || strings.Contains(msg, "tls: failed to verify"):
		return out.Errf(out.ExitConnect, "DB_CONNECT",
			"Google's certificates are signed by a public CA, so something on the way answered instead (a proxy that inspects TLS?): if it is your company's, give its CA with ?ca=secret:NAME (`komando secret set NAME < ca.pem`)",
			"cannot connect to %s: %v", c.b.Endpoint, err)
	case strings.Contains(msg, "oauth2:") || strings.Contains(msg, "google: "):
		return out.Errf(out.ExitConnect, "DB_AUTH",
			"log in again with `gcloud auth application-default login`, or check the service account key in --password-ref (`komando conn show NAME`)",
			"bigquery: the Google login was refused: %s", strings.Join(strings.Fields(msg), " "))
	}
	return err
}

// bigqueryErr maps a failed statement to an error code. The reasons are
// BigQuery's documented error reasons.
func bigqueryErr(err error) error {
	var e *bqError
	if !errors.As(err, &e) {
		return out.Errf(out.ExitRemote, "DB_ERROR", "run `komando conn test CONN` to check the project and the login", "%v", err)
	}
	low := strings.ToLower(e.Msg)
	switch {
	case e.Status == http.StatusUnauthorized:
		return out.Errf(out.ExitConnect, "DB_AUTH", "log in again with `gcloud auth application-default login`, or check the service account key in --password-ref", "%s", e)
	case e.Reason == "responseTooLarge": // sent with 403, so before the rights
		return out.Errf(out.ExitRemote, "DB_ERROR", "the result is too large to return: add LIMIT, or select fewer columns", "%s", e)
	case e.Reason == "billingNotEnabled": // 403 too
		return out.Errf(out.ExitRemote, "DB_ERROR", "the conn's project has no billing account: enable billing for it in the Google Cloud console, or use a project that has one", "%s", e)
	case e.Reason == "accessDenied" || e.Status == http.StatusForbidden && e.Reason != "quotaExceeded" && e.Reason != "rateLimitExceeded":
		return out.Errf(out.ExitRemote, "DB_PRIVILEGE", "the login lacks a right here: running queries needs roles/bigquery.jobUser on the conn's project, reading tables roles/bigquery.dataViewer on their dataset", "%s", e)
	case e.Reason == "bytesBilledLimitExceeded":
		return out.Errf(out.ExitPolicy, "DB_BYTES_LIMIT", "the query read more than --max-bytes allows, so BigQuery stopped it: narrow it, or, if that cost is intended (ask the user), raise --max-bytes", "%s", e)
	case e.Reason == "notFound" || e.Status == http.StatusNotFound:
		return out.Errf(out.ExitRemote, "DB_ERROR", "check the name (`komando db schema CONN`): dataset.table, or `project.dataset.table` in backticks; a dataset is found only in its own location (?location= in the conn URL)", "%s", e)
	case e.Reason == "quotaExceeded" || e.Reason == "rateLimitExceeded" || e.Status == http.StatusTooManyRequests:
		return out.Errf(out.ExitRemote, "DB_ERROR", "BigQuery is limiting this project's jobs; wait a little and run it again", "%s", e)
	case e.Reason == "stopped" || strings.Contains(low, "job execution was cancelled"):
		return out.Errf(out.ExitRemote, "DB_ERROR", "someone cancelled this job (`komando db kill`, or the console); run it again if it is still needed", "%s", e)
	case e.Reason == "timeout" || strings.Contains(low, "exceeded the maximum execution time") || strings.Contains(low, "job timeout"):
		return out.Errf(out.ExitTimeout, "TIMEOUT", "narrow the query (WHERE on the partition column, LIMIT) or raise --timeout", "%s", e)
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "fix the SQL; `komando db schema CONN TABLE` shows columns and types", "%s", e)
}
