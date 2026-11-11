// Package pubsub is the Google Cloud Pub/Sub engine of `komando queue`. It
// speaks the Pub/Sub REST API (v1) itself over komando's own HTTP dial, so
// --via and VPNs work and no Google SDK is needed. The login is the one
// komando uses for gs:// storage: a service account key from the conn's
// password reference, or else gcloud's application default credentials;
// the emulator needs none. It registers itself with queuex for pubsub://
// conns. Pub/Sub keeps messages in subscriptions: peek pulls from one and
// gives every message back unacknowledged. See docs/design/queue.md.
package pubsub

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

func init() { queuex.Register("pubsub", Open) }

// scope is the OAuth scope komando asks for: Pub/Sub only.
const scope = "https://www.googleapis.com/auth/pubsub"

// defaultCredentials finds gcloud's application default credentials (the
// GOOGLE_APPLICATION_CREDENTIALS file, gcloud's own file, or the metadata
// server on Google Cloud). Tests replace it.
var defaultCredentials = func(ctx context.Context) (*google.Credentials, error) {
	return google.FindDefaultCredentials(ctx, scope)
}

// testTLS is nil, except in tests, which trust their own HTTPS server.
var testTLS *tls.Config

// Pubsub is a queuex.Queue on one Google Cloud project.
type Pubsub struct {
	t       driver.Target
	hc      *http.Client
	tr      *http.Transport
	base    string // the endpoint's URL, such as https://pubsub.googleapis.com
	agent   string
	timeout time.Duration
}

// maxResponse is the most komando reads of one answer: a pull of 8
// messages of up to 10 MB each (base64 makes them a third bigger).
const maxResponse = 128 << 20

// Open connects through dial (direct, --via an SSH server, or a VPN) and
// checks that Pub/Sub answers and takes the login. key is a service
// account key (JSON) from the conn's password reference, or "".
func Open(ctx context.Context, t driver.Target, key string, dial queuex.DialFunc, timeout time.Duration, clientID string) (queuex.Queue, error) {
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	tr := &http.Transport{DialContext: dial, TLSHandshakeTimeout: timeout, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, TLSClientConfig: testTLS}
	plain := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("pub/sub answered with a redirect, which komando does not follow with your login")
	}}
	src, err := tokens(t, key, plain)
	if err != nil {
		return nil, err
	}
	p := &Pubsub{t: t, hc: plain, tr: tr, base: baseURL(t), agent: clientID, timeout: timeout}
	if src != nil {
		p.hc = &http.Client{Transport: &oauth2.Transport{Source: src, Base: tr}, Timeout: timeout, CheckRedirect: plain.CheckRedirect}
	}
	var page topicsPage
	if err := p.call(ctx, http.MethodGet, p.project()+"/topics?pageSize=1", nil, &page); err != nil {
		tr.CloseIdleConnections()
		return nil, connectErr(t, err)
	}
	return p, nil
}

// baseURL is the endpoint's URL, without the default port.
func baseURL(t driver.Target) string {
	scheme, host := "http", t.Address
	if t.Secure {
		scheme = "https"
	}
	if h, port, err := net.SplitHostPort(host); err == nil && (t.Secure && port == "443" || !t.Secure && port == "80") {
		host = h
	}
	return scheme + "://" + host
}

// onGoogle says whether the endpoint is one of Google's own.
func onGoogle(t driver.Target) bool {
	h, _, _ := net.SplitHostPort(t.Address)
	return t.Secure && (h == "googleapis.com" || strings.HasSuffix(h, ".googleapis.com"))
}

// tokens is where the access tokens come from: the service account key,
// or the application default credentials. Tokens only travel over HTTPS:
// the emulator (http://) takes no login, so it gets none. The tokens are
// fetched the conn's way too (plain), so --via also covers the login.
func tokens(t driver.Target, key string, plain *http.Client) (oauth2.TokenSource, error) {
	tctx := context.WithValue(context.Background(), oauth2.HTTPClient, plain)
	switch {
	case key != "" && !t.Secure:
		return nil, out.Usage("the pubsub endpoint is http:// (the emulator), which takes no login, and komando sends a login over https only: drop the password reference (`komando conn edit CONN --unset password-ref`)")
	case key != "":
		creds, err := google.CredentialsFromJSONWithType(tctx, []byte(key), google.ServiceAccount, scope)
		if err != nil {
			return nil, out.Errf(out.ExitConnect, "QUEUE_AUTH", "the --password-ref of a pubsub conn holds a service account key: the JSON file from the Google Cloud console (IAM, Service accounts, Keys)",
				"pubsub: the stored login is not a service account key")
		}
		return creds.TokenSource, nil
	case !t.Secure:
		return nil, nil
	}
	creds, err := defaultCredentials(tctx)
	switch {
	case err == nil:
		return creds.TokenSource, nil
	case onGoogle(t):
		return nil, out.Errf(out.ExitConnect, "QUEUE_AUTH",
			"log in with `gcloud auth application-default login`, or store a service account key with `komando secret set NAME < key.json` and pass --password-ref secret:NAME",
			"pubsub: no Google Cloud login: %v", err)
	}
	return nil, nil // an endpoint of its own that may need no login
}

// Close ends the idle connections.
func (p *Pubsub) Close() { p.tr.CloseIdleConnections() }

// project is the API path of the conn's project.
func (p *Pubsub) project() string { return "projects/" + p.t.Project }

// apiError is an error Pub/Sub answered with: the HTTP status, Google's
// status word (NOT_FOUND, PERMISSION_DENIED ...) and its message.
type apiError struct {
	HTTP    int
	Status  string
	Message string
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return e.Status
	}
	return e.Status + ": " + e.Message
}

// call runs one REST call: method on /v1/path with the JSON body in (nil:
// none), and decodes the answer into res (nil: ignore it).
func (p *Pubsub) call(ctx context.Context, method, path string, in, res any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+"/v1/"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", p.agent)
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return answerErr(resp, data)
	}
	if res == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, res); err != nil {
		return fmt.Errorf("the answer to %s %s is not Pub/Sub JSON (is the endpoint a Pub/Sub server?): %w", method, path, err)
	}
	return nil
}

// answerErr reads Google's error answer: {"error": {"code", "message",
// "status"}}, or the start of whatever else came.
func answerErr(resp *http.Response, data []byte) error {
	var e struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	_ = json.Unmarshal(data, &e)
	ae := &apiError{HTTP: resp.StatusCode, Status: e.Error.Status, Message: e.Error.Message}
	if ae.Status == "" {
		ae.Status = resp.Status
	}
	if ae.Message == "" && e.Error.Status == "" {
		ae.Message = strings.TrimSpace(string(data))
		if len(ae.Message) > 200 {
			ae.Message = ae.Message[:200] + "..."
		}
	}
	return ae
}

// A ref is a topic or a subscription as a command names it.
type ref struct {
	kind string // topic, subscription, or "" when the bare name does not say
	name string
}

// path is the ref's API path in the conn's project.
func (p *Pubsub) path(r ref, kind string) string {
	return p.project() + "/" + kind + "s/" + url.PathEscape(r.name)
}

// full is the full name of a topic or subscription of the conn's project
// (projects/P/topics/NAME), as Pub/Sub writes it.
func (p *Pubsub) full(kind, name string) string { return p.project() + "/" + kind + "s/" + name }

// escapePath escapes each part of a full name for a URL path.
func escapePath(full string) string {
	parts := strings.Split(full, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// parseRef reads NAME, topics/NAME, subscriptions/NAME or the full
// projects/PROJECT/topics/NAME of the conn's project.
func (p *Pubsub) parseRef(s string) (ref, error) {
	rest := s
	if strings.HasPrefix(rest, "projects/") {
		proj, after, _ := strings.Cut(strings.TrimPrefix(rest, "projects/"), "/")
		if proj != p.t.Project {
			return ref{}, out.Usage("%s is in project %s, and this conn is project %s: add a conn for that project (`komando conn add NAME pubsub://%s`)", s, proj, p.t.Project, proj)
		}
		rest = after
	}
	r := ref{name: rest}
	if kind, name, ok := strings.Cut(rest, "/"); ok {
		switch kind {
		case "topics", "subscriptions":
			r = ref{kind: strings.TrimSuffix(kind, "s"), name: name}
		default:
			return ref{}, out.Usage("%q is not a Pub/Sub name: give NAME, topics/NAME or subscriptions/NAME", s)
		}
	}
	return r, checkName(r.name)
}

// checkName refuses a name Pub/Sub would not have: 3 to 255 letters,
// digits and - _ . ~ + %, starting with a letter, not with "goog".
func checkName(name string) error {
	ok := len(name) >= 3 && len(name) <= 255 && !strings.HasPrefix(strings.ToLower(name), "goog")
	for i, r := range name {
		letter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		ok = ok && (letter || i > 0 && (r >= '0' && r <= '9' || strings.ContainsRune("-_.~+%", r)))
	}
	if !ok {
		return out.Usage("%q is not a Pub/Sub topic or subscription name: 3 to 255 letters, digits and - _ . ~ + %%, starting with a letter (and not with goog)", name)
	}
	return nil
}

// shortName is the last part of a full name (projects/P/topics/NAME).
func shortName(full string) string { return full[strings.LastIndex(full, "/")+1:] }

// Lag: Pub/Sub's API does not count a subscription's backlog.
func (p *Pubsub) Lag(context.Context, string) (*queuex.GroupLag, error) {
	return nil, queuex.NotSupported("queue lag", "pubsub",
		"the Pub/Sub API does not count waiting messages; Cloud Monitoring has them (subscription/num_undelivered_messages). `komando queue groups CONN` lists the subscriptions and `komando queue describe CONN subscriptions/NAME` shows one")
}
