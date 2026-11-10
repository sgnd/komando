// Package registry talks to container registries (Docker Hub, GHCR,
// GitLab, Harbor, ECR, ACR, Artifact Registry, registry:2) over the OCI
// Distribution API, with basic or bearer-token auth.
package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/proxyx"
)

// Accept lists the manifest types komando reads.
const Accept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

// Client calls one registry.
type Client struct {
	Base       *url.URL
	User       string
	Password   string
	http       *http.Client
	skipVerify bool // the certificate is not checked (?tls=skip-verify)
	mu         sync.Mutex
	tokens     map[string]string // scope -> bearer token
}

// TLS says how a client talks to its registry. The zero value is HTTPS
// with the certificate checked against the system's CAs.
type TLS struct {
	Plain      bool           // plain HTTP (a local registry:2)
	SkipVerify bool           // HTTPS without checking the certificate
	RootCAs    *x509.CertPool // the CAs to trust in place of the system's (nil = system)
}

// CAPool is the system's CAs plus the PEM certificates in pem, for a
// registry with a certificate from a private CA (mkcert, an internal CA).
func CAPool(pem []byte) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificate found (it starts with -----BEGIN CERTIFICATE-----)")
	}
	return pool, nil
}

// New makes a client. host is host[:port]. dial may be nil; it gets the
// host name, not an address, so a --via server resolves the name itself
// (its /etc/hosts applies), while the certificate check and the Host
// header keep using the name.
func New(host string, t TLS, user, password string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *Client {
	scheme := "https"
	if t.Plain {
		scheme = "http"
	}
	if host == "docker.io" || host == "index.docker.io" {
		host = "registry-1.docker.io"
	}
	tr := &http.Transport{TLSHandshakeTimeout: 15 * time.Second, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: t.RootCAs, InsecureSkipVerify: t.SkipVerify}}
	if dial != nil {
		tr.DialContext = dial // the --via path is the way out
	} else {
		tr.Proxy = proxyx.FromEnv() // HTTPS_PROXY and NO_PROXY, as docker reads them
	}
	return &Client{Base: &url.URL{Scheme: scheme, Host: host}, User: user, Password: password, skipVerify: t.SkipVerify,
		http: &http.Client{Transport: tr, Timeout: 2 * time.Minute}, tokens: map[string]string{}}
}

// CheckedTLS says whether the client talks HTTPS and checks the registry's
// certificate. A cloud login sends a token that is good for far more than
// the registry, so it goes only to a registry whose certificate is checked.
func (c *Client) CheckedTLS() bool {
	return c.Base.Scheme == "https" && !c.skipVerify
}

// Error is an error answer from the registry.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%s (%d)", e.Code, e.Status)
	}
	return fmt.Sprintf("%s (%d): %s", e.Code, e.Status, e.Message)
}

// Do sends a request with auth, retrying once with a token if the registry
// asks for one.
func (c *Client) Do(ctx context.Context, method, path string, q url.Values, accept string) (*http.Response, error) {
	u := *c.Base
	u.Path, u.RawQuery = path, q.Encode()
	return c.Send(ctx, method, &u, accept, "", nil, 0)
}

// Send is Do for any URL on the registry (upload locations are absolute)
// and with an optional body. A body cannot be sent twice, so callers get
// the token first with a body-less request in the same scope.
func (c *Client) Send(ctx context.Context, method string, u *url.URL, accept, contentType string, body io.Reader, size int64) (*http.Response, error) {
	scope := scopeFor(u.Path, method)
	// credentials go only to this registry, over its own scheme (never
	// downgraded to http), whatever an upload Location says
	sameHost := u.Scheme == c.Base.Scheme && hostPort(u) == hostPort(c.Base)
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.ContentLength = size
		}
		req.Header.Set("User-Agent", "komando")
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		c.mu.Lock()
		tok := c.tokens[scope]
		c.mu.Unlock()
		switch {
		case !sameHost:
		case tok != "":
			req.Header.Set("Authorization", "Bearer "+tok)
		case c.User != "":
			req.SetBasicAuth(c.User, c.Password)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == 401 && attempt == 0 && body == nil {
			challenge := resp.Header.Get("WWW-Authenticate")
			resp.Body.Close()
			if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
				return nil, &Error{Status: 401, Code: "UNAUTHORIZED", Message: "wrong user name or password"}
			}
			t, err := c.token(ctx, challenge, scope)
			if err != nil {
				return nil, err
			}
			c.mu.Lock()
			c.tokens[scope] = t
			c.mu.Unlock()
			continue
		}
		if resp.StatusCode >= 300 {
			defer resp.Body.Close()
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			var e struct {
				Errors []struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"errors"`
			}
			re := &Error{Status: resp.StatusCode, Code: http.StatusText(resp.StatusCode)}
			if json.Unmarshal(b, &e) == nil && len(e.Errors) > 0 {
				re.Code, re.Message = e.Errors[0].Code, e.Errors[0].Message
			}
			return nil, re
		}
		return resp, nil
	}
	return nil, &Error{Status: 401, Code: "UNAUTHORIZED", Message: "the registry refused the token"}
}

// hostPort is u's host with the scheme's default port made explicit, so
// "ghcr.io" and "ghcr.io:443" are the same place.
func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return strings.ToLower(u.Host)
	}
	port := "443"
	if u.Scheme == "http" {
		port = "80"
	}
	return strings.ToLower(net.JoinHostPort(u.Hostname(), port))
}

// scopeFor is the token scope a path needs: repository:NAME:pull (push for
// uploads, delete for deletes), or registry:catalog:*.
func scopeFor(path, method string) string {
	if path == "/v2/_catalog" {
		return "registry:catalog:*"
	}
	rest := strings.TrimPrefix(path, "/v2/")
	for _, sep := range []string{"/manifests/", "/tags/list", "/blobs/"} {
		if i := strings.Index(rest, sep); i > 0 {
			action := "pull"
			switch method {
			case "DELETE":
				action = "delete"
			case "POST", "PUT", "PATCH":
				action = "pull,push"
			}
			return "repository:" + rest[:i] + ":" + action
		}
	}
	return ""
}

// token gets a bearer token from the realm in a WWW-Authenticate challenge.
func (c *Client) token(ctx context.Context, challenge, scope string) (string, error) {
	params := map[string]string{}
	for _, part := range splitParams(challenge[len("bearer "):]) {
		k, v, _ := strings.Cut(part, "=")
		params[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Host == "" {
		return "", fmt.Errorf("bad auth challenge %q", challenge)
	}
	if realm.Scheme != "https" && c.Base.Scheme == "https" {
		// the password would travel in clear to the token service
		return "", &Error{Status: 401, Code: "UNAUTHORIZED", Message: "the registry's token service is not https: " + realm.String()}
	}
	q := realm.Query()
	if params["service"] != "" {
		q.Set("service", params["service"])
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", realm.String(), nil)
	if err != nil {
		return "", err
	}
	if c.User != "" {
		req.SetBasicAuth(c.User, c.Password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", &Error{Status: resp.StatusCode, Code: "UNAUTHORIZED", Message: "the token service refused the login"}
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return "", err
	}
	if t.Token == "" {
		t.Token = t.AccessToken
	}
	return t.Token, nil
}

// splitParams splits a,b="x,y",c on commas outside quotes.
func splitParams(s string) []string {
	var parts []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case r == ',' && !quoted:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(parts, cur.String())
}

func (c *Client) getJSON(ctx context.Context, path string, q url.Values, accept string, v any) (http.Header, error) {
	resp, err := c.Do(ctx, "GET", path, q, accept)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return resp.Header, json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(v)
}

// Ping checks that the registry answers and accepts the login (GET /v2/).
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.Do(ctx, "GET", "/v2/", nil, "")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Catalog lists repositories (registries like Docker Hub do not allow it).
func (c *Client) Catalog(ctx context.Context, limit int) ([]string, error) {
	return c.pages(ctx, "/v2/_catalog", "repositories", limit)
}

// Tags lists a repository's tags.
func (c *Client) Tags(ctx context.Context, repo string, limit int) ([]string, error) {
	return c.pages(ctx, "/v2/"+repo+"/tags/list", "tags", limit)
}

// pages reads a paged list, following the Link header, up to limit items.
func (c *Client) pages(ctx context.Context, path, field string, limit int) ([]string, error) {
	var all []string
	q := url.Values{"n": {fmt.Sprint(min(limit, 1000))}}
	for len(all) < limit {
		var r map[string]json.RawMessage
		h, err := c.getJSON(ctx, path, q, "", &r)
		if err != nil {
			return nil, err
		}
		var items []string
		if raw, ok := r[field]; ok && string(raw) != "null" {
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, err
			}
		}
		all = append(all, items...)
		next := nextLink(h.Get("Link"))
		if next == nil || len(items) == 0 {
			break
		}
		path, q = next.Path, next.Query()
	}
	sort.Strings(all) // the API promises lexical order; not every registry keeps it
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

func nextLink(h string) *url.URL {
	if h == "" || !strings.Contains(h, `rel="next"`) {
		return nil
	}
	start, end := strings.Index(h, "<"), strings.Index(h, ">")
	if start < 0 || end < start {
		return nil
	}
	u, err := url.Parse(h[start+1 : end])
	if err != nil {
		return nil
	}
	return u
}

// Manifest is what `registry inspect` shows.
type Manifest struct {
	Repo      string            `json:"repo"`
	Ref       string            `json:"ref"`
	Digest    string            `json:"digest"`
	MediaType string            `json:"media_type"`
	Size      int64             `json:"size,omitempty"` // layers, compressed
	Layers    int               `json:"layers,omitempty"`
	Platforms []string          `json:"platforms,omitempty"`
	Created   string            `json:"created,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Inspect reads a manifest (or index) and, for one image, its config.
func (c *Client) Inspect(ctx context.Context, repo, ref string) (*Manifest, error) {
	var m struct {
		MediaType string `json:"mediaType"`
		Config    struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Size int64 `json:"size"`
		} `json:"layers"`
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Variant      string `json:"variant"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	h, err := c.getJSON(ctx, "/v2/"+repo+"/manifests/"+ref, nil, Accept, &m)
	if err != nil {
		return nil, err
	}
	res := &Manifest{Repo: repo, Ref: ref, Digest: h.Get("Docker-Content-Digest"), MediaType: firstNonEmpty(m.MediaType, h.Get("Content-Type"))}
	first := ""
	for _, p := range m.Manifests {
		if p.Platform.OS == "unknown" {
			continue // attestations
		}
		if first == "" {
			first = p.Digest
		}
		s := p.Platform.OS + "/" + p.Platform.Architecture
		if p.Platform.Variant != "" {
			s += "/" + p.Platform.Variant
		}
		res.Platforms = append(res.Platforms, s)
	}
	for _, l := range m.Layers {
		res.Size += l.Size
	}
	res.Layers = len(m.Layers)
	if m.Config.Digest != "" {
		var cfg struct {
			Created string `json:"created"`
			OS      string `json:"os"`
			Arch    string `json:"architecture"`
			Config  struct {
				Labels map[string]string `json:"Labels"`
			} `json:"config"`
		}
		if _, err := c.getJSON(ctx, "/v2/"+repo+"/blobs/"+m.Config.Digest, nil, "", &cfg); err == nil {
			res.Created, res.Labels = cfg.Created, cfg.Config.Labels
			if cfg.OS != "" {
				res.Platforms = []string{cfg.OS + "/" + cfg.Arch}
			}
		}
	}
	if res.Created == "" && first != "" && first != ref {
		// an index: the build date and labels of its first image
		if one, err := c.Inspect(ctx, repo, first); err == nil {
			res.Created, res.Labels = one.Created, one.Labels
		}
	}
	return res, nil
}

// Delete removes a manifest by digest. Every tag pointing at it goes too.
func (c *Client) Delete(ctx context.Context, repo, digest string) error {
	resp, err := c.Do(ctx, "DELETE", "/v2/"+repo+"/manifests/"+digest, nil, "")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
