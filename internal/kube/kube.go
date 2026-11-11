// Package kube talks to the Kubernetes API directly over HTTPS, from one
// kubeconfig context, without client-go. It covers what komando's cluster
// commands need: discovery, get/list, logs, patch, server-side apply, and
// exec and port-forward over WebSocket (stream.go).
package kube

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/proxyx"
)

// Config is the part of a kubeconfig komando uses.
type Config struct {
	CurrentContext string         `yaml:"current-context"`
	Clusters       []NamedCluster `yaml:"clusters"`
	Users          []NamedUser    `yaml:"users"`
	Contexts       []NamedContext `yaml:"contexts"`
}

type NamedCluster struct {
	Name    string  `yaml:"name"`
	Cluster Cluster `yaml:"cluster"`
}

type NamedUser struct {
	Name string   `yaml:"name"`
	User AuthInfo `yaml:"user"`
}

type NamedContext struct {
	Name    string `yaml:"name"`
	Context struct {
		Cluster   string `yaml:"cluster"`
		User      string `yaml:"user"`
		Namespace string `yaml:"namespace,omitempty"`
	} `yaml:"context"`
}

type Cluster struct {
	Server                   string `yaml:"server"`
	CertificateAuthority     string `yaml:"certificate-authority,omitempty"`
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify,omitempty"`
	TLSServerName            string `yaml:"tls-server-name,omitempty"`
	ProxyURL                 string `yaml:"proxy-url,omitempty"`
}

type AuthInfo struct {
	ClientCertificate     string    `yaml:"client-certificate,omitempty"`
	ClientCertificateData string    `yaml:"client-certificate-data,omitempty"`
	ClientKey             string    `yaml:"client-key,omitempty"`
	ClientKeyData         string    `yaml:"client-key-data,omitempty"`
	Token                 string    `yaml:"token,omitempty"`
	TokenFile             string    `yaml:"tokenFile,omitempty"`
	Username              string    `yaml:"username,omitempty"`
	Password              string    `yaml:"password,omitempty"`
	Exec                  *ExecAuth `yaml:"exec,omitempty"`
}

// ExecAuth is a credential plugin (aws eks get-token, gke-gcloud-auth-plugin, ...).
type ExecAuth struct {
	APIVersion string   `yaml:"apiVersion,omitempty"`
	Command    string   `yaml:"command"`
	Args       []string `yaml:"args,omitempty"`
	Env        []struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	} `yaml:"env,omitempty"`
}

// Context is one resolved kubeconfig context.
type Context struct {
	Name      string
	Cluster   Cluster
	User      AuthInfo
	Namespace string
}

// Plugin is the credential plugin that logging in to this context runs as
// a program on this computer, or nil: none, a static token, or one of the
// plugins komando makes the token for itself (Builtin).
func (x *Context) Plugin() *ExecAuth {
	e := x.User.Exec
	if e == nil || x.User.Token != "" || e.Builtin() {
		return nil
	}
	return e
}

// Builtin reports whether komando makes this plugin's token itself
// (builtinToken), so its command never runs.
func (e *ExecAuth) Builtin() bool {
	switch filepath.Base(e.Command) {
	case "aws":
		return slices.Contains(e.Args, "eks") && slices.Contains(e.Args, "get-token")
	case "aws-iam-authenticator":
		return execArg(e.Args, "-i", "--cluster-id") != ""
	case "gke-gcloud-auth-plugin":
		return true
	}
	return false
}

// execArg is the value of the first of names in a plugin's args
// (--name value or --name=value).
func execArg(args []string, names ...string) string {
	for i, a := range args {
		for _, n := range names {
			if a == n && i+1 < len(args) {
				return args[i+1]
			}
			if strings.HasPrefix(a, n+"=") {
				return strings.TrimPrefix(a, n+"=")
			}
		}
	}
	return ""
}

// Parse reads a kubeconfig.
func Parse(b []byte) (*Config, error) {
	c, err := parse(b)
	if err != nil {
		return nil, err
	}
	if len(c.Contexts) == 0 {
		return nil, fmt.Errorf("the kubeconfig has no contexts")
	}
	return c, nil
}

func parse(b []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("not a kubeconfig: %w", err)
	}
	return &c, nil
}

// Load reads kubeconfig files the way kubectl reads a KUBECONFIG list:
// the first file that names a context, cluster or user wins, and so does
// the first current-context. Relative file paths in a file (a minikube or
// kind certificate) count from that file's folder, not the current one.
// read reads one file; "-" is stdin and keeps paths as they are.
func Load(read func(path string) ([]byte, error), paths ...string) (*Config, error) {
	all := &Config{}
	for _, p := range paths {
		b, err := read(p)
		if err != nil {
			return nil, err
		}
		c, err := parse(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if p != "-" {
			if abs, err := filepath.Abs(p); err == nil {
				c.absPaths(filepath.Dir(abs))
			}
		}
		all.merge(c)
	}
	if len(all.Contexts) == 0 {
		return nil, fmt.Errorf("the kubeconfig has no contexts")
	}
	return all, nil
}

// absPaths makes the relative file paths in c count from dir.
func (c *Config) absPaths(dir string) {
	fix := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) && !strings.HasPrefix(*p, "~/") {
			*p = filepath.Join(dir, *p)
		}
	}
	for i := range c.Clusters {
		fix(&c.Clusters[i].Cluster.CertificateAuthority)
	}
	for i := range c.Users {
		u := &c.Users[i].User
		fix(&u.ClientCertificate)
		fix(&u.ClientKey)
		fix(&u.TokenFile)
	}
}

// merge adds what o names and c does not yet.
func (c *Config) merge(o *Config) {
	if c.CurrentContext == "" {
		c.CurrentContext = o.CurrentContext
	}
	for _, x := range o.Clusters {
		if !slices.ContainsFunc(c.Clusters, func(y NamedCluster) bool { return y.Name == x.Name }) {
			c.Clusters = append(c.Clusters, x)
		}
	}
	for _, x := range o.Users {
		if !slices.ContainsFunc(c.Users, func(y NamedUser) bool { return y.Name == x.Name }) {
			c.Users = append(c.Users, x)
		}
	}
	for _, x := range o.Contexts {
		if !slices.ContainsFunc(c.Contexts, func(y NamedContext) bool { return y.Name == x.Name }) {
			c.Contexts = append(c.Contexts, x)
		}
	}
}

// ContextNames lists the context names in file order.
func (c *Config) ContextNames() []string {
	var n []string
	for _, x := range c.Contexts {
		n = append(n, x.Name)
	}
	return n
}

// Resolve finds a context ("" = the current one) and its cluster and user.
func (c *Config) Resolve(name string) (*Context, error) {
	if name == "" {
		name = c.CurrentContext
	}
	if name == "" && len(c.Contexts) == 1 {
		name = c.Contexts[0].Name
	}
	for _, x := range c.Contexts {
		if x.Name != name {
			continue
		}
		ctx := &Context{Name: name, Namespace: x.Context.Namespace}
		found := false
		for _, cl := range c.Clusters {
			if cl.Name == x.Context.Cluster {
				ctx.Cluster, found = cl.Cluster, true
			}
		}
		if !found {
			return nil, fmt.Errorf("context %s: cluster %s not found", name, x.Context.Cluster)
		}
		for _, u := range c.Users {
			if u.Name == x.Context.User {
				ctx.User = u.User
			}
		}
		return ctx, nil
	}
	return nil, fmt.Errorf("context %q not found", name)
}

// Standalone returns a kubeconfig with only this context, files read into
// the *-data fields, so it can live in the vault and travel.
func (x *Context) Standalone() ([]byte, error) {
	inline := func(path, data *string) error {
		if *path == "" {
			return nil
		}
		b, err := os.ReadFile(expandHome(*path))
		if err != nil {
			return err
		}
		*data, *path = base64.StdEncoding.EncodeToString(b), ""
		return nil
	}
	cl, u := x.Cluster, x.User
	if err := inline(&cl.CertificateAuthority, &cl.CertificateAuthorityData); err != nil {
		return nil, err
	}
	if err := inline(&u.ClientCertificate, &u.ClientCertificateData); err != nil {
		return nil, err
	}
	if err := inline(&u.ClientKey, &u.ClientKeyData); err != nil {
		return nil, err
	}
	if u.TokenFile != "" {
		b, err := os.ReadFile(expandHome(u.TokenFile))
		if err != nil {
			return nil, err
		}
		u.Token, u.TokenFile = strings.TrimSpace(string(b)), ""
	}
	doc := map[string]any{
		"apiVersion":      "v1",
		"kind":            "Config",
		"current-context": x.Name,
		"clusters":        []any{map[string]any{"name": x.Name, "cluster": cl}},
		"users":           []any{map[string]any{"name": x.Name, "user": u}},
		"contexts": []any{map[string]any{"name": x.Name, "context": map[string]any{
			"cluster": x.Name, "user": x.Name, "namespace": x.Namespace}}},
	}
	return yaml.Marshal(doc)
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		h, _ := os.UserHomeDir()
		return h + p[1:]
	}
	return p
}

// DialTimeout limits a direct connection to the API server; without it an
// address that never answers waits for the system's own limit (75 s and more).
const DialTimeout = 30 * time.Second

// Dialer opens TCP connections, possibly through a --via path.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Client calls one cluster's API.
type Client struct {
	Base      *url.URL
	Namespace string
	http      *http.Client
	ctx       *Context
	mu        sync.Mutex
	token     string
	discovery map[string]ResourceType // "group/version/Kind" -> ResourceType
}

// New builds a client for a context. dial may be nil (direct).
func New(x *Context, dial Dialer) (*Client, error) {
	base, err := url.Parse(x.Cluster.Server)
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("bad server URL %q", x.Cluster.Server)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: x.Cluster.TLSServerName,
		InsecureSkipVerify: x.Cluster.InsecureSkipTLSVerify} //nolint:gosec // only when the kubeconfig says so
	if d := x.Cluster.CertificateAuthorityData; d != "" {
		pem, err := base64.StdEncoding.DecodeString(d)
		if err != nil {
			return nil, fmt.Errorf("certificate-authority-data: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("certificate-authority-data holds no certificate")
		}
		tc.RootCAs = pool
	}
	if x.User.ClientCertificateData != "" {
		crt, err1 := base64.StdEncoding.DecodeString(x.User.ClientCertificateData)
		key, err2 := base64.StdEncoding.DecodeString(x.User.ClientKeyData)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("client certificate or key is not base64")
		}
		pair, err := tls.X509KeyPair(crt, key)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	}
	pick := proxyx.FromEnv() // HTTPS_PROXY and NO_PROXY, as kubectl reads them
	if p := x.Cluster.ProxyURL; p != "" {
		u, err := proxyx.Parse(p)
		if err != nil {
			return nil, fmt.Errorf("proxy-url: %w", err)
		}
		pick = http.ProxyURL(u)
	}
	tr := &http.Transport{TLSClientConfig: tc, TLSHandshakeTimeout: 15 * time.Second, ForceAttemptHTTP2: true, Proxy: pick,
		DialContext: (&net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second}).DialContext}
	if dial != nil {
		tr.DialContext = dial
		tr.Proxy = nil // the --via path is the way out
	}
	ns := x.Namespace
	if ns == "" {
		ns = "default"
	}
	return &Client{Base: base, Namespace: ns, http: &http.Client{Transport: tr}, ctx: x, token: x.User.Token}, nil
}

// APIError is an error status from the API server.
type APIError struct {
	Code    int
	Reason  string
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("%s (%d): %s", e.Reason, e.Code, e.Message) }

func (c *Client) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" || c.ctx.User.Exec == nil {
		return c.token, nil
	}
	e := c.ctx.User.Exec
	if tok, ok, err := builtinToken(ctx, e); ok {
		if err != nil {
			return "", err
		}
		c.token = tok
		return tok, nil
	}
	cmd := exec.CommandContext(ctx, e.Command, e.Args...)
	cmd.Env = os.Environ()
	for _, kv := range e.Env {
		cmd.Env = append(cmd.Env, kv.Name+"="+kv.Value)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("credential plugin %s: %v %s", e.Command, err, strings.TrimSpace(stderr.String()))
	}
	var cred struct {
		Status struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	if err := json.Unmarshal(b, &cred); err != nil || cred.Status.Token == "" {
		return "", fmt.Errorf("credential plugin %s gave no token", e.Command)
	}
	c.token = cred.Status.Token
	return c.token, nil
}

// Do sends a request; path is relative to the server ("/api/v1/...").
func (c *Client) Do(ctx context.Context, method, path string, q url.Values, body []byte, contentType string) ([]byte, error) {
	resp, err := c.send(ctx, method, path, q, body, contentType)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// Stream sends a GET and returns the body as it arrives (follow=true logs).
// The caller closes it.
func (c *Client) Stream(ctx context.Context, path string, q url.Values) (io.ReadCloser, error) {
	resp, err := c.send(ctx, "GET", path, q, nil, "")
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// send makes the request with the context's credentials. Error statuses
// come back as *APIError with the body already read and closed.
func (c *Client) send(ctx context.Context, method, path string, q url.Values, body []byte, contentType string) (*http.Response, error) {
	return c.sendAccept(ctx, method, path, q, body, contentType, "application/json")
}

func (c *Client) sendAccept(ctx context.Context, method, path string, q url.Values, body []byte, contentType, accept string) (*http.Response, error) {
	u := *c.Base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "komando")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	tok, err := c.bearer(ctx)
	if err != nil {
		return nil, err
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	} else if c.ctx.User.Username != "" {
		req.SetBasicAuth(c.ctx.User.Username, c.ctx.User.Password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var st struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &st)
		if st.Message == "" {
			st.Message = strings.TrimSpace(string(b))
		}
		if st.Reason == "" {
			st.Reason = http.StatusText(resp.StatusCode)
		}
		return nil, &APIError{Code: resp.StatusCode, Reason: st.Reason, Message: st.Message}
	}
	return resp, nil
}

// Get decodes a GET into v.
func (c *Client) Get(ctx context.Context, path string, q url.Values, v any) error {
	b, err := c.Do(ctx, "GET", path, q, nil, "")
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Discovery of resource types.

type ResourceType struct {
	Path       string // "/api/v1" or "/apis/apps/v1"
	Name       string // plural: deployments
	Kind       string
	Namespaced bool
	ShortNames []string
}

func (c *Client) discover(ctx context.Context) error {
	if c.discovery != nil {
		return nil
	}
	c.discovery = map[string]ResourceType{}
	add := func(gvPath, gv string) {
		var list struct {
			Resources []struct {
				Name       string   `json:"name"`
				Kind       string   `json:"kind"`
				Namespaced bool     `json:"namespaced"`
				ShortNames []string `json:"shortNames"`
			} `json:"resources"`
		}
		if c.Get(ctx, gvPath, nil, &list) != nil {
			return
		}
		for _, r := range list.Resources {
			if strings.Contains(r.Name, "/") {
				continue // subresources
			}
			res := ResourceType{Path: gvPath, Name: r.Name, Kind: r.Kind, Namespaced: r.Namespaced, ShortNames: r.ShortNames}
			c.discovery[gv+"/"+r.Kind] = res
			group, version, grouped := strings.Cut(gv, "/")
			for _, alias := range append([]string{r.Name, strings.ToLower(r.Kind)}, r.ShortNames...) {
				keys := []string{"name:" + alias}
				if grouped { // deployment.apps, deployments.v1.apps
					keys = append(keys, "name:"+alias+"."+group, "name:"+alias+"."+version+"."+group)
				}
				for _, k := range keys {
					if _, taken := c.discovery[k]; !taken {
						c.discovery[k] = res
					}
				}
			}
		}
	}
	add("/api/v1", "v1")
	var groups struct {
		Groups []struct {
			PreferredVersion struct {
				GroupVersion string `json:"groupVersion"`
			} `json:"preferredVersion"`
		} `json:"groups"`
	}
	if err := c.Get(ctx, "/apis", nil, &groups); err != nil {
		c.discovery = nil // ask again next time, not an empty list
		return err
	}
	for _, g := range groups.Groups {
		gv := g.PreferredVersion.GroupVersion
		add("/apis/"+gv, gv)
	}
	return nil
}

// Resource finds a ResourceType by a name people type: "pods", "pod", "po",
// "deploy" or "deployments.apps".
func (c *Client) Resource(ctx context.Context, name string) (ResourceType, error) {
	if err := c.discover(ctx); err != nil {
		return ResourceType{}, err
	}
	if r, ok := c.discovery["name:"+strings.ToLower(name)]; ok {
		return r, nil
	}
	var known []string
	for k := range c.discovery {
		if a, ok := strings.CutPrefix(k, "name:"); ok {
			known = append(known, a)
		}
	}
	return ResourceType{}, &UnknownKindError{Kind: name, Suggest: Nearest(strings.ToLower(name), known)}
}

// UnknownKindError is a kind the cluster does not serve. APIVersion is
// set for an object's apiVersion and kind (ResourceFor).
type UnknownKindError struct {
	Kind       string
	APIVersion string
	Suggest    string
}

func (e *UnknownKindError) Error() string {
	if e.APIVersion != "" {
		return fmt.Sprintf("the cluster does not serve %s %s", e.APIVersion, e.Kind)
	}
	if e.Suggest != "" {
		return fmt.Sprintf("unknown kind %q; did you mean %q?", e.Kind, e.Suggest)
	}
	return fmt.Sprintf("unknown kind %q", e.Kind)
}

// Nearest is the word in known closest to w, or "" when none is close
// (more than a third of its letters differ).
func Nearest(w string, known []string) string {
	best, bestD := "", len(w)/3+2
	sort.Strings(known)
	for _, k := range known {
		if d := distance(w, k); d < bestD || (d == bestD && best != "" && len(k) < len(best)) {
			best, bestD = k, d
		}
	}
	return best
}

// distance is the Levenshtein edit distance.
func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

// ResourceFor finds the ResourceType of an object (apiVersion + kind).
func (c *Client) ResourceFor(ctx context.Context, apiVersion, kind string) (ResourceType, error) {
	if err := c.discover(ctx); err != nil {
		return ResourceType{}, err
	}
	if r, ok := c.discovery[apiVersion+"/"+kind]; ok {
		return r, nil
	}
	return ResourceType{}, &UnknownKindError{Kind: kind, APIVersion: apiVersion}
}

// ObjectPath is the API path of a ResourceType (all namespaces when ns is "").
func (r ResourceType) ObjectPath(ns, name string) string {
	p := r.Path
	if r.Namespaced && ns != "" {
		p += "/namespaces/" + url.PathEscape(ns)
	}
	p += "/" + r.Name
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	return p
}

func (r ResourceType) IsNamespaced() bool { return r.Namespaced }
func (r ResourceType) KindName() string   { return r.Kind }

// builtinToken makes the tokens of the common credential plugins without
// running them: `aws eks get-token`, aws-iam-authenticator and
// gke-gcloud-auth-plugin. ok is false for any other plugin, which then runs
// as the kubeconfig says.
func builtinToken(ctx context.Context, e *ExecAuth) (tok string, ok bool, err error) {
	if !e.Builtin() {
		return "", false, nil
	}
	env := map[string]string{}
	for _, kv := range e.Env {
		env[kv.Name] = kv.Value
	}
	arg := func(names ...string) string { return execArg(e.Args, names...) }
	profile := cmp.Or(arg("--profile"), env["AWS_PROFILE"], os.Getenv("AWS_PROFILE"))
	switch filepath.Base(e.Command) {
	case "aws":
		cluster := arg("--cluster-name", "--cluster-id")
		if cluster == "" {
			return "", true, errors.New("aws eks get-token in the kubeconfig names no --cluster-name")
		}
		tok, err := cloud.EKSToken(ctx, profile, cmp.Or(arg("--region"), env["AWS_REGION"], env["AWS_DEFAULT_REGION"]), cluster, arg("--role-arn"))
		return tok, true, err
	case "aws-iam-authenticator":
		tok, err := cloud.EKSToken(ctx, profile, cmp.Or(arg("--region"), env["AWS_REGION"]), arg("-i", "--cluster-id"), arg("-r", "--role"))
		return tok, true, err
	case "gke-gcloud-auth-plugin":
		tok, err := cloud.GCPAccessToken(ctx)
		return tok, true, err
	}
	return "", false, nil
}

// Table is the server-side table the API prints for a list or an object,
// the same columns kubectl shows.
type Table struct {
	ColumnDefinitions []struct {
		Name     string `json:"name"`
		Priority int    `json:"priority"`
	} `json:"columnDefinitions"`
	Rows []struct {
		Cells  []any `json:"cells"`
		Object struct {
			Metadata struct {
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		} `json:"object"`
	} `json:"rows"`
}

// Table asks for path as a table (with each row's metadata).
func (c *Client) Table(ctx context.Context, path string, q url.Values) (*Table, error) {
	if q == nil {
		q = url.Values{}
	}
	q.Set("includeObject", "Metadata")
	resp, err := c.sendAccept(ctx, "GET", path, q, nil, "", "application/json;as=Table;v=v1;g=meta.k8s.io,application/json;as=Table;v=v1beta1;g=meta.k8s.io,application/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var t Table
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Group is the API group of r ("" for the core group, "apps", ...).
func (r ResourceType) Group() string {
	p := strings.TrimPrefix(r.Path, "/apis/")
	if p == r.Path {
		return ""
	}
	g, _, _ := strings.Cut(p, "/")
	return g
}

// Version is r's API version ("v1", ...).
func (r ResourceType) Version() string {
	return r.Path[strings.LastIndex(r.Path, "/")+1:]
}

// APIVersion is what objects of r carry in apiVersion ("v1", "apps/v1").
func (r ResourceType) APIVersion() string {
	if g := r.Group(); g != "" {
		return g + "/" + r.Version()
	}
	return r.Version()
}

// Resources lists every resource type the cluster serves, once each.
func (c *Client) Resources(ctx context.Context) ([]ResourceType, error) {
	if err := c.discover(ctx); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []ResourceType
	for k, r := range c.discovery {
		if strings.HasPrefix(k, "name:") || seen[r.Path+"/"+r.Name] {
			continue
		}
		seen[r.Path+"/"+r.Name] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

// Watch streams change events (one JSON object per line) for path.
func (c *Client) Watch(ctx context.Context, path string, q url.Values) (io.ReadCloser, error) {
	if q == nil {
		q = url.Values{}
	}
	q.Set("watch", "true")
	return c.Stream(ctx, path, q)
}
