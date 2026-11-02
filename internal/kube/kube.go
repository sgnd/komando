// Package kube talks to the Kubernetes API directly over HTTPS, from one
// kubeconfig context, without client-go. It covers what komando's cluster
// commands need: discovery, get/list, logs, patch and server-side apply.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the part of a kubeconfig komando uses.
type Config struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string  `yaml:"name"`
		Cluster Cluster `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string   `yaml:"name"`
		User AuthInfo `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace,omitempty"`
		} `yaml:"context"`
	} `yaml:"contexts"`
}

type Cluster struct {
	Server                   string `yaml:"server"`
	CertificateAuthority     string `yaml:"certificate-authority,omitempty"`
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify,omitempty"`
	TLSServerName            string `yaml:"tls-server-name,omitempty"`
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

// Parse reads a kubeconfig.
func Parse(b []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("not a kubeconfig: %w", err)
	}
	if len(c.Contexts) == 0 {
		return nil, fmt.Errorf("the kubeconfig has no contexts")
	}
	return &c, nil
}

// Contexts lists the context names in file order.
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
	tr := &http.Transport{TLSClientConfig: tc, TLSHandshakeTimeout: 15 * time.Second, ForceAttemptHTTP2: true}
	if dial != nil {
		tr.DialContext = dial
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
	u := *c.Base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
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

// --- discovery -------------------------------------------------------------

type ResourceType struct {
	Path       string // "/api/v1" or "/apis/apps/v1"
	Name       string // plural: deployments
	Kind       string
	Namespaced bool
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
			res := ResourceType{Path: gvPath, Name: r.Name, Kind: r.Kind, Namespaced: r.Namespaced}
			c.discovery[gv+"/"+r.Kind] = res
			for _, alias := range append([]string{r.Name, strings.ToLower(r.Kind)}, r.ShortNames...) {
				if _, taken := c.discovery["name:"+alias]; !taken {
					c.discovery["name:"+alias] = res
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
		return err
	}
	for _, g := range groups.Groups {
		gv := g.PreferredVersion.GroupVersion
		add("/apis/"+gv, gv)
	}
	return nil
}

// Resource finds a ResourceType by a name people type: "pods", "pod", "po",
// "deploy", "deployments.apps" is not needed.
func (c *Client) Resource(ctx context.Context, name string) (ResourceType, error) {
	if err := c.discover(ctx); err != nil {
		return ResourceType{}, err
	}
	if r, ok := c.discovery["name:"+strings.ToLower(name)]; ok {
		return r, nil
	}
	return ResourceType{}, fmt.Errorf("the cluster has no ResourceType type %q", name)
}

// ResourceFor finds the ResourceType of an object (apiVersion + kind).
func (c *Client) ResourceFor(ctx context.Context, apiVersion, kind string) (ResourceType, error) {
	if err := c.discover(ctx); err != nil {
		return ResourceType{}, err
	}
	if r, ok := c.discovery[apiVersion+"/"+kind]; ok {
		return r, nil
	}
	return ResourceType{}, fmt.Errorf("the cluster does not serve %s %s", apiVersion, kind)
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
