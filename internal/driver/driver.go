// Package driver describes the kinds of non-SSH resources komando can talk
// to (databases, caches, object storage) and the risk levels its safety
// checks work with.
package driver

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// Risk says how much an operation can change. The safety check (guard)
// decides from it whether --yes or --allow-dangerous is needed.
type Risk int

const (
	RiskRead        Risk = iota // changes nothing
	RiskWrite                   // changes data
	RiskDestructive             // hard or impossible to undo
)

func (r Risk) String() string {
	switch r {
	case RiskRead:
		return "read"
	case RiskWrite:
		return "write"
	case RiskDestructive:
		return "destructive"
	}
	return "unknown"
}

func (r Risk) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// Verdict is the result of classifying one operation.
type Verdict struct {
	Risk    Risk     `json:"risk"`
	RuleIDs []string `json:"rules,omitempty"` // matched rules, for error messages
	Reasons []string `json:"reasons,omitempty"`
}

// Kind is a resource type komando knows.
type Kind struct {
	Name        string   `json:"name"`
	Family      string   `json:"family"` // the command that works with it: db | cache | storage | cluster | registry
	Schemes     []string `json:"schemes"`
	DefaultPort int      `json:"default_port,omitempty"`
	File        bool     `json:"file,omitempty"` // a local file, not a network service
	Example     string   `json:"example"`
}

var kinds = map[string]Kind{}

func register(k Kind) { kinds[k.Name] = k }

func init() {
	register(Kind{Name: "postgres", Family: "db", Schemes: []string{"postgres", "postgresql"}, DefaultPort: 5432,
		Example: "postgres://app@10.0.0.5:5432/app?sslmode=require"})
	register(Kind{Name: "mysql", Family: "db", Schemes: []string{"mysql", "mariadb"}, DefaultPort: 3306,
		Example: "mysql://shop@db.internal:3306/shop?tls=true"})
	register(Kind{Name: "sqlite", Family: "db", Schemes: []string{"sqlite", "sqlite3"}, File: true,
		Example: "sqlite:///var/lib/app.db"})
	register(Kind{Name: "redis", Family: "cache", Schemes: []string{"redis", "rediss"}, DefaultPort: 6379,
		Example: "rediss://default@cache.internal:6379/0 (rediss = TLS)"})
	register(Kind{Name: "memcached", Family: "cache", Schemes: []string{"memcached", "memcacheds"}, DefaultPort: 11211,
		Example: "memcached://cache.internal:11211 (memcacheds = TLS)"})
	register(Kind{Name: "k8s", Family: "cluster", Schemes: []string{"k8s", "kubernetes"}, DefaultPort: 6443,
		Example: "k8s://api.cluster.example:6443 (the kubeconfig goes to the vault: `komando import kubeconfig`)"})
	register(Kind{Name: "registry", Family: "registry", Schemes: []string{"registry", "oci"}, DefaultPort: 443,
		Example: "registry://myuser@ghcr.io (Docker Hub: registry://myuser@docker.io; no TLS: ?tls=false)"})
	register(Kind{Name: "s3", Family: "storage", Schemes: []string{"s3"},
		Example: "s3://ACCESS_KEY_ID@my-bucket/backups?endpoint=https://minio.internal:9000&region=us-east-1"})
	register(Kind{Name: "ftps", Family: "storage", Schemes: []string{"ftps"}, DefaultPort: 21,
		Example: "ftps://deploy@files.example.com/public_html (FTP with TLS; ?tls=skip-verify for self-signed)"})
	register(Kind{Name: "ftp", Family: "storage", Schemes: []string{"ftp"}, DefaultPort: 21,
		Example: "ftp://deploy@files.example.com/www?insecure=1 (no encryption: prefer ftps or sftp)"})
	register(Kind{Name: "sftp", Family: "storage", Schemes: []string{"sftp"}, DefaultPort: 22,
		Example: "sftp://deploy@files.example.com/uploads (file access only, no shell)"})
}

// Lookup returns the kind with this name.
func Lookup(name string) (Kind, bool) {
	k, ok := kinds[name]
	return k, ok
}

// Kinds lists the known kinds, sorted by name.
func Kinds() []Kind {
	res := make([]Kind, 0, len(kinds))
	for _, k := range kinds {
		res = append(res, k)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res
}

func kindNames() string {
	var n []string
	for _, k := range Kinds() {
		n = append(n, k.Name)
	}
	return strings.Join(n, ", ")
}

// Target is a parsed conn URL.
type Target struct {
	Kind     Kind   `json:"kind"`
	Address  string `json:"address,omitempty"`  // host:port for network kinds (s3: the endpoint)
	Path     string `json:"path,omitempty"`     // file path for file kinds
	User     string `json:"user,omitempty"`     // s3: the access key ID (not secret)
	Database string `json:"database,omitempty"` // SQL database name, or redis DB number
	Bucket   string `json:"bucket,omitempty"`   // s3
	Prefix   string `json:"prefix,omitempty"`   // storage: keys are relative to this folder
	Region   string `json:"region,omitempty"`   // s3
	Secure   bool   `json:"secure,omitempty"`   // TLS (rediss, https endpoint)
	TLS      string `json:"tls,omitempty"`      // mysql: the tls= setting (true, skip-verify, preferred, false)
}

// Where is the address or path, for display.
func (t Target) Where() string {
	switch {
	case t.Kind.File:
		return t.Path
	case t.Bucket != "":
		return strings.TrimSuffix(t.Bucket+"/"+t.Prefix, "/") + " @ " + t.Address
	case t.Kind.Family == "storage":
		return t.Address + "/" + strings.TrimSuffix(t.Prefix, "/")
	}
	return t.Address
}

// passwordParams are query parameters that would carry a password or key.
var passwordParams = []string{"password", "pass", "pwd", "sslpassword", "secret", "secret_key", "secretkey", "aws_secret_access_key"}

// Parse reads a conn URL such as postgres://app@db.internal:5432/app or
// sqlite:///var/lib/app.db. The kind comes from the scheme. URLs that carry
// a password are refused: passwords belong in the vault.
func Parse(raw string) (Target, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" {
		return Target{}, out.Usage("invalid conn URL %q (expected e.g. postgres://user@host:5432/db)", raw)
	}
	var k Kind
	found := false
	for _, c := range kinds {
		for _, s := range c.Schemes {
			if strings.EqualFold(u.Scheme, s) {
				k, found = c, true
			}
		}
	}
	if !found {
		return Target{}, out.Usage("unknown conn kind %q (known: %s)", u.Scheme, kindNames())
	}
	if _, has := u.User.Password(); has || hasPasswordParam(u.Query()) {
		return Target{}, out.Errf(out.ExitUsage, "URL_HAS_PASSWORD",
			"remove the password from the URL, store it with `komando secret set NAME`, then pass --password-ref secret:NAME",
			"conn URLs must not contain a password")
	}
	t := Target{Kind: k}
	if k.Name == "s3" {
		return parseS3(u, t)
	}
	if k.Name == "ftp" || k.Name == "ftps" || k.Name == "sftp" {
		return parseFiles(u, t)
	}
	if k.File {
		t.Path = u.Opaque
		if t.Path == "" {
			t.Path = u.Path
		}
		if t.Path == "" {
			return Target{}, out.Usage("%s URL needs a file path, e.g. %s:///var/lib/app.db", k.Name, u.Scheme)
		}
		return t, nil
	}
	if u.Hostname() == "" {
		return Target{}, out.Usage("%s URL needs a host, e.g. %s://user@host:%d/db", k.Name, u.Scheme, k.DefaultPort)
	}
	port := k.DefaultPort
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return Target{}, out.Usage("invalid port %q in conn URL", p)
		}
	}
	t.Address = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	t.User = u.User.Username()
	t.Database = strings.TrimPrefix(u.Path, "/")
	if k.Name == "mysql" || k.Name == "registry" {
		t.TLS = u.Query().Get("tls")
	}
	if k.Name == "memcached" {
		t.Secure = strings.EqualFold(u.Scheme, "memcacheds")
		if t.Database != "" {
			return Target{}, out.Usage("memcached has no databases: drop %q from the URL", "/"+t.Database)
		}
	}
	if k.Name == "redis" {
		t.Secure = strings.EqualFold(u.Scheme, "rediss")
		if t.Database == "" {
			t.Database = "0"
		}
		if n, err := strconv.Atoi(t.Database); err != nil || n < 0 {
			return Target{}, out.Usage("redis URL path must be a database number, e.g. redis://cache:6379/0")
		}
	}
	return t, nil
}

// parseFiles reads ftps://, ftp:// and sftp:// URLs. The path is the folder
// keys are relative to. Plain FTP sends the password unencrypted, so it
// needs ?insecure=1 to show that this is a deliberate choice.
func parseFiles(u *url.URL, t Target) (Target, error) {
	k := t.Kind
	if u.Hostname() == "" {
		return Target{}, out.Usage("%s URL needs a host, e.g. %s", k.Name, k.Example)
	}
	if u.User.Username() == "" {
		return Target{}, out.Usage("%s URL needs a user name, e.g. %s://deploy@host/folder", k.Name, u.Scheme)
	}
	port := k.DefaultPort
	if p := u.Port(); p != "" {
		var err error
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return Target{}, out.Usage("invalid port %q in conn URL", p)
		}
	}
	t.Address = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	t.User = u.User.Username()
	t.Prefix = strings.Trim(u.Path, "/")
	if t.Prefix != "" {
		t.Prefix += "/"
	}
	q := u.Query()
	for key := range q {
		switch {
		case key == "tls" && k.Name == "ftps", key == "insecure" && k.Name == "ftp":
		default:
			return Target{}, out.Usage("unknown %s URL option %q", k.Name, key)
		}
	}
	switch k.Name {
	case "ftp":
		if q.Get("insecure") != "1" {
			return Target{}, out.Errf(out.ExitUsage, "INSECURE_PROTOCOL",
				"use ftps:// (FTP with TLS) or sftp:// if the server supports it; otherwise add ?insecure=1 to accept that the password and files travel unencrypted",
				"plain FTP sends the password unencrypted")
		}
	case "ftps":
		t.Secure = true
		t.TLS = q.Get("tls")
		if t.TLS != "" && t.TLS != "skip-verify" {
			return Target{}, out.Usage("ftps tls option must be skip-verify (or left out to verify the certificate)")
		}
	case "sftp":
		t.Secure = true
	}
	return t, nil
}

// parseS3 reads s3://ACCESS_KEY_ID@bucket/prefix?endpoint=URL&region=R. The
// endpoint defaults to AWS; any S3-compatible service (MinIO, R2, Wasabi,
// Spaces) works with its own endpoint.
func parseS3(u *url.URL, t Target) (Target, error) {
	t.Bucket = u.Host
	if t.Bucket == "" || strings.Contains(t.Bucket, ":") {
		return Target{}, out.Usage("s3 URL needs a bucket: s3://ACCESS_KEY_ID@bucket/prefix?endpoint=https://...")
	}
	t.User = u.User.Username()
	t.Prefix = strings.Trim(u.Path, "/")
	if t.Prefix != "" {
		t.Prefix += "/"
	}
	q := u.Query()
	t.Region = q.Get("region")
	endpoint := q.Get("endpoint")
	if endpoint == "" {
		endpoint = "https://s3.amazonaws.com"
		if t.Region != "" {
			endpoint = "https://s3." + t.Region + ".amazonaws.com"
		}
	}
	e, err := url.Parse(endpoint)
	if err != nil || e.Host == "" || (e.Scheme != "https" && e.Scheme != "http") {
		return Target{}, out.Usage("s3 endpoint must be a URL like https://minio.internal:9000")
	}
	t.Secure = e.Scheme == "https"
	port := e.Port()
	if port == "" {
		port = map[bool]string{true: "443", false: "80"}[t.Secure]
	}
	t.Address = net.JoinHostPort(e.Hostname(), port)
	for k := range q {
		if k != "endpoint" && k != "region" {
			return Target{}, out.Usage("unknown s3 URL option %q (known: endpoint, region)", k)
		}
	}
	return t, nil
}

// Need checks that t belongs to family (a command name: db, cache,
// storage), with a hint naming the right command.
func (t Target) Need(family string) error {
	if t.Kind.Family == family {
		return nil
	}
	return out.Errf(out.ExitUsage, "WRONG_KIND", fmt.Sprintf("use `komando %s` for %s conns", t.Kind.Family, t.Kind.Name),
		"`komando %s` does not work with %s conns", family, t.Kind.Name)
}

func hasPasswordParam(q url.Values) bool {
	for k := range q {
		for _, p := range passwordParams {
			if strings.EqualFold(k, p) {
				return true
			}
		}
	}
	return false
}

// Describe is a short human label, e.g. "postgres app@db.internal:5432/app".
func (t Target) Describe() string {
	if t.Bucket != "" {
		return t.Kind.Name + " " + t.Where()
	}
	if t.Kind.File {
		return fmt.Sprintf("%s %s", t.Kind.Name, t.Path)
	}
	s := t.Address
	if t.User != "" {
		s = t.User + "@" + s
	}
	if t.Database != "" {
		s += "/" + t.Database
	}
	return t.Kind.Name + " " + s
}
