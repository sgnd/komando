// Package driver describes the kinds of non-SSH resources komando can talk
// to (databases first) and the risk levels its safety checks work with.
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
	Schemes     []string `json:"schemes"`
	DefaultPort int      `json:"default_port,omitempty"`
	File        bool     `json:"file,omitempty"` // a local file, not a network service
}

var kinds = map[string]Kind{}

func register(k Kind) { kinds[k.Name] = k }

func init() {
	register(Kind{Name: "postgres", Schemes: []string{"postgres", "postgresql"}, DefaultPort: 5432})
	register(Kind{Name: "mysql", Schemes: []string{"mysql"}, DefaultPort: 3306})
	register(Kind{Name: "sqlite", Schemes: []string{"sqlite", "sqlite3"}, File: true})
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
	Address  string `json:"address,omitempty"` // host:port for network kinds
	Path     string `json:"path,omitempty"`    // file path for file kinds
	User     string `json:"user,omitempty"`
	Database string `json:"database,omitempty"`
}

// Where is the address or path, for display.
func (t Target) Where() string {
	if t.Kind.File {
		return t.Path
	}
	return t.Address
}

// passwordParams are query parameters that would carry a password.
var passwordParams = []string{"password", "pass", "pwd", "sslpassword"}

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
	return t, nil
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
