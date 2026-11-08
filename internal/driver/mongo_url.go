package driver

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// parseMongo reads mongodb://user@host1:27017,host2/db?replicaSet=rs0 and
// mongodb+srv://user@cluster.example.net/db. Address is the first host
// (shown, and checked by `conn test`); the driver reads the whole URL.
func parseMongo(u *url.URL, t Target) (Target, error) {
	if u.Host == "" {
		return Target{}, out.Usage("mongodb URL needs a host, e.g. %s", t.Kind.Example)
	}
	srv := strings.EqualFold(u.Scheme, "mongodb+srv")
	first := u.Host
	host, port, err := net.SplitHostPort(first)
	if err != nil {
		host, port = first, strconv.Itoa(t.Kind.DefaultPort)
	}
	if srv {
		if u.Port() != "" {
			return Target{}, out.Usage("a mongodb+srv URL names one host and no port: DNS lists the servers")
		}
		port = "27017"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return Target{}, out.Usage("invalid port %q in conn URL", port)
	}
	t.Address = net.JoinHostPort(host, port)
	t.User = u.User.Username()
	t.Database = strings.Trim(u.Path, "/")
	q := u.Query()
	t.Secure = srv || strings.EqualFold(q.Get("tls"), "true") || strings.EqualFold(q.Get("ssl"), "true")
	if q.Get("tlsInsecure") == "true" || q.Get("tlsAllowInvalidCertificates") == "true" {
		t.TLS = "skip-verify"
	}
	if err := parseCA(q, &t); err != nil {
		return Target{}, err
	}
	return t, nil
}

// firstMongoHost keeps only the first host of a MongoDB URL that lists
// several (mongodb://u@h1:27017,h2,h3/db), which net/url cannot read. The
// driver still gets the whole URL; komando shows and checks the first.
func firstMongoHost(raw string) string {
	l := strings.ToLower(raw)
	if !strings.HasPrefix(l, "mongodb://") && !strings.HasPrefix(l, "mongodb+srv://") {
		return raw
	}
	start := strings.Index(raw, "://") + 3
	end := len(raw)
	if i := strings.IndexAny(raw[start:], "/?"); i >= 0 {
		end = start + i
	}
	hosts := raw[start:end]
	if at := strings.LastIndex(hosts, "@"); at >= 0 {
		start += at + 1
		hosts = hosts[at+1:]
	}
	if i := strings.Index(hosts, ","); i >= 0 {
		return raw[:start] + hosts[:i] + raw[end:]
	}
	return raw
}

// noSQL is the error for SQL sent to a kind that does not take it.
func noSQL(kind string) error {
	if kind == "mongodb" {
		return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
			`on MongoDB, explain a query with db query: '{"explain": {"find": "users", "filter": {}}, "verbosity": "queryPlanner"}'`,
			"this db command is for SQL databases, not MongoDB")
	}
	return out.Usage("%s conns do not take SQL", kind)
}
