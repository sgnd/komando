package driver

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// ClickHouse ports: komando speaks ClickHouse's HTTP interface, 8123
// plain and 8443 with TLS. 9000 and 9440 are the native protocol, which
// komando does not speak (docs/design/clickhouse.md).
const (
	clickhouseHTTP  = 8123
	clickhouseHTTPS = 8443
)

// parseClickHouse reads clickhouse://user@host:8443/DB?tls=true. The path
// is the database (the user's default when left out). Without a port it
// is 8443 with TLS and 8123 without.
func parseClickHouse(u *url.URL, t Target) (Target, error) {
	if u.Hostname() == "" {
		return Target{}, out.Usage("clickhouse URL needs a host, e.g. %s", t.Kind.Example)
	}
	q := u.Query()
	for key := range q {
		if key != "tls" && key != "ca" {
			return Target{}, out.Usage("unknown clickhouse URL option %q (known: tls (true, skip-verify or false), ca (secret:NAME))", key)
		}
	}
	t.TLS = strings.ToLower(q.Get("tls"))
	switch t.TLS {
	case "", "true", "skip-verify", "false":
	default:
		return Target{}, out.Errf(out.ExitUsage, "USAGE",
			"tls=true is HTTPS with the certificate checked; skip-verify is HTTPS without the check; false is plain HTTP",
			"clickhouse tls option must be true, skip-verify or false, not %q", q.Get("tls"))
	}
	t.Secure = t.TLS == "true" || t.TLS == "skip-verify"
	port := clickhouseHTTP
	if t.Secure {
		port = clickhouseHTTPS
	}
	if p := u.Port(); p != "" {
		var err error
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return Target{}, out.Usage("invalid port %q in conn URL", p)
		}
	}
	switch {
	case port == 9000 || port == 9440:
		return Target{}, out.Errf(out.ExitUsage, "USAGE",
			"komando talks to ClickHouse over its HTTP interface: use port 8443 with ?tls=true (or 8123 without TLS), or leave the port out",
			"port %d is ClickHouse's native protocol, which komando does not speak", port)
	case port == clickhouseHTTP && t.Secure:
		return Target{}, out.Errf(out.ExitUsage, "USAGE",
			"ClickHouse serves HTTPS on 8443: use that port with tls=, or ?tls=false for plain HTTP on 8123",
			"port 8123 is ClickHouse's plain HTTP port, but the URL asks for TLS")
	}
	t.Address = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	t.User = u.User.Username()
	t.Database = strings.Trim(u.Path, "/")
	if strings.ContainsAny(t.Database, "/\x00\r\n") {
		return Target{}, out.Usage("clickhouse URL path is one database name, not %q", t.Database)
	}
	if err := parseCA(q, &t); err != nil {
		return Target{}, err
	}
	return t, nil
}

// ClickHouseVerified is raw with tls=true, and port 8443 in place of
// 8123 (ClickHouse's plain HTTP port), for a new conn that crosses the
// network. "" when raw does not parse.
func ClickHouseVerified(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Port() == strconv.Itoa(clickhouseHTTP) {
		u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(clickhouseHTTPS))
	}
	q := u.Query()
	switch {
	case !q.Has("tls") && u.RawQuery == "":
		u.RawQuery = "tls=true"
	case !q.Has("tls"):
		u.RawQuery += "&tls=true"
	default:
		q.Set("tls", "true")
		u.RawQuery = q.Encode()
	}
	return u.String()
}
