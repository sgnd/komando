package driver

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// Snowflake is reached over its SQL REST API (HTTPS, port 443) on
// ACCOUNT.snowflakecomputing.com. The conn URL names the account where
// other kinds name a host:
//
//	snowflake://USER@ACCOUNT/DATABASE/SCHEMA?warehouse=W&role=R
//
// ACCOUNT is an account identifier as Snowflake shows it: myorg-myaccount
// (organization and account name) or xy12345.eu-central-1 (an account
// locator with its region); ACCOUNT.snowflakecomputing.com works too.

const snowflakeDomain = ".snowflakecomputing.com"

// SnowflakeConn is what a snowflake:// URL says, beyond the Target.
type SnowflakeConn struct {
	Account    string // as written, without the domain
	JWTAccount string // the account part of a key-pair token: upper case, no region
	Host       string // ACCOUNT.snowflakecomputing.com, with - for _
	User       string
	Database   string
	Schema     string
	Warehouse  string
	Role       string
}

var sfAccount = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)

// ParseSnowflakeURL reads a snowflake:// conn URL.
func ParseSnowflakeURL(raw string) (SnowflakeConn, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return SnowflakeConn{}, out.Usage("komando cannot read the conn URL: %v", err)
	}
	var s SnowflakeConn
	host := u.Hostname()
	if len(host) > len(snowflakeDomain) && strings.EqualFold(host[len(host)-len(snowflakeDomain):], snowflakeDomain) {
		host = host[:len(host)-len(snowflakeDomain)]
	}
	if host == "" {
		return SnowflakeConn{}, out.Usage("snowflake URL needs an account, for example %s", kinds["snowflake"].Example)
	}
	if !sfAccount.MatchString(host) || strings.Contains(host, "..") || strings.HasSuffix(host, ".") {
		return SnowflakeConn{}, out.Errf(out.ExitUsage, "USAGE",
			"write the account identifier Snowflake shows (myorg-myaccount, or a locator like xy12345.eu-central-1)",
			"snowflake account %q is not an account identifier", host)
	}
	if p := u.Port(); p != "" && p != "443" {
		return SnowflakeConn{}, out.Errf(out.ExitUsage, "USAGE",
			"Snowflake's SQL API is HTTPS on port 443: leave the port out",
			"port %s is not Snowflake's", p)
	}
	s.Account = host
	s.Host = strings.ToLower(strings.ReplaceAll(host, "_", "-")) + snowflakeDomain
	acct, _, _ := strings.Cut(host, ".")
	s.JWTAccount = strings.ToUpper(acct)
	if s.User = u.User.Username(); s.User == "" {
		return SnowflakeConn{}, out.Usage("snowflake URL needs a user, for example %s", kinds["snowflake"].Example)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) > 2 {
		return SnowflakeConn{}, out.Usage("snowflake URL path is /DATABASE/SCHEMA, not %q", u.Path)
	}
	s.Database = parts[0]
	if len(parts) == 2 {
		s.Schema = parts[1]
	}
	q := u.Query()
	for key := range q {
		switch key {
		case "warehouse", "role", "ca":
		case "tls":
			return SnowflakeConn{}, out.Usage("snowflake conns are always HTTPS with the certificate checked: drop tls= (a private CA, such as a proxy's: ?ca=secret:NAME)")
		default:
			return SnowflakeConn{}, out.Usage("unknown snowflake URL option %q (known: warehouse, role, ca (secret:NAME))", key)
		}
	}
	s.Warehouse, s.Role = q.Get("warehouse"), q.Get("role")
	for _, v := range []string{s.User, s.Database, s.Schema, s.Warehouse, s.Role} {
		if strings.ContainsAny(v, "\x00\r\n") {
			return SnowflakeConn{}, out.Usage("snowflake URL has a line break or NUL in a name")
		}
	}
	return s, nil
}

// parseSnowflake fills t from a snowflake:// URL: always HTTPS on 443.
func parseSnowflake(u *url.URL, t Target) (Target, error) {
	s, err := ParseSnowflakeURL(u.String())
	if err != nil {
		return Target{}, err
	}
	t.Address = net.JoinHostPort(s.Host, "443")
	t.User = s.User
	t.Database = s.Database
	t.Secure = true
	if err := parseCA(u.Query(), &t); err != nil {
		return Target{}, err
	}
	return t, nil
}
