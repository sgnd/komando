package driver

import (
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// SQLServerOptions are the URL options a sqlserver:// conn takes. Their
// names are read without regard to case (Encrypt=true works too), as
// SQL Server's own drivers do.
type SQLServerOptions struct {
	Encrypt    string // true | strict | false | disable; "" when the URL has none
	SkipVerify bool   // tls=skip-verify: encrypt without checking the certificate
	ReadOnly   bool   // applicationintent=readonly: ask an availability group for a readable replica
	Database   string // database=NAME, for URLs written the way go-mssqldb takes them
}

// sqlserverKeys are the option names, lower case, and what each takes.
var sqlserverKeys = map[string]string{
	"encrypt": "true, strict, false or disable", "tls": "skip-verify", "ca": "secret:NAME",
	"applicationintent": "readonly or readwrite", "database": "a database name",
}

// ParseSQLServerOptions reads the options of a sqlserver:// URL.
func ParseSQLServerOptions(q url.Values) (SQLServerOptions, error) {
	var o SQLServerOptions
	seen := map[string]bool{}
	for key, vs := range q {
		k := strings.ToLower(key)
		if seen[k] || len(vs) > 1 {
			// encrypt=true&Encrypt=disable: which one wins would be chance
			return o, out.Usage("sqlserver URL option %q is given more than once: keep one", k)
		}
		seen[k] = true
		v := vs[0]
		switch k {
		case "encrypt":
			o.Encrypt = strings.ToLower(v)
			if o.Encrypt != "true" && o.Encrypt != "strict" && o.Encrypt != "false" && o.Encrypt != "disable" {
				return o, out.Errf(out.ExitUsage, "USAGE",
					"encrypt=true encrypts everything and checks the certificate; strict is the same with TDS 8.0; false encrypts only the login; disable encrypts nothing",
					"the sqlserver encrypt option takes true, strict, false or disable, not %q", v)
			}
		case "tls":
			if v != "skip-verify" {
				return o, out.Usage("the sqlserver tls option takes only skip-verify (encrypt without checking the certificate), not %q", v)
			}
			o.SkipVerify = true
		case "applicationintent":
			switch strings.ToLower(v) {
			case "readonly":
				o.ReadOnly = true
			case "readwrite":
			default:
				return o, out.Usage("the sqlserver applicationintent option takes readonly or readwrite, not %q", v)
			}
		case "database":
			o.Database = v
		case "ca":
			if key != "ca" {
				return o, out.Usage("write the sqlserver ca option in lower case: ?ca=secret:NAME")
			}
		case "trustservercertificate":
			return o, out.Errf(out.ExitUsage, "USAGE", "komando spells it ?tls=skip-verify (with encrypt=true): the traffic is encrypted, but the certificate is not checked",
				"use tls=skip-verify instead of TrustServerCertificate")
		default:
			var known []string
			for name, what := range sqlserverKeys {
				known = append(known, name+" ("+what+")")
			}
			sort.Strings(known)
			return o, out.Usage("unknown sqlserver URL option %q (known: %s)", key, strings.Join(known, ", "))
		}
	}
	switch {
	case o.SkipVerify && o.Encrypt == "disable":
		return o, out.Usage("sqlserver tls=skip-verify and encrypt=disable do not go together: with encrypt=disable there is no TLS to check")
	case o.SkipVerify && o.Encrypt == "strict":
		return o, out.Usage("sqlserver encrypt=strict always checks the certificate: drop tls=skip-verify, or use encrypt=true with it")
	}
	return o, nil
}

// parseSQLServer reads sqlserver://user@host:1433/database?encrypt=true.
// The path is the database, as for the other SQL kinds. Named instances
// (host\SQLEXPRESS) are reached by their port: the SQL Server Browser
// that maps names to ports answers over UDP, which an SSH --via cannot carry.
func parseSQLServer(u *url.URL, t Target) (Target, error) {
	if u.Hostname() == "" {
		return Target{}, out.Usage("sqlserver URL needs a host, for example %s", t.Kind.Example)
	}
	if u.User.Username() == "" {
		return Target{}, out.Usage("sqlserver URL needs a user name, for example sqlserver://app@db.internal:1433/sales")
	}
	port := t.Kind.DefaultPort
	if p := u.Port(); p != "" {
		var err error
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return Target{}, out.Usage("the port %q in the conn URL is not a number from 1 to 65535", p)
		}
	}
	t.Address = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	t.User = u.User.Username()
	path := strings.Trim(u.Path, "/")
	if strings.Contains(path, "/") {
		return Target{}, out.Errf(out.ExitUsage, "USAGE",
			"give the database after the host (sqlserver://app@host:1433/sales); for a named instance use its port instead of its name",
			"sqlserver URL path %q has more than a database name", u.Path)
	}
	o, err := ParseSQLServerOptions(u.Query())
	if err != nil {
		return Target{}, err
	}
	switch {
	case path != "" && o.Database != "" && path != o.Database:
		return Target{}, out.Usage("the sqlserver URL names two databases (%q in the path, %q in database=): keep one", path, o.Database)
	case path == "":
		path = o.Database
	}
	t.Database = path
	t.Secure = o.Encrypt == "true" || o.Encrypt == "strict"
	if o.SkipVerify {
		t.TLS = "skip-verify"
	}
	if err := parseCA(u.Query(), &t); err != nil {
		return Target{}, err
	}
	return t, nil
}
