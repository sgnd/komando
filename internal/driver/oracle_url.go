package driver

import (
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// OracleOptions are the URL options an oracle:// conn takes.
type OracleOptions struct {
	TLS string // true (TCPS, certificate checked) | skip-verify | false; "" when the URL has none
	SID string // sid=NAME: an old database reached by its SID instead of a service name
}

// oracleKeys are the option names and what each takes.
var oracleKeys = map[string]string{
	"tls": "true, skip-verify or false", "ca": "secret:NAME", "sid": "an instance SID, in place of the service name",
}

// ParseOracleOptions reads the options of an oracle:// URL.
func ParseOracleOptions(q url.Values) (OracleOptions, error) {
	var o OracleOptions
	for key, vs := range q {
		v := vs[0]
		switch key {
		case "tls":
			o.TLS = strings.ToLower(v)
			if o.TLS != "true" && o.TLS != "skip-verify" && o.TLS != "false" {
				return o, out.Errf(out.ExitUsage, "USAGE",
					"tls=true is TCPS with the certificate checked; skip-verify is TCPS without the check; false is plain TCP",
					"the oracle tls option takes true, skip-verify or false, not %q", v)
			}
		case "ca":
		case "sid":
			if !validOracleName(v) {
				return o, out.Usage("oracle sid %q: letters, digits, _ $ #", v)
			}
			o.SID = v
		default:
			var known []string
			for name, what := range oracleKeys {
				known = append(known, name+" ("+what+")")
			}
			sort.Strings(known)
			return o, out.Usage("unknown oracle URL option %q (known: %s)", key, strings.Join(known, ", "))
		}
	}
	return o, nil
}

// validOracleName: a service name or SID komando puts in the connect
// descriptor (dots for domain-qualified service names).
func validOracleName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c == '_' || c == '$' || c == '#' || c == '.' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// parseOracle reads oracle://user@host:1521/SERVICE?tls=true. The path is
// the service name (a pluggable database: ORCLPDB1, FREEPDB1); ?sid=
// reaches an old database by its SID instead.
func parseOracle(u *url.URL, t Target) (Target, error) {
	if u.Hostname() == "" {
		return Target{}, out.Usage("oracle URL needs a host, for example %s", t.Kind.Example)
	}
	if u.User.Username() == "" {
		return Target{}, out.Usage("oracle URL needs a user name, for example oracle://app@db.internal:1521/ORCLPDB1")
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
	o, err := ParseOracleOptions(u.Query())
	if err != nil {
		return Target{}, err
	}
	service := strings.Trim(u.Path, "/")
	switch {
	case service != "" && o.SID != "":
		return Target{}, out.Usage("the oracle URL names a service (%q) and a sid (%q): keep one", service, o.SID)
	case service == "" && o.SID == "":
		return Target{}, out.Errf(out.ExitUsage, "USAGE",
			"put the service name after the host (oracle://app@db:1521/ORCLPDB1); `lsnrctl status` on the server lists them",
			"oracle URL needs a service name")
	case service != "" && !validOracleName(service):
		return Target{}, out.Usage("oracle service name %q: letters, digits and _ $ # . -", service)
	case service == "":
		service = o.SID
	}
	t.Database = service
	t.TLS = o.TLS
	t.Secure = o.TLS == "true" || o.TLS == "skip-verify"
	if err := parseCA(u.Query(), &t); err != nil {
		return Target{}, err
	}
	return t, nil
}
