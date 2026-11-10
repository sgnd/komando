package driver

import (
	"net/url"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// parseNATS reads nats://user@host:4222,host2:4222 and tls:// (TLS) for
// NATS with JetStream (docs/design/queue.md). hosts are the servers the
// URL lists, as splitHostList found them; Address is the first. Options:
//
//	?creds=secret:NAME   log in with the .creds file (a user JWT and its
//	                     NKey seed) kept in the vault
//	?domain=NAME         the JetStream domain (a leaf node's own)
//	?ca=secret:NAME      tls: also trust this PEM CA certificate
//	?tls=skip-verify     tls: do not check the certificate
//	?insecure=1          accept nats:// (no TLS) across the network
func parseNATS(u *url.URL, t Target, hosts []string) (Target, error) {
	if len(hosts) == 0 || u.Hostname() == "" {
		return Target{}, out.Usage("nats URL needs a server, e.g. %s", t.Kind.Example)
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		return Target{}, out.Usage("a nats URL names servers only: drop %q from it (streams are given to each command)", "/"+p)
	}
	for _, h := range hosts {
		addr, err := hostPort(h, t.Kind.DefaultPort)
		if err != nil {
			return Target{}, err
		}
		t.Brokers = append(t.Brokers, addr)
	}
	t.Address = t.Brokers[0]
	t.Secure = strings.EqualFold(u.Scheme, "tls")
	t.User = u.User.Username()
	q := u.Query()
	for key := range q {
		switch key {
		case "tls", "ca", "insecure", "creds", "domain":
		default:
			return Target{}, out.Usage("unknown nats URL option %q (known: creds, domain, ca, tls, insecure)", key)
		}
	}
	switch v := q.Get("tls"); {
	case v == "":
	case v != "skip-verify":
		return Target{}, out.Usage("nats tls option can only be skip-verify (tls:// is TLS), not %q", v)
	case !t.Secure:
		return Target{}, out.Usage("tls=skip-verify is for tls:// (TLS); nats:// has no TLS of its own")
	default:
		t.TLS = "skip-verify"
	}
	if q.Has("creds") {
		creds := q.Get("creds")
		if name, ok := strings.CutPrefix(creds, "secret:"); !ok || name == "" {
			return Target{}, out.Errf(out.ExitUsage, "USAGE",
				"store the .creds file with `komando secret set NAME < user.creds`, then use ?creds=secret:NAME",
				"nats creds option must be secret:NAME, not %q", creds)
		}
		if t.User != "" {
			return Target{}, out.Usage("a nats URL logs in with a user or with creds=, not both: drop %s@ from it", t.User)
		}
		t.Creds = creds
	}
	t.Domain = q.Get("domain")
	if err := parseCA(q, &t); err != nil {
		return Target{}, err
	}
	return t, nil
}
