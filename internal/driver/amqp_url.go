package driver

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// parseAMQP reads amqp://user@host:5672/vhost and amqps:// (TLS, port
// 5671) for RabbitMQ (docs/features/queues.md). The path is the virtual host,
// URL-encoded ("%2F" or nothing is the default vhost "/"). Options:
//
//	?management=15672    also use the management HTTP API on this port of
//	                     the same host (HTTPS for amqps://), for ls, info
//	                     and describe
//	?ca=secret:NAME      amqps: also trust this PEM CA certificate
//	?tls=skip-verify     amqps: do not check the certificate
//	?insecure=1          accept amqp:// (no TLS) across the network
func parseAMQP(u *url.URL, t Target) (Target, error) {
	if u.Hostname() == "" {
		return Target{}, out.Usage("rabbitmq URL needs a host, for example %s", t.Kind.Example)
	}
	t.Secure = strings.EqualFold(u.Scheme, "amqps")
	port := map[bool]int{true: 5671, false: 5672}[t.Secure]
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Target{}, out.Usage("the port %q in the conn URL is not a number from 1 to 65535", p)
		}
		port = n
	}
	t.Address = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	t.User = u.User.Username()
	vhost, err := url.PathUnescape(strings.TrimPrefix(u.EscapedPath(), "/"))
	if err != nil || strings.Contains(strings.TrimPrefix(u.EscapedPath(), "/"), "/") {
		return Target{}, out.Usage("the rabbitmq URL path is one virtual host; write the vhost \"/\" as %%2F, as in amqp://app@rabbit:5672/%%2F")
	}
	if vhost == "" {
		vhost = "/"
	}
	t.Database = vhost
	q := u.Query()
	for key := range q {
		switch key {
		case "tls", "ca", "insecure", "management":
		default:
			return Target{}, out.Usage("unknown rabbitmq URL option %q (known: management, ca, tls, insecure)", key)
		}
	}
	switch v := q.Get("tls"); {
	case v == "":
	case v != "skip-verify":
		return Target{}, out.Usage("rabbitmq tls option can only be skip-verify (amqps:// is TLS), not %q", v)
	case !t.Secure:
		return Target{}, out.Usage("tls=skip-verify is for amqps:// (TLS); amqp:// has no TLS")
	default:
		t.TLS = "skip-verify"
	}
	if q.Has("management") {
		n, err := strconv.Atoi(q.Get("management"))
		if err != nil || n < 1 || n > 65535 {
			return Target{}, out.Errf(out.ExitUsage, "USAGE",
				"give the management API's port on the same host, as in ?management=15672 (15671 for HTTPS)",
				"the rabbitmq management option takes a port, not %q", q.Get("management"))
		}
		t.Management = net.JoinHostPort(u.Hostname(), strconv.Itoa(n))
	}
	if err := parseCA(q, &t); err != nil {
		return Target{}, err
	}
	return t, nil
}
