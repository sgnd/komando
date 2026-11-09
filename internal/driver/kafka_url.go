package driver

import (
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// SASL mechanisms a kafka:// URL takes (?sasl=).
var kafkaSASL = []string{"plain", "scram-sha-256", "scram-sha-512"}

// parseKafka reads kafka://user@broker1:9092,broker2:9092?tls=true&sasl=
// scram-sha-512 (docs/design/queue.md). brokers are the hosts the URL
// lists, as splitHostList found them; Address is the first.
func parseKafka(u *url.URL, t Target, brokers []string) (Target, error) {
	if len(brokers) == 0 || u.Hostname() == "" {
		return Target{}, out.Usage("kafka URL needs a broker, e.g. %s", t.Kind.Example)
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		return Target{}, out.Usage("a kafka URL names brokers only: drop %q from it (topics are given to each command)", "/"+p)
	}
	for _, b := range brokers {
		addr, err := hostPort(b, t.Kind.DefaultPort)
		if err != nil {
			return Target{}, err
		}
		t.Brokers = append(t.Brokers, addr)
	}
	t.Address = t.Brokers[0]
	t.User = u.User.Username()
	q := u.Query()
	for key := range q {
		switch key {
		case "tls", "ca", "sasl", "insecure":
		default:
			return Target{}, out.Usage("unknown kafka URL option %q (known: tls, ca, sasl, insecure)", key)
		}
	}
	switch v := q.Get("tls"); v {
	case "", "false":
	case "true", "1":
		t.Secure = true
	case "skip-verify":
		t.Secure, t.TLS = true, "skip-verify"
	default:
		return Target{}, out.Usage("kafka tls option must be true or skip-verify, not %q", v)
	}
	t.SASL = strings.ToLower(q.Get("sasl"))
	switch {
	case t.SASL != "" && !slices.Contains(kafkaSASL, t.SASL):
		return Target{}, out.Usage("kafka sasl option must be one of %s, not %q", strings.Join(kafkaSASL, ", "), q.Get("sasl"))
	case t.SASL != "" && t.User == "":
		return Target{}, out.Usage("sasl=%s logs in as a user: put it in the URL, as in kafka://USER@broker:9092?sasl=%s", t.SASL, t.SASL)
	case t.SASL == "" && t.User != "":
		return Target{}, out.Errf(out.ExitUsage, "USAGE",
			"add ?sasl=scram-sha-512 (or scram-sha-256, or plain), whichever the brokers use",
			"the kafka URL has a user (%s) but no sasl= option to say how to log in", t.User)
	}
	if err := parseCA(q, &t); err != nil {
		return Target{}, err
	}
	return t, nil
}

// hostPort is "host:port" with the default port when s has none.
func hostPort(s string, def int) (string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = strings.Trim(s, "[]"), strconv.Itoa(def)
	}
	if host == "" {
		return "", out.Usage("empty broker address in the conn URL")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", out.Usage("invalid port %q in conn URL", port)
	}
	return net.JoinHostPort(host, port), nil
}

// splitHostList keeps only the first host of a kafka:// URL that lists
// several (kafka://u@b1:9092,b2:9092), which net/url cannot read, and
// returns all of them. Other URLs come back unchanged, with no hosts.
func splitHostList(raw string) (string, []string) {
	if !strings.HasPrefix(strings.ToLower(raw), "kafka://") {
		return raw, nil
	}
	start := len("kafka://")
	end := len(raw)
	if i := strings.IndexAny(raw[start:], "/?#"); i >= 0 {
		end = start + i
	}
	hosts := raw[start:end]
	if at := strings.LastIndex(hosts, "@"); at >= 0 {
		start += at + 1
		hosts = hosts[at+1:]
	}
	var list []string
	for _, h := range strings.Split(hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			list = append(list, h)
		}
	}
	if len(list) == 0 {
		return raw, nil
	}
	return raw[:start] + list[0] + raw[end:], list
}
