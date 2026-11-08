package driver

import (
	"net"
	"net/url"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// parseRedisTopology reads the options of a Redis Cluster (?cluster=1:
// the address is any one node, the others are found from it) or of a
// Sentinel setup (?sentinel=MASTER: the address is a Sentinel, which says
// where the master is now).
func parseRedisTopology(u *url.URL, t *Target) error {
	q := u.Query()
	switch v := q.Get("cluster"); v {
	case "", "0", "false":
	case "1", "true":
		t.Cluster = true
	default:
		return out.Usage("redis cluster option is cluster=1, not %q", v)
	}
	t.Sentinel = q.Get("sentinel")
	switch {
	case t.Cluster && t.Sentinel != "":
		return out.Usage("a redis conn is a Cluster (?cluster=1) or behind Sentinels (?sentinel=NAME), not both")
	case t.Cluster && t.Database != "0":
		return out.Usage("Redis Cluster has only database 0: drop /%s from the URL", t.Database)
	case t.Sentinel == "" && (q.Has("sentinels") || q.Has("sentinel_auth")):
		return out.Usage("sentinels= and sentinel_auth= go with ?sentinel=MASTER (the master's name at the Sentinels)")
	}
	if t.Sentinel == "" {
		return nil
	}
	if u.Port() == "" { // a Sentinel's own port, not Redis's
		t.Address = net.JoinHostPort(u.Hostname(), "26379")
	}
	if s := q.Get("sentinels"); s != "" {
		for _, a := range strings.Split(s, ",") {
			a = strings.TrimSpace(a)
			if _, _, err := net.SplitHostPort(a); err != nil {
				a = net.JoinHostPort(a, "26379")
			}
			t.Sentinels = append(t.Sentinels, a)
		}
	}
	switch v := q.Get("sentinel_auth"); v {
	case "":
	case "same":
		t.SentinelAuth = true
	default:
		return out.Usage("sentinel_auth=same sends the conn's login to the Sentinels too; %q is not known", v)
	}
	return nil
}
