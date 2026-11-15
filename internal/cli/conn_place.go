package cli

import (
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Where a conn's login goes. A URL says more than its address: Postgres
// takes host=, port=, hostaddr= and service= from its settings, Redis
// sentinels=, MongoDB more seed hosts, RabbitMQ management=, and many
// kinds a CA, a TLS mode or a client certificate. So the place a conn's
// password goes is every address its driver logs in at, read as the
// driver reads the URL (connPlaces), plus every setting of the URL except
// the few that move nothing (connURLSettings). Any other change of the URL
// is a new place: an AI agent's gets SECRET_DESTINATION for a conn with a
// stored password, and it fails closed for a setting komando does not
// know.

// connSafeSettings are URL settings that change neither where a login goes
// nor how the server is checked.
var connSafeSettings = map[string]bool{
	"application_name": true, "connect_timeout": true, "timeout": true, "dial_timeout": true,
	"read_timeout": true, "write_timeout": true, "statement_timeout": true, "lock_timeout": true,
}

// connURLSettings are the URL's settings that are part of where the login
// goes, as sorted key=value pairs.
func connURLSettings(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var set []string
	for k, vs := range u.Query() {
		if connSafeSettings[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			set = append(set, k+"="+v)
		}
	}
	sort.Strings(set)
	return set
}

// connPlaces are the addresses c's driver logs in at: the URL's hosts
// (every one it lists), Kafka and NATS brokers, Redis sentinels, the
// RabbitMQ management API, ?resolve=, and for Postgres every host pgx
// reads from the URL (fallbacks included). The user is not a place: the
// login goes to the same servers.
func connPlaces(c *store.Conn) []string {
	t, err := driver.Parse(c.URL)
	if err != nil {
		return []string{c.URL}
	}
	if t.Kind.File {
		return []string{t.Path}
	}
	places := []string{t.Address}
	if u, err := url.Parse(c.URL); err == nil {
		for _, h := range strings.Split(u.Host, ",") { // mongodb://a,b/ and the like
			if h = strings.TrimSpace(h); h != "" && !slices.Contains(places, h) && !slices.ContainsFunc(places, func(p string) bool { return sameHost(p, h) }) {
				places = append(places, h)
			}
		}
	}
	places = append(places, t.Brokers...)
	places = append(places, t.Sentinels...)
	if t.Management != "" {
		places = append(places, t.Management+" (management API)")
	}
	if t.Resolve != "" && t.Resolve != t.Address {
		places = append(places, t.Resolve+" (resolve)")
	}
	if t.Kind.Name == "postgres" {
		places = append(places, dbx.PostgresTargets(c.URL)...)
	}
	var out []string
	for _, p := range places {
		if p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// sameHost: a is b with the kind's default port added.
func sameHost(a, b string) bool {
	ha, _, err := net.SplitHostPort(a)
	return err == nil && ha == b
}

// guardConnFile refuses a file conn (SQLite) that is komando's own data,
// its links included: the store holds the inventory and the sealed
// secrets, and only komando's commands read it. For an AI agent, the other
// files the agent guard keeps from it are refused too (guardLocalRead).
func guardConnFile(cl *call, c *store.Conn) error {
	t, err := driver.Parse(c.URL)
	if err != nil || !t.Kind.File {
		return nil
	}
	p := dbx.SQLitePath(t)
	if localSecret(cl, p) == komandoData {
		return out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
			"point the conn at a database of your own; komando's data is read only through komando's commands (`komando list`, `komando secret list`)",
			"%s is %s, not a database for a conn", p, komandoData).NoFlag()
	}
	return guardLocalRead(cl, p)
}
