package cli

import (
	"net/url"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// A new conn checks the server's certificate unless its URL says otherwise
// (docs/features/databases.md). When conn add, or conn edit --url, saves a
// conn that crosses the network on its own (no --via, not this computer;
// overNetwork):
//
//   - Postgres without sslmode gets sslmode=verify-full, MySQL without tls=
//     gets tls=true (verifiedTLSURL). Left out, both would take TLS only
//     when the server offers it, without checking whose certificate it is.
//   - redis://, memcached://, amqp:// and nats:// name a connection without
//     TLS, and so does kafka:// without tls=true, so they are refused unless ?insecure=1
//     says that is meant, as for ftp://. Most of these servers have no
//     TLS: --via an SSH server is the usual way.
//
// Conns saved before keep their URL; `komando doctor` lists them.

// secureConnURL applies that default to c (its Kind is set) and notes on
// res what it added.
func secureConnURL(c *store.Conn, res *connResult) error {
	t, err := driver.Parse(c.URL)
	if err != nil || !overNetwork(c, t) {
		return nil
	}
	q := url.Values{}
	if u, err := url.Parse(c.URL); err == nil {
		q = u.Query()
	}
	added := ""
	switch t.Kind.Name {
	case "postgres":
		if !q.Has("sslmode") {
			added = "sslmode=verify-full"
		}
	case "mysql":
		if !q.Has("tls") {
			added = "tls=true"
		}
	case "redis", "memcached":
		if !t.Secure && q.Get("insecure") != "1" {
			// the first hint is the error catalog's (`komando schema`),
			// which every kind shares; WithHint gives this kind's own
			return out.Errf(out.ExitUsage, "INSECURE_PROTOCOL",
				"use the URL's TLS form if the server has TLS (rediss://, memcacheds://, amqps://, nats tls://, kafka tls=true, an https:// endpoint, ftps://, webdavs://), or reach it --via an SSH server (`--via HOST`); otherwise add ?insecure=1 to accept that the login and the data travel unencrypted",
				"%s:// crosses the network to %s without TLS, so the password and the data travel unencrypted", t.Kind.Name, t.Address).
				WithHint("reach it --via an SSH server (`--via HOST`), or use " + t.Kind.Name + "s:// if the server has TLS; otherwise add ?insecure=1 to accept that the password and data travel unencrypted")
		}
	case "rabbitmq":
		if !t.Secure && q.Get("insecure") != "1" {
			return out.Errf(out.ExitUsage, "INSECURE_PROTOCOL",
				"reach it --via an SSH server (`--via HOST`), or use amqps:// (port 5671) if the server has TLS; otherwise add ?insecure=1 to accept that the login and the messages travel unencrypted",
				"amqp:// crosses the network to %s without TLS, so the password and the messages travel unencrypted", t.Address)
		}
	case "nats":
		if !t.Secure && q.Get("insecure") != "1" {
			return out.Errf(out.ExitUsage, "INSECURE_PROTOCOL",
				"reach it --via an SSH server (`--via HOST`), or use tls:// if the server has TLS; otherwise add ?insecure=1 to accept that the login and the messages travel unencrypted",
				"nats:// crosses the network to %s without TLS, so the password and the messages travel unencrypted", t.Address)
		}
	case "kafka":
		if !t.Secure && q.Get("insecure") != "1" {
			return out.Errf(out.ExitUsage, "INSECURE_PROTOCOL",
				"reach the brokers --via an SSH server (`--via HOST`), or add tls=true if they have TLS; otherwise add ?insecure=1 to accept that the login and the messages travel unencrypted",
				"kafka:// without tls=true crosses the network to %s unencrypted, so the login and the messages can be read on the way", t.Address)
		}
	}
	if added == "" {
		return nil
	}
	if u := verifiedTLSURL(c.URL, t.Kind.Name); u != "" {
		c.URL = u
		res.Warnings = append(res.Warnings, "the URL did not say how to use TLS, so komando added "+added+
			": TLS that checks the server's certificate. If the server has no TLS or a certificate from its own CA, `komando conn test "+c.Name+"` says what to do")
	}
	return nil
}
