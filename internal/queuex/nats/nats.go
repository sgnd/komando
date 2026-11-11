// Package nats is the NATS JetStream engine of `komando queue`, through
// github.com/nats-io/nats.go. It registers itself with queuex for nats://
// and tls:// conns. A queue here is a JetStream stream: ls lists streams,
// describe shows one with its consumers, peek reads messages by their
// sequence number (no consumer, nothing acknowledged, nothing removed),
// send publishes to a subject a stream keeps. See docs/design/queue.md.
package nats

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

func init() { queuex.Register("nats", Open) }

// Nats is a queuex.Queue on a NATS account with JetStream.
type Nats struct {
	nc      *natsgo.Conn
	js      jetstream.JetStream
	t       driver.Target
	timeout time.Duration

	mu       sync.Mutex
	asyncErr error // the last error the server sent on its own (a permissions violation)
}

// Open logs in to the conn's servers through dial (direct, --via an SSH
// server, or a VPN). nats.go adds TLS on top for tls:// (or when the
// server requires it), checked against the server's name.
func Open(ctx context.Context, t driver.Target, password string, dial queuex.DialFunc, timeout time.Duration, clientID string) (queuex.Queue, error) {
	n := &Nats{t: t, timeout: timeout}
	opts, err := n.options(password, dial, clientID)
	if err != nil {
		return nil, err
	}
	servers := t.Brokers
	if len(servers) == 0 {
		servers = []string{t.Address}
	}
	urls := make([]string, len(servers))
	for i, s := range servers {
		urls[i] = "nats://" + s
	}
	type result struct {
		nc  *natsgo.Conn
		err error
	}
	done := make(chan result, 1)
	go func() {
		nc, err := natsgo.Connect(strings.Join(urls, ","), opts...)
		done <- result{nc, err}
	}()
	var r result
	select {
	case r = <-done:
	case <-ctx.Done():
		go func() {
			if r := <-done; r.nc != nil {
				r.nc.Close()
			}
		}()
		return nil, connectErr(t, ctx.Err())
	}
	if r.err != nil {
		return nil, connectErr(t, r.err)
	}
	n.nc = r.nc
	if t.Domain != "" {
		n.js, err = jetstream.NewWithDomain(n.nc, t.Domain)
	} else {
		n.js, err = jetstream.New(n.nc)
	}
	if err != nil {
		n.nc.Close()
		return nil, connectErr(t, err)
	}
	return n, nil
}

// options are nats.go's options for the conn: one try per server, no
// reconnects, no servers but the conn's own, and the login.
func (n *Nats) options(password string, dial queuex.DialFunc, clientID string) ([]natsgo.Option, error) {
	if dial == nil {
		dial = (&net.Dialer{Timeout: n.timeout}).DialContext
	}
	opts := []natsgo.Option{
		natsgo.Name(clientID),
		natsgo.Timeout(n.timeout),
		natsgo.NoReconnect(),
		natsgo.DontRandomize(),
		natsgo.IgnoreDiscoveredServers(),
		natsgo.SetCustomDialer(dialer{dial: dial, timeout: n.timeout}),
		natsgo.ErrorHandler(func(_ *natsgo.Conn, _ *natsgo.Subscription, err error) {
			n.mu.Lock()
			n.asyncErr = err
			n.mu.Unlock()
		}),
	}
	if n.t.Secure {
		pool, err := n.t.RootCAs()
		if err != nil {
			return nil, err
		}
		opts = append(opts, natsgo.Secure(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, InsecureSkipVerify: n.t.TLS == "skip-verify"})) // #nosec G402 -- only with ?tls=skip-verify, which doctor flags
	}
	login, err := loginOption(n.t, password)
	if err != nil {
		return nil, err
	}
	if login != nil {
		opts = append(opts, login)
	}
	return opts, nil
}

// loginOption is how the conn logs in: a .creds file (?creds=), a user
// and password, a token (a password reference without a user), or none.
func loginOption(t driver.Target, password string) (natsgo.Option, error) {
	switch {
	case t.Creds != "":
		jwt, kp, err := creds(t.Creds)
		if err != nil {
			return nil, err
		}
		return natsgo.UserJWT(func() (string, error) { return jwt, nil }, kp.Sign), nil
	case t.User != "":
		return natsgo.UserInfo(t.User, password), nil
	case password != "":
		return natsgo.Token(password), nil
	}
	return nil, nil
}

// creds reads a .creds file from the vault: the user's JWT and the NKey
// seed that signs the server's challenge.
func creds(ref string) (string, nkeys.KeyPair, error) {
	if driver.ResolveSecret == nil {
		return "", nil, errors.New("no secret store to read the creds from")
	}
	text, err := driver.ResolveSecret(ref)
	if err != nil {
		code := "SECRET_UNRESOLVED"
		if errors.Is(err, driver.ErrSecretNotFound) {
			code = "SECRET_NOT_FOUND"
		}
		return "", nil, out.Errf(out.ExitNotFound, code, "store the .creds file with `komando secret set NAME < user.creds`", "nats creds %s: %v", ref, err)
	}
	bad := out.Errf(out.ExitConnect, "QUEUE_AUTH", "store the whole .creds file (with its NATS USER JWT and USER NKEY SEED parts) with `komando secret set NAME < user.creds`",
		"nats creds %s is not a .creds file", ref)
	jwt, err := nkeys.ParseDecoratedJWT([]byte(text))
	if err != nil || jwt == "" || jwt == strings.TrimSpace(text) {
		return "", nil, bad
	}
	kp, err := nkeys.ParseDecoratedNKey([]byte(text))
	if err != nil {
		return "", nil, bad
	}
	return jwt, kp, nil
}

// dialer opens each server connection on the conn's way there; nats.go
// adds TLS on top.
type dialer struct {
	dial    queuex.DialFunc
	timeout time.Duration
}

func (d dialer) Dial(network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	return d.dial(ctx, network, address)
}

// Close ends the connection.
func (n *Nats) Close() {
	if n.nc != nil {
		n.nc.Close()
	}
}

// lastAsyncErr is the error the server last sent on its own, if any.
func (n *Nats) lastAsyncErr() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.asyncErr
}

// stream opens a stream by name, or STREAM_NOT_FOUND.
func (n *Nats) stream(ctx context.Context, name string) (jetstream.Stream, error) {
	if err := checkName("stream", name); err != nil {
		return nil, err
	}
	s, err := n.js.Stream(ctx, name)
	if err != nil {
		return nil, n.opErr(err, name)
	}
	return s, nil
}

// checkName refuses a name NATS cannot have, before asking the server
// (which would take "a.b" as a different API subject).
func checkName(what, name string) error {
	if name == "" || strings.ContainsAny(name, " \t\r\n.*>/\\") {
		return out.Usage("%q is not a %s name: it cannot be empty or hold spaces, '.', '*', '>', '/' or '\\'", name, what)
	}
	return nil
}
