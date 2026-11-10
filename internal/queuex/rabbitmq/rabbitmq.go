// Package rabbitmq is the RabbitMQ engine of `komando queue` (AMQP 0-9-1,
// through github.com/rabbitmq/amqp091-go). It registers itself with
// queuex for amqp:// and amqps:// conns. Reading never removes a message:
// peek takes messages from the front of a queue and gives them back. ls,
// info and describe also use the management HTTP API when the URL names
// its port (?management=15672). See docs/design/queue.md.
package rabbitmq

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/queuex"
)

func init() { queuex.Register("rabbitmq", Open) }

// Rabbit is a queuex.Queue on one virtual host of a RabbitMQ server.
type Rabbit struct {
	conn     *amqp.Connection
	t        driver.Target
	user     string
	password string
	dial     queuex.DialFunc
	tls      *tls.Config // nil for amqp://
	timeout  time.Duration
}

// defaultUser is RabbitMQ's own first user (guest, password guest), which
// it lets log in only from the server itself: a conn without a user in
// its URL uses it, so a conn --via the server's SSH works out of the box.
const defaultUser = "guest"

// Open logs in to the conn's vhost through dial (direct, --via an SSH
// server, or a VPN), with TLS on top for amqps://.
func Open(ctx context.Context, t driver.Target, password string, dial queuex.DialFunc, timeout time.Duration, clientID string) (queuex.Queue, error) {
	r := &Rabbit{t: t, user: t.User, password: password, dial: dial, timeout: timeout}
	if r.user == "" {
		r.user = defaultUser
		if r.password == "" {
			r.password = defaultUser
		}
	}
	if r.dial == nil {
		r.dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	if t.Secure {
		pool, err := t.RootCAs()
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(t.Address)
		r.tls = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: host, InsecureSkipVerify: t.TLS == "skip-verify"} // #nosec G402 -- only with ?tls=skip-verify, which doctor flags
	}
	conn, err := r.open(ctx, clientID)
	if err != nil {
		return nil, connectErr(t, err)
	}
	r.conn = conn
	return r, nil
}

// open dials, adds TLS and logs in, all within the timeout.
func (r *Rabbit) open(ctx context.Context, clientID string) (*amqp.Connection, error) {
	dctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	c, err := r.dial(dctx, "tcp", r.t.Address)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(r.timeout)
	if d, ok := dctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if r.tls != nil {
		tc := tls.Client(c, r.tls)
		if err := tc.HandshakeContext(dctx); err != nil {
			c.Close()
			return nil, err
		}
		c = tc
	}
	conn, err := amqp.Open(c, amqp.Config{
		SASL:       []amqp.Authentication{&amqp.PlainAuth{Username: r.user, Password: r.password}},
		Vhost:      r.t.Database,
		Heartbeat:  10 * time.Second,
		Locale:     "en_US",
		Properties: amqp.Table{"connection_name": clientID, "product": "komando"},
	})
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return conn, nil
}

// Close ends the connection; messages a peek still held go back to their
// queue then, as RabbitMQ does for every closed connection.
func (r *Rabbit) Close() {
	if r.conn != nil {
		_ = r.conn.CloseDeadline(time.Now().Add(r.timeout))
	}
}

// do runs fn on a new channel and gives up when ctx ends: AMQP calls do
// not take a context, so the connection is closed then, which also puts
// back any message a peek held.
func (r *Rabbit) do(ctx context.Context, what string, fn func(ch *amqp.Channel) error) error {
	done := make(chan error, 1)
	go func() {
		ch, err := r.conn.Channel()
		if err != nil {
			done <- err
			return
		}
		err = fn(ch)
		if !ch.IsClosed() {
			_ = ch.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		return opErr(err, what)
	case <-ctx.Done():
		r.conn.Close()
		return opErr(ctx.Err(), what)
	}
}

// declared is a queue as a passive queue.declare sees it: ready messages
// and consumers, or QUEUE_NOT_FOUND.
func (r *Rabbit) declared(ctx context.Context, name string) (amqp.Queue, error) {
	var q amqp.Queue
	err := r.do(ctx, name, func(ch *amqp.Channel) error {
		var err error
		q, err = ch.QueueDeclarePassive(name, false, false, false, false, nil)
		return err
	})
	return q, err
}

// Groups: RabbitMQ has no consumer groups.
func (r *Rabbit) Groups(context.Context) ([]queuex.Group, error) {
	return nil, queuex.NotSupported("queue groups", "rabbitmq", noGroups)
}

// Lag: RabbitMQ has no consumer groups.
func (r *Rabbit) Lag(context.Context, string) (*queuex.GroupLag, error) {
	return nil, queuex.NotSupported("queue lag", "rabbitmq", noGroups)
}

const noGroups = "RabbitMQ has no consumer groups: `komando queue describe CONN QUEUE` shows a queue's consumers, " +
	"the messages waiting for them (ready) and those they have not acknowledged yet (unacked)"
