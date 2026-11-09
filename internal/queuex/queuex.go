// Package queuex talks to message queues for `komando queue`: Apache Kafka
// (and what speaks its protocol: Redpanda, MSK, Confluent Cloud) through
// franz-go. Reading never moves a consumer group or removes a message;
// see docs/design/queue.md.
package queuex

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/sgnd/komando/internal/driver"
)

// DialFunc opens a TCP connection, possibly through an SSH host or a VPN.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Queue is what the queue commands need from an engine.
type Queue interface {
	Info(ctx context.Context) (*Info, error)
	Topics(ctx context.Context, pattern string, internal bool) ([]Topic, error)
	Describe(ctx context.Context, topic string) (*TopicDetail, error)
	Peek(ctx context.Context, o PeekOptions) (*PeekResult, error)
	Groups(ctx context.Context) ([]Group, error)
	Lag(ctx context.Context, group string) (*GroupLag, error)
	Send(ctx context.Context, m Message, dryRun bool) (*Sent, error)
	Create(ctx context.Context, s TopicSpec, dryRun bool) (*Created, error)
	Delete(ctx context.Context, topics []string, dryRun bool) ([]Deleted, error)
	Purge(ctx context.Context, topic string, dryRun bool) (*Purged, error)
	Close()
}

// Kafka is a Queue on a Kafka cluster.
type Kafka struct {
	opts    []kgo.Opt // what every client of this conn starts from
	cl      *kgo.Client
	adm     *kadm.Client
	t       driver.Target
	timeout time.Duration
}

// Open connects to a queue conn and checks that a broker answers.
func Open(ctx context.Context, t driver.Target, password string, dial DialFunc, timeout time.Duration, clientID string) (Queue, error) {
	opts, err := clientOpts(t, password, dial, timeout, clientID)
	if err != nil {
		return nil, err
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, connectErr(t, err)
	}
	k := &Kafka{opts: opts, cl: cl, adm: kadm.NewClient(cl), t: t, timeout: timeout}
	k.adm.SetTimeoutMillis(int32(timeout / time.Millisecond))
	if _, err := k.adm.BrokerMetadata(ctx); err != nil {
		cl.Close()
		return nil, connectErr(t, err)
	}
	return k, nil
}

// Close ends the conn's connections.
func (k *Kafka) Close() { k.cl.Close() }

// clientOpts are the franz-go options for the conn: its brokers, the
// dialer (direct or --via, TLS added on top), and the SASL login.
func clientOpts(t driver.Target, password string, dial DialFunc, timeout time.Duration, clientID string) ([]kgo.Opt, error) {
	seeds := t.Brokers
	if len(seeds) == 0 {
		seeds = []string{t.Address}
	}
	var tc *tls.Config
	if t.Secure {
		pool, err := t.RootCAs()
		if err != nil {
			return nil, err
		}
		tc = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, InsecureSkipVerify: t.TLS == "skip-verify"} // #nosec G402 -- only with ?tls=skip-verify, which doctor flags
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(seeds...),
		kgo.Dialer(dialer(dial, tc, timeout)),
		kgo.ClientID(clientID),
		kgo.RequestRetries(2),
		kgo.RetryTimeout(timeout),
		kgo.RequestTimeoutOverhead(timeout),
		kgo.MetadataMinAge(time.Second),
	}
	if m := mechanism(t, password); m != nil {
		opts = append(opts, kgo.SASL(m))
	}
	return opts, nil
}

func mechanism(t driver.Target, password string) sasl.Mechanism {
	switch t.SASL {
	case "plain":
		return plain.Auth{User: t.User, Pass: password}.AsMechanism()
	case "scram-sha-256":
		return scram.Auth{User: t.User, Pass: password}.AsSha256Mechanism()
	case "scram-sha-512":
		return scram.Auth{User: t.User, Pass: password}.AsSha512Mechanism()
	}
	return nil
}

// dialer opens each broker connection on its way (direct or --via) and
// adds TLS itself, checking the certificate against the broker's own name:
// the seed brokers and the ones they advertise each have theirs.
func dialer(dial DialFunc, tc *tls.Config, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		c, err := dial(dctx, network, addr)
		if err != nil || tc == nil {
			return c, err
		}
		cfg := tc.Clone()
		cfg.ServerName, _, _ = net.SplitHostPort(addr)
		tlsc := tls.Client(c, cfg)
		if err := tlsc.HandshakeContext(dctx); err != nil {
			c.Close()
			return nil, err
		}
		return tlsc, nil
	}
}

// client is a new franz-go client from the conn's options and extra ones
// (a producer, a consumer of given partitions).
func (k *Kafka) client(extra ...kgo.Opt) (*kgo.Client, error) {
	cl, err := kgo.NewClient(append(append([]kgo.Opt(nil), k.opts...), extra...)...)
	if err != nil {
		return nil, connectErr(k.t, err)
	}
	return cl, nil
}
