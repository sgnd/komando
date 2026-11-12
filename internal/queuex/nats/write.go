package nats

import (
	"context"
	"errors"
	"sort"
	"strings"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// Send publishes one message to a subject and waits for the stream's
// acknowledgement. A stream must keep that subject: komando looks it up
// first, so a message never goes to a subject no stream keeps (core NATS
// would drop it without a word).
func (n *Nats) Send(ctx context.Context, m queuex.Message, dryRun bool) (*queuex.Sent, error) {
	switch {
	case m.Key != nil:
		return nil, queuex.NotSupported("--key", "nats", "a NATS message has no key: the subject says what it is about (put more in a --header)")
	case m.Partition >= 0:
		return nil, queuex.NotSupported("--partition", "nats", "a stream has no partitions: drop --partition")
	case m.Topic == "" || strings.ContainsAny(m.Topic, " \t\r\n*>") || strings.HasPrefix(m.Topic, ".") || strings.HasSuffix(m.Topic, ".") || strings.Contains(m.Topic, ".."):
		return nil, out.Usage("%q is not a subject to publish to: no spaces, no wildcards ('*', '>'), no empty part between dots", m.Topic)
	}
	stream, err := n.js.StreamNameBySubject(ctx, m.Topic)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		return nil, n.noStreamFor(ctx, m.Topic)
	}
	if err != nil {
		return nil, n.opErr(err, m.Topic)
	}
	res := &queuex.Sent{NatsSent: &queuex.NatsSent{Subject: m.Topic, Stream: stream}, Size: len(m.Value), DryRun: dryRun}
	if dryRun {
		return res, nil
	}
	msg := &natsgo.Msg{Subject: m.Topic, Data: m.Value}
	for _, h := range m.Headers {
		if msg.Header == nil {
			msg.Header = natsgo.Header{}
		}
		msg.Header.Add(h[0], h[1])
	}
	ack, err := n.js.PublishMsg(ctx, msg, jetstream.WithRetryAttempts(0)) // no Nats-Expected-Stream: the stream would keep that header
	if err != nil {
		return nil, n.opErr(err, m.Topic)
	}
	res.Stream, res.Sequence, res.Duplicate = ack.Stream, &ack.Sequence, ack.Duplicate
	return res, nil
}

// noStreamFor is the error for a subject no stream keeps; when it is a
// stream's name, the hint gives that stream's subjects.
func (n *Nats) noStreamFor(ctx context.Context, subject string) error {
	hint := "send takes a subject a stream keeps: see each stream's subjects with `komando queue list CONN`, or make a stream for it with `komando queue create CONN NAME --config subjects=" + subject + "`"
	if checkName("stream", subject) == nil {
		if s, err := n.js.Stream(ctx, subject); err == nil {
			hint = subject + " is a stream: send to one of its subjects (" + strings.Join(s.CachedInfo().Config.Subjects, ", ") + ")"
		}
	}
	return out.Errf(out.ExitNotFound, "STREAM_NOT_FOUND", hint, "no stream keeps messages sent to subject %s", subject)
}

// Create makes a stream. The server cannot check a stream without making
// it, so a dry run checks the name is free and komando's reading of the
// settings, and makes nothing.
func (n *Nats) Create(ctx context.Context, s queuex.TopicSpec, dryRun bool) (*queuex.Created, error) {
	switch {
	case s.Partitions != -1:
		return nil, queuex.NotSupported("--partitions", "nats", "a stream has no partitions; --replicas sets its copies on a cluster")
	case s.Type != "":
		return nil, queuex.NotSupported("--type", "nats", "a stream has no type: use --config storage=memory or --config retention=workqueue")
	}
	if err := checkName("stream", s.Topic); err != nil {
		return nil, err
	}
	cfg, err := streamConfig(s)
	if err != nil {
		return nil, err
	}
	if _, err := n.js.Stream(ctx, s.Topic); err == nil {
		return nil, streamExists(s.Topic)
	} else if !errors.Is(err, jetstream.ErrStreamNotFound) {
		return nil, n.opErr(err, s.Topic)
	}
	res := &queuex.Created{NatsCreated: &queuex.NatsCreated{Stream: s.Topic, Subjects: cfg.Subjects, Storage: word(cfg.Storage), Retention: word(cfg.Retention),
		Discard: word(cfg.Discard), NumReplicas: cfg.Replicas, Limits: limits(cfg)}, DryRun: dryRun}
	if dryRun {
		return res, nil
	}
	if _, err := n.js.CreateStream(ctx, cfg); err != nil {
		return nil, n.opErr(err, s.Topic)
	}
	return res, nil
}

// Delete deletes streams with their messages and consumers. Every name
// must exist; with dry run it only says what each holds.
func (n *Nats) Delete(ctx context.Context, streams []string, dryRun bool) ([]queuex.Deleted, error) {
	res := []queuex.Deleted{}
	for _, name := range streams {
		d := queuex.Deleted{Stream: name}
		s, err := n.stream(ctx, name)
		switch e, _ := err.(*out.Error); {
		case err == nil:
			st := s.CachedInfo().State
			consumers := st.Consumers
			d.Exists, d.Messages, d.Consumers = true, int64(st.Msgs), &consumers
		case e == nil || e.Code != "STREAM_NOT_FOUND":
			return nil, err
		}
		res = append(res, d)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Stream < res[j].Stream })
	if dryRun {
		return res, nil
	}
	for _, d := range res {
		if !d.Exists {
			return nil, streamNotFound(d.Stream)
		}
	}
	for _, d := range res {
		if err := n.js.DeleteStream(ctx, d.Stream); err != nil {
			return nil, n.opErr(err, d.Stream)
		}
	}
	return res, nil
}

// Purge deletes every message of a stream; the stream and its consumers
// stay.
func (n *Nats) Purge(ctx context.Context, stream string, dryRun bool) (*queuex.Purged, error) {
	s, err := n.stream(ctx, stream)
	if err != nil {
		return nil, err
	}
	res := &queuex.Purged{Stream: stream, Messages: int64(s.CachedInfo().State.Msgs), DryRun: dryRun}
	if dryRun {
		return res, nil
	}
	if err := s.Purge(ctx); err != nil {
		return nil, n.opErr(err, stream)
	}
	return res, nil
}
