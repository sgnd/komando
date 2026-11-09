package nats

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/queuex"
)

// TestNatsLive runs every verb against a real NATS server with JetStream:
// set KOMANDO_E2E_NATS to the conn URL and KOMANDO_E2E_NATS_PASSWORD to
// its user's password.
func TestNatsLive(t *testing.T) {
	raw := os.Getenv("KOMANDO_E2E_NATS")
	if raw == "" {
		t.Skip("set KOMANDO_E2E_NATS=nats://USER@HOST:PORT and KOMANDO_E2E_NATS_PASSWORD")
	}
	tg, err := driver.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	q, err := Open(ctx, tg, os.Getenv("KOMANDO_E2E_NATS_PASSWORD"), nil, 10*time.Second, "komando-test")
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	inf, err := q.Info(ctx)
	if err != nil || inf.Version == "" || !inf.JetStream || inf.Account == nil {
		t.Fatalf("info: %+v %v", inf, err)
	}
	const name = "KOMANDO_LIVE"
	q.Delete(ctx, []string{name}, false) // left by an earlier run
	spec := queuex.TopicSpec{Topic: name, Partitions: -1, Replicas: -1, Config: map[string]string{"subjects": "live.>", "max_age": "1d", "retention": "workqueue"}}
	if c, err := q.Create(ctx, spec, true); err != nil || !c.DryRun || c.Retention != "workqueue" {
		t.Fatalf("dry-run create: %+v %v", c, err)
	}
	if _, err := q.Describe(ctx, name); code(err) != "STREAM_NOT_FOUND" {
		t.Fatalf("a dry run made the stream: %v", err)
	}
	if _, err := q.Create(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	defer q.Delete(context.Background(), []string{name}, false)
	if _, err := q.Create(ctx, spec, false); code(err) != "STREAM_EXISTS" {
		t.Errorf("create twice: %v", err)
	}
	liveSend(ctx, t, q, name)
	liveConsumer(ctx, t, q.(*Nats), name)
	livePeek(ctx, t, q, name)
	if p, err := q.Purge(ctx, name, true); err != nil || p.Messages != 4 {
		t.Errorf("dry-run purge: %+v %v", p, err)
	}
	if _, err := q.Purge(ctx, name, false); err != nil {
		t.Fatal(err)
	}
	if d, err := q.Delete(ctx, []string{name, "NOPE"}, true); err != nil || len(d) != 2 || !d[0].Exists || d[1].Exists {
		t.Errorf("dry-run rm: %+v %v", d, err)
	}
	if _, err := q.Delete(ctx, []string{name, "NOPE"}, false); code(err) != "STREAM_NOT_FOUND" {
		t.Errorf("rm with a missing stream: %v", err)
	}
	if _, err := q.Delete(ctx, []string{name}, false); err != nil {
		t.Fatal(err)
	}
}

func liveSend(ctx context.Context, t *testing.T, q queuex.Queue, name string) {
	for i := 1; i <= 6; i++ {
		s, err := q.Send(ctx, queuex.Message{Topic: fmt.Sprintf("live.orders.%d", i), Value: []byte(fmt.Sprintf(`{"id": %d}`, i)), Headers: [][2]string{{"source", "test"}}, Partition: -1}, false)
		if err != nil || s.Stream != name || *s.Sequence != uint64(i) {
			t.Fatalf("send %d: %+v %v", i, s, err)
		}
	}
	if s, err := q.Send(ctx, queuex.Message{Topic: "live.x", Value: []byte("x"), Partition: -1}, true); err != nil || s.Sequence != nil || s.Stream != name {
		t.Errorf("dry-run send: %+v %v", s, err)
	}
	if _, err := q.Send(ctx, queuex.Message{Topic: "nowhere", Value: []byte("x"), Partition: -1}, false); code(err) != "STREAM_NOT_FOUND" {
		t.Errorf("send to no stream: %v", err)
	}
	if _, err := q.Send(ctx, queuex.Message{Topic: name, Value: []byte("x"), Partition: -1}, false); code(err) != "STREAM_NOT_FOUND" {
		t.Errorf("send to a stream's name: %v", err)
	}
}

// liveConsumer adds a durable pull consumer that takes message 1 (a work
// queue removes it once acknowledged) and checks groups and lag.
func liveConsumer(ctx context.Context, t *testing.T, n *Nats, name string) {
	c, err := n.js.CreateConsumer(ctx, name, jetstream.ConsumerConfig{Durable: "billing", AckPolicy: jetstream.AckExplicitPolicy})
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Fetch(1)
	if err != nil {
		t.Fatal(err)
	}
	for m := range b.Messages() {
		m.DoubleAck(ctx)
	}
	gs, err := n.Groups(ctx)
	if err != nil || len(gs) != 1 || gs[0].Name != "billing" || gs[0].Stream != name || gs[0].Lag != 5 {
		t.Fatalf("groups: %+v %v", gs, err)
	}
	for _, g := range []string{"billing", name + "/billing"} {
		l, err := n.Lag(ctx, g)
		if err != nil || l.Lag != 5 || l.AckFloorSeq != 1 || l.Kind != "pull" {
			t.Errorf("lag %s: %+v %v", g, l, err)
		}
	}
	if _, err := n.Lag(ctx, "nobody"); code(err) != "CONSUMER_NOT_FOUND" {
		t.Errorf("lag of no consumer: %v", err)
	}
	d, err := n.Describe(ctx, name)
	if err != nil || d.Messages != 5 || len(d.ConsumerInfo) != 1 || d.Retention != "workqueue" || d.Limits.MaxAge != "24h0m0s" {
		t.Errorf("describe: %+v %v", d, err)
	}
}

func livePeek(ctx context.Context, t *testing.T, q queuex.Queue, name string) {
	s, err := q.(*Nats).js.Stream(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteMsg(ctx, 4); err != nil { // a hole in the middle
		t.Fatal(err)
	}
	p, err := q.Peek(ctx, queuex.PeekOptions{Topic: name, Limit: 3, Partition: -1})
	if err != nil || p.Count != 3 || !p.More || p.Messages[0].Sequence != 3 || p.Messages[2].Sequence != 6 || p.Messages[0].Headers["source"] != "test" {
		t.Fatalf("peek newest: %+v %v", p, err)
	}
	p, err = q.Peek(ctx, queuex.PeekOptions{Topic: name, Limit: 3, Oldest: true, Partition: -1})
	if err != nil || p.Count != 3 || p.Messages[0].Sequence != 2 || p.Messages[2].Sequence != 5 {
		t.Fatalf("peek oldest: %+v %v", p, err)
	}
	if ts, err := q.Topics(ctx, "KOMANDO_*", false); err != nil || len(ts) != 1 || ts[0].Messages != 4 {
		t.Errorf("peek removed messages, or ls is wrong: %+v %v", ts, err)
	}
	if _, err := q.Peek(ctx, queuex.PeekOptions{Topic: name, Limit: 1, Partition: 0}); code(err) != "NOT_SUPPORTED" {
		t.Errorf("peek --partition: %v", err)
	}
}
