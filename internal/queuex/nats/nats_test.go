package nats

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

func code(err error) string {
	var e *out.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

func open(t *testing.T, f *fakeServer, url, password string) (*Nats, error) {
	t.Helper()
	tg, err := driver.Parse(url)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	q, err := queuex.Open(ctx, tg, password, nil, 2*time.Second, "komando-test")
	if err != nil {
		return nil, err
	}
	t.Cleanup(q.Close)
	return q.(*Nats), nil
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func orders(f *fakeServer) *fakeStream {
	s := f.add(jetstream.StreamConfig{Name: "ORDERS", Subjects: []string{"orders.>"}, Retention: jetstream.WorkQueuePolicy, MaxAge: time.Hour, Replicas: 1},
		`{"id": 1}`, `{"id": 2}`, `{"id": 3}`, "\xff\xfe", `{"id": 5}`)
	s.consumers = []*jetstream.ConsumerInfo{{Stream: "ORDERS", Name: "billing", Config: jetstream.ConsumerConfig{Durable: "billing", AckPolicy: jetstream.AckExplicitPolicy, FilterSubject: "orders.>"},
		NumPending: 3, NumAckPending: 1, NumWaiting: 2, Delivered: jetstream.SequenceInfo{Stream: 2}, AckFloor: jetstream.SequenceInfo{Stream: 1}}}
	return s
}

func TestNatsRead(t *testing.T) {
	f := newFake(t)
	orders(f)
	f.add(jetstream.StreamConfig{Name: "KV_config", Subjects: []string{"$KV.config.>"}, Storage: jetstream.MemoryStorage})
	n, err := open(t, f, "nats://"+f.addr(), "")
	if err != nil {
		t.Fatal(err)
	}
	inf, err := n.Info(ctx(t))
	if err != nil || inf.Engine != "nats" || inf.Version != "2.12.1" || !inf.JetStream || inf.Account.Streams != 2 || inf.ServerName != "fake-1" || inf.ClusterName != "lab" {
		t.Fatalf("info: %+v %v", inf, err)
	}
	ts, err := n.Topics(ctx(t), "", false)
	if err != nil || len(ts) != 2 || ts[0].Name != "KV_config" || ts[1].Messages != 5 || ts[1].Retention != "workqueue" || ts[0].Storage != "memory" || ts[1].ConsumerCount != 1 {
		t.Fatalf("ls: %+v %v", ts, err)
	}
	if ts, _ := n.Topics(ctx(t), "ORD*", false); len(ts) != 1 {
		t.Errorf("ls ORD*: %+v", ts)
	}
	if _, err := n.Topics(ctx(t), "", true); code(err) != "NOT_SUPPORTED" {
		t.Errorf("ls --internal: %v", err)
	}
	d, err := n.Describe(ctx(t), "ORDERS")
	if err != nil || d.Messages != 5 || d.Limits.MaxAge != "1h0m0s" || len(d.ConsumerInfo) != 1 || d.ConsumerInfo[0].Consumer != "billing" || d.FirstTime == nil {
		t.Fatalf("describe: %+v %v", d, err)
	}
	for name, want := range map[string]string{"NOPE": "STREAM_NOT_FOUND", "a.b": "USAGE"} {
		if _, err := n.Describe(ctx(t), name); code(err) != want {
			t.Errorf("describe %s: %v, want %s", name, err, want)
		}
	}
	gs, err := n.Groups(ctx(t))
	if err != nil || len(gs) != 1 || gs[0].Lag != 3 || gs[0].State != "active" || gs[0].Members != 2 || gs[0].Kind != "pull" || gs[0].AckPolicy != "explicit" {
		t.Fatalf("groups: %+v %v", gs, err)
	}
	for _, g := range []string{"billing", "ORDERS/billing"} {
		if l, err := n.Lag(ctx(t), g); err != nil || l.Lag != 3 || l.Group != "billing" || l.DeliveredSeq != 2 {
			t.Errorf("lag %s: %+v %v", g, l, err)
		}
	}
	for g, want := range map[string]string{"nobody": "CONSUMER_NOT_FOUND", "ORDERS/nobody": "CONSUMER_NOT_FOUND", "NOPE/billing": "STREAM_NOT_FOUND", "ORDERS/a.b": "USAGE"} {
		if _, err := n.Lag(ctx(t), g); code(err) != want {
			t.Errorf("lag %s: %v, want %s", g, err, want)
		}
	}
}

func TestNatsLagTwoStreams(t *testing.T) {
	f := newFake(t)
	orders(f)
	s := f.add(jetstream.StreamConfig{Name: "RETURNS", Subjects: []string{"returns.>"}})
	s.consumers = []*jetstream.ConsumerInfo{{Stream: "RETURNS", Name: "billing", Config: jetstream.ConsumerConfig{DeliverSubject: "deliver.x"}, PushBound: true}}
	n, err := open(t, f, "nats://"+f.addr(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Lag(ctx(t), "billing"); code(err) != "USAGE" || !strings.Contains(err.Error(), "ORDERS, RETURNS") {
		t.Errorf("lag of a name in two streams: %v", err)
	}
	if l, err := n.Lag(ctx(t), "RETURNS/billing"); err != nil || l.Kind != "push" || l.State != "active" || l.Members != 1 {
		t.Errorf("push consumer: %+v %v", l, err)
	}
}

func TestNatsPeek(t *testing.T) {
	f := newFake(t)
	s := orders(f)
	n, err := open(t, f, "nats://"+f.addr(), "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := n.Peek(ctx(t), queuex.PeekOptions{Topic: "ORDERS", Limit: 2, Partition: -1})
	if err != nil || p.Count != 2 || !p.More || p.From != "newest" || p.Messages[0].Sequence != 4 || p.Messages[0].Encoding != "base64" || p.Messages[1].Value != `{"id": 5}` {
		t.Fatalf("peek newest: %+v %v", p, err)
	}
	p, err = n.Peek(ctx(t), queuex.PeekOptions{Topic: "ORDERS", Limit: 2, Oldest: true, Partition: -1, MaxBytes: 4})
	if err != nil || p.Count != 2 || p.From != "oldest" || p.Messages[0].Sequence != 1 || p.Messages[0].Value != `{"id` || !p.Messages[0].ValueTruncated {
		t.Fatalf("peek oldest: %+v %v", p, err)
	}
	// holes in the middle: the newest are found from the deleted list
	f.mu.Lock()
	s.msgs = append(s.msgs[:1], s.msgs[3:]...) // 2 and 3 are gone
	s.deleted = []uint64{2, 3}
	f.mu.Unlock()
	p, err = n.Peek(ctx(t), queuex.PeekOptions{Topic: "ORDERS", Limit: 3, Partition: -1})
	if err != nil || p.Count != 3 || p.Messages[0].Sequence != 1 || p.Messages[2].Sequence != 5 || p.More || p.Partial {
		t.Fatalf("peek over holes: %+v %v", p, err)
	}
	if _, err := n.Peek(ctx(t), queuex.PeekOptions{Topic: "ORDERS", Limit: 1, Partition: 0}); code(err) != "NOT_SUPPORTED" {
		t.Errorf("peek --partition: %v", err)
	}
	f.add(jetstream.StreamConfig{Name: "EMPTY", Subjects: []string{"empty.>"}})
	if p, err := n.Peek(ctx(t), queuex.PeekOptions{Topic: "EMPTY", Limit: 3, Partition: -1}); err != nil || p.Count != 0 || p.More {
		t.Errorf("peek empty: %+v %v", p, err)
	}
}

func TestNatsWrite(t *testing.T) {
	f := newFake(t)
	orders(f)
	n, err := open(t, f, "nats://"+f.addr(), "")
	if err != nil {
		t.Fatal(err)
	}
	s, err := n.Send(ctx(t), queuex.Message{Topic: "orders.new", Value: []byte("hi"), Headers: [][2]string{{"source", "test"}}, Partition: -1}, false)
	if err != nil || s.Stream != "ORDERS" || *s.Sequence != 6 || s.Size != 2 {
		t.Fatalf("send: %+v %v", s, err)
	}
	if got := string(f.streams["ORDERS"].msgs[5].hdr); !strings.Contains(got, "source: test") {
		t.Errorf("headers sent: %q", got)
	}
	if s, err := n.Send(ctx(t), queuex.Message{Topic: "orders.new", Value: []byte("hi"), Partition: -1}, true); err != nil || s.Sequence != nil || len(f.streams["ORDERS"].msgs) != 6 {
		t.Errorf("dry-run send: %+v %v", s, err)
	}
	for m, want := range map[*queuex.Message]string{
		{Topic: "ORDERS", Partition: -1}:                     "STREAM_NOT_FOUND",
		{Topic: "nowhere", Partition: -1}:                    "STREAM_NOT_FOUND",
		{Topic: "orders.*", Partition: -1}:                   "USAGE",
		{Topic: "orders..x", Partition: -1}:                  "USAGE",
		{Topic: "orders.x", Key: []byte("k"), Partition: -1}: "NOT_SUPPORTED",
		{Topic: "orders.x", Partition: 1}:                    "NOT_SUPPORTED",
	} {
		if _, err := n.Send(ctx(t), *m, false); code(err) != want {
			t.Errorf("send %+v: %v, want %s", *m, err, want)
		} else if m.Topic == "ORDERS" && !strings.Contains(err.(*out.Error).Hint, "orders.>") {
			t.Errorf("send to a stream's name: hint %q", err.(*out.Error).Hint)
		}
	}

	spec := queuex.TopicSpec{Topic: "EVENTS", Partitions: -1, Replicas: 3, Config: map[string]string{"subjects": "events.>, audit.*", "storage": "memory", "max_age": "7d", "max_msgs": "1000"}}
	c, err := n.Create(ctx(t), spec, true)
	if err != nil || !c.DryRun || c.NumReplicas != 3 || c.Storage != "memory" || c.Limits.MaxAge != "168h0m0s" || len(c.Subjects) != 2 || f.streams["EVENTS"] != nil {
		t.Fatalf("dry-run create: %+v %v", c, err)
	}
	if _, err := n.Create(ctx(t), spec, false); err != nil || f.streams["EVENTS"] == nil || f.streams["EVENTS"].cfg.MaxMsgs != 1000 {
		t.Fatalf("create: %v", err)
	}
	if _, err := n.Create(ctx(t), spec, false); code(err) != "STREAM_EXISTS" {
		t.Errorf("create twice: %v", err)
	}
	if c, err := n.Create(ctx(t), queuex.TopicSpec{Topic: "PLAIN", Partitions: -1, Replicas: -1}, true); err != nil || c.Subjects[0] != "PLAIN" || c.NumReplicas != 1 || c.Retention != "limits" {
		t.Errorf("create with defaults: %+v %v", c, err)
	}
	for _, sp := range []queuex.TopicSpec{{Topic: "X", Partitions: 3, Replicas: -1}, {Topic: "X", Partitions: -1, Replicas: -1, Type: "quorum"}} {
		if _, err := n.Create(ctx(t), sp, true); code(err) != "NOT_SUPPORTED" {
			t.Errorf("create %+v: %v", sp, err)
		}
	}

	if p, err := n.Purge(ctx(t), "ORDERS", true); err != nil || p.Messages != 6 || len(f.streams["ORDERS"].msgs) != 6 {
		t.Errorf("dry-run purge: %+v %v", p, err)
	}
	if p, err := n.Purge(ctx(t), "ORDERS", false); err != nil || p.Messages != 6 || len(f.streams["ORDERS"].msgs) != 0 {
		t.Errorf("purge: %+v %v", p, err)
	}
	d, err := n.Delete(ctx(t), []string{"ORDERS", "NOPE"}, true)
	if err != nil || len(d) != 2 || d[0].Stream != "NOPE" || d[0].Exists || !d[1].Exists || *d[1].Consumers != 1 {
		t.Errorf("dry-run rm: %+v %v", d, err)
	}
	if _, err := n.Delete(ctx(t), []string{"ORDERS", "NOPE"}, false); code(err) != "STREAM_NOT_FOUND" || f.streams["ORDERS"] == nil {
		t.Errorf("rm with a missing stream: %v", err)
	}
	if _, err := n.Delete(ctx(t), []string{"ORDERS"}, false); err != nil || f.streams["ORDERS"] != nil {
		t.Errorf("rm: %v", err)
	}
}

func TestNatsStreamConfig(t *testing.T) {
	for k, v := range map[string]string{"storage": "disk", "retention": "forever", "discard": "all", "max_msgs": "lots", "max_age": "-1h", "duplicate_window": "xd",
		"subjects": " , ", "max_msg_size": "99999999999", "max_consumers": "x", "max_bytes": "1e9", "max_msgs_per_subject": "?", "replicas": "3"} {
		if _, err := streamConfig(queuex.TopicSpec{Topic: "S", Config: map[string]string{k: v}}); code(err) != "USAGE" {
			t.Errorf("%s=%s: %v", k, v, err)
		}
	}
	cfg, err := streamConfig(queuex.TopicSpec{Topic: "S", Config: map[string]string{"retention": "Interest", "discard": "new", "description": "test",
		"duplicate_window": "2m", "max_bytes": "1024", "max_msg_size": "512", "max_consumers": "4", "max_msgs_per_subject": "1", "storage": "file"}})
	if err != nil || cfg.Retention != jetstream.InterestPolicy || cfg.Discard != jetstream.DiscardNew || cfg.Duplicates != 2*time.Minute || cfg.MaxBytes != 1024 ||
		cfg.MaxMsgSize != 512 || cfg.MaxConsumers != 4 || cfg.MaxMsgsPerSubject != 1 || cfg.Description != "test" {
		t.Errorf("config: %+v %v", cfg, err)
	}
}

func TestNatsLogin(t *testing.T) {
	f := newFake(t, func(f *fakeServer) { f.user, f.pass = "app", "natspass" })
	if _, err := open(t, f, "nats://app@"+f.addr(), "natspass"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := open(t, f, "nats://app@"+f.addr(), "wrong"); code(err) != "QUEUE_AUTH" {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := open(t, f, "tls://"+f.addr(), ""); code(err) != "QUEUE_CONNECT" {
		t.Errorf("tls to a server without TLS: %v", err)
	}
	ln := newFake(t)
	addr := ln.addr()
	ln.ln.Close()
	if _, err := open(t, ln, "nats://"+addr, ""); code(err) != "QUEUE_CONNECT" {
		t.Errorf("nothing listening: %v", err)
	}
}

func TestNatsNoJetStream(t *testing.T) {
	f := newFake(t, func(f *fakeServer) { f.noJS = true })
	n, err := open(t, f, "nats://"+f.addr(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if inf, err := n.Info(ctx(t)); err != nil || inf.JetStream || inf.Account != nil {
		t.Errorf("info without JetStream: %+v %v", inf, err)
	}
	if _, err := n.Topics(ctx(t), "", false); code(err) != "NOT_SUPPORTED" {
		t.Errorf("ls without JetStream: %v", err)
	}
}

func TestNatsDenied(t *testing.T) {
	f := newFake(t, func(f *fakeServer) { f.deny = "$JS.API.STREAM.PURGE" })
	orders(f)
	n, err := open(t, f, "nats://"+f.addr(), "")
	if err != nil {
		t.Fatal(err)
	}
	c, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := n.Purge(c, "ORDERS", false); code(err) != "QUEUE_DENIED" {
		t.Errorf("purge without the right: %v", err)
	}
	if _, err := n.Describe(ctx(t), "NOPE"); code(err) != "STREAM_NOT_FOUND" {
		t.Errorf("an answer after a refusal: %v", err)
	}
}

func TestNatsCreds(t *testing.T) {
	const seed = "SUAMK2FG4MI6UE3ACF3FK3OIQBCEIEZV7NSWFFEW63UXMRLFM2XLAXK4GY"
	const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJzdWIiOiJVQUJDIn0.sig"
	file := "-----BEGIN NATS USER JWT-----\n" + jwt + "\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n" + seed + "\n------END USER NKEY SEED------\n"
	vault := map[string]string{"secret:good": file, "secret:bad": "not a creds file"}
	driver.ResolveSecret = func(ref string) (string, error) {
		if v, ok := vault[ref]; ok {
			return v, nil
		}
		return "", driver.ErrSecretNotFound
	}
	defer func() { driver.ResolveSecret = nil }()
	got, kp, err := creds("secret:good")
	if err != nil || got != jwt || kp == nil {
		t.Fatalf("creds: %q %v", got, err)
	}
	if _, _, err := creds("secret:bad"); code(err) != "QUEUE_AUTH" || strings.Contains(err.Error(), "not a creds file") {
		t.Errorf("bad creds: %v", err)
	}
	if _, _, err := creds("secret:none"); code(err) != "SECRET_NOT_FOUND" {
		t.Errorf("no creds: %v", err)
	}
	tg, _ := driver.Parse("nats://h?creds=secret:good")
	if o, err := loginOption(tg, ""); err != nil || o == nil {
		t.Errorf("login option: %v", err)
	}
}
