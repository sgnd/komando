package queuex

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kfake"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// fakeCluster is an in-process Kafka (franz-go's kfake) for the tests.
func fakeCluster(t *testing.T, opts ...kfake.Opt) *kfake.Cluster {
	t.Helper()
	c, err := kfake.NewCluster(append([]kfake.Opt{kfake.NumBrokers(1)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func open(t *testing.T, raw, password string, dial DialFunc) Queue {
	t.Helper()
	tg, err := driver.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q, err := Open(ctx, tg, password, dial, 5*time.Second, "komando-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(q.Close)
	return q
}

func code(err error) string {
	var e *out.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return fmt.Sprint(err)
}

func TestKafkaRoundTrip(t *testing.T) {
	c := fakeCluster(t)
	var dials atomic.Int32
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) { // like --via: every broker connection goes here
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	q := open(t, "kafka://"+strings.Join(c.ListenAddrs(), ","), "", dial)
	ctx := context.Background()

	if _, err := q.Create(ctx, TopicSpec{Topic: "orders", Partitions: 2, Replicas: 1}, true); err != nil {
		t.Fatal(err)
	}
	if ts, _ := q.Topics(ctx, "", false); len(ts) != 0 {
		t.Fatalf("a dry-run create made a topic: %+v", ts)
	}
	cr, err := q.Create(ctx, TopicSpec{Topic: "orders", Partitions: 2, Replicas: 1, Config: map[string]string{"retention.ms": "3600000"}}, false)
	if err != nil || cr.Partitions != 2 {
		t.Fatalf("create: %+v %v", cr, err)
	}
	if _, err := q.Create(ctx, TopicSpec{Topic: "orders", Partitions: 1, Replicas: 1}, false); code(err) != "TOPIC_EXISTS" {
		t.Errorf("second create: %v", err)
	}
	if _, err := q.Send(ctx, Message{Topic: "nope", Value: []byte("x"), Partition: -1}, false); code(err) != "TOPIC_NOT_FOUND" {
		t.Errorf("send to a missing topic: %v", err)
	}
	if _, err := q.Send(ctx, Message{Topic: "orders", Value: []byte("x"), Partition: 7}, false); code(err) != "PARTITION_NOT_FOUND" {
		t.Errorf("send to a missing partition: %v", err)
	}
	dry, err := q.Send(ctx, Message{Topic: "orders", Value: []byte("x"), Partition: -1}, true)
	if err != nil || !dry.DryRun || dry.Offset != nil {
		t.Fatalf("dry send: %+v %v", dry, err)
	}
	for i := range 5 {
		s, err := q.Send(ctx, Message{Topic: "orders", Key: []byte(fmt.Sprint("k", i)), Value: []byte(fmt.Sprint("order ", i)),
			Headers: [][2]string{{"source", "test"}}, Partition: int32(i % 2)}, false)
		if err != nil || *s.Partition != int32(i%2) {
			t.Fatalf("send %d: %+v %v", i, s, err)
		}
		time.Sleep(2 * time.Millisecond) // distinct timestamps, so peek's order is known
	}
	if _, err := q.Send(ctx, Message{Topic: "orders", Value: []byte{0xff, 0x00, 0xfe}, Partition: 0}, false); err != nil {
		t.Fatal(err)
	}

	ts, err := q.Topics(ctx, "ord*", false)
	if err != nil || len(ts) != 1 || ts[0].Messages != 6 || ts[0].Partitions != 2 {
		t.Fatalf("topics: %+v %v", ts, err)
	}
	if ts, _ := q.Topics(ctx, "x*", false); len(ts) != 0 {
		t.Errorf("pattern x* matched %+v", ts)
	}

	p, err := q.Peek(ctx, PeekOptions{Topic: "orders", Limit: 3, Partition: -1})
	if err != nil || p.Count != 3 || !p.More || p.Partial {
		t.Fatalf("peek newest: %+v %v", p, err)
	}
	if p.Messages[0].Value != "order 3" || p.Messages[1].Value != "order 4" || p.Messages[2].Encoding != "base64" {
		t.Errorf("peek newest gave %+v", p.Messages)
	}
	if h := p.Messages[0].Headers["source"]; h != "test" || *p.Messages[0].Key != "k3" {
		t.Errorf("headers %v key %v", p.Messages[0].Headers, *p.Messages[0].Key)
	}
	p, err = q.Peek(ctx, PeekOptions{Topic: "orders", Limit: 2, Oldest: true, Partition: 1, MaxBytes: 4})
	if err != nil || p.Count != 2 || p.Messages[0].Value != "orde" || !p.Messages[0].ValueTruncated || p.Messages[1].Offset != 1 {
		t.Fatalf("peek oldest of partition 1: %+v %v", p, err)
	}

	// peek moved no group: there is none
	if gs, err := q.Groups(ctx); err != nil || len(gs) != 0 {
		t.Fatalf("groups after peek: %+v %v", gs, err)
	}
	k := q.(*Kafka)
	commit := kadm.Offsets{}
	commit.Add(kadm.Offset{Topic: "orders", Partition: 0, At: 1, LeaderEpoch: -1})
	commit.Add(kadm.Offset{Topic: "orders", Partition: 1, At: 2, LeaderEpoch: -1})
	if _, err := k.adm.CommitOffsets(ctx, "billing", commit); err != nil {
		t.Fatal(err)
	}
	gs, err := q.Groups(ctx)
	if err != nil || len(gs) != 1 || gs[0].Name != "billing" || gs[0].Lag != 3 {
		t.Fatalf("groups: %+v %v", gs, err)
	}
	lag, err := q.Lag(ctx, "billing")
	if err != nil || lag.Lag != 3 || len(lag.Partitions) != 2 || lag.Partitions[0].Lag != 3 || lag.Partitions[1].Lag != 0 {
		t.Fatalf("lag: %+v %v", lag, err)
	}
	if _, err := q.Lag(ctx, "nobody"); code(err) != "CONSUMER_GROUP_NOT_FOUND" {
		t.Errorf("lag of a missing group: %v", err)
	}

	d, err := q.Describe(ctx, "orders")
	if err != nil || len(d.Partitions) != 2 || d.Messages != 6 || len(d.Groups) != 1 || d.Groups[0].Lag != 3 {
		t.Fatalf("describe: %+v %v", d, err)
	}
	if _, err := q.Describe(ctx, "nope"); code(err) != "TOPIC_NOT_FOUND" {
		t.Errorf("describe a missing topic: %v", err)
	}

	pg, err := q.Purge(ctx, "orders", true)
	if err != nil || pg.Messages != 6 {
		t.Fatalf("dry purge: %+v %v", pg, err)
	}
	if ts, _ := q.Topics(ctx, "orders", false); ts[0].Messages != 6 {
		t.Fatal("a dry-run purge removed messages")
	}
	if pg, err = q.Purge(ctx, "orders", false); err != nil || pg.Messages != 6 {
		t.Fatalf("purge: %+v %v", pg, err)
	}
	if ts, _ := q.Topics(ctx, "orders", false); ts[0].Messages != 0 {
		t.Errorf("after purge: %+v", ts)
	}
	if p, err := q.Peek(ctx, PeekOptions{Topic: "orders", Limit: 3, Partition: -1}); err != nil || p.Count != 0 || p.More {
		t.Errorf("peek an empty topic: %+v %v", p, err)
	}

	del, err := q.Delete(ctx, []string{"orders", "ghost"}, true)
	if err != nil || len(del) != 2 || del[0].Exists || !del[1].Exists {
		t.Fatalf("dry delete: %+v %v", del, err)
	}
	if _, err := q.Delete(ctx, []string{"orders", "ghost"}, false); code(err) != "TOPIC_NOT_FOUND" {
		t.Errorf("delete with a missing topic: %v", err)
	}
	if _, err := q.Delete(ctx, []string{"orders"}, false); err != nil {
		t.Fatal(err)
	}
	fresh := open(t, "kafka://"+c.ListenAddrs()[0], "", nil) // q keeps the brokers' list of topics for a second
	if ts, _ := fresh.Topics(ctx, "", false); len(ts) != 0 {
		t.Errorf("after delete: %+v", ts)
	}

	inf, err := q.Info(ctx)
	if err != nil || len(inf.Brokers) != 1 || !inf.Brokers[0].Controller {
		t.Fatalf("info: %+v %v", inf, err)
	}
	if dials.Load() == 0 {
		t.Error("the conn's dialer was not used")
	}
}

func TestKafkaSASL(t *testing.T) {
	c := fakeCluster(t, kfake.EnableSASL(), kfake.Superuser("SCRAM-SHA-512", "app", "s3cret"))
	addr := c.ListenAddrs()[0]
	q := open(t, "kafka://app@"+addr+"?sasl=scram-sha-512", "s3cret", nil)
	if _, err := q.Info(context.Background()); err != nil {
		t.Fatal(err)
	}
	tg, _ := driver.Parse("kafka://app@" + addr + "?sasl=scram-sha-512")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Open(ctx, tg, "wrong", nil, 3*time.Second, "komando-test")
	if c := code(err); c != "QUEUE_AUTH" && c != "QUEUE_CONNECT" { // kfake hangs up; Kafka answers SASL_AUTHENTICATION_FAILED
		t.Fatalf("wrong password: %v", err)
	}
	if strings.Contains(err.Error(), "wrong") || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("the error shows a password: %v", err)
	}
}

func TestKafkaUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // nothing listens there now
	tg, _ := driver.Parse("kafka://" + addr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = Open(ctx, tg, "", nil, 2*time.Second, "komando-test")
	if c := code(err); c != "QUEUE_CONNECT" && c != "TIMEOUT" {
		t.Fatalf("got %v", err)
	}
}

func TestText(t *testing.T) {
	for _, c := range []struct {
		in       []byte
		max      int
		want     string
		encoding string
		cut      bool
	}{
		{[]byte("hello"), 0, "hello", "", false},
		{[]byte("héllo"), 2, "h", "", true}, // é cut in half is dropped
		{[]byte{0xff, 0x01}, 0, "/wE=", "base64", false},
		{[]byte{0xff, 0x01, 0x02}, 2, "/wE=", "base64", true},
	} {
		got, enc, cut := text(c.in, c.max)
		if got != c.want || enc != c.encoding || cut != c.cut {
			t.Errorf("text(%q, %d) = %q %q %v", c.in, c.max, got, enc, cut)
		}
	}
}

func TestConnectErr(t *testing.T) {
	tg, _ := driver.Parse("kafka://app@b1:9093?tls=true&sasl=plain")
	for err, want := range map[error]string{
		kerr.SaslAuthenticationFailed:                               "QUEUE_AUTH",
		kerr.UnsupportedSaslMechanism:                               "QUEUE_AUTH",
		&kadm.AuthError{Err: kerr.ClusterAuthorizationFailed}:       "QUEUE_DENIED",
		context.DeadlineExceeded:                                    "TIMEOUT",
		errors.New("x509: certificate signed by unknown authority"): "QUEUE_CONNECT",
		errors.New("EOF"):                                           "QUEUE_CONNECT",
	} {
		if got := code(connectErr(tg, err)); got != want {
			t.Errorf("%v: got %s, want %s", err, got, want)
		}
	}
	for err, want := range map[error]string{
		kerr.UnknownTopicOrPartition:  "TOPIC_NOT_FOUND",
		kerr.TopicAlreadyExists:       "TOPIC_EXISTS",
		kerr.TopicAuthorizationFailed: "QUEUE_DENIED",
		kerr.GroupIDNotFound:          "CONSUMER_GROUP_NOT_FOUND",
		kerr.PolicyViolation:          "QUEUE_ERROR",
	} {
		if got := code(opErr(err, "orders")); got != want {
			t.Errorf("%v: got %s, want %s", err, got, want)
		}
	}
}
