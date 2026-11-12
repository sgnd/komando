package rabbitmq

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// TestRabbitLive runs every verb against a real RabbitMQ: set
// KOMANDO_E2E_RABBITMQ to the conn URL (with ?management=PORT) and
// KOMANDO_E2E_RABBITMQ_PASSWORD to its user's password. peek gives every
// message back (marked redelivered), on classic and quorum queues alike.
func TestRabbitLive(t *testing.T) {
	raw := os.Getenv("KOMANDO_E2E_RABBITMQ")
	if raw == "" {
		t.Skip("set KOMANDO_E2E_RABBITMQ=amqp://USER@HOST:PORT/?management=PORT and KOMANDO_E2E_RABBITMQ_PASSWORD")
	}
	tg, err := driver.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	q, err := Open(ctx, tg, os.Getenv("KOMANDO_E2E_RABBITMQ_PASSWORD"), nil, 10*time.Second, "komando-test")
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	inf, err := q.Info(ctx)
	if err != nil || inf.Version == "" || inf.Product != "RabbitMQ" || inf.Totals == nil || len(inf.Nodes) == 0 {
		t.Fatalf("info: %+v %+v %v", inf, inf.RabbitInfo, err)
	}
	for _, typ := range []string{"classic", "quorum"} {
		t.Run(typ, func(t *testing.T) { liveQueue(ctx, t, q, typ) })
	}
	q.Delete(ctx, []string{"komando-live-stream"}, false) // left by an earlier run
	if _, err := q.Create(ctx, queuex.TopicSpec{Topic: "komando-live-stream", Type: "stream", Partitions: -1, Replicas: -1}, false); err != nil {
		t.Fatal(err)
	}
	defer func() {
		q, _ := Open(context.Background(), tg, os.Getenv("KOMANDO_E2E_RABBITMQ_PASSWORD"), nil, 10*time.Second, "komando-test")
		defer q.Close()
		if _, err := q.Delete(context.Background(), []string{"komando-live-stream"}, false); err != nil {
			t.Errorf("rm the stream: %v", err)
		}
	}()
	if _, err := q.Send(ctx, queuex.Message{Topic: "komando-live-stream", Value: []byte("s"), Partition: -1}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Peek(ctx, queuex.PeekOptions{Topic: "komando-live-stream", Limit: 1, Partition: -1}); code(err) != "NOT_SUPPORTED" {
		t.Errorf("peek a stream: %v", err)
	}
	tg.Management = ""
	if q, err := Open(ctx, tg, os.Getenv("KOMANDO_E2E_RABBITMQ_PASSWORD"), nil, 10*time.Second, "komando-test"); err == nil {
		if _, err := q.Peek(ctx, queuex.PeekOptions{Topic: "komando-live-stream", Limit: 1, Partition: -1}); code(err) != "NOT_SUPPORTED" {
			t.Errorf("peek a stream without the management API: %v", err)
		}
		q.Close()
	}
	// AMQP only: describe still works, ls says what it needs
	tg.Management = ""
	q2, err := Open(ctx, tg, os.Getenv("KOMANDO_E2E_RABBITMQ_PASSWORD"), nil, 10*time.Second, "komando-test")
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	if _, err := q2.Topics(ctx, "", false, 0); code(err) != "NOT_SUPPORTED" {
		t.Errorf("ls without management: %v", err)
	}
	if inf, err := q2.Info(ctx); err != nil || inf.Version == "" || inf.Management {
		t.Errorf("info without management: %+v %v", inf, err)
	}
}

func liveQueue(ctx context.Context, t *testing.T, q queuex.Queue, typ string) {
	name := "komando-live-" + typ
	spec := queuex.TopicSpec{Topic: name, Type: typ, Partitions: -1, Replicas: -1, Config: map[string]string{"x-max-length": "100"}}
	if _, err := q.Create(ctx, spec, true); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Describe(ctx, name); code(err) != "QUEUE_NOT_FOUND" {
		t.Fatalf("a dry-run create made the queue: %v", err)
	}
	if _, err := q.Create(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	defer q.Delete(context.Background(), []string{name}, false)
	if _, err := q.Create(ctx, spec, false); code(err) != "QUEUE_EXISTS" {
		t.Errorf("create twice: %v", err)
	}
	for _, v := range []string{"one", "two", "three"} {
		if _, err := q.Send(ctx, queuex.Message{Topic: name, Value: []byte(v), Headers: [][2]string{{"source", "test"}}, Partition: -1}, false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := q.Send(ctx, queuex.Message{Topic: "komando-nope", Value: []byte("x"), Partition: -1}, false); code(err) != "QUEUE_NOT_FOUND" {
		t.Errorf("send to a missing queue: %v", err)
	}
	for i := 0; i < 3; i++ { // peek again and again: nothing goes
		p, err := q.Peek(ctx, queuex.PeekOptions{Topic: name, Limit: 2, Partition: -1})
		if err != nil || p.Count != 2 || !p.More || !p.Requeued || p.Messages[0].Value != "one" || p.Messages[0].Headers["source"] != "test" {
			t.Fatalf("peek %d: %+v %v", i, p, err)
		}
		if i > 0 && !p.Messages[0].Redelivered {
			t.Errorf("peek %d: not marked redelivered", i)
		}
	}
	var d *queuex.TopicDetail
	var err error
	for i := 0; i < 30; i++ { // the management API's numbers lag a few seconds
		if d, err = q.Describe(ctx, name); err != nil || d.Messages == 3 {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil || d.Messages != 3 || d.Ready != 3 || d.Type != typ || d.Arguments["x-max-length"] == nil {
		t.Fatalf("describe: %+v %+v %v", d, d.RabbitQueueDetail, err)
	}
	ts, err := q.Topics(ctx, "komando-live-"+typ[:1]+"*", false, 0)
	if err != nil || len(ts) != 1 || ts[0].Messages != 3 || ts[0].Type != typ {
		t.Fatalf("ls: %+v %v", ts, err)
	}
	pg, err := q.Purge(ctx, name, true)
	if err != nil || pg.Messages != 3 {
		t.Fatalf("dry-run purge: %+v %v", pg, err)
	}
	if pg, err = q.Purge(ctx, name, false); err != nil || pg.Messages != 3 {
		t.Fatalf("purge: %+v %v", pg, err)
	}
	if p, err := q.Peek(ctx, queuex.PeekOptions{Topic: name, Limit: 2, Partition: -1}); err != nil || p.Count != 0 || p.More {
		t.Errorf("peek after purge: %+v %v", p, err)
	}
	del, err := q.Delete(ctx, []string{name, "komando-ghost"}, true)
	if err != nil || len(del) != 2 || !del[1].Exists || del[0].Exists {
		t.Errorf("dry-run rm: %+v %v", del, err)
	}
	if _, err := q.Delete(ctx, []string{name, "komando-ghost"}, false); code(err) != "QUEUE_NOT_FOUND" {
		t.Errorf("rm with a missing queue: %v", err)
	}
}

// TestRabbitLiveDeliveryLimit: a quorum queue counts each peek's return
// as a delivery, so peek stops before a message runs out of them. Without
// the management API it cannot read the queue's own limit (here 3, below
// RabbitMQ 4's default of 20) and refuses before it takes the message.
func TestRabbitLiveDeliveryLimit(t *testing.T) {
	raw := os.Getenv("KOMANDO_E2E_RABBITMQ")
	if raw == "" {
		t.Skip("set KOMANDO_E2E_RABBITMQ")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, limit := range []string{"5", "3"} {
		tg, _ := driver.Parse(raw)
		q, err := Open(ctx, tg, os.Getenv("KOMANDO_E2E_RABBITMQ_PASSWORD"), nil, 10*time.Second, "komando-test")
		if err != nil {
			t.Fatal(err)
		}
		name := "komando-live-limit"
		q.Delete(ctx, []string{name}, false)
		if _, err := q.Create(ctx, queuex.TopicSpec{Topic: name, Type: "quorum", Partitions: -1, Replicas: -1, Config: map[string]string{"x-delivery-limit": limit}}, false); err != nil {
			t.Fatal(err)
		}
		q.Send(ctx, queuex.Message{Topic: name, Value: []byte("x"), Partition: -1}, false)
		peeks := 0
		for ; peeks < 30; peeks++ {
			p, err := q.Peek(ctx, queuex.PeekOptions{Topic: name, Limit: 1, Partition: -1})
			if code(err) == "DELIVERY_LIMIT_NEAR" {
				break
			}
			if err != nil || p.Count != 1 {
				t.Fatalf("limit %s, peek %d: %+v %v", limit, peeks, p, err)
			}
		}
		if p, err := q.Peek(ctx, queuex.PeekOptions{Topic: name, Limit: 1, Partition: -1}); code(err) != "DELIVERY_LIMIT_NEAR" {
			t.Errorf("limit %s: the message is gone after %d peeks: %+v %v", limit, peeks, p, err)
		}
		t.Logf("limit %s: refused after %d peeks", limit, peeks)
		tg.Management = ""
		if q2, err := Open(ctx, tg, os.Getenv("KOMANDO_E2E_RABBITMQ_PASSWORD"), nil, 10*time.Second, "komando-test"); err == nil {
			if _, err := q2.Peek(ctx, queuex.PeekOptions{Topic: name, Limit: 1, Partition: -1}); code(err) != "NOT_SUPPORTED" {
				t.Errorf("limit %s: peek without the management API: %v", limit, err)
			}
			q2.Close()
		}
		q.Delete(ctx, []string{name}, false)
		q.Close()
	}
}

// TestRabbitLiveErrors: a wrong password, a vhost the user lacks, and the
// management port in place of AMQP's each say what to fix.
func TestRabbitLiveErrors(t *testing.T) {
	raw := os.Getenv("KOMANDO_E2E_RABBITMQ")
	if raw == "" {
		t.Skip("set KOMANDO_E2E_RABBITMQ")
	}
	ctx := context.Background()
	tg, _ := driver.Parse(raw)
	if _, err := Open(ctx, tg, "wrong", nil, 5*time.Second, "komando-test"); code(err) != "QUEUE_AUTH" {
		t.Errorf("wrong password: %v", err)
	}
	vh := tg
	vh.Database = "komando-no-such-vhost"
	if _, err := Open(ctx, vh, os.Getenv("KOMANDO_E2E_RABBITMQ_PASSWORD"), nil, 5*time.Second, "komando-test"); code(err) != "QUEUE_DENIED" {
		t.Errorf("missing vhost: %v", err)
	}
	http := tg
	http.Address = tg.Management
	if _, err := Open(ctx, http, os.Getenv("KOMANDO_E2E_RABBITMQ_PASSWORD"), nil, 2*time.Second, "komando-test"); code(err) != "TIMEOUT" {
		t.Errorf("the management port: %v", err)
	}
	q, err := Open(ctx, tg, os.Getenv("KOMANDO_E2E_RABBITMQ_PASSWORD"), nil, 5*time.Second, "komando-test")
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if _, err := q.Describe(ctx, "komando-nope"); code(err) != "QUEUE_NOT_FOUND" {
		t.Errorf("describe a missing queue: %v", err)
	}
	if _, err := q.Peek(ctx, queuex.PeekOptions{Topic: "komando-nope", Limit: 1, Partition: -1}); code(err) != "QUEUE_NOT_FOUND" {
		t.Errorf("peek a missing queue: %v", err)
	}
	if _, err := q.Purge(ctx, "komando-nope", true); code(err) != "QUEUE_NOT_FOUND" {
		t.Errorf("purge a missing queue: %v", err)
	}
}

func code(err error) string {
	var e *out.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return fmt.Sprint(err)
}

// TestRabbitLivePeekStopsEarly: once a message peek took is near the
// queue's delivery limit, peek takes no further messages, so it puts only
// that one closer to its limit, not every message behind it.
func TestRabbitLivePeekStopsEarly(t *testing.T) {
	raw := os.Getenv("KOMANDO_E2E_RABBITMQ")
	if raw == "" {
		t.Skip("set KOMANDO_E2E_RABBITMQ")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tg, _ := driver.Parse(raw)
	q, err := Open(ctx, tg, os.Getenv("KOMANDO_E2E_RABBITMQ_PASSWORD"), nil, 10*time.Second, "komando-test")
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	name := "komando-live-early"
	q.Delete(ctx, []string{name}, false)
	defer q.Delete(ctx, []string{name}, false)
	if _, err := q.Create(ctx, queuex.TopicSpec{Topic: name, Type: "quorum", Partitions: -1, Replicas: -1, Config: map[string]string{"x-delivery-limit": "5"}}, false); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		q.Send(ctx, queuex.Message{Topic: name, Value: fmt.Appendf(nil, "m%d", i), Partition: -1}, false)
	}
	// limit 5, keep 3: peeks 1 and 2 take all three; peek 3 stops after
	// the first, which then has 2 deliveries left
	for i := 1; i <= 2; i++ {
		if p, err := q.Peek(ctx, queuex.PeekOptions{Topic: name, Limit: 3, Partition: -1}); err != nil || p.Count != 3 {
			t.Fatalf("peek %d: %+v %v", i, p, err)
		}
	}
	p, err := q.Peek(ctx, queuex.PeekOptions{Topic: name, Limit: 3, Partition: -1})
	if code(err) != "DELIVERY_LIMIT_NEAR" || p == nil || p.Count != 1 {
		t.Fatalf("peek 3 took more than the message near its limit: %+v %v", p, err)
	}
	// the management API's counts lag a few seconds behind the broker
	var d *queuex.TopicDetail
	for range 20 {
		if d, err = q.Describe(ctx, name); err == nil && d.Messages == 3 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Errorf("a message was lost: %+v %v", d, err)
}
