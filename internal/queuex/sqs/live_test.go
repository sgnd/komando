package sqs

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/queuex"
)

// TestLive runs the engine against a real SQS API: set KOMANDO_E2E_SQS to
// an endpoint such as http://127.0.0.1:5000 (moto or LocalStack; any keys
// work there). Passed against motoserver/moto:5.1.16.
func TestLive(t *testing.T) {
	endpoint := os.Getenv("KOMANDO_E2E_SQS")
	if endpoint == "" {
		t.Skip("set KOMANDO_E2E_SQS to an SQS endpoint (moto, LocalStack)")
	}
	tg, err := driver.Parse("sqs://test@us-east-1?endpoint=" + endpoint)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	q, err := queuex.Open(ctx, tg, "test", nil, 10*time.Second, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	dlq, main := "komando-live-dlq", "komando-live"
	_, _ = q.Delete(ctx, []string{main}, false) // left by an earlier run
	_, _ = q.Delete(ctx, []string{dlq}, false)
	_, _ = q.Delete(ctx, []string{"komando-live.fifo"}, false)
	spec := func(name string, cfg map[string]string) queuex.TopicSpec {
		return queuex.TopicSpec{Topic: name, Partitions: -1, Replicas: -1, Config: cfg}
	}
	if _, err := q.Create(ctx, spec(dlq, nil), false); err != nil {
		t.Fatal(err)
	}
	policy := `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:` + dlq + `","maxReceiveCount":"10"}`
	if c, err := q.Create(ctx, spec(main, map[string]string{"RedrivePolicy": policy, "visibilitytimeout": "45"}), false); err != nil || c.URL == "" {
		t.Fatalf("create: %+v %v", c, err)
	}
	if _, err := q.Create(ctx, spec(main, nil), true); code(err) != "QUEUE_EXISTS" {
		t.Errorf("create twice: %v", err)
	}
	for _, v := range []string{"one", "two", "three"} {
		if _, err := q.Send(ctx, queuex.Message{Topic: main, Value: []byte(v), Headers: [][2]string{{"source", "live"}}, Partition: -1}, false); err != nil {
			t.Fatal(err)
		}
	}
	p, err := q.Peek(ctx, queuex.PeekOptions{Topic: main, Limit: 10, Partition: -1})
	if err != nil || p.Count != 3 || p.Messages[0].Headers["source"] != "live" || p.DeliveryLimit != 10 {
		t.Fatalf("peek: %+v %v", p, err)
	}
	d, err := q.Describe(ctx, main)
	if err != nil || d.Messages != 3 || d.InFlight != 0 || d.VisibilityTimeout != 45 || d.DeadLetterQueue != dlq {
		t.Errorf("after peek nothing is hidden or gone: %+v %+v %v", d, d.SqsQueueDetail, err)
	}
	if d, _ := q.Describe(ctx, dlq); len(d.DeadLetterSources) != 1 {
		t.Errorf("dead-letter sources: %+v", d.SqsQueueDetail)
	}
	ts, err := q.Topics(ctx, "komando-live*", false)
	if err != nil || len(ts) != 2 || ts[0].Name != main || ts[0].Messages != 3 {
		t.Errorf("ls: %+v %v", ts, err)
	}
	if _, err := q.Create(ctx, spec("komando-live.fifo", map[string]string{"ContentBasedDeduplication": "true"}), false); err != nil {
		t.Fatal(err)
	}
	s, err := q.Send(ctx, queuex.Message{Topic: "komando-live.fifo", Key: []byte("g1"), Value: []byte("x"), Partition: -1}, false)
	if err != nil || s.MessageID == nil || s.MessageGroupID != "g1" {
		t.Errorf("fifo send: %+v %v", s, err)
	}
	if p, err := q.Peek(ctx, queuex.PeekOptions{Topic: "komando-live.fifo", Limit: 5, Partition: -1}); err != nil || p.Count != 1 || p.Messages[0].MessageGroupID != "g1" {
		t.Errorf("fifo peek: %+v %v", p, err)
	}
	if pr, err := q.Purge(ctx, main, false); err != nil || pr.Messages != 3 {
		t.Errorf("purge: %+v %v", pr, err)
	}
	if inf, err := q.Info(ctx); err != nil || inf.Queues < 3 || !strings.HasPrefix(inf.AccountID, "1") {
		t.Errorf("info: %+v %v", inf, err)
	}
	if _, err := q.Delete(ctx, []string{main, dlq, "komando-live.fifo"}, false); err != nil {
		t.Errorf("delete: %v", err)
	}
	if _, err := q.Describe(ctx, main); code(err) != "QUEUE_NOT_FOUND" {
		t.Errorf("after delete: %v", err)
	}
}
