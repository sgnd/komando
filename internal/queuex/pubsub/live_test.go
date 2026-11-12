package pubsub

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/queuex"
)

// TestLive runs the engine against a real Pub/Sub API: set
// KOMANDO_E2E_PUBSUB to the emulator's address, such as
// http://127.0.0.1:8085 (gcloud beta emulators pubsub start, in the image
// gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators), project
// test-project. Passed against that image (emulator 0.8.x).
func TestLive(t *testing.T) {
	endpoint := os.Getenv("KOMANDO_E2E_PUBSUB")
	if endpoint == "" {
		t.Skip("set KOMANDO_E2E_PUBSUB to the Pub/Sub emulator's address")
	}
	tg, err := driver.Parse("pubsub://test-project?endpoint=" + endpoint)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	q, err := queuex.Open(ctx, tg, "", nil, 10*time.Second, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	topic, sub, dead := "komando-live", "komando-live-sub", "komando-live-dead"
	_, _ = q.Delete(ctx, []string{"subscriptions/" + sub, topic, dead}, false) // left by an earlier run
	spec := func(name string, cfg map[string]string) queuex.TopicSpec {
		return queuex.TopicSpec{Topic: name, Partitions: -1, Replicas: -1, Config: cfg}
	}
	for _, name := range []string{topic, dead} {
		if _, err := q.Create(ctx, spec(name, nil), false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := q.Create(ctx, spec(topic, nil), false); code(err) != "TOPIC_EXISTS" {
		t.Errorf("create twice: %v", err)
	}
	cfg := map[string]string{"topic": topic, "ackDeadlineSeconds": "30", "deadLetterTopic": dead, "maxDeliveryAttempts": "10", "labels.team": "billing"}
	if c, err := q.Create(ctx, spec("subscriptions/"+sub, cfg), false); err != nil || c.OfTopic != topic {
		t.Fatalf("create subscription: %+v %v", c, err)
	}
	for _, v := range []string{"one", "two", "three"} {
		if _, err := q.Send(ctx, queuex.Message{Topic: topic, Value: []byte(v), Headers: [][2]string{{"source", "live"}}, Partition: -1}, false); err != nil {
			t.Fatal(err)
		}
	}
	for round := 1; round <= 2; round++ { // peek gives every message back, so a second peek sees them again
		p, err := q.Peek(ctx, queuex.PeekOptions{Topic: sub, Limit: 10, Partition: -1})
		if err != nil || p.Count != 3 || p.Messages[0].Headers["source"] != "live" || p.DeliveryLimit != 10 || !p.Requeued {
			t.Fatalf("peek %d: %+v %v", round, p, err)
		}
		if p.Messages[0].DeliveryAttempt != round {
			t.Errorf("peek %d: delivery attempt %d", round, p.Messages[0].DeliveryAttempt)
		}
	}
	d, err := q.Describe(ctx, topic)
	if err != nil || d.Resource != "topic" || len(d.SubscriptionInfo) != 1 || d.SubscriptionInfo[0].AckDeadline != 30 || d.SubscriptionInfo[0].DeadLetterTopic != dead {
		t.Errorf("describe: %+v %v", d, err)
	}
	if d, err := q.Describe(ctx, sub); err != nil || d.Resource != "subscription" || d.Labels["team"] != "billing" {
		t.Errorf("describe subscription: %+v %v", d, err)
	}
	if ts, err := q.Topics(ctx, "komando-live*", false, 0); err != nil || len(ts) != 2 || ts[0].SubscriptionCount != 1 {
		t.Errorf("ls: %+v %v", ts, err)
	}
	if gs, err := q.Groups(ctx); err != nil || len(gs) == 0 {
		t.Errorf("groups: %+v %v", gs, err)
	}
	if _, err := q.Purge(ctx, sub, false); err != nil {
		t.Errorf("purge: %v", err)
	}
	if p, err := q.Peek(ctx, queuex.PeekOptions{Topic: sub, Limit: 10, Partition: -1}); err != nil || p.Count != 0 {
		t.Errorf("after purge: %+v %v", p, err)
	}
	if ds, err := q.Delete(ctx, []string{topic, "subscriptions/" + sub, dead}, false); err != nil || len(ds) != 3 {
		t.Errorf("rm: %+v %v", ds, err)
	}
	if _, err := q.Describe(ctx, "topics/"+topic); code(err) != "TOPIC_NOT_FOUND" {
		t.Errorf("after rm: %v", err)
	}
}
