package queuex

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// TestKafkaLive runs against a real broker (set KOMANDO_E2E_KAFKA=host:port
// to one with no SASL): a consumer group reads and commits, and lag and
// describe see it; peek before and after leaves the group where it was.
func TestKafkaLive(t *testing.T) {
	addr := os.Getenv("KOMANDO_E2E_KAFKA")
	if addr == "" {
		t.Skip("set KOMANDO_E2E_KAFKA=host:port")
	}
	q := open(t, "kafka://"+addr, "", nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	topic := "komando-live-" + time.Now().Format("150405")
	if _, err := q.Create(ctx, TopicSpec{Topic: topic, Partitions: 1, Replicas: 1}, false); err != nil {
		t.Fatal(err)
	}
	defer q.Delete(context.Background(), []string{topic}, false)
	for _, v := range []string{"a", "b", "c"} {
		if _, err := q.Send(ctx, Message{Topic: topic, Value: []byte(v), Partition: -1}, false); err != nil {
			t.Fatal(err)
		}
	}
	cl, err := kgo.NewClient(kgo.SeedBrokers(addr), kgo.ConsumerGroup("komando-live"), kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()), kgo.DisableAutoCommit())
	if err != nil {
		t.Fatal(err)
	}
	var got []*kgo.Record
	for len(got) < 2 {
		fs := cl.PollRecords(ctx, 2-len(got))
		if err := fs.Err0(); err != nil {
			t.Fatal(err)
		}
		got = append(got, fs.Records()...)
	}
	if err := cl.CommitRecords(ctx, got...); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Peek(ctx, PeekOptions{Topic: topic, Limit: 3, Partition: -1}); err != nil {
		t.Fatal(err)
	}
	lag, err := q.Lag(ctx, "komando-live")
	if err != nil || lag.Lag != 1 || lag.Members != 1 || lag.Partitions[0].Client == "" {
		t.Fatalf("lag while the member is there: %+v %v", lag, err)
	}
	cl.Close()
	d, err := q.Describe(ctx, topic)
	if err != nil || len(d.Groups) != 1 || d.Groups[0].Lag != 1 {
		t.Fatalf("describe: %+v %v", d, err)
	}
}
