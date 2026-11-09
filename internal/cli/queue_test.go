package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kfake"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/sgnd/komando/internal/queuex"
	"github.com/sgnd/komando/internal/store"
)

// TestQueueKafka runs the queue commands against an in-process Kafka
// (franz-go's kfake): reads need no flag, rm and purge need
// --allow-dangerous, every change has a dry run, and peek moves no group.
func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestQueueKafka(t *testing.T) {
	invHome(t)
	c, err := kfake.NewCluster(kfake.NumBrokers(1))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	addr := c.ListenAddrs()[0]
	mustRun(t, "conn", "add", "events", "kafka://"+addr)
	if d := mustRun(t, "conn", "test", "events"); !strings.Contains(jsonOf(d), `"check":"login"`) {
		t.Errorf("conn test: %v", d)
	}

	if d := mustRun(t, "--dry-run", "queue", "create", "events", "orders", "--partitions", "2", "--replicas", "1"); d["dry_run"] != true {
		t.Errorf("dry-run create: %v", d)
	}
	g.dryRun, store.DryRun = false, false
	if d := mustRun(t, "queue", "ls", "events"); d["count"].(float64) != 0 {
		t.Fatalf("a dry-run create made a topic: %v", d)
	}
	mustRun(t, "queue", "create", "events", "orders", "--partitions", "2", "--replicas", "1", "--config", "retention.ms=3600000")
	wantCode(t, "TOPIC_EXISTS", "queue", "create", "events", "orders")

	mustRun(t, "queue", "send", "events", "orders", "--value", `{"id": 1}`, "--key", "1", "--partition", "0")
	file := filepath.Join(t.TempDir(), "msg.json")
	os.WriteFile(file, []byte(`{"id": 2}`), 0o600)
	if d := mustRun(t, "queue", "send", "events", "orders", "--from", file, "--header", "source=test", "--partition", "1"); d["offset"].(float64) != 0 {
		t.Errorf("send --from: %v", d)
	}
	wantCode(t, "TOPIC_NOT_FOUND", "queue", "send", "events", "nope", "--value", "x")
	wantCode(t, "USAGE", "queue", "send", "events", "orders", "--value", "x", "--from", file)
	wantCode(t, "USAGE", "queue", "send", "events", "orders", "--header", "novalue", "--value", "x")
	wantCode(t, "HIDDEN_VALUE", "queue", "send", "events", "orders", "--value", "password=[hidden]")

	d := mustRun(t, "queue", "peek", "events", "orders")
	if d["count"].(float64) != 2 || !strings.Contains(jsonOf(d), `"source":"test"`) {
		t.Errorf("peek: %v", d)
	}
	wantCode(t, "PARTITION_NOT_FOUND", "queue", "peek", "events", "orders", "--partition", "9")
	wantCode(t, "USAGE", "queue", "peek", "events", "orders", "-n", "0")
	if d := mustRun(t, "queue", "describe", "events", "orders"); len(d["partitions"].([]any)) != 2 || d["config"].(map[string]any)["retention.ms"] != "3600000" {
		t.Errorf("describe: %v", d)
	}
	if d := mustRun(t, "queue", "info", "events"); len(d["brokers"].([]any)) != 1 {
		t.Errorf("info: %v", d)
	}

	// a group that read partition 0 only
	cl, _ := kgo.NewClient(kgo.SeedBrokers(addr))
	commit := kadm.Offsets{}
	commit.Add(kadm.Offset{Topic: "orders", Partition: 0, At: 1, LeaderEpoch: -1})
	if _, err := kadm.NewClient(cl).CommitOffsets(context.Background(), "billing", commit); err != nil {
		t.Fatal(err)
	}
	cl.Close()
	if d := mustRun(t, "queue", "groups", "events"); d["count"].(float64) != 1 {
		t.Errorf("groups: %v", d)
	}
	if d := mustRun(t, "queue", "lag", "events", "billing"); d["lag"].(float64) != 1 {
		t.Errorf("lag: %v", d)
	}
	wantCode(t, "CONSUMER_GROUP_NOT_FOUND", "queue", "lag", "events", "nobody")

	wantCode(t, "POLICY_BLOCKED", "queue", "purge", "events", "orders")
	if d := mustRun(t, "--dry-run", "queue", "purge", "events", "orders"); d["messages"].(float64) != 2 || !strings.Contains(jsonOf(d), "POLICY_BLOCKED") {
		t.Errorf("dry-run purge: %v", d)
	}
	g.dryRun, store.DryRun = false, false
	mustRun(t, "queue", "purge", "events", "orders", "--allow-dangerous")
	g.allowDangerous = false
	if d := mustRun(t, "queue", "peek", "events", "orders"); d["count"].(float64) != 0 {
		t.Errorf("peek after purge: %v", d)
	}
	wantCode(t, "POLICY_BLOCKED", "queue", "rm", "events", "orders")
	mustRun(t, "queue", "rm", "events", "orders", "--allow-dangerous")
	g.allowDangerous = false

	if e := wantCode(t, "NO_MATCHING_TARGETS", "cache", "info", "events"); !strings.Contains(e.Hint, "komando queue") {
		t.Errorf("hint: %s", e.Hint)
	}
}

// TestQueueConnTLS: a kafka conn straight over the network needs tls=true
// or ?insecure=1, like redis://; doctor flags the weak ones.
func TestQueueConnTLS(t *testing.T) {
	invHome(t)
	wantCode(t, "INSECURE_PROTOCOL", "conn", "add", "k", "kafka://broker.example.com:9092")
	mustRun(t, "conn", "add", "k", "kafka://app@broker.example.com:9093,b2.example.com:9093?tls=true&sasl=scram-sha-512")
	mustRun(t, "host", "add", "office", "u@10.0.0.1")
	mustRun(t, "conn", "add", "k-via", "kafka://broker.internal:9092", "--via", "office")
	mustRun(t, "conn", "add", "k-plain", "kafka://broker.example.com:9092?insecure=1")
	if got := plainConn(&store.Conn{Name: "k-plain", URL: "kafka://broker.example.com:9092?insecure=1"}); !strings.Contains(got, "tls=true") {
		t.Errorf("doctor: %q", got)
	}
	if got := plainConn(&store.Conn{Name: "k", URL: "kafka://broker.example.com:9093?tls=skip-verify"}); !strings.Contains(got, "not checked") {
		t.Errorf("doctor skip-verify: %q", got)
	}
	if w := weakTLS("", "kafka://broker.example.com:9093?tls=skip-verify"); len(w) != 1 {
		t.Errorf("weakTLS: %v", w)
	}
	if p := connPlace(&store.Conn{URL: "kafka://app@b1:9093,b2:9093?tls=true&sasl=plain", PasswordRef: "secret:k"}); p.dest != "b1:9093,b2:9093" {
		t.Errorf("the password goes to %q", p.dest)
	}
}

func TestQueueText(t *testing.T) {
	key, p, o := "k1", int32(1), int64(7)
	for _, c := range []struct {
		v    interface{ Text() string }
		want string
	}{
		{queueTopics{}, "no topics"},
		{queueTopics{Topics: []queuex.Topic{{Name: "orders", Partitions: 3, Replicas: 2, Messages: 10}}}, "orders  3           2         10"},
		{queueTopic{TopicDetail: &queuex.TopicDetail{Name: "orders", Messages: 1, Partitions: []queuex.Partition{{Leader: -1}}}}, "orders (1 partition, 0 replicas, 1 message)"},
		{queuePeek{PeekResult: &queuex.PeekResult{From: "newest", Count: 1, More: true, Partial: true,
			Messages: []queuex.Received{{Partition: 1, Offset: 7, Key: &key, Value: "aGk=", Encoding: "base64", ValueTruncated: true, Size: 2048}}}}, "key k1, base64\naGk=\n(cut: the value is 2.0 KiB)"},
		{queuePeek{PeekResult: &queuex.PeekResult{}}, "no messages"},
		{queueGroups{Groups: []queuex.Group{{Name: "billing", State: "Stable", Members: 2, Topics: []string{"orders"}, Lag: 5}}}, "billing  Stable"},
		{queueLag{GroupLag: &queuex.GroupLag{Group: "billing", Members: 1, Partitions: []queuex.PartitionLag{{Topic: "orders", Committed: -1, Lag: -1, Error: "no commit"}}}}, "(, 1 member)"},
		{queueSent{Sent: &queuex.Sent{Topic: "orders", Partition: &p, Offset: &o, Size: 3}}, "partition 1, offset 7"},
		{queueSent{Sent: &queuex.Sent{Topic: "orders", DryRun: true}}, "the partition its key picks"},
		{queueCreated{Created: &queuex.Created{Topic: "orders", Partitions: -1, Replicas: 3, DryRun: true}}, "the default number of partitions, 3 replicas"},
		{queueDeleted{Topics: []queuex.Deleted{{Topic: "a", Exists: true, Messages: 2}, {Topic: "b"}}, DryRun: true}, "would delete a (2 messages)\nb does not exist"},
		{queuePurged{Purged: &queuex.Purged{Topic: "a", Messages: 1, Partitions: 1, DryRun: true}}, "would delete 1 message from a (1 partition)"},
		{queueInfo{Info: &queuex.Info{Brokers: []queuex.Broker{{ID: 1, Address: "b1:9092", Controller: true}}}}, "version: unknown"},
	} {
		if got := c.v.Text(); !strings.Contains(got, c.want) {
			t.Errorf("%T: %q does not hold %q", c.v, got, c.want)
		}
	}
}
