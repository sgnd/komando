package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/queuex"
	"github.com/sgnd/komando/internal/queuex/sqs"
	"github.com/sgnd/komando/internal/store"
)

// TestQueueSQSConn: an http:// endpoint straight over the network needs
// ?insecure=1 (or --via); doctor flags it; a password reference needs an
// access key ID; a profile that is not there is named.
func TestQueueSQSConn(t *testing.T) {
	invHome(t)
	wantCode(t, "INSECURE_PROTOCOL", "conn", "add", "s", "sqs://us-east-1?endpoint=http://sqs.example.com")
	mustRun(t, "conn", "add", "sqs", "sqs://eu-west-1", "--option", "aws_profile=nowhere")
	mustRun(t, "host", "add", "office", "u@10.0.0.1")
	mustRun(t, "conn", "add", "s-via", "sqs://us-east-1?endpoint=http://moto:5000", "--via", "office")
	mustRun(t, "conn", "add", "s-plain", "sqs://us-east-1?endpoint=http://sqs.example.com&insecure=1")
	if got := plainConn(&store.Conn{Name: "s-plain", URL: "sqs://us-east-1?endpoint=http://sqs.example.com&insecure=1"}); !strings.Contains(got, "https endpoint") {
		t.Errorf("doctor: %q", got)
	}
	if w := weakTLS("", "sqs://us-east-1?endpoint=http://sqs.example.com&insecure=1"); len(w) != 1 {
		t.Errorf("weakTLS: %v", w)
	}
	if d := mustRun(t, "conn", "show", "sqs"); !strings.Contains(jsonOf(d), "eu-west-1") {
		t.Errorf("conn show: %v", d)
	}
	t.Setenv("AWS_CONFIG_FILE", os.DevNull)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", os.DevNull)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	wantCode(t, "AWS_PROFILE_NOT_FOUND", "queue", "info", "sqs")
	t.Setenv("KOMANDO_TEST_SQS_SECRET", "x")
	mustRun(t, "conn", "add", "nokey", "sqs://us-east-1?endpoint=http://127.0.0.1:9", "--password-ref", "env:KOMANDO_TEST_SQS_SECRET")
	wantCode(t, "USAGE", "queue", "info", "nokey")
}

func TestQueueTextSQS(t *testing.T) {
	at, id, inflight := time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC), "m-1", int64(2)
	detail := &queuex.SqsQueueDetail{SqsQueue: queuex.SqsQueue{Fifo: true, InFlight: 1, DeadLetterQueue: "orders-dlq", MaxReceiveCount: 5},
		URL: "https://sqs/1/orders.fifo", VisibilityTimeout: 30, RetentionSeconds: 345600, MaxMessageSize: 262144, ContentDedup: true, Encryption: "sqs-managed",
		CreatedAt: &at, DeadLetterSources: []string{"a"}, Tags: map[string]string{"team": "billing"}, Attributes: map[string]string{"Policy": "{}"}}
	for _, c := range []struct {
		v    interface{ Text() string }
		want string
	}{
		{queueInfo{Info: &queuex.Info{Engine: "sqs", SqsInfo: &queuex.SqsInfo{Region: "eu-west-1", Endpoint: "sqs.eu-west-1.amazonaws.com:443", Queues: 3}}}, "Amazon SQS, region eu-west-1\nendpoint: sqs.eu-west-1.amazonaws.com:443\naccount:  -\nqueues:   3"},
		{queueTopics{kind: "sqs"}, "no queues"},
		{queueTopics{kind: "sqs", Topics: []queuex.Topic{{Name: "orders", Messages: 3, SqsQueue: &queuex.SqsQueue{InFlight: 1, DeadLetterQueue: "dlq", MaxReceiveCount: 5}}}}, "orders  standard  3         1          0        dlq after 5\n(SQS counts are approximate)"},
		{queueTopic{TopicDetail: &queuex.TopicDetail{Name: "orders.fifo", Messages: 4, SqsQueueDetail: detail}}, "queue: orders.fifo (fifo)\nurl:   https://sqs/1/orders.fifo\nmessages: about 4 waiting, 1 in flight"},
		{queueTopic{TopicDetail: &queuex.TopicDetail{Name: "orders.fifo", Messages: 4, SqsQueueDetail: detail}}, "visibility timeout: 30s, kept for: 96h0m0s, delay: 0s, receive wait: 0s\nlargest message: 256.0 KiB, encryption: sqs-managed, deduplication by content\ndead-letter queue: orders-dlq, after 5 receives\ndead-letter queue of: a\ncreated: 2026-11-10T08:00:00Z"},
		{queueTopic{TopicDetail: &queuex.TopicDetail{Name: "orders.fifo", Messages: 4, SqsQueueDetail: detail}}, "tags:\n  team=billing\n\nother settings:\n  Policy={}"},
		{queuePeek{PeekResult: &queuex.PeekResult{Queue: "orders", From: "sample", Count: 1, More: true, DeliveryLimit: 5, Messages: []queuex.Received{{Value: "hi",
			SqsMessage: &queuex.SqsMessage{MessageID: "m-1", ReceiveCount: 2, SentAt: &at, MessageGroupID: "g"}, Headers: map[string]string{"source": "web"}}}}}, "# m-1, received 2 times, sent 2026-11-10T08:00:00Z, group g, attributes source=web\nhi\n(received with visibility timeout 0 and not deleted"},
		{queuePeek{PeekResult: &queuex.PeekResult{Queue: "orders", From: "sample", Count: 1, More: true, DeliveryLimit: 5, Messages: []queuex.Received{{Value: "hi", SqsMessage: &queuex.SqsMessage{}}}}}, "after 5 receives SQS moves a message to the dead-letter queue)\n(a sample of 1 message; the queue holds more"},
		{queuePeek{PeekResult: &queuex.PeekResult{Queue: "orders", From: "sample", Messages: []queuex.Received{}}}, "no messages"},
		{queueSent{Sent: &queuex.Sent{Queue: "orders.fifo", Size: 2, SqsSent: &queuex.SqsSent{MessageID: &id, MessageGroupID: "g"}}}, "sent 2 B to queue orders.fifo, message group g; message ID m-1"},
		{queueSent{Sent: &queuex.Sent{Queue: "orders", DryRun: true, SqsSent: &queuex.SqsSent{}}}, "would send 0 B to queue orders (nothing sent)"},
		{queueCreated{Created: &queuex.Created{Queue: "jobs.fifo", SqsCreated: &queuex.SqsCreated{Fifo: true}, DryRun: true}}, "would create FIFO queue jobs.fifo (the name is free; nothing created)"},
		{queueCreated{Created: &queuex.Created{Queue: "jobs", SqsCreated: &queuex.SqsCreated{URL: "https://sqs/1/jobs"}}}, "created standard queue jobs\nurl: https://sqs/1/jobs"},
		{queuePurged{Purged: &queuex.Purged{Queue: "orders", Messages: 3, InFlight: &inflight, DryRun: true}}, "would delete about 3 messages from queue orders, and 2 in flight"},
		{queuePurged{Purged: &queuex.Purged{Queue: "orders", Messages: 3, InFlight: &inflight}}, "deleting about 3 messages from queue orders, and 2 in flight; the queue stays (SQS may take up to 60 seconds"},
	} {
		if got := c.v.Text(); !strings.Contains(got, c.want) {
			t.Errorf("%T: %q does not hold %q", c.v, got, c.want)
		}
	}
}

// TestQueueSQSLive runs the queue commands against a real SQS API: set
// KOMANDO_E2E_SQS to an endpoint such as http://127.0.0.1:5000 (moto or
// LocalStack, where any keys work). It logs in once with keys in the URL
// and once with an AWS profile.
func TestQueueSQSLive(t *testing.T) {
	endpoint := os.Getenv("KOMANDO_E2E_SQS")
	if endpoint == "" {
		t.Skip("set KOMANDO_E2E_SQS to an SQS endpoint (moto, LocalStack)")
	}
	invHome(t)
	t.Setenv("KOMANDO_TEST_SQS_SECRET", "test")
	creds := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(creds, []byte("[e2e]\naws_access_key_id = test\naws_secret_access_key = test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)
	t.Setenv("AWS_CONFIG_FILE", os.DevNull)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	mustRun(t, "conn", "add", "sqs", "sqs://test@us-east-1?endpoint="+endpoint, "--password-ref", "env:KOMANDO_TEST_SQS_SECRET")
	mustRun(t, "conn", "add", "aws-sso", "sqs://us-east-1?endpoint="+endpoint, "--option", "aws_profile=e2e")
	const name = "komando-cli"
	tg, _ := driver.Parse("sqs://test@us-east-1?endpoint=" + endpoint)
	cleanup := func() { // without --allow-dangerous: straight through the engine
		if q, err := sqs.Open(context.Background(), tg, "test", nil, 10*time.Second, "komando/test"); err == nil {
			_, _ = q.Delete(context.Background(), []string{name}, false)
			q.Close()
		}
	}
	cleanup()
	t.Cleanup(cleanup)
	for _, conn := range []string{"sqs", "aws-sso"} {
		if d := mustRun(t, "conn", "test", conn); !strings.Contains(jsonOf(d), `"check":"login"`) {
			t.Errorf("conn test %s: %v", conn, d)
		}
	}
	if d := mustRun(t, "queue", "info", "aws-sso"); d["engine"] != "sqs" || d["region"] != "us-east-1" {
		t.Errorf("info: %v", d)
	}
	if d := mustRun(t, "--dry-run", "queue", "create", "sqs", name, "--config", "VisibilityTimeout=60"); d["dry_run"] != true {
		t.Errorf("dry-run create: %v", d)
	}
	tcl.flags.dryRun, store.DryRun = false, false
	wantCode(t, "QUEUE_NOT_FOUND", "queue", "describe", "sqs", name)
	mustRun(t, "queue", "create", "sqs", name, "--config", "VisibilityTimeout=60")
	wantCode(t, "QUEUE_EXISTS", "queue", "create", "sqs", name)
	if d := mustRun(t, "queue", "send", "sqs", name, "--value", `{"id": 1}`, "--header", "source=test"); d["message_id"] == "" {
		t.Errorf("send: %v", d)
	}
	wantCode(t, "NOT_SUPPORTED", "queue", "send", "sqs", name, "--value", "x", "--key", "k")
	wantCode(t, "HIDDEN_VALUE", "queue", "send", "sqs", name, "--value", "password=[hidden]")
	for range 2 { // peek takes nothing away
		d := mustRun(t, "queue", "peek", "aws-sso", name)
		if d["count"].(float64) != 1 || d["queue"] != name || !strings.Contains(jsonOf(d), `"source":"test"`) {
			t.Errorf("peek: %v", d)
		}
	}
	if d := mustRun(t, "queue", "describe", "sqs", name); d["messages"].(float64) != 1 || d["in_flight"].(float64) != 0 || d["visibility_timeout"].(float64) != 60 {
		t.Errorf("describe after peek: %v", d)
	}
	if d := mustRun(t, "queue", "ls", "sqs", "komando-*"); d["count"].(float64) < 1 {
		t.Errorf("ls: %v", d)
	}
	wantCode(t, "NOT_SUPPORTED", "queue", "groups", "sqs")
	wantCode(t, "POLICY_BLOCKED", "queue", "purge", "sqs", name)
	if d := mustRun(t, "--dry-run", "queue", "purge", "sqs", name); d["messages"].(float64) != 1 {
		t.Errorf("dry-run purge: %v", d)
	}
	tcl.flags.dryRun, store.DryRun = false, false
	wantCode(t, "POLICY_BLOCKED", "queue", "rm", "sqs", name)
	if d := mustRun(t, "--dry-run", "queue", "rm", "sqs", name); !strings.Contains(jsonOf(d), `"exists":true`) {
		t.Errorf("dry-run rm: %v", d)
	}
}
