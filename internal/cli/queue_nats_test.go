package cli

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/queuex"
	"github.com/sgnd/komando/internal/store"
)

// TestQueueNatsConn: nats:// straight over the network needs tls:// or
// ?insecure=1, like redis://; doctor flags the weak ones and says how to
// fix them; the login goes to every server the URL lists.
func TestQueueNatsConn(t *testing.T) {
	invHome(t)
	wantCode(t, "INSECURE_PROTOCOL", "conn", "add", "n", "nats://nats.example.com")
	mustRun(t, "conn", "add", "n", "tls://app@n1.example.com,n2.example.com:4223")
	mustRun(t, "host", "add", "office", "u@10.0.0.1")
	mustRun(t, "conn", "add", "n-via", "nats://nats.internal", "--via", "office")
	mustRun(t, "conn", "add", "n-plain", "nats://nats.example.com:4222?insecure=1")
	if got := plainConn(&store.Conn{Name: "n-plain", URL: "nats://nats.example.com:4222?insecure=1&domain=hub"}); !strings.Contains(got, "tls://nats.example.com:4222?domain=hub") {
		t.Errorf("doctor: %q", got)
	}
	if got := plainConn(&store.Conn{Name: "n", URL: "tls://nats.example.com?tls=skip-verify"}); !strings.Contains(got, "not checked") || strings.Contains(got, "skip-verify'") {
		t.Errorf("doctor skip-verify: %q", got)
	}
	if w := weakTLS("", "tls://nats.example.com?tls=skip-verify"); len(w) != 1 {
		t.Errorf("weakTLS: %v", w)
	}
	if w := weakTLS("tls://nats.example.com", "nats://nats.example.com?insecure=1"); len(w) != 2 {
		t.Errorf("weakTLS downgrade: %v", w)
	}
	if p := connPlace(&store.Conn{URL: "tls://app@n1:4222,n2:4222", PasswordRef: "secret:n"}); p.dest != "n1:4222,n2:4222" {
		t.Errorf("the password goes to %q", p.dest)
	}
	if p := connPlace(&store.Conn{URL: "tls://n1:4222?creds=secret:ngs"}); !slices.Contains(p.refs, "secret:ngs") {
		t.Errorf("the creds are not counted as sent: %v", p.refs)
	}
}

func TestQueueTextNats(t *testing.T) {
	seq, at, two := uint64(7), time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC), 2
	billing := &queuex.NatsConsumer{Stream: "ORDERS", Durable: true, Kind: "pull", AckPolicy: "explicit", Pending: 3, AckPending: 1, Waiting: 2,
		DeliveredSeq: 5, AckFloorSeq: 4, FilterSubjects: []string{"orders.>"}, LastActive: &at, Paused: true}
	detail := &queuex.NatsStreamDetail{NatsStream: queuex.NatsStream{Subjects: []string{"orders.>"}, Storage: "file", Retention: "workqueue", NumReplicas: 3, FirstSeq: 1, LastSeq: 9, Sealed: true},
		Discard: "old", Description: "orders from the shop", Limits: queuex.NatsLimits{MaxMsgs: -1, MaxBytes: 1 << 30, MaxAge: "0s"}, NumDeleted: 2, FirstTime: &at, LastTime: &at, DenyPurge: true,
		Mirror: "UPSTREAM", Sources: []string{"A"}, Cluster: &queuex.NatsCluster{Name: "lab", Leader: "n1", Replicas: []queuex.NatsReplica{{Name: "n2", Current: true}, {Name: "n3", Lag: 4}}},
		ConsumerInfo: []queuex.NatsConsumer{{Consumer: "billing", Stream: "ORDERS", Kind: "push"}}}
	for _, c := range []struct {
		v    interface{ Text() string }
		want string
	}{
		{queueInfo{Info: &queuex.Info{Version: "2.12.1", NatsInfo: &queuex.NatsInfo{ServerName: "n1", ServerID: "NID", Connected: "n1:4222", MaxPayload: 1 << 20}}}, "server:  NATS 2.12.1, n1 (NID)\ncluster: -\naddress: n1:4222\nlargest message: 1.0 MiB\n\nJetStream: off"},
		{queueInfo{Info: &queuex.Info{NatsInfo: &queuex.NatsInfo{ServerID: "NID", JetStream: true, Domain: "hub", Account: &queuex.NatsAccount{Streams: 2, MaxStreams: 10, Storage: 2048, MaxStorage: -1, MaxMemory: 1 << 20}}}}, "domain:  hub\n\nJetStream for this account: 2 streams (of 10), 0 consumers (of no limit)\nstorage: 2.0 KiB on file (of no limit), 0 B in memory (of 1.0 MiB)"},
		{queueTopics{kind: "nats"}, "no streams"},
		{queueTopics{kind: "nats", Topics: []queuex.Topic{{Name: "ORDERS", Messages: 3, NatsStream: &queuex.NatsStream{Subjects: []string{"orders.>"}, Bytes: 10, ConsumerCount: 1, Storage: "file", Retention: "limits", NumReplicas: 1}}}}, "ORDERS  orders.>  3         10 B  1          file     limits     1"},
		{queueTopic{TopicDetail: &queuex.TopicDetail{Name: "ORDERS", Messages: 7, NatsStreamDetail: detail}}, "stream: ORDERS (file, workqueue retention, 3 replicas)\norders from the shop\nsubjects: orders.>\nmessages: 7 (0 B), sequence 1 to 9, 2 deleted in between"},
		{queueTopic{TopicDetail: &queuex.TopicDetail{Name: "ORDERS", Messages: 7, NatsStreamDetail: detail}}, "limits: messages no limit, size 1.0 GiB, age no limit, per subject no limit; when full, discard old\nsettings: deny-purge, sealed\nmirror of: UPSTREAM\nsources: A\ncluster: lab, leader n1\n  replica n2: current\n  replica n3: behind by 4"},
		{queueTopic{TopicDetail: &queuex.TopicDetail{Name: "ORDERS", Messages: 7, NatsStreamDetail: detail}}, "billing   ORDERS  push"},
		{queueTopic{TopicDetail: &queuex.TopicDetail{Name: "E", NatsStreamDetail: &queuex.NatsStreamDetail{Limits: queuex.NatsLimits{MaxAge: "1h0m0s"}}}}, "age 1h0m0s"},
		{queueGroups{Groups: []queuex.Group{{Name: "billing", NatsConsumer: billing}}}, "billing   ORDERS  pull  3        1            0            2        orders.>"},
		{queueLag{GroupLag: &queuex.GroupLag{Group: "billing", State: "paused", Lag: 3, NatsConsumer: billing}}, "consumer: billing on stream ORDERS (durable pull, ack explicit), paused\npending: 3 not given to it yet"},
		{queueLag{GroupLag: &queuex.GroupLag{Group: "billing", State: "paused", Lag: 3, NatsConsumer: billing}}, "waiting pull requests: 2\nreads subjects: orders.>\nlast given a message: 2026-11-10T08:00:00Z\npaused"},
		{queuePeek{PeekResult: &queuex.PeekResult{Stream: "ORDERS", From: "newest", Count: 1, More: true, Partial: true, Messages: []queuex.Received{{Value: "aGk=", Encoding: "base64",
			NatsMsg: &queuex.NatsMsg{Subject: "orders.new", Sequence: 7, Time: at}, Headers: map[string]string{"source": "web"}}}}}, "# sequence 7, 2026-11-10T08:00:00Z, subject orders.new, source=web, base64\naGk=\n(the newest 1 message; the stream holds more"},
		{queuePeek{PeekResult: &queuex.PeekResult{Stream: "ORDERS", Partial: true, Messages: []queuex.Received{}}}, "no messages\n(the stream has many deleted"},
		{queueSent{Sent: &queuex.Sent{NatsSent: &queuex.NatsSent{Subject: "orders.new", Stream: "ORDERS", Sequence: &seq, Duplicate: true}, Size: 2}}, "sent 2 B to orders.new; stream ORDERS keeps it as sequence 7 (a duplicate"},
		{queueSent{Sent: &queuex.Sent{NatsSent: &queuex.NatsSent{Subject: "orders.new", Stream: "ORDERS"}, DryRun: true}}, "would send 0 B to orders.new, kept by stream ORDERS (nothing sent)"},
		{queueCreated{Created: &queuex.Created{NatsCreated: &queuex.NatsCreated{Stream: "ORDERS", Subjects: []string{"orders.>"}, Storage: "file", Retention: "limits", NumReplicas: 1}, DryRun: true}}, "would create (the name is free; nothing created): stream ORDERS for orders.> (file storage, limits retention, 1 replica)"},
		{queueDeleted{Topics: []queuex.Deleted{{Stream: "ORDERS", Exists: true, Messages: 1, Consumers: &two}}}, "deleted ORDERS (1 message; its 2 consumers were deleted with it)"},
		{queuePurged{Purged: &queuex.Purged{Stream: "ORDERS", Messages: 2}}, "deleted 2 messages from stream ORDERS; the stream and its consumers stay"},
	} {
		if got := c.v.Text(); !strings.Contains(got, c.want) {
			t.Errorf("%T: %q does not hold %q", c.v, got, c.want)
		}
	}
}

// TestQueueNatsLive runs the queue commands against a real NATS server
// with JetStream: set KOMANDO_E2E_NATS to a conn URL and
// KOMANDO_E2E_NATS_PASSWORD to its user's password.
func TestQueueNatsLive(t *testing.T) {
	url := os.Getenv("KOMANDO_E2E_NATS")
	if url == "" {
		t.Skip("set KOMANDO_E2E_NATS and KOMANDO_E2E_NATS_PASSWORD")
	}
	invHome(t)
	mustRun(t, "conn", "add", "stream", url, "--password-ref", "env:KOMANDO_E2E_NATS_PASSWORD")
	if d := mustRun(t, "conn", "test", "stream"); !strings.Contains(jsonOf(d), `"check":"login"`) {
		t.Errorf("conn test: %v", d)
	}
	if d := mustRun(t, "queue", "info", "stream"); d["engine"] != "nats" || d["jetstream"] != true {
		t.Errorf("info: %v", d)
	}
	invRun(t, "queue", "rm", "stream", "KOMANDO_CLI", "--allow-dangerous") // left by an earlier run
	tcl.flags.allowDangerous = false
	if d := mustRun(t, "--dry-run", "queue", "create", "stream", "KOMANDO_CLI", "--config", "subjects=cli.>"); d["dry_run"] != true {
		t.Errorf("dry-run create: %v", d)
	}
	tcl.flags.dryRun = false
	wantCode(t, "STREAM_NOT_FOUND", "queue", "describe", "stream", "KOMANDO_CLI")
	wantCode(t, "NOT_SUPPORTED", "queue", "create", "stream", "KOMANDO_CLI", "--partitions", "3")
	mustRun(t, "queue", "create", "stream", "KOMANDO_CLI", "--config", "subjects=cli.>", "--config", "max_age=1h")
	wantCode(t, "STREAM_EXISTS", "queue", "create", "stream", "KOMANDO_CLI")
	if d := mustRun(t, "queue", "send", "stream", "cli.orders", "--value", `{"id": 1}`, "--header", "source=test"); d["sequence"].(float64) != 1 || d["stream"] != "KOMANDO_CLI" {
		t.Errorf("send: %v", d)
	}
	wantCode(t, "NOT_SUPPORTED", "queue", "send", "stream", "cli.orders", "--value", "x", "--key", "k")
	wantCode(t, "STREAM_NOT_FOUND", "queue", "send", "stream", "KOMANDO_CLI", "--value", "x")
	wantCode(t, "HIDDEN_VALUE", "queue", "send", "stream", "cli.orders", "--value", "password=[hidden]")
	for range 2 { // peek takes nothing away
		d := mustRun(t, "queue", "peek", "stream", "KOMANDO_CLI")
		if d["count"].(float64) != 1 || d["stream"] != "KOMANDO_CLI" || !strings.Contains(jsonOf(d), `"source":"test"`) {
			t.Errorf("peek: %v", d)
		}
	}
	if d := mustRun(t, "queue", "ls", "stream", "KOMANDO_*"); d["count"].(float64) != 1 {
		t.Errorf("ls: %v", d)
	}
	if d := mustRun(t, "queue", "groups", "stream"); d["count"] == nil {
		t.Errorf("groups: %v", d)
	}
	wantCode(t, "CONSUMER_NOT_FOUND", "queue", "lag", "stream", "KOMANDO_CLI/nobody")
	wantCode(t, "POLICY_BLOCKED", "queue", "purge", "stream", "KOMANDO_CLI")
	if d := mustRun(t, "--dry-run", "queue", "purge", "stream", "KOMANDO_CLI"); d["messages"].(float64) != 1 {
		t.Errorf("dry-run purge: %v", d)
	}
	tcl.flags.dryRun = false
	mustRun(t, "queue", "purge", "stream", "KOMANDO_CLI", "--allow-dangerous")
	tcl.flags.allowDangerous = false
	wantCode(t, "POLICY_BLOCKED", "queue", "rm", "stream", "KOMANDO_CLI")
	mustRun(t, "queue", "rm", "stream", "KOMANDO_CLI", "--allow-dangerous")
	tcl.flags.allowDangerous = false
}
