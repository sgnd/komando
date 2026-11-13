package cli

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/queuex"
	"github.com/sgnd/komando/internal/store"
)

// TestQueuePubsubConn: an http:// endpoint straight over the network needs
// ?insecure=1 (or --via, or this computer); doctor flags it; a service
// account key is never sent to the emulator.
func TestQueuePubsubConn(t *testing.T) {
	invHome(t)
	wantCode(t, "INSECURE_PROTOCOL", "conn", "add", "p", "pubsub://my-project?endpoint=http://pubsub.example.com:8085")
	mustRun(t, "conn", "add", "pubsub", "pubsub://my-project")
	mustRun(t, "conn", "add", "local", "pubsub://test-project?endpoint=http://127.0.0.1:9")
	mustRun(t, "host", "add", "office", "u@10.0.0.1")
	mustRun(t, "conn", "add", "p-via", "pubsub://test-project?endpoint=http://pubsub:8085", "--via", "office")
	mustRun(t, "conn", "add", "p-plain", "pubsub://test-project?endpoint=http://pubsub.example.com&insecure=1")
	if got := plainConn(&store.Conn{Name: "p-plain", URL: "pubsub://test-project?endpoint=http://pubsub.example.com&insecure=1"}); !strings.Contains(got, "https endpoint") {
		t.Errorf("doctor: %q", got)
	}
	if w := weakTLS("", "pubsub://test-project?endpoint=http://pubsub.example.com&insecure=1"); len(w) != 1 {
		t.Errorf("weakTLS: %v", w)
	}
	if d := mustRun(t, "conn", "show", "pubsub"); !strings.Contains(jsonOf(d), "my-project") {
		t.Errorf("conn show: %v", d)
	}
	t.Setenv("KOMANDO_TEST_PUBSUB_KEY", "{}")
	mustRun(t, "conn", "add", "keyed", "pubsub://test-project?endpoint=http://127.0.0.1:9", "--password-ref", "env:KOMANDO_TEST_PUBSUB_KEY")
	wantCode(t, "USAGE", "queue", "info", "keyed")
}

func TestQueueTextPubsub(t *testing.T) {
	at, id, one, two := time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC), "17", 1, 2
	sub := queuex.PubsubSubscription{Subscription: "billing", Topic: "orders", Delivery: "push", PushEndpoint: "https://h", AckDeadline: 20,
		BacklogRetention: "168h0m0s", Ordering: true, Filter: `attributes.x="1"`, DeadLetterTopic: "dead", MaxDeliveryAttempts: 5, SubscriptionState: "resource_error"}
	topic := &queuex.PubsubDetail{Resource: "topic", FullName: "projects/p/topics/orders", MessageRetention: "168h0m0s", KmsKey: "k", Schema: "s",
		AllowedRegions: []string{"europe-west1"}, Labels: map[string]string{"team": "pay"}, SubscriptionInfo: []queuex.PubsubSubscription{sub}}
	for _, c := range []struct {
		v    interface{ Text() string }
		want string
	}{
		{queueInfo{Info: &queuex.Info{Engine: "pubsub", PubsubInfo: &queuex.PubsubInfo{Project: "p", APIEndpoint: "pubsub.googleapis.com:443", TopicCount: 2, SubscriptionCount: 3}}}, "Google Cloud Pub/Sub, project p\nendpoint:      pubsub.googleapis.com:443\ntopics:        2\nsubscriptions: 3"},
		{queueTopics{kind: "pubsub", Topics: []queuex.Topic{{Name: "orders", Messages: -1, PubsubTopic: &queuex.PubsubTopic{SubscriptionCount: 2}}}}, "orders  2              -\n(Pub/Sub does not count messages"},
		{queueTopic{TopicDetail: &queuex.TopicDetail{Name: "orders", Messages: -1, PubsubDetail: topic}}, "topic: orders\nname: projects/p/topics/orders\nkeeps messages for: 168h0m0s (a subscription can seek back that far)\nencryption key: k\nschema: s\nkept in: europe-west1\n\nlabels:\n  team=pay\n\nsubscriptions (each gets every message):\n  billing (push, ack deadline 20s), dead letters to dead after 5"},
		{queueTopic{TopicDetail: &queuex.TopicDetail{Name: "lone", Messages: -1, PubsubDetail: &queuex.PubsubDetail{Resource: "topic"}}}, "none: messages sent now reach nobody"},
		{queueTopic{TopicDetail: &queuex.TopicDetail{Name: "billing", Messages: -1, PubsubDetail: &queuex.PubsubDetail{Resource: "subscription", PubsubSubscription: &sub}}}, "subscription: billing\nname: \ntopic: orders\ndelivery: push to https://h\nack deadline: 20s, keeps unacknowledged messages for: 168h0m0s\nordering by key\nfilter: attributes.x=\"1\"\ndead-letter topic: dead, after 5 deliveries\nstate: resource_error"},
		{queueGroups{kind: "pubsub"}, "no subscriptions"},
		{queueGroups{Groups: []queuex.Group{{Name: "billing", PubsubSubscription: &sub}}}, "billing       orders  push      20s           dead               -"},
		{queuePeek{PeekResult: &queuex.PeekResult{Subscription: "billing", From: "pulled", Count: 1, More: true, DeliveryLimit: 5, Messages: []queuex.Received{{Value: "hi",
			PubsubMessage: &queuex.PubsubMessage{ID: "17", PublishTime: &at, OrderingKey: "k1", DeliveryAttempt: 2}, Headers: map[string]string{"source": "web"}, Encoding: "base64"}}}},
			"# 17, published 2026-11-10T08:00:00Z, ordering key k1, delivery 2, attributes source=web, base64\nhi\n(pulled and given straight back unacknowledged: every message stays and is delivered again; each pull counts as a delivery, and after 5 Pub/Sub moves a message to the dead-letter topic)\n(the first 1 message a pull got; there may be more: raise -n)"},
		{queuePeek{PeekResult: &queuex.PeekResult{Subscription: "billing", From: "pulled", Messages: []queuex.Received{}}}, "no messages (or none a pull got at once)"},
		{queueSent{Sent: &queuex.Sent{Topic: "orders", Size: 2, PubsubSent: &queuex.PubsubSent{ID: &id, OrderingKey: "k1"}}}, "published 2 B to topic orders, ordering key k1; message ID 17"},
		{queueSent{Sent: &queuex.Sent{Topic: "orders", DryRun: true, PubsubSent: &queuex.PubsubSent{}}}, "would publish 0 B to topic orders (nothing sent)"},
		{queueCreated{Created: &queuex.Created{Subscription: "billing", PubsubCreated: &queuex.PubsubCreated{OfTopic: "orders"}, DryRun: true}}, "would create subscription billing of topic orders (the name is free; nothing created)"},
		{queueCreated{Created: &queuex.Created{Topic: "orders", PubsubCreated: &queuex.PubsubCreated{FullName: "projects/p/topics/orders"}}}, "created topic orders\nname: projects/p/topics/orders"},
		{queueDeleted{kind: "pubsub", DryRun: true, Topics: []queuex.Deleted{{Subscription: "billing", Exists: true, Messages: -1}, {Topic: "nope"},
			{Topic: "one", Exists: true, Consumers: &one}, {Topic: "two", Exists: true, Consumers: &two}, {Topic: "zero", Exists: true}}},
			"would delete subscription billing and the messages waiting in it\ntopic nope does not exist\nwould delete topic one; its subscription stays, with its messages, cut off from the topic\nwould delete topic two; its 2 subscriptions stay, with their messages, cut off from the topic\nwould delete topic zero (it has no subscriptions)"},
		{queuePurged{Purged: &queuex.Purged{Subscription: "billing", Messages: -1, DryRun: true}}, "would acknowledge every message waiting in subscription billing"},
		{queuePurged{Purged: &queuex.Purged{Subscription: "billing", Messages: -1}}, "acknowledged every message published to subscription billing until now"},
	} {
		if got := c.v.Text(); !strings.Contains(got, c.want) {
			t.Errorf("%T: %q does not hold %q", c.v, got, c.want)
		}
	}
}

// TestQueuePubsubLive runs the queue commands against the Pub/Sub
// emulator: set KOMANDO_E2E_PUBSUB to its address, such as
// http://127.0.0.1:8085 (project test-project).
func TestQueuePubsubLive(t *testing.T) {
	endpoint := os.Getenv("KOMANDO_E2E_PUBSUB")
	if endpoint == "" {
		t.Skip("set KOMANDO_E2E_PUBSUB to the Pub/Sub emulator's address")
	}
	invHome(t)
	mustRun(t, "conn", "add", "pubsub", "pubsub://test-project?endpoint="+endpoint)
	const topic, sub = "komando-cli", "komando-cli-sub"
	tg, _ := driver.Parse("pubsub://test-project?endpoint=" + endpoint)
	cleanup := func() { // without --allow-dangerous: straight through the engine
		if q, err := queuex.Open(context.Background(), tg, "", nil, 10*time.Second, "komando/test"); err == nil {
			_, _ = q.Delete(context.Background(), []string{"subscriptions/" + sub, topic}, false)
			q.Close()
		}
	}
	cleanup()
	t.Cleanup(cleanup)
	if d := mustRun(t, "conn", "test", "pubsub"); !strings.Contains(jsonOf(d), `"check":"login"`) {
		t.Errorf("conn test: %v", d)
	}
	if d := mustRun(t, "queue", "info", "pubsub"); d["engine"] != "pubsub" || d["project"] != "test-project" {
		t.Errorf("info: %v", d)
	}
	if d := mustRun(t, "--dry-run", "queue", "create", "pubsub", topic); d["dry_run"] != true {
		t.Errorf("dry-run create: %v", d)
	}
	tcl.flags.dryRun, store.DryRun = false, false
	wantCode(t, "TOPIC_NOT_FOUND", "queue", "describe", "pubsub", topic)
	mustRun(t, "queue", "create", "pubsub", topic)
	wantCode(t, "TOPIC_EXISTS", "queue", "create", "pubsub", topic)
	mustRun(t, "queue", "create", "pubsub", "subscriptions/"+sub, "--config", "topic="+topic, "--config", "ackDeadlineSeconds=20")
	if d := mustRun(t, "queue", "send", "pubsub", topic, "--value", `{"id": 1}`, "--header", "source=test", "--key", "k1"); d["id"] == nil {
		t.Errorf("send: %v", d)
	}
	wantCode(t, "HIDDEN_VALUE", "queue", "send", "pubsub", topic, "--value", "password=[hidden]")
	for range 2 { // peek gives every message back
		d := mustRun(t, "queue", "peek", "pubsub", sub)
		if d["count"].(float64) != 1 || d["subscription"] != sub || !strings.Contains(jsonOf(d), `"ordering_key":"k1"`) {
			t.Errorf("peek: %v", d)
		}
	}
	if d := mustRun(t, "queue", "describe", "pubsub", topic); !strings.Contains(jsonOf(d), `"ack_deadline_seconds":20`) {
		t.Errorf("describe: %v", d)
	}
	if d := mustRun(t, "queue", "groups", "pubsub"); d["count"].(float64) < 1 {
		t.Errorf("groups: %v", d)
	}
	wantCode(t, "NOT_SUPPORTED", "queue", "lag", "pubsub", sub)
	wantCode(t, "POLICY_BLOCKED", "queue", "purge", "pubsub", sub)
	if d := mustRun(t, "--dry-run", "queue", "purge", "pubsub", sub); d["messages"].(float64) != -1 {
		t.Errorf("dry-run purge: %v", d)
	}
	tcl.flags.dryRun, store.DryRun = false, false
	wantCode(t, "POLICY_BLOCKED", "queue", "rm", "pubsub", topic)
	if d := mustRun(t, "--dry-run", "queue", "rm", "pubsub", topic, "subscriptions/"+sub); !strings.Contains(jsonOf(d), `"exists":true`) {
		t.Errorf("dry-run rm: %v", d)
	}
}
