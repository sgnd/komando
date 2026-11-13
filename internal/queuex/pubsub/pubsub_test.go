package pubsub

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/queuex"
)

func target(t *testing.T, srv *httptest.Server) driver.Target {
	t.Helper()
	tg, err := driver.Parse("pubsub://" + fakeProject + "?endpoint=" + srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func open(t *testing.T, srv *httptest.Server) *Pubsub {
	t.Helper()
	q, err := queuex.Open(context.Background(), target(t, srv), "", nil, 5*time.Second, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(q.Close)
	return q.(*Pubsub)
}

func noADC(t *testing.T) {
	t.Helper()
	old := defaultCredentials
	defaultCredentials = func(context.Context) (*google.Credentials, error) { return nil, errors.New("no login here") }
	t.Cleanup(func() { defaultCredentials = old })
}

// serviceAccountKey is a key file whose token_uri is the fake server.
func serviceAccountKey(t *testing.T, tokenURI string) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	b, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": fakeProject, "private_key_id": "k1",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "client_email": "bot@" + fakeProject + ".iam.gserviceaccount.com",
		"token_uri": tokenURI})
	return string(b)
}

func TestOpenEmulatorSendsNoLogin(t *testing.T) {
	f, srv := newFake(t, false)
	open(t, srv)
	if len(f.auth) != 1 || f.auth[0] != "" {
		t.Errorf("auth: %q", f.auth)
	}
	if _, err := Open(context.Background(), target(t, srv), "{}", nil, time.Second, "x"); code(err) != "USAGE" {
		t.Errorf("a key over http: %v", err)
	}
}

func TestOpenServiceAccountKey(t *testing.T) {
	f, srv := newFake(t, true)
	key := serviceAccountKey(t, srv.URL+"/token")
	q, err := Open(context.Background(), target(t, srv), key, nil, 5*time.Second, "x")
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if len(f.auth) != 1 || f.auth[0] != "Bearer tok-1" {
		t.Errorf("auth: %q", f.auth)
	}
	if _, err := Open(context.Background(), target(t, srv), "not json", nil, time.Second, "x"); code(err) != "QUEUE_AUTH" || strings.Contains(err.Error(), "not json") {
		t.Errorf("bad key: %v", err)
	}
}

func TestOpenDefaultCredentials(t *testing.T) {
	f, srv := newFake(t, true)
	old := defaultCredentials
	defer func() { defaultCredentials = old }()
	defaultCredentials = func(context.Context) (*google.Credentials, error) {
		return &google.Credentials{TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "adc"})}, nil
	}
	open(t, srv)
	if f.auth[0] != "Bearer adc" {
		t.Errorf("auth: %q", f.auth)
	}
	noADC(t)
	open(t, srv) // an endpoint of its own may need no login
	if f.auth[1] != "" {
		t.Errorf("auth: %q", f.auth)
	}
	tg, _ := driver.Parse("pubsub://" + fakeProject)
	if _, err := Open(context.Background(), tg, "", nil, time.Second, "x"); code(err) != "QUEUE_AUTH" {
		t.Errorf("Google without a login: %v", err)
	}
}

func TestOpenErrors(t *testing.T) {
	for status, want := range map[int]string{401: "QUEUE_AUTH", 403: "QUEUE_DENIED", 500: "QUEUE_CONNECT"} {
		f, srv := newFake(t, false)
		f.fail["topics"] = status
		if _, err := Open(context.Background(), target(t, srv), "", nil, time.Second, "x"); code(err) != want {
			t.Errorf("%d: %v", status, err)
		}
	}
	_, srv := newFake(t, false)
	tg, _ := driver.Parse("pubsub://other-project?endpoint=" + srv.URL)
	if _, err := Open(context.Background(), tg, "", nil, time.Second, "x"); code(err) != "QUEUE_CONNECT" || !strings.Contains(err.Error(), "other-project") {
		t.Errorf("no such project: %v", err)
	}
	notPubsub := httptest.NewServer(nil)
	defer notPubsub.Close()
	if _, err := Open(context.Background(), target(t, notPubsub), "", nil, time.Second, "x"); code(err) != "QUEUE_CONNECT" {
		t.Errorf("not pubsub: %v", err)
	}
	tg, _ = driver.Parse("pubsub://" + fakeProject + "?endpoint=http://127.0.0.1:1")
	if _, err := Open(context.Background(), tg, "", nil, time.Second, "x"); code(err) != "QUEUE_CONNECT" {
		t.Errorf("nothing listening: %v", err)
	}
}

func TestRefs(t *testing.T) {
	_, srv := newFake(t, false)
	p := open(t, srv)
	for in, want := range map[string]ref{
		"orders":                                    {name: "orders"},
		"topics/orders":                             {kind: "topic", name: "orders"},
		"subscriptions/billing":                     {kind: "subscription", name: "billing"},
		"projects/test-project/topics/orders":       {kind: "topic", name: "orders"},
		"projects/test-project/subscriptions/bill1": {kind: "subscription", name: "bill1"},
	} {
		if got, err := p.parseRef(in); err != nil || got != want {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{"ab", "1abc", "goog-x", "orders/x", "projects/other/topics/abc", "a b c", "snapshots/abc"} {
		if _, err := p.parseRef(bad); code(err) != "USAGE" {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func TestReadVerbs(t *testing.T) {
	f, srv := newFake(t, false)
	f.pageSize = 1
	f.addTopic("orders")
	f.addTopic("audit")
	f.addSub("billing", "orders", map[string]any{"deadLetterPolicy": map[string]any{"deadLetterTopic": "projects/test-project/topics/audit"},
		"labels": map[string]any{"team": "pay"}, "enableMessageOrdering": true, "state": "ACTIVE"})
	f.addSub("hook", "orders", map[string]any{"pushConfig": map[string]any{"pushEndpoint": "https://example.com/h"}})
	f.addSub("bq", "audit", map[string]any{"bigqueryConfig": map[string]any{"table": "a.b.c"}, "detached": true})
	p := open(t, srv)
	ctx := context.Background()
	inf, err := p.Info(ctx)
	if err != nil || inf.TopicCount != 2 || inf.SubscriptionCount != 3 || inf.Engine != "pubsub" {
		t.Errorf("info: %+v %v", inf, err)
	}
	ts, err := p.Topics(ctx, "ord*", false, 0)
	if err != nil || len(ts) != 1 || ts[0].SubscriptionCount != 2 || ts[0].Messages != -1 {
		t.Errorf("ls: %+v %v", ts, err)
	}
	if _, err := p.Topics(ctx, "", true, 0); code(err) != "NOT_SUPPORTED" {
		t.Errorf("--internal: %v", err)
	}
	d, err := p.Describe(ctx, "orders")
	if err != nil || d.Resource != "topic" || len(d.SubscriptionInfo) != 2 || d.SubscriptionInfo[1].Delivery != "push" {
		t.Fatalf("describe topic: %+v %v", d, err)
	}
	s := d.SubscriptionInfo[0]
	if s.DeadLetterTopic != "audit" || s.MaxDeliveryAttempts != 5 || !s.Ordering || s.BacklogRetention != "168h0m0s" || s.SubscriptionState != "active" {
		t.Errorf("subscription: %+v", s)
	}
	if d, err := p.Describe(ctx, "billing"); err != nil || d.Resource != "subscription" || d.Labels["team"] != "pay" || d.Topic != "orders" {
		t.Errorf("describe falls back to a subscription: %+v %v", d, err)
	}
	for name, want := range map[string]string{"nope": "TOPIC_NOT_FOUND", "topics/billing": "TOPIC_NOT_FOUND", "subscriptions/nope": "SUBSCRIPTION_NOT_FOUND"} {
		if _, err := p.Describe(ctx, name); code(err) != want {
			t.Errorf("describe %s: %v", name, err)
		}
	}
	gs, err := p.Groups(ctx)
	if err != nil || len(gs) != 3 || gs[0].Name != "billing" || gs[0].Lag != -1 || gs[1].State != "detached" || gs[1].Protocol != "bigquery" {
		t.Errorf("groups: %+v %v", gs, err)
	}
	if _, err := p.Lag(ctx, "billing"); code(err) != "NOT_SUPPORTED" {
		t.Errorf("lag: %v", err)
	}
	b, _ := json.Marshal(d)
	for _, field := range []string{`"resource":"topic"`, `"subscription_info"`, `"dead_letter_topic":"audit"`, `"messages":-1`} {
		if !strings.Contains(string(b), field) {
			t.Errorf("JSON lost %s: %s", field, b)
		}
	}
}

func TestPeekGivesBack(t *testing.T) {
	f, srv := newFake(t, false)
	f.addTopic("orders")
	sub := f.addSub("billing", "orders", nil, "one", "two", "three", "\xff\xfe")
	sub.msgs[0].attrs = map[string]string{"source": "web"}
	p := open(t, srv)
	ctx := context.Background()
	for round := 0; round < 2; round++ {
		res, err := p.Peek(ctx, queuex.PeekOptions{Topic: "billing", Limit: 10, Partition: -1, MaxBytes: 2})
		if err != nil || res.Count != 4 || !res.Requeued || res.More || res.Messages[0].Value != "on" || !res.Messages[0].ValueTruncated ||
			res.Messages[0].Headers["source"] != "we" || res.Messages[3].Encoding != "base64" || res.Messages[0].PublishTime == nil {
			t.Fatalf("peek %d: %+v %v", round, res, err)
		}
	}
	if len(sub.acks) != 0 || sub.nacks != 8 {
		t.Errorf("not all given back: held %d, given back %d", len(sub.acks), sub.nacks)
	}
	res, err := p.Peek(ctx, queuex.PeekOptions{Topic: "subscriptions/billing", Limit: 2, Partition: -1})
	if err != nil || res.Count != 2 || !res.More {
		t.Errorf("peek -n 2: %+v %v", res, err)
	}
}

func TestPeekRefuses(t *testing.T) {
	f, srv := newFake(t, false)
	f.addTopic("orders")
	f.addSub("hook", "orders", map[string]any{"pushConfig": map[string]any{"pushEndpoint": "https://example.com/h"}})
	f.addSub("strict", "orders", map[string]any{"deadLetterPolicy": map[string]any{"deadLetterTopic": "projects/test-project/topics/orders", "maxDeliveryAttempts": 3}})
	near := f.addSub("near", "orders", map[string]any{"deadLetterPolicy": map[string]any{"deadLetterTopic": "projects/test-project/topics/orders", "maxDeliveryAttempts": 5}}, "x")
	near.msgs[0].deliveries = 2
	p := open(t, srv)
	ctx := context.Background()
	for _, c := range []struct {
		o    queuex.PeekOptions
		want string
	}{
		{queuex.PeekOptions{Topic: "near", Limit: 1, Partition: 0}, "NOT_SUPPORTED"},
		{queuex.PeekOptions{Topic: "near", Limit: 1, Partition: -1, Oldest: true}, "NOT_SUPPORTED"},
		{queuex.PeekOptions{Topic: "topics/orders", Limit: 1, Partition: -1}, "USAGE"},
		{queuex.PeekOptions{Topic: "orders", Limit: 1, Partition: -1}, "SUBSCRIPTION_NOT_FOUND"},
		{queuex.PeekOptions{Topic: "nothing", Limit: 1, Partition: -1}, "SUBSCRIPTION_NOT_FOUND"},
		{queuex.PeekOptions{Topic: "hook", Limit: 1, Partition: -1}, "NOT_SUPPORTED"},
		{queuex.PeekOptions{Topic: "strict", Limit: 1, Partition: -1}, "DELIVERY_LIMIT_NEAR"},
		{queuex.PeekOptions{Topic: "near", Limit: 1, Partition: -1}, "DELIVERY_LIMIT_NEAR"},
	} {
		if _, err := p.Peek(ctx, c.o); code(err) != c.want {
			t.Errorf("%+v: %v, want %s", c.o, err, c.want)
		}
	}
	if len(near.acks) != 0 || near.nacks != 1 {
		t.Errorf("a refused peek still gives back what it pulled: held %d", len(near.acks))
	}
	f.fail[":modifyAckDeadline"] = 500
	near.msgs[0].deliveries = 0
	if _, err := p.Peek(ctx, queuex.PeekOptions{Topic: "near", Limit: 1, Partition: -1}); code(err) != "QUEUE_ERROR" || !strings.Contains(err.Error(), "give back") {
		t.Errorf("give back fails: %v", err)
	}
}

func TestSend(t *testing.T) {
	f, srv := newFake(t, false)
	f.addTopic("orders")
	sub := f.addSub("billing", "orders", nil)
	p := open(t, srv)
	ctx := context.Background()
	m := queuex.Message{Topic: "orders", Value: []byte("hi"), Key: []byte("k1"), Headers: [][2]string{{"source", "cli"}}, Partition: -1}
	if s, err := p.Send(ctx, m, true); err != nil || s.ID != nil || !s.DryRun || len(sub.msgs) != 0 {
		t.Errorf("dry run: %+v %v", s, err)
	}
	s, err := p.Send(ctx, m, false)
	if err != nil || s.ID == nil || s.OrderingKey != "k1" || len(sub.msgs) != 1 || sub.msgs[0].key != "k1" || sub.msgs[0].attrs["source"] != "cli" {
		t.Errorf("send: %+v %v", s, err)
	}
	for _, c := range []struct {
		m    queuex.Message
		want string
	}{
		{queuex.Message{Topic: "orders", Value: []byte("x"), Partition: 1}, "NOT_SUPPORTED"},
		{queuex.Message{Topic: "subscriptions/billing", Value: []byte("x"), Partition: -1}, "USAGE"},
		{queuex.Message{Topic: "orders", Partition: -1}, "USAGE"},
		{queuex.Message{Topic: "nope", Value: []byte("x"), Partition: -1}, "TOPIC_NOT_FOUND"},
	} {
		if _, err := p.Send(ctx, c.m, false); code(err) != c.want {
			t.Errorf("%+v: %v, want %s", c.m, err, c.want)
		}
	}
	f.fail[":publish"] = 403
	if _, err := p.Send(ctx, m, false); code(err) != "QUEUE_DENIED" {
		t.Errorf("denied: %v", err)
	}
}

func spec(name string, cfg map[string]string) queuex.TopicSpec {
	return queuex.TopicSpec{Topic: name, Partitions: -1, Replicas: -1, Config: cfg}
}

func TestCreate(t *testing.T) {
	f, srv := newFake(t, false)
	p := open(t, srv)
	ctx := context.Background()
	if c, err := p.Create(ctx, spec("orders", map[string]string{"messageretentionduration": "7d", "labels.team": "pay"}), true); err != nil || !c.DryRun || len(f.topics) != 0 {
		t.Errorf("dry run: %+v %v", c, err)
	}
	c, err := p.Create(ctx, spec("orders", map[string]string{"messageRetentionDuration": "36h", "kmsKeyName": "k"}), false)
	if err != nil || c.Topic != "orders" || c.FullName != "projects/test-project/topics/orders" || f.topics["orders"]["messageRetentionDuration"] != "129600s" {
		t.Fatalf("create topic: %+v %v %v", c, err, f.topics)
	}
	if _, err := p.Create(ctx, spec("orders", nil), false); code(err) != "TOPIC_EXISTS" {
		t.Errorf("twice: %v", err)
	}
	cfg := map[string]string{"topic": "orders", "ackDeadlineSeconds": "60", "retainAckedMessages": "true", "deadLetterTopic": "orders",
		"maxDeliveryAttempts": "7", "pushEndpoint": "https://example.com/h", "filter": `attributes.x = "1"`, "enableExactlyOnceDelivery": "false"}
	c, err = p.Create(ctx, spec("subscriptions/billing", cfg), false)
	if err != nil || c.Subscription != "billing" || c.OfTopic != "orders" {
		t.Fatalf("create subscription: %+v %v", c, err)
	}
	b := f.subs["billing"].body
	if b["ackDeadlineSeconds"] != 60.0 || b["deadLetterPolicy"].(map[string]any)["maxDeliveryAttempts"] != 7.0 || b["retainAckedMessages"] != true {
		t.Errorf("body: %v", b)
	}
	if _, err := p.Create(ctx, spec("billing", map[string]string{"topic": "projects/test-project/topics/orders"}), false); code(err) != "SUBSCRIPTION_EXISTS" {
		t.Errorf("subscription twice: %v", err)
	}
	for _, c := range []struct {
		s    queuex.TopicSpec
		want string
	}{
		{queuex.TopicSpec{Topic: "x1x", Partitions: 3, Replicas: -1}, "NOT_SUPPORTED"},
		{queuex.TopicSpec{Topic: "x1x", Partitions: -1, Replicas: -1, Type: "quorum"}, "NOT_SUPPORTED"},
		{spec("subscriptions/s2x", nil), "USAGE"},
		{spec("topics/t2x", map[string]string{"topic": "orders"}), "USAGE"},
		{spec("t2x", map[string]string{"ackDeadlineSeconds": "60"}), "USAGE"},
		{spec("s2x", map[string]string{"topic": "orders", "ackDeadlineSeconds": "soon"}), "USAGE"},
		{spec("s2x", map[string]string{"topic": "orders", "ordering": "yes"}), "USAGE"},
		{spec("s2x", map[string]string{"topic": "orders", "enableMessageOrdering": "maybe"}), "USAGE"},
		{spec("s2x", map[string]string{"topic": "orders", "pushEndpoint": "http://x"}), "USAGE"},
		{spec("s2x", map[string]string{"topic": "subscriptions/billing"}), "USAGE"},
		{spec("t2x", map[string]string{"messageRetentionDuration": "1ms"}), "USAGE"},
		{spec("t2x", map[string]string{"messageRetentionDuration": "xd"}), "USAGE"},
		{spec("s2x", map[string]string{"topic": "nope"}), "TOPIC_NOT_FOUND"},
	} {
		if _, err := p.Create(ctx, c.s, false); code(err) != c.want {
			t.Errorf("%+v: %v, want %s", c.s, err, c.want)
		}
	}
	f.fail["PUT"] = 400
	if _, err := p.Create(ctx, spec("t3x", nil), false); code(err) != "QUEUE_ERROR" {
		t.Errorf("refused: %v", err)
	}
}

func TestDeleteAndPurge(t *testing.T) {
	f, srv := newFake(t, false)
	f.addTopic("orders")
	f.addTopic("lonely")
	f.addSub("billing", "orders", nil, "a", "b")
	f.addSub("audit", "orders", nil)
	p := open(t, srv)
	ctx := context.Background()
	ds, err := p.Delete(ctx, []string{"orders", "subscriptions/billing", "nope"}, true)
	if err != nil || len(ds) != 3 || ds[0].Name() != "billing" || ds[1].Exists || *ds[2].Consumers != 2 || ds[2].Messages != -1 {
		t.Errorf("dry run: %+v %v", ds, err)
	}
	if _, err := p.Delete(ctx, []string{"orders", "nope"}, false); code(err) != "TOPIC_NOT_FOUND" || f.topics["orders"] == nil {
		t.Errorf("a missing name stops it all: %v", err)
	}
	if _, err := p.Delete(ctx, []string{"subscriptions/nope"}, false); code(err) != "SUBSCRIPTION_NOT_FOUND" {
		t.Errorf("missing subscription: %v", err)
	}
	if pr, err := p.Purge(ctx, "billing", true); err != nil || pr.Messages != -1 || len(f.subs["billing"].msgs) != 2 {
		t.Errorf("purge dry run: %+v %v", pr, err)
	}
	if _, err := p.Purge(ctx, "subscriptions/billing", false); err != nil || len(f.subs["billing"].msgs) != 0 || f.count("POST /v1/projects/test-project/subscriptions/billing:seek") != 1 {
		t.Errorf("purge: %v", err)
	}
	for name, want := range map[string]string{"topics/orders": "USAGE", "nope": "SUBSCRIPTION_NOT_FOUND"} {
		if _, err := p.Purge(ctx, name, false); code(err) != want {
			t.Errorf("purge %s: %v", name, err)
		}
	}
	if ds, err := p.Delete(ctx, []string{"orders", "lonely", "subscriptions/audit"}, false); err != nil || len(ds) != 3 || f.topics["orders"] != nil || f.subs["audit"] != nil {
		t.Errorf("rm: %+v %v", ds, err)
	}
	if f.subs["billing"].body["topic"] != "_deleted-topic_" {
		t.Errorf("the topic's subscription stays, cut off: %v", f.subs["billing"].body)
	}
	if d, err := p.Describe(ctx, "subscriptions/billing"); err != nil || d.Topic != "_deleted-topic_" {
		t.Errorf("cut off: %+v %v", d, err)
	}
}

func TestOpErrors(t *testing.T) {
	for status, want := range map[int]string{401: "QUEUE_AUTH", 403: "QUEUE_DENIED", 429: "QUEUE_ERROR", 400: "QUEUE_ERROR", 500: "QUEUE_ERROR"} {
		f, srv := newFake(t, false)
		p := open(t, srv)
		f.fail["subscriptions"] = status
		if _, err := p.Groups(context.Background()); code(err) != want {
			t.Errorf("%d: %v", status, err)
		}
	}
	for err, want := range map[error]string{
		context.DeadlineExceeded:                          "TIMEOUT",
		errors.New("connection reset"):                    "QUEUE_ERROR",
		&oauth2.RetrieveError{ErrorCode: "invalid_grant"}: "QUEUE_AUTH",
	} {
		if got := opErr(err, "x", nil); code(got) != want {
			t.Errorf("%v: %v", err, got)
		}
	}
	tg, _ := driver.Parse("pubsub://test-project")
	for err, want := range map[error]string{
		context.DeadlineExceeded:                          "TIMEOUT",
		errors.New("x509: certificate signed by unknown"): "QUEUE_CONNECT",
		&oauth2.RetrieveError{ErrorCode: "invalid_grant"}: "QUEUE_AUTH",
	} {
		if got := connectErr(tg, err); code(got) != want {
			t.Errorf("connect %v: %v", err, got)
		}
	}
	if duration("1.5s") != "1.5s" || duration("") != "" || duration("odd") != "odd" {
		t.Error("duration")
	}
}
