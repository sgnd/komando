package sqs

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

func open(t *testing.T, srv *httptest.Server, query string) *SQS {
	t.Helper()
	tg, err := driver.Parse("sqs://AKIDEXAMPLE@us-east-1?endpoint=" + srv.URL + query)
	if err != nil {
		t.Fatal(err)
	}
	q, err := queuex.Open(context.Background(), tg, "secret", nil, 5*time.Second, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(q.Close)
	return q.(*SQS)
}

func code(err error) string {
	var e *out.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "not an out.Error: " + err.Error()
}

func TestOpenSigns(t *testing.T) {
	f, srv := newFake(t)
	open(t, srv, "")
	if len(f.auth) != 1 || !strings.Contains(f.auth[0], "Credential=AKIDEXAMPLE/") || !strings.Contains(f.auth[0], "/us-east-1/sqs/aws4_request") {
		t.Errorf("signature: %v", f.auth)
	}
	if strings.Contains(strings.Join(f.auth, " "), "secret") {
		t.Error("the secret key went on the wire")
	}
}

func TestOpenRefuses(t *testing.T) {
	f, srv := newFake(t)
	tg, _ := driver.Parse("sqs://us-east-1?endpoint=" + srv.URL)
	if _, err := Open(context.Background(), tg, "", nil, time.Second, "x"); code(err) != "USAGE" {
		t.Errorf("no access key: %v", err)
	}
	tg.User = "AKID"
	if _, err := Open(context.Background(), tg, "", nil, time.Second, "x"); code(err) != "USAGE" {
		t.Errorf("no secret: %v", err)
	}
	f.fail["ListQueues"] = "InvalidClientTokenId"
	if _, err := Open(context.Background(), tg, "s", nil, time.Second, "x"); code(err) != "QUEUE_AUTH" {
		t.Errorf("bad keys: %v", err)
	}
	f.fail["ListQueues"] = "AccessDenied"
	if _, err := Open(context.Background(), tg, "s", nil, time.Second, "x"); code(err) != "QUEUE_DENIED" {
		t.Errorf("denied: %v", err)
	}
	f.fail["ListQueues"] = "InternalError"
	if _, err := Open(context.Background(), tg, "s", nil, time.Second, "x"); code(err) != "QUEUE_CONNECT" {
		t.Errorf("other: %v", err)
	}
}

func TestOpenNotSQS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>hello</html>")) }))
	defer srv.Close()
	tg, _ := driver.Parse("sqs://AKID@us-east-1?endpoint=" + srv.URL)
	_, err := Open(context.Background(), tg, "s", nil, time.Second, "x")
	if code(err) != "QUEUE_CONNECT" || !strings.Contains(err.Error(), "not SQS JSON") {
		t.Errorf("not sqs: %v", err)
	}
	// nothing listens: the connection is refused
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	tg, _ = driver.Parse("sqs://AKID@us-east-1?endpoint=http://" + addr)
	if _, err := Open(context.Background(), tg, "s", nil, time.Second, "x"); code(err) != "QUEUE_CONNECT" {
		t.Errorf("refused: %v", err)
	}
	// an endpoint that never answers
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { time.Sleep(time.Second) }))
	defer slow.Close()
	tg, _ = driver.Parse("sqs://AKID@us-east-1?endpoint=" + slow.URL)
	if _, err := Open(context.Background(), tg, "s", nil, 100*time.Millisecond, "x"); code(err) != "TIMEOUT" {
		t.Errorf("slow: %v", err)
	}
}

func TestInfoAndList(t *testing.T) {
	f, srv := newFake(t)
	f.pageSize = 2
	f.add("orders", map[string]string{"RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:orders-dlq","maxReceiveCount":"5"}`}, "a", "b")
	f.add("orders-dlq", nil)
	f.add("emails.fifo", nil, "x")
	f.add("audit", nil)
	q := open(t, srv, "")
	inf, err := q.Info(context.Background())
	if err != nil || inf.Engine != "sqs" || inf.Queues != 4 || inf.AccountID != fakeAccount || inf.Region != "us-east-1" {
		t.Fatalf("info: %+v %v", inf, err)
	}
	ts, err := q.Topics(context.Background(), "orders*", false)
	if err != nil || len(ts) != 2 {
		t.Fatalf("ls: %+v %v", ts, err)
	}
	if ts[0].Name != "orders" || ts[0].Messages != 2 || ts[0].DeadLetterQueue != "orders-dlq" || ts[0].MaxReceiveCount != 5 || ts[0].Fifo {
		t.Errorf("orders: %+v %+v", ts[0], ts[0].SqsQueue)
	}
	if last := f.last["ListQueues"].(map[string]any); last["QueueNamePrefix"] != "orders" {
		t.Errorf("the prefix goes to SQS: %v", last)
	}
	all, _ := q.Topics(context.Background(), "", false)
	if len(all) != 4 || all[1].Name != "emails.fifo" || !all[1].Fifo {
		t.Errorf("all: %+v", all)
	}
	if _, err := q.Topics(context.Background(), "", true); code(err) != "NOT_SUPPORTED" {
		t.Errorf("--internal: %v", err)
	}
	f.fail["ListQueues"] = "AccessDenied"
	if _, err := q.Topics(context.Background(), "", false); code(err) != "QUEUE_DENIED" {
		t.Errorf("denied: %v", err)
	}
}

func TestDescribe(t *testing.T) {
	f, srv := newFake(t)
	f.add("orders", map[string]string{"RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:orders-dlq","maxReceiveCount":5}`,
		"SqsManagedSseEnabled": "true", "Policy": `{"Version":"2012-10-17"}`}, "a")
	dlq := f.add("orders-dlq", map[string]string{"KmsMasterKeyId": "alias/sqs"})
	dlq.tags = map[string]string{"team": "billing"}
	q := open(t, srv, "")
	d, err := q.Describe(context.Background(), "orders")
	if err != nil {
		t.Fatal(err)
	}
	if d.Messages != 1 || d.URL != queueURLOf("orders") || d.VisibilityTimeout != 30 || d.RetentionSeconds != 345600 || d.Encryption != "sqs-managed" ||
		d.DeadLetterQueue != "orders-dlq" || d.MaxReceiveCount != 5 || d.CreatedAt == nil || d.Attributes["Policy"] == "" || len(d.DeadLetterSources) != 0 {
		t.Errorf("orders: %+v", d.SqsQueueDetail)
	}
	d, _ = q.Describe(context.Background(), "orders-dlq")
	if d.Encryption != "kms:alias/sqs" || d.Tags["team"] != "billing" || len(d.DeadLetterSources) != 1 || d.DeadLetterSources[0] != "orders" {
		t.Errorf("dlq: %+v", d.SqsQueueDetail)
	}
	if _, err := q.Describe(context.Background(), "nope"); code(err) != "QUEUE_NOT_FOUND" {
		t.Errorf("missing: %v", err)
	}
	if _, err := q.Describe(context.Background(), "bad name!"); code(err) != "USAGE" {
		t.Errorf("bad name: %v", err)
	}
}

func TestPeekKeepsMessages(t *testing.T) {
	f, srv := newFake(t)
	bodies := make([]string, 25)
	for i := range bodies {
		bodies[i] = "msg"
	}
	fq := f.add("orders", nil, bodies...)
	fq.msgs[1].attrs = map[string]any{"source": map[string]any{"DataType": "String", "StringValue": "web"}, "bin": map[string]any{"DataType": "Binary", "BinaryValue": "AAE="}}
	q := open(t, srv, "")
	p, err := q.Peek(context.Background(), queuex.PeekOptions{Topic: "orders", Limit: 5, Partition: -1, MaxBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	if p.Count != 5 || p.From != "sample" || !p.More || p.Partial || p.Messages[0].Value != "msg" || p.Messages[0].ReceiveCount != 1 || p.Messages[0].SentAt == nil {
		t.Errorf("peek: %+v %+v", p, p.Messages[0].SqsMessage)
	}
	if h := p.Messages[1].Headers; h["source"] != "web" || h["bin"] != "base64:AAE=" {
		t.Errorf("attributes: %v", h)
	}
	if len(fq.msgs) != 25 || f.count("DeleteMessage") != 0 || f.count("ChangeMessageVisibility") != 0 {
		t.Errorf("peek took messages away: %d left, calls %v", len(fq.msgs), f.calls)
	}
	in := f.last["ReceiveMessage"].(map[string]any)
	if in["VisibilityTimeout"] != float64(0) || in["MaxNumberOfMessages"] != float64(5) {
		t.Errorf("receive: %v", in)
	}
	// SQS gives the same messages again: peek stops instead of raising counts
	p, _ = q.Peek(context.Background(), queuex.PeekOptions{Topic: "orders", Limit: 30, Partition: -1})
	if p.Count != 10 || p.Messages[0].ReceiveCount != 3 {
		t.Errorf("repeat: %d messages, first received %d times", p.Count, p.Messages[0].ReceiveCount)
	}
	for _, o := range []queuex.PeekOptions{{Topic: "orders", Limit: 1, Partition: 0}, {Topic: "orders", Limit: 1, Partition: -1, Oldest: true}} {
		if _, err := q.Peek(context.Background(), o); code(err) != "NOT_SUPPORTED" {
			t.Errorf("%+v: %v", o, err)
		}
	}
	f.add("empty", nil)
	if p, err := q.Peek(context.Background(), queuex.PeekOptions{Topic: "empty", Limit: 10, Partition: -1}); err != nil || p.Count != 0 || p.More {
		t.Errorf("empty: %+v %v", p, err)
	}
	if _, err := q.Peek(context.Background(), queuex.PeekOptions{Topic: "nope", Limit: 1, Partition: -1}); code(err) != "QUEUE_NOT_FOUND" {
		t.Errorf("missing: %v", err)
	}
}

func TestPeekDeadLetterGuard(t *testing.T) {
	f, srv := newFake(t)
	f.add("low", map[string]string{"RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:dlq","maxReceiveCount":3}`}, "a")
	fq := f.add("retried", map[string]string{"RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:dlq","maxReceiveCount":"10"}`}, "a")
	fq.msgs[0].received = 7
	q := open(t, srv, "")
	if _, err := q.Peek(context.Background(), queuex.PeekOptions{Topic: "low", Limit: 1, Partition: -1}); code(err) != "DELIVERY_LIMIT_NEAR" || f.count("ReceiveMessage") != 0 {
		t.Errorf("low limit: %v, %d receives", err, f.count("ReceiveMessage"))
	}
	_, err := q.Peek(context.Background(), queuex.PeekOptions{Topic: "retried", Limit: 1, Partition: -1})
	if code(err) != "DELIVERY_LIMIT_NEAR" || !strings.Contains(err.Error(), "received 8 times") {
		t.Errorf("near: %v", err)
	}
}

func TestSend(t *testing.T) {
	f, srv := newFake(t)
	std := f.add("orders", map[string]string{"MaximumMessageSize": "10"})
	fifo := f.add("orders.fifo", nil)
	f.add("dedup.fifo", map[string]string{"ContentBasedDeduplication": "true"})
	q := open(t, srv, "")
	ctx := context.Background()
	s, err := q.Send(ctx, queuex.Message{Topic: "orders", Value: []byte("hi"), Headers: [][2]string{{"source", "test"}}, Partition: -1}, false)
	if err != nil || s.MessageID == nil || *s.MessageID == "" || s.Size != 2 || len(std.msgs) != 1 || std.msgs[0].attrs["source"] == nil {
		t.Fatalf("send: %+v %v", s, err)
	}
	if s, err := q.Send(ctx, queuex.Message{Topic: "orders", Value: []byte("hi"), Partition: -1}, true); err != nil || !s.DryRun || s.MessageID != nil || len(std.msgs) != 1 {
		t.Errorf("dry run: %+v %v", s, err)
	}
	if _, err := q.Send(ctx, queuex.Message{Topic: "orders", Value: []byte("too long, more than ten"), Partition: -1}, false); code(err) != "USAGE" {
		t.Errorf("size: %v", err)
	}
	if _, err := q.Send(ctx, queuex.Message{Topic: "orders", Value: []byte{0, 1}, Partition: -1}, false); code(err) != "USAGE" {
		t.Errorf("binary: %v", err)
	}
	if _, err := q.Send(ctx, queuex.Message{Topic: "orders", Key: []byte("k"), Value: []byte("x"), Partition: -1}, false); code(err) != "NOT_SUPPORTED" {
		t.Errorf("key on standard: %v", err)
	}
	if _, err := q.Send(ctx, queuex.Message{Topic: "orders", Value: []byte("x"), Partition: 1}, false); code(err) != "NOT_SUPPORTED" {
		t.Errorf("partition: %v", err)
	}
	if _, err := q.Send(ctx, queuex.Message{Topic: "orders.fifo", Value: []byte("x"), Partition: -1}, false); code(err) != "USAGE" {
		t.Errorf("fifo without key: %v", err)
	}
	s, err = q.Send(ctx, queuex.Message{Topic: "orders.fifo", Key: []byte("cust-1"), Value: []byte("x"), Partition: -1}, false)
	if err != nil || s.MessageGroupID != "cust-1" || s.SequenceNumber == "" || fifo.msgs[0].group != "cust-1" || len(fifo.msgs[0].dedup) != 32 {
		t.Errorf("fifo: %+v %v %+v", s, err, fifo.msgs)
	}
	if _, err := q.Send(ctx, queuex.Message{Topic: "dedup.fifo", Key: []byte("g"), Value: []byte("x"), Partition: -1}, false); err != nil {
		t.Fatal(err)
	}
	if in := f.last["SendMessage"].(map[string]any); in["MessageDeduplicationId"] != nil {
		t.Errorf("content-based dedup still got an ID: %v", in)
	}
	if _, err := q.Send(ctx, queuex.Message{Topic: "nope", Value: []byte("x"), Partition: -1}, false); code(err) != "QUEUE_NOT_FOUND" {
		t.Errorf("missing: %v", err)
	}
	f.fail["SendMessage"] = "KmsAccessDenied"
	if _, err := q.Send(ctx, queuex.Message{Topic: "orders", Value: []byte("x"), Partition: -1}, false); code(err) != "QUEUE_DENIED" {
		t.Errorf("kms: %v", err)
	}
}

func TestCreate(t *testing.T) {
	f, srv := newFake(t)
	f.add("orders", nil)
	q := open(t, srv, "")
	ctx := context.Background()
	spec := func(name string, cfg map[string]string) queuex.TopicSpec {
		return queuex.TopicSpec{Topic: name, Partitions: -1, Replicas: -1, Config: cfg}
	}
	if _, err := q.Create(ctx, spec("orders", nil), false); code(err) != "QUEUE_EXISTS" {
		t.Errorf("exists: %v", err)
	}
	c, err := q.Create(ctx, spec("jobs.fifo", map[string]string{"contentbaseddeduplication": "true"}), true)
	if err != nil || !c.DryRun || !c.Fifo || c.Attributes["ContentBasedDeduplication"] != "true" || c.Attributes["FifoQueue"] != "true" || f.queues["jobs.fifo"] != nil {
		t.Fatalf("dry run: %+v %v", c, err)
	}
	c, err = q.Create(ctx, spec("jobs.fifo", map[string]string{"ContentBasedDeduplication": "true"}), false)
	if err != nil || c.URL != queueURLOf("jobs.fifo") || f.queues["jobs.fifo"].attrs["FifoQueue"] != "true" {
		t.Fatalf("create: %+v %v", c, err)
	}
	if c, err := q.Create(ctx, spec("plain", nil), false); err != nil || c.Fifo || c.Attributes != nil {
		t.Errorf("plain: %+v %v", c, err)
	}
	for name, cfg := range map[string]map[string]string{
		"a": {"Colour": "blue"}, "b": {"ContentBasedDeduplication": "true"}, "c": {"FifoQueue": "true"}, "bad name": nil,
	} {
		if _, err := q.Create(ctx, spec(name, cfg), true); code(err) != "USAGE" {
			t.Errorf("%s %v: %v", name, cfg, err)
		}
	}
	if _, err := q.Create(ctx, queuex.TopicSpec{Topic: "x", Partitions: 3, Replicas: -1}, true); code(err) != "NOT_SUPPORTED" {
		t.Errorf("partitions: %v", err)
	}
	if _, err := q.Create(ctx, queuex.TopicSpec{Topic: "x", Partitions: -1, Replicas: -1, Type: "quorum"}, true); code(err) != "NOT_SUPPORTED" {
		t.Errorf("type: %v", err)
	}
	f.fail["CreateQueue"] = "QueueDeletedRecently"
	if _, err := q.Create(ctx, spec("again", nil), false); code(err) != "QUEUE_ERROR" || !strings.Contains(toHint(err), "60 seconds") {
		t.Errorf("recently: %v", err)
	}
	f.fail["CreateQueue"] = "InvalidAttributeValue"
	if _, err := q.Create(ctx, spec("again", map[string]string{"DelaySeconds": "9999"}), false); code(err) != "QUEUE_ERROR" || !strings.Contains(toHint(err), "--config") {
		t.Errorf("bad value: %v", err)
	}
}

func toHint(err error) string {
	var e *out.Error
	if errors.As(err, &e) {
		return e.Hint
	}
	return ""
}

func TestDeleteAndPurge(t *testing.T) {
	f, srv := newFake(t)
	f.add("a", nil, "1", "2")
	f.add("b", nil)
	q := open(t, srv, "")
	ctx := context.Background()
	d, err := q.Delete(ctx, []string{"b", "a", "nope"}, true)
	if err != nil || len(d) != 3 || d[0].Queue != "a" || d[0].Messages != 2 || !d[0].Exists || d[2].Exists || f.count("DeleteQueue") != 0 {
		t.Fatalf("dry run: %+v %v", d, err)
	}
	if _, err := q.Delete(ctx, []string{"b", "nope"}, false); code(err) != "QUEUE_NOT_FOUND" || f.queues["b"] == nil {
		t.Errorf("a missing name deletes nothing: %v", err)
	}
	p, err := q.Purge(ctx, "a", true)
	if err != nil || p.Messages != 2 || p.InFlight == nil || len(f.queues["a"].msgs) != 2 {
		t.Fatalf("purge dry run: %+v %v", p, err)
	}
	if p, err := q.Purge(ctx, "a", false); err != nil || p.Messages != 2 || len(f.queues["a"].msgs) != 0 {
		t.Errorf("purge: %+v %v", p, err)
	}
	f.fail["PurgeQueue"] = "PurgeQueueInProgress"
	if _, err := q.Purge(ctx, "a", false); code(err) != "QUEUE_ERROR" || !strings.Contains(toHint(err), "60 seconds") {
		t.Errorf("in progress: %v", err)
	}
	if _, err := q.Purge(ctx, "nope", false); code(err) != "QUEUE_NOT_FOUND" {
		t.Errorf("missing: %v", err)
	}
	if d, err := q.Delete(ctx, []string{"a", "b"}, false); err != nil || len(d) != 2 || len(f.queues) != 0 {
		t.Errorf("delete: %+v %v", d, err)
	}
	if _, err := q.Groups(ctx); code(err) != "NOT_SUPPORTED" {
		t.Errorf("groups: %v", err)
	}
	if _, err := q.Lag(ctx, "x"); code(err) != "NOT_SUPPORTED" {
		t.Errorf("lag: %v", err)
	}
}

func TestOtherAccount(t *testing.T) {
	f, srv := newFake(t)
	f.add("shared", nil)
	q := open(t, srv, "&account=210987654321")
	if _, err := q.Describe(context.Background(), "shared"); err != nil {
		t.Fatal(err)
	}
	if in := f.last["GetQueueUrl"].(map[string]any); in["QueueOwnerAWSAccountId"] != "210987654321" {
		t.Errorf("owner: %v", in)
	}
	if inf, _ := q.Info(context.Background()); inf.AccountID != "210987654321" {
		t.Errorf("info: %+v", inf.SqsInfo)
	}
}

func TestOpErr(t *testing.T) {
	for c, want := range map[string]string{
		"AWS.SimpleQueueService.NonExistentQueue": "QUEUE_NOT_FOUND", "QueueNameExists": "QUEUE_EXISTS", "ExpiredToken": "QUEUE_AUTH",
		"ThrottlingException": "QUEUE_ERROR", "Weird": "QUEUE_ERROR",
	} {
		if got := code(opErr(&apiError{Code: c}, "q")); got != want {
			t.Errorf("%s: %s, want %s", c, got, want)
		}
	}
	if code(opErr(context.DeadlineExceeded, "q")) != "TIMEOUT" || code(opErr(errors.New("reset"), "q")) != "QUEUE_ERROR" || opErr(nil, "q") != nil {
		t.Error("plain errors")
	}
	if (&apiError{Code: "X"}).Error() != "X" {
		t.Error("apiError without a message")
	}
	resp := &http.Response{StatusCode: 400, Status: "400 Bad Request", Header: http.Header{"X-Amzn-Query-Error": {"AWS.SimpleQueueService.NonExistentQueue;Sender"}}}
	if e := answerErr(resp, []byte("<xml/>")).(*apiError); e.Code != "AWS.SimpleQueueService.NonExistentQueue" {
		t.Errorf("query error header: %+v", e)
	}
	resp.Header = http.Header{}
	if e := answerErr(resp, []byte(strings.Repeat("x", 300))).(*apiError); e.Code != "400 Bad Request" || len(e.Message) > 210 {
		t.Errorf("no code: %+v", e)
	}
}

// TestJSONFields: the SQS parts sit next to the other engines' in one
// JSON object, so a field name both use would drop both silently.
func TestJSONFields(t *testing.T) {
	now := time.Now()
	one := int64(1)
	id := "m1"
	for _, c := range []struct {
		v    any
		keys []string
	}{
		{queuex.Info{Engine: "sqs", SqsInfo: &queuex.SqsInfo{AccountID: "1"}}, []string{"region", "endpoint", "account_id", "queues"}},
		{queuex.Topic{SqsQueue: &queuex.SqsQueue{DeadLetterQueue: "d"}}, []string{"fifo", "in_flight", "delayed", "dead_letter_queue"}},
		{queuex.TopicDetail{SqsQueueDetail: &queuex.SqsQueueDetail{CreatedAt: &now}}, []string{"url", "arn", "created_at", "visibility_timeout", "in_flight"}},
		{queuex.Received{SqsMessage: &queuex.SqsMessage{SentAt: &now}}, []string{"message_id", "sent_at", "receive_count"}},
		{queuex.Sent{SqsSent: &queuex.SqsSent{MessageID: &id, SequenceNumber: "1"}}, []string{"message_id", "sequence_number"}},
		{queuex.Created{SqsCreated: &queuex.SqsCreated{URL: "u", Attributes: map[string]string{"a": "b"}}}, []string{"url", "fifo", "attributes"}},
		{queuex.Purged{InFlight: &one}, []string{"in_flight"}},
	} {
		b, _ := json.Marshal(c.v)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		for _, k := range c.keys {
			if _, ok := m[k]; !ok {
				t.Errorf("%T: no %q in %s", c.v, k, b)
			}
		}
	}
}

func TestReceivedSkipsEmptyAttributes(t *testing.T) {
	var m sqsMessage
	raw := `{"MessageId": "m1", "Body": "hi", "MessageAttributes": {"SenderId": {}, "source": {"DataType": "String", "StringValue": "me"}}}`
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	r := received(m, 0)
	if len(r.Headers) != 1 || r.Headers["source"] != "me" {
		t.Errorf("headers: %v", r.Headers)
	}
}
