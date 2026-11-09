package rabbitmq

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

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// fakeMgmt is a management API with one vhost "/" and two queues.
func fakeMgmt(t *testing.T) *httptest.Server {
	answers := map[string]any{
		"/api/overview": map[string]any{"rabbitmq_version": "4.1.4", "cluster_name": "rabbit@prod",
			"object_totals": map[string]int{"queues": 2, "exchanges": 7, "connections": 3, "channels": 3, "consumers": 1},
			"queue_totals":  map[string]int64{"messages": 5, "messages_ready": 4, "messages_unacknowledged": 1}},
		"/api/nodes": []map[string]any{{"name": "rabbit@b", "running": false, "type": "disc"}, {"name": "rabbit@a", "running": true, "type": "disc"}},
		"/api/queues/%2F": []map[string]any{
			{"name": "orders", "type": "quorum", "durable": true, "messages": 4, "messages_ready": 3, "messages_unacknowledged": 1, "consumers": 1, "state": "running"},
			{"name": "emails", "type": "classic", "durable": true, "messages": 1, "messages_ready": 1},
		},
		"/api/queues/%2F/orders": map[string]any{"name": "orders", "type": "quorum", "durable": true, "messages": 4, "messages_ready": 3, "messages_unacknowledged": 1,
			"consumers": 1, "state": "running", "leader": "rabbit@a", "policy": "ha", "arguments": map[string]any{"x-delivery-limit": 5},
			"effective_policy_definition": []any{},
			"consumer_details": []map[string]any{{"consumer_tag": "ctag-1", "ack_required": true, "prefetch_count": 10, "active": true,
				"channel_details": map[string]any{"connection_name": "", "peer_host": "10.0.0.5", "user": "worker"}}}},
		"/api/queues/%2F/emails": map[string]any{"name": "emails", "type": "classic", "durable": true, "arguments": map[string]any{},
			"effective_policy_definition": map[string]any{"delivery-limit": 7}},
		"/api/queues/%2F/jobs": map[string]any{"name": "jobs", "type": "quorum", "durable": true, "arguments": map[string]any{}, "effective_policy_definition": []any{}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if u, p, _ := req.BasicAuth(); u != "app" || p != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch req.URL.EscapedPath() {
		case "/api/queues/%2F/broken":
			w.Write([]byte("<html>"))
			return
		case "/api/queues/%2F/locked":
			w.WriteHeader(http.StatusForbidden)
			return
		case "/api/queues/%2F/boom":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"internal"}`))
			return
		}
		a, ok := answers[req.URL.EscapedPath()]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(a)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fake is a Rabbit whose AMQP connection is only its server properties:
// enough for what reads the management API.
func fake(t *testing.T, mgmt string, password string) *Rabbit {
	tg, err := driver.Parse("amqp://app@127.0.0.1/?management=1")
	if err != nil {
		t.Fatal(err)
	}
	tg.Management = mgmt
	return &Rabbit{conn: &amqp.Connection{Properties: amqp.Table{"product": "RabbitMQ", "version": "4.1.4", "platform": "Erlang/OTP 27"}},
		t: tg, user: "app", password: password, dial: (&net.Dialer{}).DialContext, timeout: 5 * time.Second}
}

func TestManagement(t *testing.T) {
	srv := fakeMgmt(t)
	r := fake(t, strings.TrimPrefix(srv.URL, "http://"), "pw")
	ctx := context.Background()
	inf, err := r.Info(ctx)
	if err != nil || inf.Engine != "rabbitmq" || inf.Version != "4.1.4" || inf.Cluster != "rabbit@prod" || inf.Totals.Queues != 2 || len(inf.Nodes) != 2 || inf.Nodes[0].Name != "rabbit@a" {
		t.Fatalf("info: %+v %v", inf, err)
	}
	ts, err := r.Topics(ctx, "", false)
	if err != nil || len(ts) != 2 || ts[0].Name != "emails" || ts[1].Type != "quorum" || ts[1].Unacked != 1 {
		t.Fatalf("ls: %+v %v", ts, err)
	}
	if ts, _ := r.Topics(ctx, "ord*", false); len(ts) != 1 {
		t.Errorf("ls pattern: %+v", ts)
	}
	d, err := r.Describe(ctx, "orders")
	if err != nil || d.Messages != 4 || *d.Unacked != 1 || d.Node != "rabbit@a" || len(d.ConsumerOf) != 1 || d.ConsumerOf[0].Connection != "10.0.0.5" {
		t.Fatalf("describe: %+v %v", d.RabbitQueueDetail, err)
	}
	if q, n, err := r.deliveryLimit(ctx, "orders"); !q || n != 5 || err != nil {
		t.Errorf("limit from the argument: %v %d %v", q, n, err)
	}
	if q, n, err := r.deliveryLimit(ctx, "emails"); q || n != 0 || err != nil {
		t.Errorf("a classic queue has no limit: %v %d %v", q, n, err)
	}
	if q, n, err := r.deliveryLimit(ctx, "jobs"); !q || n != 20 || err != nil {
		t.Errorf("a quorum queue without its own limit: RabbitMQ 4's default: %v %d %v", q, n, err)
	}
	r.conn.Properties["version"] = "3.13.7"
	if _, n, _ := r.deliveryLimit(ctx, "jobs"); n != 0 {
		t.Errorf("RabbitMQ 3 has no default limit: %d", n)
	}
	r.conn.Properties["version"] = "4.1.4"
	// the queue may have a limit of its own (x-delivery-limit=3): peek
	// that cannot read it stops before it takes a message
	for name, want := range map[string]string{"boom": "QUEUE_ERROR", "locked": "QUEUE_DENIED"} {
		if _, _, err := r.deliveryLimit(ctx, name); code(err) != want || !strings.Contains(toErr(err).Hint, "delivery limit") {
			t.Errorf("the management API fails for %s: peek must stop: %v", name, err)
		}
	}
	for name, want := range map[string]string{"nope": "QUEUE_NOT_FOUND", "broken": "QUEUE_ERROR", "locked": "QUEUE_DENIED", "boom": "QUEUE_ERROR"} {
		if _, err := r.Describe(ctx, name); code(err) != want {
			t.Errorf("describe %s: %v, want %s", name, err, want)
		}
	}
	r.t.Database = "nowhere"
	if _, err := r.Topics(ctx, "", false); code(err) != "QUEUE_ERROR" || !strings.Contains(err.Error(), "/api/queues/nowhere") {
		t.Errorf("a missing vhost: %v", err)
	}
	if _, err := fake(t, r.t.Management, "wrong").Info(ctx); code(err) != "QUEUE_AUTH" {
		t.Errorf("wrong password: %v", err)
	}
	srv.Close()
	if _, err := fake(t, r.t.Management, "pw").Info(ctx); code(err) != "QUEUE_CONNECT" {
		t.Errorf("no management API: %v", err)
	}
}

func TestWithoutManagement(t *testing.T) {
	r := fake(t, "", "pw")
	ctx := context.Background()
	inf, err := r.Info(ctx)
	if err != nil || inf.Product != "RabbitMQ" || inf.Management || inf.Platform != "Erlang/OTP 27" || inf.Totals != nil {
		t.Errorf("info: %+v %v", inf.RabbitInfo, err)
	}
	if _, err := r.Topics(ctx, "", false); code(err) != "NOT_SUPPORTED" || !strings.Contains(toErr(err).Hint, "management=15672") {
		t.Errorf("ls: %v", err)
	}
	// AMQP cannot tell a queue's type or its own x-delivery-limit, so
	// peek refuses instead of assuming a default that may be too high
	for _, v := range []string{"4.1.4", "3.13.7"} {
		r.conn.Properties["version"] = v
		if _, _, err := r.deliveryLimit(ctx, "x"); code(err) != "NOT_SUPPORTED" || !strings.Contains(toErr(err).Hint, "management=15672") {
			t.Errorf("peek without the management API on %s: %v", v, err)
		}
	}
}

// TestNotSupported: what RabbitMQ cannot do says so before it touches the
// server.
func TestNotSupported(t *testing.T) {
	r := fake(t, "", "pw")
	ctx := context.Background()
	for what, err := range map[string]error{
		"groups":      second(r.Groups(ctx)),
		"lag":         second(r.Lag(ctx, "g")),
		"ls internal": second(r.Topics(ctx, "", true)),
		"peek part":   second(r.Peek(ctx, queuex.PeekOptions{Topic: "q", Limit: 1, Partition: 0})),
		"send key":    second(r.Send(ctx, queuex.Message{Topic: "q", Key: []byte("k"), Partition: -1}, true)),
		"send part":   second(r.Send(ctx, queuex.Message{Topic: "q", Partition: 1}, true)),
		"create part": second(r.Create(ctx, queuex.TopicSpec{Topic: "q", Partitions: 3, Replicas: -1}, true)),
	} {
		if code(err) != "NOT_SUPPORTED" {
			t.Errorf("%s: %v", what, err)
		}
	}
	if _, err := r.Create(ctx, queuex.TopicSpec{Topic: "q", Partitions: -1, Replicas: -1, Type: "lazy"}, true); code(err) != "USAGE" {
		t.Errorf("--type lazy: %v", err)
	}
}

func second[T any](_ T, err error) error { return err }

func toErr(err error) *out.Error {
	var e *out.Error
	errors.As(err, &e)
	if e == nil {
		return &out.Error{}
	}
	return e
}

func TestOpenFails(t *testing.T) {
	ctx := context.Background()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	go func() { // a server that speaks something else and hangs up
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	defer l.Close()
	tg, _ := driver.Parse("amqp://" + addr + "/")
	if _, err := Open(ctx, tg, "", nil, 2*time.Second, "test"); code(err) != "QUEUE_CONNECT" {
		t.Errorf("not AMQP: %v", err)
	}
	tg, _ = driver.Parse("amqps://" + addr + "/")
	if _, err := Open(ctx, tg, "", nil, 2*time.Second, "test"); code(err) != "QUEUE_CONNECT" {
		t.Errorf("TLS to a plain port: %v", err)
	}
	silent, _ := net.Listen("tcp", "127.0.0.1:0")
	defer silent.Close()
	tg, _ = driver.Parse("amqp://" + silent.Addr().String() + "/")
	if _, err := Open(ctx, tg, "", nil, 300*time.Millisecond, "test"); code(err) != "TIMEOUT" {
		t.Errorf("a server that says nothing: %v", err)
	}
	l.Close()
	tg, _ = driver.Parse("amqp://" + addr + "/")
	if _, err := Open(ctx, tg, "", nil, time.Second, "test"); code(err) != "QUEUE_CONNECT" {
		t.Errorf("nothing listening: %v", err)
	}
	tg, _ = driver.Parse("amqps://" + addr + "/?ca=secret:missing")
	driver.ResolveSecret = func(string) (string, error) { return "", driver.ErrSecretNotFound }
	defer func() { driver.ResolveSecret = nil }()
	if _, err := Open(ctx, tg, "", nil, time.Second, "test"); err == nil {
		t.Error("a missing CA secret opened")
	}
}

func TestErrors(t *testing.T) {
	tg, _ := driver.Parse("amqps://app@r.example.com/prod")
	for err, want := range map[error]string{
		amqp.ErrCredentials: "QUEUE_AUTH",
		amqp.ErrVhost:       "QUEUE_DENIED",
		&amqp.Error{Code: amqp.NotAllowed, Reason: "vhost prod not found"}:       "QUEUE_DENIED",
		errors.New("tls: failed to verify certificate: x509: unknown authority"): "QUEUE_CONNECT",
		errors.New("tls: first record does not look like a TLS handshake"):       "QUEUE_CONNECT",
		context.DeadlineExceeded:                   "TIMEOUT",
		errors.New("dial tcp: connection refused"): "QUEUE_CONNECT",
	} {
		if got := code(connectErr(tg, err)); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
	for err, want := range map[error]string{
		&amqp.Error{Code: amqp.NotFound, Reason: "NOT_FOUND"}:              "QUEUE_NOT_FOUND",
		&amqp.Error{Code: amqp.AccessRefused, Reason: "ACCESS_REFUSED"}:    "QUEUE_DENIED",
		&amqp.Error{Code: amqp.ResourceLocked, Reason: "RESOURCE_LOCKED"}:  "QUEUE_ERROR",
		&amqp.Error{Code: amqp.PreconditionFailed, Reason: "inequivalent"}: "QUEUE_ERROR",
		&amqp.Error{Code: amqp.InternalError, Reason: "INTERNAL_ERROR"}:    "QUEUE_ERROR",
		amqp.ErrClosed:           "QUEUE_ERROR",
		context.DeadlineExceeded: "TIMEOUT",
	} {
		if got := code(opErr(err, "orders")); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
	if opErr(nil, "x") != nil {
		t.Error("opErr(nil)")
	}
	if code(streamErr(&amqp.Error{Code: amqp.NotImplemented, Reason: "basic.get not supported by stream queues"})) != "NOT_SUPPORTED" {
		t.Error("stream")
	}
}

func TestDelivery(t *testing.T) {
	d := amqp.Delivery{Body: []byte("hello world"), Redelivered: true, Exchange: "orders", RoutingKey: "paid", ContentType: "application/json",
		MessageId: "m1", Timestamp: time.Date(2026, 11, 10, 1, 2, 3, 0, time.UTC), DeliveryMode: amqp.Persistent, Priority: 3,
		Headers: amqp.Table{"x-delivery-count": int64(4), "source": "web", "raw": []byte{0xff}, "n": int32(7)}}
	m := delivery(d, 5, false)
	if m.Value != "hello" || !m.ValueTruncated || m.Size != 11 || m.Deliveries != 5 || m.Headers["source"] != "web" || m.Headers["n"] != "7" ||
		m.Properties["timestamp"] != "2026-11-10T01:02:03Z" || m.Properties["priority"] != "3" || m.Properties["delivery_mode"] != "persistent" {
		t.Errorf("delivery: %+v %+v", m, m.RabbitDelivery)
	}
	if m := delivery(amqp.Delivery{Body: []byte("x")}, 0, true); m.Deliveries != 1 || m.Properties != nil || m.Headers != nil {
		t.Errorf("a fresh message of a quorum queue: %+v", m.RabbitDelivery)
	}
	if m := delivery(amqp.Delivery{Body: []byte("x")}, 0, false); m.Deliveries != 0 {
		t.Errorf("a classic queue counts nothing: %+v", m.RabbitDelivery)
	}
	for v, want := range map[any]int64{int8(1): 1, int16(2): 2, int32(3): 3, int64(4): 4, 5: 5, uint8(6): 6, uint16(7): 7, uint32(8): 8, float64(9): 9} {
		if n, ok := number(v); !ok || n != want {
			t.Errorf("number(%T)", v)
		}
	}
	if _, ok := number("1"); ok {
		t.Error("number of text")
	}
}

func TestNearLimit(t *testing.T) {
	msg := func(n int64) queuex.Received {
		return queuex.Received{RabbitDelivery: &queuex.RabbitDelivery{Deliveries: n}}
	}
	for _, c := range []struct {
		limit int64
		got   []int64
		want  string
	}{
		{20, []int64{1, 2}, ""},
		{20, []int64{1, 17}, ""},
		{20, []int64{18, 1}, "has 2 deliveries left"},
		{20, []int64{21}, "went over it"},
		{0, []int64{100}, ""},
		{5, []int64{0}, ""},
	} {
		res := &queuex.PeekResult{Queue: "q"}
		for _, n := range c.got {
			res.Messages = append(res.Messages, msg(n))
		}
		err := nearLimit(res, c.limit)
		if c.want == "" && err != nil || c.want != "" && (code(err) != "DELIVERY_LIMIT_NEAR" || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("limit %d, deliveries %v: %v", c.limit, c.got, err)
		}
	}
}

func TestArgument(t *testing.T) {
	if argument("1000") != int64(1000) || argument("true") != true || argument("reject-publish") != "reject-publish" || argument("1") != int64(1) {
		t.Error("argument")
	}
	if str(nil) != "" || str([]byte("b")) != "b" || str(3) != "3" {
		t.Error("str")
	}
	if table(nil, 0) != nil {
		t.Error("table(nil)")
	}
}
