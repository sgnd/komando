package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// TestQueueRabbitConn: amqp:// straight over the network needs amqps:// or
// ?insecure=1, like redis://; doctor flags the weak ones and says how to
// fix them.
func TestQueueRabbitConn(t *testing.T) {
	invHome(t)
	wantCode(t, "INSECURE_PROTOCOL", "conn", "add", "r", "amqp://app@rabbit.example.com/")
	mustRun(t, "conn", "add", "r", "amqps://app@rabbit.example.com/%2F?management=15671")
	mustRun(t, "host", "add", "office", "u@10.0.0.1")
	mustRun(t, "conn", "add", "r-via", "amqp://app@rabbit.internal/", "--via", "office")
	mustRun(t, "conn", "add", "r-plain", "amqp://app@rabbit.example.com:5672/?insecure=1")
	if got := plainConn(&store.Conn{Name: "r-plain", URL: "amqp://app@rabbit.example.com:5672/prod?insecure=1"}); !strings.Contains(got, "amqps://app@rabbit.example.com:5671/prod") {
		t.Errorf("doctor: %q", got)
	}
	if got := plainConn(&store.Conn{Name: "r", URL: "amqps://rabbit.example.com/?tls=skip-verify"}); !strings.Contains(got, "not checked") || strings.Contains(got, "skip-verify'") {
		t.Errorf("doctor skip-verify: %q", got)
	}
	if w := weakTLS("", "amqps://rabbit.example.com/?tls=skip-verify"); len(w) != 1 {
		t.Errorf("weakTLS: %v", w)
	}
	if w := weakTLS("amqps://rabbit.example.com/", "amqp://rabbit.example.com/?insecure=1"); len(w) != 2 {
		t.Errorf("weakTLS downgrade: %v", w)
	}
	if d := mustRun(t, "conn", "show", "r"); !strings.Contains(jsonOf(d), "vhost /") && !strings.Contains(jsonOf(d), "rabbitmq") {
		t.Errorf("conn show: %v", d)
	}
}

// TestQueueRabbitLive runs the queue commands against a real RabbitMQ:
// set KOMANDO_E2E_RABBITMQ to a conn URL with ?management=PORT and
// KOMANDO_E2E_RABBITMQ_PASSWORD to its user's password.
func TestQueueRabbitLive(t *testing.T) {
	url := os.Getenv("KOMANDO_E2E_RABBITMQ")
	if url == "" {
		t.Skip("set KOMANDO_E2E_RABBITMQ and KOMANDO_E2E_RABBITMQ_PASSWORD")
	}
	invHome(t)
	mustRun(t, "conn", "add", "jobs", url, "--password-ref", "env:KOMANDO_E2E_RABBITMQ_PASSWORD")
	if d := mustRun(t, "conn", "test", "jobs"); !strings.Contains(jsonOf(d), `"check":"login"`) {
		t.Errorf("conn test: %v", d)
	}
	if d := mustRun(t, "queue", "info", "jobs"); d["engine"] != "rabbitmq" || d["management"] != true {
		t.Errorf("info: %v", d)
	}
	invRun(t, "queue", "rm", "jobs", "komando-cli", "--allow-dangerous") // left by an earlier run
	g.allowDangerous = false
	if d := mustRun(t, "--dry-run", "queue", "create", "jobs", "komando-cli", "--type", "quorum"); d["dry_run"] != true {
		t.Errorf("dry-run create: %v", d)
	}
	g.dryRun, store.DryRun = false, false
	wantCode(t, "QUEUE_NOT_FOUND", "queue", "describe", "jobs", "komando-cli")
	wantCode(t, "NOT_SUPPORTED", "queue", "create", "jobs", "komando-cli", "--partitions", "3")
	mustRun(t, "queue", "create", "jobs", "komando-cli", "--type", "quorum", "--config", "x-max-length=100")
	wantCode(t, "QUEUE_EXISTS", "queue", "create", "jobs", "komando-cli")
	mustRun(t, "queue", "send", "jobs", "komando-cli", "--value", `{"id": 1}`, "--header", "source=test")
	wantCode(t, "NOT_SUPPORTED", "queue", "send", "jobs", "komando-cli", "--value", "x", "--key", "k")
	wantCode(t, "HIDDEN_VALUE", "queue", "send", "jobs", "komando-cli", "--value", "password=[hidden]")
	d := mustRun(t, "queue", "peek", "jobs", "komando-cli")
	if d["count"].(float64) != 1 || d["requeued"] != true || d["queue"] != "komando-cli" || !strings.Contains(jsonOf(d), `"source":"test"`) {
		t.Errorf("peek: %v", d)
	}
	if d := mustRun(t, "queue", "peek", "jobs", "komando-cli"); !strings.Contains(jsonOf(d), `"redelivered":true`) || d["delivery_limit"] == nil {
		t.Errorf("peek again: %v", d)
	}
	wantCode(t, "NOT_SUPPORTED", "queue", "groups", "jobs")
	wantCode(t, "NOT_SUPPORTED", "queue", "lag", "jobs", "billing")
	wantCode(t, "POLICY_BLOCKED", "queue", "purge", "jobs", "komando-cli")
	if d := mustRun(t, "--dry-run", "queue", "purge", "jobs", "komando-cli"); d["messages"].(float64) != 1 {
		t.Errorf("dry-run purge: %v", d)
	}
	g.dryRun, store.DryRun = false, false
	mustRun(t, "queue", "purge", "jobs", "komando-cli", "--allow-dangerous")
	g.allowDangerous = false
	wantCode(t, "POLICY_BLOCKED", "queue", "rm", "jobs", "komando-cli")
	mustRun(t, "queue", "rm", "jobs", "komando-cli", "--allow-dangerous")
	g.allowDangerous = false
}
