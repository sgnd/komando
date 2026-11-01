package cachex

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		cmd  string
		want driver.Risk
		rule string
	}{
		{"GET k", driver.RiskRead, ""},
		{"hgetall user:1", driver.RiskRead, ""},
		{"SCAN 0 MATCH x* COUNT 100", driver.RiskRead, ""},
		{"CONFIG GET maxmemory", driver.RiskRead, ""},
		{"CLIENT LIST", driver.RiskRead, ""},
		{"XINFO STREAM events", driver.RiskRead, ""},
		{"EVAL_RO 'return 1' 0", driver.RiskRead, ""},
		{"SET k v", driver.RiskWrite, ""},
		{"DEL k", driver.RiskDestructive, "data-delete"},
		{"unlink a b", driver.RiskDestructive, "data-delete"},
		{"EXPIRE k 10", driver.RiskWrite, ""},
		{"EVAL 'return 1' 0", driver.RiskDestructive, "redis-script-run"},
		{"fcall myfn 0", driver.RiskDestructive, "redis-script-run"},
		{"CLIENT SETNAME x", driver.RiskWrite, ""},
		{"SOMEMODULE.CMD x", driver.RiskWrite, ""},
		{"FLUSHALL", driver.RiskDestructive, "redis-flush"},
		{"flushdb async", driver.RiskDestructive, "redis-flush"},
		{"KEYS *", driver.RiskDestructive, "redis-blocking"},
		{"CONFIG SET maxmemory 1", driver.RiskDestructive, "redis-server-config"},
		{"CLIENT KILL ID 5", driver.RiskDestructive, "redis-kill"},
		{"SHUTDOWN NOSAVE", driver.RiskDestructive, "redis-kill"},
		{"ACL SETUSER eve on >pw", driver.RiskDestructive, "redis-acl"},
		{"SCRIPT FLUSH", driver.RiskDestructive, "redis-scripts"},
		{"REPLICAOF evil 6379", driver.RiskDestructive, "redis-server-config"},
	}
	for _, c := range cases {
		v := Classify(strings.Fields(c.cmd))
		if v.Risk != c.want {
			t.Errorf("%s: %s, want %s", c.cmd, v.Risk, c.want)
		}
		if c.rule != "" && (len(v.RuleIDs) != 1 || v.RuleIDs[0] != c.rule) {
			t.Errorf("%s: rules %v, want %s", c.cmd, v.RuleIDs, c.rule)
		}
	}
}

func TestReply(t *testing.T) {
	got := reply([]any{"a", string([]byte{0, 255}), int64(3), map[any]any{"k": "v"}})
	l := got.([]any)
	if l[0] != "a" || l[2] != int64(3) {
		t.Errorf("reply: %v", got)
	}
	if m, ok := l[1].(map[string]string); !ok || m["base64"] != "AP8=" {
		t.Errorf("binary not base64: %v", l[1])
	}
	if m := l[3].(map[string]any); m["k"] != "v" {
		t.Errorf("map: %v", l[3])
	}
}
