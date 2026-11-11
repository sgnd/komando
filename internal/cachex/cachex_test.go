package cachex

import (
	"errors"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
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
		{"CONFIG GET requirepass", driver.RiskRead, ""}, // a read; HideSecrets hides the value from agents
		// a read-only script cannot write, but it can loop and block the server
		{"EVAL_RO 'return 1' 0", driver.RiskDestructive, "redis-script-run"},
		{"evalsha_ro e0e1f9fabfc9d4800c877a703b823ac0578ff8db 0", driver.RiskDestructive, "redis-script-run"},
		{"FCALL_RO myfn 0", driver.RiskDestructive, "redis-script-run"},
		// REPLACE swaps the code behind functions the application calls
		{"FUNCTION LOAD REPLACE code", driver.RiskDestructive, "redis-scripts"},
		{"function load replace code", driver.RiskDestructive, "redis-scripts"},
		{"FUNCTION LOAD code", driver.RiskWrite, ""},
		{"FUNCTION DELETE lib", driver.RiskDestructive, "redis-scripts"},
		{"FUNCTION RESTORE payload REPLACE", driver.RiskDestructive, "redis-scripts"},
		{"FUNCTION LIST", driver.RiskRead, ""},
		{"SCRIPT LOAD code", driver.RiskWrite, ""},
		// module code komando cannot inspect: Triggers and Functions, RedisGears
		{"TFCALL lib.fn 0", driver.RiskDestructive, "redis-script-run"},
		{"tfcallasync lib.fn 1 k", driver.RiskDestructive, "redis-script-run"},
		{"RG.PYEXECUTE GB().run()", driver.RiskDestructive, "redis-script-run"},
		{"rg.trigger t1", driver.RiskDestructive, "redis-script-run"},
		{"RG.TRIGGERONKEY t1 k", driver.RiskDestructive, "redis-script-run"},
		{"RG.UNREGISTER 0000000000000000000000000000000000000000-1", driver.RiskDestructive, "redis-scripts"},
		{"TFUNCTION LOAD REPLACE code", driver.RiskDestructive, "redis-scripts"},
		{"TFUNCTION LOAD CONFIG {} REPLACE code", driver.RiskDestructive, "redis-scripts"},
		{"TFUNCTION LOAD code", driver.RiskWrite, ""},
		{"TFUNCTION DELETE lib", driver.RiskDestructive, "redis-scripts"},
		{"TFUNCTION LIST", driver.RiskRead, ""},
		{"FUNCTION LOAD", driver.RiskWrite, ""},
		{"FUNCTION LOAD REPLACE", driver.RiskWrite, ""}, // no code: the server refuses it
		{"FUNCTION LOAD replace", driver.RiskWrite, ""}, // "replace" is the code here
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
		{"GETDEL k", driver.RiskDestructive, "data-delete"},
		{"RENAME a b", driver.RiskDestructive, "data-delete"},
		{"RENAMENX a b", driver.RiskWrite, ""},
		{"EXPIRE k 0", driver.RiskDestructive, "data-delete"},
		{"pexpire k -1", driver.RiskDestructive, "data-delete"},
		{"EXPIREAT k 1", driver.RiskDestructive, "data-delete"},
		{"EXPIREAT k 99999999999", driver.RiskWrite, ""},
		{"ACL LOG", driver.RiskRead, ""},
		{"ACL LOG RESET", driver.RiskWrite, ""},
		{"JSON.GET doc $", driver.RiskRead, ""},
		{"FT.SEARCH idx hello", driver.RiskRead, ""},
		{"TS.RANGE t - +", driver.RiskRead, ""},
		{"JSON.SET doc $ 1", driver.RiskWrite, ""},
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

// A TLS failure gets a hint about TLS, not about reachability.
func TestConnectErrTLS(t *testing.T) {
	tg := driver.Target{Kind: driver.Kind{Name: "redis"}, Address: "cache:6380", Secure: true}
	for msg, want := range map[string]string{
		"tls: failed to verify certificate: x509: certificate signed by unknown authority": "could not be checked",
		"tls: first record does not look like a TLS handshake":                             "does not speak TLS",
	} {
		var oe *out.Error
		if err := connectErr(tg, errors.New(msg)); !errors.As(err, &oe) || !strings.Contains(oe.Hint, want) {
			t.Errorf("%s: %v", msg, err)
		}
	}
}

// A command given as one argument splits like a redis-cli line.
func TestSplitCommand(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want []string
	}{
		{[]string{"GET", "foo"}, []string{"GET", "foo"}},
		{[]string{"get foo"}, []string{"get", "foo"}},
		{[]string{`SET "a b" 'it''s'`}, []string{"SET", "a b", "its"}},
		{[]string{`SET k "x\ny\x41\"q"`}, []string{"SET", "k", "x\nyA\"q"}},
		{[]string{`SET k 'a\'b\n'`}, []string{"SET", "k", `a'b\n`}},
		{[]string{"PING"}, []string{"PING"}},
	} {
		got, err := SplitCommand(c.in)
		if err != nil || strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%q: %q %v", c.in, got, err)
		}
	}
	if _, err := SplitCommand([]string{`GET "foo`}); err == nil {
		t.Error("unbalanced quote accepted")
	}
}

// cache run waits for one reply: XREAD is a read, and commands that
// stream without end are refused.
func TestOneReply(t *testing.T) {
	if v := Classify(strings.Fields("XREAD COUNT 1 STREAMS s 0")); v.Risk != driver.RiskRead {
		t.Errorf("XREAD: %v", v.Risk)
	}
	for _, c := range []string{"MONITOR", "subscribe ch", "PSUBSCRIBE a*", "XREAD BLOCK 0 STREAMS s $", "XREADGROUP GROUP g c block 10 STREAMS s >"} {
		var e *out.Error
		if err := OneReply(strings.Fields(c)); !errors.As(err, &e) || e.Code != "NOT_SUPPORTED" {
			t.Errorf("%s: %v", c, err)
		}
	}
	for _, c := range []string{"GET k", "XREAD COUNT 1 STREAMS s 0", "PUBLISH ch hi"} {
		if err := OneReply(strings.Fields(c)); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
}
