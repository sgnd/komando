package cli

import (
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// C363 (issue #490, Audit K4): a protected entry keeps its --yes on every
// raw path, per built provider, before D4 removes the typed cache and
// cluster verbs and confirmObject. Each case says who runs it, with which
// flags, and whether the command reaches the server.

// rawTarget is one built provider with a protected entry and its raw path.
type rawTarget struct {
	provider string
	add      func(t *testing.T) (name string, reached func() int)
	raw      []string            // the path up to the entry: cache redis raw
	write    []string            // a change that deletes nothing
	danger   map[string][]string // destructive changes, by label
}

func rawTargets() []rawTarget {
	return []rawTarget{
		{
			provider: "cache redis",
			add: func(t *testing.T) (string, func() int) {
				addr, n := acceptCounter(t)
				mustRun(t, "cache", "redis", "add", "pcache", "redis://"+addr+"/0", "--protected")
				return "pcache", n
			},
			raw:    []string{"cache", "redis", "raw"},
			write:  []string{"SET", "k", "v"},
			danger: map[string][]string{"DEL": {"DEL", "k"}, "FLUSHALL": {"FLUSHALL"}},
		},
		{
			provider: "cache memcached",
			add: func(t *testing.T) (string, func() int) {
				addr, lines := fakeMemcached(t)
				mustRun(t, "cache", "memcached", "add", "pmc", "memcached://"+addr, "--protected")
				return "pmc", func() int { return len(lines()) }
			},
			raw:    []string{"cache", "memcached", "raw"},
			write:  []string{"touch", "k", "30"},
			danger: map[string][]string{"delete": {"delete", "k"}, "flush_all": {"flush_all"}},
		},
		{
			provider: "cluster kubernetes",
			add: func(t *testing.T) (string, func() int) {
				l := newLabCluster(t)
				kc := "apiVersion: v1\nkind: Config\ncurrent-context: prod\nclusters:\n- name: prod\n  cluster:\n    server: " + l.srv.URL +
					"\nusers:\n- name: prod\n  user:\n    token: test-token-abcdef\ncontexts:\n- name: prod\n  context:\n    cluster: prod\n    user: prod\n    namespace: shop\n"
				ref := savedRef(t, "pk8s-kubeconfig", kc)
				mustRun(t, "cluster", "kubernetes", "add", "pk8s", "k8s://"+strings.TrimPrefix(l.srv.URL, "http://"),
					"--credential", strings.TrimPrefix(ref, "credential:"), "--protected")
				return "pk8s", func() int { return l.changes() }
			},
			raw:   []string{"cluster", "kubernetes", "raw"},
			write: []string{"scale", "deploy/api", "--replicas=3"},
			danger: map[string][]string{
				"delete":       {"delete", "deploy/api", "--wait=false"},
				"scale-to-0":   {"scale", "deploy/api", "--replicas=0"}, // rule kubectl-scale-zero
				"scale-to-0-n": {"scale", "--replicas", "0", "deployment", "api"},
			},
		},
		{
			provider: "cluster swarm",
			add: func(t *testing.T) (string, func() int) {
				addr, n := acceptCounter(t)
				mustRun(t, "host", "add", "pswarm", "deploy@"+addr, "--tag", "swarm", "--protected", "--password-ref", savedRef(t, "pswarm-pass", "Test-pass-7"))
				return "pswarm", n
			},
			raw:    []string{"cluster", "swarm", "raw"},
			write:  []string{"service", "scale", "web=3"},
			danger: map[string][]string{"service-rm": {"service", "rm", "web"}, "scale-to-0": {"service", "scale", "web=0"}},
		},
	}
}

// acceptCounter is a loopback server that counts the connections it is
// sent and closes each at once: a stopped command opens none.
func acceptCounter(t *testing.T) (string, func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	return ln.Addr().String(), func() int { return int(n.Load()) }
}

// changes counts the requests that are not reads: a stopped kubectl
// change sends none.
func (l *labCluster) changes() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.reqs {
		if !strings.HasPrefix(r, "GET ") {
			n++
		}
	}
	return n
}

// rawCase is one run: who, the gate flags, the change, and the answer.
type rawCase struct {
	name   string
	agent  bool
	window string // agent only: "none" (no window can open), "deny", "allow"
	flags  []string
	danger bool
	code   string // the stop, or "" when the command reaches the server
	asked  bool   // komando asked for a window (a person's flags never ask)
}

// rawCases is the table of guard answers on a protected entry.
var rawCases = []rawCase{
	{name: "person/write", flags: nil, code: "PROTECTED_TARGET"},
	{name: "person/write --yes", flags: []string{"--yes"}},
	{name: "person/danger --yes", flags: []string{"--yes"}, danger: true, code: "POLICY_BLOCKED"},
	{name: "person/danger --allow-dangerous", flags: []string{"--allow-dangerous"}, danger: true, code: "PROTECTED_TARGET"},
	{name: "person/danger both", flags: []string{"--yes", "--allow-dangerous"}, danger: true},

	{name: "agent/write", agent: true, window: "allow", code: "PROTECTED_TARGET"},
	{name: "agent/write --yes no window", agent: true, window: "none", flags: []string{"--yes"}, code: "PROTECTED_TARGET", asked: true},
	{name: "agent/write --yes denied", agent: true, window: "deny", flags: []string{"--yes"}, code: "PROTECTED_TARGET", asked: true},
	{name: "agent/write --yes allowed", agent: true, window: "allow", flags: []string{"--yes"}, asked: true},
	{name: "agent/danger", agent: true, window: "allow", danger: true, code: "POLICY_BLOCKED"},
	{name: "agent/danger --yes allowed", agent: true, window: "allow", flags: []string{"--yes"}, danger: true, code: "POLICY_BLOCKED"},
	{name: "agent/danger --allow-dangerous allowed", agent: true, window: "allow", flags: []string{"--allow-dangerous"}, danger: true, code: "PROTECTED_TARGET", asked: true},
	{name: "agent/danger both no window", agent: true, window: "none", flags: []string{"--yes", "--allow-dangerous"}, danger: true, code: "POLICY_BLOCKED", asked: true},
	{name: "agent/danger both denied", agent: true, window: "deny", flags: []string{"--yes", "--allow-dangerous"}, danger: true, code: "POLICY_BLOCKED", asked: true},
	{name: "agent/danger both allowed", agent: true, window: "allow", flags: []string{"--yes", "--allow-dangerous"}, danger: true, asked: true},
}

// TestRawProtectedYes runs every case of rawCases on every built provider:
// a stop sends nothing to the server, and a run gets past every guard.
func TestRawProtectedYes(t *testing.T) {
	for _, rt := range rawTargets() {
		for _, c := range rawCases {
			commands := map[string][]string{"write": rt.write}
			if c.danger {
				commands = rt.danger
			}
			for label, command := range commands {
				t.Run(rt.provider+"/"+c.name+"/"+label, func(t *testing.T) {
					invHome(t)
					noAgent(t)
					name, reached := rt.add(t)
					windows := rawActor(t, c)
					before := reached()
					args := append(slices.Clone(c.flags), rt.raw...)
					args = append(append(args, name, "--write", "--"), command...)
					_, e := cliRun(t, args...)
					sent := reached() > before
					switch {
					case c.code != "" && (e == nil || e.Code != c.code):
						t.Errorf("want %s, got %+v", c.code, e)
					case c.code != "" && e.Exit != out.ExitPolicy:
						t.Errorf("%s exits %d, want %d", e.Code, e.Exit, out.ExitPolicy)
					case c.code != "" && sent:
						t.Errorf("%s, yet the command reached the server", c.code)
					case c.code == "" && e != nil && e.Exit == out.ExitPolicy:
						t.Errorf("want a run, got the stop %s: %s", e.Code, e.Message)
					case c.code == "" && !sent:
						t.Errorf("want a run, but nothing reached the server (%+v)", e)
					}
					if asked := len(*windows) > 0; asked != c.asked {
						t.Errorf("windows asked for: %q, want any: %v", *windows, c.asked)
					}
					// the person whose yes lets the change through read that the entry is protected
					if c.agent && c.code == "" && !strings.Contains(strings.Join(*windows, "\n"), "protected") {
						t.Errorf("no window names the protected entry: %q", *windows)
					}
				})
			}
		}
	}
}

// TestRawScaleToZeroDangerous: on an entry that is not protected, a raw
// kubectl delete or scale to 0 (rule kubectl-scale-zero) still needs
// --allow-dangerous from a person and from an agent; a scale up does not.
func TestRawScaleToZeroDangerous(t *testing.T) {
	for _, agent := range []bool{false, true} {
		for _, c := range []struct {
			command []string
			code    string
		}{
			{[]string{"scale", "deploy/api", "--replicas=0"}, "POLICY_BLOCKED"},
			{[]string{"scale", "--replicas", "0", "deployment", "api"}, "POLICY_BLOCKED"},
			{[]string{"delete", "deploy/api", "--wait=false"}, "POLICY_BLOCKED"},
			{[]string{"scale", "deploy/api", "--replicas=3"}, ""},
		} {
			t.Run(map[bool]string{false: "person", true: "agent"}[agent]+"/"+strings.Join(c.command, " "), func(t *testing.T) {
				invHome(t)
				noAgent(t)
				l := newLabCluster(t)
				mustRun(t, "import", "kubeconfig", l.kubeconfigFile(t, "    token: test-token-abcdef"))
				windows := rawActor(t, rawCase{agent: agent, window: "allow"})
				_, e := cliRun(t, append([]string{"cluster", "kubernetes", "raw", "prod", "--write", "--"}, c.command...)...)
				switch {
				case c.code != "" && (e == nil || e.Code != c.code):
					t.Errorf("want %s, got %+v", c.code, e)
				case c.code != "" && l.changes() > 0:
					t.Errorf("%s, yet the cluster was changed", c.code)
				case c.code == "" && (e != nil || l.changes() == 0):
					t.Errorf("want a run, got %+v (changes %d)", e, l.changes())
				}
				if len(*windows) > 0 {
					t.Errorf("no flag was given, yet a window was asked for: %q", *windows)
				}
			})
		}
	}
}

// rawActor makes the rest of the test run as c's caller and returns the
// texts of the approval windows komando asked for.
func rawActor(t *testing.T, c rawCase) *[]string {
	t.Helper()
	texts := new([]string)
	saved := askOnScreen
	askOnScreen = func(_ *call, text string) (bool, bool) {
		*texts = append(*texts, text)
		return c.window == "allow", c.window != "none"
	}
	t.Cleanup(func() { askOnScreen = saved; resetApproval() })
	if c.agent {
		setCallerEnv(t, "CLAUDECODE", "1")
	}
	resetApproval()
	return texts
}
