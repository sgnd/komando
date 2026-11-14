package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// bufCall is a new call, entered as a command that runs, with its stdout
// in o. It leaves when the test ends.
func bufCall(t *testing.T, env map[string]string, o *syncBuf) *call {
	t.Helper()
	cl := newCall(engine.Call{Program: "komando", LookupEnv: envOf(env, &sync.Map{}), Stdout: o, Stderr: &syncBuf{}}, nil)
	cl.enter()
	t.Cleanup(cl.leave)
	return cl
}

// pinnedIn is what cl's next answer would report in meta.host_keys_pinned.
func pinnedIn(t *testing.T, cl *call, o *syncBuf) []out.HostKey {
	t.Helper()
	cl.out.Format = "json"
	cl.out.Print("check", map[string]any{}, nil)
	var env struct {
		Meta struct {
			Pinned []out.HostKey `json:"host_keys_pinned"`
		} `json:"meta"`
	}
	line := strings.TrimSpace(o.String())
	if i := strings.LastIndex(line, "\n"); i >= 0 {
		line = line[i+1:]
	}
	if err := json.Unmarshal([]byte(line), &env); err != nil {
		t.Fatalf("answer %q: %v", o.String(), err)
	}
	return env.Meta.Pinned
}

// A connection whose context carries no call pins nothing and reports
// nothing: it never borrows another running call's output or audit log,
// whose flags that call's own goroutine writes as it runs (run with
// -race). The same connection made for a call pins the key for that
// call alone.
func TestHostKeyPinNeedsItsCall(t *testing.T) {
	startFakeServer(t)
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	dev := st.Hosts["dev"]
	var o syncBuf
	b := bufCall(t, map[string]string{"KOMANDO_HOME": os.Getenv("KOMANDO_HOME"), "USER": "ana", "CLAUDECODE": "1"}, &o)

	// b runs its command meanwhile: its flags change as it parses them
	stop := make(chan struct{})
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		for {
			select {
			case <-stop:
				return
			default:
				b.flags.dryRun = !b.flags.dryRun
				b.personalCmd = !b.personalCmd
			}
		}
	}()
	opts := sshx.Options{ConnectTimeout: 5 * time.Second, HostKeyPolicy: "accept-new"}
	var dials sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		dials.Add(1)
		go func() {
			defer dials.Done()
			c, err := sshx.Dial(context.Background(), st, dev, opts)
			if c != nil {
				c.Close()
			}
			errs[i] = err
			sshx.HostKeyPinned(context.Background(), sshx.NewHostKey{Host: "web9", Address: "203.0.113.9:22", Type: "ssh-ed25519", Fingerprint: "SHA256:nocall"})
		}()
	}
	dials.Wait()
	close(stop)
	running.Wait()

	for _, err := range errs {
		var oe *out.Error
		if err == nil || errors.As(err, &oe) || !strings.Contains(err.Error(), "pin a new server's host key outside a command, and refused") {
			t.Fatalf("a dial with no call in its context: %v, want the refusal to pin outside a command", err)
		}
	}
	addr := net.JoinHostPort(dev.Address, strconv.Itoa(dev.EffectivePort()))
	if pins, _ := sshx.PinnedKeys(addr); len(pins) != 0 {
		t.Fatalf("a dial with no call pinned %d keys", len(pins))
	}
	if got := pinnedIn(t, b, &o); len(got) != 0 {
		t.Errorf("another call reports keys it never pinned: %v", got)
	}
	if a := auditText(t); strings.Contains(a, "host.key-pinned") {
		t.Errorf("a pin with no call went into an audit log: %s", a)
	}

	// the same connection, made for b, pins the key for b
	c, err := sshx.Dial(withCall(context.Background(), b), st, dev, opts)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := pinnedIn(t, b, &o); len(got) != 1 || got[0].Host != "dev" {
		t.Errorf("b's own pin: %v", got)
	}
	if a := auditText(t); strings.Count(a, "host.key-pinned") != 1 || !strings.Contains(a, `"hosts":["dev"]`) {
		t.Errorf("audit after b's pin: %s", a)
	}
}

// One command that reaches two new servers at once (exec prod,dev -P 2)
// pins both keys from two dial goroutines. Each records its pin in the
// audit log; neither writes anything of the call the other reads (run
// with -race).
func TestOneCallPinsTwoKeysAtOnce(t *testing.T) {
	startFakeServer(t)
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	var o syncBuf
	b := bufCall(t, map[string]string{"KOMANDO_HOME": os.Getenv("KOMANDO_HOME"), "USER": "ana"}, &o)
	ctx := withCall(context.Background(), b)
	opts := sshx.Options{ConnectTimeout: 5 * time.Second, HostKeyPolicy: "accept-new"}
	names := []string{"prod", "dev"}
	errs := make([]error, len(names))
	start := make(chan struct{})
	var dials sync.WaitGroup
	for i, name := range names {
		dials.Add(1)
		go func() {
			defer dials.Done()
			<-start
			c, err := sshx.Dial(ctx, st, st.Hosts[name], opts)
			if c != nil {
				c.Close()
			}
			errs[i] = err
		}()
	}
	close(start)
	dials.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("dial %s: %v", names[i], err)
		}
	}
	got := pinnedIn(t, b, &o)
	hosts := []string{}
	for _, k := range got {
		hosts = append(hosts, k.Host)
	}
	slices.Sort(hosts)
	if !slices.Equal(hosts, []string{"dev", "prod"}) {
		t.Errorf("the call reports pins %v, want dev and prod", hosts)
	}
	a := auditText(t)
	if strings.Count(a, "host.key-pinned") != 2 || !strings.Contains(a, `"hosts":["dev"]`) || !strings.Contains(a, `"hosts":["prod"]`) {
		t.Errorf("audit after two pins at once: %s", a)
	}
}

// A secret another call read (vault.OnResolve) after this call entered,
// but before its command reached newRoot, stays hidden in this call's
// output: starting the command tree forgets nothing a running call hides.
func TestResolvedValueStaysHiddenFromEnter(t *testing.T) {
	const v = "resolved-by-another-call-4821"
	for range 20 {
		var o syncBuf
		b := newCall(engine.Call{Program: "komando", LookupEnv: envOf(map[string]string{"USER": "ana"}, &sync.Map{}), Stdout: &o, Stderr: &syncBuf{}}, nil)
		b.enter()
		// call A reads the secret on its own goroutine while b starts
		// its command
		var a sync.WaitGroup
		a.Add(1)
		go func() { defer a.Done(); vault.OnResolve(v) }()
		a.Wait()
		newRoot(b)
		if got := b.out.Redact("token " + v); strings.Contains(got, v) {
			b.leave()
			t.Fatalf("b shows a secret another call read: %q", got)
		}
		b.leave()
	}
	// the next command of a call starts without what the one before hid
	b := testCall()
	b.enter()
	vault.OnResolve(v)
	b.leave()
	b.enter()
	defer b.leave()
	if got := b.out.Redact(v); got != v {
		t.Errorf("a value of the command before is still hidden: %q", got)
	}
}

// Each command owns the paths through jump hosts it opens
// (sshx.ChainOwner): two calls running at once never share one, the
// servers of one command do, and a path opened with no command in its
// context is shared with nobody.
func TestChainOwnerIsTheCommand(t *testing.T) {
	person := bufCall(t, map[string]string{"USER": "ana"}, &syncBuf{})
	agent := bufCall(t, map[string]string{"USER": "ana", "CLAUDECODE": "1"}, &syncBuf{})
	pctx, actx := withCall(context.Background(), person), withCall(context.Background(), agent)
	owners := make([]string, 8)
	var wg sync.WaitGroup
	for i := range owners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch i % 3 {
			case 0:
				owners[i] = sshx.ChainOwner(pctx)
			case 1:
				owners[i] = sshx.ChainOwner(actx)
			default:
				owners[i] = sshx.ChainOwner(context.Background())
			}
		}()
	}
	wg.Wait()
	if owners[0] != owners[3] || owners[1] != owners[4] {
		t.Errorf("one command got two owners: %q", owners)
	}
	if owners[0] == owners[1] {
		t.Errorf("a person's and an agent's command share an owner: %q", owners[0])
	}
	if owners[2] == owners[5] || owners[2] == owners[0] || owners[2] == owners[1] {
		t.Errorf("a path with no command is shared: %q", owners)
	}
	// the call's next command owns new paths
	before := sshx.ChainOwner(pctx)
	person.leave()
	person.enter()
	if sshx.ChainOwner(pctx) == before {
		t.Error("the next command of a call got the paths of the one before")
	}
}
