package cli

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// syncBuf is a buffer safe for writes from several goroutines: a call
// with Terminal true may get notices from another goroutine
// (netx.LockBusy).
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// The hooks of the lower packages (call_hooks.go) read every running call
// from any goroutine: a connection or a vault read of one call asks about
// all of them. A call is running from the first step of its command, so
// nothing they read may be written later without a lock. One goroutine
// keeps calling the hooks while a person's calls and agents' calls run
// their commands, some of which open the store; run with -race, which
// reports any such write. The test fails if the hooks never ran while a
// person's call and an agent's call were running.
func TestHooksReadRunningCallsSafely(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	agentEnv := map[string]string{"KOMANDO_HOME": home, "USER": "ana", "CLAUDECODE": "1"}
	personEnv := map[string]string{"KOMANDO_HOME": home, "USER": "ana", "KOMANDO_OUTPUT": "json"}
	noWindow := func(string) (bool, bool) { t.Error("a call opened a window"); return false, true }

	done := make(chan struct{})
	var hooks sync.WaitGroup
	hooks.Add(1)
	var sawAgent, sawPerson atomic.Bool
	go func() {
		defer hooks.Done()
		client := &sshx.Client{Host: &store.Host{Name: "web1"}}
		for {
			select {
			case <-done:
				return
			default:
			}
			// vault.AgentCall's answer (TestMain leaves the hook itself
			// nil, so no agent's test reads the real keychain); tcl runs
			// for the whole test binary and is neither
			if agentCallRunning() {
				sawAgent.Store(true)
			}
			for _, cl := range runningCalls() {
				if cl != tcl && cl.caller().Kind == engine.Person {
					sawPerson.Store(true)
				}
			}
			_ = sshx.HostSecretEnv(client)
			_ = vault.RefGuard("env", "HOME")
			_ = sshx.PersonAtTerminal()
			vault.OnResolve("hook-race-value-never-printed")
		}
	}()

	type res struct {
		who, cmd, out, err string
		code               int
	}
	var (
		mu      sync.Mutex
		results []res
	)
	run := func(who string, env map[string]string, terminal bool, args ...string) {
		var o, e syncBuf
		c := engine.Call{Program: "komando", LookupEnv: envOf(env, &sync.Map{}), Stdout: &o, Stderr: &e, Terminal: terminal, Ask: noWindow}
		code := RunCall(context.Background(), c, args)
		mu.Lock()
		results = append(results, res{who, strings.Join(args, " "), o.String(), e.String(), code})
		mu.Unlock()
	}
	commands := [][]string{{"version"}, {"list"}, {"secret", "list"}}

	// rounds go on until the hooks ran beside both kinds of call, at least
	// minRounds of them
	const minRounds = 4
	deadline := time.Now().Add(30 * time.Second)
	for round := 0; round < minRounds || !(sawAgent.Load() && sawPerson.Load()); round++ {
		if time.Now().After(deadline) {
			break
		}
		var calls sync.WaitGroup
		for _, args := range commands {
			calls.Add(2)
			go func() { defer calls.Done(); run("agent", agentEnv, false, args...) }()
			go func() { defer calls.Done(); run("person", personEnv, true, args...) }()
		}
		calls.Wait()
	}
	close(done)
	hooks.Wait()

	for _, r := range results {
		if r.code != 0 || !strings.HasPrefix(r.out, `{"ok":true,"command":"`) {
			t.Errorf("%s's %s: exit %d, stdout %q, stderr %q", r.who, r.cmd, r.code, r.out, r.err)
		}
	}
	if !sawAgent.Load() {
		t.Error("the hooks never ran while an agent's call was running")
	}
	if !sawPerson.Load() {
		t.Error("the hooks never ran while a person's call was running")
	}
}
