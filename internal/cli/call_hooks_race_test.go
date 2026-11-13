package cli

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// The hooks of the lower packages (call_hooks.go) read every running call
// from any goroutine: a connection or a vault read of one call asks about
// all of them. A call is running from the first step of its command, so
// nothing they read may be written later without a lock. One goroutine
// keeps calling the hooks while agents' calls run their commands; run
// with -race, which reports any such write.
func TestHooksReadRunningCallsSafely(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	agentEnv := map[string]string{"KOMANDO_HOME": home, "USER": "ana", "CLAUDECODE": "1"}
	noWindow := func(string) (bool, bool) { t.Error("a call opened a window"); return false, true }

	done := make(chan struct{})
	var hooks sync.WaitGroup
	hooks.Add(1)
	sawAgent := false
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
			// nil, so no agent's test reads the real keychain)
			if agentCallRunning() {
				sawAgent = true
			}
			_ = sshx.HostSecretEnv(client)
			_ = vault.RefGuard("env", "HOME")
			_ = sshx.PersonAtTerminal()
			vault.OnResolve("hook-race-value-never-printed")
		}
	}()

	const rounds = 8
	var calls sync.WaitGroup
	codes := make([]int, rounds)
	outs := make([]string, rounds)
	for i := range rounds {
		calls.Add(1)
		go func() {
			defer calls.Done()
			var o, e bytes.Buffer
			c := engine.Call{Program: "komando", LookupEnv: envOf(agentEnv, &sync.Map{}), Stdout: &o, Stderr: &e, Ask: noWindow}
			codes[i] = RunCall(context.Background(), c, []string{"version"})
			outs[i] = o.String()
		}()
	}
	calls.Wait()
	close(done)
	hooks.Wait()

	for i := range rounds {
		if codes[i] != 0 || !strings.HasPrefix(outs[i], `{"ok":true,"command":"version"`) {
			t.Errorf("call %d: exit %d, stdout %q", i, codes[i], outs[i])
		}
	}
	if !sawAgent {
		t.Log("the hooks never saw an agent's call running (the calls ended first)")
	}
}
