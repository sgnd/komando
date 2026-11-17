package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// An AI agent's call counts among the running calls before anything in
// its setup can open the store or the vault. An agent's --reveal opens
// the store (is the approval code on?) before the command runs; had the
// call not counted yet, vault.AgentCall would answer "no agent", the
// agent's KOMANDO_KEYCHAIN=off would skip the old-copy check, and the
// store, opened once per process, would stay open unchecked for the whole
// command. TestMain counts tcl in and leaves vault.AgentCall nil, which
// hid this: here only the agent's own call is running, with the real hook.
func TestAgentCallCountsBeforeTheStoreOpens(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	if err := store.Update(store.Save(), func(*store.State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	store.Close() // the next open checks the store again

	tcl.leave()
	t.Cleanup(tcl.enter)
	vault.AgentCall = agentCallRunning
	t.Cleanup(func() { vault.AgentCall = nil })
	// a stand-in for the keychain's change count (no real keychain): it
	// remembers a newer change than the store has, so the store is an old
	// copy. As the vault's own (genGet), a KOMANDO_KEYCHAIN=off reads it
	// only for an agent.
	var mu sync.Mutex
	var counted []bool
	saved := store.GenerationKeeper
	t.Cleanup(func() { store.GenerationKeeper = saved; store.Close() })
	store.GenerationKeeper = store.GenerationKeep{
		Get: func() (uint64, bool, error) {
			agent := vault.AgentCall()
			mu.Lock()
			counted = append(counted, agent)
			mu.Unlock()
			if !agent {
				return 0, false, errors.New("komando uses no keychain on this computer (KOMANDO_KEYCHAIN is off)")
			}
			return 1 << 40, true, nil
		},
		Set: func(uint64) error { return nil },
		Del: func() {},
	}

	var inWindow []bool
	ask := func(string) (bool, bool) {
		inWindow = append(inWindow, vault.AgentCall())
		return false, true // the person denies it
	}
	env := map[string]string{"KOMANDO_HOME": home, "CLAUDECODE": "1", "KOMANDO_KEYCHAIN": "off"}
	var o, e bytes.Buffer
	c := engine.Call{Program: "komando", LookupEnv: envOf(env, &sync.Map{}), Stdout: &o, Stderr: &e, Ask: ask}
	code := RunCall(context.Background(), c, []string{"list", "--reveal"})

	if len(inWindow) != 1 || !inWindow[0] {
		t.Errorf("in the approval window, vault.AgentCall answered %v; want the agent's call counted", inWindow)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(counted) == 0 {
		t.Fatal("the store's change count was never read")
	}
	for i, agent := range counted {
		if !agent {
			t.Errorf("read %d of the change count was made as for no agent", i+1)
		}
	}
	if code != 6 || !strings.Contains(o.String(), `"code":"STORE_OLD_COPY"`) {
		t.Errorf("an agent's call on an old copy: exit %d, stdout %s, stderr %s", code, o.String(), e.String())
	}
}
