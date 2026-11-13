package cli

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/engine"
)

// envOf is an environment lookup over m that notes every name read.
func envOf(m map[string]string, read *sync.Map) func(string) (string, bool) {
	return func(k string) (string, bool) {
		read.Store(k, true)
		v, ok := m[k]
		return v, ok
	}
}

// A person's call and an AI agent's call run at the same time in one
// process, as the Mac app will run them: each prints only its own output
// (the person's as text, the agent's as JSON), each reads only its own
// environment, never the process's (run with -race).
func TestPersonAndAgentCallsAtOnce(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("KOMANDO_OUTPUT", "json") // the process's; neither call reads it

	var personRead, agentRead sync.Map
	personEnv := map[string]string{"KOMANDO_HOME": home, "USER": "ana", "KOMANDO_OUTPUT": "text"}
	agentEnv := map[string]string{"KOMANDO_HOME": home, "USER": "ana", "CLAUDECODE": "1"}
	noWindow := func(string) (bool, bool) { t.Error("a call opened a window"); return false, true }

	const rounds = 8
	type res struct {
		code     int
		out, err string
	}
	var people, agents [rounds]res
	var wg sync.WaitGroup
	for i := range rounds {
		wg.Add(2)
		go func() {
			defer wg.Done()
			var o, e bytes.Buffer
			c := engine.Call{Program: "komando", LookupEnv: envOf(personEnv, &personRead), Stdout: &o, Stderr: &e, Terminal: true, Ask: noWindow}
			people[i] = res{RunCall(context.Background(), c, []string{"version"}), o.String(), e.String()}
		}()
		go func() {
			defer wg.Done()
			var o, e bytes.Buffer
			c := engine.Call{Program: "komando", LookupEnv: envOf(agentEnv, &agentRead), Stdout: &o, Stderr: &e, Ask: noWindow}
			agents[i] = res{RunCall(context.Background(), c, []string{"version"}), o.String(), e.String()}
		}()
	}
	wg.Wait()

	for i := range rounds {
		p, a := people[i], agents[i]
		if p.code != 0 || !strings.Contains(p.out, "version: ") || strings.Contains(p.out, "{") || p.err != "" {
			t.Errorf("person %d: exit %d, stdout %q, stderr %q", i, p.code, p.out, p.err)
		}
		if a.code != 0 || !strings.HasPrefix(a.out, `{"ok":true,"command":"version"`) || strings.Count(a.out, "\n") != 1 || a.err != "" {
			t.Errorf("agent %d: exit %d, stdout %q, stderr %q", i, a.code, a.out, a.err)
		}
	}
	for name, read := range map[string]*sync.Map{"person": &personRead, "agent": &agentRead} {
		for _, k := range []string{"KOMANDO_OUTPUT", "CLAUDECODE"} {
			if _, ok := read.Load(k); !ok {
				t.Errorf("the %s's call never read %s from its own environment", name, k)
			}
		}
	}
}

// A person's call and an AI agent's call at the same time keep their
// approvals apart: the person's yes to a safety change and to a
// dangerous action is not the agent's, and the agent's window (which
// the person denies) never asks for the person's call (run with -race).
func TestPersonAndAgentApprovalsApart(t *testing.T) {
	setHome(t, t.TempDir())
	personYes := make(chan struct{})
	var windows atomic.Int32
	person := newCall(engine.Call{Program: "komando", Terminal: true,
		LookupEnv: envOf(map[string]string{"USER": "ana"}, &sync.Map{}),
		Ask:       func(string) (bool, bool) { t.Error("the person's call opened a window"); return true, true },
	}, []string{"config", "set", "audit", "off"})
	agent := newCall(engine.Call{Program: "komando",
		LookupEnv: envOf(map[string]string{"USER": "ana", "CLAUDECODE": "1"}, &sync.Map{}),
		Ask: func(string) (bool, bool) {
			windows.Add(1)
			select { // the person's yes is given while this window is open
			case <-personYes:
			case <-time.After(10 * time.Second):
				t.Error("the person's call never answered")
			}
			return false, true // the person denies the agent
		},
	}, []string{"config", "set", "audit", "off"})

	run := func(cl *call, body func(own *call)) {
		cmd := &cobra.Command{Use: "set", SilenceErrors: true, SilenceUsage: true,
			RunE: func(cmd *cobra.Command, _ []string) error { body(callOf(cmd)); return nil }}
		cmd.SetArgs([]string{})
		if err := cmd.ExecuteContext(withCall(context.Background(), cl)); err != nil {
			t.Error(err)
		}
	}
	var agentYes, agentSafety, agentDanger, personOK bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		run(person, func(own *call) {
			own.sess.ApproveSafety("audit off")
			own.sess.ConfirmDanger("host rm web1")
			own.flags.yes = true
			personOK = own.yesOK("audit off") // a person's own flag: no window
			close(personYes)
		})
	}()
	go func() {
		defer wg.Done()
		run(agent, func(own *call) {
			own.flags.yes = true
			agentYes = own.yesOK("audit off")
			agentSafety = own.sess.SafetyApproved("audit off")
			agentDanger = own.sess.DangerConfirmed("host rm web1")
		})
	}()
	wg.Wait()

	if person.isAgent() || person.caller.Kind != engine.Person {
		t.Fatalf("the person's call is a %v", person.caller.Kind)
	}
	if !agent.isAgent() {
		t.Fatal("the agent's call is no agent's")
	}
	if !personOK || !person.sess.SafetyApproved("audit off") || !person.sess.DangerConfirmed("host rm web1") {
		t.Errorf("the person's call lost its own answers: yes %v", personOK)
	}
	if agentYes || agentSafety || agentDanger || agent.sess.Allowed() || agent.sess.Window().Why != "denied" {
		t.Errorf("the person's yes reached the agent's call: yes %v, safety %v, danger %v, why %q", agentYes, agentSafety, agentDanger, agent.sess.Window().Why)
	}
	if n := windows.Load(); n != 1 {
		t.Errorf("%d windows, want 1 (the agent's)", n)
	}
	if person.sess.Window().Asked {
		t.Error("the agent's window counted for the person's call")
	}
}
