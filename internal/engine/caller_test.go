package engine

import "testing"

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestCallerFrom(t *testing.T) {
	for _, c := range []struct {
		name     string
		env      map[string]string
		terminal bool
		kind     Kind
		agent    string
		actor    string
	}{
		{"a person", map[string]string{"USER": "ana"}, true, Person, "", "ana"},
		{"a script", map[string]string{"USER": "ci"}, false, Script, "", "ci"},
		{"over ssh from another loopback address", map[string]string{"SSH_CONNECTION": "127.0.0.2 5 127.0.0.1 22", "USER": "ana"}, true, Script, "", "ana"},
		{"over ssh from a malformed address", map[string]string{"SSH_CONNECTION": "bogus 5 127.0.0.1 22", "USER": "ana"}, true, Person, "", "ana"},
		{"over ssh from this computer, a terminal does not make a person", map[string]string{"SSH_CONNECTION": "127.0.0.1 5 127.0.0.1 22", "USER": "ana"}, true, Script, "", "ana"},
		{"over ssh from ::1", map[string]string{"SSH_CONNECTION": "::1 5 ::1 22"}, true, Script, "", ""},
		{"over ssh from another computer is a person", map[string]string{"SSH_CONNECTION": "10.0.0.7 5 10.0.0.2 22"}, true, Person, "", ""},
		{"claude", map[string]string{"CLAUDECODE": "1"}, true, Agent, "Claude Code", ""},
		{"an empty value still counts", map[string]string{"CLAUDECODE": "0"}, true, Agent, "Claude Code", ""},
		{"ssh-gate names the key", map[string]string{GateEnv: "ops-ro", "CLAUDECODE": "1"}, false, Agent, "ssh-gate key ops-ro", ""},
		{"a bad gate label is just an agent", map[string]string{GateEnv: "-x y"}, false, Agent, "An SSH key through ssh-gate", ""},
		{"KOMANDO_ACTOR wins", map[string]string{"KOMANDO_ACTOR": "deploy-bot", "USER": "root"}, false, Script, "", "deploy-bot"},
		{"Windows sets USERNAME only", map[string]string{"USERNAME": "budi"}, true, Person, "", "budi"},
		{"USER before USERNAME", map[string]string{"USER": "ana", "USERNAME": "budi"}, true, Person, "", "ana"},
	} {
		got := CallerFrom(env(c.env), c.terminal)
		if got.Kind != c.kind || got.Agent != c.agent || got.Actor != c.actor {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}

// Two sessions are apart: one call's yes is not another's.
func TestSessionsApart(t *testing.T) {
	a, b := NewSession(), NewSession()
	a.Lock()
	a.SetAsked(true)
	a.MarkShown("ssh-keygen")
	a.Unlock()
	a.ApproveSafety("audit off")
	a.ConfirmDanger("rm web1")
	a.SaidNo(true)
	if b.Allowed() || b.SafetyApproved("audit off") || b.DangerConfirmed("rm web1") || b.PersonSaidNo() || b.Shown("ssh-keygen") {
		t.Fatal("one session's answers reached another")
	}
	if !a.Allowed() || !a.SafetyApproved("audit off") || !a.DangerConfirmed("rm web1") || !a.PersonSaidNo() || !a.Shown("ssh-keygen") {
		t.Fatal("a session forgot its answers")
	}
	a.SaidNo(false)
	if !a.PersonSaidNo() {
		t.Fatal("a later yes undid a no")
	}
}
