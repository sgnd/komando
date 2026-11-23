package capability

import (
	"slices"
	"testing"
)

// TestSessionOptions pins the exec session: an agent comes
// back to a long exec with --attach ID, and stops or removes it there.
func TestSessionOptions(t *testing.T) {
	exec, ok := Find(Key{Type: "host", Provider: "ssh", Verb: "exec"})
	if !ok {
		t.Fatal("no host ssh exec")
	}
	want := map[string][]string{"attach": nil, "stop": {"attach"}, "signal": {"stop"}, "remove": {"attach"}}
	for name, needs := range want {
		o, ok := exec.Option(name)
		if !ok {
			t.Errorf("host ssh exec: no --%s", name)
			continue
		}
		if !slices.Equal(o.Needs, needs) {
			t.Errorf("host ssh exec --%s: needs %v, want %v", name, o.Needs, needs)
		}
	}
	if o, _ := exec.Option("remove"); !slices.Contains(o.Conflicts, "stop") {
		t.Error("host ssh exec --remove: must conflict with --stop")
	}
	shell, ok := Find(Key{Type: "host", Provider: "ssh", Verb: "shell"})
	if !ok {
		t.Fatal("no host ssh shell")
	}
	for _, l := range []Leaf{exec, shell} {
		if o, ok := l.Option("attach"); !ok || o.Pattern != sessionID {
			t.Errorf("%s --attach: pattern %q, want %q", l.Key, o.Pattern, sessionID)
		}
	}
}

// TestSessionEnd: a person ends a kept two-factor or cloud session early
// with test --end, on one host or on all of them (no logout command).
func TestSessionEnd(t *testing.T) {
	for _, k := range []Key{{Type: "host", Provider: "ssh", Verb: "test"}, {Verb: "test"}} {
		l, ok := Find(k)
		if !ok {
			t.Fatalf("no %s", k)
		}
		if o, ok := l.Option("end"); !ok || o.Kind != Bool {
			t.Errorf("%s: no --end that ends the kept session", k)
		}
	}
	for _, id := range []string{"logout", "logout.aws"} {
		if len(carriers()[id]) == 0 {
			t.Errorf("%s: no leaf carries it; test --end does now", id)
		}
	}
}

// TestSudoCredential: today's --sudo-ref becomes --sudo-credential on the
// ssh host entry (sudo is ssh only), so a sudo password is not lost at the
// cut; as a credential option it goes through RefGuard and reservedSecret.
func TestSudoCredential(t *testing.T) {
	for _, verb := range []string{"add", "edit"} {
		k := Key{Type: "host", Provider: "ssh", Verb: verb}
		l, _ := Find(k)
		if o, ok := l.Option("sudo-credential"); !ok || o.Kind != Credential {
			t.Errorf("%s: no --sudo-credential naming a credential", k)
		}
	}
	winrm, _ := Find(Key{Type: "host", Provider: "winrm", Verb: "add"})
	if _, ok := winrm.Option("sudo-credential"); ok {
		t.Error("host winrm add: WinRM has no sudo")
	}
}
