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
