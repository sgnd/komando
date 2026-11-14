package cli

import (
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/engine"
)

// A program a call starts gets the call's environment and nothing else,
// without the secret stores' unlock values. A call with no environment
// (an app's call made without Environ) gets an empty one, never nil: an
// exec.Cmd whose Env is nil inherits the process's whole environment.
func TestCallEnvironForChildren(t *testing.T) {
	t.Setenv("KOMANDO_TEST_PROCESS_ONLY", "process-value")
	t.Setenv("KOMANDO_VAULT_PASS", "process-pass")

	none := newCall(engine.Call{Program: "komando"}, nil).environ()
	if none == nil || len(none) != 0 {
		t.Fatalf("a call with no environment: %#v, want an empty one that is not nil", none)
	}
	own := newCall(engine.Call{Program: "komando", Environ: func() []string {
		return []string{"PATH=/usr/bin:/bin", "KOMANDO_VAULT_PASS=call-pass", "VAULT_TOKEN=t", "HOME=/h"}
	}}, nil).environ()
	if want := []string{"PATH=/usr/bin:/bin", "HOME=/h"}; !slices.Equal(own, want) {
		t.Fatalf("a call's own environment: %v, want %v", own, want)
	}

	if runtime.GOOS == "windows" {
		return
	}
	env, err := exec.LookPath("env")
	if err != nil {
		t.Skip("no env program here")
	}
	c := exec.Command(env)
	c.Env = none
	b, err := c.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != "" {
		t.Errorf("a child of a call with no environment saw %q", got)
	}
}
