package cli

import (
	"errors"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// Until the cut, exec runs as before: the session flags exist (hints and
// docs name them) but are hidden and refused.
func TestExecSessionFlagsOffUntilTheCut(t *testing.T) {
	if sessionsOn {
		t.Skip("sessions are on")
	}
	c, _, err := newRoot(tcl).Find([]string{"exec"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"attach", "offset", "wait", "log-max"} {
		f := c.Flags().Lookup(name)
		if f == nil || !f.Hidden {
			t.Errorf("--%s: missing or shown", name)
		}
	}
	for _, args := range [][]string{
		{"exec", "web1", "--attach", "x"},
		{"exec", "web1", "--wait", "5s", "--", "uptime"},
		{"exec", "web1", "--log-max", "1MiB", "--", "uptime"},
		{"exec", "web1", "--offset", "3", "--", "uptime"},
	} {
		var oe *out.Error
		if err := runRoot(t, args...); !errors.As(err, &oe) || oe.Code != "USAGE" {
			t.Errorf("%v: got %v, want a usage error", args, err)
		}
	}
}
