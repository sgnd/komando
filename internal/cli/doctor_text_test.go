package cli

import (
	"strings"
	"testing"
)

// doctor's text names each check in plain words, not its JSON name, and
// wraps a long detail at 80 columns under the check at a terminal (M-7,
// M-9); in a pipe each check is one line.
func TestDoctorTextLabels(t *testing.T) {
	r := doctorReport{width: 80, Checks: []doctorCheck{
		{Name: "state", OK: true, Detail: "/home/u/.komando"},
		{Name: "vpn:office:openconnect", OK: false, Detail: "not installed"},
		{Name: "agent_guard", OK: false, Detail: strings.Repeat("Claude Code runs without komando's guard, ", 3) + "`komando guide install` adds it"},
	}}
	got := r.Text()
	for _, want := range []string{"✓ komando folder: /home/u/.komando\n", "✗ VPN office needs openconnect: not installed\n", "✗ Claude Code guard: "} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, l := range strings.Split(got, "\n") {
		if n := len([]rune(l)); n > 80 {
			t.Errorf("line of %d columns: %q", n, l)
		}
	}
	if !strings.Contains(got, "`komando guide install`") {
		t.Errorf("the command was broken up:\n%s", got)
	}
	r.width = 0 // komando doctor -o text | grep ...
	if got := r.Text(); !strings.Contains(got, "✗ Claude Code guard: "+r.Checks[2].Detail+"\n") {
		t.Errorf("a pipe gets a check split over lines:\n%s", got)
	}
}
