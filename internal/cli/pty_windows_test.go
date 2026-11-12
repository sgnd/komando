package cli

import "testing"

// The pseudo-terminal tests need a Unix pty; on Windows they are skipped.
type ptyRun struct{}

// ptyAvailable is false: Windows has no Unix pseudo-terminal to test with.
var ptyAvailable = false

func startPTY(t *testing.T, _ ...string) *ptyRun {
	if !ptyAvailable {
		t.Skip("pseudo-terminal tests run on Unix only")
	}
	return &ptyRun{}
}

func (p *ptyRun) shown() string      { return "" }
func (p *ptyRun) waitFor(string)     {}
func (p *ptyRun) answer(_, _ string) {}
func (p *ptyRun) exit() int          { return 0 }

func startPTYEnv(t *testing.T, _ []string, _ ...string) *ptyRun { return startPTY(t) }
