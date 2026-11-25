//go:build unix

package cli

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// hardStop ends komando by the signal itself, not by its exit 130
// fallback: a shell loop that runs komando must see the process die of
// the Ctrl-C (or SIGTERM) to stop too.
func TestHardStopDiesOfTheSignal(t *testing.T) {
	if os.Getenv("KOMANDO_TEST_HARDSTOP_CHILD") == "1" {
		hardStop(syscall.SIGTERM)
		os.Exit(0) // hardStop returned: it must never
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHardStopDiesOfTheSignal$")
	cmd.Env = append(os.Environ(), "KOMANDO_TEST_HARDSTOP_CHILD=1")
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("the child outlived hardStop: %v", err)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("no wait status: %v", err)
	}
	if !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
		t.Fatalf("want the child killed by SIGTERM, got %v", err)
	}
}
