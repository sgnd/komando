//go:build unix

package cli

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// A second Ctrl-C ends komando at once: the first one only cancels the
// command, and a clean stop that hangs must not swallow every later one.
func TestSecondInterruptEndsKomando(t *testing.T) {
	if os.Getenv("KOMANDO_TEST_SIGNAL_CHILD") == "1" {
		ctx, cancel := signalContext()
		defer cancel()
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
			os.Exit(3) // the first Ctrl-C did not cancel
		}
		time.Sleep(200 * time.Millisecond) // let the handler go
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		time.Sleep(10 * time.Second)
		os.Exit(0) // still alive: the second Ctrl-C was swallowed
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSecondInterruptEndsKomando$")
	cmd.Env = append(os.Environ(), "KOMANDO_TEST_SIGNAL_CHILD=1")
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("the child survived the second Ctrl-C: %v", err)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGINT {
		t.Fatalf("want the child ended by SIGINT, got %v", err)
	}
}
