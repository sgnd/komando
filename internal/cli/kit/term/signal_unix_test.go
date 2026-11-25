//go:build unix

package term

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// signalWait is how long a test waits for a signal to arrive: far longer
// than it takes, so a busy machine does not fail the test.
const signalWait = 2 * time.Minute

// A caller that passes no onSecond still gets a process that a second
// Ctrl-C ends (exit 130, or killed by the signal itself): a nil handler
// must never swallow it.
func TestSignalContextNilSecondEndsProcess(t *testing.T) {
	if os.Getenv("KOMANDO_TEST_TERM_SIGNAL_CHILD") == "1" {
		ctx, cancel := SignalContext(context.Background(), nil)
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
	cmd := exec.Command(os.Args[0], "-test.run=^TestSignalContextNilSecondEndsProcess$")
	cmd.Env = append(os.Environ(), "KOMANDO_TEST_TERM_SIGNAL_CHILD=1")
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("the child survived the second Ctrl-C: %v", err)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("no wait status: %v", err)
	}
	if !(ws.Signaled() && ws.Signal() == syscall.SIGINT) && ws.ExitStatus() != 130 {
		t.Fatalf("want the child ended by SIGINT or exit 130, got %v", err)
	}
}

// The first signal cancels the context; the second goes to onSecond with
// the signal that arrived.
func TestSignalContextCallsOnSecond(t *testing.T) {
	got := make(chan os.Signal, 1)
	ctx, cancel := SignalContext(context.Background(), func(s os.Signal) { got <- s })
	defer cancel()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(signalWait):
		t.Fatal("SIGTERM did not cancel the context")
	}
	select {
	case s := <-got:
		t.Fatalf("onSecond ran on the first signal (%v)", s)
	default:
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s != syscall.SIGTERM {
			t.Errorf("onSecond got %v, want SIGTERM", s)
		}
	case <-time.After(signalWait):
		t.Fatal("the second signal did not reach onSecond")
	}
}

// The returned cancel ends the context and may run more than once.
func TestSignalContextCancelTwice(t *testing.T) {
	ctx, cancel := SignalContext(context.Background(), nil)
	cancel()
	cancel()
	if ctx.Err() == nil {
		t.Fatal("cancel did not end the context")
	}
}

// A process started with SIGHUP ignored (nohup, a login holder) keeps it
// ignored: closing the terminal does not stop it. Run in a child that
// starts with SIGHUP ignored, whatever this process was started with.
func TestIgnoredSIGHUPStaysIgnored(t *testing.T) {
	if os.Getenv("KOMANDO_SIGHUP_CHILD") == "1" {
		// SignalContext must not take over an ignored SIGHUP: listening
		// for it would end the ignoring, which signal.Ignored shows at
		// once, with no waiting for a signal
		_, cancel := SignalContext(context.Background(), nil)
		defer cancel()
		if signal.Ignored(syscall.SIGHUP) {
			os.Stdout.WriteString("kept running\n")
		} else {
			os.Stdout.WriteString("listens for SIGHUP\n")
		}
		return
	}
	// nohup is the usual way a SIGHUP is ignored from the start
	nohup, err := exec.LookPath("nohup")
	if err != nil {
		t.Skip("no nohup here")
	}
	cmd := exec.Command(nohup, os.Args[0], "-test.run=^TestIgnoredSIGHUPStaysIgnored$", "-test.timeout=10m")
	cmd.Env = append(os.Environ(), "KOMANDO_SIGHUP_CHILD=1")
	cmd.Dir = t.TempDir() // nohup writes nohup.out here when it cannot use the terminal
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "kept running") {
		t.Errorf("a SIGHUP ignored from the start would stop the command (%v):\n%s", err, out)
	}
}
