//go:build !windows

package cli

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/tmpclean"
)

// signalWait is how long the test waits for a signal to arrive: far longer
// than it takes, so a busy machine does not fail the test.
const signalWait = 2 * time.Minute

// O14: a second Ctrl-C (or a SIGHUP: the terminal closed) ended komando
// without its deferred cleanup, leaving temporary files (a download before
// its rename, a sign-in browser profile, an AWS token file) behind. The
// first signal stops the command cleanly; the second removes what this
// run made before komando exits.
func TestSecondSignalRemovesTempFiles(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), ".komando-download-1")
	if err := os.WriteFile(tmp, []byte("server bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer tmpclean.Add(tmp)()
	stopped := make(chan struct{})
	saved := hardStop
	hardStop = func(os.Signal) { tmpclean.RemoveAll(); close(stopped) }
	t.Cleanup(func() { hardStop = saved })

	// started under nohup (or by a holder), this process ignores SIGHUP,
	// and komando rightly keeps it ignored: then a SIGTERM is the first
	// signal (TestIgnoredSIGHUPStaysIgnored covers that case)
	first := syscall.SIGHUP
	if signal.Ignored(syscall.SIGHUP) {
		first = syscall.SIGTERM
	}
	ctx, cancel := signalContext(context.Background())
	defer cancel()
	if err := syscall.Kill(os.Getpid(), first); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(signalWait):
		t.Fatalf("%v did not stop the command", first)
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Fatal("the first signal removed files the clean stop still uses")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(signalWait):
		t.Fatal("a second signal did not end komando")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("the temporary file stayed: %v", err)
	}
}

// A komando started with SIGHUP ignored (nohup, a login holder) keeps it
// ignored: closing the terminal does not stop it. Run in a child that
// starts with SIGHUP ignored, whatever this process was started with.
func TestIgnoredSIGHUPStaysIgnored(t *testing.T) {
	if os.Getenv("KOMANDO_SIGHUP_CHILD") == "1" {
		// signalContext must not take over an ignored SIGHUP: listening
		// for it would end the ignoring, which signal.Ignored shows at
		// once, with no waiting for a signal
		_, cancel := signalContext(context.Background())
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
