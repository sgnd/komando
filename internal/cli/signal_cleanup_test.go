//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/tmpclean"
)

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
	hardStop = func() { tmpclean.RemoveAll(); close(stopped) }
	t.Cleanup(func() { hardStop = saved })

	ctx, cancel := signalContext()
	defer cancel()
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP did not stop the command")
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Fatal("the first signal removed files the clean stop still uses")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("a second signal did not end komando")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("the temporary file stayed: %v", err)
	}
}
