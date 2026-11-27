package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// Protecting a file server's sftp:// conn protects the SSH server at that
// address and port, whatever name it is used by: a host entry, or
// user@address written out.
func TestProtectedSftpConnProtectsItsServer(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "files", "sftp://u@10.0.0.7/srv", "--protected")
	mustRun(t, "conn", "add", "open", "sftp://u@10.0.0.8:2222/srv")
	mustRun(t, "host", "ssh", "add", "fs", "deploy@10.0.0.7")
	mustRun(t, "host", "ssh", "add", "fs-other-port", "deploy@10.0.0.7", "--port", "2200")
	mustRun(t, "host", "ssh", "add", "other", "deploy@10.0.0.8", "--port", "2222")
	st := mustState(t)
	for name, want := range map[string]bool{"fs": true, "fs-other-port": false, "other": false} {
		if got := protectedHost(st, st.Hosts[name]); got != want {
			t.Errorf("protectedHost(%s) = %v, want %v", name, got, want)
		}
	}
	if !protectedHost(st, &store.Host{Name: "root@10.0.0.7", Address: "10.0.0.7", User: "root"}) {
		t.Error("user@address of the protected sftp conn's server is protected")
	}
	texts := windowText(t, true)
	wantCode(t, "PROTECTED_TARGET", "exec", "fs", "--", "touch", "/tmp/x")
	wantCode(t, "PROTECTED_TARGET", "fs", "mkdir", "fs", "/srv/data")
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
}
