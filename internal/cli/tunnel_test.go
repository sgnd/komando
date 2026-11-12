package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
)

func TestGuardBind(t *testing.T) {
	g.yes = false
	for spec, open := range map[string]bool{
		"8080:db:5432":           false,
		"127.0.0.1:8080:db:5432": false,
		"localhost:8080:db:5432": false,
		"0.0.0.0:8080:db:5432":   true,
		"10.0.0.5:8080:db:5432":  true,
	} {
		ts, err := parseTunnel("local", spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if err := guardBind(ts); (err != nil) != open {
			t.Errorf("%s: guardBind = %v, want blocked=%v", spec, err, open)
		}
	}
	g.yes = true
	defer func() { g.yes = false }()
	ts, _ := parseTunnel("dynamic", "0.0.0.0:1080")
	if err := guardBind(ts); err != nil {
		t.Errorf("--yes must allow an open bind: %v", err)
	}
}

func TestPlaceNewNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	dst, tmp := filepath.Join(dir, "f"), filepath.Join(dir, "tmp")
	os.WriteFile(dst, []byte("mine"), 0o644)
	os.WriteFile(tmp, []byte("theirs"), 0o644)
	if err := placeNew(tmp, dst); err == nil || toErr(err).Code != "FILE_EXISTS" {
		t.Fatalf("placeNew over an existing file: %v", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "mine" {
		t.Errorf("existing file changed to %q", b)
	}
	os.Remove(dst)
	if err := placeNew(tmp, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "theirs" {
		t.Errorf("new file = %q", b)
	}
}

func TestCheckValidate(t *testing.T) {
	if checkValidate("visudo -cf %s") != nil || checkValidate("") != nil {
		t.Error("valid --validate refused")
	}
	if checkValidate("nginx -t") == nil {
		t.Errorf("--validate without a %%s placeholder must be refused")
	}
}

// TestTunnelStartCtrlC: Ctrl-C while tunnel start waits for its background
// process stops that process and forgets the tunnel; it used to wait on and
// could still bring the tunnel up after the person cancelled.
func TestTunnelStartCtrlC(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:2")
	var child *exec.Cmd
	saved := tunnelServeCommand
	tunnelServeCommand = func(string, []string) *exec.Cmd { child = exec.Command("sleep", "60"); return child }
	t.Cleanup(func() { tunnelServeCommand = saved })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, cancel)
	root := newRoot()
	root.SetArgs([]string{"-o", "json", "tunnel", "start", "web1", "-L", "0:localhost:80"})
	var buf bytes.Buffer
	savedW := out.P.W
	out.P.W = &buf
	t0 := time.Now()
	err := root.ExecuteContext(ctx)
	out.P.W = savedW
	if e := toErr(err); e == nil || e.Code != "CANCELLED" {
		t.Fatalf("want CANCELLED, got %v", err)
	}
	if d := time.Since(t0); d > 5*time.Second {
		t.Errorf("took %s after Ctrl-C", d)
	}
	if child == nil || child.Wait() == nil { // killed: Wait reports the signal
		t.Error("the background process was not stopped")
	}
	if st := mustState(t); len(st.Tunnels) != 0 {
		t.Errorf("tunnel kept: %v", st.Tunnels)
	}
}
