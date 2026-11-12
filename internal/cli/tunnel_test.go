package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
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
	tunnelServeCommand = func(string, []string) *exec.Cmd { child = sleeperCmd(); return child }
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

// TestParseTunnelIPv6: IPv6 addresses go in brackets, as with ssh; an open
// IPv6 bind ([::]) still needs a person's yes, the loopback ([::1]) not.
func TestParseTunnelIPv6(t *testing.T) {
	g.yes = false
	for _, c := range []struct {
		kind, spec, bind, target string
		open                     bool
	}{
		{"local", "8080:[::1]:80", "127.0.0.1:8080", "[::1]:80", false},
		{"local", "[::1]:8080:[fd00::5]:5432", "[::1]:8080", "[fd00::5]:5432", false},
		{"local", "[::]:8080:db:5432", "[::]:8080", "db:5432", true},
		{"dynamic", "[::1]:1080", "[::1]:1080", "", false},
		{"dynamic", "[::]:1080", "[::]:1080", "", true},
	} {
		ts, err := parseTunnel(c.kind, c.spec)
		if err != nil {
			t.Fatalf("%s: %v", c.spec, err)
		}
		if ts.BindAddr != c.bind || ts.TargetAddr != c.target {
			t.Errorf("%s: bind %q target %q", c.spec, ts.BindAddr, ts.TargetAddr)
		}
		if err := guardBind(ts); (err != nil) != c.open {
			t.Errorf("%s: guardBind = %v, want blocked=%v", c.spec, err, c.open)
		}
	}
	for _, bad := range []string{"8080:::1:80", "8080:[::1:80", "8080:[::1]x:80", "8080:db:"} {
		if _, err := parseTunnel("local", bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

// TestAllWithNames: vpn down and tunnel stop refuse names together with
// --all, as logout does; the names (even unknown ones) were ignored.
func TestAllWithNames(t *testing.T) {
	invHome(t)
	wantCode(t, "USAGE", "vpn", "down", "nosuch", "--all")
	wantCode(t, "USAGE", "tunnel", "stop", "t-nosuch", "--all")
	wantCode(t, "USAGE", "logout", "web1", "--all")
	mustRun(t, "vpn", "down", "--all")
	mustRun(t, "tunnel", "stop", "--all")
}

// TestViaTwice: a --via path that names a step twice is refused with
// VIA_CYCLE and the path without the repeat; office,office was told to
// "put the VPN first", and a,b,a was accepted.
func TestViaTwice(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "add", "office", "socks", "--address", "127.0.0.1:1")
	mustRun(t, "host", "add", "bastion", "u@10.0.0.1")
	mustRun(t, "host", "add", "b2", "u@10.0.0.3")
	e := wantCode(t, "VIA_CYCLE", "host", "add", "app", "u@10.0.0.2", "--via", "office,office")
	if !strings.Contains(e.Hint, "--via office") || strings.Contains(e.Hint, "office,office") {
		t.Errorf("hint: %s", e.Hint)
	}
	e = wantCode(t, "VIA_CYCLE", "host", "add", "app", "u@10.0.0.2", "--via", "bastion,b2,bastion")
	if !strings.Contains(e.Hint, "--via bastion,b2") {
		t.Errorf("hint: %s", e.Hint)
	}
	wantCode(t, "VIA_CYCLE", "conn", "add", "pg", "postgres://u@10.0.0.9/db", "--via", "office,bastion,bastion")
	mustRun(t, "host", "add", "app", "u@10.0.0.2", "--via", "office,bastion,b2")
}

// TestTunnelStopOtherProgram: a tunnel whose pid now belongs to another
// program (after a crash or a restart) is forgotten, never signalled.
func TestTunnelStopOtherProgram(t *testing.T) {
	invHome(t)
	// a program other than komando (and this test program) that waits:
	// sleep, or ping on Windows, which has no sleep
	other, otherName := exec.Command("sleep", "60"), "sleep"
	if runtime.GOOS == "windows" {
		other, otherName = exec.Command("ping", "-n", "60", "127.0.0.1"), "ping.exe"
	}
	if err := other.Start(); err != nil {
		t.Skip("no sleep program:", err)
	}
	exited := make(chan struct{})
	go func() { _ = other.Wait(); close(exited) }()
	defer func() { _ = other.Process.Kill(); <-exited }()
	if err := store.UpdateRuntime(func(s *store.State) error {
		s.Tunnels["t-old"] = &store.Tunnel{ID: "t-old", Host: "web1", Kind: "local", Spec: "0:localhost:80", PID: other.Process.Pid, StartedAt: time.Now()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	d := mustRun(t, "tunnel", "list")
	if r := d["tunnels"].([]any)[0].(map[string]any); r["alive"] != false {
		t.Errorf("another program's pid listed as the tunnel: %v", r)
	}
	if err := store.UpdateRuntime(func(s *store.State) error {
		s.Tunnels["t-old"] = &store.Tunnel{ID: "t-old", Host: "web1", Kind: "local", Spec: "0:localhost:80", PID: other.Process.Pid, StartedAt: time.Now()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// status and the restart list after a key change must not count it
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(runningStatus(st).Tunnels); n != 0 {
		t.Errorf("status lists another program's pid as a running tunnel (%d)", n)
	}
	if r := runningServes(); slices.Contains(r, "tunnel t-old") {
		t.Errorf("restart list names another program's pid: %v", r)
	}
	mustRun(t, "tunnel", "stop", "t-old")
	select {
	case <-exited:
		t.Fatal("tunnel stop signalled another program")
	case <-time.After(300 * time.Millisecond):
	}
	// komando's own process (this test binary stands in) is still seen
	saved := tunnelExe
	tunnelExe = func() string { return otherName }
	defer func() { tunnelExe = saved }()
	if !tunnelAlive(&store.Tunnel{PID: other.Process.Pid}) {
		t.Error("a running tunnel process is not seen")
	}
}
