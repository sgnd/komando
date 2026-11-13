package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// writePromptState writes runtime.pids as the store keeps it for the
// sessions and tunnels of st, in a fresh home, and returns its path.
func writePromptState(t *testing.T, st *store.State) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", home)
	var p store.RuntimePIDs
	for _, v := range st.Sessions {
		p.Vpns = append(p.Vpns, store.VpnPID{PID: v.PID, LastUsed: v.LastUsed})
	}
	for _, tn := range st.Tunnels {
		p.Tunnels = append(p.Tunnels, tn.PID)
	}
	b, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "runtime.pids")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPromptText(t *testing.T) {
	now := time.Now()
	me, dead := os.Getpid(), 1<<30
	st := &store.State{
		// the default vpn_idle, 30m, applies: the prompt never opens the store
		Sessions: map[string]*store.VpnSession{
			"office": {Vpn: "office", PID: me, LastUsed: now.Add(-time.Minute)},
			"gone":   {Vpn: "gone", PID: dead, LastUsed: now},
			"idle":   {Vpn: "idle", PID: me, LastUsed: now.Add(-time.Hour)},
		},
		Tunnels: map[string]*store.Tunnel{
			"t1": {ID: "t1", PID: me},
			"t2": {ID: "t2", PID: me},
			"t3": {ID: "t3", PID: dead},
		},
	}
	writePromptState(t, st)
	if got := promptText(now); got != "vpn:1 tun:2\n" {
		t.Errorf("got %q", got)
	}

	writePromptState(t, &store.State{})
	if got := promptText(now); got != "" {
		t.Errorf("nothing running: got %q", got)
	}
}

// TestPromptNeverBreaks: a prompt must not fail or print errors, and must
// not create komando's folder.
func TestPromptNeverBreaks(t *testing.T) {
	home := filepath.Join(t.TempDir(), "none")
	t.Setenv("KOMANDO_HOME", home)
	if got := promptText(time.Now()); got != "" {
		t.Errorf("no state: %q", got)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Errorf("prompt created %s", home)
	}
	p := writePromptState(t, &store.State{})
	for _, bad := range []string{"", "{", "null", `{"sessions":{"x":null},"tunnels":{"y":null}}`, "\x00\xff"} {
		if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := promptText(time.Now()); got != "" {
			t.Errorf("state %q: %q", bad, got)
		}
	}
}

// TestPromptCommandChangesNothing runs `komando status --short` itself: the root's
// checks (which close idle VPN sessions and need the audit log) are
// skipped, and runtime.pids stays byte for byte the same.
func TestPromptCommandChangesNothing(t *testing.T) {
	for _, args := range [][]string{{"status", "--short"}} {
		st := &store.State{
			Settings: store.DefaultSettings(),
			Sessions: map[string]*store.VpnSession{"stale": {Vpn: "stale", PID: 1 << 30}},
		}
		p := writePromptState(t, st)
		before, _ := os.ReadFile(p)
		root := newRoot()
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		after, _ := os.ReadFile(p)
		if string(before) != string(after) {
			t.Errorf("%v changed runtime.pids", args)
		}
		if _, err := os.Stat(store.Path(store.StoreFile)); !os.IsNotExist(err) {
			t.Errorf("%v made a store", args)
		}
	}
}

func TestPromptIsQuick(t *testing.T) {
	st := &store.State{Settings: store.DefaultSettings(), Sessions: map[string]*store.VpnSession{}, Tunnels: map[string]*store.Tunnel{}}
	for i := range 50 {
		n := strconv.Itoa(i)
		st.Sessions["v"+n] = &store.VpnSession{Vpn: "v" + n, PID: os.Getpid(), LastUsed: time.Now()}
		st.Tunnels["t"+n] = &store.Tunnel{ID: "t" + n, PID: os.Getpid()}
	}
	writePromptState(t, st)
	start := time.Now()
	promptText(time.Now())
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("50 VPNs and 50 tunnels took %v", d)
	}
}

// The prompt counts from runtime.pids, without names and without opening
// the store.
func TestPromptSealed(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	p := store.RuntimePIDs{Vpns: []store.VpnPID{{PID: os.Getpid(), LastUsed: time.Now()}}, Tunnels: []int{os.Getpid()}}
	b, _ := json.Marshal(&p)
	if err := os.WriteFile(store.Path("runtime.pids"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := promptText(time.Now()); got != "vpn:1 tun:1\n" {
		t.Fatalf("prompt %q", got)
	}
}
