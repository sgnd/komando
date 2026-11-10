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

func writePromptState(t *testing.T, st *store.State) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", home)
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(home, "state.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPromptText(t *testing.T) {
	now := time.Now()
	me, dead := os.Getpid(), 1<<30
	st := &store.State{
		Settings: store.Settings{}, // vpn_idle unset: the default 30m applies
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
	if got := promptText(now); got != "vpn:office tun:2\n" {
		t.Errorf("got %q", got)
	}

	st.Settings.VpnIdle = "0" // never closes by itself
	writePromptState(t, st)
	if got := promptText(now); got != "vpn:idle,office tun:2\n" {
		t.Errorf("vpn_idle 0: got %q", got)
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

// TestPromptCommandChangesNothing runs `komando prompt` itself: the root's
// checks (which close idle VPN sessions and need the audit log) are
// skipped, and the state file stays byte for byte the same.
func TestPromptCommandChangesNothing(t *testing.T) {
	st := &store.State{
		Settings: store.DefaultSettings(),
		Sessions: map[string]*store.VpnSession{"stale": {Vpn: "stale", PID: 1 << 30}},
	}
	p := writePromptState(t, st)
	before, _ := os.ReadFile(p)
	root := newRoot()
	root.SetArgs([]string{"prompt"})
	if err := root.Execute(); err != nil {
		t.Fatalf("prompt: %v", err)
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Error("prompt changed the state file")
	}
	if _, err := os.Stat(store.Path("keys")); !os.IsNotExist(err) {
		t.Error("prompt created the keys folder")
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

// A sealed folder has no state.json: the prompt still counts what
// runtime.json holds, tunnels included.
func TestPromptWithoutStateFile(t *testing.T) {
	filesOnly(t) // a sealed home's prompt reads runtime.pids: TestPromptSealed
	t.Setenv("KOMANDO_HOME", t.TempDir())
	rt := store.Runtime{Tunnels: map[string]*store.Tunnel{"t1": {ID: "t1", PID: os.Getpid()}}}
	b, _ := json.Marshal(&rt)
	if err := os.WriteFile(store.Path("runtime.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := promptText(time.Now()); got != "tun:1\n" {
		t.Fatalf("prompt %q", got)
	}
}

// On a sealed home the prompt counts from runtime.pids, without names and
// without opening the store.
func TestPromptSealed(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	store.UseSealedForNewHomes(true)
	t.Cleanup(func() { store.UseSealedForNewHomes(os.Getenv("KOMANDO_TEST_SEALED") == "1") })
	p := store.RuntimePIDs{Vpns: []store.VpnPID{{PID: os.Getpid(), LastUsed: time.Now()}}, Tunnels: []int{os.Getpid()}}
	b, _ := json.Marshal(&p)
	if err := os.WriteFile(store.Path("runtime.pids"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := promptText(time.Now()); got != "vpn:1 tun:1\n" {
		t.Fatalf("prompt %q", got)
	}
}
