package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRuntimeLivesApart(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", home)
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
	inv, _ := os.ReadFile(filepath.Join(home, "state.json"))

	if err := UpdateRuntime(func(s *State) error {
		s.Sessions["office"] = &VpnSession{Vpn: "office", PID: 42, SocksPass: "p"}
		s.Jobs["j1"] = &Job{ID: "j1", Host: "web"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(home, "state.json"))
	if string(after) != string(inv) {
		t.Fatal("a runtime change rewrote state.json")
	}
	rt, _ := os.ReadFile(filepath.Join(home, "runtime.json"))
	if !strings.Contains(string(rt), `"office"`) {
		t.Fatalf("runtime.json: %s", rt)
	}
	s, err := Load()
	if err != nil || s.Sessions["office"] == nil || s.Jobs["j1"] == nil || s.Hosts["web"] == nil {
		t.Fatalf("load: %v %+v", err, s)
	}

	// an inventory change keeps runtime data, and state.json never holds it
	update(t, func(s *State) { s.Hosts["db"] = &Host{Name: "db"} })
	inv, _ = os.ReadFile(filepath.Join(home, "state.json"))
	for _, k := range []string{"vpn_sessions", "jobs", "tunnels", "ssh_logins", "office"} {
		if strings.Contains(string(inv), `"`+k+`"`) {
			t.Fatalf("state.json holds %s", k)
		}
	}
	if s, _ := Load(); s.Sessions["office"] == nil {
		t.Fatal("runtime lost by an inventory change")
	}
}

func TestUpdateRuntimeRefusesInventory(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
	err := UpdateRuntime(func(s *State) error {
		s.Hosts["web"].Address = "x"
		s.Jobs["j"] = &Job{ID: "j"}
		return nil
	})
	if !errors.Is(err, ErrRuntimeOnly) {
		t.Fatalf("err %v", err)
	}
	if s, _ := Load(); s.Hosts["web"].Address != "" || s.Jobs["j"] != nil {
		t.Fatal("something was saved")
	}
}

func TestLegacyRuntimeMoves(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", home)
	old := `{"hosts":{"web":{"name":"web"}},"vpn_sessions":{"office":{"vpn":"office","pid":7}},"jobs":{"j1":{"id":"j1"}},"tunnels":{}}`
	if err := os.WriteFile(filepath.Join(home, "state.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load()
	if err != nil || s.Sessions["office"] == nil || s.Jobs["j1"] == nil {
		t.Fatalf("old file: %v", err)
	}
	// a runtime-only removal must not bring the entry back from state.json
	if err := UpdateRuntime(func(s *State) error { delete(s.Jobs, "j1"); return nil }); err != nil {
		t.Fatal(err)
	}
	s, _ = Load()
	if s.Jobs["j1"] != nil || s.Sessions["office"] == nil {
		t.Fatalf("after move: jobs %v sessions %v", s.Jobs, s.Sessions)
	}
	inv, _ := os.ReadFile(filepath.Join(home, "state.json"))
	if strings.Contains(string(inv), "vpn_sessions") {
		t.Fatal("state.json still holds runtime data")
	}
}

func TestCorruptRuntime(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", home)
	if err := os.WriteFile(filepath.Join(home, "runtime.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "runtime") {
		t.Fatalf("err %v", err)
	}
}

// Update and UpdateRuntime at the same time lose no change of either.
func TestRuntimeAndInventoryTogether(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	update(t, func(*State) {})
	var wg sync.WaitGroup
	const n = 20
	for i := range n {
		wg.Add(2)
		go func() {
			defer wg.Done()
			name := "h" + string(rune('a'+i))
			if err := Update(func(s *State) error { s.Hosts[name] = &Host{Name: name}; return nil }); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			id := "j" + string(rune('a'+i))
			if err := UpdateRuntime(func(s *State) error { s.Jobs[id] = &Job{ID: id}; return nil }); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	s, _ := Load()
	if len(s.Hosts) != n || len(s.Jobs) != n {
		t.Fatalf("hosts %d jobs %d, want %d each", len(s.Hosts), len(s.Jobs), n)
	}
}

// A crash after runtime.json was written and before state.json was: an
// entry removed in that step must not come back from state.json.
func TestRuntimeFileIsTheRecord(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", home)
	old := `{"hosts":{},"vpn_sessions":{"office":{"vpn":"office","pid":7}}}`
	if err := os.WriteFile(filepath.Join(home, "state.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "runtime.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load()
	if err != nil || s.Sessions["office"] != nil {
		t.Fatalf("removed session came back: %v", err)
	}
	if !s.legacyRuntime {
		t.Fatal("state.json's leftovers not marked for removal")
	}
	update(t, func(*State) {})
	inv, _ := os.ReadFile(filepath.Join(home, "state.json"))
	if strings.Contains(string(inv), "office") {
		t.Fatal("leftover kept in state.json")
	}
}

func TestUpdateRuntimeDryRun(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
	DryRun = true
	defer func() { DryRun = false }()
	if err := UpdateRuntime(func(s *State) error { s.Hosts["web"].Address = "x"; return nil }); !errors.Is(err, ErrRuntimeOnly) {
		t.Fatalf("dry run skipped the check: %v", err)
	}
	if err := UpdateRuntime(func(s *State) error { s.Jobs["j"] = &Job{ID: "j"}; return nil }); err != nil {
		t.Fatal(err)
	}
	DryRun = false
	if s, _ := Load(); s.Jobs["j"] != nil {
		t.Fatal("dry run saved")
	}
}
