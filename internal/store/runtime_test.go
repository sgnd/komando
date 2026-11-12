package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestRuntimeLivesApart(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", home)
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
	inv, _ := os.ReadFile(filepath.Join(home, StoreFile))

	if err := UpdateRuntime(func(s *State) error {
		s.Sessions["office"] = &VpnSession{Vpn: "office", PID: 42, SocksPass: "p"}
		s.Jobs["j1"] = &Job{ID: "j1", Host: "web"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(home, StoreFile))
	if string(after) != string(inv) {
		t.Fatal("a runtime change rewrote the store")
	}
	rt, _ := os.ReadFile(filepath.Join(home, "runtime.json"))
	if !strings.HasPrefix(string(rt), string(runtimeMagic)) || strings.Contains(string(rt), "office") {
		t.Fatal("runtime.json is not sealed")
	}
	s, err := Load()
	if err != nil || s.Sessions["office"] == nil || s.Jobs["j1"] == nil || s.Hosts["web"] == nil {
		t.Fatalf("load: %v %+v", err, s)
	}

	// an inventory change keeps runtime data
	update(t, func(s *State) { s.Hosts["db"] = &Host{Name: "db"} })
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

func TestCorruptRuntime(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", home)
	if err := os.WriteFile(filepath.Join(home, "runtime.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	// plain, so never komando's own: read as empty, not trusted
	if _, err := Load(); err != nil {
		t.Fatalf("err %v", err)
	}
	// broken while `komando seal` reads a folder of before: stop
	if err := SealPlainRuntime(); err == nil || !strings.Contains(err.Error(), "runtime") {
		t.Fatalf("seal err %v", err)
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

// ReadOldState reads a folder of before as an earlier komando did: once
// runtime.json is there it is the record of runtime data, and what
// state.json still holds of it is left behind. It writes nothing.
func TestReadOldState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", home)
	old := `{"hosts":{"web":{"name":"web","address":"10.0.0.1","via":"bastion"}},"vpn_sessions":{"office":{"vpn":"office","pid":7}},"settings":{"audit":true},"ids":{"host":{"web":{"id":"x","version":3}}}}`
	if err := os.WriteFile(filepath.Join(home, "state.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ReadOldState()
	if err != nil || s.Sessions["office"] == nil || s.Hosts["web"].Via != "bastion" || !s.Settings.Audit || s.Settings.HostKeyPolicy == "" {
		t.Fatalf("read: %+v %v", s, err)
	}
	if err := os.WriteFile(filepath.Join(home, "runtime.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err = ReadOldState(); err != nil || s.Sessions["office"] != nil {
		t.Fatalf("removed session came back: %v", err)
	}
	if ents, _ := os.ReadDir(home); len(ents) != 2 {
		t.Fatalf("reading wrote files: %v", ents)
	}
	if err := os.WriteFile(filepath.Join(home, "state.json"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var oe *out.Error
	if _, err := ReadOldState(); !errors.As(err, &oe) || oe.Code != "STATE_CORRUPT" {
		t.Fatalf("a cut-short state.json: %v", err)
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
