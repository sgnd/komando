package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func markHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("KOMANDO_HOME", home)
	t.Cleanup(Close) // before the folder goes: Windows cannot remove an open file
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
	return home
}

func runtimeSet(t *testing.T, fn func(s *State)) {
	t.Helper()
	if err := UpdateRuntime(Save(), func(s *State) error { fn(s); return nil }); err != nil {
		t.Fatal(err)
	}
}

// An old runtime.json put back after the sessions changed reads as empty:
// its mark is not the store's.
func TestRuntimeOldCopyReadsEmpty(t *testing.T) {
	home := markHome(t)
	rtPath := filepath.Join(home, "runtime.json")
	runtimeSet(t, func(s *State) {
		s.Sessions["office"] = &VpnSession{Vpn: "office", PID: 42, Socks: "127.0.0.1:1080", SocksPass: "old"}
	})
	old, err := os.ReadFile(rtPath)
	if err != nil {
		t.Fatal(err)
	}
	runtimeSet(t, func(s *State) {
		s.Sessions["office"] = &VpnSession{Vpn: "office", PID: 43, Socks: "127.0.0.1:1081", SocksPass: "new"}
	})
	if err := os.WriteFile(rtPath, old, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Sessions) != 0 {
		t.Fatalf("an old runtime.json opened: %+v", s.Sessions["office"])
	}
	if rt, err := ReadRuntime(); err != nil || len(rt.Sessions) != 0 {
		t.Fatalf("ReadRuntime: %v %+v", err, rt)
	}
}

// Marking a session used keeps the mark: store.db is not written.
func TestRuntimeLastUsedKeepsMark(t *testing.T) {
	home := markHome(t)
	runtimeSet(t, func(s *State) { s.Sessions["office"] = &VpnSession{Vpn: "office", PID: 42} })
	before, _ := os.ReadFile(filepath.Join(home, StoreFile))
	runtimeSet(t, func(s *State) { s.Sessions["office"].LastUsed = time.Now() })
	runtimeSet(t, func(s *State) { s.Jobs["j1"] = &Job{ID: "j1", Host: "web"} })
	after, _ := os.ReadFile(filepath.Join(home, StoreFile))
	if string(before) != string(after) {
		t.Fatal("last_used or a job rewrote the store")
	}
	if s, err := Load(); err != nil || s.Sessions["office"] == nil || s.Jobs["j1"] == nil {
		t.Fatalf("load: %v", err)
	}
}

// A home from before marks: no mark in either file, runtime.json opens.
func TestRuntimeNoMarkOpens(t *testing.T) {
	markHome(t)
	s := &State{}
	s.init()
	s.Runtime.Sessions["office"] = &VpnSession{Vpn: "office", PID: 42}
	if err := s.saveRuntime(); err != nil { // no mark: as komando before C115 wrote it
		t.Fatal(err)
	}
	if s, err := Load(); err != nil || s.Sessions["office"] == nil {
		t.Fatalf("a runtime.json without a mark beside a store without one did not open: %v", err)
	}
}

// An inventory change that also changes a session (Update) moves the mark
// in the same write.
func TestUpdateMovesMark(t *testing.T) {
	home := markHome(t)
	rtPath := filepath.Join(home, "runtime.json")
	runtimeSet(t, func(s *State) { s.Logins["web"] = &SSHLogin{Host: "web", Token: "a"} })
	old, _ := os.ReadFile(rtPath)
	update(t, func(s *State) { delete(s.Logins, "web"); s.Hosts["db"] = &Host{Name: "db"} })
	_ = os.WriteFile(rtPath, old, 0o600)
	if s, err := Load(); err != nil || s.Logins["web"] != nil {
		t.Fatalf("an old login came back: %v", err)
	}
}
