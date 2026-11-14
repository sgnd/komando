package store

import "testing"

func TestCommitsCountsChangingWrites(t *testing.T) {
	sealedStore(t)
	n := Commits()
	if _, err := Load(); err != nil || Commits() != n {
		t.Fatalf("a read counted as a write: %v", err)
	}
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web", Address: "10.0.0.1"} })
	if Commits() == n {
		t.Fatal("a committed write was not counted")
	}
	n = Commits()
	if err := Update(Save(), func(*State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if Commits() != n {
		t.Fatal("a write step that changed nothing was counted")
	}
}
