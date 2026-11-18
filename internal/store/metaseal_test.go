package store

import (
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// tamperMeta adds a row to the store's meta table behind komando's back.
func tamperMeta(t *testing.T) {
	t.Helper()
	Close()
	db, err := sql.Open("sqlite", "file:"+DBPath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO meta(k,v) VALUES('note','x')`); err != nil {
		t.Fatal(err)
	}
}

func errCode(err error) string {
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe.Code
	}
	return ""
}

// ResealMeta seals a changed meta table again and tells the keychain the
// store's new change count (C08).
func TestResealMetaRaisesTheCount(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
	before := *kept
	tamperMeta(t)
	if _, err := Load(); errCode(err) != "STATE_CORRUPT" {
		t.Fatalf("a changed meta table: %v", err)
	}
	if m, err := ResealMeta(); err != nil || m["note"] != "x" {
		t.Fatalf("reseal: %v %v", m, err)
	}
	if *kept <= before {
		t.Errorf("the keychain's count stayed at %d", *kept)
	}
	if s, err := Load(); err != nil || s.Hosts["web"] == nil {
		t.Fatalf("after the reseal: %v", err)
	}
}

// An older copy with a changed meta table is not resealed: the write
// would raise its change count towards the keychain's (C08).
func TestResealMetaNotOnAnOldCopy(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web", Protected: true} })
	backup, err := os.ReadFile(DBPath())
	if err != nil {
		t.Fatal(err)
	}
	update(t, func(s *State) { s.Hosts["web"].Protected = false })
	newest := *kept
	Close()
	if err := os.WriteFile(DBPath(), backup, 0o600); err != nil {
		t.Fatal(err)
	}
	tamperMeta(t)
	if _, err := ResealMeta(); errCode(err) != "STORE_OLD_COPY" {
		t.Fatalf("an old copy was resealed: %v", err)
	}
	if *kept != newest {
		t.Errorf("the keychain's count went from %d to %d", newest, *kept)
	}
	now, err := os.ReadFile(DBPath())
	if err != nil {
		t.Fatal(err)
	}
	Close()
	if _, err := Load(); errCode(err) != "STATE_CORRUPT" {
		t.Errorf("the old copy after a refused reseal: %v (%d bytes, was %d)", err, len(now), len(backup))
	}
}
