package store

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// keychainStore is a sealed home whose key is "in the keychain", with a
// stand-in keychain for the generation.
func keychainStore(t *testing.T) *uint64 {
	t.Helper()
	sealedHome(t)
	oldKS, oldGK := KeySource, GenerationKeeper
	KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
		return bytes.Repeat([]byte{5}, 32), map[string]string{"key_mode": "keychain"}, nil
	}
	var kept uint64
	have := false
	GenerationKeeper = GenerationKeep{
		Get: func() (uint64, bool, error) { return kept, have, nil },
		Set: func(n uint64) error { kept, have = n, true; return nil },
	}
	t.Cleanup(func() { KeySource, GenerationKeeper = oldKS, oldGK; closeDBs(); AllowOldCopy = false })
	return &kept
}

func TestOldCopyIsStopped(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web", Protected: true} })
	if *kept == 0 {
		t.Fatal("the keychain was not told the generation")
	}
	backup, _ := os.ReadFile(Path(StoreFile))
	update(t, func(s *State) { s.Hosts["web"].Protected = false })
	newer := *kept

	// someone puts the old copy back
	closeDBs()
	if err := os.WriteFile(Path(StoreFile), backup, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" || oe.Exit != out.ExitPolicy {
		t.Fatalf("old copy: %v", err)
	}
	if !strings.Contains(oe.Hint, "--accept-old-copy") {
		t.Fatalf("hint %q", oe.Hint)
	}
	if err := Update(func(s *State) error { return nil }); err == nil {
		t.Fatal("a change went into an old copy")
	}

	// doctor and dry runs may look
	AllowOldCopy = true
	if s, err := Load(); err != nil || !s.Hosts["web"].Protected {
		t.Fatalf("allowed look: %v", err)
	}
	AllowOldCopy = false
	closeDBs()
	have, k, guarded, old, err := CopyState()
	if err != nil || !guarded || !old || k != newer || have >= k {
		t.Fatalf("copy state %d %d %v %v %v", have, k, guarded, old, err)
	}

	// the look-only handle is not reused once looking is over
	AllowOldCopy = true
	if _, err := DB(false); err != nil {
		t.Fatal(err)
	}
	AllowOldCopy = false
	if _, err := DB(false); err == nil {
		t.Fatal("a handle opened to look at an old copy was handed to a normal command")
	}
	// a write through a look-only handle never lowers the keychain
	AllowOldCopy = true
	_ = Update(func(s *State) error { s.Hosts["x"] = &Host{Name: "x"}; return nil })
	AllowOldCopy = false
	if *kept != newer {
		t.Fatalf("the keychain went down to %d", *kept)
	}
	closeDBs()
	have, _, _, _, _ = CopyState()

	// a person accepts it, the number they saw only
	if _, err := AcceptOldCopy(have + 7); err == nil {
		t.Fatal("accepted a number nobody saw")
	}
	if _, err := AcceptOldCopy(have); err != nil {
		t.Fatal(err)
	}
	closeDBs()
	if _, err := Load(); err != nil {
		t.Fatalf("after accepting: %v", err)
	}
}

// The store ahead of the keychain (a crash between the two writes, a
// keychain that was locked) is normal: the keychain is raised.
func TestKeychainBehindIsRaised(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	update(t, func(s *State) { s.Hosts["b"] = &Host{Name: "b"} })
	want := *kept
	*kept = 1
	closeDBs()
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	if *kept != want {
		t.Fatalf("keychain %d, want %d", *kept, want)
	}
}

// A store with its key in a file has no keychain to compare with.
func TestNoGuardWithoutKeychain(t *testing.T) {
	sealedStore(t) // key_mode "test"
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	if _, _, guarded, _, _ := CopyState(); guarded {
		t.Fatal("guarded without the keychain")
	}
}

// keychainItems gives the stand-in keychain's number and lets a test
// remove it or put rubbish in it.
func TestMissingOrBrokenCountStops(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	_ = kept
	for name, gk := range map[string]GenerationKeep{
		"removed": {Get: func() (uint64, bool, error) { return 0, false, nil }, Set: func(uint64) error { return nil }},
		"rubbish": {Get: func() (uint64, bool, error) { return 0, false, errors.New("not a number") }, Set: func(uint64) error { return nil }},
	} {
		saved := GenerationKeeper
		GenerationKeeper = gk
		closeDBs()
		_, err := Load()
		var oe *out.Error
		if !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" {
			t.Errorf("%s count: %v", name, err)
		}
		GenerationKeeper = saved
	}
	// a slow keychain lets work go on
	saved := GenerationKeeper
	GenerationKeeper = GenerationKeep{Get: func() (uint64, bool, error) { return 0, false, ErrKeychainSlow }, Set: func(uint64) error { return nil }}
	closeDBs()
	if _, err := Load(); err != nil {
		t.Errorf("slow keychain: %v", err)
	}
	GenerationKeeper = saved
}

// A new store whose key goes into the keychain gets its number there at
// once.
func TestNewStoreStartsItsCount(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	if *kept == 0 {
		t.Fatal("no number for a new store")
	}
	closeDBs()
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}

// A new store whose change count cannot go into the keychain is not kept:
// on the next run it would be taken for an old copy and never open.
func TestNewStoreCountNotSaved(t *testing.T) {
	kept := keychainStore(t)
	set := GenerationKeeper.Set
	GenerationKeeper.Set = func(uint64) error { return errors.New("keychain locked") }
	err := Update(func(s *State) error { s.Hosts["a"] = &Host{Name: "a"}; return nil })
	if err == nil || !strings.Contains(err.Error(), "change count") {
		t.Fatalf("a new store without its count: %v", err)
	}
	if _, err := os.Stat(Path(StoreFile)); !os.IsNotExist(err) {
		t.Fatal("the store without a count was kept")
	}
	GenerationKeeper.Set = set
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	if *kept == 0 {
		t.Fatal("no number once the keychain works")
	}
}

// A store set aside takes a journal left by a write with it, and the copy
// set aside still opens with everything in it.
func TestRemoveStoreKeepsItWhole(t *testing.T) {
	keychainStore(t)
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	if err := RemoveStore("store.db.aside"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(Path(StoreFile)); !os.IsNotExist(err) {
		t.Fatal("store.db still there")
	}
	if _, err := os.Stat(Path("store.db.aside-journal")); err == nil {
		t.Fatal("a finished write left a journal")
	}
	if err := os.Rename(Path("store.db.aside"), Path(StoreFile)); err != nil {
		t.Fatal(err)
	}
	AllowOldCopy = true // its count left the keychain with it
	st, err := Load()
	if err != nil || st.Hosts["a"] == nil {
		t.Fatalf("the store set aside lost data: %v", err)
	}
}
