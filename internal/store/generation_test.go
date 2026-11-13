package store

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// keychainStore is a sealed home whose key is "in the keychain", with a
// stand-in keychain for the generation.
func keychainStore(t *testing.T) *uint64 {
	t.Helper()
	sealedHome(t)
	oldKS, oldGK := KeySource, GenerationKeeper
	slowUntil = time.Time{}
	KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
		return bytes.Repeat([]byte{5}, 32), map[string]string{"key_mode": "keychain"}, nil
	}
	var kept uint64
	have := false
	GenerationKeeper = GenerationKeep{
		Get: func() (uint64, bool, error) { return kept, have, nil },
		Set: func(n uint64) error { kept, have = n, true; return nil },
		Del: func() { kept, have = 0, false },
	}
	t.Cleanup(func() {
		KeySource, GenerationKeeper = oldKS, oldGK
		closeDBs()
		AllowOldCopy = false
		slowUntil = time.Time{}
	})
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
	// a slow keychain lets reading go on, never a change
	saved := GenerationKeeper
	GenerationKeeper = GenerationKeep{Get: func() (uint64, bool, error) { return 0, false, ErrKeychainSlow }, Set: func(uint64) error { return nil }}
	closeDBs()
	if _, err := Load(); err != nil {
		t.Errorf("slow keychain: %v", err)
	}
	err := Update(func(s *State) error { s.Hosts["b"] = &Host{Name: "b"}; return nil })
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "KEYCHAIN_SLOW" {
		t.Errorf("a write with a slow keychain: %v", err)
	}
	if _, _, err := keptCount(); !errors.Is(err, ErrKeychainSlow) {
		t.Errorf("a slow keychain was asked again at once: %v", err)
	}
	GenerationKeeper = saved
	slowUntil = time.Time{} // a minute later
	closeDBs()
	update(t, func(s *State) { s.Hosts["b"] = &Host{Name: "b"} })
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

// A keyfile-era backup put back after the key moved to the keychain: the
// store says "file", but the keychain holds a count, so it is an old copy.
func TestKeyfileBackupAfterKeychainIsStopped(t *testing.T) {
	kept := keychainStore(t)
	KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
		return bytes.Repeat([]byte{5}, 32), map[string]string{"key_mode": "file"}, nil
	}
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
	closeDBs()
	if err := GenerationKeeper.Set(*kept + 50); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" {
		t.Fatalf("keyfile backup: %v", err)
	}
}

// A deleted store.db while the keychain holds a count stops; it never
// starts empty until a person accepts, which forgets the count.
func TestMissingStoreWithCountStops(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
	if *kept == 0 {
		t.Fatal("no count")
	}
	closeDBs()
	if err := os.Remove(Path(StoreFile)); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" || oe.Exit != out.ExitPolicy {
		t.Fatalf("missing store: %v", err)
	}
	if _, err := os.Stat(Path(StoreFile)); err == nil {
		t.Fatal("a fresh store was made")
	}
	have, k, guardedStore, old, err := CopyState()
	if err != nil || have != 0 || k == 0 || !guardedStore || !old {
		t.Fatalf("copy state %d %d %v %v %v", have, k, guardedStore, old, err)
	}
	if _, err := AcceptOldCopy(3); err == nil {
		t.Fatal("accepted a number nobody saw")
	}
	if _, err := AcceptOldCopy(0); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := GenerationKeeper.Get(); ok {
		t.Fatal("the count was not forgotten")
	}
	closeDBs()
	if _, err := Load(); err != nil {
		t.Fatalf("after accepting: %v", err)
	}
}
