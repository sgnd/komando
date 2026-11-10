package store

import (
	"bytes"
	"errors"
	"os"
	"sync"
	"testing"
)

// fakeKeys is a KeySource with a fixed key per mode, counting new keys.
func fakeKeys(t *testing.T) *int {
	t.Helper()
	made := 0
	var mu sync.Mutex
	old := KeySource
	KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
		mu.Lock()
		defer mu.Unlock()
		if create {
			made++
			return bytes.Repeat([]byte{7}, 32), map[string]string{"key_mode": "test"}, nil
		}
		if meta["key_mode"] != "test" {
			return nil, nil, errors.New("no key_mode in the store")
		}
		return bytes.Repeat([]byte{7}, 32), nil, nil
	}
	t.Cleanup(func() { KeySource = old; closeDBs() })
	return &made
}

func sealedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", home)
	was := freshSealed
	freshSealed = true
	t.Cleanup(func() { freshSealed = was })
	return home
}

func TestSealedChoice(t *testing.T) {
	home := sealedHome(t)
	if !Sealed() {
		t.Fatal("fresh home not sealed")
	}
	if err := os.WriteFile(Path("vault.key"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !Sealed() {
		t.Fatal("vault.key alone made it a files home")
	}
	for _, f := range []string{"state.json", "vault.json", "known_hosts", "keys/k"} {
		t.Run(f, func(t *testing.T) {
			t.Setenv("KOMANDO_HOME", t.TempDir())
			_ = os.MkdirAll(Path("keys"), 0o700)
			if err := os.WriteFile(Path(f), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if Sealed() {
				t.Fatalf("%s: a home with old files chose sealed", f)
			}
			if err := os.WriteFile(Path(StoreFile), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if !Sealed() || !MixedHome() {
				t.Fatal("store.db beside old files must win and be reported")
			}
		})
	}
	freshSealed = false
	t.Setenv("KOMANDO_HOME", home)
	_ = os.Remove(Path("vault.key"))
	if Sealed() {
		t.Fatal("switch off, yet a fresh home chose sealed")
	}
}

func TestDBReadMakesNothing(t *testing.T) {
	home := sealedHome(t)
	made := fakeKeys(t)
	if _, err := DB(false); !errors.Is(err, ErrNoStore) {
		t.Fatalf("read: %v", err)
	}
	ents, _ := os.ReadDir(home)
	if len(ents) != 0 || *made != 0 {
		t.Fatalf("a read made %d files and %d keys", len(ents), *made)
	}
	d, err := DB(true)
	if err != nil {
		t.Fatal(err)
	}
	if d2, _ := DB(false); d2 != d {
		t.Fatal("not opened once per process")
	}
	closeDBs()
	if _, err := DB(false); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if *made != 1 {
		t.Fatalf("%d keys made", *made)
	}
	if _, err := os.Stat(Path(StoreFile + ".new")); !os.IsNotExist(err) {
		t.Fatal("temporary file left")
	}
}

func TestDBCreateRace(t *testing.T) {
	sealedHome(t)
	made := fakeKeys(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := DB(true); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if *made != 1 {
		t.Fatalf("%d keys made by 8 openers", *made)
	}
}

// A store file replaced while open (a restore) is opened again.
func TestDBReopensReplacedFile(t *testing.T) {
	sealedHome(t)
	fakeKeys(t)
	d, err := DB(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(Home()); err != nil {
		t.Fatal(err)
	}
	if _, err := DB(false); !errors.Is(err, ErrNoStore) {
		t.Fatalf("after removal: %v", err)
	}
	d2, err := DB(true)
	if err != nil || d2 == d {
		t.Fatalf("not reopened: %v", err)
	}
}
