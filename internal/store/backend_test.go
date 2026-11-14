package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sealrow"
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
	t.Cleanup(closeDBs)
	return home
}

// A home with files of an earlier komando and no store.db starts fresh, as
// a new install does: the files are never read.
func TestOldFilesStartFresh(t *testing.T) {
	for _, f := range []string{"state.json", "vault.json", "known_hosts", "keys/k"} {
		t.Run(f, func(t *testing.T) {
			sealedHome(t)
			fakeKeys(t)
			_ = os.MkdirAll(Path("keys"), 0o700)
			if err := os.WriteFile(Path(f), []byte(`{"hosts":{"old":{"name":"old"}}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := DB(true); err != nil {
				t.Fatalf("a store beside old files: %v", err)
			}
			s, err := Load()
			if err != nil || len(s.Hosts) != 0 {
				t.Fatalf("Load: %v %v", s.Hosts, err)
			}
		})
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot remove or replace a file while it is open, so a store is never replaced under an open handle there")
	}
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

// A home whose store.db is missing or moved never starts empty and never
// falls back to files: any sign it had a store stops it.
func TestMissingStoreOfSealedFolder(t *testing.T) {
	signs := map[string]func(t *testing.T){
		"store key":    func(*testing.T) { os.WriteFile(Path("store.key"), make([]byte, 32), 0o600) },
		"runtime pids": func(*testing.T) { os.WriteFile(Path("runtime.pids"), []byte("{}"), 0o600) },
		"keychain count": func(t *testing.T) {
			old := GenerationKeeper
			GenerationKeeper.Get = func() (uint64, bool, error) { return 3, true, nil }
			t.Cleanup(func() { GenerationKeeper = old })
		},
	}
	for name, sign := range signs {
		t.Run(name, func(t *testing.T) {
			sealedHome(t)
			fakeKeys(t)
			sign(t)
			want := "STATE_CORRUPT"
			if name == "keychain count" {
				want = "STORE_OLD_COPY" // doctor --accept-old-copy clears it
			}
			// a plain state.json someone put there must not be read either
			os.WriteFile(Path("state.json"), []byte(`{"hosts":{"x":{"name":"x"}}}`), 0o600)
			var oe *out.Error
			for what, err := range map[string]error{"Load": func() error { _, e := Load(); return e }(), "Update": Update(Save, func(*State) error { return nil })} {
				if !errors.As(err, &oe) || oe.Code != want || (want == "STATE_CORRUPT" && !strings.Contains(oe.Hint, "store.db back")) {
					t.Fatalf("%s: %v", what, err)
				}
			}
			if _, err := os.Stat(Path(StoreFile)); !os.IsNotExist(err) {
				t.Fatal("an empty store was made")
			}
		})
	}
}

// A plain state.json beside store.db is never the inventory.
func TestStateFileBesideStoreIgnored(t *testing.T) {
	sealedHome(t)
	fakeKeys(t)
	if err := Update(Save, func(s *State) error { s.Hosts["real"] = &Host{Name: "real"}; return nil }); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(Path("state.json"), []byte(`{"hosts":{"planted":{"name":"planted"}},"settings":{"host_key_policy":"off"}}`), 0o600)
	s, err := Load()
	if err != nil || s.Hosts["planted"] != nil || s.Hosts["real"] == nil || s.Settings.HostKeyPolicy == "off" {
		t.Fatalf("%+v %v", s, err)
	}
}

// A store whose key another process changed is opened again with the new
// key, never written through the old handle.
func TestDBReopensAfterKeyChange(t *testing.T) {
	sealedHome(t)
	fakeKeys(t)
	d1, err := DB(true)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	oldKey, _ := sealrow.NewKey(bytes.Repeat([]byte{7}, 32))
	newKey, _ := sealrow.NewKey(bytes.Repeat([]byte{9}, 32))
	other, err := sealdb.Open(ctx, DBPath(), oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Rekey(ctx, newKey, nil); err != nil {
		t.Fatal(err)
	}
	other.Close()
	inner := KeySource
	KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
		if create {
			return inner(meta, create)
		}
		return bytes.Repeat([]byte{9}, 32), nil, nil
	}
	d2, err := DB(false)
	if err != nil {
		t.Fatal(err)
	}
	if d2 == d1 {
		t.Fatal("the handle with the old key was kept")
	}
	if err := d2.Update(ctx, func(tx *sealdb.Tx) error { return tx.AppendAudit([]byte("x")) }); err != nil {
		t.Fatal(err)
	}
}
