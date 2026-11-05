package vault

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// keyfileHome is a fresh state directory with a key-file vault.
func keyfileHome(t *testing.T) {
	t.Helper()
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "")
	passMu.Lock()
	pass = ""
	passMu.Unlock()
}

// Parallel `secret set` / `secret rm` (several agents at once) must not
// drop each other's changes, and on a brand-new vault they must all end up
// with the one key that is on disk.
func TestParallelChangesKeepEverySecret(t *testing.T) {
	keyfileHome(t)
	if err := Set("gone", "to-be-removed"); err != nil {
		t.Fatal(err)
	}
	// start again from nothing, so the workers also race to create vault.key
	if err := os.RemoveAll(store.Home()); err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n+1)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- Set(fmt.Sprintf("s%d", i), fmt.Sprintf("value-%d", i))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	list, err := List()
	if err != nil || len(list) != n {
		t.Fatalf("after %d parallel sets the vault holds %v (%v)", n, list, err)
	}
	for i := 0; i < n; i++ {
		if v, err := Get(fmt.Sprintf("s%d", i)); err != nil || v != fmt.Sprintf("value-%d", i) {
			t.Errorf("s%d = %q, %v", i, v, err)
		}
	}

	// removes and sets at the same time
	var wg2 sync.WaitGroup
	for i := 0; i < n; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			if i%2 == 0 {
				_ = Delete(fmt.Sprintf("s%d", i))
			} else {
				_ = Set(fmt.Sprintf("t%d", i), "other-value")
			}
		}(i)
	}
	wg2.Wait()
	list, _ = List()
	var names []string
	for _, e := range list {
		names = append(names, e.Name)
	}
	if got := strings.Join(names, " "); got != "s1 s3 s5 s7 t1 t3 t5 t7" {
		t.Fatalf("after parallel removes and sets: %s", got)
	}
}

func TestNewKeyFileNeverReplacesAKey(t *testing.T) {
	keyfileHome(t)
	if err := store.EnsureHome(); err != nil {
		t.Fatal(err)
	}
	kp := store.Path("vault.key")
	first, err := newKeyFile(kp)
	if err != nil || len(first) != keyLen {
		t.Fatalf("first key: %d bytes, %v", len(first), err)
	}
	// a second process that also found no key a moment ago
	second, err := newKeyFile(kp)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, _ := os.ReadFile(kp)
	if !bytes.Equal(second, first) || !bytes.Equal(onDisk, first) {
		t.Fatal("newKeyFile replaced the key another process made")
	}
	if fi, _ := os.Stat(kp); fi.Mode().Perm() != 0o600 {
		t.Fatalf("vault.key mode %o", fi.Mode().Perm())
	}
	if left, _ := os.ReadDir(store.Home()); len(left) != 2 { // keys/ and vault.key
		t.Fatalf("temporary files left behind: %v", left)
	}
}

func TestShortKeyFileIsRefused(t *testing.T) {
	keyfileHome(t)
	if err := Set("db", "s3cret-value"); err != nil {
		t.Fatal(err)
	}
	// what a crash or power loss can leave
	if err := os.WriteFile(store.Path("vault.key"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Set("new", "other-value"); err == nil || !strings.Contains(err.Error(), "cut short") {
		t.Fatalf("Set with an empty vault.key: %v", err)
	}
	if _, err := Get("db"); err == nil || !strings.Contains(err.Error(), "cut short") {
		t.Fatalf("Get with an empty vault.key: %v", err)
	}
}

// Moving the key to or from the keychain rewrites vault.json: it waits for
// a change another komando process is making, so that change is not lost.
func TestKeyMoveWaitsForTheVaultLock(t *testing.T) {
	keyfileHome(t)
	if err := Set("a", "1"); err != nil {
		t.Fatal(err)
	}
	unlock, err := store.Lock(lockName)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- KeyToFile() }()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("KeyToFile did not wait for the lock (err %v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("KeyToFile still waits after the lock was released")
	}
}
