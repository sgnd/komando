package vault

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

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
	kp := storeKeyFile()
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
		t.Fatalf("store.key mode %o", fi.Mode().Perm())
	}
	if left, _ := os.ReadDir(store.Home()); len(left) != 1 { // store.key
		t.Fatalf("temporary files left behind: %v", left)
	}
}
