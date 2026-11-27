package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sealkey"
	"github.com/sgnd/komando/internal/store"
)

func sealedVault(t *testing.T) {
	t.Helper()
	freshHome(t)
}

func TestSealedVault(t *testing.T) {
	sealedVault(t)
	if l, err := List(); err != nil || len(l) != 0 {
		t.Fatalf("empty: %v %v", l, err)
	}
	if s, err := Check(); err != nil || !s.NoVaultYet {
		t.Fatalf("check before: %+v %v", s, err)
	}
	for k, v := range map[string]string{"db": "s3cret-value", "api": "tok-123", "old": "x"} {
		if err := Set(store.Save(), k, v); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := Get("db"); err != nil || v != "s3cret-value" {
		t.Fatalf("get %q %v", v, err)
	}
	if err := Set(store.Save(), "db", "changed"); err != nil {
		t.Fatal(err)
	}
	if v, _ := Get("db"); v != "changed" {
		t.Fatalf("after change %q", v)
	}
	if err := Delete(store.Save(), "old"); err != nil {
		t.Fatal(err)
	}
	if _, err := Get("old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	if err := Copy(store.Save(), "api", "api2", false); err != nil {
		t.Fatal(err)
	}
	if err := Rename(store.Save(), "api2", "api3", false); err != nil {
		t.Fatal(err)
	}
	if err := Rename(store.Save(), "api", "db", false); !errors.Is(err, ErrExists) {
		t.Fatalf("rename onto a name: %v", err)
	}
	if err := RenameMany(store.Save(), map[string]string{"api3": "api4"}); err != nil {
		t.Fatal(err)
	}
	l, _ := List()
	var names []string
	for _, i := range l {
		names = append(names, i.Name)
	}
	if strings.Join(names, ",") != "api,api4,db" {
		t.Fatalf("names %v", names)
	}
	if v, _ := Get("api4"); v != "tok-123" {
		t.Fatalf("renamed value %q", v)
	}
	// no vault.json, nothing readable in the store, and the mode is the
	// store's own
	for _, f := range []string{"vault.json", "vault.key"} {
		if _, err := os.Stat(store.Path(f)); !os.IsNotExist(err) {
			t.Fatalf("%s written in a sealed home", f)
		}
	}
	b, _ := os.ReadFile(store.Path(store.StoreFile))
	for _, w := range []string{"changed", "tok-123", "api4"} {
		if strings.Contains(string(b), w) {
			t.Fatalf("%q readable in store.db", w)
		}
	}
	if s, err := Check(); err != nil || s.Mode != "keyfile" {
		t.Fatalf("check %+v %v", s, err)
	}
	if err := KeyToFile(); err != nil { // a key file already: nothing to do
		t.Fatalf("key move: %v", err)
	}
}

func TestSealedVaultParallel(t *testing.T) {
	sealedVault(t)
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Set(store.Save(), fmt.Sprintf("s%d", i), "v"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if l, _ := List(); len(l) != 12 {
		t.Fatalf("%d secrets, want 12", len(l))
	}
}

// The inventory and the vault share the store; a secret set beside a
// server change keeps both.
func TestSealedVaultBesideInventory(t *testing.T) {
	sealedVault(t)
	if err := Set(store.Save(), "db", "pw"); err != nil {
		t.Fatal(err)
	}
	// a server names a credential that exists (format 3)
	if err := store.Update(store.Save(), func(s *store.State) error {
		s.Hosts["web"] = &store.Host{Name: "web", PasswordRef: "credential:db"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, err := store.Load()
	if err != nil || st.Hosts["web"] == nil {
		t.Fatalf("inventory lost: %v", err)
	}
	if v, err := Resolve("credential:db"); err != nil || v != "pw" {
		t.Fatalf("resolve %q %v", v, err)
	}
}

// A sealed store's key: from store.key to a passphrase, to another
// passphrase, back to a key file, and into the keychain and out; every
// secret and server survives, and the old key no longer opens the store.
func TestSealedKeyChanges(t *testing.T) {
	sealedVault(t)
	n := PassphraseN
	PassphraseN = 1 << 10
	t.Cleanup(func() { PassphraseN = n })
	if err := store.Update(store.Save(), func(s *store.State) error {
		s.Hosts["web"] = &store.Host{Name: "web"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := Set(store.Save(), "db", "pw-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateRuntime(store.Save(), func(s *store.State) error {
		s.Jobs["j1"] = &store.Job{ID: "j1"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ChangeKey(store.Save(), "", "short"); !errors.Is(err, ErrShortPassphrase) {
		t.Fatalf("short: %v", err)
	}
	if _, err := ChangeKey(store.Save(), "", ""); !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("no passphrase: %v", err)
	}
	both := func(step string) {
		t.Helper()
		if v, err := Get("db"); err != nil || v != "pw-1" {
			t.Fatalf("%s: secret %q %v", step, v, err)
		}
		if st, err := store.Load(); err != nil || st.Hosts["web"] == nil || st.Jobs["j1"] == nil {
			t.Fatalf("%s: inventory or runtime %v", step, err)
		}
	}
	r, err := ChangeKey(store.Save(), "", "first passphrase, long")
	if err != nil || r.From != "keyfile" || r.To != "passphrase" || r.Secrets != 1 || r.Removed != "store.key" {
		t.Fatalf("to passphrase: %+v %v", r, err)
	}
	if _, err := os.Stat(storeKeyFile()); !os.IsNotExist(err) {
		t.Fatal("store.key left")
	}
	both("passphrase")
	if err := Opens("wrong passphrase entirely"); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong passphrase opens: %v", err)
	}
	r, err = ChangeKey(store.Save(), "first passphrase, long", "second passphrase, long")
	if err != nil || r.To != "passphrase" {
		t.Fatalf("new passphrase: %+v %v", r, err)
	}
	both("second passphrase")
	if err := Opens("first passphrase, long"); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("the old passphrase still opens: %v", err)
	}
	r, err = ChangeKey(store.Save(), "", "")
	if err != nil || r.To != "keyfile" {
		t.Fatalf("to key file: %+v %v", r, err)
	}
	both("key file")
	if s, _ := Check(); s.Mode != "keyfile" {
		t.Fatalf("mode %q", s.Mode)
	}
}

// fakeKeychainFiles puts a secret-tool that keeps items in files on PATH,
// so the keychain moves run without a real keychain.
func fakeKeychainFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	saved := keychainOS
	keychainOS = "linux"
	t.Cleanup(func() { keychainOS = saved })
	script := `#!/bin/sh
d="` + dir + `"
f() { echo "$d/$(echo "$1" | tr ' /' '__')"; }
case "$1" in
  store) cat > "$(f "$4")" ;;
  lookup) [ -f "$(f "$3")" ] && cat "$(f "$3")" || exit 1 ;;
  search) if [ -f "$(f "$4")" ]; then printf '[/org/freedesktop/secrets/collection/login/1]\nlabel = %s\n' "$4"; fi ;;
  clear) rm -f "$(f "$3")" ;;
esac
`
	os.WriteFile(dir+"/secret-tool", []byte(script), 0o755)
	lockTool(t, dir, "gdbus", "echo '(<false>,)'")
	savedDirs := toolDirs
	toolDirs = []string{dir}
	t.Cleanup(func() { toolDirs = savedDirs })
}

func TestSealedKeyToKeychainAndBack(t *testing.T) {
	sealedVault(t)
	fakeKeychainFiles(t)
	if err := Set(store.Save(), "db", "pw"); err != nil { // a key file store
		t.Fatal(err)
	}
	t.Setenv("KOMANDO_KEYCHAIN", "")
	if _, err := KeyToKeychain(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(storeKeyFile()); !os.IsNotExist(err) {
		t.Fatal("store.key left after the move")
	}
	if s, _ := Check(); s.Mode != "keychain" {
		t.Fatalf("mode %q", s.Mode)
	}
	if v, err := Get("db"); err != nil || v != "pw" {
		t.Fatalf("with the keychain: %q %v", v, err)
	}
	if err := KeyToFile(); err != nil {
		t.Fatal(err)
	}
	if v, err := Get("db"); err != nil || v != "pw" {
		t.Fatalf("back in a key file: %q %v", v, err)
	}
	if _, err := keychainGet(); err == nil {
		t.Fatal("the key stayed in the keychain")
	}
}

// A move to the keychain whose change count cannot be saved leaves the
// store on its key file: it must not end up a keychain store with no
// count, which would never open again.
func TestSealedKeyToKeychainCountFails(t *testing.T) {
	sealedVault(t)
	fakeKeychainFiles(t)
	if err := Set(store.Save(), "db", "pw"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMANDO_KEYCHAIN", "")
	saved := store.GenerationKeeper
	store.GenerationKeeper.Set = func(uint64) error { return errors.New("keychain locked") }
	_, err := KeyToKeychain()
	store.GenerationKeeper = saved
	if err == nil {
		t.Fatal("the move worked without a change count")
	}
	if s, _ := Check(); s.Mode != "keyfile" {
		t.Fatalf("mode %q after a failed move", s.Mode)
	}
	if v, err := Get("db"); err != nil || v != "pw" {
		t.Fatalf("after a failed move: %q %v", v, err)
	}
}

// A change to a key file that stopped halfway is finished or undone by
// the next command, never left stuck.
func TestSealedKeyFileChangeStoppedHalfway(t *testing.T) {
	sealedVault(t)
	n := PassphraseN
	PassphraseN = 1 << 10
	t.Cleanup(func() { PassphraseN = n })
	if err := Set(store.Save(), "db", "pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := ChangeKey(store.Save(), "", "a passphrase, long enough"); err != nil {
		t.Fatal(err)
	}
	// stopped before the commit: a store.key.new nobody uses
	if err := os.WriteFile(newKeyFilePath(), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ChangeKey(store.Save(), "a passphrase, long enough", ""); err != nil {
		t.Fatalf("a leftover store.key.new blocks the change: %v", err)
	}
	if _, err := os.Stat(newKeyFilePath()); !os.IsNotExist(err) {
		t.Fatal("store.key.new left after the change")
	}
	// stopped after the commit, before the rename
	if err := os.Rename(storeKeyFile(), newKeyFilePath()); err != nil {
		t.Fatal(err)
	}
	// a new process: the store file is new to this one, the key not known
	b, err := os.ReadFile(store.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	store.Close() // Windows cannot replace an open file
	os.WriteFile(store.DBPath()+".tmp", b, 0o600)
	if err := os.Rename(store.DBPath()+".tmp", store.DBPath()); err != nil {
		t.Fatal(err)
	}
	if v, err := Get("db"); err != nil || v != "pw" {
		t.Fatalf("store.key.new not taken as the key: %q %v", v, err)
	}
	if _, err := os.Stat(storeKeyFile()); err != nil {
		t.Fatalf("store.key not in place: %v", err)
	}
}

// The row key (handed out later by the vault agent) opens no secret value
// and makes no ticket: the value and ticket keys come from the master key
// under their own labels, never from the row key.
func TestRowKeyOpensNoValue(t *testing.T) {
	sealedVault(t)
	if err := Set(store.Save(), "db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	f, err := loadSealed()
	if err != nil {
		t.Fatal(err)
	}
	e := f.Entries["db-pass"]
	master, err := store.MasterKey()
	if err != nil {
		t.Fatal(err)
	}
	row, _ := sealkey.Derive(master, sealkey.RowsV3)
	for _, k := range [][]byte{row, mustDerive(t, row, sealkey.Values)} {
		blk, _ := aes.NewCipher(k)
		a, _ := cipher.NewGCM(blk)
		if _, err := a.Open(nil, e.Nonce, e.Data, []byte("db-pass")); err == nil {
			t.Error("the row key opened a secret value")
		}
	}
	if v, err := Get("db-pass"); err != nil || v != "s3cret" {
		t.Fatalf("the value key: %q %v", v, err)
	}
	msg := []byte("komando spawn v1\x00ticket")
	want, err := TicketMAC(msg)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range [][]byte{row, mustDerive(t, row, sealkey.Tickets)} {
		h := hmac.New(sha256.New, k)
		h.Write(msg)
		if hmac.Equal(h.Sum(nil), want) {
			t.Error("the row key makes the ticket")
		}
	}
}

func mustDerive(t *testing.T, k []byte, l sealkey.Label) []byte {
	t.Helper()
	d, err := sealkey.Derive(k, l)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// A store an older komando made (format 1, no policy MAC, the v0.17
// record shapes) moves to format 3 at a person's first open in each key
// mode: its secret values still open, and its protected server stays
// protected.
func TestUpgradeEachKeyMode(t *testing.T) {
	for _, mode := range []string{"keyfile", "passphrase", "keychain"} {
		t.Run(mode, func(t *testing.T) {
			// a hang here is a failure, never a stuck run (Audit C2)
			stuck := time.AfterFunc(time.Minute, func() { panic("TestUpgradeEachKeyMode/" + mode + ": still running after a minute") })
			defer stuck.Stop()
			switch mode {
			case "keyfile":
				freshHome(t)
			case "passphrase":
				passHome(t, oldPass)
			case "keychain":
				unixOnly(t, "the stand-in keychain is a sh script")
				freshHome(t)
				fakeSecretTool(t)
			}
			format1Store(t, "db-pass", "s3cret", &store.Host{Name: "web", Address: "10.0.0.1", Protected: true})
			if m := peekMeta(t); m["format"] != "1" || m["key_mode"] != mode {
				t.Fatalf("the old store: %v", m)
			}
			old := store.MigrateCaller
			store.MigrateCaller = func() store.MigrateCall {
				return store.MigrateCall{Way: store.MigrateTerminal, Alive: func(int, string) bool { return false }, Ask: func(string) bool { return true }}
			}
			t.Cleanup(func() { store.MigrateCaller = old })
			store.Close() // the next command
			if v, err := Get("db-pass"); err != nil || v != "s3cret" {
				t.Fatalf("a secret of the old store: %q %v", v, err)
			}
			if m := peekMeta(t); m["format"] != "3" {
				t.Fatalf("not moved to format 3: %v", m)
			}
			store.Close()
			s, err := store.Load()
			if err != nil || !s.Hosts["web"].Protected {
				t.Fatalf("after the upgrade: %v", err)
			}
		})
	}
}

// format1Store makes this home's store as komando before format 2 did: a
// secret row sealed with the value key under its name, and a server record
// in the old shape. Nothing goes through today's writers.
func format1Store(t *testing.T, name, value string, h *store.Host) {
	t.Helper()
	sealdb.CreateFormat = 1
	t.Cleanup(func() { sealdb.CreateFormat = sealdb.Format })
	d, err := store.DB(true)
	if err != nil {
		t.Fatal(err)
	}
	sealdb.CreateFormat = sealdb.Format
	master, _, err := store.KeySource(peekMeta(t), false)
	if err != nil {
		t.Fatal(err)
	}
	a, err := vaultAEADFrom(master)
	clear(master)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sec, _ := json.Marshal(map[string]any{"name": name, "nonce": nonce, "data": a.Seal(nil, nonce, []byte(value), []byte(name)), "updated_at": time.Now().UTC()})
	host, _ := json.Marshal(h)
	err = d.Update(context.Background(), func(tx *sealdb.Tx) error {
		if _, err := tx.Put("secret", "", sec); err != nil {
			return err
		}
		_, err := tx.Put(store.KindHost, "", host)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func peekMeta(t *testing.T) map[string]string {
	t.Helper()
	m, err := sealdb.Peek(context.Background(), store.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	return m
}
