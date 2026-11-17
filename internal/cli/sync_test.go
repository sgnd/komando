package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSyncCopiesOnlyChanges(t *testing.T) {
	tcl.flags.dryRun = false
	src, dst := t.TempDir(), t.TempDir()
	writeTree(t, src, map[string]string{"a.txt": "one", "dir/b.txt": "two", ".git/HEAD": "x", "c.log": "log"})
	ctx := context.Background()
	o := syncOpts{exclude: []string{".git", "*.log"}}
	r, err := runSync(tcl, ctx, localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", o)
	if err != nil || r.Copied != 2 || r.Updated != 0 {
		t.Fatalf("first sync: %+v %v", r, err)
	}
	if _, err := os.Stat(filepath.Join(dst, ".git/HEAD")); !os.IsNotExist(err) {
		t.Error("excluded folder was copied")
	}
	r, _ = runSync(tcl, ctx, localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", o)
	if r.Copied+r.Updated != 0 || r.Unchanged != 2 {
		t.Errorf("second sync must copy nothing: %+v", r)
	}
	writeTree(t, src, map[string]string{"a.txt": "one, longer"})
	os.Remove(filepath.Join(src, "dir/b.txt"))
	writeTree(t, dst, map[string]string{"extra.txt": "only in dst"})
	r, _ = runSync(tcl, ctx, localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", syncOpts{delete: true, exclude: o.exclude})
	if r.Updated != 1 || r.Deleted != 2 {
		t.Errorf("update + delete: %+v", r)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "a.txt")); string(b) != "one, longer" {
		t.Errorf("a.txt = %q", b)
	}
}

func TestSyncDryRunAndOnlyNew(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	writeTree(t, src, map[string]string{"new.txt": "n", "same.txt": "changed in src"})
	writeTree(t, dst, map[string]string{"same.txt": "mine"})
	old := time.Now().Add(-time.Hour)
	os.Chtimes(filepath.Join(dst, "same.txt"), old, old)
	tcl.flags.dryRun = true
	r, _ := runSync(tcl, context.Background(), localSide{tcl, src}, localSide{tcl, dst}, "s", "d", syncOpts{})
	tcl.flags.dryRun = false
	if r.Copied != 1 || r.Updated != 1 {
		t.Errorf("dry run plan: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(dst, "new.txt")); !os.IsNotExist(err) {
		t.Error("dry run wrote a file")
	}
	r, _ = runSync(tcl, context.Background(), localSide{tcl, src}, localSide{tcl, dst}, "s", "d", syncOpts{onlyNew: true})
	if r.Copied != 1 || r.Kept != 1 {
		t.Errorf("onlyNew: %+v", r)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "same.txt")); string(b) != "mine" {
		t.Error("onlyNew replaced an existing file")
	}
}

func TestExcluded(t *testing.T) {
	for rel, want := range map[string]bool{
		".git/HEAD": true, "src/.git/x": true, "app.log": true, "logs/app.log": true,
		"node_modules/a/b.js": true, "src/main.go": false, "README.md": false,
	} {
		if got := excluded(rel, []string{".git", "*.log", "node_modules"}); got != want {
			t.Errorf("excluded(%q) = %v, want %v", rel, got, want)
		}
	}
}

func TestRevokeTarget(t *testing.T) {
	st := testState()
	st.Keys = map[string]*store.Key{"old": {Name: "old", PublicKey: "ssh-ed25519 AAAAblob1 me@x"}}
	if blob, _, k, err := revokeTarget(st, "old"); err != nil || blob != "AAAAblob1" || k == nil {
		t.Errorf("keychain key: %q %v %v", blob, k, err)
	}
	if blob, _, k, err := revokeTarget(st, "ssh-rsa AAAAblob2 budi"); err != nil || blob != "AAAAblob2" || k != nil {
		t.Errorf("key line: %q %v", blob, err)
	}
	pub := filepath.Join(t.TempDir(), "k.pub")
	os.WriteFile(pub, []byte("ssh-ed25519 AAAAblob3 file\n"), 0o644)
	if blob, _, _, err := revokeTarget(st, pub); err != nil || blob != "AAAAblob3" {
		t.Errorf(".pub file: %q %v", blob, err)
	}
	if _, _, _, err := revokeTarget(st, "nonsense"); err == nil {
		t.Error("nonsense must be refused")
	}
}
