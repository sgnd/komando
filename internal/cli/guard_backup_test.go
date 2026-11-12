//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// O15: installing or removing the guard keeps the old settings file under
// a name of its own, 0600: the user's own settings.json.bak (0644) is not
// written over, and its mode is not what the copy gets.
func TestGuardSettingsBackupIsNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"env":{"TOKEN":"abc"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mine := path + ".bak"
	if err := os.WriteFile(mine, []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := installGuardHook(path, "/usr/local/bin/komando", false)
	if err != nil {
		t.Fatal(err)
	}
	if f.Backup == mine || !strings.HasPrefix(f.Backup, mine+".") {
		t.Fatalf("backup %q", f.Backup)
	}
	if read(t, mine) != "mine\n" || mode(t, mine) != 0o644 {
		t.Fatal("the user's own .bak was changed")
	}
	if read(t, f.Backup) != `{"env":{"TOKEN":"abc"}}`+"\n" || mode(t, f.Backup) != 0o600 {
		t.Fatalf("backup %q: mode %04o", read(t, f.Backup), mode(t, f.Backup))
	}
	r, err := removeGuard(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Backup == f.Backup || r.Backup == mine || mode(t, r.Backup) != 0o600 {
		t.Fatalf("uninstall backup %q", r.Backup)
	}
	if read(t, f.Backup) != `{"env":{"TOKEN":"abc"}}`+"\n" {
		t.Fatal("install's backup was written over")
	}
}
