package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The file a person said yes to is the file that is restored: one that is
// rewritten while the approval window is open stops with FILE_CHANGED
// before the database is opened. (Before, the restore opened the path
// again and ran whatever was there.)
func TestRestoreStopsWhenTheFileChangesAfterTheCheck(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "pg", "postgres://app@127.0.0.1:1/app?sslmode=disable")
	file := filepath.Join(t.TempDir(), "f.sql")
	if err := os.WriteFile(file, []byte("INSERT INTO t VALUES (1);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	windows := 0
	saved := askOnScreen
	askOnScreen = func(_ *call, text string) (bool, bool) {
		windows++
		// the agent swaps the file while the person reads the window
		os.WriteFile(file, []byte("COPY t TO PROGRAM 'id';\n"), 0o600)
		return true, true
	}
	t.Cleanup(func() { askOnScreen = saved; resetApproval() })
	resetApproval()
	_, e := invRun(t, "db", "restore", "pg", "--from", file, "--allow-dangerous")
	if windows == 0 {
		t.Fatal("no approval window was opened")
	}
	if e == nil || e.Code != "FILE_CHANGED" {
		t.Fatalf("want FILE_CHANGED, got %+v", e)
	}
}

// C197: body_sha256 of a restore is taken in the sealing pass, so it is
// the hash of the bytes the restore sends. A file swapped between the
// seal and the window's own read stops with FILE_CHANGED, and the record
// names the sealed content, not the swapped one.
func TestRestoreBodySHA256IsTheSealedContent(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "pg", "postgres://app@127.0.0.1:1/app?sslmode=disable")
	file := filepath.Join(t.TempDir(), "f.sql")
	sealed := []byte("INSERT INTO t VALUES (1);\n")
	if err := os.WriteFile(file, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(sealed)
	want := hex.EncodeToString(sum[:])
	setCallerEnv(t, "CLAUDECODE", "1")
	saved := afterRestoreSeal
	afterRestoreSeal = func(path string) { os.WriteFile(path, []byte("INSERT INTO t VALUES (2);\n"), 0o600) }
	t.Cleanup(func() { afterRestoreSeal = saved; resetApproval() })
	resetApproval()
	_, e := invRun(t, "db", "restore", "pg", "--from", file, "--allow-dangerous")
	if e == nil || e.Code != "FILE_CHANGED" {
		t.Fatalf("want FILE_CHANGED, got %+v", e)
	}
	if !strings.Contains(auditText(t), `"body_sha256":"`+want+`"`) {
		t.Errorf("want the sealed hash %s in: %s", want, auditText(t))
	}
}

// A person's restore records body_sha256 too.
func TestRestoreBodySHA256ForAPerson(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "pg", "postgres://app@127.0.0.1:1/app?sslmode=disable")
	file := filepath.Join(t.TempDir(), "f.sql")
	b := []byte("CREATE TABLE t (id int);\n")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	d := mustRun(t, "db", "restore", "pg", "--from", file, "--dry-run")
	if got := d["_meta"].(map[string]any)["body_sha256"]; got != hex.EncodeToString(sum[:]) {
		t.Errorf("body_sha256 %v, want %x", got, sum)
	}
}
