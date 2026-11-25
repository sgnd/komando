package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// E1-6: the backup is written under a temporary .partial name, checked,
// then renamed: no .partial is left, and a stale .partial of an earlier
// run that died does not stop this one.
func TestMigrate3BackupPartial(t *testing.T) {
	format2Store(t)
	now := time.Date(2026, 11, 25, 9, 30, 0, 0, time.UTC)
	stale := Path("store-v0-17-backup-2026-11-25-093000.db.partial")
	if err := os.WriteFile(stale, []byte("half a copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := personOpts()
	o.now = func() time.Time { return now }
	res, err := migrateFormat3(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(res.report.Backup, ".partial") {
		t.Fatalf("the report names a partial file: %s", res.report.Backup)
	}
	fi, err := os.Stat(res.report.Backup)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup %s: %v %v", res.report.Backup, fi, err)
	}
	if _, err := os.Stat(res.report.Backup + ".partial"); !os.IsNotExist(err) {
		t.Error("this run left its .partial file")
	}
	// doctor's sweep removes stale .partial files only
	removed, err := RemoveBackupParts()
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != filepath.Base(stale) {
		t.Errorf("removed %v", removed)
	}
	if _, err := os.Stat(res.report.Backup); err != nil {
		t.Error("the sweep removed a real backup")
	}
}

// E1-5: the window names the backup it expects; when that name is taken
// by the time the backup is written, the report and the audit entry name
// the file actually written and say that it differs.
func TestMigrate3BackupNameDiffersFromWindow(t *testing.T) {
	format2Store(t)
	Close()
	now := time.Date(2026, 11, 25, 9, 31, 0, 0, time.UTC)
	var shown string
	o := personOpts()
	o.way, o.now = MigrateWindow, func() time.Time { return now }
	o.ask = func(text string) bool { shown = text; return true }
	o.beforeLock = func() {
		_ = os.WriteFile(Path("store-v0-17-backup-2026-11-25-093100.db"), []byte("taken"), 0o600)
	}
	res, err := migrateFormat3(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shown, "store-v0-17-backup-2026-11-25-093100.db") {
		t.Fatalf("window %q", shown)
	}
	if filepath.Base(res.report.Backup) != "store-v0-17-backup-2026-11-25-093100-2.db" || res.report.BackupNote == "" {
		t.Errorf("report backup %s, note %q", res.report.Backup, res.report.BackupNote)
	}
	var e map[string]any
	if err := json.Unmarshal([]byte(res.auditEntry), &e); err != nil {
		t.Fatal(err)
	}
	if e["backup"] != "store-v0-17-backup-2026-11-25-093100-2.db" || e["via"] != "window" {
		t.Errorf("audit entry %s", res.auditEntry)
	}
}
