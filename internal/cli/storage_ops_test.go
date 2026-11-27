package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// storage mkdir on a bucket: a folder marker, which storage list then
// shows as an empty folder rather than FOLDER_NOT_FOUND.
func TestStorageMkdir(t *testing.T) {
	m := &memBucket{objs: map[string]string{"a.txt": "a"}}
	withMemBucket(t, m)
	if d := mustRun(t, "storage", "mkdir", "bk", "reports/2026", "--dry-run"); d["created"] != true || d["dry_run"] != true || len(m.objs) != 1 {
		t.Errorf("dry run: %v %v", d, m.objs)
	}
	if d := mustRun(t, "storage", "mkdir", "bk", "/reports/2026/"); d["created"] != true || d["path"] != "reports/2026/" {
		t.Errorf("mkdir: %v", d)
	}
	if _, ok := m.objs["reports/2026/"]; !ok {
		t.Errorf("no folder marker: %v", m.objs)
	}
	if d := mustRun(t, "storage", "list", "bk", "reports/2026/"); d["count"] != float64(0) {
		t.Errorf("the empty folder lists: %v", d)
	}
	if d := mustRun(t, "storage", "mkdir", "bk", "reports"); d["created"] != false {
		t.Errorf("a folder that is there: %v", d)
	}
	wantCode(t, "FILE_EXISTS", "storage", "mkdir", "bk", "a.txt")
	wantCode(t, "FILE_EXISTS", "storage", "mkdir", "bk", "a.txt", "--dry-run")
	wantCode(t, "FOLDER_NOT_FOUND", "storage", "list", "bk", "nope/")
	for _, bad := range []string{"../up", "/"} {
		wantCode(t, "USAGE", "storage", "mkdir", "bk", bad)
	}
}

// storage mv on a bucket is a copy, then a delete; DST/ moves into a
// folder; an existing file needs --overwrite.
func TestStorageMv(t *testing.T) {
	m := &memBucket{objs: map[string]string{"db/old.sql.gz": "old", "keep.txt": "k", "archive/x": "x"}}
	withMemBucket(t, m)
	d := mustRun(t, "storage", "mv", "bk", "db/old.sql.gz", "archive/", "--dry-run")
	if d["dst"] != "archive/old.sql.gz" || d["method"] != "copy_then_delete" || d["dry_run"] != true || d["size_bytes"] != float64(3) || m.objs["db/old.sql.gz"] != "old" {
		t.Errorf("dry run: %v", d)
	}
	d = mustRun(t, "storage", "mv", "bk", "db/old.sql.gz", "archive/")
	if d["replaced"] != false || m.objs["archive/old.sql.gz"] != "old" || slices.Contains(keysOf(m.objs), "db/old.sql.gz") {
		t.Errorf("mv: %v %v", d, m.objs)
	}
	wantCode(t, "FILE_EXISTS", "storage", "mv", "bk", "keep.txt", "archive/x")
	if d := mustRun(t, "storage", "mv", "bk", "keep.txt", "archive/x", "--overwrite"); d["replaced"] != true || m.objs["archive/x"] != "k" {
		t.Errorf("--overwrite: %v %v", d, m.objs)
	}
	wantCode(t, "OBJECT_NOT_FOUND", "storage", "mv", "bk", "nope", "x")
	wantCode(t, "STORAGE_UNSUPPORTED", "storage", "mv", "bk", "archive", "attic")
	e := wantCode(t, "USAGE", "storage", "mv", "bk", "a.txt", "a.txt")
	if !strings.Contains(e.Message, "the same") {
		t.Errorf("same: %v", e)
	}
	wantCode(t, "USAGE", "storage", "mv", "bk", "a.txt", "../a.txt")
	if a := mustRun(t, "audit", "list", "--limit", "20"); !strings.Contains(fmt.Sprint(a), "storage.mv") {
		t.Errorf("no audit entry: %v", a)
	}
}

// On a protected conn, a change stops an agent; its dry run says which
// flag the real run needs, and is never blocked.
func TestStorageOpsProtected(t *testing.T) {
	m := &memBucket{objs: map[string]string{"a.txt": "a"}}
	withMemBucket(t, m)
	mustRun(t, "conn", "edit", "bk", "--protected")
	for _, args := range [][]string{
		{"storage", "mkdir", "bk", "new"},
		{"storage", "mv", "bk", "a.txt", "b.txt"},
	} {
		wantCode(t, "PROTECTED_TARGET", args...)
		d := mustRun(t, append(args, "--dry-run")...)
		meta, _ := d["_meta"].(map[string]any)
		if need := fmt.Sprint(meta["would_need"]); !strings.Contains(need, "--yes") {
			t.Errorf("%v --dry-run: would_need %v", args, meta)
		}
	}
	if _, ok := m.objs["new/"]; ok || m.objs["a.txt"] != "a" {
		t.Errorf("a stopped change changed: %v", m.objs)
	}
}

// storage chmod works on SFTP conns only, and says so before contacting
// any other kind.
func TestStorageChmod(t *testing.T) {
	withMemBucket(t, &memBucket{objs: map[string]string{"a.txt": "a"}})
	opened := false
	openBucket = func(*call, context.Context, *store.State, *store.Conn) (storex.Bucket, error) {
		opened = true
		return nil, out.Usage("not reached")
	}
	e := wantCode(t, "STORAGE_UNSUPPORTED", "storage", "chmod", "bk", "0640", "a.txt", "--dry-run")
	if opened || e.Exit != out.ExitUsage || !strings.Contains(e.Message, "bk is S3 storage") {
		t.Errorf("chmod on S3: %+v, opened %v", e, opened)
	}
	for _, c := range []struct{ mode, path, want string }{
		{"u+x", "a.txt", "digits"},
		{"99", "a.txt", "digits"},
		{"a.txt", "0640", "the mode goes first"},
	} {
		if e := wantCode(t, "USAGE", "storage", "chmod", "bk", c.mode, c.path); !strings.Contains(e.Message, c.want) {
			t.Errorf("chmod %s %s: %v", c.mode, c.path, e)
		}
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.yml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sc := localSFTP(t)
	mustRun(t, "conn", "add", "files", "sftp://deploy@10.0.0.5/srv")
	openBucket = func(*call, context.Context, *store.State, *store.Conn) (storex.Bucket, error) {
		// kept open across commands, like the closeBoth around a real one
		return keepOpen{storex.NewSFTP(sc, strings.TrimPrefix(filepath.ToSlash(dir), "/")+"/", nil)}, nil
	}
	perm := func() os.FileMode {
		fi, _ := os.Stat(filepath.Join(dir, "app.yml"))
		return fi.Mode().Perm()
	}
	d := mustRun(t, "storage", "chmod", "files", "640", "app.yml", "--dry-run")
	if d["mode"] != "0640" || d["old_mode"] != "0644" || d["dry_run"] != true || perm() != 0o644 {
		t.Errorf("dry run: %v %v", d, perm())
	}
	d = mustRun(t, "storage", "chmod", "files", "0640", "app.yml")
	if d["mode"] != "0640" || d["old_mode"] != "0644" || perm() != 0o640 {
		t.Errorf("chmod: %v %v", d, perm())
	}
	wantCode(t, "OBJECT_NOT_FOUND", "storage", "chmod", "files", "0600", "nope.yml")
	if a := mustRun(t, "audit", "list", "--limit", "20"); !strings.Contains(fmt.Sprint(a), "storage.chmod") {
		t.Errorf("no audit entry: %v", a)
	}
}

func TestStorageModeDigits(t *testing.T) {
	for _, s := range []string{"0644", "0640", "0750", "2775", "1777", "4755"} {
		m, err := parseStorageMode(s)
		if err != nil || modeDigits(m) != s {
			t.Errorf("%s: %v %v", s, modeDigits(m), err)
		}
	}
	if m, _ := parseStorageMode("644"); modeDigits(m) != "0644" {
		t.Errorf("644: %v", m)
	}
	for _, bad := range []string{"", "8", "64", "08000", "12345", "rw-r--r--"} {
		if _, err := parseStorageMode(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestStorageOpsText(t *testing.T) {
	for d, want := range map[interface{ Text() string }]string{
		mkdirData{Path: "a/", Created: true}:                                               "made the folder a/\n",
		mkdirData{Path: "a/", Created: true, DryRun: true}:                                 "would make the folder a/\n",
		mkdirData{Path: "a/"}:                                                              "a/ is already there\n",
		mvData{Src: "a", Dst: "b", Method: "rename", SizeBytes: 3}:                         "moved a -> b (3 B)\n",
		mvData{Src: "a", Dst: "b", Method: "rename", Folder: true, Replaced: true}:         "moved a -> b (folder), replaced the old file\n",
		mvData{Src: "a", Dst: "b", Method: "copy_then_delete", SizeBytes: 3, DryRun: true}: "would move a -> b (3 B, by a copy that is checked before the original is deleted; replaces a file: no)\n",
		chmodData{Path: "a", Mode: "0640", OldMode: "0644"}:                                "mode 0640 on a (was 0644)\n",
	} {
		if got := d.Text(); got != want {
			t.Errorf("%+v: %q", d, got)
		}
	}
}

// keepOpen is a bucket whose Close leaves it open (the test's SFTP pipes
// close at its end), and that wraps the real one as closeBoth does.
type keepOpen struct{ storex.Bucket }

func (keepOpen) Close() error            { return nil }
func (k keepOpen) Unwrap() storex.Bucket { return k.Bucket }

// A path with . or // in it stops before the conn is contacted.
func TestStorageOpsRefuseDotPaths(t *testing.T) {
	m := &memBucket{objs: map[string]string{"a.txt": "a"}}
	withMemBucket(t, m)
	wantCode(t, "USAGE", "storage", "mv", "bk", ".", "x")
	wantCode(t, "USAGE", "storage", "mv", "bk", "a.txt", "./b.txt")
	wantCode(t, "USAGE", "storage", "mkdir", "bk", "a//b")
	if len(m.objs) != 1 {
		t.Errorf("changed: %v", m.objs)
	}
}

// An AI agent cannot rename a file that is secret by its name into one
// that is not: the new name would pass every stop for secret files
// (download, cat, cp). Moving it with its name kept is an ordinary move.
func TestStorageMvKeepsASecretFilesName(t *testing.T) {
	m := &memBucket{objs: map[string]string{"app/.env": "DB=1", "keys/site.p12": "p"}}
	withMemBucket(t, m)
	windowText(t, false)
	e := wantCode(t, "SENSITIVE_FILE", "storage", "mv", "bk", "app/.env", "app/notes.txt")
	if e.Exit != out.ExitPolicy || m.objs["app/.env"] != "DB=1" {
		t.Errorf("exit %d, objects %v", e.Exit, m.objs)
	}
	wantCode(t, "SENSITIVE_FILE", "storage", "mv", "bk", "keys/site.p12", "keys/site.bin", "--dry-run")
	if d := mustRun(t, "storage", "mv", "bk", "app/.env", "old/"); d["dst"] != "old/.env" {
		t.Errorf("a move that keeps the name: %v", d)
	}
}
