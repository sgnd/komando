package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Every db command names its conn CONN in Use, so completion and the
// prompter's picker find it, and no Use line carries flags (they show in
// [flags] and in the help) except a required one, with its UPPERCASE
// value (S-4.3: db restore --from FILE).
var requiredInUse = regexp.MustCompile(` --[a-z-]+ [A-Z_]+`)

func TestDBUseLines(t *testing.T) {
	root := newRoot(tcl)
	db, _, err := root.Find([]string{"db"})
	if err != nil {
		t.Fatal(err)
	}
	stack := db.Commands()
	for len(stack) > 0 {
		c := stack[0]
		stack = append(stack[1:], c.Commands()...)
		if c.HasSubCommands() {
			continue
		}
		f := strings.Fields(c.Use)
		if len(f) < 2 || f[1] != "CONN" {
			t.Errorf("%s: Use %q: the first argument must be CONN", c.CommandPath(), c.Use)
		}
		if u := requiredInUse.ReplaceAllString(c.Use, ""); strings.Contains(u, "--") || strings.Contains(u, "(") {
			t.Errorf("%s: Use %q carries flags", c.CommandPath(), c.Use)
		}
	}
}

// db dump --to FOLDER puts the usual CONN-<date> file in it; --to - is
// refused (it would have made a file named "-").
func TestDBDumpToFolder(t *testing.T) {
	invHome(t)
	dir := t.TempDir()
	mustRun(t, "conn", "add", "lite", "sqlite://"+filepath.Join(dir, "app.db"))
	mustRun(t, "database", "sqlite", "query", "lite", "--write", "create table t (id int)")
	backups := filepath.Join(dir, "backups")
	if err := os.Mkdir(backups, 0o700); err != nil {
		t.Fatal(err)
	}
	d := mustRun(t, "database", "sqlite", "backup", "kind:sqlite", "--to", backups)
	want := filepath.Join(backups, "lite-"+time.Now().Format("2006-01-02")+".db")
	if d["file"] != want {
		t.Fatalf("file %v, want %s", d["file"], want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatal(err)
	}
	wantCode(t, "USAGE", "database", "sqlite", "backup", "lite", "--to", "-")
}

// A db error's hint names the conn that was given, not the CONN
// placeholder, so it is the exact next command.
func TestDBHintNamesConn(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "lite", "sqlite://"+filepath.Join(t.TempDir(), "app.db"))
	mustRun(t, "database", "sqlite", "query", "lite", "--write", "create table t (id int)")
	e := wantCode(t, "TABLE_NOT_FOUND", "db", "schema", "lite", "nosuch")
	if !strings.Contains(e.Hint, "`komando db schema lite`") || strings.Contains(e.Hint, "CONN") {
		t.Errorf("hint %q", e.Hint)
	}
	e = wantCode(t, "DB_ERROR", "database", "sqlite", "query", "lite", "select * from nosuch")
	if !strings.Contains(e.Hint, "`komando db schema lite TABLE`") {
		t.Errorf("hint %q", e.Hint)
	}
}
