package cli

import (
	"bytes"
	"crypto/sha256"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/store"
)

type fileState struct {
	sum   [32]byte
	mode  fs.FileMode
	mtime time.Time
}

// snapshotOf is every file and folder under each root that exists: content,
// mode and modification time.
func snapshotOf(t *testing.T, roots ...string) map[string]fileState {
	t.Helper()
	m := map[string]fileState{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if os.IsNotExist(err) && p == root {
				return filepath.SkipDir
			}
			if err != nil {
				return err
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			st := fileState{mode: fi.Mode(), mtime: fi.ModTime()}
			if !d.IsDir() {
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				st.sum = sha256.Sum256(b)
			}
			m[p] = st
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return m
}

// filesOf is tree without its folders.
func filesOf(tree map[string]fileState) map[string]fileState {
	m := map[string]fileState{}
	for p, st := range tree {
		if !st.mode.IsDir() {
			m[p] = st
		}
	}
	return m
}

// The person's dry run before the move to format 3 (owner, 2026-11-27):
// `komando doctor --dry-run` on a store of format 2 says what the move
// would do, in counts, and writes nothing: every file of the home is
// byte-equal with the same mode and time, and no file is new. A home that
// others may read (0755: a copy, an unzip) keeps its mode too: the dry
// run does not tighten it (Audit E1, low).
func TestDoctorDryRunPreviewsTheMove(t *testing.T) {
	modes := []os.FileMode{0o700, 0o755}
	if runtime.GOOS == "windows" {
		modes = modes[:1] // no mode bits: the access list keeps the home private
	}
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) { dryRunPreviewsTheMove(t, mode) })
	}
}

func dryRunPreviewsTheMove(t *testing.T, mode os.FileMode) {
	invHome(t)
	sealdb.CreateFormat = 2
	t.Cleanup(func() { sealdb.CreateFormat = sealdb.Format })
	if _, err := store.DB(true); err != nil {
		t.Fatal(err)
	}
	store.Close()
	sealdb.CreateFormat = sealdb.Format
	if err := os.Chmod(store.Home(), mode); err != nil {
		t.Fatal(err)
	}
	// komando's other folders: the files in them (the test binary shares
	// these folders, so their own times are not compared)
	var shared []string
	for _, dir := range []func() (string, error){os.UserCacheDir, os.UserConfigDir} {
		if d, err := dir(); err == nil {
			shared = append(shared, filepath.Join(d, "komando"))
		}
	}
	time.Sleep(10 * time.Millisecond) // a write now would show in the times
	before, beforeShared := snapshotOf(t, store.Home()), filesOf(snapshotOf(t, shared...))
	d := mustRun(t, "doctor", "--dry-run")
	if after := snapshotOf(t, store.Home()); !maps.Equal(before, after) {
		t.Fatalf("the dry run changed the home:\nbefore %v\nafter  %v", before, after)
	}
	if after := filesOf(snapshotOf(t, shared...)); !maps.Equal(beforeShared, after) {
		t.Fatalf("the dry run changed komando's other folders:\nbefore %v\nafter  %v", beforeShared, after)
	}
	if d["format"] != "2" || d["would_move"] != true {
		t.Fatalf("dry run: %s", asJSON(d))
	}
	if f, err := sealdb.Peek(t.Context(), store.DBPath()); err != nil || f["format"] != "2" {
		t.Fatalf("the store moved: %v %v", f, err)
	}
	s, err := runCache(t, "-o", "text", "doctor", "--dry-run")
	if err != nil || !strings.Contains(s, "format 2") || !strings.Contains(s, "nothing was written") {
		t.Fatalf("text: %v\n%s", err, s)
	}
}

// P0 of 2026-11-27 and its re-audit: a person at a terminal runs commands
// on a store of format 2 through the whole program (promptFill first).
// Only `komando doctor` with a yes moves it: a dry run, help, version,
// completion (run from .zshrc), a mistyped line and every other command
// leave store.db byte-equal, format 2, with no backup made.
func TestPersonAtTerminalOnlyDoctorMoves(t *testing.T) {
	invHome(t)
	noAgent(t)
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	sealdb.CreateFormat = 2
	t.Cleanup(func() { sealdb.CreateFormat = sealdb.Format })
	if _, err := store.DB(true); err != nil {
		t.Fatal(err)
	}
	store.Close()
	sealdb.CreateFormat = sealdb.Format
	saved := promptable
	promptable = func(*call, string) bool { return true }
	t.Cleanup(func() { promptable = saved })
	// the person's call is the only one running, as in the program
	tcl.leave()
	t.Cleanup(tcl.enter)
	before, err := os.ReadFile(store.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		ok   bool
		says string // on stdout or stderr
	}{
		{[]string{"doctor", "--dry-run"}, true, "would"},
		{[]string{"-o", "text", "doctor", "--dry-run"}, true, "nothing was written"},
		{[]string{"version"}, true, ""},
		{[]string{"completion", "zsh"}, true, ""},
		{[]string{"help"}, true, ""},
		{[]string{"schema"}, true, ""},
		{[]string{"guide"}, true, ""},
		{nil, false, "komando needs a command"},                       // stdout here is no terminal: the USAGE envelope
		{[]string{"__complete", "host", "ssh", "show", ""}, true, ""}, // the shell's helper, typed by hand
		{[]string{"list"}, false, "only `komando doctor`"},
		{[]string{"logs"}, false, "nothing is asked: the store is still to move to format 3"},
		{[]string{"lsit"}, false, ""},
	} {
		name := strings.Join(c.args, " ")
		if name == "" {
			name = "komando alone"
		}
		t.Run(name, func(t *testing.T) {
			var o, e strings.Builder
			pc := processCall()
			pc.Terminal, pc.Stdout, pc.Stderr = true, &o, &e
			code := execute(newCall(pc, c.args), t.Context(), c.args)
			store.Close()
			if (code == 0) != c.ok || !strings.Contains(o.String()+e.String(), c.says) {
				t.Fatalf("%v: exit %d\n%s%s", c.args, code, o.String(), e.String())
			}
			// owner, 2026-11-27: "Dry run: nothing was changed" came right after
			// the move's report
			if strings.Contains(e.String(), "moved its store") {
				t.Fatalf("%v moved the store:\n%s", c.args, e.String())
			}
			if after, err := os.ReadFile(store.DBPath()); err != nil || !bytes.Equal(before, after) {
				t.Fatalf("%v changed store.db: %v", c.args, err)
			}
			if f, err := sealdb.Peek(t.Context(), store.DBPath()); err != nil || f["format"] != "2" {
				t.Fatalf("%v moved the store: %v %v", c.args, f, err)
			}
			if b, _ := filepath.Glob(store.Path("store-v0-17-backup-*")); len(b) > 0 {
				t.Fatalf("%v made a backup: %v", c.args, b)
			}
		})
	}
}

// A dry run never moves the store, whoever runs it.
func TestMigrateCallForDryRun(t *testing.T) {
	cl := testCall()
	parsedGate(t, cl, "doctor", "--dry-run")
	if c := migrateCallFor(cl); c.Way != store.MigrateRefuse || !strings.Contains(c.Why, "dry run") {
		t.Fatalf("a dry run: way %d, why %q", c.Way, c.Why)
	}
}

// C558: the dry run's text gives the steps of the fix word for word, as
// the move does when it stops (the store builds both from one list).
func TestDoctorDryRunTextGivesTheFix(t *testing.T) {
	pv := store.MigrationPreview{Format: "2", WouldRefuse: []string{"host: field password_ref names an outside store (vault), which a login no longer reads"},
		Fix: []string{"install komando " + store.LastFormat2Release + ", the last release", "there, do it", "then run `komando update` again"}}
	s := migrationPreview{pv}.Text()
	want := "the move to format 3 would stop:\n  ✗ " + pv.WouldRefuse[0] + "\nto fix it:\n  1. " + pv.Fix[0] + "\n  2. " + pv.Fix[1] + "\n  3. " + pv.Fix[2] + "\n"
	if !strings.Contains(s, want) {
		t.Fatalf("text\n%s\nlacks\n%s", s, want)
	}
}

// doctor --dry-run on a moved store deletes nothing (Audit E1, low): the
// .partial file a stopped move left stays, and the check says what doctor
// would remove. doctor itself removes it, under the store lock.
func TestDoctorDryRunKeepsBackupParts(t *testing.T) {
	invHome(t)
	if _, err := store.DB(true); err != nil {
		t.Fatal(err)
	}
	store.Close()
	part := store.Path("store-v0-17-backup-2026-11-25-093000.db.partial")
	if err := os.WriteFile(part, []byte("half a copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, _ := invRun(t, "doctor", "--dry-run")
	if b, err := os.ReadFile(part); err != nil || string(b) != "half a copy" {
		t.Fatalf("the dry run removed or changed the .partial file: %v", err)
	}
	if s := asJSON(d); !strings.Contains(s, "would remove 1 half-written backup file") {
		t.Fatalf("the dry run does not say what doctor would remove:\n%s", s)
	}
	if d, _ = invRun(t, "doctor"); !strings.Contains(asJSON(d), "removed 1 half-written backup file") {
		t.Fatalf("doctor did not remove it:\n%s", asJSON(d))
	}
	if _, err := os.Stat(part); !os.IsNotExist(err) {
		t.Fatalf("the .partial file is still there: %v", err)
	}
}
