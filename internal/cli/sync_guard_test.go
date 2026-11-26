package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/storex"
	"github.com/sgnd/komando/internal/storex/ftptest"
)

// files makes a sync side's listing from paths.
func files(paths ...string) map[string]syncFile {
	m := map[string]syncFile{}
	for _, p := range paths {
		m[p] = syncFile{Size: 1}
	}
	return m
}

// C124: a source folder that lists no files while --delete would empty it
// on the destination is named, once, at the top of the emptied subtree.
func TestEmptiedFolders(t *testing.T) {
	for _, c := range []struct {
		name     string
		src, dst map[string]syncFile
		exclude  []string
		want     []emptiedFolder
	}{
		{"a folder lists empty", files("a/x"), files("a/x", "b/y", "b/z"), nil, []emptiedFolder{{"b", 2}}},
		{"nested: the top folder once", files("a/x"), files("a/x", "b/c/y", "b/z"), nil, []emptiedFolder{{"b", 2}}},
		{"two folders", files("a/x"), files("a/x", "b/y", "c/z"), nil, []emptiedFolder{{"b", 1}, {"c", 1}}},
		{"partly emptied: no", files("b/keep"), files("b/keep", "b/old"), nil, nil},
		{"a deeper folder empties", files("a/x"), files("a/x", "a/d/y"), nil, []emptiedFolder{{"a/d", 1}}},
		{"top-level file: no folder", files("a/x"), files("a/x", "old.txt"), nil, nil},
		{"excluded files are not deleted", files("a/x"), files("a/x", "b/y.log"), []string{"*.log"}, nil},
		{"excluded and not", files("a/x"), files("a/x", "b/y.log", "b/z"), []string{"*.log"}, []emptiedFolder{{"b", 1}}},
		{"only excluded source files: still emptied", files("a/x", "b/s.log"), files("a/x", "b/z"), []string{"*.log"}, []emptiedFolder{{"b", 1}}},
		{"only a skipped link: still emptied", map[string]syncFile{"a/x": {Size: 1}, "b/link": {Skip: true}}, files("a/x", "b/y"), nil, []emptiedFolder{{"b", 1}}},
		{"first sync into an empty destination", files("a/x", "b/y"), files(), nil, nil},
	} {
		o := syncOpts{delete: true, exclude: c.exclude}
		got := emptiedFolders(c.src, c.dst, planSync(c.src, c.dst, o), o.exclude)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// guardTrees: the source lists a/ only; the destination also has b/.
func guardTrees(t *testing.T) (src, dst string) {
	t.Helper()
	src, dst = t.TempDir(), t.TempDir()
	writeTree(t, src, map[string]string{"a/x": "x"})
	writeTree(t, dst, map[string]string{"a/x": "x", "b/y": "y", "c/z": "z"})
	return src, dst
}

func resetGuardFlags(t *testing.T) {
	t.Cleanup(func() {
		setGate(tcl, false, gateDryRun, gateAllowDangerous)
		tcl.terminal, tcl.stdin = false, nil
		tcl.out.Reset()
	})
	setGate(tcl, false, gateDryRun)
}

func exists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Stat(p)
	return err == nil
}

// A script stops even with --allow-dangerous, and goes on only for the
// folders it names with --emptied.
func TestSyncEmptiedFolderScript(t *testing.T) {
	noAgent(t)
	resetGuardFlags(t)
	setGate(tcl, true, gateAllowDangerous)
	ctx := context.Background()

	src, dst := guardTrees(t)
	_, err := runSync(tcl, ctx, localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", syncOpts{delete: true})
	e := toErr(err)
	if e == nil || e.Code != "EMPTY_FOLDER_CONFIRM_REQUIRED" || e.Exit != out.ExitPolicy {
		t.Fatalf("script with --allow-dangerous: %v", err)
	}
	if !exists(t, filepath.Join(dst, "b/y")) || !exists(t, filepath.Join(dst, "c/z")) {
		t.Error("files were deleted before the stop")
	}
	if !strings.Contains(e.Hint, "--emptied") {
		t.Errorf("hint %q does not name --emptied", e.Hint)
	}
	j, _ := json.Marshal(e)
	var got struct {
		Details struct {
			Folders []emptiedFolder `json:"folders"`
		} `json:"details"`
	}
	if json.Unmarshal(j, &got); !reflect.DeepEqual(got.Details.Folders, []emptiedFolder{{"b", 1}, {"c", 1}}) {
		t.Errorf("error.details.folders: %s", j)
	}

	// one named, one not: still stops, names only c, deletes nothing
	_, err = runSync(tcl, ctx, localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", syncOpts{delete: true, emptied: []string{"b"}})
	if e := toErr(err); e == nil || e.Code != "EMPTY_FOLDER_CONFIRM_REQUIRED" || strings.Contains(e.Message, "b ") || !strings.Contains(e.Message, "c") {
		t.Fatalf("--emptied b, c not named: %v", err)
	}
	if !exists(t, filepath.Join(dst, "b/y")) {
		t.Error("b/y was deleted although the run stopped")
	}

	// a name that matches nothing is a usage error
	_, err = runSync(tcl, ctx, localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", syncOpts{delete: true, emptied: []string{"b", "c", "zzz"}})
	if e := toErr(err); e == nil || e.Exit != out.ExitUsage {
		t.Fatalf("--emptied zzz: %v", err)
	}

	// both named: goes on
	r, err := runSync(tcl, ctx, localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", syncOpts{delete: true, emptied: []string{"b/", "c"}})
	if err != nil || r.Deleted != 2 || exists(t, filepath.Join(dst, "b/y")) {
		t.Fatalf("--emptied b c: %+v %v", r, err)
	}
}

// --dry-run reports the stop and goes on to show the plan.
func TestSyncEmptiedFolderDryRun(t *testing.T) {
	noAgent(t)
	resetGuardFlags(t)
	setGate(tcl, true, gateDryRun)
	src, dst := guardTrees(t)
	r, err := runSync(tcl, context.Background(), localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", syncOpts{delete: true})
	if err != nil || r.Deleted != 2 {
		t.Fatalf("dry run: %+v %v", r, err)
	}
	if b := tcl.out.Blocked(); b == nil || b.Code != "EMPTY_FOLDER_CONFIRM_REQUIRED" {
		t.Errorf("meta.would_be_blocked: %+v", b)
	}
}

// A person at a terminal types the folder to go on.
func TestSyncEmptiedFolderPerson(t *testing.T) {
	noAgent(t)
	resetGuardFlags(t)
	for _, c := range []struct {
		typed string
		ok    bool
	}{{"no", false}, {"b", true}} {
		resetApproval()
		src, dst := t.TempDir(), t.TempDir()
		writeTree(t, src, map[string]string{"a/x": "x"})
		writeTree(t, dst, map[string]string{"a/x": "x", "b/y": "y"})
		tcl.terminal, tcl.stdin = true, strings.NewReader(c.typed+"\n")
		setGate(tcl, true, gateAllowDangerous) // --delete's own question is answered by it
		_, err := runSync(tcl, context.Background(), localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", syncOpts{delete: true})
		if (err == nil) != c.ok || exists(t, filepath.Join(dst, "b/y")) == c.ok {
			t.Errorf("typed %q: %v", c.typed, err)
		}
	}
}

// An AI agent: --allow-dangerous opens the window, which names the folder
// and the count; without it, or with a no, it stops.
func TestSyncEmptiedFolderAgent(t *testing.T) {
	resetGuardFlags(t)
	ctx := context.Background()
	for _, c := range []struct {
		flag, allow, ok bool
	}{{false, true, false}, {true, false, false}, {true, true, true}} {
		windows := asAgent(t, c.allow, true)
		setGate(tcl, c.flag, gateAllowDangerous)
		src, dst := guardTrees(t)
		_, err := runSync(tcl, ctx, localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", syncOpts{delete: true})
		if (err == nil) != c.ok {
			t.Errorf("flag=%v allow=%v: %v", c.flag, c.allow, err)
		}
		if c.flag && *windows != 1 {
			t.Errorf("flag=%v allow=%v: %d windows", c.flag, c.allow, *windows)
		}
		if !c.ok && toErr(err).Code != "EMPTY_FOLDER_CONFIRM_REQUIRED" {
			t.Errorf("flag=%v allow=%v: code %s", c.flag, c.allow, toErr(err).Code)
		}
	}
}

// C124 on plain FTP: a listing that ends early looks complete, so only
// this guard stops sync --delete from acting on it.
func TestSyncEmptiedFolderPlainFTP(t *testing.T) {
	noAgent(t)
	resetGuardFlags(t)
	setGate(tcl, true, gateAllowDangerous)
	s := ftptest.New(t)
	s.Dirs = map[string]string{
		"/":    "-rw-r--r-- 1 u u 3 Nov 07 12:00 top.txt\r\ndrwxr-xr-x 1 u u 0 Nov 07 12:00 sub\r\n",
		"/sub": "", // cut: the data connection closed, the server said 226
	}
	b, err := storex.OpenFTP(context.Background(), s.Target(), "p", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	dst := t.TempDir()
	writeTree(t, dst, map[string]string{"top.txt": "top", "sub/a.txt": "aaa"})
	_, err = runSync(tcl, context.Background(), bucketSide{b: b}, localSide{tcl, dst}, "files-ftp:", "dst", syncOpts{delete: true})
	if e := toErr(err); e == nil || e.Code != "EMPTY_FOLDER_CONFIRM_REQUIRED" {
		t.Errorf("plain FTP, cut listing: %v", err)
	}
	if !exists(t, filepath.Join(dst, "sub/a.txt")) {
		t.Error("sub/a.txt was deleted")
	}
}

// --emptied is checked before anything is listed.
func TestCheckEmptied(t *testing.T) {
	for _, c := range []struct {
		o  syncOpts
		ok bool
	}{
		{syncOpts{delete: true, emptied: []string{"b"}}, true},
		{syncOpts{delete: true, emptied: []string{"./b/"}}, true},
		{syncOpts{emptied: []string{"b"}}, false},
		{syncOpts{delete: true, emptied: []string{"/"}}, false},
		{syncOpts{delete: true, emptied: []string{"."}}, false},
		{syncOpts{delete: true, emptied: []string{""}}, false},
		{syncOpts{delete: true, emptied: []string{"b/../.."}}, false},
	} {
		if err := checkEmptied(c.o); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.o, err)
		}
	}
	if emptiedName(`b\c`) != "b/c" {
		t.Error(`--emptied b\c is not b/c`)
	}
}

// A script's error names --emptied, never --allow-dangerous (which it
// already gave, and which does not do here).
func TestSyncEmptiedFolderScriptHint(t *testing.T) {
	noAgent(t)
	resetGuardFlags(t)
	setGate(tcl, true, gateAllowDangerous)
	src, dst := guardTrees(t)
	_, err := runSync(tcl, context.Background(), localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", syncOpts{delete: true})
	j, _ := json.Marshal(toErr(err))
	if strings.Contains(string(j), "allow-dangerous") {
		t.Errorf("a script's error suggests --allow-dangerous: %s", j)
	}
}

// On several servers a name may match nothing on one of them (the folder
// is gone there already): that is no error, and an unnamed folder still
// stops.
func TestSyncEmptiedFolderSeveralServers(t *testing.T) {
	noAgent(t)
	resetGuardFlags(t)
	setGate(tcl, true, gateAllowDangerous)
	src, dst := guardTrees(t)
	_, err := runSync(tcl, context.Background(), localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", syncOpts{delete: true, multi: true, emptied: []string{"b", "gone"}})
	if e := toErr(err); e == nil || e.Code != "EMPTY_FOLDER_CONFIRM_REQUIRED" {
		t.Fatalf("several servers: %v", err)
	}
	r, err := runSync(tcl, context.Background(), localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", syncOpts{delete: true, multi: true, emptied: []string{"b", "c", "gone"}})
	if err != nil || r.Deleted != 2 {
		t.Errorf("several servers, all named: %+v %v", r, err)
	}
}

// An answer the person typed to another question in the same command
// (--delete's, another server's) does not answer this one.
func TestSyncEmptiedFolderAsksAgain(t *testing.T) {
	noAgent(t)
	resetGuardFlags(t)
	resetApproval()
	src, dst := t.TempDir(), t.TempDir()
	long := strings.Repeat("x", 70) // a long name is asked as a count: "1"
	writeTree(t, src, map[string]string{"a/x": "x"})
	writeTree(t, dst, map[string]string{"a/x": "x", long + "/y": "y"})
	tcl.sess.ConfirmDanger("1") // the person typed 1 for --delete's question
	tcl.terminal, tcl.stdin = true, strings.NewReader("")
	_, err := runSync(tcl, context.Background(), localSide{tcl, src}, localSide{tcl, dst}, "src", "dst", syncOpts{delete: true})
	if err == nil || !exists(t, filepath.Join(dst, long, "y")) {
		t.Errorf("the earlier answer counted: %v", err)
	}
}
