package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// withBuckets makes each conn named in m open its bucket in memory.
func withBuckets(t *testing.T, m map[string]*memBucket) {
	t.Helper()
	saved := openBucket
	openBucket = func(_ *call, _ context.Context, _ *store.State, c *store.Conn) (storex.Bucket, error) {
		return m[c.Name], nil
	}
	t.Cleanup(func() { openBucket = saved })
}

// cp between two remote places, every pairing: server to server, server
// to storage, storage to server and storage to storage, one file and a
// folder. A file reports its sha256; nothing is saved on this computer.
func TestRemoteCopyEveryPairing(t *testing.T) {
	sc := localSFTP(t)
	ctx := context.Background()
	web1 := &copyEnd{host: &store.Host{Name: "web1"}, sc: sc}
	web2 := &copyEnd{host: &store.Host{Name: "web2"}, sc: sc}
	bk := &copyEnd{conn: &store.Conn{Name: "bk"}, b: &memBucket{objs: map[string]string{}}}
	bk2 := &copyEnd{conn: &store.Conn{Name: "bk2"}, b: &memBucket{objs: map[string]string{}}}
	data := payload(70_000)
	a, b := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(a, "db.sql.gz"), data)
	writeTree(t, filepath.Join(a, "site"), map[string]string{"index.html": "hello", "css/a.css": "body{}"})

	// one file
	st, err := remoteCopy(tcl, ctx, web1, web2, filepath.Join(a, "db.sql.gz"), b+"/", cpOpts{})
	if err != nil || st.SHA256 != sumOf(data) || st.Dest != "web2:"+filepath.Join(b, "db.sql.gz") || st.Source != "web1:"+filepath.Join(a, "db.sql.gz") {
		t.Fatalf("server to server: %+v %v", st, err)
	}
	if !bytes.Equal(readBytes(t, filepath.Join(b, "db.sql.gz")), data) {
		t.Error("server to server: the copy differs")
	}
	if st, err = remoteCopy(tcl, ctx, web1, bk, filepath.Join(a, "db.sql.gz"), "2026/", cpOpts{}); err != nil || st.SHA256 != sumOf(data) || st.Dest != "bk:2026/db.sql.gz" {
		t.Fatalf("server to storage: %+v %v", st, err)
	}
	if st, err = remoteCopy(tcl, ctx, bk, bk2, "2026/db.sql.gz", "copy.gz", cpOpts{}); err != nil || st.SHA256 != sumOf(data) || st.Bytes != int64(len(data)) {
		t.Fatalf("storage to storage: %+v %v", st, err)
	}
	if bk2.b.(*memBucket).objs["copy.gz"] != string(data) {
		t.Error("storage to storage: the copy differs")
	}
	back := filepath.Join(b, "back.gz")
	if st, err = remoteCopy(tcl, ctx, bk2, web1, "copy.gz", back, cpOpts{}); err != nil || st.SHA256 != sumOf(data) || st.Replaced {
		t.Fatalf("storage to server: %+v %v", st, err)
	}
	if st, err = remoteCopy(tcl, ctx, bk2, web1, "copy.gz", back, cpOpts{}); err != nil || !st.Replaced {
		t.Fatalf("storage to server again: %+v %v", st, err)
	}
	if !bytes.Equal(readBytes(t, back), data) {
		t.Error("storage to server: the copy differs")
	}

	// folders, by cpFolderRule
	if _, err := remoteCopy(tcl, ctx, web1, web2, filepath.Join(a, "site"), b, cpOpts{}); toErr(err).Code != "IS_A_DIRECTORY" {
		t.Errorf("a folder without -r: %v", err)
	}
	if st, err = remoteCopy(tcl, ctx, web1, web2, filepath.Join(a, "site"), b, cpOpts{recursive: true}); err != nil || st.Files != 2 || st.Dest != "web2:"+filepath.Join(b, "site") {
		t.Fatalf("folder server to server: %+v %v", st, err)
	}
	if string(readBytes(t, filepath.Join(b, "site", "css", "a.css"))) != "body{}" {
		t.Error("folder server to server: a file is missing")
	}
	if st, err = remoteCopy(tcl, ctx, web1, bk, filepath.Join(a, "site")+"/", "www/", cpOpts{recursive: true}); err != nil || st.Files != 2 {
		t.Fatalf("folder contents to storage: %+v %v", st, err)
	}
	if bk.b.(*memBucket).objs["www/css/a.css"] != "body{}" {
		t.Errorf("folder contents to storage: %v", bk.b.(*memBucket).objs)
	}
	if st, err = remoteCopy(tcl, ctx, bk, bk2, "www", "", cpOpts{recursive: true}); err != nil || st.Files != 2 || bk2.b.(*memBucket).objs["www/index.html"] != "hello" {
		t.Fatalf("folder storage to storage: %+v %v", st, err)
	}
	out := filepath.Join(b, "from-storage")
	if st, err = remoteCopy(tcl, ctx, bk, web1, "www/", out, cpOpts{recursive: true}); err != nil || st.Files != 2 {
		t.Fatalf("folder storage to server: %+v %v", st, err)
	}
	if string(readBytes(t, filepath.Join(out, "index.html"))) != "hello" {
		t.Error("folder storage to server: a file is missing")
	}

	if _, err := remoteCopy(tcl, ctx, web1, web2, filepath.Join(a, "nope"), b, cpOpts{}); toErr(err).Code != "PATH_NOT_FOUND" {
		t.Errorf("a missing source: %v", err)
	}
	if _, err := remoteCopy(tcl, ctx, web1, web2, filepath.Join(a, "db.sql.gz"), filepath.Join(b, "no", "such", "x"), cpOpts{}); toErr(err).Code != "FOLDER_NOT_FOUND" {
		t.Errorf("a missing folder: %v", err)
	}
	if l := leftovers(t, b); len(l) > 0 {
		t.Errorf("temporary files left: %v", l)
	}
}

// --continue between two remote places: a cut file on a server is
// finished; object storage cannot be added to.
func TestRemoteCopyContinue(t *testing.T) {
	sc := localSFTP(t)
	ctx := context.Background()
	web1 := &copyEnd{host: &store.Host{Name: "web1"}, sc: sc}
	web2 := &copyEnd{host: &store.Host{Name: "web2"}, sc: sc}
	bk := &copyEnd{conn: &store.Conn{Name: "bk"}, b: &memBucket{objs: map[string]string{}}}
	data := payload(90_000)
	a, b := t.TempDir(), t.TempDir()
	src := filepath.Join(a, "big.bin")
	writeFile(t, src, data)
	dst := filepath.Join(b, "big.bin")
	writeFile(t, dst, data[:40_000])
	st, err := remoteCopy(tcl, ctx, web1, web2, src, dst, cpOpts{resume: true})
	if err != nil || st.ContinuedFrom != 40_000 || st.SHA256 != sumOf(data) || !bytes.Equal(readBytes(t, dst), data) {
		t.Fatalf("server to server: %+v %v", st, err)
	}
	bk.b.(*memBucket).objs["big.bin"] = string(data[:10])
	if _, err := remoteCopy(tcl, ctx, web1, bk, src, "big.bin", cpOpts{resume: true}); toErr(err).Code != "RESUME_UNSUPPORTED" {
		t.Errorf("to S3-like storage: %v", err)
	}
	// from storage to a server: read on from the offset
	bk.b.(*memBucket).objs["big.bin"] = string(data)
	writeFile(t, dst, data[:5])
	if st, err = remoteCopy(tcl, ctx, bk, web2, "big.bin", dst, cpOpts{resume: true}); err != nil || st.ContinuedFrom != 5 || !bytes.Equal(readBytes(t, dst), data) {
		t.Fatalf("storage to server: %+v %v", st, err)
	}
}

// The command: storage to storage, with one audit record for the whole
// copy, --progress lines like an upload's, a protected destination that
// asks, and a dry run that names both sides.
func TestRemoteCopyCommand(t *testing.T) {
	invHome(t)
	useFakeClock(t)
	mustRun(t, "conn", "add", "bk", "s3://AKIAEXAMPLE@shop-dev/backups?region=eu-west-1")
	mustRun(t, "conn", "add", "bk2", "s3://AKIAEXAMPLE@shop-dr/backups?region=eu-west-1")
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	one := &memBucket{objs: map[string]string{"db.sql": strings.Repeat("x", 3000)}}
	two := &memBucket{objs: map[string]string{}}
	withBuckets(t, map[string]*memBucket{"bk": one, "bk2": two})

	var d map[string]any
	said := stderrOf(t, func() { d = mustRun(t, "cp", "bk:db.sql", "bk2:2026/", "--progress") })
	wantCounts(t, "cp storage to storage", lastDone(t, progressLines(t, said)), 3000, 3000, 1, 1)
	r := d["results"].([]any)[0].(map[string]any)
	if r["sha256"] != sumOf([]byte(strings.Repeat("x", 3000))) || r["source"] != "bk:db.sql" || r["dest"] != "bk2:2026/db.sql" || r["ok"] != true || r["host"] != "bk2" {
		t.Errorf("result: %v", r)
	}
	if two.objs["2026/db.sql"] != one.objs["db.sql"] {
		t.Error("the copy did not arrive")
	}
	a := mustRun(t, "audit", "--limit", "20")
	n := 0
	for _, e := range a["entries"].([]any) {
		e := e.(map[string]any)
		if e["command"] == "cp" {
			n++
			if e["src"] != "bk:db.sql" || e["dst"] != "bk2:2026/" || e["bytes"].(float64) != 3000 || e["sha256"] == nil {
				t.Errorf("audit: %v", e)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d audit records for one copy", n)
	}

	plan := mustRun(t, "--dry-run", "cp", "web1:/etc/hosts", "bk2:hosts")
	if plan["direction"] != "copy" || plan["src"] != "web1:/etc/hosts" || plan["dst"] != "bk2:hosts" {
		t.Errorf("dry run: %v", plan)
	}

	mustRun(t, "conn", "edit", "bk2", "--protected")
	wantCode(t, "PROTECTED_TARGET", "cp", "bk:db.sql", "bk2:again.sql")
	if _, ok := two.objs["again.sql"]; ok {
		t.Error("a protected conn was written without a yes")
	}

	for _, args := range [][]string{
		{"cp", "bk:db.sql", "bk2:x", "--sudo"},
		{"cp", "bk:db.sql", "bk2:x", "--overwrite"},
		{"cp", "bk:db.sql", "bk2:x", "-p"},
		{"cp", "web1:/a", "web1:/b", "--mode", "99x"},
	} {
		wantCode(t, "USAGE", args...)
	}
	wantCode(t, "PATH_NOT_FOUND", "cp", "bk:nope.sql", "bk:x")
}

// An AI agent copies a file that is a secret by name to another place
// only with the user's yes (--reveal), as it downloads one.
func TestRemoteCopySecretsForAgents(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "bk", "s3://AKIAEXAMPLE@shop-dev/backups?region=eu-west-1")
	one := &memBucket{objs: map[string]string{"app/.env": "DB=x", "app/a.txt": "a"}}
	two := &memBucket{objs: map[string]string{}}
	withBuckets(t, map[string]*memBucket{"bk": one})
	asAgent(t, false, false)
	wantCode(t, "SENSITIVE_FILE", "cp", "bk:app/.env", "bk:copy/.env")
	withBuckets(t, map[string]*memBucket{"bk": one, "bk2": two})
	src := &copyEnd{conn: &store.Conn{Name: "bk"}, b: one}
	dst := &copyEnd{conn: &store.Conn{Name: "bk2"}, b: two}
	st, err := remoteCopy(tcl, context.Background(), src, dst, "app", "", cpOpts{recursive: true})
	if err != nil || st.Files != 1 || two.objs["app/.env"] != "" || two.objs["app/a.txt"] != "a" {
		t.Errorf("folder: %+v %v %v", st, err, two.objs)
	}
}

// A protected server as the destination stops the copy before anything is
// contacted, and its dry run says the flag the real run needs; a protected
// source is only read, so it does not ask.
func TestRemoteCopyProtectedServer(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	mustRun(t, "host", "add", "web2", "u@10.0.0.2")
	mustRun(t, "conn", "add", "bk", "s3://AKIAEXAMPLE@shop-dev/backups?region=eu-west-1")
	one := &memBucket{objs: map[string]string{"db.sql": "x"}}
	withBuckets(t, map[string]*memBucket{"bk": one})
	mustRun(t, "host", "edit", "web2", "--protected")
	// the protected stop (its name is C79's to settle): exit 6, nothing copied
	for _, args := range [][]string{
		{"cp", "web1:/tmp/a", "web2:/tmp/a"},
		{"cp", "bk:db.sql", "web2:/tmp/db.sql", "--continue"},
	} {
		if _, e := invRun(t, args...); e == nil || e.Exit != out.ExitPolicy || !strings.HasPrefix(e.Code, "PROTECTED_") {
			t.Errorf("%v: want the protected stop, got %+v", args, e)
		}
	}
	d := mustRun(t, "cp", "web1:/tmp/a", "web2:/tmp/a", "--dry-run")
	meta, _ := d["_meta"].(map[string]any)
	if need := fmt.Sprint(meta["would_need"]); !strings.Contains(need, "--yes") {
		t.Errorf("dry run: would_need %v (%v)", meta, d)
	}
	// web2 as the source: only read; the copy goes on to bk (its own result)
	d = mustRun(t, "cp", "web2:/tmp/a", "bk:a", "--dry-run")
	if d["src"] != "web2:/tmp/a" || d["dst"] != "bk:a" {
		t.Errorf("a protected source: %v", d)
	}
	if meta, _ := d["_meta"].(map[string]any); meta["would_need"] != nil {
		t.Errorf("a protected source needs nothing: %v", meta)
	}
}

// --continue makes an empty file that is not there yet, like a whole copy.
func TestRemoteCopyContinueAnEmptyFile(t *testing.T) {
	sc := localSFTP(t)
	web1 := &copyEnd{host: &store.Host{Name: "web1"}, sc: sc}
	web2 := &copyEnd{host: &store.Host{Name: "web2"}, sc: sc}
	src := filepath.Join(t.TempDir(), "empty.txt")
	writeFile(t, src, nil)
	dst := filepath.Join(t.TempDir(), "empty.txt")
	st, err := remoteCopy(tcl, context.Background(), web1, web2, src, dst, cpOpts{resume: true})
	if err != nil || st.Bytes != 0 {
		t.Fatalf("an empty file: %+v %v", st, err)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Size() != 0 {
		t.Fatalf("the empty file was not made: %v", err)
	}
}

// fileServerBucket answers Stat for a folder as SFTP, FTP, SMB and WebDAV
// conns do: a usage error, not "not found".
type fileServerBucket struct{ *memBucket }

func (b fileServerBucket) Stat(ctx context.Context, key string) (storex.Object, error) {
	if o, found, _ := b.Lookup(ctx, key); found && o.Dir {
		return storex.Object{}, out.Usage("%q is a folder; give a file, or use -r for everything in it", key)
	}
	return b.memBucket.Stat(ctx, key)
}

// A folder in a file-server conn is a folder to cp -r, with or without a
// slash at its end.
func TestRemoteCopyStatsAFileServerFolder(t *testing.T) {
	e := &copyEnd{conn: &store.Conn{Name: "files"}, b: fileServerBucket{&memBucket{objs: map[string]string{"reports/a.txt": "a", "top.txt": "t"}}}}
	for _, p := range []string{"reports", "reports/"} {
		if s, ok, err := e.stat(context.Background(), p); err != nil || !ok || !s.dir {
			t.Errorf("%q: %+v %v %v, want a folder", p, s, ok, err)
		}
	}
	if s, ok, err := e.stat(context.Background(), "top.txt"); err != nil || !ok || s.dir || s.size != 1 {
		t.Errorf("a file: %+v %v %v", s, ok, err)
	}
	if _, ok, err := e.stat(context.Background(), "nope"); err != nil || ok {
		t.Errorf("nothing there: %v %v", ok, err)
	}
}

// For an AI agent a copy between two remote places is read on its way: a
// file holding a value from komando's vault does not land in another
// place, where a link or another server could show it unhidden.
func TestRemoteCopyStopsAVaultValueForAgents(t *testing.T) {
	saved := tcl.out
	t.Cleanup(func() { tcl.out = saved })
	tcl.out = &out.Printer{Format: "json", W: io.Discard, Mask: true,
		Secrets: func() map[string]string { return map[string]string{"db": "vault-value-77"} }}
	ctx := context.Background()
	one := &memBucket{objs: map[string]string{"app/config.yml": "password: vault-value-77\n", "app/a.txt": "a"}}
	two := &memBucket{objs: map[string]string{}}
	src := &copyEnd{conn: &store.Conn{Name: "bk"}, b: one}
	dst := &copyEnd{conn: &store.Conn{Name: "bk2"}, b: two}
	if _, err := remoteCopy(tcl, ctx, src, dst, "app/config.yml", "x.yml", cpOpts{}); toErr(err).Code != "SENSITIVE_FILE" || len(two.objs) != 0 {
		t.Fatalf("one file: %v %v", err, two.objs)
	}
	st, err := remoteCopy(tcl, ctx, src, dst, "app", "", cpOpts{recursive: true})
	if err != nil || len(st.Errors) != 1 || st.Errors[0].Path != "config.yml" || two.objs["app/a.txt"] != "a" || two.objs["app/config.yml"] != "" {
		t.Fatalf("folder: %+v %v %v", st, err, two.objs)
	}
	// --continue writes in place: the source is read before anything is added
	sc := localSFTP(t)
	web := &copyEnd{host: &store.Host{Name: "web1"}, sc: sc}
	dstFile := filepath.Join(t.TempDir(), "config.yml")
	writeFile(t, dstFile, []byte("pass"))
	if _, err := remoteCopy(tcl, ctx, src, web, "app/config.yml", dstFile, cpOpts{resume: true}); toErr(err).Code != "SENSITIVE_FILE" || string(readBytes(t, dstFile)) != "pass" {
		t.Fatalf("--continue: %v %q", err, readBytes(t, dstFile))
	}
}

// A folder without -r is IS_A_DIRECTORY, as fs cat answers for a folder.
func TestRemoteCopyFolderNeedsR(t *testing.T) {
	one := &memBucket{objs: map[string]string{"app/a.txt": "a"}}
	src := &copyEnd{conn: &store.Conn{Name: "bk"}, b: one}
	dst := &copyEnd{conn: &store.Conn{Name: "bk2"}, b: &memBucket{objs: map[string]string{}}}
	_, err := remoteCopy(tcl, context.Background(), src, dst, "app", "", cpOpts{})
	if e := toErr(err); e.Code != "IS_A_DIRECTORY" || e.Exit != out.ExitUsage || e.Hint != "copy the folder and everything in it with -r: `komando cp -r bk:app bk2:`" {
		t.Fatalf("a folder without -r: %v (exit %d, hint %q)", err, e.Exit, e.Hint)
	}
}
