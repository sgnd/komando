package storex

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// organizeSteps runs mkdir and mv the same way on every kind of storage:
// a file server renames (folders too), an object store copies, checks and
// deletes, and refuses to move a folder.
func organizeSteps(t *testing.T, b Bucket, objectStore bool) {
	t.Helper()
	ctx := context.Background()
	for key, body := range map[string]string{"a.txt": "aaa", "dir/b.txt": "bb", "dir/sub/c.txt": "c", "other.txt": "o"} {
		if err := b.Put(ctx, key, strings.NewReader(body), int64(len(body)), ""); err != nil {
			t.Fatalf("put %s: %v", key, err)
		}
	}
	get := func(key string) string {
		var buf bytes.Buffer
		if _, err := b.Get(ctx, key, &buf); err != nil {
			return "error: " + code(err)
		}
		return buf.String()
	}
	there := func(key string) bool {
		_, found, err := b.Lookup(ctx, key)
		if err != nil {
			t.Fatalf("lookup %s: %v", key, err)
		}
		return found
	}

	// Lookup
	if o, found, err := b.Lookup(ctx, "a.txt"); err != nil || !found || o.Dir || o.Size != 3 || o.Key != "a.txt" {
		t.Errorf("lookup a file: %+v %v %v", o, found, err)
	}
	for _, k := range []string{"dir", "dir/", "/dir/sub"} {
		if o, found, err := b.Lookup(ctx, k); err != nil || !found || !o.Dir || !strings.HasSuffix(o.Key, "/") {
			t.Errorf("lookup the folder %s: %+v %v %v", k, o, found, err)
		}
	}
	if _, found, err := b.Lookup(ctx, "nope/x.txt"); found || err != nil {
		t.Errorf("lookup nothing: %v %v", found, err)
	}
	if _, _, err := b.Lookup(ctx, "../x"); code(err) != "USAGE" {
		t.Errorf("lookup outside the folder: %v", err)
	}

	// Mkdir
	if existed, err := b.Mkdir(ctx, "new/deep/"); existed || err != nil {
		t.Fatalf("mkdir: %v %v", existed, err)
	}
	if o, found, _ := b.Lookup(ctx, "new/deep"); !found || !o.Dir {
		t.Errorf("after mkdir: %+v %v", o, found)
	}
	if objs, _, err := b.List(ctx, "new/", false, 0); err != nil || len(objs) != 1 || objs[0].Key != "new/deep/" || !objs[0].Dir {
		t.Errorf("the new folder lists as a folder: %+v %v", objs, err)
	}
	if objs, _, err := b.List(ctx, "new/deep/", false, 0); err != nil || len(objs) != 0 {
		t.Errorf("an empty folder lists nothing: %+v %v", objs, err)
	}
	if existed, err := b.Mkdir(ctx, "new/deep"); !existed || err != nil {
		t.Errorf("mkdir again: %v %v", existed, err)
	}
	if existed, err := b.Mkdir(ctx, "dir"); !existed || err != nil {
		t.Errorf("mkdir of a folder with files: %v %v", existed, err)
	}
	if _, err := b.Mkdir(ctx, "a.txt"); code(err) != "OBJECT_EXISTS" {
		t.Errorf("mkdir over a file: %v", err)
	}
	for _, bad := range []string{"", "/", "../up", `a\..\..\x`} {
		if _, err := b.Mkdir(ctx, bad); code(err) != "USAGE" {
			t.Errorf("mkdir %q: %v", bad, err)
		}
	}

	// Move a file, into a folder that does not exist yet
	m, err := b.Move(ctx, "a.txt", "moved/a2.txt", MoveOpts{})
	if err != nil || m.Folder || m.Replaced || m.Size != 3 || m.Copied != objectStore {
		t.Fatalf("move: %+v %v", m, err)
	}
	if there("a.txt") || get("moved/a2.txt") != "aaa" {
		t.Errorf("after the move: a.txt there %v, moved/a2.txt %q", there("a.txt"), get("moved/a2.txt"))
	}

	// an existing file stops it, unless --overwrite; a dry run changes nothing
	if _, err := b.Move(ctx, "other.txt", "dir/b.txt", MoveOpts{}); code(err) != "OBJECT_EXISTS" {
		t.Errorf("over a file: %v", err)
	}
	if m, err := b.Move(ctx, "other.txt", "dir/b.txt", MoveOpts{Overwrite: true, DryRun: true}); err != nil || !m.Replaced || get("dir/b.txt") != "bb" || !there("other.txt") {
		t.Errorf("dry run: %+v %v", m, err)
	}
	if m, err := b.Move(ctx, "other.txt", "dir/b.txt", MoveOpts{Overwrite: true}); err != nil || !m.Replaced || get("dir/b.txt") != "o" || there("other.txt") {
		t.Errorf("--overwrite: %+v %v %q", m, err, get("dir/b.txt"))
	}

	for _, c := range []struct{ src, dst, want string }{
		{"nope.txt", "x.txt", "OBJECT_NOT_FOUND"},
		{"moved/a2.txt", "dir", "OBJECT_EXISTS"},      // a folder is never replaced
		{"moved/a2.txt", "moved/a2.txt", "USAGE"},     // the same
		{"moved/a2.txt", "../a.txt", "USAGE"},         // out of the folder
		{"dir", "dir/sub/x", "USAGE"},                 // into itself
		{"moved/a2.txt", "new/deep", "OBJECT_EXISTS"}, // an empty folder too
	} {
		if _, err := b.Move(ctx, c.src, c.dst, MoveOpts{Overwrite: true}); code(err) != c.want {
			t.Errorf("mv %s %s: %v, want %s", c.src, c.dst, err, c.want)
		}
	}

	// a folder: renamed on a file server, refused on an object store
	m, err = b.Move(ctx, "dir", "dir2", MoveOpts{})
	if objectStore {
		if code(err) != "STORAGE_UNSUPPORTED" || !there("dir/sub/c.txt") {
			t.Errorf("a folder on an object store: %v", err)
		}
		return
	}
	if err != nil || !m.Folder || get("dir2/sub/c.txt") != "c" || there("dir") {
		t.Errorf("a folder: %+v %v", m, err)
	}
	if _, err := b.Move(ctx, "dir2", "moved/a2.txt", MoveOpts{Overwrite: true}); code(err) != "OBJECT_EXISTS" {
		t.Errorf("a folder over a file: %v", err)
	}
}

func TestOrganizeS3(t *testing.T) {
	b, f := openFakeS3(t)
	organizeSteps(t, b, true)
	if _, ok := f.objs["site/new/deep/"]; !ok {
		t.Errorf("mkdir makes a folder marker under the conn's folder: %v", keysOf(f.objs))
	}
	if f.copies == 0 {
		t.Error("the move was not a copy on the server")
	}
}

func keysOf[V any](m map[string]V) []string {
	var k []string
	for key := range m {
		k = append(k, key)
	}
	return k
}

func TestOrganizeGCS(t *testing.T) {
	withGCSLogin(t)
	f := &fakeGCS{objs: map[string][]byte{}, steps: 2}
	srv := httptest.NewServer(f)
	defer srv.Close()
	tg, _ := driver.Parse("gs://media/site?endpoint=" + srv.URL)
	b, err := OpenGCS(context.Background(), tg, "", nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	organizeSteps(t, b, true)
	if _, ok := f.objs["site/new/deep/"]; !ok || f.rewrites == 0 {
		t.Errorf("marker and rewrite: %v, %d rewrites", keysOf(f.objs), f.rewrites)
	}
	// the copy itself refuses an object that appeared after the check
	f.objs["site/x"], f.objs["site/y"] = []byte("x"), []byte("y")
	if err := b.(*gcsBucket).copyObject(context.Background(), "x", "y", false); code(err) != "OBJECT_EXISTS" {
		t.Errorf("rewrite over an object: %v", err)
	}
}

func TestOrganizeAzure(t *testing.T) {
	f := &fakeAzure{blobs: map[string][]byte{}, blocks: map[string][]byte{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	tg, _ := driver.Parse("azblob://acct@media/site?endpoint=" + srv.URL)
	b, err := OpenAzure(tg, azuriteKey, nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	saved := azCopyWait
	azCopyWait = time.Millisecond
	defer func() { azCopyWait = saved }()
	organizeSteps(t, b, true)
	if _, ok := f.blobs["site/new/deep/"]; !ok || f.copies == 0 {
		t.Errorf("marker and copy: %v, %d copies", keysOf(f.blobs), f.copies)
	}
	// a copy the service finishes later is waited for
	f.blobs["site/p.txt"] = []byte("later")
	f.pending = 2
	if _, err := b.Move(context.Background(), "p.txt", "q.txt", MoveOpts{}); err != nil || string(f.blobs["site/q.txt"]) != "later" || f.blobs["site/p.txt"] != nil {
		t.Errorf("a pending copy: %v %v", err, keysOf(f.blobs))
	}
	f.blobs["site/x"], f.blobs["site/y"] = []byte("x"), []byte("y")
	if err := b.(*azBucket).copyObject(context.Background(), "x", "y", false); code(err) != "OBJECT_EXISTS" {
		t.Errorf("copy over a blob: %v", err)
	}
}

func TestOrganizeWebDAV(t *testing.T) {
	organizeSteps(t, openDav(t, davServer(t), "pw"), false)
}

func TestOrganizeSMB(t *testing.T) {
	b, _ := localSMB(t, "team/")
	organizeSteps(t, b, false)
}

// SMB never renames over a file: --overwrite moves the old one aside and
// puts it back when the rename fails.
func TestSMBMoveOverwriteKeepsTheOldFileOnFailure(t *testing.T) {
	ctx := context.Background()
	b, d := localSMB(t, "")
	for k, v := range map[string]string{"a.txt": "new", "b.txt": "old"} {
		if err := b.Put(ctx, k, strings.NewReader(v), 3, ""); err != nil {
			t.Fatal(err)
		}
	}
	once := 1
	d.failMove, d.renameErr, d.failLeft = "b.txt", errors.New("boom"), &once
	if _, err := b.Move(ctx, "a.txt", "b.txt", MoveOpts{Overwrite: true}); err == nil {
		t.Fatal("a failed rename succeeded")
	}
	got, _ := os.ReadFile(d.p("b.txt"))
	src, _ := os.ReadFile(d.p("a.txt"))
	if string(got) != "old" || string(src) != "new" {
		t.Errorf("after a failed move: b.txt %q, a.txt %q", got, src)
	}
	if es, _ := os.ReadDir(d.root); len(es) != 2 {
		t.Errorf("left over: %v", es)
	}
	// the old file cannot go back either: the error says where it is
	twice := 2
	d.failLeft = &twice
	_, err := b.Move(ctx, "a.txt", "b.txt", MoveOpts{Overwrite: true})
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "MOVE_FAILED" || !strings.Contains(oe.Hint, "komando storage mv CONN .komando-old-b.txt b.txt") {
		t.Errorf("both renames fail: %v", err)
	}
	if got, _ := os.ReadFile(d.p(".komando-old-b.txt")); string(got) != "old" {
		t.Errorf("the old file is kept aside: %q", got)
	}
}

func TestOrganizeFTP(t *testing.T) {
	s := newDirFTP(t)
	if err := os.MkdirAll(filepath.Join(s.root, "site"), 0o755); err != nil {
		t.Fatal(err)
	}
	organizeSteps(t, s.open(t), false)
	if _, err := os.Stat(filepath.Join(s.root, "site", "new", "deep")); err != nil {
		t.Errorf("mkdir on the server: %v", err)
	}
}

// localSFTP is an SFTP server in this process over pipes, serving the
// local file system, as an SFTP conn whose folder is dir.
func localSFTP(t *testing.T, dir string) Bucket {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a local SFTP server stands in for a Unix server")
	}
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	srv, err := sftp.NewServer(struct {
		io.Reader
		io.WriteCloser
	}{sr, sw})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	sc, err := sftp.NewClientPipe(cr, cw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cw.Close(); sw.Close(); sc.Close(); srv.Close() })
	return NewSFTP(sc, strings.TrimPrefix(filepath.ToSlash(dir), "/")+"/", nil)
}

func TestOrganizeSFTP(t *testing.T) {
	dir := t.TempDir()
	b := localSFTP(t, dir)
	organizeSteps(t, b, false)
	if fi, err := os.Stat(filepath.Join(dir, "new", "deep")); err != nil || !fi.IsDir() {
		t.Errorf("mkdir on the server: %v", err)
	}
}

func TestSFTPChmod(t *testing.T) {
	dir := t.TempDir()
	b := localSFTP(t, dir)
	ctx := context.Background()
	if err := b.Put(ctx, "app/config.yml", strings.NewReader("x"), 1, ""); err != nil {
		t.Fatal(err)
	}
	m, ok := b.(Modes)
	if !ok {
		t.Fatal("an SFTP conn has no modes")
	}
	if mode, err := m.Mode(ctx, "app/config.yml"); err != nil || mode.Perm() != 0o644 {
		t.Errorf("mode: %v %v", mode, err)
	}
	if err := m.Chmod(ctx, "app/config.yml", 0o640); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "app", "config.yml")); fi.Mode().Perm() != 0o640 {
		t.Errorf("after chmod: %v", fi.Mode())
	}
	if err := m.Chmod(ctx, "app", 0o750|fs.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if mode, _ := m.Mode(ctx, "app"); mode.Perm() != 0o750 || mode&fs.ModeSetgid == 0 || !mode.IsDir() {
		t.Errorf("a folder with setgid: %v", mode)
	}
	if err := m.Chmod(ctx, "nope", 0o600); code(err) != "OBJECT_NOT_FOUND" {
		t.Errorf("chmod of nothing: %v", err)
	}
	if _, err := m.Mode(ctx, "../x"); code(err) != "USAGE" {
		t.Errorf("outside the folder: %v", err)
	}
	for _, other := range []Bucket{&s3Bucket{}, &gcsBucket{}, &azBucket{}, &davBucket{}, &ftpBucket{}, &smbBucket{}} {
		if _, ok := other.(Modes); ok {
			t.Errorf("%T has modes", other)
		}
	}
}

// fakeCopier is an object store in memory, for what copyMove does when
// the copy or the delete goes wrong.
type fakeCopier struct {
	objs    map[string]string
	badCopy bool
	denyDel bool
}

func (f *fakeCopier) Lookup(_ context.Context, rel string) (Object, bool, error) {
	v, ok := f.objs[strings.Trim(rel, "/")]
	return Object{Key: rel, Size: int64(len(v))}, ok, nil
}

func (f *fakeCopier) Remove(_ context.Context, key string) error {
	if f.denyDel && key == "src" {
		return out.Errf(out.ExitConnect, "STORAGE_AUTH", "", "AccessDenied")
	}
	delete(f.objs, key)
	return nil
}

func (f *fakeCopier) copyObject(_ context.Context, src, dst string, _ bool) error {
	v := f.objs[src]
	if f.badCopy {
		v = v[1:]
	}
	f.objs[dst] = v
	return nil
}

func (f *fakeCopier) fingerprint(_ context.Context, rel string) (int64, string, error) {
	v, ok := f.objs[rel]
	if !ok {
		return 0, "", NotThere(rel)
	}
	return int64(len(v)), "sum:" + v, nil
}

// The source is deleted only after the copy is checked; a copy that does
// not match is deleted and the source kept.
func TestCopyMoveDeletesOnlyAfterTheCheck(t *testing.T) {
	ctx := context.Background()
	f := &fakeCopier{objs: map[string]string{"src": "data"}, badCopy: true}
	_, err := copyMove(ctx, f, "src", "dst", MoveOpts{}, "S3")
	if code(err) != "MOVE_FAILED" || f.objs["src"] != "data" || len(f.objs) != 1 || !strings.Contains(err.Error(), `"src" was kept`) {
		t.Errorf("a bad copy: %v %v", err, f.objs)
	}
	f = &fakeCopier{objs: map[string]string{"src": "data"}, denyDel: true}
	_, err = copyMove(ctx, f, "src", "dst", MoveOpts{}, "S3")
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "MOVE_FAILED" || f.objs["src"] != "data" || f.objs["dst"] != "data" || !strings.Contains(oe.Hint, "komando storage rm CONN src") {
		t.Errorf("a delete that fails: %v %v", err, f.objs)
	}
	f = &fakeCopier{objs: map[string]string{"src": "data"}}
	if m, err := copyMove(ctx, f, "src", "dst", MoveOpts{DryRun: true}, "S3"); err != nil || !m.Copied || len(f.objs) != 1 {
		t.Errorf("a dry run: %+v %v %v", m, err, f.objs)
	}
}

// A bad copy on a real S3 API: caught by the size, the source stays.
func TestS3MoveChecksTheCopy(t *testing.T) {
	b, f := openFakeS3(t)
	ctx := context.Background()
	if err := b.Put(ctx, "a.txt", strings.NewReader("abc"), 3, ""); err != nil {
		t.Fatal(err)
	}
	f.badCopy = true
	if _, err := b.Move(ctx, "a.txt", "b.txt", MoveOpts{}); code(err) != "MOVE_FAILED" {
		t.Errorf("a bad copy: %v", err)
	}
	if _, ok := f.objs["site/a.txt"]; !ok || f.objs["site/b.txt"] != nil {
		t.Errorf("after a bad copy: %v", keysOf(f.objs))
	}
	f.badCopy, f.denyDel = false, true
	if _, err := b.Move(ctx, "a.txt", "b.txt", MoveOpts{}); code(err) != "MOVE_FAILED" {
		t.Errorf("a delete that fails: %v", err)
	}
	if len(f.objs) != 2 {
		t.Errorf("both stay: %v", keysOf(f.objs))
	}
}

func TestArg(t *testing.T) {
	for in, want := range map[string]string{"a/b.txt": "a/b.txt", "c d.txt": "'c d.txt'", "it's": `'it'\''s'`} {
		if got := arg(in); got != want {
			t.Errorf("arg(%q) = %s", in, got)
		}
	}
}
