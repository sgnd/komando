package storex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"

	"github.com/sgnd/komando/internal/driver"
)

// dirFS is a local folder as an smbFS, renaming like SMB does: never over
// an existing file.
type dirFS struct {
	root      string
	failMove  string // Rename to this name fails
	renameErr error
}

func (d dirFS) p(name string) string { return filepath.Join(d.root, filepath.FromSlash(name)) }

func (d dirFS) ReadDir(dir string) ([]os.FileInfo, error) {
	es, err := os.ReadDir(d.p(dir))
	if err != nil {
		return nil, err
	}
	var fis []os.FileInfo
	for i := len(es) - 1; i >= 0; i-- { // out of order, as a server may send them
		fi, _ := es[i].Info()
		fis = append(fis, fi)
	}
	return fis, nil
}
func (d dirFS) Stat(name string) (os.FileInfo, error)      { return os.Stat(d.p(name)) }
func (d dirFS) Open(name string) (io.ReadCloser, error)    { return os.Open(d.p(name)) }
func (d dirFS) Create(name string) (io.WriteCloser, error) { return os.Create(d.p(name)) }
func (d dirFS) MkdirAll(dir string) error                  { return os.MkdirAll(d.p(dir), 0o755) }
func (d dirFS) Remove(name string) error                   { return os.Remove(d.p(name)) }
func (d dirFS) Rename(from, to string) error {
	if to == d.failMove {
		return d.renameErr
	}
	if _, err := os.Stat(d.p(to)); err == nil {
		return os.ErrExist
	}
	return os.Rename(d.p(from), d.p(to))
}

func localSMB(t *testing.T, prefix string) (*smbBucket, *dirFS) {
	t.Helper()
	d := &dirFS{root: t.TempDir()}
	if prefix != "" {
		_ = os.MkdirAll(d.p(prefix), 0o755)
	}
	return &smbBucket{fs: func(context.Context) smbFS { return *d }, prefix: prefix}, d
}

func TestSMBBucket(t *testing.T) {
	ctx := context.Background()
	b, d := localSMB(t, "team/")
	smbSteps(t, ctx, b)
	if _, err := os.Stat(d.p("team/a/deep")); err != nil {
		t.Errorf("the conn's folder is not used: %v", err)
	}
	// replacing a file goes through a moved-aside copy, and leaves no temporary files
	for _, body := range []string{"old", "new"} {
		if err := b.Put(ctx, "a/b.txt", strings.NewReader(body), 3, ""); err != nil {
			t.Fatal(err)
		}
	}
	es, _ := os.ReadDir(d.p("team/a"))
	if len(es) != 2 { // b.txt and deep/
		t.Errorf("left over: %v", es)
	}
	// the new file cannot be renamed in: the old one comes back
	d.failMove, d.renameErr = "team/a/b.txt", errors.New("boom")
	if err := b.Put(ctx, "a/b.txt", strings.NewReader("newer"), 5, ""); code(err) != "STORAGE_ERROR" {
		t.Errorf("failed rename: %v", err)
	}
	if got, _ := os.ReadFile(d.p("team/a/b.txt")); string(got) != "new" {
		t.Errorf("old file not restored: %q", got)
	}
	if err := b.Close(); err != nil {
		t.Error(err)
	}
}

// smbSteps is every Bucket call against a share holding nothing yet.
func smbSteps(t *testing.T, ctx context.Context, b Bucket) {
	t.Helper()
	for key, body := range map[string]string{"a/b.txt": "hello", "a/deep/c.txt": "deep", "top é.txt": "top"} {
		if err := b.Put(ctx, key, strings.NewReader(body), int64(len(body)), "text/plain"); err != nil {
			t.Fatalf("put %s: %v", key, err)
		}
	}
	if err := b.Put(ctx, "a/b.txt", strings.NewReader("hello"), 5, ""); err != nil {
		t.Fatalf("replace: %v", err)
	}
	keys := func(objs []Object) string {
		var k []string
		for _, o := range objs {
			k = append(k, o.Key)
		}
		return strings.Join(k, ",")
	}
	objs, more, err := b.List(ctx, "", false, 0)
	if err != nil || more || keys(objs) != "a/,top é.txt" {
		t.Fatalf("one level: %q %v %v", keys(objs), more, err)
	}
	if !objs[0].Dir || objs[1].Size != 3 || objs[1].Modified.IsZero() {
		t.Errorf("entries: %+v", objs)
	}
	if objs, _, err = b.List(ctx, "a/", true, 0); err != nil || keys(objs) != "a/b.txt,a/deep/,a/deep/c.txt" {
		t.Errorf("recursive: %q %v", keys(objs), err)
	}
	if objs, more, _ = b.List(ctx, "", true, 2); len(objs) != 2 || !more {
		t.Errorf("limit: %v %v", keys(objs), more)
	}
	if _, _, err = b.List(ctx, "nope/", false, 0); code(err) != "FOLDER_NOT_FOUND" {
		t.Errorf("missing folder: %v", err)
	}
	if _, _, err = b.List(ctx, "../x", false, 0); code(err) != "USAGE" {
		t.Errorf("leaving the folder: %v", err)
	}
	if _, _, err = b.List(ctx, `a\..\..\x`, false, 0); code(err) != "USAGE" {
		t.Errorf("leaving the folder with \\: %v", err)
	}
	if _, err := b.Stat(ctx, `a\..\..\x`); code(err) != "USAGE" {
		t.Errorf("stat outside the folder with \\: %v", err)
	}
	var buf bytes.Buffer
	if n, err := b.Get(ctx, "a/deep/c.txt", &buf); err != nil || n != 4 || buf.String() != "deep" {
		t.Errorf("get: %d %q %v", n, buf.String(), err)
	}
	if _, err := b.Get(ctx, "a", &buf); code(err) != "USAGE" {
		t.Errorf("get a folder: %v", err)
	}
	if _, err := b.Get(ctx, "nope.txt", &buf); code(err) != "OBJECT_NOT_FOUND" {
		t.Errorf("get missing: %v", err)
	}
	if o, err := b.Stat(ctx, "a/b.txt"); err != nil || o.Size != 5 || o.Key != "a/b.txt" {
		t.Errorf("stat: %+v %v", o, err)
	}
	if _, err := b.Stat(ctx, "a"); code(err) != "USAGE" {
		t.Errorf("stat a folder: %v", err)
	}
	if ok, err := b.Exists(ctx, "a/b.txt"); !ok || err != nil {
		t.Errorf("exists: %v %v", ok, err)
	}
	if ok, err := b.Exists(ctx, "a/x.txt"); ok || err != nil {
		t.Errorf("exists missing: %v %v", ok, err)
	}
	if err := b.Put(ctx, "a/deep", strings.NewReader("x"), 1, ""); code(err) != "USAGE" {
		t.Errorf("upload over a folder: %v", err)
	}
	if err := b.Remove(ctx, "a/deep"); code(err) != "USAGE" {
		t.Errorf("rm a folder: %v", err)
	}
	for _, k := range []string{"a/b.txt", "a/deep/c.txt", "top é.txt"} {
		if err := b.Remove(ctx, k); err != nil {
			t.Errorf("rm %s: %v", k, err)
		}
	}
	if err := b.Remove(ctx, "a/b.txt"); code(err) != "OBJECT_NOT_FOUND" {
		t.Errorf("rm missing: %v", err)
	}
	if _, err := b.Link(ctx, "x", time.Hour); code(err) != "NOT_SUPPORTED" {
		t.Errorf("link: %v", err)
	}
}

func TestSMBErrors(t *testing.T) {
	tg := driver.Target{User: "alice", Domain: "CORP", Bucket: "team"}
	for err, want := range map[error]string{
		&smb2.ResponseError{Code: ntLogonFailure}:         "STORAGE_AUTH",
		&smb2.ResponseError{Code: ntAccountLocked}:        "STORAGE_AUTH",
		&smb2.ResponseError{Code: ntBadNetworkName}:       "BUCKET_NOT_FOUND",
		&smb2.InvalidResponseError{Message: "guest x"}:    "STORAGE_AUTH",
		&smb2.TransportError{Err: errors.New("EOF")}:      "STORAGE_CONNECT",
		&smb2.ContextError{Err: context.DeadlineExceeded}: "TIMEOUT",
		fmt.Errorf("x: %w", os.ErrPermission):             "STORAGE_AUTH",
		errors.New("strange"):                             "STORAGE_ERROR",
	} {
		if got := code(smbLoginErr(err, tg)); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
	if e := smbLoginErr(&smb2.ResponseError{Code: ntLogonFailure}, tg).Error(); !strings.Contains(e, `CORP\alice`) {
		t.Errorf("login message: %s", e)
	}
	for c, want := range map[uint32]string{
		ntSharingViolation: "STORAGE_ERROR", ntIsADirectory: "USAGE", ntDiskFull: "STORAGE_ERROR",
		ntNameInvalid: "USAGE", ntNotEmpty: "USAGE", 0xC0000001: "STORAGE_ERROR",
	} {
		if got := code(smbErr(&smb2.ResponseError{Code: c})); got != want {
			t.Errorf("%#x: %s, want %s", c, got, want)
		}
	}
	if smbErr(nil) != nil {
		t.Error("nil")
	}
}

func TestOpenSMBUnreachable(t *testing.T) {
	tg, err := driver.Parse("smb://alice@127.0.0.1:1/team")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSMB(context.Background(), tg, "pw", nil, 2*time.Second); code(err) != "STORAGE_CONNECT" {
		t.Errorf("closed port: %v", err)
	}
}

// TestSamba runs the same steps against a real SMB server, when
// KOMANDO_TEST_SMB names one (smb://alice@127.0.0.1:PORT/share/folder) with
// the password in KOMANDO_TEST_SMB_PASSWORD. The e2e lab sets it.
func TestSamba(t *testing.T) {
	raw := os.Getenv("KOMANDO_TEST_SMB")
	if raw == "" {
		t.Skip("KOMANDO_TEST_SMB is not set")
	}
	tg, err := driver.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := OpenSMB(ctx, tg, "wrong", nil, 10*time.Second); code(err) != "STORAGE_AUTH" {
		t.Errorf("wrong password: %v", err)
	}
	bad := tg
	bad.Bucket = "no-such-share"
	if _, err := OpenSMB(ctx, bad, os.Getenv("KOMANDO_TEST_SMB_PASSWORD"), nil, 10*time.Second); code(err) != "BUCKET_NOT_FOUND" {
		t.Errorf("missing share: %v", err)
	}
	b, err := OpenSMB(ctx, tg, os.Getenv("KOMANDO_TEST_SMB_PASSWORD"), nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	smbSteps(t, ctx, b)
	big := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB, several SMB writes
	if err := b.Put(ctx, "big.bin", bytes.NewReader(big), int64(len(big)), ""); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if _, err := b.Get(ctx, "big.bin", &got); err != nil || !bytes.Equal(got.Bytes(), big) {
		t.Errorf("big file: %d bytes, %v", got.Len(), err)
	}
	_ = b.Remove(ctx, "big.bin")
}

type closeCount struct{ n int }

func (c *closeCount) Close() error { c.n++; return nil }

// A server that stops answering at the end cannot keep komando from exiting.
func TestSMBCloseDoesNotHang(t *testing.T) {
	conn := &closeCount{}
	silent := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	done := make(chan error, 1)
	go func() { done <- smbCloser(50*time.Millisecond, conn, silent, silent)() }()
	select {
	case err := <-done:
		if err != nil || conn.n != 1 {
			t.Errorf("close: %v, conn closed %d times", err, conn.n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close waits forever on a silent server")
	}
}
