package storex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/storex/ftpfake"
)

func openFake(t *testing.T, s *ftpfake.Server) Bucket {
	t.Helper()
	b, err := OpenFTP(context.Background(), s.Target(), "p", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func errCode(err error) string {
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe.Code
	}
	return fmt.Sprint(err)
}

func TestFTPReconnectsOnceAfterADroppedConnection(t *testing.T) {
	for _, recursive := range []bool{false, true} {
		s := ftpfake.New(t)
		s.Drop = "LIST"
		b := openFake(t, s)
		objs, _, err := b.List(context.Background(), "", recursive, 0)
		if err != nil {
			t.Fatalf("recursive=%v: List after a drop: %v", recursive, err)
		}
		if len(objs) != 1 || objs[0].Key != "obj.txt" {
			t.Fatalf("recursive=%v: List = %+v", recursive, objs)
		}
		if got := s.LoginCount(); got != 2 {
			t.Fatalf("recursive=%v: %d logins, want 2 (one new session)", recursive, got)
		}
	}
}

func TestFTPDoesNotRepeatAfterAnFTPError(t *testing.T) {
	s := ftpfake.New(t)
	s.Reply550 = "LIST"
	b := openFake(t, s)
	if _, _, err := b.List(context.Background(), "", false, 0); err == nil {
		t.Fatal("List with a 550 reply: no error")
	}
	if got := s.LoginCount(); got != 1 {
		t.Fatalf("%d logins after an FTP error reply, want 1 (no new session)", got)
	}
}

func TestFTPGetRepeatsOnlyBeforeAnyByte(t *testing.T) {
	s := ftpfake.New(t)
	s.Drop = "RETR"
	b := openFake(t, s)
	var w bytes.Buffer
	n, err := b.Get(context.Background(), "obj.txt", &w)
	if err != nil || n != 4 || w.String() != "old\n" {
		t.Fatalf("Get after a drop before the data: n=%d %q err=%v", n, w.String(), err)
	}
	if got := s.LoginCount(); got != 2 {
		t.Fatalf("%d logins, want 2", got)
	}
}

// onlyReader hides the Seek of a bytes.Reader: a source that cannot start over.
type onlyReader struct{ io.Reader }

func TestFTPPutRepeatsOnlyWhenTheSourceCanStartOver(t *testing.T) {
	s := ftpfake.New(t)
	s.Drop = "STOR"
	b := openFake(t, s)
	err := b.Put(context.Background(), "obj.txt", onlyReader{strings.NewReader("new\n")}, 4, "")
	if errCode(err) != "STORAGE_CONNECT" {
		t.Fatalf("Put from a pipe after a drop: %v, want STORAGE_CONNECT", err)
	}
	if got := s.LoginCount(); got != 1 {
		t.Fatalf("%d logins for a source that cannot start over, want 1", got)
	}

	s2 := ftpfake.New(t)
	s2.Drop = "STOR"
	b2 := openFake(t, s2)
	if err := b2.Put(context.Background(), "obj.txt", bytes.NewReader([]byte("new\n")), 4, ""); err != nil {
		t.Fatalf("Put from a file after a drop: %v", err)
	}
	s2.Mu.Lock()
	got := string(s2.File)
	s2.Mu.Unlock()
	if got != "new\n" {
		t.Fatalf("server has %q after the repeated upload, want the whole new file", got)
	}
	if n := s2.LoginCount(); n != 2 {
		t.Fatalf("%d logins, want 2", n)
	}
}

func TestFTPRemoveCountsAFirstTryThatWorked(t *testing.T) {
	s := ftpfake.New(t)
	s.Drop = "DELE"
	// the drop happens before the server deletes; remove it by hand to act
	// like a reply lost after the file was gone
	s.Exists = false
	b := openFake(t, s)
	if err := b.Remove(context.Background(), "obj.txt"); err != nil {
		t.Fatalf("Remove whose repeat finds no file: %v, want nil", err)
	}
	if got := s.LoginCount(); got != 2 {
		t.Fatalf("%d logins, want 2", got)
	}
}

// An FTP server sends a folder in any order; storage ls lists it by name,
// each folder's contents right after the folder.
func TestFTPListSortsByName(t *testing.T) {
	s := ftpfake.New(t)
	file := func(name string) string { return "-rw-r--r-- 1 u u 1 Nov 07 12:00 " + name + "\r\n" }
	s.Dirs = map[string]string{
		"/":  file("c.txt") + "drwxr-xr-x 1 u u 0 Nov 07 12:00 b\r\n" + file("a.txt"),
		"/b": file("z") + file("y"),
	}
	b := openFake(t, s)
	keys := func(recursive bool, limit int) (string, bool) {
		objs, more, err := b.List(context.Background(), "", recursive, limit)
		if err != nil {
			t.Fatal(err)
		}
		var k []string
		for _, o := range objs {
			k = append(k, o.Key)
		}
		return strings.Join(k, ","), more
	}
	if got, _ := keys(false, 0); got != "a.txt,b/,c.txt" {
		t.Errorf("one level: %s", got)
	}
	if got, _ := keys(true, 0); got != "a.txt,b/,b/y,b/z,c.txt" {
		t.Errorf("recursive: %s", got)
	}
	if got, more := keys(true, 3); got != "a.txt,b/,b/y" || !more {
		t.Errorf("recursive, limit 3: %s, more %v", got, more)
	}
}

// When the new session cannot be opened either, the error names both: the
// drop, and why logging in again failed.
func TestFTPSaysWhyTheSecondLoginFailed(t *testing.T) {
	s := ftpfake.New(t)
	s.Drop = "LIST"
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		s.Mu.Lock()
		gone := s.Dropped
		s.Mu.Unlock()
		if gone {
			return nil, errors.New("the hop is gone")
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	b, err := OpenFTP(context.Background(), s.Target(), "p", dial, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	_, _, err = b.List(context.Background(), "", false, 0)
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "STORAGE_CONNECT" {
		t.Fatalf("List: %v, want STORAGE_CONNECT", err)
	}
	if !strings.Contains(oe.Message, "EOF") || !strings.Contains(oe.Message, "; logging in again failed: ") || !strings.Contains(oe.Message, "the hop is gone") {
		t.Fatalf("message %q: want the drop and the second login's error", oe.Message)
	}
	if got := s.LoginCount(); got != 1 {
		t.Fatalf("%d logins, want 1", got)
	}
}
