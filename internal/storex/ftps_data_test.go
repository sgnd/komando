package storex

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"testing"
)

// newFakeFTPS is fakeFTP with explicit TLS on the control and data
// connections, with a test certificate (the conn skips verifying it).
func newFakeFTPS(t *testing.T) *fakeFTP {
	t.Helper()
	srv := httptest.NewTLSServer(nil)
	cfg := srv.TLS.Clone()
	srv.Close()
	s := newFakeFTP(t)
	s.tls = &tls.Config{Certificates: cfg.Certificates}
	return s
}

func openFakeFTPS(t *testing.T, s *fakeFTP) Bucket {
	t.Helper()
	tg := s.target()
	tg.Secure, tg.TLS = true, "skip-verify"
	b, err := OpenFTP(context.Background(), tg, "p", nil, 5e9)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

const oneEntry = "-rw-r--r-- 1 u u 4 Nov 07 12:00 keep.txt\r\n"

func TestFTPSListWorks(t *testing.T) {
	s := newFakeFTPS(t)
	s.dirs = map[string]string{"/": oneEntry}
	objs, _, err := openFakeFTPS(t, s).List(context.Background(), "", false, 0)
	if err != nil || len(objs) != 1 || objs[0].Key != "keep.txt" {
		t.Fatalf("got %v, %v; want keep.txt", objs, err)
	}
}

// A listing whose data connection closes before TLS is set up holds no
// entries but is no answer either: komando must not take it as an empty
// folder (sync --delete would then remove that folder's files on the
// other side).
func TestFTPSListCutBeforeTLSIsAnError(t *testing.T) {
	s := newFakeFTPS(t)
	s.dirs = map[string]string{"/": oneEntry}
	s.cutData = "LIST"
	objs, _, err := openFakeFTPS(t, s).List(context.Background(), "", false, 0)
	if err == nil {
		t.Fatalf("got %d objects and no error; want an error", len(objs))
	}
	if got := errCode(err); got != "STORAGE_CONNECT" {
		t.Errorf("code %s (%v); want STORAGE_CONNECT", got, err)
	}
	if !strings.Contains(err.Error(), "LIST") {
		t.Errorf("%q does not name the FTP step (LIST)", err)
	}
}

// Lookup lists the folder: a cut listing is an error, not "not there".
func TestFTPSLookupCutBeforeTLSIsAnError(t *testing.T) {
	s := newFakeFTPS(t)
	s.dirs = map[string]string{"/": oneEntry}
	s.cutData = "LIST"
	b := openFakeFTPS(t, s)
	_, found, err := b.(*ftpReconnect).Lookup(context.Background(), "sub")
	if err == nil {
		t.Fatalf("found=%v and no error; want an error", found)
	}
}

// A dropped connection names the FTP step komando was on.
func TestFTPErrorNamesTheStep(t *testing.T) {
	s := newFakeFTP(t)
	s.drop = "RETR"
	var sb strings.Builder
	_, err := openFake(t, s).(*ftpReconnect).ftpBucket.Get(context.Background(), "obj.txt", &sb)
	if err == nil || !strings.Contains(err.Error(), "RETR") {
		t.Fatalf("%v does not name RETR", err)
	}
}
