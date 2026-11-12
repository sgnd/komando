package storex

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sgnd/komando/internal/driver"
)

func TestCtxReaderStopsAndKeepsSize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, _ = f.Seek(30, io.SeekStart)
	ctx, cancel := context.WithCancel(context.Background())
	r := CtxReader(ctx, f)
	s, ok := r.(interface{ Size() int64 })
	if !ok || s.Size() != 70 {
		t.Fatalf("size: %v %v", ok, s)
	}
	buf := make([]byte, 10)
	if n, err := r.Read(buf); n != 10 || err != nil {
		t.Fatalf("read %d %v", n, err)
	}
	cancel()
	if _, err := r.Read(buf); !errors.Is(err, context.Canceled) {
		t.Errorf("after cancel: %v", err)
	}
	if _, ok := CtxReader(ctx, bytes.NewReader(nil)).(interface{ Size() int64 }); ok {
		t.Error("a reader of unknown size says a size")
	}
}

func TestCtxWriterStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var b bytes.Buffer
	w := CtxWriter(ctx, &b)
	if _, err := w.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := w.Write([]byte("b")); !errors.Is(err, context.Canceled) || b.String() != "a" {
		t.Errorf("after cancel: %v %q", err, b.String())
	}
}

// the drivers' error mapping lets Ctrl-C through, so komando says
// CANCELLED and not STORAGE_ERROR
func TestDriverErrorsKeepCancel(t *testing.T) {
	for name, fn := range map[string]func(error) error{
		"sftp": sftpErr,
		"smb":  smbErr,
		"web":  func(err error) error { return webErr("webdav", nil, err) },
		"ftp":  func(err error) error { return ftpErr(err, driver.Target{}) },
	} {
		if err := fn(context.Canceled); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
