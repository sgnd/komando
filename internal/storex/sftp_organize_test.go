//go:build !windows

package storex

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The organize steps on an SFTP conn, with the in-process SFTP server of
// sftp_put_test.go (a Unix server: these tests are not built on Windows).

// localSFTPBucket is the in-process SFTP server of localSFTP, as an SFTP
// conn whose folder is dir.
func localSFTPBucket(t *testing.T, dir string) Bucket {
	t.Helper()
	return NewSFTP(localSFTP(t), strings.TrimPrefix(filepath.ToSlash(dir), "/")+"/", nil)
}

func TestOrganizeSFTP(t *testing.T) {
	dir := t.TempDir()
	b := localSFTPBucket(t, dir)
	organizeSteps(t, b, false)
	if fi, err := os.Stat(filepath.Join(dir, "new", "deep")); err != nil || !fi.IsDir() {
		t.Errorf("mkdir on the server: %v", err)
	}
}

func TestSFTPChmod(t *testing.T) {
	dir := t.TempDir()
	b := localSFTPBucket(t, dir)
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
