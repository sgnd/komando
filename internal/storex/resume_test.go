package storex

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --continue on a file server conn: Append adds the rest to a cut file,
// refuses a file of another length (FILE_CHANGED) and makes a new one
// from nothing; GetFrom reads on from an offset. FTP, SMB and SFTP
// (sftp_organize_test.go) can; object stores and WebDAV cannot (CanAppend
// false).
func TestAppendOnFileServers(t *testing.T) {
	ftp := newDirFTP(t)
	if err := os.MkdirAll(filepath.Join(ftp.root, "site"), 0o755); err != nil {
		t.Fatal(err)
	}
	smb, _ := localSMB(t, "")
	for name, b := range map[string]Bucket{
		"ftp": ftp.open(t),
		"smb": smb,
	} {
		appendSteps(t, name, b)
	}
	for _, b := range []Bucket{&s3Bucket{}, &gcsBucket{}, &azBucket{}, &davBucket{}} {
		if CanAppend(b) {
			t.Errorf("%T can append", b)
		}
	}
}

// appendSteps runs Append and GetFrom against b, a conn that can append.
func appendSteps(t *testing.T, name string, b Bucket) {
	t.Helper()
	ctx := context.Background()
	if !CanAppend(b) {
		t.Fatalf("%s: cannot append", name)
	}
	if err := b.Put(ctx, "dir/big.bin", strings.NewReader("hello "), 6, ""); err != nil {
		t.Fatalf("%s: put: %v", name, err)
	}
	if _, err := Append(ctx, b, "dir/big.bin", 3, strings.NewReader("x")); code(err) != "FILE_CHANGED" {
		t.Errorf("%s: a file of another length: %v", name, err)
	}
	if n, err := Append(ctx, b, "dir/big.bin", 6, strings.NewReader("world")); err != nil || n != 5 {
		t.Fatalf("%s: append: %d %v", name, n, err)
	}
	var buf bytes.Buffer
	if _, err := b.Get(ctx, "dir/big.bin", &buf); err != nil || buf.String() != "hello world" {
		t.Errorf("%s: after append: %q %v", name, buf.String(), err)
	}
	buf.Reset()
	if n, err := GetFrom(ctx, b, "dir/big.bin", 6, &buf); err != nil || n != 5 || buf.String() != "world" {
		t.Errorf("%s: get from 6: %d %q %v", name, n, buf.String(), err)
	}
	if _, err := Append(ctx, b, "new/one.bin", 0, strings.NewReader("abc")); err != nil {
		t.Fatalf("%s: a new file: %v", name, err)
	}
	buf.Reset()
	if _, err := b.Get(ctx, "new/one.bin", &buf); err != nil || buf.String() != "abc" {
		t.Errorf("%s: the new file: %q %v", name, buf.String(), err)
	}
	if _, err := Append(ctx, b, "../x", 0, strings.NewReader("a")); code(err) != "USAGE" {
		t.Errorf("%s: outside the folder: %v", name, err)
	}
}
