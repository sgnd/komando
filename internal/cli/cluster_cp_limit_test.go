package cli

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The files of a copy together stay under the cap, whatever the stream's
// own size was.
func TestClusterCpTotalCap(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755})
	for _, n := range []string{"d/a", "d/b", "d/c"} {
		tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: 400})
		tw.Write(bytes.Repeat([]byte("x"), 400))
	}
	tw.Close()
	dst := filepath.Join(t.TempDir(), "out")
	err := untarLimit(tcl, b.Bytes(), dst, "d", 1000)
	var ke *kctlError
	if !errors.As(err, &ke) || ke.stop == nil || ke.stop.Code != "FILE_TOO_LARGE" {
		t.Fatalf("want FILE_TOO_LARGE, got %v", err)
	}
	if _, serr := os.Stat(dst); serr == nil {
		t.Error("something was written before the stop")
	}
	if err := untarLimit(tcl, b.Bytes(), dst, "d", 1200); err != nil {
		t.Fatalf("1200 bytes fit: %v", err)
	}
}
