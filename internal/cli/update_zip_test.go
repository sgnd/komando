package cli

import (
	"archive/zip"
	"bytes"
	"testing"
)

// A Windows release archive is a .zip: komando.exe is taken from it, and
// one without komando.exe is refused.
func TestBinaryFromZip(t *testing.T) {
	mk := func(name string) []byte {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		for _, n := range []string{"LICENSE", name} {
			w, err := zw.Create(n)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte("body of " + n))
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	got, err := binaryFromArchive(mk("komando.exe"))
	if err != nil || string(got) != "body of komando.exe" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := binaryFromArchive(mk("other.exe")); err == nil {
		t.Fatal("an archive without komando.exe was taken")
	}
}
