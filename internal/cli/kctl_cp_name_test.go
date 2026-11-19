package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// C04: a copy from a pod of a file named like a secret stops before the
// pod is asked for anything, as download stops before it reads (the
// client is nil here: any read from the pod would panic).
func TestPodCopyNameCheckedFirst(t *testing.T) {
	invHome(t)
	asAgent(t, false, false)
	dst := filepath.Join(t.TempDir(), "x")
	for _, src := range []string{"web-1:/srv/app/.env", "shop/web-1:/root/.ssh/id_ed25519"} {
		r := &kctlRun{cl: tcl, ctx: context.Background(), a: kargs{verb: "cp", pos: []string{src, dst}}}
		var err error
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("%s: the pod was read before the name was checked", src)
				}
			}()
			err = r.cp()
		}()
		var ke *kctlError
		if !errors.As(err, &ke) || ke.stop == nil || ke.stop.Code != "SENSITIVE_FILE" {
			t.Errorf("%s: want SENSITIVE_FILE, got %v", src, err)
		}
	}
}

// A tar entry named app/.env/. is written as app/.env: the name check
// reads the cleaned name, the one that is written.
func TestPodCopyNameCleaned(t *testing.T) {
	invHome(t)
	asAgent(t, false, false)
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Name: "app/", Typeflag: tar.TypeDir, Mode: 0o755})
	tw.WriteHeader(&tar.Header{Name: "app/.env/.", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3})
	tw.Write([]byte("A=1"))
	tw.Close()
	dst := t.TempDir()
	err := untarTo(tcl, b.Bytes(), dst, "app")
	var ke *kctlError
	if !errors.As(err, &ke) || ke.stop == nil || ke.stop.Code != "SENSITIVE_FILE" {
		t.Errorf("want SENSITIVE_FILE, got %v", err)
	}
	if ents, _ := os.ReadDir(dst); len(ents) > 0 {
		t.Errorf("wrote %s", ents[0].Name())
	}
}
