package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// O11: an upload over a file that is there keeps that file's mode (a 0600
// .env stays 0600) unless --mode says otherwise; a new file gets the
// local file's mode.
func TestUploadKeepsTheRemoteMode(t *testing.T) {
	sc := localSFTP(t)
	local, remote := t.TempDir(), t.TempDir()
	src := filepath.Join(local, "app.env")
	if err := os.WriteFile(src, []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(remote, ".env")
	if err := os.WriteFile(dst, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := upload(ctx, nil, sc, src, dst, cpOpts{}); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, dst); m != 0o600 || read(t, dst) != "A=1\n" {
		t.Fatalf("existing file: mode %04o", m)
	}
	if _, err := upload(ctx, nil, sc, src, filepath.Join(remote, "new.env"), cpOpts{}); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, filepath.Join(remote, "new.env")); m != 0o644 {
		t.Fatalf("new file: mode %04o", m)
	}
	if _, err := upload(ctx, nil, sc, src, dst, cpOpts{mode: "0640"}); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, dst); m != 0o640 {
		t.Fatalf("--mode: %04o", m)
	}

	// a folder upload: the same for each file
	tree := filepath.Join(local, "conf")
	_ = os.MkdirAll(tree, 0o755)
	_ = os.WriteFile(filepath.Join(tree, "secret.yml"), []byte("x\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tree, "plain.yml"), []byte("y\n"), 0o644)
	into := filepath.Join(remote, "conf")
	_ = os.MkdirAll(into, 0o755)
	_ = os.WriteFile(filepath.Join(into, "secret.yml"), []byte("old\n"), 0o600)
	if _, err := upload(ctx, nil, sc, tree+"/", into, cpOpts{recursive: true}); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, filepath.Join(into, "secret.yml")); m != 0o600 {
		t.Fatalf("folder upload, existing file: mode %04o", m)
	}
	if m := mode(t, filepath.Join(into, "plain.yml")); m != 0o644 {
		t.Fatalf("folder upload, new file: mode %04o", m)
	}
}
