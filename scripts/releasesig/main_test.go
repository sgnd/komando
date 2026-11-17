package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/releasesig"
)

func TestNewSignAndCheck(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "release.key")
	if err := run([]string{"new", keyFile}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v, want 0600", fi.Mode().Perm())
	}
	if err := run([]string{"new", keyFile}); err == nil {
		t.Error("new wrote over an existing key")
	}
	priv, _ := os.ReadFile(keyFile)
	pub, err := releasesig.PublicOf(string(priv))
	if err != nil {
		t.Fatal(err)
	}

	sums := filepath.Join(dir, "checksums.txt")
	if err := os.WriteFile(sums, []byte("abc  komando_linux_amd64.tar.gz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := releasesig.Keys
	t.Cleanup(func() { releasesig.Keys = saved })

	t.Setenv("RELEASE_SIGNING_KEY", "")
	if err := run([]string{"sign", sums}); err == nil || !strings.Contains(err.Error(), "RELEASE_SIGNING_KEY is empty") {
		t.Errorf("no key: %v", err)
	}
	t.Setenv("RELEASE_SIGNING_KEY", string(priv))
	releasesig.Keys = nil // a komando that would refuse it: nothing is written
	if err := run([]string{"sign", sums}); err == nil || !strings.Contains(err.Error(), "komando would refuse this release") {
		t.Errorf("key not built in: %v", err)
	}
	if _, err := os.Stat(sums + ".sig"); err == nil {
		t.Error("wrote a signature komando refuses")
	}
	releasesig.Keys = []string{pub}
	if err := run([]string{"sign", sums}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(sums)
	sig, _ := os.ReadFile(sums + ".sig")
	if err := releasesig.Verify(b, sig); err != nil {
		t.Errorf("the written signature: %v", err)
	}
	if err := run([]string{"public", keyFile}); err != nil {
		t.Error(err)
	}
	if err := run([]string{"what", keyFile}); err == nil {
		t.Error("an unknown command worked")
	}
}
