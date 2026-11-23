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
	if err := os.WriteFile(sums, []byte(releasesig.VersionLine("v0.15.0", "2026-11-20")+"abc  komando_linux_amd64.tar.gz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := releasesig.Keys
	t.Cleanup(func() { releasesig.Keys = saved })

	t.Setenv("RELEASE_SIGNING_KEY", "")
	if err := run([]string{"sign", sums, "v0.15.0"}); err == nil || !strings.Contains(err.Error(), "RELEASE_SIGNING_KEY is empty") {
		t.Errorf("no key: %v", err)
	}
	t.Setenv("RELEASE_SIGNING_KEY", string(priv))
	releasesig.Keys = nil // a komando that would refuse it: nothing is written
	if err := run([]string{"sign", sums, "v0.15.0"}); err == nil || !strings.Contains(err.Error(), "komando would refuse this release") {
		t.Errorf("key not built in: %v", err)
	}
	if _, err := os.Stat(sums + ".sig"); err == nil {
		t.Error("wrote a signature komando refuses")
	}
	releasesig.Keys = []string{pub}
	if err := run([]string{"sign", sums, "v0.15.0"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(sums)
	sig, _ := os.ReadFile(sums + ".sig")
	if err := releasesig.Verify(b, sig); err != nil {
		t.Errorf("the written signature: %v", err)
	}
	// a checksums.txt that names another release, or none, is not signed
	for _, tag := range []string{"v0.16.0"} {
		if err := run([]string{"sign", sums, tag}); err == nil || !strings.Contains(err.Error(), "must name v0.16.0") {
			t.Errorf("signed under another tag: %v", err)
		}
	}
	if err := run([]string{"sign", sums}); err == nil {
		t.Error("sign without a tag worked")
	}
	if err := run([]string{"public", keyFile}); err != nil {
		t.Error(err)
	}
	if err := run([]string{"what", keyFile}); err == nil {
		t.Error("an unknown command worked")
	}
}

// The release workflow adds install.sh to checksums.txt before it signs the
// file, so checksums.txt.sig covers the installer the site pins by hash.
func TestReleaseWorkflowSignsInstallScript(t *testing.T) {
	b, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	wf := string(b)
	add := strings.Index(wf, "sha256sum install.sh >> dist/checksums.txt")
	sign := strings.Index(wf, "go run ./scripts/releasesig sign dist/checksums.txt")
	if add < 0 {
		t.Fatal("release.yml does not add install.sh to dist/checksums.txt")
	}
	if sign < 0 {
		t.Fatal("release.yml no longer signs dist/checksums.txt")
	}
	if add > sign {
		t.Error("release.yml adds install.sh to checksums.txt after it signs it, so the signature would not cover it")
	}
}

// An install.sh line in checksums.txt, after the archives, leaves the version
// line, the signature and the archive lookups as they were.
func TestInstallLineKeepsChecksumsValid(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "release.key")
	if err := run([]string{"new", keyFile}); err != nil {
		t.Fatal(err)
	}
	priv, _ := os.ReadFile(keyFile)
	pub, err := releasesig.PublicOf(string(priv))
	if err != nil {
		t.Fatal(err)
	}
	saved := releasesig.Keys
	t.Cleanup(func() { releasesig.Keys = saved })
	releasesig.Keys = []string{pub}
	t.Setenv("RELEASE_SIGNING_KEY", string(priv))

	sums := filepath.Join(dir, "checksums.txt")
	body := releasesig.VersionLine("v0.18.0", "2026-12-01") +
		"aaaa  komando_linux_amd64.tar.gz\nbbbb  komando_windows_amd64.zip\ncccc  install.sh\n"
	if err := os.WriteFile(sums, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", sums, "v0.18.0"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(sums)
	sig, _ := os.ReadFile(sums + ".sig")
	if err := releasesig.Verify(b, sig); err != nil {
		t.Errorf("signature of checksums.txt with an install.sh line: %v", err)
	}
	if err := releasesig.CheckVersion(b, "v0.18.0"); err != nil {
		t.Errorf("version line: %v", err)
	}
}
