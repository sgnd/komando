package rundir

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDirIsMadePrivate(t *testing.T) {
	base := filepath.Join(t.TempDir(), "run")
	saved := Base
	Base = func() (string, error) { return base, nil }
	t.Cleanup(func() { Base = saved })
	d, err := Dir()
	if err != nil || d != base {
		t.Fatalf("Dir: %q, %v", d, err)
	}
	fi, err := os.Lstat(d)
	if err != nil || !fi.IsDir() {
		t.Fatalf("no folder: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
		t.Errorf("mode %o, want 700", fi.Mode().Perm())
	}
}

func TestDirRefusesALinkOrAWideMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the folder is in the user's own LocalAppData")
	}
	root := t.TempDir()
	real := filepath.Join(root, "real")
	os.Mkdir(real, 0o700)
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	wide := filepath.Join(root, "wide")
	os.Mkdir(wide, 0o700)
	os.Chmod(wide, 0o755)
	saved := Base
	t.Cleanup(func() { Base = saved })
	for name, p := range map[string]string{"symlink": link, "mode 755": wide} {
		Base = func() (string, error) { return p, nil }
		if _, err := Dir(); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
}

func TestCreateIsExclusiveAndPrivate(t *testing.T) {
	dir := t.TempDir()
	f, err := Create(dir, "restore")
	if err != nil || f == nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()
	n := filepath.Base(f.Name())
	if filepath.Dir(f.Name()) != dir || !strings.HasPrefix(n, "restore-") || !strings.HasSuffix(n, ".tmp") {
		t.Errorf("name %s", f.Name())
	}
	fi, _ := os.Lstat(f.Name())
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %o, want 600", fi.Mode().Perm())
	}
	// O_EXCL: a name that exists (a planted link) is never opened
	if _, err := create(f.Name()); err == nil {
		t.Error("an existing name was opened")
	}
}

func TestSweepRemovesOldLeftovers(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "restore-abc.tmp")
	fresh := filepath.Join(dir, "restore-def.tmp")
	other := filepath.Join(dir, "keep.tmp")
	for _, p := range []string{old, fresh, other} {
		os.WriteFile(p, nil, 0o600)
	}
	past := timeAgo(2 * Stale)
	os.Chtimes(old, past, past)
	os.Chtimes(other, past, past)
	Sweep(dir, "restore")
	if _, err := os.Lstat(old); err == nil {
		t.Error("the old leftover stayed")
	}
	for _, p := range []string{fresh, other} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was removed", p)
		}
	}
}

func timeAgo(d time.Duration) time.Time { return time.Now().Add(-d) }
