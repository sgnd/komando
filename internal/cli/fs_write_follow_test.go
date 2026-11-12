//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runFollow runs sudoFollowScript for p with a stat stand-in that says
// root owns everything but the paths in notRoot. It prints the path root
// would write, or exits 95.
func runFollow(t *testing.T, p string, notRoot ...string) (string, int) {
	t.Helper()
	bin := t.TempDir()
	stat := "#!/bin/sh\nfor a; do f=$a; done\ncase \" $NOTROOT \" in *\" $f \"*) echo 1000;; *) echo 0;; esac\n"
	if err := os.WriteFile(filepath.Join(bin, "stat"), []byte(stat), 0o700); err != nil {
		t.Fatal(err)
	}
	c := exec.Command("/bin/sh", "-c", "p='"+p+"'; "+sudoFollowScript("/nonexistent")+`echo "$p"`)
	c.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "NOTROOT=" + strings.Join(notRoot, " ")}
	b, err := c.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b)), code
}

func TestSudoFollowOnlyRootsLinks(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	target := filepath.Join(d, "sites-available", "app")
	_ = os.MkdirAll(filepath.Dir(target), 0o755)
	_ = os.WriteFile(target, []byte("x"), 0o644)
	link := filepath.Join(d, "app.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	// root's link into root's folder: followed
	if got, code := runFollow(t, link); code != 0 || got != target {
		t.Fatalf("root's link: %q %d", got, code)
	}
	// a link another user made (an app's .env -> /etc/sudoers.d/x): stop
	if got, code := runFollow(t, link, link); code != 95 {
		t.Fatalf("another user's link followed: %q %d", got, code)
	}
	// root's link into a folder another user owns: stop
	if got, code := runFollow(t, link, filepath.Dir(target)); code != 95 {
		t.Fatalf("followed into another user's folder: %q %d", got, code)
	}
	// no link: unchanged
	if got, code := runFollow(t, target); code != 0 || got != target {
		t.Fatalf("plain file: %q %d", got, code)
	}
}
