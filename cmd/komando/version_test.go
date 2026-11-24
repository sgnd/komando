package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

var versionFlag = regexp.MustCompile(`-X (github\.com/sgnd/komando/\S+)\.Version=\$\(VERSION\)`)

// The Makefile stamps releases with -X <package>.Version. The linker
// ignores -X for a variable that does not exist, so a stale path would
// ship every release as "dev": build with the Makefile's path and look
// for the stamped value in the binary. The binary is not run: under an
// AI agent it would use the real home folder.
func TestMakefileStampsVersion(t *testing.T) {
	mk, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	m := versionFlag.FindSubmatch(mk)
	if m == nil {
		t.Fatalf("the Makefile's LDFLAGS has no -X github.com/sgnd/komando/<package>.Version=$(VERSION)")
	}
	const stamp = "v9.8.7-stamp-c396"
	bin := filepath.Join(t.TempDir(), "komando")
	cmd := exec.Command("go", "build", "-o", bin, "-ldflags", "-X "+string(m[1])+".Version="+stamp, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	// the build info keeps the -ldflags text, "...Version=<stamp>": only a
	// copy without that prefix is the variable's value
	if bytes.Count(b, []byte(stamp)) == bytes.Count(b, []byte(".Version="+stamp)) {
		t.Errorf("-X %s.Version did not reach the binary: the Makefile names a variable that does not exist", m[1])
	}
}
