package sshx

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The ProxyCommand shell is Windows' own cmd.exe: ComSpec or SystemRoot
// set to a program of the caller's does not change it.
func TestProxyShellIgnoresTheEnvironment(t *testing.T) {
	own := filepath.Join(t.TempDir(), "cmd.exe")
	t.Setenv("ComSpec", own)
	t.Setenv("SystemRoot", t.TempDir())
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	c := proxyCommand("echo hi")
	if !strings.EqualFold(c.Path, filepath.Join(sys, "cmd.exe")) {
		t.Errorf("the ProxyCommand shell is %s, not Windows' cmd.exe", c.Path)
	}
}
