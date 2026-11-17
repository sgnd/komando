//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestToolSafe(t *testing.T) {
	if !toolSafe(tcl, "/bin/sh") {
		t.Error("/bin/sh counts as changeable")
	}
	p := filepath.Join(t.TempDir(), "pg_dump")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if toolSafe(tcl, p) {
		t.Error("a program in a folder of this user counts as safe")
	}
	// a root-owned link to a file of this user is not safe: the target counts
	link := filepath.Join(t.TempDir(), "sh")
	if err := os.Symlink(p, link); err == nil && toolSafe(tcl, link) {
		t.Error("a link to a program of this user counts as safe")
	}
}

// An AI agent that puts its own openconnect first in PATH does not get the
// VPN password: the program never runs without a person's yes.
func TestVPNClientFromPATHNeedsAPerson(t *testing.T) {
	secretHome(t)
	defer func() { tcl.flags.yes, tcl.flags.dryRun = false, false }()
	mustRun(t, "vpn", "add", "office", "fortinet", "--portal", "vpn.example.com", "--user", "u", "--password-ref", "secret:db-pass")
	bin := t.TempDir()
	leak := filepath.Join(t.TempDir(), "leak")
	for _, name := range []string{"openconnect", "ocproxy"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\ncat > "+leak+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	windows := asAgent(t, false, false)
	if _, err := localTool(tcl, "openconnect", []string{"secret:db-pass"}); toErr(err).Code != "SECRET_DESTINATION" {
		t.Fatalf("localTool: %v", err)
	}
	if p, err := localTool(tcl, "sh", []string{"secret:db-pass"}); err != nil || !filepath.IsAbs(p) {
		t.Fatalf("a system program: %q %v", p, err)
	}
	wantCode(t, "SECRET_DESTINATION", "vpn", "up", "office")
	if _, err := os.Stat(leak); err == nil {
		t.Fatal("the stand-in openconnect got the password")
	}
	if *windows != 0 {
		t.Fatal("a window without --yes")
	}
}
