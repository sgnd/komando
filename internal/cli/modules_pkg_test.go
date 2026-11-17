package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// Package names are checked with an allowlist (the server's shell splits
// the list on any whitespace), and the essential-package stop sees through
// case, :arch, =version, /release and -version.
func TestPkgNames(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@127.0.0.1", "--port", "2")
	cases := []struct {
		name string
		code string // "" = goes through (checked with --dry-run)
	}{
		{"nginx", ""},
		{"nginx:amd64", ""},
		{"python3.12=3.12.3-1", ""},
		{"libstdc++6", ""},
		{"foo\topenssh-server", "USAGE"},
		{"foo\nopenssh-server", "USAGE"},
		{"foo openssh-server", "USAGE"},
		{"-y", "USAGE"},
		{"openssh-*", "USAGE"},
		{"nginx;reboot", "USAGE"},
		{"", "USAGE"},
		{"openssh-server", "POLICY_BLOCKED"},
		{"OpenSSH-Server", "POLICY_BLOCKED"},
		{"openssh-server:amd64", "POLICY_BLOCKED"},
		{"sudo=1.9.15p5-3", "POLICY_BLOCKED"},
		{"systemd/bookworm-backports", "POLICY_BLOCKED"},
		{"openssh-server-8.0p1-19.el8", "POLICY_BLOCKED"},
		// name.arch (dnf, yum, zypper), also after a version
		{"openssh-server.x86_64", "POLICY_BLOCKED"},
		{"sudo.noarch", "POLICY_BLOCKED"},
		{"systemd.x86_64", "POLICY_BLOCKED"},
		{"bash.aarch64", "POLICY_BLOCKED"},
		{"glibc.i686", "POLICY_BLOCKED"},
		{"openssh-server-8.0p1-19.el8.x86_64", "POLICY_BLOCKED"},
		{"nginx.x86_64", ""},
		// a dot makes a name a regular expression to apt
		{"openssh.server", "POLICY_BLOCKED"},
		{"lib.6", "POLICY_BLOCKED"},
		{"python3.12", ""},
		{"libssl1.1", ""},
		// apt reads a trailing - as "remove this package"
		{"openssh-server-", "USAGE"},
		{"sudo-", "USAGE"},
		{"sud.", "USAGE"},
		{"g++", ""},
		// local package files
		{"./app.deb", "USAGE"},
		{"/tmp/app.rpm", "USAGE"},
		{"app.deb", "USAGE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.code == "" {
				d := mustRun(t, "pkg", "rm", "web1", tc.name, "--dry-run")
				if m, _ := d["_meta"].(map[string]any); m != nil && m["would_be_blocked"] != nil {
					t.Errorf("blocked: %v", d)
				}
				return
			}
			wantCode(t, tc.code, "pkg", "rm", "web1", tc.name)
		})
	}
}

// A dry run of a blocked removal still shows the plan, marked
// would_be_blocked, instead of printing nothing.
func TestPkgRmDryRunShowsTheBlock(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@127.0.0.1", "--port", "2")
	d := mustRun(t, "pkg", "rm", "web1", "openssh-server", "--dry-run")
	m, _ := d["_meta"].(map[string]any)
	if m == nil || m["would_be_blocked"] == nil || d["would_run"] == nil {
		t.Errorf("dry run: %v", d)
	}
}

// A trailing - removes the package in apt even for install and upgrade
// (upgrade becomes apt-get install --only-upgrade), so it is refused for
// every action, and a package file gets a message that says what to do.
func TestPkgNameRemovalSuffixOnEveryAction(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@127.0.0.1", "--port", "2")
	for _, args := range [][]string{
		{"pkg", "install", "web1", "openssh-server-"},
		{"pkg", "upgrade", "web1", "sudo-"},
		{"pkg", "rm", "web1", "sudo-"},
		{"pkg", "install", "web1", "sudo=1.9.15-"},
	} {
		wantCode(t, "USAGE", append(args, "--dry-run")...)
	}
	if e := wantCode(t, "USAGE", "pkg", "install", "web1", "./app.deb"); !strings.Contains(e.Message, "komando upload") {
		t.Errorf("message: %s", e.Message)
	}
}

// Removing a library can take an essential package with it (libssl3 takes
// openssh-server): apt is asked first, and the answer stops the removal.
func TestPkgRmStopsOnEssentialDependents(t *testing.T) {
	if s := pkgChangeScript("remove", []string{"libssl3"}, true); !strings.Contains(s, "ACTION=simulate-remove") || !strings.Contains(s, "#komando:essential") {
		t.Errorf("guarded script: %s", s)
	}
	if s := pkgChangeScript("remove", []string{"libssl3"}, false); strings.Contains(s, "ACTION=simulate-remove") {
		t.Error("--allow-dangerous still simulates")
	}
	if s := pkgChangeScript("install", []string{"nginx"}, true); strings.Contains(s, "ACTION=simulate-remove") {
		t.Error("install simulates a removal")
	}
	_, e := pkgChangeResult(tcl, "remove", []string{"libssl3"}, &sshx.RunResult{Stdout: "#komando:essential\nopenssh-server\nsudo\n"})
	if e == nil || e.Code != "POLICY_BLOCKED" || !strings.Contains(e.Message, "openssh-server, sudo") || e.Exit != out.ExitPolicy {
		t.Errorf("result: %+v", e)
	}
}
