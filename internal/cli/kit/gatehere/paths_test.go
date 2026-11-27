//go:build !windows

package gatehere

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testPaths makes a home with the files rule a protects, komando's own
// folder, the gate's binary and another user's home, all in a temp dir.
func testPaths(t *testing.T) Paths {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home", "anna")
	other := filepath.Join(root, "home", "budi")
	for _, d := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".komando"), filepath.Join(home, "dotfiles"),
		filepath.Join(home, "work"), other, filepath.Join(root, "usr", "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{".ssh/authorized_keys", ".profile", ".komando/audit.log", "work/notes.txt", "dotfiles/bashrc"} {
		if err := os.WriteFile(filepath.Join(home, f), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// ~/.bashrc is a symlink into dotfiles, as many people keep it
	if err := os.Symlink(filepath.Join(home, "dotfiles", "bashrc"), filepath.Join(home, ".bashrc")); err != nil {
		t.Fatal(err)
	}
	self := filepath.Join(root, "usr", "bin", "komando")
	if err := os.WriteFile(self, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	return Paths{Home: home, Komando: filepath.Join(home, ".komando"), Self: self, Homes: map[string]string{"budi": other}}
}

// TestWriteRefusalProtectsTheGate pins rule a: through the gate nothing
// writes, moves or changes the gate's binary, the key files, a start file
// or komando's own files, by any name. Mutant: WriteRefusal returning ""
// (or dropping any one check below) turns a line red.
func TestWriteRefusalProtectsTheGate(t *testing.T) {
	p := testPaths(t)
	link := func(name, target string) string {
		t.Helper()
		l := filepath.Join(p.Home, "work", name)
		if err := os.Symlink(target, l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	hard := filepath.Join(p.Home, "work", "hard")
	if err := os.Link(filepath.Join(p.Home, ".ssh", "authorized_keys"), hard); err != nil {
		t.Fatal(err)
	}
	refused := map[string]string{
		"~/.ssh/authorized_keys":         "authorized_keys",
		".ssh/authorized_keys":           "authorized_keys", // relative to the home
		"~/.ssh/authorized_keys2":        "authorized_keys2",
		"~/.ssh/config":                  ".ssh",
		"~/.ssh/rc":                      ".ssh",
		"~/.ssh/environment":             ".ssh",
		"~/.ssh/new-file":                ".ssh", // the whole folder: sshd reads more than one file there
		"~/work/../.ssh/authorized_keys": "authorized_keys",
		"~//.ssh///authorized_keys":      "authorized_keys",
		"~/.profile":                     ".profile",
		"~/.zshrc":                       ".zshrc", // not there yet: creating it counts
		"~/.bash_profile":                ".bash_profile",
		"~/.config/fish/config.fish":     "fish",
		"~/.bashrc":                      ".bashrc",
		"~/dotfiles/bashrc":              "bashrc",   // what ~/.bashrc points at
		"~/dotfiles":                     "dotfiles", // a parent of a start file: mv would replace it
		"~/.komando/audit.log":           ".komando",
		"~/.claude/settings.json":        "guard",
		"~/.komando":                     ".komando",
		"~":                              "holds",
		"/":                              "holds",
		p.Self:                           "komando",
		filepath.Dir(p.Self):             "holds",
		link("to-keys", "../.ssh/authorized_keys"):   "authorized_keys",  // a symlink to it
		link("to-keys2", "../.ssh/authorized_keys2"): "authorized_keys2", // a dangling one
		link("to-ssh", "../.ssh"):                    ".ssh",
		hard:                                         "other names", // a hardlink of authorized_keys
		filepath.Join(p.Homes["budi"], ".profile"):   "budi",        // another user's home
	}
	for path, why := range refused {
		got := p.WriteRefusal(path)
		if got == "" || !strings.Contains(got, why) {
			t.Errorf("%s: %q, want a refusal that names %q", path, got, why)
		}
	}
	for _, path := range []string{"~/work/notes.txt", "~/work/new.txt", "notes.txt", "/tmp/komando-test-out.txt", "nginx", "openssh-server"} {
		if got := p.WriteRefusal(path); got != "" {
			t.Errorf("%s: refused (%s), want allowed", path, got)
		}
	}
}

// TestReadRefusalKeepsSecretsAndOtherHomes pins rule f: reads of another
// user's home, of ~/.ssh and of komando's own folder are refused, by any
// name. Mutant: ReadRefusal returning "" turns it red.
func TestReadRefusalKeepsSecretsAndOtherHomes(t *testing.T) {
	p := testPaths(t)
	l := filepath.Join(p.Home, "work", "peek")
	if err := os.Symlink(p.Homes["budi"], l); err != nil {
		t.Fatal(err)
	}
	for path, why := range map[string]string{
		filepath.Join(p.Homes["budi"], ".bash_history"): "budi",
		"~budi/.bash_history":                           "budi",
		l + "/x":                                        "budi",
		"~/.ssh/id_ed25519":                             ".ssh",
		"~/.komando/vault":                              ".komando",
	} {
		if got := p.ReadRefusal(path); got == "" || !strings.Contains(got, why) {
			t.Errorf("%s: %q, want a refusal that names %q", path, got, why)
		}
	}
	for _, path := range []string{"/var/log/syslog", "~/work/notes.txt", "/etc/os-release", "nginx"} {
		if got := p.ReadRefusal(path); got != "" {
			t.Errorf("%s: refused (%s), want allowed", path, got)
		}
	}
}

func TestOtherHomes(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"anna:x:1000:1000::/home/anna:/bin/bash\n" +
		"budi:x:1001:1001::/home/budi:/bin/bash\n" +
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n" +
		"svc:x:999:999::/:/usr/sbin/nologin\n" +
		"# a comment\n\nbroken line\n"
	// daemon's /usr/sbin, nobody's /nonexistent and / are no homes: their
	// last word is not the user's name
	got := OtherHomes([]byte(passwd), "/home/anna")
	want := map[string]string{"root": "/root", "budi": "/home/budi"}
	if len(got) != len(want) || got["root"] != want["root"] || got["budi"] != want["budi"] {
		t.Errorf("%v, want %v", got, want)
	}
}

func TestNextTo(t *testing.T) {
	p := testPaths(t)
	got := NextTo(p.Home)
	if len(got) != 1 || got["budi"] != p.Homes["budi"] {
		t.Errorf("%v, want only budi's home", got)
	}
	if got := NextTo("/root"); len(got) != 0 {
		t.Errorf("/root: %v, want none (its neighbours are system folders)", got)
	}
}
