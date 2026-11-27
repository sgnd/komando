// Package gatehere holds the rules of ssh-gate's server mode (--here): a
// phone's key that logs in to a server runs komando there through the
// gate, and the gate decides what may run on that server itself. The
// rules are pure: the cli hands in the paths and the command's words.
package gatehere

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Paths are what the server mode protects (rule a) and keeps unread (rule
// f), for the user the key logs in as.
type Paths struct {
	Home    string            // the paired user's home, from the user database
	Komando string            // komando's own folder: settings, rules, guard, audit
	Self    string            // the gate's own binary, symlinks resolved
	Homes   map[string]string // every other user's home, by name (OtherHomes)
}

// SSHFiles are the files in ~/.ssh sshd reads for a login. The whole
// folder is protected; these are named so a refusal says which.
var SSHFiles = []string{"authorized_keys", "authorized_keys2", "config", "rc", "environment"}

// StartFiles are the files a shell or a login reads as it starts, in the
// home: a line written there runs at the user's next login.
var StartFiles = []string{
	".profile", ".bash_profile", ".bash_login", ".bashrc", ".bash_logout",
	".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout",
	".kshrc", ".mkshrc", ".cshrc", ".tcshrc", ".login", ".logout",
	".xprofile", ".xsession", ".xinitrc", ".pam_environment",
}

// startDirs are folders in the home whose files a shell or a login reads.
var startDirs = []string{".config/fish", ".config/environment.d", ".config/systemd", ".config/autostart"}

// guardDirs are the AI agents' setting folders, where komando's guard hook
// lives (guide install): a change there switches the guard off.
var guardDirs = []string{".claude", ".codex", ".cursor", ".gemini", ".agents"}

// protected is one protected place: the path as named, and what it is.
type protected struct {
	path, what string
	dir        bool // everything under it too
}

// list is every protected place, each as named and, when that differs,
// as its symlinks resolve (~/.bashrc -> ~/dotfiles/bashrc).
func (p Paths) list() []protected {
	var l []protected
	add := func(path, what string, dir bool) {
		l = append(l, protected{filepath.Clean(path), what, dir})
		if r := Resolve(path, p.Home); r != filepath.Clean(path) {
			l = append(l, protected{r, what + " (" + r + ")", dir})
		}
	}
	// the files first, so a refusal names the one it is
	for _, f := range SSHFiles {
		add(filepath.Join(p.Home, ".ssh", f), "~/.ssh/"+f, false)
	}
	add(filepath.Join(p.Home, ".ssh"), "~/.ssh, which sshd reads at login", true)
	for _, f := range StartFiles {
		add(filepath.Join(p.Home, f), "the start file ~/"+f, false)
	}
	for _, d := range startDirs {
		add(filepath.Join(p.Home, d), "~/"+d+", whose files run at login", true)
	}
	for _, d := range guardDirs {
		add(filepath.Join(p.Home, d), "~/"+d+", where komando's guard hook lives", true)
	}
	if p.Komando != "" {
		add(p.Komando, "komando's own folder "+p.Komando+" (settings, rules, audit)", true)
	}
	if p.Self != "" {
		add(p.Self, "the gate's own program "+p.Self, false)
	}
	for name, h := range p.Homes {
		add(h, "the home of "+name+" ("+h+")", true)
	}
	return l
}

// WriteRefusal says why a command through the gate may not write, move,
// remove or change the mode of path, or "" (rule a). It checks the path as
// named and as its symlinks resolve, a parent folder of a protected place
// (a rename moves what is in it), and a file with other names (a hardlink
// of a protected file is that file).
func (p Paths) WriteRefusal(path string) string {
	named, real := p.abs(path), Resolve(path, p.Home)
	for _, at := range []string{named, real} {
		for _, pr := range p.list() {
			switch {
			case same(at, pr.path), pr.dir && under(at, pr.path):
				return path + " is " + pr.what
			case under(pr.path, at):
				return path + " holds " + pr.what
			}
		}
	}
	if fi, err := os.Lstat(real); err == nil && fi.Mode().IsRegular() && links(fi) > 1 {
		return path + " has other names (hardlinks), which may be a protected file"
	}
	return ""
}

// ReadRefusal says why a command through the gate may not read path, or
// "" (rule f): another user's home, ~/.ssh (private keys) and komando's own
// folder (its vault and keys), by any name.
func (p Paths) ReadRefusal(path string) string {
	secret := []protected{{filepath.Join(p.Home, ".ssh"), "~/.ssh (private keys)", true}}
	if p.Komando != "" {
		secret = append(secret, protected{p.Komando, "komando's own folder (its vault and keys)", true})
	}
	for name, h := range p.Homes {
		secret = append(secret, protected{h, "the home of " + name + " (" + h + ")", true})
	}
	named, real := p.abs(path), Resolve(path, p.Home)
	for _, at := range []string{named, real} {
		for _, s := range secret {
			for _, sp := range []string{s.path, Resolve(s.path, p.Home)} {
				if same(at, sp) || under(at, sp) {
					return path + " is in " + s.what
				}
			}
		}
	}
	return ""
}

// abs is path as an absolute, clean path: relative to the home, with ~
// and ~NAME read as homes. Nothing else is expanded.
func (p Paths) abs(path string) string {
	switch {
	case path == "~" || strings.HasPrefix(path, "~/"):
		return filepath.Join(p.Home, strings.TrimPrefix(path, "~"))
	case strings.HasPrefix(path, "~"):
		name, rest, _ := strings.Cut(path[1:], "/")
		if h, ok := p.Homes[name]; ok {
			return filepath.Join(h, rest)
		}
		return filepath.Join(p.Home, path) // a file named ~x
	case filepath.IsAbs(path):
		return filepath.Clean(path)
	}
	return filepath.Join(p.Home, path)
}

// Resolve is path as an absolute path with every symlink resolved, also
// one that points at nothing yet and one under a folder that does not
// exist yet: what a write to path would really change.
func Resolve(path, home string) string {
	return Paths{Home: home}.resolve(Paths{Home: home}.abs(path), 0)
}

func (p Paths) resolve(path string, depth int) string {
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	if depth > 40 {
		return path // a loop: as named
	}
	fi, err := os.Lstat(path)
	if err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		t, err := os.Readlink(path)
		if err != nil {
			return path
		}
		if !filepath.IsAbs(t) {
			t = filepath.Join(filepath.Dir(path), t)
		}
		return p.resolve(filepath.Clean(t), depth+1)
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return path
	}
	dir, base := filepath.Split(path)
	dir = filepath.Clean(dir)
	if dir == path {
		return path // the root
	}
	return filepath.Join(p.resolve(dir, depth+1), base)
}

// OtherHomes are the homes of the users in an /etc/passwd text other than
// the one at home. A home counts when its last word is the user's name
// (/home/budi, /root): /usr/sbin, / and /nonexistent are none.
func OtherHomes(passwd []byte, home string) map[string]string {
	homes := map[string]string{}
	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || strings.HasPrefix(line, "#") {
			continue
		}
		name, h := f[0], filepath.Clean(f[5])
		if h == filepath.Clean(home) || !filepath.IsAbs(h) || filepath.Base(h) != name {
			continue
		}
		homes[name] = h
	}
	return homes
}

// foldCase: this system's files may differ only in case (macOS, Windows).
var foldCase = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

func same(a, b string) bool {
	if foldCase {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// under: a is inside folder dir (not dir itself).
func under(a, dir string) bool {
	if dir == string(filepath.Separator) {
		return a != dir
	}
	prefix := dir + string(filepath.Separator)
	if foldCase {
		return len(a) > len(prefix) && strings.EqualFold(a[:len(prefix)], prefix)
	}
	return strings.HasPrefix(a, prefix)
}

// NextTo are the folders next to home (/home/*, /Users/*), as other users'
// homes: the users a system keeps outside /etc/passwd (macOS, a directory
// service) have their homes there too. Folders starting with a dot, and
// macOS's /Users/Shared, are no homes.
func NextTo(home string) map[string]string {
	homes := map[string]string{}
	parent := filepath.Dir(filepath.Clean(home))
	if parent == filepath.Clean(home) || parent == string(filepath.Separator) {
		return homes // a home at the root (/root): its neighbours are system folders
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return homes
	}
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() || strings.HasPrefix(n, ".") || n == "Shared" || same(n, filepath.Base(home)) {
			continue
		}
		homes[n] = filepath.Join(parent, n)
	}
	return homes
}
