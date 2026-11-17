package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// A link followed by .. leads where the kernel goes, not where the text
// does: proj/l/../x with l -> ~/.ssh/sub is ~/.ssh/x. Every local writer
// and the agent guard follow the kernel.
func TestGuardDotDotThroughLink(t *testing.T) {
	home, _ := agentWriteHome(t)
	os.MkdirAll(filepath.Join(home, ".ssh", "sub"), 0o700)
	os.MkdirAll(filepath.Join(home, ".komando", "zsub"), 0o700)
	os.MkdirAll(filepath.Join(home, ".aws", "sso"), 0o700)
	proj := t.TempDir()
	os.Symlink(filepath.Join(home, ".ssh", "sub"), filepath.Join(proj, "l"))
	os.Symlink(filepath.Join(home, ".komando", "zsub"), filepath.Join(proj, "k"))
	os.Symlink(filepath.Join(home, ".aws", "sso"), filepath.Join(proj, "a"))
	for _, args := range [][]string{
		{"db", "dump", "lite", "--to", filepath.Join(proj, "l") + "/../authorized_keys"},
		{"export", "--to", filepath.Join(proj, "l") + "/../exported"},
		{"db", "dump", "lite", "--to", filepath.Join(proj, "k") + "/../dump.sql"},
		{"export", "--to", filepath.Join(proj, "a") + "/../config", "--overwrite"},
		{"download", "web1", "/etc/hosts", "--to", filepath.Join(proj, "l") + "/../authorized_keys"},
	} {
		if _, e := invRun(t, args...); e == nil || e.Code != "SENSITIVE_FILE" {
			t.Errorf("%v: want SENSITIVE_FILE, got %+v", args, e)
		}
	}
	for _, d := range []string{".ssh", ".komando", ".aws"} {
		for _, n := range []string{"authorized_keys", "exported", "dump.sql", "config"} {
			if _, err := os.Lstat(filepath.Join(home, d, n)); err == nil {
				t.Errorf("%s/%s was written", d, n)
			}
		}
	}

	// the agent guard (a hook's Read and Bash): store.db is secret only by
	// its folder
	os.WriteFile(filepath.Join(home, ".komando", "zsub", "x"), []byte("k"), 0o600)
	k := filepath.Join(proj, "k")
	for _, c := range []struct {
		tool string
		in   map[string]any
	}{
		{"Read", map[string]any{"file_path": k + "/../store.db"}},
		{"Bash", map[string]any{"command": "cat " + k + "/../store.db"}},
		{"Bash", map[string]any{"command": "cat k/../store.db"}},
	} {
		if d := checkTool(tcl, c.tool, c.in, home, proj); !d.Deny {
			t.Errorf("%s %v: not denied", c.tool, c.in)
		}
	}
}

// APFS and NTFS fold more than strings.ToLower does: ſ (U+017F) is s, K
// (U+212A) is k. ~/.ſsh is ~/.ssh there.
func TestGuardUnicodeCaseFold(t *testing.T) {
	saved := caseFoldFS
	caseFoldFS = true
	t.Cleanup(func() { caseFoldFS = saved })
	home, _ := agentWriteHome(t)
	for _, args := range [][]string{
		{"db", "dump", "lite", "--to", filepath.Join(home, ".ſsh", "authorized_keys")},
		{"export", "--to", filepath.Join(home, ".awſ", "config")},
		{"db", "dump", "lite", "--to", filepath.Join(home, ".KOMANDO", "x.db")},
		{"db", "dump", "lite", "--to", filepath.Join(home, ".Kube", "config")},
	} {
		if _, e := invRun(t, args...); e == nil || e.Code != "SENSITIVE_FILE" {
			t.Errorf("%v: want SENSITIVE_FILE, got %+v", args, e)
		}
	}
	hook := t.TempDir()
	os.MkdirAll(filepath.Join(hook, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(hook, ".ssh", "mykey"), []byte("k"), 0o600)
	kk := filepath.Join(hook, ".ſsh", "mykey") // a private key by its folder only
	for _, c := range []struct {
		tool string
		in   map[string]any
	}{
		{"Read", map[string]any{"file_path": kk}},
		{"Bash", map[string]any{"command": "cat " + kk}},
		{"Bash", map[string]any{"command": "cat ~/.ſsh/mykey"}},
	} {
		if d := checkTool(tcl, c.tool, c.in, hook, ""); !d.Deny {
			t.Errorf("%s %v: not denied", c.tool, c.in)
		}
	}
}

// Files that run code or hold credentials at the next login, and the AI
// agents' own folders (where the guard hooks live), are no place for an
// agent's download either.
func TestAgentLocalWriteMoreProtected(t *testing.T) {
	home, _ := agentWriteHome(t)
	for _, rel := range []string{
		"Library/LaunchAgents/x.plist", ".config/systemd/user/x.service", ".zshrc", ".zshenv", ".zprofile",
		".bashrc", ".bash_profile", ".profile", ".gitconfig", ".netrc", ".config/gh/hosts.yml",
		".claude/settings.json", ".codex/hooks.json", ".gemini/settings.json", ".cursor/hooks.json", ".agents/skills/x/SKILL.md",
	} {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if _, e := invRun(t, "db", "dump", "lite", "--to", p); e == nil || e.Code != "SENSITIVE_FILE" {
			t.Errorf("%s: want SENSITIVE_FILE, got %+v", rel, e)
		}
	}
}
