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
