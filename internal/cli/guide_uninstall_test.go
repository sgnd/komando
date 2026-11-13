package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A guide uninstall that stops for the guard removes nothing, not even the
// skill files, and says so in the audit log; its dry run names the stop.
func TestGuideUninstallStopsBeforeRemovingAnything(t *testing.T) {
	invHome(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir reads USERPROFILE on Windows
	noAgent(t)
	mustRun(t, "guide", "install")
	skill := filepath.Join(home, ".claude", "skills", "komando", "SKILL.md")
	asAgent(t, false, true)
	d := mustRun(t, "guide", "uninstall", "--dry-run")
	meta, _ := d["_meta"].(map[string]any)
	if b, _ := meta["would_be_blocked"].(map[string]any); b["code"] != "SAFETY_SETTING" {
		t.Errorf("dry run: meta %v", meta)
	}
	if _, e := invRun(t, "guide", "uninstall"); e == nil || e.Code != "SAFETY_SETTING" {
		t.Fatalf("an agent removes its guard: %+v", e)
	}
	for _, p := range []string{skill, filepath.Join(home, ".agents", "skills", "komando", "SKILL.md")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("a stopped uninstall removed %s", p)
		}
	}
	a := mustRun(t, "audit", "--command", "guide.uninstall")
	found := false
	for _, e := range a["entries"].([]any) {
		m := e.(map[string]any)
		if m["ok"] == false && m["blocked"] == "SAFETY_SETTING" && m["dry_run"] == false {
			found = true
		}
	}
	if !found {
		t.Errorf("the stopped run is not in the audit log: %v", a)
	}
}

// Text says what a dry run would do, and asks for a restart only after a
// change, in words that fit install or uninstall.
func TestSkillResultText(t *testing.T) {
	t.Cleanup(func() { g.dryRun = false })
	files := []skillFile{{Path: "/h/.claude/skills/komando/SKILL.md", Action: "created"}, {Path: "/h/.claude/settings.json", Action: "unchanged"}}
	for _, tc := range []struct {
		dry       bool
		r         skillResult
		want, not string
	}{
		{false, skillResult{Files: files}, "created  /h/.claude/skills/komando/SKILL.md\nunchanged  /h/.claude/settings.json\nRestart your AI agent so it sees the skill.", ""},
		{true, skillResult{Files: files}, "would create  /h/", "Restart"},
		{false, skillResult{Files: []skillFile{{Path: "/x", Action: "unchanged"}}}, "unchanged  /x", "Restart"},
		{false, skillResult{Files: []skillFile{{Path: "/x", Action: "removed"}}, uninstall: true}, "stops using komando's skill", "sees the skill"},
		{true, skillResult{Files: []skillFile{{Path: "/x", Action: "removed"}}, uninstall: true}, "would remove  /x", "Restart"},
		{false, skillResult{Files: []skillFile{}, uninstall: true}, "nothing to remove", "Restart"},
	} {
		g.dryRun = tc.dry
		got := tc.r.Text()
		if !strings.Contains(got, tc.want) || tc.not != "" && strings.Contains(got, tc.not) {
			t.Errorf("dry %v %+v:\n%s", tc.dry, tc.r, got)
		}
	}
}

// doctor's agent_guard check fails when the hook names a komando that is
// not there: Claude Code then goes on without the guard.
func TestClaudeGuardChecksTheProgram(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "settings.json")
	write := func(cmd string) {
		c, _ := json.Marshal(cmd) // a Windows path's \ is escaped, as guide install writes it
		os.WriteFile(p, []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":`+string(c)+`}]}]}}`), 0o600)
	}
	self, _ := os.Executable()
	write("/nonexistent/komando guide guard")
	if found, problem := claudeGuard(p); !found || !strings.Contains(problem, "/nonexistent/komando does not exist") {
		t.Errorf("missing program: %v %q", found, problem)
	}
	write(shellQuote(self) + " guide guard")
	if found, problem := claudeGuard(p); !found || problem != "" {
		t.Errorf("this program: %v %q", found, problem)
	}
	write("komando-nowhere-here guide guard")
	if _, problem := claudeGuard(p); !strings.Contains(problem, "not in PATH") {
		t.Errorf("not in PATH: %q", problem)
	}
	if found, _ := claudeGuard(filepath.Join(dir, "none.json")); found {
		t.Error("no file: no guard")
	}
	for in, want := range map[string]string{
		"'/My Apps/komando' guide guard":     "/My Apps/komando",
		`'/it'\''s/komando' guide guard`:     "/it's/komando",
		"/usr/local/bin/komando guide guard": "/usr/local/bin/komando",
	} {
		if got := firstWord(in); got != want {
			t.Errorf("firstWord(%q) = %q", in, got)
		}
	}
}

// guide install --project writes the name komando has in PATH, which works
// on every computer the project's files go to.
func TestGuideInstallProjectUsesThePathName(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	bin := t.TempDir()
	name := "komando"
	if runtime.GOOS == "windows" {
		name += ".exe" // PATH finds a program there by its extension
	}
	if err := os.Symlink(self, filepath.Join(bin, name)); err != nil {
		t.Skip(err)
	}
	t.Setenv("PATH", bin)
	if prog, note := hookProgram(true); prog != "komando" || note != "" {
		t.Errorf("in PATH: %q %q", prog, note)
	}
	if prog, _ := hookProgram(false); !filepath.IsAbs(prog) {
		t.Errorf("home folder: %q", prog)
	}
	t.Setenv("PATH", t.TempDir())
	if prog, note := hookProgram(true); prog == "komando" || !strings.Contains(note, "a path on this computer only") {
		t.Errorf("not in PATH: %q %q", prog, note)
	}
}
