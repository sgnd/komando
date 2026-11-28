package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// gitBashSpellings are the ways a Git Bash line names the Windows path p:
// quoted with backslashes, with slashes after the drive, and as MSYS's
// /c/... (an unquoted backslash is an escape there and names another path).
func gitBashSpellings(p string) []string {
	s := filepath.ToSlash(p)
	return []string{"'" + p + "'", s, "/" + strings.ToLower(s[:1]) + s[2:]}
}

// Each spelling of a protected folder is refused as the slash form is.
func TestGuardWindowsSpellingsOfProtectedFolders(t *testing.T) {
	home, repo := guardLineHome(t)
	agentRepo(t, repo)
	const secret = "keeps it away from AI agents"
	for _, r := range gitBashSpellings(repo) {
		checkRefusedBy(t, home, repo, []string{`rm -rf ` + r, `mv ` + r + ` /tmp/r`}, treeRefusal)
		checkLines(t, home, repo, []string{`git -C ` + r + ` checkout -- .`}, true)
	}
	for _, h := range gitBashSpellings(home) {
		checkRefusedBy(t, home, repo, []string{`rm -rf ` + h + `/.ssh`}, treeRefusal)
		checkRefusedBy(t, home, repo, []string{
			`mv ` + h + `/.komando /tmp/k`,
			`echo x > ` + h + `/.komando/state.json`,
			`cp /tmp/a ` + h + `/.komando/state.json`,
			`cat ` + h + `/.ssh/id_ed25519`,
		}, secret)
		checkLines(t, home, repo, []string{`cp /tmp/a ` + h + `/.claude/settings.json`}, true)
	}
}
