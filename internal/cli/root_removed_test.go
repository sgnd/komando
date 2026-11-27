package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// removedTypedAllowed are the files that may name a removed command: the
// frozen v0.17 lists and the history of the changes.
var removedTypedAllowed = []string{
	"CHANGELOG.md",
	"internal/capability/today.go", "internal/capability/today_rows.go", "internal/capability/replaced.go",
	"internal/cli/root_removed.go", "internal/cli/root_removed_test.go",
	"internal/cli/testdata/command_ids.txt", "internal/cli/testdata/tier_runs.txt",
}

// removedTypedPending are the commands of D1 (C493) that docs and guides
// still type: docs/features/system.md, health.md, windows.md, files.md, the
// guide, the skill and the READMEs describe svc, net, user, cron, reboot and
// facts. The typed check skips them until a row cleans that text; the tree
// check still covers them.
var removedTypedPending = []string{"cron", "facts", "net", "reboot", "svc", "user"}

// TestRemovedGone: a command of removedIDs is not in the tree, and no
// program text, test, e2e check, doc, skill or golden types it any more
// (`komando cache get`): a hint that names a command that is gone is the
// failure the catalog tests cannot see (TestHintCommandsExist reads the
// catalog only). Every removal step adds its IDs to removedIDs.
func TestRemovedGone(t *testing.T) {
	for _, c := range allCommands(newRoot(tcl)) {
		if id := cmdID(c); slices.Contains(removedIDs, id) {
			t.Errorf("%s is a command again: %s", id, c.CommandPath())
		}
	}
	forms := map[string]*regexp.Regexp{}
	for _, id := range removedIDs {
		if slices.Contains(removedTypedPending, strings.SplitN(id, ".", 2)[0]) {
			continue
		}
		words := strings.ReplaceAll(regexp.QuoteMeta(id), `\.`, " +")
		forms[id] = regexp.MustCompile("(komando|\\$K|\\$\\{K\\}) +" + words + `($|[^A-Za-z0-9_-])`)
	}
	root := filepath.Join("..", "..")
	roots := []string{"internal", "cmd", "docs", "skills", "test", "README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md"}
	for _, r := range roots {
		_ = filepath.WalkDir(filepath.Join(root, r), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			if slices.Contains(removedTypedAllowed, rel) || strings.HasSuffix(rel, "shapes.json") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			text := string(b)
			if !strings.Contains(text, "komando") && !strings.Contains(text, "$K") {
				return nil
			}
			for _, id := range removedIDs {
				if forms[id] == nil {
					continue
				}
				if loc := forms[id].FindStringIndex(text); loc != nil {
					line := 1 + strings.Count(text[:loc[0]], "\n")
					t.Errorf("%s:%d types the removed command %s", rel, line, id)
				}
			}
			return nil
		})
	}
}
