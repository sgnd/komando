package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// removedTyped is how a person types a removed ID when it is not its dotted
// path: the help topics were typed after `help`.
var removedTyped = map[string]string{
	"help": "help", "environment": "help environment", "exit-codes": "help exit-codes",
	"output": "help output", "safety": "help safety",
}

// removedTextOpen are IDs of earlier steps (D1) that the text still names:
// guide.md and skill.md tell agents to run `komando facts`, `svc`, `net` and
// `reboot`, and tests and goldens still run `db user ...`. They are in the
// tree check below but not in the text check, until the coordinator's row
// for that text is done; every ID a later step adds is checked in full.
var removedTextOpen = map[string]bool{
	"cron": true, "cron.list": true, "cron.rm": true, "cron.set": true, "facts": true,
	"net": true, "net.check": true, "net.dns": true, "net.http": true, "net.ports": true, "reboot": true,
	"svc": true, "svc.daemon-reload": true, "svc.disable": true, "svc.enable": true, "svc.list": true, "svc.logs": true,
	"svc.reload": true, "svc.restart": true, "svc.start": true, "svc.status": true, "svc.stop": true,
	"user": true, "user.add": true, "user.list": true, "user.lock": true, "user.rm": true, "user.unlock": true,
}

// removedCodes are the error codes only a removed command gave: no doc,
// test or program text keeps one.
var removedCodes = []string{"CERT_PROBLEMS", "NO_CERTIFICATE", "TLS_HANDSHAKE_FAILED", "NOTHING_TO_RENAME", "SECRET_MISMATCH", "SSH_AGENT_NEEDED", "SSH_AGENT_REFUSED", "VPN_NOT_FOR_OPENSSH"}

// removedGoneAllowed are the files that may still name a removed command: the
// release history and the frozen v0.17 tables (they say what was there).
var removedGoneAllowed = map[string]bool{
	"CHANGELOG.md":                               true,
	"internal/capability/today.go":               true,
	"internal/capability/today_rows.go":          true,
	"internal/capability/replaced.go":            true,
	"internal/capability/fate.go":                true,
	"internal/capability/cache.go":               true, // Carries: the IDs `cache redis raw` took over (TestMovedLeavesCarryTheirTables)
	"internal/capability/cluster.go":             true, // rawCarries: the same for `cluster kubernetes raw`
	"internal/capability/testdata/v0_17_ids.txt": true,
	"internal/store/migrate3_fix.go":             true, // its steps run in the last format 2 release, where `komando secret set` exists
	"internal/store/migrate3_refs_test.go":       true, // pins those steps and the format 2 reference spellings
	"internal/cli/root_removed.go":               true,
	"internal/cli/root_removed_test.go":          true,
}

// removedGoneRoots are the places that tell people or programs how to run
// komando: program, tests, e2e scripts, docs, skills and goldens.
var removedGoneRoots = []string{"cmd", "internal", "test", "docs", "skills", "README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md"}

// removedForms are the two spellings of a removed command in text:
// `komando net dns` or `$K net dns` (typed), and "net", "dns" (an argument
// list). A one-word ID has no argument-list form: "user" alone is a word.
func removedForms(id string) []*regexp.Regexp {
	typed := removedTyped[id]
	if typed == "" {
		typed = strings.ReplaceAll(id, ".", " ")
	}
	end := `($|[^A-Za-z0-9_-])`
	forms := []*regexp.Regexp{regexp.MustCompile(`(komando|\$K) +` + regexp.QuoteMeta(typed) + end)}
	if parts := strings.Split(typed, " "); len(parts) > 1 {
		q := make([]string, len(parts))
		for i, p := range parts {
			q[i] = `"` + regexp.QuoteMeta(p) + `"`
		}
		forms = append(forms, regexp.MustCompile(strings.Join(q, `, *`)))
	}
	return forms
}

// A removed command is out of the tree, and no program text, test, script,
// doc, skill or golden still names it (a hint that sends a person to a
// command that is gone). TestCommandIDsStable only sees the tree; this sees
// the text. Every step of the cut adds its IDs to removedIDs.
func TestRemovedGone(t *testing.T) {
	ids := treeIDs(t)
	for _, id := range removedIDs {
		if _, ok := ids[id]; ok {
			t.Errorf("removed command %q is in the tree", id)
		}
	}
	forms := map[string][]*regexp.Regexp{}
	for _, id := range removedIDs {
		if !removedTextOpen[id] {
			forms[id] = removedForms(id)
		}
	}
	for _, code := range removedCodes {
		forms[code] = []*regexp.Regexp{regexp.MustCompile(`\b` + code + `\b`)}
	}
	for _, root := range removedGoneRoots {
		err := filepath.WalkDir(filepath.Join("..", "..", root), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel := removedRel(p)
			if d.IsDir() {
				if d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "fuzz" {
					return filepath.SkipDir
				}
				return nil
			}
			if removedGoneAllowed[rel] {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for n, line := range strings.Split(string(b), "\n") {
				for id, res := range forms {
					for _, re := range res {
						if matchesAtStart(re, line) {
							t.Errorf("%s:%d names the removed command or code %q: %s", rel, n+1, id, strings.TrimSpace(line))
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// removedRel is the repo-relative, slash-joined name of a walked path, the key
// of removedGoneAllowed. Windows walks `..\..\dir\file`: the separators are
// turned into slashes before the prefix is cut.
func removedRel(p string) string {
	return strings.TrimPrefix(strings.ReplaceAll(p, `\`, "/"), "../../")
}

// The skip list is keyed by slash paths; a Windows path must find the same key.
func TestRemovedRelFindsAllowedFilesOnEveryOS(t *testing.T) {
	for p, want := range map[string]string{
		`..\..\internal\cli\root_removed_test.go`: "internal/cli/root_removed_test.go",
		`..\..\CHANGELOG.md`:                      "CHANGELOG.md",
		"../../internal/cli/root_removed.go":      "internal/cli/root_removed.go",
	} {
		got := removedRel(p)
		if got != want || !removedGoneAllowed[got] {
			t.Errorf("removedRel(%q) = %q (allowed %v), want %q allowed", p, got, removedGoneAllowed[got], want)
		}
	}
	if removedRel(`..\..\docs\guide.md`) != "docs/guide.md" || removedGoneAllowed["docs/guide.md"] {
		t.Errorf("a doc file must keep its key and stay out of the skip list")
	}
}

// longerPath is the end of a line that already holds a lowercase argument
// word before the match: `"database", "user", "add"` is another command's
// path, not `"user", "add"`. An uppercase word (an error code) is no path.
var longerPath = regexp.MustCompile(`"[a-z][a-z0-9-]*", *$`)

// matchesAtStart says whether re matches line at the start of a command path.
func matchesAtStart(re *regexp.Regexp, line string) bool {
	for _, m := range re.FindAllStringIndex(line, -1) {
		if !longerPath.MatchString(line[:m[0]]) {
			return true
		}
	}
	return false
}

// There is no help command and there are no help topics: `komando help` and
// `komando help safety` are unknown commands, and `--help` is the help.
func TestHelpIsOnlyTheFlag(t *testing.T) {
	invHome(t)
	for _, args := range [][]string{{"help"}, {"help", "host", "list"}, {"help", "safety"}} {
		e := wantCode(t, "USAGE", args...)
		if !strings.Contains(e.Message, "unknown command") || !strings.Contains(e.Hint, "komando --help") {
			t.Errorf("%v: %+v, want an unknown command that points at komando --help", args, e)
		}
	}
	root := newRoot(tcl)
	for _, c := range root.Commands() {
		if c.Name() == "help" {
			t.Errorf("the tree has a help command")
		}
	}
}
