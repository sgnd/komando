// Package layout keeps komando's packages and files named the way
// docs/design/code-layout.md says: every package is listed there, every
// file in internal/cli starts with the command noun it serves or a shared
// area from that page, and a file that builds only on some systems says so
// in its name. The page is the source: its tables are read here, so the
// rule and its check cannot drift apart.
package layout

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	root      = "../.."
	layoutDoc = root + "/docs/design/code-layout.md"
	cliDir    = root + "/internal/cli"
	idsFile   = cliDir + "/testdata/command_ids.txt"
)

// The system and processor words Go reads at the end of a file name
// (go/build: knownOS, knownArch).
var (
	knownOS   = words("aix android darwin dragonfly freebsd hurd illumos ios js linux nacl netbsd openbsd plan9 solaris wasip1 windows zos")
	knownArch = words("386 amd64 amd64p32 arm armbe arm64 arm64be loong64 mips mipsle mips64 mips64le mips64p32 mips64p32le ppc ppc64 ppc64le riscv riscv64 s390 s390x sparc sparc64 wasm")
)

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

var tableRow = regexp.MustCompile("^\\| `([a-z0-9/]+)` \\|")

// docTable returns the first-column names of the table under the heading
// that starts with heading in code-layout.md.
func docTable(t *testing.T, heading string) map[string]bool {
	t.Helper()
	f, err := os.Open(layoutDoc)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	names := map[string]bool{}
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			in = strings.HasPrefix(line, heading)
			continue
		}
		if m := tableRow.FindStringSubmatch(line); in && m != nil {
			names[m[1]] = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatalf("%s: no table under %q", layoutDoc, heading)
	}
	return names
}

// nouns are the top-level commands, with any hyphen left out (ssh-gate is
// sshgate), from the stable command IDs.
func nouns(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(idsFile)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]bool{}
	for _, id := range strings.Fields(string(b)) {
		noun, _, _ := strings.Cut(id, ".")
		m[strings.ReplaceAll(noun, "-", "")] = true
	}
	return m
}

func sorted(m map[string]bool) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

// programFiles walks dirs and calls fn for every Go file that is not a
// test and not under testdata.
func programFiles(t *testing.T, fn func(rel, name string), dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			fn(filepath.ToSlash(rel), d.Name())
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPackagesListed(t *testing.T) {
	listed := docTable(t, "## Packages")
	found := map[string]bool{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(p, ".go") {
				rel, _ := filepath.Rel(root, filepath.Dir(p))
				found[filepath.ToSlash(rel)] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range sorted(found) {
		if !listed[p] {
			t.Errorf("%s is not in the package table of docs/design/code-layout.md: add a row saying what it is (and name it by the rule there)", p)
		}
	}
	for _, p := range sorted(listed) {
		if !found[p] {
			t.Errorf("docs/design/code-layout.md lists %s, which has no Go files: drop its row", p)
		}
	}
}

// cliPrefix is the first word of a file name in internal/cli, after the
// platform ending is taken off: db_dump_tls.go is db, term_unix.go is term.
func cliPrefix(name string) string {
	stem := strings.TrimSuffix(name, ".go")
	parts := strings.Split(stem, "_")
	if n := len(parts); n > 1 && (knownOS[parts[n-1]] || parts[n-1] == "unix" || parts[n-1] == "other") {
		parts = parts[:n-1]
	}
	return parts[0]
}

func TestCLIFileNames(t *testing.T) {
	nouns := nouns(t)
	areas := docTable(t, "### Shared areas")
	for _, a := range sorted(areas) {
		if nouns[a] {
			t.Errorf("docs/design/code-layout.md: %q is a command noun, not a shared area: drop its row", a)
		}
	}
	used := map[string]bool{}
	programFiles(t, func(rel, name string) {
		p := cliPrefix(name)
		used[p] = true
		if nouns[p] || areas[p] {
			return
		}
		hint := "name it <noun>.go, <noun>_<verb>.go or <noun>_<topic>.go after the command it serves, or <area>_<topic>.go with a shared area of docs/design/code-layout.md"
		for _, n := range append(sorted(nouns), sorted(areas)...) {
			if len(p) > len(n) && strings.HasPrefix(p, n) {
				hint = "join the words with _: " + n + "_" + strings.TrimPrefix(strings.TrimSuffix(name, ".go"), n) + ".go"
				break
			}
		}
		t.Errorf("%s: %q is neither a command noun nor a shared area; %s", rel, p, hint)
	}, "internal/cli")
	for _, a := range sorted(areas) {
		if !used[a] {
			t.Errorf("docs/design/code-layout.md: no file in internal/cli uses the shared area %q: drop its row", a)
		}
	}
}

// buildLine is a file's //go:build expression, "" when it has none.
func buildLine(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if expr, ok := strings.CutPrefix(line, "//go:build "); ok {
			return strings.TrimSpace(expr)
		}
		if strings.HasPrefix(line, "package ") {
			break
		}
	}
	return ""
}

var buildWord = regexp.MustCompile(`!?[A-Za-z0-9_.]+`)

// checkPlatform says what is wrong with a program file's platform ending
// and //go:build line, or "" when they agree. siblings are the file names
// in the same folder.
func checkPlatform(name, expr string, siblings map[string]bool) string {
	stem := strings.TrimSuffix(name, ".go")
	parts := strings.Split(stem, "_")
	end := ""
	if len(parts) > 1 {
		end = parts[len(parts)-1]
	}
	terms := buildWord.FindAllString(expr, -1)
	namesOS := false
	for _, w := range terms {
		w = strings.TrimPrefix(w, "!")
		if knownOS[w] || w == "unix" {
			namesOS = true
		}
	}
	switch {
	case knownArch[end]:
		return "ends with the processor word _" + end + ", so Go builds it only there: rename it"
	case knownOS[end]:
		if expr != "" && !strings.Contains(expr, end) {
			return "is a _" + end + " file, but its //go:build line (" + expr + ") does not name " + end
		}
	case end == "unix":
		if expr != "!windows" && expr != "unix" {
			return "a _unix file needs //go:build !windows (or unix), not " + strings.TrimSpace("//go:build "+expr)
		}
	case end == "other":
		if len(terms) == 0 {
			return "an _other file needs a //go:build line naming the systems of the files beside it (!windows, !darwin)"
		}
		base := strings.TrimSuffix(stem, "_other")
		for _, w := range terms {
			goos, neg := strings.CutPrefix(w, "!")
			if !neg || !knownOS[goos] {
				return "an _other file's //go:build line only rules out systems (!windows && !darwin), not " + w
			}
			if !siblings[base+"_"+goos+".go"] {
				return "rules out " + goos + ", but there is no " + base + "_" + goos + ".go beside it"
			}
		}
	default:
		if namesOS {
			return "its //go:build line (" + expr + ") names a system: end the name with _<system>, _unix or _other"
		}
	}
	return ""
}

func TestPlatformFileNames(t *testing.T) {
	dirFiles := map[string]map[string]bool{}
	siblings := func(dir string) map[string]bool {
		if m, ok := dirFiles[dir]; ok {
			return m
		}
		m := map[string]bool{}
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			m[e.Name()] = true
		}
		dirFiles[dir] = m
		return m
	}
	programFiles(t, func(rel, name string) {
		expr := buildLine(t, filepath.Join(root, rel))
		if msg := checkPlatform(name, expr, siblings(filepath.Dir(rel))); msg != "" {
			t.Errorf("%s: %s", rel, msg)
		}
	}, "internal", "cmd")
}

// The checks themselves, on names that break each rule.
func TestPlatformRuleCatches(t *testing.T) {
	sib := map[string]bool{"a_windows.go": true, "a_other.go": true, "b_darwin.go": true}
	for _, c := range []struct {
		name, expr string
		bad        bool
	}{
		{"a_windows.go", "", false},
		{"a_windows.go", "windows", false},
		{"a_windows.go", "linux", true},
		{"a_other.go", "!windows", false},
		{"a_other.go", "!darwin", true}, // no a_darwin.go beside it
		{"a_other.go", "", true},
		{"a_other.go", "linux", true},
		{"b_unix.go", "!windows", false},
		{"b_unix.go", "unix", false},
		{"b_unix.go", "linux", true},
		{"b_unix.go", "", true},
		{"c_arm.go", "", true},
		{"c.go", "!windows", true},
		{"c.go", "", false},
		{"windows_fs.go", "", false},
	} {
		if got := checkPlatform(c.name, c.expr, sib); (got != "") != c.bad {
			t.Errorf("checkPlatform(%q, %q) = %q, want bad=%v", c.name, c.expr, got, c.bad)
		}
	}
}

func TestCLIPrefix(t *testing.T) {
	for name, want := range map[string]string{
		"db_dump_tls.go":         "db",
		"term_unix.go":           "term",
		"doctor_sec_windows.go":  "doctor",
		"approval_win_other.go":  "approval",
		"windows.go":             "windows",
		"windows_fs.go":          "windows",
		"cluster_kctl_change.go": "cluster",
	} {
		if got := cliPrefix(name); got != want {
			t.Errorf("cliPrefix(%q) = %q, want %q", name, got, want)
		}
	}
}
