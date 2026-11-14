package boundary

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// releaseSites are the komando-owned addresses the code may name: the
// release site and the same repository, nothing else. A URL matches when it
// is the prefix itself or goes on with "/", "#" or "?".
var releaseSites = []struct{ prefix, why string }{
	{"https://github.com/sgnd/komando", "the release site: `komando update` reads releases here, and hints link to the install steps and docs of the same repo"},
	{"https://raw.githubusercontent.com/sgnd/komando", "files of the same repo, such as the install line's install.sh"},
	{"https://api.github.com/repos/sgnd/komando", "GitHub's API for the same release site"},
}

// projectOwner is the GitHub account komando's repositories live under.
const projectOwner = "sgnd"

// codeHosts are shared code hosts: a URL there is komando-owned only when
// its path is under projectOwner (api.github.com puts "repos/" first).
var codeHosts = map[string]bool{
	"github.com":                true,
	"api.github.com":            true,
	"raw.githubusercontent.com": true,
	"codeload.github.com":       true,
}

// komandoOwned says whether u points at a place komando's makers run: a
// host with "komando" in its name (komando.dev, cloud.komando.example), or
// a shared code host under the project's own account. Everyone else's hosts
// (cloud providers, docs, GitHub's download servers) are not komando-owned.
func komandoOwned(u string) bool {
	rest := u[strings.Index(u, "://")+3:]
	host, path, _ := strings.Cut(rest, "/")
	host = strings.ToLower(host)
	if i := strings.IndexAny(host, ":?#"); i >= 0 {
		host = host[:i]
	}
	if strings.Contains(host, "komando") {
		return true
	}
	if codeHosts[host] {
		path = strings.TrimPrefix(path, "repos/")
		owner, _, _ := strings.Cut(path, "/")
		return strings.EqualFold(strings.TrimRight(owner, "#?"), projectOwner)
	}
	return false
}

func releaseSite(u string) bool {
	for _, s := range releaseSites {
		if u == s.prefix || (strings.HasPrefix(u, s.prefix) && strings.ContainsRune("/#?", rune(u[len(s.prefix)]))) {
			return true
		}
	}
	return false
}

// webURL finds web addresses in a string. Only the address is taken: it
// stops at a space, a quote or a format verb's brackets.
var webURL = regexp.MustCompile(`https?://[^\s"'` + "`" + `<>()\[\]{}]+`)

// TestNoKomandoHosts reads every string in the program code (not tests, not
// testdata) under internal/ and cmd/ and fails on a komando-owned web
// address other than the release site. Only strings are read, since only a
// string can become an address the program calls; comments may link
// anywhere. A host built from pieces at run time is not caught here:
// review keeps that out.
func TestNoKomandoHosts(t *testing.T) {
	fset := token.NewFileSet()
	strs := 0
	for _, dir := range []string{"internal", "cmd"} {
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
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				strs++
				for _, u := range webURL.FindAllString(s, -1) {
					if komandoOwned(u) && !releaseSite(u) {
						t.Errorf("%s:%d: %s is a komando-owned address. komando calls no komando-owned host "+
							"except the release site, and only when a person runs `komando update` "+
							"(docs/design/principles.md, the paid boundary). Remove it, or move the code that "+
							"needs it to Komando Cloud or the apps. If it is the release site at a new address, "+
							"add it to releaseSites in internal/boundary/urls_test.go with its reason.",
							filepath.ToSlash(rel), fset.Position(lit.Pos()).Line, u)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if strs < 1000 {
		t.Errorf("only %d strings read; the scan is broken", strs)
	}
}

// TestKomandoOwned keeps the meaning of "komando-owned" exact.
func TestKomandoOwned(t *testing.T) {
	for u, want := range map[string]bool{
		"https://cloud.komando.example/v1":                     true,
		"https://komando.dev":                                  true,
		"https://api.Komando-Cloud.com:443/sync":               true,
		"https://github.com/sgnd/komando-sync":                 true,
		"https://api.github.com/repos/sgnd/komando/releases":   true,
		"https://github.com/sgnd":                              true,
		"https://github.com/someone/komandox":                  false,
		"https://github.com/spf13/cobra":                       false,
		"https://objects.githubusercontent.com/release-assets": false,
		"https://www.googleapis.com/storage/v1":                false,
		"https://management.core.windows.net/":                 false,
		"http://localhost:8080":                                false,
	} {
		if got := komandoOwned(u); got != want {
			t.Errorf("komandoOwned(%q) = %v, want %v", u, got, want)
		}
	}
	for u, want := range map[string]bool{
		"https://github.com/sgnd/komando":                    true,
		"https://github.com/sgnd/komando#install":            true,
		"https://github.com/sgnd/komando/releases/latest":    true,
		"https://github.com/sgnd/komando-sync":               false,
		"https://github.com/sgnd/komandocloud/releases":      false,
		"https://api.github.com/repos/sgnd/komando/releases": true,
	} {
		if got := releaseSite(u); got != want {
			t.Errorf("releaseSite(%q) = %v, want %v", u, got, want)
		}
	}
}
