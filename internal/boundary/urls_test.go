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

	"golang.org/x/net/publicsuffix"
)

// releaseSites are the komando-owned addresses the code may name: the
// release site and the same repository, nothing else. An address matches
// when it is the prefix itself or goes on with "/", "#" or "?". A name
// with no scheme (github.com/sgnd/komando) counts as https.
var releaseSites = []struct{ prefix, why string }{
	{"https://github.com/sgnd/komando", "the release site: `komando update` reads releases here, and hints link to the install steps and docs of the same repo"},
}

// projectOwner is the GitHub account komando's repositories live under.
const projectOwner = "sgnd"

// codeHosts are shared code hosts: an address there is komando-owned only
// when its path is under projectOwner (api.github.com puts "repos/" first).
var codeHosts = map[string]bool{
	"github.com":                true,
	"api.github.com":            true,
	"raw.githubusercontent.com": true,
	"codeload.github.com":       true,
}

// notHosts are names in program code that look like a komando-owned host
// but are not addresses. They are excused only as bare names: with a
// scheme (https://komando.id) they are still caught.
var notHosts = map[string]string{
	"komando.id":   "a command annotation key (cmdIDNote in internal/cli/cmdid.go)",
	"komando.fish": "the fish completion file name",
}

// komandoOwned says whether addr points at a place komando's makers run:
// a host with "komando" in its name (komando.dev, relay.komando.example),
// or a shared code host under the project's own account. addr may have any
// scheme (https://, wss://, grpc://) or none. Everyone else's hosts (cloud
// providers, docs, GitHub's download servers) are not komando-owned.
func komandoOwned(addr string) bool {
	if i := strings.Index(addr, "://"); i >= 0 {
		addr = addr[i+3:]
	}
	host, path, _ := strings.Cut(addr, "/")
	if i := strings.IndexAny(host, "?#"); i >= 0 {
		host = host[:i]
	}
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)
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

func releaseSite(addr string) bool {
	if !strings.Contains(addr, "://") {
		addr = "https://" + addr
	}
	for _, s := range releaseSites {
		if addr == s.prefix || (strings.HasPrefix(addr, s.prefix) && strings.ContainsRune("/#?", rune(addr[len(s.prefix)]))) {
			return true
		}
	}
	return false
}

// stop ends an address: a space, a quote or a bracket (as around a format
// verb).
const stop = `\s"'` + "`" + `<>()\[\]{}`

// schemeURL finds addresses with any scheme: https://, wss://, grpc://.
var schemeURL = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^` + stop + `]+`)

// bareHost finds a dotted name with no scheme, with what follows it up to
// a stop: relay.komando.dev, github.com/sgnd/komando-sync. It must start
// a word: the "komando.dev" in "x_komando.dev" is not taken.
var bareHost = regexp.MustCompile(`(?i)(?:^|[^a-z0-9._-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z](?:[a-z0-9-]*[a-z0-9])?)([:/?#][^` + stop + `]*)?`)

// badAddresses returns the komando-owned addresses in s other than the
// release site, with or without a scheme. A bare name counts as a host
// only when it ends in a real top-level domain from the public suffix
// list, so komando.exe and komando-backup.json stay file names.
func badAddresses(s string) []string {
	var bad []string
	for _, u := range schemeURL.FindAllString(s, -1) {
		if komandoOwned(u) && !releaseSite(u) {
			bad = append(bad, u)
		}
	}
	s = schemeURL.ReplaceAllString(s, " ")
	for _, m := range bareHost.FindAllStringSubmatch(s, -1) {
		host, rest := strings.ToLower(m[1]), m[2]
		if _, ok := notHosts[host]; ok {
			continue
		}
		tld := host[strings.LastIndex(host, ".")+1:]
		if _, icann := publicsuffix.PublicSuffix(tld); !icann {
			continue
		}
		if addr := host + rest; komandoOwned(addr) && !releaseSite(addr) {
			bad = append(bad, m[1]+rest)
		}
	}
	return bad
}

// TestNoKomandoHosts reads every string in the program code (not tests, not
// testdata) under internal/ and cmd/ and fails on a komando-owned address
// other than the release site, with any scheme or none. Only strings are
// read, since only a string can become an address the program calls;
// comments may link anywhere. A host built from pieces at run time is not caught here:
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
				for _, u := range badAddresses(s) {
					t.Errorf("%s:%d: %s is a komando-owned address. komando calls no komando-owned host "+
						"except the release site, and only when a person runs `komando update` "+
						"(docs/design/principles.md, the paid boundary). Remove it, or move the code that "+
						"needs it to Komando Cloud or the apps. If it is the release site at a new address, "+
						"add it to releaseSites in internal/boundary/urls_test.go with its reason. If it is "+
						"not an address at all (a key or a file name), add it to notHosts there.",
						filepath.ToSlash(rel), fset.Position(lit.Pos()).Line, u)
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
		"wss://relay.komando.dev/v1":                           true,
		"relay.komando.dev":                                    true,
		"user@relay.komando.dev:22":                            true,
		"https://github.com/sgnd/komando-sync":                 true,
		"github.com/sgnd/komando-sync":                         true,
		"https://api.github.com/repos/sgnd/komando/releases":   true,
		"https://github.com/sgnd":                              true,
		"https://github.com/someone/komandox":                  false,
		"https://github.com/spf13/cobra":                       false,
		"https://objects.githubusercontent.com/release-assets": false,
		"https://www.googleapis.com/storage/v1":                false,
		"s3.amazonaws.com":                                     false,
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
		"github.com/sgnd/komando/releases":                   true,
		"https://github.com/sgnd/komando-sync":               false,
		"https://github.com/sgnd/komandocloud/releases":      false,
		"wss://github.com/sgnd/komando":                      false,
		"https://api.github.com/repos/sgnd/komando/releases": false,
		"https://raw.githubusercontent.com/sgnd/komando/x":   false,
	} {
		if got := releaseSite(u); got != want {
			t.Errorf("releaseSite(%q) = %v, want %v", u, got, want)
		}
	}
}

// TestBadAddresses finds komando-owned addresses with any scheme or none,
// and leaves file names, keys and everyone else's hosts alone.
func TestBadAddresses(t *testing.T) {
	for s, want := range map[string]string{
		"wss://relay.komando.dev/v1":                         "wss://relay.komando.dev/v1",
		"grpc://sync.komando.app:443":                        "grpc://sync.komando.app:443",
		"relay.komando.dev":                                  "relay.komando.dev",
		"dial relay.komando.dev:443 now":                     "relay.komando.dev:443",
		"addr=api.komando.cloud/v1":                          "api.komando.cloud/v1",
		"go get github.com/sgnd/komando-sync":                "github.com/sgnd/komando-sync",
		"https://komando.id":                                 "https://komando.id",
		"see https://github.com/sgnd/komando/releases":       "",
		"github.com/sgnd/komando#install":                    "",
		"komando.id":                                         "",
		"~/.config/fish/completions/komando.fish":            "",
		"komando.exe":                                        "",
		"komando export --to komando-backup.json":            "",
		"komando.synonym-of":                                 "",
		"https://storage.googleapis.com/b/o":                 "",
		"s3.amazonaws.com":                                   "",
		"internal/cloud/aws":                                 "",
		"wss://example.com/socket":                           "",
		"https://objects.githubusercontent.com/github-x/abc": "",
	} {
		got := strings.Join(badAddresses(s), " ")
		if got != want {
			t.Errorf("badAddresses(%q) = %q, want %q", s, got, want)
		}
	}
}
