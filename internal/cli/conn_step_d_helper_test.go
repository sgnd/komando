package cli

import (
	"cmp"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/store"
)

// Row C488 (step D): the command that does a verb for an entry is the
// entry's type and provider path, from the saved entry or from its URL.
func TestEntryWordsOfURL(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{"postgres://u@127.0.0.1:5/db", []string{"database", "postgres"}},
		{"mariadb://u@127.0.0.1:5/db", []string{"database", "mysql"}}, // a mariadb URL parses as kind mysql
		{"redis://127.0.0.1:6379/0", []string{"cache", "redis"}},
		{"k8s://1.2.3.4", []string{"cluster", "kubernetes"}},
		{"registry://ghcr.io", []string{"registry", "oci"}},
		{"ftps://u@127.0.0.1:1/p", []string{"storage", "ftp"}},
		{"s3://bucket?endpoint=http://s3:3900", []string{"storage", "s3"}}, // only the first scheme counts
		{"  postgres://u@127.0.0.1:5/db ", []string{"database", "postgres"}},
		{"no scheme here", nil},
		{"", nil},
	} {
		if got := entryWordsOfURL(tc.raw); !slices.Equal(got, tc.want) {
			t.Errorf("entryWordsOfURL(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestEntryWords(t *testing.T) {
	for _, tc := range []struct {
		c    *store.Conn
		want []string
	}{
		{&store.Conn{Name: "pg", Kind: "postgres", URL: "postgres://u@127.0.0.1:5/db"}, []string{"database", "postgres"}},
		{&store.Conn{Name: "k1", Kind: "k8s", URL: "k8s://1.2.3.4"}, []string{"cluster", "kubernetes"}},
		{&store.Conn{Name: "bad", URL: "::"}, nil},
		{nil, nil},
	} {
		if got := entryWords(tc.c); !slices.Equal(got, tc.want) {
			t.Errorf("entryWords(%v) = %q, want %q", tc.c, got, tc.want)
		}
	}
}

// entryCmd writes the placeholders fillHint fills when the type, the
// provider or the name is not known where the text is written.
func TestEntryCmd(t *testing.T) {
	for _, tc := range []struct {
		words      []string
		verb, name string
		want       string
	}{
		{[]string{"database", "postgres"}, "show", "pg", "komando database postgres show pg"},
		{[]string{"database", "postgres"}, "edit", "", "komando database postgres edit NAME"},
		{[]string{"cache"}, "show", "r1", "komando cache PROVIDER show r1"},
		{nil, "remove", "x", "komando TYPE PROVIDER remove x"},
		{[]string{"registry", "oci"}, "", "", "komando registry oci"},
	} {
		if got := entryCmd(tc.words, tc.verb, tc.name); got != tc.want {
			t.Errorf("entryCmd(%q, %q, %q) = %q, want %q", tc.words, tc.verb, tc.name, got, tc.want)
		}
	}
}

var sampleEntryHead = regexp.MustCompile(`^(TYPE|[a-z]+) (KIND|PROVIDER)\b`)

// sampleProviders stand for an unfilled provider in the reference checks.
var sampleProviders = map[string]string{"database": "postgres", "cache": "redis", "queue": "kafka",
	"storage": "s3", "cluster": "kubernetes", "registry": "oci"}

// sampleEntryPath writes an entry's path that a hint leaves for fillHint
// (TYPE, and KIND or PROVIDER after a type) with a sample provider, so the
// reference checks see a command: TYPE is a database.
func sampleEntryPath(ref string) string {
	m := sampleEntryHead.FindStringSubmatch(ref)
	if m == nil {
		return ref
	}
	typ := cmp.Or(strings.TrimPrefix(m[1], "TYPE"), "database")
	if p, ok := sampleProviders[typ]; ok {
		return typ + " " + p + ref[len(m[0]):]
	}
	return ref // a VPN's KIND is its own Use word
}

// Every conn type has a sample provider, and it is one of the type's.
func TestSampleProvidersAreProviders(t *testing.T) {
	types := map[string]bool{}
	for _, k := range driver.Kinds() {
		w := entryWordsOfKind(k)
		types[w[0]] = true
		if p := sampleProviders[w[0]]; p == "" {
			t.Errorf("type %s has no sample provider", w[0])
		}
	}
	for typ, p := range sampleProviders {
		if !types[typ] || !slices.ContainsFunc(driver.Kinds(), func(k driver.Kind) bool { return slices.Equal(entryWordsOfKind(k), []string{typ, p}) }) {
			t.Errorf("sample %s %s is no provider of a conn type", typ, p)
		}
	}
}

func TestSampleEntryPath(t *testing.T) {
	for ref, want := range map[string]string{
		"database KIND query NAME":         "database postgres query NAME",
		"TYPE PROVIDER show NAME":          "database postgres show NAME",
		"cache PROVIDER edit NAME --url U": "cache redis edit NAME --url U",
		"vpn KIND start NAME":              "vpn KIND start NAME",
		"test NAME":                        "test NAME",
		"database PROVIDERS":               "database PROVIDERS",
	} {
		if got := sampleEntryPath(ref); got != want {
			t.Errorf("sampleEntryPath(%q) = %q, want %q", ref, got, want)
		}
	}
}

// Every conn kind has moved to the table, so its path is one the tree
// has: entryPath has no other answer left (row C488).
func TestEveryConnKindHasItsPath(t *testing.T) {
	root := newRoot(tcl)
	for _, k := range driver.Kinds() {
		if !slices.Contains(movedTypes, typeWord(k.Family)) {
			t.Errorf("kind %s: type %s has not moved", k.Name, typeWord(k.Family))
			continue
		}
		words := strings.Fields(entryCmd(entryWordsOfKind(k), "add", "NAME"))[1:]
		c, _, err := root.Find(words)
		if err != nil || cmdID(c) != strings.Join(words[:3], ".") {
			t.Errorf("kind %s: %q is no command (found %q, %v)", k.Name, words, cmdID(c), err)
		}
		if got, want := entryPath(k), "komando "+strings.Join(entryWordsOfKind(k), " "); got != want {
			t.Errorf("entryPath(%s) = %q, want %q", k.Name, got, want)
		}
	}
}
