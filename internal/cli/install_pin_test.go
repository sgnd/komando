package cli

import (
	"os"
	"regexp"
	"testing"
)

var (
	changelogHeadRe = regexp.MustCompile(`(?m)^## (?:\[v?(\d+\.\d+\.\d+)\]|v(\d+\.\d+\.\d+)(?:\s|$))`)
	installPinRes   = []*regexp.Regexp{
		regexp.MustCompile(`raw\.githubusercontent\.com/sgnd/komando/(v\d+\.\d+\.\d+)/install\.sh`),
		regexp.MustCompile(`KOMANDO_VERSION=(v\d+\.\d+\.\d+) (?:sudo )?sh`),
		regexp.MustCompile(`installer of release (v\d+\.\d+\.\d+)`),
	}
)

// newestChangelogTag returns the first released version heading of the
// changelog, as a tag, skipping [Unreleased].
func newestChangelogTag(t *testing.T, changelog string) string {
	t.Helper()
	m := changelogHeadRe.FindStringSubmatch(changelog)
	if m == nil {
		t.Fatal("no released version heading found in CHANGELOG.md")
	}
	if m[1] != "" {
		return "v" + m[1]
	}
	return "v" + m[2]
}

// TestInstallDocPinsNewestRelease keeps the install lines in
// docs/features/install.md on the newest released version, so a release
// cannot merge while the page still names the one before. Examples of old
// versions are not install lines and are not checked.
func TestInstallDocPinsNewestRelease(t *testing.T) {
	cl, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../docs/features/install.md")
	if err != nil {
		t.Fatal(err)
	}
	want := newestChangelogTag(t, string(cl))
	found := 0
	for _, re := range installPinRes {
		for _, m := range re.FindAllStringSubmatch(string(doc), -1) {
			found++
			if m[1] != want {
				t.Errorf("docs/features/install.md pins %s in %q; the newest release in CHANGELOG.md is %s", m[1], m[0], want)
			}
		}
	}
	if found < 5 {
		t.Errorf("only %d pinned install lines found; the scan is broken", found)
	}
}

func TestNewestChangelogTag(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"## [Unreleased]\n\n## [0.17.0] - 2026-11-22\n## [0.16.0] - x\n", "v0.17.0"},
		{"## [Unreleased]\n\n## v0.18.1 - 2026-12-01\n## v0.18.0 - x\n", "v0.18.1"},
	} {
		if got := newestChangelogTag(t, c.in); got != c.want {
			t.Errorf("newestChangelogTag = %s, want %s", got, c.want)
		}
	}
}
