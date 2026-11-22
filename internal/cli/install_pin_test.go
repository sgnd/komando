package cli

import (
	"bytes"
	"os"
	"regexp"
	"strings"
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

// install.sh is pinned by the hash in the release's signed checksums.txt, and
// that hash is of the tag's copy. The install line in a release's notes must
// fetch the tag's copy, not main's, which moves on.
func TestReleaseNotesInstallLineUsesTag(t *testing.T) {
	wf, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wf, []byte("/komando/main/install.sh")) {
		t.Error("release.yml fetches install.sh from main; a release's install line must use its tag")
	}
	if !bytes.Contains(wf, []byte("/komando/@TAG@/install.sh")) || !bytes.Contains(wf, []byte("s|@TAG@|$GITHUB_REF_NAME|g")) {
		t.Error("release.yml does not put the release tag into the install line of the notes")
	}
}

// The install page says the hash in checksums.txt is of the tag's copy of
// install.sh.
func TestInstallDocSaysHashIsOfTagCopy(t *testing.T) {
	doc, err := os.ReadFile("../../docs/features/install.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(doc, []byte("install.sh` line in a release's `checksums.txt`")) {
		t.Error("docs/features/install.md does not say which copy of install.sh the checksums.txt hash covers")
	}
}

// A tag is any ref git accepts, `|` and `&` included, and the workflow puts it
// into shell and sed programs. Every job that reads GITHUB_REF_NAME starts
// with a step that stops anything but vX.Y.Z.
func TestReleaseJobsCheckTagFirst(t *testing.T) {
	wf, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	const guard = `[[ "$GITHUB_REF_NAME" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]`
	_, jobs, ok := strings.Cut(string(wf), "\njobs:\n")
	if !ok {
		t.Fatal("release.yml has no jobs")
	}
	jobHead := regexp.MustCompile(`(?m)^  ([a-z-]+):\n`)
	idx := jobHead.FindAllStringSubmatchIndex(jobs, -1)
	checked := 0
	for i, m := range idx {
		end := len(jobs)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		name, body := jobs[m[2]:m[3]], jobs[m[1]:end]
		if !strings.Contains(body, "GITHUB_REF_NAME") {
			continue
		}
		checked++
		_, steps, _ := strings.Cut(body, "    steps:\n")
		_, fromFirst, _ := strings.Cut(steps, "      - ")
		firstStep, _, _ := strings.Cut(fromFirst, "\n      - ")
		if !strings.Contains(firstStep, guard) {
			t.Errorf("job %q: its first step is not the check that the tag is vX.Y.Z", name)
		}
	}
	if checked < 2 {
		t.Errorf("only %d jobs read the tag; the scan is broken", checked)
	}
}
