package store

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// C558: the release a person installs to fix a store is spelled in one
// place, LastFormat2Release, so that raising it changes every message,
// the dry run and the docs at once. No other file of the repository spells
// it; CHANGELOG.md lists releases by name and is left out.
func TestLastFormat2ReleaseSpelledOnce(t *testing.T) {
	root := filepath.Join("..", "..")
	home := filepath.Join(root, "internal", "store", "migrate3_fix.go")
	needle := []byte(LastFormat2Release)
	var found []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if p == home || p == filepath.Join(root, "CHANGELOG.md") || !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		// a built program (komando.exe of the Windows job) holds the
		// constant itself; only text spells it
		if bytes.Contains(b, needle) && !bytes.Contains(b[:min(len(b), 8000)], []byte{0}) {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) > 0 {
		t.Fatalf("%s is spelled outside migrate3_fix.go: %v (use store.LastFormat2Release)", LastFormat2Release, found)
	}
	if b, err := os.ReadFile(home); err != nil || !bytes.Contains(b, needle) {
		t.Fatalf("migrate3_fix.go does not spell %s: %v", LastFormat2Release, err)
	}
}

// The install line of the fix is the one docs/features/install.md gives
// for macOS and Linux, with the version of the release.
func TestInstallFormat2FollowsTheDocs(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "features", "install.md"))
	if err != nil {
		t.Fatal(err)
	}
	shape := strings.ReplaceAll(regexp.QuoteMeta(installFormat2), regexp.QuoteMeta(LastFormat2Release), `v[0-9]+\.[0-9]+\.[0-9]+`)
	if !regexp.MustCompile(`(?m)^` + shape + `$`).Match(b) {
		t.Fatalf("docs/features/install.md has no install line of the shape\n%s", installFormat2)
	}
	if !strings.Contains(getFormat2, installFormat2) || strings.Count(installFormat2, LastFormat2Release) != 2 {
		t.Fatalf("the first step %q does not give the install line of %s", getFormat2, LastFormat2Release)
	}
}

// The steps for fields that name no outside store: the release, fix the
// fields there, update again (the steps for an outside login are pinned in
// TestMigrate3StopsOnOutsideLogin).
func TestFixStepsOtherFields(t *testing.T) {
	want := []string{getFormat2, "there, fix each other field listed", "then run `komando update` again"}
	if got := fixSteps(false, true); !slices.Equal(got, want) {
		t.Fatalf("steps\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := numbered([]string{"a", "b"}); got != "1. a 2. b" {
		t.Fatalf("numbered: %q", got)
	}
}
