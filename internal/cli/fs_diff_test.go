package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnifiedDiffHeaders(t *testing.T) {
	a := "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n"
	b := "1\n2\n3\n4\nfive\n6\n7\n8\n9\n10\n"
	want := "@@ -2,7 +2,7 @@\n 2\n 3\n 4\n-5\n+five\n 6\n 7\n 8\n"
	if got := unifiedDiff(a, b, 3); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	// an insertion keeps the unchanged lines as context, not -/+
	got := unifiedDiff("a\nb\nc\n", "a\nx\nb\nc\n", 3)
	if strings.Contains(got, "-b") || !strings.Contains(got, "@@ -1,3 +1,4 @@") {
		t.Errorf("insertion diff:\n%s", got)
	}
	if unifiedDiff("same\n", "same\n", 3) != "" {
		t.Error("no change must give no diff")
	}
}

// TestUnifiedDiffMatchesDiffU compares hunks with the system diff -u.
func TestUnifiedDiffMatchesDiffU(t *testing.T) {
	unixOnly(t, "compares with the diff program")
	if _, err := exec.LookPath("diff"); err != nil {
		t.Skip("no diff")
	}
	cases := [][2]string{
		{"a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\n", "a\nB\nc\nd\ne\nf\ng\nh\ni\nj\nk\nL\nm\nn\n"},
		{"a\nb\nc\n", "a\nb\nc\nd\n"},
		{"", "new\n"},
		{"old\n", ""},
		{"x\ny\nz\n", "z\ny\nx\n"},
		{"1\n2\n3\n4\n5\n6\n7\n8\n", "1\n2\n4\n5\n6\n7\n8\n9\n"},
		{"no newline", "no newline\n"},
	}
	dir := t.TempDir()
	for _, c := range cases {
		pa, pb := filepath.Join(dir, "a"), filepath.Join(dir, "b")
		_ = os.WriteFile(pa, []byte(c[0]), 0o600)
		_ = os.WriteFile(pb, []byte(c[1]), 0o600)
		o, _ := exec.Command("diff", "-u", pa, pb).Output()
		lines := strings.SplitN(string(o), "\n", 3)
		want := ""
		if len(lines) == 3 {
			want = lines[2] // without the --- / +++ header
		}
		if got := unifiedDiff(c[0], c[1], 3); got != want {
			t.Errorf("%q -> %q\ngot:\n%s\nwant:\n%s", c[0], c[1], got, want)
		}
	}
}
