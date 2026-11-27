package term

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// These tests pin the width, table and empty-list helpers before they move
// into internal/cli/kit/term: the same inputs must give the same bytes
// after the move.

func TestDisplayWidthCases(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"ascii", "host", 4},
		{"empty", "", 0},
		{"cjk takes two columns", "日本", 4},
		{"emoji takes two columns", "a🚀", 3},
		{"combining mark takes none", "é", 1},
		{"control characters take none", "a\tb\x7f", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DisplayWidth(tt.in); got != tt.want {
				t.Errorf("DisplayWidth(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestTruncateWidthCases(t *testing.T) {
	tests := []struct {
		name string
		in   string
		w    int
		want string
	}{
		{"fits", "abc", 3, "abc"},
		{"cut ends in an ellipsis", "abcdef", 4, "abc…"},
		{"never splits a wide character", "日本語", 4, "日…"},
		{"width one keeps only the ellipsis", "abc", 1, "…"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TruncateWidth(tt.in, tt.w); got != tt.want {
				t.Errorf("TruncateWidth(%q, %d) = %q, want %q", tt.in, tt.w, got, tt.want)
			}
		})
	}
}

func TestLayoutTable(t *testing.T) {
	got := LayoutTable([]string{"name", "status"}, [][]string{{"web1", "up"}, {"日本", ""}, {"a"}})
	want := "name  status\nweb1  up\n日本\na\n"
	if got != want {
		t.Errorf("LayoutTable:\n got %q\nwant %q", got, want)
	}
}

func TestDataTable(t *testing.T) {
	rows := [][]string{{"web1", ""}, {"db", "up"}}
	got := DataTable([]string{"name", "status"}, rows)
	want := "NAME  STATUS\nweb1  -\ndb    up\n"
	if got != want {
		t.Errorf("DataTable:\n got %q\nwant %q", got, want)
	}
	if rows[0][1] != "-" {
		t.Errorf("DataTable fills the empty cell in the rows it is given: %q", rows[0][1])
	}
}

func TestEmptyListLines(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"yet with an add command", NoneYet("SSH keys", "credential key create NAME"), "no SSH keys yet: `komando credential key create NAME`\n"},
		{"yet for a list komando does not fill", NoneYet("recordings", ""), "no recordings yet\n"},
		{"yet with notes", NoneYet("servers", "host ssh add NAME", "a", "b"), "no servers yet: `komando host ssh add NAME` (a; b)\n"},
		{"match", NoneMatch("cache keys", `"user:*"`), "no cache keys match \"user:*\"\n"},
		{"match with a note", NoneMatch("jobs", "web", "5 hidden"), "no jobs match web (5 hidden)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestDisplayWidth(t *testing.T) {
	for s, want := range map[string]int{"abc": 3, "日本": 4, "🎉": 2, "é": 1, "é": 1, "Ünïcødé 日本 🎉": 15} {
		if got := DisplayWidth(s); got != want {
			t.Errorf("%q: %d, want %d", s, got, want)
		}
	}
	if got := TruncateWidth("日本語のテキスト", 9); got != "日本語の…" {
		t.Errorf("truncate: %q", got)
	}
	// A long command of multi-byte characters is cut whole, never mid-character.
	if got := TruncateWidth(strings.Repeat("é", 70), 60); !utf8.ValidString(got) || DisplayWidth(got) != 60 {
		t.Errorf("multi-byte cut: %q", got)
	}
}

// Columns line up by terminal width, also next to wide characters.
func TestLayoutTableWide(t *testing.T) {
	tab := LayoutTable([]string{"name", "n"}, [][]string{{"日本", "1"}, {"abcdef", "2"}})
	lines := strings.Split(strings.TrimSpace(tab), "\n")
	col := -1
	for _, l := range lines {
		idx := strings.LastIndex(l, " ") + 1
		w := DisplayWidth(l[:idx])
		if col >= 0 && w != col {
			t.Fatalf("misaligned:\n%s", tab)
		}
		col = w
	}
}
