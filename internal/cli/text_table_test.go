package cli

import "testing"

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
			if got := displayWidth(tt.in); got != tt.want {
				t.Errorf("displayWidth(%q) = %d, want %d", tt.in, got, tt.want)
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
			if got := truncateWidth(tt.in, tt.w); got != tt.want {
				t.Errorf("truncateWidth(%q, %d) = %q, want %q", tt.in, tt.w, got, tt.want)
			}
		})
	}
}

func TestLayoutTable(t *testing.T) {
	got := layoutTable([]string{"name", "status"}, [][]string{{"web1", "up"}, {"日本", ""}, {"a"}})
	want := "name  status\nweb1  up\n日本\na\n"
	if got != want {
		t.Errorf("layoutTable:\n got %q\nwant %q", got, want)
	}
}

func TestDataTable(t *testing.T) {
	rows := [][]string{{"web1", ""}, {"db", "up"}}
	got := dataTable([]string{"name", "status"}, rows)
	want := "NAME  STATUS\nweb1  -\ndb    up\n"
	if got != want {
		t.Errorf("dataTable:\n got %q\nwant %q", got, want)
	}
	if rows[0][1] != "-" {
		t.Errorf("dataTable fills the empty cell in the rows it is given: %q", rows[0][1])
	}
}

func TestEmptyListLines(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"yet with an add command", noneYet("SSH keys", "key gen NAME"), "no SSH keys yet: `komando key gen NAME`\n"},
		{"yet for a list komando does not fill", noneYet("recordings", ""), "no recordings yet\n"},
		{"yet with notes", noneYet("servers", "host add NAME", "a", "b"), "no servers yet: `komando host add NAME` (a; b)\n"},
		{"match", noneMatch("cache keys", `"user:*"`), "no cache keys match \"user:*\"\n"},
		{"match with a note", noneMatch("jobs", "web", "5 hidden"), "no jobs match web (5 hidden)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}
