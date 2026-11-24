package cli

import (
	"testing"
	"time"
)

// These tests pin the small formatting helpers that move into
// internal/cli/kit/term, before they move: the same inputs must give the
// same bytes after.

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1 << 20, "1.0 MiB"},
		{5 << 30, "5.0 GiB"},
		{1 << 40, "1.0 TiB"},
		{1 << 60, "1.0 EiB"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := humanBytes(tt.in); got != tt.want {
				t.Errorf("humanBytes(%d) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCleanTextCases(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain text stays", "web1: up", "web1: up"},
		{"control characters go", "a\x1b[31mb\x07\n", "a[31mb"},
		{"bidi controls go", "a\u202eb\u2066c", "abc"},
		{"letters of any script stay", "日本 é", "日本 é"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanText(tt.in); got != tt.want {
				t.Errorf("cleanText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestJoinAnd(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b"}, "a and b"},
		{[]string{"a", "b", "c"}, "a, b and c"},
	}
	for _, tt := range tests {
		if got := joinAnd(tt.in); got != tt.want {
			t.Errorf("joinAnd(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPlural(t *testing.T) {
	for n, want := range map[int]string{0: "s", 1: "", 2: "s", 100: "s"} {
		if got := plural(n); got != want {
			t.Errorf("plural(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestYesAndTimeCells(t *testing.T) {
	if yesCell(true) != "yes" || yesCell(false) != "-" {
		t.Errorf("yesCell: %q %q", yesCell(true), yesCell(false))
	}
	if got := timeCell(time.Time{}); got != "-" {
		t.Errorf("timeCell(zero) = %q", got)
	}
	at := time.Date(2026, 11, 7, 7, 30, 0, 0, time.UTC)
	if got, want := timeCell(at), at.Local().Format("2006-01-02 15:04 MST"); got != want {
		t.Errorf("timeCell = %q, want %q", got, want)
	}
}
