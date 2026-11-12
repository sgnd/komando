package out

import (
	"bytes"
	"testing"
)

func TestUnicodeOK(t *testing.T) {
	for _, c := range []struct {
		term, all, ctype, lang string
		want                   bool
	}{
		{"xterm-256color", "", "", "en_US.UTF-8", true},
		{"xterm", "", "", "", true}, // no locale: Windows, containers
		{"dumb", "", "", "en_US.UTF-8", false},
		{"xterm", "C", "", "en_US.UTF-8", false}, // LC_ALL wins
		{"xterm", "", "en_US.ISO-8859-1", "", false},
		{"xterm", "", "C.utf8", "", true},
		{"xterm", "", "", "POSIX", false},
	} {
		t.Setenv("TERM", c.term)
		t.Setenv("LC_ALL", c.all)
		t.Setenv("LC_CTYPE", c.ctype)
		t.Setenv("LANG", c.lang)
		if got := UnicodeOK(); got != c.want {
			t.Errorf("TERM=%q LC_ALL=%q LC_CTYPE=%q LANG=%q: UnicodeOK %v, want %v", c.term, c.all, c.ctype, c.lang, got, c.want)
		}
	}
}

func TestTextMarksFallBackToASCII(t *testing.T) {
	// a result's text is data (a file, a row, a log line): it is shown as
	// it is, so a person can copy it into fs replace --old. Only komando's
	// own lines (errors, hints, warnings) fall back to ASCII.
	data := textOf("✓ state  ok\n● web1  ok · 2 updates\nupdated komando v1 → v2…\n")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("TERM", "dumb")
	var buf bytes.Buffer
	(&Printer{Format: "text", W: &buf}).Print("x", data, nil)
	if got := buf.String(); got != string(data) {
		t.Fatalf("TERM=dumb changed the data: %q", got)
	}
	if got := Marks("v1 → v2…"); got != "v1 -> v2..." {
		t.Errorf("komando's own line: %q", got)
	}
	t.Setenv("TERM", "xterm-256color")
	if got := Marks("v1 → v2"); got != "v1 → v2" {
		t.Errorf("a UTF-8 terminal must keep the marks: %q", got)
	}
}

type textOf string

func (t textOf) Text() string { return string(t) }
