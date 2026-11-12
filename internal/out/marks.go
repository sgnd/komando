package out

import (
	"os"
	"strings"
)

// asciiMarks spells komando's own marks in ASCII, for a terminal that
// cannot show them: TERM=dumb, or a locale that is not UTF-8 (LANG=C on an
// old server console, a serial line). There they would show as "?" or as
// several broken characters.
var asciiMarks = strings.NewReplacer(
	"✓", "+",
	"✗", "x",
	"●", "*",
	"→", "->",
	"·", "-",
	"…", "...",
	"—", "--",
	"↑↓", "up/down",
	"⚠", "!",
)

// UnicodeOK reports whether the terminal can show non-ASCII marks. TERM=dumb
// cannot. The locale is the first of LC_ALL, LC_CTYPE and LANG that is set,
// as the C library picks it; a set locale that does not name UTF-8 (C,
// POSIX, en_US.ISO-8859-1) cannot either. With no locale at all (Windows,
// most containers) komando keeps the marks: those terminals show UTF-8.
var UnicodeOK = func() bool {
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := os.Getenv(k); v != "" {
			v = strings.ToLower(v)
			return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
		}
	}
	return true
}

// Marks returns s as the terminal can show it: unchanged, or with komando's
// marks (✓ ✗ ● → · …) spelled in ASCII when UnicodeOK is false. It is used
// for komando's own lines (errors, hints, warnings, status), never for a
// result's text: that is data (a file, a row, a log line) and is shown as it is.
func Marks(s string) string {
	if UnicodeOK() {
		return s
	}
	return asciiMarks.Replace(s)
}
