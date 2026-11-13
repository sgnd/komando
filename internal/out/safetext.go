package out

import (
	"fmt"
	"regexp"
	"strings"
)

// sgr is a colour or style sequence (ESC [ ... m): harmless, and what
// `ls --color` or a log line uses, so it stays.
var sgr = regexp.MustCompile(`^\x1b\[[0-9;]*m`)

// SafeText makes text from servers and databases safe to print on a
// terminal: escape sequences other than colours (window titles, clipboard
// writes, cursor moves that fake output), a colour sequence that hides
// text (SGR 8), control characters and bidi overrides (which make text
// read in another order than it runs) are shown as \e, \xNN and \uNNNN
// instead of being run by the terminal. Tabs, newlines and carriage
// returns stay (progress bars use \r; NoCR takes it out where a line
// carries a server's name).
func SafeText(s string) string {
	if !needsSafe(s) {
		return s
	}
	var b strings.Builder
	for i, r := range s {
		switch {
		case r == '\x1b':
			if m := sgr.FindString(s[i:]); m != "" && !conceals(m) {
				b.WriteByte('\x1b')
				continue
			}
			b.WriteString(`\e`)
		case bidiControl(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// noteText is SafeText for komando's own error and hint lines, which can
// carry the command line: no colours or styles either (ESC[8m hides text)
// and no carriage return (it lets the rest overwrite the line). They show
// as \e and \r.
func noteText(s string) string {
	return strings.NewReplacer("\x1b", `\e`, "\r", `\r`).Replace(SafeText(s))
}

func needsSafe(s string) bool {
	for _, r := range s {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0x7f || r >= 0x80 && r <= 0x9f || bidiControl(r) {
			return true
		}
	}
	return false
}

// bidiControl: an embedding, override or isolate (U+202A-U+202E,
// U+2066-U+2069), which reorders the text after it on screen. The plain
// marks U+200E and U+200F stay: right-to-left text uses them.
func bidiControl(r rune) bool {
	return r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
}

// conceals: the colour sequence m turns on hidden text (SGR 8), which
// would let a line carry text a person cannot see. The numbers of a 256 or
// true colour (38;5;N, 48;2;R;G;B) are colours, not 8.
func conceals(m string) bool {
	ps := strings.Split(strings.TrimSuffix(strings.TrimPrefix(m, "\x1b["), "m"), ";")
	for i := 0; i < len(ps); i++ {
		switch ps[i] {
		case "38", "48", "58":
			if i+1 < len(ps) && ps[i+1] == "5" {
				i += 2
			} else if i+1 < len(ps) && ps[i+1] == "2" {
				i += 4
			}
		case "8", "08":
			return true
		}
	}
	return false
}

// NoCR shows a carriage return that does not end a line as \r. A line
// that starts with a server's or pod's name ("[web1] ...") goes through it,
// so the server cannot move back over its name and print another one.
func NoCR(s string) string {
	if !strings.Contains(s, "\r") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' && (i+1 == len(s) || s[i+1] != '\n') {
			b.WriteString(`\r`)
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
