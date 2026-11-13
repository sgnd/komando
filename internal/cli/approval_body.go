package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/out"
)

// approvalBody is a file a command sends besides its command line
// (exec --script FILE, --stdin-file, job start --script). The approval
// window shows its SHA-256 and first lines, so a person does not allow a
// script they never saw.
type approvalBody struct {
	label string // "the script ./deploy.sh"
	body  []byte
}

// Lines of a body the window shows, and the most characters of each.
const (
	bodyShownLines = 10
	bodyLineMax    = 160
)

// noteApprovalBody tells the approval window of this command what it sends.
func noteApprovalBody(label string, body []byte) {
	cur().body = &approvalBody{label: label, body: body}
}

// scriptLabel names a file the command reads: "-" is komando's stdin.
func scriptLabel(kind, file string) string {
	if file == "-" {
		return kind + " from komando's stdin"
	}
	return kind + " " + file
}

// shown is the window's text for the body, or why it cannot be shown:
// as for the command line, text that is not valid, or that holds
// invisible characters (bidi overrides, zero-width marks) anywhere, is
// refused. So is a body with what looks like a password, key or token:
// masking it would hide text that runs (the pattern masker takes
// "pass=x|sh</tmp/s" whole as a value), and showing it would put the
// secret on the screen. Values komando keeps secret show as [hidden]
// (hiddenInInput refuses them in the file already). The SHA-256 is of the
// body as sent.
func (b *approvalBody) shown() (text, bad string) {
	if why := hiddenArgs([]string{string(b.body)}); why != "" {
		return "", b.label + " " + strings.TrimPrefix(why, "it ")
	}
	if s := string(b.body); out.MaskSecrets(s) != s {
		return "", b.label + " holds what looks like a password, key or token, which the window does not show"
	}
	sum := sha256.Sum256(b.body)
	lines := strings.Split(strings.TrimSuffix(string(b.body), "\n"), "\n")
	if len(b.body) == 0 {
		lines = nil
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "It also sends %s (%d bytes, %d lines, SHA-256 %s)", b.label, len(b.body), len(lines), hex.EncodeToString(sum[:]))
	if len(lines) == 0 {
		return sb.String() + ".\n\n", ""
	}
	sb.WriteString(", which starts:\n\n")
	for i, l := range lines {
		if i == bodyShownLines {
			fmt.Fprintf(&sb, "… and %d more lines\n", len(lines)-i)
			break
		}
		sb.WriteString(bodyLine(l) + "\n")
	}
	return sb.String() + "\n", ""
}

// bodyLine is one line of a body as the window shows it: komando's own
// secrets hidden, its indent kept short, cut when long, and written with escapes ($'...')
// when a character in it would not show as itself.
func bodyLine(l string) string {
	l = strings.TrimSuffix(l, "\r")
	l = strings.ReplaceAll(l, "\t", "  ")
	l = out.P.RedactExact(l)
	rest := strings.TrimLeft(l, " ")
	indent := min(len(l)-len(rest), maxSpaces)
	cut := ""
	if n := utf8.RuneCountInString(rest); n > bodyLineMax {
		rest = string([]rune(rest)[:bodyLineMax])
		cut = fmt.Sprintf(" …(%d more characters)", n-bodyLineMax)
	}
	if needsEscapes(rest) {
		rest = ansiQuote(rest)
	}
	return "  " + strings.Repeat(" ", indent) + rest + cut
}
