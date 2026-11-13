package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// approvalBody is a file a command sends besides its command line
// (exec --script FILE, --stdin-file, job start --script). The approval
// window shows its SHA-256 and every line of it, so a person does not
// allow a script they never saw whole.
type approvalBody struct {
	label string // "the script ./deploy.sh"
	body  []byte
}

// The window shows a body whole or not at all: a part left out could be
// the one that runs a payload. A long line is wrapped, never cut, and
// each piece counts as a line. The cap keeps the whole text on one
// screen (the macOS and zenity windows do not scroll); a bigger body gets
// no window, and the agent asks the person to run it in their terminal.
const (
	bodyMaxLines = 40       // lines the window shows, wrapped pieces included
	bodyWrap     = 100      // characters of a line per shown piece
	bodyMaxBytes = 16 << 10 // a body this big cannot fit in bodyMaxLines
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
// (hiddenInInput refuses them in the file already). So is a body too
// long to show whole. The SHA-256 is of the body as sent.
func (b *approvalBody) shown() (text, bad string) {
	if len(b.body) > bodyMaxBytes {
		return "", fmt.Sprintf("%s is %d bytes, more than the %d the window shows whole", b.label, len(b.body), bodyMaxBytes)
	}
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
	var shown []string
	numW := len(strconv.Itoa(len(lines)))
	for i, l := range lines {
		for j, piece := range bodyLine(l) {
			num := strconv.Itoa(i + 1)
			if j > 0 {
				num = "" // a wrapped piece of the line above
			}
			shown = append(shown, fmt.Sprintf("  %*s  %s", numW, num, piece))
		}
		if len(shown) > bodyMaxLines {
			return "", fmt.Sprintf("%s is more than the %d lines the window shows whole (%d lines, long ones wrapped at %d characters)", b.label, bodyMaxLines, len(lines), bodyWrap)
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "It also sends %s (%d bytes, %d lines, SHA-256 %s)", b.label, len(b.body), len(lines), hex.EncodeToString(sum[:]))
	if len(lines) == 0 {
		return sb.String() + ".\n\n", ""
	}
	sb.WriteString(", all of it:\n\n")
	for _, l := range shown {
		sb.WriteString(l + "\n")
	}
	return sb.String() + "\n", ""
}

// bodyLine is one line of a body as the window shows it, in pieces of at
// most bodyWrap characters: komando's own secrets hidden, its indent kept
// short, and written with escapes ($'...') when a character in it would
// not show as itself. A wrapped piece keeps the indent.
func bodyLine(l string) []string {
	l = strings.TrimSuffix(l, "\r")
	l = strings.ReplaceAll(l, "\t", "  ")
	l = out.P.RedactExact(l)
	rest := strings.TrimLeft(l, " ")
	indent := strings.Repeat(" ", min(len(l)-len(rest), maxSpaces))
	if needsEscapes(rest) {
		rest = ansiQuote(rest)
	}
	r := []rune(rest)
	pieces := []string{indent + string(r[:min(len(r), bodyWrap)])}
	for r = r[min(len(r), bodyWrap):]; len(r) > 0; r = r[min(len(r), bodyWrap):] {
		pieces = append(pieces, indent+string(r[:min(len(r), bodyWrap)]))
	}
	return pieces
}
