package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
)

// approvalBody is a file a command sends besides its command line
// (exec --script FILE, --stdin-file, job start --script). The approval
// window shows its SHA-256 and every line of it, so a person does not
// allow a script they never saw whole.
type approvalBody struct {
	label string // "the script ./deploy.sh"
	body  []byte
	data  bool // content to store or send, not code to run (noteApprovalData)
	big   bool // more than bodyMaxBytes: body is nil, size and sum say what it is
	// overLimit: whole() found more lines than the window takes
	overLimit bool
	kind      bodyKind
	size      int64    // bytes sent
	sum       [32]byte // SHA-256 of what is sent
	file      string   // the file the window read, resolved (resolvedFile); "" for a body that is not one file
}

// resolvedFile is path as the file it names: ~ expanded, absolute, cleaned
// and with symbolic links followed, so two spellings of one file match.
func resolvedFile(path string) string {
	a, err := filepath.Abs(inventory.ExpandHome(path))
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(a); err == nil {
		return r
	}
	return a
}

// newBody is an approvalBody for body as a whole.
func newBody(label string, body []byte, data bool) *approvalBody {
	kind := bodyInput
	if data {
		kind = bodyData
	}
	return &approvalBody{label: label, body: body, data: data, kind: kind, size: int64(len(body)), sum: sha256.Sum256(body)}
}

// bodyKind is what a body is: it sets the window's line limit and the
// advice when the body is too long to show.
type bodyKind int

const (
	bodyInput  bodyKind = iota // code sent on stdin (exec --stdin-file, job start)
	bodyScript                 // a script file (exec --script, job start --script)
	bodySQL                    // the SQL of database KIND query --file
	bodyData                   // content stored or sent, not run (noteApprovalData)
)

// noteApprovalScript is noteApprovalBody for a script file.
func noteApprovalScript(cl *call, label string, body []byte) {
	b := newBody(label, body, false)
	b.kind = bodyScript
	setBody(cl, b)
}

// noteApprovalSQL is noteApprovalBody for an SQL file.
func noteApprovalSQL(cl *call, label string, body []byte) {
	b := newBody(label, body, false)
	b.kind = bodySQL
	setBody(cl, b)
}

// tooLongAdvice is what an agent does with a body of kind too long for
// the window.
func tooLongAdvice(kind bodyKind) string {
	var do string
	switch kind {
	case bodyScript:
		do = "Split the script into shorter ones and run each with `komando exec TARGET --script FILE`"
	case bodySQL:
		do = "Split the SQL into shorter files and run each with `komando database KIND query NAME --file FILE`"
	case bodyData:
		do = "Send it in smaller pieces (a few `komando fs replace` runs instead of one big change)"
	default:
		do = "Shorten it, or put it in a script file and run it with `komando exec TARGET --script FILE`"
	}
	return do + ", or ask the user to run it in their own terminal"
}

// The window shows a body whole or not at all: a part left out could be
// the one that runs a payload. A long line is wrapped, never cut, and
// each piece counts as a line. The cap keeps the whole text on one
// screen (the macOS and zenity windows do not scroll); a bigger body gets
// no window, and the agent asks the person to run it in their terminal.
const (
	bodyMaxLines = 40 // lines the window shows, wrapped pieces included
	// bodyMaxLinesScroll is the limit of the macOS window, which scrolls
	// and enables Allow only once its last line was seen (SEEN in
	// approval_view.go). It applies to scripts only (lineLimit).
	bodyMaxLinesScroll = 200
	bodyWrap           = 100      // characters of a line per shown piece
	bodyMaxBytes       = 16 << 10 // a body this big cannot fit in bodyMaxLines
)

// noteApprovalBody tells the approval window of this command what it sends.
func noteApprovalBody(cl *call, label string, body []byte) {
	setBody(cl, newBody(label, body, false))
}

// setBody makes b the body this command sends, and puts its full
// SHA-256 in meta.body_sha256 (the audit record reads cl.body).
func setBody(cl *call, b *approvalBody) {
	cl.body = b
	cl.out.BodySHA256(b.sha256())
}

// sha256 is the full SHA-256 of the body, lowercase hex.
func (b *approvalBody) sha256() string { return hex.EncodeToString(b.sum[:]) }

// noteApprovalData is noteApprovalBody for content a command stores or
// sends as it is: a file's new content, a manifest, a queue message. The
// window shows it whole when it can. When it cannot (too long, not text,
// or it holds what looks like a secret) the window still names its size
// and SHA-256 and says that it is not shown: unlike a script, such
// content is often long, and refusing it would leave a protected target
// no way to get a config file from an agent at all.
func noteApprovalData(cl *call, label string, body []byte) {
	setBody(cl, newBody(label, body, true))
}

// noteApprovalFile is noteApprovalData for a file on this computer an AI
// agent's command sends as it is (an upload, a pg_dump archive): a big one
// is read once for its SHA-256, not kept. Only an agent's call gets an
// approval window, so a person's upload reads nothing more.
func noteApprovalFile(cl *call, label, path string) error {
	if !cl.caller().IsAgent() {
		return nil
	}
	b, err := readCapped(path, nil)
	if err != nil {
		return localFileErr("PATH_NOT_FOUND", err, "")
	}
	body := b.as(label, true)
	body.file = resolvedFile(path)
	setBody(cl, body)
	return nil
}

// capped is what readCapped read: the bytes when they fit the window's
// byte cap, else only their size and SHA-256.
type capped struct {
	body []byte
	big  bool
	size int64
	sum  [32]byte
}

func (c capped) as(label string, data bool) *approvalBody {
	if !c.big {
		return newBody(label, c.body, data)
	}
	return &approvalBody{label: label, data: data, big: true, size: c.size, sum: c.sum}
}

// readCapped reads path (through wrap when given, for a .gz) keeping at
// most bodyMaxBytes of it, and the SHA-256 and size of all of it.
func readCapped(path string, wrap func(io.Reader) (io.Reader, error)) (capped, error) {
	f, err := os.Open(path)
	if err != nil {
		return capped{}, err
	}
	defer f.Close()
	var r io.Reader = f
	if wrap != nil {
		if r, err = wrap(f); err != nil {
			return capped{}, err
		}
	}
	h := sha256.New()
	var keep bytes.Buffer
	n, err := io.Copy(io.MultiWriter(h, &keepWriter{&keep, bodyMaxBytes + 1}), r)
	if err != nil {
		return capped{}, err
	}
	c := capped{size: n, big: n > bodyMaxBytes}
	copy(c.sum[:], h.Sum(nil))
	if !c.big {
		c.body = keep.Bytes()
	}
	return c, nil
}

// keepWriter keeps the first left bytes written to it and drops the rest.
type keepWriter struct {
	b    *bytes.Buffer
	left int
}

func (w *keepWriter) Write(p []byte) (int, error) {
	if k := min(len(p), w.left); k > 0 {
		w.b.Write(p[:k])
		w.left -= k
	}
	return len(p), nil
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
func (b *approvalBody) shown(cl *call) (text, bad string) {
	text, bad = b.whole(cl)
	// only a named file too long to show gets the digest line instead: the
	// person can check that file. Content made unshowable (what looks like
	// a secret, an invisible character, not text) or sent on stdin gets
	// no window, as a script does.
	if bad == "" || !b.data || strings.Contains(b.label, "komando's stdin") {
		return text, bad
	}
	why := "it is too long"
	switch {
	case b.binary():
		why = "it is not text"
	case !b.tooLong():
		return text, bad
	}
	return fmt.Sprintf("It also sends %s (%d bytes, SHA-256 %s). Its content is not shown here: %s. Check the file (shasum -a 256) before you allow.\n\n",
		b.label, b.size, b.sha256(), why), ""
}

// binary reports content that is not text at all (it has a NUL byte, as
// an archive or an image does) and holds nothing that looks like a
// secret: a window cannot show it, so a named file is shown by its digest.
func (b *approvalBody) binary() bool {
	if b.big || bytes.IndexByte(b.body, 0) < 0 {
		return false
	}
	s := string(b.body)
	return out.MaskSecrets(s) == s
}

// tooLong reports a body that is plain text with nothing hidden in it,
// only longer than the window shows.
func (b *approvalBody) tooLong() bool {
	if b.big || len(b.body) > bodyMaxBytes {
		return true
	}
	if hiddenArgs([]string{string(b.body)}) != "" {
		return false
	}
	if s := string(b.body); out.MaskSecrets(s) != s {
		return false
	}
	return true
}

// whole is the body's text for the window with every line of it, or why
// it cannot be shown that way.
func (b *approvalBody) whole(cl *call) (text, bad string) {
	if b.big || len(b.body) > bodyMaxBytes {
		return "", fmt.Sprintf("%s is %d bytes, more than the %d the window shows whole", b.label, b.size, bodyMaxBytes)
	}
	if why := hiddenArgs([]string{string(b.body)}); why != "" {
		return "", b.label + " " + strings.TrimPrefix(why, "it ")
	}
	if s := string(b.body); out.MaskSecrets(s) != s {
		return "", b.label + " holds what looks like a password, key or token, which the window does not show"
	}
	lines := strings.Split(strings.TrimSuffix(string(b.body), "\n"), "\n")
	if len(b.body) == 0 {
		lines = nil
	}
	var shown []string
	numW := len(strconv.Itoa(len(lines)))
	for i, l := range lines {
		for j, piece := range bodyLine(cl, l) {
			num := strconv.Itoa(i + 1)
			if j > 0 {
				num = "" // a wrapped piece of the line above
			}
			shown = append(shown, fmt.Sprintf("  %*s  %s", numW, num, piece))
		}
	}
	// the limit counts lines as shown, wrapped pieces included, and the
	// message names that same number
	if limit := b.lineLimit(); len(shown) > limit {
		b.overLimit = true
		return "", fmt.Sprintf("%s is more than the %d lines the window shows whole: %d lines as shown, with lines over %d characters wrapped (%d lines in it)", b.label, limit, len(shown), bodyWrap, len(lines))
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "It also sends %s (%d bytes, %d lines, SHA-256 %s)", b.label, len(b.body), len(lines), b.sha256())
	if len(lines) == 0 {
		return sb.String() + ".\n\n", ""
	}
	sb.WriteString(", all of it:\n\n")
	for _, l := range shown {
		sb.WriteString(l + "\n")
	}
	return sb.String() + "\n", ""
}

// lineLimit is how many shown lines the window takes for b: a script on
// macOS gets bodyMaxLinesScroll; every other body, and every body on
// Windows and Linux, bodyMaxLines.
func (b *approvalBody) lineLimit() int {
	if desktopOS == "darwin" && b.kind == bodyScript {
		return bodyMaxLinesScroll
	}
	return bodyMaxLines
}

// bodyLine is one line of a body as the window shows it, in pieces of at
// most bodyWrap characters: komando's own secrets hidden, its indent kept
// short (spaces past maxSpaces named as "(+N) "), and written with escapes
// ($'...') when a character in it would not show as itself. A wrapped
// piece keeps the indent.
func bodyLine(cl *call, l string) []string {
	l = strings.TrimSuffix(l, "\r")
	l = strings.ReplaceAll(l, "\t", "  ")
	l = cl.out.RedactExact(l)
	rest := strings.TrimLeft(l, " ")
	n := len(l) - len(rest)
	indent := strings.Repeat(" ", min(n, maxSpaces))
	if n > maxSpaces {
		// deep nesting (YAML) stays readable: the spaces past the window's
		// longest run are named, so 16 and 20 spaces do not look the same
		indent += fmt.Sprintf("(+%d) ", n-maxSpaces)
	}
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
