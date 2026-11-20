package policy

import (
	"regexp"
	"strings"
)

// Encoded is one block of encoded data in a script or command: lines
// First to Last (from 1) that are mostly one kind of encoding.
type Encoded struct {
	Kind    string // base64, base32, hex, hex escapes, octal escapes, private key
	Chars   int    // encoded characters
	Decoded int    // about how many bytes they decode to
	First   int
	Last    int
}

// encodedMin is the size, in encoded characters, of a block worth a line
// in the approval window.
const encodedMin = 64

var (
	encToken  = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
	hexEsc    = regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){16,}`)
	octEsc    = regexp.MustCompile(`(\\[0-7]{3}){16,}`)
	pemBegin  = regexp.MustCompile(`-----BEGIN ([A-Z0-9 ]+)-----`)
	pemEnd    = regexp.MustCompile(`-----END ([A-Z0-9 ]+)-----`)
	hashWords = regexp.MustCompile(`(?i)\bsha-?(1|224|256|384|512)|shasum|sha\d*sum|checksum|digest`)
	privKey   = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----.*-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`)
)

// HasPrivateKey reports whether text holds a whole private key block.
func HasPrivateKey(text string) bool { return privKey.MatchString(text) }

// tokenKind is what an encoded-looking token is, or "" for a word, a
// path or a short id.
func tokenKind(t string) string {
	body := strings.TrimRight(t, "=")
	var up, low, dig, b32dig, hex bool = false, false, false, false, true
	for _, c := range body {
		switch {
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= 'a' && c <= 'z':
			low = true
		case c >= '0' && c <= '9':
			dig = true
			b32dig = b32dig || c >= '2' && c <= '7'
		}
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			hex = false
		}
	}
	switch {
	case hex && dig && (up || low) && len(body) == len(t):
		return "hex"
	case up && !low && b32dig && !strings.ContainsAny(body, "0189+/"):
		return "base32"
	case up && low && dig:
		return "base64"
	}
	return ""
}

type encLine struct {
	kind   string
	chars  int
	tokens []string
	mostly bool
}

func scanLine(l string) encLine {
	count := map[string]int{}
	var e encLine
	for _, m := range hexEsc.FindAllString(l, -1) {
		count["hex escapes"] += len(m)
		e.tokens = append(e.tokens, m)
	}
	for _, m := range octEsc.FindAllString(l, -1) {
		count["octal escapes"] += len(m)
		e.tokens = append(e.tokens, m)
	}
	if len(e.tokens) == 0 {
		for _, m := range encToken.FindAllString(l, -1) {
			if k := tokenKind(m); k != "" {
				count[k] += len(m)
				e.tokens = append(e.tokens, m)
			}
		}
	}
	for k, n := range count {
		e.chars += n
		if n > count[e.kind] || n == count[e.kind] && k < e.kind {
			e.kind = k
		}
	}
	e.mostly = e.chars > 0 && e.chars*2 >= len(strings.Join(strings.Fields(l), ""))
	return e
}

// decodedSize is about how many bytes chars characters of kind decode to.
func decodedSize(kind string, chars int) int {
	switch kind {
	case "hex":
		return chars / 2
	case "base32":
		return chars * 5 / 8
	case "hex escapes", "octal escapes":
		return chars / 4
	}
	return chars * 3 / 4
}

// ScanEncoded finds the encoded data in text, by run and by block: lines
// in a row that are mostly encoded (a heredoc, a+="…" pieces) are one
// block, and a block or a single run of encodedMin characters or more
// counts. Not counted: one 64-hex-digit hash alone on a line that says
// it is a hash, and public PEM blocks (a certificate, a public key). A
// private key block counts as its own kind.
func ScanEncoded(text string) []Encoded {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var out []Encoded
	var cur *Encoded
	var curLines []encLine
	flush := func() {
		if cur == nil {
			return
		}
		if cur.Chars >= encodedMin && !hashOnly(lines, cur, curLines) {
			cur.Decoded = decodedSize(cur.Kind, cur.Chars)
			out = append(out, *cur)
		}
		cur, curLines = nil, nil
	}
	pem := ""
	for i, l := range lines {
		n := i + 1
		if pem != "" {
			if strings.Contains(pem, "PRIVATE") {
				cur.Last = n
				if !pemEnd.MatchString(l) {
					cur.Chars += len(strings.TrimSpace(l))
				}
			}
			if pemEnd.MatchString(l) {
				if strings.Contains(pem, "PRIVATE") {
					cur.Decoded = decodedSize("base64", cur.Chars)
					out = append(out, *cur)
					cur = nil
				}
				pem = ""
			}
			continue
		}
		if m := pemBegin.FindStringSubmatch(l); m != nil {
			flush()
			pem = m[1]
			if strings.Contains(pem, "PRIVATE") {
				cur = &Encoded{Kind: "private key", First: n, Last: n}
			}
			continue
		}
		e := scanLine(l)
		switch {
		case e.mostly:
			if cur == nil {
				cur = &Encoded{Kind: e.kind, First: n}
			}
			cur.Last, cur.Chars = n, cur.Chars+e.chars
			curLines = append(curLines, e)
			if e.kind != cur.Kind && kindChars(curLines, e.kind) > kindChars(curLines, cur.Kind) {
				cur.Kind = e.kind
			}
		default:
			flush()
			if e.chars >= encodedMin {
				cur, curLines = &Encoded{Kind: e.kind, Chars: e.chars, First: n, Last: n}, []encLine{e}
				flush()
			}
		}
	}
	if pem != "" && cur != nil {
		cur.Decoded = decodedSize("base64", cur.Chars)
		out = append(out, *cur)
		cur = nil
	}
	flush()
	return out
}

func kindChars(ls []encLine, kind string) int {
	n := 0
	for _, l := range ls {
		if l.kind == kind {
			n += l.chars
		}
	}
	return n
}

// hashOnly: the block is one line with one hex token of exactly 64
// digits, on a line that names a hash (sha256sum -c, sha256:).
func hashOnly(lines []string, b *Encoded, ls []encLine) bool {
	return b.First == b.Last && len(ls) == 1 && b.Kind == "hex" && len(ls[0].tokens) == 1 &&
		len(ls[0].tokens[0]) == 64 && hashWords.MatchString(lines[b.First-1])
}
