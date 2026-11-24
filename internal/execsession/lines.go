package execsession

import (
	"bytes"
	"regexp"
)

// ReadMax is the most of out.log one read takes; LineMax is the longest
// line an agent is shown.
const (
	ReadMax = 1 << 20
	LineMax = 64 << 10
)

var (
	keyBegin = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`)
	keyEnd   = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`)
)

const (
	hiddenKey  = "[hidden: private key]\n"
	hiddenLine = "[hidden: a line over 64 KiB]\n"
)

// Lines passes a session log to the masker by whole lines, the same way
// exec's stream does (cli lineBuffer), but without keeping the text: each
// read starts at the offset the last one used, which is always the start
// of a line, so a read with --offset N masks the same as the stream. An
// open private key is held back until its END line; a key that outgrows a
// read, and for an agent a line over LineMax, is hidden whole.
type Lines struct {
	Redact func(string) string
	Agent  bool
	skip   skipping
	open   int // bytes of the hidden line or key used so far
}

type skipping int

const (
	noSkip   skipping = iota
	skipLine          // drop up to the end of the line
	skipKey           // drop up to the key's END line
)

// Read takes the log from the next offset on and returns the text to show
// and how many bytes it used; the rest is read again next time. end says
// that b runs to the end of a finished run's log.
func (l *Lines) Read(b []byte, end bool) (string, int) {
	used := l.skipped(b)
	if l.skip != noSkip {
		l.open += len(b)
		return "", len(b)
	}
	var shown []byte
	full := len(b) >= ReadMax
	for used < len(b) {
		rest := b[used:]
		nl := bytes.IndexByte(rest, '\n')
		line := rest
		if nl >= 0 {
			line = rest[:nl+1]
		}
		if loc := keyBegin.FindIndex(line); loc != nil && !keyEnd.Match(line[loc[1]:]) {
			n := keyLen(rest)
			switch {
			case n > 0:
				line = rest[:n]
			case end:
				return string(l.mask(shown)) + hiddenKey, len(b)
			case used == 0 && full:
				l.skip, l.open = skipKey, len(b)
				return hiddenKey, len(b)
			default:
				return string(l.mask(shown)), used
			}
		} else if nl < 0 && !end && !(full && used == 0) && !(l.Agent && len(line) > LineMax) {
			break
		}
		if l.Agent && len(bytes.TrimSuffix(line, []byte("\n"))) > LineMax && !keyBegin.Match(line) {
			shown = append(shown, hiddenLine...)
			if nl < 0 && !end {
				l.skip, l.open = skipLine, len(line)
			}
		} else {
			shown = append(shown, line...)
		}
		used += len(line)
	}
	return string(l.mask(shown)), used
}

// skipped drops what is left of a hidden line or key at the head of b.
func (l *Lines) skipped(b []byte) int {
	switch l.skip {
	case skipLine:
		if nl := bytes.IndexByte(b, '\n'); nl >= 0 {
			l.skip, l.open = noSkip, 0
			return nl + 1
		}
	case skipKey:
		if loc := keyEnd.FindIndex(b); loc != nil {
			l.skip, l.open = noSkip, 0
			if nl := bytes.IndexByte(b[loc[1]:], '\n'); nl >= 0 {
				return loc[1] + nl + 1
			}
			return len(b)
		}
	}
	return 0
}

// keyLen is the length of the key block at the head of b up to the end of
// its END line, or 0 when that line has not come yet.
func keyLen(b []byte) int {
	loc := keyEnd.FindIndex(b)
	if loc == nil {
		return 0
	}
	nl := bytes.IndexByte(b[loc[1]:], '\n')
	if nl < 0 {
		return 0
	}
	return loc[1] + nl + 1
}

func (l *Lines) mask(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	return []byte(l.Redact(string(b)))
}

// Open is how many bytes of a hidden line or key the reads so far used
// past its start: the offset a later read starts from (next_from) is the
// next read's offset less this.
func (l *Lines) Open() int { return l.open }
