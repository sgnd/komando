package term

import "unicode/utf8"

// The keys of the interactive mode (C162), read from a terminal in raw
// mode. Every byte is either part of a key komando knows or dropped: an
// escape sequence komando does not know goes whole, up to its last byte,
// so its tail never shows up as typed text. A paste is text only: it
// never presses Enter and never moves the screen.

// KeyKind is what a key does.
type KeyKind uint8

const (
	KeyNone      KeyKind = iota // nothing to act on (input that was dropped)
	KeyRune                     // a typed character, in Key.Rune
	KeyEnter                    // Enter (CR or LF)
	KeyEsc                      // Esc on its own
	KeyUp                       // arrow up
	KeyDown                     // arrow down
	KeyLeft                     // arrow left
	KeyRight                    // arrow right
	KeyHome                     // Home
	KeyEnd                      // End
	KeyPageUp                   // Page Up
	KeyPageDown                 // Page Down
	KeyTab                      // Tab
	KeyBackTab                  // Shift-Tab
	KeyBackspace                // Backspace
	KeyDelete                   // Delete
	KeyClear                    // Ctrl-U: clear the field
	KeyInterrupt                // Ctrl-C: stop, nothing runs
	KeyEOF                      // Ctrl-D
	KeySuspend                  // Ctrl-Z
	KeyPaste                    // a bracketed paste, in Key.Text
	KeyResize                   // the window changed size and the screen still fits
)

// Key is one key a person pressed, or one paste.
type Key struct {
	Kind KeyKind
	Rune rune   // for KeyRune
	Text string // for KeyPaste: printable text; line breaks kept as \n
	// TooLong: the paste was longer than FieldMax; Text is empty and
	// nothing of it is used
	TooLong bool
}

// FieldMax is the most bytes one field or one paste takes: the read
// buffer size of today's questions.
const FieldMax = 4096

// seqMax is the longest escape sequence komando collects. A longer one is
// dropped whole: the bytes so far, then everything up to its last byte.
const seqMax = 64

// decoder turns bytes into keys. It keeps the bytes of a key that has not
// fully arrived and the state of a paste. It knows nothing of time: the
// reader says when no more bytes came (final), so a lone Esc and a cut
// sequence can be decided.
type decoder struct {
	buf     []byte
	pasting bool   // inside ESC[200~ ... ESC[201~
	paste   []byte // the paste so far, cleaned
	tooLong bool   // the paste passed FieldMax
	skip    bool   // dropping an over-long sequence up to its last byte
}

// add appends bytes read from the terminal.
func (d *decoder) add(b []byte) { d.buf = append(d.buf, b...) }

// pending says whether bytes wait in the decoder.
func (d *decoder) pending() bool { return len(d.buf) > 0 || d.pasting }

// next returns the next key. ok is false when it needs more bytes; with
// final set (no more bytes came in time) it decides with what it has: a
// lone ESC is Esc, a cut sequence is dropped, an unended paste ends.
func (d *decoder) next(final bool) (k Key, ok bool) {
	for {
		if d.skip {
			i := 0
			for i < len(d.buf) && !isFinal(d.buf[i]) {
				i++
			}
			if i == len(d.buf) {
				d.buf = d.buf[:0]
				if final {
					d.skip = false
				}
				return Key{}, false
			}
			d.buf, d.skip = d.buf[i+1:], false
			continue
		}
		if d.pasting {
			k, ok := d.nextPaste(final)
			if !ok || k.Kind != KeyNone {
				return k, ok
			}
			continue
		}
		if len(d.buf) == 0 {
			return Key{}, false
		}
		k, n, ok := d.one(final)
		if !ok {
			return Key{}, false
		}
		d.buf = d.buf[n:]
		if k.Kind == KeyNone && (d.pasting || d.skip) {
			continue
		}
		return k, true
	}
}

// one decodes one key at the start of buf: the key, how many bytes it
// took, and ok false when more bytes are needed.
func (d *decoder) one(final bool) (Key, int, bool) {
	b := d.buf
	c := b[0]
	switch {
	case c == 0x1b:
		return d.escape(final)
	case c == '\r' || c == '\n':
		return Key{Kind: KeyEnter}, 1, true
	case c == '\t':
		return Key{Kind: KeyTab}, 1, true
	case c == 0x7f || c == 0x08:
		return Key{Kind: KeyBackspace}, 1, true
	case c == 0x15:
		return Key{Kind: KeyClear}, 1, true
	case c == 0x03:
		return Key{Kind: KeyInterrupt}, 1, true
	case c == 0x04:
		return Key{Kind: KeyEOF}, 1, true
	case c == 0x1a:
		return Key{Kind: KeySuspend}, 1, true
	case c < 0x20:
		return Key{}, 1, true // other control keys: dropped
	}
	if !utf8.FullRune(b) && !final {
		return Key{}, 0, false
	}
	r, n := utf8.DecodeRune(b)
	if r == utf8.RuneError && n <= 1 {
		return Key{}, 1, true // not UTF-8: dropped
	}
	return Key{Kind: KeyRune, Rune: r}, n, true
}

// escape decodes a key that starts with ESC.
func (d *decoder) escape(final bool) (Key, int, bool) {
	b := d.buf
	if len(b) == 1 {
		if final {
			return Key{Kind: KeyEsc}, 1, true
		}
		return Key{}, 0, false
	}
	switch b[1] {
	case 'O': // SS3: ESC O and one byte
		if len(b) < 3 {
			if final {
				return Key{}, len(b), true
			}
			return Key{}, 0, false
		}
		return Key{Kind: ss3Keys[b[2]]}, 3, true
	case '[': // CSI: ESC [ parameters, then one last byte
		if len(b) >= 3 && b[2] == '[' { // the Linux console's F1 to F5: ESC [ [ A
			if len(b) < 4 {
				if final {
					return Key{}, len(b), true
				}
				return Key{}, 0, false
			}
			return Key{}, 4, true
		}
		i := 2
		for i < len(b) && !isFinal(b[i]) {
			i++
		}
		if i == len(b) {
			if i >= seqMax {
				d.skip = true
				return Key{}, i, true
			}
			if final {
				return Key{}, len(b), true
			}
			return Key{}, 0, false
		}
		return d.csi(string(b[2:i]), b[i]), i + 1, true
	}
	return Key{}, 2, true // Alt with a key, or ESC ESC: dropped
}

// isFinal says whether c ends an escape sequence.
func isFinal(c byte) bool { return c >= 0x40 && c <= 0x7e }

// ss3Keys are the keys of ESC O x.
var ss3Keys = map[byte]KeyKind{'A': KeyUp, 'B': KeyDown, 'C': KeyRight, 'D': KeyLeft, 'H': KeyHome, 'F': KeyEnd}

// csi decodes ESC [ params final. A modifier (ESC[1;5A, Ctrl-Up) does not
// change the key.
func (d *decoder) csi(params string, final byte) Key {
	switch final {
	case 'A':
		return Key{Kind: KeyUp}
	case 'B':
		return Key{Kind: KeyDown}
	case 'C':
		return Key{Kind: KeyRight}
	case 'D':
		return Key{Kind: KeyLeft}
	case 'H':
		return Key{Kind: KeyHome}
	case 'F':
		return Key{Kind: KeyEnd}
	case 'Z':
		return Key{Kind: KeyBackTab}
	case '~':
		n := params
		for i := 0; i < len(params); i++ {
			if params[i] == ';' {
				n = params[:i]
				break
			}
		}
		switch n {
		case "1", "7":
			return Key{Kind: KeyHome}
		case "4", "8":
			return Key{Kind: KeyEnd}
		case "3":
			return Key{Kind: KeyDelete}
		case "5":
			return Key{Kind: KeyPageUp}
		case "6":
			return Key{Kind: KeyPageDown}
		case "200":
			d.pasting, d.paste, d.tooLong = true, d.paste[:0], false
		}
	}
	return Key{} // unknown: dropped whole
}

// nextPaste reads the paste up to its end mark. Escape sequences inside
// it go whole; control bytes go; CR and CRLF become \n. Past FieldMax the
// rest is dropped and the paste comes back TooLong.
func (d *decoder) nextPaste(final bool) (Key, bool) {
	for len(d.buf) > 0 {
		c := d.buf[0]
		if c == 0x1b {
			if len(d.buf) < len(pasteEnd) && !final && string(d.buf) == pasteEnd[:len(d.buf)] {
				return Key{}, false // the end mark may be on its way
			}
			if len(d.buf) >= len(pasteEnd) && string(d.buf[:len(pasteEnd)]) == pasteEnd {
				d.buf = d.buf[len(pasteEnd):]
				return d.endPaste(), true
			}
			// another sequence inside the paste: dropped whole
			inner := &decoder{buf: d.buf}
			_, n, ok := inner.escape(final)
			if !ok {
				return Key{}, false
			}
			d.buf, d.skip = d.buf[n:], inner.skip
			if d.skip {
				return Key{}, true // next drops the rest of it, then the paste goes on
			}
			continue
		}
		var add []byte
		n := 1
		switch {
		case c == '\r':
			add = []byte{'\n'}
			if len(d.buf) > 1 && d.buf[1] == '\n' {
				n = 2
			} else if len(d.buf) == 1 && !final {
				return Key{}, false // a CRLF may be cut between reads
			}
		case c == '\n' || c == '\t':
			add = []byte{c}
		case c < 0x20 || c == 0x7f:
		default:
			if !utf8.FullRune(d.buf) && !final {
				return Key{}, false
			}
			r, size := utf8.DecodeRune(d.buf)
			n = size
			if r != utf8.RuneError || size > 1 {
				add = d.buf[:size]
			}
		}
		if len(d.paste)+len(add) > FieldMax {
			d.tooLong = true
		}
		if !d.tooLong {
			d.paste = append(d.paste, add...)
		}
		d.buf = d.buf[n:]
	}
	if final {
		return d.endPaste(), true // no end mark came: the paste ends here
	}
	return Key{}, false
}

// endPaste ends the paste and returns it.
func (d *decoder) endPaste() Key {
	k := Key{Kind: KeyPaste, TooLong: d.tooLong}
	if !d.tooLong {
		k.Text = string(d.paste)
	}
	d.pasting, d.paste, d.tooLong = false, d.paste[:0], false
	return k
}
