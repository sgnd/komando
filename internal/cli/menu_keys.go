package cli

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// keyKind is a key the menu understands (menu.go).
type keyKind int

const (
	keyNone keyKind = iota // a byte or sequence the menu ignores
	keyUp
	keyDown
	keyLeft
	keyRight
	keyHome
	keyEnd
	keyPageUp
	keyPageDown
	keyEnter
	keyEsc
	keyBackspace
	keyClear // Ctrl-U: empty the filter
	keyQuit  // Ctrl-C or Ctrl-D: the terminal is raw, so they arrive as bytes
	keyRune  // a printable character, in menuKey.r
)

// menuKey is one key press.
type menuKey struct {
	kind keyKind
	r    rune
}

// decodeKeys turns bytes read from a raw terminal into keys. One read can
// hold several keys (typed fast, held down, or pasted), and it can end
// inside a key: an escape sequence or a UTF-8 character whose last bytes
// have not arrived yet. Unless final is set, that unfinished end is not
// decoded but returned as rest, for the caller to put before the next read.
// With final set (nothing more came), a lone ESC is the Esc key and a cut
// sequence is dropped.
func decodeKeys(b []byte, final bool) (keys []menuKey, rest []byte) {
	for len(b) > 0 {
		if !final && unfinished(b) {
			return keys, b
		}
		k, n := decodeKey(b)
		if k.kind != keyNone {
			keys = append(keys, k)
		}
		b = b[n:]
	}
	return keys, nil
}

// unfinished: b starts with a key whose last bytes may still be on the way.
func unfinished(b []byte) bool {
	if b[0] != 0x1b {
		return b[0] >= 0x80 && !utf8.FullRune(b)
	}
	switch {
	case len(b) == 1:
		return true
	case b[1] == 'O':
		return len(b) == 2
	case b[1] == '[':
		for _, c := range b[2:] {
			if c >= 0x40 && c <= 0x7e {
				return false
			}
		}
		return true
	}
	return false
}

// decodeKey reads the first key in b and says how many bytes it took.
func decodeKey(b []byte) (menuKey, int) {
	switch c := b[0]; {
	case c == 0x1b:
		return decodeEscape(b)
	case c == '\r' && len(b) > 1 && b[1] == '\n': // a pasted line end
		return menuKey{kind: keyEnter}, 2
	case c == '\r' || c == '\n':
		return menuKey{kind: keyEnter}, 1
	case c == 0x7f || c == 0x08:
		return menuKey{kind: keyBackspace}, 1
	case c == 0x15:
		return menuKey{kind: keyClear}, 1
	case c == 0x03 || c == 0x04:
		return menuKey{kind: keyQuit}, 1
	case c == 0x10: // Ctrl-P, as in a shell's history
		return menuKey{kind: keyUp}, 1
	case c == 0x0e: // Ctrl-N
		return menuKey{kind: keyDown}, 1
	case c < 0x20:
		return menuKey{}, 1
	}
	r, n := utf8.DecodeRune(b)
	if r == utf8.RuneError && n <= 1 {
		return menuKey{}, 1
	}
	if !unicode.IsPrint(r) { // C1 controls, bidi marks: never into the filter on screen
		return menuKey{}, n
	}
	return menuKey{kind: keyRune, r: r}, n
}

// decodeEscape reads ESC [ params final (CSI), or ESC O x (the cursor keys
// of a terminal in application mode). A lone ESC is the Esc key; ESC before
// any other byte (Alt+key) is Esc too, and the byte after it is its own key.
func decodeEscape(b []byte) (menuKey, int) {
	if len(b) == 1 || (b[1] != '[' && b[1] != 'O') {
		return menuKey{kind: keyEsc}, 1
	}
	if len(b) == 2 { // ESC [ or ESC O and nothing more: cut short
		return menuKey{}, 2
	}
	if b[1] == 'O' {
		return menuKey{kind: csiKey(b[2])}, 3
	}
	i := 2 // parameter and intermediate bytes, then one final byte
	for i < len(b) && (b[i] < 0x40 || b[i] > 0x7e) {
		i++
	}
	if i == len(b) { // cut short: drop it rather than read it as typing
		return menuKey{}, len(b)
	}
	if b[i] == '~' {
		return menuKey{kind: tildeKey(string(b[2:i]))}, i + 1
	}
	return menuKey{kind: csiKey(b[i])}, i + 1
}

// csiKey is the key for the final byte of ESC [ x or ESC O x. A modifier
// (ESC [ 1 ; 5 A is Ctrl+Up) does not change which key it is.
func csiKey(final byte) keyKind {
	switch final {
	case 'A':
		return keyUp
	case 'B':
		return keyDown
	case 'C':
		return keyRight
	case 'D':
		return keyLeft
	case 'H':
		return keyHome
	case 'F':
		return keyEnd
	}
	return keyNone
}

// tildeKey is the key for ESC [ n ~ (VT220 style, also the paste marks
// ESC [ 200 ~ and ESC [ 201 ~, which the menu ignores).
func tildeKey(params string) keyKind {
	n, _, _ := strings.Cut(params, ";")
	switch n {
	case "1", "7":
		return keyHome
	case "4", "8":
		return keyEnd
	case "5":
		return keyPageUp
	case "6":
		return keyPageDown
	}
	return keyNone
}
