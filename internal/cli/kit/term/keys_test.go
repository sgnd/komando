package term

import (
	"reflect"
	"strings"
	"testing"
)

// decodeAll feeds the chunks one by one, as reads from a terminal, takes
// every key that is whole, and decides what is left as when no more bytes
// come in time.
func decodeAll(chunks ...string) []Key {
	var d decoder
	var got []Key
	take := func(final bool) {
		for {
			k, ok := d.next(final)
			if !ok {
				return
			}
			if k.Kind != KeyNone {
				got = append(got, k)
			}
			if final && !d.pending() {
				return
			}
		}
	}
	for _, c := range chunks {
		d.add([]byte(c))
		take(false)
	}
	take(true)
	return got
}

func kinds(ks ...KeyKind) []Key {
	out := make([]Key, len(ks))
	for i, k := range ks {
		out[i] = Key{Kind: k}
	}
	return out
}

// Every key the screen knows decodes, in each form terminals send it.
func TestDecodeKnownKeys(t *testing.T) {
	tests := []struct {
		name, in string
		want     []Key
	}{
		{"arrows CSI", "\x1b[A\x1b[B\x1b[C\x1b[D", kinds(KeyUp, KeyDown, KeyRight, KeyLeft)},
		{"arrows SS3", "\x1bOA\x1bOB\x1bOC\x1bOD", kinds(KeyUp, KeyDown, KeyRight, KeyLeft)},
		{"arrow with a modifier", "\x1b[1;5A\x1b[1;2B", kinds(KeyUp, KeyDown)},
		{"home and end", "\x1b[H\x1b[F\x1bOH\x1bOF\x1b[1~\x1b[4~\x1b[7~\x1b[8~", kinds(KeyHome, KeyEnd, KeyHome, KeyEnd, KeyHome, KeyEnd, KeyHome, KeyEnd)},
		{"page keys and delete", "\x1b[5~\x1b[6~\x1b[3~\x1b[5;5~", kinds(KeyPageUp, KeyPageDown, KeyDelete, KeyPageUp)},
		{"shift-tab", "\x1b[Z", kinds(KeyBackTab)},
		{"enter as CR and LF", "\r\n", kinds(KeyEnter, KeyEnter)},
		{"tab, backspace both ways", "\t\x7f\x08", kinds(KeyTab, KeyBackspace, KeyBackspace)},
		{"ctrl keys", "\x15\x03\x04\x1a", kinds(KeyClear, KeyInterrupt, KeyEOF, KeySuspend)},
		{"text", "ab", []Key{{Kind: KeyRune, Rune: 'a'}, {Kind: KeyRune, Rune: 'b'}}},
		{"UTF-8", "é世", []Key{{Kind: KeyRune, Rune: 'é'}, {Kind: KeyRune, Rune: '世'}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeAll(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decode %q = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// What komando does not know is dropped whole: no tail of a sequence ever
// shows up as typed text, and the keys around it still decode.
func TestDecodeDropsUnknownWhole(t *testing.T) {
	a, b := Key{Kind: KeyRune, Rune: 'a'}, Key{Kind: KeyRune, Rune: 'b'}
	tests := []struct {
		name, in string
	}{
		{"unknown CSI final", "a\x1b[5nb"},
		{"unknown tilde number", "a\x1b[99~b"},
		{"colour sequence typed in", "a\x1b[31;1mb"},
		{"focus in and out", "a\x1b[I\x1b[Ob"},
		{"mouse report", "a\x1b[<0;10;5Mb"},
		{"unknown SS3", "a\x1bOPb"},
		{"alt with a key", "a\x1bxb"},
		{"other control bytes", "a\x01\x02\x07\x0e\x1fb"},
		{"bytes that are not UTF-8", "a\xff\xfeb"},
		{"over-long sequence", "a\x1b[" + strings.Repeat("1;", 60) + "Xb"},
		{"Linux console F1", "a\x1b[[Ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeAll(tt.in); !reflect.DeepEqual(got, []Key{a, b}) {
				t.Errorf("decode %q = %v, want only a and b", tt.in, got)
			}
		})
	}
}

// A key cut between two reads is whole once its rest comes; the first
// part alone never counts.
func TestDecodeAcrossReads(t *testing.T) {
	tests := []struct {
		name   string
		chunks []string
		want   []Key
	}{
		{"CSI cut after ESC", []string{"\x1b", "[A"}, kinds(KeyUp)},
		{"CSI cut after [", []string{"\x1b[", "B"}, kinds(KeyDown)},
		{"tilde key cut", []string{"\x1b[5", "~"}, kinds(KeyPageUp)},
		{"SS3 cut", []string{"\x1bO", "C"}, kinds(KeyRight)},
		{"UTF-8 cut", []string{"\xe4\xb8", "\x96"}, []Key{{Kind: KeyRune, Rune: '世'}}},
		{"over-long sequence cut", []string{"\x1b[" + strings.Repeat("1", 70), "9X", "a"}, []Key{{Kind: KeyRune, Rune: 'a'}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeAll(tt.chunks...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decode %q = %v, want %v", tt.chunks, got, tt.want)
			}
		})
	}
}

// A lone ESC waits: only when nothing follows in time (final) is it Esc.
// A sequence cut off for good is dropped, never read as Esc and text.
func TestDecodeLoneEsc(t *testing.T) {
	var d decoder
	d.add([]byte{0x1b})
	if k, ok := d.next(false); ok {
		t.Fatalf("a lone ESC was decided before its wait: %v", k)
	}
	if k, ok := d.next(true); !ok || k.Kind != KeyEsc {
		t.Fatalf("a lone ESC after its wait = %v %v, want Esc", k, ok)
	}
	if got := decodeAll("\x1b[1;"); len(got) != 0 {
		t.Errorf("a cut sequence = %v, want nothing", got)
	}
	if got := decodeAll("\x1bO"); len(got) != 0 {
		t.Errorf("a cut SS3 = %v, want nothing", got)
	}
	if got := decodeAll("\x1b", "\x1b"); len(got) != 0 {
		t.Errorf("ESC ESC = %v, want nothing (dropped as Alt-Esc)", got)
	}
}

// A paste is text: its Enter never presses Enter, its sequences go, and
// past FieldMax nothing of it is used.
func TestDecodePaste(t *testing.T) {
	paste := func(s string) string { return "\x1b[200~" + s + "\x1b[201~" }
	tests := []struct {
		name   string
		chunks []string
		want   []Key
	}{
		{"plain", []string{paste("db-prod")}, []Key{{Kind: KeyPaste, Text: "db-prod"}}},
		{"line breaks stay text", []string{paste("a\r\nb\rc\nd")}, []Key{{Kind: KeyPaste, Text: "a\nb\nc\nd"}}},
		{"control bytes and sequences dropped", []string{paste("a\x03\x1b[31mb\x1b[Ac\x7f")}, []Key{{Kind: KeyPaste, Text: "abc"}}},
		{"ctrl-c inside is not a stop", []string{paste("\x03\x04\x1a")}, []Key{{Kind: KeyPaste, Text: ""}}},
		{"end mark cut between reads", []string{"\x1b[200~ab\x1b[20", "1~x"}, []Key{{Kind: KeyPaste, Text: "ab"}, {Kind: KeyRune, Rune: 'x'}}},
		{"paste in parts", []string{"\x1b[200~ab", "cd", "\x1b[201~"}, []Key{{Kind: KeyPaste, Text: "abcd"}}},
		{"CRLF cut between reads", []string{"\x1b[200~a\r", "\nb\x1b[201~"}, []Key{{Kind: KeyPaste, Text: "a\nb"}}},
		{"no end mark: ends when nothing more comes", []string{"\x1b[200~abc"}, []Key{{Kind: KeyPaste, Text: "abc"}}},
		{"exactly FieldMax", []string{paste(strings.Repeat("x", FieldMax))}, []Key{{Kind: KeyPaste, Text: strings.Repeat("x", FieldMax)}}},
		{"one byte over FieldMax", []string{paste(strings.Repeat("x", FieldMax+1)) + "z"}, []Key{{Kind: KeyPaste, TooLong: true}, {Kind: KeyRune, Rune: 'z'}}},
		{"over-long sequence inside", []string{paste("a\x1b[" + strings.Repeat("9", 80) + "mb")}, []Key{{Kind: KeyPaste, Text: "ab"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeAll(tt.chunks...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decode = %v, want %v", got, tt.want)
			}
		})
	}
}

// A paste that never ends holds at most FieldMax bytes while it lasts:
// a flood of pasted text cannot grow komando's memory.
func TestDecodePasteMemoryBounded(t *testing.T) {
	var d decoder
	d.add([]byte("\x1b[200~"))
	chunk := []byte(strings.Repeat("x", 1000))
	for range 20 {
		d.add(chunk)
		if k, ok := d.next(false); ok {
			t.Fatalf("an unended paste came back early: %v", k)
		}
		if len(d.paste) > FieldMax {
			t.Fatalf("the paste holds %d bytes, more than FieldMax", len(d.paste))
		}
	}
}

// FuzzDecode: no input makes the decoder panic, loop or give a typed rune
// that is a control character.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"\x1b[A", "\x1b[200~a\r\nb\x1b[201~", "\x1b[1;5A", "\x1bO", "é", "\x1b[" + strings.Repeat("1", 70)} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, k := range decodeAll(string(b)) {
			if k.Kind == KeyRune && (k.Rune < 0x20 || k.Rune == 0x7f) {
				t.Fatalf("control byte %q came back as text", k.Rune)
			}
			if k.Kind == KeyPaste && len(k.Text) > FieldMax {
				t.Fatalf("paste of %d bytes passed FieldMax", len(k.Text))
			}
			if k.Kind == KeyPaste && strings.ContainsAny(k.Text, "\x1b\x03\r") {
				t.Fatalf("paste kept a control byte: %q", k.Text)
			}
		}
	})
}
