package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
)

// encodedWords is the encoded-data risk line in one language.
type encodedWords struct {
	line           string // kind, size, decoded size, places
	lines, oneLine string // "lines %d–%d", "line %d"
	command, sep   string
	kinds          map[string]string
	thousands      string
}

var encodedEN = encodedWords{
	line:  "Encoded data (%s), %s bytes (about %s decoded) in %s; it cannot be reviewed here",
	lines: "lines %d–%d", oneLine: "line %d", command: "the command", sep: ", ", thousands: ",",
}

var encodedID = encodedWords{
	line:  "Data tersandi (%s), %s byte (sekitar %s setelah didekode) di %s; tidak bisa diperiksa di sini",
	lines: "baris %d–%d", oneLine: "baris %d", command: "perintah", sep: ", ", thousands: ".",
	kinds: map[string]string{"hex escapes": "escape hex", "octal escapes": "escape oktal", "private key": "kunci privat"},
}

// encodedRisks is the window's encoded-data lines (C208), one per kind,
// for the command and the body it shows: the line numbers are the
// body's own, without the heading komando puts over it.
func encodedRisks(line, body, lang string) []string {
	w := encodedEN
	if lang == "id" {
		w = encodedID
	}
	type total struct {
		chars, decoded int
		places         []string
	}
	var order []string
	totals := map[string]*total{}
	add := func(b policy.Encoded, place string) {
		t := totals[b.Kind]
		if t == nil {
			t = &total{}
			totals[b.Kind] = t
			order = append(order, b.Kind)
		}
		t.chars, t.decoded = t.chars+b.Chars, t.decoded+b.Decoded
		if len(t.places) == 0 || t.places[len(t.places)-1] != place {
			t.places = append(t.places, place)
		}
	}
	_, run, split := strings.Cut(line, " -- ")
	if !split {
		run = line
	}
	for _, b := range policy.ScanEncoded(run) {
		add(b, w.command)
	}
	if first, rest, ok := strings.Cut(body, "\n"); ok && bodyHead.MatchString(first) {
		body = rest
	}
	for _, b := range policy.ScanEncoded(body) {
		place := fmt.Sprintf(w.oneLine, b.First)
		if b.Last > b.First {
			place = fmt.Sprintf(w.lines, b.First, b.Last)
		}
		add(b, place)
	}
	var outLines []string
	for _, k := range order {
		t := totals[k]
		kind := k
		if tr, ok := w.kinds[k]; ok {
			kind = tr
		}
		outLines = append(outLines, fmt.Sprintf(w.line, kind, grouped(t.chars, w.thousands), grouped(t.decoded, w.thousands), strings.Join(t.places, w.sep)))
	}
	return outLines
}

// grouped writes n with a thousands separator: 3,012 or 3.012.
func grouped(n int, sep string) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + sep + s[i:]
	}
	return s
}

// refuseEncodedSecret stops a script or command that holds a private key,
// for an agent and a person alike: the key would reach the approval
// window, the audit log and the server's process list.
func refuseEncodedSecret(command string) error {
	if !policy.HasPrivateKey(command) {
		return nil
	}
	return out.Errf(out.ExitUsage, "ENCODED_SECRET_INVALID",
		"put the key in the vault and pass it with secret run: `komando credential token add NAME < key`, then `komando credential run --env KEY=secret:NAME -- …`; to search for keys, quote only 'PRIVATE KEY-----', not the whole BEGIN line",
		"the script or command holds a private key; komando does not send one this way")
}
