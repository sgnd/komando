package out

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// agentPrinter prints JSON as for an AI agent, with one vault value.
func agentPrinter(buf *bytes.Buffer, personal bool) *Printer {
	return &Printer{Format: "json", W: buf, Mask: true, Personal: personal, Secrets: func() map[string]string {
		return map[string]string{"db-pass": "Sup3rS3cretPw"}
	}}
}

// A value that is not UTF-8 text is shown as {"base64": ...}. What it
// holds is still checked: a vault value, a secret by its shape or (where
// personal data is hidden) an email inside it is one base64 decode away,
// so the whole value is hidden.
func TestBase64ValuesAreChecked(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	bin := "\xff\x00" // makes the value binary
	cases := map[string]struct {
		raw      string
		personal bool
		hidden   bool
	}{
		"a vault value inside":               {bin + "login Sup3rS3cretPw now", false, true},
		"a secret by its shape":              {bin + "\nDB_PASSWORD=hunter2hunter2\n", false, true},
		"an email, personal data hidden":     {bin + " mail alice@example.com ", true, true},
		"an email, personal data not hidden": {bin + " mail alice@example.com ", false, false},
		"plain binary":                       {bin + "\x01\x02\x03 nothing here", true, false},
	}
	for name, c := range cases {
		var buf bytes.Buffer
		p := agentPrinter(&buf, c.personal)
		p.Print("db.query", map[string]any{"rows": [][]any{{1, map[string]string{"base64": b64(c.raw)}}}}, nil)
		got := buf.String()
		if !json.Valid(buf.Bytes()) {
			t.Fatalf("%s: not JSON: %s", name, got)
		}
		if hid := !strings.Contains(got, b64(c.raw)); hid != c.hidden {
			t.Errorf("%s: hidden=%v, want %v: %s", name, hid, c.hidden, got)
		}
		if c.hidden && !strings.Contains(got, `{"base64":"[hidden]"}`) {
			t.Errorf("%s: the value reads [hidden]: %s", name, got)
		}
	}
	// a person sees what the server sent, but never a vault value
	var buf bytes.Buffer
	p := &Printer{Format: "json", W: &buf, Secrets: func() map[string]string { return map[string]string{"db-pass": "Sup3rS3cretPw"} }}
	p.Print("db.query", map[string]any{"a": map[string]string{"base64": b64(bin + "x alice@example.com")}, "b": map[string]string{"base64": b64(bin + "Sup3rS3cretPw")}}, nil)
	if got := buf.String(); !strings.Contains(got, b64(bin+"x alice@example.com")) || strings.Contains(got, b64(bin+"Sup3rS3cretPw")) {
		t.Errorf("a person: %s", got)
	}
	// BinaryHidden is the same check for callers that encode themselves
	// (a queue message's value with "encoding":"base64")
	if p := agentPrinter(&buf, true); !p.BinaryHidden([]byte(bin+"Sup3rS3cretPw")) || !p.BinaryHidden([]byte(bin+"alice@example.com")) || p.BinaryHidden([]byte(bin+"nothing")) {
		t.Error("BinaryHidden")
	}
}

// Text in UTF-16 is still text; a value too large to check is hidden
// whole for an AI agent.
func TestBinaryHiddenWideAndLarge(t *testing.T) {
	p := &Printer{Mask: true, Personal: true}
	wide := []byte{}
	for _, c := range []byte("mail bob@example.com now") {
		wide = append(wide, c, 0)
	}
	if !p.BinaryHidden(wide) {
		t.Error("UTF-16 text with an email")
	}
	if !p.BinaryHidden(make([]byte, binaryCheckMax+1)) {
		t.Error("a value larger than komando checks is hidden for an AI agent")
	}
	if (&Printer{}).BinaryHidden(make([]byte, binaryCheckMax+1)) {
		t.Error("a person sees large values")
	}
}

// Off targets whose personal data is hidden, a large value is checked
// (its start for shapes, all of it for vault values), not hidden whole.
func TestLargeValueOffPersonalTargets(t *testing.T) {
	big := make([]byte, binaryCheckMax+100)
	p := &Printer{Mask: true, Secrets: func() map[string]string { return map[string]string{"k": "Sup3rS3cretPw"} }}
	if p.BinaryHidden(big) {
		t.Error("a large plain value is hidden on an ordinary target")
	}
	copy(big[binaryCheckMax+1:], "Sup3rS3cretPw")
	if !p.BinaryHidden(big) {
		t.Error("a vault value past the cap")
	}
	if !(&Printer{Mask: true, Personal: true}).BinaryHidden(make([]byte, binaryCheckMax+10)) {
		t.Error("a large value on a target whose personal data is hidden")
	}
}
