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

// Everything under a key that names stored credentials is hidden, whatever
// its shape: MongoDB keeps each user's SCRAM verifiers (salt, storedKey,
// serverKey) in an object under "credentials", and a list under a
// secret-named key ("apiKeys": [...]) holds secrets too.
func TestNestedCredentialsAreHidden(t *testing.T) {
	in := `{"ok":true,"data":{"documents":[{"user":"app","db":"admin","credentials":{"SCRAM-SHA-1":{"iterationCount":10000,"salt":"c2FsdHNhbHRzYWx0","storedKey":"U3RvcmVkS2V5U3RvcmVkS2V5","serverKey":"U2VydmVyS2V5U2VydmVyS2V5"},` +
		`"SCRAM-SHA-256":{"salt":"c2FsdDI1NnNhbHQyNTY=","storedKey":"U3RvcmVkMjU2","serverKey":"U2VydmVyMjU2"}},"roles":[{"role":"readWrite","db":"shop"}],"apiKeys":["ak_live_1234567890abcdef","ak_live_fedcba0987654321"],` +
		`"scramKeys":{"storedKey":"TG9vc2VTdG9yZWRLZXk="}}]}}`
	got := string(maskJSON([]byte(in)))
	if !json.Valid([]byte(got)) {
		t.Fatalf("not JSON: %s", got)
	}
	for _, leak := range []string{"c2FsdHNhbHRzYWx0", "U3RvcmVkS2V5U3RvcmVkS2V5", "U2VydmVyS2V5U2VydmVyS2V5", "c2FsdDI1NnNhbHQyNTY=", "U3RvcmVkMjU2", "U2VydmVyMjU2", "ak_live_1234567890abcdef", "ak_live_fedcba0987654321", "TG9vc2VTdG9yZWRLZXk="} {
		if strings.Contains(got, leak) {
			t.Errorf("%q leaked: %s", leak, got)
		}
	}
	for _, keep := range []string{`"user":"app"`, `"role":"readWrite"`, `"db":"shop"`, `"iterationCount":10000`} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q should stay: %s", keep, got)
		}
	}
	// the same in text (-o text prints indented JSON through Redact)
	var pretty bytes.Buffer
	_ = json.Indent(&pretty, []byte(in), "", "  ")
	text := (&Printer{Mask: true}).Redact(pretty.String())
	for _, leak := range []string{"U3RvcmVkS2V5U3RvcmVkS2V5", "U2VydmVyS2V5U2VydmVyS2V5", "TG9vc2VTdG9yZWRLZXk="} {
		if strings.Contains(text, leak) {
			t.Errorf("text: %q leaked: %s", leak, text)
		}
	}
	// komando's own lists of names under such a key stay readable
	own := `{"ok":true,"data":{"secrets":[{"name":"db-pass"}],"would_set":["web1-pass"],"password_ref":"secret:db","credentials":{"note":"secret:db"}}}`
	if got := string(maskJSON([]byte(own))); got != own {
		t.Errorf("komando's own output changed: %s", got)
	}
}

// View is what fs replace shows of a file (its matches and its diff):
// where personal data is hidden, it is hidden there too.
func TestViewHidesPersonalData(t *testing.T) {
	src := "admin = alice@example.com\nport = 8080\n"
	v := (&Printer{Mask: true, Personal: true}).View(src)
	if strings.Contains(v.Text, "alice@example.com") || !strings.Contains(v.Text, "[hidden: email]") || !strings.Contains(v.Text, "port = 8080") {
		t.Errorf("view: %q", v.Text)
	}
	if v := (&Printer{Mask: true}).View(src); !strings.Contains(v.Text, "alice@example.com") {
		t.Errorf("without Personal: %q", v.Text)
	}
}

// komando's own lists of names, and lists of public things, stay readable
// for an AI agent; credentials are hidden under the keys that hold them.
func TestOwnListsStayReadable(t *testing.T) {
	own := `{"ok":true,"data":{"secrets_unused":["db-pass"],"host_keys_kept":["node2"],"authorized_keys":["ssh-ed25519 AAAA bob"],"imagePullSecrets":["regcred"],"primary_keys":["id"],` +
		`"password":{"min_length":"12","policy":"strong"},"scramble":{"x":"hello"},"credentials":{"type":"basic","helper_name":"osxkeychain"}}}`
	if got := string(maskJSON([]byte(own))); got != own {
		t.Errorf("changed:\n got %s\nwant %s", got, own)
	}
}

// A label is never read as personal data: a secret named like an email
// address keeps its label, in Redact and in View alike.
func TestLabelsAreNotPersonalData(t *testing.T) {
	p := &Printer{Mask: true, Personal: true, Secrets: func() map[string]string { return map[string]string{"ops@corp.example": "Sup3rS3cretPw"} }}
	s := "x Sup3rS3cretPw y bob@example.com"
	want := "x [secret:ops@corp.example] y [hidden: email]"
	if got := p.Redact(s); got != want {
		t.Errorf("Redact: %q", got)
	}
	if got := p.View(s).Text; got != want {
		t.Errorf("View: %q", got)
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
	own := `{"ok":true,"data":{"secrets_unused":["shop-db-password"],"secrets_needed":["shop-db-password"],"host_keys_kept":["node2.example.com"]}}`
	if got := string(maskJSON([]byte(own))); got != own {
		t.Errorf("komando's own lists: %s", got)
	}
}
