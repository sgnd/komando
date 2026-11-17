package out

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// What a server or a tool wrote into an error reaches -o json as safe as
// it reaches the terminal: no escape sequences, no text-direction marks.
func TestJSONErrorTextIsSafe(t *testing.T) {
	evil := "disk full \x1b]0;pwned\x07\x1b[2J \u202egnp.exe \u009b31m \x1b[8mhidden\x1b[0m <b> & \"q\""
	var buf bytes.Buffer
	p := &Printer{W: &buf, Format: "json", Start: time.Now()}
	p.Warn("audit: " + evil)
	p.WouldBlock(&Error{Code: "POLICY_BLOCKED", Message: evil, Exit: ExitPolicy})
	p.Fail("exec", &Error{Code: "REMOTE_ERROR", Message: evil, Hint: "try " + evil, Suggestion: evil, Exit: ExitRemote})
	var env struct {
		Error struct{ Message, Hint, Suggestion string }
		Meta  struct {
			Warnings       []string
			WouldBeBlocked struct{ Message string } `json:"would_be_blocked"`
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("%v: %s", err, buf.String())
	}
	texts := map[string]string{"message": env.Error.Message, "hint": env.Error.Hint, "suggestion": env.Error.Suggestion, "would_be_blocked": env.Meta.WouldBeBlocked.Message}
	if len(env.Meta.Warnings) != 1 {
		t.Fatalf("warnings: %v", env.Meta.Warnings)
	}
	texts["warning"] = env.Meta.Warnings[0]
	for name, s := range texts {
		if strings.ContainsAny(s, "\x1b\x07\x9b\u202e") {
			t.Errorf("%s still holds a control character: %q", name, s)
		}
		if !strings.Contains(s, `\e]0;pwned\x07`) || !strings.Contains(s, "\\u202e") || !strings.Contains(s, `<b> & "q"`) {
			t.Errorf("%s: %q", name, s)
		}
	}
}

// Ordinary text is untouched.
func TestJSONErrorTextPlain(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{W: &buf, Format: "json", Start: time.Now()}
	p.Fail("x", &Error{Code: "USAGE", Message: "tab\there, line\nbreak, é ü 日本 <ok>", Exit: ExitUsage})
	if !strings.Contains(buf.String(), `"message":"tab\there, line\nbreak, é ü 日本 <ok>"`) {
		t.Errorf("%s", buf.String())
	}
}
