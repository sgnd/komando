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
		if strings.ContainsAny(s, "\x1b\x07\u009b\u202e") {
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

// Invisible format characters only hide text from the person reading a
// message; they are shown. The zero-width joiner stays for emoji.
func TestNoteTextInvisible(t *testing.T) {
	in := "ok\u200bhidden\ufeff\U000e0041\u2060 \u061c family \U0001f468\u200d\U0001f469"
	got := noteText(in)
	for _, want := range []string{`\u200b`, `\ufeff`, `\ue0041`, `\u2060`, `\u061c`, "\U0001f468\u200d\U0001f469"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q lacks %q", got, want)
		}
	}
}

// meta.skipped reasons are cleaned like warnings.
func TestSkippedReasonSafe(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{W: &buf, Format: "json", Start: time.Now()}
	p.Skip(Skipped{Name: "db\x1b[2J", Kind: "postgres", Reason: "server said \x1b]0;x\x07"})
	p.Print("x", map[string]any{}, nil)
	if strings.Contains(buf.String(), `\u001b`) || !strings.Contains(buf.String(), `\\e]0;x`) {
		t.Errorf("%s", buf.String())
	}
}
