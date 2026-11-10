package out

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// captureStderr runs f with stderr and hintW going to one buffer.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	savedErr, savedHint := os.Stderr, hintW
	os.Stderr, hintW = w, w
	f()
	os.Stderr, hintW = savedErr, savedHint
	w.Close()
	var b bytes.Buffer
	b.ReadFrom(r)
	return b.String()
}

func TestTextErrorLeadsWithMeaning(t *testing.T) {
	p := &Printer{Format: "text", W: &bytes.Buffer{}}
	e := Errf(ExitPolicy, "PROTECTED_HOST", "re-run with --yes after the user confirms", "this changes protected host: web1").
		Say("web1 is a protected server (production), so komando asks before changing it", "Run it again in a terminal.")
	got := captureStderr(t, func() { p.Fail("exec", e) })
	want := "Stopped: web1 is a protected server (production), so komando asks before changing it. Nothing was changed.\nhint: Run it again in a terminal.\n(code PROTECTED_HOST, exit 6)\n"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if e.Message != "this changes protected host: web1" || e.Hint != "re-run with --yes after the user confirms" {
		t.Errorf("Say changed the JSON fields: %+v", e)
	}
}

func TestTextErrorPlain(t *testing.T) {
	p := &Printer{Format: "text", W: &bytes.Buffer{}}
	got := captureStderr(t, func() {
		p.Fail("x", Errf(ExitNotFound, "HOST_NOT_FOUND", "run komando list", "host %q not found", "a"))
	})
	if !strings.HasPrefix(got, "Error: host \"a\" not found\nhint: run komando list\n(code HOST_NOT_FOUND, exit 3)") {
		t.Errorf("got %q", got)
	}
}

func TestTextCancelled(t *testing.T) {
	p := &Printer{Format: "text", W: &bytes.Buffer{}}
	e := Errf(ExitPolicy, "PROTECTED_HOST", "h", "m").Cancel("Cancelled. Nothing was changed on web1.")
	if got := captureStderr(t, func() { p.Fail("x", e) }); got != "Cancelled. Nothing was changed on web1.\n" {
		t.Errorf("got %q", got)
	}
}
