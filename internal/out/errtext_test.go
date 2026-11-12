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
	want := "Stopped: web1 is a protected server (production), so komando asks before changing it; nothing was changed\nHint: Run it again in a terminal.\n(code PROTECTED_HOST, exit 6)\n"
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
	if !strings.HasPrefix(got, "Error: host \"a\" not found\nHint: run komando list\n(code HOST_NOT_FOUND, exit 3)") {
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

// A person at a terminal reads errors, hints and warnings wrapped at 80
// columns (M-9), with a hanging indent and every backticked command whole;
// a pipe gets each on one line.
func TestTextWrapsAt80(t *testing.T) {
	saved := StderrWidth
	defer func() { StderrWidth = saved }()
	hint := strings.Repeat("check the address and the port of the server first, ", 3) +
		"then run `komando conn edit NAME --via bastion --url postgres://app@db:5432/shop` and try again"
	e := Errf(ExitConnect, "CONN_UNREACHABLE", hint, "%s", strings.Repeat("cannot reach the database ", 6))
	p := &Printer{Format: "text"}

	StderrWidth = func() int { return 80 }
	got := captureStderr(t, func() { p.Fail("x", e) })
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if n := len([]rune(line)); n > 80 && !strings.Contains(line, "`") {
			t.Errorf("line of %d columns: %q", n, line)
		}
	}
	if !strings.Contains(got, "`komando conn edit NAME --via bastion --url postgres://app@db:5432/shop`") {
		t.Errorf("the command was broken up:\n%s", got)
	}
	if !strings.Contains(got, "\n  ") {
		t.Errorf("no hanging indent:\n%s", got)
	}

	StderrWidth = func() int { return 0 }
	got = captureStderr(t, func() { p.Fail("x", e) })
	if n := strings.Count(got, "\n"); n != 3 {
		t.Errorf("a pipe gets %d lines, want 3 (error, hint, code):\n%s", n, got)
	}
}

// A person's stop line set with Say ("Stopped (Ctrl-C) ...") is its own
// label: no "Error:" in front of it (M-12).
func TestTextStopLineHasNoErrorLabel(t *testing.T) {
	p := &Printer{Format: "text"}
	e := (&Error{Code: "CANCELLED", Message: "interrupted", Exit: ExitError}).
		Say("Stopped (Ctrl-C) before the end; what already ran stays as it is", "check what it left, then run it again")
	got := captureStderr(t, func() { p.Fail("x", e) })
	want := "Stopped (Ctrl-C) before the end; what already ran stays as it is\nHint: check what it left, then run it again\n(code CANCELLED, exit 1)\n"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}
