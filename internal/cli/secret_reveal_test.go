package cli

import (
	"strings"
	"testing"
)

// revealWindow stands in for komando's window: it counts the windows,
// keeps the last text and answers allow (shown says a screen was there).
// It runs the rest of the test as a program without a terminal (the Mac
// app) on a Mac, where a click-only window is allowed.
func revealWindow(t *testing.T, allow, shown bool) (n *int, text *string) {
	t.Helper()
	noAgent(t)
	n, text = new(int), new(string)
	savedAsk, savedOS, savedFrom, savedTerminal := askOnScreen, desktopOS, startedFrom, tcl.terminal
	askOnScreen = func(_ *call, s string) (bool, bool) {
		*n++
		*text = s
		return allow && shown, shown
	}
	desktopOS, startedFrom = "darwin", func(*call) string { return "Komando ← launchd" }
	tcl.terminal = false
	t.Cleanup(func() {
		askOnScreen, desktopOS, startedFrom, tcl.terminal = savedAsk, savedOS, savedFrom, savedTerminal
		resetApproval()
	})
	return n, text
}

func revealHome(t *testing.T) {
	t.Helper()
	invHome(t)
	t.Setenv("KOMANDO_NO_DIALOG", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	t.Setenv("KOMANDO_SECRET", "s3cret-value-long")
	mustRun(t, "secret", "set", "db-pass", "--from-env", "KOMANDO_SECRET")
	t.Cleanup(endCommand)
}

// The Mac app runs komando without a terminal: komando shows the value
// only after the person's yes in its own window, and records how.
func TestRevealFromAnAppAsksInTheWindow(t *testing.T) {
	revealHome(t)
	n, text := revealWindow(t, true, true)
	savedArgs := tcl.args
	tcl.args = []string{"komando", "secret", "show", "db-pass", "--reveal"} // what the window quotes
	t.Cleanup(func() { tcl.args = savedArgs })
	d := mustRun(t, "secret", "show", "db-pass", "--reveal")
	if d["value"] != "s3cret-value-long" || *n != 1 {
		t.Fatalf("value %v after %d windows", d["value"], *n)
	}
	for _, want := range []string{"secret:db-pass", "komando secret show db-pass --reveal", "Started from: Komando ← launchd"} {
		if !strings.Contains(*text, want) {
			t.Errorf("window text lacks %q: %q", want, *text)
		}
	}
	if strings.Contains(*text, "s3cret") {
		t.Errorf("the window shows the value: %q", *text)
	}
	a := lastAudit(t)
	if a["command"] != "secret.reveal" || a["secret"] != "db-pass" || a["via"] != "window" || a["started_from"] != "Komando ← launchd" {
		t.Errorf("audit: %v", a)
	}
	if strings.Contains(auditText(t), "s3cret") {
		t.Error("the audit log holds the value")
	}
}

func TestRevealDeniedOrNoScreen(t *testing.T) {
	revealHome(t)
	revealWindow(t, false, true)
	d, e := invRun(t, "secret", "show", "db-pass", "--reveal")
	if e == nil || e.Code != "DECLINED" || d["value"] != nil {
		t.Fatalf("Deny: %+v %v", e, d)
	}
	if a := lastAudit(t); a["blocked"] != "DECLINED" || a["secret"] != "db-pass" {
		t.Errorf("audit of the refusal: %v", a)
	}
	n, _ := revealWindow(t, true, false) // no screen: nobody to ask
	if e := wantCode(t, "REVEAL_NEEDS_HUMAN", "secret", "show", "db-pass", "--reveal"); !strings.Contains(e.Hint, "in a terminal") || *n != 1 {
		t.Errorf("hint %q after %d windows", e.Hint, *n)
	}
}

// A Linux or BSD desktop gets no click-only window: another program
// could press Allow once there.
func TestRevealNoClickWindowOnLinux(t *testing.T) {
	revealHome(t)
	n, _ := revealWindow(t, true, true)
	desktopOS = "linux"
	t.Setenv("DISPLAY", ":0")
	wantCode(t, "REVEAL_NEEDS_HUMAN", "secret", "show", "db-pass", "--reveal")
	if *n != 0 {
		t.Errorf("%d click-only windows on a Linux desktop", *n)
	}
}

// A person at a terminal typed the command: no window.
func TestRevealAtATerminal(t *testing.T) {
	revealHome(t)
	n, _ := revealWindow(t, false, true)
	tcl.terminal = true // a person at a terminal (TestMain unsets CI)
	if d := mustRun(t, "secret", "show", "db-pass", "--reveal"); d["value"] != "s3cret-value-long" || *n != 0 {
		t.Fatalf("value %v after %d windows", d["value"], *n)
	}
	if a := lastAudit(t); a["via"] != "terminal" {
		t.Errorf("audit: %v", a)
	}
}

// A dry run shows no value and asks nobody.
func TestRevealDryRun(t *testing.T) {
	revealHome(t)
	n, _ := revealWindow(t, true, true)
	if d := mustRun(t, "secret", "show", "db-pass", "--reveal", "--dry-run"); d["value"] != nil || *n != 0 {
		t.Fatalf("dry run: value %v after %d windows", d["value"], *n)
	}
}

// An AI agent never gets a value or a private key, not even with the
// person's yes: no window opens, and the refusal is recorded with the name.
func TestRevealNeverForAnAgent(t *testing.T) {
	revealHome(t)
	mustRun(t, "key", "gen", "deploy")
	n := asAgent(t, true, true)
	for _, args := range [][]string{
		{"secret", "show", "db-pass", "--reveal"},
		{"key", "show", "deploy", "--reveal"},
	} {
		d, e := invRun(t, args...)
		if e == nil || e.Code != "REVEAL_NEEDS_HUMAN" || d["value"] != nil || d["private_key"] != nil || *n != 0 {
			t.Fatalf("%v: %+v, %d windows", args, e, *n)
		}
	}
	if a := lastAudit(t); a["blocked"] != "REVEAL_NEEDS_HUMAN" || a["key"] != "deploy" || a["agent"] != "Claude Code" {
		t.Errorf("audit of the refusal: %v", a)
	}
}

// key show --reveal gives a person the private key of a key komando made;
// a key added from a file names the file.
func TestKeyShowReveal(t *testing.T) {
	revealHome(t)
	mustRun(t, "key", "gen", "deploy")
	if d := mustRun(t, "key", "show", "deploy"); d["private_key"] != nil {
		t.Fatalf("key show without --reveal: %v", d)
	}
	n, _ := revealWindow(t, true, true)
	d := mustRun(t, "key", "show", "deploy", "--reveal")
	if pk, _ := d["private_key"].(string); !strings.Contains(pk, "PRIVATE KEY") || *n != 1 {
		t.Fatalf("private key %.40q after %d windows", pk, *n)
	}
	if a := lastAudit(t); a["command"] != "key.reveal" || a["key"] != "deploy" || a["via"] != "window" {
		t.Errorf("audit: %v", a)
	}
}
