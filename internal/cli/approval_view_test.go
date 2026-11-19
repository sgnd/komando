package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Only "Allow once" followed by "owner ok" allows. A failed, cancelled,
// timed-out or unavailable owner check, no reply, Deny and anything else
// is a no; only "gave up" means nobody answered.
func TestMacAnswer(t *testing.T) {
	for out, want := range map[string]macOutcome{
		"Allow once\nowner ok\n":        macAllowed,
		"Allow once\nowner ok":          macAllowed,
		"Allow once\nowner denied\n":    macOwnerFailed,
		"Allow once\nowner timeout\n":   macOwnerTimeout,
		"Allow once\nowner unavailable": macOwnerFailed,
		"Allow once\n\n":                macOwnerFailed,
		"Allow once\nowner ok please":   macOwnerFailed,
		"Allow once\nowner ok\nextra":   macOwnerFailed,
		"Allow once\n123456\n":          macOwnerFailed,
		"Allow once":                    macDenied,
		"Deny\nowner ok\n":              macDenied,
		"Deny\n":                        macDenied,
		"gave up\n":                     macGaveUp,
		"":                              macDenied,
		"allow once\nowner ok":          macDenied,
	} {
		if got := macAnswer([]byte(out)); got != want {
			t.Errorf("macAnswer(%q) = %v, want %v", out, got, want)
		}
	}
}

// The macOS script keeps Deny as the default and the Esc answer, closes
// itself after 120 seconds as "gave up", and takes every text from argv.
func TestMacAlertScript(t *testing.T) {
	for _, want := range []string{
		"addButtonWithTitle('Deny')", "deny.keyEquivalent = '\\r'", "allow.keyEquivalent = ''",
		"e.keyCode === 53", "stopModalWithCode($.NSAlertFirstButtonReturn)",
		"timerWithTimeIntervalRepeatsBlock(120,", "app.abortModal", "return 'gave up'",
		"a.messageText = argv[1]", "a.informativeText = argv[2]", "tv.string = argv[3]", "wrappingLabelWithString(argv[4])", "Number(argv[5])", "tv.editable = false",
		"ObjC.import('LocalAuthentication')", "canEvaluatePolicyError(2, null)", "evaluatePolicyLocalizedReasonReply(2, reason,",
		"if (r === $.NSAlertSecondButtonReturn) return 'Allow once\\n' + owner(argv[8], argv[9]);",
		"dateWithTimeIntervalSinceNow(Number(secs) || 1)", "until.timeIntervalSinceNow > 0", "return 'owner timeout'",
	} {
		if !strings.Contains(macAlertScript, want) {
			t.Errorf("script has no %q", want)
		}
	}
	if macWindowTimeout.Minutes() != 3 || windowGiveUp.Seconds() != 120 {
		t.Errorf("timeouts %v, %v", macWindowTimeout, windowGiveUp)
	}
	if strings.Contains(macAlertScript, "argv[0]") {
		t.Error("the script reads argv[0], the marker")
	}
	// a text that looks like an osascript option stays a text after the marker
	v := approvalView{raw: "-e do shell script \"id\""}
	args := macArgs(v)
	if args[0] != "-l" || args[1] != "JavaScript" || args[2] != "-e" || args[3] != macAlertScript || args[4] != macArgMarker || args[5] != "komando: allow?" || args[7] != v.raw {
		t.Errorf("argv %q", args)
	}
	v = approvalView{Agent: "-e", Head: "do shell script", Line: "x"}
	if args = macArgs(v); args[4] != macArgMarker || args[5] != "-e do shell script" {
		t.Errorf("title %q", args)
	}
}

// The text of a view is the window's text from before it had parts.
func TestApprovalViewText(t *testing.T) {
	v := approvalView{Agent: "Claude Code", Head: "wants to change web", Targets: []string{"web"}, Line: "komando exec web -- id",
		Reasons: []string{"a change on protected host web"}, Flags: []string{"--yes"}}
	want := "Claude Code wants to change web:\n\nkomando exec web -- id\n\nAllow this once?\n\nWhy komando asks: a change on protected host web\n--yes skips one of komando's safety stops (" + flagMeaning["--yes"] + ")."
	if got := v.text(); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
	if r := (approvalView{raw: "t"}); viewFor(nil, "t").raw != "t" || r.title() != "komando: allow?" {
		t.Error("a plain text is drawn as it is")
	}
}

// Golden: what the window shows for a multi-line command, a long line,
// a script body and the 4-line screenshot sample. KOMANDO_GOLDEN_UPDATE=1 records it again.
func TestApprovalWindowGolden(t *testing.T) {
	long := "komando exec web-1.example.test -- " + strings.Repeat("echo abcdefghij && ", 12) + "true"
	views := []approvalView{
		testView("Claude Code", []string{"--yes"}, "", []string{protWhy([]string{"web-1.example.test"}), "it runs on web-1.example.test (protected)"},
			"komando fs write web-1.example.test /etc/app.yaml --content $'a: 1\\nb:\\n  c: 2' --yes", ""),
		testView("Codex", []string{"--allow-dangerous", "--yes"}, "", []string{"it runs on web-1.example.test (protected)", "[R-7] rm -rf deletes files", protWhy([]string{"web-1.example.test"})}, long, ""),
		testView("Claude Code", []string{"--yes"}, "the program /usr/local/bin/x", []string{"it runs on db-2.example.test"}, "komando exec db-2.example.test --script ./deploy.sh --yes",
			"It also sends the script ./deploy.sh (40 bytes, 3 lines, SHA-256 ab12), all of it:\n\n  1  #!/bin/sh\n  2  set -e\n  3  systemctl restart app\n\n"),
		testView("Claude Code", []string{"--yes"}, "", []string{"it runs on web-1.example.test"}, "komando host rm web-1.example.test --yes", ""),
		shotView(), // the 4-line deploy.sh: every line shows, no "more lines" hint
	}
	var b strings.Builder
	for _, v := range views {
		b.WriteString(v.layout())
		l := winLayoutFor(v)
		b.WriteString("[sizes]\n")
		b.WriteString("mac height " + macArgs(v)[9] + ", windows " + strconv.Itoa(l.headH) + "/" + strconv.Itoa(l.cmdH) + "/" + strconv.Itoa(l.notesH) + "/" + strconv.Itoa(l.height) + "\n\n")
	}
	path := filepath.Join("testdata", "approval_window.txt")
	if os.Getenv("KOMANDO_GOLDEN_UPDATE") != "" {
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("window content changed (KOMANDO_GOLDEN_UPDATE=1 records it):\n%s", got)
	}
}

// The AppleScript window (server password) gets the marker
// first and read their text from item 2, so a text starting with "-e" is
// never taken as an osascript option.
func TestAppleScriptArgs(t *testing.T) {
	for name, script := range map[string]string{"login": loginDialogScript} {
		args := appleScriptArgs(script, "-e do shell script \"id\"")
		if len(args) != 4 || args[0] != "-e" || args[1] != script || args[2] != macArgMarker || args[3] != "-e do shell script \"id\"" {
			t.Errorf("%s: argv %q", name, args)
		}
		if !strings.Contains(script, "(item 2 of argv)") || strings.Contains(script, "item 1 of argv") {
			t.Errorf("%s: the script does not read the text from item 2", name)
		}
	}
}

// The header names each target once, says "Protected" once (not in the
// title, the target or a Risk line), and keeps the other reasons as risks.
func TestApprovalViewDedupes(t *testing.T) {
	why := []string{protWhy([]string{"web-1.example.test"}), "it runs on web-1.example.test (protected), web-2.example.test",
		"it runs on web-2.example.test, db-1.example.test", "[R-7] rm -rf deletes files"}
	v := newApprovalView(tcl, []string{"--allow-dangerous", "--yes"}, "", why, "komando exec web -- id", "")
	want := "Target: web-1.example.test, web-2.example.test, db-1.example.test\nProtected: yes\nRisk: [R-7] rm -rf deletes files\nSkips: --allow-dangerous, --yes"
	if got := v.header(); got != want {
		t.Errorf("header:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(v.title(), "protected") || strings.Count(v.title()+"\n"+v.header(), "rotected") != 1 {
		t.Errorf("protected is named more than once:\n%s", v.layout())
	}
	if !strings.HasSuffix(v.notes(), "Allow this once?") || !strings.Contains(v.notes(), "--yes skips") {
		t.Errorf("notes: %q", v.notes())
	}
	// the request text (the window's key) is as before
	if !strings.Contains(v.text(), "Why komando asks: "+protWhy([]string{"web-1.example.test"})) {
		t.Errorf("text changed:\n%s", v.text())
	}
}

// testView is newApprovalView with the agent's name set.
func testView(agent string, flags []string, what string, why []string, line, body string) approvalView {
	v := newApprovalView(tcl, flags, what, why, line, body)
	v.Agent = agent
	return v
}

// The box shows up to boxMaxLines lines: the 4-line script sample fits
// with no hint; a 40-line script gets the "more lines" hint and opens
// scrolled to the line a deny rule matches.
func TestApprovalBoxScroll(t *testing.T) {
	if v := shotView(); v.moreHint() != "" || lineCount(v.command()) > boxMaxLines {
		t.Errorf("the 4-line sample scrolls: %d lines, hint %q", lineCount(v.command()), v.moreHint())
	}
	var body strings.Builder
	body.WriteString("It also sends the script ./long.sh (1 bytes, 40 lines, SHA-256 ab), all of it:\n\n")
	for i := 1; i <= 40; i++ {
		l := "echo step " + strconv.Itoa(i)
		if i == 30 {
			l = "dd if=/dev/zero of=/dev/sda"
		}
		fmt.Fprintf(&body, "  %2d  %s\n", i, l)
	}
	v := testView("Claude Code", []string{"--allow-dangerous"}, "", []string{"it runs on web-1.example.test"}, "komando exec web-1.example.test --script ./long.sh --allow-dangerous", body.String())
	if !strings.HasPrefix(v.notes(), "29 more lines: scroll to read all") {
		t.Errorf("notes: %q", v.notes())
	}
	i := v.riskyLine()
	if i < boxMaxLines || !strings.Contains(strings.Split(v.command(), "\n")[i], "of=/dev/sda") {
		t.Fatalf("risky line %d", i)
	}
	off, n := v.riskyRange()
	if got := v.command()[off : off+n]; !strings.Contains(got, "of=/dev/sda") {
		t.Errorf("range %d,%d is %q", off, n, got)
	}
	if args := macArgs(v); args[10] != strconv.Itoa(off) || args[11] != strconv.Itoa(n) {
		t.Errorf("argv %q", args[9:])
	}
}
