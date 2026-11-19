package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The window says no unless "Allow once" came back: Deny, a timeout, an
// empty answer or anything else is a no, and only "gave up" means nobody
// answered.
func TestMacAnswer(t *testing.T) {
	for _, c := range []struct {
		out             string
		allowed, gaveUp bool
	}{
		{"Allow once\n", true, false},
		{"Deny\n", false, false},
		{"gave up\n", false, true},
		{"", false, false},
		{"allow once", false, false},
		{"Allow once please", false, false},
	} {
		a, g := macAnswer([]byte(c.out))
		if a != c.allowed || g != c.gaveUp {
			t.Errorf("macAnswer(%q) = %v, %v", c.out, a, g)
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
		"if (r === $.NSAlertSecondButtonReturn) return 'Allow once'",
		"a.messageText = argv[0]", "a.informativeText = argv[1]", "tv.string = argv[2]", "tv.editable = false",
	} {
		if !strings.Contains(macAlertScript, want) {
			t.Errorf("script has no %q", want)
		}
	}
	if macWindowTimeout.Minutes() != 3 || windowGiveUp.Seconds() != 120 {
		t.Errorf("timeouts %v, %v", macWindowTimeout, windowGiveUp)
	}
	v := approvalView{raw: "x'); doShellScript('id"}
	args := macArgs(v)
	if args[0] != "-l" || args[1] != "JavaScript" || args[3] != macAlertScript || args[6] != v.raw {
		t.Errorf("argv %q", args)
	}
}

// The text of a view is the window's text from before it had parts.
func TestApprovalViewText(t *testing.T) {
	v := approvalView{Agent: "Claude Code", Head: "wants to change web", Target: "web", Line: "komando exec web -- id",
		Reasons: []string{"a change on protected host web"}, Flags: []string{"--yes"}}
	want := "Claude Code wants to change web:\n\nkomando exec web -- id\n\nAllow this once?\n\nWhy komando asks: a change on protected host web\n--yes skips one of komando's safety stops (" + flagMeaning["--yes"] + ")."
	if got := v.text(); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
	if r := (approvalView{raw: "t"}); viewFor(nil, "t").raw != "t" || r.title() != "komando: allow?" {
		t.Error("a plain text is drawn as it is")
	}
}

// Golden: what the window shows for a multi-line command, a long line and
// a script body. KOMANDO_GOLDEN_UPDATE=1 records it again.
func TestApprovalWindowGolden(t *testing.T) {
	long := "komando exec web-1.example.test -- " + strings.Repeat("echo abcdefghij && ", 12) + "true"
	views := []approvalView{
		{Agent: "Claude Code", Head: "wants to change web-1.example.test (protected)", Target: "web-1.example.test (protected)",
			Line:    "komando fs write web-1.example.test /etc/app.yaml --content $'a: 1\\nb:\\n  c: 2' --yes",
			Reasons: []string{"a change on protected host web-1.example.test"}, Flags: []string{"--yes"}},
		{Agent: "Codex", Head: "wants to change web-1.example.test", Target: "web-1.example.test", Line: long,
			Reasons: []string{"[R-7] rm -rf deletes files", "a change on protected host web-1.example.test"}, Flags: []string{"--allow-dangerous", "--yes"}},
		{Agent: "Claude Code", Head: "wants to change db-2.example.test", Target: "db-2.example.test", Line: "komando exec db-2.example.test --script ./deploy.sh --yes",
			Body: "It also sends the script ./deploy.sh (40 bytes, 3 lines, SHA-256 ab12), all of it:\n\n  1  #!/bin/sh\n  2  set -e\n  3  systemctl restart app\n\n",
			What: "the program /usr/local/bin/x", Flags: []string{"--yes"}},
	}
	var b strings.Builder
	for _, v := range views {
		b.WriteString(v.layout())
		l := winLayoutFor(v)
		b.WriteString("[sizes]\n")
		b.WriteString("mac height " + macArgs(v)[8] + ", windows " + strconv.Itoa(l.headH) + "/" + strconv.Itoa(l.cmdH) + "/" + strconv.Itoa(l.notesH) + "/" + strconv.Itoa(l.height) + "\n\n")
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
