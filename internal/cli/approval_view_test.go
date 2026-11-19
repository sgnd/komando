package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/policy"
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

// The macOS script is a plain NSAlert: no accessory view, no custom
// colour, an empty 1x1 icon; Deny is the default and Esc, it closes
// itself after 120 seconds, takes every text from argv, and asks for the
// device owner only after Allow once.
func TestMacAlertScript(t *testing.T) {
	for _, want := range []string{
		"addButtonWithTitle('Deny')", "deny.keyEquivalent = '\\r'", "allow.keyEquivalent = ''",
		"e.keyCode === 53", "stopModalWithCode($.NSAlertFirstButtonReturn)",
		"timerWithTimeIntervalRepeatsBlock(120,", "app.abortModal", "return 'gave up'",
		"a.messageText = argv[1]", "a.informativeText = argv[2]", "a.icon = $.NSImage.alloc.initWithSize($.NSMakeSize(1, 1))",
		"ObjC.import('LocalAuthentication')", "canEvaluatePolicyError(2, null)", "evaluatePolicyLocalizedReasonReply(2, reason,",
		"if (r === $.NSAlertSecondButtonReturn) return 'Allow once\\n' + owner(argv[3], argv[4]);",
		"dateWithTimeIntervalSinceNow(Number(secs) || 1)", "until.timeIntervalSinceNow > 0", "return 'owner timeout'",
	} {
		if !strings.Contains(macAlertScript, want) {
			t.Errorf("script has no %q", want)
		}
	}
	for _, bad := range []string{"accessoryView", "NSColor", "NSScrollView", "NSTextView", "NSFont", "AttributedString", "hasDestructiveAction", "argv[0]", "argv[5]"} {
		if strings.Contains(macAlertScript, bad) {
			t.Errorf("the script uses %s", bad)
		}
	}
	if macWindowTimeout.Minutes() != 3 || windowGiveUp.Seconds() != 120 {
		t.Errorf("timeouts %v, %v", macWindowTimeout, windowGiveUp)
	}
	// a text that looks like an osascript option stays a text after the marker
	v := approvalView{raw: "-e do shell script \"id\""}
	args := macArgs(v)
	if len(args) != 9 || args[0] != "-l" || args[1] != "JavaScript" || args[2] != "-e" || args[3] != macAlertScript || args[4] != macArgMarker || args[5] != "komando: allow?" || args[6] != v.raw {
		t.Errorf("argv %q", args)
	}
	v = approvalView{Agent: "-e", Head: "do shell script", Line: "x"}
	if args = macArgs(v); args[4] != macArgMarker || args[5] != "Run a komando command" || !strings.HasPrefix(args[6], "Asked by -e\n") {
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
		testView("Codex", []string{"--allow-dangerous", "--yes"}, "", []string{"it runs on web-1.example.test (protected)", "[rm-system-dir] deletes a system folder recursively", protWhy([]string{"web-1.example.test"})}, long, ""),
		testView("Claude Code", []string{"--yes"}, "the program /usr/local/bin/x", []string{"it runs on db-2.example.test"}, "komando exec db-2.example.test --script ./deploy.sh --yes",
			"It also sends the script ./deploy.sh (40 bytes, 3 lines, SHA-256 ab12), all of it:\n\n  1  #!/bin/sh\n  2  set -e\n  3  systemctl restart app\n\n"),
		testView("Claude Code", []string{"--yes"}, "", []string{"it runs on web-1.example.test"}, "komando host rm web-1.example.test --yes", ""),
		shotView(), // the 4-line deploy.sh: every line shows, no "more lines" hint
	}
	windowGolden(t, "approval_window.txt", views)
}

// Golden: each screenshot case's text layout, so a case's content is
// checked without a window. KOMANDO_GOLDEN_UPDATE=1 records it again.
func TestApprovalShotCasesGolden(t *testing.T) {
	var views []approvalView
	seen := map[string]bool{}
	for _, c := range shotCases {
		if seen[c.name] || c.name != strings.ToLower(c.name) || strings.ContainsAny(c.name, " _/") {
			t.Errorf("case name %q: want unique, lowercase, hyphens only", c.name)
		}
		seen[c.name] = true
		views = append(views, c.view())
	}
	windowGolden(t, "approval_shot_cases.txt", views)
}

// windowGolden compares each view's layout and sizes with testdata/name.

func windowGolden(t *testing.T, name string, views []approvalView) {
	t.Helper()
	var b strings.Builder
	for _, v := range views {
		b.WriteString(v.layout())
		l := winLayoutFor(v)
		b.WriteString("[windows sizes]\n" + strconv.Itoa(l.titleH) + "/" + strconv.Itoa(l.textH) + "/" + strconv.Itoa(l.height) + "\n\n")
	}
	path := filepath.Join("testdata", name)
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

// The text names each target once, says "Protected" once, keeps the
// other reasons as risks in plain words, and the title names the action.
func TestApprovalViewDedupes(t *testing.T) {
	why := []string{protWhy([]string{"web-1.example.test"}), "it runs on web-1.example.test (protected), web-2.example.test",
		"it runs on web-2.example.test, db-1.example.test", "[rm-system-dir] deletes a system folder recursively"}
	v := newApprovalView(tcl, []string{"--allow-dangerous", "--yes"}, "", why, "komando exec web -- id", "")
	v.Agent = "Codex"
	want := "Asked by Codex\nTargets: web-1.example.test, web-2.example.test, db-1.example.test\nStatus: Protected\n" +
		"Risk: Deletes a system folder recursively (rm -rf)\nSkips: the dangerous-command stop, the protected-server stop\n\nkomando exec web -- id"
	if got := v.details(); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
	if v.title() != "Run a command on 3 servers" {
		t.Errorf("title %q", v.title())
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

// An alert cannot scroll: a long script shows shownMax lines and says how
// many it left out; the line a deny rule matches is always shown, with
// one line before and after it; the caption keeps the full SHA-256.
func TestApprovalShownCap(t *testing.T) {
	script := func(n, risky int) approvalView {
		var body strings.Builder
		body.WriteString("It also sends the script ./long.sh (100 bytes, " + strconv.Itoa(n) + " lines, SHA-256 " + strings.Repeat("ab", 32) + "), all of it:\n\n")
		for i := 1; i <= n; i++ {
			l := "echo step " + strconv.Itoa(i)
			if i == risky {
				l = "dd if=/dev/zero of=/dev/sda"
			}
			fmt.Fprintf(&body, "  %2d  %s\n", i, l)
		}
		return testView("Codex", nil, "", []string{"it runs on web-1.example.test"}, "komando exec web-1.example.test --script ./long.sh", body.String())
	}
	for _, tc := range []struct {
		name        string
		n, risky    int
		lines, more string
	}{
		{"fits", 6, 0, "", ""},
		{"long, risk near the top", 40, 3, "", "(33 more lines)"},
		{"long, risk far down", 40, 30, "(25 lines not shown)", "(9 more lines)"},
		{"long, risk last", 40, 40, "(35 lines not shown)", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := script(tc.n, tc.risky)
			shown := v.shown()
			rows := strings.Split(shown, "\n")
			if len(rows) > shownMax+2 {
				t.Errorf("%d rows:\n%s", len(rows), shown)
			}
			if !strings.Contains(shown, "SHA-256: "+strings.Repeat("ab", 32)) {
				t.Errorf("no full SHA-256:\n%s", shown)
			}
			if tc.risky > 0 && !strings.Contains(shown, "of=/dev/sda") {
				t.Errorf("the risky line is not shown:\n%s", shown)
			}
			if tc.risky > 1 && !strings.Contains(shown, fmt.Sprintf("  %2d  echo step %d", tc.risky-1, tc.risky-1)) {
				t.Errorf("no line before the risky one:\n%s", shown)
			}
			if tc.risky > 0 && tc.risky < tc.n && !strings.Contains(shown, fmt.Sprintf("  %2d  echo step %d", tc.risky+1, tc.risky+1)) {
				t.Errorf("no line after the risky one:\n%s", shown)
			}
			if (tc.lines != "") != strings.Contains(shown, "lines not shown") || (tc.lines != "" && !strings.Contains(shown, tc.lines)) {
				t.Errorf("want %q:\n%s", tc.lines, shown)
			}
			if (tc.more != "") != strings.Contains(shown, "more lines") || (tc.more != "" && !strings.HasSuffix(shown, tc.more)) {
				t.Errorf("want %q at the end:\n%s", tc.more, shown)
			}
		})
	}
}

// A deny-rule reason loses its rule ids and names its trigger; every
// built-in rule has one; any other reason stays as it is, capitalised.
func TestRiskWords(t *testing.T) {
	for in, want := range map[string][]string{
		"[rm-system-dir,db-drop] deletes a system folder recursively; drops a database":                         {"Deletes a system folder recursively (rm -rf)", "Drops a database (DROP DATABASE)"},
		"[rm-root,rm-system-dir] deletes / or the home folder recursively; deletes a system folder recursively": {"Deletes / or the home folder recursively (rm -rf)", "Deletes a system folder recursively (rm -rf)"},
		"[" + policy.CustomID("x") + "] matches your deny rule x":                                               {"Matches your deny rule x"},
		"[web] restarts the service":    {"[web] restarts the service"},
		"[a,b] one reason":              {"[a,b] one reason"},
		"sudo runs the command as root": {"Sudo runs the command as root"},
	} {
		if got := riskWords(in); !slices.Equal(got, want) {
			t.Errorf("riskWords(%q) = %q, want %q", in, got, want)
		}
	}
	for _, r := range policy.Rules() {
		if ruleTrigger[r.ID] == "" {
			t.Errorf("rule %s has no trigger in ruleTrigger", r.ID)
		}
	}
}

// No row of the command box is wider than boxCols, so it never scrolls
// sideways; a wrapped row hangs under the text, after a script line's
