package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

// The macOS script is a plain NSPanel of standard controls: no NSAlert,
// no icon, no colour; Deny is the default (Return), Esc and the first
// focus; it gives up after 120 seconds, answers with the strings
// macAnswer reads, takes every text from argv, and asks for the device
// owner only after Allow once.
func TestMacAlertScript(t *testing.T) {
	for _, want := range []string{
		"$.NSPanel.alloc.initWithContentRectStyleMaskBackingDefer(", "panel.title = argv[6]",
		"buttonWithTitleTargetAction(argv[7], answer, 'deny:')", "deny.keyEquivalent = '\\r'", "allow.keyEquivalent = ''",
		"panel.initialFirstResponder = deny", "deny.nextKeyView = allow", "setAccessibilityLabel(argv[7])", "setAccessibilityLabel(argv[8])",
		"Number(e.keyCode) === 53", "app.stopModalWithCode(DENY)", "app.runModalForWindow(panel)", "panel.level = $.NSFloatingWindowLevel",
		"timerWithTimeIntervalRepeatsBlock(120,", "app.stopModalWithCode(GAVE_UP)", "return 'gave up'", "return 'Deny'",
		"label(argv[1], $.NSFont.boldSystemFontOfSize(fs), w, true)", "argv[5].split('\\n\\n')", "var w = 440, pad = 20, gap = 12",
		"ObjC.import('LocalAuthentication')", "canEvaluatePolicyError(2, null)", "evaluatePolicyLocalizedReasonReply(2, reason,",
		"if (CHOICE === 'Allow') return 'Allow once\\n' + owner(argv[3], argv[4]);",
		"dateWithTimeIntervalSinceNow(Number(secs) || 1)", "until.timeIntervalSinceNow > 0", "return 'owner timeout'",
	} {
		if !strings.Contains(macAlertScript, want) {
			t.Errorf("script has no %q", want)
		}
	}
	for _, bad := range []string{"NSAlert", ".icon", "NSImage", "NSColor", "AttributedString", "argv[0]", "argv[9]"} {
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
	if len(args) != 13 || args[0] != "-l" || args[1] != "JavaScript" || args[2] != "-e" || args[3] != macAlertScript || args[4] != macArgMarker || args[5] != "komando: allow?" || args[6] != "" || args[9] != noBreakHyphens(v.raw) {
		t.Errorf("argv %q", args)
	}
	v = approvalView{Agent: "-e", Head: "do shell script", Line: "x"}
	if args = macArgs(v); args[4] != macArgMarker || args[5] != "Run a komando command" || args[6] != "Asked by -e" {
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
		"Risk: Deletes a system folder recursively (rm -rf)\nSkips: the dangerous-command check\n\nCommand: id"
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

// A script the window can show whole (bodyMaxLines) shows every line;
// one line more opens no window (approval_body.go refuses it).
func TestApprovalScriptWhole(t *testing.T) {
	script := func(n int) []byte {
		var b strings.Builder
		for i := 1; i <= n; i++ {
			fmt.Fprintf(&b, "echo step %d\n", i)
		}
		return []byte(b.String())
	}
	text, bad := newBody("the script ./a.sh", script(bodyMaxLines), false).shown(tcl)
	if bad != "" {
		t.Fatalf("%d lines refused: %s", bodyMaxLines, bad)
	}
	v := testView("Codex", nil, "", []string{"it runs on web-1.example.test"}, "komando exec web-1.example.test --script ./a.sh", text)
	shown := v.details()
	for i := 1; i <= bodyMaxLines; i++ {
		if !strings.Contains(shown, fmt.Sprintf("echo step %d\n", i)) && !strings.HasSuffix(shown, fmt.Sprintf("echo step %d", i)) {
			t.Errorf("line %d is not shown", i)
		}
	}
	if !strings.Contains(shown, "Script: ./a.sh · 40 lines · ") || !regexp.MustCompile(`SHA-256: [0-9a-f]{16}…\n`).MatchString(shown) {
		t.Errorf("caption:\n%s", shown)
	}
	if _, bad := newBody("the script ./a.sh", script(bodyMaxLines+1), false).shown(tcl); bad == "" {
		t.Errorf("%d lines get a window", bodyMaxLines+1)
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
		if got := riskWords(in, "en"); !slices.Equal(got, want) {
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

// The Windows dialog grows with its text; on a screen too small for it,
// the text area shrinks and scrolls, and the window fits the screen.
func TestWinLayoutFit(t *testing.T) {
	l := winLayout{titleH: 20, textH: 800, height: 850}
	if got := l.fit(1000); got != l {
		t.Errorf("fits, changed: %+v", got)
	}
	got := l.fit(600)
	if !got.scroll || got.height != 600 || got.textH != 550 {
		t.Errorf("too tall: %+v", got)
	}
}

// The window shows what runs and nothing approved is hidden: the command
// after "--", every option that changes what runs or where (an --env
// value never), and no Options line when only covered flags are given.
func TestApprovalOptions(t *testing.T) {
	for _, tc := range []struct{ name, line, want string }{
		{"user and env", "komando exec web-1.example.test --user deploy --env TOKEN=abc --env=MODE=x --yes -- uptime", "Options: --user deploy, --env TOKEN, --env MODE\nCommand: uptime"},
		{"yes only", "komando exec web-1.example.test --yes -- uptime", "Command: uptime"},
		{"via, timeout, sudo", "komando exec web-1.example.test --via bastion --timeout 30s --sudo --allow-dangerous -- id", "Options: --via bastion, --timeout 30s, --sudo\nCommand: id"},
		{"no --", "komando fs write web-1.example.test /etc/a --content x --yes", "Command: komando fs write web-1.example.test /etc/a --content x --yes"},
		{"script", "komando exec web-1.example.test --script ./a.sh --user deploy --yes", "Options: --user deploy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := testView("Codex", []string{"--yes"}, "", []string{"it runs on web-1.example.test"}, tc.line, "")
			got := v.shown()
			if o := v.optionLine(); o != "" {
				got = o + "\n" + got
			}
			got = strings.TrimSuffix(got, "\n")
			if got != tc.want {
				t.Errorf("shown:\n%s\nwant:\n%s", got, tc.want)
			}
			if strings.Contains(v.shown(), "abc") || strings.Contains(v.shown(), "=x") {
				t.Error("an --env value is shown")
			}
		})
	}
	sudo := testView("Codex", nil, "", []string{"it runs on web-1.example.test", "sudo runs the command as root"}, "komando exec web-1.example.test --sudo -- id", "")
	if sudo.shown() != "Command: id" {
		t.Errorf("--sudo repeated next to its Risk line: %q", sudo.shown())
	}
	prot := testView("Codex", []string{"--yes"}, "", []string{"it runs on web-1.example.test (protected)"}, "komando exec web-1.example.test --yes -- id", "")
	if strings.Contains(prot.details(), "Skips") {
		t.Errorf("Skips with only --yes on a protected target:\n%s", prot.details())
	}
}

// The panel prints "gave up" only when its 120 s timer fires; Deny, Esc,
// Return, the close button and Cmd-W print "Deny"; Allow once goes to the
// owner check. The button actions stop the modal through the app object
// itself: in JXA $.NSApp is not the application (it reads as a nil
// function), so calling it threw and the panel ended as "gave up".
func TestMacPanelAnswers(t *testing.T) {
	script := macAlertScript
	for _, tc := range []struct{ name, want string }{
		{"deny button", "'deny:': { types: ['void', ['id']], implementation: function (s) { CHOICE = 'Deny'; CHOSEN = true; APP.stopModalWithCode(DENY); } }"},
		{"allow button", "'allow:': { types: ['void', ['id']], implementation: function (s) { CHOICE = 'Allow'; CHOSEN = true; APP.stopModalWithCode(ALLOW); } }"},
		{"close button", "'windowWillClose:': { types: ['void', ['id']], implementation: function (n) { if (!CHOSEN) { CHOICE = 'Deny'; CHOSEN = true; } APP.stopModalWithCode(DENY); } }"},
		{"close wired", "panel.delegate = answer"},
		{"closable", "$.NSWindowStyleMaskTitled | $.NSWindowStyleMaskClosable"},
		{"esc", "if (Number(e.keyCode) === 53) { CHOICE = 'Deny'; CHOSEN = true; app.stopModalWithCode(DENY); return null; }"},
		{"cmd-w", "if (Number(e.keyCode) === 13 && (Number(e.modifierFlags) & $.NSEventModifierFlagCommand)) { CHOICE = 'Deny'; CHOSEN = true; app.stopModalWithCode(DENY); return null; }"},
		{"give-up timer", "timerWithTimeIntervalRepeatsBlock(120, false, function () { CHOICE = 'gave up'; CHOSEN = true; app.stopModalWithCode(GAVE_UP); })"},
		{"gave up only from the timer", "if (CHOICE === 'gave up') return 'gave up';"},
		{"allow goes to the owner check", "if (CHOICE === 'Allow') return 'Allow once\\n' + owner(argv[3], argv[4]);"},
		{"anything else is Deny", "return 'Deny';\n}`"},
	} {
		if !strings.Contains(script+"`", tc.want) {
			t.Errorf("%s: the script has no %q", tc.name, tc.want)
		}
	}
	for _, bad := range []string{"$.NSApp.", "abortModal", "return 'gave up';\n}"} {
		if strings.Contains(script+"`", bad) {
			t.Errorf("the script has %q", bad)
		}
	}
	// what each printed answer means: only Allow once with owner ok allows
	for out, want := range map[string]macOutcome{
		"Deny\n": macDenied, "gave up\n": macGaveUp,
		"Allow once\nowner ok\n": macAllowed, "Allow once\nowner denied\n": macOwnerFailed,
	} {
		if got := macAnswer([]byte(out)); got != want {
			t.Errorf("%q: %v, want %v", out, got, want)
		}
	}
}

// Each button stops the panel with its own code, and the code runModal
// returns is compared with the same constants as a number: JXA hands an
// NSInteger back as a string ("1001"), so without Number() the Allow code
// never matched and fell through to Deny. Only ALLOW reaches the owner
// check, and the Deny fallback comes after both checks.
func TestMacPanelCodes(t *testing.T) {
	s := macAlertScript
	consts := regexp.MustCompile(`var DENY = (\d+), ALLOW = (\d+), GAVE_UP = (\d+)`).FindStringSubmatch(s)
	if consts == nil || consts[1] == consts[2] || consts[2] == consts[3] || consts[1] == consts[3] {
		t.Fatalf("codes not distinct: %q", consts)
	}
	for _, want := range []string{
		"buttonWithTitleTargetAction(argv[7], answer, 'deny:')", "'deny:': { types: ['void', ['id']], implementation: function (s) { CHOICE = 'Deny'; CHOSEN = true; APP.stopModalWithCode(DENY); } }",
		"buttonWithTitleTargetAction(argv[8], answer, 'allow:')", "'allow:': { types: ['void', ['id']], implementation: function (s) { CHOICE = 'Allow'; CHOSEN = true; APP.stopModalWithCode(ALLOW); } }",
		"app.runModalForWindow(panel); // the answer is CHOICE",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	allow, gave, deny := strings.Index(s, "if (CHOICE === 'Allow') return 'Allow once"), strings.Index(s, "if (CHOICE === 'gave up') return 'gave up';"), strings.LastIndex(s, "return 'Deny';")
	if allow < 0 || gave < 0 || deny < allow || deny < gave {
		t.Errorf("answer order: allow %d, gave up %d, deny %d", allow, gave, deny)
	}
	if strings.Count(s, "owner(argv[3], argv[4])") != 1 {
		t.Error("the owner check is reached other than from ALLOW")
	}
}

// The answer is decided by CHOICE, which each path sets itself, not by
// the code runModal returns (JXA may hand that back wrapped); a close after
// a choice never downgrades it.
func TestMacPanelChoice(t *testing.T) {
	s := macAlertScript
	for _, want := range []string{
		"var CHOICE = 'Deny', CHOSEN = false;",
		"implementation: function (s) { CHOICE = 'Deny'; CHOSEN = true; APP.stopModalWithCode(DENY); }",
		"implementation: function (s) { CHOICE = 'Allow'; CHOSEN = true; APP.stopModalWithCode(ALLOW); }",
		"implementation: function (n) { if (!CHOSEN) { CHOICE = 'Deny'; CHOSEN = true; } APP.stopModalWithCode(DENY); }",
		"function () { CHOICE = 'gave up'; CHOSEN = true; app.stopModalWithCode(GAVE_UP); }",
		"if (CHOICE === 'Allow') return 'Allow once\\n' + owner(argv[3], argv[4]);",
		"if (CHOICE === 'gave up') return 'gave up';",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	if strings.Contains(s, "r === ") {
		t.Error("the runModal code still decides the answer")
	}
}

// No debug output reaches stderr in a normal run.
func TestMacPanelNoDebugStderr(t *testing.T) {
	if strings.Contains(macAlertScript, "typeof r") || strings.Contains(macAlertScript, "'modal: '") {
		t.Error("the panel script still writes the modal debug line")
	}
}

// What runs (the command, a script) is drawn with non-breaking hyphens
// and cannot be selected, so no copy of it runs differently; the info
// lines can be copied and keep plain hyphens.
func TestMacCopyRule(t *testing.T) {
	for _, want := range []string{"function label(text, font, w, copy) {", "l.selectable = copy;",
		"label(argv[2], $.NSFont.systemFontOfSize(fs), w, true)", "label(g, $.NSFont.systemFontOfSize(fs), w, false)", "argv[5].split("} {
		if !strings.Contains(macAlertScript, want) {
			t.Errorf("script has no %q", want)
		}
	}
	for _, c := range shotCases {
		args := macArgs(c.view())
		if strings.ContainsRune(args[5]+args[6], '\u2011') {
			t.Errorf("%s: a copyable label has U+2011: %q", c.name, args[6])
		}
		if strings.Contains(args[9], "-") {
			t.Errorf("%s: the command label has a breakable hyphen", c.name)
		}
	}
}
