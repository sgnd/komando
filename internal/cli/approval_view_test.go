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
// no icon, no colour; Deny is the default (Return) and Esc;
// it gives up after 120 seconds, answers with the strings
// macAnswer reads, takes every text from argv, and asks for the device
// owner only after Allow once.
func TestMacAlertScript(t *testing.T) {
	for _, want := range []string{
		"$.KomandoPanel.alloc.initWithContentRectStyleMaskBackingDefer(", "superclass: 'NSPanel'", "panel.title = argv[6]",
		"buttonWithTitleTargetAction(argv[7], answer, 'deny:')", "deny.keyEquivalent = '\\r'", "allow.keyEquivalent = ''",
		"setAccessibilityLabel(argv[7])", "setAccessibilityLabel(argv[8])",
		"code === 53 || code === 36", "APP.stopModalWithCode(DENY)", "app.runModalForWindow(panel)", "panel.level = $.NSFloatingWindowLevel",
		"timerWithTimeIntervalRepeatsBlock(120,", "app.stopModalWithCode(GAVE_UP)", "return 'gave up'", "return 'Deny'",
		"label(argv[1], $.NSFont.boldSystemFontOfSize(fs), w, true)", "var w = 440, pad = 20, gap = 12",
		"ObjC.import('LocalAuthentication')", "canEvaluatePolicyError(2, null)", "evaluatePolicyLocalizedReasonReply(2, reason,",
		"if (CHOICE === 'Allow') return 'Allow once\\n' + owner(argv[3], argv[4]);",
		"dateWithTimeIntervalSinceNow(Number(secs) || 1)", "until.timeIntervalSinceNow > 0", "return 'owner timeout'",
	} {
		if !strings.Contains(macAlertScript, want) {
			t.Errorf("script has no %q", want)
		}
	}
	for _, bad := range []string{"NSAlert", ".icon", "NSImage", "NSAttributedString", "initWithString", "argv[0]", "argv[11]"} {
		if strings.Contains(macAlertScript, bad) {
			t.Errorf("the script uses %s", bad)
		}
	}
	// argv[10] is only the debug switch (approval_debug.go)
	if strings.Count(macAlertScript, "argv[10]") != 1 || !strings.Contains(macAlertScript, "DEBUG = argv[10] === '1';") {
		t.Error("argv[10] is used for more than the debug switch")
	}
	// no colours of its own: only the system's focus indicator colour
	if strings.Count(macAlertScript, "NSColor.") != strings.Count(macAlertScript, "NSColor.keyboardFocusIndicatorColor") {
		t.Error("the script uses a colour other than the focus indicator's")
	}
	if macWindowTimeout.Minutes() != 3 || windowGiveUp.Seconds() != 120 {
		t.Errorf("timeouts %v, %v", macWindowTimeout, windowGiveUp)
	}
	// a text that looks like an osascript option stays a text after the marker
	v := approvalView{raw: "-e do shell script \"id\""}
	args := macArgs(v)
	if len(args) != 14 || args[0] != "-l" || args[1] != "JavaScript" || args[2] != "-e" || args[3] != macAlertScript || args[4] != macArgMarker || args[5] != "komando: allow?" || args[6] != "" || args[9] != noBreakHyphens(v.raw) {
		t.Errorf("argv %q", args)
	}
	v = approvalView{Agent: "-e", Head: "do shell script", Line: "x"}
	if args = macArgs(v); args[4] != macArgMarker || args[5] != "Run a komando command" || args[6] != "Asked by -e" {
		t.Errorf("title %q", args)
	}
}

// The macOS panel never grows past the screen: the title, the info
// lines and the buttons stay fixed, and what runs (argv[5]) sits alone in
// a scroll view that takes the height left over, scrolling only when it
// has to (C207).
func TestMacPanelScrollsBody(t *testing.T) {
	s := macAlertScript
	for _, want := range []string{
		"$.NSScreen.mainScreen", "visibleFrame.size.height", "maxH = ",
		"$.NSScrollView.alloc.initWithFrame(", "sv.documentView = DOC", "sv.hasHorizontalScroller = false",
		"sv.hasVerticalScroller = scroll", "sv.drawsBackground = false", "sv.setAccessibilityLabel(",
		"monospacedSystemFontOfSizeWeight(fs, 0)", "label(argv[5], mono, ", "view.addSubview(sv)",
		"Math.min(body.h, room)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	// what runs is one label in the scroll view, not stacked parts
	if strings.Contains(s, "argv[5].split('\\n") {
		t.Error("argv[5] is still split into stacked parts")
	}
	// the fixed parts hold only the title and the info lines
	fixed := s[strings.Index(s, "var parts = ["):strings.Index(s, "var answer")]
	if strings.Contains(fixed, "argv[5]") {
		t.Errorf("argv[5] is among the fixed parts: %s", fixed)
	}
	// the panel is made at the capped height, after the cap is known
	if c, p := strings.Index(s, "maxH = "), strings.Index(s, "initWithContentRectStyleMaskBackingDefer("); c < 0 || p < c {
		t.Error("the panel is created before the screen cap")
	}
	// the command and script stay non-selectable
	if !strings.Contains(s, "label(argv[5], mono, bw, false)") {
		t.Error("what runs is selectable or not measured at the scroll width")
	}
}

// A script that scrolls cannot hide its last lines: the scroller is
// always drawn, a fixed line says how many lines there are, and "Allow
// once" stays off until the end has been shown once (C207 audit).
func TestMacPanelScrollGate(t *testing.T) {
	s := macAlertScript
	for _, want := range []string{
		"sv.scrollerStyle = 0",
		"hint = label(argv[9], $.NSFont.systemFontOfSize(fs), w, true)",
		"allow.enabled = !scroll", "SEEN = !scroll",
		"sv.contentView.postsBoundsChangedNotifications = true",
		"addObserverSelectorNameObject(answer, 'scrolled:', $.NSViewBoundsDidChangeNotification, sv.contentView)",
		"'scrolled:': { types: ['void', ['id']]",
		"function seenEnd(y, h, docH) { return y + h >= docH - 1; }", "if (seenEnd(r.origin.y, r.size.height, DOC.frame.size.height)) { SEEN = true; ALLOW_BTN.enabled = true; note('read to the end'); }",
		"'allow:': { types: ['void', ['id']], implementation: function (s) { if (DEBUG) note((SEEN ? 'end: Allow once, ' : 'Allow once ignored: not read to the end, ') + how()); if (!SEEN) return; CHOICE = 'Allow'",
		"removeObserver(answer)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	// the hint is measured before the panel exists and sits above the buttons
	if h, p := strings.Index(s, "hint = label(argv[9]"), strings.Index(s, "initWithContentRectStyleMaskBackingDefer("); h < 0 || p < h {
		t.Error("the hint is not measured before the panel")
	}
	if !strings.Contains(s, "hint.v.frame = $.NSMakeRect(pad, y, w, hint.h)") {
		t.Error("the hint is not placed under the scroll view")
	}
	// Deny keeps the default and is never disabled
	if strings.Contains(s, "deny.enabled") {
		t.Error("the script disables Deny")
	}
	body := strings.Repeat("x\n", 12) + "x"
	for _, c := range []struct{ lang, want string }{
		{"en", "Scroll to read all 13 lines"},
		{"id", "Gulir untuk membaca semua 13 baris"},
	} {
		v := approvalView{raw: body, Lang: c.lang}
		if got := macArgs(v)[13]; got != c.want {
			t.Errorf("%s: hint %q, want %q", c.lang, got, c.want)
		}
	}
}

// The script region opens at its first line: the document view is
// flipped, the clip view is put at the top before the panel shows, and
// the gate looks at the visible rect's bottom edge, so the start position
// never counts as read (C207, CI shots of 862d50cc).
func TestMacPanelStartsAtTop(t *testing.T) {
	s := macAlertScript
	for _, want := range []string{
		"name: 'KomandoDoc'", "superclass: 'NSView'", "'isFlipped': { types: ['bool', []], implementation: function () { return true; } }",
		"DOC = $.KomandoDoc.alloc.initWithFrame($.NSMakeRect(0, 0, bw, body.h))", "DOC.addSubview(body.v)", "sv.documentView = DOC",
		"sv.contentView.scrollToPoint($.NSMakePoint(0, 0))",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	for _, bad := range []string{"r.origin.y <= 1", "body.h - bodyH))", "sv.documentView = body.v"} {
		if strings.Contains(s, bad) {
			t.Errorf("script still has %q", bad)
		}
	}
	if top, show := strings.Index(s, "scrollToPoint($.NSMakePoint(0, 0))"), strings.Index(s, "panel.makeKeyAndOrderFront(null)"); top < 0 || show < top {
		t.Error("the region is not put at the top before the panel shows")
	}
}

// The hint counts the script's own lines, not the rows the window shows
// for it (heading and SHA-256 line included).
func TestMacScrollHintCount(t *testing.T) {
	for name, want := range map[string]string{"long-lines": "Scroll to read all 13 lines", "tall-script": "Scroll to read all 40 lines"} {
		for _, c := range shotCases {
			if c.name == name {
				if got := macArgs(c.view())[13]; got != want {
					t.Errorf("%s: %q, want %q", name, got, want)
				}
			}
		}
	}
}

// A keyboard-only person can read a long script to its end: the script
// has the focus when the panel opens (Tab: script, Deny, Allow once),
// shows a focus ring, and the arrows, Page Up/Down, Home/End and Space scroll it. Return
// and Esc stay Deny, and the gate is the same seenEnd (C209).
func TestMacPanelKeyboardScroll(t *testing.T) {
	s := macAlertScript
	for _, want := range []string{
		"'acceptsFirstResponder': { types: ['bool', []], implementation: function () { return SCROLLS; } }",
		"'becomeFirstResponder': { types: ['bool', []], implementation: function () { try { showFocus('script'); note('script area has focus'); } catch (x) { note('error in becomeFirstResponder: ' + x); } return true; } }",
		"'resignFirstResponder': { types: ['bool', []], implementation: function () { try { showFocus(''); note('script area lost focus'); } catch (x) { note('error in resignFirstResponder: ' + x); } return true; } }",
		"function keyScroll(code, y, line, page, maxY) {",
		"code === 126 ? y - line", "code === 125 ? y + line", "code === 116 ? y - page",
		"code === 121 || code === 49 ? y + page", "code === 115 ? 0", "code === 119 ? maxY",
		"CLIP.scrollToPoint($.NSMakePoint(0, to))", "SV.reflectScrolledClipView(CLIP)",
		"b.borderColor = $.NSColor.keyboardFocusIndicatorColor;",
		"SCROLLS = scroll", "if (scroll && real(DOC)) panel.initialFirstResponder = DOC;",
		"DOC.setAccessibilityElement(true)", "DOC.setAccessibilityRole($.NSAccessibilityGroupRole)", "DOC.setAccessibilityLabel(",
		"deny.keyEquivalent = '\\r'", "code === 53 || code === 36",
		"if (seenEnd(r.origin.y, r.size.height, DOC.frame.size.height)) { SEEN = true; ALLOW_BTN.enabled = true; note('read to the end'); }",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	// Return (36), Tab (48) and Esc (53) are never taken by the script area
	k := s[strings.Index(s, "function keyScroll("):]
	k = k[:strings.Index(k, "\n}")]
	for _, code := range []string{"36", "48", "53", "76"} {
		if strings.Contains(k, "=== "+code) {
			t.Errorf("keyScroll handles key %s", code)
		}
	}
	// the gate's only way to turn Allow on is the bounds observer
	if strings.Count(s, "ALLOW_BTN.enabled = true") != 1 {
		t.Error("Allow is enabled somewhere other than the scroll observer")
	}
}

// The script scrolls with Up, Down, Page Up/Down and Home/End whatever
// has the focus (Tab may have put it on a button), and with Space only
// while the script has it; Return, Enter, Tab and Esc are never scroll
// keys (C237, approval_keys_test.go).
func TestMacPanelScrollKeysAnyFocus(t *testing.T) {
	s := macAlertScript
	on := macFunc(t, "onKey")
	if !strings.Contains(on, onKeyScroll) {
		t.Errorf("onKey has no %q", onKeyScroll)
	}
	keys := s[strings.Index(s, "var SCROLL_KEYS"):]
	keys = keys[:strings.Index(keys, "\n")]
	if keys != "var SCROLL_KEYS = [126, 125, 116, 121, 115, 119];" {
		t.Errorf("the scroll keys are %s", keys)
	}
	for _, bad := range []string{"36", "76", "48", "49", "53"} {
		if strings.Contains(keys, bad) {
			t.Errorf("key %s scrolls whatever has focus", bad)
		}
	}
}

// A wrapped row of a numbered script line hangs under the text, not under
// the line number, so it cannot pass for a line of its own (C215).
func TestMacPanelHangingIndent(t *testing.T) {
	s := macAlertScript
	for _, want := range []string{
		"function hanging(text, font) {", "$.NSMutableAttributedString.new",
		"replaceCharactersInRangeWithString($.NSMakeRange(0, 0), text)",
		"addAttributeValueRange($.NSFontAttributeName, font, $.NSMakeRange(0, text.length))",
		"$.NSMutableParagraphStyle.new", "ps.headIndent = m[0].length * cw",
		"addAttributeValueRange($.NSParagraphStyleAttributeName, ps, $.NSMakeRange(at, ln.length))",
		"/^ *\\d+  /", "font.maximumAdvancement.width",
		"if (!copy) l.attributedStringValue = hanging(text, font);",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	// the hanging text is set before the label is measured
	if a, m := strings.Index(s, "l.attributedStringValue = hanging("), strings.Index(s, "cellSizeForBounds"); a < 0 || m < a {
		t.Error("the label is measured before the hanging indent is set")
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
		{"deny button", "'deny:': { types: ['void', ['id']], implementation: function (s) { if (DEBUG) note('end: Deny, ' + how()); CHOICE = 'Deny'; CHOSEN = true; APP.stopModalWithCode(DENY); } }"},
		{"allow button", "'allow:': { types: ['void', ['id']], implementation: function (s) { if (DEBUG) note((SEEN ? 'end: Allow once, ' : 'Allow once ignored: not read to the end, ') + how()); if (!SEEN) return; CHOICE = 'Allow'; CHOSEN = true; APP.stopModalWithCode(ALLOW); } }"},
		{"close button", "'windowWillClose:': { types: ['void', ['id']], implementation: function (n) { if (DEBUG) note('end: window closes, ' + how()); if (!CHOSEN) { CHOICE = 'Deny'; CHOSEN = true; } APP.stopModalWithCode(DENY); } }"},
		{"close wired", "panel.delegate = answer"},
		{"closable", "$.NSWindowStyleMaskTitled | $.NSWindowStyleMaskClosable"},
		{"esc, return and cmd-w", onKeyDeny},
		{"give-up timer", "timerWithTimeIntervalRepeatsBlock(120, false, function () { note('end: no answer in 120 s'); CHOICE = 'gave up'; CHOSEN = true; app.stopModalWithCode(GAVE_UP); })"},
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
		"buttonWithTitleTargetAction(argv[7], answer, 'deny:')", "'deny:': { types: ['void', ['id']], implementation: function (s) { if (DEBUG) note('end: Deny, ' + how()); CHOICE = 'Deny'; CHOSEN = true; APP.stopModalWithCode(DENY); } }",
		"buttonWithTitleTargetAction(argv[8], answer, 'allow:')", "'allow:': { types: ['void', ['id']], implementation: function (s) { if (DEBUG) note((SEEN ? 'end: Allow once, ' : 'Allow once ignored: not read to the end, ') + how()); if (!SEEN) return; CHOICE = 'Allow'; CHOSEN = true; APP.stopModalWithCode(ALLOW); } }",
		"try { app.runModalForWindow(panel); } catch (x) { note('error: the modal loop threw ' + x); throw x; }",
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
		"implementation: function (s) { if (DEBUG) note('end: Deny, ' + how()); CHOICE = 'Deny'; CHOSEN = true; APP.stopModalWithCode(DENY); }",
		"implementation: function (s) { if (DEBUG) note((SEEN ? 'end: Allow once, ' : 'Allow once ignored: not read to the end, ') + how()); if (!SEEN) return; CHOICE = 'Allow'; CHOSEN = true; APP.stopModalWithCode(ALLOW); }",
		"implementation: function (n) { if (DEBUG) note('end: window closes, ' + how()); if (!CHOSEN) { CHOICE = 'Deny'; CHOSEN = true; } APP.stopModalWithCode(DENY); }",
		"function () { note('end: no answer in 120 s'); CHOICE = 'gave up'; CHOSEN = true; app.stopModalWithCode(GAVE_UP); }",
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
		"label(argv[2], $.NSFont.systemFontOfSize(fs), w, true)", "label(argv[5], mono, bw, false)"} {
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

// C189: the macOS window's 120-second timer stops before the owner check
// (Touch ID or the password) starts, so it cannot end that check's run
// loop as "gave up" while the person is still proving who they are.
func TestMacAlertTimerStopsBeforeOwnerCheck(t *testing.T) {
	stop := strings.Index(macAlertScript, "t.invalidate")
	call := strings.LastIndex(macAlertScript, "owner(")
	def := strings.Index(macAlertScript, "function owner(")
	if stop < 0 || call < 0 || call == def+len("function ") {
		t.Fatalf("script: timer stop at %d, owner call at %d", stop, call)
	}
	if stop > call {
		t.Errorf("the timer stops (at %d) after the owner check is called (at %d)", stop, call)
	}
}

// TestRiskWordsTriggerCoversRule: the trigger shown names what the rule
// really catches, not one command of several (C194 L7).
func TestRiskWordsTriggerCoversRule(t *testing.T) {
	for r, want := range map[string]string{
		"[power] powers off or reboots the server":                                    "Powers off or reboots the server (shutdown or reboot)",
		"[win-power] powers off or restarts the server":                               "Powers off or restarts the server (Stop-Computer or shutdown)",
		"[win-remote-access] stops remote access (SSH or WinRM), which locks you out": "Stops remote access (SSH or WinRM), which locks you out (stopping sshd or WinRM)",
	} {
		if got := riskWords(r, "en"); len(got) != 1 || got[0] != want {
			t.Errorf("riskWords(%q) = %q, want %q", r, got, want)
		}
	}
}
