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
	"unicode/utf16"
	"unicode/utf8"

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
func TestMacAlertScript(t *testing.T) {
	for _, want := range []string{
		"addButtonWithTitle('Deny')", "deny.keyEquivalent = '\\r'", "allow.keyEquivalent = ''",
		"e.keyCode === 53", "stopModalWithCode($.NSAlertFirstButtonReturn)",
		"timerWithTimeIntervalRepeatsBlock(120,", "app.abortModal", "return 'gave up'",
		"a.messageText = argv[1]", "a.informativeText = argv[2]", "tv.string = argv[3]", "label(argv[4],", "Number(argv[5])", "tv.editable = false",
		"ObjC.import('LocalAuthentication')", "canEvaluatePolicyError(2, null)", "evaluatePolicyLocalizedReasonReply(2, reason,",
		"if (r === $.NSAlertSecondButtonReturn) return 'Allow once\\n' + owner(argv[8], argv[9]);",
		"dateWithTimeIntervalSinceNow(Number(secs) || 1)", "until.timeIntervalSinceNow > 0", "return 'owner timeout'",
		"symbol('lock.shield', 48)", "allow.attributedTitle = m;", "$.NSMutableAttributedString.new", "if (argv[11] === '1') {", "sv.hasHorizontalScroller = false",
		"tv.horizontallyResizable = false", "argv[10].split(", "label(argv[12], bold", "symbol('exclamationmark.triangle', fs)", "$.NSColor.systemRedColor",
		"$.NSUnderlineStyleAttributeName, 1, rr", "argv[7].split(',')", "quaternarySystemFillColor", "kind === '2' ? $.NSColor.systemRedColor", "imageNamed('NSCaution')",
	} {
		if !strings.Contains(macAlertScript, want) {
			t.Errorf("script has no %q", want)
		}
	}
	if macWindowTimeout.Minutes() != 3 || windowGiveUp.Seconds() != 120 {
		t.Errorf("timeouts %v, %v", macWindowTimeout, windowGiveUp)
	}
	// semantic colours only, so dark mode works
	for _, c := range regexp.MustCompile(`NSColor\.(\w+)`).FindAllStringSubmatch(macAlertScript, -1) {
		if !slices.Contains([]string{"labelColor", "secondaryLabelColor", "systemRedColor", "controlBackgroundColor", "quaternarySystemFillColor"}, c[1]) {
			t.Errorf("the script uses NSColor.%s, not a semantic colour", c[1])
		}
	}
	for _, bad := range []string{"NSAttributedString.alloc", "NSMutableAttributedString.alloc", "findHighlightColor", "NSBackgroundColorAttributeName", "hasDestructiveAction"} {
		if strings.Contains(macAlertScript, bad) {
			t.Errorf("the script uses %s", bad)
		}
	}
	if strings.Contains(macAlertScript, "argv[0]") {
		t.Error("the script reads argv[0], the marker")
	}
	// a text that looks like an osascript option stays a text after the marker
	v := approvalView{raw: "-e do shell script \"id\""}
	args := macArgs(v)
	if args[0] != "-l" || args[1] != "JavaScript" || args[2] != "-e" || args[3] != macAlertScript || args[4] != macArgMarker || args[5] != "komando: allow?" || args[6] != "" || args[7] != v.raw {
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
		b.WriteString("[sizes]\n")
		b.WriteString("mac box " + macArgs(v)[9] + ", windows " + strconv.Itoa(l.titleH) + "/" + strconv.Itoa(l.subH) + "/" + strconv.Itoa(l.cmdH) + "/" + strconv.Itoa(l.notesH) + "/" + strconv.Itoa(l.height) + "\n\n")
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
// title, the target or a Risk line), and keeps the other reasons as risks.
func TestApprovalViewDedupes(t *testing.T) {
	why := []string{protWhy([]string{"web-1.example.test"}), "it runs on web-1.example.test (protected), web-2.example.test",
		"it runs on web-2.example.test, db-1.example.test", "[rm-system-dir] deletes a system folder recursively"}
	v := newApprovalView(tcl, []string{"--allow-dangerous", "--yes"}, "", why, "komando exec web -- id", "")
	want := "Target   web-1.example.test, web-2.example.test, db-1.example.test\n         [Protected]\nRisk     (!) Deletes a system folder recursively (rm -rf)\nSkips    the dangerous-command stop, the protected-server stop"
	if got := v.header(); got != want {
		t.Errorf("header:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(v.title(), "protected") || strings.Count(v.title()+"\n"+v.header(), "Protected") != 1 {
		t.Errorf("protected is named more than once:\n%s", v.layout())
	}
	if v.notes() != "" || v.title() != "Run a command on 3 servers" {
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
	if v := shotView(); v.moreHint() != "" || v.boxRows() > boxMaxLines {
		t.Errorf("the 4-line sample scrolls: %d rows, hint %q", v.boxRows(), v.moreHint())
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
	if i < boxMaxLines || !strings.Contains(strings.Split(v.boxText(), "\n")[i], "of=/dev/sda") {
		t.Fatalf("risky line %d", i)
	}
	off, n := v.riskyRange()
	if got := string(utf16.Decode(utf16.Encode([]rune(v.boxText()))[off : off+n])); !strings.Contains(got, "of=/dev/sda") {
		t.Errorf("range %d,%d is %q", off, n, got)
	}
	if args := macArgs(v); args[10] != strconv.Itoa(off) || args[11] != v.dangerArg() || !strings.Contains(args[11], ":") {
		t.Errorf("argv %q", args[9:])
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
// number; nothing of the command is lost.
func TestApprovalBoxWraps(t *testing.T) {
	long := "komando exec web-1.example.test -- " + strings.Repeat("echo abcdefghij && ", 20) + "true"
	views := []approvalView{testView("Codex", nil, "", nil, long, "It also sends the script ./a.sh (1 bytes, 1 lines, SHA-256 ab), all of it:\n\n   1  "+long+"\n")}
	for _, c := range shotCases {
		views = append(views, c.view())
	}
	for _, v := range views {
		rows, _ := v.box()
		for _, r := range rows {
			if utf8.RuneCountInString(r) > boxCols {
				t.Errorf("row of %d characters: %q", utf8.RuneCountInString(r), r)
			}
		}
		if strings.Join(strings.Fields(v.boxText()), "") != strings.Join(strings.Fields(v.command()), "") {
			t.Errorf("wrapping lost text:\n%s", v.boxText())
		}
	}
	rows, start := views[0].box()
	if strings.Contains(rows[1], "komando") || !strings.HasPrefix(rows[1], "    ") {
		t.Errorf("command continuation row %q", rows[1])
	}
	n := start[len(start)-1]
	if !strings.HasPrefix(rows[n], "   1  komando") || !strings.HasPrefix(rows[n+1], "      ") || strings.HasPrefix(rows[n+1], "       ") {
		t.Errorf("script rows %q / %q", rows[n], rows[n+1])
	}
	if !strings.Contains(macAlertScript, "hasHorizontalScroller = false") {
		t.Error("the macOS box may scroll sideways")
	}
}

// "Allow once" is dangerous (red) exactly when a risk line shows, and
// the script gets that as argv[11].
func TestApprovalDestructiveButton(t *testing.T) {
	for _, c := range shotCases {
		v := c.view()
		want := strings.Contains(v.header(), "(!)")
		if v.destructive() != want || (macArgs(v)[15] == "1") != want {
			t.Errorf("%s: destructive %v, argv %q, want %v", c.name, v.destructive(), macArgs(v)[15], want)
		}
	}
	if (approvalView{raw: "t"}).destructive() {
		t.Error("a plain text is dangerous")
	}
}

// Wrapping breaks after a space, a comma or a slash, and splits a token
// only when it is longer than a whole row.
func TestWrapLineBreaks(t *testing.T) {
	l := "komando exec web-1.example.test,web-2.example.test,db-2.example.test,203.0.113.10 --yes -- systemctl reload nginx"
	rows := wrapLine(l, boxCols)
	if !strings.HasSuffix(rows[0], ",") || !strings.HasPrefix(strings.TrimSpace(rows[1]), "203.0.113.10") {
		t.Errorf("rows %q", rows)
	}
	long := strings.Repeat("x", 100)
	if rows := wrapLine("echo "+long, boxCols); len(rows) != 3 || rows[0] != "echo" || utf8.RuneCountInString(rows[1]) != boxCols {
		t.Errorf("a token past the width: %q", rows)
	}
	if rows := wrapLine("cat /srv/app/"+strings.Repeat("dir/", 20)+"file", boxCols); !strings.HasSuffix(rows[0], "/") {
		t.Errorf("path rows %q", rows)
	}
}

// Only the dangerous commands are marked, at their place in the box; a
// script body gets a short caption; the title names the action.
func TestApprovalDangerAndCaption(t *testing.T) {
	var d approvalView
	for _, c := range shotCases {
		if c.name == "destructive" {
			d = c.view()
		}
	}
	u := utf16.Encode([]rune(d.boxText()))
	var got []string
	for _, r := range d.dangerRanges() {
		got = append(got, string(utf16.Decode(u[r[0]:r[0]+r[1]])))
	}
	if !slices.Equal(got, []string{"rm -rf", "DROP DATABASE"}) {
		t.Errorf("danger %q in\n%s", got, d.boxText())
	}
	if d.title() != "Run a command on db-2.example.test" || strings.Contains(d.header(), "Target") {
		t.Errorf("title %q, grid\n%s", d.title(), d.header())
	}
	cmd := shotView().command()
	if !strings.Contains(cmd, "\n\nScript ./deploy.sh · 4 lines · sha256 9f2c…\n") || strings.Contains(cmd, "It also sends") {
		t.Errorf("caption:\n%s", cmd)
	}
	if r := (approvalView{raw: "x", Owner: "komando: show secret:db"}); r.title() != "Show secret:db" {
		t.Errorf("reveal title %q", r.title())
	}
}

// A protected single target, named in the title, keeps its Protected
// badge on its own Status row in the macOS argv; the script builds no
// attributed string with an init method (not bridged in JXA).
func TestMacProtectedBadge(t *testing.T) {
	v := testView("Codex", []string{"--yes"}, "", []string{"it runs on db-2.example.test (protected)"}, "komando exec db-2.example.test --yes -- id", "")
	if got := macArgs(v)[14]; !strings.HasPrefix(got, "1\tStatus\tProtected\n") {
		t.Errorf("grid argv %q", got)
	}
	if regexp.MustCompile(`(NSAttributedString|NSMutableAttributedString)\.alloc\.initWith`).MatchString(macAlertScript) {
		t.Error("the script builds an attributed string with alloc.initWith")
	}
}
