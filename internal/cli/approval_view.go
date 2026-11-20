package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"regexp"
	"unicode/utf8"
)

// approvalView is the approval window's content, built in one place
// (newApprovalView); the platform code only draws it. text is what the
// window held before it had parts, and stays the key of the request.
type approvalView struct {
	Agent, Head string   // "Claude Code", "wants to change web"
	Line, Body  string   // the command line; the body it sends, as shown
	What        string   // what the flag also lets through
	Reasons     []string // why komando asks, as text() words them
	Flags       []string
	Targets     []string // where it runs, each named once
	Protected   bool     // a target is protected (targetsWhy, protWhy)
	Risks       []string // the reasons left once targets and protection have their own lines
	Owner       string   // what the device-owner prompt names, when not the targets
	Lang        string   // en or id: the words komando writes (approval_language)
	raw         string   // a window with no parts: the text as it came
}

func newApprovalView(cl *call, flags []string, what string, why []string, line, body string) approvalView {
	v := approvalView{Agent: cl.caller().Agent, Head: "wants komando to run", Line: line, Body: body, Flags: flags, Lang: approvalLang(cl)}
	for _, w := range why {
		if w = strings.TrimSpace(w); w != "" {
			if unshowable(w) != "" {
				w = strconv.QuoteToASCII(w)
			}
			if on, ok := strings.CutPrefix(w, "it runs on "); ok {
				v.addTargets(on)
				if v.Head == "wants komando to run" {
					v.Head = "wants to change " + on
					continue
				}
			} else if _, ok := strings.CutPrefix(w, protChangePrefix); ok {
				v.Protected = true
			} else {
				v.Risks = append(v.Risks, w)
			}
			v.Reasons = append(v.Reasons, w)
		}
	}
	if what != "" && unshowable(what) != "" {
		what = strconv.QuoteToASCII(what)
	}
	v.What = what
	return v
}

// addTargets adds the names of a targetsWhy list, each once, without
// its protected mark (the Protected line says it).
func (v *approvalView) addTargets(list string) {
	for _, n := range strings.Split(list, ", ") {
		if bare, ok := strings.CutSuffix(n, protectedMark); ok {
			n, v.Protected = bare, true
		}
		if n != "" && !slices.Contains(v.Targets, n) {
			v.Targets = append(v.Targets, n)
		}
	}
}

// text is the whole request as one text (the key for noteGaveUp and the
// test hooks).
func (v approvalView) text() string {
	if v.raw != "" {
		return v.raw
	}
	text := fmt.Sprintf("%s %s:\n\n%s\n\n", v.Agent, v.Head, v.Line) + v.Body
	if v.What != "" {
		text += "This also lets through:\n\n" + v.What + "\n\n"
	}
	text += "Allow this once?\n\n"
	for _, w := range v.Reasons {
		text += "Why komando asks: " + w + "\n"
	}
	return text + v.flagLines()
}

func (v approvalView) flagLines() string {
	var b []string
	for _, f := range v.Flags {
		b = append(b, fmt.Sprintf("%s skips one of komando's safety stops (%s).", f, flagMeaning[f]))
	}
	return strings.Join(b, "\n")
}

// title is the window's first, bold line: the action in plain words.
func (v approvalView) title() string {
	w := wordsFor(v.Lang)
	if v.raw != "" {
		if what, ok := strings.CutPrefix(v.Owner, "komando: show "); ok {
			return w.show + what
		}
		return w.allowAny
	}
	verb := w.change
	switch {
	case strings.HasPrefix(v.Line, "komando exec "):
		verb = w.runOn
	case strings.HasPrefix(v.Line, "komando db query "):
		verb = w.queryOn
	}
	switch len(v.Targets) {
	case 0:
		return w.runKomando
	case 1:
		return verb + " " + v.Targets[0]
	}
	return verb + " " + strconv.Itoa(len(v.Targets)) + " " + w.servers
}

// bodyHead is the first line of a body that approval_body.go shows whole.
var bodyHead = regexp.MustCompile(`^It also sends (?:the )?(.+) \((\d+) bytes, (\d+) lines, SHA-256 ([0-9a-f]+)\)(?:, all of it:|\.)$`)

// layout is the window's content as plain text, for the golden test.
func (v approvalView) layout() string {
	return "[title]\n" + v.title() + "\n[text]\n" + v.details() + "\n[owner]\n" + v.ownerReason() + "\n"
}

// viewFor is the window content for text: the view this call built for
// it, or the text alone.
func viewFor(cl *call, text string) approvalView {
	if cl != nil && cl.view != nil && cl.view.text() == text {
		return *cl.view
	}
	if cl != nil && cl.view != nil {
		return approvalView{raw: text, Lang: cl.view.Lang}
	}
	return approvalView{raw: text, Lang: approvalLang(cl)}
}

// macAlertScript draws the macOS window: a plain NSPanel of standard
// AppKit controls (no icon, no colours), titled argv[6] ("komando needs
// your OK"):
// argv[1] as the bold first label, argv[2] (the info lines, selectable)
// under it, then argv[5] (what runs, not selectable), one label per group
// split at blank lines, 12 pt apart, 440 pt wide with 20 pt
// padding, then the buttons argv[7] (Deny) and argv[8] (Allow once) on
// the right. Whatever their labels, the script answers with the fixed
// tokens "Deny" and "Allow once" (macAnswer). Every text arrives in argv after
// macArgMarker, never in the script. Deny is the default (Return), Esc,
// the close button and Cmd-W, and has the first focus; only the 120 s
// timer prints "gave up", and any other end is a Deny. After
// "Allow once" the same run asks LocalAuthentication for the device owner
// (policy 2: Touch ID, an Apple Watch or the login password) with argv[3]
// as the reason, waiting at most argv[4] seconds of its own; it prints
// "owner ok" on the next line only when the reply says ok.
const macAlertScript = `ObjC.import('AppKit');
ObjC.import('LocalAuthentication');
function owner(reason, secs) {
  var until = $.NSDate.dateWithTimeIntervalSinceNow(Number(secs) || 1);
  var ctx = $.LAContext.alloc.init;
  if (!ctx.canEvaluatePolicyError(2, null)) return 'owner unavailable';
  var res = null;
  ctx.evaluatePolicyLocalizedReasonReply(2, reason, function (ok, err) { res = (ok === true || ok === 1) ? 'owner ok' : 'owner denied'; });
  while (res === null && until.timeIntervalSinceNow > 0) {
    $.NSRunLoop.currentRunLoop.runModeBeforeDate($.NSDefaultRunLoopMode, $.NSDate.dateWithTimeIntervalSinceNow(0.2));
  }
  if (res === null) { ctx.invalidate; return 'owner timeout'; }
  return res;
}
// $.NSApp is not the application in JXA: the actions use APP, set in run
var DENY = 1000, ALLOW = 1001, GAVE_UP = 1002, APP = null;
// the answer each path sets itself; a close after a choice keeps it
var CHOICE = 'Deny', CHOSEN = false;
ObjC.registerSubclass({
  name: 'KomandoAnswer',
  methods: {
    'deny:': { types: ['void', ['id']], implementation: function (s) { CHOICE = 'Deny'; CHOSEN = true; APP.stopModalWithCode(DENY); } },
    'allow:': { types: ['void', ['id']], implementation: function (s) { CHOICE = 'Allow'; CHOSEN = true; APP.stopModalWithCode(ALLOW); } },
    'windowWillClose:': { types: ['void', ['id']], implementation: function (n) { if (!CHOSEN) { CHOICE = 'Deny'; CHOSEN = true; } APP.stopModalWithCode(DENY); } }
  }
});
function label(text, font, w, copy) {
  var l = $.NSTextField.wrappingLabelWithString(text);
  l.font = font;
  // the command and script are not selectable: they show U+2011 so a
  // flag never breaks over a line, and a copy of them would not run as shown
  l.selectable = copy;
  l.preferredMaxLayoutWidth = w;
  return { v: l, h: Math.ceil(l.cell.cellSizeForBounds($.NSMakeRect(0, 0, w, 1e5)).height) };
}
function run(argv) {
  var app = $.NSApplication.sharedApplication;
  APP = app;
  app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
  var w = 440, pad = 20, gap = 12, fs = $.NSFont.systemFontSize;
  var parts = [label(argv[1], $.NSFont.boldSystemFontOfSize(fs), w, true)];
  if (argv[2] !== '') parts.push(label(argv[2], $.NSFont.systemFontOfSize(fs), w, true));
  argv[5].split('\n\n').forEach(function (g) { if (g !== '') parts.push(label(g, $.NSFont.systemFontOfSize(fs), w, false)); });
  var answer = $.KomandoAnswer.alloc.init;
  var deny = $.NSButton.buttonWithTitleTargetAction(argv[7], answer, 'deny:');
  deny.keyEquivalent = '\r';
  deny.setAccessibilityLabel(argv[7]);
  var allow = $.NSButton.buttonWithTitleTargetAction(argv[8], answer, 'allow:');
  allow.keyEquivalent = '';
  allow.setAccessibilityLabel(argv[8]);
  var bh = Math.ceil(deny.fittingSize.height), dw = Math.ceil(deny.fittingSize.width), aw = Math.ceil(allow.fittingSize.width);
  var h = pad + bh + pad;
  parts.forEach(function (p, i) { h += p.h + (i ? gap : 0); });
  h += pad;
  var panel = $.NSPanel.alloc.initWithContentRectStyleMaskBackingDefer($.NSMakeRect(0, 0, w + 2 * pad, h), $.NSWindowStyleMaskTitled | $.NSWindowStyleMaskClosable, $.NSBackingStoreBuffered, false);
  panel.title = argv[6];
  panel.delegate = answer;
  var view = panel.contentView, y = h - pad;
  parts.forEach(function (p, i) {
    if (i) y -= gap;
    y -= p.h;
    p.v.frame = $.NSMakeRect(pad, y, w, p.h);
    view.addSubview(p.v);
  });
  allow.frame = $.NSMakeRect(pad + w - aw, pad, aw, bh);
  deny.frame = $.NSMakeRect(pad + w - aw - 12 - dw, pad, dw, bh);
  view.addSubview(deny);
  view.addSubview(allow);
  deny.nextKeyView = allow;
  allow.nextKeyView = deny;
  panel.initialFirstResponder = deny;
  panel.level = $.NSFloatingWindowLevel;
  panel.center;
  var esc = $.NSEvent.addLocalMonitorForEventsMatchingMaskHandler($.NSEventMaskKeyDown, function (e) {
    if (Number(e.keyCode) === 53) { CHOICE = 'Deny'; CHOSEN = true; app.stopModalWithCode(DENY); return null; }
    if (Number(e.keyCode) === 13 && (Number(e.modifierFlags) & $.NSEventModifierFlagCommand)) { CHOICE = 'Deny'; CHOSEN = true; app.stopModalWithCode(DENY); return null; }
    return e;
  });
  var t = $.NSTimer.timerWithTimeIntervalRepeatsBlock(120, false, function () { CHOICE = 'gave up'; CHOSEN = true; app.stopModalWithCode(GAVE_UP); });
  $.NSRunLoop.currentRunLoop.addTimerForMode(t, $.NSRunLoopCommonModes);
  app.activateIgnoringOtherApps(true);
  panel.makeKeyAndOrderFront(null);
  app.runModalForWindow(panel); // the answer is CHOICE: JXA returns NSInteger as a string
  t.invalidate;
  $.NSEvent.removeMonitor(esc);
  panel.delegate = null;
  panel.orderOut(null);
  if (CHOICE === 'Allow') return 'Allow once\n' + owner(argv[3], argv[4]);
  if (CHOICE === 'gave up') return 'gave up';
  return 'Deny';
}`

// macArgMarker is the first argument after every osascript script, so a
// text (which may start with "-e") is never the first one.
const macArgMarker = "komando"

// appleScriptArgs is osascript's command line for an AppleScript that
// reads its texts from item 2 of argv on.
func appleScriptArgs(script string, texts ...string) []string {
	return append([]string{"-e", script, macArgMarker}, texts...)
}

// ownerReason is what the macOS device-owner prompt says komando asks
// for: Owner when set (a reveal), the targets, or the command line.
func (v approvalView) ownerReason() string {
	if v.Owner != "" {
		return v.Owner
	}
	w := wordsFor(v.Lang)
	what := strings.Join(v.Targets, ", ")
	if what == "" {
		what = v.Line
	}
	if what == "" || utf8.RuneCountInString(what) > 120 {
		what = w.thisCommand
	}
	return w.ownerAllow + what
}

// macArgs is osascript's command line: the script, then argv.
func macArgs(v approvalView) []string {
	w := wordsFor(v.Lang)
	return []string{"-l", "JavaScript", "-e", macAlertScript, macArgMarker, v.title(), v.info(), v.ownerReason(), strconv.Itoa(int(ownerTimeout.Seconds())), noBreakHyphens(v.shown()),
		w.panel, w.deny, w.allow}
}

// noBreakHyphens keeps "--yes" and "rm -rf" whole when a label wraps:
// AppKit may break a line after a hyphen, so each becomes U+2011, the
// non-breaking hyphen, which looks the same.
func noBreakHyphens(s string) string { return strings.ReplaceAll(s, "-", "\u2011") }

// macOutcome is how the macOS window ended.
type macOutcome int

const (
	macDenied       macOutcome = iota // Deny, Esc, an error or anything unexpected
	macAllowed                        // Allow once, then the device owner confirmed
	macOwnerFailed                    // Allow once, but the owner check did not say ok
	macOwnerTimeout                   // Allow once, then nobody confirmed in ownerTimeout
	macGaveUp                         // nobody answered in 120 seconds
)

// macAnswer reads what osascript printed. Only "Allow once" followed by
// "owner ok" allows; every other answer, an error included, is a no.
func macAnswer(out []byte) macOutcome {
	switch strings.TrimSuffix(string(out), "\n") {
	case "Allow once\nowner ok":
		return macAllowed
	case "gave up":
		return macGaveUp
	case "Allow once\nowner timeout":
		return macOwnerTimeout
	}
	if strings.HasPrefix(string(out), "Allow once\n") {
		return macOwnerFailed
	}
	return macDenied
}

// windowGiveUp is when the Windows window closes itself (the macOS one
// says 120 in macAlertScript); macWindowTimeout bounds osascript past it.
// Only the CI screenshot test shortens them.
var (
	windowGiveUp     = 120 * time.Second
	macWindowTimeout = 3 * time.Minute
)

// ownerTimeout bounds the device-owner check after "Allow once"; the
// window's 120 s plus this stay inside macWindowTimeout.
const ownerTimeout = 50 * time.Second

// askMac shows the macOS window. shown is false when osascript could not
// start; an error exit after it started (the script failed) is a no.
var askMac = func(v approvalView) (ans macOutcome, shown bool) {
	ctx, cancel := context.WithTimeout(context.Background(), macWindowTimeout)
	defer cancel()
	b, err := exec.CommandContext(ctx, "/usr/bin/osascript", macArgs(v)...).Output()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return macDenied, false
	}
	if err != nil {
		return macDenied, true
	}
	return macAnswer(b), true
}

// The Windows window's size, in pixels: a dialog of the system's own
// look (Segoe UI 9 pt, 16 px rows), the title in bold, the text under it.
const (
	winW, winPad = 480, 12              // 440 px of text, as the macOS window
	winInner     = winW - 2*winPad - 16 // 16: the window's side borders
	winRowH      = 16
	winTextCols  = 60 // characters on a row, kept low so wrapped text is never cut
)

type winLayout struct {
	titleH, textH, height int
	scroll                bool // the text is taller than the screen allows
}

// fit shrinks the text area so the window is at most maxH tall; the text
// then scrolls, every line still in the dialog.
func (l winLayout) fit(maxH int) winLayout {
	if over := l.height - maxH; over > 0 && l.textH-over >= 4*winRowH {
		l.textH -= over
		l.height -= over
		l.scroll = true
	}
	return l
}

func winLayoutFor(v approvalView) winLayout {
	var l winLayout
	l.titleH = textRows(v.title(), winTextCols-8)*winRowH + 4
	l.textH = textRows(v.details(), winTextCols) * winRowH
	l.height = winPad + l.titleH + winPad/2 + l.textH + winPad
	return l
}
