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
	"unicode/utf16"

	"github.com/sgnd/komando/internal/policy"
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
	raw         string   // a window with no parts: the text as it came
}

func newApprovalView(cl *call, flags []string, what string, why []string, line, body string) approvalView {
	v := approvalView{Agent: cl.caller().Agent, Head: "wants komando to run", Line: line, Body: body, Flags: flags}
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

// title is the window's first, bold line.
func (v approvalView) title() string {
	switch {
	case v.raw != "":
		return "komando: allow?"
	case len(v.Targets) > 0:
		return v.Agent + " wants to change " + strings.Join(v.Targets, ", ")
	}
	return v.Agent + " " + v.Head
}

// header is the labelled lines above the command: where, how risky, why.
func (v approvalView) header() string {
	if v.raw != "" {
		return ""
	}
	var b []string
	if len(v.Targets) > 0 {
		b = append(b, "Target: "+strings.Join(v.Targets, ", "))
	}
	if v.Protected {
		b = append(b, "Protected: yes")
	}
	for _, r := range v.Risks {
		b = append(b, "Risk: "+r)
	}
	if len(v.Flags) > 0 {
		b = append(b, "Skips: "+strings.Join(v.Flags, ", "))
	}
	return strings.Join(b, "\n")
}

// command is the monospace box: the command line, then the body.
func (v approvalView) command() string {
	if v.raw != "" {
		return strings.TrimRight(v.raw, "\n")
	}
	if v.Body == "" {
		return v.Line
	}
	return v.Line + "\n\n" + strings.TrimRight(v.Body, "\n")
}

// boxMaxLines is how many lines the command box shows before it scrolls,
// on macOS and Windows alike.
const boxMaxLines = 15

// moreHint is the line under a box that scrolls, or "".
func (v approvalView) moreHint() string {
	if n := lineCount(v.command()) - boxMaxLines; n > 0 {
		return fmt.Sprintf("%d more lines: scroll to read all", n)
	}
	return ""
}

// riskyLine is the first line of the box that a deny rule matches (the
// check that rated the command), or -1. The box opens scrolled to it.
func (v approvalView) riskyLine() int {
	for i, l := range strings.Split(v.command(), "\n") {
		if len(policy.Check(l, nil)) > 0 {
			return i
		}
	}
	return -1
}

// riskyRange is riskyLine as a UTF-16 offset and length into command(),
// as AppKit counts; -1, 0 for none.
func (v approvalView) riskyRange() (off, n int) {
	i := v.riskyLine()
	if i < 0 {
		return -1, 0
	}
	lines := strings.Split(v.command(), "\n")
	for _, l := range lines[:i] {
		off += len(utf16.Encode([]rune(l))) + 1
	}
	return off, len(utf16.Encode([]rune(lines[i])))
}

// notes is the explanation under the box, the question last.
func (v approvalView) notes() string {
	if v.raw != "" {
		return v.moreHint()
	}
	var b []string
	if h := v.moreHint(); h != "" {
		b = append(b, h)
	}
	if v.What != "" {
		b = append(b, "This also lets through: "+v.What)
	}
	if f := v.flagLines(); f != "" {
		b = append(b, f)
	}
	return strings.Join(append(b, "Allow this once?"), "\n\n")
}

// layout is the window's content as plain text, for the golden test.
func (v approvalView) layout() string {
	s := "[title]\n" + v.title() + "\n[header]\n" + v.header() + "\n[command]\n" + v.command() + "\n"
	return s + "[owner]\n" + v.ownerReason() + "\n[notes]\n" + v.notes() + "\n[risky line]\n" + strconv.Itoa(v.riskyLine()) + "\n"
}

// lineCount is how many lines s has (the command box does not wrap).
func lineCount(s string) int { return strings.Count(s, "\n") + 1 }

// commandRows is how many rows s takes, wrapped at cols.
func commandRows(s string, cols int) int {
	n := 0
	for l := range strings.SplitSeq(s, "\n") {
		n += max(1, (utf8.RuneCountInString(l)+cols-1)/cols)
	}
	return n
}

// viewFor is the window content for text: the view this call built for
// it, or the text alone.
func viewFor(cl *call, text string) approvalView {
	if cl != nil && cl.view != nil && cl.view.text() == text {
		return *cl.view
	}
	return approvalView{raw: text}
}

// macAlertScript draws the macOS window (JXA, AppKit's NSAlert). Every
// text arrives in argv after macArgMarker, never in the script. Deny is
// the default (Return) and Esc; after 120 seconds it closes as "gave up".
// After "Allow once" the same run asks LocalAuthentication for the device
// owner (policy 2: Touch ID, a watch or the login password) with argv[8]
// as the reason, waiting no longer than the window's 120 seconds; it
// prints "owner ok" on the next line only when the reply says ok.
const macAlertScript = `ObjC.import('AppKit');
ObjC.import('LocalAuthentication');
function owner(reason, until) {
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
function run(argv) {
  var until = $.NSDate.dateWithTimeIntervalSinceNow(120);
  var app = $.NSApplication.sharedApplication;
  app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
  var a = $.NSAlert.alloc.init;
  a.alertStyle = $.NSAlertStyleCritical;
  a.messageText = argv[1];
  a.informativeText = argv[2];
  var deny = a.addButtonWithTitle('Deny');
  deny.keyEquivalent = '\r';
  var allow = a.addButtonWithTitle('Allow once');
  allow.keyEquivalent = '';
  var w = 600, h = Number(argv[5]) || 120;
  var sv = $.NSScrollView.alloc.initWithFrame($.NSMakeRect(0, 0, w, h));
  sv.hasVerticalScroller = true;
  sv.hasHorizontalScroller = true;
  sv.borderType = $.NSBezelBorder;
  var tv = $.NSTextView.alloc.initWithFrame($.NSMakeRect(0, 0, w, h));
  tv.editable = false;
  tv.selectable = true;
  tv.richText = false;
  var fs = $.NSFont.smallSystemFontSize, mf = null;
  try { mf = $.NSFont.monospacedSystemFontOfSizeWeight(fs, 0); } catch (e) {}
  tv.font = (mf && !mf.isNil()) ? mf : $.NSFont.userFixedPitchFontOfSize(fs);
  tv.textContainerInset = $.NSMakeSize(6, 6);
  tv.horizontallyResizable = true;
  tv.maxSize = $.NSMakeSize(1e7, 1e7);
  tv.textContainer.widthTracksTextView = false;
  tv.textContainer.containerSize = $.NSMakeSize(1e7, 1e7);
  tv.string = argv[3];
  sv.documentView = tv;
  var ro = Number(argv[6]), rn = Number(argv[7]);
  if (ro >= 0) {
    var rr = $.NSMakeRange(ro, rn);
    tv.textStorage.addAttributeValueRange($.NSBackgroundColorAttributeName, $.NSColor.findHighlightColor, rr);
    tv.scrollRangeToVisible(rr);
  }
  var note = $.NSTextField.wrappingLabelWithString(argv[4]);
  note.preferredMaxLayoutWidth = w;
  var nh = argv[4] === '' ? 0 : Math.ceil(note.cell.cellSizeForBounds($.NSMakeRect(0, 0, w, 1e5)).height);
  var under = nh ? nh + 12 : 0;
  var box = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, w, h + under));
  sv.frame = $.NSMakeRect(0, under, w, h);
  note.frame = $.NSMakeRect(0, 0, w, nh);
  box.addSubview(sv);
  if (nh) box.addSubview(note);
  a.accessoryView = box;
  a.layout;
  a.window.level = $.NSFloatingWindowLevel;
  var esc = $.NSEvent.addLocalMonitorForEventsMatchingMaskHandler($.NSEventMaskKeyDown, function (e) {
    if (e.keyCode === 53) { app.stopModalWithCode($.NSAlertFirstButtonReturn); return null; }
    return e;
  });
  var t = $.NSTimer.timerWithTimeIntervalRepeatsBlock(120, false, function () { app.abortModal; });
  $.NSRunLoop.currentRunLoop.addTimerForMode(t, $.NSRunLoopCommonModes);
  app.activateIgnoringOtherApps(true);
  var r = a.runModal;
  t.invalidate;
  $.NSEvent.removeMonitor(esc);
  if (r === $.NSAlertSecondButtonReturn) return 'Allow once\n' + owner(argv[8], until);
  if (r === $.NSAlertFirstButtonReturn) return 'Deny';
  return 'gave up';
}`

// macArgMarker is the first argument after every osascript script, so a
// text (which may start with "-e") is never the first one.
const macArgMarker = "komando"

// appleScriptArgs is osascript's command line for an AppleScript that
// reads its texts from item 2 of argv on.
func appleScriptArgs(script string, texts ...string) []string {
	return append([]string{"-e", script, macArgMarker}, texts...)
}

// ownerReason is what the macOS Touch ID or password prompt says komando
// asks for: the targets, or the command line when there are none.
func (v approvalView) ownerReason() string {
	what := strings.Join(v.Targets, ", ")
	if what == "" {
		what = v.Line
	}
	if what == "" || utf8.RuneCountInString(what) > 120 {
		what = "this command"
	}
	return "komando: allow " + what
}

// macArgs is osascript's command line: the script, then argv.
func macArgs(v approvalView) []string {
	rows := min(lineCount(v.command()), boxMaxLines)
	off, n := v.riskyRange()
	// 15 px a row, 12 for the insets, 16 for the sideways scroller
	return []string{"-l", "JavaScript", "-e", macAlertScript, macArgMarker, v.title(), v.header(), v.command(), v.notes(), strconv.Itoa(rows*15 + 28), strconv.Itoa(off), strconv.Itoa(n), v.ownerReason()}
}

// macOutcome is how the macOS window ended.
type macOutcome int

const (
	macDenied      macOutcome = iota // Deny, Esc, an error or anything unexpected
	macAllowed                       // Allow once, then the device owner confirmed
	macOwnerFailed                   // Allow once, but the owner check did not say ok
	macGaveUp                        // nobody answered in 120 seconds
)

// macAnswer reads what osascript printed. Only "Allow once" followed by
// "owner ok" allows; every other answer, an error included, is a no.
func macAnswer(out []byte) macOutcome {
	switch strings.TrimSuffix(string(out), "\n") {
	case "Allow once\nowner ok":
		return macAllowed
	case "gave up":
		return macGaveUp
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

// The Windows window's size, in pixels: 16 px rows of the GUI font and of
// Consolas; the command box shows up to 15 lines, then scrolls (also sideways).
const (
	winW, winPad = 680, 12
	winInner     = winW - 2*winPad - 16 // 16: the window's side borders
	winRowH      = 16
	winTextCols  = 80 // GUI-font characters on a row, kept low so wrapped text is never cut
	winHScrollH  = 17
)

type winLayout struct{ headH, cmdH, notesH, height int }

func winLayoutFor(v approvalView) winLayout {
	var l winLayout
	l.headH = commandRows(v.title()+"\n"+v.header(), winTextCols) * winRowH
	l.cmdH = min(lineCount(v.command()), boxMaxLines)*winRowH + 8 + winHScrollH
	if n := v.notes(); n != "" {
		l.notesH = commandRows(n, winTextCols) * winRowH
	}
	l.height = winPad + l.headH + winPad + l.cmdH + winPad
	if l.notesH > 0 {
		l.height += l.notesH + winPad
	}
	return l
}
