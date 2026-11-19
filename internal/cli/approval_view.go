package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// approvalView is the approval window's content, built in one place
// (newApprovalView); the platform code only draws it. text is what the
// window held before it had parts, and stays the key of the request.
type approvalView struct {
	Agent, Head string   // "Claude Code", "wants to change web"
	Target      string   // the servers it runs on, "" when not named
	Line, Body  string   // the command line; the body it sends, as shown
	What        string   // what the flag also lets through
	Reasons     []string // why komando asks: a protected target, a rule, a secret's destination
	Flags       []string
	raw         string // a window with no parts: the text as it came
}

func newApprovalView(cl *call, flags []string, what string, why []string, line, body string) approvalView {
	v := approvalView{Agent: cl.caller().Agent, Head: "wants komando to run", Line: line, Body: body, Flags: flags}
	for _, w := range why {
		if w = strings.TrimSpace(w); w != "" {
			if unshowable(w) != "" {
				w = strconv.QuoteToASCII(w)
			}
			if on, ok := strings.CutPrefix(w, "it runs on "); ok && v.Target == "" {
				v.Head, v.Target = "wants to change "+on, on
				continue
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
	if v.raw != "" {
		return "komando: allow?"
	}
	return v.Agent + " " + v.Head
}

// protected reports a protected target among the targets or the reasons.
func (v approvalView) protected() bool {
	if strings.Contains(v.Target, "(protected)") {
		return true
	}
	for _, r := range v.Reasons {
		if strings.HasPrefix(r, "a change on protected ") {
			return true
		}
	}
	return false
}

// header is the labelled lines above the command: where, how risky, why.
func (v approvalView) header() string {
	if v.raw != "" {
		return ""
	}
	var b strings.Builder
	if v.Target != "" {
		b.WriteString("Target: " + v.Target + "\n")
	}
	if v.protected() {
		b.WriteString("Protected: yes\n")
	}
	for _, r := range v.Reasons {
		b.WriteString("Risk: " + r + "\n")
	}
	if len(v.Flags) > 0 {
		b.WriteString("Skips: " + strings.Join(v.Flags, ", ") + "\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// command is the monospace block: the command line, then the body.
func (v approvalView) command() string {
	if v.raw != "" {
		return strings.TrimRight(v.raw, "\n")
	}
	if v.Body == "" {
		return v.Line
	}
	return v.Line + "\n\n" + strings.TrimRight(v.Body, "\n")
}

// notes is the explanation under the command.
func (v approvalView) notes() string {
	if v.raw != "" {
		return ""
	}
	s := ""
	if v.What != "" {
		s += "This also lets through: " + v.What + "\n\n"
	}
	s += "Allow this once?"
	if f := v.flagLines(); f != "" {
		s += "\n\n" + f
	}
	return s
}

// layout is the window's content as plain text, for the golden test.
func (v approvalView) layout() string {
	return "[title]\n" + v.title() + "\n[header]\n" + v.header() + "\n[command]\n" + v.command() + "\n[notes]\n" + v.notes() + "\n"
}

// commandRows is how many rows the command block takes, wrapped at cols.
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
const macAlertScript = `ObjC.import('AppKit');
function run(argv) {
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
  sv.borderType = $.NSBezelBorder;
  var tv = $.NSTextView.alloc.initWithFrame($.NSMakeRect(0, 0, w, h));
  tv.editable = false;
  tv.selectable = true;
  tv.richText = false;
  tv.font = $.NSFont.userFixedPitchFontOfSize(12);
  tv.textContainerInset = $.NSMakeSize(6, 6);
  tv.autoresizingMask = $.NSViewWidthSizable;
  tv.textContainer.widthTracksTextView = true;
  tv.string = argv[3];
  sv.documentView = tv;
  var note = $.NSTextField.wrappingLabelWithString(argv[4]);
  note.preferredMaxLayoutWidth = w;
  var nh = argv[4] === '' ? 0 : note.fittingSize.height;
  var box = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, w, h + (nh ? nh + 12 : 0)));
  sv.frame = $.NSMakeRect(0, nh ? nh + 12 : 0, w, h);
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
  if (r === $.NSAlertSecondButtonReturn) return 'Allow once';
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

// macArgs is osascript's command line: the script, then argv.
func macArgs(v approvalView) []string {
	rows := min(commandRows(v.command(), 80), 20)
	return []string{"-l", "JavaScript", "-e", macAlertScript, macArgMarker, v.title(), v.header(), v.command(), v.notes(), strconv.Itoa(rows*15 + 16)}
}

// macAnswer reads what osascript printed: only "Allow once" allows; every
// other answer, an error included, is a no. gaveUp: nobody answered.
func macAnswer(out []byte) (allowed, gaveUp bool) {
	a := strings.TrimSpace(string(out))
	return a == "Allow once", a == "gave up"
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
func askMac(v approvalView) (allowed, gaveUp, shown bool) {
	ctx, cancel := context.WithTimeout(context.Background(), macWindowTimeout)
	defer cancel()
	b, err := exec.CommandContext(ctx, "/usr/bin/osascript", macArgs(v)...).Output()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return false, false, false
	}
	allowed, gaveUp = macAnswer(b)
	return allowed, gaveUp, true
}

// The Windows window's size, in pixels: 16 px rows of the GUI font and of
// Consolas; the command block scrolls past 18 rows.
const (
	winW, winPad = 680, 12
	winInner     = winW - 2*winPad - 16 // 16: the window's side borders
	winRowH      = 16
	winCols      = 78 // Consolas characters on one row of the command block
	winTextCols  = 100
)

type winLayout struct{ headH, cmdH, notesH, height int }

func winLayoutFor(v approvalView) winLayout {
	var l winLayout
	l.headH = commandRows(v.title()+"\n"+v.header(), winTextCols) * winRowH
	l.cmdH = min(commandRows(v.command(), winCols), 18)*winRowH + 8
	if n := v.notes(); n != "" {
		l.notesH = commandRows(n, winTextCols) * winRowH
	}
	l.height = winPad + l.headH + winPad + l.cmdH + winPad
	if l.notesH > 0 {
		l.height += l.notesH + winPad
	}
	return l
}

// crlf is s with Windows line ends, which an edit control needs.
func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}
