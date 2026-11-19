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

// title is the window's first, bold line: the action in plain words.
func (v approvalView) title() string {
	if v.raw != "" {
		if what, ok := strings.CutPrefix(v.Owner, "komando: show "); ok {
			return "Show " + what
		}
		return "komando: allow?"
	}
	verb := "Change"
	switch {
	case strings.HasPrefix(v.Line, "komando exec "):
		verb = "Run a command on"
	case strings.HasPrefix(v.Line, "komando db query "):
		verb = "Run a query on"
	}
	switch len(v.Targets) {
	case 0:
		return "Run a komando command"
	case 1:
		return verb + " " + v.Targets[0]
	}
	return verb + " " + strconv.Itoa(len(v.Targets)) + " servers"
}

// subtitle is the secondary line under the title: who asks.
func (v approvalView) subtitle() string {
	if v.raw != "" || v.Agent == "" {
		return ""
	}
	return "Asked by " + v.Agent
}

// question is the window's last line, above the buttons.
const question = "Allow this once?"

// command is the command line, then the body, as sent; a body's
// "It also sends ..." line shows as a short caption.
func (v approvalView) command() string {
	if v.raw != "" {
		return strings.TrimRight(v.raw, "\n")
	}
	if v.Body == "" {
		return v.Line
	}
	body := strings.TrimRight(v.Body, "\n")
	if first, rest, _ := strings.Cut(body, "\n"); bodyHead.MatchString(first) {
		m := bodyHead.FindStringSubmatch(first)
		body = capitalise(m[1]) + " · " + m[3] + " lines · sha256 " + m[4][:min(8, len(m[4]))] + "…\n" + rest
	}
	return v.Line + "\n\n" + body
}

// bodyHead is the first line of a body that approval_body.go shows whole.
var bodyHead = regexp.MustCompile(`^It also sends (?:the )?(.+) \((\d+) bytes, (\d+) lines, SHA-256 ([0-9a-f]+)\)(?:, all of it:|\.)$`)

// boxMaxLines is how many rows the command box shows before it scrolls
// (only down, never sideways), on macOS and Windows alike.
const boxMaxLines = 15

// boxCols is the command box's width in monospace characters, on macOS
// and Windows alike: box() wraps every line to it, so it never scrolls
// sideways and no tail of a command is out of view.
const boxCols = 80

// moreHint is the line under a box that scrolls, or "".
func (v approvalView) moreHint() string {
	if n := v.boxRows() - boxMaxLines; n > 0 {
		return fmt.Sprintf("%d more lines: scroll to read all", n)
	}
	return ""
}

// riskyLine is the first row of the box where a line that a deny rule
// matches begins (the check that rated the command), or -1. The box opens
// scrolled to it.
func (v approvalView) riskyLine() int {
	_, start := v.box()
	for i, l := range strings.Split(v.command(), "\n") {
		if len(policy.Check(l, nil)) > 0 {
			return start[i]
		}
	}
	return -1
}

// riskyRange is the risky line's rows as a UTF-16 offset and length into
// boxText(), as AppKit counts; -1, 0 for none.
func (v approvalView) riskyRange() (off, n int) {
	first := v.riskyLine()
	if first < 0 {
		return -1, 0
	}
	rows, start := v.box()
	last := len(rows)
	for _, s := range start {
		if s > first {
			last = s
			break
		}
	}
	for _, l := range rows[:first] {
		off += len(utf16.Encode([]rune(l))) + 1
	}
	n = len(utf16.Encode([]rune(strings.Join(rows[first:last], "\n"))))
	return off, n
}

// notes is the secondary text under the box: the scroll hint and what
// the flag also lets through.
func (v approvalView) notes() string {
	if v.raw != "" {
		return v.moreHint()
	}
	var b []string
	if h := v.moreHint(); h != "" {
		b = append(b, h)
	}
	if v.What != "" {
		b = append(b, "Also lets through: "+v.What)
	}
	return strings.Join(b, "\n\n")
}

// layout is the window's content as plain text, for the golden test.
func (v approvalView) layout() string {
	s := "[title]\n" + v.title() + "\n[subtitle]\n" + v.subtitle() + "\n[grid]\n" + v.header() + "\n[command]\n" + v.boxText() + "\n"
	s += "[owner]\n" + v.ownerReason() + "\n[notes]\n" + v.notes() + "\n[question]\n" + question + "\n[danger]\n" + v.dangerArg() + "\n"
	return s + "[risky line]\n" + strconv.Itoa(v.riskyLine()) + "\n[allow is destructive]\n" + strconv.FormatBool(v.destructive()) + "\n"
}

// textRows is how many rows s takes, wrapped at cols.
func textRows(s string, cols int) int {
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
// text arrives in argv after macArgMarker, never in the script: 1 the
// title, 2 who asks, 3 the command box, 4 the notes, 5 the box height,
// 6 the risky line's offset (the box opens scrolled to it), 7 the
// dangerous commands' ranges ("off:len,..."), 8 and 9 the owner check, 10 the grid (kind,
// label, text a line), 11 "1" when Allow once shows red, 12 the question.
// Deny is the default (Return) and Esc; after 120 seconds it closes as
// "gave up". After "Allow once" the same run asks LocalAuthentication for
// the device owner (policy 2: Touch ID, an Apple Watch or the login
// password) with argv[8] as the reason, waiting at most argv[9] seconds of
// its own; it prints "owner ok" on the next line only when the reply says
// ok. Colours are semantic only, so dark mode draws itself.
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
function warn(msg) {
  try { $.NSFileHandle.fileHandleWithStandardError.writeData($(msg + '\n').dataUsingEncoding($.NSUTF8StringEncoding)); } catch (e) {}
}
function symbol(name, size) {
  var im = null;
  try { im = $.NSImage.imageWithSystemSymbolNameAccessibilityDescription(name, name); } catch (e) { warn('symbol ' + name + ': ' + e); }
  if (!im || im.isNil()) { warn('symbol ' + name + ': none'); return null; }
  try {
    var cfg = $.NSClassFromString('NSImageSymbolConfiguration').configurationWithPointSizeWeight(size, 0);
    var c = im.imageWithSymbolConfiguration(cfg);
    if (c && !c.isNil()) return c;
  } catch (e) { warn('symbol ' + name + ' size: ' + e); }
  im.size = $.NSMakeSize(size, size);
  return im;
}
function label(text, font, colour, w) {
  var l = $.NSTextField.wrappingLabelWithString(text);
  l.font = font;
  l.textColor = colour;
  l.preferredMaxLayoutWidth = w;
  var h = text === '' ? 0 : Math.ceil(l.cell.cellSizeForBounds($.NSMakeRect(0, 0, w, 1e5)).height);
  return { v: l, h: h };
}
function run(argv) {
  var app = $.NSApplication.sharedApplication;
  app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
  var a = $.NSAlert.alloc.init;
  a.alertStyle = $.NSAlertStyleWarning;
  var icon = symbol('lock.shield', 48);
  if (!icon) { icon = $.NSImage.imageNamed('NSCaution'); if (icon && icon.isNil()) icon = null; }
  if (icon) a.icon = icon;
  a.messageText = argv[1];
  a.informativeText = argv[2];
  var deny = a.addButtonWithTitle('Deny');
  deny.keyEquivalent = '\r';
  var allow = a.addButtonWithTitle('Allow once');
  allow.keyEquivalent = '';
  if (argv[11] === '1') {
    // red title text on a normal button, the same weight as Deny
    var ps = $.NSMutableParagraphStyle.alloc.init;
    ps.alignment = $.NSTextAlignmentCenter;
    allow.attributedTitle = $.NSAttributedString.alloc.initWithStringAttributes('Allow once',
      $.NSDictionary.dictionaryWithObjectsForKeys([$.NSColor.systemRedColor, allow.font, ps], [$.NSForegroundColorAttributeName, $.NSFontAttributeName, $.NSParagraphStyleAttributeName]));
  }
  var x0 = 4, w = 596, gap = 10, lw = 64, vx = lw + 8, fs = $.NSFont.systemFontSize;
  var font = $.NSFont.systemFontOfSize(fs), bold = $.NSFont.boldSystemFontOfSize(fs);
  var parts = []; // {v, x, h, w}, top to bottom; a row of the grid is one part
  argv[10].split('\n').forEach(function (line) {
    if (line === '') return;
    var f = line.split('\t'), kind = f[0];
    var row = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, w, 0));
    var lab = label(f[1], font, $.NSColor.secondaryLabelColor, lw);
    var tx = vx, h = 0;
    if (kind === '2') {
      var warn = symbol('exclamationmark.triangle', fs);
      if (warn) {
        var iv = $.NSImageView.imageViewWithImage(warn);
        iv.contentTintColor = $.NSColor.systemRedColor;
        iv.setAccessibilityLabel('Risk');
        iv.frame = $.NSMakeRect(vx, 0, 16, 16);
        row.addSubview(iv);
        tx = vx + 22;
      }
    }
    if (kind === '1') {
      var bl = label(f[2], $.NSFont.systemFontOfSizeWeight(fs - 2, 0.23), $.NSColor.secondaryLabelColor, 200);
      var bw = Math.ceil(bl.v.fittingSize.width) + 12;
      var badge = $.NSBox.alloc.initWithFrame($.NSMakeRect(vx, 0, bw, bl.h + 4));
      badge.boxType = 4;
      badge.titlePosition = 0;
      badge.borderWidth = 1;
      badge.cornerRadius = 4;
      badge.borderColor = $.NSColor.secondaryLabelColor;
      badge.fillColor = $.NSColor.controlBackgroundColor;
      badge.contentViewMargins = $.NSMakeSize(0, 0);
      bl.v.frame = $.NSMakeRect(6, 2, bw - 12, bl.h);
      badge.contentView.addSubview(bl.v);
      row.addSubview(badge);
      h = bl.h + 4;
    } else {
      var val = label(f[2], font, kind === '2' ? $.NSColor.systemRedColor : $.NSColor.labelColor, w - tx);
      h = Math.max(val.h, 16);
      val.v.frame = $.NSMakeRect(tx, h - val.h, w - tx, val.h);
      row.addSubview(val.v);
      if (kind === '2' && row.subviews.count > 1) row.subviews.objectAtIndex(0).frame = $.NSMakeRect(vx, h - 16, 16, 16);
    }
    lab.v.frame = $.NSMakeRect(0, h - lab.h, lw, lab.h);
    row.addSubview(lab.v);
    parts.push({ v: row, h: h, gap: 4 });
  });
  if (parts.length) parts[parts.length - 1].gap = gap;
  var h = Number(argv[5]) || 120;
  var sv = $.NSScrollView.alloc.initWithFrame($.NSMakeRect(0, 0, w, h));
  sv.hasVerticalScroller = true;
  sv.hasHorizontalScroller = false;
  sv.autohidesScrollers = true;
  sv.borderType = $.NSBezelBorder;
  var tv = $.NSTextView.alloc.initWithFrame($.NSMakeRect(0, 0, w, h));
  tv.editable = false;
  tv.selectable = true;
  tv.richText = false;
  var ms = $.NSFont.smallSystemFontSize, mf = null;
  try { mf = $.NSFont.monospacedSystemFontOfSizeWeight(ms, 0); } catch (e) {}
  tv.font = (mf && !mf.isNil()) ? mf : $.NSFont.userFixedPitchFontOfSize(ms);
  tv.textColor = $.NSColor.labelColor;
  var fill = $.NSColor.quaternarySystemFillColor;
  tv.backgroundColor = (fill && !fill.isNil()) ? fill : $.NSColor.controlBackgroundColor;
  sv.drawsBackground = false;
  tv.textContainerInset = $.NSMakeSize(6, 6);
  tv.horizontallyResizable = false;
  tv.textContainer.widthTracksTextView = true;
  tv.string = argv[3];
  tv.setAccessibilityLabel('Command');
  sv.documentView = tv;
  // only the dangerous commands are marked: red text, a thin underline
  argv[7].split(',').forEach(function (r) {
    var p = r.split(':');
    if (p.length !== 2) return;
    var rr = $.NSMakeRange(Number(p[0]), Number(p[1]));
    tv.textStorage.addAttributeValueRange($.NSForegroundColorAttributeName, $.NSColor.systemRedColor, rr);
    tv.textStorage.addAttributeValueRange($.NSUnderlineStyleAttributeName, 1, rr);
  });
  if (Number(argv[6]) >= 0) tv.scrollRangeToVisible($.NSMakeRange(Number(argv[6]), 0));
  parts.push({ v: sv, h: h, gap: gap });
  var note = label(argv[4], $.NSFont.systemFontOfSize($.NSFont.smallSystemFontSize), $.NSColor.secondaryLabelColor, w);
  if (note.h) parts.push({ v: note.v, h: note.h, gap: gap });
  var ask = label(argv[12], bold, $.NSColor.labelColor, w);
  parts.push({ v: ask.v, h: ask.h, gap: 0 });
  var total = 0;
  parts.forEach(function (p) { total += p.h + p.gap; });
  var box = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, x0 + w, total));
  var y = total;
  parts.forEach(function (p) {
    y -= p.h;
    p.v.frame = $.NSMakeRect(x0, y, w, p.h);
    box.addSubview(p.v);
    y -= p.gap;
  });
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
  if (r === $.NSAlertSecondButtonReturn) return 'Allow once\n' + owner(argv[8], argv[9]);
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

// ownerReason is what the macOS device-owner prompt says komando asks
// for: Owner when set (a reveal), the targets, or the command line.
func (v approvalView) ownerReason() string {
	if v.Owner != "" {
		return v.Owner
	}
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
	rows := min(v.boxRows(), boxMaxLines)
	off, _ := v.riskyRange()
	dangerous := "0"
	if v.destructive() {
		dangerous = "1"
	}
	// 15 px a row, 12 for the insets; no sideways scroller (box() wraps)
	return []string{"-l", "JavaScript", "-e", macAlertScript, macArgMarker, v.title(), v.subtitle(), v.boxText(), v.notes(), strconv.Itoa(rows*15 + 14),
		strconv.Itoa(off), v.dangerArg(), v.ownerReason(), strconv.Itoa(int(ownerTimeout.Seconds())), v.gridArg(), dangerous, question}
}

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

// The Windows window's size, in pixels: a white content area with 12 px
// padding, 16 px rows of Segoe UI 9 pt and of Consolas; the grid's label
// column, then the values; the command box shows up to boxMaxLines rows
// of boxCols characters, then scrolls down (never sideways).
const (
	winW, winPad = 680, 12
	winInner     = winW - 2*winPad - 16 // 16: the window's side borders
	winRowH      = 16
	winLabelW    = 64
	winTextCols  = 88 // Segoe UI characters on a full row, kept low so wrapped text is never cut
	winValueCols = 76 // the same in the grid's value column
	winTitleCols = 80 // bold characters on a full row
	winBadgeW    = 72
)

type winLayout struct{ titleH, subH, cmdH, notesH, height int }

// winGridH is the height of each grid row, in order.
func winGridH(v approvalView) []int {
	var hs []int
	for _, r := range v.grid() {
		h := winRowH + 4
		if r.Kind != rowBadge {
			h = textRows(r.Text, winValueCols)*winRowH + 4
		}
		hs = append(hs, h)
	}
	return hs
}

func winLayoutFor(v approvalView) winLayout {
	var l winLayout
	l.titleH = textRows(v.title(), winTitleCols)*winRowH + 4
	if s := v.subtitle(); s != "" {
		l.subH = winRowH
	}
	l.cmdH = min(v.boxRows(), boxMaxLines)*winRowH + 10
	if n := v.notes(); n != "" {
		l.notesH = textRows(n, winTextCols) * winRowH
	}
	l.height = winPad + l.titleH + l.subH + winPad
	for _, h := range winGridH(v) {
		l.height += h
	}
	l.height += winPad + l.cmdH + winPad
	if l.notesH > 0 {
		l.height += l.notesH + winPad
	}
	l.height += winRowH + winPad // the question
	return l
}
