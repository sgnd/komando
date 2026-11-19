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
	switch {
	case v.raw != "":
		return "komando: allow?"
	case len(v.Targets) > 0:
		return "Change " + strings.Join(v.Targets, ", ")
	}
	return "Run a komando command"
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

// rowKind is how a grid row is drawn.
type rowKind int

const (
	rowPlain rowKind = iota
	rowBadge         // a small framed label ("Protected")
	rowRisk          // a red warning symbol, then the text
)

// gridRow is one line of the two-column grid above the command.
type gridRow struct {
	Label, Text string // Label is "" on a row that continues the one above
	Kind        rowKind
}

// grid is where it runs, whether that is protected, and each risk in
// plain words, one per line.
func (v approvalView) grid() []gridRow {
	if v.raw != "" {
		return nil
	}
	var g []gridRow
	if len(v.Targets) > 0 {
		g = append(g, gridRow{"Target", strings.Join(v.Targets, ", "), rowPlain})
	}
	if v.Protected {
		g = append(g, gridRow{"", "Protected", rowBadge})
	}
	label := "Risk"
	for _, r := range v.Risks {
		for _, w := range riskWords(r) {
			g = append(g, gridRow{label, w, rowRisk})
			label = ""
		}
	}
	return g
}

// destructive says whether "Allow once" is drawn as a dangerous button:
// whenever a risk line is shown.
func (v approvalView) destructive() bool {
	for _, r := range v.grid() {
		if r.Kind == rowRisk {
			return true
		}
	}
	return false
}

// header is the grid as plain text, for the golden test.
func (v approvalView) header() string {
	var b []string
	for _, r := range v.grid() {
		t := r.Text
		switch r.Kind {
		case rowBadge:
			t = "[" + t + "]"
		case rowRisk:
			t = "(!) " + t
		}
		b = append(b, fmt.Sprintf("%-8s %s", r.Label, t))
	}
	return strings.Join(b, "\n")
}

// gridArg is the grid for the macOS script's argv: one row a line,
// kind, label and text split by tabs (unshowable keeps both out of a text).
func (v approvalView) gridArg() string {
	var b []string
	for _, r := range v.grid() {
		b = append(b, strconv.Itoa(int(r.Kind))+"\t"+r.Label+"\t"+r.Text)
	}
	return strings.Join(b, "\n")
}

// ruleTrigger is the command a built-in deny rule (internal/policy) is
// about, shown after its reason so a person sees what triggered it.
var ruleTrigger = map[string]string{
	"rm-root": "rm -rf", "rm-cd-root": "rm -rf", "find-delete-root": "find -delete", "rm-system-dir": "rm -rf",
	"mkfs": "mkfs", "dd-device": "dd", "redirect-device": "> /dev", "wipefs": "wipefs", "fdisk": "fdisk",
	"power": "shutdown", "power-systemctl": "systemctl reboot", "fork-bomb": "fork bomb",
	"chmod-root": "chmod -R", "chown-root": "chown -R", "firewall-flush": "firewall flush", "firewall-drop-all": "iptables -P DROP",
	"sshd-stop": "stop sshd", "passwd-files": "/etc/passwd", "passwd-files-write": "/etc/passwd", "db-drop": "DROP DATABASE",
	"docker-prune-all": "docker prune", "kubectl-delete-ns": "kubectl delete", "base64-pipe-sh": "base64 | sh",
	"curl-pipe-sh": "curl | sh", "crontab-r": "crontab -r", "userdel": "userdel",
	"win-rm-root": "Remove-Item -Recurse", "win-format": "Format-Volume", "win-power": "Stop-Computer", "win-remote-access": "Stop-Service",
	"win-firewall-block": "Set-NetFirewallProfile", "win-user-delete": "Remove-LocalUser", "win-encoded": "-EncodedCommand",
	"win-download-run": "download | iex", "win-backups": "vssadmin delete", "win-registry-hive": "reg delete",
}

// riskWords is a risk reason in plain words, one line each: a deny-rule
// reason ("[rm-system-dir,db-drop] deletes ...; drops a database") loses
// its rule ids and names what triggered it ("Deletes a system folder
// recursively (rm -rf)"); any other reason is shown as it is, capitalised.
func riskWords(r string) []string {
	if ids, rest, ok := strings.Cut(strings.TrimPrefix(r, "["), "] "); ok && strings.HasPrefix(r, "[") {
		idl, reasons := strings.Split(ids, ","), strings.Split(rest, "; ")
		if len(idl) == len(reasons) {
			var out []string
			for i, id := range idl {
				t, known := ruleTrigger[id]
				if !known && !strings.HasPrefix(id, "custom-") {
					out = nil
					break
				}
				w := capitalise(reasons[i])
				if t != "" {
					w += " (" + t + ")"
				}
				if !slices.Contains(out, w) {
					out = append(out, w)
				}
			}
			if out != nil {
				return out
			}
		}
	}
	return []string{capitalise(r)}
}

func capitalise(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return strings.ToUpper(string(r)) + s[n:]
}

// flagSkip is the stop each approval flag skips, in a few words.
var flagSkip = map[string]string{
	"--yes":             "the protected-server stop",
	"--allow-dangerous": "the dangerous-command stop",
	"--reveal":          "the secret-hiding stop",
}

// skipLines is one short line per skipped flag.
func (v approvalView) skipLines() string {
	var b []string
	for _, f := range v.Flags {
		what := flagSkip[f]
		if what == "" {
			what = "a safety stop"
		}
		b = append(b, "Skips "+what+" ("+f+")")
	}
	return strings.Join(b, "\n")
}

// command is the command line, then the body, as sent.
func (v approvalView) command() string {
	if v.raw != "" {
		return strings.TrimRight(v.raw, "\n")
	}
	if v.Body == "" {
		return v.Line
	}
	return v.Line + "\n\n" + strings.TrimRight(v.Body, "\n")
}

// boxMaxLines is how many rows the command box shows before it scrolls
// (only down, never sideways), on macOS and Windows alike.
const boxMaxLines = 15

// boxCols is the command box's width in monospace characters, on macOS
// and Windows alike: box() wraps every line to it, so it never scrolls
// sideways and no tail of a command is out of view.
const boxCols = 80

// box is command() wrapped at boxCols; start[i] is the row where line i
// of command() begins.
func (v approvalView) box() (rows []string, start []int) {
	for _, l := range strings.Split(v.command(), "\n") {
		start = append(start, len(rows))
		rows = append(rows, wrapLine(l, boxCols)...)
	}
	return rows, start
}

// boxText is the command box's text.
func (v approvalView) boxText() string {
	rows, _ := v.box()
	return strings.Join(rows, "\n")
}

// wrapLine breaks l into rows of at most cols characters, at a space
// where it can. Rows after the first hang under the text: after a script
// line's number ("  12  "), or four spaces in from the line's own indent.
func wrapLine(l string, cols int) []string {
	r := []rune(l)
	if len(r) <= cols {
		return []string{l}
	}
	indent := len(r) - len([]rune(strings.TrimLeft(l, " ")))
	if m := scriptLineNo.FindString(l); m != "" {
		indent = utf8.RuneCountInString(m)
	} else {
		indent += 4
	}
	if indent > cols/2 {
		indent = 4
	}
	var rows []string
	pad := ""
	for len(r) > 0 {
		room := cols - utf8.RuneCountInString(pad)
		if len(r) <= room {
			rows = append(rows, pad+string(r))
			break
		}
		cut := room
		for i := room; i > room/2; i-- {
			if r[i-1] == ' ' {
				cut = i
				break
			}
		}
		rows = append(rows, pad+strings.TrimRight(string(r[:cut]), " "))
		r = r[cut:]
		pad = strings.Repeat(" ", indent)
	}
	return rows
}

// scriptLineNo is the number in front of a script line in the body.
var scriptLineNo = regexp.MustCompile(`^ *\d+  `)

// boxRows is how many rows the command box has.
func (v approvalView) boxRows() int {
	rows, _ := v.box()
	return len(rows)
}

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

// notes is the secondary text under the box: the scroll hint, what the
// flag also lets through, and the skipped stops.
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
	if f := v.skipLines(); f != "" {
		b = append(b, f)
	}
	return strings.Join(b, "\n\n")
}

// layout is the window's content as plain text, for the golden test.
func (v approvalView) layout() string {
	s := "[title]\n" + v.title() + "\n[subtitle]\n" + v.subtitle() + "\n[grid]\n" + v.header() + "\n[command]\n" + v.boxText() + "\n"
	s += "[owner]\n" + v.ownerReason() + "\n[notes]\n" + v.notes() + "\n[question]\n" + question + "\n"
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
// 6 and 7 the risky range, 8 and 9 the owner check, 10 the grid (kind,
// label, text a line), 11 "1" when Allow once is dangerous, 12 the question.
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
function symbol(name, size) {
  try {
    var im = $.NSImage.imageWithSystemSymbolNameAccessibilityDescription(name, null);
    if (!im || im.isNil()) return null;
    var c = im.imageWithSymbolConfiguration($.NSImageSymbolConfiguration.configurationWithPointSizeWeight(size, 0));
    return (c && !c.isNil()) ? c : im;
  } catch (e) { return null; }
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
  if (icon) a.icon = icon;
  a.messageText = argv[1];
  a.informativeText = argv[2];
  var deny = a.addButtonWithTitle('Deny');
  deny.keyEquivalent = '\r';
  var allow = a.addButtonWithTitle('Allow once');
  allow.keyEquivalent = '';
  if (argv[11] === '1') { try { allow.hasDestructiveAction = true; } catch (e) {} }
  var w = 600, gap = 10, lw = 64, vx = lw + 8, fs = $.NSFont.systemFontSize;
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
      var val = label(f[2], font, $.NSColor.labelColor, w - tx);
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
  tv.backgroundColor = $.NSColor.controlBackgroundColor;
  tv.textContainerInset = $.NSMakeSize(6, 6);
  tv.horizontallyResizable = false;
  tv.textContainer.widthTracksTextView = true;
  tv.string = argv[3];
  tv.setAccessibilityLabel('Command');
  sv.documentView = tv;
  var ro = Number(argv[6]), rn = Number(argv[7]);
  if (ro >= 0) {
    var rr = $.NSMakeRange(ro, rn);
    tv.textStorage.addAttributeValueRange($.NSBackgroundColorAttributeName, $.NSColor.findHighlightColor, rr);
    tv.scrollRangeToVisible(rr);
  }
  parts.push({ v: sv, h: h, gap: gap });
  var note = label(argv[4], $.NSFont.systemFontOfSize($.NSFont.smallSystemFontSize), $.NSColor.secondaryLabelColor, w);
  if (note.h) parts.push({ v: note.v, h: note.h, gap: gap });
  var ask = label(argv[12], bold, $.NSColor.labelColor, w);
  parts.push({ v: ask.v, h: ask.h, gap: 0 });
  var total = 0;
  parts.forEach(function (p) { total += p.h + p.gap; });
  var box = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, w, total));
  var y = total;
  parts.forEach(function (p) {
    y -= p.h;
    p.v.frame = $.NSMakeRect(0, y, w, p.h);
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
	off, n := v.riskyRange()
	dangerous := "0"
	if v.destructive() {
		dangerous = "1"
	}
	// 15 px a row, 12 for the insets; no sideways scroller (box() wraps)
	return []string{"-l", "JavaScript", "-e", macAlertScript, macArgMarker, v.title(), v.subtitle(), v.boxText(), v.notes(), strconv.Itoa(rows*15 + 14),
		strconv.Itoa(off), strconv.Itoa(n), v.ownerReason(), strconv.Itoa(int(ownerTimeout.Seconds())), v.gridArg(), dangerous, question}
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
	winTitleCols = 60 // the bold title is wider
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
	l.titleH = textRows(v.title(), winTitleCols) * (winRowH + 4)
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
