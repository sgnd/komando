package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
	for _, e := range encodedRisks(v.Line, v.Body, "en") {
		text += e + "\n\n"
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
// under it, then argv[5] (what runs, monospace, not selectable) in a
// scroll view, 12 pt apart, 440 pt wide with 20 pt padding, then the
// buttons argv[7] (Deny) and argv[8] (Allow once) on the right. The
// panel stays inside the screen's visible frame: the title, the info
// lines and the buttons always show, and what runs takes the height left
// and scrolls (no scroller when it fits). Whatever their labels, the script answers with the fixed
// tokens "Deny" and "Allow once" (macAnswer). Every text arrives in argv after
// macArgMarker, never in the script. Deny is the default (Return), Esc,
// the close button and Cmd-W; only the 120 s timer prints "gave up", and
// any other end is a Deny. The script area (or, when nothing scrolls, the
// panel) keeps AppKit's first responder, so every key reaches onKey
// through typed keyDown: overrides; Tab moves the panel's own focus
// (nextFocus, a ring on each stop), and a click on the script or the
// background gives it the keys back. No callback in the modal loop hands
// AppKit a value it must read as an object (C237). After
// "Allow once" the same run asks LocalAuthentication for the device owner
// (policy 2: Touch ID, an Apple Watch or the login password) with argv[3]
// as the reason, waiting at most argv[4] seconds of its own; it prints
// "owner ok" on the next line only when the reply says ok. argv[10] is "1"
// only in a debug run (macDebugArgs): the script then notes on stderr each
// key, focus change, handler error and end, never a text.
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
// DEBUG is set in run for a debug run (KOMANDO_APPROVAL_DEBUG): note writes one
// line to stderr for komando's debug log, with the first responder and
// FOCUS, and never throws; PANEL and DENY_BTN let who name the first responder
var DEBUG = false, T0 = Date.now(), PANEL = null, DENY_BTN = null;
function note(what) {
  if (!DEBUG) return;
  try { console.log('komando-debug +' + (Date.now() - T0) + ' ' + what + ' | first ' + who() + ' focus ' + (FOCUS || 'none')); } catch (x) {}
}
// who is the first responder: deny, allow, script, panel or a class name
function who() {
  try {
    var r = PANEL.firstResponder;
    if (r.isNil()) return 'none';
    if (r.isEqual(DENY_BTN)) return 'deny';
    if (r.isEqual(ALLOW_BTN)) return 'allow';
    if (DOC !== null && r.isEqual(DOC)) return 'script';
    if (r.isEqual(PANEL)) return 'panel';
    return ObjC.unwrap(r.className);
  } catch (x) { return '?'; }
}
// how is the event AppKit is handling: a click, or a key (keyName)
function how() {
  try {
    var e = APP.currentEvent, t = e.isNil() ? -1 : Number(e.type);
    return t === 10 ? 'key ' + keyName(e) : t === 1 || t === 2 ? 'click' : 'event type ' + t;
  } catch (x) { return '?'; }
}
// keyName names a key for the debug log only while a panel control has
// focus; in a text field it gives a class, so a typed secret never shows (C256)
var SHIFT = 0x20000, CMD = 0x100000;
var KEY_NAMES = { 36: 'Return', 53: 'Esc', 48: 'Tab', 49: 'Space', 123: 'Left', 124: 'Right', 125: 'Down', 126: 'Up', 116: 'PageUp', 121: 'PageDown', 115: 'Home', 119: 'End' };
function keyName(e) {
  try {
    var code = Number(e.keyCode), mods = Number(e.modifierFlags), own = ['deny', 'allow', 'script', 'panel'].indexOf(who()) >= 0;
    if (own && KEY_NAMES[code]) return KEY_NAMES[code] + (mods & SHIFT ? ' shift' : '') + (mods & CMD ? ' cmd' : '');
    if (code === 48) return 'Tab';
    if (code >= 123 && code <= 126) return 'arrow';
    var ch = ObjC.unwrap(e.charactersIgnoringModifiers) || '';
    return /^[0-9]$/.test(ch) ? 'digit' : ch.length === 1 && ch.toLowerCase() !== ch.toUpperCase() ? 'letter' : 'other';
  } catch (x) { return '?'; }
}
// state is the focus state when the panel shows (fka: keyboard navigation)
function state() {
  try {
    return 'scroll=' + SCROLLS + ' seen=' + SEEN + ' ' + where() + ' fka=' + APP.isFullKeyboardAccessEnabled + ' key=' + PANEL.isKeyWindow + ' active=' + APP.isActive +
      ' nonactivating=' + ((Number(PANEL.styleMask) & 128) !== 0);
  } catch (x) { return '?'; }
}
// where is the script area's top edge in points, for the debug log
function where() {
  try {
    return SCROLLS ? 'y=' + Math.round(CLIP.documentVisibleRect.origin.y) : 'y=-';
  } catch (x) { return '?'; }
}
// a body that scrolls must have shown its last line (SEEN) before
// "Allow once" works; CLIP is its clip view, ALLOW_BTN the button
var SEEN = true, CLIP = null, DOC = null, SV = null, ALLOW_BTN = null, SCROLLS = false;
// FOCUS is where Tab is: script, deny, allow, or '' while a selectable
// text field holds the keys. The buttons refuse AppKit's focus, so the
// first responder stays the script area (or the panel) and every key
// reaches onKey, whatever the keyboard-navigation setting. RINGS holds a
// hidden focus ring per stop.
var FOCUS = '', RINGS = {};
// nextFocus is where Tab (back: Shift-Tab) goes: script, Deny, then Allow
// once only while it is on, and round
function nextFocus(f, back, scrolls, allowOn) {
  var order = (scrolls ? ['script'] : []).concat(allowOn ? ['deny', 'allow'] : ['deny']);
  var i = order.indexOf(f);
  if (i < 0) return order[0];
  return order[(i + (back ? order.length - 1 : 1)) % order.length];
}
function showFocus(f) {
  FOCUS = f;
  for (var k in RINGS) RINGS[k].hidden = k !== f;
}
// real is true for an AppKit object: JXA hands a JavaScript null to
// AppKit as NSNull, not nil, and NSNull is no responder
function real(o) {
  try { return o !== null && o !== undefined && !o.isNil() && ObjC.unwrap(o.className) !== 'NSNull'; } catch (x) { note('error in real: ' + x); return false; }
}
// focusHome gives the keys to the script area, or to the panel itself when
// nothing scrolls (Deny then has the ring)
function focusHome() {
  var toScript = SCROLLS && real(DOC);
  PANEL.makeFirstResponder(toScript ? DOC : PANEL);
  showFocus(toScript ? 'script' : 'deny');
}
// keyScroll is where a key moves the script area's top edge: the arrows
// a line, Page Up/Down and Space a page, Home/End the ends; null for any
// other key (Return, Tab and Esc keep their meaning)
function keyScroll(code, y, line, page, maxY) {
  var to = code === 126 ? y - line : code === 125 ? y + line : code === 116 ? y - page :
    code === 121 || code === 49 ? y + page : code === 115 ? 0 : code === 119 ? maxY : null;
  return to === null ? null : Math.max(0, Math.min(maxY, to));
}
// SCROLL_KEYS scroll the script whatever has the focus: Up, Down, Page
// Up, Page Down, Home, End; Space scrolls only when the script has it
var SCROLL_KEYS = [126, 125, 116, 121, 115, 119];
// scrollKey scrolls the clip view; the bounds observer then runs the gate.
// An error in a JXA callback ends the panel as a Deny, so it answers
// false instead (C237)
function scrollKey(code) {
  try {
    if (!SCROLLS) return false;
    var r = CLIP.documentVisibleRect, line = 16;
    var to = keyScroll(code, r.origin.y, line, Math.max(line, r.size.height - line), Math.max(0, DOC.frame.size.height - r.size.height));
    if (to === null) return false;
    CLIP.scrollToPoint($.NSMakePoint(0, to));
    SV.reflectScrolledClipView(CLIP);
    return true;
  } catch (x) { note('error in scrollKey: ' + x); return false; }
}
// onKey is the keyDown: of the panel and of the script area; it returns
// nothing to AppKit, where a key monitor's block returned a JSValue (C237)
function onKey(e) {
  try {
    var code = Number(e.keyCode), mods = Number(e.modifierFlags);
    if (DEBUG) note('key ' + keyName(e));
    if (code === 53 || code === 36 || (code === 13 && (mods & CMD))) { note('end: Deny, key'); CHOICE = 'Deny'; CHOSEN = true; APP.stopModalWithCode(DENY); return; }
    if (code === 48) { showFocus(nextFocus(FOCUS, (mods & SHIFT) !== 0, SCROLLS, SEEN)); note('focus moved'); return; }
    if (code === 49 && (FOCUS === 'deny' || FOCUS === 'allow')) { var btn = FOCUS === 'allow' ? ALLOW_BTN : DENY_BTN; note('Space presses the focused button'); btn.performClick(btn); return; }
    if (SCROLLS && (SCROLL_KEYS.indexOf(code) >= 0 || (code === 49 && FOCUS === 'script')) && scrollKey(code)) { if (DEBUG) note('scrolled to ' + where()); }
  } catch (x) { note('error in onKey: ' + x); }
}
// ringBox adds a hidden focus ring 3 pt outside a frame of view: a box in
// the system's focus colour (an NSBox takes the NSColor itself; a layer
// border needs a CGColor). Add it before what it rings, so it sits behind.
function ringBox(view, x, y, w, h) {
  var b = $.NSBox.alloc.initWithFrame($.NSMakeRect(x - 3, y - 3, w + 6, h + 6));
  b.boxType = 4;
  b.titlePosition = 0;
  b.borderWidth = 3;
  b.cornerRadius = 4;
  b.borderColor = $.NSColor.keyboardFocusIndicatorColor;
  b.hidden = true;
  view.addSubview(b);
  return b;
}
// seenEnd: the visible rect's bottom (NSMaxY, flipped) has reached the
// document's last line, with 1 pt of slack; at the top it is false
function seenEnd(y, h, docH) { return y + h >= docH - 1; }
// the script's document view is flipped: y 0 is its first line
ObjC.registerSubclass({
  name: 'KomandoDoc',
  superclass: 'NSView',
  methods: {
    'isFlipped': { types: ['bool', []], implementation: function () { return true; } },
    // a script that scrolls takes focus, so the keys can read it to the end
    'acceptsFirstResponder': { types: ['bool', []], implementation: function () { return SCROLLS; } },
    'keyDown:': { types: ['void', ['id']], implementation: function (e) { onKey(e); } },
    'mouseDown:': { types: ['void', ['id']], implementation: function (e) { try { note('click: script area'); focusHome(); } catch (x) { note('error in mouseDown: ' + x); } } },
    'becomeFirstResponder': { types: ['bool', []], implementation: function () { try { showFocus('script'); note('script area has focus'); } catch (x) { note('error in becomeFirstResponder: ' + x); } return true; } },
    'resignFirstResponder': { types: ['bool', []], implementation: function () { try { showFocus(''); note('script area lost focus'); } catch (x) { note('error in resignFirstResponder: ' + x); } return true; } }
  }
});
// KomandoClick lies over the script's text, a label that would take a
// click itself, so a click anywhere on the script gives it the keys back
ObjC.registerSubclass({
  name: 'KomandoClick',
  superclass: 'NSView',
  methods: {
    'mouseDown:': { types: ['void', ['id']], implementation: function (e) { try { note('click: script area'); focusHome(); } catch (x) { note('error in mouseDown: ' + x); } } }
  }
});
ObjC.registerSubclass({
  name: 'KomandoPanel',
  superclass: 'NSPanel',
  methods: {
    'keyDown:': { types: ['void', ['id']], implementation: function (e) { onKey(e); } },
    // a click on the background reaches the window through the content view
    'mouseDown:': { types: ['void', ['id']], implementation: function (e) { try { note('click: panel background'); focusHome(); } catch (x) { note('error in mouseDown: ' + x); } } }
  }
});
// the panel comes back to the front when it stops being key, at most 3
// times in 10 seconds: the cap stops two panels (each in its own osascript
// process) or a full-screen app from re-fronting each other
var REFRONTS = [];
// HELD is true for 500 ms after a re-front: the Allow once button is disabled
// then; scrolled: and allow: both honour it, so a click or key meant for the
// app that had the focus cannot answer the panel
var HELD = false;
function holdAllow() {
  HELD = true;
  ALLOW_BTN.enabled = false;
  var h = $.NSTimer.timerWithTimeIntervalRepeatsBlock(0.5, false, function () { HELD = false; ALLOW_BTN.enabled = SEEN; });
  $.NSRunLoop.currentRunLoop.addTimerForMode(h, $.NSRunLoopCommonModes);
}
// otherPanelIsKey sees only this process's windows; the cap above is what
// holds against a panel of another process
function otherPanelIsKey() {
  try {
    var kw = APP.keyWindow;
    return real(kw) && ObjC.unwrap(kw.className) === 'KomandoPanel' && !kw.isEqual(PANEL);
  } catch (x) { note('error in otherPanelIsKey: ' + x); return false; }
}
function refront() {
  var now = Date.now();
  var recent = [];
  for (var i = 0; i < REFRONTS.length; i++) { if (now - REFRONTS[i] < 10000) recent.push(REFRONTS[i]); }
  REFRONTS = recent;
  if (REFRONTS.length >= 3) { note('re-front limit: stays ordered front'); PANEL.orderFront(PANEL); return; }
  REFRONTS.push(now);
  APP.activateIgnoringOtherApps(true);
  PANEL.makeKeyAndOrderFront(PANEL);
  holdAllow();
}
ObjC.registerSubclass({
  name: 'KomandoAnswer',
  methods: {
    'deny:': { types: ['void', ['id']], implementation: function (s) { if (DEBUG) note('end: Deny, ' + how()); CHOICE = 'Deny'; CHOSEN = true; APP.stopModalWithCode(DENY); } },
    // Space on a focused Allow once button reaches allow: like a click
    // (onKey presses it). That is safe only because the device-owner check
    // (Touch ID or the login password) runs after this panel and no key
    // press can satisfy it. A change that drops or weakens that check must
    // stop keys reaching allow:.
    'allow:': { types: ['void', ['id']], implementation: function (s) { if (DEBUG) note((SEEN ? 'end: Allow once, ' : 'Allow once ignored: not read to the end, ') + how()); if (!SEEN || HELD) return; CHOICE = 'Allow'; CHOSEN = true; APP.stopModalWithCode(ALLOW); } },
    // the last line is in view when the visible rect reaches the document's bottom
    'scrolled:': { types: ['void', ['id']], implementation: function (n) { try { if (SEEN) return; var r = CLIP.documentVisibleRect; if (seenEnd(r.origin.y, r.size.height, DOC.frame.size.height)) { SEEN = true; ALLOW_BTN.enabled = !HELD; note('read to the end'); } } catch (x) { note('error in scrolled: ' + x); } } },
    'windowWillClose:': { types: ['void', ['id']], implementation: function (n) { if (DEBUG) note('end: window closes, ' + how()); if (!CHOSEN) { CHOICE = 'Deny'; CHOSEN = true; } APP.stopModalWithCode(DENY); } },
    // losing key (another app or session took the focus) ends nothing: the
    // panel comes back to the front, and only an answer or the timer ends it
    'windowDidResignKey:': { types: ['void', ['id']], implementation: function (n) { try { if (!CHOSEN && !otherPanelIsKey()) { note('panel lost key'); refront(); } } catch (x) { note('error in windowDidResignKey: ' + x); } } },
    'windowDidBecomeKey:': { types: ['void', ['id']], implementation: function (n) { note('panel is key'); } }
  }
});
// hanging is text with each numbered script line's wrapped rows indented
// past its number, so a wrapped row never looks like a line of its own
// (the attributed-string init methods are not bridged: new, then fill)
function hanging(text, font) {
  var as = $.NSMutableAttributedString.new, cw = font.maximumAdvancement.width, at = 0;
  as.replaceCharactersInRangeWithString($.NSMakeRange(0, 0), text);
  as.addAttributeValueRange($.NSFontAttributeName, font, $.NSMakeRange(0, text.length));
  text.split('\n').forEach(function (ln) {
    var m = /^ *\d+  /.exec(ln);
    if (m) {
      var ps = $.NSMutableParagraphStyle.new;
      ps.headIndent = m[0].length * cw;
      as.addAttributeValueRange($.NSParagraphStyleAttributeName, ps, $.NSMakeRange(at, ln.length));
    }
    at += ln.length + 1;
  });
  return as;
}
function label(text, font, w, copy) {
  var l = $.NSTextField.wrappingLabelWithString(text);
  l.font = font;
  if (!copy) l.attributedStringValue = hanging(text, font);
  // the command and script are not selectable: they show U+2011 so a
  // flag never breaks over a line, and a copy of them would not run as shown
  l.selectable = copy;
  l.preferredMaxLayoutWidth = w;
  return { v: l, h: Math.ceil(l.cell.cellSizeForBounds($.NSMakeRect(0, 0, w, 1e5)).height) };
}
function run(argv) {
  DEBUG = argv[10] === '1';
  var app = $.NSApplication.sharedApplication;
  APP = app;
  app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
  var w = 440, pad = 20, gap = 12, fs = $.NSFont.systemFontSize;
  var parts = [label(argv[1], $.NSFont.boldSystemFontOfSize(fs), w, true)];
  if (argv[2] !== '') parts.push(label(argv[2], $.NSFont.systemFontOfSize(fs), w, true));
  var answer = $.KomandoAnswer.alloc.init;
  var deny = $.NSButton.buttonWithTitleTargetAction(argv[7], answer, 'deny:');
  DENY_BTN = deny;
  deny.keyEquivalent = '\r';
  deny.setAccessibilityLabel(argv[7]);
  var allow = $.NSButton.buttonWithTitleTargetAction(argv[8], answer, 'allow:');
  allow.keyEquivalent = '';
  allow.setAccessibilityLabel(argv[8]);
  // the buttons never take AppKit's focus, whatever the keyboard-navigation
  // setting: the keys stay with onKey, and FOCUS with the rings shows Tab's place
  deny.refusesFirstResponder = true;
  allow.refusesFirstResponder = true;
  var bh = Math.ceil(deny.fittingSize.height), dw = Math.ceil(deny.fittingSize.width), aw = Math.ceil(allow.fittingSize.width);
  // the title, the info lines and the buttons always show; what runs
  // (argv[5]) takes the height left on the screen and scrolls past it
  var fixedH = pad + bh + pad + pad;
  parts.forEach(function (p, i) { fixedH += p.h + (i ? gap : 0); });
  var screen = $.NSScreen.mainScreen;
  // 80 pt: the title bar and a margin above and below the panel
  var maxH = (screen.isNil() ? 600 : Math.floor(screen.visibleFrame.size.height)) - 80;
  var room = Math.max(maxH - fixedH - gap, 80);
  var mono = $.NSFont.monospacedSystemFontOfSizeWeight(fs, 0), bw = w, body = null, bodyH = 0, scroll = false, hint = null;
  if (argv[5] !== '') {
    body = label(argv[5], mono, bw, false);
    if (body.h > room) {
      // 16 pt for a scroller that does not overlay the text
      scroll = true;
      bw = w - 16;
      body = label(argv[5], mono, bw, false);
      // argv[9], "Scroll to read all N lines", sits over the buttons
      hint = label(argv[9], $.NSFont.systemFontOfSize(fs), w, true);
      room = Math.max(room - hint.h - gap, 80);
    }
    bodyH = Math.min(body.h, room);
  }
  var h = fixedH + (body ? gap + bodyH : 0) + (hint ? gap + hint.h : 0);
  // Allow once stays off until the last line has been in view once
  ALLOW_BTN = allow;
  SEEN = !scroll;
  allow.enabled = !scroll;
  var panel = $.KomandoPanel.alloc.initWithContentRectStyleMaskBackingDefer($.NSMakeRect(0, 0, w + 2 * pad, h), $.NSWindowStyleMaskTitled | $.NSWindowStyleMaskClosable | $.NSWindowStyleMaskNonactivatingPanel, $.NSBackingStoreBuffered, false);
  PANEL = panel;
  panel.title = argv[6];
  panel.delegate = answer;
  var view = panel.contentView, y = h - pad;
  parts.forEach(function (p, i) {
    if (i) y -= gap;
    y -= p.h;
    p.v.frame = $.NSMakeRect(pad, y, w, p.h);
    view.addSubview(p.v);
  });
  if (body) {
    y -= gap + bodyH;
    var sv = $.NSScrollView.alloc.initWithFrame($.NSMakeRect(pad, y, w, bodyH));
    sv.hasHorizontalScroller = false;
    sv.hasVerticalScroller = scroll;
    // legacy scrollers: the bar is drawn even before the first scroll
    sv.scrollerStyle = 0;
    sv.drawsBackground = false;
    body.v.frame = $.NSMakeRect(0, 0, bw, body.h);
    DOC = $.KomandoDoc.alloc.initWithFrame($.NSMakeRect(0, 0, bw, body.h));
    DOC.addSubview(body.v);
    DOC.addSubview($.KomandoClick.alloc.initWithFrame($.NSMakeRect(0, 0, bw, body.h)));
    sv.documentView = DOC;
    SV = sv;
    SCROLLS = scroll;
    DOC.setAccessibilityElement(true);
    DOC.setAccessibilityRole($.NSAccessibilityGroupRole);
    // the name before the first colon ("Command", "Script"), else the panel title
    var name = argv[5].split(':')[0];
    sv.setAccessibilityLabel(name !== argv[5] && name.length <= 24 ? name : argv[6]);
    DOC.setAccessibilityLabel(name !== argv[5] && name.length <= 24 ? name : argv[6]);
    if (scroll) RINGS.script = ringBox(view, pad, y, w, bodyH);
    view.addSubview(sv);
    // start at the first line (the document is flipped)
    sv.contentView.scrollToPoint($.NSMakePoint(0, 0));
    sv.reflectScrolledClipView(sv.contentView);
    if (scroll) {
      CLIP = sv.contentView;
      sv.contentView.postsBoundsChangedNotifications = true;
      $.NSNotificationCenter.defaultCenter.addObserverSelectorNameObject(answer, 'scrolled:', $.NSViewBoundsDidChangeNotification, sv.contentView);
    }
  }
  if (hint) {
    y -= gap + hint.h;
    hint.v.frame = $.NSMakeRect(pad, y, w, hint.h);
    view.addSubview(hint.v);
  }
  allow.frame = $.NSMakeRect(pad + w - aw, pad, aw, bh);
  deny.frame = $.NSMakeRect(pad + w - aw - 12 - dw, pad, dw, bh);
  RINGS.deny = ringBox(view, pad + w - aw - 12 - dw, pad, dw, bh);
  RINGS.allow = ringBox(view, pad + w - aw, pad, aw, bh);
  view.addSubview(deny);
  view.addSubview(allow);
  if (scroll && real(DOC)) panel.initialFirstResponder = DOC;
  // another app taking the focus must not hide the panel
  panel.hidesOnDeactivate = false;
  // show over another app's full-screen Space
  panel.collectionBehavior = $.NSWindowCollectionBehaviorCanJoinAllSpaces | $.NSWindowCollectionBehaviorFullScreenAuxiliary;
  panel.level = $.NSFloatingWindowLevel;
  panel.center;
  // the timer's block returns nothing: NSTimer's block type is void
  var t = $.NSTimer.timerWithTimeIntervalRepeatsBlock(120, false, function () { note('end: no answer in 120 s'); CHOICE = 'gave up'; CHOSEN = true; app.stopModalWithCode(GAVE_UP); });
  $.NSRunLoop.currentRunLoop.addTimerForMode(t, $.NSRunLoopCommonModes);
  app.activateIgnoringOtherApps(true);
  panel.makeKeyAndOrderFront(null);
  // AppKit may have given the keys to a selectable text field
  focusHome();
  if (DEBUG) note('shown ' + state());
  // the answer is CHOICE (JXA returns NSInteger as a string); an error out
  // of the modal loop is noted and still ends the run
  try { app.runModalForWindow(panel); } catch (x) { note('error: the modal loop threw ' + x); throw x; }
  note('modal ended, answer ' + CHOICE);
  t.invalidate;
  $.NSNotificationCenter.defaultCenter.removeObserver(answer);
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
	shown := noBreakHyphens(v.shown())
	return []string{"-l", "JavaScript", "-e", macAlertScript, macArgMarker, v.title(), v.info(), v.ownerReason(), strconv.Itoa(int(ownerTimeout.Seconds())), shown,
		w.panel, w.deny, w.allow, fmt.Sprintf(w.scrollAll, v.bodyLines())}
}

// bodyLines is what the scroll hint counts: the script's own lines when
// the body has its head, else the lines of what the window shows.
func (v approvalView) bodyLines() int {
	if first, _, _ := strings.Cut(v.Body, "\n"); v.raw == "" && bodyHead.MatchString(first) {
		if n, err := strconv.Atoi(bodyHead.FindStringSubmatch(first)[3]); err == nil {
			return n
		}
	}
	return strings.Count(v.shown(), "\n") + 1
}

// noBreakHyphens keeps "--yes" and "rm -rf" whole when a label wraps:
// AppKit may break a line after a hyphen, so each becomes U+2011, the
// non-breaking hyphen, which looks the same.
func noBreakHyphens(s string) string { return strings.ReplaceAll(s, "-", "\u2011") }

// macOutcome is how the macOS window ended.
type macOutcome int

const (
	macDenied       macOutcome = iota // Deny, Esc, Return, the close button or anything unexpected
	macAllowed                        // Allow once, then the device owner confirmed
	macOwnerFailed                    // Allow once, but the owner check did not say ok
	macOwnerTimeout                   // Allow once, then nobody confirmed in ownerTimeout
	macGaveUp                         // nobody answered in 120 seconds
	macFailed                         // the panel crashed or printed nothing: nobody answered it
)

// macAnswer reads what osascript printed. Only "Allow once" followed by
// "owner ok" allows; every other answer is a no. No answer at all means the
// panel failed (macFailed), which is not a Deny.
func macAnswer(out []byte) macOutcome {
	if len(out) == 0 {
		return macFailed
	}
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
// Only the CI window tests (approval_shot_test.go) shorten them.
var (
	windowGiveUp     = 120 * time.Second
	macWindowTimeout = 3 * time.Minute
)

// ownerTimeout bounds the device-owner check after "Allow once"; the
// window's 120 s plus this stay inside macWindowTimeout.
const ownerTimeout = 50 * time.Second

// askMac shows the macOS window. With dbg set (KOMANDO_APPROVAL_DEBUG) the
// panel notes what it sees on stderr, and the run goes to dbg
// (macDebugLog).
var askMac = func(v approvalView, dbg io.Writer) (ans macOutcome, shown bool) {
	r := macPanelRun(v, dbg != nil)
	if dbg != nil {
		macDebugLog(dbg, v, r)
	}
	return r.ans, r.shown
}

// macPanelRun runs osascript for the panel once. A debug run turns the
// script's notes on and keeps its stderr in errOut.
func macPanelRun(v approvalView, debug bool) macRun {
	ctx, cancel := context.WithTimeout(context.Background(), macWindowTimeout)
	defer cancel()
	args := macArgs(v)
	var errOut bytes.Buffer
	if debug {
		args = macDebugArgs(v)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", args...)
	if debug {
		cmd.Stderr = &errOut
	}
	r := macRun{start: time.Now()}
	r.out, r.err = cmd.Output()
	r.took = time.Since(r.start)
	r.errOut = errOut.Bytes()
	r.ans, r.shown = macResult(r.out, r.err)
	return r
}

// macResult reads an osascript run of the panel. shown is false when
// osascript could not start; an error exit after it started (the script
// failed) is macFailed: a no, but not one the person gave.
func macResult(out []byte, err error) (ans macOutcome, shown bool) {
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return macDenied, false
	}
	if err != nil {
		return macFailed, true
	}
	return macAnswer(out), true
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
