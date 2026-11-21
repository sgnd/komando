package cli

import (
	"regexp"
	"strings"
	"testing"
)

// macFunc is the body of the panel script's top-level function name.
func macFunc(t *testing.T, name string) string {
	t.Helper()
	s := macAlertScript
	i := strings.Index(s, "function "+name+"(")
	if i < 0 {
		t.Fatalf("no function %s", name)
	}
	return s[i : i+strings.Index(s[i:], "\n}")+2]
}

// macOverride is the one-line registration of a JXA method override.
func macOverride(t *testing.T, name string) string {
	t.Helper()
	s := macAlertScript
	i := strings.Index(s, "'"+name+"': { types:")
	if i < 0 {
		t.Fatalf("no override %s", name)
	}
	return s[i : i+strings.Index(s[i:], "\n")]
}

// macEndLines are the script's lines that end the panel or set its answer.
func macEndLines() []string {
	var out []string
	for _, l := range strings.Split(macAlertScript, "\n") {
		if strings.Contains(l, "stopModal") || strings.Contains(l, "abortModal") || strings.Contains(l, "CHOICE = ") || strings.Contains(l, "performClose") || strings.Contains(l, "panel.close") {
			out = append(out, l)
		}
	}
	return out
}

const (
	onKeyDeny   = "if (code === 53 || code === 36 || (code === 13 && (mods & CMD))) { note('end: Deny, key'); CHOICE = 'Deny'; CHOSEN = true; APP.stopModalWithCode(DENY); return; }"
	onKeyTab    = "if (code === 48) { showFocus(nextFocus(FOCUS, (mods & SHIFT) !== 0, SCROLLS, SEEN)); note('focus moved'); return; }"
	onKeySpace  = "if (code === 49 && (FOCUS === 'deny' || FOCUS === 'allow')) { var btn = FOCUS === 'allow' ? ALLOW_BTN : DENY_BTN; note('Space presses the focused button'); btn.performClick(btn); return; }"
	onKeyScroll = "if (SCROLLS && (SCROLL_KEYS.indexOf(code) >= 0 || (code === 49 && FOCUS === 'script')) && scrollKey(code)) { if (DEBUG) note('scrolled to ' + where()); }"
)

// C237: one test per key. Esc, Return and Cmd-W deny in onKey, the one
// key handler; every other key below is named in no line that ends the
// panel or sets the answer, and has the handling it needs: Tab and
// Shift-Tab move the panel's own focus (nextFocus); Up, Down, Page Up/Down
// and Home/End scroll the script whatever has focus; Space scrolls while
// the script has focus and presses a focused button; Left and Right do
// nothing.
func TestMacPanelKeys(t *testing.T) {
	on := macFunc(t, "onKey")
	for _, k := range []struct {
		name, code string
		want       []string // in onKey
		scroll     string   // keyScroll's move for the key
		denies     bool
	}{
		{"tab", "48", []string{onKeyTab}, "", false},
		{"shift-tab", "48", []string{onKeyTab, "(mods & SHIFT) !== 0"}, "", false},
		{"up", "126", []string{onKeyScroll}, "code === 126 ? y - line", false},
		{"down", "125", []string{onKeyScroll}, "code === 125 ? y + line", false},
		{"left", "123", nil, "", false},
		{"right", "124", nil, "", false},
		{"page-up", "116", []string{onKeyScroll}, "code === 116 ? y - page", false},
		{"page-down", "121", []string{onKeyScroll}, "code === 121 || code === 49 ? y + page", false},
		{"home", "115", []string{onKeyScroll}, "code === 115 ? 0", false},
		{"end", "119", []string{onKeyScroll}, "code === 119 ? maxY", false},
		{"space", "49", []string{onKeyScroll, onKeySpace, "code === 49 && FOCUS === 'script'"}, "code === 121 || code === 49 ? y + page", false},
		{"return", "36", []string{onKeyDeny}, "", true},
		{"esc", "53", []string{onKeyDeny}, "", true},
		{"cmd-w", "13", []string{onKeyDeny, "code === 13 && (mods & CMD)"}, "", true},
	} {
		t.Run(k.name, func(t *testing.T) {
			for _, w := range k.want {
				if !strings.Contains(on, w) {
					t.Errorf("onKey has no %q", w)
				}
			}
			if k.scroll != "" && !strings.Contains(macAlertScript, k.scroll) {
				t.Errorf("keyScroll has no %q", k.scroll)
			}
			code := regexp.MustCompile(`\b` + k.code + `\b`)
			var named []string
			for _, l := range macEndLines() {
				if code.MatchString(l) {
					named = append(named, l)
				}
			}
			switch {
			case k.denies && (len(named) != 1 || strings.TrimSpace(named[0]) != onKeyDeny):
				t.Errorf("key %s ends the panel in %q, want only onKey's Deny line", k.code, named)
			case !k.denies && len(named) > 0:
				t.Errorf("a line that ends the panel names key %s: %q", k.code, named)
			}
			if k.name == "left" || k.name == "right" {
				if code.MatchString(on) || strings.Contains(macAlertScript[strings.Index(macAlertScript, "var SCROLL_KEYS"):strings.Index(macAlertScript, "var SCROLL_KEYS")+50], k.code) {
					t.Errorf("key %s is handled", k.code)
				}
			}
		})
	}
	// Space is not one of the keys that scroll whatever has focus
	if !strings.Contains(macAlertScript, "var SCROLL_KEYS = [126, 125, 116, 121, 115, 119];") {
		t.Error("the scroll keys are not Up, Down, Page Up/Down and Home/End")
	}
	// Deny's keys first, then Tab, then Space on a button, then the scroll keys; nothing after
	d, tb, sp, sc := strings.Index(on, onKeyDeny), strings.Index(on, onKeyTab), strings.Index(on, onKeySpace), strings.Index(on, onKeyScroll)
	if d < 0 || tb < d || sp < tb || sc < sp || !strings.HasPrefix(on[sc+len(onKeyScroll):], "\n  } catch") {
		t.Errorf("onKey order: Deny %d, Tab %d, Space %d, scroll %d:\n%s", d, tb, sp, sc, on)
	}
	// no button answers to any other key: Deny has Return, Allow once none
	for _, l := range strings.Split(macAlertScript, "\n") {
		if strings.Contains(l, "keyEquivalent") && !strings.Contains(l, "deny.keyEquivalent = '\\r'") && !strings.Contains(l, "allow.keyEquivalent = ''") {
			t.Errorf("unexpected key equivalent: %s", l)
		}
	}
}

// C237: no ObjC-to-JS callback in the modal loop hands AppKit a value it
// cannot read. The key monitor's block returned the event as a JSValue,
// AppKit sent it -type and raised an exception outside the script. Keys
// now reach onKey through two typed keyDown: overrides that return void.
// Every override declares its return type (void, or bool for the script
// area's AppKit questions), which the bridge converts. The two blocks
// left return void and say no return: the 120 s timer, and the owner
// check's reply, which runs after the modal loop.
func TestMacPanelNoValueToAppKit(t *testing.T) {
	s := macAlertScript
	for _, bad := range []string{"addLocalMonitor", "addGlobalMonitor", "removeMonitor", "Handler("} {
		if strings.Contains(s, bad) {
			t.Errorf("the script uses %s", bad)
		}
	}
	for _, want := range []string{
		"name: 'KomandoPanel',\n  superclass: 'NSPanel',",
		"var panel = $.KomandoPanel.alloc.initWithContentRectStyleMaskBackingDefer(",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	keyDown := "'keyDown:': { types: ['void', ['id']], implementation: function (e) { onKey(e); } }"
	if n := strings.Count(s, "'keyDown:'"); n != 2 || strings.Count(s, keyDown) != 2 {
		t.Errorf("%d keyDown: overrides; want the panel's and the script area's, each %q", n, keyDown)
	}
	// every override returns void or bool
	for _, m := range regexp.MustCompile(`types: \['([a-z]+)'`).FindAllStringSubmatch(s, -1) {
		if m[1] != "void" && m[1] != "bool" {
			t.Errorf("an override returns %s", m[1])
		}
	}
	// a function handed to the bridge is an override, a JS-only forEach, or
	// one of the two void blocks
	blocks := map[string]string{
		"timerWithTimeIntervalRepeatsBlock(120, false, ": "function () { note('end: no answer in 120 s'); CHOICE = 'gave up'; CHOSEN = true; app.stopModalWithCode(GAVE_UP); }",
		"evaluatePolicyLocalizedReasonReply(2, reason, ": "function (ok, err) { res = (ok === true || ok === 1) ? 'owner ok' : 'owner denied'; }",
	}
	for _, at := range regexp.MustCompile(`function \(`).FindAllStringIndex(s, -1) {
		before := s[:at[0]]
		switch {
		case strings.HasSuffix(before, "implementation: "), strings.HasSuffix(before, ".forEach("):
			continue
		}
		ok := false
		for call, body := range blocks {
			if strings.HasSuffix(before, call) && strings.HasPrefix(s[at[0]:], body) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("a function goes to the bridge as a block: %.90s", s[max(0, at[0]-50):])
		}
	}
	for _, body := range blocks {
		if strings.Contains(body, "return") {
			t.Errorf("a block returns a value: %s", body)
		}
	}
	// the owner check's block runs after the modal loop
	if strings.Index(s, "app.runModalForWindow(panel)") > strings.LastIndex(s, "owner(argv[3], argv[4])") {
		t.Error("the owner check runs inside the modal loop")
	}
}

// C237: an error in a key, focus or scroll handler can never end the
// panel. onKey's whole body is in a try; scrollKey (the bridge calls and
// keyScroll) answers "not scrolled"; the focus and scroll overrides catch
// their own. A catch only notes the error for the debug log (and scrollKey
// answers false, the modal loop's catch throws on); it never answers or
// turns Allow on. The answer handlers (deny:, allow:, windowWillClose:) are
// meant to end the panel.
func TestMacPanelHandlersCannotThrow(t *testing.T) {
	on := macFunc(t, "onKey")
	if !strings.HasPrefix(on, "function onKey(e) {\n  try {\n") || !strings.HasSuffix(on, "\n  } catch (x) { note('error in onKey: ' + x); }\n}") {
		t.Errorf("onKey is not one try that only notes an error:\n%s", on)
	}
	sk := macFunc(t, "scrollKey")
	if !strings.HasPrefix(sk, "function scrollKey(code) {\n  try {\n") || !strings.HasSuffix(sk, "\n  } catch (x) { note('error in scrollKey: ' + x); return false; }\n}") {
		t.Errorf("scrollKey is not one try that answers false:\n%s", sk)
	}
	for name, want := range map[string]string{
		"becomeFirstResponder": "implementation: function () { try { showFocus('script'); note('script area has focus'); } catch (x) { note('error in becomeFirstResponder: ' + x); } return true; } },",
		"resignFirstResponder": "implementation: function () { try { showFocus(''); note('script area lost focus'); } catch (x) { note('error in resignFirstResponder: ' + x); } return true; } }",
		"scrolled:":            "implementation: function (n) { try { if (SEEN) return; var r = CLIP.documentVisibleRect; if (seenEnd(r.origin.y, r.size.height, DOC.frame.size.height)) { SEEN = true; ALLOW_BTN.enabled = true; note('read to the end'); } } catch (x) { note('error in scrolled: ' + x); } } },",
		// a constant or a variable cannot throw
		"isFlipped":             "implementation: function () { return true; } },",
		"acceptsFirstResponder": "implementation: function () { return SCROLLS; } },",
	} {
		if got := macOverride(t, name); !strings.HasSuffix(got, want) {
			t.Errorf("%s: %s\nwant it to end with %s", name, got, want)
		}
	}
	// empty (inside note and its helpers), "?" from a helper, a note of the
	// error, scrollKey's false, the modal loop's throw
	allowed := regexp.MustCompile(`^catch \(x\) \{(?:| return '\?'; | note\('[a-zA-Z: ]+' \+ x\);(?: return false;| throw x;)? )\}$`)
	s := macAlertScript
	all := regexp.MustCompile(`catch \(x\) \{[^}]*\}`).FindAllString(s, -1)
	for _, c := range all {
		if !allowed.MatchString(c) {
			t.Errorf("a catch does something: %s", c)
		}
	}
	if n := strings.Count(s, "catch ("); n != len(all) {
		t.Errorf("%d catches, %d of them checked", n, len(all))
	}
}

// C237: the key and focus paths call no bridge that no working path of
// the panel uses: no ObjC.super, and each focus ring is an NSBox in the
// system focus colour (a CALayer border needs a CGColor, which JXA hands
// over only as an opaque Ref).
func TestMacPanelFocusPathBridges(t *testing.T) {
	s := macAlertScript
	for _, bad := range []string{"ObjC.super", ".CGColor", ".layer", "wantsLayer"} {
		if strings.Contains(s, bad) {
			t.Errorf("the script still uses %s", bad)
		}
	}
	rb := macFunc(t, "ringBox")
	for _, want := range []string{
		"var b = $.NSBox.alloc.initWithFrame($.NSMakeRect(x - 3, y - 3, w + 6, h + 6));",
		"b.boxType = 4;", "b.titlePosition = 0;", "b.borderWidth = 3;", "b.cornerRadius = 4;",
		"b.borderColor = $.NSColor.keyboardFocusIndicatorColor;", "b.hidden = true;", "view.addSubview(b);", "return b;",
	} {
		if !strings.Contains(rb, want) {
			t.Errorf("ringBox has no %q", want)
		}
	}
}

// C237: each place Tab stops has its own ring, and only the focused one
// shows: the script area's ring sits behind the scroll view, the buttons'
// rings behind the buttons.
func TestMacPanelFocusRings(t *testing.T) {
	s := macAlertScript
	if got := macFunc(t, "showFocus"); got != "function showFocus(f) {\n  FOCUS = f;\n  for (var k in RINGS) RINGS[k].hidden = k !== f;\n}" {
		t.Errorf("showFocus:\n%s", got)
	}
	for _, want := range []string{
		"RINGS.script = ringBox(view, pad, y, w, bodyH);",
		"RINGS.deny = ringBox(view, pad + w - aw - 12 - dw, pad, dw, bh);",
		"RINGS.allow = ringBox(view, pad + w - aw, pad, aw, bh);",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	if r, v := strings.Index(s, "RINGS.script = ringBox("), strings.Index(s, "view.addSubview(sv)"); r < 0 || v < r {
		t.Error("the script's ring is not added before the scroll view")
	}
	if r, b := strings.Index(s, "RINGS.allow = ringBox("), strings.Index(s, "view.addSubview(deny)"); r < 0 || b < r {
		t.Error("the buttons' rings are not added before the buttons")
	}
	if strings.Count(s, "= ringBox(view,") != 3 {
		t.Error("a ring other than the script's, Deny's and Allow once's")
	}
}

// C237: the script area is the first responder when the panel opens, with
// its ring, so the arrows, Page keys, Home and End scroll at once, with no
// click. A panel with nothing to scroll gives the keys to itself and the
// ring to Deny. focusHome runs once the panel is up, so a selectable text
// field AppKit may have picked never holds the keys.
func TestMacPanelScriptFocusAtOpen(t *testing.T) {
	s := macAlertScript
	if got := macFunc(t, "focusHome"); got != macFocusHome {
		t.Errorf("focusHome:\n%s", got)
	}
	if !strings.Contains(s, "if (scroll && real(DOC)) panel.initialFirstResponder = DOC;") {
		t.Error("the script area is not the initial first responder")
	}
	front, home, modal := strings.Index(s, "panel.makeKeyAndOrderFront(null);"), strings.Index(s, "  focusHome();\n"), strings.Index(s, "app.runModalForWindow(panel)")
	if front < 0 || home < front || modal < home {
		t.Errorf("focusHome must run after the panel is up and before the modal loop: front %d, focusHome %d, modal %d", front, home, modal)
	}
}

const macFocusHome = "function focusHome() {\n" +
	"  var toScript = SCROLLS && real(DOC);\n" +
	"  PANEL.makeFirstResponder(toScript ? DOC : PANEL);\n" +
	"  showFocus(toScript ? 'script' : 'deny');\n}"

// C237: JXA hands a JavaScript null to AppKit as NSNull, not nil, so
// makeFirstResponder(null) raised "-[NSNull becomeFirstResponder]" in every
// panel with nothing to scroll (run 44874878640). No AppKit call gets a
// null that stands for a control: real() tells an AppKit object from null,
// undefined, nil and NSNull, and the only nulls left are a sender AppKit
// ignores and an NSError out-argument.
func TestMacPanelNoNullToAppKit(t *testing.T) {
	s := macAlertScript
	want := "function real(o) {\n" +
		"  try { return o !== null && o !== undefined && !o.isNil() && ObjC.unwrap(o.className) !== 'NSNull'; } catch (x) { note('error in real: ' + x); return false; }\n}"
	if got := macFunc(t, "real"); got != want {
		t.Errorf("real:\n%s\nwant:\n%s", got, want)
	}
	allowed := map[string]bool{
		"panel.makeKeyAndOrderFront(null)":    true, // sender, unused
		"panel.orderOut(null)":                true, // sender, unused
		"ctx.canEvaluatePolicyError(2, null)": true, // NSError ** out-argument
	}
	for _, m := range regexp.MustCompile(`[\w.$]+\([^()]*\bnull\)`).FindAllString(s, -1) {
		if !allowed[m] {
			t.Errorf("an AppKit call gets null: %s", m)
		}
	}
	for _, bad := range []string{": null)", "makeFirstResponder(null", "performClick(null", "Responder = null"} {
		if strings.Contains(s, bad) {
			t.Errorf("the script has %q", bad)
		}
	}
	if n := strings.Count(s, "makeFirstResponder("); n != 1 || !strings.Contains(s, "PANEL.makeFirstResponder(toScript ? DOC : PANEL);") {
		t.Errorf("%d makeFirstResponder calls; want only focusHome's, with the script or the panel", n)
	}
}

// C237: a panel with no script view (no argv[5]) or one whose script fits
// gives the keys to the panel itself and the ring to Deny. DOC stays null
// then: the click view, the script's ring and initialFirstResponder are
// set only where DOC exists and scrolls, and focusHome checks real(DOC).
func TestMacPanelNoScriptView(t *testing.T) {
	s := macAlertScript
	if got := macFunc(t, "focusHome"); got != macFocusHome {
		t.Errorf("focusHome:\n%s", got)
	}
	body := s[strings.Index(s, "  if (body) {\n"):strings.Index(s, "  if (hint) {\n")]
	for _, want := range []string{"DOC = $.KomandoDoc.alloc.initWithFrame(", "DOC.addSubview($.KomandoClick.alloc.initWithFrame(", "if (scroll) RINGS.script = ringBox("} {
		if !strings.Contains(body, want) {
			t.Errorf("%q is not inside if (body)", want)
		}
	}
	if !strings.Contains(s, "var SEEN = true, CLIP = null, DOC = null,") {
		t.Error("DOC does not start as null")
	}
	// with an empty argv[5] there is no body, so no script view at all
	if !strings.Contains(s, "  if (argv[5] !== '') {\n    body = label(argv[5], mono, bw, false);") {
		t.Error("the script view is made without an argv[5]")
	}
}

// C237: with Allow once off (a script not yet read to its end), Tab and
// Shift-Tab cycle the script and Deny only; Space on Deny denies.
func TestMacPanelAllowOff(t *testing.T) {
	nf := macFunc(t, "nextFocus")
	if !strings.Contains(nf, "(scrolls ? ['script'] : []).concat(allowOn ? ['deny', 'allow'] : ['deny'])") {
		t.Errorf("nextFocus does not drop Allow once while it is off:\n%s", nf)
	}
	if !strings.Contains(onKeyTab, "nextFocus(FOCUS, (mods & SHIFT) !== 0, SCROLLS, SEEN)") {
		t.Error("Tab does not pass the gate (SEEN) as allowOn")
	}
	if !strings.Contains(macAlertScript, "allow.enabled = !scroll;") || !strings.Contains(macAlertScript, "SEEN = !scroll;") {
		t.Error("Allow once and SEEN do not start off together for a script that scrolls")
	}
}

// C237: the macOS screenshot cases with nothing to scroll (hosts, short,
// db-query, sudo, destructive, indonesian) show a few lines under the title,
// far below a screen; their panel takes the focusHome fallback to the
// panel and Deny, the path that raised the NSNull exception.
func TestMacPanelShortCases(t *testing.T) {
	for _, name := range []string{"hosts", "short", "db-query", "sudo", "destructive", "indonesian"} {
		t.Run(name, func(t *testing.T) {
			var v approvalView
			for _, c := range shotCases {
				if c.name == name {
					v = c.view()
				}
			}
			if v.Agent == "" {
				t.Fatalf("no shot case %s", name)
			}
			shown := macArgs(v)[9]
			if n := strings.Count(shown, "\n") + 1; n > 4 {
				t.Errorf("%s shows %d lines: not a short case", name, n)
			}
		})
	}
	if !strings.Contains(macFocusHome, "toScript ? DOC : PANEL") {
		t.Error("the short cases have no fallback to the panel")
	}
}

// C237: Tab and Shift-Tab cycle script, Deny, Allow once and back,
// whatever the macOS keyboard-navigation setting: the buttons refuse
// AppKit's focus, so the first responder stays the script area (or the
// panel) and every key reaches onKey; FOCUS and the rings show where Tab
// is. Allow once is a stop only once it is on (SEEN).
func TestMacPanelTabCycle(t *testing.T) {
	s := macAlertScript
	want := "function nextFocus(f, back, scrolls, allowOn) {\n" +
		"  var order = (scrolls ? ['script'] : []).concat(allowOn ? ['deny', 'allow'] : ['deny']);\n" +
		"  var i = order.indexOf(f);\n" +
		"  if (i < 0) return order[0];\n" +
		"  return order[(i + (back ? order.length - 1 : 1)) % order.length];\n}"
	if got := macFunc(t, "nextFocus"); got != want {
		t.Errorf("nextFocus:\n%s\nwant:\n%s", got, want)
	}
	if !strings.Contains(macFunc(t, "onKey"), onKeyTab) {
		t.Errorf("onKey has no %q", onKeyTab)
	}
	for _, w := range []string{"deny.refusesFirstResponder = true;", "allow.refusesFirstResponder = true;"} {
		if !strings.Contains(s, w) {
			t.Errorf("script has no %q", w)
		}
	}
	// AppKit's key-view loop is not used: it skips the buttons while keyboard navigation is off
	for _, bad := range []string{"nextKeyView", "selectNextKeyView", "selectPreviousKeyView", "initialFirstResponder = deny"} {
		if strings.Contains(s, bad) {
			t.Errorf("the script uses %s", bad)
		}
	}
}

// C237: Space on a focused button presses it as a click would
// (performClick runs the button's own action), so Allow once still meets
// its gate in allow: and the owner check after the panel. Allow once can
// hold the focus only once it is on. Return is never a press of Allow
// once: onKey denies on Return before it looks at the focus.
func TestMacPanelSpacePressesFocusedButton(t *testing.T) {
	s := macAlertScript
	on := macFunc(t, "onKey")
	if !strings.Contains(on, onKeySpace) || strings.Count(s, "performClick") != 1 {
		t.Errorf("Space on a button is not only %q", onKeySpace)
	}
	if strings.Index(on, onKeyDeny) > strings.Index(on, onKeySpace) || strings.Contains(onKeyDeny, "FOCUS") {
		t.Error("Return is read after the focus")
	}
	if !strings.Contains(onKeyTab, "SEEN)") {
		t.Error("Tab can stop on Allow once before the gate opens")
	}
	if !strings.Contains(s, "'allow:': { types: ['void', ['id']], implementation: function (s) { if (DEBUG) note((SEEN ? 'end: Allow once, ' : 'Allow once ignored: not read to the end, ') + how()); if (!SEEN) return;") {
		t.Error("the Allow gate changed")
	}
}

// C237: a click on the script area always gives it the keys back. Its
// text is a label that would take the click itself, so KomandoClick lies
// over it; KomandoDoc takes a click on its own too. A click on the
// panel's background reaches KomandoPanel's mouseDown: and also gives the
// keys back, so the focus is never left on nothing.
func TestMacPanelClickGivesKeysBack(t *testing.T) {
	s := macAlertScript
	click := "'mouseDown:': { types: ['void', ['id']], implementation: function (e) { try { note('click: script area'); focusHome(); } catch (x) { note('error in mouseDown: ' + x); } } }"
	bg := "'mouseDown:': { types: ['void', ['id']], implementation: function (e) { try { note('click: panel background'); focusHome(); } catch (x) { note('error in mouseDown: ' + x); } } }"
	if strings.Count(s, click) != 2 || strings.Count(s, bg) != 1 || strings.Count(s, "'mouseDown:'") != 3 {
		t.Errorf("want the script area's mouseDown: in KomandoDoc and KomandoClick and the panel's own")
	}
	for _, name := range []string{"KomandoDoc", "KomandoClick"} {
		i := strings.Index(s, "name: '"+name+"'")
		if i < 0 || !strings.Contains(s[i:i+strings.Index(s[i:], "\n});")], click) {
			t.Errorf("%s has no click handler", name)
		}
	}
	i := strings.Index(s, "name: 'KomandoPanel'")
	if i < 0 || !strings.Contains(s[i:i+strings.Index(s[i:], "\n});")], bg) {
		t.Error("KomandoPanel has no background click handler")
	}
	// the catcher lies over the text: added after it, the document's size
	for _, want := range []string{"name: 'KomandoClick',\n  superclass: 'NSView',", "DOC.addSubview(body.v);\n    DOC.addSubview($.KomandoClick.alloc.initWithFrame($.NSMakeRect(0, 0, bw, body.h)));"} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
}

// C237: the panel takes the keys while it is up even when macOS does not
// make komando the active app (another app keeps the keys while a
// background process asks to activate): a non-activating panel becomes
// the key window by itself. The debug log notes when it does and says the
// panel's style.
func TestMacPanelKeyWithoutActivation(t *testing.T) {
	s := macAlertScript
	for _, want := range []string{
		"$.NSWindowStyleMaskTitled | $.NSWindowStyleMaskClosable | $.NSWindowStyleMaskNonactivatingPanel",
		"'windowDidBecomeKey:': { types: ['void', ['id']], implementation: function (n) { note('panel is key'); } }",
		"' nonactivating=' + ((Number(PANEL.styleMask) & 128) !== 0)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
}

// C237: Return and Esc mean Deny as before. Return is also Deny's key
// equivalent (AppKit may click it before any keyDown:), keypad Enter is
// neither, and the Allow gate is the same.
func TestMacPanelReturnEscUnchanged(t *testing.T) {
	s := macAlertScript
	on := macFunc(t, "onKey")
	if !strings.Contains(on, onKeyDeny) {
		t.Errorf("onKey has no %q", onKeyDeny)
	}
	if strings.Contains(on, "76") {
		t.Error("onKey takes keypad Enter")
	}
	if !strings.Contains(s, "deny.keyEquivalent = '\\r'") {
		t.Error("Return is not Deny's key equivalent")
	}
	if strings.Count(s, "ALLOW_BTN.enabled = true") != 1 || !strings.Contains(s, "'allow:': { types: ['void', ['id']], implementation: function (s) { if (DEBUG) note((SEEN ? 'end: Allow once, ' : 'Allow once ignored: not read to the end, ') + how()); if (!SEEN) return;") {
		t.Error("the Allow gate changed")
	}
}

// C256: the debug log names a key only while one of the panel's own
// controls has focus, and then only the keys the panel acts on. Otherwise
// (a selectable text field has focus) it writes a class: digit, letter,
// Tab, arrow or other. No note writes a key code.
func TestMacPanelKeyNames(t *testing.T) {
	s := macAlertScript
	kn := macFunc(t, "keyName")
	for _, want := range []string{
		"var KEY_NAMES = { 36: 'Return', 53: 'Esc', 48: 'Tab', 49: 'Space', 123: 'Left', 124: 'Right', 125: 'Down', 126: 'Up', 116: 'PageUp', 121: 'PageDown', 115: 'Home', 119: 'End' };",
		"own = ['deny', 'allow', 'script', 'panel'].indexOf(who()) >= 0;",
		"if (own && KEY_NAMES[code]) return KEY_NAMES[code] + (mods & SHIFT ? ' shift' : '') + (mods & CMD ? ' cmd' : '');",
		"if (code === 48) return 'Tab';",
		"if (code >= 123 && code <= 126) return 'arrow';",
		"return /^[0-9]$/.test(ch) ? 'digit' : ch.length === 1 && ch.toLowerCase() !== ch.toUpperCase() ? 'letter' : 'other';",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	if !strings.HasSuffix(kn, "\n  } catch (x) { return '?'; }\n}") {
		t.Errorf("keyName is not one try that answers '?':\n%s", kn)
	}
	// the only return of a name is behind own; the rest are classes
	for _, l := range strings.Split(kn, "\n") {
		if strings.Contains(l, "return KEY_NAMES") && !strings.Contains(l, "if (own && KEY_NAMES[code])") {
			t.Errorf("a key is named without its own control's focus: %s", l)
		}
	}
	for _, want := range []string{"if (DEBUG) note('key ' + keyName(e));", "return t === 10 ? 'key ' + keyName(e) :"} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	if regexp.MustCompile(`note\([^;]*keyCode`).MatchString(s) || strings.Contains(s, "'key ' + Number(") {
		t.Error("a note writes a key code")
	}
}
