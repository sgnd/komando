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
	onKeyTab    = "if (code === 48) { if (mods & SHIFT) PANEL.selectPreviousKeyView(null); else PANEL.selectNextKeyView(null); note('focus moved'); return; }"
	onKeyScroll = "if (SCROLLS && (SCROLL_KEYS.indexOf(code) >= 0 || (code === 49 && HAS_FOCUS)) && scrollKey(code)) note('scrolled');"
)

// C237: one test per key. Esc, Return and Cmd-W deny in onKey, the one
// key handler; every other key below is named in no line that ends the
// panel or sets the answer, and has the handling it needs: Tab and
// Shift-Tab move the focus through the panel's key-view loop; Up, Down,
// Page Up/Down and Home/End scroll the script whatever has focus; Space
// scrolls only while the script has focus; Left and Right do nothing.
func TestMacPanelKeys(t *testing.T) {
	on := macFunc(t, "onKey")
	for _, k := range []struct {
		name, code string
		want       []string // in onKey
		scroll     string   // keyScroll's move for the key
		denies     bool
	}{
		{"tab", "48", []string{onKeyTab}, "", false},
		{"shift-tab", "48", []string{onKeyTab, "if (mods & SHIFT) PANEL.selectPreviousKeyView(null)"}, "", false},
		{"up", "126", []string{onKeyScroll}, "code === 126 ? y - line", false},
		{"down", "125", []string{onKeyScroll}, "code === 125 ? y + line", false},
		{"left", "123", nil, "", false},
		{"right", "124", nil, "", false},
		{"page-up", "116", []string{onKeyScroll}, "code === 116 ? y - page", false},
		{"page-down", "121", []string{onKeyScroll}, "code === 121 || code === 49 ? y + page", false},
		{"home", "115", []string{onKeyScroll}, "code === 115 ? 0", false},
		{"end", "119", []string{onKeyScroll}, "code === 119 ? maxY", false},
		{"space", "49", []string{onKeyScroll, "code === 49 && HAS_FOCUS"}, "code === 121 || code === 49 ? y + page", false},
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
	// Deny's keys first, then Tab, then the scroll keys; nothing after
	d, tb, sc := strings.Index(on, onKeyDeny), strings.Index(on, onKeyTab), strings.Index(on, onKeyScroll)
	if d < 0 || tb < d || sc < tb || !strings.HasPrefix(on[sc+len(onKeyScroll):], "\n  } catch") {
		t.Errorf("onKey order: Deny %d, Tab %d, scroll %d:\n%s", d, tb, sc, on)
	}
	// the loop Tab walks: Deny, Allow once (AppKit skips it while it is off), the script
	for _, want := range []string{"deny.nextKeyView = allow", "allow.nextKeyView = scroll ? DOC : deny", "if (scroll) DOC.nextKeyView = deny", "allow.enabled = !scroll"} {
		if !strings.Contains(macAlertScript, want) {
			t.Errorf("script has no %q", want)
		}
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
		"becomeFirstResponder": "implementation: function () { try { focusRing(true); note('script area has focus'); } catch (x) { note('error in becomeFirstResponder: ' + x); } return true; } },",
		"resignFirstResponder": "implementation: function () { try { focusRing(false); note('script area lost focus'); } catch (x) { note('error in resignFirstResponder: ' + x); } return true; } }",
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
// the panel uses: no ObjC.super, and the focus ring is an NSBox in the
// system focus colour (a CALayer border needs a CGColor, which JXA hands
// over only as an opaque Ref).
func TestMacPanelFocusPathBridges(t *testing.T) {
	s := macAlertScript
	for _, bad := range []string{"ObjC.super", ".CGColor", ".layer", "wantsLayer"} {
		if strings.Contains(s, bad) {
			t.Errorf("the script still uses %s", bad)
		}
	}
	for _, want := range []string{
		"function focusRing(on) { HAS_FOCUS = on; RING.hidden = !on; }",
		"RING = $.NSBox.alloc.initWithFrame($.NSMakeRect(pad - 3, y - 3, w + 6, bodyH + 6));",
		"RING.boxType = 4;", "RING.titlePosition = 0;", "RING.borderWidth = 3;", "RING.cornerRadius = 4;",
		"RING.borderColor = $.NSColor.keyboardFocusIndicatorColor;", "RING.hidden = true;", "view.addSubview(RING);",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	// the ring sits behind the script area: added before it, only when it scrolls
	if r, v := strings.Index(s, "view.addSubview(RING)"), strings.Index(s, "view.addSubview(sv)"); r < 0 || v < r {
		t.Error("the ring is not added before the scroll view")
	}
}

// C237: Return and Esc mean Deny as before. Return is also Deny's key
// equivalent (AppKit may click it before any keyDown:), keypad Enter is
// neither; Deny keeps the first focus, and the Allow gate is the same.
func TestMacPanelReturnEscUnchanged(t *testing.T) {
	s := macAlertScript
	on := macFunc(t, "onKey")
	if !strings.Contains(on, onKeyDeny) {
		t.Errorf("onKey has no %q", onKeyDeny)
	}
	if strings.Contains(on, "76") {
		t.Error("onKey takes keypad Enter")
	}
	for _, want := range []string{"deny.keyEquivalent = '\\r'", "panel.initialFirstResponder = deny"} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
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
