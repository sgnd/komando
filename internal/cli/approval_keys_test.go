package cli

import (
	"regexp"
	"strings"
	"testing"
)

// macMonitor is the body of the macOS panel's local key monitor.
func macMonitor(t *testing.T) string {
	t.Helper()
	s := macAlertScript
	i := strings.Index(s, "addLocalMonitorForEventsMatchingMaskHandler(")
	if i < 0 {
		t.Fatal("no key monitor")
	}
	return s[i : i+strings.Index(s[i:], "\n  });")]
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

// C237: no key but Esc, Cmd-W and Return (Deny's key equivalent) ends the
// panel. Each key below is named in no line that ends it or sets the
// answer, and has the handling it needs: Tab and Shift-Tab move the focus
// through the panel's own key-view loop; the arrows, Page Up/Down and
// Home/End scroll the script from the monitor (C209), whatever has focus;
// Space scrolls only while the script has focus.
func TestMacPanelKeysNeverDismiss(t *testing.T) {
	mon := macMonitor(t)
	scroll := "if (SCROLLS && (MONITOR_KEYS.indexOf(Number(e.keyCode)) >= 0 || (Number(e.keyCode) === 49 && HAS_FOCUS)) && scrollKey(Number(e.keyCode))) { note('monitor: scrolled, key taken'); return null; }"
	tab := "if (Number(e.keyCode) === 48) { if (Number(e.modifierFlags) & $.NSEventModifierFlagShift) panel.selectPreviousKeyView(null); else panel.selectNextKeyView(null); note('monitor: focus moved, key taken'); return null; }"
	for _, k := range []struct {
		name, code string
		want       []string // in the monitor
		scroll     string   // keyScroll's move for the key
	}{
		{"tab", "48", []string{tab}, ""},
		{"shift-tab", "48", []string{tab, "$.NSEventModifierFlagShift) panel.selectPreviousKeyView(null)"}, ""},
		{"up", "126", []string{scroll}, "code === 126 ? y - line"},
		{"down", "125", []string{scroll}, "code === 125 ? y + line"},
		{"page-up", "116", []string{scroll}, "code === 116 ? y - page"},
		{"page-down", "121", []string{scroll}, "code === 121 || code === 49 ? y + page"},
		{"home", "115", []string{scroll}, "code === 115 ? 0"},
		{"end", "119", []string{scroll}, "code === 119 ? maxY"},
		{"space", "49", []string{scroll}, "code === 121 || code === 49 ? y + page"},
	} {
		t.Run(k.name, func(t *testing.T) {
			for _, w := range k.want {
				if !strings.Contains(mon, w) {
					t.Errorf("the monitor has no %q", w)
				}
			}
			if k.scroll != "" && !strings.Contains(macAlertScript, k.scroll) {
				t.Errorf("keyScroll has no %q", k.scroll)
			}
			code := regexp.MustCompile(`\b` + k.code + `\b`)
			for _, l := range macEndLines() {
				if code.MatchString(l) {
					t.Errorf("a line that ends the panel names key %s: %s", k.code, l)
				}
			}
			// the monitor's branches that answer are Esc and Cmd-W alone
			for _, l := range strings.Split(mon, "\n") {
				if strings.Contains(l, "stopModal") && !strings.Contains(l, "=== 53)") && !strings.Contains(l, "=== 13 &&") {
					t.Errorf("a monitor line answers for another key: %s", l)
				}
			}
		})
	}
	// Space is not one of the keys the monitor scrolls with whatever has focus
	if !strings.Contains(macAlertScript, "var MONITOR_KEYS = [126, 125, 116, 121, 115, 119];") {
		t.Error("the monitor keys are not the arrows, Page Up/Down and Home/End")
	}
	// Tab is taken after Esc and Cmd-W, before the scroll keys
	esc, cmdW, tabAt, sc := strings.Index(mon, "=== 53)"), strings.Index(mon, "=== 13 &&"), strings.Index(mon, "=== 48)"), strings.Index(mon, "MONITOR_KEYS")
	if esc < 0 || cmdW < esc || tabAt < cmdW || sc < tabAt {
		t.Errorf("monitor order: Esc %d, Cmd-W %d, Tab %d, scroll %d", esc, cmdW, tabAt, sc)
	}
	// the loop Tab walks: Deny, Allow once (AppKit skips it while it is off), the script
	for _, want := range []string{"deny.nextKeyView = allow", "allow.nextKeyView = scroll ? DOC : deny", "if (scroll) DOC.nextKeyView = deny", "allow.enabled = !scroll"} {
		if !strings.Contains(macAlertScript, want) {
			t.Errorf("script has no %q", want)
		}
	}
	// no button answers to any of these keys: Deny has Return, Allow once none
	for _, l := range strings.Split(macAlertScript, "\n") {
		if strings.Contains(l, "keyEquivalent = ") && !strings.Contains(l, "deny.keyEquivalent = '\\r'") && !strings.Contains(l, "allow.keyEquivalent = ''") {
			t.Errorf("unexpected key equivalent: %s", l)
		}
	}
}

// C237: an error in a key, focus or scroll handler can never end the
// panel. The monitor's whole body is in a try, and after a caught error it
// hands the event back to the system; scrollKey (the bridge calls and
// keyScroll) answers "not scrolled"; the focus and scroll overrides catch
// their own. A catch only notes the error for the debug log (and scrollKey
// answers false, the modal loop's catch throws on); it never answers or
// turns Allow on. The answer handlers (deny:, allow:, windowWillClose:) are
// meant to end the panel.
func TestMacPanelHandlersCannotThrow(t *testing.T) {
	mon := macMonitor(t)
	if !strings.Contains(mon, "function (e) {\n    try {\n") || !strings.HasSuffix(mon, "\n    } catch (x) { note('error in the key monitor: ' + x); }\n    note('monitor: key passed on');\n    return e;") {
		t.Errorf("the monitor is not one try that returns the event after an error:\n%s", mon)
	}
	s := macAlertScript
	sk := s[strings.Index(s, "function scrollKey(code) {"):]
	sk = sk[:strings.Index(sk, "\n}")+2]
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

// C237: the key and focus paths use no bridge that no working path of the
// panel uses. The script area has no keyDown: override (its
// ObjC.super(this).keyDown(e) is gone): the monitor scrolls, and every
// other key goes up the responder chain natively, so Return reaches Deny.
// The focus ring is an NSBox in the system focus colour, shown while the
// area has focus; the CALayer border and its CGColor (a CoreFoundation
// value, which JXA hands over only as an opaque Ref) are gone.
func TestMacPanelFocusPathBridges(t *testing.T) {
	s := macAlertScript
	for _, bad := range []string{"ObjC.super", "'keyDown:'", ".CGColor", ".layer", "wantsLayer"} {
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

// C237: Return and Esc mean Deny as before. Esc and Cmd-W stop the panel
// first in the monitor; Return is Deny's key equivalent and the monitor
// never takes it (nor keypad Enter); Deny keeps the first focus, and the
// Allow gate is the same.
func TestMacPanelReturnEscUnchanged(t *testing.T) {
	s := macAlertScript
	mon := macMonitor(t)
	for _, want := range []string{
		"if (Number(e.keyCode) === 53) { note('end: Esc, key monitor'); CHOICE = 'Deny'; CHOSEN = true; app.stopModalWithCode(DENY); return null; }",
		"if (Number(e.keyCode) === 13 && (Number(e.modifierFlags) & $.NSEventModifierFlagCommand)) { note('end: Cmd-W, key monitor'); CHOICE = 'Deny'; CHOSEN = true; app.stopModalWithCode(DENY); return null; }",
	} {
		if !strings.Contains(mon, want) {
			t.Errorf("the monitor has no %q", want)
		}
	}
	for _, bad := range []string{"=== 36", "=== 76"} {
		if strings.Contains(mon, bad) {
			t.Errorf("the monitor takes %s", bad)
		}
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
