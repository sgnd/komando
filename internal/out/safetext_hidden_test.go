package out

import "testing"

// A server cannot hide text in its output (SGR 8), reorder it with bidi
// overrides, or move back over a server's name with \r; colours, the
// 256-colour 8 and progress bars without a name stay.
func TestSafeTextHidesNothing(t *testing.T) {
	for in, want := range map[string]string{
		"\x1b[8msecret\x1b[0m":         `\e[8msecret` + "\x1b[0m",
		"\x1b[1;8mx":                   `\e[1;8mx`,
		"\x1b[38;5;8mgrey\x1b[0m":      "\x1b[38;5;8mgrey\x1b[0m",
		"\x1b[48;2;8;8;8mdark":         "\x1b[48;2;8;8;8mdark",
		"\x1b[31mred\x1b[0m":           "\x1b[31mred\x1b[0m",
		"rm -rf \u202e/ fdsa":          "rm -rf \\u202e/ fdsa",
		"a\u2066b\u2069c":              "a\\u2066b\\u2069c",
		"\u200fright to left\u200e ok": "\u200fright to left\u200e ok",
		"50%\r100%\n":                  "50%\r100%\n",
	} {
		if got := SafeText(in); got != want {
			t.Errorf("SafeText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := NoCR("50%\r[web2] ok\r\n"); got != `50%\r[web2] ok`+"\r\n" {
		t.Errorf("NoCR: %q", got)
	}
}
