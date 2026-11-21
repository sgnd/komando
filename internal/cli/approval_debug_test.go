package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/rundir"
)

// debugRunDir points the per-user run folder at a new temp folder.
func debugRunDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run")
	saved := rundir.Base
	rundir.Base = func() (string, error) { return dir, nil }
	t.Cleanup(func() { rundir.Base = saved })
	return dir
}

// C237: without KOMANDO_APPROVAL_DEBUG nothing is written anywhere.
func TestApprovalDebugOffByDefault(t *testing.T) {
	dir := debugRunDir(t)
	t.Setenv(approvalDebugEnv, "")
	if w := openApprovalDebug(tcl); w != nil {
		w.Close()
		t.Fatal("a debug log opened without " + approvalDebugEnv)
	}
	if _, err := os.Lstat(dir); err == nil {
		t.Error("the run folder was made without " + approvalDebugEnv)
	}
}

// C237: with it set, the log is approval-debug.log in the run folder,
// 0600, and each run adds to it.
func TestApprovalDebugOpensAPrivateFile(t *testing.T) {
	dir := debugRunDir(t)
	t.Setenv(approvalDebugEnv, "1")
	for _, s := range []string{"first\n", "second\n"} {
		w := openApprovalDebug(tcl)
		if w == nil {
			t.Fatal("no debug log with " + approvalDebugEnv + "=1")
		}
		w.Write([]byte(s))
		w.Close()
	}
	p := filepath.Join(dir, "approval-debug.log")
	if b, err := os.ReadFile(p); err != nil || string(b) != "first\nsecond\n" {
		t.Errorf("log %q, %v", b, err)
	}
	if fi, _ := os.Lstat(p); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %o, want 600", fi.Mode().Perm())
	}
}

// exitStatus2 is a real *exec.ExitError: the test binary refuses a flag.
func exitStatus2(t *testing.T) error {
	t.Helper()
	err := exec.Command(os.Args[0], "-test.no-such-flag").Run()
	if err == nil {
		t.Fatal("the test binary took an unknown flag")
	}
	return err
}

// C237: the log holds what the panel noted and how osascript ended, never
// the texts the panel shows: a text in osascript's error output is
// replaced, and an answer that is not one of the fixed tokens is counted,
// not copied.
func TestMacDebugLogKeepsThePanelTextsOut(t *testing.T) {
	v := testView("Claude Code", []string{"--yes"}, "", []string{"it runs on web-9.example.test"},
		"komando exec web-9.example.test --script ./x.sh --yes",
		shotScript("./x.sh", "abcd", []string{"echo LINEMARK-SECRET-42", "echo done"}))
	errOut := "komando-debug +0 shown scroll=false seen=true fka=false key=true active=true | first deny\n" +
		"komando-debug +2104 key 48 mods 0 | first deny\n" +
		"execution error: Error: echo LINEMARK-SECRET-42 on web-9.example.test (-2700)\n"
	var b bytes.Buffer
	macDebugLog(&b, v, macRun{start: time.Date(2026, 11, 21, 9, 21, 5, 0, time.UTC), took: 4200 * time.Millisecond,
		out: []byte("Deny\n"), errOut: []byte(errOut), err: exitStatus2(t), ans: macDenied, shown: true})
	log := b.String()
	for _, want := range []string{
		"== 2026-11-21 09:21:05.000 UTC macOS approval panel, komando ",
		"view: 2 lines, ", "lang en, flags --yes",
		"js +0 shown scroll=false seen=true fka=false key=true active=true | first deny\n",
		"js +2104 key 48 mods 0 | first deny\n",
		"osascript: exit status 2 after 4.2s\n",
		"stdout: \"Deny\"\n",
		"stderr: execution error: Error: [panel text] on [panel text] (-2700)\n",
		"outcome: denied\n",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log has no %q:\n%s", want, log)
		}
	}
	for _, bad := range []string{"LINEMARK-SECRET-42", "web-9.example.test", "x.sh", "Claude Code"} {
		if strings.Contains(log, bad) {
			t.Errorf("log shows %q:\n%s", bad, log)
		}
	}

	b.Reset()
	macDebugLog(&b, v, macRun{out: []byte("echo LINEMARK-SECRET-42\n"), ans: macDenied, shown: true})
	if log = b.String(); !strings.Contains(log, "stdout: 24 bytes, not one of the answers\n") || strings.Contains(log, "LINEMARK") {
		t.Errorf("an unknown answer is not counted only:\n%s", log)
	}
}

// C237: how osascript ended, by kind: an exit status, a start that failed,
// and the 0 of a run that answered.
func TestMacDebugLogExit(t *testing.T) {
	for _, c := range []struct {
		run  macRun
		want string
	}{
		{macRun{took: time.Second, ans: macGaveUp, shown: true}, "osascript: exit 0 after 1s\n"},
		{macRun{err: exec.ErrNotFound}, "osascript: did not start: " + exec.ErrNotFound.Error() + "\n"},
		{macRun{took: macWindowTimeout, err: exitStatus2(t), shown: true}, "osascript: exit status 2 after 3m0s (komando stops it at 3m0s)\n"},
	} {
		var b bytes.Buffer
		macDebugLog(&b, approvalView{raw: "t"}, c.run)
		if !strings.Contains(b.String(), c.want) {
			t.Errorf("want %q in:\n%s", c.want, b.String())
		}
	}
}

// C237: in a debug run the panel notes, on its error output, each key
// onKey gets (keyName, C256), the first responder, every handler error and
// each way it ends: onKey's Deny keys, Deny and Allow once (a click, or a
// key), the window closing, the timer, the modal loop's end and an error
// that leaves it. A normal run notes nothing: note returns
// at once, and a note that reads AppKit runs only under DEBUG.
func TestMacPanelDebugNotes(t *testing.T) {
	s := macAlertScript
	for _, want := range []string{
		"function run(argv) {\n  DEBUG = argv[10] === '1';\n",
		"function note(what) {\n  if (!DEBUG) return;\n  try { console.log('komando-debug +' + (Date.now() - T0) + ' ' + what + ' | first ' + who()); } catch (x) {}\n}",
		"if (DEBUG) note('key ' + keyName(e));",
		"{ note('end: Deny, key'); CHOICE = 'Deny';",
		"PANEL.selectNextKeyView(null); note('focus moved'); return; }",
		"scrollKey(code)) note('scrolled');",
		"if (DEBUG) note('end: Deny, ' + how());",
		"if (DEBUG) note((SEEN ? 'end: Allow once, ' : 'Allow once ignored: not read to the end, ') + how());",
		"if (DEBUG) note('end: window closes, ' + how());",
		"note('end: no answer in 120 s');",
		"try { app.runModalForWindow(panel); } catch (x) { note('error: the modal loop threw ' + x); throw x; }",
		"note('modal ended, answer ' + CHOICE);",
		"if (DEBUG) note('shown ' + state());",
		"note('script area has focus')", "note('script area lost focus')", "note('read to the end')",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	// a note outside DEBUG takes a plain text, at most with the error or the answer
	plain := regexp.MustCompile(`^note\('[^']*'(?: \+ (?:x|CHOICE))?\)`)
	for i := strings.Index(s, "note("); i >= 0; i = nextNote(s, i) {
		if strings.HasSuffix(s[:i], "function ") || strings.HasSuffix(s[:i], "if (DEBUG) ") {
			continue
		}
		if !plain.MatchString(s[i:]) {
			t.Errorf("a note outside DEBUG reads more than a text: %.80s", s[i:])
		}
	}
	// who, how and state answer "?" after an error
	for _, f := range []string{"function who() {", "function how() {", "function state() {", "function keyName(e) {"} {
		body := s[strings.Index(s, f):]
		body = body[:strings.Index(body, "\n}")+2]
		if !strings.Contains(body, "\n  try {") || !strings.HasSuffix(body, "\n  } catch (x) { return '?'; }\n}") {
			t.Errorf("%s is not one try that answers '?':\n%s", f, body)
		}
	}
}

// nextNote is the index of the next "note(" after i, or -1.
func nextNote(s string, i int) int {
	j := strings.Index(s[i+1:], "note(")
	if j < 0 {
		return -1
	}
	return i + 1 + j
}

// C237: the debug run passes one more argument, "1" as argv[10]; a normal
// run passes none, so the panel notes nothing.
func TestMacDebugArgs(t *testing.T) {
	v := approvalView{raw: "t"}
	got, plain := macDebugArgs(v), macArgs(v)
	if len(got) != len(plain)+1 || got[len(got)-1] != "1" || strings.Join(got[:len(plain)], "\x00") != strings.Join(plain, "\x00") {
		t.Errorf("debug argv %q", got)
	}
	// the script's argv[0] is the marker
	if i := len(got) - 1 - slices.Index(got, macArgMarker); i != 10 {
		t.Errorf("the flag is argv[%d], want argv[10]", i)
	}
}
