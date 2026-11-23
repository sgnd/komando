package cli

import (
	"strconv"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// longBodyWindow runs an agent's protected exec with body on the given
// desktop and returns the windows shown and the error with its agent hint.
func longBodyWindow(t *testing.T, osName, body string) ([]string, error) {
	t.Helper()
	saved, savedOS := tcl.args, desktopOS
	savedAsk := askOnScreen
	t.Cleanup(func() {
		tcl.args, desktopOS, askOnScreen = saved, savedOS, savedAsk
		tcl.flags.yes = false
		resetApproval()
	})
	setCallerEnv(t, "CLAUDECODE", "1")
	desktopOS = osName
	var texts []string
	askOnScreen = func(_ *call, text string) (bool, bool) { texts = append(texts, text); return false, true }
	st := &store.State{Hosts: map[string]*store.Host{"web": {Name: "web", Address: "10.0.0.1", Protected: true}}}
	tcl.flags.yes = true
	tcl.args = []string{"komando", "exec", "web", "--script", "./deploy.sh", "--yes"}
	resetApproval()
	noteApprovalBody(tcl, scriptLabel("the script", "./deploy.sh"), []byte(body))
	err := guard(tcl, st, []*store.Host{st.Hosts["web"]}, "sh -s", true)
	if err != nil {
		approvalHint(tcl, toErr(err))
	}
	return texts, err
}

func shortLines(n int) string { return strings.Repeat("true\n", n) }

// The macOS window scrolls and enables Allow only once its last line was
// seen, so it shows a long script whole.
func TestLongScriptShownWholeOnMac(t *testing.T) {
	texts, err := longBodyWindow(t, "darwin", shortLines(bodyMaxLinesScroll-1)+"rm -rf /srv/old\n")
	if err == nil {
		t.Fatal("the person said no, but it passed")
	}
	if len(texts) != 1 {
		t.Fatalf("%d windows for a %d-line script on macOS", len(texts), bodyMaxLinesScroll)
	}
	if want := "rm -rf /srv/old\n"; !strings.Contains(texts[0], want) {
		t.Errorf("the window leaves out the last line %q", want)
	}
}

// Over each desktop's limit: no window, a code of its own, and a message
// that names the number it compared.
func TestTooLongForWindowHasItsOwnCode(t *testing.T) {
	for _, c := range []struct {
		os    string
		limit int
	}{{"darwin", bodyMaxLinesScroll}, {"linux", bodyMaxLines}, {"windows", bodyMaxLines}} {
		// two lines wrap to two pieces each, so the script has limit-1
		// lines and limit+1 shown lines
		long := strings.Repeat("x", bodyWrap+1) + "\n"
		body := shortLines(c.limit-3) + long + long
		texts, err := longBodyWindow(t, c.os, body)
		if err == nil || len(texts) != 0 {
			t.Fatalf("%s: err %v, %d windows", c.os, err, len(texts))
		}
		e := toErr(err)
		if e.Code != "SHORTER_SCRIPT_REQUIRED" {
			t.Errorf("%s: code %s, want SHORTER_SCRIPT_REQUIRED", c.os, e.Code)
		}
		shown, inFile := strconv.Itoa(c.limit+1)+" lines as shown", strconv.Itoa(c.limit-1)+" lines in it"
		if !strings.Contains(e.Hint, shown) || !strings.Contains(e.Hint, inFile) || !strings.Contains(e.Hint, "the "+strconv.Itoa(c.limit)+" lines") {
			t.Errorf("%s: hint does not name the counted numbers (%q, %q, limit %d): %s", c.os, shown, inFile, c.limit, e.Hint)
		}
		if strings.Contains(e.Hint, "clicked Deny") {
			t.Errorf("%s: hint says the user denied: %s", c.os, e.Hint)
		}
	}
}

// At each desktop's limit the script still gets its window.
func TestScriptAtLimitGetsWindow(t *testing.T) {
	for _, c := range []struct {
		os    string
		limit int
	}{{"darwin", bodyMaxLinesScroll}, {"linux", bodyMaxLines}} {
		texts, _ := longBodyWindow(t, c.os, shortLines(c.limit))
		if len(texts) != 1 {
			t.Errorf("%s: %d windows for a script of exactly %d lines", c.os, len(texts), c.limit)
		}
	}
}
