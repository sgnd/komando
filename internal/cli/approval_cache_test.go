package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// A person's yes covers what the window showed. A window opened before
// the command knew its script (the one for --reveal) does not answer the
// later checks: the script, the matched rules and the protected server
// get a window that shows them, and a script no window can show is
// refused, as it is without the earlier window.
func TestEarlierWindowDoesNotCoverUnshownBody(t *testing.T) {
	saved := tcl.args
	t.Cleanup(func() {
		tcl.args = saved
		setGate(tcl, false, gateAllowDangerous, gateYes, gateReveal)
	})
	setCallerEnv(t, "CLAUDECODE", "1")
	var texts []string
	savedAsk := askOnScreen
	askOnScreen = func(_ *call, text string) (bool, bool) { texts = append(texts, text); return true, true }
	t.Cleanup(func() { askOnScreen = savedAsk; resetApproval() })

	st := &store.State{Hosts: map[string]*store.Host{"web": {Name: "web", Address: "10.0.0.1", Protected: true}}}
	hosts := []*store.Host{st.Hosts["web"]}
	setGate(tcl, true, gateYes, gateAllowDangerous, gateReveal)
	tcl.args = []string{"komando", "host", "ssh", "exec", "web", "--script", "./deploy.sh", "--yes", "--allow-dangerous", "--reveal"}

	resetApproval()
	if !tcl.revealOK() || len(texts) != 1 { // as the root command does before the command runs
		t.Fatalf("the --reveal window: %d", len(texts))
	}
	body := "rm -rf /srv/app\n"
	noteApprovalBody(tcl, scriptLabel("the script", "./deploy.sh"), []byte(body))
	if err := Guard(tcl, st, nil, body, false); err != nil { // guardBody
		t.Fatalf("the person allows the window that shows the script: %v", err)
	}
	if err := Guard(tcl, st, hosts, "sh -s", true); err != nil {
		t.Fatal(err)
	}
	if len(texts) < 2 {
		t.Fatalf("the --reveal window answered for a script it never showed: %q", texts)
	}
	rest := strings.Join(texts[1:], "\n")
	for _, want := range []string{"rm -rf /srv/app", "It also sends the script ./deploy.sh", "protected host web"} {
		if !strings.Contains(rest, want) {
			t.Errorf("no later window shows %q:\n%s", want, rest)
		}
	}
	if strings.Contains(texts[0], "rm -rf /srv/app") {
		t.Fatalf("the first window had no script yet: %s", texts[0])
	}

	// a script no window can show is refused, earlier yes or not
	for _, bad := range []string{"echo \u202erm -rf /\n", strings.Repeat("true\n", bodyMaxLinesScroll+1)} {
		resetApproval()
		texts = nil
		if !tcl.revealOK() {
			t.Fatal("the --reveal window")
		}
		noteApprovalBody(tcl, scriptLabel("the script", "./deploy.sh"), []byte(bad))
		if err := Guard(tcl, st, hosts, "sh -s", true); err == nil {
			t.Errorf("a script the window cannot show passed on the --reveal yes (%d windows)", len(texts))
		}
		if len(texts) != 1 {
			t.Errorf("an unshowable script opens no window: %d", len(texts))
		}
	}

	// one command, one question, when the first window showed everything
	resetApproval()
	texts = nil
	setGate(tcl, false, gateReveal)
	tcl.args = []string{"komando", "host", "ssh", "exec", "web", "--yes", "--allow-dangerous", "--", "rm", "-rf", "/srv/app"}
	if err := Guard(tcl, st, hosts, "rm -rf /srv/app", true); err != nil || len(texts) != 1 {
		t.Errorf("destructive on a protected server asks once: %v, %d windows", err, len(texts))
	}
	if len(texts) == 1 && !strings.Contains(texts[0], "protected host web") {
		t.Errorf("that window names the protected server: %s", texts[0])
	}
}

// A yes is for the flag its window named: the --reveal window does not
// answer a --yes check, even one that brings no reason of its own. And a
// destructive query on a protected conn asks once, in a window that
// names both.
func TestYesIsForTheFlagItsWindowNamed(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web", "u@10.0.0.9", "--protected")
	if err := vault.Set(store.Save(), "web-pw", "old-value"); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "host", "ssh", "edit", "web", "--credential", "web-pw", "--yes")
	texts := windowText(t, true)
	t.Setenv("V", "agent-value")
	mustRun(t, "credential", "password", "add", "web-pw", "--from-env", "V", "--yes", "--reveal")
	if len(*texts) != 2 || !strings.Contains((*texts)[1], "--yes skips") {
		t.Errorf("the --yes check gets its own window: %q", *texts)
	}

	*texts = nil
	resetApproval()
	mustRun(t, "conn", "add", "lite", "sqlite://"+filepath.Join(t.TempDir(), "app.db"), "--protected")
	*texts = nil
	resetApproval()
	mustRun(t, "database", "sqlite", "query", "lite", "--write", "--yes", "--allow-dangerous", "drop table if exists t")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "protected conn lite") {
		t.Errorf("one window that names the protected conn: %q", *texts)
	}
}
